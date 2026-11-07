"""Blast Radius — measure what a destructive command will actually destroy.

Hermes already has two things in this area, and neither one measures:

  * regex approval floors (`tools/approval_floors.py`) match a command shape and ask;
  * smart approval (`tools/approval_smart.py`) asks an auxiliary LLM for an opinion.

Both answer "is this dangerous?". Neither answers "what dies if I say yes?", because
neither ever opens the target. This plugin does: it expands the paths, walks them, and
splits the result into files git can restore and files it cannot. That split is the point.
`git clean -fd`, an uncommitted `.env`, a local database: all untracked, all unrecoverable,
and invisible to a risk opinion formed from the command text.

The number is measured on the filesystem before the command runs, so it cannot be wrong in
the way an estimate can. It can still be *incomplete*: damage that happens inside a program
(`python cleanup.py`), over SSH, or in a subshell this parser does not see is out of scope.
That limit is documented rather than papered over.

Confirmation, not a wall: a block is followed by the user deciding. `blast_allow("<cmd>")`
grants exactly one future execution of that exact command, for five minutes. After it is
used, the gate is closed again. `BLASTRADIUS_ALLOW=1` is the operator's blanket override.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

MAX_FILES = 50_000
MAX_SAMPLES = 5
ALLOW_TTL_S = 300
OVERRIDE_ENV = "BLASTRADIUS_ALLOW"

# Command shapes we can measure honestly. Everything else passes through untouched.
_RM_RE = re.compile(r"(?:^|[|;&]\s*|\bthen\s+|\bdo\s+)rm\b")
_GIT_CLEAN_RE = re.compile(r"\bgit\s+clean\b[^\n]*?(?<![\w-])-[\w-]*f")
_GIT_RESET_RE = re.compile(r"\bgit\s+reset\b[^\n]*--hard")
_TRUNCATE_RE = re.compile(r"(?:^|[|;&]\s*)(?:truncate\s+-s\s*0|:)\s*>")
_MV_RE = re.compile(r"(?:^|[|;&]\s*)mv\b")

_store_dir_override: Path | None = None


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- paths


def data_dir() -> Path:
    global _store_dir_override
    if _store_dir_override is not None:
        path = _store_dir_override
    else:
        home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")
        path = Path(home) / "plugin-data" / "blastradius"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allow_file() -> Path:
    return data_dir() / "allow.json"


def _load_allow() -> list[dict]:
    path = _allow_file()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    now = time.time()
    return [e for e in data if isinstance(e, dict) and e.get("expires", 0) > now]


def _write_allow(entries: list[dict]) -> None:
    try:
        _allow_file().write_text(json.dumps(entries), encoding="utf-8")
    except OSError:
        pass


def grant_allow(command: str, ttl_s: int = ALLOW_TTL_S) -> dict:
    """Allow the next execution of exactly this command, once, within the TTL."""
    entries = [e for e in _load_allow() if e.get("command") != command]
    entries.append({"command": command, "expires": time.time() + ttl_s, "ttl_s": ttl_s})
    _write_allow(entries)
    return {"command": command, "ttl_s": ttl_s, "pending": len(entries)}


def consume_allow(command: str) -> bool:
    """Spend a grant for this command. True if one was pending."""
    entries = _load_allow()
    for i, entry in enumerate(entries):
        if entry.get("command") == command:
            entries.pop(i)
            _write_allow(entries)
            return True
    return False


# --------------------------------------------------------------------- detection


def classify(command: str) -> str | None:
    if not command or not isinstance(command, str):
        return None
    if _GIT_CLEAN_RE.search(command):
        return "git-clean"
    if _GIT_RESET_RE.search(command):
        return "git-reset-hard"
    if _RM_RE.search(command):
        return "rm"
    if _TRUNCATE_RE.search(command):
        return "truncate"
    if _MV_RE.search(command):
        return "mv"
    return None


def _leading_tokens(command: str) -> list[str]:
    segment = re.split(r"[|;&]", command, maxsplit=1)[0].strip()
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def targets_of(command: str, kind: str) -> list[str]:
    if kind.startswith("git-") or kind == "truncate":
        return []
    paths: list[str] = []
    for token in _leading_tokens(command)[1:]:
        if token.startswith("-") or token == "" or token.startswith(">"):
            continue
        paths.append(token)
    return paths


def mv_destination(command: str) -> str | None:
    """`mv src dst` overwrites only when dst already exists as a file, or with -T.
    Moving into an existing directory nests; a plain rename destroys nothing."""
    tokens = _leading_tokens(command)[1:]
    positional = [t for t in tokens if not t.startswith("-")]
    return positional[-1] if len(positional) >= 2 else None


def mv_overwrites(command: str, workdir: Path) -> tuple[bool, Path | None]:
    """(does this mv destroy an existing file, the path it would destroy)."""
    dest = mv_destination(command)
    if dest is None:
        return False, None
    dest_path = (workdir / dest) if not Path(dest).is_absolute() else Path(dest)
    if not dest_path.exists():
        return False, None
    replace_dir = any(t in {"-T", "--no-target-directory"} for t in _leading_tokens(command)[1:])
    if dest_path.is_dir() and not replace_dir:
        return False, None  # mv into a directory: the source is nested, nothing is lost
    return True, dest_path


# ----------------------------------------------------------------------- measuring


def _git_root(start: Path) -> Path | None:
    directory = start if start.is_dir() else start.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return Path(out.stdout.strip())


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _tracked_files(root: Path) -> set[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if out.returncode != 0:
        return set()
    return {p for p in out.stdout.split("\0") if p}


def _walk(root: Path, wanted: list[str], files: list[Path], limit: int = MAX_FILES) -> None:
    for rel in wanted:
        target = (root / rel).resolve() if not Path(rel).is_absolute() else Path(rel)
        try:
            if target.is_dir():
                for dirpath, _dirnames, filenames in os.walk(target):
                    for name in filenames:
                        files.append(Path(dirpath) / name)
                        if len(files) >= limit:
                            return
            elif target.exists():
                files.append(target)
        except OSError:
            continue


def _repo_files(root: Path, files: list[Path]) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            files.append(Path(dirpath) / name)


def _empty(reason: str) -> dict:
    return {
        "kind": None, "measured": False, "reason": reason,
        "files": 0, "tracked": 0, "untracked": 0, "bytes": 0,
        "samples_untracked": [], "targets": [], "truncated": False,
        "git_root": None, "cwd": str(Path.cwd()),
    }


def measure(command: str, cwd: str | None = None) -> dict:
    """Measure a command's target. Never executes the command itself."""
    kind = classify(command)
    if kind is None:
        return _empty("not a command shape we measure")

    workdir = Path(cwd or os.getcwd()).resolve()

    if kind == "mv":
        overwrites, dest_path = mv_overwrites(command, workdir)
        if not overwrites or dest_path is None:
            return _empty("mv to a new path or into a directory: nothing is overwritten")

    files: list[Path] = []
    if kind.startswith("git-"):
        root = _git_root(workdir) or workdir
        _repo_files(root, files)
    elif kind == "mv":
        _overwrites, dest_path = mv_overwrites(command, workdir)
        if dest_path is not None:
            if dest_path.is_dir():
                _walk(workdir, [str(dest_path)], files)
            else:
                files.append(dest_path)
    else:
        _walk(workdir, targets_of(command, kind), files)

    deduped = sorted({f.resolve() for f in files})
    root = _git_root(workdir)
    tracked_set = _tracked_files(root) if root is not None else set()
    tracked = [p for p in deduped if root and _under(p, root) and str(p.relative_to(root)) in tracked_set]
    tracked_ids = {id(p) for p in tracked}
    untracked = [p for p in deduped if id(p) not in tracked_ids]

    total_bytes = 0
    for path in deduped[:MAX_FILES]:
        try:
            total_bytes += path.stat().st_size
        except OSError:
            pass

    return {
        "kind": kind,
        "measured": True,
        "cwd": str(workdir),
        "git_root": str(root) if root else None,
        "targets": targets_of(command, kind),
        "files": len(deduped),
        "tracked": len(tracked),
        "untracked": len(untracked),
        "bytes": total_bytes,
        "samples_untracked": [
            str(p.relative_to(root)) if root and _under(p, root) else str(p)
            for p in untracked[:MAX_SAMPLES]
        ],
        "truncated": len(files) >= MAX_FILES,
    }


def report(m: dict) -> str:
    if not m.get("measured"):
        return f"[blastradius] not measured: {m.get('reason')}"
    if m["files"] == 0:
        return f"[blastradius] {m['kind']}: target is empty or does not exist, nothing to destroy"
    lines = [
        f"⛔ blast radius: {m['kind']} in {m['cwd']}",
        f"   {m['files']:,} file(s), {m['bytes']:,} bytes",
        f"   tracked by git : {m['tracked']:,}   (recoverable)",
        f"   UNTRACKED      : {m['untracked']:,}   (gone permanently)",
    ]
    if m["samples_untracked"]:
        lines.append("   e.g. " + ", ".join(m["samples_untracked"]))
    if m["git_root"] is None:
        lines.append("   (not a git repo, nothing here is recoverable)")
    if m["truncated"]:
        lines.append(f"   (stopped counting at {MAX_FILES:,} files)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- hook


def on_pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """Block a destructive terminal call until its blast radius is on the record."""
    if tool_name != "terminal" or not isinstance(args, dict):
        return None
    command = args.get("command") or args.get("cmd")
    if not isinstance(command, str):
        return None
    if _truthy(OVERRIDE_ENV):
        return None

    m = measure(command, args.get("workdir") or args.get("cwd"))
    if not m.get("measured") or m["files"] == 0:
        return None
    if consume_allow(command.strip()):
        return None
    return {
        "action": "block",
        "message": (
            report(m)
            + "\n\nThis command was not executed. Show the user these numbers, then either "
              "narrow the target, or confirm and call "
              f"blast_allow(\"{command.strip()}\") to permit this exact command once "
              f"(valid {ALLOW_TTL_S // 60} minutes), or set {OVERRIDE_ENV}=1 for a session-wide override."
        ),
    }


# -------------------------------------------------------------------------- tools


def blast_radius(command: str, cwd: str | None = None) -> str:
    """Preview a destructive command's impact without running it."""
    return report(measure(command, cwd))


def blast_allow(command: str, ttl_s: int = ALLOW_TTL_S) -> str:
    """Permit one future execution of exactly this command."""
    if not isinstance(command, str) or not command.strip():
        return "[blastradius] need the exact command string to allow"
    info = grant_allow(command.strip(), max(1, min(int(ttl_s or ALLOW_TTL_S), 3600)))
    return (
        f"[blastradius] allowed once: {info['command']}\n"
        f"valid for {info['ttl_s'] // 60} minute(s). It is spent on the next matching call, "
        "then the gate closes again."
    )


_RADIUS_SCHEMA = {
    "name": "blast_radius",
    "description": (
        "Preview what a destructive command (rm, git clean -fd, git reset --hard, truncate, "
        "mv onto an existing path) would delete, split into files git can restore and files "
        "that would be lost. Runs nothing; measures the filesystem."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command you intend to run."},
            "cwd": {"type": "string", "description": "Directory it would run in (default: cwd)."},
        },
        "required": ["command"],
    },
}

_ALLOW_SCHEMA = {
    "name": "blast_allow",
    "description": (
        "Permit exactly one future execution of a specific destructive command, after the user "
        "has seen its blast radius and said yes. The grant is spent on the next matching call."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The exact command string to allow."},
            "ttl_s": {"type": "integer", "description": "Seconds the grant stays valid (default 300)."},
        },
        "required": ["command"],
    },
}


def _radius_handler(args: dict, **_) -> str:
    return blast_radius(str(args.get("command") or ""), args.get("cwd"))


def _allow_handler(args: dict, **_) -> str:
    return blast_allow(str(args.get("command") or ""), int(args.get("ttl_s") or ALLOW_TTL_S))


def _blast_command(raw_args: str) -> str:
    return blast_radius(raw_args.strip() or "rm -rf .")


def register(ctx) -> None:
    global _store_dir_override
    try:
        candidate = getattr(ctx, "plugin_data_dir", None)
        if callable(candidate):
            _store_dir_override = Path(candidate())
        elif isinstance(candidate, (str, Path)):
            _store_dir_override = Path(candidate)
    except Exception:
        _store_dir_override = None

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_tool(
        name="blast_radius",
        toolset="blastradius",
        schema=_RADIUS_SCHEMA,
        handler=_radius_handler,
        description="Measure what a destructive command would delete.",
        emoji="💥",
    )
    ctx.register_tool(
        name="blast_allow",
        toolset="blastradius",
        schema=_ALLOW_SCHEMA,
        handler=_allow_handler,
        description="Allow one confirmed destructive command exactly once.",
        emoji="🔓",
    )
    ctx.register_command(
        "blast",
        _blast_command,
        description="Preview a destructive command's blast radius.",
        args_hint="<command>",
    )
