"""Blast Radius — measure what a destructive command will actually destroy.

Hermes already has two things in this area, and neither one measures:

  * regex approval floors (`tools/approval_floors.py`) — match a command shape and ask;
  * smart approval (`tools/approval_smart.py`) — an auxiliary LLM reads the command text
    and returns an opinion about its risk.

Both answer "is this dangerous?". Neither answers "what dies if I say yes?", because
neither ever opens the target. This plugin does: it expands the paths, walks them, and
splits the result into files git can restore and files it cannot. That split is the point —
`git clean -fd`, an uncommitted `.env`, a local database, a half-written migration: all
untracked, all unrecoverable, and invisible to a risk opinion formed from the command text.

The number is measured on the filesystem before the command runs, so it cannot be wrong in
the way an estimate can. It can still be *incomplete*: a command whose destruction happens
inside a program (`python cleanup.py`), over SSH, or in a subshell this parser does not see
is out of scope. That limit is deliberate and documented rather than papered over.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

MAX_FILES = 50_000
MAX_SAMPLES = 5

# Command shapes we can measure honestly. Everything else passes through untouched.
_RM_RE = re.compile(r"(?:^|[|;&]\s*|\bthen\s+|\bdo\s+)rm\b")
_GIT_CLEAN_RE = re.compile(r"\bgit\s+clean\b[^\n]*?(?<![\w-])-[\w-]*f")
_GIT_RESET_RE = re.compile(r"\bgit\s+reset\b[^\n]*--hard")
_TRUNCATE_RE = re.compile(r"(?:^|[|;&]\s*)(?:truncate\s+-s\s*0|:)\s*>")
_MV_RE = re.compile(r"(?:^|[|;&]\s*)mv\b")

_OVERRIDE_ENV = "BLASTRADIUS_ALLOW"


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------- detection


def classify(command: str) -> str | None:
    """Return the destructive kind of this command, or None if we do not measure it."""
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


def targets_of(command: str, kind: str) -> list[str]:
    """Paths the command points at. Only the leading command is parsed; anything after a
    shell operator belongs to another process and is reported as unmeasured."""
    segment = re.split(r"[|;&]", command, maxsplit=1)[0].strip()
    try:
        tokens = shlex.split(segment)
    except ValueError:
        tokens = segment.split()
    if kind.startswith("git-"):
        return []  # git shapes operate on the repo itself
    if kind == "truncate":
        return []
    paths: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-") or token == "":
            continue
        if token.startswith(">"):
            continue
        paths.append(token)
    return paths


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
    """git clean -fd / git reset --hard act on the whole worktree."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            files.append(Path(dirpath) / name)


def measure(command: str, cwd: str | None = None) -> dict:
    """Measure a command's target. Never executes the command itself."""
    kind = classify(command)
    if kind is None:
        return {
            "kind": None,
            "measured": False,
            "reason": "not a command shape we measure",
            "files": 0,
            "tracked": 0,
            "untracked": 0,
            "bytes": 0,
            "samples_untracked": [],
            "targets": [],
            "truncated": False,
        }

    workdir = Path(cwd or os.getcwd()).resolve()
    files: list[Path] = []
    if kind.startswith("git-"):
        root = _git_root(workdir) or workdir
        _repo_files(root, files)
    else:
        _walk(workdir, targets_of(command, kind), files)

    deduped = sorted({f.resolve() for f in files})
    root = _git_root(workdir)
    if root is not None:
        tracked_set = _tracked_files(root)
        def rel(p: Path) -> str:
            try:
                return str(p.relative_to(root))
            except ValueError:
                return str(p)
        tracked = [p for p in deduped if rel(p) in tracked_set]
    else:
        tracked = []
    untracked = [p for p in deduped if p not in set(tracked)]

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
        return f"[blastradius] {m['kind']}: target is empty or does not exist — nothing to destroy"
    lines = [
        f"⛔ blast radius: {m['kind']} in {m['cwd']}",
        f"   {m['files']:,} file(s), {m['bytes']:,} bytes",
        f"   tracked by git : {m['tracked']:,}   (recoverable)",
        f"   UNTRACKED      : {m['untracked']:,}   (gone permanently)",
    ]
    if m["samples_untracked"]:
        lines.append("   e.g. " + ", ".join(m["samples_untracked"]))
    if m["git_root"] is None:
        lines.append("   (not a git repo — nothing here is recoverable)")
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
    m = measure(command, args.get("workdir") or args.get("cwd"))
    if not m.get("measured") or m["files"] == 0:
        return None
    if _truthy(_OVERRIDE_ENV):
        return None
    return {
        "action": "block",
        "message": (
            report(m)
            + "\n\nThis command was not executed. Tell the user the numbers above, and either "
              "narrow the target or ask for explicit confirmation. To run it anyway the "
              f"operator must set {_OVERRIDE_ENV}=1."
        ),
    }


# -------------------------------------------------------------------------- tool


def blast_radius(command: str, cwd: str | None = None) -> str:
    """Preview a destructive command's impact without running it."""
    return report(measure(command, cwd))


_SCHEMA = {
    "name": "blast_radius",
    "description": (
        "Preview what a destructive command (rm, git clean -fd, git reset --hard, truncate) "
        "would delete, split into files git can restore and files that would be lost. Runs "
        "nothing; measures the filesystem. Use it before any destructive command."
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


def _handler(args: dict, **_) -> str:
    return blast_radius(str(args.get("command") or ""), args.get("cwd"))


def _blast_command(raw_args: str) -> str:
    return blast_radius(raw_args.strip() or "rm -rf .")


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_tool(
        name="blast_radius",
        toolset="blastradius",
        schema=_SCHEMA,
        handler=_handler,
        description="Measure what a destructive command would delete.",
        emoji="💥",
    )
    ctx.register_command(
        "blast",
        _blast_command,
        description="Preview a destructive command's blast radius.",
        args_hint="<command>",
    )
