"""Recursive command parsing and impact measurement.

Version 1 measured one flat command. That left the biggest hole: `bash -c "cd build && rm -rf ."`
looked like a harmless `bash` call, and a chain only ever had its first segment read. This module
splits a command the way a shell would (quotes, `&&`, `||`, `;`, `|`, newlines), unwraps `-c`
strings and subshells, follows `cd` inside the chain, and unions everything it can see.

What it still cannot see is reported, never guessed: command substitution, unresolved variables,
`ssh`, `eval`/`source`, and dynamic `xargs`. A segment that looks destructive and cannot be
resolved marks the whole result as partial, so the user is told which part is invisible instead
of being told "safe".
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .paths import human_bytes

MAX_FILES = 50_000
MAX_SAMPLES = 5
MAX_VALUABLE = 8
MAX_DEPTH = 3

_RM_RE = re.compile(r"(?:^|[|;&]\s*|\bthen\s+|\bdo\s+)rm\b")
_GIT_CLEAN_RE = re.compile(r"\bgit\s+clean\b[^\n]*?(?<![\w-])-[\w-]*f")
_GIT_RESET_RE = re.compile(r"\bgit\s+reset\b[^\n]*--hard")
_TRUNCATE_RE = re.compile(r"(?:^|[|;&]\s*)(?:truncate\s+-s\s*0|:)\s*>")
_MV_RE = re.compile(r"(?:^|[|;&]\s*)mv\b")

_DESTRUCTIVE_WORD_RE = re.compile(
    r"\b(?:rm|rmdir|mv|truncate|shred)\b|\bgit\s+(?:clean|reset)\b|\bDROP\s+TABLE\b",
    re.IGNORECASE,
)

# A shell wrapper whose body is itself a command line: bash -c "...", sh -lc '...'
_WRAPPER_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:env\s+)?(?:bash|sh|zsh|dash|ksh)\s+(?:-[a-zA-Z]*c[a-zA-Z]*)\s+(?P<q>['\"])(?P<inner>.*)(?P=q)\s*$",
    re.DOTALL,
)
_SUBSHELL_RE = re.compile(r"^\s*\((?P<inner>.*)\)\s*$", re.DOTALL)
_BRACE_RE = re.compile(r"^\s*\{(?P<inner>.*)\}\s*$", re.DOTALL)
_CD_RE = re.compile(r"^\s*cd\s+(?P<path>[^;&|]+?)\s*$")

# Constructs whose value only exists at runtime.
_UNRESOLVABLE_RE = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_][A-Za-z0-9_]*")
_OPAQUE_RE = re.compile(r"^\s*(?:eval|source|\.)\b|\bxargs\b|\bssh\b")

_VALUABLE_EXACT = {
    ".env", ".env.local", ".env.production", ".env.development", ".envrc",
    "id_rsa", "id_ed25519", "id_dsa", ".pgpass", ".netrc", ".npmrc", ".pypirc",
    "docker-compose.override.yml",
}
_VALUABLE_SUFFIX = (
    ".db", ".sqlite", ".sqlite3", ".sql", ".dump", ".bak", ".backup",
    ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks",
    ".parquet", ".pkl", ".h5", ".ckpt", ".onnx",
)
_VALUABLE_DIRS = ("migrations", "migration", "seeds", "fixtures")


# ------------------------------------------------------------------ shell parsing


def split_top_level(command: str) -> list[str]:
    """Split on && || ; | and newlines, ignoring separators inside quotes or nesting."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    depth = 0
    i = 0
    while i < len(command):
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(command):
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == "{":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch in ")}":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
            continue
        if depth == 0:
            pair = command[i:i + 2]
            if pair in ("&&", "||"):
                segments.append("".join(buf))
                buf = []
                i += 2
                continue
            if ch in ";|\n":
                segments.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [s.strip() for s in segments if s.strip()]


@dataclass
class Task:
    segment: str
    cwd: Path


def _resolve(cwd: Path, target: str) -> Path:
    candidate = Path(target).expanduser()
    return candidate if candidate.is_absolute() else (cwd / candidate)


def expand(command: str, cwd: Path, depth: int = 0) -> tuple[list[Task], list[str]]:
    """Walk the command tree. Returns (measurable tasks, unmeasured segments)."""
    tasks: list[Task] = []
    unmeasured: list[str] = []
    current = cwd

    for segment in split_top_level(command):
        if depth > MAX_DEPTH:
            unmeasured.append(f"{segment}  (deeper than {MAX_DEPTH} wrappers)")
            continue

        wrapper = _WRAPPER_RE.match(segment)
        if wrapper:
            inner_tasks, inner_unmeasured = expand(wrapper.group("inner"), current, depth + 1)
            tasks.extend(inner_tasks)
            unmeasured.extend(inner_unmeasured)
            continue

        shell = _SUBSHELL_RE.match(segment) or _BRACE_RE.match(segment)
        if shell:
            inner_tasks, inner_unmeasured = expand(shell.group("inner"), current, depth + 1)
            tasks.extend(inner_tasks)
            unmeasured.extend(inner_unmeasured)
            continue

        change_dir = _CD_RE.match(segment)
        if change_dir:
            target = _resolve(current, change_dir.group("path").strip().strip("'\""))
            if target.is_dir():
                current = target
            else:
                unmeasured.append(f"{segment}  (directory does not exist, later paths unknown)")
            continue

        if _UNRESOLVABLE_RE.search(segment) and _DESTRUCTIVE_WORD_RE.search(segment):
            unmeasured.append(f"{segment}  (value only known at runtime)")
            continue
        if _OPAQUE_RE.search(segment) and _DESTRUCTIVE_WORD_RE.search(segment):
            unmeasured.append(f"{segment}  (runs somewhere the parser cannot follow)")
            continue

        tasks.append(Task(segment, current))

    return tasks, unmeasured


# ---------------------------------------------------------------------- detection


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


def looks_destructive(command: str) -> bool:
    return bool(command and _DESTRUCTIVE_WORD_RE.search(command))


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
    tokens = _leading_tokens(command)[1:]
    positional = [t for t in tokens if not t.startswith("-")]
    return positional[-1] if len(positional) >= 2 else None


def mv_overwrites(command: str, workdir: Path) -> tuple[bool, Path | None]:
    dest = mv_destination(command)
    if dest is None:
        return False, None
    dest_path = _resolve(workdir, dest)
    if not dest_path.exists():
        return False, None
    replace_dir = any(t in {"-T", "--no-target-directory"} for t in _leading_tokens(command)[1:])
    if dest_path.is_dir() and not replace_dir:
        return False, None
    return True, dest_path


# ----------------------------------------------------------------------- git facts


_git_root_cache: dict[str, Path | None] = {}


def git_root_of(start: Path) -> Path | None:
    key = str(start)
    if key in _git_root_cache:
        return _git_root_cache[key]
    directory = start if start.is_dir() else start.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=15,
        )
        root = Path(out.stdout.strip()) if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        root = None
    _git_root_cache[key] = root
    return root


def _tracked_files(root: Path) -> set[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if out.returncode != 0:
        return set()
    return {p for p in out.stdout.split("\0") if p}


def _ignored_files(root: Path, relatives: list[str]) -> set[str]:
    if not relatives:
        return set()
    try:
        out = subprocess.run(["git", "-C", str(root), "check-ignore", "-z", "--stdin"],
                             input="\0".join(relatives), capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if out.returncode not in (0, 1):
        return set()
    return {p for p in out.stdout.split("\0") if p}


def is_valuable(path: Path) -> bool:
    name = path.name.lower()
    if name in _VALUABLE_EXACT or name.startswith(".env"):
        return True
    if any(name.endswith(suffix) for suffix in _VALUABLE_SUFFIX):
        return True
    return any(part.lower() in _VALUABLE_DIRS for part in path.parts[:-1])


# --------------------------------------------------------------------- collecting


def _walk(target: Path, files: list[Path], limit: int = MAX_FILES) -> None:
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
        pass


def _repo_files(root: Path, files: list[Path]) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            files.append(Path(dirpath) / name)
            if len(files) >= MAX_FILES:
                return


def _files_for_task(task: Task) -> list[Path]:
    kind = classify(task.segment)
    if kind is None:
        return []
    files: list[Path] = []
    if kind.startswith("git-"):
        _repo_files(git_root_of(task.cwd) or task.cwd, files)
    elif kind == "mv":
        overwrites, dest = mv_overwrites(task.segment, task.cwd)
        if overwrites and dest is not None:
            _walk(dest, files)
    else:
        for raw in targets_of(task.segment, kind):
            _walk(_resolve(task.cwd, raw), files)
    return files


def _empty(reason: str) -> dict:
    return {
        "kind": None, "measured": False, "reason": reason, "partial": False,
        "segments": 0, "unmeasured_segments": [], "files": 0, "tracked": 0,
        "untracked": 0, "ignored": 0, "bytes": 0, "samples_untracked": [],
        "valuable": [], "targets": [], "truncated": False, "git_root": None,
        "cwd": str(Path.cwd()), "risk": "unknown",
        "recovery": {"git": False, "snapshot": False}, "_paths": [], "_root": None,
    }


def measure(command: str, cwd: str | None = None) -> dict:
    """Measure a command's real target, following wrappers, chains and `cd`."""
    if not isinstance(command, str) or not command.strip():
        return _empty("no command to measure")

    workdir = Path(cwd or os.getcwd()).resolve()
    tasks, unmeasured = expand(command, workdir)

    if not tasks:
        if unmeasured:
            return _empty("every segment is unmeasurable: " + "; ".join(unmeasured[:2]))
        return _empty("not a command shape we measure")

    files: list[Path] = []
    kinds: list[str] = []
    for task in tasks:
        kind = classify(task.segment)
        if kind is None:
            continue
        kinds.append(kind)
        files.extend(_files_for_task(task))

    if not kinds:
        if unmeasured:
            return _empty("every segment is unmeasurable: " + "; ".join(unmeasured[:2]))
        return _empty("not a command shape we measure")

    deduped = sorted({p.resolve() for p in files})
    roots = {str(r) for r in (git_root_of(workdir),) if r}
    root = Path(next(iter(roots))) if roots else None
    tracked_set = _tracked_files(root) if root else set()

    relatives: list[str] = []
    for path in deduped:
        file_root = git_root_of(path.parent)
        if file_root is not None:
            try:
                relatives.append(str(path.relative_to(file_root)))
            except ValueError:
                pass
    ignored_set = _ignored_files(root, relatives) if root else set()

    tracked = untracked = 0
    total_bytes = 0
    valuable: list[str] = []
    sample_untracked: list[str] = []
    ignored_count = 0

    for path in deduped:
        file_root = git_root_of(path.parent)
        rel = None
        if file_root is not None:
            try:
                rel = str(path.relative_to(file_root))
            except ValueError:
                rel = None
        is_tracked = bool(rel and file_root == root and rel in tracked_set)
        if is_tracked:
            tracked += 1
        else:
            untracked += 1
            if len(sample_untracked) < MAX_SAMPLES:
                sample_untracked.append(str(path.relative_to(root)) if root and rel else str(path))
        if rel and rel in ignored_set:
            ignored_count += 1
        try:
            total_bytes += path.lstat().st_size
        except OSError:
            pass
        if len(valuable) < MAX_VALUABLE and is_valuable(path):
            valuable.append(str(path.relative_to(root)) if root and rel else str(path))

    if not untracked and total_bytes < 1024 * 1024:
        risk = "low"
    elif valuable or untracked > 200 or total_bytes > 100 * 1024 * 1024:
        risk = "high"
    elif untracked:
        risk = "medium"
    else:
        risk = "low"
    if valuable and untracked > 200:
        risk = "critical"

    return {
        "kind": kinds[0] if len(set(kinds)) == 1 else "composite",
        "measured": True,
        "partial": bool(unmeasured),
        "segments": len([t for t in tasks if classify(t.segment)]),
        "unmeasured_segments": unmeasured[:6],
        "cwd": str(workdir),
        "git_root": str(root) if root else None,
        "targets": [t.segment for t in tasks],
        "files": len(deduped),
        "tracked": tracked,
        "untracked": untracked,
        "ignored": ignored_count,
        "bytes": total_bytes,
        "samples_untracked": sample_untracked,
        "valuable": valuable,
        "truncated": len(files) >= MAX_FILES,
        "risk": risk,
        "recovery": {"git": tracked > 0, "snapshot": False},
        "_paths": [str(p) for p in deduped],
        "_root": str(root) if root else str(workdir),
    }


def public(analysis: dict) -> dict:
    return {k: v for k, v in analysis.items() if not k.startswith("_")}


def report(m: dict, command: str | None = None) -> str:
    if not m.get("measured"):
        return (f"[blastradius] not measured: {m.get('reason')}\n"
                "   No number is invented for a command the parser cannot follow.")
    if m["files"] == 0:
        return f"[blastradius] {m['kind']}: target is empty or does not exist, nothing to destroy"

    lines = ["BLASTRADIUS // IMPACT REPORT", ""]
    if command:
        lines += [f'Command: "{command}"', ""]
    if m.get("segments", 1) > 1:
        lines += [f"Segments measured: {m['segments']}", ""]

    lines += [
        "Impact:",
        f"  {m['files']:,} file(s) affected",
        f"  {m['tracked']:,} tracked by git",
        f"  {m['untracked']:,} untracked" + (f" ({m['ignored']:,} ignored)" if m.get("ignored") else ""),
        f"  {human_bytes(m['bytes'])} affected",
    ]
    if m.get("valuable"):
        lines += ["", "Potentially valuable data:"]
        lines += [f'  "{p}"' for p in m["valuable"]]
    lines += ["", "Recovery:"]
    lines.append("  Git-tracked files may be recoverable from the repository."
                 if m["tracked"] else "  No git-tracked files here.")
    lines.append("  Untracked files are not recoverable from Git." if m["untracked"]
                 else "  Nothing untracked in the target.")
    lines += ["", f"Risk level: {str(m.get('risk', 'unknown')).upper()}"]

    if m.get("partial"):
        lines += ["", "Partial measurement — these parts could not be seen:"]
        lines += [f"  {s}" for s in m["unmeasured_segments"]]
        lines += ["  The real impact may be larger than the numbers above."]
    if m["truncated"]:
        lines += ["", f"Analysis incomplete: stopped counting at {MAX_FILES:,} files."]
    if m["git_root"] is None:
        lines += ["", "Not a git repository: no file in this target has a git recovery source."]
    return "\n".join(lines)
