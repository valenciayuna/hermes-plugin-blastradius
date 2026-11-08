"""Blast Radius 2.0 — impact analysis, verified snapshots, real restore, risk policies.

Version 1 answered one question well: "what dies if I say yes?" It expanded the paths, walked
them, split the result into files git can restore and files it cannot, and blocked the call with
the numbers. That core is preserved here.

2.0 adds the part that was missing: a way back. Before a destructive command runs, the affected
files can be copied into a checksummed snapshot; after the damage, they can be restored and the
result verified. Around both sits a policy knob, because how much friction a team wants is a
choice, not a constant.

What this plugin still cannot do is stated in the report rather than hidden: damage that happens
inside a program (`python cleanup.py`), over SSH, or in a subshell this parser does not see is
outside the measurement. An unmeasured command is reported as unmeasured, never guessed.

Security posture, unchanged and extended:
  * the hook never approves anything on its own — it blocks, or it lets Hermes decide;
  * snapshots live outside the target tree, are created 0700/0600, and never follow symlinks;
  * a snapshot is only called verified after its checksums re-read clean;
  * a destructive command is not authorised when a mandatory snapshot fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_FILES = 50_000
MAX_SAMPLES = 5
MAX_VALUABLE = 8
ALLOW_TTL_S = 300
OVERRIDE_ENV = "BLASTRADIUS_ALLOW"
POLICY_ENV = "BLASTRADIUS_POLICY"
SNAPSHOT_DIR_ENV = "BLASTRADIUS_SNAPSHOT_DIR"
DEFAULT_POLICY = "balanced"
POLICIES = ("relaxed", "balanced", "strict")

# Command shapes we can measure honestly. Everything else passes through untouched.
_RM_RE = re.compile(r"(?:^|[|;&]\s*|\bthen\s+|\bdo\s+)rm\b")
_GIT_CLEAN_RE = re.compile(r"\bgit\s+clean\b[^\n]*?(?<![\w-])-[\w-]*f")
_GIT_RESET_RE = re.compile(r"\bgit\s+reset\b[^\n]*--hard")
_TRUNCATE_RE = re.compile(r"(?:^|[|;&]\s*)(?:truncate\s+-s\s*0|:)\s*>")
_MV_RE = re.compile(r"(?:^|[|;&]\s*)mv\b")
# Shapes whose real work happens somewhere the parser cannot see. Reporting these as
# measured would be a guess, and a guess is worse than an honest unknown.
_NESTED_RE = re.compile(
    r"\b(?:bash|sh|zsh|dash|ksh)\s+-c\b"   # code passed as a string
    r"|\bssh\b"                              # runs on another machine
    r"|\$\("                                 # command substitution builds the path
    r"|`"                                    # backtick substitution
    r"|(?:^|[|;&]\s*)\(\s*(?:rm|mv|git|truncate)\b"   # destructive command in a subshell
)

# File kinds that hurt to lose even when git never saw them.
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


def snapshot_root() -> Path:
    """Snapshots live outside the tree they protect, so a command cannot eat them."""
    override = os.environ.get(SNAPSHOT_DIR_ENV)
    root = Path(override) if override else data_dir() / "snapshots"
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _allow_file() -> Path:
    return data_dir() / "allow.json"


def _policy_file() -> Path:
    return data_dir() / "policy.json"


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


# ------------------------------------------------------------------------ policy


def get_policy() -> str:
    """relaxed | balanced | strict. Env wins, then the saved setting, then the default."""
    env = os.environ.get(POLICY_ENV, "").strip().lower()
    if env in POLICIES:
        return env
    path = _policy_file()
    if path.is_file():
        try:
            value = str(json.loads(path.read_text(encoding="utf-8")).get("policy", "")).lower()
            if value in POLICIES:
                return value
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_POLICY


def set_policy(policy: str) -> str:
    policy = (policy or "").strip().lower()
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {', '.join(POLICIES)}")
    try:
        _policy_file().write_text(json.dumps({"policy": policy}), encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"could not save policy: {exc}") from exc
    return policy


def _policy_blocks(analysis: dict) -> tuple[bool, str]:
    """(does this policy stop the command, one-line reason)."""
    policy = get_policy()
    untracked = analysis.get("untracked", 0)
    valuable = len(analysis.get("valuable", []))
    size = analysis.get("bytes", 0)

    if policy == "relaxed":
        if untracked >= 10 or valuable >= 3 or size >= 50 * 1024 * 1024:
            return True, "relaxed: high-impact change"
        return False, "relaxed: below the reporting threshold"
    if policy == "strict":
        return True, "strict: every measured destructive call needs a verified snapshot"
    return (untracked >= 1), "balanced: untracked data would not be recoverable from git"


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


_DESTRUCTIVE_WORD_RE = re.compile(
    r"\b(?:rm|rmdir|mv|truncate|shred)\b|\bgit\s+(?:clean|reset)\b|\bDROP\s+TABLE\b",
    re.IGNORECASE,
)


def looks_destructive(command: str) -> bool:
    """True when the text mentions a destructive verb, even if the target is unmeasurable."""
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


def _ignored_files(root: Path, relatives: list[str]) -> set[str]:
    """Ask git which of these paths match .gitignore. Best effort, never fatal."""
    if not relatives:
        return set()
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-z", "--stdin"],
            input="\0".join(relatives), capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if out.returncode not in (0, 1):
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


def is_valuable(path: Path) -> bool:
    name = path.name.lower()
    if name in _VALUABLE_EXACT or name.startswith(".env"):
        return True
    if any(name.endswith(suffix) for suffix in _VALUABLE_SUFFIX):
        return True
    return any(part.lower() in _VALUABLE_DIRS for part in path.parts[:-1])


def _empty(reason: str) -> dict:
    return {
        "kind": None, "measured": False, "reason": reason,
        "files": 0, "tracked": 0, "untracked": 0, "ignored": 0, "bytes": 0,
        "samples_untracked": [], "valuable": [], "targets": [], "truncated": False,
        "git_root": None, "cwd": str(Path.cwd()), "risk": "unknown",
        "recovery": {"git": False, "snapshot": False},
    }


def measure(command: str, cwd: str | None = None) -> dict:
    """Measure a command's target. Never executes the command itself."""
    if _NESTED_RE.search(command):
        return _empty(
            "runs inside a subshell, a -c string, or a remote session: the real target "
            "cannot be verified from here"
        )

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

    relatives = []
    for p in deduped:
        if root and _under(p, root):
            relatives.append(str(p.relative_to(root)))
    ignored_set = _ignored_files(root, relatives) if root else set()

    tracked: list[Path] = []
    untracked: list[Path] = []
    for p in deduped:
        rel = str(p.relative_to(root)) if root and _under(p, root) else None
        if rel is not None and rel in tracked_set:
            tracked.append(p)
        else:
            untracked.append(p)

    total_bytes = 0
    valuable: list[str] = []
    for path in deduped[:MAX_FILES]:
        try:
            total_bytes += path.lstat().st_size
        except OSError:
            pass
        if is_valuable(path) and len(valuable) < MAX_VALUABLE:
            valuable.append(rel_of(path, root))

    ignored_count = len([r for r in relatives if r in ignored_set])

    untracked_n = len(untracked)
    if not untracked_n and total_bytes < 1024 * 1024:
        risk = "low"
    elif valuable or untracked_n > 200 or total_bytes > 100 * 1024 * 1024:
        risk = "high"
    elif untracked_n:
        risk = "medium"
    else:
        risk = "low"
    if valuable and untracked_n > 200:
        risk = "critical"

    return {
        "kind": kind,
        "measured": True,
        "cwd": str(workdir),
        "git_root": str(root) if root else None,
        "targets": targets_of(command, kind),
        "files": len(deduped),
        "tracked": len(tracked),
        "untracked": len(untracked),
        "ignored": ignored_count,
        "bytes": total_bytes,
        "samples_untracked": [rel_of(p, root) for p in untracked[:MAX_SAMPLES]],
        "valuable": valuable,
        "truncated": len(files) >= MAX_FILES,
        "risk": risk,
        "recovery": {"git": bool(tracked), "snapshot": False},
        "_paths": [str(p) for p in deduped],
        "_root": str(root) if root else None,
    }


def rel_of(path: Path, root: Path | None) -> str:
    if root is not None and _under(path, root):
        return str(path.relative_to(root))
    return str(path)


def public(analysis: dict) -> dict:
    """The part of an analysis that is safe to hand to a caller or store in a manifest."""
    return {k: v for k, v in analysis.items() if not k.startswith("_")}


# ------------------------------------------------------------------- snapshots


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(block)
    return digest.hexdigest()


def _free_bytes(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0


def create_snapshot(analysis: dict, command: str) -> dict:
    """Copy the affected regular files into a checksummed snapshot.

    Symlinks are recorded but not followed: a link pointing outside the target would otherwise
    pull unrelated data into the backup. The snapshot is only reported verified when every copy
    re-reads to the checksum taken from the original.
    """
    paths = [Path(p) for p in analysis.get("_paths", [])]
    root = Path(analysis["_root"]) if analysis.get("_root") else None
    if not paths:
        return {"ok": False, "error": "nothing to snapshot", "verified": False}

    regular = [p for p in paths if p.is_file() and not p.is_symlink()]
    links = [p for p in paths if p.is_symlink()]
    needed = 0
    for p in regular:
        try:
            needed += p.lstat().st_size
        except OSError:
            pass

    snap_root = snapshot_root()
    if _free_bytes(snap_root) < needed * 1.2 + (8 * 1024 * 1024):
        return {"ok": False, "error": "not enough free space for a snapshot", "verified": False}

    snap_id = f"blast-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
    snap_dir = snap_root / snap_id
    files_dir = snap_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=False)
    try:
        os.chmod(snap_dir, 0o700)
        os.chmod(files_dir, 0o700)
    except OSError:
        pass

    entries: list[dict] = []
    copied = 0
    for src in regular:
        rel = rel_of(src, root)
        # keep the mirror inside the snapshot directory even for absolute paths
        safe_rel = rel.lstrip("/").replace("..", "__")
        dest = files_dir / safe_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dest)
            os.chmod(dest, 0o600)
            original_hash = _sha256(src)
            copy_hash = _sha256(dest)
            entries.append({
                "path": rel, "stored": str(dest.relative_to(snap_dir)),
                "bytes": dest.stat().st_size, "sha256": original_hash,
                "verified": original_hash == copy_hash,
                "mode": oct(src.stat().st_mode & 0o777),
            })
            copied += 1
        except OSError as exc:
            entries.append({"path": rel, "error": str(exc), "verified": False})

    for link in links:
        entries.append({"path": rel_of(link, root), "type": "symlink",
                        "target": os.readlink(link), "verified": False, "skipped": True})

    manifest = {
        "id": snap_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": command,
        "cwd": analysis.get("cwd"),
        "git_root": analysis.get("git_root"),
        "analysis": public(analysis),
        "files": entries,
        "count": copied,
        "bytes": sum(e.get("bytes", 0) for e in entries),
        "verified": all(e.get("verified") for e in entries if e.get("error") is None
                        and not e.get("skipped")) and bool(entries),
    }
    manifest_path = snap_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        os.chmod(manifest_path, 0o600)
    except OSError:
        pass

    if not manifest["verified"]:
        manifest["warning"] = "one or more files failed the checksum comparison"
    return {
        "ok": True, "id": snap_id, "dir": str(snap_dir), "count": copied,
        "bytes": manifest["bytes"], "verified": manifest["verified"],
        "skipped_links": len(links),
    }


def list_snapshots(limit: int = 20) -> list[dict]:
    root = snapshot_root()
    rows: list[dict] = []
    for entry in sorted(root.iterdir(), reverse=True):
        manifest = entry / "manifest.json"
        if not manifest.is_file():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        rows.append({
            "id": data.get("id", entry.name), "created": data.get("created"),
            "command": data.get("command"), "count": data.get("count", 0),
            "bytes": data.get("bytes", 0), "verified": data.get("verified", False),
        })
        if len(rows) >= limit:
            break
    return rows


def _find_snapshot(snap_id: str) -> Path | None:
    root = snapshot_root()
    if snap_id in {"last", "latest", ""}:
        for entry in sorted(root.iterdir(), reverse=True):
            if (entry / "manifest.json").is_file():
                return entry
        return None
    candidate = root / snap_id
    if (candidate / "manifest.json").is_file():
        return candidate
    for entry in sorted(root.iterdir(), reverse=True):
        if entry.name.startswith(snap_id) and (entry / "manifest.json").is_file():
            return entry
    return None


def verify_snapshot(snap_id: str) -> dict:
    """Re-read every stored file and compare it with the manifest checksum."""
    snap_dir = _find_snapshot(snap_id)
    if snap_dir is None:
        return {"ok": False, "error": f"snapshot not found: {snap_id}"}
    try:
        manifest = json.loads((snap_dir / "manifest.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "error": f"manifest unreadable: {exc}"}

    bad: list[str] = []
    checked = 0
    for entry in manifest.get("files", []):
        if entry.get("skipped") or entry.get("error"):
            continue
        stored = snap_dir / entry.get("stored", "")
        if not stored.is_file():
            bad.append(f"{entry.get('path')} (missing)")
            continue
        checked += 1
        if _sha256(stored) != entry.get("sha256"):
            bad.append(f"{entry.get('path')} (checksum mismatch)")
    return {
        "ok": not bad, "id": manifest.get("id"), "checked": checked,
        "bad": bad[:10], "count": manifest.get("count", 0),
    }


def restore_snapshot(snap_id: str = "last", confirm: bool = False) -> dict:
    """Plan or apply a restore. Refuses to overwrite newer files without confirmation."""
    snap_dir = _find_snapshot(snap_id)
    if snap_dir is None:
        return {"ok": False, "error": f"snapshot not found: {snap_id}"}
    try:
        manifest = json.loads((snap_dir / "manifest.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "error": f"manifest unreadable: {exc}"}

    base = Path(manifest.get("git_root") or manifest.get("cwd") or ".").resolve()
    healthy = verify_snapshot(snap_dir.name)
    if not healthy.get("ok"):
        return {"ok": False, "error": "snapshot failed verification, refusing to restore",
                "detail": healthy.get("bad", [])}

    targets: list[dict] = []
    conflicts: list[dict] = []
    for entry in manifest.get("files", []):
        if entry.get("skipped") or entry.get("error"):
            continue
        dest = base / entry["path"]
        stored = snap_dir / entry["stored"]
        state = {"path": entry["path"], "dest": str(dest), "stored": str(stored)}
        if dest.exists() and dest.is_file():
            current_hash = _sha256(dest)
            if current_hash != entry.get("sha256"):
                state["conflict"] = "exists and differs from the snapshot"
                conflicts.append(state)
            else:
                state["status"] = "already identical"
                targets.append(state)
                continue
        else:
            state["status"] = "missing on disk, will be recreated"
        targets.append(state)

    if not confirm:
        return {"ok": True, "planned": True, "id": manifest.get("id"), "base": str(base),
                "targets": len(targets), "conflicts": len(conflicts),
                "conflict_paths": [c["path"] for c in conflicts][:10]}

    if conflicts and not confirm:
        return {"ok": False, "error": "conflicts need confirmation"}

    restored, failed = 0, []
    for state in targets:
        dest = Path(state["dest"])
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(state["stored"], dest)
            restored += 1
        except OSError as exc:
            failed.append(f"{state['path']}: {exc}")

    # verify what actually landed
    verified = 0
    for state in targets:
        dest = Path(state["dest"])
        entry = next((e for e in manifest["files"] if e.get("path") == state["path"]), None)
        if entry and dest.is_file() and _sha256(dest) == entry.get("sha256"):
            verified += 1

    log_dir = data_dir()
    try:
        with (log_dir / "recovery.log").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "snapshot": manifest.get("id"), "restored": restored,
                "verified": verified, "failed": len(failed),
            }) + "\n")
    except OSError:
        pass

    return {"ok": verified == restored and not failed, "id": manifest.get("id"),
            "restored": restored, "verified": verified, "failed": failed[:10]}


# ----------------------------------------------------------------------- report


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n/1:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def report(m: dict, command: str | None = None) -> str:
    if not m.get("measured"):
        return (f"[blastradius] not measured: {m.get('reason')}\n"
                "   This shape is outside what the parser can verify, so no number is invented. "
                "Treat the impact as unknown.")

    if m["files"] == 0:
        return f"[blastradius] {m['kind']}: target is empty or does not exist, nothing to destroy"

    lines = ["BLASTRADIUS // IMPACT REPORT", ""]
    if command:
        lines += [f'Command: "{command}"', ""]
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
    if m["truncated"]:
        lines += ["", f"Analysis incomplete: stopped counting at {MAX_FILES:,} files."]
    if m["git_root"] is None:
        lines += ["", "Not a git repository: no file in this target has a git recovery source."]
    return "\n".join(lines)


# --------------------------------------------------------------------------- hook


def on_pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """Block a destructive terminal call until its impact is on the record."""
    if tool_name != "terminal" or not isinstance(args, dict):
        return None
    command = args.get("command") or args.get("cmd")
    if not isinstance(command, str):
        return None
    if _truthy(OVERRIDE_ENV):
        return None

    policy = get_policy()
    m = measure(command, args.get("workdir") or args.get("cwd"))

    if not m.get("measured"):
        if policy == "strict" and looks_destructive(command):
            return {
                "action": "block",
                "message": (
                    "[blastradius] strict policy: this command matches a destructive shape but "
                    "its target cannot be measured, so its impact is unknown.\n"
                    "   Narrow it to a path the parser can verify, or run it deliberately "
                    f"with {OVERRIDE_ENV}=1."
                ),
            }
        return None

    if m["files"] == 0:
        return None

    if consume_allow(command.strip()):
        return None

    blocked, reason = _policy_blocks(m)
    if not blocked:
        return None

    text = report(m, command.strip())
    if policy == "strict":
        text += ("\n\nStrict policy: create a verified snapshot first, then re-authorise.\n"
                 '  blast_restore can bring these files back afterwards: "/blast snapshots" lists them.')
    text += (
        "\n\nThis command was not executed. Show the user these numbers, then either "
        "narrow the target, or confirm and call "
        f'blast_allow("{command.strip()}") to permit this exact command once '
        f"(valid {ALLOW_TTL_S // 60} minutes), or set {OVERRIDE_ENV}=1 for a session-wide override."
    )
    return {"action": "block", "message": text}


# -------------------------------------------------------------------------- tools


def blast_radius(command: str, cwd: str | None = None) -> str:
    """Preview a destructive command's impact without running it."""
    return report(measure(command, cwd), command)


def blast_allow(command: str, ttl_s: int = ALLOW_TTL_S) -> str:
    """Permit one future execution of exactly this command.

    Under the strict policy a verified snapshot is required first: if it cannot be created, the
    grant is withheld, because authorising without protection is the thing strict exists to stop.
    """
    if not isinstance(command, str) or not command.strip():
        return "[blastradius] need the exact command string to allow"
    command = command.strip()
    ttl = max(1, min(int(ttl_s or ALLOW_TTL_S), 3600))

    note = ""
    if get_policy() == "strict":
        m = measure(command)
        if not m.get("measured") or m["files"] == 0:
            return ("[blastradius] strict policy: cannot measure this command, so no grant was "
                    "issued. Narrow the target first.")
        snap = create_snapshot(m, command)
        if not snap.get("ok") or not snap.get("verified"):
            return (f"[blastradius] strict policy: snapshot failed ({snap.get('error', 'unverified')}). "
                    "No grant issued; the command stays blocked.")
        note = f"\nsnapshot {snap['id']} verified ({snap['count']} files, {human_bytes(snap['bytes'])})"

    info = grant_allow(command, ttl)
    return (
        f"[blastradius] allowed once: {info['command']}\n"
        f"valid for {info['ttl_s'] // 60} minute(s). It is spent on the next matching call, "
        f"then the gate closes again.{note}"
    )


def blast_snapshot(command: str, cwd: str | None = None) -> str:
    """Back up everything a command would destroy, and prove the copy is intact."""
    m = measure(command, cwd)
    if not m.get("measured"):
        return f"[blastradius] cannot snapshot: {m.get('reason')}"
    if m["files"] == 0:
        return "[blastradius] nothing to snapshot, the target is empty"
    snap = create_snapshot(m, command)
    if not snap.get("ok"):
        return f"[blastradius] snapshot FAILED: {snap.get('error')}. Do not run the command."
    status = "verified" if snap["verified"] else "FAILED verification"
    return (
        f"[blastradius] snapshot {snap['id']} {status}\n"
        f"  files: {snap['count']}  size: {human_bytes(snap['bytes'])}\n"
        f"  links skipped: {snap['skipped_links']}\n"
        f'  restore with: /blast restore {snap["id"]}'
    )


def blast_snapshots() -> str:
    rows = list_snapshots()
    if not rows:
        return "[blastradius] no snapshots yet"
    lines = ["BLASTRADIUS // SNAPSHOTS", ""]
    for row in rows:
        mark = "ok" if row["verified"] else "UNVERIFIED"
        lines.append(f"  {row['id']}  {row['count']} files  {human_bytes(row['bytes'])}  {mark}")
        if row.get("command"):
            lines.append(f'      from: {row["command"][:90]}')
    return "\n".join(lines)


def blast_restore(snap_id: str = "last", confirm: bool = False) -> str:
    """Restore files from a snapshot, after showing what would change."""
    result = restore_snapshot(snap_id, confirm=confirm)
    if not result.get("ok") and result.get("error"):
        return f"[blastradius] restore failed: {result['error']}"
    if result.get("planned"):
        lines = ["BLASTRADIUS // RECOVERY", "",
                 f"Snapshot: {result['id']}",
                 f"Files to restore: {result['targets']}",
                 f"Conflicts: {result['conflicts']}"]
        if result["conflict_paths"]:
            lines += ["", "These exist now and differ from the snapshot:"]
            lines += [f'  "{p}"' for p in result["conflict_paths"]]
        lines += ["", "Nothing has been written yet. Re-run with confirm to apply."]
        return "\n".join(lines)
    lines = ["BLASTRADIUS // RECOVERY", "",
             f"Snapshot: {result['id']}",
             f"Files restored: {result['restored']}",
             f"Checksums verified: {result['verified']}"]
    if result.get("failed"):
        lines += ["", "Failed:"] + [f"  {f}" for f in result["failed"]]
    lines += ["", "Recovery is limited to what the snapshot holds: files created after it are "
                  "untouched, and database or external-service state is not covered."]
    return "\n".join(lines)


def blast_policy(new_policy: str = "") -> str:
    if new_policy:
        try:
            set_policy(new_policy)
        except (ValueError, RuntimeError) as exc:
            return f"[blastradius] {exc}"
    current = get_policy()
    detail = {
        "relaxed": "report the impact, block only high-impact changes",
        "balanced": "block when untracked data would be unrecoverable from git",
        "strict": "block every measured destructive call until a verified snapshot exists",
    }[current]
    return f"[blastradius] policy: {current} — {detail}"


# ----------------------------------------------------------------- registration

_RADIUS_SCHEMA = {
    "name": "blast_radius",
    "description": (
        "Preview what a destructive command (rm, git clean -fd, git reset --hard, truncate, "
        "mv onto an existing path) would delete, split into files git can restore and files "
        "that would not be recoverable from git. Flags valuable files (.env, databases, "
        "migrations) and a risk level. Runs nothing; measures the filesystem."
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
        "has seen its blast radius and said yes. The grant is spent on the next matching call. "
        "Under the strict policy this creates and verifies a snapshot first."
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

_SNAPSHOT_SCHEMA = {
    "name": "blast_snapshot",
    "description": (
        "Copy every file a destructive command would destroy into a checksummed snapshot "
        "outside the target tree, then verify the copies. Use before approving data loss."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The destructive command to protect against."},
            "cwd": {"type": "string", "description": "Directory it would run in (default: cwd)."},
        },
        "required": ["command"],
    },
}

_RESTORE_SCHEMA = {
    "name": "blast_restore",
    "description": (
        "Restore files from a snapshot. Without confirm it only reports what would change; "
        "with confirm it writes the files and verifies their checksums afterwards."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string", "description": "Snapshot id, prefix, or 'last'."},
            "confirm": {"type": "boolean", "description": "Actually write the files."},
        },
        "required": [],
    },
}

_SNAPSHOTS_SCHEMA = {
    "name": "blast_snapshots",
    "description": "List recovery snapshots with their size and verification status.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

_POLICY_SCHEMA = {
    "name": "blast_policy",
    "description": "Read or set the risk policy: relaxed, balanced, or strict.",
    "parameters": {
        "type": "object",
        "properties": {"policy": {"type": "string", "description": "New policy (omit to read)."}},
        "required": [],
    },
}


def _radius_handler(args: dict, **_) -> str:
    return blast_radius(str(args.get("command") or ""), args.get("cwd"))


def _allow_handler(args: dict, **_) -> str:
    return blast_allow(str(args.get("command") or ""), int(args.get("ttl_s") or ALLOW_TTL_S))


def _snapshot_handler(args: dict, **_) -> str:
    return blast_snapshot(str(args.get("command") or ""), args.get("cwd"))


def _restore_handler(args: dict, **_) -> str:
    return blast_restore(str(args.get("snapshot_id") or "last"), bool(args.get("confirm")))


def _snapshots_handler(args: dict, **_) -> str:
    return blast_snapshots()


def _policy_handler(args: dict, **_) -> str:
    return blast_policy(str(args.get("policy") or ""))


def _blast_command(raw_args: str) -> str:
    text = (raw_args or "").strip()
    if not text:
        return blast_radius("rm -rf .")
    if text.startswith("restore"):
        parts = text.split()
        snap_id = parts[1] if len(parts) > 1 else "last"
        confirm = "--confirm" in parts or "confirm" in parts
        return blast_restore(snap_id, confirm)
    if text.startswith("snapshots"):
        return blast_snapshots()
    if text.startswith("snapshot"):
        return blast_snapshot(text[len("snapshot"):].strip() or "rm -rf .")
    if text.startswith("policy"):
        return blast_policy(text[len("policy"):].strip())
    return blast_radius(text)


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

    for schema, handler, description, emoji in (
        (_RADIUS_SCHEMA, _radius_handler, "Measure what a destructive command would delete.", "💥"),
        (_ALLOW_SCHEMA, _allow_handler, "Allow one confirmed destructive command exactly once.", "🔓"),
        (_SNAPSHOT_SCHEMA, _snapshot_handler, "Back up a command's targets before it runs.", "🧷"),
        (_RESTORE_SCHEMA, _restore_handler, "Restore files from a verified snapshot.", "♻️"),
        (_SNAPSHOTS_SCHEMA, _snapshots_handler, "List recovery snapshots.", "🗂️"),
        (_POLICY_SCHEMA, _policy_handler, "Read or set the risk policy.", "⚖️"),
    ):
        ctx.register_tool(
            name=schema["name"], toolset="blastradius", schema=schema,
            handler=handler, description=description, emoji=emoji,
        )

    ctx.register_command(
        "blast",
        _blast_command,
        description="Preview impact, or manage snapshots, restore, and policy.",
        args_hint="<command> | snapshots | snapshot <cmd> | restore [id] [confirm] | policy [name]",
    )
