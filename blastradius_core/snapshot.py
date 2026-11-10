"""Snapshot storage: create, verify, list, pin, and keep the disk cost bounded.

The on-disk format is unchanged from 2.0 so old snapshots still restore: `manifest.json` with
`files[]` entries carrying `path`, `stored`, `sha256`, `bytes` and `verified`. New information is
added as optional fields (`pinned`, `excluded`, `last_used`), which older readers ignore.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .paths import (DEFAULT_EXCLUDES, Retention, data_dir, free_bytes, human_bytes,
                    is_excluded, snapshot_root)

# Files a snapshot keeps even when the directory name looks like build output.
_NEVER_EXCLUDE = {".env", ".env.local", "docker-compose.yml"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load(snap_dir: Path) -> dict | None:
    try:
        return json.loads((snap_dir / "manifest.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _save(snap_dir: Path, manifest: dict) -> None:
    path = snap_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _log(entry: dict) -> None:
    try:
        with (data_dir() / "recovery.log").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"at": _now(), **entry}) + "\n")
    except OSError:
        pass


def exists(snap_dir) -> bool:
    return isinstance(snap_dir, Path) and (snap_dir / "manifest.json").is_file()


# ------------------------------------------------------------------ retention


def _snapshots() -> list[tuple[Path, dict]]:
    root = snapshot_root()
    rows: list[tuple[Path, dict]] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        manifest = _load(entry)
        if manifest is not None:
            rows.append((entry, manifest))
    rows.sort(key=lambda r: r[1].get("created", ""))
    return rows


def _age_days(manifest: dict) -> float:
    try:
        created = datetime.fromisoformat(manifest.get("created", ""))
    except ValueError:
        return 0.0
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).total_seconds() / 86400


def _recently_used(manifest: dict, hours: int = 24) -> bool:
    raw = manifest.get("last_used")
    if not raw:
        return False
    try:
        used = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if used.tzinfo is None:
        used = used.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - used < timedelta(hours=hours)


def prune(plan: bool = True, retention: Retention | None = None) -> dict:
    """Delete the oldest unpinned snapshots until age, count and size limits hold."""
    limits = retention or Retention.load()
    rows = [r for r in _snapshots()]
    total_mb = sum(m.get("bytes", 0) for _, m in rows) / (1024 * 1024)
    doomed: list[tuple[Path, dict, str]] = []

    keep: list[tuple[Path, dict]] = []
    for entry, manifest in rows:  # oldest first
        if manifest.get("pinned"):
            keep.append((entry, manifest))
            continue
        if _recently_used(manifest):
            keep.append((entry, manifest))
            continue
        if limits.max_age_days and _age_days(manifest) > limits.max_age_days:
            doomed.append((entry, manifest, f"older than {limits.max_age_days} days"))
            total_mb -= manifest.get("bytes", 0) / (1024 * 1024)
            continue
        keep.append((entry, manifest))

    # count limit: drop the oldest kept entries first
    while limits.max_count and len(keep) > limits.max_count:
        entry, manifest = keep.pop(0)
        doomed.append((entry, manifest, f"keep at most {limits.max_count} snapshots"))
        total_mb -= manifest.get("bytes", 0) / (1024 * 1024)

    # size limit: drop the oldest kept entries first
    while limits.max_total_mb and total_mb > limits.max_total_mb and keep:
        entry, manifest = keep.pop(0)
        doomed.append((entry, manifest, f"total budget {limits.max_total_mb} MB"))
        total_mb -= manifest.get("bytes", 0) / (1024 * 1024)

    removed = []
    if not plan:
        for entry, manifest, reason in doomed:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append({"id": manifest.get("id", entry.name), "reason": reason})
            _log({"pruned": manifest.get("id", entry.name), "reason": reason})

    return {
        "ok": True,
        "planned": plan,
        "limits": limits.__dict__,
        "would_remove": [{"id": m.get("id", e.name), "reason": r} for e, m, r in doomed],
        "removed": removed,
        "kept": len(keep),
        "total_mb": round(total_mb, 1),
    }


# -------------------------------------------------------------------- creation


def _rel(path: Path, root: Path | None) -> str:
    """Relative key for the manifest.

    Targets outside the git root are normal (rm -rf /tmp/build from inside a repo), so they get an
    abs/ prefix instead of raising ValueError.
    """
    if root is not None:
        try:
            return str(path.relative_to(root))
        except ValueError:
            pass
    return "abs/" + str(path).lstrip("/")


def create_snapshot(analysis: dict, command: str, include_excluded: bool = False) -> dict:
    """Copy the affected regular files into a checksummed snapshot, then verify the copies.

    Directory exclusions (node_modules, .venv, dist, ...) keep the snapshot budget for data that
    cannot be rebuilt. Excluded files are still counted in the impact report and listed in the
    manifest, so the report can say "not snapshotted (excluded)" instead of implying protection.
    """
    paths = [Path(p) for p in analysis.get("_paths", [])]
    root = Path(analysis["_root"]) if analysis.get("_root") else None
    if not paths:
        return {"ok": False, "error": "nothing to snapshot", "verified": False}

    regular: list[Path] = []
    excluded: list[str] = []
    links: list[Path] = []
    for path in paths:
        if path.is_symlink():
            links.append(path)
            continue
        if not path.is_file():
            continue
        relative = _rel(path, root)
        if not include_excluded and is_excluded(Path(relative)) and path.name not in _NEVER_EXCLUDE:
            excluded.append(relative)
            continue
        regular.append(path)

    needed = 0
    for path in regular:
        try:
            needed += path.lstat().st_size
        except OSError:
            pass

    snap_root = snapshot_root()
    if free_bytes(snap_root) < needed * 1.2 + (8 * 1024 * 1024):
        return {"ok": False, "error": "not enough free space for a snapshot", "verified": False}

    pruned = prune(plan=False)  # keep the budget before this one lands

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
        relative = _rel(src, root)
        safe = relative.lstrip("/").replace("..", "__")
        dest = files_dir / safe
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dest)
            os.chmod(dest, 0o600)
            original = _sha256(src)
            entries.append({
                "path": relative, "stored": str(dest.relative_to(snap_dir)),
                "bytes": dest.stat().st_size, "sha256": original,
                "verified": original == _sha256(dest),
                "mode": oct(src.stat().st_mode & 0o777),
            })
            copied += 1
        except OSError as exc:
            entries.append({"path": relative, "error": str(exc), "verified": False})

    for link in links:
        relative = _rel(link, root)
        entries.append({"path": relative, "type": "symlink",
                        "target": os.readlink(link), "verified": False, "skipped": True})

    manifest = {
        "id": snap_id,
        "created": _now(),
        "command": command,
        "cwd": analysis.get("cwd"),
        "git_root": analysis.get("git_root"),
        "analysis": {k: v for k, v in analysis.items() if not k.startswith("_")},
        "files": entries,
        "excluded": excluded[:200],
        "pinned": False,
        "count": copied,
        "bytes": sum(e.get("bytes", 0) for e in entries),
        "verified": all(e.get("verified") for e in entries
                        if e.get("error") is None and not e.get("skipped")) and bool(entries),
    }
    _save(snap_dir, manifest)

    return {
        "ok": True, "id": snap_id, "dir": str(snap_dir), "count": copied,
        "bytes": manifest["bytes"], "verified": manifest["verified"],
        "skipped_links": len(links), "excluded": len(excluded),
        "pruned": pruned.get("removed", []),
    }


# ----------------------------------------------------------------------- reading


def list_snapshots(limit: int = 20) -> list[dict]:
    rows = []
    for entry, manifest in reversed(_snapshots()):
        rows.append({
            "id": manifest.get("id", entry.name), "created": manifest.get("created"),
            "command": manifest.get("command"), "count": manifest.get("count", 0),
            "bytes": manifest.get("bytes", 0), "verified": manifest.get("verified", False),
            "pinned": manifest.get("pinned", False), "excluded": len(manifest.get("excluded", [])),
        })
        if len(rows) >= limit:
            break
    return rows


def find_snapshot(snap_id: str) -> Path | None:
    root = snapshot_root()
    if snap_id in {"last", "latest", ""}:
        rows = _snapshots()
        return rows[-1][0] if rows else None
    candidate = root / snap_id
    if (candidate / "manifest.json").is_file():
        return candidate
    for entry in sorted(root.iterdir(), reverse=True):
        if entry.name.startswith(snap_id) and (entry / "manifest.json").is_file():
            return entry
    return None


def read_manifest(snap_dir: Path) -> dict | None:
    return _load(snap_dir)


def verify_snapshot(snap_id: str) -> dict:
    snap_dir = find_snapshot(snap_id)
    if snap_dir is None:
        return {"ok": False, "error": f"snapshot not found: {snap_id}"}
    manifest = _load(snap_dir)
    if manifest is None:
        return {"ok": False, "error": "manifest unreadable"}

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
    return {"ok": not bad, "id": manifest.get("id"), "checked": checked,
            "bad": bad[:10], "count": manifest.get("count", 0)}


def mark_used(snap_id: str) -> None:
    snap_dir = find_snapshot(snap_id)
    if snap_dir is None:
        return
    manifest = _load(snap_dir)
    if manifest is None:
        return
    manifest["last_used"] = _now()
    _save(snap_dir, manifest)


def set_pinned(snap_id: str, pinned: bool) -> dict:
    snap_dir = find_snapshot(snap_id)
    if snap_dir is None:
        return {"ok": False, "error": f"snapshot not found: {snap_id}"}
    manifest = _load(snap_dir)
    if manifest is None:
        return {"ok": False, "error": "manifest unreadable"}
    manifest["pinned"] = bool(pinned)
    _save(snap_dir, manifest)
    return {"ok": True, "id": manifest.get("id"), "pinned": manifest["pinned"]}


def describe_prune(result: dict) -> str:
    limits = result["limits"]
    head = ["BLASTRADIUS // SNAPSHOT RETENTION", ""]
    head.append(f"Limits: {limits['max_age_days']} days · {limits['max_count']} snapshots · "
                f"{limits['max_total_mb']} MB")
    rows = result["would_remove"] if result["planned"] else result["removed"]
    if not rows:
        head += ["", "Nothing to remove; the budget already holds."]
        return "\n".join(head)
    verb = "would remove" if result["planned"] else "removed"
    head += ["", f"{len(rows)} snapshot(s) {verb} (oldest first):"]
    for row in rows:
        head.append(f"  {row['id']}  — {row['reason']}")
    if result["planned"]:
        head += ["", 'Nothing has been deleted. Re-run with "confirm" to apply.']
    return "\n".join(head)


def describe_list(rows: list[dict]) -> str:
    if not rows:
        return "[blastradius] no snapshots yet"
    lines = ["BLASTRADIUS // SNAPSHOTS", ""]
    for row in rows:
        mark = "ok" if row["verified"] else "UNVERIFIED"
        pin = " · PINNED" if row["pinned"] else ""
        extra = f" · {row['excluded']} excluded" if row.get("excluded") else ""
        lines.append(f"  {row['id']}  {row['count']} files  {human_bytes(row['bytes'])}  "
                     f"{mark}{pin}{extra}")
        if row.get("command"):
            lines.append(f'      from: {row["command"][:90]}')
    return "\n".join(lines)
