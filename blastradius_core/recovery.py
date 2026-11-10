"""Restore and the allow-grant store."""

from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from . import snapshot as snap
from .paths import data_dir, human_bytes

ALLOW_TTL_S = 300


# ------------------------------------------------------------------------ allow


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
    entries = [e for e in _load_allow() if e.get("command") != command]
    entries.append({"command": command, "expires": time.time() + ttl_s, "ttl_s": ttl_s})
    _write_allow(entries)
    return {"command": command, "ttl_s": ttl_s, "pending": len(entries)}


def consume_allow(command: str) -> bool:
    entries = _load_allow()
    for i, entry in enumerate(entries):
        if entry.get("command") == command:
            entries.pop(i)
            _write_allow(entries)
            return True
    return False


# ---------------------------------------------------------------------- restore


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(block)
    return digest.hexdigest()


def restore(snap_id: str = "last", confirm: bool = False,
            overwrite_conflicts: bool = False) -> dict:
    """Plan or apply a restore. Refuses to run from a snapshot that fails verification.

    Files changed since the snapshot are conflicts. They are never written over unless the caller
    asks for it explicitly, because the newer file is usually the user's work.
    """
    snap_dir = snap.find_snapshot(snap_id)
    if snap_dir is None:
        return {"ok": False, "error": f"snapshot not found: {snap_id}"}
    manifest = snap.read_manifest(snap_dir)
    if manifest is None:
        return {"ok": False, "error": "manifest unreadable"}

    healthy = snap.verify_snapshot(snap_dir.name)
    if not healthy.get("ok"):
        return {"ok": False, "error": "snapshot failed verification, refusing to restore",
                "detail": healthy.get("bad", [])}

    base = Path(manifest.get("git_root") or manifest.get("cwd") or ".").resolve()
    targets: list[dict] = []
    conflicts: list[dict] = []
    for entry in manifest.get("files", []):
        if entry.get("skipped") or entry.get("error"):
            continue
        key = entry["path"]
        dest = Path("/" + key[4:]) if key.startswith("abs/") else base / key
        stored = snap_dir / entry["stored"]
        state = {"path": entry["path"], "dest": str(dest), "stored": str(stored)}
        if dest.is_file():
            if _sha256(dest) != entry.get("sha256"):
                state["conflict"] = "exists and differs from the snapshot"
                conflicts.append(state)
                if not overwrite_conflicts:
                    continue          # never replace work done after the snapshot
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
                "conflict_paths": [c["path"] for c in conflicts][:10],
                "restored": 0, "verified": 0, "failed": []}

    restored, failed = 0, []
    for state in targets:
        dest = Path(state["dest"])
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(state["stored"], dest)
            restored += 1
        except OSError as exc:
            failed.append(f"{state['path']}: {exc}")

    verified = 0
    by_path = {e.get("path"): e for e in manifest.get("files", [])}
    for state in targets:
        entry = by_path.get(state["path"])
        dest = Path(state["dest"])
        if entry and dest.is_file() and _sha256(dest) == entry.get("sha256"):
            verified += 1

    snap.mark_used(manifest.get("id", snap_dir.name))
    snap._log({"restored": manifest.get("id"), "files": restored, "verified": verified,
               "failed": len(failed)})
    return {"ok": verified == restored and not failed, "id": manifest.get("id"),
            "restored": restored, "verified": verified, "failed": failed[:10]}


def describe_restore(result: dict) -> str:
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
    lines += ["", "Recovery covers what the snapshot holds. Files created after it, database "
                  "state and external services are outside its scope."]
    return "\n".join(lines)


__all__ = ["ALLOW_TTL_S", "consume_allow", "grant_allow", "restore", "describe_restore",
           "datetime", "timezone"]
