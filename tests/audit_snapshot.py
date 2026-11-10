#!/usr/bin/env python3
"""Snapshot, restore and policy audit for Blast Radius.

The question is not "does it copy files" but "when it says verified, is that true, and when it
cannot be sure, does it say so".
"""

from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path("/root/hackathon/hermes-plugin-blastradius")
sys.path.insert(0, str(ROOT))

paths = importlib.import_module("blastradius_core.paths")
snap = importlib.import_module("blastradius_core.snapshot")
rec = importlib.import_module("blastradius_core.recovery")
pol = importlib.import_module("blastradius_core.policy")
hooks = importlib.import_module("blastradius_core.hooks")
M = importlib.import_module("blastradius_core.measure")

CHECKS: list[tuple[str, bool, str]] = []


def ok(name: str, condition: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(condition), detail))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    store = Path(tempfile.mkdtemp(prefix="br-store-"))
    os.environ["BLASTRADIUS_SNAPSHOT_DIR"] = str(store)
    paths.set_store_dir(store)

    tree = Path(tempfile.mkdtemp(prefix="br-tree-"))
    (tree / "src").mkdir()
    (tree / "data").mkdir()
    for name in ("src/app.py", "src/util.py", "README.md"):
        (tree / name).write_text(f"content of {name}\n")
    (tree / "data/app.db").write_bytes(b"\x00\x01\x02" * 100)
    (tree / ".env").write_text("SECRET=1\n")
    before = {p.relative_to(tree): sha(p) for p in tree.rglob("*") if p.is_file()}

    analysis = M.measure(f"rm -rf {tree}", str(tree))
    ok("the target is measured before anything runs",
       analysis.get("measured") is True and analysis.get("files", 0) >= 5,
       f"files={analysis.get('files')} untracked={analysis.get('untracked')}")

    made = snap.create_snapshot(analysis, command=f"rm -rf {tree}")
    ok("snapshot reports verified", made.get("verified") is True,
       f"files={made.get('files')} bytes={made.get('bytes')}")
    snap_id = made.get("id")

    ok("the snapshot is listed", any(s.get("id") == snap_id for s in snap.list_snapshots()),
       f"{len(snap.list_snapshots())} snapshot(s)")

    shutil.rmtree(tree)
    ok("the tree is really gone", not tree.exists())

    restored = rec.restore(snap_id, confirm=True)
    ok("restore verifies every file it writes",
       restored.get("ok") is True and not restored.get("failed"),
       f"restored={restored.get('restored')} verified={restored.get('verified')}")

    after = {p.relative_to(tree): sha(p) for p in tree.rglob("*") if p.is_file()}
    ok("bytes are identical after restore", before == after, f"{len(after)}/{len(before)} files")

    # tamper with a stored blob: a restore must not call that verified
    tree2 = Path(tempfile.mkdtemp(prefix="br-tree2-"))
    (tree2 / "only.txt").write_text("original bytes\n")
    a2 = M.measure(f"rm -rf {tree2}", str(tree2))
    made2 = snap.create_snapshot(a2, command=f"rm -rf {tree2}")
    manifest_path = store / str(made2.get("id")) / "manifest.json"
    blob = None
    if manifest_path.is_file():
        import json
        manifest = json.loads(manifest_path.read_text())
        stored = (manifest.get("files") or [{}])[0].get("stored")
        if stored:
            blob = store / str(made2.get("id")) / stored
    if blob is not None and blob.is_file():
        blob.write_bytes(b"tampered bytes, longer than before")
        shutil.rmtree(tree2)
        bad = rec.restore(made2.get("id"), confirm=True)
        ok("a tampered snapshot is reported, not restored as verified",
           bad.get("ok") is False or bool(bad.get("failed")),
           f"ok={bad.get('ok')} failed={bad.get('failed')} verified={bad.get('verified')}")
    else:
        ok("a tampered snapshot is reported, not restored as verified", False, "blob not found")

    # policy behaviour
    unmeasurable = M.measure("rm -rf $(pwd)/x", str(tree))
    pol.set_policy("strict")
    blocked, why = pol.blocks(unmeasurable, partial=False)
    ok("strict policy blocks an unmeasurable destructive command", blocked is True, why[:60])

    pol.set_policy("balanced")
    allowed, why2 = pol.blocks(unmeasurable, partial=False)
    ok("balanced policy does not block it", allowed is False, why2[:60])

    # the hook ignores other tools and benign commands
    pol.set_policy("strict")
    ok("non-terminal tools are left alone",
       hooks.on_pre_tool_call(tool_name="read_file", args={"path": "/etc/passwd"}) is None)
    ok("benign command passes under strict",
       hooks.on_pre_tool_call(tool_name="terminal", args={"command": "git status"}) is None)

    # one-shot allow: passes once, blocks again after
    command = f"rm -rf {tree}/src"
    rec.grant_allow(command, ttl_s=60)
    first = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command})
    second = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command})
    ok("a one-shot allow is spent exactly once",
       first is None and isinstance(second, dict) and second.get("action") == "block",
       f"first={first} second={(second or {}).get('action') if isinstance(second, dict) else second}")

    passed = sum(1 for _, good, _ in CHECKS if good)
    print()
    for name, good, detail in CHECKS:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    print(f"\n{passed}/{len(CHECKS)} snapshot and policy audit checks passed")
    shutil.rmtree(store, ignore_errors=True)
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
