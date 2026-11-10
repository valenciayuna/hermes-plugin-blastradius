#!/usr/bin/env python3
"""Regression tests for the three review findings on Blast Radius.

1. restore must not overwrite files edited after the snapshot unless asked
2. snapshots must survive targets outside the git root
3. a plain `> file` redirect is measured, `2>` and `>>` are not
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

M = importlib.import_module("blastradius_core.measure")
SNAP = importlib.import_module("blastradius_core.snapshot")
REC = importlib.import_module("blastradius_core.recovery")

checks = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, bool(ok), detail))
    print(f"{'ok  ' if ok else 'FAIL'} {name}{'' if ok else ' :: ' + detail}")


def repo(tmp: Path) -> Path:
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    (tmp / "src" / "a.txt").write_text("original a\n")
    (tmp / "src" / "b.txt").write_text("original b\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "i"],
                   cwd=tmp, check=True)
    return tmp


# ---------------------------------------------------------------- conflicts
tmp = Path(tempfile.mkdtemp(prefix="br-fix-conflict-"))
try:
    root = repo(tmp)
    analysis = M.measure(f"rm -rf {root}/src", str(root))
    made = SNAP.create_snapshot(analysis, command="test")
    snap_id = made.get("id")
    check("snapshot for the conflict test is verified", made.get("verified") is True,
          str(made)[:120])

    # the user edits a file after the snapshot and deletes another one.
    # a.txt stays on disk so it is a real conflict; b.txt is gone and gets recreated.
    (root / "src" / "a.txt").write_text("work done after the snapshot\n")
    (root / "src" / "b.txt").unlink()

    plan = REC.restore(snap_id, confirm=False)
    check("the edited file is reported as a conflict", plan.get("conflicts") == 1, str(plan)[:140])

    done = REC.restore(snap_id, confirm=True)
    kept = (root / "src" / "a.txt").read_text()
    restored_b = (root / "src" / "b.txt").read_text()
    check("restore leaves the newer file alone", kept == "work done after the snapshot\n", kept[:40])
    check("restore still brings back the untouched file", restored_b == "original b\n", restored_b[:40])
    check("the conflict is counted, not silently restored", done.get("restored") == 1, str(done)[:140])

    forced = REC.restore(snap_id, confirm=True, overwrite_conflicts=True)
    after = (root / "src" / "a.txt").read_text()
    check("overwrite_conflicts does replace it", after == "original a\n", after[:40])
    check("overwrite_conflicts reports two files", forced.get("restored") == 2, str(forced)[:140])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# ------------------------------------------------------- outside the repo
tmp = Path(tempfile.mkdtemp(prefix="br-fix-outside-"))
outside = Path(tempfile.mkdtemp(prefix="br-fix-target-"))
try:
    root = repo(tmp)
    (outside / "build.bin").write_text("payload\n")
    analysis = M.measure(f"rm -rf {outside}", str(root))
    made = SNAP.create_snapshot(analysis, command="test")
    check("snapshot outside the git root succeeds", made.get("ok") is not False, str(made)[:140])

    manifest = SNAP.read_manifest(SNAP.find_snapshot(made.get("id"))) or {}
    keys = [e.get("path", "") for e in manifest.get("files", [])]
    check("outside targets are stored under abs/", any(k.startswith("abs/") for k in keys),
          str(keys)[:140])

    shutil.rmtree(outside)
    back = REC.restore(made.get("id"), confirm=True)
    check("restore puts the outside file back",
          (outside / "build.bin").is_file() and back.get("verified", 0) >= 1, str(back)[:140])
finally:
    shutil.rmtree(tmp, ignore_errors=True)
    if outside.exists():
        shutil.rmtree(outside, ignore_errors=True)

# ------------------------------------------------------------- redirects
tmp = Path(tempfile.mkdtemp(prefix="br-fix-redirect-"))
try:
    root = repo(tmp)
    (root / "notes.txt").write_text("line\nline\n")
    (root / "check.log").write_text("x\n")

    trunc = M.measure("echo hi > notes.txt", str(root))
    check("`> file` is measured as one file", trunc.get("files") == 1 and trunc.get("measured") is True,
          str(trunc)[:140])

    stderr_red = M.measure("echo hi 2> check.log", str(root))
    check("`2>` is not treated as truncation", stderr_red.get("files") == 0, str(stderr_red)[:120])

    append = M.measure("echo hi >> check.log", str(root))
    check("`>>` is not treated as truncation", append.get("files") == 0, str(append)[:120])

    plain_trunc = M.measure("truncate -s 0 check.log", str(root))
    check("truncate -s 0 file is measured", plain_trunc.get("files") == 1, str(plain_trunc)[:120])

    unresolved = M.measure("echo hi > $(mktemp)", str(root))
    check("an unresolvable redirect stays unmeasured", unresolved.get("measured") is False,
          str(unresolved)[:120])

    harmless = M.measure("rm -rf src > /dev/null", str(root))
    named = json.dumps(harmless.get("samples_untracked", []) + harmless.get("valuable", []))
    check("/dev/null is not counted as a deleted file",
          harmless.get("files") == 2 and "/dev/null" not in named, str(harmless)[:160])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

passed = sum(1 for _, ok, _ in checks if ok)
print(f"\n{passed}/{len(checks)} checks passed")
sys.exit(0 if passed == len(checks) else 1)
