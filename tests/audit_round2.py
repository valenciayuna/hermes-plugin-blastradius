#!/usr/bin/env python3
"""Second-pass audit of the fixes: try to make them wrong."""
import importlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/root/hackathon/hermes-plugin-blastradius")
M = importlib.import_module("blastradius_core.measure")
SNAP = importlib.import_module("blastradius_core.snapshot")
REC = importlib.import_module("blastradius_core.recovery")

checks = []


def check(name, ok, detail=""):
    checks.append(bool(ok))
    print(f"{'ok  ' if ok else 'FAIL'} {name}{'' if ok else ' :: ' + str(detail)[:150]}")


def repo(tmp):
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp / "src" / name).write_text(f"{name}\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "i"],
                   cwd=tmp, check=True)
    return tmp


tmp = Path(tempfile.mkdtemp(prefix="br-audit2-"))
try:
    root = repo(tmp)

    # a redirect inside a quoted string is text, not a redirect, even when the file exists
    quoted = M.measure('echo "check the log > src/a.txt"', str(root))
    check("a > inside double quotes is not a redirect", quoted.get("measured") is False, quoted)
    quoted_single = M.measure("echo 'see > src/a.txt'", str(root))
    check("a > inside single quotes is not a redirect", quoted_single.get("measured") is False,
          quoted_single)

    # fd duplication and appends stay out
    for cmd in ("echo x 2>&1 > notes.txt", "cmd >> notes.txt", "echo x >| notes.txt"):
        r = M.measure(cmd, str(root))
        check(f"not a truncation: {cmd}", r.get("kind") != "truncate" or r.get("files") == 0, r)

    # a real redirect to an existing file is one file, tracked
    real = M.measure("printf x > src/a.txt", str(root))
    check("a real redirect counts the tracked file", real.get("files") == 1 and real.get("tracked") == 1,
          real)

    # glob redirect target stays unmeasured rather than claiming zero
    wild = M.measure("echo x > src/*.log", str(root))
    check("a glob redirect is unmeasured", wild.get("measured") is False, wild)

    # restore: conflict respected, then opt-in overwrite, twice in a row
    analysis = M.measure(f"rm -rf {root}/src", str(root))
    made = SNAP.create_snapshot(analysis, command="t")
    (root / "src" / "a.txt").write_text("newer\n")
    first = REC.restore(made["id"], confirm=True)
    check("first restore keeps the newer file", (root / "src" / "a.txt").read_text() == "newer\n",
          first)
    second = REC.restore(made["id"], confirm=True, overwrite_conflicts=True)
    check("second restore with the flag replaces it",
          (root / "src" / "a.txt").read_text() == "a.txt\n", second)
    third = REC.restore(made["id"], confirm=True)
    check("a third plain restore is a no-op", (root / "src" / "a.txt").read_text() == "a.txt\n",
          third)

    # snapshot of a directory three levels outside the repo, then restore
    far = Path(tempfile.mkdtemp(prefix="br-audit2-far-"))
    (far / "deep" / "deeper").mkdir(parents=True)
    (far / "deep" / "deeper" / "x.bin").write_text("payload\n")
    a2 = M.measure(f"rm -rf {far}", str(root))
    made2 = SNAP.create_snapshot(a2, command="t")
    shutil.rmtree(far)
    back = REC.restore(made2["id"], confirm=True)
    check("a deep outside target round trips",
          (far / "deep" / "deeper" / "x.bin").is_file() and back.get("verified", 0) >= 1, back)
    shutil.rmtree(far, ignore_errors=True)

    # the manifest must not claim a path it cannot restore
    manifest = SNAP.read_manifest(SNAP.find_snapshot(made2["id"])) or {}
    keys = [e.get("path", "") for e in manifest.get("files", [])]
    check("outside paths are prefixed, not absolute", all(k.startswith("abs/") for k in keys), keys)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

passed = sum(checks)
print(f"\n{passed}/{len(checks)} checks passed")
sys.exit(0 if passed == len(checks) else 1)
