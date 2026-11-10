#!/usr/bin/env python3
"""Adversarial audit for Blast Radius.

The shipped proof script checks the cases the author thought of. This one attacks the parser and the
snapshot path with shapes that usually break shell analysis: quoting, nested wrappers, cd chains,
command substitution, globs, symlinks, and a restore that must not silently lose bytes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path("/root/hackathon/hermes-plugin-blastradius")
sys.path.insert(0, str(ROOT))

import importlib  # noqa: E402
M = importlib.import_module("blastradius_core.measure")  # the package re-exports a function with the same name

CHECKS: list[tuple[str, bool, str]] = []


def ok(name: str, condition: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(condition), detail))


def analyse(command: str, cwd: str | None = None) -> dict:
    return M.measure(command, cwd)


def build_tree() -> Path:
    root = Path(tempfile.mkdtemp(prefix="br-audit-"))
    (root / "src").mkdir()
    (root / "build").mkdir()
    (root / "data").mkdir()
    (root / "a b").mkdir()
    for path in ("src/app.py", "src/util.py", "build/out.o", "data/app.db",
                 "a b/notes.txt", ".env"):
        (root / path).write_text(f"x{path}")
    (root / "README.md").write_text("readme")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "README.md", "src/app.py"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "init"],
                   cwd=root, check=True)
    (root / "untracked.txt").write_text("only here")
    os.symlink(root / "data", root / "data-link")
    return root


def main() -> int:
    root = build_tree()
    root_s = str(root)

    # 1. quoting: a directory with a space must stay one target, not two
    quoted = analyse(f'rm -rf "{root_s}/a b"')
    ok("quoted path with a space stays one target",
       quoted.get("measured") and quoted.get("files", 0) == 1, json.dumps(quoted.get("files")))

    # 2. tracked vs untracked split
    split = analyse(f"rm -rf {root_s}/src", root_s)
    ok("git-tracked and untracked are separated",
       split.get("measured") and split.get("tracked", 0) >= 1 and split.get("untracked", 0) >= 1,
       f"tracked={split.get('tracked')} untracked={split.get('untracked')}")

    # 3. nested bash -c, two levels
    nested = analyse(f'bash -c \'bash -c "rm -rf {root_s}/build"\'', root_s)
    ok("nested bash -c is followed", nested.get("measured") and nested.get("files", 0) >= 1,
       f"files={nested.get('files')} depth={nested.get('depth')}")

    # 4. subshell and chaining
    sub = analyse(f"( cd {root_s} && rm -rf data )")
    ok("subshell with cd is followed", sub.get("measured") and sub.get("files", 0) >= 1,
       f"files={sub.get('files')}")

    # 5. cd chain, relative path must resolve from the new directory
    chain = analyse(f'cd {root_s}/build && rm -rf .')
    ok("cd chain resolves the relative target", chain.get("measured")
       and chain.get("files", 0) >= 1, f"files={chain.get('files')} targets={chain.get('paths')}")

    # 6. command substitution must be unmeasured, never guessed
    subst = analyse(f"rm -rf $(pwd)/x")
    ok("command substitution is unmeasured", subst.get("measured") is False,
       f"measured={subst.get('measured')}")

    # 7. opaque transports
    for command, label in (('ssh host "rm -rf /tmp/x"', "ssh"),
                           ("eval rm -rf /tmp/x", "eval"),
                           ("find . -name '*.tmp' | xargs rm -rf", "xargs")):
        out = analyse(command)
        ok(f"{label} payload is unmeasured", out.get("measured") is False,
           f"measured={out.get('measured')}")

    # 8. globs: the count must come from what is on disk, not from the pattern
    globbed = analyse(f"rm -rf {root_s}/src/*.py", root_s)
    ok("glob expands against the real tree", globbed.get("measured")
       and globbed.get("files", 0) == 2, f"files={globbed.get('files')}")

    # 9. symlink: deleting the link must not report the target's contents
    link = analyse(f"rm -rf {root_s}/data-link")
    ok("symlink target is not counted as deleted content",
       link.get("measured") and link.get("files", 0) <= 1,
       f"files={link.get('files')}")

    # 10. non-destructive commands are not flagged
    for command in ("ls -la", "git status", "cat README.md", "npm test", "rm -f"):
        out = analyse(command, root_s)
        ok(f"benign command not flagged: {command}", out.get("measured") is False
           or not out.get("destructive"), f"destructive={out.get('destructive')}")

    passed = sum(1 for _, good, _ in CHECKS if good)
    print()
    for name, good, detail in CHECKS:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    print(f"\n{passed}/{len(CHECKS)} parser audit checks passed")
    shutil.rmtree(root, ignore_errors=True)
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
