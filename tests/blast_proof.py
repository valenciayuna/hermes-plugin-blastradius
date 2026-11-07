#!/usr/bin/env python3
"""Proof for Blast Radius.

Builds a real git repo with 84 files in a folder (3 committed, 81 never added) and checks
that the measurement, the split, the oneshot confirmation, and the mv semantics are right.
Stdlib only: python3 tests/blast_proof.py
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(tmp_home: Path):
    os.environ["HERMES_HOME"] = str(tmp_home)
    spec = importlib.util.spec_from_file_location("blastradius", HERE / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["blastradius"] = module
    spec.loader.exec_module(module)
    module._store_dir_override = tmp_home / "blastradius"
    return module


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"},
    )


def build_fixture(root: Path) -> Path:
    repo = root / "repo"
    data = repo / "data"
    data.mkdir(parents=True)
    (repo / ".gitignore").write_text("*.local\n")
    for i in range(84):
        suffix = ".local" if i % 20 == 0 else ".txt"
        (data / f"file{i:02d}{suffix}").write_text(f"payload {i}\n")
    git(repo, "init")
    git(repo, "add", ".gitignore")
    for i in (1, 2, 3):
        git(repo, "add", f"data/file{i:02d}.txt")
    git(repo, "commit", "-m", "seed")
    return repo


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="blastradius-"))
    cwd = os.getcwd()
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append((name, bool(passed), detail))

    try:
        br = load(tmp / "home")
        repo = build_fixture(tmp)
        os.chdir(repo)

        # --- measurement
        m = br.measure("rm -rf data", str(repo))
        check("rm target measured", m["measured"] and m["kind"] == "rm", str(m.get("kind")))
        check("counts every file", m["files"] == 84, str(m["files"]))
        check("counts tracked correctly", m["tracked"] == 3, str(m["tracked"]))
        check("counts untracked correctly", m["untracked"] == 81, str(m["untracked"]))
        check("bytes reported", m["bytes"] > 0, f"{m['bytes']:,} B")
        check("git clean counts the untracked set",
              br.measure("git clean -fd", str(repo))["untracked"] >= 81,
              str(br.measure("git clean -fd", str(repo))["untracked"]))

        # --- the gate
        verdict = br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)})
        check("hook blocks the call", isinstance(verdict, dict) and verdict.get("action") == "block")
        msg = (verdict or {}).get("message", "") if isinstance(verdict, dict) else ""
        check("message carries the numbers", "84" in msg and "81" in msg)
        check("message offers the one-shot path", "blast_allow" in msg)

        # --- oneshot confirmation
        br.blast_allow("rm -rf data")
        allowed = br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)})
        check("confirmed command passes once", allowed is None)
        blocked_again = br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)})
        check("grant is spent, gate closes again",
              isinstance(blocked_again, dict) and blocked_again.get("action") == "block")

        # --- mv semantics: rename destroys nothing, overwrite does
        rename = br.on_pre_tool_call(tool_name="terminal", args={"command": "mv data data_backup", "workdir": str(repo)})
        check("plain rename is not gated", rename is None)
        check("plain rename is not even measured",
              br.measure("mv data data_backup", str(repo))["measured"] is False,
              br.measure("mv data data_backup", str(repo)).get("reason", ""))
        (repo / "target.txt").write_text("old contents\n")
        (repo / "source.txt").write_text("new contents\n")
        overwrite = br.on_pre_tool_call(tool_name="terminal", args={"command": "mv source.txt target.txt", "workdir": str(repo)})
        check("mv onto an existing file is gated",
              isinstance(overwrite, dict) and overwrite.get("action") == "block")
        (repo / "existing").mkdir(exist_ok=True)
        into_dir = br.on_pre_tool_call(tool_name="terminal", args={"command": "mv source.txt existing", "workdir": str(repo)})
        check("mv into a directory is not gated", into_dir is None)

        # --- things we must not touch
        check("read-only command untouched",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "ls -la"}) is None)
        check("non-terminal tool untouched",
              br.on_pre_tool_call(tool_name="read_file", args={"path": "x"}) is None)
        check("unrecognised destructive script not guessed",
              br.measure("python cleanup.py", str(repo))["measured"] is False)
        check("missing target is not a block",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf nope_dir"}) is None)

        # --- operator override and expiry
        os.environ["BLASTRADIUS_ALLOW"] = "1"
        check("session override passes everything",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)}) is None)
        del os.environ["BLASTRADIUS_ALLOW"]
        br.blast_allow("rm -rf data", ttl_s=1)
        time.sleep(1.2)
        check("expired grant does not pass",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf data", "workdir": str(repo)}), dict))

        width = max(len(n) for n, _, _ in checks)
        ok = True
        for name, passed, detail in checks:
            ok &= passed
            print(f"{'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
        print(f"\n{sum(1 for _, p, _ in checks if p)}/{len(checks)} checks passed")
        print("\n--- what the user sees before the command runs ---")
        print(br.report(br.measure("rm -rf data", str(repo))))
        return 0 if ok else 1
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
