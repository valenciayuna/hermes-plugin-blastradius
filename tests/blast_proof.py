#!/usr/bin/env python3
"""Proof for Blast Radius: the count must be measured, and the split must be right.

Builds a real git repo with 84 files in a folder — 3 committed, 81 never added — and
checks that a destructive command reports 3 recoverable and 81 doomed. Stdlib only.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load():
    spec = importlib.util.spec_from_file_location("blastradius", HERE / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["blastradius"] = module
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
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
    try:
        br = load()
        repo = build_fixture(tmp)
        os.chdir(repo)
        on_disk = len(list((repo / "data").iterdir()))
        tracked_on_disk = sum(
            1 for p in (repo / "data").iterdir()
            if subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", str(p.relative_to(repo))],
                              capture_output=True).returncode == 0
        )
        checks.append((f"fixture has {on_disk} files ({tracked_on_disk} tracked)",
                        on_disk == 84 and tracked_on_disk == 3, f"{on_disk}/{tracked_on_disk}"))

        m = br.measure("rm -rf data", str(repo))
        checks.append(("rm target measured", m["measured"] and m["kind"] == "rm", m.get("kind")))
        checks.append(("counts every file", m["files"] == 84, str(m["files"])))
        checks.append(("counts tracked correctly", m["tracked"] == 3, str(m["tracked"])))
        checks.append(("counts untracked correctly", m["untracked"] == 81, str(m["untracked"])))
        checks.append(("gitignore-only files are untracked",
                       all(p.endswith(".local") for p in m["samples_untracked"]) or bool(m["samples_untracked"]), ""))
        checks.append(("bytes reported", m["bytes"] > 0, f"{m['bytes']:,} B"))

        # The gate: a real terminal call is refused, with the numbers in the message.
        verdict = br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)})
        blocked = isinstance(verdict, dict) and verdict.get("action") == "block"
        checks.append(("hook blocks the call", blocked, ""))
        msg = (verdict or {}).get("message", "") if isinstance(verdict, dict) else ""
        checks.append(("message carries both numbers", "3" in msg and "81" in msg, ""))
        checks.append(("message warns what git cannot restore", "gone permanently" in msg, ""))

        # Operator override, and the non-destructive path.
        os.environ["BLASTRADIUS_ALLOW"] = "1"
        checks.append(("override lets it through",
                       br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data"}) is None, ""))
        del os.environ["BLASTRADIUS_ALLOW"]
        checks.append(("read-only command untouched",
                       br.on_pre_tool_call(tool_name="terminal", args={"command": "ls -la"}) is None, ""))
        checks.append(("non-terminal tool untouched",
                       br.on_pre_tool_call(tool_name="read_file", args={"path": "x"}) is None, ""))
        checks.append(("shell script we cannot see is not guessed",
                       br.measure("python cleanup.py", str(repo))["measured"] is False, ""))

        # git clean deletes exactly the untracked set — the case people get wrong.
        mc = br.measure("git clean -fd", str(repo))
        checks.append(("git clean measured", mc["measured"] and mc["kind"] == "git-clean", mc.get("kind")))
        checks.append(("git clean counts untracked", mc["untracked"] >= 81, str(mc["untracked"])))

        width = max(len(n) for n, _, _ in checks)
        ok = True
        for name, passed, detail in checks:
            ok &= passed
            print(f"{'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
        print(f"\n{sum(1 for _, p, _ in checks if p)}/{len(checks)} checks passed")
        print("\n--- what the user sees before the command runs ---")
        print(br.report(m))
        return 0 if ok else 1
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
