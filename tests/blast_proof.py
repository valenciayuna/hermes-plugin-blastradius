#!/usr/bin/env python3
"""Proof for Blast Radius 2.0.

Same fixture as v1 (a real git repo with tracked and untracked data) plus the parts 2.0 adds:
valuable-file detection, snapshots, verified restore, conflict handling, corrupted snapshots,
and the three risk policies. Stdlib only: python3 tests/blast_proof.py

Every destructive action here happens inside a temporary directory that is deleted afterwards.
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
    os.environ.pop("BLASTRADIUS_POLICY", None)
    os.environ.pop("BLASTRADIUS_ALLOW", None)
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
    """84 generated files, 3 of them committed, plus the data people actually lose."""
    repo = root / "repo"
    data = repo / "data"
    (data / "migrations").mkdir(parents=True)
    (repo / ".gitignore").write_text("*.local\n")
    for i in range(84):
        suffix = ".local" if i % 20 == 0 else ".txt"
        (data / f"file{i:02d}{suffix}").write_text(f"payload {i}\n")
    (data / ".env.local").write_text("DB_PASSWORD=hunter2\n")
    (data / "app.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    (data / "migrations" / "0007_draft.sql").write_text("ALTER TABLE users ADD COLUMN plan;\n")

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
        data = repo / "data"
        os.chdir(repo)

        # ---------------------------------------------------------------- impact
        m = br.measure("rm -rf data", str(repo))
        check("rm target measured", m["measured"] and m["kind"] == "rm", str(m.get("kind")))
        check("counts every file", m["files"] == 87, str(m["files"]))
        check("counts tracked correctly", m["tracked"] == 3, str(m["tracked"]))
        check("counts untracked correctly", m["untracked"] == 84, str(m["untracked"]))
        check("bytes reported", m["bytes"] > 0, f"{m['bytes']:,} B")
        check("ignored files counted", m["ignored"] >= 1, str(m["ignored"]))
        check("valuable files spotted",
              {Path(p).name for p in m["valuable"]} >= {".env.local", "app.db", "0007_draft.sql"},
              str(m["valuable"]))
        check("risk level escalates on valuable data", m["risk"] in {"high", "critical"}, m["risk"])
        text = br.report(m, "rm -rf data")
        check("report has the impact block", "IMPACT REPORT" in text and "Risk level" in text)
        check("report refuses to say 'gone permanently'", "gone permanently" not in text.lower())

        # ---------------------------------------------------------------- gate
        verdict = br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)})
        check("hook blocks the call", isinstance(verdict, dict) and verdict.get("action") == "block")
        msg = (verdict or {}).get("message", "") if isinstance(verdict, dict) else ""
        check("message carries the numbers", "87" in msg and "84" in msg)
        check("message offers the one-shot path", "blast_allow" in msg)

        br.blast_allow("rm -rf data")
        check("confirmed command passes once",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)}) is None)
        check("grant is spent",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                            args={"command": "rm -rf data", "workdir": str(repo)}), dict))

        # ---------------------------------------------------------------- snapshot
        snap = br.create_snapshot(br.measure("rm -rf data", str(repo)), "rm -rf data")
        check("snapshot created", snap.get("ok") is True, str(snap.get("error", "")))
        check("snapshot verified on creation", snap.get("verified") is True)
        check("snapshot copied the files", snap.get("count", 0) >= 87, str(snap.get("count")))
        check("snapshot lives outside the target",
              not str(snap.get("dir", "")).startswith(str(data)))
        snap_dir = Path(snap["dir"])
        manifest = json.loads((snap_dir / "manifest.json").read_text())
        check("manifest has checksums", all("sha256" in e for e in manifest["files"] if not e.get("skipped")))
        check("manifest records the command", manifest.get("command") == "rm -rf data")

        healthy = br.verify_snapshot(snap["id"])
        check("independent verification passes", healthy.get("ok") is True, str(healthy.get("bad")))

        # ---------------------------------------------------------------- restore
        shutil.rmtree(data)  # the destructive command, for real
        check("target is gone", not data.exists())
        plan = br.restore_snapshot(snap["id"])
        check("restore plans before writing", plan.get("planned") is True and not data.exists(),
              f"targets={plan.get('targets')}")
        applied = br.restore_snapshot(snap["id"], confirm=True)
        check("restore brings the files back", data.exists() and applied.get("restored", 0) >= 87,
              str(applied.get("restored")))
        check("restored contents verified", applied.get("verified") == applied.get("restored"),
              f"{applied.get('verified')}/{applied.get('restored')}")
        check("secret file content is intact",
              (data / ".env.local").read_text().strip() == "DB_PASSWORD=hunter2")

        # ---------------------------------------------------------------- conflicts
        (data / "file07.txt").write_text("changed after the snapshot\n")
        conflict_plan = br.restore_snapshot(snap["id"])
        check("conflict detected", conflict_plan.get("conflicts", 0) >= 1, str(conflict_plan.get("conflict_paths")))
        br.restore_snapshot(snap["id"], confirm=True)
        check("confirmed restore overwrites the newer file",
              (data / "file07.txt").read_text() == "payload 7\n")

        # ---------------------------------------------------------------- corruption
        stored = next(p for p in (snap_dir / "files").rglob("app.db"))
        stored.write_bytes(b"corrupted")
        corrupted = br.verify_snapshot(snap["id"])
        check("corruption detected", corrupted.get("ok") is False and corrupted.get("bad"),
              str(corrupted.get("bad")))
        refused = br.restore_snapshot(snap["id"], confirm=True)
        check("restore refuses a corrupted snapshot",
              refused.get("ok") is False and "verification" in str(refused.get("error", "")))

        # ---------------------------------------------------------------- policies
        br.set_policy("balanced")
        check("default policy is balanced", br.get_policy() == "balanced")

        tracked_only = repo / "tracked_only"
        tracked_only.mkdir()
        (tracked_only / "a.txt").write_text("x\n")
        git(repo, "add", "tracked_only/a.txt")
        git(repo, "commit", "-m", "tracked")

        os.environ["BLASTRADIUS_POLICY"] = "relaxed"
        check("relaxed lets small tracked-only deletes through",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "rm -rf tracked_only", "workdir": str(repo)}) is None)
        check("relaxed still blocks a large untracked sweep",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf data", "workdir": str(repo)}), dict))

        os.environ["BLASTRADIUS_POLICY"] = "strict"
        check("strict blocks even tracked-only targets",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf tracked_only", "workdir": str(repo)}), dict))
        strict_msg = br.blast_allow("rm -rf data")
        check("strict allow reports a verified snapshot", "snapshot" in strict_msg and "verified" in strict_msg,
              strict_msg.splitlines()[-1][:60])
        check("strict grant then passes",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "rm -rf data", "workdir": str(repo)}) is None)

        os.environ["BLASTRADIUS_POLICY"] = "strict"
        nested = br.on_pre_tool_call(tool_name="terminal",
                                     args={"command": "bash -c 'rm -rf data'", "workdir": str(repo)})
        check("strict blocks an unmeasurable destructive shape",
              isinstance(nested, dict) and nested.get("action") == "block")

        del os.environ["BLASTRADIUS_POLICY"]
        br.set_policy("balanced")

        # ---------------------------------------------------------------- unmeasured
        check("subshell reported unmeasured", br.measure("bash -c 'rm -rf data'", str(repo))["measured"] is False)
        check("ssh reported unmeasured", br.measure("ssh host rm -rf /x", str(repo))["measured"] is False)
        check("command substitution reported unmeasured",
              br.measure("rm -rf $(pwd)/data", str(repo))["measured"] is False)
        check("unrecognised destructive script not guessed",
              br.measure("python cleanup.py", str(repo))["measured"] is False)

        # ---------------------------------------------------------------- untouched
        check("read-only command untouched",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "ls -la"}) is None)
        check("non-terminal tool untouched",
              br.on_pre_tool_call(tool_name="read_file", args={"path": "x"}) is None)
        check("missing target is not a block",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf nope_dir"}) is None)

        # ---------------------------------------------------------------- mv
        (repo / "target.txt").write_text("old\n")
        (repo / "source.txt").write_text("new\n")
        check("mv onto an existing file is gated",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "mv source.txt target.txt", "workdir": str(repo)}),
                         dict))
        (repo / "existing").mkdir(exist_ok=True)
        check("mv into a directory is not gated",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "mv source.txt existing", "workdir": str(repo)}) is None)

        # ---------------------------------------------------------------- override + expiry
        os.environ["BLASTRADIUS_ALLOW"] = "1"
        check("session override passes everything",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf data", "workdir": str(repo)}) is None)
        del os.environ["BLASTRADIUS_ALLOW"]
        br.blast_allow("rm -rf data", ttl_s=1)
        time.sleep(1.2)
        check("expired grant does not pass",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf data", "workdir": str(repo)}), dict))

        # ---------------------------------------------------------------- output
        width = max(len(n) for n, _, _ in checks)
        ok = True
        for name, passed, detail in checks:
            ok &= passed
            print(f"{'PASS' if passed else 'FAIL'}  {name:<{width}}  {detail}")
        passed = sum(1 for _, p, _ in checks if p)
        print(f"\n{passed}/{len(checks)} checks passed")
        print("\n--- what the user sees before the command runs ---")
        print(br.report(br.measure("rm -rf data", str(repo)), "rm -rf data"))
        return 0 if ok else 1
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
