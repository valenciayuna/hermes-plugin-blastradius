#!/usr/bin/env python3
"""Proof for Blast Radius 2.0 (recursive parsing + retention).

Covers the flat cases from v1 plus the upgrade: bash -c wrappers, nested wrappers, subshells,
chains, `cd` tracking, depth limits, unresolvable segments, snapshot exclusion, retention
(age/count/size, pinning), and the partial-measurement warning.

    python3 tests/blast_proof.py
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(tmp_home: Path):
    os.environ["HERMES_HOME"] = str(tmp_home)
    for key in ("BLASTRADIUS_POLICY", "BLASTRADIUS_ALLOW", "BLASTRADIUS_SNAP_MAX_AGE_DAYS",
                "BLASTRADIUS_SNAP_MAX_COUNT", "BLASTRADIUS_SNAP_MAX_TOTAL_MB"):
        os.environ.pop(key, None)
    spec = importlib.util.spec_from_file_location("blastradius", HERE / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["blastradius"] = module
    spec.loader.exec_module(module)

    from blastradius_core import paths, snapshot as snapstore  # core modules, already importable
    paths.set_store_dir(tmp_home / "blastradius")
    return module, paths, snapstore


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def build_fixture(root: Path) -> Path:
    repo = root / "repo"
    data = repo / "data"
    build = repo / "build"
    (data / "migrations").mkdir(parents=True)
    build.mkdir()
    (repo / ".gitignore").write_text("*.local\n")
    for i in range(84):
        suffix = ".local" if i % 20 == 0 else ".txt"
        (data / f"file{i:02d}{suffix}").write_text(f"payload {i}\n")
    (data / ".env.local").write_text("DB_PASSWORD=hunter2\n")
    (data / "app.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    (data / "migrations" / "0007_draft.sql").write_text("ALTER TABLE users ADD COLUMN plan;\n")
    (build / "artifact.bin").write_bytes(b"built" * 100)
    (repo / "data with space").mkdir()
    (repo / "data with space" / "note.txt").write_text("quoted path\n")

    git(repo, "init")
    git(repo, "add", ".gitignore")
    for i in (1, 2, 3):
        git(repo, "add", f"data/file{i:02d}.txt")
    git(repo, "commit", "-m", "seed")
    return repo


def fake_snapshot(root: Path, snap_id: str, days_ago: float, mb: float, pinned=False) -> Path:
    entry = root / snap_id
    (entry / "files").mkdir(parents=True, exist_ok=True)
    created = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")
    (entry / "manifest.json").write_text(json.dumps({
        "id": snap_id, "created": created, "command": "rm -rf x", "count": 1,
        "bytes": int(mb * 1024 * 1024), "verified": True, "pinned": pinned, "files": [],
        "cwd": str(root), "git_root": None, "excluded": [],
    }))
    return entry


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="blastradius-"))
    cwd = os.getcwd()
    checks: list[tuple[str, bool, str]] = []

    def check(name, passed, detail=""):
        checks.append((name, bool(passed), str(detail)))

    try:
        br, paths, snapstore = load(tmp / "home")
        repo = build_fixture(tmp)
        data = repo / "data"
        build = repo / "build"
        os.chdir(repo)

        # ------------------------------------------------------------ flat measurement
        m = br.measure("rm -rf data", str(repo))
        check("rm target measured", m["measured"] and m["kind"] == "rm", m.get("kind"))
        check("counts every file", m["files"] == 87, m["files"])
        check("counts tracked correctly", m["tracked"] == 3, m["tracked"])
        check("counts untracked correctly", m["untracked"] == 84, m["untracked"])
        check("bytes reported", m["bytes"] > 0, m["bytes"])
        check("ignored files counted", m["ignored"] >= 1, m["ignored"])
        check("valuable files spotted",
              {"app.db", "0007_draft.sql"} <= {Path(p).name for p in m["valuable"]}, m["valuable"])
        check("risk level escalates", m["risk"] in {"high", "critical"}, m["risk"])
        check("report has the impact block", "IMPACT REPORT" in br.report(m, "rm -rf data"))
        check("report never claims 'gone permanently'", "gone permanently" not in br.report(m).lower())

        # ------------------------------------------------------------ parser: quoting
        segments = br.split_top_level("rm -rf 'a b' && echo \"x;y\" ; ls")
        check("parser splits on && and ;", len(segments) == 3, segments)
        check("parser keeps quoted separators intact", segments[0] == "rm -rf 'a b'", segments[0])
        check("parser keeps quoted ; inside a value", segments[1] == 'echo "x;y"', segments[1])
        spaced = br.measure('rm -rf "data with space"', str(repo))
        check("quoted path measured", spaced["files"] == 1, spaced["files"])

        # ------------------------------------------------------------ parser: wrappers
        wrapped = br.measure('bash -c "cd build && rm -rf ."', str(repo))
        check("bash -c with cd is measured", wrapped["measured"] is True)
        check("bash -c measures the cd'd directory", wrapped["files"] == 1, wrapped["files"])
        check("bash -c report resolves into build",
              any("build" in p for p in wrapped["_paths"]), wrapped["_paths"][:1])

        nested = br.measure("""sh -c 'bash -c "rm -rf data"'""", str(repo))
        check("nested -c is measured", nested["measured"] is True)
        check("nested -c reaches the real target", nested["files"] == 87, nested["files"])

        flag = br.measure("""bash -lc 'rm -rf data'""", str(repo))
        check("-lc wrapper handled", flag["files"] == 87, flag["files"])

        subshell = br.measure("(rm -rf data)", str(repo))
        check("subshell measured", subshell["files"] == 87, subshell["files"])

        braces = br.measure("{ rm -rf data; }", str(repo))
        check("brace group measured", braces["files"] == 87, braces["files"])

        chain = br.measure("cd data && rm -rf .", str(repo))
        check("chain follows cd", chain["files"] == 87, chain["files"])

        # ------------------------------------------------------------ parser: limits
        runtime = br.measure('bash -c "rm -rf $(pwd)/x"', str(repo))
        check("command substitution never crashes", isinstance(runtime, dict))
        check("command substitution reported unmeasured", runtime["measured"] is False,
              runtime.get("reason", "")[:50])

        deep_tasks, deep_unmeasured = br.expand("rm -rf data", repo, depth=4)
        check("depth limit marks it unmeasured", bool(deep_unmeasured) and not deep_tasks,
              deep_unmeasured[:1])

        mixed = br.measure('rm -rf build && rm -rf $(pwd)/mystery', str(repo))
        check("partial result flagged", mixed.get("partial") is True)
        check("partial keeps what it could measure", mixed["files"] >= 1, mixed["files"])
        check("partial report warns the user",
              "Partial measurement" in br.report(mixed), "")

        ssh = br.measure("ssh host rm -rf /x", str(repo))
        check("ssh reported unmeasured", ssh["measured"] is False)

        # ------------------------------------------------------------ policy + hook
        br.set_policy("balanced")
        verdict = br.on_pre_tool_call(tool_name="terminal",
                                      args={"command": "rm -rf data", "workdir": str(repo)})
        check("hook blocks the call", isinstance(verdict, dict) and verdict["action"] == "block")
        check("message carries the numbers", "87" in verdict["message"] and "84" in verdict["message"])
        check("message offers the one-shot path", "blast_allow" in verdict["message"])

        partial_verdict = br.on_pre_tool_call(
            tool_name="terminal",
            args={"command": "rm -rf build && rm -rf $(pwd)/mystery", "workdir": str(repo)})
        check("balanced blocks a partially measured call",
              isinstance(partial_verdict, dict) and partial_verdict["action"] == "block")
        check("the block explains what it could not see",
              "Partial measurement" in partial_verdict["message"])

        os.environ["BLASTRADIUS_POLICY"] = "relaxed"
        relaxed_small = br.on_pre_tool_call(tool_name="terminal",
                                            args={"command": "rm -rf build", "workdir": str(repo)})
        check("relaxed lets a small tracked-only delete through", relaxed_small is None)
        relaxed_partial = br.on_pre_tool_call(
            tool_name="terminal",
            args={"command": "rm -rf build && rm -rf $(pwd)/x", "workdir": str(repo)})
        check("relaxed still refuses to pass a partial one silently",
              isinstance(relaxed_partial, dict))
        os.environ["BLASTRADIUS_POLICY"] = "strict"
        check("strict blocks a measured destructive call",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf build",
                                                   "workdir": str(repo)}), dict))
        check("strict blocks an unmeasurable destructive call",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "bash -c 'rm -rf $(pwd)/x'",
                                                   "workdir": str(repo)}), dict))
        os.environ.pop("BLASTRADIUS_POLICY")
        br.set_policy("balanced")

        # ------------------------------------------------------------ allow semantics
        br.blast_allow("rm -rf data")
        check("confirmed command passes once",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "rm -rf data", "workdir": str(repo)}) is None)
        check("grant is spent",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf data",
                                                   "workdir": str(repo)}), dict))
        br.blast_allow("rm -rf data", ttl_s=1)
        time.sleep(1.2)
        check("expired grant does not pass",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "rm -rf data",
                                                   "workdir": str(repo)}), dict))
        os.environ["BLASTRADIUS_ALLOW"] = "1"
        check("session override passes everything",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "rm -rf data", "workdir": str(repo)}) is None)
        os.environ.pop("BLASTRADIUS_ALLOW")

        # ------------------------------------------------------------ snapshots
        created = snapstore.create_snapshot(br.measure("rm -rf data", str(repo)), "rm -rf data")
        check("snapshot created", created["ok"] is True, created.get("error", ""))
        check("snapshot verified on creation", created["verified"] is True)
        check("snapshot copied the files", created["count"] >= 87, created["count"])
        manifest = json.loads((Path(created["dir"]) / "manifest.json").read_text())
        check("manifest keeps the old shape",
              {"id", "created", "command", "files", "count", "bytes", "verified"} <= set(manifest))
        check("manifest records checksums",
              all("sha256" in e for e in manifest["files"] if not e.get("skipped")))
        check("snapshot lives outside the target",
              not str(created["dir"]).startswith(str(data)))
        check("independent verification passes", snapstore.verify_snapshot(created["id"])["ok"])

        # ------------------------------------------------------------ exclusion
        big = repo / "node_modules" / "pkg"
        big.mkdir(parents=True)
        (big / "index.js").write_text("module.exports = 1\n")
        analysis = br.measure("rm -rf node_modules", str(repo))
        check("excluded files still counted in the report", analysis["files"] == 1, analysis["files"])
        excluded_snap = snapstore.create_snapshot(analysis, "rm -rf node_modules")
        check("snapshot reports what it excluded", excluded_snap["excluded"] == 1,
              excluded_snap["excluded"])
        check("excluded files are not copied", excluded_snap["count"] == 0, excluded_snap["count"])
        forced = snapstore.create_snapshot(analysis, "rm -rf node_modules", include_excluded=True)
        check("--include overrides the exclusion", forced["count"] == 1, forced["count"])

        # ------------------------------------------------------------ restore
        shutil.rmtree(data)
        plan = br.blast_restore(created["id"])
        check("restore plans before writing", "Nothing has been written yet" in plan)
        applied = br.blast_restore(created["id"], True)
        check("restore brings the files back", data.exists() and "Files restored" in applied)
        check("restore verified the checksums", "Checksums verified" in applied)
        check("secret content intact", (data / ".env.local").read_text().strip() == "DB_PASSWORD=hunter2")

        (data / "file07.txt").write_text("changed later\n")
        conflict_plan = br.blast_restore(created["id"])
        check("conflict detected in the plan", "Conflicts: 1" in conflict_plan, conflict_plan[:60])
        br.blast_restore(created["id"], True)
        check("confirmed restore leaves the newer file alone",
              (data / "file07.txt").read_text() == "changed later\n")
        br.blast_restore(created["id"], True, True)
        check("restore only replaces it when overwrite_conflicts is set",
              (data / "file07.txt").read_text() == "payload 7\n")

        stored = next(p for p in (Path(created["dir"]) / "files").rglob("app.db"))
        stored.write_bytes(b"corrupted")
        check("corruption detected", snapstore.verify_snapshot(created["id"])["ok"] is False)
        check("restore refuses a corrupted snapshot",
              "failed verification" in br.blast_restore(created["id"], True))

        # ------------------------------------------------------------ retention
        ret_root = paths.snapshot_root()
        for entry in ret_root.iterdir():
            shutil.rmtree(entry, ignore_errors=True)

        fake_snapshot(ret_root, "blast-a-old", 30, 10)
        fake_snapshot(ret_root, "blast-b-mid", 5, 10)
        fake_snapshot(ret_root, "blast-c-new", 1, 10)
        fake_snapshot(ret_root, "blast-d-pinned", 40, 10, pinned=True)

        os.environ["BLASTRADIUS_SNAP_MAX_AGE_DAYS"] = "14"
        plan_age = snapstore.prune(plan=True)
        ids = {row["id"] for row in plan_age["would_remove"]}
        check("age limit selects the old one", "blast-a-old" in ids, ids)
        check("age limit spares the recent one", "blast-c-new" not in ids, ids)
        check("pinned survives the age limit", "blast-d-pinned" not in ids, ids)
        check("plan deletes nothing", len(list(ret_root.iterdir())) == 4,
              len(list(ret_root.iterdir())))

        os.environ.pop("BLASTRADIUS_SNAP_MAX_AGE_DAYS")
        os.environ["BLASTRADIUS_SNAP_MAX_COUNT"] = "2"
        plan_count = snapstore.prune(plan=True)
        oldest_first = [row["id"] for row in plan_count["would_remove"]]
        check("count limit triggers", len(oldest_first) >= 1, oldest_first)
        os.environ.pop("BLASTRADIUS_SNAP_MAX_COUNT")

        os.environ["BLASTRADIUS_SNAP_MAX_TOTAL_MB"] = "15"
        plan_size = snapstore.prune(plan=True)
        check("size limit triggers", len(plan_size["would_remove"]) >= 1,
              [r["id"] for r in plan_size["would_remove"]])
        os.environ.pop("BLASTRADIUS_SNAP_MAX_TOTAL_MB")

        os.environ["BLASTRADIUS_SNAP_MAX_AGE_DAYS"] = "14"
        applied_prune = snapstore.prune(plan=False)
        remaining = {p.name for p in ret_root.iterdir()}
        check("prune actually deletes", "blast-a-old" not in remaining, remaining)
        check("prune keeps the pinned snapshot", "blast-d-pinned" in remaining, remaining)
        check("prune is written to the recovery log",
              "pruned" in (paths.data_dir() / "recovery.log").read_text())
        os.environ.pop("BLASTRADIUS_SNAP_MAX_AGE_DAYS")

        check("prune output shows the limits",
              "RETENTION" in snapstore.describe_prune(snapstore.prune(plan=True)))

        pin_result = snapstore.set_pinned("blast-b-mid", True)
        check("pin command works", pin_result["ok"] and pin_result["pinned"] is True)
        listed = snapstore.describe_list(snapstore.list_snapshots())
        check("pinned snapshots are marked in the list", "PINNED" in listed)

        # ------------------------------------------------------------ untouched shapes
        check("read-only command untouched",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "ls -la"}) is None)
        check("non-terminal tool untouched",
              br.on_pre_tool_call(tool_name="read_file", args={"path": "x"}) is None)
        check("missing target is not a block",
              br.on_pre_tool_call(tool_name="terminal", args={"command": "rm -rf nope_dir"}) is None)
        check("unknown script not guessed",
              br.measure("python cleanup.py", str(repo))["measured"] is False)

        (repo / "target.txt").write_text("old\n")
        (repo / "source.txt").write_text("new\n")
        check("mv onto an existing file is gated",
              isinstance(br.on_pre_tool_call(tool_name="terminal",
                                             args={"command": "mv source.txt target.txt",
                                                   "workdir": str(repo)}), dict))
        (repo / "existing").mkdir(exist_ok=True)
        check("mv into a directory is not gated",
              br.on_pre_tool_call(tool_name="terminal",
                                  args={"command": "mv source.txt existing",
                                        "workdir": str(repo)}) is None)

        # ------------------------------------------------------------ summary
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
