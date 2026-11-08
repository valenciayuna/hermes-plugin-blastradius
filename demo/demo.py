#!/usr/bin/env python3
"""The Blast Radius demo, played for real.

Builds a throwaway git repo that looks like a working project (tracked source, an uncommitted
.env, a local database, a draft migration), then walks the whole protection cycle:

    preview -> snapshot -> verify -> destroy -> restore -> verify

Nothing here is mocked: the delete really happens, the restore really puts the bytes back, and
every number printed comes from the filesystem at that moment.

    python3 demo/demo.py
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(home: Path):
    os.environ["HERMES_HOME"] = str(home)
    spec = importlib.util.spec_from_file_location("blastradius", HERE / "__init__.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["blastradius"] = module
    spec.loader.exec_module(module)
    module._store_dir_override = home / "blastradius"
    return module


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "demo", "GIT_AUTHOR_EMAIL": "d@d",
                        "GIT_COMMITTER_NAME": "demo", "GIT_COMMITTER_EMAIL": "d@d"})


def build(root: Path) -> Path:
    repo = root / "acme-api"
    (repo / "src").mkdir(parents=True)
    (repo / "migrations").mkdir()
    (repo / "data").mkdir()
    (repo / ".gitignore").write_text(".env\n*.db\n")

    for name in ("app.py", "models.py", "views.py", "worker.py", "settings.py"):
        (repo / "src" / name).write_text(f"# {name}\nprint('ok')\n")
    (repo / "README.md").write_text("# acme-api\n")
    (repo / ".env").write_text("STRIPE_SECRET=sk_live_do_not_lose_me\n")
    (repo / "data" / "app.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 2048)
    (repo / "migrations" / "0007_draft.sql").write_text("ALTER TABLE users ADD COLUMN plan;\n")

    git(repo, "init")
    git(repo, "add", ".gitignore", "README.md", "src")
    git(repo, "commit", "-m", "initial")
    return repo


def rule(title: str) -> None:
    print(f"\n{'=' * 74}\n{title}\n{'=' * 74}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="blastradius-demo-"))
    cwd = os.getcwd()
    try:
        br = load(tmp / "home")
        repo = build(tmp)
        os.chdir(repo)
        command = "rm -rf ."

        rule("1. The agent is about to run:  rm -rf .")
        analysis = br.measure(command)
        print(br.report(analysis, command))

        rule("2. Blast Radius stops it (pre_tool_call) and offers the numbers")
        verdict = br.on_pre_tool_call(tool_name="terminal", args={"command": command, "workdir": str(repo)})
        print("hook verdict:", verdict.get("action") if isinstance(verdict, dict) else verdict)
        if isinstance(verdict, dict):
            print(verdict["message"].split("\n\nThis command was not executed.")[0])

        rule("3. Snapshot: copy what git cannot give back")
        snap = br.create_snapshot(br.measure(command), command)
        print(f"snapshot id : {snap['id']}")
        print(f"files copied: {snap['count']}")
        print(f"bytes copied: {snap['bytes']:,}")
        print(f"verified    : {snap['verified']}")

        rule("4. Independent verification (re-read every checksum)")
        print(br.verify_snapshot(snap["id"]))

        rule("5. The command runs. Everything is gone.")
        shutil.rmtree(repo / "src")
        (repo / "README.md").unlink()
        (repo / ".env").unlink()
        (repo / "data" / "app.db").unlink()
        (repo / "migrations" / "0007_draft.sql").unlink()
        for path in ("src", "README.md", ".env", "data/app.db", "migrations/0007_draft.sql"):
            print(f"  {path:24} exists={Path(repo / path).exists()}")

        rule("6. Restore: plan first, then apply")
        print(br.restore(snap["id"]))
        print()
        print(br.restore(snap["id"], confirm=True))

        rule("7. Proof the bytes came back")
        print("  .env      :", (repo / ".env").read_text().strip())
        print("  app.db    :", len((repo / "data" / "app.db").read_bytes()), "bytes")
        print("  migration :", (repo / "migrations" / "0007_draft.sql").read_text().strip())
        print("  src files :", sorted(p.name for p in (repo / "src").glob("*.py")))
        return 0
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
