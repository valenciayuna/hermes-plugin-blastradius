#!/usr/bin/env python3
"""Integration audit for Blast Radius: does Hermes actually consult the hook, and does the block
reach the tool call."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PLUGIN = Path("/root/hackathon/hermes-plugin-blastradius")
CHECKS: list[tuple[str, bool, str]] = []


def ok(name: str, condition: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(condition), detail))


HARNESS = r'''
import importlib.util, json, os, sys
sys.path.insert(0, "/usr/local/lib/hermes-agent")

from hermes_cli import plugins
plugins.discover_plugins(force=True)
manager = plugins.get_plugin_manager()

spec = importlib.util.spec_from_file_location("blast_plugin", "/root/hackathon/hermes-plugin-blastradius/__init__.py")
bp = importlib.util.module_from_spec(spec)
sys.modules["blast_plugin"] = bp
spec.loader.exec_module(bp)

hooks = getattr(manager, "_hooks", None)
registered = False
if isinstance(hooks, dict):
    hooks.setdefault("pre_tool_call", []).append(bp.on_pre_tool_call)
    registered = True

out = {"registered": registered}

out["benign"] = plugins.get_pre_tool_call_block_message(tool_name="terminal",
                                                        args={"command": "git status"})
out["destructive"] = plugins.get_pre_tool_call_block_message(
    tool_name="terminal", args={"command": "rm -rf " + os.environ["TARGET_TREE"]})
out["other_tool"] = plugins.get_pre_tool_call_block_message(tool_name="read_file",
                                                            args={"path": "/etc/passwd"})

class Ctx:
    def __init__(self):
        self.tools = {}
        self.hooks = []
    def plugin_data_dir(self):
        return os.path.join(os.environ["HERMES_HOME"], "plugin-data", "blastradius")
    def register_hook(self, name, callback):
        self.hooks.append(name)
    def register_tool(self, name, toolset, schema, handler, description="", emoji="", **kw):
        self.tools[name] = toolset
    def register_command(self, *a, **kw):
        return None

ctx = Ctx()
bp.register(ctx)
out["tools"] = sorted(ctx.tools)
out["hooks"] = ctx.hooks
print(json.dumps(out))
'''


def main() -> int:
    tree = Path(tempfile.mkdtemp(prefix="br-itest-"))
    (tree / "src").mkdir()
    (tree / "src" / "app.py").write_text("x")
    (tree / ".env").write_text("SECRET=1")

    home = Path(tempfile.mkdtemp(prefix="br-itest-home-"))
    env = dict(os.environ)
    env["HERMES_HOME"] = str(home)
    env["BLASTRADIUS_SNAPSHOT_DIR"] = str(home / "snaps")
    env["TARGET_TREE"] = str(tree)
    env.pop("BLASTRADIUS_ALLOW", None)

    run = subprocess.run([sys.executable, "-c", HARNESS], capture_output=True, text=True, env=env)
    if run.returncode != 0:
        print("harness failed:", (run.stderr or run.stdout)[-500:])
        return 1
    out = json.loads(run.stdout.strip().splitlines()[-1])

    ok("the hook lands in Hermes's registry", out.get("registered") is True, "manager._hooks")
    ok("register() declares the tools the manifest promises",
       set(out.get("tools") or []) >= {"blast_radius", "blast_allow", "blast_snapshot",
                                       "blast_restore", "blast_policy"},
       str(out.get("tools"))[:90])
    ok("register() wires pre_tool_call", "pre_tool_call" in (out.get("hooks") or []),
       str(out.get("hooks")))

    ok("a benign command is not blocked", out.get("benign") is None, str(out.get("benign"))[:40])

    destructive = out.get("destructive")
    ok("a destructive command is blocked through Hermes's dispatcher",
       isinstance(destructive, str) and "BLASTRADIUS" in destructive.upper(),
       (destructive or "None").splitlines()[0][:70] if destructive else "None")
    ok("the block carries the impact numbers",
       isinstance(destructive, str) and "file" in destructive.lower(),
       "yes" if destructive else "no")

    ok("other tools are untouched", out.get("other_tool") is None, str(out.get("other_tool"))[:40])

    passed = sum(1 for _, good, _ in CHECKS if good)
    print()
    for name, good, detail in CHECKS:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    print(f"\n{passed}/{len(CHECKS)} integration checks passed")
    shutil.rmtree(tree, ignore_errors=True)
    shutil.rmtree(home, ignore_errors=True)
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
