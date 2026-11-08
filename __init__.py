"""Blast Radius — measure what a destructive command will actually destroy, then make it undoable.

Hermes already asks "allow this command?" and can ask a model "is this dangerous?". Neither
answers the useful question: what dies if I say yes? A risk opinion is formed from the command
text; it never opens the target. This plugin opens it, and then keeps a copy.

    impact report  ->  what is affected, what git can restore, what it cannot, what is valuable
    verified snapshot  ->  the bytes are copied out and checksummed before anything runs
    restore  ->  plan, confirm, write, verify
    policy  ->  relaxed / balanced / strict

Two rules shape the whole thing. First, nothing is guessed: a command the parser cannot follow
(bash -c chains it can resolve, subshells, `cd` sequences) is followed; anything genuinely opaque
(command substitution, ssh, eval, dynamic xargs) is reported as unmeasured, never estimated.
Second, nothing is claimed: a snapshot is only called verified when every copy re-reads to the
checksum taken from the original.

Implementation lives in `blastradius_core`; this file only registers it with Hermes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import blastradius_core  # noqa: E402
from blastradius_core import (  # noqa: E402
    ALLOW_TTL_S, blast_allow, blast_pin, blast_policy, blast_prune, blast_radius, blast_restore,
    blast_snapshot, blast_snapshots, on_pre_tool_call, set_store_dir, _blast_command,
)

# Legacy attribute kept for callers that set it directly (older tests, ad-hoc scripts).
_store_dir_override = None


def __getattr__(name):  # pragma: no cover - module-level compatibility shim
    """Let callers reach the core modules through this module (measure, report, set_policy...)."""
    if name == "_store_dir_override":
        return _store_dir_override
    import blastradius_core as _core

    try:
        return getattr(_core, name)
    except AttributeError:
        raise AttributeError(name) from None


_RADIUS_SCHEMA = {
    "name": "blast_radius",
    "description": (
        "Preview what a destructive command would delete, following bash -c wrappers, subshells "
        "and cd chains. Splits the result into files git can restore and files it cannot, flags "
        "valuable data (.env, databases, migrations) and a risk level. Runs nothing."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command you intend to run."},
            "cwd": {"type": "string", "description": "Directory it would run in (default: cwd)."},
        },
        "required": ["command"],
    },
}

_ALLOW_SCHEMA = {
    "name": "blast_allow",
    "description": (
        "Permit exactly one future execution of a specific destructive command. Spent on the next "
        "matching call. Under the strict policy a verified snapshot is created first."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The exact command string to allow."},
            "ttl_s": {"type": "integer", "description": "Seconds the grant stays valid (default 300)."},
        },
        "required": ["command"],
    },
}

_SNAPSHOT_SCHEMA = {
    "name": "blast_snapshot",
    "description": (
        "Copy every file a destructive command would destroy into a checksummed snapshot outside "
        "the target tree, verify the copies, and report what was excluded as rebuildable."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The destructive command to protect against."},
            "cwd": {"type": "string", "description": "Directory it would run in (default: cwd)."},
            "include_excluded": {
                "type": "boolean",
                "description": "Also snapshot build output that is normally excluded.",
            },
        },
        "required": ["command"],
    },
}

_SNAPSHOTS_SCHEMA = {
    "name": "blast_snapshots",
    "description": "List recovery snapshots with size, verification status, pin state and exclusions.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

_RESTORE_SCHEMA = {
    "name": "blast_restore",
    "description": (
        "Restore files from a snapshot. Without confirm it only reports what would change; with "
        "confirm it writes the files and verifies their checksums afterwards."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string", "description": "Snapshot id, prefix, or 'last'."},
            "confirm": {"type": "boolean", "description": "Actually write the files."},
        },
        "required": [],
    },
}

_POLICY_SCHEMA = {
    "name": "blast_policy",
    "description": "Read or set the risk policy: relaxed, balanced, or strict.",
    "parameters": {
        "type": "object",
        "properties": {"policy": {"type": "string", "description": "New policy (omit to read)."}},
        "required": [],
    },
}

_PRUNE_SCHEMA = {
    "name": "blast_prune",
    "description": (
        "Apply the snapshot retention limits (age, count, total size). Without confirm it only "
        "shows what would be deleted. Pinned and recently restored snapshots are never removed."
    ),
    "parameters": {
        "type": "object",
        "properties": {"confirm": {"type": "boolean", "description": "Actually delete."}},
        "required": [],
    },
}

_PIN_SCHEMA = {
    "name": "blast_pin",
    "description": "Pin or unpin a snapshot so retention never removes it.",
    "parameters": {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string", "description": "Snapshot id, prefix, or 'last'."},
            "pinned": {"type": "boolean", "description": "True to pin, false to unpin."},
        },
        "required": [],
    },
}


def _radius_handler(args: dict, **_) -> str:
    return blast_radius(str(args.get("command") or ""), args.get("cwd"))


def _allow_handler(args: dict, **_) -> str:
    return blast_allow(str(args.get("command") or ""), int(args.get("ttl_s") or ALLOW_TTL_S))


def _snapshot_handler(args: dict, **_) -> str:
    return blast_snapshot(str(args.get("command") or ""), args.get("cwd"),
                          bool(args.get("include_excluded")))


def _snapshots_handler(args: dict, **_) -> str:
    return blast_snapshots()


def _restore_handler(args: dict, **_) -> str:
    return blast_restore(str(args.get("snapshot_id") or "last"), bool(args.get("confirm")))


def _policy_handler(args: dict, **_) -> str:
    return blast_policy(str(args.get("policy") or ""))


def _prune_handler(args: dict, **_) -> str:
    return blast_prune(bool(args.get("confirm")))


def _pin_handler(args: dict, **_) -> str:
    return blast_pin(str(args.get("snapshot_id") or "last"), bool(args.get("pinned", True)))


def register(ctx) -> None:
    global _store_dir_override
    try:
        candidate = getattr(ctx, "plugin_data_dir", None)
        if callable(candidate):
            _store_dir_override = Path(candidate())
        elif isinstance(candidate, (str, Path)):
            _store_dir_override = Path(candidate)
        if _store_dir_override is not None:
            set_store_dir(_store_dir_override)
    except Exception:
        _store_dir_override = None

    ctx.register_hook("pre_tool_call", on_pre_tool_call)

    for schema, handler, description, emoji in (
        (_RADIUS_SCHEMA, _radius_handler, "Measure what a destructive command would delete.", "💥"),
        (_ALLOW_SCHEMA, _allow_handler, "Allow one confirmed destructive command exactly once.", "🔓"),
        (_SNAPSHOT_SCHEMA, _snapshot_handler, "Back up a command's targets before it runs.", "🧷"),
        (_SNAPSHOTS_SCHEMA, _snapshots_handler, "List recovery snapshots.", "🗂️"),
        (_RESTORE_SCHEMA, _restore_handler, "Restore files from a verified snapshot.", "♻️"),
        (_POLICY_SCHEMA, _policy_handler, "Read or set the risk policy.", "⚖️"),
        (_PRUNE_SCHEMA, _prune_handler, "Apply snapshot retention limits.", "🧹"),
        (_PIN_SCHEMA, _pin_handler, "Pin a snapshot so retention keeps it.", "📌"),
    ):
        ctx.register_tool(name=schema["name"], toolset="blastradius", schema=schema,
                          handler=handler, description=description, emoji=emoji)

    ctx.register_command(
        "blast",
        _blast_command,
        description="Preview impact, or manage snapshots, restore, policy and retention.",
        args_hint="<command> | snapshots | snapshot <cmd> [--include] | restore [id] [confirm] | "
                  "prune [confirm] | pin|unpin [id] | policy [name]",
    )
