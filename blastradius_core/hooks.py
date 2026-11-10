"""The Hermes-facing surface: the pre_tool_call hook, the tools, and the /blast command."""

from __future__ import annotations

from pathlib import Path

from . import policy as pol
from . import recovery as rec
from . import snapshot as snap
from .measure import MAX_DEPTH, looks_destructive, measure, report
from .paths import OVERRIDE_ENV, human_bytes, truthy

ALLOW_TTL_S = rec.ALLOW_TTL_S


# ------------------------------------------------------------------------- hook


def on_pre_tool_call(tool_name: str = "", args=None, **_):
    """Block a destructive terminal call until its impact is on the record."""
    if tool_name != "terminal" or not isinstance(args, dict):
        return None
    command = args.get("command") or args.get("cmd")
    if not isinstance(command, str) or not command.strip():
        return None
    if truthy(OVERRIDE_ENV):
        return None

    policy = pol.get_policy()
    analysis = measure(command, args.get("workdir") or args.get("cwd"))

    if not analysis.get("measured"):
        if not looks_destructive(command):
            return None
        if policy == "strict":
            return {
                "action": "block",
                "message": (
                    "[blastradius] strict policy: this command matches a destructive shape but "
                    "its target cannot be measured, so its impact is unknown.\n"
                    f"   Narrow it to something the parser can follow, or run it deliberately "
                    f"with {OVERRIDE_ENV}=1."
                ),
            }
        return {
            "action": "block",
            "message": (
                "[blastradius] this command cannot be measured, so its blast radius is unknown:\n"
                f"   {analysis.get('reason')}\n\n"
                "   It was not executed. Show the user this, then confirm and call "
                f'blast_allow("{command.strip()}") to permit it once, '
                f"or set {OVERRIDE_ENV}=1 for the session."
            ),
        }

    if analysis["files"] == 0:
        return None
    if rec.consume_allow(command.strip()):
        return None

    blocked, reason = pol.blocks(analysis, partial=analysis.get("partial", False))
    if not blocked:
        return None

    text = report(analysis, command.strip())
    if policy == "strict":
        text += ("\n\nStrict policy: authorise with blast_allow, which takes a verified snapshot "
                 "first and withholds the grant if the snapshot fails.")
    text += (
        f"\n\nThis command was not executed ({reason}). Show the user these numbers, then either "
        "narrow the target, or confirm and call "
        f'blast_allow("{command.strip()}") to permit this exact command once '
        f"(valid {ALLOW_TTL_S // 60} minutes), or set {OVERRIDE_ENV}=1 for a session-wide override."
    )
    return {"action": "block", "message": text}


# ------------------------------------------------------------------------ tools


def blast_radius(command: str, cwd: str | None = None) -> str:
    return report(measure(command, cwd), command)


def blast_allow(command: str, ttl_s: int = ALLOW_TTL_S) -> str:
    """Permit one future execution. Under strict, a verified snapshot is required first."""
    if not isinstance(command, str) or not command.strip():
        return "[blastradius] need the exact command string to allow"
    command = command.strip()
    ttl = max(1, min(int(ttl_s or ALLOW_TTL_S), 3600))

    note = ""
    if pol.get_policy() == "strict":
        analysis = measure(command)
        if not analysis.get("measured") or analysis["files"] == 0:
            return ("[blastradius] strict policy: cannot measure this command, so no grant was "
                    "issued. Narrow the target first.")
        created = snap.create_snapshot(analysis, command)
        if not created.get("ok") or not created.get("verified"):
            return (f"[blastradius] strict policy: snapshot failed "
                    f"({created.get('error', 'unverified')}). No grant issued; the command "
                    "stays blocked.")
        note = (f"\nsnapshot {created['id']} verified ({created['count']} files, "
                f"{human_bytes(created['bytes'])})")

    info = rec.grant_allow(command, ttl)
    return (f"[blastradius] allowed once: {info['command']}\n"
            f"valid for {info['ttl_s'] // 60} minute(s). Spent on the next matching call.{note}")


def blast_snapshot(command: str, cwd: str | None = None, include_excluded: bool = False) -> str:
    analysis = measure(command, cwd)
    if not analysis.get("measured"):
        return f"[blastradius] cannot snapshot: {analysis.get('reason')}"
    if analysis["files"] == 0:
        return "[blastradius] nothing to snapshot, the target is empty"

    created = snap.create_snapshot(analysis, command, include_excluded=include_excluded)
    if not created.get("ok"):
        return f"[blastradius] snapshot FAILED: {created.get('error')}. Do not run the command."

    status = "verified" if created["verified"] else "FAILED verification"
    lines = [
        f"[blastradius] snapshot {created['id']} {status}",
        f"  files snapshotted: {created['count']}  size: {human_bytes(created['bytes'])}",
        f"  links skipped: {created['skipped_links']}",
    ]
    if created.get("excluded"):
        lines.append(f"  not snapshotted (excluded): {created['excluded']} files — these are "
                     "rebuilt, not restored")
    if created.get("pruned"):
        lines.append(f"  retention removed {len(created['pruned'])} older snapshot(s)")
    lines.append(f'  restore with: /blast restore {created["id"]}')
    return "\n".join(lines)


def blast_snapshots() -> str:
    return snap.describe_list(snap.list_snapshots())


def blast_restore(snap_id: str = "last", confirm: bool = False,
                  overwrite_conflicts: bool = False) -> str:
    return rec.describe_restore(rec.restore(snap_id, confirm=confirm,
                                            overwrite_conflicts=overwrite_conflicts))


def blast_policy(new_policy: str = "") -> str:
    return pol.describe(new_policy)


def blast_prune(confirm: bool = False) -> str:
    return snap.describe_prune(snap.prune(plan=not confirm))


def blast_pin(snap_id: str = "last", pinned: bool = True) -> str:
    result = snap.set_pinned(snap_id, pinned)
    if not result.get("ok"):
        return f"[blastradius] {result.get('error')}"
    word = "pinned" if result["pinned"] else "unpinned"
    return f"[blastradius] snapshot {result['id']} {word}. Pinned snapshots are never pruned."


def _blast_command(raw_args: str) -> str:
    text = (raw_args or "").strip()
    if not text:
        return blast_radius("rm -rf .")
    words = text.split()
    head = words[0]

    if head == "restore":
        snap_id = words[1] if len(words) > 1 and not words[1] == "confirm" else "last"
        return blast_restore(snap_id,
                             confirm="confirm" in words or "--confirm" in words,
                             overwrite_conflicts="--overwrite" in words)
    if head == "snapshots":
        return blast_snapshots()
    if head == "snapshot":
        rest = text[len("snapshot"):].strip()
        include = "--include" in rest
        return blast_snapshot(rest.replace("--include", "").strip() or "rm -rf .",
                              include_excluded=include)
    if head == "prune":
        return blast_prune(confirm="confirm" in words or "--confirm" in words)
    if head in {"pin", "unpin"}:
        snap_id = words[1] if len(words) > 1 else "last"
        return blast_pin(snap_id, pinned=head == "pin")
    if head == "policy":
        return blast_policy(text[len("policy"):].strip())
    return blast_radius(text)


__all__ = [
    "ALLOW_TTL_S", "MAX_DEPTH", "blast_allow", "blast_pin", "blast_policy", "blast_prune",
    "blast_radius", "blast_restore", "blast_snapshot", "blast_snapshots", "on_pre_tool_call",
    "_blast_command",
]
