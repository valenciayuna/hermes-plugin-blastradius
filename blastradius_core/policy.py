"""Risk policies: how much friction a destructive command should cost."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .paths import data_dir

POLICY_ENV = "BLASTRADIUS_POLICY"
DEFAULT_POLICY = "balanced"
POLICIES = ("relaxed", "balanced", "strict")

DETAIL = {
    "relaxed": "report the impact, block only high-impact changes",
    "balanced": "block when untracked data would not be recoverable from git",
    "strict": "block every measured destructive call until a verified snapshot exists",
}


def _policy_file() -> Path:
    return data_dir() / "policy.json"


def get_policy() -> str:
    env = os.environ.get(POLICY_ENV, "").strip().lower()
    if env in POLICIES:
        return env
    path = _policy_file()
    if path.is_file():
        try:
            value = str(json.loads(path.read_text(encoding="utf-8")).get("policy", "")).lower()
            if value in POLICIES:
                return value
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_POLICY


def set_policy(policy: str) -> str:
    policy = (policy or "").strip().lower()
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {', '.join(POLICIES)}")
    try:
        _policy_file().write_text(json.dumps({"policy": policy}), encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"could not save policy: {exc}") from exc
    return policy


def blocks(analysis: dict, partial: bool = False) -> tuple[bool, str]:
    """(does this policy stop the command, one-line reason)."""
    policy = get_policy()
    untracked = analysis.get("untracked", 0)
    valuable = len(analysis.get("valuable", []))
    size = analysis.get("bytes", 0)

    if policy == "strict":
        return True, "strict: every measured destructive call needs a verified snapshot"
    if policy == "relaxed":
        if untracked >= 10 or valuable >= 3 or size >= 50 * 1024 * 1024 or partial:
            return True, "relaxed: high-impact change or an unmeasured part"
        return False, "relaxed: below the reporting threshold"
    if partial:
        return True, "balanced: part of this command could not be measured"
    return untracked >= 1, "balanced: untracked data would not be recoverable from git"


def describe(new_policy: str = "") -> str:
    if new_policy:
        try:
            set_policy(new_policy)
        except (ValueError, RuntimeError) as exc:
            return f"[blastradius] {exc}"
    current = get_policy()
    return f"[blastradius] policy: {current} — {DETAIL[current]}"
