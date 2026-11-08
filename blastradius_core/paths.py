"""Shared paths, config and small helpers.

Kept separate so measure/snapshot/restore/policy do not import each other in a cycle.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

OVERRIDE_ENV = "BLASTRADIUS_ALLOW"
POLICY_ENV = "BLASTRADIUS_POLICY"
SNAPSHOT_DIR_ENV = "BLASTRADIUS_SNAPSHOT_DIR"

MAX_AGE_ENV = "BLASTRADIUS_SNAP_MAX_AGE_DAYS"
MAX_COUNT_ENV = "BLASTRADIUS_SNAP_MAX_COUNT"
MAX_MB_ENV = "BLASTRADIUS_SNAP_MAX_TOTAL_MB"

_store_dir_override: Path | None = None


def data_dir() -> Path:
    if _store_dir_override is not None:
        path = _store_dir_override
    else:
        home = os.environ.get("HERMES_HOME") or str(Path.home() / ".hermes")
        path = Path(home) / "plugin-data" / "blastradius"
    path.mkdir(parents=True, exist_ok=True)
    return path


def set_store_dir(path: Path | None) -> None:
    global _store_dir_override
    _store_dir_override = path


def snapshot_root() -> Path:
    """Snapshots live outside the tree they protect, so a command cannot eat them."""
    override = os.environ.get(SNAPSHOT_DIR_ENV)
    root = Path(override) if override else data_dir() / "snapshots"
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


@dataclass(frozen=True)
class Retention:
    """Snapshot retention limits. Defaults are deliberately conservative."""

    max_age_days: int = 14
    max_count: int = 20
    max_total_mb: int = 2048

    @classmethod
    def load(cls) -> "Retention":
        return cls(
            max_age_days=_int_env(MAX_AGE_ENV, 14),
            max_count=_int_env(MAX_COUNT_ENV, 20),
            max_total_mb=_int_env(MAX_MB_ENV, 2048),
        )


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def free_bytes(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0


# Directories that are rebuilt, not restored: backing them up wastes the snapshot budget.
DEFAULT_EXCLUDES = (
    "node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build",
    ".next", ".nuxt", ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "target", "coverage", ".turbo", ".parcel-cache",
)


def is_excluded(path: Path, excludes=DEFAULT_EXCLUDES) -> bool:
    return any(part in excludes for part in path.parts)
