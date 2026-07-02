#!/usr/bin/env python3
"""Shared freshness checks for monitor raw-data consumers."""

import os
import time
from pathlib import Path
from typing import Dict, Tuple


ASSET_STATUSES = {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}


def read_asset_snapshot(path: str = "assets.ini") -> Tuple[Dict[str, str], float, bool]:
    """Return hostname statuses, snapshot mtime, and whether the snapshot exists."""
    asset_path = Path(os.environ.get("LLDPQ_ASSETS_FILE", path))
    try:
        snapshot_mtime = asset_path.stat().st_mtime
        lines = asset_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}, 0.0, False

    statuses: Dict[str, str] = {}
    for line in lines:
        parts = line.split()
        if not parts or parts[0] in {"Created", "DEVICE-NAME"}:
            continue
        status = next(
            (part.upper() for part in parts[1:] if part.upper() in ASSET_STATUSES),
            None,
        )
        if status:
            statuses[parts[0]] = status
    return statuses, snapshot_mtime, True


def max_data_age_seconds() -> float:
    try:
        minutes = float(os.environ.get("MONITOR_DATA_MAX_AGE_MINUTES", "30"))
    except ValueError:
        minutes = 30.0
    return max(minutes, 0.0) * 60.0


def is_current_collection(
    filepath: str,
    hostname: str,
    asset_snapshot=None,
) -> bool:
    """True only when a raw file belongs to a current successful collection."""
    try:
        file_mtime = os.path.getmtime(filepath)
    except OSError:
        return False

    if time.time() - file_mtime > max_data_age_seconds():
        return False

    statuses, asset_mtime, assets_available = (
        asset_snapshot if asset_snapshot is not None else read_asset_snapshot()
    )
    if assets_available:
        # assets.ini is the inventory snapshot for this run. Missing hosts are
        # retired/not-current; non-OK hosts did not produce trustworthy data.
        if statuses.get(hostname) != "OK":
            return False
        if asset_mtime > file_mtime + 1:
            return False
    return True
