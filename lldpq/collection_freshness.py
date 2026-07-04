#!/usr/bin/env python3
"""Shared freshness checks for monitor raw-data consumers."""

import os
import re
import time
import tempfile
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

import yaml


ASSET_STATUSES = {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}
ASSET_HEADER = (
    "DEVICE-NAME", "IP", "ETH0-MAC", "SERIAL", "MODEL", "RELEASE",
    "UPTIME", "STATUS", "LAST-SEEN",
)
CREATED_PATTERN = re.compile(
    r"^Created on (\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2})$"
)


class AssetStatusMap(dict):
    """Dictionary-compatible status map with snapshot validation metadata."""

    def __init__(
        self,
        *args,
        snapshot_valid: bool = False,
        authoritative: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.snapshot_valid = snapshot_valid
        self.authoritative = authoritative


def _read_inventory_hosts(asset_path: Path) -> Tuple[Optional[Set[str]], bool]:
    """Return inventory hosts and whether an existing inventory parsed safely.

    A missing inventory is not an error: callers may still use a structurally
    valid assets snapshot for status/freshness checks, but must not use it to
    delete hosts as retired.
    """
    configured = os.environ.get("LLDPQ_DEVICES_FILE")
    inventory_path = Path(configured) if configured else asset_path.with_name("devices.yaml")
    if not inventory_path.is_file():
        return None, False

    try:
        config = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            return set(), False
        devices = config.get("devices")
        if not isinstance(devices, dict) or not devices:
            return set(), False

        hosts = set()
        for value in devices.values():
            if isinstance(value, str):
                hostname = re.sub(
                    r"\s+@[A-Za-z0-9_.-]+$", "", value.strip()
                )
            elif isinstance(value, dict):
                hostname = str(value.get("hostname", "unknown")).strip()
            else:
                return set(), False
            if not hostname or hostname in hosts:
                return set(), False
            hosts.add(hostname)
        return hosts, True
    except (OSError, yaml.YAMLError, UnicodeError):
        return set(), False


def asset_snapshot_is_valid(asset_snapshot) -> bool:
    statuses, _mtime, assets_available = asset_snapshot
    return bool(
        assets_available
        and getattr(statuses, "snapshot_valid", bool(statuses))
    )


def asset_snapshot_is_authoritative(asset_snapshot) -> bool:
    statuses, _mtime, assets_available = asset_snapshot
    return bool(
        assets_available
        and getattr(statuses, "authoritative", bool(statuses))
    )


def read_asset_snapshot(path: str = "assets.ini") -> Tuple[Dict[str, str], float, bool]:
    """Return validated hostname statuses, snapshot mtime, and file presence.

    A present but malformed or inventory-mismatched file returns an empty map
    with ``assets_available=True``. That intentionally makes freshness checks
    fail closed while preserving existing raw artifacts.
    """
    asset_path = Path(os.environ.get("LLDPQ_ASSETS_FILE", path))
    try:
        snapshot_mtime = asset_path.stat().st_mtime
        lines = asset_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return AssetStatusMap(), 0.0, False

    created_at = None
    header_index = None
    for index, line in enumerate(lines):
        match = CREATED_PATTERN.fullmatch(line.strip())
        if match and created_at is None:
            try:
                created_at = datetime.strptime(
                    match.group(1), "%Y-%m-%d %H-%M-%S"
                ).timestamp()
            except ValueError:
                created_at = None
        if tuple(line.split()) == ASSET_HEADER:
            header_index = index
            break

    if created_at is None or header_index is None:
        return AssetStatusMap(), snapshot_mtime, True

    try:
        timestamp_tolerance = max(
            float(os.environ.get("ASSET_TIMESTAMP_TOLERANCE_SECONDS", "120")),
            0.0,
        )
    except ValueError:
        timestamp_tolerance = 120.0
    now = time.time()
    if (
        abs(snapshot_mtime - created_at) > timestamp_tolerance
        or created_at > now + timestamp_tolerance
        or now - created_at > max_data_age_seconds()
    ):
        return AssetStatusMap(), snapshot_mtime, True

    statuses: Dict[str, str] = {}
    for line in lines[header_index + 1:]:
        parts = line.split()
        if not parts:
            continue
        if len(parts) < len(ASSET_HEADER):
            return AssetStatusMap(), snapshot_mtime, True
        hostname = parts[0]
        status = parts[7].upper()
        if status not in ASSET_STATUSES or hostname in statuses:
            return AssetStatusMap(), snapshot_mtime, True
        statuses[hostname] = status

    if not statuses:
        return AssetStatusMap(), snapshot_mtime, True

    inventory_hosts, inventory_valid = _read_inventory_hosts(asset_path)
    if inventory_hosts is not None:
        if not inventory_valid or inventory_hosts != set(statuses):
            return AssetStatusMap(), snapshot_mtime, True

        configured = os.environ.get("LLDPQ_DEVICES_FILE")
        inventory_path = (
            Path(configured) if configured else asset_path.with_name("devices.yaml")
        )
        try:
            # A newer inventory may have changed even when the hostname set is
            # unchanged; require assets.sh to refresh it before destructive use.
            if inventory_path.stat().st_mtime > created_at + 2:
                return AssetStatusMap(), snapshot_mtime, True
        except OSError:
            return AssetStatusMap(), snapshot_mtime, True

    validated = AssetStatusMap(
        statuses,
        snapshot_valid=True,
        authoritative=inventory_hosts is not None and inventory_valid,
    )
    return validated, snapshot_mtime, True


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


def mark_html_collection_unavailable(output_file: str) -> None:
    """Atomically add an explicit no-current-telemetry banner to an HTML report."""
    path = Path(output_file)
    content = path.read_text(encoding="utf-8")
    marker = 'data-collection-status="unavailable"'
    if marker in content:
        return
    message = html.escape(
        "No current device telemetry is available because every inventory "
        "device was unreachable during this collection."
    )
    banner = (
        f'<div {marker} style="margin:16px 0;padding:12px;border-left:4px '
        f'solid #ff9800;background:#332b20;color:#ffcc80">{message}</div>'
    )
    updated, count = re.subn(
        r'(<body(?:\s[^>]*)?>)', r'\1' + banner, content, count=1,
        flags=re.IGNORECASE,
    )
    if count != 1:
        raise ValueError(f"HTML report has no body element: {path}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o7777)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
