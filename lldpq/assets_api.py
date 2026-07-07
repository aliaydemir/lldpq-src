#!/usr/bin/env python3
"""Validated, structured reader for the Assets web API."""

from __future__ import annotations

from datetime import datetime
import math
import os
from pathlib import Path
import time
from typing import Any

try:
    from .parse_devices import get_all_devices, load_devices_yaml
except ImportError:  # Installed scripts are also imported directly from LLDPQ_DIR.
    from parse_devices import get_all_devices, load_devices_yaml


ASSET_HEADER = (
    "DEVICE-NAME",
    "IP",
    "ETH0-MAC",
    "SERIAL",
    "MODEL",
    "RELEASE",
    "UPTIME",
    "STATUS",
    "LAST-SEEN",
)
ASSET_STATUSES = {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}
CREATED_FORMAT = "%Y-%m-%d %H-%M-%S"
LAST_SEEN_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")
INVENTORY_MTIME_TOLERANCE_SECONDS = 2.0


class AssetReportError(ValueError):
    """Raised when an Assets snapshot must not be presented as current."""


def _inventory_by_hostname(devices_path: Path) -> dict[str, dict[str, str]]:
    try:
        config = load_devices_yaml(str(devices_path))
        records = get_all_devices(config)
    except SystemExit as error:
        raise AssetReportError("inventory is invalid") from error

    inventory: dict[str, dict[str, str]] = {}
    for address, username, hostname, role in records:
        if hostname in inventory:
            raise AssetReportError(f"inventory contains duplicate hostname: {hostname}")
        inventory[hostname] = {
            "address": address,
            "username": username,
            "role": role or "N/A",
        }
    if not inventory:
        raise AssetReportError("inventory is empty")
    return inventory


def _positive_number(value: float | int, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise AssetReportError(f"invalid {name}") from error
    if not math.isfinite(result) or result < 0:
        raise AssetReportError(f"invalid {name}")
    return result


def load_assets_payload(
    assets_path: str | os.PathLike[str],
    devices_path: str | os.PathLike[str],
    *,
    max_age_seconds: float = 1800,
    timestamp_tolerance_seconds: float = 120,
    now: float | None = None,
) -> dict[str, Any]:
    """Return a validated API payload or fail closed with ``AssetReportError``."""

    asset_file = Path(assets_path)
    inventory_file = Path(devices_path)
    max_age = _positive_number(max_age_seconds, "maximum Assets age")
    tolerance = _positive_number(
        timestamp_tolerance_seconds, "Assets timestamp tolerance"
    )
    current_time = time.time() if now is None else float(now)

    try:
        metadata = asset_file.stat()
        lines = asset_file.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as error:
        raise AssetReportError(f"Assets report is unavailable: {error}") from error

    nonempty = [line.strip() for line in lines if line.strip()]
    if len(nonempty) < 3 or not nonempty[0].startswith("Created on "):
        raise AssetReportError("Assets report header is missing or invalid")
    if tuple(nonempty[1].split()) != ASSET_HEADER:
        raise AssetReportError("Assets report column header is invalid")

    created_text = nonempty[0].removeprefix("Created on ")
    try:
        created = datetime.strptime(created_text, CREATED_FORMAT)
    except ValueError as error:
        raise AssetReportError("Assets report creation time is invalid") from error
    created_epoch = created.timestamp()
    if abs(metadata.st_mtime - created_epoch) > tolerance:
        raise AssetReportError("Assets report timestamp does not match its publication time")
    if created_epoch > current_time + tolerance:
        raise AssetReportError("Assets report is from the future")
    age_seconds = current_time - created_epoch
    if age_seconds > max_age:
        raise AssetReportError(
            f"Assets report is stale ({int(age_seconds)} seconds old)"
        )

    inventory = _inventory_by_hostname(inventory_file)
    try:
        inventory_mtime = inventory_file.stat().st_mtime
    except OSError as error:
        raise AssetReportError(f"inventory is unavailable: {error}") from error
    if inventory_mtime > created_epoch + INVENTORY_MTIME_TOLERANCE_SECONDS:
        raise AssetReportError("inventory is newer than the Assets report")

    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for line in nonempty[2:]:
        parts = line.split()
        if len(parts) < len(ASSET_HEADER):
            raise AssetReportError(f"invalid Assets row: {line}")
        device_name = parts[0]
        if device_name in seen:
            raise AssetReportError(f"duplicate Assets row: {device_name}")
        seen.add(device_name)

        status = parts[7].upper()
        if status not in ASSET_STATUSES:
            raise AssetReportError(
                f"unknown status {parts[7]!r} in Assets row for {device_name}"
            )
        last_seen_parts = parts[8:]
        if len(last_seen_parts) > 2:
            raise AssetReportError(
                f"invalid last seen value in Assets row for {device_name}"
            )
        last_seen = " ".join(last_seen_parts).replace("_", " ")
        if last_seen != "Never":
            valid_last_seen = False
            for last_seen_format in LAST_SEEN_FORMATS:
                try:
                    datetime.strptime(last_seen, last_seen_format)
                except ValueError:
                    continue
                valid_last_seen = True
                break
            if not valid_last_seen:
                raise AssetReportError(
                    f"invalid last seen value in Assets row for {device_name}"
                )
        rows.append(
            {
                "device_name": device_name,
                "ip_address": parts[1],
                "mac_address": parts[2],
                "serial_number": parts[3],
                "role": inventory.get(device_name, {}).get("role", "N/A"),
                "model": parts[4],
                "release": parts[5],
                "uptime": parts[6],
                "status": status,
                "last_seen": last_seen,
            }
        )

    expected = set(inventory)
    if seen != expected:
        missing = sorted(expected - seen)
        unexpected = sorted(seen - expected)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing[:10]))
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected[:10]))
        raise AssetReportError(
            "Assets device set does not match inventory"
            + (": " + "; ".join(detail) if detail else "")
        )

    return {
        "success": True,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%S"),
        "age_seconds": max(0, int(age_seconds)),
        "total": len(rows),
        "rows": rows,
    }


def configured_max_age_seconds() -> float:
    """Read the shared freshness policy used by monitoring consumers."""

    try:
        minutes = float(os.environ.get("MONITOR_DATA_MAX_AGE_MINUTES", "30"))
        if not math.isfinite(minutes):
            raise ValueError("non-finite maximum age")
    except ValueError:
        minutes = 30.0
    return max(minutes, 0.0) * 60.0
