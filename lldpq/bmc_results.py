#!/usr/bin/env python3
"""Compare BMC expectations with independently validated switch FDB/link data."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path

try:
    from .bmc_config import BMCValidationError, PORT_PATTERN, get_config, normalize_mac
except ImportError:
    from bmc_config import BMCValidationError, PORT_PATTERN, get_config, normalize_mac


STATUSES = ("MATCH", "MISMATCH", "WRONG_PORT", "NOT_SEEN", "PORT_DOWN", "UNKNOWN", "STALE", "DISABLED")
EXCLUDED_FLAGS = {"self", "local", "router", "permanent", "static", "extern_learn", "extern_learned"}


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        result = parsed.timestamp()
        return result if math.isfinite(result) else None
    except (ValueError, OverflowError):
        return None


def _vlan(value):
    if value is None or value == "":
        return None
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    return value if type(value) is int and 1 <= value <= 4094 else False


def _port_state(port):
    if not isinstance(port, dict):
        return "UNKNOWN"
    if port.get("admin_up") is False or port.get("carrier") is False:
        return "DOWN"
    state = str(port.get("operstate", "UNKNOWN")).upper()
    if state in {"DOWN", "LOWERLAYERDOWN", "NOTPRESENT"}:
        return "DOWN"
    if state == "UP" and port.get("admin_up") is not False:
        return "UP"
    return "UNKNOWN"


def _load_observation(directory_fd, hostname, now, max_age):
    observation = {"available": False, "current": False, "stale": False,
                   "checked_at": None, "ports": {}, "entries": [], "history": {},
                   "fdb_ok": False, "link_ok": False, "reason": "No BMC collection is available for this switch."}
    try:
        descriptor = os.open(f"{hostname}.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return observation
        if payload.get("hostname", hostname).casefold() != hostname.casefold():
            return observation
        data = payload.get("bmc")
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return observation
        observed = _timestamp(data.get("checked_at"))
        observation["checked_at"] = data.get("checked_at") if observed is not None else None
        observation["available"] = True
        observation["current"] = observed is not None and -120 <= now - observed <= max_age
        observation["stale"] = observed is not None and now - observed > max_age
        observation["fdb_ok"] = data.get("fdb_status") == "ok"
        observation["link_ok"] = data.get("link_status") == "ok"
        observation["ports"] = data.get("ports") if isinstance(data.get("ports"), dict) else {}
        history = defaultdict(list)
        if isinstance(data.get("last_seen"), dict):
            for key, value in data["last_seen"].items():
                if not isinstance(key, str):
                    continue
                parts = key.split("|")
                if len(parts) != 3:
                    continue
                port, mac, raw_vlan = parts
                vlan, seen = _vlan(raw_vlan), _timestamp(value)
                if vlan is not False and seen is not None and seen <= now + 120:
                    history[(port, mac)].append((vlan, seen, value))
        observation["history"] = history
        raw_macs = data.get("macs")
        if not isinstance(raw_macs, list):
            observation["fdb_ok"] = False
            raw_macs = []
        if not isinstance(data.get("ports"), dict):
            observation["link_ok"] = False
        entries = []
        for entry in raw_macs:
            if not isinstance(entry, dict):
                observation["fdb_ok"] = False
                continue
            port = entry.get("port")
            flags = entry.get("flags", [])
            if not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
                observation["fdb_ok"] = False
                continue
            # Never project a bond FDB entry onto a physical member, nor use
            # remote EVPN or the switch's own hardware address as BMC evidence.
            if (not isinstance(port, str) or not PORT_PATTERN.fullmatch(port)
                    or entry.get("is_local") is not True
                    or entry.get("is_remote") is not False
                    or entry.get("is_static") is not False
                    or EXCLUDED_FLAGS.intersection(flag.lower() for flag in flags)
                    or entry.get("dst")):
                continue
            port_data = observation["ports"].get(port, {})
            if not isinstance(port_data, dict):
                continue
            if port_data.get("is_uplink") is True or port_data.get("is_physical") is False:
                continue
            if port_data.get("kind") in {"bond", "bridge", "vxlan", "vlan", "vrf"}:
                continue
            vlan = _vlan(entry.get("vlan"))
            if vlan is False:
                observation["fdb_ok"] = False
                continue
            try:
                mac = normalize_mac(entry.get("mac"))
            except BMCValidationError:
                # Multicast/all-zero switch table entries are normal and do
                # not make a completed FDB collection fail.
                continue
            entries.append({"mac": mac, "port": port, "vlan": vlan})
        observation["entries"] = entries
        observation["reason"] = "The latest MAC or port collection failed."
        if observed is None or now - observed < -120:
            observation["reason"] = "The collection timestamp is missing or invalid."
        return observation
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        return observation


def _last_seen(observation, mapping, now):
    candidates = [(timestamp, value) for vlan, timestamp, value in
                  observation["history"].get((mapping["port"], mapping["expected_mac"]), [])
                  if mapping["vlan"] is None or mapping["vlan"] == vlan]
    return max(candidates)[1] if candidates else None


def get_results(devices_path, bmc_path, tables_dir, *, now=None, max_age_seconds=900):
    """Render saved expectations against read-only cached BMC observations.

    Only configured BMC ports are searched for moves: an uplink carrying a
    remote switch's MAC must not become a false WRONG_PORT result.
    """
    config = get_config(devices_path, bmc_path)
    now = datetime.now(timezone.utc).timestamp() if now is None else float(now)
    max_age = max(1, float(max_age_seconds))
    names = {switch["hostname"].casefold(): switch["hostname"] for switch in config["switches"]}
    enabled_ports = {(row["switch"].casefold(), row["port"])
                     for row in config["mappings"] if row["enabled"]}
    observations = {}
    by_port = defaultdict(list)
    by_mac = defaultdict(list)
    try:
        directory_fd = os.open(Path(tables_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        directory_fd = None
    if directory_fd is not None:
        try:
            # Pin the directory inode, not its pathname. Publication swaps
            # directories atomically; a reader must never combine old switch A
            # with new switch B and report a spurious move. Concurrent removal
            # of an old generation can only make its unread files UNKNOWN.
            for switch in sorted({switch for switch, _port in enabled_ports}):
                if switch in names:
                    observations[switch] = _load_observation(directory_fd, names[switch], now, max_age)
        finally:
            os.close(directory_fd)
    for switch, observation in observations.items():
        for entry in observation["entries"]:
            if (switch, entry["port"]) not in enabled_ports or not observation["fdb_ok"]:
                continue
            by_port[(switch, entry["port"])].append(entry)
            if (observation["current"] and observation["fdb_ok"] and observation["link_ok"]
                    and _port_state(observation["ports"].get(entry["port"])) == "UP"):
                by_mac[entry["mac"]].append({"switch": names[switch], "port": entry["port"],
                                             "vlan": entry["vlan"]})
    rows = []
    counts = {status: 0 for status in STATUSES}
    for mapping in config["mappings"]:
        switch = mapping["switch"].casefold()
        observation = observations.get(switch)
        candidates = by_port.get((switch, mapping["port"]), [])
        entries = [entry for entry in candidates if mapping["vlan"] is None or entry["vlan"] == mapping["vlan"]]
        active = sorted({entry["mac"] for entry in entries})
        locations = [entry for entry in by_mac.get(mapping["expected_mac"], [])
                     if mapping["vlan"] is None or entry["vlan"] == mapping["vlan"]]
        locations = [dict(values) for values in sorted({tuple(item.items()) for item in locations}, key=str)]
        row = {**mapping, "switch": names.get(switch, mapping["switch"]),
               "active_macs": active, "observed_locations": locations, "warnings": [],
               "link_state": "UNKNOWN", "observed_at": observation["checked_at"] if observation else None,
               "last_seen": _last_seen(observation, mapping, now) if observation else None}
        if len(active) > 1:
            row["warnings"].append("MULTIPLE_MACS")
        if len(locations) > 1:
            row["warnings"].append("AMBIGUOUS")
        port_data = observation["ports"].get(mapping["port"]) if observation else None
        if observation and observation["current"] and observation["link_ok"]:
            row["link_state"] = _port_state(port_data)
        if not mapping["enabled"]:
            status, detail = "DISABLED", "This mapping is disabled."
        elif switch not in names:
            status, detail = "UNKNOWN", "The configured switch is no longer in devices.yaml."
        elif not observation or not observation["available"]:
            status, detail = "UNKNOWN", "No BMC collection is available for this switch."
        elif observation["stale"]:
            status, detail = "STALE", "Cached observations are too old; run a scan before comparing."
        elif not observation["current"]:
            status, detail = "UNKNOWN", observation["reason"]
        elif isinstance(port_data, dict) and port_data.get("is_uplink") is True:
            status, detail = "UNKNOWN", "This port is a known switch uplink, not a direct BMC connection."
        elif isinstance(port_data, dict) and (port_data.get("is_physical") is False or
                port_data.get("kind") in {"bond", "bridge", "vxlan", "vlan", "vrf"}):
            status, detail = "UNKNOWN", "The configured port is not a physical BMC access port."
        elif row["link_state"] == "DOWN":
            status, detail = "PORT_DOWN", "The latest port collection reports the link down."
        elif not observation["fdb_ok"] or not observation["link_ok"]:
            status, detail = "UNKNOWN", observation["reason"]
        elif not isinstance(port_data, dict) or row["link_state"] != "UP":
            status, detail = "UNKNOWN", "The configured physical port has no usable current link state."
        elif mapping["expected_mac"] in active:
            status, detail = "MATCH", "The expected MAC is learned on this port; BMC application health is not checked."
            row["last_seen"] = observation["checked_at"]
        elif locations:
            status, detail = "WRONG_PORT", "The expected MAC is currently learned on another configured BMC port."
        elif active:
            status, detail = "MISMATCH", "Different MAC addresses are learned on this port; the expected MAC is absent."
        else:
            status, detail = "NOT_SEEN", "The link is up, but no matching MAC is learned. A quiet BMC can age out of the MAC table."
        row.update(status=status, detail=detail)
        counts[status] += 1
        rows.append(row)
    return {"success": True, "revision": config["revision"], "rows": rows,
            "summary": {"total": len(rows), **counts},
            "generated_at": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "max_age_seconds": max_age, "orphaned_switches": config["orphaned_switches"]}
