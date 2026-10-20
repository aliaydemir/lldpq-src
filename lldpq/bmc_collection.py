#!/usr/bin/env python3
"""Add independent BMC observations to the existing atomic fabric snapshot.

The fabric scanner supplies one remote stdout bundle per switch.  A broken
route/ARP command must not discard a successful FDB or link observation, and
an empty successful FDB must remain distinguishable from a failed command.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time

import yaml


MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
PHYSICAL_PORT = re.compile(r"swp\d+(?:s\d+)?\Z")
FDB_FLAGS = frozenset(("self", "master", "static", "permanent", "dynamic",
                       "extern_learn", "offload", "sticky", "router", "local"))


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def closed_sections(raw: str) -> dict[str, list[str]]:
    """Only accept a section whose closing/next marker actually arrived."""
    result = {}
    current = None
    lines = []
    for line in raw.splitlines():
        if re.fullmatch(r"===[A-Z_]+===", line.strip()):
            if current is not None:
                # Duplicated source markers make that source ambiguous.
                result[current] = (lines if current not in result else
                                   ["__LLDPQ_COLLECTION_ERROR__:DUPLICATE"])
            current = line.strip()[3:-3]
            lines = []
        elif current is not None:
            lines.append(line)
    return result


def parse_fdb(lines: list[str] | None) -> list[dict]:
    if lines is None:
        raise ValueError("FDB section is missing or incomplete")
    result = []
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if line.startswith("__LLDPQ_COLLECTION_ERROR__:"):
            raise ValueError("FDB command failed")
        mac = parts[0].lower()
        if not MAC.fullmatch(mac) or "dev" not in parts:
            raise ValueError("FDB output is malformed")

        def token(key: str) -> str:
            position = parts.index(key) if key in parts else -1
            if position < 0:
                return ""
            if position + 1 >= len(parts):
                raise ValueError("FDB output is truncated")
            return parts[position + 1]

        port = token("dev")
        vlan_text = token("vlan")
        if vlan_text and (not vlan_text.isdigit() or not 1 <= int(vlan_text) <= 4094):
            raise ValueError("FDB VLAN is invalid")
        flags = sorted(FDB_FLAGS.intersection(parts))
        remote = bool(token("dst")) or "extern_learn" in flags
        static = bool({"permanent", "static"}.intersection(flags))
        self_entry = bool({"self", "local", "router"}.intersection(flags))
        unicast = mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 1
        result.append({
            "mac": mac, "port": port, "vlan": int(vlan_text) if vlan_text else None,
            "flags": flags, "is_remote": remote, "is_static": static,
            "is_local": bool(unicast and not remote and not self_entry and not static
                             and PHYSICAL_PORT.fullmatch(port)),
        })
    return result


def parse_links(lines: list[str] | None, uplinks: set[str]) -> dict:
    if lines is None:
        raise ValueError("Link section is missing or incomplete")
    if any(line.startswith("__LLDPQ_COLLECTION_ERROR__:") for line in lines):
        raise ValueError("Link command failed")
    try:
        value = json.loads("\n".join(lines))
    except ValueError as exc:
        raise ValueError("Link output is malformed") from exc
    if not isinstance(value, list) or not value:
        raise ValueError("Link output has no interfaces")
    ports = {}
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get("ifname"), str):
            raise ValueError("Link interface is invalid")
        name = entry["ifname"]
        flags = entry.get("flags")
        if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
            raise ValueError("Link flags are invalid")
        operstate = entry.get("operstate", "UNKNOWN")
        if not isinstance(operstate, str):
            raise ValueError("Link state is invalid")
        linkinfo = entry.get("linkinfo") or {}
        if not isinstance(linkinfo, dict):
            raise ValueError("Link metadata is invalid")
        kind = linkinfo.get("info_kind", "")
        carrier = (True if "LOWER_UP" in flags else False
                   if "NO-CARRIER" in flags or operstate.upper() == "DOWN" else None)
        ports[name] = {
            "operstate": operstate.upper(), "admin_up": "UP" in flags,
            "carrier": carrier, "kind": kind, "master": entry.get("master", ""),
            # NVIDIA Spectrum switch ports advertise the sx_netdev rtnl
            # kind.  It is a physical port driver, not a virtual interface.
            "is_physical": bool(PHYSICAL_PORT.fullmatch(name) and kind in ("", "sx_netdev")),
            "is_uplink": name in uplinks,
        }
    return ports


def observe(raw: str, previous: dict, mappings: list[dict], *,
            checked_at: str | None = None, uplinks: set[str] | None = None) -> dict:
    checked_at = checked_at or datetime.now(timezone.utc).isoformat()
    sections = closed_sections(raw)
    result = {
        "schema_version": 1, "checked_at": checked_at,
        "fdb_status": "error", "link_status": "error",
        "fdb_error": None, "link_error": None, "ports": {}, "macs": [],
    }
    for source, marker, parser, destination in (
        ("fdb", "MAC", parse_fdb, "macs"),
        ("link", "BMC_LINK", lambda lines: parse_links(lines, uplinks or set()), "ports"),
    ):
        try:
            result[destination] = parser(sections.get(marker))
            result[source + "_status"] = "ok"
        except (ValueError, TypeError) as exc:
            result[source + "_error"] = str(exc)

    # Keep history only for currently configured expectations.  Never grow a
    # second complete FDB database or stamp an old entry with today's time.
    wanted = {(str(row.get("port", "")), str(row.get("expected_mac", "")).lower(),
               row.get("vlan")) for row in mappings if row.get("enabled", True)}
    previous_history = previous.get("last_seen", {})
    previous_history = previous_history if isinstance(previous_history, dict) else {}
    history = {}
    for key, value in previous_history.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        try:
            port, mac, vlan_text = key.split("|")
            vlan = int(vlan_text) if vlan_text else None
        except ValueError:
            continue
        if (port, mac, vlan) in wanted or (port, mac, None) in wanted:
            history[key] = value
    if result["fdb_status"] == "ok":
        for entry in result["macs"]:
            identity = (entry["port"], entry["mac"], entry["vlan"])
            if (entry["is_local"] and entry["port"] not in (uplinks or set()) and
                    (identity in wanted or (identity[0], identity[1], None) in wanted)):
                key = f'{identity[0]}|{identity[1]}|{identity[2] or ""}'
                history[key] = checked_at
    result["last_seen"] = history
    return result


def merge_snapshots(inventory: Path, raw_dir: Path, staged_dir: Path,
                    previous_dir: Path, config: Path, lldp: Path) -> None:
    rows = [line.split("\t", 2) for line in inventory.read_text().splitlines() if line]
    known_switches = {row[2].casefold() for row in rows}
    configured = {}
    try:
        content = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
        for row in content.get("mappings", []):
            if (isinstance(row, dict) and isinstance(row.get("switch"), str)
                    and PHYSICAL_PORT.fullmatch(str(row.get("port", "")))
                    and MAC.fullmatch(str(row.get("expected_mac", "")).lower())
                    and (row.get("vlan") is None or
                         type(row["vlan"]) is int and 1 <= row["vlan"] <= 4094)):
                configured.setdefault(str(row.get("switch", "")).casefold(), []).append(row)
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError):
        # Invalid inventory is reported by the mappings API; other fabric
        # consumers must continue to receive their network tables.
        pass
    neighbors = {}
    try:
        if 0 <= time.time() - lldp.stat().st_mtime <= 900:
            neighbors = read_json(lldp).get("neighbors", {})
    except OSError:
        pass
    neighbors = neighbors if isinstance(neighbors, dict) else {}
    neighbors = {str(key).casefold(): value for key, value in neighbors.items()}
    for address, _username, hostname in rows:
        old = read_json(previous_dir / f"{hostname}.json")
        destination = staged_dir / f"{hostname}.json"
        data = read_json(destination)
        if not data:
            data = {"_collection": {"status": "unavailable", "address": address,
                                     "error": "fabric_collection_unavailable"}}
        try:
            raw = (raw_dir / f"{hostname}.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = ""
        try:
            checked_at = (raw_dir / f"{hostname}.checked-at").read_text().strip()
            datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        except (OSError, ValueError):
            checked_at = None
        peer_ports = neighbors.get(hostname.casefold(), {})
        uplinks = {
            port for port, peer in peer_ports.items()
            if isinstance(peer, dict) and str(peer.get("device", "")).casefold() in known_switches
        } if isinstance(peer_ports, dict) else set()
        previous = old.get("bmc", {})
        data["bmc"] = observe(raw, previous if isinstance(previous, dict) else {},
                              configured.get(hostname.casefold(), []),
                              checked_at=checked_at, uplinks=uplinks)
        destination.write_text(json.dumps(data), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "raw_dir", "staged_dir", "previous_dir", "config", "lldp"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    merge_snapshots(**vars(args))


if __name__ == "__main__":
    main()
