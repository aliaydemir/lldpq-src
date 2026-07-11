#!/usr/bin/env python3
"""Build the static EVPN Multi-Homing analysis report.

The collector owns switch access and emits one marker-delimited snapshot per
device.  This module is deliberately read-only: it correlates effective ESIs,
the BGP EAD view, applied bond configuration and Linux LACP state, then writes
one atomic HTML report under ``monitor-results``.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    read_asset_snapshot,
)


SECTION_HEADERS = {
    "=== EVPN MH GLOBAL JSON ===": "global",
    "=== EVPN MH ESI JSON ===": "esi",
    "=== EVPN MH BGP ESI JSON ===": "bgp_esi",
    "=== EVPN MH ES EVI TEXT ===": "es_evi",
    "=== EVPN MH BGP ES EVI TEXT ===": "bgp_es_evi",
    "=== EVPN MH INTERFACES APPLIED JSON ===": "interfaces",
    "=== EVPN MH LINK DETAIL JSON ===": "links",
    "=== EVPN MH BYPASS STATE ===": "bypass",
}
COLLECTION_ERROR = "__LLDPQ_COLLECTION_ERROR__:"
COVERAGE_RE = re.compile(
    r"^__LLDPQ_EVPN_MH_COVERAGE__:([A-Z_]+):([A-Z_]+)$"
)
LOCAL_COUNT_RE = re.compile(r"^__LLDPQ_EVPN_MH_LOCAL_ESI__:([0-9]+)$")
COLLECTION_UTC_RE = re.compile(r"^__LLDPQ_EVPN_MH_COLLECTION_UTC__:(\S+)$")
EVI_RE = re.compile(
    r"^\s*(?P<vni>[0-9]+)\s+"
    r"(?P<esi>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){9})\s+"
    r"(?P<flags>\S+)(?:\s+(?P<vteps>.*))?$"
)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _json_section(lines: Sequence[str]) -> Any:
    payload = "\n".join(
        line for line in lines
        if not line.startswith("__LLDPQ_") and line.strip()
    ).strip()
    if not payload:
        return {}
    return json.loads(payload)


def parse_snapshot(content: str) -> Dict[str, Any]:
    """Parse one collector snapshot without converting failures into zeros."""
    bodies: Dict[str, List[str]] = {name: [] for name in SECTION_HEADERS.values()}
    coverage: Dict[str, str] = {}
    errors: List[str] = []
    current: Optional[str] = None
    local_count = 0
    collection_utc = ""

    for raw_line in content.splitlines():
        line = raw_line.rstrip("\r")
        if line in SECTION_HEADERS:
            current = SECTION_HEADERS[line]
            continue
        match = COVERAGE_RE.match(line)
        if match:
            coverage[match.group(1)] = match.group(2)
            continue
        match = LOCAL_COUNT_RE.match(line)
        if match:
            local_count = int(match.group(1))
            continue
        match = COLLECTION_UTC_RE.match(line)
        if match:
            collection_utc = match.group(1)
            continue
        if line.startswith(COLLECTION_ERROR):
            errors.append(line[len(COLLECTION_ERROR):])
            continue
        if line.startswith("__LLDPQ_"):
            continue
        if current is not None:
            bodies[current].append(line)

    parsed: Dict[str, Any] = {
        "coverage": coverage,
        "errors": errors,
        "local_count": local_count,
        "collection_utc": collection_utc,
    }
    for name in ("global", "esi", "bgp_esi", "interfaces", "links"):
        try:
            parsed[name] = _json_section(bodies[name])
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            parsed[name] = {} if name != "links" else []
            parsed["errors"].append(f"{name.upper()}_JSON:{exc}")
    parsed["es_evi"] = _parse_evi_lines(bodies["es_evi"])
    parsed["bgp_es_evi"] = _parse_evi_lines(bodies["bgp_es_evi"])
    parsed["bypass"] = _parse_bypass_lines(bodies["bypass"])
    return parsed


def _parse_evi_lines(lines: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    for line in lines:
        match = EVI_RE.match(line)
        if not match:
            continue
        esi = match.group("esi").lower()
        result.setdefault(esi, []).append({
            "vni": int(match.group("vni")),
            "flags": match.group("flags"),
            "vteps": (match.group("vteps") or "").strip(),
        })
    return result


def _parse_bypass_lines(lines: Iterable[str]) -> Dict[Tuple[str, str], int]:
    result: Dict[Tuple[str, str], int] = {}
    for line in lines:
        if line.startswith("__LLDPQ_"):
            continue
        fields = line.split("|")
        if len(fields) != 3:
            continue
        bond, member, value = (field.strip() for field in fields)
        if not bond or not member:
            continue
        try:
            result[(bond, member)] = int(value)
        except ValueError:
            continue
    return result


def _flag(item: Mapping[str, Any], name: str) -> bool:
    return _mapping(item.get("flags")).get(name) in {"on", "yes", True}


def _link_map(value: Any) -> Dict[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        return {}
    return {
        str(item.get("ifname")): item
        for item in value
        if isinstance(item, Mapping) and item.get("ifname")
    }


def _bridge_vlans(interface: Mapping[str, Any]) -> List[str]:
    values: Set[str] = set()
    domains = _mapping(_mapping(interface.get("bridge")).get("domain"))
    for domain in domains.values():
        config = _mapping(domain)
        access = config.get("access")
        if access is not None and str(access):
            values.add(str(access))
        vlans = config.get("vlan")
        if isinstance(vlans, Mapping):
            values.update(str(value) for value in vlans)
        elif isinstance(vlans, list):
            values.update(str(value) for value in vlans)
    return sorted(values, key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))


def _member_runtime(link: Mapping[str, Any]) -> Mapping[str, Any]:
    linkinfo = _mapping(link.get("linkinfo"))
    return _mapping(linkinfo.get("info_slave_data"))


def _bond_runtime(link: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(_mapping(link.get("linkinfo")).get("info_data"))


def _lacp_state(
    members: Sequence[str],
    links: Mapping[str, Mapping[str, Any]],
    bypass: Mapping[Tuple[str, str], int],
    bond: str,
    bond_up: bool,
    mode: str,
) -> Tuple[str, bool, List[Dict[str, Any]]]:
    details: List[Dict[str, Any]] = []
    active_bypass = False
    all_synced = bool(members)
    for member in members:
        runtime = _member_runtime(links.get(member, {}))
        actor = [str(value) for value in runtime.get("ad_actor_oper_port_state_str", [])]
        partner = [str(value) for value in runtime.get("ad_partner_oper_port_state_str", [])]
        member_bypass = bypass.get((bond, member), 0) == 1
        active_bypass = active_bypass or member_bypass
        required = {"in_sync", "collecting", "distributing"}
        synced = required.issubset(set(actor)) and required.issubset(set(partner))
        all_synced = all_synced and synced
        details.append({
            "name": member,
            "state": str(runtime.get("state", "")),
            "mii": str(runtime.get("mii_status", "")),
            "actor": actor,
            "partner": partner,
            "bypass": member_bypass,
            "synced": synced,
            "speed": links.get(member, {}).get("linkinfo", {}).get(
                "info_slave_data", {}
            ).get("speed", ""),
        })
    if str(mode).lower() in {"static", "balance-xor", "xor"}:
        all_up = bool(details) and all(
            item["mii"].upper() == "UP" or item["state"].upper() == "ACTIVE"
            for item in details
        )
        return ("Static" if bond_up and all_up else "Degraded"), False, details
    if active_bypass:
        return "Bypass", True, details
    if not bond_up:
        return "Down", False, details
    if all_synced:
        return "Synced", False, details
    if not members:
        return "No members", False, details
    return "Degraded", False, details


def build_attachment(
    hostname: str,
    esi: str,
    operational: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    bond = str(operational.get("local-interface", ""))
    interfaces = _mapping(snapshot.get("interfaces"))
    if isinstance(interfaces.get("interface"), Mapping):
        interfaces = _mapping(interfaces.get("interface"))
    interface = _mapping(interfaces.get(bond))
    segment = _mapping(
        _mapping(_mapping(interface.get("evpn")).get("multihoming")).get("segment")
    )
    bond_config = _mapping(interface.get("bond"))
    links = _link_map(snapshot.get("links"))
    bond_link = _mapping(links.get(bond))
    members_value = bond_config.get("member")
    members = (
        sorted(str(member) for member in members_value)
        if isinstance(members_value, Mapping) else []
    )
    if not members:
        members = sorted(
            name for name, link in links.items()
            if str(link.get("master", "")) == bond
            and _mapping(link.get("linkinfo")).get("info_slave_kind") == "bond"
        )
    runtime = _bond_runtime(bond_link)
    bond_mode = str(bond_config.get("mode") or runtime.get("mode") or "")
    ad_info = _mapping(runtime.get("ad_info"))
    bond_up = _flag(operational, "oper-up") or str(
        bond_link.get("operstate", "")
    ).upper() == "UP"
    lacp, bypass_active, member_details = _lacp_state(
        members, links, _mapping(snapshot.get("bypass")), bond, bond_up, bond_mode
    )
    bgp_item = _mapping(_mapping(snapshot.get("bgp_esi")).get(esi))
    evi_rows = _mapping(snapshot.get("bgp_es_evi")).get(esi, [])
    vnis = sorted({
        int(row["vni"]) for row in evi_rows
        if isinstance(row, Mapping) and isinstance(row.get("vni"), int)
    })
    inconsistent = (
        int(bgp_item.get("inconsistent-vni-count") or 0) > 0
        or any("I" in str(row.get("flags", "")) for row in evi_rows)
    )
    return {
        "hostname": hostname,
        "bond": bond,
        "description": str(
            interface.get("description") or bond_link.get("ifalias") or ""
        ),
        "esi": esi,
        "df_preference": int(
            segment.get("df-preference", operational.get("df-preference", 0)) or 0
        ),
        "df": _flag(operational, "designated-forward"),
        "non_df": _flag(operational, "non-designated-forward"),
        "oper_up": bond_up,
        "ready_bgp": _flag(operational, "ready-for-bgp"),
        "remote": _flag(operational, "remote"),
        "remote_vteps": sorted(str(value) for value in _mapping(
            operational.get("remote-vtep")
        )),
        "mac_count": int(operational.get("mac-count") or 0),
        "vni_count": int(operational.get("vni-count") or 0),
        "vnis": vnis,
        "vlans": _bridge_vlans(interface),
        "segment_mac": str(segment.get("mac-address", "")),
        "local_id": segment.get("local-id", segment.get("identifier", "")),
        "segment_state": str(segment.get("state", "")),
        "members": members,
        "member_details": member_details,
        "lacp": lacp,
        "bypass_configured": str(bond_config.get("lacp-bypass", "")).lower()
            in {"on", "enabled", "true"},
        "bypass_active": bypass_active,
        "actor_key": ad_info.get("actor_key", ""),
        "partner_key": ad_info.get("partner_key", ""),
        "partner_mac": str(ad_info.get("partner_mac", "")),
        "aggregator": ad_info.get("aggregator", ""),
        "num_ports": ad_info.get("num_ports", ""),
        "inconsistent": inconsistent,
        "bgp_present": bool(bgp_item),
        "originator_ip": str(bgp_item.get("originator-ip", "")),
        "rd": str(bgp_item.get("rd", "")),
        "collection_partial": bool(snapshot.get("errors")),
    }


def correlate_snapshots(
    snapshots: Mapping[str, Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for hostname, snapshot in snapshots.items():
        esi_map = _mapping(snapshot.get("esi"))
        for esi_value, operational_value in esi_map.items():
            operational = _mapping(operational_value)
            if not operational.get("local-interface"):
                continue
            esi = str(esi_value).lower()
            grouped.setdefault(esi, []).append(
                build_attachment(hostname, esi, operational, snapshot)
            )

    rows: List[Dict[str, Any]] = []
    for esi, attachments in sorted(grouped.items()):
        attachments.sort(key=lambda item: item["hostname"].lower())
        orphan = len(attachments) == 1
        collision = len(attachments) > 2
        bypass_active = any(item["bypass_active"] for item in attachments)
        inconsistent = any(item["inconsistent"] for item in attachments)
        all_oper = all(item["oper_up"] for item in attachments)
        all_remote = len(attachments) >= 2 and all(
            item["remote"] for item in attachments[:2]
        )
        df_count = sum(bool(item["df"]) for item in attachments[:2])
        dual_df_conflict = (
            len(attachments) == 2 and all_oper and all_remote
            and df_count == 2 and not bypass_active
        )
        no_df_conflict = (
            len(attachments) == 2 and all_oper and all_remote and df_count == 0
        )
        lacp_degraded = any(
            item["lacp"] not in {"Synced", "Bypass", "Static"} for item in attachments
            if item["oper_up"]
        )
        vni_sets = {tuple(item["vnis"]) for item in attachments}
        vni_mismatch = len(vni_sets) > 1
        bgp_missing = any(not item["bgp_present"] for item in attachments)

        if collision or inconsistent or dual_df_conflict or no_df_conflict:
            status = "critical"
        elif bypass_active:
            status = "bypass"
        elif not all_oper:
            status = "inactive"
        elif orphan or not all_remote or lacp_degraded or vni_mismatch or bgp_missing:
            status = "warning"
        else:
            status = "healthy"

        reasons: List[str] = []
        if collision:
            reasons.append(f"ESI present on {len(attachments)} local PEs")
        if inconsistent:
            reasons.append("BGP reports inconsistent VNI state")
        if dual_df_conflict:
            reasons.append("both active remote PEs are DF")
        if no_df_conflict:
            reasons.append("no active PE is DF")
        if bypass_active:
            reasons.append("LACP bypass active")
        if not all_oper:
            reasons.append("one or more local bonds inactive")
        if orphan:
            reasons.append("peer PE not found")
        if len(attachments) >= 2 and not all_remote and not bypass_active:
            reasons.append("remote ES peer not operational")
        if lacp_degraded:
            reasons.append("LACP not fully synchronized")
        if vni_mismatch:
            reasons.append("VNI membership mismatch")
        if bgp_missing:
            reasons.append("BGP ES record missing")
        if not reasons:
            reasons.append("operational and synchronized")

        rows.append({
            "esi": esi,
            "attachments": attachments,
            "status": status,
            "reason": "; ".join(reasons),
            "orphan": orphan,
            "inconsistent": inconsistent,
            "bypass_active": bypass_active,
            "vnis": sorted({vni for item in attachments for vni in item["vnis"]}),
        })
    return rows


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _display_values(attachments: Sequence[Mapping[str, Any]]) -> Tuple[Mapping[str, Any], Mapping[str, Any]]:
    empty: Mapping[str, Any] = {
        "hostname": "Not discovered", "bond": "—", "description": "",
        "df": False, "non_df": False, "df_preference": 0, "lacp": "—",
        "oper_up": False, "partner_mac": "", "partner_key": "",
        "actor_key": "", "members": [], "member_details": [],
        "bypass_active": False, "segment_mac": "", "local_id": "",
    }
    first = attachments[0] if attachments else empty
    second = attachments[1] if len(attachments) > 1 else empty
    return first, second


def _df_text(item: Mapping[str, Any]) -> str:
    if item.get("df"):
        return f"DF {item.get('df_preference', 0)}"
    if item.get("non_df"):
        return f"non-DF {item.get('df_preference', 0)}"
    return "—"


def _row_html(row: Mapping[str, Any]) -> str:
    first, second = _display_values(row["attachments"])
    endpoint = first.get("description") or second.get("description") or "—"
    vni_text = ", ".join(str(value) for value in row["vnis"]) or "—"
    devices = " ".join(
        str(item["hostname"]) for item in row["attachments"]
    )
    attrs = {
        "device-a": first.get("hostname", ""),
        "device-b": second.get("hostname", ""),
        "bond-a": first.get("bond", ""),
        "bond-b": second.get("bond", ""),
        "df-a": _df_text(first),
        "df-b": _df_text(second),
        "lacp-a": first.get("lacp", ""),
        "lacp-b": second.get("lacp", ""),
    }
    data_attrs = " ".join(
        f'data-{key}="{_h(value)}"' for key, value in attrs.items()
    )
    status = str(row["status"])
    return f"""
<tr class="mh-row status-{_h(status)}" data-devices="{_h(devices)}"
    data-esi="{_h(row['esi'])}" data-status="{_h(status)}"
    data-bypass-active="{'1' if row['bypass_active'] else '0'}"
    data-inconsistent="{'1' if row['inconsistent'] else '0'}"
    data-orphan="{'1' if row['orphan'] else '0'}" {data_attrs}
    onclick="toggleDetails(this)">
  <td class="cell-device" data-p2p-namespace="devices" data-p2p-key="{_h(first.get('hostname', ''))}">{_h(first.get('hostname', '—'))}</td>
  <td class="cell-peer" data-p2p-namespace="devices" data-p2p-key="{_h(second.get('hostname', ''))}">{_h(second.get('hostname', '—'))}</td>
  <td><code class="cell-local-bond" data-p2p-namespace="interfaces" data-p2p-key="{_h(first.get('bond', ''))}">{_h(first.get('bond', '—'))}</code></td>
  <td><code class="cell-peer-bond" data-p2p-namespace="interfaces" data-p2p-key="{_h(second.get('bond', ''))}">{_h(second.get('bond', '—'))}</code></td>
  <td><code>{_h(row['esi'])}</code></td>
  <td title="{_h(endpoint)}">{_h(endpoint)}</td>
  <td class="cell-df">{_h(_df_text(first))} / {_h(_df_text(second))}</td>
  <td class="cell-lacp">{_h(first.get('lacp', '—'))} / {_h(second.get('lacp', '—'))}</td>
  <td>{_h(vni_text)}</td>
  <td><span class="status-badge badge-{_h(status)}">{_h(status.replace('_', ' ').upper())}</span></td>
</tr>"""


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o664)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def render_report(
    rows: Sequence[Mapping[str, Any]],
    *,
    coverage_status: str,
    coverage_failures: Mapping[str, str],
    generated_at: datetime,
) -> str:
    counts = {
        "total": len(rows),
        "healthy": sum(row["status"] == "healthy" for row in rows),
        "inactive": sum(row["status"] == "inactive" for row in rows),
        "bypass": sum(bool(row["bypass_active"]) for row in rows),
        "bypass_status": sum(row["status"] == "bypass" for row in rows),
        "critical": sum(row["status"] == "critical" for row in rows),
        "warning": sum(row["status"] == "warning" for row in rows),
        "inconsistent": sum(bool(row["inconsistent"]) for row in rows),
        "orphan": sum(bool(row["orphan"]) for row in rows),
    }
    device_names = sorted({
        str(item["hostname"]) for row in rows for item in row["attachments"]
    }, key=str.lower)
    details = {
        str(row["esi"]): row["attachments"]
        for row in rows
    }
    details_json = json.dumps(details, separators=(",", ":"), ensure_ascii=True).replace(
        "</", "<\\/"
    )
    options = "".join(
        f'<option value="{_h(device)}">{_h(device)}</option>'
        for device in device_names
    )
    table_rows = "\n".join(_row_html(row) for row in rows)
    if not table_rows:
        table_rows = (
            '<tr class="empty-row"><td colspan="10">No local EVPN multihoming '
            "Ethernet Segments were found in the current collection.</td></tr>"
        )
    coverage_message = ""
    if coverage_failures:
        coverage_message = (
            '<div class="coverage-banner">Partial collection: '
            + _h("; ".join(
                f"{host}: {reason}" for host, reason in sorted(coverage_failures.items())
            ))
            + "</div>"
        )
    updated = generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    partial = "true" if coverage_status != "current" else "false"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EVPN Multi-Homing Analysis</title>
<style>
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:14px; background:#1e1e1e; color:#d4d4d4; font-family:'Segoe UI',Tahoma,sans-serif; font-size:13px; }}
.page-header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:20px; padding-bottom:12px; border-bottom:1px solid #333; }}
.page-title {{ color:#76b900; font-size:22px; font-weight:700; }}
.last-updated {{ color:#888; font-size:11px; margin-top:3px; }}
.action-buttons {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; justify-content:flex-end; }}
.device-search-container {{ position:relative; }}
select {{ width:210px; padding:7px 28px 7px 10px; background:#333; border:1px solid #4a4a4a; color:#ddd; border-radius:3px; }}
.btn {{ display:inline-flex; align-items:center; gap:6px; border:0; border-radius:3px; padding:7px 12px; color:white; cursor:pointer; font-size:12px; }}
.btn-secondary {{ background:#149fc7; }} .btn-secondary:hover {{ background:#19b6e2; }}
.btn-primary {{ background:#76b900; }} .btn-primary:hover {{ background:#89d000; }}
.summary-grid {{ display:grid; grid-template-columns:repeat(6,minmax(120px,1fr)); gap:10px; margin:14px 0; }}
.summary-card {{ background:#292929; border:1px solid #383838; border-left:3px solid #76b900; padding:12px; cursor:pointer; min-height:74px; }}
.summary-card:nth-child(3) {{ border-left-color:#888; }} .summary-card:nth-child(4) {{ border-left-color:#ff9800; }}
.summary-card:nth-child(5) {{ border-left-color:#f44336; }} .summary-card:nth-child(6) {{ border-left-color:#ba68c8; }}
.metric {{ font-size:24px; font-weight:700; color:#76b900; }} .metric-label {{ color:#999; font-size:10px; text-transform:uppercase; margin-top:5px; }}
.dashboard-section {{ background:#292929; border:1px solid #383838; border-radius:8px; margin:12px 0 20px; overflow:hidden; }}
.section-header {{ padding:12px 16px; background:#333; color:#76b900; font-weight:600; font-size:14px; display:flex; align-items:center; gap:8px; }}
.table-wrap {{ overflow:auto; }}
table {{ border-collapse:collapse; width:100%; min-width:1320px; table-layout:auto; font-size:13px; }}
th,td {{ border:1px solid #404040; padding:10px 12px; text-align:left; }}
th {{ background:#333; color:#76b900; font-weight:600; font-size:12px; white-space:nowrap; }}
.sortable {{ cursor:pointer; user-select:none; padding-right:20px; }}
.sortable:hover {{ background:#3c3c3c; }}
.sortable:focus-visible {{ outline:2px solid #76b900; outline-offset:-2px; }}
.sort-arrow {{ font-size:10px; color:#666; margin-left:5px; opacity:.5; }}
.sort-arrow::before {{ content:'▲▼'; }}
.sortable.asc .sort-arrow::before {{ content:'▲'; color:#76b900; opacity:1; }}
.sortable.desc .sort-arrow::before {{ content:'▼'; color:#76b900; opacity:1; }}
.sortable.asc .sort-arrow,.sortable.desc .sort-arrow {{ opacity:1; }}
td {{ color:#ccc; white-space:nowrap; max-width:220px; overflow:hidden; text-overflow:ellipsis; }}
tbody tr {{ background:#252526; }} tr.mh-row {{ cursor:pointer; border-left:3px solid #76b900; }} tr.mh-row:hover {{ background:#2d2d2d; }}
tr.status-bypass {{ border-left-color:#ff9800; }} tr.status-warning {{ border-left-color:#ffc107; }}
tr.status-inactive {{ border-left-color:#777; }} tr.status-critical {{ border-left-color:#f44336; }}
.cell-device,.cell-peer {{ font-weight:600; color:#a5d64d; }} code {{ color:#6fc7df; }}
.status-badge {{ padding:3px 7px; border-radius:2px; font-size:9px; font-weight:700; border:1px solid currentColor; }}
.badge-healthy {{ color:#76b900; }} .badge-bypass {{ color:#ff9800; }} .badge-warning {{ color:#ffc107; }}
.badge-inactive {{ color:#999; }} .badge-critical {{ color:#f44336; }}
.detail-row td {{ padding:0; white-space:normal; max-width:none; }}
.detail-panel {{ padding:14px 20px 18px; background:#202020; border:1px solid #ff9800; }}
.detail-title {{ color:#ffb300; font-weight:700; margin-bottom:12px; }}
.compare-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
.peer-card {{ background:#292929; border:1px solid #444; border-radius:4px; padding:12px; }}
.peer-title {{ color:#76b900; font-size:15px; font-weight:700; border-bottom:1px solid #444; padding-bottom:7px; margin-bottom:7px; }}
.kv {{ display:grid; grid-template-columns:145px 1fr; gap:8px; padding:4px 0; border-bottom:1px solid #333; }}
.kv span:first-child {{ color:#999; }} .good {{ color:#76b900; }} .warn {{ color:#ff9800; }}
.detail-note {{ margin-top:12px; padding:10px 12px; background:#362b10; border:1px solid #8b6700; color:#ffc107; }}
.coverage-banner {{ margin:12px 0; padding:9px 12px; background:#35270f; color:#ffb74d; border:1px solid #6d511d; }}
.empty-row td {{ text-align:center; color:#888; padding:30px; }}
.threshold-modal {{ display:none; position:fixed; inset:0; background:rgba(0,0,0,.72); z-index:1000; align-items:center; justify-content:center; }}
.threshold-modal.show {{ display:flex; }} .modal-card {{ width:min(720px,90vw); background:#292929; border:1px solid #555; box-shadow:0 12px 45px #000; }}
.modal-head {{ display:flex; justify-content:space-between; padding:14px 16px; color:#76b900; font-weight:700; border-bottom:1px solid #444; }}
.modal-body {{ padding:16px; line-height:1.55; }} .modal-body li {{ margin:7px 0; }} .close {{ cursor:pointer; color:#aaa; font-size:20px; }}
@media (max-width:1100px) {{ .summary-grid {{ grid-template-columns:repeat(3,1fr); }} .page-header {{ flex-direction:column; }} }}
</style>
</head>
<body data-coverage-status="{_h(coverage_status)}">
<div hidden data-analysis-summary="evpn-mh" data-coverage-status="{_h(coverage_status)}"
     data-coverage-partial="{partial}" data-total-es="{counts['total']}"
     data-healthy-es="{counts['healthy']}" data-inactive-es="{counts['inactive']}"
     data-bypass-es="{counts['bypass']}" data-bypass-issue-es="{counts['bypass_status']}"
     data-critical-es="{counts['critical']}"
     data-warning-es="{counts['warning']}" data-inconsistent-es="{counts['inconsistent']}"
     data-orphan-es="{counts['orphan']}" data-metric-key="total_es"
     data-metric-value="{counts['total']}"></div>
<div class="page-header">
  <div><div class="page-title">EVPN Multi-Homing Analysis</div><div class="last-updated">Last Updated: {_h(updated)}</div></div>
  <div class="action-buttons">
    <div class="device-search-container"><select id="deviceSearch" onchange="filterRows()"><option value="">Search Device...</option>{options}</select></div>
    <button id="thresholds-btn" class="btn btn-secondary" onclick="openThresholdsModal()">⚙ Thresholds</button>
    <button id="run-analysis" class="btn btn-secondary" onclick="runAnalysis()">↻ Run Analysis</button>
    <button id="download-csv" class="btn btn-primary" onclick="downloadCSV()">⇩ Download CSV</button>
  </div>
</div>
{coverage_message}
<div class="summary-grid">
  <div class="summary-card" onclick="setStatus('')"><div class="metric" id="total-es">{counts['total']}</div><div class="metric-label">Local Ethernet Segments</div></div>
  <div class="summary-card" onclick="setStatus('healthy')"><div class="metric" id="healthy-es">{counts['healthy']}</div><div class="metric-label">Healthy</div></div>
  <div class="summary-card" onclick="setStatus('inactive')"><div class="metric" id="inactive-es">{counts['inactive']}</div><div class="metric-label">Inactive / Down</div></div>
  <div class="summary-card" onclick="setStatus('bypass')"><div class="metric" id="bypass-es">{counts['bypass']}</div><div class="metric-label">LACP Bypass Active</div></div>
  <div class="summary-card" onclick="setStatus('critical')"><div class="metric" id="inconsistent-es">{counts['inconsistent']}</div><div class="metric-label">BGP Inconsistent</div></div>
  <div class="summary-card" onclick="setOrphan()"><div class="metric" id="orphan-es">{counts['orphan']}</div><div class="metric-label">Orphan ESI</div></div>
</div>
<div class="dashboard-section">
  <div class="section-header">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
    Device &amp; Peer Health ({counts['total']} total)
  </div>
  <div class="table-wrap">
  <table id="evpn-mh-table">
    <thead><tr>
      <th class="sortable" aria-sort="none" onclick="sortTable(0,this)">Device<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(1,this)">Peer Device<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(2,this)">Local Bond<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(3,this)">Peer Bond<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(4,this)">ESI<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(5,this)">Endpoint<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(6,this)">DF Local / Peer<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(7,this)">LACP Local / Peer<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(8,this)">VNI<span class="sort-arrow"></span></th>
      <th class="sortable" aria-sort="none" onclick="sortTable(9,this)">Status<span class="sort-arrow"></span></th>
    </tr></thead>
    <tbody id="evpn-mh-body">{table_rows}</tbody>
  </table>
  </div>
</div>
<div id="thresholdModal" class="threshold-modal" role="dialog" aria-modal="true">
 <div class="modal-card"><div class="modal-head"><span>EVPN-MH Health Rules</span><span class="close" onclick="closeThresholdsModal()">×</span></div>
 <div class="modal-body"><ul>
   <li><b>Healthy:</b> two local PEs, bonds operational, LACP synchronized, remote ES present and one DF.</li>
   <li><b>Bypass:</b> LACP bypass is actively forwarding. Dual DF is expected because Type-1/Type-4 and DF filtering are withdrawn.</li>
   <li><b>Inactive:</b> one or more local ES bonds are down or not operational.</li>
   <li><b>Warning:</b> orphan ESI, missing remote ES, unsynchronized LACP, VNI mismatch or missing BGP ES state.</li>
   <li><b>Critical:</b> BGP inconsistent VNI, ESI collision, or dual/no DF while both remote PEs are active and bypass is not active.</li>
 </ul></div></div>
</div>
<script>
const MH_DETAILS={details_json};
let statusFilter='';
let orphanOnly=false;
let sortState={{column:-1,ascending:true}};
function esc(v){{return String(v??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));}}
function side(item,role){{
  item=item||{{}};
  const members=(item.members||[]).join(', ')||'—';
  const state=item.bypass_active?'Bypass active':(item.lacp||'—');
  return `<div class="peer-card"><div class="peer-title">${{role}} · ${{esc(item.hostname||'Not discovered')}}</div>
    <div class="kv"><span>Bond</span><code>${{esc(item.bond||'—')}}</code></div>
    <div class="kv"><span>Endpoint</span><span>${{esc(item.description||'—')}}</span></div>
    <div class="kv"><span>DF Preference</span><span>${{esc(item.df_preference??'—')}}</span></div>
    <div class="kv"><span>DF State</span><span class="${{item.df?'warn':''}}">${{item.df?'Designated':(item.non_df?'non-DF':'—')}}</span></div>
    <div class="kv"><span>Members</span><span>${{esc(members)}}</span></div>
    <div class="kv"><span>LACP</span><span class="${{item.lacp==='Synced'?'good':'warn'}}">${{esc(state)}}</span></div>
    <div class="kv"><span>Actor / Partner Key</span><span>${{esc(item.actor_key||'—')}} / ${{esc(item.partner_key||'—')}}</span></div>
    <div class="kv"><span>Partner MAC</span><code>${{esc(item.partner_mac||'—')}}</code></div>
    <div class="kv"><span>ES MAC / Local ID</span><span>${{esc(item.segment_mac||'—')}} / ${{esc(item.local_id??'—')}}</span></div></div>`;
}}
function selectedSides(row){{
  const list=MH_DETAILS[row.dataset.esi]||[];
  const selected=document.getElementById('deviceSearch').value;
  if(selected&&list.length>1&&list[1].hostname===selected)return [list[1],list[0]];
  return [list[0]||{{}},list[1]||{{}}];
}}
function setCell(cell,value,namespace){{
  if(!cell)return; cell.textContent=value||'—';
  if(namespace){{cell.dataset.p2pNamespace=namespace;cell.dataset.p2pKey=value||'';cell.dataset.p2pOrig=value||'';}}
}}
function orientRow(row){{
  const [a,b]=selectedSides(row);
  setCell(row.querySelector('.cell-device'),a.hostname,'devices');
  setCell(row.querySelector('.cell-peer'),b.hostname,'devices');
  setCell(row.querySelector('.cell-local-bond'),a.bond,'interfaces');
  setCell(row.querySelector('.cell-peer-bond'),b.bond,'interfaces');
  setCell(row.querySelector('.cell-df'),`${{a.df?'DF '+a.df_preference:(a.non_df?'non-DF '+a.df_preference:'—')}} / ${{b.df?'DF '+b.df_preference:(b.non_df?'non-DF '+b.df_preference:'—')}}`);
  setCell(row.querySelector('.cell-lacp'),`${{a.lacp||'—'}} / ${{b.lacp||'—'}}`);
}}
function visibleByLifecycle(row){{return !row.classList.contains('lldpq-lifecycle-hidden');}}
function filterRows(){{
  const device=document.getElementById('deviceSearch').value;
  document.querySelectorAll('tr.detail-row').forEach(r=>r.remove());
  document.querySelectorAll('tr.mh-row').forEach(row=>{{
    orientRow(row);
    const devices=(row.dataset.devices||'').split(/\\s+/);
    const show=(!device||devices.includes(device))&&(!statusFilter||row.dataset.status===statusFilter)&&(!orphanOnly||row.dataset.orphan==='1');
    row.style.display=show?'':'none';
  }});
}}
function setStatus(value){{statusFilter=value;orphanOnly=false;filterRows();}}
function setOrphan(){{statusFilter='';orphanOnly=true;filterRows();}}
function sortTable(column,header){{
  document.querySelectorAll('tr.detail-row').forEach(r=>r.remove());
  const body=document.getElementById('evpn-mh-body');
  const rows=Array.from(body.querySelectorAll('tr.mh-row'));
  const ascending=sortState.column===column?!sortState.ascending:true;
  sortState={{column,ascending}};
  rows.sort((a,b)=>{{
    const av=(a.cells[column]?.textContent||'').trim();
    const bv=(b.cells[column]?.textContent||'').trim();
    const result=av.localeCompare(bv,undefined,{{numeric:true,sensitivity:'base'}});
    return ascending?result:-result;
  }});
  rows.forEach(row=>body.appendChild(row));
  document.querySelectorAll('th.sortable').forEach(th=>{{
    th.setAttribute('aria-sort','none');
    th.classList.remove('asc','desc');
  }});
  header.classList.add(ascending?'asc':'desc');
  header.setAttribute('aria-sort',ascending?'ascending':'descending');
}}
function toggleDetails(row){{
  const next=row.nextElementSibling;
  if(next&&next.classList.contains('detail-row')){{next.remove();return;}}
  document.querySelectorAll('tr.detail-row').forEach(r=>r.remove());
  const [a,b]=selectedSides(row);const bypass=a.bypass_active||b.bypass_active;
  const detail=document.createElement('tr');detail.className='detail-row';
  detail.innerHTML=`<td colspan="10"><div class="detail-panel"><div class="detail-title">${{esc(a.hostname||'Device')}} ↔ ${{esc(b.hostname||'Peer')}} — ESI ${{esc(row.dataset.esi)}}</div>
    <div class="compare-grid">${{side(a,'DEVICE')}}${{side(b,'PEER')}}</div>
    <div class="detail-note">${{bypass?'LACP bypass is active. Type-1/Type-4 advertisements and DF filtering are intentionally withdrawn — dual DF is expected, not a conflict.':esc(row.title||row.dataset.status)}}</div></div></td>`;
  row.after(detail);
}}
function openThresholdsModal(){{document.getElementById('thresholdModal').classList.add('show');}}
function closeThresholdsModal(){{document.getElementById('thresholdModal').classList.remove('show');}}
document.getElementById('thresholdModal').addEventListener('click',e=>{{if(e.target.id==='thresholdModal')closeThresholdsModal();}});
document.addEventListener('keydown',e=>{{if(e.key==='Escape')closeThresholdsModal();}});
function downloadCSV(){{
  const headers=['Device','Peer Device','Local Bond','Peer Bond','ESI','Endpoint','DF Local / Peer','LACP Local / Peer','VNI','Status'];
  const lines=[headers];
  document.querySelectorAll('tr.mh-row').forEach(row=>{{
    if(row.style.display==='none'||!visibleByLifecycle(row))return;
    lines.push(Array.from(row.cells).map(cell=>(window.LLDPqP2P?.canonicalText(cell)||cell.textContent).trim()));
  }});
  const csv=lines.map(line=>line.map(v=>`"${{String(v).replace(/"/g,'""')}}"`).join(',')).join('\\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{{type:'text/csv'}}));a.download='evpn-mh-analysis.csv';a.click();URL.revokeObjectURL(a.href);
}}
async function runAnalysis(){{
  const button=document.getElementById('run-analysis'),original=button.innerHTML;
  button.disabled=true;button.textContent='Running...';
  try{{
    const response=await fetch('/trigger-monitor?scope=evpn-mh',{{method:'POST'}});
    const data=await response.json();
    if(!response.ok||data.status!=='success')throw new Error(data.message||'Trigger failed');
    if(window.waitForLldpqAnalysisCompletion)await window.waitForLldpqAnalysisCompletion(null,{{scope:'evpn-mh',pipelineId:data.trigger_id}});
    location.replace(location.pathname+'?_analysis_refresh='+Date.now());
  }}catch(error){{alert('Analysis did not complete: '+(error.message||error));button.disabled=false;button.innerHTML=original;}}
}}
filterRows();
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/analysis-guard.js?v=20260710-evpn-mh"></script>
</body></html>"""


def process_evpn_mh_data_files(
    data_dir: str = "monitor-results/evpn-mh-data",
) -> bool:
    data_path = Path(data_dir).resolve()
    result_dir = data_path.parent
    if not data_path.is_dir():
        print(f"EVPN-MH data directory not found: {data_path}", file=sys.stderr)
        return False

    asset_snapshot = read_asset_snapshot(str(result_dir.parent / "assets.ini"))
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    authoritative = asset_snapshot_is_authoritative(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("Asset snapshot is invalid or incomplete", file=sys.stderr)
        return False

    if authoritative:
        active_hosts = set(statuses)
        for raw_file in data_path.glob("*_evpn_mh.txt"):
            if raw_file.name.removesuffix("_evpn_mh.txt") not in active_hosts:
                raw_file.unlink(missing_ok=True)

    current_files = [
        path for path in data_path.glob("*_evpn_mh.txt")
        if is_current_collection(
            str(path), path.name.removesuffix("_evpn_mh.txt"), asset_snapshot
        )
    ]
    expected_hosts = (
        {host for host, status in statuses.items() if status == "OK"}
        if snapshot_valid else set()
    )
    collected_hosts = {
        path.name.removesuffix("_evpn_mh.txt") for path in current_files
    }
    coverage_failures: Dict[str, str] = {}
    if snapshot_valid:
        coverage_failures.update({
            host: f"asset status {status}"
            for host, status in statuses.items() if status != "OK"
        })
        for host in expected_hosts - collected_hosts:
            coverage_failures[host] = "current EVPN-MH collection missing"

    snapshots: Dict[str, Dict[str, Any]] = {}
    for raw_file in sorted(current_files):
        hostname = raw_file.name.removesuffix("_evpn_mh.txt")
        try:
            snapshot = parse_snapshot(
                raw_file.read_text(encoding="utf-8", errors="replace")
            )
        except OSError as exc:
            coverage_failures[hostname] = f"snapshot read failed: {exc}"
            continue
        # A failed ESI query always reports local_count 0, so it must be
        # recorded as a coverage failure regardless of local_count.
        esi_failed = any(
            error == "EVPN_MH_ESI" or error.startswith("ESI_JSON:")
            for error in snapshot["errors"]
        )
        if snapshot["errors"] and (
            esi_failed or snapshot.get("local_count", 0) > 0
        ):
            coverage_failures[hostname] = ", ".join(snapshot["errors"][:3])
        snapshots[hostname] = snapshot

    rows = correlate_snapshots(snapshots)
    coverage_status = "partial" if coverage_failures else "current"
    report = render_report(
        rows,
        coverage_status=coverage_status,
        coverage_failures=coverage_failures,
        generated_at=datetime.now(timezone.utc),
    )
    try:
        _atomic_write(result_dir / "evpn-mh-analysis.html", report)
    except OSError as exc:
        print(f"Could not write EVPN-MH report: {exc}", file=sys.stderr)
        return False
    return True


def main() -> int:
    data_dir = (
        sys.argv[1] if len(sys.argv) > 1
        else str(Path(__file__).resolve().parent / "monitor-results" / "evpn-mh-data")
    )
    return 0 if process_evpn_mh_data_files(data_dir) else 1


if __name__ == "__main__":
    raise SystemExit(main())
