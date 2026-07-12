#!/usr/bin/env python3
"""IPAM (IP-Allocation / logical design) workbook parser for LLDPq Ask-AI.

Parses real-world IP allocation/assignment workbooks (.xlsx/.xlsm) into a
canonical JSON shape so the Inventory page and Ask-AI can answer addressing
questions and diff design vs live state (devices.yaml, BGP loopbacks/ASNs).

The xlsx reader is reused from ai_p2p (same directory); this module only adds
IPAM-specific header sniffing. Data tabs are detected by header sniffing,
never by sheet names, so Change Log / Topology / README style tabs fail the
sniff naturally and land in skipped_sheets.

Recognized schema families (field-verified against real workbooks):
  - Assignment blocks: DEVICE/HOSTNAME/INTERFACE/IP ADDRESS/MASK/GATEWAY/VLAN
    header clusters, possibly repeated side-by-side across the column axis of
    one sheet (each block is parsed independently) -> hosts
  - Subnet catalogs: VRF/VLAN/Network/GW/Purpose, Name+Subnet, or
    Subnet-CIDR/VLAN/VRF/Gateway/Purpose rows; several mini-tables may stack
    vertically inside one sheet -> subnets
  - Fabric inventory: Device/Hostname/Role/Management IP/Loopback IP/ASN
    tables -> fabric (ASN scientific-notation artifacts are normalized)
  - Wide host tables: hostname plus many IP columns (Rail0..N, bmc_ip/bmc_net
    pairs, '<role> IP') -> hosts
  - L3 links: Source/Interface/IP <-> Destination/Interface/IP intent rows,
    including border eBGP variants (Local IP / Peer IP) -> l3_links

Top-level:
    {format, source_file, generated_at, total_records,
     subnets: [{name, prefix, gateway?, vrf?, vlan?, type?, sheet}],
     hosts: [{hostname, assignments: [{role_or_interface, ip,
                                       prefixlen_or_mask?, gateway?, vlan?,
                                       vrf?}], sheet}],
     fabric: [{hostname, role?, mgmt_ip?, loopback_ip?, asn?, device?, sheet}],
     l3_links: [{a_host, a_if, a_ip, b_host, b_if, b_ip, mask?, sheet}],
     skipped_sheets: [...], warnings: [...]}

IPs are validated with the ipaddress module; invalid values are reported in
warnings, never stored in records. Blank/tbd cells are tolerated (counted in
warnings, excluded from truth outputs).

CLI: python3 ai_ipam.py <file.xlsx|file.xlsm> [--summary]
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai_p2p import iter_workbook_sheets, read_workbook, _clean_value  # noqa: E402,F401

CANONICAL_FORMAT = "ipam"

MAX_HEADER_SCAN_ROWS = 50
MAX_WARNING_EXAMPLES = 3

_PLACEHOLDERS = {
    "", "tbd", "tba", "n/a", "na", "none", "null", "-", "--", "?", "x", "xx",
    "l2-only", "l2 only", "l2only",
}


def _squash(value):
    """Header text lowered with everything non-alphanumeric removed."""
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _is_placeholder(text):
    return str(text or "").strip().lower() in _PLACEHOLDERS


# ---------------------------------------------------------------------------
# IP / mask / ASN normalization
# ---------------------------------------------------------------------------

def _parse_ip(value):
    """-> (ip, prefixlen_or_None, status); status is 'ok'|'blank'|'invalid'.

    Accepts bare addresses and CIDR-suffixed cells ('192.0.2.0/31').
    """
    text = _clean_value(value)
    if _is_placeholder(text):
        return "", None, "blank"
    core, prefixlen = text, None
    if "/" in text:
        core, _, suffix = text.partition("/")
        core, suffix = core.strip(), suffix.strip()
        if not suffix.isdigit():
            return "", None, "invalid"
        prefixlen = int(suffix)
    try:
        ip = ipaddress.ip_address(core)
    except ValueError:
        return "", None, "invalid"
    if prefixlen is not None and prefixlen > ip.max_prefixlen:
        return "", None, "invalid"
    return str(ip), prefixlen, "ok"


def _parse_prefix(value):
    """-> (network_cidr, status); status is 'ok'|'blank'|'invalid'."""
    text = _clean_value(value)
    if _is_placeholder(text):
        return "", "blank"
    if "/" not in text:
        return "", "invalid"
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return "", "invalid"
    return str(net), "ok"


def _norm_mask(value):
    """'/23' -> '23'; dotted masks and bare numbers pass through cleaned."""
    text = _clean_value(value)
    if _is_placeholder(text):
        return ""
    if text.startswith("/"):
        text = text[1:].strip()
    return text


_ASN_RE = re.compile(r"^\d+(?:\.\d+)?(?:[eE]\+?\d+)?$")


def _norm_asn(value):
    """Normalize an ASN cell ('4200000101', '4.200000101E9', '65100.0')."""
    text = _clean_value(value)
    if not text or not _ASN_RE.match(text):
        return ""
    try:
        asn = int(float(text))
    except (ValueError, OverflowError):
        return ""
    if not 0 < asn < 2 ** 32:
        return ""
    return str(asn)


# ---------------------------------------------------------------------------
# Header vocabulary
# ---------------------------------------------------------------------------

_HOSTNAME_HEADERS = {
    "hostname", "hostnames", "host", "nvishostname", "nvisvendorhostname",
    "vendorhostname", "devicename", "customerhostname",
}
_DEVICE_HEADERS = {"device", "server", "node"}
_INTERFACE_HEADERS = {"interface", "iface", "interfaces", "port"}
_IP_RE = re.compile(r"^ip(?:address|addr)?$")
_MASK_HEADERS = {"mask", "subnetmask", "netmask"}
_SUBNET_HEADERS = {"subnet", "subnets", "subnetcidr", "cidr", "prefix", "iprange"}


def _skip_header(raw):
    """Helper/underscore columns (_pfx, _netint...) are never mapped."""
    return str(raw or "").strip().startswith("_")


def _is_hostname_header(sq):
    return sq in _HOSTNAME_HEADERS


def _is_device_header(sq):
    return sq in _DEVICE_HEADERS


# ---------------------------------------------------------------------------
# Family 1: assignment blocks (side-by-side repeatable)
# ---------------------------------------------------------------------------

def _assign_kind(sq):
    if _is_hostname_header(sq):
        return "hostname"
    if _is_device_header(sq):
        return "device"
    if sq in _INTERFACE_HEADERS:
        return "interface"
    if _IP_RE.match(sq):
        return "ip"
    if sq in _MASK_HEADERS:
        return "mask"
    if sq in _SUBNET_HEADERS:
        return "subnet"
    if sq == "gw" or sq.startswith("gateway"):
        return "gateway"
    if sq.startswith("vlan"):
        return "vlan"
    if sq.startswith("vrf"):
        return "vrf"
    return ""


def _map_assignment_blocks(values):
    """Map repeated NODE/INTERFACE/IP header clusters across the column axis.

    Returns a list of column maps, one per block (empty list if the row is
    not an assignment header).
    """
    blocks = []
    cur = None
    for idx, raw in enumerate(values):
        text = str(raw or "").strip()
        if not text or _skip_header(text):
            continue
        kind = _assign_kind(_squash(text))
        if not kind:
            continue
        if kind in ("hostname", "device"):
            if cur is not None and "ip" in cur:
                blocks.append(cur)
                cur = None
            if cur is None:
                cur = {}
            cur.setdefault(kind, idx)
        elif cur is not None:
            cur.setdefault(kind, idx)
    if cur is not None:
        blocks.append(cur)
    return [
        b for b in blocks
        if ("hostname" in b or "device" in b) and "ip" in b and "interface" in b
    ]


def _cell(values, col_map, key):
    idx = col_map.get(key, -1)
    if idx < 0 or idx >= len(values):
        return ""
    return _clean_value(values[idx])


def _looks_like_header_repeat(name):
    sq = _squash(name)
    return _is_hostname_header(sq) or _is_device_header(sq)


class _SheetStats:
    """Per-sheet blank/invalid accounting -> aggregated warnings."""

    def __init__(self, sheet_name):
        self.sheet_name = sheet_name
        self.blank = 0
        self.invalid = []

    def note_invalid(self, raw):
        self.invalid.append(_clean_value(raw))

    def warnings(self, blank_label="row(s) with blank/tbd IP skipped"):
        out = []
        if self.blank:
            out.append("sheet '%s': %d %s" % (self.sheet_name, self.blank, blank_label))
        if self.invalid:
            examples = ", ".join(repr(v) for v in self.invalid[:MAX_WARNING_EXAMPLES])
            out.append(
                "sheet '%s': %d invalid IP/prefix value(s) skipped (e.g. %s)"
                % (self.sheet_name, len(self.invalid), examples)
            )
        return out


def _assignment_from_block(values, block, stats):
    """Build one assignment dict from a data row and a block col map."""
    ip, prefixlen, status = _parse_ip(_cell(values, block, "ip"))
    if status == "blank":
        stats.blank += 1
        return None
    if status == "invalid":
        stats.note_invalid(_cell(values, block, "ip"))
        return None
    assignment = {
        "role_or_interface": _cell(values, block, "interface"),
        "ip": ip,
    }
    mask = _norm_mask(_cell(values, block, "mask"))
    if not mask and prefixlen is not None:
        mask = str(prefixlen)
    if not mask and "subnet" in block:
        prefix, pstatus = _parse_prefix(_cell(values, block, "subnet"))
        if pstatus == "ok":
            mask = prefix.rsplit("/", 1)[1]
    if mask:
        assignment["prefixlen_or_mask"] = mask
    gw, _, gw_status = _parse_ip(_cell(values, block, "gateway"))
    if gw_status == "ok":
        assignment["gateway"] = gw
    vlan = _cell(values, block, "vlan")
    if vlan:
        assignment["vlan"] = vlan
    vrf = _cell(values, block, "vrf")
    if vrf:
        assignment["vrf"] = vrf
    return assignment


def _assignment_row(values, blocks, hosts, sheet_name, stats):
    for block in blocks:
        hostname = _cell(values, block, "hostname") or _cell(values, block, "device")
        if not hostname or _is_placeholder(hostname) or _looks_like_header_repeat(hostname):
            continue
        assignment = _assignment_from_block(values, block, stats)
        if assignment is None:
            continue
        record = hosts.setdefault(hostname, {
            "hostname": hostname, "assignments": [], "sheet": sheet_name,
        })
        record["assignments"].append(assignment)


# ---------------------------------------------------------------------------
# Family 2: L3 links (source/dest or border-eBGP local/peer intent rows)
# ---------------------------------------------------------------------------

_A_SIDE_PREFIXES = ("source", "src", "local", "border", "near")
_B_SIDE_PREFIXES = ("destination", "dest", "dst", "remote", "peer", "far", "firewall")

_L3_HOST_RE = re.compile(r"^(?:hostname|host|switch|device|node|name|router)$")
_L3_IP_RE = re.compile(r"^ip(?:address|addr)?\d*$")
_L3_IF_RE = re.compile(r"^(?:interface|iface|port|int)$")


def _l3_field(sq):
    """-> ('a'|'b'|'', 'host'|'if'|'ip'|'mask'|'asn'|'vrf'|'') for one header."""
    side = ""
    rest = sq
    stripped = True
    while stripped:
        stripped = False
        for prefix in _A_SIDE_PREFIXES + _B_SIDE_PREFIXES:
            if rest.startswith(prefix) and len(rest) > len(prefix):
                if not side:
                    side = "a" if prefix in _A_SIDE_PREFIXES else "b"
                rest = rest[len(prefix):]
                stripped = True
                break
    if _L3_HOST_RE.match(rest):
        return side, "host"
    if _L3_IF_RE.match(rest):
        return side, "if"
    if _L3_IP_RE.match(rest):
        return side, "ip"
    if rest in _MASK_HEADERS:
        return side, "mask"
    if rest == "asn":
        return side, "asn"
    if rest == "vrf":
        return side, "vrf"
    return side, ""


def _map_l3(values):
    col_map = {}
    for idx, raw in enumerate(values):
        text = str(raw or "").strip()
        if not text or _skip_header(text):
            continue
        side, field = _l3_field(_squash(text))
        if not field:
            continue
        if field in ("mask", "vrf") and not side:
            col_map.setdefault(field, idx)
            continue
        if not side:
            continue
        col_map.setdefault(side + "_" + field, idx)
    if all(k in col_map for k in ("a_host", "a_ip", "b_ip")):
        return col_map
    return {}


def _l3_row(values, col_map, links, sheet_name, stats):
    a_host = _cell(values, col_map, "a_host")
    if not a_host or _is_placeholder(a_host) or _looks_like_header_repeat(a_host):
        return
    a_ip, a_pfx, a_status = _parse_ip(_cell(values, col_map, "a_ip"))
    b_ip, _, b_status = _parse_ip(_cell(values, col_map, "b_ip"))
    if a_status == "invalid" or b_status == "invalid":
        stats.note_invalid(_cell(values, col_map, "a_ip" if a_status == "invalid" else "b_ip"))
        return
    if a_status == "blank" or b_status == "blank":
        stats.blank += 1
        return
    link = {
        "a_host": a_host,
        "a_if": _cell(values, col_map, "a_if"),
        "a_ip": a_ip,
        "b_host": _cell(values, col_map, "b_host"),
        "b_if": _cell(values, col_map, "b_if"),
        "b_ip": b_ip,
        "sheet": sheet_name,
    }
    mask = _norm_mask(_cell(values, col_map, "mask"))
    if not mask and a_pfx is not None:
        mask = str(a_pfx)
    if mask:
        link["mask"] = mask
    for key in ("a_asn", "b_asn"):
        asn = _norm_asn(_cell(values, col_map, key))
        if asn:
            link[key] = asn
    vrf = _cell(values, col_map, "vrf")
    if vrf:
        link["vrf"] = vrf
    links.append(link)


# ---------------------------------------------------------------------------
# Family 3: fabric inventory (Device/Hostname/Role/Mgmt IP/Loopback/ASN)
# ---------------------------------------------------------------------------

def _map_fabric(values):
    col_map = {}
    for idx, raw in enumerate(values):
        text = str(raw or "").strip()
        if not text or _skip_header(text):
            continue
        sq = _squash(text)
        if sq == "customerhostname":
            col_map.setdefault("customer", idx)
        elif _is_hostname_header(sq):
            col_map.setdefault("hostname", idx)
        elif _is_device_header(sq):
            col_map.setdefault("device", idx)
        elif sq == "role":
            col_map.setdefault("role", idx)
        elif sq in ("managementip", "mgmtip"):
            col_map.setdefault("mgmt_ip", idx)
        elif sq in ("loopback", "loopbackip"):
            col_map.setdefault("loopback_ip", idx)
        elif sq in ("asn", "bgpasn", "asnumber", "asnum"):
            col_map.setdefault("asn", idx)
        elif sq == "fabric":
            col_map.setdefault("fabric", idx)
    if "hostname" not in col_map and "device" not in col_map:
        return {}
    if "loopback_ip" in col_map or "asn" in col_map or (
            "mgmt_ip" in col_map and "role" in col_map):
        return col_map
    return {}


def _fabric_row(values, col_map, records, sheet_name, stats):
    hostname = _cell(values, col_map, "hostname") or _cell(values, col_map, "device")
    if not hostname or _is_placeholder(hostname) or _looks_like_header_repeat(hostname):
        return
    record = {"hostname": hostname, "sheet": sheet_name}
    device = _cell(values, col_map, "device")
    if device and device != hostname:
        record["device"] = device
    role = _cell(values, col_map, "role")
    if role:
        record["role"] = role
    fabric = _cell(values, col_map, "fabric")
    if fabric:
        record["fabric"] = fabric
    for key in ("mgmt_ip", "loopback_ip"):
        raw = _cell(values, col_map, key)
        ip, _, status = _parse_ip(raw)
        if status == "ok":
            record[key] = ip
        elif status == "invalid":
            stats.note_invalid(raw)
    asn = _norm_asn(_cell(values, col_map, "asn"))
    if asn:
        record["asn"] = asn
    if len(record) > 2:
        records.append(record)


# ---------------------------------------------------------------------------
# Family 4: subnet catalogs (re-sniffed row by row: mini-tables can stack)
# ---------------------------------------------------------------------------

def _map_catalog(values):
    col_map = {}
    for idx, raw in enumerate(values):
        text = str(raw or "").strip()
        if not text or _skip_header(text):
            continue
        sq = _squash(text)
        if sq in _SUBNET_HEADERS:
            col_map.setdefault("subnet", idx)
        elif sq in ("network", "networks"):
            col_map.setdefault("network", idx)
        elif sq in ("name", "networkname", "subnetname"):
            col_map.setdefault("name", idx)
        elif sq in ("purpose", "purposedescription"):
            col_map.setdefault("purpose", idx)
        elif sq in ("description", "desc"):
            col_map.setdefault("description", idx)
        elif sq == "gw" or sq.endswith("gw") or sq.startswith("gateway"):
            col_map.setdefault("gateway", idx)
        elif sq.startswith("vlan"):
            col_map.setdefault("vlan", idx)
        elif sq == "vrf":
            col_map.setdefault("vrf", idx)
        elif sq in ("type", "fabric"):
            col_map.setdefault("type", idx)
    if "subnet" not in col_map and "network" not in col_map:
        return {}
    prefix_key = "subnet" if "subnet" in col_map else "network"
    extras = set(col_map) - {prefix_key}
    if not extras:
        return {}
    col_map["_prefix"] = col_map[prefix_key]
    return col_map


def _catalog_name(values, col_map):
    for key in ("name", "network", "purpose", "description"):
        if key == "network" and col_map.get("_prefix") == col_map.get("network"):
            continue  # 'Network' column is the prefix itself, not a name
        value = _cell(values, col_map, key)
        if value and not _is_placeholder(value):
            return value
    return ""


def _catalog_row(values, col_map, records, sheet_name, stats):
    raw = _cell(values, col_map, "_prefix")
    prefix, status = _parse_prefix(raw)
    if status == "blank":
        return
    if status == "invalid":
        stats.note_invalid(raw)
        return
    record = {"name": _catalog_name(values, col_map), "prefix": prefix,
              "sheet": sheet_name}
    gw, _, gw_status = _parse_ip(_cell(values, col_map, "gateway"))
    if gw_status == "ok":
        record["gateway"] = gw
    for key in ("vrf", "vlan", "type"):
        value = _cell(values, col_map, key)
        if value and not _is_placeholder(value):
            record[key] = value
    records.append(record)


# ---------------------------------------------------------------------------
# Family 5: wide host tables (hostname + many IP columns)
# ---------------------------------------------------------------------------

_RAIL_RE = re.compile(r"^rail\d+$")


def _map_wide_host(values):
    host_col = device_col = global_mask = None
    ip_cols = []       # [(idx, header_text, stem)]
    mask_cols = {}     # stem -> idx
    for idx, raw in enumerate(values):
        text = str(raw or "").strip()
        if not text or _skip_header(text):
            continue
        sq = _squash(text)
        if _is_hostname_header(sq):
            if host_col is None:
                host_col = idx
        elif _is_device_header(sq):
            if device_col is None:
                device_col = idx
        elif _RAIL_RE.match(sq):
            ip_cols.append((idx, text, sq))
        elif sq.endswith("ip") and len(sq) > 2 and "mac" not in sq:
            ip_cols.append((idx, text, sq[:-2]))
        elif sq in ("cidr", "mask", "subnetmask") and global_mask is None:
            global_mask = idx
        elif sq.endswith("net") and len(sq) > 3:
            mask_cols[sq[:-3]] = idx
        elif sq.endswith("mask") and len(sq) > 4:
            mask_cols[sq[:-4]] = idx
    if host_col is None:
        host_col = device_col
    if host_col is None or not ip_cols:
        return {}
    return {"host": host_col, "ips": ip_cols, "masks": mask_cols,
            "global_mask": global_mask}


def _parse_wide_host_sheet(sheet_name, rows, header_idx, wide_map):
    hosts = {}
    stats = _SheetStats(sheet_name)
    host_col = wide_map["host"]
    for row_idx in range(header_idx + 1, len(rows)):
        values = rows[row_idx]
        if not values or host_col >= len(values):
            continue
        hostname = _clean_value(values[host_col])
        if not hostname or _is_placeholder(hostname) or _looks_like_header_repeat(hostname):
            continue
        assignments = []
        for idx, header, stem in wide_map["ips"]:
            raw = values[idx] if idx < len(values) else None
            ip, prefixlen, status = _parse_ip(raw)
            if status == "blank":
                continue  # sparse wide tables: empty cells are normal
            if status == "invalid":
                stats.note_invalid(raw)
                continue
            assignment = {"role_or_interface": header, "ip": ip}
            mask = ""
            if stem in wide_map["masks"]:
                mask = _norm_mask(_cell(values, {"m": wide_map["masks"][stem]}, "m"))
            if not mask and prefixlen is not None:
                mask = str(prefixlen)
            if not mask and wide_map["global_mask"] is not None:
                mask = _norm_mask(_cell(values, {"m": wide_map["global_mask"]}, "m"))
            if mask:
                assignment["prefixlen_or_mask"] = mask
            assignments.append(assignment)
        if not assignments:
            continue
        record = hosts.setdefault(hostname, {
            "hostname": hostname, "assignments": [], "sheet": sheet_name,
        })
        record["assignments"].extend(assignments)
    return list(hosts.values()), stats.warnings()


# ---------------------------------------------------------------------------
# Sheet dispatch + workbook -> canonical dict
# ---------------------------------------------------------------------------

def _parse_sheet(sheet_name, rows):
    """-> ({category: records}, warnings) or (None, None) for non-data tabs.

    Every row is checked against the header sniffers in specificity order
    (assignment blocks, L3 links, fabric inventory, subnet catalog); a match
    switches the active table state, so mini-tables of different families
    stacked vertically inside one sheet (subnet catalogs above hostname/ASN
    tables, repeated catalog headers, ...) all parse. Wide host tables are a
    whole-sheet fallback because their sniff is the loosest.
    """
    stats = _SheetStats(sheet_name)
    hosts = {}
    out = {"subnets": [], "fabric": [], "l3_links": []}
    state = None
    for values in rows:
        if not values:
            continue
        blocks = _map_assignment_blocks(values)
        if blocks:
            state = ("hosts", blocks)
            continue
        l3_map = _map_l3(values)
        if l3_map:
            state = ("l3_links", l3_map)
            continue
        fabric_map = _map_fabric(values)
        if fabric_map:
            state = ("fabric", fabric_map)
            continue
        catalog_map = _map_catalog(values)
        if catalog_map:
            state = ("subnets", catalog_map)
            continue
        if state is None:
            continue
        category, mapping = state
        if category == "hosts":
            _assignment_row(values, mapping, hosts, sheet_name, stats)
        elif category == "l3_links":
            _l3_row(values, mapping, out["l3_links"], sheet_name, stats)
        elif category == "fabric":
            _fabric_row(values, mapping, out["fabric"], sheet_name, stats)
        else:
            _catalog_row(values, mapping, out["subnets"], sheet_name, stats)
    if state is not None:
        out["hosts"] = list(hosts.values())
        return out, stats.warnings()
    # Fallback: wide host tables (hostname + many IP columns)
    limit = min(len(rows), MAX_HEADER_SCAN_ROWS)
    for idx in range(limit):
        values = rows[idx]
        if not values:
            continue
        wide_map = _map_wide_host(values)
        if wide_map:
            records, warnings = _parse_wide_host_sheet(sheet_name, rows, idx, wide_map)
            return {"hosts": records}, warnings
    return None, None


def parse_workbook(path):
    """Parse an IP-allocation workbook into the canonical IPAM dict."""
    path = Path(path)
    result = {
        "format": CANONICAL_FORMAT,
        "source_file": path.name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_records": 0,
        "subnets": [],
        "hosts": [],
        "fabric": [],
        "l3_links": [],
        "skipped_sheets": [],
        "warnings": [],
    }
    for sheet_name, rows in iter_workbook_sheets(path):
        parsed, warnings = _parse_sheet(sheet_name, rows)
        if parsed is None:
            result["skipped_sheets"].append(sheet_name)
            continue
        total = 0
        for category in ("subnets", "hosts", "fabric", "l3_links"):
            records = parsed.get(category) or []
            result[category].extend(records)
            total += len(records)
        if not total:
            result["warnings"].append(
                "sheet '%s': data header found but no usable rows" % sheet_name)
        result["warnings"].extend(warnings)
    result["total_records"] = (
        len(result["subnets"]) + len(result["fabric"]) + len(result["l3_links"])
        + sum(len(h["assignments"]) for h in result["hosts"])
    )
    return result


# ---------------------------------------------------------------------------
# Query helpers (Ask-AI / Inventory wiring)
# ---------------------------------------------------------------------------

def _host_keys(name):
    """Case/FQDN tolerant device keys, same semantics as ai_p2p lookup."""
    low = str(name or "").strip().lower()
    keys = {low}
    if "." in low:
        keys.add(low.split(".", 1)[0])
    return keys


def lookup_host(data, hostname):
    """All design records for a hostname (case/FQDN tolerant).

    -> {'hostname', 'hosts': [host records], 'fabric': [fabric records]}
    Fabric records also match on their 'device' label alias.
    """
    want = _host_keys(hostname)
    hosts = [h for h in data.get("hosts", []) if _host_keys(h.get("hostname")) & want]
    fabric = [
        f for f in data.get("fabric", [])
        if (_host_keys(f.get("hostname")) | _host_keys(f.get("device"))) & want
    ]
    return {"hostname": hostname, "hosts": hosts, "fabric": fabric}


def lookup_ip(data, ip):
    """Design records matching one IP.

    -> {'ip', 'hosts': [{hostname, sheet, assignment}], 'fabric':
        [{record, match_field}], 'subnets': [subnet records, longest prefix
        first]}
    """
    ip_str, _, status = _parse_ip(ip)
    result = {"ip": ip_str or _clean_value(ip), "hosts": [], "fabric": [], "subnets": []}
    if status != "ok":
        return result
    ip_obj = ipaddress.ip_address(ip_str)
    for host in data.get("hosts", []):
        for assignment in host.get("assignments", []):
            if assignment.get("ip") == ip_str:
                result["hosts"].append({
                    "hostname": host.get("hostname", ""),
                    "sheet": host.get("sheet", ""),
                    "assignment": assignment,
                })
    for record in data.get("fabric", []):
        for field in ("mgmt_ip", "loopback_ip"):
            if record.get(field) == ip_str:
                result["fabric"].append({"record": record, "match_field": field})
                break
    matches = []
    for subnet in data.get("subnets", []):
        try:
            net = ipaddress.ip_network(subnet.get("prefix", ""))
        except ValueError:
            continue
        if net.version == ip_obj.version and ip_obj in net:
            matches.append((net.prefixlen, subnet))
    matches.sort(key=lambda item: item[0], reverse=True)
    result["subnets"] = [subnet for _, subnet in matches]
    return result


def expected_bgp(data):
    """Design BGP truth for design-vs-live checks.

    -> {hostname: {'loopback': ip_or_'', 'asn': str_or_''}} from fabric
    records that carry a loopback and/or ASN.
    """
    out = {}
    for record in data.get("fabric", []):
        hostname = record.get("hostname", "")
        loopback = record.get("loopback_ip", "")
        asn = record.get("asn", "")
        if not hostname or not (loopback or asn):
            continue
        out.setdefault(hostname, {"loopback": loopback, "asn": asn})
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_summary(result):
    print("format:        %s" % result.get("format", ""))
    print("source_file:   %s" % result.get("source_file", ""))
    print("total_records: %s" % result.get("total_records", 0))
    assignments = sum(len(h["assignments"]) for h in result.get("hosts", []))
    print("subnets:       %d" % len(result.get("subnets", [])))
    print("hosts:         %d (%d assignments)" % (len(result.get("hosts", [])), assignments))
    print("fabric:        %d" % len(result.get("fabric", [])))
    print("l3_links:      %d" % len(result.get("l3_links", [])))
    per_sheet = {}
    for category in ("subnets", "hosts", "fabric", "l3_links"):
        for record in result.get(category, []):
            key = (record.get("sheet", ""), category)
            per_sheet[key] = per_sheet.get(key, 0) + 1
    print("\nrecords per sheet:")
    for (sheet, category), count in per_sheet.items():
        print("  %-40s %-10s %6d" % (sheet, category, count))
    skipped = result.get("skipped_sheets", [])
    print("\nskipped sheets (%d):" % len(skipped))
    for name in skipped:
        print("  %s" % name)
    warnings = result.get("warnings", [])
    print("\nwarnings (%d):" % len(warnings))
    for warning in warnings[:20]:
        print("  %s" % warning)
    if len(warnings) > 20:
        print("  ... and %d more" % (len(warnings) - 20))


def main(argv):
    args = [a for a in argv[1:] if a != "--summary"]
    summary = "--summary" in argv[1:]
    if len(args) != 1:
        print("usage: python3 ai_ipam.py <file.xlsx|file.xlsm> [--summary]", file=sys.stderr)
        return 2
    path = Path(args[0])
    if path.suffix.lower() not in (".xlsx", ".xlsm", ".xltx", ".xltm"):
        print("error: unsupported IPAM input: %s (expected .xlsx/.xlsm)" % path, file=sys.stderr)
        return 2
    try:
        result = parse_workbook(path)
    except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if summary:
        _print_summary(result)
    else:
        json.dump(result, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
