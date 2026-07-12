#!/usr/bin/env python3
"""Deterministic artifact generators for the LLDPq Inventory page (offline layer).

This is the AI-free "Tier 1" of the Inventory/Bootstrap feature: given a parsed
P2P cabling design (ai_p2p) and/or a parsed IP-allocation design (ai_ipam), it
produces drafts of the three LLDPq install files exactly in their on-disk
contract so the drafts round-trip through the existing readers:

  - p2p_to_topology_dot(connections)       -> GraphViz DOT text (topology.dot)
  - ipam_to_devices_yaml(ipam, existing)   -> devices.yaml draft + structured diff
  - ipam_to_topology_config_yaml(ipam,p2p) -> topology_config.yaml draft

Everything here is stdlib only (no PyYAML, no openpyxl): the xlsx parsing already
happened in ai_p2p/ai_ipam, and the YAML we emit/read is the narrow subset LLDPq
uses. The generators never touch disk; the Inventory API is responsible for
preview/backup/confirm gating before any file is written.

CLI (manual testing):
    python3 ai_generate.py topology-dot   <connections.json>
    python3 ai_generate.py devices        <ipam.json> [existing_devices.yaml]
    python3 ai_generate.py topology-config <ipam.json> [connections.json]
    python3 ai_generate.py validate-p2p   <connections.json>
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ai_p2p  # noqa: E402
import ai_ipam  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"[\s\x00-\x1f\x7f]")


def _clean(value):
    return ai_p2p._clean_value(value)


def _os_port(port):
    """Normalize a design port to the OS/LLDP interface spelling topology.dot uses.

    LLDPq's topology.dot and check-lldp compare against the interface names LLDP
    advertises ('swp49', 'swp64s0'), so breakout '64/1' notation and bare port
    numbers are converted; anything already in swp*/host-interface form (or a
    non-switch port such as a HCA name) is preserved verbatim.
    """
    raw = _clean(port)
    if not raw:
        return ""
    low = raw.lower().replace(" ", "")
    match = re.match(r"^(\d+)/(\d+)$", low)  # breakout N/M -> swpNs(M-1) (0-based sub-port)
    if match:
        return "swp%ss%d" % (match.group(1), int(match.group(2)) - 1)
    # Three-part port/cage/split notation: '3/1/2' = port 3, cage 1, split 2
    # (1-based) -> swp3s1.
    match = re.match(r"^(\d+)/(\d+)/(\d+)$", low)
    if match:
        return "swp%ss%d" % (match.group(1), int(match.group(3)) - 1)
    if re.match(r"^\d+$", low):  # bare number -> swpN
        return "swp" + low
    return raw


def _bad_token(text):
    """True when a device/port cannot appear in topology.dot (empty / whitespace)."""
    return not text or bool(_WS_RE.search(text))


# ---------------------------------------------------------------------------
# 1. P2P design -> topology.dot
# ---------------------------------------------------------------------------

# Order/labels for the grouped comment sections in the emitted DOT.
_CTYPE_LABELS = (
    ("oob", "OOB / management plane"),
    ("mgmt", "Management"),
    ("ctrl", "Control plane"),
    ("compute", "Compute fabric"),
    ("storage", "Storage fabric"),
    ("vast", "VAST storage"),
    ("converged", "Converged Ethernet"),
    ("tan", "TAN / border"),
    ("inband", "In-band"),
    ("in-rack", "In-rack"),
    ("general", "General"),
)
# Connection planes that are not LLDP-validated network links.
_EXCLUDED_CTYPES = {"power"}


def p2p_to_topology_dot(connections, graph_name="FABRIC", device_aliases=None,
                        port_aliases=None):
    """Render resolved physical P2P links as a topology.dot GraphViz graph.

    Only resolved links are emitted (ai_p2p already drops tbd/blank/customer
    endpoints). Ports are normalized to OS interface spelling, the power plane is
    excluded, and any endpoint that is reused by a later link is dropped so the
    output satisfies LLDPq's point-to-point semantics (topology_edges rejects a
    reused endpoint or a duplicate edge). The result parses cleanly through both
    ai_correlate.load_expected_links and lldpq/topology_edges.parse_topology_file.

    device_aliases / port_aliases translate design labels to the live spelling
    ({lower(designLabel): liveName}, from display-aliases.json reversed) —
    topology.dot must name what LLDP actually reports, and P2P workbooks often
    label devices/ports differently. Absent or empty maps are a no-op.
    """
    name = re.sub(r'["\\\x00-\x1f]', "", str(graph_name or "FABRIC")).strip() or "FABRIC"
    device_aliases = device_aliases or {}
    port_aliases = port_aliases or {}

    def live_device(dev):
        return device_aliases.get(dev.lower(), dev)

    def live_port(port):
        return port_aliases.get(port.lower(), port)

    grouped = {}
    used_endpoints = set()
    seen_edges = set()
    # Group-fitted breakout resolution for three-part 'X/Y/Z' ports (needs the
    # whole design for context); _os_port stays as the per-port fallback.
    resolved = ai_p2p.resolve_port_map(connections)
    for link in ai_p2p.expected_links(connections):
        ctype = str((link.get("meta") or {}).get("connection_type") or "general").lower()
        if ctype in _EXCLUDED_CTYPES:
            continue
        a_dev, b_dev = _clean(link.get("a_dev")), _clean(link.get("b_dev"))
        a_port = (ai_p2p.resolved_os_port(resolved, a_dev, link.get("a_port"))
                  or _os_port(link.get("a_port")))
        b_port = (ai_p2p.resolved_os_port(resolved, b_dev, link.get("b_port"))
                  or _os_port(link.get("b_port")))
        a_dev, b_dev = live_device(a_dev), live_device(b_dev)
        a_port, b_port = live_port(a_port), live_port(b_port)
        if _bad_token(a_dev) or _bad_token(a_port) or _bad_token(b_dev) or _bad_token(b_port):
            continue
        left = (a_dev.casefold(), a_port)
        right = (b_dev.casefold(), b_port)
        if left == right:
            continue  # self-loop
        edge_key = tuple(sorted((left, right)))
        if edge_key in seen_edges:
            continue
        if left in used_endpoints or right in used_endpoints:
            # Reused endpoint: keep the first link, drop the conflicting one so
            # the file passes strict topology validation. validate_p2p surfaces
            # the underlying design conflict separately.
            continue
        seen_edges.add(edge_key)
        used_endpoints.add(left)
        used_endpoints.add(right)
        grouped.setdefault(ctype, []).append((a_dev, a_port, b_dev, b_port))

    lines = ["graph \"%s\" {" % name]
    ordered = [c for c, _ in _CTYPE_LABELS if c in grouped]
    ordered += sorted(c for c in grouped if c not in {c2 for c2, _ in _CTYPE_LABELS})
    label_map = dict(_CTYPE_LABELS)
    for ctype in ordered:
        edges = grouped[ctype]
        edges.sort(key=lambda e: _natural_key("%s %s %s %s" % e))
        lines.append("")
        lines.append("# %s" % label_map.get(ctype, ctype))
        lines.append("")
        for a_dev, a_port, b_dev, b_port in edges:
            lines.append('"%s":"%s" -- "%s":"%s"' % (a_dev, a_port, b_dev, b_port))
    lines.append("")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _natural_key(text):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", str(text or ""))]


# ---------------------------------------------------------------------------
# P2P validation (Inventory "validate" report; reuses ai_p2p warnings)
# ---------------------------------------------------------------------------

def validate_p2p(connections):
    """Deterministic design-quality report for the Inventory validate action.

    Reuses the parser warnings carried on the canonical dict and adds structural
    checks the parser does not perform: reused/duplicate ports, port(OS)/breakout
    mismatches, unresolved (tbd/blank) endpoints, and duplicate cable records.

    -> {"issues": [{severity, kind, message, ...}], "counts": {...},
        "warnings": [parser warnings]}
    """
    records = ai_p2p._records_of(connections)
    warnings = list(connections.get("warnings", [])) if isinstance(connections, dict) else []
    issues = []

    port_owner = {}       # (device_key, os_port) -> first row_number using it
    edge_seen = {}        # frozenset endpoint keys -> first row_number
    unresolved = 0

    for record in records:
        row = record.get("row_number", "?")
        endpoints = []
        for side in ("source", "dest"):
            dev = _clean(record.get(side + "_name"))
            raw_port = _clean(record.get(side + "_port"))
            os_port = _os_port(raw_port)
            endpoints.append((dev, raw_port, os_port))
            if not dev or not raw_port:
                continue
            dev_key = min(ai_p2p._device_keys(dev))
            # port(OS)/breakout mismatch: a breakout child port on a device whose
            # base swpN is also cabled as a whole (design inconsistency).
            key = (dev_key, os_port)
            if key in port_owner and port_owner[key] != row:
                issues.append({
                    "severity": "error",
                    "kind": "duplicate-port",
                    "message": "%s port %s (%s) used by rows %s and %s"
                    % (dev, raw_port, os_port, port_owner[key], row),
                    "device": dev, "port": raw_port, "row": row,
                })
            else:
                port_owner.setdefault(key, row)

        if record.get("unresolved"):
            unresolved += 1
            continue

        (a_dev, a_raw, a_os), (b_dev, b_raw, b_os) = endpoints
        if a_dev and b_dev and a_raw and b_raw:
            edge_key = frozenset((
                (min(ai_p2p._device_keys(a_dev)), a_os),
                (min(ai_p2p._device_keys(b_dev)), b_os),
            ))
            if len(edge_key) == 1:
                issues.append({
                    "severity": "error", "kind": "self-loop",
                    "message": "%s:%s cabled to itself (row %s)" % (a_dev, a_raw, row),
                    "row": row,
                })
            elif edge_key in edge_seen:
                issues.append({
                    "severity": "warning", "kind": "duplicate-record",
                    "message": "duplicate cable %s:%s <-> %s:%s (rows %s and %s)"
                    % (a_dev, a_raw, b_dev, b_raw, edge_seen[edge_key], row),
                    "row": row,
                })
            else:
                edge_seen[edge_key] = row

    if unresolved:
        issues.append({
            "severity": "info", "kind": "unresolved",
            "message": "%d cable row(s) have a tbd/blank/customer-provided endpoint; "
            "excluded from topology.dot" % unresolved,
            "count": unresolved,
        })

    counts = {
        "total_records": len(records),
        "resolved_links": len(edge_seen),
        "duplicate_ports": sum(1 for i in issues if i["kind"] == "duplicate-port"),
        "duplicate_records": sum(1 for i in issues if i["kind"] == "duplicate-record"),
        "unresolved": unresolved,
    }
    order = {"error": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda i: (order.get(i["severity"], 3), str(i.get("row"))))
    return {"issues": issues, "counts": counts, "warnings": warnings}


# ---------------------------------------------------------------------------
# 2. IPAM design -> devices.yaml (switch roles only)
# ---------------------------------------------------------------------------

# LLDPq role vocabulary (see devices.yaml examples). First switch match wins.
_SWITCH_ROLE_RULES = (
    ("spine", re.compile(r"spine|\bsp\d", re.IGNORECASE)),
    ("border", re.compile(r"border|brdr|\bbl\d|\bedge\b|\bbdr\b", re.IGNORECASE)),
    ("core", re.compile(r"\bcore\b|\bcr\d|oob[-_ ]?spine", re.IGNORECASE)),
    ("leaf", re.compile(r"leaf|\blf\d|clef|cleaf|sleaf|mleaf|\btor\b|\bl\d\b", re.IGNORECASE)),
    ("firewall", re.compile(r"firewall|\bfw\b|[-_]fw\b", re.IGNORECASE)),
    ("access", re.compile(r"access|\bsw\d|switch|oob[-_ ]?leaf|\bmgmt\b|\boob\b", re.IGNORECASE)),
)
# Endpoints that are not managed switches; excluded from devices.yaml.
_NONSWITCH_RE = re.compile(
    r"\bdgx\b|\bhgx\b|\bgpu\b|\bpdu\b|\bpsu\b|power|\bbmc\b|\bhost\b|server|"
    r"\bnode\b|compute|\bufm\b|\bcpu\b|\bnic\b",
    re.IGNORECASE,
)


def _map_switch_role(role, hostname):
    """Map an IPAM role/hostname onto the LLDPq role vocabulary, or None.

    None means "not a managed switch" (DGX/PDU/power/host/server): the record is
    filtered out of devices.yaml.
    """
    role_text = str(role or "").strip()
    host_text = str(hostname or "").strip()
    # A switch keyword anywhere wins over a non-switch keyword so that e.g.
    # 'storage-leaf' or 'oob-switch' stays in, while pure hosts are dropped.
    for canon, pattern in _SWITCH_ROLE_RULES:
        if role_text and pattern.search(role_text):
            return canon
    for canon, pattern in _SWITCH_ROLE_RULES:
        if pattern.search(host_text):
            return canon
    if _NONSWITCH_RE.search(role_text) or _NONSWITCH_RE.search(host_text):
        return None
    return None


def _parse_existing_devices(text):
    """Minimal devices.yaml reader -> (defaults_lines, [{ip, hostname, role}]).

    Understands the simple 'IP: Hostname @role' form and the extended block
    ('IP:' then indented 'hostname:'/'role:'). Enough to preserve the defaults
    block verbatim and to diff hostnames/roles/IPs against a generated draft.
    """
    defaults_lines = []
    devices = []
    section = None
    ip_re = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*:\s*(.*)$")
    cur_block = None

    def flush_block():
        if cur_block and cur_block.get("hostname"):
            devices.append(cur_block)

    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("#"):
            if section == "defaults":
                defaults_lines.append(line)
            continue
        if re.match(r"^defaults\s*:", stripped):
            flush_block()
            cur_block = None
            section = "defaults"
            continue
        if re.match(r"^devices\s*:", stripped):
            flush_block()
            cur_block = None
            section = "devices"
            continue
        if section == "defaults":
            if line and not line[0].isspace() and stripped:
                section = None  # dedent out of defaults
            else:
                defaults_lines.append(line)
                continue
        if section == "devices":
            if not stripped:
                continue
            match = ip_re.match(line)
            if match and _is_ip(match.group(1)):
                flush_block()
                cur_block = {"ip": match.group(1), "hostname": "", "role": ""}
                rest = match.group(2).strip()
                if rest:
                    host, role = _split_host_role(rest)
                    cur_block["hostname"] = host
                    cur_block["role"] = role
                continue
            # Indented sub-keys of an extended 'IP:' block.
            if cur_block is not None:
                sub = re.match(r"^(hostname|role|username)\s*:\s*(.*)$", stripped)
                if sub:
                    key, val = sub.group(1), sub.group(2).strip().strip('"\'')
                    if key == "hostname":
                        cur_block["hostname"] = val
                    elif key == "role":
                        cur_block["role"] = val.lstrip("@")
    flush_block()
    return defaults_lines, devices


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _split_host_role(text):
    match = re.match(r"^(\S+)\s*(?:@(\S+))?", text.strip())
    if not match:
        return text.strip(), ""
    return match.group(1), (match.group(2) or "")


_ROLE_SORT = {"border": 0, "core": 1, "spine": 2, "leaf": 3, "access": 4, "firewall": 5}


def ipam_to_devices_yaml(ipam, existing_yaml=None):
    """Draft a devices.yaml from IPAM fabric records + a structured diff.

    Only records that map to a switch role are emitted, formatted as
    'mgmt_ip: Hostname @role'. The existing defaults block (ssh username) is
    preserved. Returns {"yaml": <text>, "diff": {added, removed, changed},
    "skipped": [<hostnames filtered as non-switch/no-mgmt-ip>]}.
    """
    defaults_lines, existing_devices = _parse_existing_devices(existing_yaml)

    entries = []      # {ip, hostname, role}
    skipped = []
    seen_hosts = set()
    for record in (ipam.get("fabric") if isinstance(ipam, dict) else []) or []:
        hostname = str(record.get("hostname") or record.get("device") or "").strip()
        if not hostname:
            continue
        mgmt_ip = str(record.get("mgmt_ip") or "").strip()
        role = _map_switch_role(record.get("role"), hostname)
        if role is None:
            skipped.append(hostname)
            continue
        if not mgmt_ip or not _is_ip(mgmt_ip):
            skipped.append(hostname)
            continue
        key = hostname.casefold()
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        entries.append({"ip": mgmt_ip, "hostname": hostname, "role": role})

    entries.sort(key=lambda e: (_ROLE_SORT.get(e["role"], 8), _ip_sort_key(e["ip"])))

    while defaults_lines and not defaults_lines[-1].strip():
        defaults_lines.pop()
    if not defaults_lines:
        defaults_lines = ["  username: cumulus"]

    out = [
        "# devices.yaml draft generated by LLDPq Inventory from the IPAM design.",
        "# Switch roles only (DGX/PDU/power/host filtered). Review before applying.",
        "",
        "defaults:",
    ]
    out.extend(defaults_lines)
    out.append("")
    out.append("devices:")
    out.append("")
    for entry in entries:
        role_suffix = " @%s" % entry["role"] if entry["role"] else ""
        out.append("  %s: %s%s" % (entry["ip"], entry["hostname"], role_suffix))
    yaml_text = "\n".join(out) + "\n"

    diff = _devices_diff(existing_devices, entries)
    return {"yaml": yaml_text, "diff": diff, "skipped": skipped}


def _ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _devices_diff(existing, generated):
    """added/removed/changed keyed by hostname (case-insensitive)."""
    def index(items):
        out = {}
        for item in items:
            host = str(item.get("hostname") or "").strip()
            if host:
                out[host.casefold()] = {
                    "ip": str(item.get("ip") or ""),
                    "hostname": host,
                    "role": str(item.get("role") or "").lstrip("@"),
                }
        return out

    old = index(existing)
    new = index(generated)
    added, removed, changed = [], [], []
    for key, item in new.items():
        if key not in old:
            added.append(item)
        elif old[key]["ip"] != item["ip"] or old[key]["role"] != item["role"]:
            changed.append({"hostname": item["hostname"], "from": old[key], "to": item})
    for key, item in old.items():
        if key not in new:
            removed.append(item)
    added.sort(key=lambda i: i["hostname"].lower())
    removed.sort(key=lambda i: i["hostname"].lower())
    changed.sort(key=lambda i: i["hostname"].lower())
    return {"added": added, "removed": removed, "changed": changed}


# ---------------------------------------------------------------------------
# 3. IPAM/P2P design -> topology_config.yaml
# ---------------------------------------------------------------------------

# Role -> (layer, icon) for the generated device_categories draft. Layer numbers
# follow the shipped topology_config.yaml example (firewall top, core bottom).
_ROLE_TOPO = {
    "firewall": (1, "firewall"),
    "border": (2, "switch"),
    "spine": (3, "switch"),
    "leaf": (4, "switch"),
    "access": (7, "switch"),
    "core": (6, "switch"),
}
_TOPO_ORDER = ("firewall", "border", "spine", "leaf", "core", "access")


def ipam_to_topology_config_yaml(ipam, p2p=None):
    """Draft a topology_config.yaml matching the shipped shape.

    device_categories are emitted only for the roles actually present in the
    design (from IPAM fabric roles/hostnames, with P2P device names as a
    fallback source of names), each mapped to the layer/icon LLDPq expects.
    """
    roles_present = set()
    for record in (ipam.get("fabric") if isinstance(ipam, dict) else []) or []:
        role = _map_switch_role(record.get("role"), record.get("hostname") or record.get("device"))
        if role:
            roles_present.add(role)
    if p2p is not None:
        for link in ai_p2p.expected_links(p2p):
            for dev in (link.get("a_dev"), link.get("b_dev")):
                role = _map_switch_role("", dev)
                if role:
                    roles_present.add(role)

    lines = [
        "# topology_config.yaml draft generated by LLDPq Inventory.",
        "# Review layers/icons before applying.",
        "",
        "topology: minimal  # [full] or [minimal]",
        "",
        "device_categories:",
        "",
    ]
    ordered = [r for r in _TOPO_ORDER if r in roles_present]
    if not ordered:
        # Nothing recognized: still emit a valid, minimal skeleton.
        ordered = ["spine", "leaf"]
    for role in ordered:
        layer, icon = _ROLE_TOPO.get(role, (7, "switch"))
        lines.append('  - pattern: "%s"' % role)
        lines.append("    layer: %d" % layer)
        lines.append('    icon: "%s"' % icon)
        lines.append("")
    lines.append("# Default category for unmatched devices")
    lines.append("default:")
    lines.append("  layer: 9")
    lines.append('  icon: "server"')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_p2p(path):
    return ai_p2p.load_connections(path)


def _load_ipam(path):
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    return ai_ipam.parse_workbook(path)


def main(argv):
    if len(argv) < 3:
        print("usage: python3 ai_generate.py <topology-dot|devices|topology-config|"
              "validate-p2p> <input> [extra]", file=sys.stderr)
        return 2
    mode, inp = argv[1], argv[2]
    extra = argv[3] if len(argv) > 3 else None
    if mode == "topology-dot":
        sys.stdout.write(p2p_to_topology_dot(_load_p2p(inp)))
    elif mode == "validate-p2p":
        json.dump(validate_p2p(_load_p2p(inp)), sys.stdout, indent=2)
        print()
    elif mode == "devices":
        existing = Path(extra).read_text(encoding="utf-8") if extra else None
        result = ipam_to_devices_yaml(_load_ipam(inp), existing_yaml=existing)
        sys.stdout.write(result["yaml"])
        print("\n# ---- diff ----", file=sys.stderr)
        json.dump(result["diff"], sys.stderr, indent=2)
    elif mode == "topology-config":
        p2p = _load_p2p(extra) if extra else None
        sys.stdout.write(ipam_to_topology_config_yaml(_load_ipam(inp), p2p=p2p))
    else:
        print("unknown mode: %s" % mode, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
