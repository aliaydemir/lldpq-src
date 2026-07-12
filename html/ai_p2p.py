#!/usr/bin/env python3
"""P2P (point-to-point cabling design) workbook parser for LLDPq Ask-AI.

Parses real-world P2P cabling workbooks (.xlsx/.xlsm, one row per cable:
source rack/RU/host/port/transceiver <-> destination) into a canonical JSON
shape so Ask-AI can answer design questions, diff design vs live LLDP, and
enrich link incidents with cable metadata.

Stdlib only: xlsx/xlsm files are read with zipfile + xml.etree (sharedStrings
plus per-sheet XML streamed one sheet at a time). Data tabs are detected by
header sniffing (rack/U/name/port column cluster appearing twice), never by
sheet names, so BOM / Change Log / Floor plan style tabs fail the sniff
naturally and land in skipped_sheets.

Canonical record shape (flat, one record per cable):
    {source_rack, source_ru, source_name, source_port, source_transceiver,
     dest_rack, dest_ru, dest_name, dest_port, dest_transceiver,
     connection_type, sheet_name, network_type, row_number,
     cable_length?, cable_type?, cable_part?, seq?, bundle_id?, unresolved?}

Top-level:
    {format, source_file, generated_at, total_connections,
     connections: [...], skipped_sheets: [...], warnings: [...]}

CLI: python3 ai_p2p.py <file.xlsx|file.xlsm|connections.json> [--summary]
"""

from __future__ import annotations

import json
import re
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

CANONICAL_FORMAT = "lldpq-p2p-v1"

_M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R_ID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"

MAX_HEADER_SCAN_ROWS = 50

BASE_FIELDS = (
    "source_rack", "source_ru", "source_name", "source_port", "source_transceiver",
    "dest_rack", "dest_ru", "dest_name", "dest_port", "dest_transceiver",
)
OPTIONAL_FIELDS = ("cable_length", "cable_type", "cable_part", "seq", "bundle_id")

_PLACEHOLDER_NAMES = {"", "tbd", "tba", "n/a", "na", "none", "null", "-", "--", "?", "x", "xx"}
_PLACEHOLDER_MARKERS = ("customer", "tbd", "to be determined", "future", "not used", "spare port")

# Ports that mark a row as OOB/BMC management plane even inside compute sheets
_BMC_PORT_TOKENS = {"bmc", "bfbmc", "bf-bmc", "bf bmc", "ipmi", "mgmt", "mgmt0", "idrac", "ilo"}
_POWER_NAME_RE = re.compile(
    r"\b(?:PDU|PSU)\d*\b|\bPWR\b|\bPOWER\s*(?:SHELF|SHLF|SHLVS?)?\b"
    r"|(?:PWR|POWER)[-_ ]?SH(?:E?LF|LVS?)",
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# Workbook reading (zipfile + xml.etree, streamed one sheet at a time)
# ---------------------------------------------------------------------------

def _col_ref_to_index(ref):
    """'AB12' -> 27 (0-based column index)."""
    idx = 0
    for ch in ref:
        if ch.isalpha():
            idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
        else:
            break
    return idx - 1


def _load_shared_strings(zf):
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    strings = []
    root = ET.fromstring(data)
    for si in root:
        parts = []
        for elem in si.iter():
            if elem.tag == _M + "t" and elem.text:
                parts.append(elem.text)
        strings.append("".join(parts))
    return strings


def _sheet_targets(zf):
    """Ordered [(sheet_name, zip_member_path)] for worksheet tabs."""
    wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
    rel_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rel_map = {rel.get("Id"): rel.get("Target") or "" for rel in rel_root}
    out = []
    sheets_el = wb_root.find(_M + "sheets")
    if sheets_el is None:
        return out
    names = set(zf.namelist())
    for sheet in sheets_el:
        name = sheet.get("name") or ""
        target = rel_map.get(sheet.get(_R_ID) or "", "")
        if not target:
            continue
        target = target.lstrip("/")
        if not target.startswith("xl/"):
            target = "xl/" + target
        if "worksheets/" not in target or target not in names:
            continue  # chartsheets, macros, missing members
        out.append((name, target))
    return out


def _cell_value(cell, shared):
    ctype = cell.get("t") or "n"
    if ctype == "inlineStr":
        parts = []
        for elem in cell.iter():
            if elem.tag == _M + "t" and elem.text:
                parts.append(elem.text)
        return "".join(parts) if parts else None
    v = cell.find(_M + "v")
    if v is None or v.text is None:
        return None
    if ctype == "s":
        try:
            return shared[int(v.text)]
        except (ValueError, IndexError):
            return None
    if ctype == "b":
        return "TRUE" if v.text.strip() == "1" else "FALSE"
    # 'n', 'str' (cached formula string), 'e' -> raw text
    return v.text


def _stream_sheet_rows(zf, target, shared):
    """Yield (excel_row_number, list_of_values) for one sheet, streaming."""
    with zf.open(target) as fh:
        seq = 0
        for _event, elem in ET.iterparse(fh, events=("end",)):
            if elem.tag != _M + "row":
                continue
            seq += 1
            try:
                row_num = int(elem.get("r") or seq)
            except ValueError:
                row_num = seq
            cells = {}
            for cell in elem:
                if cell.tag != _M + "c":
                    continue
                ref = cell.get("r")
                col = _col_ref_to_index(ref) if ref else len(cells)
                if col < 0:
                    col = len(cells)
                cells[col] = _cell_value(cell, shared)
            width = max(cells) + 1 if cells else 0
            yield row_num, [cells.get(i) for i in range(width)]
            elem.clear()


def iter_workbook_sheets(path):
    """Yield (sheet_name, rows) one sheet at a time; rows are positional lists.

    Row index in the returned list matches Excel row number - 1 (gaps from
    sparse workbooks are padded with empty lists).
    """
    with zipfile.ZipFile(str(path)) as zf:
        shared = _load_shared_strings(zf)
        for name, target in _sheet_targets(zf):
            rows = []
            for row_num, values in _stream_sheet_rows(zf, target, shared):
                while len(rows) < row_num - 1:
                    rows.append([])
                if len(rows) == row_num - 1:
                    rows.append(values)
                else:  # out-of-order/duplicate row refs: keep last
                    rows[row_num - 1] = values
            yield name, rows


def read_workbook(path):
    """Read an .xlsx/.xlsm workbook -> {sheet_name: rows(list[list[str|None]])}."""
    return dict(iter_workbook_sheets(path))


# ---------------------------------------------------------------------------
# Value cleaning
# ---------------------------------------------------------------------------

_FLOAT_ARTIFACT_RE = re.compile(r"^\d+\.0+$")


def _clean_value(value):
    """Normalize a cell value to a clean string ('' for empty)."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if _FLOAT_ARTIFACT_RE.match(text):
        return text.split(".", 1)[0]
    if "/" in text and "." in text:
        parts = text.split("/")
        if all(_FLOAT_ARTIFACT_RE.match(p) or p.isdigit() for p in parts if p):
            text = "/".join(p.split(".", 1)[0] for p in parts)
    return text


def _norm_header(value):
    """Lowercase header text with separators collapsed to single spaces."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[_/\\.\-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _squash_header(value):
    """Header text lowered with all separators removed (flat-header matching)."""
    return re.sub(r"[\s_/\\.\-#]+", "", str(value or "").strip().lower())


# ---------------------------------------------------------------------------
# Header sniffing
# ---------------------------------------------------------------------------

_FLAT_PATTERNS = (
    ("source_rack", re.compile(r"^(?:source|src)rack$")),
    ("source_ru", re.compile(r"^(?:source|src)r?u$")),
    ("source_name", re.compile(r"^(?:source|src)(?:host)?na?me$")),
    ("source_port", re.compile(r"^(?:source|src)(?:physical|hca|bf\d?)?port$")),
    ("source_transceiver", re.compile(r"^(?:source|src)(?:transceiver|optics?|sfp|module)$")),
    ("dest_rack", re.compile(r"^(?:dest(?:ination)?|dst)rack$")),
    ("dest_ru", re.compile(r"^(?:dest(?:ination)?|dst)r?u$")),
    ("dest_name", re.compile(r"^(?:dest(?:ination)?|dst)(?:host)?na?me$")),
    ("dest_port", re.compile(r"^(?:dest(?:ination)?|dst)(?:physical)?port$")),
    ("dest_transceiver", re.compile(r"^(?:dest(?:ination)?|dst)(?:transceiver|optics?|sfp|module)$")),
    ("cable_length", re.compile(r"^cablelength$")),
    ("cable_length", re.compile(r"^calculatedcablelength$")),
    ("cable_type", re.compile(r"^cabletype$")),
    ("cable_part", re.compile(r"^cablepart(?:no|number)?$")),
    ("seq", re.compile(r"^seq$")),
    ("bundle_id", re.compile(r"^bundleid$")),
)

_NAME_TOKENS = {"name", "hostname", "nae", "device name", "host name"}
_RACK_TOKENS = {"rack", "rack name", "rack id"}
_RU_TOKENS = {"u", "ru", "u#", "ru#", "rack u", "unit"}


def _is_port_header(norm):
    if norm in ("hca", "port", "ports", "hca port", "bf port", "physical port",
                "switch port", "port a", "port b"):
        return True
    return bool(re.match(r"^(?:hca|bf\d?)? ?ports?$", norm)) or norm.endswith(" port")


def _is_transceiver_header(norm):
    return ("transceiver" in norm or norm in ("optic", "optics", "sfp", "module")) and "cable" not in norm


def _map_flat_header(values):
    col_map = {}
    for idx, raw in enumerate(values):
        squashed = _squash_header(raw)
        if not squashed:
            continue
        for key, pattern in _FLAT_PATTERNS:
            if key not in col_map and pattern.match(squashed):
                col_map[key] = idx
                break
    return col_map


def _section_bounds(prev_values, width):
    """Find (src_start, dest_start, dest_end) from a SOURCE/DEST grouping row."""
    if not prev_values:
        return None
    src_start = dest_start = None
    for idx, raw in enumerate(prev_values):
        norm = _norm_header(raw)
        if not norm:
            continue
        if src_start is None and (norm.startswith("source") or norm == "src"):
            src_start = idx
        elif src_start is not None and dest_start is None and norm.startswith(("dest", "dst", "target", "far end")):
            dest_start = idx
    if src_start is None or dest_start is None:
        return None
    dest_end = width
    for idx in range(dest_start + 1, len(prev_values)):
        norm = _norm_header(prev_values[idx])
        if norm and not norm.startswith(("dest", "dst")):
            dest_end = idx
            break
    return src_start, dest_start, dest_end


def _map_section(values, start, end, prefix):
    """Map one SOURCE or DEST column section of a split header row."""
    col_map = {}

    def put(key, idx):
        if key not in col_map:
            col_map[key] = idx

    for idx in range(start, min(end, len(values))):
        norm = _norm_header(values[idx])
        if not norm:
            continue
        if "tray" in norm:
            continue
        if norm in _RACK_TOKENS:
            put(prefix + "rack", idx)
        elif norm in _RU_TOKENS:
            put(prefix + "ru", idx)
        elif norm in _NAME_TOKENS:
            put(prefix + "name", idx)
        elif _is_transceiver_header(norm):
            put(prefix + "transceiver", idx)
        elif _is_port_header(norm):
            put(prefix + "port", idx)
        elif "length" in norm and "cable" in norm or norm == "length":
            put("cable_length", idx)
        elif "cable" in norm and "type" in norm:
            put("cable_type", idx)
        elif "cable" in norm and ("part" in norm or "p n" in norm or "pn" == norm.replace("cable ", "")):
            put("cable_part", idx)
    return col_map


def _map_prefix(values, end):
    """Map SEQ / Bundle_ID style prefix columns before the SOURCE section."""
    col_map = {}
    for idx in range(0, min(end, len(values))):
        norm = _norm_header(values[idx])
        if norm in ("seq", "seq#", "sequence") and "seq" not in col_map:
            col_map["seq"] = idx
        elif norm in ("bundle id", "bundleid", "bundle") and "bundle_id" not in col_map:
            col_map["bundle_id"] = idx
    return col_map


def _map_split_header(values, prev_values):
    """Map a two-row header (SOURCE/DEST grouping row + real header row)."""
    width = len(values)
    bounds = _section_bounds(prev_values, width)
    if bounds is None:
        # Fallback: split at the second rack-like column (no grouping row).
        rack_idx = [i for i, v in enumerate(values) if _norm_header(v) in _RACK_TOKENS]
        if len(rack_idx) < 2:
            return {}
        bounds = (rack_idx[0], rack_idx[1], width)
    src_start, dest_start, dest_end = bounds
    col_map = {}
    col_map.update(_map_prefix(values, src_start))
    col_map.update(_map_section(values, src_start, dest_start, "source_"))
    col_map.update(_map_section(values, dest_start, dest_end, "dest_"))
    return col_map


def _is_complete(col_map):
    return all(k in col_map for k in ("source_name", "source_port", "dest_name", "dest_port"))


def sniff_header(rows):
    """Find the data table header in a sheet by header sniffing.

    Returns (header_row_index, col_map) with 0-based row index, or (-1, {})
    when the sheet does not look like a P2P data tab.
    """
    limit = min(len(rows), MAX_HEADER_SCAN_ROWS)
    for idx in range(limit):
        values = rows[idx]
        if not values:
            continue
        col_map = _map_flat_header(values)
        if _is_complete(col_map):
            return idx, col_map
        prev = rows[idx - 1] if idx > 0 else []
        col_map = _map_split_header(values, prev)
        if _is_complete(col_map):
            return idx, col_map
    return -1, {}


# ---------------------------------------------------------------------------
# Classification (sheet name + endpoint signals)
# ---------------------------------------------------------------------------

_SHEET_CLASS_RULES = (
    # (connection_type, network_type, pattern) -- first match wins
    ("oob", "eth", re.compile(r"\bOOB\b|IPMI|\bBMC\b", re.IGNORECASE)),
    ("ctrl", "eth", re.compile(r"\bCTRL\b|CONTROL\s*PLANE|CONTROL\s*NET", re.IGNORECASE)),
    ("mgmt", "eth", re.compile(r"\bMGMT\b|MANAGEMENT|MLEAF|M[-_ ]LEAF", re.IGNORECASE)),
    ("tan", "eth", re.compile(r"\bTAN\b|BRDR|BORDER", re.IGNORECASE)),
    ("vast", "eth", re.compile(r"\bVAST\b", re.IGNORECASE)),
    ("storage", "eth", re.compile(r"STORAGE|\bSTOR\b|SLEAF|\bSL\b[-_ ]|\bHPS\b", re.IGNORECASE)),
    ("in-rack", "eth", re.compile(r"IN[-_ ]?RACK", re.IGNORECASE)),
    ("converged", "eth", re.compile(r"CONVERGED|CONV[-_ ]?ETH", re.IGNORECASE)),
    ("inband", "eth", re.compile(r"IN[-_ ]?BAND|\bINB\b", re.IGNORECASE)),
)

_COMPUTE_SHEET_RE = re.compile(
    r"GB\d|DGX|HGX|\bGPU\b|CLEAF|CSPINE|\bCL\b|\bCS\b|CL\s*TO|RAIL\s*\d|COMPUTE|"
    r"\bXDR\b|\bNDR\b|\bHDR\b|\bIB\b|IBLEAF|SU\d|LEAF|SPINE|\bHCA\b|\bUFM\b",
    re.IGNORECASE,
)

_SECTION_RULES = (
    ("compute", "ib", re.compile(r"COMPUTE\s*FABRIC", re.IGNORECASE)),
    ("converged", "eth", re.compile(r"CONVERGED", re.IGNORECASE)),
    ("tan", "eth", re.compile(r"TAN\s*(?:FABRIC|NETWORK)", re.IGNORECASE)),
    ("oob", "eth", re.compile(r"OOB\s*(?:FABRIC|NETWORK)", re.IGNORECASE)),
    ("storage", "eth", re.compile(r"STOR(?:AGE)?\s*(?:FABRIC|NETWORK)|VAST", re.IGNORECASE)),
    ("ctrl", "eth", re.compile(r"(?:CTRL|CONTROL|MGMT|MANAGEMENT)\s*(?:FABRIC|NETWORK|PLANE)", re.IGNORECASE)),
)


def _section_for_sheet(sheet_name):
    """Return (connection_type, network_type) if a non-data tab is a section divider."""
    for ctype, ntype, pattern in _SECTION_RULES:
        if pattern.search(sheet_name):
            return ctype, ntype
    return None


def _classify_sheet(sheet_name, section):
    """Return (connection_type, network_type) for a data sheet."""
    for ctype, ntype, pattern in _SHEET_CLASS_RULES:
        if pattern.search(sheet_name):
            return ctype, ntype
    if _COMPUTE_SHEET_RE.search(sheet_name):
        if section and section[0] != "compute":
            return section  # e.g. CLeaf/Spine tabs under a Converged Ethernet section
        return "compute", "ib"
    if section:
        return section
    return "general", "eth"


def _classify_row(record, sheet_ctype, sheet_ntype):
    """Row-level fabric separation: OOB/BMC/power rows must not be compute."""
    sport = record["source_port"].strip().lower()
    dport = record["dest_port"].strip().lower()
    # Power-plane naming wins over the BMC-port check: power shelves commonly
    # expose a 'mgmt' port, which would otherwise classify them as oob.
    names = record["source_name"] + " " + record["dest_name"]
    if _POWER_NAME_RE.search(names):
        return "power", "eth"
    if sport in _BMC_PORT_TOKENS or dport in _BMC_PORT_TOKENS:
        return "oob", "eth"
    if re.search(r"\bOOB\b|[-_]OOB[-_]|[-_]oob[-_]", names):
        if sheet_ctype in ("compute", "converged"):
            return "oob", "eth"
    return sheet_ctype, sheet_ntype


def _is_placeholder_name(name):
    low = name.strip().lower()
    if low in _PLACEHOLDER_NAMES:
        return True
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


# ---------------------------------------------------------------------------
# Workbook -> canonical dict
# ---------------------------------------------------------------------------

def _cell(values, col_map, key):
    idx = col_map.get(key, -1)
    if idx < 0 or idx >= len(values):
        return ""
    return _clean_value(values[idx])


def _parse_sheet(sheet_name, rows, section):
    """Parse one data sheet. Returns (records, warnings) or (None, None) if not a data tab."""
    header_idx, col_map = sniff_header(rows)
    if header_idx < 0:
        return None, None

    sheet_ctype, sheet_ntype = _classify_sheet(sheet_name, section)
    records = []
    warnings = []
    unresolved_count = 0
    last_bundle = ("", -10)  # (bundle_id, row_number) for merged-cell forward fill

    for row_idx in range(header_idx + 1, len(rows)):
        values = rows[row_idx]
        if not values:
            continue
        record = {key: _cell(values, col_map, key) for key in BASE_FIELDS}
        src_name, dst_name = record["source_name"], record["dest_name"]
        # Repeated header rows inside the sheet
        if _norm_header(src_name) in _NAME_TOKENS or _norm_header(dst_name) in _NAME_TOKENS:
            continue
        src_ph, dst_ph = _is_placeholder_name(src_name), _is_placeholder_name(dst_name)
        if src_ph and dst_ph:
            continue  # neither endpoint usable: furniture/blank row

        row_number = row_idx + 1
        ctype, ntype = _classify_row(record, sheet_ctype, sheet_ntype)
        record["connection_type"] = ctype
        record["sheet_name"] = sheet_name
        record["network_type"] = ntype
        record["row_number"] = row_number
        for key in OPTIONAL_FIELDS:
            value = _cell(values, col_map, key)
            if value:
                record[key] = value
        # Bundle IDs live in merged cells: forward-fill across contiguous rows
        if "bundle_id" in col_map:
            if record.get("bundle_id"):
                last_bundle = (record["bundle_id"], row_number)
            elif last_bundle[0] and row_number == last_bundle[1] + 1:
                record["bundle_id"] = last_bundle[0]
                last_bundle = (last_bundle[0], row_number)
        if src_ph or dst_ph or _is_placeholder_name(record["source_port"]) or _is_placeholder_name(record["dest_port"]):
            record["unresolved"] = True
            unresolved_count += 1
        records.append(record)

    if unresolved_count:
        warnings.append(
            "sheet '%s': %d row(s) with unresolved peer (tbd/customer-provided/blank); "
            "kept but excluded from link-truth outputs" % (sheet_name, unresolved_count)
        )
    return records, warnings


def parse_workbook(path):
    """Parse a P2P workbook into the canonical dict."""
    path = Path(path)
    connections = []
    skipped = []
    warnings = []
    section = None
    for sheet_name, rows in iter_workbook_sheets(path):
        records, sheet_warnings = _parse_sheet(sheet_name, rows, section)
        if records is None:
            skipped.append(sheet_name)
            divider = _section_for_sheet(sheet_name)
            if divider:
                section = divider
            continue
        if not records:
            warnings.append("sheet '%s': data header found but no connection rows" % sheet_name)
        connections.extend(records)
        warnings.extend(sheet_warnings)
    return {
        "format": CANONICAL_FORMAT,
        "source_file": path.name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_connections": len(connections),
        "connections": connections,
        "skipped_sheets": skipped,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Artifact ingestion (p2p-parser connections.json) + generic loader
# ---------------------------------------------------------------------------

def _normalize_record(raw, default_ctype=""):
    record = {}
    for key in BASE_FIELDS:
        record[key] = _clean_value(raw.get(key, ""))
    record["connection_type"] = str(raw.get("connection_type") or default_ctype or "general")
    record["sheet_name"] = str(raw.get("sheet_name") or "")
    record["network_type"] = str(raw.get("network_type") or "eth")
    if raw.get("row_number") is not None:
        record["row_number"] = raw["row_number"]
    for key in OPTIONAL_FIELDS:
        value = _clean_value(raw.get(key, ""))
        if value:
            record[key] = value
    if raw.get("unresolved") or any(
        _is_placeholder_name(record[key])
        for key in ("source_name", "dest_name", "source_port", "dest_port")
    ):
        record["unresolved"] = True
    return record


def _normalize_parsed_json(data, source_name=""):
    """Normalize a parsed dict/list (canonical or p2p-parser artifact) to canonical."""
    if isinstance(data, list):
        records = [_normalize_record(r) for r in data if isinstance(r, dict)]
        base = {}
    elif isinstance(data, dict):
        base = data
        if isinstance(data.get("connections"), list):
            records = [_normalize_record(r) for r in data["connections"] if isinstance(r, dict)]
        elif isinstance(data.get("connections_by_type"), dict):
            # p2p-parser artifact layout: {connection_type: [records]}
            records = []
            for ctype, recs in data["connections_by_type"].items():
                if not isinstance(recs, list):
                    continue
                for raw in recs:
                    if isinstance(raw, dict):
                        records.append(_normalize_record(raw, default_ctype=str(ctype)))
        else:
            raise ValueError("unrecognized connections JSON layout (no 'connections' or 'connections_by_type')")
    else:
        raise ValueError("unsupported connections payload type: %s" % type(data).__name__)
    return {
        "format": str(base.get("format") or CANONICAL_FORMAT),
        "source_file": str(base.get("source_file") or source_name),
        "generated_at": str(base.get("generated_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        "total_connections": len(records),
        "connections": records,
        "skipped_sheets": list(base.get("skipped_sheets") or []),
        "warnings": list(base.get("warnings") or []),
    }


def load_connections(path_or_json):
    """Load P2P connections from a workbook path, a connections.json path,
    a JSON string, or an already-parsed dict/list. Returns the canonical dict."""
    if isinstance(path_or_json, (dict, list)):
        return _normalize_parsed_json(path_or_json)
    text = str(path_or_json).strip()
    if text.startswith("{") or text.startswith("["):
        return _normalize_parsed_json(json.loads(text))
    path = Path(text)
    suffix = path.suffix.lower()
    if suffix in (".xlsx", ".xlsm", ".xltx", ".xltm"):
        return parse_workbook(path)
    if suffix == ".json":
        with open(path, "r", encoding="utf-8") as fh:
            return _normalize_parsed_json(json.load(fh), source_name=path.name)
    raise ValueError("unsupported P2P input: %s (expected .xlsx/.xlsm/.json)" % path)


# ---------------------------------------------------------------------------
# Query helpers (Ask-AI wiring)
# ---------------------------------------------------------------------------

def _records_of(conns):
    if isinstance(conns, dict):
        return conns.get("connections") or []
    return conns or []


def _device_keys(name):
    low = str(name or "").strip().lower()
    keys = {low}
    if "." in low:
        keys.add(low.split(".", 1)[0])  # FQDN -> short name
    return keys


def _port_aliases(port):
    """Tolerant port aliases: '41/1' <-> 'swp41s0', '41' <-> 'swp41', float artifacts.

    Includes the three-part port/cage/split notation some P2P workbooks use:
    '3/1/2' = port 3, cage 1, split 2 (1-based) <-> 'swp3s1'.
    """
    p = _clean_value(port).lower().replace(" ", "")
    if not p:
        return set()
    aliases = {p}
    m = re.match(r"^swp(\d+)s(\d+)$", p)
    if m:
        aliases.add("%s/%d" % (m.group(1), int(m.group(2)) + 1))
        aliases.add("%s/1/%d" % (m.group(1), int(m.group(2)) + 1))
    m = re.match(r"^swp(\d+)$", p)
    if m:
        aliases.add(m.group(1))
        aliases.add(m.group(1) + "/1")
        aliases.add(m.group(1) + "/1/1")
    m = re.match(r"^(\d+)/(\d+)$", p)
    if m:
        aliases.add("swp%ss%d" % (m.group(1), int(m.group(2)) - 1))
        if m.group(2) == "1":
            aliases.add("swp" + m.group(1))
    m = re.match(r"^(\d+)/(\d+)/(\d+)$", p)
    if m:
        # Without group context the breakout mode (2x/4x/8x, p2p-parser's
        # formula family) is ambiguous: accept every candidate lane. Use
        # resolve_port_map() when the whole design is available.
        x, y, z = m.group(1), int(m.group(2)), int(m.group(3))
        for lane in {y - 1, z - 1, (y - 1) * 2 + (z - 1), (y - 1) * 4 + (z - 1)}:
            aliases.add("swp%ss%d" % (x, lane))
        aliases.add("%s/%d" % (x, z))
        if y == 1 and z == 1:
            aliases.add("swp" + x)
    if re.match(r"^\d+$", p):
        aliases.add("swp" + p)
    return aliases


def _port_key(port):
    """Canonical single key for dedup: prefer 'N/M' slash form."""
    aliases = _port_aliases(port)
    for alias in sorted(aliases):
        if re.match(r"^\d+(?:/\d+)*$", alias):
            return alias
    return min(aliases) if aliases else ""


def resolve_port_map(conns):
    """Group-fitted OS spelling for three-part 'X/Y/Z' design ports.

    'X/Y/Z' = port X, group Y, sub Z (all 1-based). The OS lane is
    s = (Y-1)*maxZ + (Z-1), where maxZ (subs per group) is inferred from every
    design row sharing the same device+port — e.g. rows 1/1/1..1/2/4 mean an
    8x split, so 1/2/1 -> swp1s4. This is p2p-parser's breakout formula family
    (2x_group/2x_sub/4x/8x) collapsed to the one consistent general form.

    Returns {(device_key, port_text): 'swpXsN'} with device_key =
    min(_device_keys(name)) and port_text the cleaned lowercase design port.
    """
    groups = {}
    device_max_z = {}
    for record in _records_of(conns):
        for side in ("source", "dest"):
            name = record.get(side + "_name", "")
            port = _clean_value(record.get(side + "_port", "")).lower().replace(" ", "")
            m = re.match(r"^(\d+)/(\d+)/(\d+)$", port)
            if not name or not m:
                continue
            keys = _device_keys(name)
            if not keys:
                continue
            dev = min(keys)
            group = groups.setdefault((dev, int(m.group(1))), set())
            group.add((int(m.group(2)), int(m.group(3)), port))
            device_max_z[dev] = max(device_max_z.get(dev, 1), int(m.group(3)))
    resolved = {}
    for (dev, x), entries in groups.items():
        # Subs-per-group comes from the device, not the single port: a port may
        # leave trailing lanes uncabled (3/2/1..3/2/3 on a 4x-split switch still
        # means lanes s4..s6), while the breakout type is uniform per switch.
        max_z = device_max_z.get(dev, 1)
        for y, z, port in entries:
            resolved[(dev, port)] = "swp%ds%d" % (x, (y - 1) * max_z + (z - 1))
    return resolved


def resolved_os_port(resolved, name, port):
    """Look up a resolve_port_map() entry by any device spelling; '' if absent."""
    p = _clean_value(port).lower().replace(" ", "")
    keys = _device_keys(name)
    if not p or not keys:
        return ""
    return resolved.get((min(keys), p), "")


def _meta_of(record):
    meta = {
        "sheet_name": record.get("sheet_name", ""),
        "network_type": record.get("network_type", ""),
        "connection_type": record.get("connection_type", ""),
    }
    for key in OPTIONAL_FIELDS:
        if record.get(key):
            meta[key] = record[key]
    return meta


def lookup(conns, device, port=None):
    """Design peers for a device (optionally one port), with cable metadata.

    Matching is case/format tolerant: FQDN short names, '41/1' breakout
    notation and swp-style names ('swp41s0') are treated as equivalent.
    """
    want_keys = _device_keys(device)
    want_ports = _port_aliases(port) if port else None
    results = []
    for record in _records_of(conns):
        for side, peer in (("source", "dest"), ("dest", "source")):
            name = record.get(side + "_name", "")
            if not (_device_keys(name) & want_keys):
                continue
            if want_ports is not None and not (_port_aliases(record.get(side + "_port", "")) & want_ports):
                continue
            entry = {
                "device": name,
                "port": record.get(side + "_port", ""),
                "rack": record.get(side + "_rack", ""),
                "ru": record.get(side + "_ru", ""),
                "transceiver": record.get(side + "_transceiver", ""),
                "peer_device": record.get(peer + "_name", ""),
                "peer_port": record.get(peer + "_port", ""),
                "peer_rack": record.get(peer + "_rack", ""),
                "peer_ru": record.get(peer + "_ru", ""),
                "peer_transceiver": record.get(peer + "_transceiver", ""),
                "unresolved": bool(record.get("unresolved")),
            }
            entry.update(_meta_of(record))
            results.append(entry)
            break  # one match per record even if device appears on both sides
    return results


def expected_links(conns, network_type=None):
    """Deduped, resolved-only design links: [{a_dev, a_port, b_dev, b_port, meta}].

    Unresolved rows (tbd/customer-provided/blank peers) are excluded so this
    can be used as link truth when diffing design vs live LLDP.
    """
    seen = {}
    for record in _records_of(conns):
        if record.get("unresolved"):
            continue
        if network_type and record.get("network_type") != network_type:
            continue
        a = (record.get("source_name", ""), record.get("source_port", ""))
        b = (record.get("dest_name", ""), record.get("dest_port", ""))
        if not a[0] or not b[0]:
            continue
        key = tuple(sorted((
            (min(_device_keys(a[0])), _port_key(a[1])),
            (min(_device_keys(b[0])), _port_key(b[1])),
        )))
        if key in seen:
            continue
        # Keep source->dest orientation from the design sheet
        seen[key] = {
            "a_dev": a[0], "a_port": a[1],
            "b_dev": b[0], "b_port": b[1],
            "meta": _meta_of(record),
        }
    return list(seen.values())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_summary(result):
    print("format:            %s" % result.get("format", ""))
    print("source_file:       %s" % result.get("source_file", ""))
    print("total_connections: %s" % result.get("total_connections", 0))
    per_sheet = {}
    per_class = {}
    unresolved = 0
    for record in result.get("connections", []):
        per_sheet[record.get("sheet_name", "")] = per_sheet.get(record.get("sheet_name", ""), 0) + 1
        ckey = "%s/%s" % (record.get("connection_type", ""), record.get("network_type", ""))
        per_class[ckey] = per_class.get(ckey, 0) + 1
        if record.get("unresolved"):
            unresolved += 1
    print("unresolved rows:   %d" % unresolved)
    print("\nconnections per sheet:")
    for name, count in per_sheet.items():
        print("  %-40s %6d" % (name, count))
    print("\nconnections per type (connection_type/network_type):")
    for name in sorted(per_class):
        print("  %-40s %6d" % (name, per_class[name]))
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
        print("usage: python3 ai_p2p.py <file.xlsx|file.xlsm|connections.json> [--summary]", file=sys.stderr)
        return 2
    try:
        result = load_connections(args[0])
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError, ET.ParseError) as exc:
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
