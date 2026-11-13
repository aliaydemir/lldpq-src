#!/usr/bin/env python3
"""Shared contract for the public machine-readable report exports.

Each analyzer publishes, in the same atomic monitor transaction as its HTML
report and summary JSON, a flat machine-first snapshot of its current state:

    monitor-results/export/<domain>.json   {schema_version, domain, generated_at,
                                            collection_status, counts, columns, rows}
    monitor-results/export/<domain>.csv    same rows, columns in the same order

nginx serves these under the friendly URLs /<domain>/export_json and
/<domain>/export_csv without authentication — the exports are derived views of
data the web tree already exposes publicly.

This module is the single owner of the export contract: the per-domain column
registry (order == CSV column order == JSON "columns"), the value coercion
rules, and the CSV rendering semantics (ported from lldp.html's csvField /
spreadsheetSafeValue / displayValue so spreadsheet-formula injection is guarded
identically everywhere; the one exemption is a cell of pure numbers in a
column listed in NUMERIC_LIST_COLUMNS).  Analyzers only hand it the row
mappings they already assembled for their HTML tables.

Contract rules:
- Unknown row keys are rejected loudly (a silent schema widening in one
  analyzer must fail its tests/run, not drift the public contract).
- Missing keys become None; values are coerced to JSON-safe scalars, never
  raised on (content problems must not take down an analyzer run).
- CSV cells map JSON scalars deterministically: JSON null <-> CSV 'N/A',
  JSON true/false <-> CSV 'true'/'false' (JSON spelling, not Python's
  str(True)); everything else renders as its display text.
- Columns are append-only across releases; consumers key on "schema_version".
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Mapping, Optional, Sequence, Union

import analysis_sidecar

SCHEMA_VERSION = 1
EXPORT_SUBDIR = "export"

# domain -> ordered column tuple.  Order is the CSV column order and the JSON
# "columns" list.  Append new columns at the end only.
EXPORT_SCHEMAS: dict[str, tuple[str, ...]] = {
    "bgp": (
        "device", "neighbor", "neighbor_ip", "vrf", "address_family",
        "interface", "state", "health", "asn", "uptime", "down_since",
        "prefixes_received", "prefixes_sent", "messages_received",
        "messages_sent", "in_queue", "out_queue", "table_version",
        "version", "description",
    ),
    "evpn-mh": (
        "esi", "status", "reason", "device_a", "bond_a", "df_a", "lacp_a",
        "device_b", "bond_b", "df_b", "lacp_b", "vnis", "orphan",
        "inconsistent", "bypass_active",
    ),
    "duplicate": (
        "finding_type", "severity", "kind", "vlan", "vni", "address",
        "macs", "hosts", "local_ports", "vteps", "sequence", "delta",
        "events", "stale", "count", "note", "mac_count",
        "historical_macs", "historical_mac_count",
        "stale_binding_macs", "stale_binding_mac_count",
    ),
    "flap": (
        "device", "interface", "status", "flaps_30s", "flaps_1m", "flaps_5m",
        "flaps_1h", "flaps_12h", "flaps_24h", "total_transitions",
    ),
    "optical": (
        "device", "interface", "health", "rx_power_dbm", "tx_power_dbm",
        "temperature_c", "link_margin_db", "voltage_v", "bias_current_ma",
        "rx_lanes", "tx_lanes", "bias_lanes", "anomalies", "inactive_lanes",
        "rx_lane_ids", "tx_lane_ids", "bias_lane_ids",
        "rx_power_lane", "tx_power_lane", "bias_current_lane",
    ),
    "ber": (
        "device", "interface", "neighbor_device", "neighbor_port", "status",
        "sample_status", "raw_ber", "effective_ber", "frame_error_density",
        "symbol_errors", "symbol_error_delta", "delta_packets",
        "delta_rx_errors", "delta_tx_errors",
        "delta_rx_dropped", "delta_tx_dropped", "sample_window",
        "severity_reasons",
    ),
    "pfc-ecn": (
        "device", "interface", "status", "signal", "ecn_marked_delta",
        "ecn_marked_rate", "rx_pause_delta", "rx_pause_rate",
        "tx_pause_delta", "tx_pause_rate", "loss_delta", "sample_status",
    ),
    "hardware": (
        "device", "model", "health", "cpu_temp_c", "asic_temp_c",
        "memory_pct", "load_raw", "load_per_core", "cores",
        "psu_efficiency", "psu_in_w", "psu_out_w", "fans",
        "psu_status", "psu_status_complete", "psu_status_detail", "psus",
        "psu_redundancy", "power_leds",
        "fan_status", "fan_status_complete", "fan_status_detail", "fan_states",
    ),
    "log": (
        "device", "severity", "age", "timestamp", "section",
        "message",
    ),
    "config-drift": (
        "detected_at", "device", "change_type", "lines_added",
        "lines_removed", "collected_at", "summary",
    ),
    "routes": (
        "device", "vrf", "status", "routes_total", "routes_delta",
        "bgp_routes", "kernel_routes", "static_routes", "other_routes",
        "ecmp_routes", "max_ecmp_width", "arp_entries", "note",
    ),
    "fabric-check": (
        "check", "severity", "device_a", "port_a", "value_a",
        "device_b", "port_b", "value_b", "detail",
    ),
    "transceiver": (
        "device", "port", "identifier", "vendor", "part_number", "serial",
        "vendor_rev", "connector", "fw_version", "cable_byte130", "fw_status",
        "fw_status_detail",
        # The physical module a port row belongs to ("<device>/<cage>" plus
        # "/<serial>" when one is printed): the sub-ports of a breakout cage
        # carry the same value, so rows can be counted per module.
        "module",
    ),
    # Rendered on request by the LLDP export CGI (lldp_export.py), not
    # published by monitor.sh; registered here so column governance is uniform.
    "lldp_results": (
        "local_device", "local_port", "port_status", "expected_device",
        "expected_port", "actual_device", "actual_port", "lldp_status",
        "status", "connection_health",
    ),
}

# domain -> the columns whose cells are blank-separated lists of numbers the
# analyzer wrote itself (lane readings such as "-1.2 -0.9 -1.5", lane
# numbers).  Only these cells may skip the formula guard, and only while
# they hold nothing but numbers; see spreadsheet_safe_value.
NUMERIC_LIST_COLUMNS: dict[str, frozenset[str]] = {
    "optical": frozenset({
        "rx_lanes", "tx_lanes", "bias_lanes", "inactive_lanes",
        "rx_lane_ids", "tx_lane_ids", "bias_lane_ids",
    }),
}


class ExportContractError(ValueError):
    """Raised when an analyzer violates the export schema registry."""


# ---------------------------------------------------------------------------
# Value/CSV semantics — ports of lldp.html's displayValue,
# spreadsheetSafeValue and csvField; shared by every export and by the LLDP
# export CGI so there is exactly one injection guard.  With the default
# arguments they are verbatim ports: the headless LLDP CSV is promised to be
# byte-identical to the page's Download CSV, so the default guard must not
# drift from the page's.  The one exemption (``numeric_list``) is opt-in per
# column and no LLDP column uses it.
# ---------------------------------------------------------------------------

_FORMULA_GUARD_RE = re.compile(r"^\s*[=+\-@]")
# A cell made only of numbers, signs, dots and blanks (a list of lane
# readings such as "-1.2 -0.9 -1.5") cannot name a function or a command.
_NUMERIC_LIST_RE = re.compile(r"[0-9+\-. ]+")
_CSV_QUOTE_RE = re.compile(r'[",\r\n]')


def display_value(value: Any) -> str:
    """'' / None / 'none' / 'n/a' (trimmed, case-insensitive) -> 'N/A'."""
    if isinstance(value, bool):
        # Python's str(True) is 'True'; the JS original (String(true)) and
        # the JSON rows spell booleans lowercase, so the CSV must match.
        return "true" if value else "false"
    text = "" if value is None else str(value).strip()
    return "N/A" if text.lower() in ("", "none", "n/a") else text


def spreadsheet_safe_value(value: Any, numeric_list: bool = False) -> str:
    """``numeric_list`` marks a cell of a NUMERIC_LIST_COLUMNS column."""
    # Real numbers cannot be formula-injection vectors, and guarding them
    # would corrupt negative telemetry (optical dBm, counter deltas) into
    # apostrophe-prefixed strings.  Only untrusted text gets the guard.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return display_value(value)
    text = display_value(value)
    # The guard exists for text a spreadsheet would run; prefixing a list
    # of negative readings only made its first value unparseable.  Limited
    # to the columns that hold such lists: everywhere else text that merely
    # looks numeric (an operator-supplied "-1") keeps the guard, as on the
    # LLDP page.
    if (numeric_list and _NUMERIC_LIST_RE.fullmatch(text)
            and re.search(r"[0-9]", text)):
        return text
    return f"'{text}" if _FORMULA_GUARD_RE.match(text) else text


def csv_field(value: Any, numeric_list: bool = False) -> str:
    text = spreadsheet_safe_value(value, numeric_list)
    if _CSV_QUOTE_RE.search(text):
        text = '"' + text.replace('"', '""') + '"'
    return text


def render_csv(
    columns: Sequence[str],
    rows: Sequence[Mapping[str, Any]],
    numeric_list_columns: Sequence[str] = (),
) -> str:
    """RFC-4180 CSV with CRLF line endings and a trailing CRLF.

    ``numeric_list_columns`` names the columns of this domain that hold
    lists of numbers (NUMERIC_LIST_COLUMNS).
    """
    lines = [",".join(csv_field(column) for column in columns)]
    for row in rows:
        lines.append(",".join(
            csv_field(row.get(column), column in numeric_list_columns)
            for column in columns))
    return "\r\n".join(lines) + "\r\n"


# ---------------------------------------------------------------------------
# Row normalization
# ---------------------------------------------------------------------------

def _coerce_scalar(value: Any) -> Any:
    """Coerce a cell to a JSON-safe scalar; never raises on content."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        # NaN/Infinity are not valid strict JSON; absent beats unparseable.
        return value if math.isfinite(value) else None
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(item) for item in value)
    return str(value)


def normalize_rows(
    domain: str, rows: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    columns = EXPORT_SCHEMAS.get(domain)
    if columns is None:
        raise ExportContractError(f"unknown export domain {domain!r}")
    column_set = set(columns)
    normalized = []
    for index, row in enumerate(rows):
        unknown = set(row) - column_set
        if unknown:
            raise ExportContractError(
                f"{domain} export row {index} carries keys outside the "
                f"registry: {sorted(unknown)}"
            )
        normalized.append(
            {column: _coerce_scalar(row.get(column)) for column in columns}
        )
    return normalized


# ---------------------------------------------------------------------------
# Atomic publication (same choreography as the analyzers' _atomic_write:
# mkstemp -> fsync -> chmod 0664 BEFORE replace -> replace -> fsync parent).
# The pre-replace chmod is load-bearing: mkstemp creates 0600 and these files
# are served by nginx as www-data.
# ---------------------------------------------------------------------------

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


def build_payload(
    domain: str,
    rows: Sequence[Mapping[str, Any]],
    counts: Mapping[str, Any],
    collection_status: Any,
    *,
    generated_at: Optional[Union[int, float]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    normalized = normalize_rows(domain, rows)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "domain": domain,
        "generated_at": int(generated_at if generated_at is not None else time.time()),
        "collection_status": collection_status,
        "counts": dict(counts),
        "row_count": len(normalized),
        "columns": list(EXPORT_SCHEMAS[domain]),
        "rows": normalized,
    }
    if extra:
        payload["extra"] = dict(extra)
    return payload


def write_export(
    result_dir: Union[str, Path],
    domain: str,
    rows: Sequence[Mapping[str, Any]],
    counts: Mapping[str, Any],
    collection_status: Any,
    *,
    generated_at: Optional[Union[int, float]] = None,
    extra: Optional[Mapping[str, Any]] = None,
    subdir: Optional[str] = EXPORT_SUBDIR,
    basename: Optional[str] = None,
) -> None:
    """Write <domain>.json + <domain>.csv (plus .sha256 sidecars) atomically.

    Raises ExportContractError for registry violations and OSError for I/O
    failures (both must fail the analyzer run so the monitor transaction
    rolls back); content-level oddities are coerced, never raised on.
    """
    payload = build_payload(
        domain, rows, counts, collection_status,
        generated_at=generated_at, extra=extra,
    )
    target_dir = Path(result_dir)
    if subdir:
        target_dir = target_dir / subdir
    stem = basename if basename is not None else domain

    # Producer-side digests: the content is already in memory, so hash it
    # here instead of write_sidecar's re-read of the file from disk.
    json_text = json.dumps(payload, sort_keys=False)
    json_path = target_dir / f"{stem}.json"
    _atomic_write(json_path, json_text)
    analysis_sidecar.publish_digest(
        json_path, hashlib.sha256(json_text.encode("utf-8")).hexdigest()
    )

    csv_text = render_csv(payload["columns"], payload["rows"],
                          NUMERIC_LIST_COLUMNS.get(domain, ()))
    csv_path = target_dir / f"{stem}.csv"
    _atomic_write(csv_path, csv_text)
    analysis_sidecar.publish_digest(
        csv_path, hashlib.sha256(csv_text.encode("utf-8")).hexdigest()
    )


__all__ = (
    "EXPORT_SCHEMAS",
    "EXPORT_SUBDIR",
    "ExportContractError",
    "NUMERIC_LIST_COLUMNS",
    "SCHEMA_VERSION",
    "build_payload",
    "csv_field",
    "display_value",
    "normalize_rows",
    "render_csv",
    "spreadsheet_safe_value",
    "write_export",
)
