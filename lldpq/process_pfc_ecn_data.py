#!/usr/bin/env python3
"""Build the static PFC/ECN analysis report from monitor.sh snapshots.

The collector owns switch access.  This analyzer only reads the current raw
files, derives interval deltas/rates from a local baseline, and writes static
artifacts under ``monitor-results``.  Missing or failed counters are kept as
``None`` throughout; they are never presented as zero.
"""

from __future__ import annotations

import html
import json
import math
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    read_asset_snapshot,
)


PORT_RE = re.compile(r"^swp[0-9]+(?:s[0-9]+)?$")
LEGACY_START_RE = re.compile(
    r"^===PFC_ECN_PORT_START\s+port=([^\s=]+)===$"
)
LEGACY_END_RE = re.compile(
    r"^===PFC_ECN_PORT_END\s+port=([^\s=]+)\s+status=(ok|error)===$",
    re.IGNORECASE,
)
COLLECTOR_START_RE = re.compile(r"^__LLDPQ_PFC_ECN_PORT_START__:(\S+)$")
COLLECTOR_STATUS_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_PORT_STATUS__:(\S+):(OK|ERROR):(-?[0-9]+)$",
    re.IGNORECASE,
)
COLLECTOR_END_RE = re.compile(r"^__LLDPQ_PFC_ECN_PORT_END__:(\S+)$")
INVENTORY_STATUS_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_INVENTORY_STATUS__:(OK|EMPTY|ERROR):([0-9]+)$",
    re.IGNORECASE,
)
INVENTORY_COUNT_RE = re.compile(
    r"^__LLDPQ_PFC_ECN_INVENTORY_COUNT__:([0-9]+)$"
)

COUNTER_PATHS = {
    "ecn_marked_frames": ("egress-queue-stats", "ecn-marked-frames"),
    "tx_frames": ("egress-queue-stats", "tx-frames"),
    "tx_uc_buffer_discards": (
        "egress-queue-stats",
        "tx-uc-buffer-discards",
    ),
    "wred_discards": ("egress-queue-stats", "wred-discards"),
    "rx_pause_frames": ("pfc-stats", "rx-pause-frames"),
    "tx_pause_frames": ("pfc-stats", "tx-pause-frames"),
}
REQUIRED_COUNTERS = (
    "ecn_marked_frames",
    "rx_pause_frames",
    "tx_pause_frames",
)
HISTORY_SECONDS = 24 * 60 * 60
HISTORY_MAX_RECORDS_PER_PORT = 288


def _deep_merge(target: MutableMapping[str, Any], source: Mapping[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), MutableMapping):
            _deep_merge(target[key], value)
        else:
            target[key] = value


def _decode_json_values(text: str) -> List[Any]:
    """Decode one or more whitespace-separated JSON values."""
    decoder = json.JSONDecoder()
    values: List[Any] = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            break
        value, position = decoder.raw_decode(text, position)
        values.append(value)
    return values


def _payload_for_port(value: Any, port: str) -> Optional[Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    if isinstance(value.get(port), Mapping):
        return value[port]
    ports = value.get("ports")
    if isinstance(ports, Mapping) and isinstance(ports.get(port), Mapping):
        return ports[port]
    named_port = value.get("interface", value.get("port", value.get("name")))
    if named_port is not None and str(named_port) == port:
        for wrapper in ("data", "counters", "qos"):
            if isinstance(value.get(wrapper), Mapping):
                return value[wrapper]
    return value


def _direct_payloads(value: Any) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    """Yield ``(port, payload)`` from useful unmarked JSON layouts."""
    if isinstance(value, list):
        for item in value:
            yield from _direct_payloads(item)
        return
    if not isinstance(value, Mapping):
        return
    ports = value.get("ports")
    if isinstance(ports, Mapping):
        for port, payload in ports.items():
            if isinstance(payload, Mapping):
                yield str(port), payload
        return
    if isinstance(ports, list):
        for item in ports:
            yield from _direct_payloads(item)
        return
    named_port = value.get("interface", value.get("port", value.get("name")))
    if named_port is not None:
        payload = _payload_for_port(value, str(named_port))
        if payload is not None:
            yield str(named_port), payload
        return
    for port, payload in value.items():
        if PORT_RE.fullmatch(str(port)) and isinstance(payload, Mapping):
            yield str(port), payload


def parse_pfc_ecn_snapshot(content: str) -> Dict[str, Dict[str, Any]]:
    """Parse marker-delimited collector output or direct JSON.

    The current collector uses ``__LLDPQ_...`` markers.  The earlier proposed
    ``===PFC_ECN...===`` markers remain accepted so stored fixtures and manual
    captures stay useful.  A collector ``ERROR`` status produces a port entry
    with no trusted payload instead of a zero-filled record.
    """
    ports: Dict[str, Dict[str, Any]] = {}
    current: Optional[str] = None
    current_body: List[str] = []
    current_status: Optional[str] = None
    current_rc: Optional[int] = None
    saw_markers = False

    def finish(port: str, status_from_end: Optional[str] = None) -> None:
        nonlocal current, current_body, current_status, current_rc
        effective = (status_from_end or current_status or "error").lower()
        payload: Dict[str, Any] = {}
        error: Optional[str] = None
        if effective == "ok":
            try:
                for value in _decode_json_values("\n".join(current_body)):
                    candidate = _payload_for_port(value, port)
                    if candidate is not None:
                        _deep_merge(payload, candidate)
                if not payload:
                    error = "successful collector record contained no JSON object"
                    effective = "error"
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                error = f"invalid JSON payload: {exc}"
                effective = "error"
        elif current_body:
            error = "collector reported an error"

        existing = ports.get(port)
        if existing is not None and existing.get("status") == "ok" and effective == "ok":
            _deep_merge(existing["payload"], payload)
        else:
            ports[port] = {
                "status": effective,
                "return_code": current_rc,
                "payload": payload if effective == "ok" else {},
                "error": error,
            }
        current = None
        current_body = []
        current_status = None
        current_rc = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        start = COLLECTOR_START_RE.fullmatch(line) or LEGACY_START_RE.fullmatch(line)
        if start:
            saw_markers = True
            if current is not None:
                finish(current, "error")
            current = start.group(1)
            current_body = []
            current_status = None
            current_rc = None
            continue
        if current is None:
            continue
        status = COLLECTOR_STATUS_RE.fullmatch(line)
        if status and status.group(1) == current:
            current_status = status.group(2).lower()
            current_rc = int(status.group(3))
            continue
        legacy_end = LEGACY_END_RE.fullmatch(line)
        if legacy_end and legacy_end.group(1) == current:
            finish(current, legacy_end.group(2))
            continue
        collector_end = COLLECTOR_END_RE.fullmatch(line)
        if collector_end and collector_end.group(1) == current:
            finish(current)
            continue
        current_body.append(raw_line)

    if current is not None:
        finish(current, "error")
    if saw_markers:
        return ports

    try:
        for value in _decode_json_values(content):
            for port, payload in _direct_payloads(value):
                entry = ports.setdefault(
                    port,
                    {"status": "ok", "return_code": 0, "payload": {}, "error": None},
                )
                _deep_merge(entry["payload"], payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return ports


def validate_inventory_contract(
    content: str, ports: Mapping[str, Any]
) -> Tuple[bool, Optional[str]]:
    """Validate optional collector inventory markers against parsed ports.

    Legacy captures and direct JSON have no inventory marker and remain valid.
    Current collector output is rejected if it was truncated between the
    inventory declaration and the final port record.
    """
    status: Optional[str] = None
    declared_count: Optional[int] = None
    separate_count: Optional[int] = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        match = INVENTORY_STATUS_RE.fullmatch(line)
        if match:
            if status is not None:
                return False, "duplicate inventory status marker"
            status = match.group(1).lower()
            declared_count = int(match.group(2))
            continue
        match = INVENTORY_COUNT_RE.fullmatch(line)
        if match:
            if separate_count is not None:
                return False, "duplicate inventory count marker"
            separate_count = int(match.group(1))

    if status is None and separate_count is None:
        return True, None
    expected = separate_count if separate_count is not None else declared_count
    if declared_count is not None and separate_count is not None and declared_count != separate_count:
        return False, "inventory status/count markers disagree"
    if status == "error":
        return False, "collector reported an inventory error"
    if status == "empty" and (expected != 0 or ports):
        return False, "empty inventory marker conflicts with port records"
    if status == "ok" and (expected is None or expected <= 0):
        return False, "successful inventory has an invalid port count"
    if expected is not None and len(ports) != expected:
        return False, f"inventory declared {expected} ports but parsed {len(ports)}"
    return True, None


def _find_qos_object(value: Any) -> Optional[Mapping[str, Any]]:
    """Recursively locate the NVUE object containing both exact QoS groups."""
    if isinstance(value, Mapping):
        if "egress-queue-stats" in value and "pfc-stats" in value:
            return value
        for child in value.values():
            found = _find_qos_object(child)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_qos_object(child)
            if found is not None:
                return found
    return None


def _priority_three(group: Any) -> Optional[Mapping[str, Any]]:
    if isinstance(group, Mapping):
        candidate = group.get("3")
        if isinstance(candidate, Mapping):
            return candidate
    if isinstance(group, list):
        for candidate in group:
            if not isinstance(candidate, Mapping):
                continue
            selector = candidate.get(
                "traffic-class", candidate.get("switch-priority", candidate.get("id"))
            )
            if str(selector) == "3":
                return candidate
    return None


def _counter_number(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if re.fullmatch(r"[0-9]+", text):
            return int(text)
    if isinstance(value, Mapping):
        for key in ("value", "counter", "operational"):
            if key in value:
                return _counter_number(value[key])
    return None


def extract_counters(payload: Mapping[str, Any]) -> Dict[str, Optional[int]]:
    qos = _find_qos_object(payload)
    result: Dict[str, Optional[int]] = {name: None for name in COUNTER_PATHS}
    if qos is None:
        return result
    groups = {
        "egress-queue-stats": _priority_three(qos.get("egress-queue-stats")),
        "pfc-stats": _priority_three(qos.get("pfc-stats")),
    }
    for name, (group_name, field) in COUNTER_PATHS.items():
        group = groups[group_name]
        if group is not None:
            result[name] = _counter_number(group.get(field))
    return result


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def build_port_record(
    hostname: str,
    interface: str,
    counters: Mapping[str, Optional[int]],
    previous: Optional[Mapping[str, Any]],
    timestamp: float,
    collection_status: str = "ok",
) -> Dict[str, Any]:
    previous_counters = previous.get("counters", {}) if isinstance(previous, Mapping) else {}
    previous_timestamp = previous.get("timestamp") if isinstance(previous, Mapping) else None
    duration = (
        timestamp - float(previous_timestamp)
        if isinstance(previous_timestamp, (int, float)) and timestamp > previous_timestamp
        else None
    )
    deltas: Dict[str, Optional[int]] = {}
    rates: Dict[str, Optional[float]] = {}
    reset_counters: List[str] = []
    missing_baseline: List[str] = []

    for name in COUNTER_PATHS:
        current = counters.get(name)
        old = previous_counters.get(name) if isinstance(previous_counters, Mapping) else None
        if current is None or old is None or duration is None:
            deltas[name] = None
            rates[name] = None
            if current is not None and old is None:
                missing_baseline.append(name)
            continue
        if current < old:
            deltas[name] = None
            rates[name] = None
            reset_counters.append(name)
            continue
        delta = current - old
        deltas[name] = delta
        rates[name] = delta / duration

    exact = all(counters.get(name) is not None for name in REQUIRED_COUNTERS)
    if collection_status != "ok":
        sample_status = "collection_error"
    elif not exact:
        sample_status = "missing"
    elif any(name in reset_counters for name in REQUIRED_COUNTERS):
        sample_status = "counter_reset"
    elif (
        previous is None
        or duration is None
        or any(name in missing_baseline for name in REQUIRED_COUNTERS)
    ):
        sample_status = "first_sample"
    else:
        sample_status = "analyzed"

    discard_values = [
        deltas.get("tx_uc_buffer_discards"), deltas.get("wred_discards")
    ]
    # The table labels this as the combined TC3 discard delta.  Showing a
    # partial sum as zero would hide an unavailable constituent counter.
    loss_delta = (
        sum(discard_values) if all(value is not None for value in discard_values)
        else None
    )
    ecn_delta = deltas.get("ecn_marked_frames")
    tx_delta = deltas.get("tx_frames")
    ecn_share = (
        ecn_delta / tx_delta * 100.0
        if ecn_delta is not None and tx_delta is not None and tx_delta > 0
        else None
    )
    pfc_active = any(
        (deltas.get(name) or 0) > 0
        for name in ("rx_pause_frames", "tx_pause_frames")
    )
    ecn_active = (ecn_delta or 0) > 0
    if sample_status != "analyzed":
        signal = sample_status
    elif (loss_delta or 0) > 0:
        signal = "loss"
    elif ecn_active and pfc_active:
        signal = "combined"
    elif pfc_active:
        signal = "pfc"
    elif ecn_active:
        signal = "ecn"
    else:
        signal = "quiet"

    return {
        "hostname": hostname,
        "interface": interface,
        "port_key": f"{hostname}:{interface}",
        "timestamp": timestamp,
        "timestamp_iso": _iso(timestamp),
        "sample_duration_seconds": duration,
        "sample_status": sample_status,
        "signal": signal,
        "exact": exact,
        "counters": dict(counters),
        "deltas": deltas,
        "rates": rates,
        "reset_counters": reset_counters,
        "ecn_share_percent": ecn_share,
        "loss_delta": loss_delta,
    }


def _read_state(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    """Stream compact JSON to the atomic stage without duplicating it in RAM."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        mode = (path.stat().st_mode & 0o7777) if path.exists() else 0o664
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(value, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = ""
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _fmt_total(value: Optional[int]) -> str:
    return "&mdash;" if value is None else f"{value:,}"


def _fmt_delta(value: Optional[int]) -> str:
    return "&mdash;" if value is None else f"+{value:,}"


def _fmt_rate(value: Optional[float]) -> str:
    if value is None:
        return "&mdash;"
    if value >= 1000:
        return f"{value:,.0f}/s"
    if value >= 1:
        return f"{value:,.2f}/s"
    return f"{value:,.4f}/s"


def _fmt_percent(value: Optional[float]) -> str:
    return "&mdash;" if value is None else f"{value:.4f}%"


def _fmt_duration(value: Optional[float]) -> str:
    if value is None or value < 0:
        return "—"
    seconds = int(round(value))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _fmt_sample_time(timestamp: float) -> str:
    value = datetime.fromtimestamp(timestamp, timezone.utc)
    return f"{value.day} {value:%b %Y, %H:%M:%S} UTC"


def render_report(
    records: List[Mapping[str, Any]],
    _history: Mapping[str, Any],
    expected_hosts: Optional[int] = None,
    current_hosts: Optional[int] = None,
    collection_unavailable: bool = False,
    coverage_failures: Optional[Mapping[str, str]] = None,
) -> str:
    records = sorted(records, key=lambda row: (row["hostname"], row["interface"]))
    total = len(records)
    exact = sum(bool(row.get("exact")) for row in records)
    analyzed_records = [
        row for row in records if row.get("sample_status") == "analyzed"
    ]
    ready = len(analyzed_records)
    ecn_active = sum(
        (row["deltas"].get("ecn_marked_frames") or 0) > 0
        for row in analyzed_records
    )
    rx_active = sum(
        (row["deltas"].get("rx_pause_frames") or 0) > 0
        for row in analyzed_records
    )
    tx_active = sum(
        (row["deltas"].get("tx_pause_frames") or 0) > 0
        for row in analyzed_records
    )
    discard_ready = sum(
        row.get("loss_delta") is not None for row in analyzed_records
    )
    loss_active = sum(
        (row.get("loss_delta") or 0) > 0 for row in analyzed_records
    )
    incomplete = total - ready
    device_coverage = (
        f"{current_hosts}/{expected_hosts}"
        if expected_hosts is not None and current_hosts is not None
        else "&mdash;"
    )
    coverage_attrs = ""
    collection_status = "partial"
    coverage_status = "partial"
    if collection_unavailable:
        coverage_attrs = ' data-collection-status="unavailable" data-coverage-status="unavailable"'
        collection_status = "unavailable"
        coverage_status = "unavailable"
    elif expected_hosts is not None and current_hosts is not None:
        coverage = "complete" if current_hosts >= expected_hosts else "partial"
        coverage_attrs = (
            f' data-coverage-status="{coverage}" data-coverage-expected="{expected_hosts}"'
            f' data-coverage-current="{current_hosts}"'
        )
        coverage_status = coverage
        collection_status = "current" if coverage == "complete" else "partial"

    interval_status = (
        "unavailable"
        if collection_unavailable or total == 0 or ready == 0
        else "complete"
        if ready == total and coverage_status == "complete"
        else "partial"
    )
    coverage_metadata_attrs = ""
    if current_hosts is not None:
        coverage_metadata_attrs += f' data-coverage-current="{current_hosts}"'
    if expected_hosts is not None:
        coverage_metadata_attrs += f' data-coverage-expected="{expected_hosts}"'
    failure_hosts = sorted(coverage_failures or {})
    failure_metadata = (
        ' data-coverage-failed-hosts="'
        + html.escape(",".join(failure_hosts), quote=True)
        + '"'
        if failure_hosts else ""
    )
    summary_metadata = (
        '<div hidden data-analysis-summary="pfc-ecn"'
        f' data-collection-status="{collection_status}"'
        f' data-coverage-status="{coverage_status}"'
        f'{coverage_metadata_attrs}'
        f'{failure_metadata}'
        f' data-interval-status="{interval_status}"'
        f' data-total-ports="{total}" data-ready-ports="{ready}"'
        f' data-ecn-active-ports="{ecn_active}"'
        f' data-pfc-rx-active-ports="{rx_active}"'
        f' data-pfc-tx-active-ports="{tx_active}"'
        f' data-discard-ready-ports="{discard_ready}"'
        f' data-discard-active-ports="{loss_active}"></div>'
    )

    rows = []
    for row in records:
        counters, deltas, rates = row["counters"], row["deltas"], row["rates"]
        status = str(row["sample_status"])
        status_key = str({
            "analyzed": row.get("signal", "quiet"),
            "first_sample": "first_sample",
            "counter_reset": "counter_reset",
            "collection_error": "collection_error",
            "missing": "missing",
        }.get(status, status))
        status_label = {
            "quiet": "No ECN/PFC activity",
            "ecn": "ECN marking",
            "pfc": "PFC activity",
            "combined": "ECN + PFC",
            "loss": "Discards",
            "first_sample": "Baseline set",
            "counter_reset": "Counter reset",
            "collection_error": "Collection failed",
            "missing": "Data missing",
        }.get(status_key, status_key.replace("_", " ").title())
        status_class = {
            "loss": "danger", "combined": "warn", "pfc": "warn", "ecn": "info",
            "quiet": "ok", "first_sample": "muted", "counter_reset": "muted",
            "collection_error": "danger", "missing": "muted",
        }.get(status_key, "muted")
        hostname = str(row["hostname"])
        interface = str(row["interface"])
        search = html.escape(
            f"{hostname} {interface} {status_key} {status_label}".lower(), quote=True
        )
        sort = lambda value: "" if value is None else str(value)
        ecn_delta_display = _fmt_delta(deltas.get("ecn_marked_frames"))
        ecn_rate_display = _fmt_rate(rates.get("ecn_marked_frames"))
        rx_delta_display = _fmt_delta(deltas.get("rx_pause_frames"))
        rx_rate_display = _fmt_rate(rates.get("rx_pause_frames"))
        tx_delta_display = _fmt_delta(deltas.get("tx_pause_frames"))
        tx_rate_display = _fmt_rate(rates.get("tx_pause_frames"))
        sample_time = _fmt_sample_time(float(row["timestamp"]))
        sample_window = _fmt_duration(row.get("sample_duration_seconds"))
        row_analyzed = row.get("sample_status") == "analyzed"
        row_flags = {
            "exact": bool(row.get("exact")),
            "ecn_active": row_analyzed and (deltas.get("ecn_marked_frames") or 0) > 0,
            "rx_active": row_analyzed and (deltas.get("rx_pause_frames") or 0) > 0,
            "tx_active": row_analyzed and (deltas.get("tx_pause_frames") or 0) > 0,
            "loss_active": row_analyzed and (row.get("loss_delta") or 0) > 0,
            "attention": not row_analyzed,
        }
        flag_attrs = " ".join(
            f'data-{name.replace("_", "-")}="{int(value)}"'
            for name, value in row_flags.items()
        )
        rows.append(f'''<tr data-search="{search}" data-status="{html.escape(status_key, quote=True)}" data-device="{html.escape(hostname, quote=True)}" {flag_attrs}>
<td data-sort="{html.escape(hostname, quote=True)}" data-csv-value="{html.escape(hostname, quote=True)}" data-p2p-namespace="devices"><span data-p2p-key="{html.escape(hostname, quote=True)}" data-p2p-namespace="devices">{html.escape(hostname)}</span></td>
<td data-sort="{html.escape(interface, quote=True)}" data-csv-value="{html.escape(interface, quote=True)}" data-p2p-namespace="interfaces"><code data-p2p-key="{html.escape(interface, quote=True)}" data-p2p-namespace="interfaces">{html.escape(interface)}</code></td>
<td data-sort="{html.escape(status_label, quote=True)}"><span class="badge {status_class}">{html.escape(status_label)}</span></td>
<td data-sort="{sort(counters.get('ecn_marked_frames'))}">{_fmt_total(counters.get('ecn_marked_frames'))}</td>
<td data-sort="{sort(deltas.get('ecn_marked_frames'))}" data-csv-value="{ecn_delta_display} / {ecn_rate_display}">{ecn_delta_display}<small>{ecn_rate_display}</small></td>
<td data-sort="{sort(row.get('ecn_share_percent'))}">{_fmt_percent(row.get('ecn_share_percent'))}</td>
<td data-sort="{sort(counters.get('rx_pause_frames'))}">{_fmt_total(counters.get('rx_pause_frames'))}</td>
<td data-sort="{sort(deltas.get('rx_pause_frames'))}" data-csv-value="{rx_delta_display} / {rx_rate_display}">{rx_delta_display}<small>{rx_rate_display}</small></td>
<td data-sort="{sort(counters.get('tx_pause_frames'))}">{_fmt_total(counters.get('tx_pause_frames'))}</td>
<td data-sort="{sort(deltas.get('tx_pause_frames'))}" data-csv-value="{tx_delta_display} / {tx_rate_display}">{tx_delta_display}<small>{tx_rate_display}</small></td>
<td data-sort="{sort(deltas.get('tx_frames'))}">{_fmt_delta(deltas.get('tx_frames'))}</td>
<td data-sort="{sort(row.get('loss_delta'))}">{_fmt_delta(row.get('loss_delta'))}</td>
<td data-sort="{row['timestamp']}" data-csv-value="{html.escape(sample_time, quote=True)} / {html.escape(sample_window, quote=True)} window" title="{html.escape(str(row['timestamp_iso']), quote=True)}">{html.escape(sample_time)}<small>{html.escape(sample_window)} window</small></td>
</tr>''')

    latest_timestamp = max(
        (float(row["timestamp"]) for row in records),
        default=time.time(),
    )
    last_updated = datetime.fromtimestamp(
        latest_timestamp, timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")
    unavailable_banner = (
        '<div class="notice">No current switch collection is available; '
        'the table intentionally shows no current counters.</div>'
        if collection_unavailable else ""
    )
    partial_banner = ""
    if coverage_failures and not collection_unavailable:
        failure_text = "; ".join(
            f"{host}: {coverage_failures[host]}" for host in failure_hosts
        )
        partial_banner = (
            '<div class="notice">Partial PFC/ECN collection. '
            + html.escape(failure_text)
            + '</div>'
        )
    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PFC/ECN Analysis</title>
<link rel="shortcut icon" href="/png/favicon.ico">
<link rel="stylesheet" type="text/css" href="/css/select2.min.css">
<meta name="totalPorts" content="{total}"><meta name="exactPorts" content="{exact}">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#1e1e1e;color:#d4d4d4;padding:20px;min-height:100vh}}
.page-header{{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid #404040}}
.page-title{{font-size:24px;font-weight:600;color:#76b900}}.last-updated{{font-size:13px;color:#888;margin-top:2px}}
.action-buttons{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end}}.device-search-container{{display:flex;align-items:center}}
.device-search-container .select2-container{{min-width:220px}}.device-search-container .select2-container--default .select2-selection--single{{height:34px;border:1px solid #555;border-radius:4px;background:#3c3c3c;display:flex;align-items:center}}
.device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered{{line-height:34px;color:#d4d4d4;padding-left:10px;font-size:13px}}.device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow{{height:34px}}.device-search-container .select2-container--default .select2-selection--single .select2-selection__placeholder{{color:#888}}
.select2-dropdown{{background:#2d2d2d;border:1px solid #555}}.select2-container--default .select2-search--dropdown .select2-search__field{{background:#3c3c3c;border:1px solid #555;color:#d4d4d4}}.select2-container--default .select2-results__option{{color:#d4d4d4;padding:8px 12px}}.select2-container--default .select2-results__option--highlighted[aria-selected]{{background:#76b900;color:#000}}.select2-container--default .select2-results__option[aria-selected=true]{{background:#3c3c3c}}
.btn{{height:34px;padding:8px 14px;border:none;border-radius:4px;font-size:13px;font-weight:500;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}}
.btn-primary{{background:linear-gradient(0deg,#76b900 0%,#5a8c00 100%);color:#fff}}.btn-primary:hover{{background:linear-gradient(0deg,#8bd400 0%,#6ba000 100%)}}
.btn-secondary{{background:linear-gradient(0deg,#4fc3f7 0%,#0288d1 100%);color:#fff}}.btn-secondary:hover{{background:linear-gradient(0deg,#81d4fa 0%,#039be5 100%)}}.btn:disabled{{opacity:.6;cursor:wait}}
.notice{{margin:0 0 20px;padding:12px 14px;border-left:4px solid #ff9800;background:#332b20;color:#ffcc80}}
.dashboard-section{{background:#2d2d2d;border-radius:8px;margin-bottom:20px;overflow:hidden}}.section-header{{padding:12px 16px;background:#333;font-weight:600;font-size:14px;color:#76b900;border-bottom:1px solid #404040}}
.section-content{{padding:16px}}.section-content-table{{padding:0}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}}
.summary-card{{background:#252526;padding:15px;border-radius:6px;border-left:3px solid #76b900;cursor:pointer;transition:all .2s ease;outline:none}}.summary-card:hover{{background:#2d2d2d;transform:translateY(-1px)}}.summary-card.active{{background:#333;border-left-width:5px}}.summary-card:focus-visible{{outline:2px solid #76b900;outline-offset:2px}}.card-info{{border-left-color:#4fc3f7}}.card-good{{border-left-color:#8bc34a}}.card-warning{{border-left-color:#ff9800}}.card-critical{{border-left-color:#f44336}}
.metric{{font-size:22px;font-weight:bold;color:#d4d4d4}}.card-info .metric{{color:#4fc3f7}}.card-good .metric{{color:#8bc34a}}.card-warning .metric{{color:#ff9800}}.card-critical .metric{{color:#f44336}}.metric-label{{font-size:12px;color:#aaa;margin-top:4px}}.metric-caption{{font-size:10px;color:#777;margin-top:3px}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid #404040}}.toolbar input,.toolbar select{{height:34px;background:#3c3c3c;color:#d4d4d4;border:1px solid #555;border-radius:4px;padding:0 10px;font-size:13px}}.toolbar input{{min-width:260px;flex:1}}
.filter-info{{margin:10px 16px;padding:8px 12px;background:rgba(118,185,0,.1);border:1px solid rgba(118,185,0,.3);border-radius:5px;color:#9ccc65;font-size:12px}}.filter-info[hidden]{{display:none}}.filter-info button{{margin-left:8px;padding:3px 9px;background:#76b900;color:#000;border:0;border-radius:4px;cursor:pointer;font-size:11px}}
.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:1200px;font-size:13px}}th,td{{border:1px solid #404040;padding:9px 10px;text-align:left;white-space:nowrap}}th{{background:#333;color:#76b900;font-weight:600;font-size:12px;position:sticky;top:0;z-index:1}}tbody tr{{background:#252526}}tbody tr:hover{{background:#2d2d2d}}td:nth-child(n+4){{text-align:right}}td small{{display:block;color:#888;margin-top:2px}}code{{color:#9cdcfe}}
.sortable{{cursor:pointer;user-select:none;padding-right:16px}}.sortable:hover{{background:#3c3c3c}}.sort-arrow{{font-size:10px;color:#666;margin-left:3px;opacity:.65}}.sortable.asc .sort-arrow,.sortable.desc .sort-arrow{{color:#76b900;opacity:1}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}}.badge.ok{{background:rgba(118,185,0,.2);color:#76b900}}.badge.info{{background:rgba(79,195,247,.2);color:#4fc3f7}}.badge.warn{{background:rgba(255,152,0,.2);color:#ffb74d}}.badge.danger{{background:rgba(244,67,54,.2);color:#ff6b6b}}.badge.muted{{background:rgba(158,158,158,.2);color:#aaa}}
.guide-modal{{display:none;position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.68);padding:40px 16px}}.guide-modal.open{{display:flex;align-items:flex-start;justify-content:center}}.guide-modal-box{{background:#1e1e1e;border:1px solid #3c3c3c;border-radius:8px;width:92%;max-width:960px;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 12px 48px rgba(0,0,0,.55)}}
.guide-modal-head{{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #3c3c3c}}.guide-modal-head h2{{font-size:17px;color:#e0e0e0}}.guide-modal-close{{background:none;border:none;color:#aaa;font-size:26px;line-height:1;cursor:pointer;padding:0 6px}}.guide-modal-close:hover{{color:#fff}}.guide-modal-body{{padding:18px;overflow:auto;color:#aaa;font-size:13px;line-height:1.65}}
.guide-intro{{padding:12px 14px;background:#252526;border-left:3px solid #76b900;color:#d4d4d4;margin-bottom:16px}}.guide-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px}}.guide-card{{background:#252526;border-left:3px solid #4fc3f7;padding:12px}}.guide-card:first-child{{border-left-color:#76b900}}.guide-card:last-child{{border-left-color:#ff9800}}.guide-card h3,.guide-section h3{{font-size:14px;color:#d4d4d4;margin-bottom:5px}}
.guide-section{{margin-top:18px}}.guide-section ul{{margin:7px 0 0 20px}}.guide-section li{{margin:6px 0}}.guide-table{{width:100%;min-width:0;margin-top:8px;font-size:12px}}.guide-table th,.guide-table td{{white-space:normal;text-align:left}}.guide-table th{{position:static;color:#d4d4d4;background:#333}}.guide-note{{margin-top:18px;padding:10px 12px;background:#332b20;border-left:3px solid #ff9800;color:#ffcc80}}
@media(max-width:1100px){{.page-header{{align-items:flex-start}}.action-buttons{{max-width:62%}}}}@media(max-width:760px){{body{{padding:12px}}.page-header{{display:block}}.action-buttons{{max-width:none;justify-content:flex-start;margin-top:12px}}.device-search-container .select2-container{{min-width:180px}}.guide-grid{{grid-template-columns:1fr}}}}
</style></head><body{coverage_attrs}>
{summary_metadata}
<div class="page-header">
  <div><div class="page-title">PFC/ECN Analysis</div><div class="last-updated">Last Updated: {html.escape(last_updated)}</div></div>
  <div class="action-buttons">
    <div class="device-search-container"><select id="deviceSearch" aria-label="Filter by device"><option value="">Search Device...</option></select></div>
    <button id="metric-guide-btn" class="btn btn-secondary" type="button" onclick="openMetricGuide()" title="How to interpret PFC and ECN counters"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>Metric Guide</button>
    <button id="run-analysis" class="btn btn-secondary" type="button" onclick="runAnalysis()"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>Run Analysis</button>
    <button id="download-csv" class="btn btn-primary" type="button"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>Download CSV</button>
  </div>
</div>
{unavailable_banner}
{partial_banner}
<section class="dashboard-section"><div class="section-header">PFC/ECN Summary</div><div class="section-content"><div class="summary-grid">
<div id="devices-card" class="summary-card card-info" data-card-filter="all" data-filter-label="All reporting devices" role="button" tabindex="0" aria-pressed="false"><div class="metric">{device_coverage}</div><div class="metric-label">Devices reporting</div></div>
<div id="ports-card" class="summary-card card-good" data-card-filter="all" data-filter-label="All checked ports" role="button" tabindex="0" aria-pressed="false"><div class="metric">{total:,}</div><div class="metric-label">Ports checked</div></div>
<div id="exact-card" class="summary-card card-good" data-card-filter="exact" data-filter-label="Counters available" role="button" tabindex="0" aria-pressed="false"><div class="metric">{exact:,}/{total:,}</div><div class="metric-label">Counters available</div></div>
<div id="ecn-card" class="summary-card card-good" data-card-filter="ecn" data-filter-label="Ports marking ECN" role="button" tabindex="0" aria-pressed="false"><div class="metric">{ecn_active:,}</div><div class="metric-label">Ports marking ECN</div><div class="metric-caption">Since previous sample</div></div>
<div id="rx-card" class="summary-card card-warning" data-card-filter="rx" data-filter-label="Paused by peer (PFC RX)" role="button" tabindex="0" aria-pressed="false"><div class="metric">{rx_active:,}</div><div class="metric-label">Paused by peer (PFC RX)</div><div class="metric-caption">Since previous sample</div></div>
<div id="tx-card" class="summary-card card-warning" data-card-filter="tx" data-filter-label="Asked peer to pause (PFC TX)" role="button" tabindex="0" aria-pressed="false"><div class="metric">{tx_active:,}</div><div class="metric-label">Asked peer to pause (PFC TX)</div><div class="metric-caption">Since previous sample</div></div>
<div id="loss-card" class="summary-card card-critical" data-card-filter="loss" data-filter-label="Ports with discards" role="button" tabindex="0" aria-pressed="false"><div class="metric">{loss_active:,}</div><div class="metric-label">Ports with discards</div><div class="metric-caption">Since previous sample</div></div>
<div id="attention-card" class="summary-card {'card-warning' if incomplete else 'card-good'}" data-card-filter="attention" data-filter-label="Needs attention" role="button" tabindex="0" aria-pressed="false"><div class="metric">{incomplete:,}</div><div class="metric-label">Needs attention</div><div class="metric-caption">Missing, reset, or awaiting sample</div></div>
</div></div></section>
<section class="dashboard-section"><div class="section-header">Port Details</div><div class="section-content-table">
<div class="toolbar"><input id="search" type="search" placeholder="Search device, port, or status..." aria-label="Search ports"><select id="statusFilter" aria-label="Filter status"><option value="">All statuses</option><option value="quiet">No ECN/PFC activity</option><option value="ecn">ECN marking</option><option value="pfc">PFC activity</option><option value="combined">ECN + PFC</option><option value="loss">Discards</option><option value="missing">Data missing</option><option value="first_sample">Baseline set</option><option value="counter_reset">Counter reset</option><option value="collection_error">Collection failed</option></select></div>
<div id="summary-filter-info" class="filter-info" hidden><span id="summary-filter-text"></span><button id="clear-summary-filter" type="button">Clear card filter</button></div>
<div class="table-wrap"><table id="ports"><thead><tr>
<th class="sortable" data-type="string" aria-sort="none" title="Switch hostname">Device <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="string" aria-sort="none" title="Physical switch interface">Port <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="string" aria-sort="none" title="Highest-priority signal in this sample window">Status <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="Cumulative TC3 ECN-marked frames">ECN Total <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="TC3 ECN-marked change and average rate">ECN Δ / Rate <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="ECN-marked share of TC3 transmitted frames">ECN % <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="Cumulative SP3 pause frames received">PFC RX Total <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="SP3 received pause-frame change and average rate">PFC RX Δ / Rate <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="Cumulative SP3 pause frames transmitted">PFC TX Total <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="SP3 transmitted pause-frame change and average rate">PFC TX Δ / Rate <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="TC3 transmitted frames since the previous sample">TC3 TX Δ <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="Combined TC3 unicast-buffer and WRED discard change">Discard Δ <span class="sort-arrow">▲▼</span></th>
<th class="sortable" data-type="number" aria-sort="none" title="Latest sample time and elapsed comparison window">Sample / Window <span class="sort-arrow">▲▼</span></th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></div></div></section>
<div id="metricGuideModal" class="guide-modal" role="dialog" aria-modal="true" aria-labelledby="metricGuideTitle" aria-hidden="true">
  <div class="guide-modal-box"><div class="guide-modal-head"><h2 id="metricGuideTitle">PFC/ECN Metric Guide</h2><button type="button" class="guide-modal-close" onclick="closeMetricGuide()" title="Close" aria-label="Close metric guide">&times;</button></div>
  <div class="guide-modal-body"><div class="guide-intro">This report compares the latest switch counters with the previous successful collection. It monitors traffic class 3 (TC3) and switch priority 3 (SP3). Totals are cumulative hardware counters; “since last sample” values show what changed during the comparison window.</div>
  <div class="guide-grid"><div class="guide-card"><h3>TC3 ECN marked</h3>ECN-capable traffic marked by this port's egress queue. An increase is evidence of egress congestion, but it does not mean packets were dropped.</div><div class="guide-card"><h3>SP3 PFC RX — peer paused us</h3>Priority-3 pause frames received from the link partner. An increase means the peer asked this port to pause priority-3 transmission.</div><div class="guide-card"><h3>SP3 PFC TX — we paused the peer</h3>Priority-3 pause frames sent to the link partner. An increase means this switch asked the peer to pause because of local ingress pressure.</div></div>
  <div class="guide-section"><h3>Table columns</h3><table class="guide-table"><tbody><tr><th>Total</th><td>Current cumulative hardware counter. It can include activity from before the current sample window.</td></tr><tr><th>Δ</th><td>Increase since the previous successful sample: current total minus previous total.</td></tr><tr><th>Rate</th><td>Δ divided by the elapsed sample window. It is an average in frames/s, not an instantaneous rate.</td></tr><tr><th>ECN %</th><td>TC3 ECN Δ divided by TC3 TX Δ for the same window. It is unavailable when TC3 TX Δ is zero or missing.</td></tr><tr><th>PFC RX</th><td>SP3 pause frames received. The peer asked this port to pause priority-3 transmission.</td></tr><tr><th>PFC TX</th><td>SP3 pause frames sent. This switch asked the peer to pause priority-3 transmission because of local ingress pressure.</td></tr><tr><th>TC3 TX Δ</th><td>Traffic-class 3 frames transmitted since the previous successful sample; this is the denominator for ECN %.</td></tr><tr><th>Discard Δ</th><td>TC3 unicast-buffer discards plus WRED discards since the previous successful sample. Both counters must be available; a non-zero value is direct drop evidence.</td></tr><tr><th>Sample / Window</th><td>Time of the latest sample and elapsed time since the previous successful sample.</td></tr><tr><th>—</th><td>Data is unavailable; it does not mean zero.</td></tr></tbody></table></div>
  <div class="guide-section"><h3>Filtering</h3><p>Click a signal summary card to filter the port table; click the active card again to clear it. Signal cards work together with device, status, and text filters. Devices reporting and Ports checked return the table to all rows.</p></div>
  <div class="guide-section"><h3>Status meanings</h3><ul><li><strong>No ECN/PFC activity:</strong> no new ECN marks or PFC frames were observed; check the Discards column separately.</li><li><strong>ECN marking:</strong> new ECN marks were observed.</li><li><strong>PFC activity:</strong> new PFC RX or TX frames were observed.</li><li><strong>ECN + PFC:</strong> both ECN marking and PFC activity occurred.</li><li><strong>Discards:</strong> new drop counters were observed; this status takes precedence.</li><li><strong>Baseline set:</strong> one more sample is required for deltas and rates.</li><li><strong>Counter reset:</strong> a counter decreased, so no misleading negative delta is shown.</li><li><strong>Data missing / Collection failed:</strong> exact counters were unavailable or the command did not return a usable sample.</li></ul></div>
  <div class="guide-note">There are no arbitrary warning or critical thresholds on this page. ECN and PFC are operational signals that must be interpreted by direction, duration, and affected ports. PFC counters count pause frames, not how long traffic remained paused.</div></div></div>
</div>
<script src="/css/jquery-3.5.1.min.js"></script>
<script src="/css/select2.min.js"></script>
<script>
(function() {{
  const table = document.querySelector('#ports');
  const body = table.tBodies[0];
  const search = document.querySelector('#search');
  const statusFilter = document.querySelector('#statusFilter');
  const deviceSearch = document.querySelector('#deviceSearch');
  const summaryCards = [...document.querySelectorAll('.summary-card[data-card-filter]')];
  const summaryFilterInfo = document.querySelector('#summary-filter-info');
  const summaryFilterText = document.querySelector('#summary-filter-text');
  const headers = [...table.tHead.rows[0].cells];
  let activeCard = null;
  let activeCardFilter = '';
  let direction = 1;
  let lastColumn = -1;

  function matchesCardFilter(row) {{
    if (!activeCardFilter || activeCardFilter === 'all') return true;
    const dataKey = {{
      exact: 'exact',
      ecn: 'ecnActive',
      rx: 'rxActive',
      tx: 'txActive',
      loss: 'lossActive',
      attention: 'attention'
    }}[activeCardFilter];
    return Boolean(dataKey && row.dataset[dataKey] === '1');
  }}

  function applyFilters() {{
    const query = search.value.trim().toLowerCase();
    const status = statusFilter.value;
    const device = deviceSearch.value;
    [...body.rows].forEach(row => {{
      const searchable = (row.dataset.search + ' ' + row.textContent).toLowerCase();
      row.hidden = Boolean(
        (query && !searchable.includes(query)) ||
        (status && row.dataset.status !== status) ||
        (device && row.dataset.device !== device) ||
        !matchesCardFilter(row)
      );
    }});
  }}

  function clearNonCardFilters() {{
    search.value = '';
    statusFilter.value = '';
    deviceSearch.value = '';
    const jq = window.jQuery;
    if (jq && jq.fn && typeof jq.fn.select2 === 'function') {{
      jq(deviceSearch).val('').trigger('change.select2');
    }}
  }}

  function clearCardFilter() {{
    activeCard = null;
    activeCardFilter = '';
    summaryCards.forEach(card => {{
      card.classList.remove('active');
      card.setAttribute('aria-pressed', 'false');
    }});
    summaryFilterInfo.hidden = true;
    applyFilters();
  }}

  function toggleCardFilter(card) {{
    if (activeCard === card) {{
      clearCardFilter();
      return;
    }}
    activeCard = card;
    activeCardFilter = card.dataset.cardFilter;
    if (activeCardFilter === 'all') clearNonCardFilters();
    summaryCards.forEach(item => {{
      const selected = item === card;
      item.classList.toggle('active', selected);
      item.setAttribute('aria-pressed', selected ? 'true' : 'false');
    }});
    const showInfo = activeCardFilter !== 'all';
    summaryFilterInfo.hidden = !showInfo;
    summaryFilterText.textContent = 'Card filter: ' + card.dataset.filterLabel;
    applyFilters();
  }}

  function populateDevices() {{
    const devices = [...new Set(
      [...body.rows].map(row => row.dataset.device).filter(Boolean)
    )].sort((a, b) => a.localeCompare(b, undefined, {{numeric: true, sensitivity: 'base'}}));
    devices.forEach(device => {{
      const option = document.createElement('option');
      option.value = device;
      option.textContent = device;
      option.setAttribute('data-p2p-key', device);
      option.setAttribute('data-p2p-namespace', 'devices');
      deviceSearch.appendChild(option);
    }});
  }}

  function initDeviceSearch() {{
    const jq = window.jQuery;
    if (!jq || !jq.fn || typeof jq.fn.select2 !== 'function') return;
    const optionLabel = data => data.element ? data.element.textContent : data.text;
    jq(deviceSearch).select2({{
      placeholder: 'Search Device...',
      allowClear: true,
      width: '220px',
      dropdownAutoWidth: true,
      templateResult: optionLabel,
      templateSelection: optionLabel,
      matcher: function(params, data) {{
        const term = jq.trim(params.term || '').toLowerCase();
        if (!term) return data;
        const option = data.element;
        const terms = [
          data.text, data.id,
          option && option.textContent,
          option && option.getAttribute('data-p2p-orig'),
          option && option.getAttribute('data-p2p-key')
        ].filter(Boolean).join(' ').toLowerCase();
        return terms.includes(term) ? data : null;
      }}
    }});
    jq(deviceSearch).on('change', applyFilters);
  }}

  function applyRequestedCardFilter() {{
    const requested = new URLSearchParams(window.location.search).get('filter');
    if (!requested) return;
    const card = summaryCards.find(item => item.dataset.cardFilter === requested);
    if (card) toggleCardFilter(card);
  }}

  function resetSortIndicators() {{
    headers.forEach(header => {{
      header.classList.remove('asc', 'desc');
      header.setAttribute('aria-sort', 'none');
      const arrow = header.querySelector('.sort-arrow');
      if (arrow) arrow.textContent = '▲▼';
    }});
  }}

  search.addEventListener('input', applyFilters);
  statusFilter.addEventListener('change', applyFilters);
  deviceSearch.addEventListener('change', applyFilters);
  document.querySelector('#clear-summary-filter').addEventListener('click', clearCardFilter);
  summaryCards.forEach(card => {{
    card.addEventListener('click', () => toggleCardFilter(card));
    card.addEventListener('keydown', event => {{
      if (event.key === 'Enter' || event.key === ' ') {{
        event.preventDefault();
        toggleCardFilter(card);
      }}
    }});
  }});
  headers.forEach((header, index) => header.addEventListener('click', () => {{
    direction = lastColumn === index ? -direction : 1;
    lastColumn = index;
    resetSortIndicators();
    header.classList.add(direction === 1 ? 'asc' : 'desc');
    header.setAttribute('aria-sort', direction === 1 ? 'ascending' : 'descending');
    const arrow = header.querySelector('.sort-arrow');
    if (arrow) arrow.textContent = direction === 1 ? '▲' : '▼';
    const numeric = header.dataset.type === 'number';
    [...body.rows].sort((a, b) => {{
      let first = a.cells[index].dataset.sort ?? '';
      let second = b.cells[index].dataset.sort ?? '';
      if (first === '' && second === '') return 0;
      if (first === '') return 1;
      if (second === '') return -1;
      if (numeric) return (Number(first) - Number(second)) * direction;
      return first.localeCompare(second, undefined, {{numeric: true, sensitivity: 'base'}}) * direction;
    }}).forEach(row => body.appendChild(row));
  }}));

  document.querySelector('#download-csv').addEventListener('click', () => {{
    const cleanHeader = cell => cell.textContent.replace(/[▲▼]/g, '').trim();
    const canonicalCell = cell => {{
      if (cell.dataset.csvValue) return cell.dataset.csvValue;
      if (window.LLDPqP2P && typeof window.LLDPqP2P.canonicalText === 'function') {{
        return window.LLDPqP2P.canonicalText(cell).trim().replace(/\\s+/g, ' ');
      }}
      return cell.textContent.trim().replace(/\\s+/g, ' ');
    }};
    const visibleRows = [...body.rows].filter(row => !row.hidden);
    const lines = [
      headers.map(cleanHeader),
      ...visibleRows.map(row => [...row.cells].map(canonicalCell))
    ].map(row => row.map(value => '"' + value.replaceAll('"', '""') + '"').join(','));
    const blob = new Blob([lines.join('\\n') + '\\n'], {{type: 'text/csv;charset=utf-8'}});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'PFC_ECN_Analysis.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }});

  populateDevices();
  initDeviceSearch();
  applyRequestedCardFilter();
}})();

let metricGuideReturnFocus = null;
function openMetricGuide() {{
  const modal = document.getElementById('metricGuideModal');
  metricGuideReturnFocus = document.activeElement;
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  const closeButton = modal.querySelector('.guide-modal-close');
  if (closeButton) closeButton.focus();
}}
function closeMetricGuide() {{
  const modal = document.getElementById('metricGuideModal');
  if (!modal.classList.contains('open')) return;
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  const returnTarget = metricGuideReturnFocus;
  metricGuideReturnFocus = null;
  if (returnTarget && typeof returnTarget.focus === 'function') returnTarget.focus();
}}
document.getElementById('metricGuideModal').addEventListener('click', event => {{
  if (event.target === event.currentTarget) closeMetricGuide();
}});
document.addEventListener('keydown', event => {{
  if (event.key === 'Escape') closeMetricGuide();
}});

async function runAnalysis() {{
  const button = document.getElementById('run-analysis');
  const original = button.innerHTML;
  button.disabled = true;
  button.textContent = 'Running...';
  try {{
    let baseline = null;
    if (typeof window.lldpqCaptureAnalysisState === 'function') {{
      baseline = await window.lldpqCaptureAnalysisState('pfc-ecn');
    }}
    const response = await fetch('/trigger-monitor?scope=pfc-ecn', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}}
    }});
    const data = await response.json();
    if (!response.ok || data.status !== 'success' || !data.trigger_id || data.scope !== 'pfc-ecn') {{
      throw new Error(data.message || 'Failed to trigger monitor analysis');
    }}
    if (typeof window.waitForLldpqAnalysisCompletion === 'function') {{
      await window.waitForLldpqAnalysisCompletion(
        baseline, {{scope: 'pfc-ecn', pipelineId: data.trigger_id}});
    }} else {{
      await new Promise(resolve => setTimeout(resolve, 35000));
    }}
    window.location.reload();
  }} catch (error) {{
    alert('Analysis did not complete: ' + (error.message || error));
    button.disabled = false;
    button.innerHTML = original;
  }}
}}
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/analysis-guard.js?v=20260707-scoped-runner-2"></script>
</body></html>'''


def process_pfc_ecn_data_files(data_dir: str = "monitor-results/pfc-ecn-data") -> bool:
    data_path = Path(data_dir).resolve()
    result_dir = data_path.parent
    if not data_path.is_dir():
        print(f"PFC/ECN data directory not found: {data_path}", file=sys.stderr)
        return False

    timing_enabled = os.environ.get("LLDPQ_ANALYZER_TIMING", "").lower() in {
        "1", "true", "yes", "on",
    }
    phase_started = time.monotonic()

    def finish_phase(name: str) -> None:
        nonlocal phase_started
        now = time.monotonic()
        if timing_enabled:
            elapsed_ms = max(0, int((now - phase_started) * 1000))
            print(
                f"__LLDPQ_ANALYZER_TIMING__:pfc-ecn:{name}:{elapsed_ms}",
                flush=True,
            )
        phase_started = now

    asset_snapshot = read_asset_snapshot(str(result_dir.parent / "assets.ini"))
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    authoritative = asset_snapshot_is_authoritative(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("Asset snapshot is invalid or incomplete", file=sys.stderr)
        return False

    if authoritative:
        active_hosts = set(statuses)
        for raw_file in data_path.glob("*_pfc_ecn.txt"):
            if raw_file.name.removesuffix("_pfc_ecn.txt") not in active_hosts:
                try:
                    raw_file.unlink()
                except OSError as exc:
                    print(f"Could not prune retired PFC/ECN data: {exc}", file=sys.stderr)
                    return False

    current_files = [
        path for path in data_path.glob("*_pfc_ecn.txt")
        if is_current_collection(
            str(path), path.name.removesuffix("_pfc_ecn.txt"), asset_snapshot
        )
    ]
    inventory_hosts = set(statuses) if snapshot_valid else set()
    expected_hosts = (
        {host for host, status in statuses.items() if status == "OK"}
        if snapshot_valid else set()
    )
    collected_hosts = {path.name.removesuffix("_pfc_ecn.txt") for path in current_files}
    coverage_failures: Dict[str, str] = {}
    if snapshot_valid:
        coverage_failures.update({
            host: f"asset status {status}"
            for host, status in statuses.items()
            if status != "OK"
        })
    missing_collections = expected_hosts - collected_hosts
    if snapshot_valid and missing_collections:
        for host in missing_collections:
            coverage_failures[host] = "current collection missing"
        print(
            "Missing current PFC/ECN collections for: "
            + ", ".join(sorted(missing_collections)),
            file=sys.stderr,
        )
    all_devices_unavailable = snapshot_valid and not expected_hosts

    baseline_path = result_dir / "pfc_ecn_baseline.json"
    history_path = result_dir / "pfc_ecn_history.json"
    report_path = result_dir / "pfc-ecn-analysis.html"
    baseline_state = _read_state(baseline_path, {"version": 1, "ports": {}})
    history_state = _read_state(history_path, {"version": 1, "history": {}})
    baselines = baseline_state.get("ports", {})
    histories = history_state.get("history", {})
    if not isinstance(baselines, dict):
        baselines = {}
    if not isinstance(histories, dict):
        histories = {}
    if authoritative:
        baselines = {
            key: value for key, value in baselines.items()
            if key.split(":", 1)[0] in statuses
        }
        histories = {
            key: value for key, value in histories.items()
            if key.split(":", 1)[0] in statuses
        }
    finish_phase("load")

    records: List[Dict[str, Any]] = []
    hosts_with_ports = set()
    for raw_file in sorted(current_files):
        hostname = raw_file.name.removesuffix("_pfc_ecn.txt")
        try:
            raw_content = raw_file.read_text(encoding="utf-8", errors="replace")
            parsed_ports = parse_pfc_ecn_snapshot(raw_content)
            timestamp = raw_file.stat().st_mtime
        except OSError as exc:
            coverage_failures[hostname] = f"snapshot read failed: {exc}"
            print(f"Could not read {raw_file}: {exc}", file=sys.stderr)
            continue
        inventory_valid, inventory_error = validate_inventory_contract(
            raw_content, parsed_ports
        )
        if not inventory_valid:
            # An explicit collector-side inventory failure is a category-local
            # coverage gap.  Contract contradictions (duplicates, count
            # mismatches, or truncation) remain fatal because accepting them
            # would publish a structurally ambiguous snapshot.
            if inventory_error == "collector reported an inventory error":
                coverage_failures[hostname] = inventory_error
                print(
                    f"PFC/ECN inventory unavailable for {hostname}: "
                    f"{inventory_error}",
                    file=sys.stderr,
                )
                continue
            print(
                f"Invalid PFC/ECN inventory for {hostname}: {inventory_error}",
                file=sys.stderr,
            )
            return False
        physical_ports = {
            name: entry for name, entry in parsed_ports.items() if PORT_RE.fullmatch(name)
        }
        if not physical_ports:
            coverage_failures[hostname] = "no physical port records"
            print(f"No physical PFC/ECN port records for {hostname}", file=sys.stderr)
            continue
        hosts_with_ports.add(hostname)
        for interface, entry in sorted(physical_ports.items()):
            key = f"{hostname}:{interface}"
            counters = (
                extract_counters(entry.get("payload", {}))
                if entry.get("status") == "ok" else
                {name: None for name in COUNTER_PATHS}
            )
            record = build_port_record(
                hostname, interface, counters, baselines.get(key), timestamp,
                str(entry.get("status", "error")),
            )
            records.append(record)
            if entry.get("status") == "ok" and any(value is not None for value in counters.values()):
                baselines[key] = {
                    "hostname": hostname,
                    "interface": interface,
                    "timestamp": timestamp,
                    "counters": {
                        name: value for name, value in counters.items() if value is not None
                    },
                }
            port_history = histories.setdefault(key, [])
            if not isinstance(port_history, list):
                port_history = histories[key] = []
            port_history.append(record)

    hosts_without_ports = expected_hosts - hosts_with_ports
    if hosts_without_ports:
        for host in hosts_without_ports:
            coverage_failures.setdefault(host, "no physical counter records")
        print(
            "No physical PFC/ECN counters for: "
            + ", ".join(sorted(hosts_without_ports)),
            file=sys.stderr,
        )
    if not records and not all_devices_unavailable and not snapshot_valid:
        print("No current PFC/ECN records", file=sys.stderr)
        return False
    finish_phase("parse_records")

    cutoff = time.time() - HISTORY_SECONDS
    for key in list(histories):
        values = histories[key]
        if not isinstance(values, list):
            histories[key] = []
            continue
        histories[key] = [
            value for value in values
            if isinstance(value, Mapping)
            and isinstance(value.get("timestamp"), (int, float))
            and value["timestamp"] >= cutoff
        ][-HISTORY_MAX_RECORDS_PER_PORT:]

    now = time.time()
    baseline_output = {"version": 1, "updated_at": _iso(now), "ports": baselines}
    history_output = {"version": 1, "updated_at": _iso(now), "history": histories}
    finish_phase("history_prune")
    report = render_report(
        records,
        histories,
        len(inventory_hosts) if snapshot_valid else None,
        len(hosts_with_ports) if snapshot_valid else None,
        collection_unavailable=all_devices_unavailable,
        coverage_failures=coverage_failures,
    )
    finish_phase("render")
    _atomic_json(baseline_path, baseline_output)
    _atomic_json(history_path, history_output)
    _atomic_write(report_path, report)
    finish_phase("write_state")
    print(f"PFC/ECN analysis report generated: {report_path}")
    return True


def main() -> int:
    try:
        return 0 if process_pfc_ecn_data_files() else 1
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"PFC/ECN analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
