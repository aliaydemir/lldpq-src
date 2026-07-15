#!/usr/bin/env python3
"""Deterministic cross-domain correlation for LLDPq Analysis v2.

This module joins per-domain anomalies persisted under ``monitor-results``
into evidence-bundled incident candidates, so the hourly LLM analysis can
reason over pre-correlated cases instead of parallel domain dumps.

Only the analyzers' own persisted statuses/grades are read (the same files
and vocabularies used by ai-api.sh, ai_insights.py and check_alerts.py); raw
data is never re-graded here.  Every source is optional: missing or partial
files contribute nothing instead of failing.

Standard library only; importable standalone.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys


SEVERITY_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

# Grade words the producers persist, normalized by the same rules the
# timeline extractor (ai_insights) applies to historical vocabularies.
_CRITICAL_WORDS = {"critical", "down", "failed", "failure", "bad", "poor"}
_WARNING_WORDS = {"warning", "warn", "degraded", "marginal", "fair"}

# The flap producer grades per-hour, and check_alerts reads the same window.
FLAP_WINDOW_SECONDS = 3600

# Fabric-wide grouping: an anomaly type shared by at least this share of the
# device universe collapses into one incident.  A minimum of three distinct
# devices keeps a two-node link problem from masquerading as fabric-wide.
FABRIC_SHARE_THRESHOLD = 0.6
FABRIC_MIN_DEVICES = 3


# ======================== small shared helpers ========================

def _load_json(path):
    """Return parsed JSON dict or None; never raise for a bad source."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parsed = json.load(handle)
        return parsed if isinstance(parsed, dict) else None
    except (OSError, UnicodeError, ValueError):
        return None


def _split_port_key(key):
    """Split the producers' 'host:port' series key."""
    text = str(key or "")
    if ":" in text:
        device, port = text.split(":", 1)
        return device.strip(), port.strip()
    return text.strip(), ""


def _number(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result == result else None  # reject NaN


def _integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _norm_status(value):
    """Normalize a persisted grade word, including enum-repr legacy forms."""
    text = str(value or "").strip().lower()
    if "." in text and text.split(".", 1)[0] in (
        "opticalhealth", "bergrade", "bgpstate", "flapstatus"
    ):
        text = text.split(".", 1)[1]
    return text


def _bgp_state_established(value):
    state = _norm_status(value).replace("_", "")
    return state == "established"


def severity_for(anomaly):
    """Map one anomaly's producer status word to CRITICAL/WARNING/INFO."""
    domain = str(anomaly.get("domain") or "")
    status = _norm_status(anomaly.get("status"))
    if domain == "bgp":
        # Any persisted non-established session state is a hard failure.
        return "INFO" if _bgp_state_established(status) else "CRITICAL"
    if domain == "log":
        if status == "critical":
            return "CRITICAL"
        return "WARNING" if status == "error" else "INFO"
    if domain == "flap":
        # Grading thresholds are configurable and not persisted in
        # flap_history.json; like the timeline, never invent a critical grade.
        return "WARNING"
    if domain == "pfc_ecn":
        return "WARNING" if status == "loss" else "INFO"
    if status in _CRITICAL_WORDS:
        return "CRITICAL"
    if status in _WARNING_WORDS:
        return "WARNING"
    return "INFO"


def _anomaly(domain, device, port, metric, value, status, detail, source):
    return {
        "domain": domain,
        "device": str(device),
        "port": str(port) if port else None,
        "metric": metric,
        "value": value,
        "status": status,
        "detail": detail,
        "source": source,
    }


# ======================== per-domain collectors ========================

def _current_bgp_stats(document):
    """Normalize current and legacy BGP history schemas to device stats."""
    if not isinstance(document, dict):
        return {}
    current = document.get("current_bgp_stats")
    if isinstance(current, dict):
        return current
    normalized = {}
    metadata_keys = {"bgp_history", "collection_coverage", "last_update"}
    for device, value in document.items():
        if device in metadata_keys or not isinstance(value, dict):
            continue
        if isinstance(value.get("neighbors"), list):
            normalized[device] = value
            continue
        neighbors = []
        for neighbor_name, neighbor in value.items():
            if isinstance(neighbor, dict) and "state" in neighbor:
                item = dict(neighbor)
                item.setdefault("neighbor_name", neighbor_name)
                neighbors.append(item)
        if neighbors:
            normalized[device] = {"neighbors": neighbors}
    return normalized


def _collect_bgp(mr_dir):
    document = _load_json(os.path.join(mr_dir, "bgp_history.json"))
    current_stats = _current_bgp_stats(document)
    anomalies = []
    for device in sorted(current_stats):
        stats = current_stats.get(device)
        neighbors = stats.get("neighbors") if isinstance(stats, dict) else None
        for info in neighbors if isinstance(neighbors, list) else []:
            if not isinstance(info, dict):
                continue
            state = _norm_status(info.get("state", "unknown"))
            if _bgp_state_established(state):
                continue
            neighbor = info.get("neighbor_name") or info.get("neighbor_ip") or "?"
            interface = info.get("interface")
            anomalies.append(_anomaly(
                "bgp", device, interface, "session_state", state, state,
                "BGP neighbor %s not established (state %s)" % (neighbor, state),
                "bgp_history.json",
            ))
    return anomalies


def _collect_optical(mr_dir):
    document = _load_json(os.path.join(mr_dir, "optical_history.json"))
    stats = (document or {}).get("current_optical_stats")
    anomalies = []
    for key in sorted(stats if isinstance(stats, dict) else {}):
        record = stats[key]
        if not isinstance(record, dict):
            continue
        health = _norm_status(record.get("health_status"))
        if health not in {"warning", "critical", "down"}:
            continue
        device, port = _split_port_key(key)
        parts = []
        for label, field in (("rx", "rx_power_dbm"), ("tx", "tx_power_dbm"),
                             ("margin", "link_margin_db")):
            reading = _number(record.get(field))
            if reading is not None:
                parts.append("%s=%.1fdB%s" % (label, reading,
                                              "" if label == "margin" else "m"))
        anomalies.append(_anomaly(
            "optical", device, port, "health_status", health, health,
            "Optical health %s%s" % (health, " (" + " ".join(parts) + ")" if parts else ""),
            "optical_history.json",
        ))
    return anomalies


def _normalized_ber_grade(record):
    # status is the explicit combined producer grade; older histories persist
    # only per-component grades, in which case use the worst component.
    if record.get("status"):
        return _norm_status(record.get("status"))
    priority = {"unknown": 0, "excellent": 1, "good": 2, "warning": 3, "critical": 4}
    candidates = [
        _norm_status(record.get(key))
        for key in ("grade", "frame_grade", "raw_grade", "effective_grade", "symbol_grade")
        if record.get(key)
    ]
    return max(candidates, key=lambda value: priority.get(value, 0)) if candidates else ""


def _collect_ber(mr_dir):
    document = _load_json(os.path.join(mr_dir, "ber_history.json"))
    stats = (document or {}).get("current_ber_stats")
    anomalies = []
    for key in sorted(stats if isinstance(stats, dict) else {}):
        record = stats[key]
        if not isinstance(record, dict):
            continue
        grade = _normalized_ber_grade(record)
        if grade not in {"warning", "critical"}:
            continue
        device, port = _split_port_key(key)
        detail = "BER grade %s" % grade
        effective = _number(record.get("effective_ber"))
        raw = _number(record.get("raw_ber"))
        density = _number(record.get("frame_error_density", record.get("ber_value")))
        if effective is not None:
            detail += "; effective PHY BER %.3g" % effective
        elif raw is not None:
            detail += "; raw PHY BER %.3g" % raw
        elif density is not None:
            detail += "; frame error-event density %.3g" % density
        anomalies.append(_anomaly(
            "ber", device, port, "grade", grade, grade, detail, "ber_history.json",
        ))
    return anomalies


def _collect_flaps(mr_dir):
    document = _load_json(os.path.join(mr_dir, "flap_history.json"))
    history = (document or {}).get("flapping_hist")
    if not isinstance(history, dict):
        return []
    # Anchor the window to producer time, not wall clock, so a stale file is
    # judged by its own collection horizon and results stay reproducible.
    reference = _number((document or {}).get("last_update"))
    if reference is None:
        stamps = [
            _number(item[0])
            for series in history.values() if isinstance(series, list)
            for item in series if isinstance(item, (list, tuple)) and item
        ]
        stamps = [stamp for stamp in stamps if stamp is not None]
        reference = max(stamps) if stamps else None
    if reference is None:
        return []
    anomalies = []
    for key in sorted(history):
        series = history[key]
        if not isinstance(series, list):
            continue
        flaps = 0
        for item in series:
            stamp = flap_count = None
            if isinstance(item, (list, tuple)) and len(item) >= 3:
                stamp = _number(item[0])
                flap_count = _integer(item[2])
            elif isinstance(item, dict):
                stamp = _number(item.get("timestamp"))
                flap_count = _integer(item.get("flaps") or item.get("count"))
            if stamp is None or flap_count is None or flap_count <= 0:
                continue
            if reference - stamp <= FLAP_WINDOW_SECONDS:
                flaps += flap_count
        if flaps <= 0:
            continue
        device, port = _split_port_key(key)
        anomalies.append(_anomaly(
            "flap", device, port, "flaps_1h", flaps, "warning",
            "%d link flap%s detected in the last hour" % (
                flaps, "" if flaps == 1 else "s"),
            "flap_history.json",
        ))
    return anomalies


def _load_pfc_history(mr_dir):
    """Merge the per-device shard directory; fall back to the monolith.

    The fallback keeps correlation working across the one-run migration
    window and on installations whose analyzer has not produced shards yet.
    """
    shard_dir = os.path.join(mr_dir, "pfc-ecn-history")
    if os.path.isdir(shard_dir):
        merged = {}
        for name in sorted(os.listdir(shard_dir)):
            if not name.endswith(".json"):
                continue
            document = _load_json(os.path.join(shard_dir, name))
            history = (document or {}).get("history")
            if isinstance(history, dict):
                merged.update(history)
        return merged
    document = _load_json(os.path.join(mr_dir, "pfc_ecn_history.json"))
    history = (document or {}).get("history")
    return history if isinstance(history, dict) else {}


def _collect_pfc_ecn(mr_dir):
    history = _load_pfc_history(mr_dir)
    anomalies = []
    for key in sorted(history if isinstance(history, dict) else {}):
        series = history[key]
        if not isinstance(series, list) or not series:
            continue
        record = series[-1]
        if not isinstance(record, dict):
            continue
        if record.get("sample_status") != "analyzed":
            continue
        signal = _norm_status(record.get("signal"))
        if signal not in {"loss", "combined", "pfc", "ecn"}:
            continue
        device, port = _split_port_key(key)
        detail = "PFC/ECN signal %s" % signal
        loss = _integer(record.get("loss_delta"))
        if loss:
            detail += "; discard counter delta %d" % loss
        share = _number(record.get("ecn_share_percent"))
        if share is not None:
            detail += "; ECN marking share %.2f%%" % share
        anomalies.append(_anomaly(
            "pfc_ecn", device, port, "signal", signal, signal, detail,
            "pfc_ecn_history.json",
        ))
    return anomalies


def _collect_hardware(mr_dir):
    document = _load_json(os.path.join(mr_dir, "hardware_history.json"))
    history = (document or {}).get("hardware_history")
    anomalies = []
    for device in sorted(history if isinstance(history, dict) else {}):
        entries = history[device]
        if not isinstance(entries, list) or not entries:
            continue
        latest = entries[-1]
        if not isinstance(latest, dict):
            continue
        grade = _norm_status(latest.get("overall_grade"))
        if grade not in {"warning", "critical"}:
            continue
        anomalies.append(_anomaly(
            "hardware", device, None, "overall_grade", grade, grade,
            "Hardware health grade %s" % grade, "hardware_history.json",
        ))
    return anomalies


def _collect_logs(mr_dir):
    document = _load_json(os.path.join(mr_dir, "log_summary.json"))
    if not isinstance(document, dict):
        return []
    # Only the explicit per-device map is trusted; falling back to the whole
    # document would turn metadata keys like "totals" into phantom devices.
    device_counts = document.get("device_counts")
    anomalies = []
    for device in sorted(device_counts if isinstance(device_counts, dict) else {}):
        counts = device_counts[device]
        if not isinstance(counts, dict):
            continue
        critical = _integer(counts.get("critical")) or 0
        errors = _integer(counts.get("error")) or 0
        if critical > 0:
            anomalies.append(_anomaly(
                "log", device, None, "log_critical", critical, "critical",
                "%d critical log message%s" % (critical, "" if critical == 1 else "s"),
                "log_summary.json",
            ))
        elif errors > 0:
            anomalies.append(_anomaly(
                "log", device, None, "log_errors", errors, "error",
                "%d error log message%s" % (errors, "" if errors == 1 else "s"),
                "log_summary.json",
            ))
    return anomalies


_COLLECTORS = (
    _collect_bgp,
    _collect_optical,
    _collect_ber,
    _collect_flaps,
    _collect_pfc_ecn,
    _collect_hardware,
    _collect_logs,
)


def collect_anomalies(mr_dir):
    """Extract per-domain anomalies from the analyzers' persisted grades."""
    anomalies = []
    for collector in _COLLECTORS:
        try:
            anomalies.extend(collector(str(mr_dir)))
        except Exception:
            # One malformed domain file must never hide the other domains.
            continue
    return anomalies


# ======================== expected topology ========================

_DOT_ENDPOINT = r'(?:"([^"]+)"|([A-Za-z0-9_.\-]+))\s*:\s*(?:"([^"]+)"|([A-Za-z0-9_./\-]+))'
_DOT_EDGE_RE = re.compile(_DOT_ENDPOINT + r"\s*--\s*" + _DOT_ENDPOINT)


def _parse_dot_links(text):
    # topology.dot is point-to-point "A":"p1" -- "B":"p2" statements; strip
    # comment forms first so documented examples never become edges.
    stripped = re.sub(r"/\*.*?\*/", " ", str(text or ""), flags=re.DOTALL)
    stripped = re.sub(r"(?m)(?://|#).*$", " ", stripped)
    links = []
    for match in _DOT_EDGE_RE.finditer(stripped):
        groups = match.groups()
        a_dev, a_port = groups[0] or groups[1], groups[2] or groups[3]
        b_dev, b_port = groups[4] or groups[5], groups[6] or groups[7]
        if a_dev and a_port and b_dev and b_port:
            links.append({
                "a_dev": a_dev, "a_port": a_port,
                "b_dev": b_dev, "b_port": b_port,
            })
    return links


def load_expected_links(topology_path=None, mr_dir=None):
    """Load expected point-to-point links from topology.dot; [] when absent."""
    candidates = []
    if topology_path:
        candidates.append(str(topology_path))
    if mr_dir:
        # topology.dot lives next to monitor-results in the LLDPq tree, and
        # some deployments sync a copy into the results directory itself.
        candidates.append(os.path.join(str(mr_dir), os.pardir, "topology.dot"))
        candidates.append(os.path.join(str(mr_dir), "topology.dot"))
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                text = handle.read()
        except (OSError, UnicodeError):
            continue
        links = _parse_dot_links(text)
        if links:
            return links
    return []


# ======================== correlation ========================

def _endpoint_key(device, port):
    return (str(device or "").casefold(), str(port or "").casefold())


def _device_universe(devices, anomalies):
    if devices:
        names = set()
        values = devices.values() if isinstance(devices, dict) else devices
        for value in values:
            if isinstance(value, dict):
                name = value.get("hostname")
            else:
                # devices.yaml style "Hostname @role" values are accepted.
                name = re.sub(r"\s+@\S+$", "", str(value or "")).strip()
            if name:
                names.add(str(name).casefold())
        if names:
            return names
    return {str(item.get("device") or "").casefold() for item in anomalies}


def _sorted_evidence(members):
    return sorted(members, key=lambda item: (
        str(item.get("domain") or ""),
        str(item.get("device") or ""),
        str(item.get("port") or ""),
        str(item.get("metric") or ""),
    ))


def _incident_severity(members):
    ranks = [SEVERITY_ORDER[severity_for(item)] for item in members]
    return [name for name, rank in SEVERITY_ORDER.items() if rank == min(ranks)][0]


def _subject(anomaly):
    device = str(anomaly.get("device") or "")
    port = anomaly.get("port")
    return "%s:%s" % (device, port) if port else device


def _build_incident(kind, members, link=None, summary=None):
    evidence = _sorted_evidence(members)
    endpoints = sorted({_subject(item) for item in evidence})
    devices = sorted({str(item.get("device") or "") for item in evidence})
    ports = sorted({_subject(item) for item in evidence if item.get("port")})
    severity = _incident_severity(evidence)
    summary_key = kind + "|" + ",".join(endpoints)
    # The id must stay unique when distinct domain leftovers share one
    # endpoint fingerprint, so it also covers the evidence identity.
    identity = summary_key + "|" + ",".join(sorted(
        "%s:%s" % (item.get("domain"), item.get("metric")) for item in evidence
    ))
    incident_id = "inc-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    if summary is None:
        findings = ", ".join(sorted({
            "%s %s" % (item.get("domain"), _norm_status(item.get("status")))
            for item in evidence
        }))
        summary = "%s: %s" % (" + ".join(endpoints), findings)
    return {
        "id": incident_id,
        "kind": kind,
        "severity": severity,
        "devices": devices,
        "ports": ports,
        "link": link,
        "evidence": evidence,
        "summary": summary,
        "summary_key": summary_key,
    }


def _single_kind(members):
    domains = {str(item.get("domain") or "") for item in members}
    if domains == {"bgp"}:
        return "protocol"
    if domains <= {"bgp", "optical", "ber", "flap", "pfc_ecn", "hardware", "log"}:
        return "device-local"
    return "other"


def correlate(anomalies, links, devices=None):
    """Join anomalies into deterministic, evidence-bundled incidents."""
    valid = [
        item for item in (anomalies or [])
        if isinstance(item, dict) and item.get("device")
    ]
    universe = _device_universe(devices, valid)
    incidents = []
    consumed = set()

    # 1) Fabric-wide: one incident per widely shared anomaly type.
    by_type = {}
    for index, item in enumerate(valid):
        type_key = (str(item.get("domain") or ""), str(item.get("metric") or ""))
        by_type.setdefault(type_key, []).append(index)
    for type_key in sorted(by_type):
        indexes = by_type[type_key]
        type_devices = {str(valid[i].get("device") or "").casefold() for i in indexes}
        if (
            len(universe) >= FABRIC_MIN_DEVICES
            and len(type_devices) >= FABRIC_MIN_DEVICES
            and len(type_devices) / len(universe) >= FABRIC_SHARE_THRESHOLD
        ):
            members = [valid[i] for i in indexes]
            consumed.update(indexes)
            domain, metric = type_key
            incidents.append(_build_incident(
                "fabric-wide", members,
                summary="Fabric-wide %s %s anomaly on %d of %d devices" % (
                    domain, metric, len(type_devices), len(universe)),
            ))

    # 2) Same device+port across domains joins into one endpoint group.
    endpoint_groups = {}
    endpoint_labels = {}
    singles = []
    for index, item in enumerate(valid):
        if index in consumed:
            continue
        if item.get("port"):
            key = _endpoint_key(item.get("device"), item.get("port"))
            endpoint_groups.setdefault(key, []).append(item)
            endpoint_labels.setdefault(key, _subject(item))
        else:
            singles.append(item)

    # 3) Both ends of an expected link anomalous -> one link incident.
    linked = set()
    for link in sorted(
        (item for item in (links or []) if isinstance(item, dict)),
        key=lambda item: (str(item.get("a_dev")), str(item.get("a_port")),
                          str(item.get("b_dev")), str(item.get("b_port"))),
    ):
        key_a = _endpoint_key(link.get("a_dev"), link.get("a_port"))
        key_b = _endpoint_key(link.get("b_dev"), link.get("b_port"))
        if key_a in linked or key_b in linked or key_a == key_b:
            continue
        if key_a in endpoint_groups and key_b in endpoint_groups:
            label_a, label_b = sorted(
                (endpoint_labels[key_a], endpoint_labels[key_b])
            )
            members = endpoint_groups[key_a] + endpoint_groups[key_b]
            incidents.append(_build_incident(
                "link-degradation", members,
                link={"a": label_a, "b": label_b},
                summary="Expected link %s <-> %s degraded on both ends" % (
                    label_a, label_b),
            ))
            linked.update((key_a, key_b))

    # 4) Remaining endpoint groups and device-scoped leftovers.
    for key in sorted(endpoint_groups):
        if key in linked:
            continue
        incidents.append(_build_incident(
            _single_kind(endpoint_groups[key]), endpoint_groups[key]
        ))
    for item in singles:
        incidents.append(_build_incident(_single_kind([item]), [item]))

    incidents.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]], item["summary_key"], item["id"]
    ))
    return incidents


# ======================== prompt rendering ========================

def _render_incident(incident):
    lines = ["[%s] %s %s" % (
        incident.get("severity"), incident.get("kind"), incident.get("summary")
    )]
    for item in incident.get("evidence") or []:
        lines.append("  %s %s %s=%s (%s)" % (
            item.get("domain"), _subject(item), item.get("metric"),
            item.get("value"), item.get("status"),
        ))
    return "\n".join(lines)


def render_candidates(incidents, max_chars=8000):
    """Render a compact severity-first prompt block within max_chars."""
    ordered = sorted(incidents or [], key=lambda item: (
        SEVERITY_ORDER.get(item.get("severity"), len(SEVERITY_ORDER)),
        str(item.get("summary_key") or ""),
        str(item.get("id") or ""),
    ))
    if not ordered:
        return ""
    header = "INCIDENT CANDIDATES (%d, deterministic pre-correlation):" % len(ordered)
    blocks = [header]
    used = len(header)
    rendered = 0
    for incident in ordered:
        block = _render_incident(incident)
        remaining = len(ordered) - rendered - 1
        marker_room = len("\n(+%d more incidents omitted)" % remaining) if remaining else 0
        # Truncate whole incidents only: the block either fits together with
        # the room a truncation marker would need, or it is omitted entirely.
        if used + 1 + len(block) + marker_room > max_chars:
            break
        blocks.append(block)
        used += 1 + len(block)
        rendered += 1
    omitted = len(ordered) - rendered
    if omitted:
        blocks.append("(+%d more incidents omitted)" % omitted)
    return "\n".join(blocks)


# ======================== CLI ========================

def main(argv):
    if len(argv) != 2:
        print("Usage: ai_correlate.py <monitor-results-dir>", file=sys.stderr)
        return 2
    mr_dir = argv[1]
    anomalies = collect_anomalies(mr_dir)
    links = load_expected_links(mr_dir=mr_dir)
    incidents = correlate(anomalies, links)
    print(json.dumps(incidents, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
