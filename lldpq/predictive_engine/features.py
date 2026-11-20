"""LLDPq ``monitor-results/`` loader and temporal/cross-entity feature extractor.

Parses real LLDPq persisted JSON artifacts across all 12 monitoring domains +
BMC + Prometheus/OTEL telemetry (gracefully tolerating missing or partial files
just like ``html/ai_correlate.py``) and computes fixed-order feature vectors
per ``(entity_key, family)``:
  - Rolling OLS slopes & acceleration across short/medium/long windows
  - Log-BER velocity (``d(log10(BER))/dt``)
  - Peer-group anomaly Z-score & robust MAD-score (operational on Day 1 with
    ZERO labeled historical failures)
  - Cross-domain interaction features (``rx_drop * ber_climb``,
    ``fan_rpm_ratio * temp_delta``, ``pfc_pause_accel * hoq_discards``)

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import math
import os
from pathlib import Path
import re
import statistics
import time
from typing import Any, Mapping, Sequence

from .schemas import (
    CongestionPortSample,
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
    FAMILY_PHYSICAL,
    HardwareControlSample,
    HardwareSensorReading,
    LLDPqSnapshot,
    PhysicalPortSample,
)

# ---------------------------------------------------------------------------
# Fixed-Order Feature Schemas per Domain Family
# ---------------------------------------------------------------------------

PHYSICAL_FEATURE_NAMES: tuple[str, ...] = (
    "rx_power_dbm",
    "tx_power_dbm",
    "link_margin_db",
    "bias_current_ma",
    "module_temp_c",
    "voltage_dev_v",
    "rx_power_slope_24h",
    "rx_power_accel",
    "bias_current_slope_24h",
    "temp_slope_24h",
    "log10_raw_ber",
    "log10_eff_ber",
    "log10_ber_slope_24h",
    "symbol_error_rate_log1p",
    "crc_fcs_error_rate_log1p",
    "flaps_1h",
    "flaps_24h",
    "fabric_mismatch_flags",
    "peer_rx_mad_zscore",
    "cross_rx_drop_x_ber_climb",
)

CONGESTION_FEATURE_NAMES: tuple[str, ...] = (
    "rx_pause_rate_log1p",
    "tx_pause_rate_log1p",
    "rx_pause_slope_1h",
    "tx_pause_slope_1h",
    "pfc_pause_accel",
    "ecn_marked_rate_log1p",
    "ecn_share_percent",
    "ecn_slope_1h",
    "loss_delta_log1p",
    "rx_buffer_full_rate_log1p",
    "rx_buffer_almost_full_rate_log1p",
    "egress_hoq_rate_log1p",
    "egress_hoq_stall_rate_log1p",
    "if_discards_rate_log1p",
    "tx_wait_rate_log1p",
    "culprit_asymmetry",
    "peer_congestion_mad_zscore",
    "cross_pfc_accel_x_hoq",
)

HARDWARE_CONTROL_FEATURE_NAMES: tuple[str, ...] = (
    "max_temp_c",
    "tlimit_margin_c",
    "temp_delta_above_ambient",
    "temp_slope_24h",
    "thermal_resistance_c_per_w",
    "peer_temp_mad_zscore",
    "peer_rth_mad_zscore",
    "fan_rpm_ratio",
    "fan_min_cohort_ratio",
    "fan_failed_count",
    "cross_fan_rpm_x_temp_delta",
    "psu_efficiency_deficit",
    "psu_fault_flag",
    "load_per_core",
    "memory_pct",
    "bmc_anomaly_count",
    "bgp_down_ratio",
    "bgp_flap_velocity",
    "evpn_mh_desync_count",
    "route_churn_score",
    "dup_mac_ip_rate",
    "syslog_error_velocity",
)

FEATURE_NAMES_BY_FAMILY: dict[str, tuple[str, ...]] = {
    FAMILY_PHYSICAL: PHYSICAL_FEATURE_NAMES,
    FAMILY_CONGESTION: CONGESTION_FEATURE_NAMES,
    FAMILY_HARDWARE_CONTROL: HARDWARE_CONTROL_FEATURE_NAMES,
}

# Regex matching topology.dot edges identically to html/ai_correlate.py
_DOT_ENDPOINT = r'(?:"([^"]+)"|([A-Za-z0-9_.\-]+))\s*:\s*(?:"([^"]+)"|([A-Za-z0-9_./\-]+))'
_DOT_EDGE_RE = re.compile(_DOT_ENDPOINT + r"\s*--\s*" + _DOT_ENDPOINT)


# ---------------------------------------------------------------------------
# Small safe parsers (aligned with ai_correlate.py)
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, ValueError):
        return None


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        res = float(value)
    except (TypeError, ValueError):
        return None
    return res if math.isfinite(res) else None


def _int(value: Any) -> int | None:
    n = _num(value)
    if n is None:
        return None
    return int(round(n))


def _epoch(value: Any, fallback: float | None = None) -> float | None:
    n = _num(value)
    if n is not None:
        if n > 10_000_000_000:
            n /= 1000.0
        return n if n > 0 else fallback
    text = str(value or "").strip()
    if not text:
        return fallback
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except (ValueError, OverflowError, OSError):
        return fallback


def _split_port_key(key: str) -> tuple[str, str]:
    text = str(key or "")
    if ":" in text:
        dev, port = text.split(":", 1)
        return dev.strip(), port.strip()
    return text.strip(), ""


def _norm_grade(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "." in text:
        prefix, rest = text.split(".", 1)
        if prefix in ("opticalhealth", "bergrade", "bgpstate", "flapstatus"):
            return rest
    return text


def _infer_role(device: str) -> str:
    low = device.lower()
    if "spine" in low or "core" in low:
        return "spine"
    if "leaf" in low or "tor" in low:
        return "leaf"
    if "dgx" in low or "hgx" in low or "gpu" in low or "compute" in low:
        return "gpu_host"
    if "oob" in low or "mgmt" in low:
        return "oob"
    if "bmc" in low:
        return "bmc"
    return "switch"


def _parse_float_list(value: Any) -> list[float]:
    if isinstance(value, list):
        out = []
        for item in value:
            v = _num(item)
            if v is not None:
                out.append(v)
        return out
    if isinstance(value, str):
        out = []
        for tok in value.replace(",", " ").split():
            v = _num(tok)
            if v is not None:
                out.append(v)
        return out
    return []


# ---------------------------------------------------------------------------
# Statistical / Temporal Math Primitives (Pure Python)
# ---------------------------------------------------------------------------


def safe_log10_ber(ber: float | None, floor: float = 1e-15) -> float:
    """Convert raw/effective BER into log10 space (``1e-12 -> -12.0``)."""
    if ber is None or not math.isfinite(ber) or ber <= 0.0:
        return math.log10(floor)
    return math.log10(max(ber, floor))


def linear_slope(timestamps: Sequence[float], values: Sequence[float], *, unit_seconds: float = 86400.0) -> float:
    """Ordinary least-squares slope expressed in value-change per ``unit_seconds``."""
    pairs = [
        (float(t), float(v))
        for t, v in zip(timestamps, values)
        if t is not None and v is not None and math.isfinite(t) and math.isfinite(v)
    ]
    if len(pairs) < 2:
        return 0.0
    pairs.sort(key=lambda p: p[0])
    t0 = pairs[0][0]
    xs = [(t - t0) / unit_seconds for t, _ in pairs]
    ys = [v for _, v in pairs]
    span = xs[-1] - xs[0]
    if span <= 1e-6:
        return 0.0
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den <= 1e-12:
        return 0.0
    return num / den


def windowed_slopes(
    timestamps: Sequence[float],
    values: Sequence[float],
    *,
    unit_seconds: float = 86400.0,
) -> tuple[float, float, float, float]:
    """Return ``(short_slope, medium_slope, long_slope, acceleration)``.

    - ``short``: last 6 hours (or newest 3 samples if sparse)
    - ``medium``: last 24 hours (or full series)
    - ``long``: last 72 hours (or full series)
    - ``acceleration``: ``recent_half_slope - earlier_half_slope``
    """
    pairs = [
        (float(t), float(v))
        for t, v in zip(timestamps, values)
        if t is not None and v is not None and math.isfinite(t) and math.isfinite(v)
    ]
    if len(pairs) < 2:
        return 0.0, 0.0, 0.0, 0.0
    pairs.sort(key=lambda p: p[0])
    t_end = pairs[-1][0]

    def _slice_slope(window_sec: float, min_pts: int = 2, min_span_sec: float = 0.0) -> float:
        sub = [p for p in pairs if t_end - p[0] <= window_sec]
        if len(sub) < min_pts or (min_span_sec > 0.0 and sub and (sub[-1][0] - sub[0][0]) < min_span_sec):
            sub = [p for p in pairs if t_end - p[0] <= max(window_sec, 24 * 3600.0)]
            if len(sub) < min_pts:
                sub = pairs[-min(len(pairs), max(min_pts, 3)) :]
        return linear_slope([p[0] for p in sub], [p[1] for p in sub], unit_seconds=unit_seconds)

    # Require >=2h span when extrapolating daily (86400s) short slopes so post-gap 0.02 dB ADC ticks
    # over a 45-minute window aren't amplified 30x into phantom daily decay slopes.
    short_min_span = 2 * 3600.0 if unit_seconds >= 86400.0 else 0.0
    short_s = _slice_slope(6 * 3600.0, min_pts=2, min_span_sec=short_min_span)
    med_s = _slice_slope(24 * 3600.0, min_pts=2)
    long_s = _slice_slope(72 * 3600.0, min_pts=2)

    accel = 0.0
    if len(pairs) >= 4:
        mid = len(pairs) // 2
        early = pairs[: mid + 1]
        late = pairs[mid:]
        s_early = linear_slope([p[0] for p in early], [p[1] for p in early], unit_seconds=unit_seconds)
        s_late = linear_slope([p[0] for p in late], [p[1] for p in late], unit_seconds=unit_seconds)
        accel = s_late - s_early
    return short_s, med_s, long_s, accel


def peer_group_z_and_mad(
    values_by_entity: Mapping[str, float],
    *,
    mad_floor: float = 1.0,
) -> dict[str, tuple[float, float, float]]:
    """Compute ``(classical_z, robust_mad_z, delta_from_median)`` per entity.

    Robust MAD-score uses ``1.4826 * MAD`` floored by ``mad_floor`` so even
    identical healthy peers (MAD=0) yield stable, non-singular outlier scores
    when 1–2 peers deviate sharply (e.g., 6 GPUs at 32 °C + 2 GPUs at 55 °C).
    """
    valid = {
        k: float(v)
        for k, v in values_by_entity.items()
        if v is not None and math.isfinite(float(v))
    }
    if len(valid) < 2:
        return {k: (0.0, 0.0, 0.0) for k in valid}
    vals = list(valid.values())
    med = statistics.median(vals)
    abs_devs = [abs(v - med) for v in vals]
    mad = statistics.median(abs_devs)
    robust_sigma = max(1.4826 * mad, mad_floor)

    mean = sum(vals) / len(vals)
    var = sum((v - mean) ** 2 for v in vals) / max(len(vals) - 1, 1)
    std = max(math.sqrt(var), mad_floor)

    out: dict[str, tuple[float, float, float]] = {}
    for k, v in valid.items():
        delta = v - med
        z = (v - mean) / std
        mad_z = delta / robust_sigma
        out[k] = (z, mad_z, delta)
    return out


# ---------------------------------------------------------------------------
# LLDPqSnapshotLoader (real monitor-results/ reader)
# ---------------------------------------------------------------------------


class LLDPqSnapshotLoader:
    """Read-only parser for LLDPq ``monitor-results/`` directories.

    Supports both current sharded layouts (``optical-history/``,
    ``ber-history/``, ``pfc-ecn-history/``, ``routes-history/``) and legacy
    monoliths plus ``export/*.json``, ``summary/*.json``, BMC, and Prometheus
    telemetry exports. Missing or corrupt files are skipped cleanly.
    """

    def _infer_snapshot_now(self, root: Path) -> float | None:
        """Infer producer reference epoch from lightweight summary/event/export timestamps."""
        stamps: list[float] = []
        for sub in ("summary", "events"):
            sdir = root / sub
            if sdir.is_dir():
                for p in sorted(sdir.glob("*.json")):
                    doc = _load_json(p)
                    if isinstance(doc, dict):
                        ts = _epoch(doc.get("generated_at") or doc.get("updated_at"))
                        if ts is not None:
                            stamps.append(ts)
        if not stamps:
            for fname in ("system-watchdog-state.json", "hardware_history.json", "flap_history.json", "log_summary.json"):
                doc = _load_json(root / fname)
                if isinstance(doc, dict):
                    ts = _epoch(doc.get("last_update") or doc.get("generated_at") or doc.get("updated_at"))
                    if ts is not None:
                        stamps.append(ts)
        if not stamps:
            exp_dir = root / "export"
            if exp_dir.is_dir():
                for p in sorted(exp_dir.glob("*.json"))[:3]:
                    doc = _load_json(p)
                    if isinstance(doc, dict):
                        ts = _epoch(doc.get("generated_at"))
                        if ts is not None:
                            stamps.append(ts)
        return max(stamps) if stamps else None

    def load(
        self,
        mr_dir: str | Path,
        *,
        now: float | None = None,
        topology_path: str | Path | None = None,
    ) -> LLDPqSnapshot:
        root = Path(mr_dir)
        inferred_now = self._infer_snapshot_now(root) if now is None else None
        ref_now = float(now if now is not None else (inferred_now if inferred_now is not None else time.time()))
        snapshot = LLDPqSnapshot(timestamp=ref_now)
        devices_seen: set[str] = set()
        ber_neighbor_edges: list[tuple[str, str, str, str]] = []

        snapshot.links = self._load_topology(root, topology_path)
        for edge in snapshot.links:
            devices_seen.add(edge["a_dev"])
            devices_seen.add(edge["b_dev"])

        # Family A: optical, ber, flap, fabric-check
        self._load_optical(root, snapshot, devices_seen, ref_now)
        self._load_ber(root, snapshot, devices_seen, ref_now, ber_neighbor_edges)
        self._load_flaps(root, snapshot, devices_seen, ref_now)
        self._load_fabric_check(root, snapshot, devices_seen, ref_now)

        # Family B: pfc-ecn + prometheus/otel
        self._load_pfc_ecn(root, snapshot, devices_seen, ref_now)
        self._load_prometheus_otel(root, snapshot, devices_seen, ref_now)

        # Family C: hardware, sensors, watchdog, bmc, bgp, evpn-mh, routes, duplicate, logs, config-drift
        self._load_hardware(root, snapshot, devices_seen, ref_now)
        self._load_sensors(root, snapshot, devices_seen, ref_now)
        self._load_system_watchdog(root, snapshot, devices_seen, ref_now)
        self._load_bmc(root, snapshot, devices_seen, ref_now)
        self._load_bgp(root, snapshot, devices_seen, ref_now)
        self._load_evpn_mh(root, snapshot, devices_seen, ref_now)
        self._load_routes(root, snapshot, devices_seen, ref_now)
        self._load_duplicate(root, snapshot, devices_seen, ref_now)
        self._load_logs(root, snapshot, devices_seen, ref_now)
        self._load_config_drift(root, snapshot, devices_seen, ref_now)

        # Fallback: when topology.dot is absent, recover switch-to-switch links from export/ber.json LLDP neighbors
        if not snapshot.links and ber_neighbor_edges:
            seen_edges: set[tuple[tuple[str, str], tuple[str, str]]] = set()
            for d1, p1, d2, p2 in ber_neighbor_edges:
                if d2 not in devices_seen or d1 == d2:
                    continue
                ep_a, ep_b = (d1, p1), (d2, p2)
                canon = (ep_a, ep_b) if ep_a <= ep_b else (ep_b, ep_a)
                if canon in seen_edges:
                    continue
                seen_edges.add(canon)
                snapshot.links.append(
                    {
                        "a_dev": canon[0][0],
                        "a_port": canon[0][1],
                        "b_dev": canon[1][0],
                        "b_port": canon[1][1],
                    }
                )

        # Sort every time series chronologically
        for series in snapshot.physical.values():
            series.sort(key=lambda s: s.timestamp)
        for series in snapshot.congestion.values():
            series.sort(key=lambda s: s.timestamp)
        for series in snapshot.hardware_control.values():
            series.sort(key=lambda s: s.timestamp)
        for series in snapshot.sensors.values():
            series.sort(key=lambda s: s.timestamp)

        # Attach neighbor hints from topology.dot / BER LLDP neighbors onto congestion samples
        neighbor_map: dict[tuple[str, str], tuple[str, str]] = {}
        for link in snapshot.links:
            neighbor_map[(link["a_dev"], link["a_port"])] = (link["b_dev"], link["b_port"])
            neighbor_map[(link["b_dev"], link["b_port"])] = (link["a_dev"], link["a_port"])
        for series in snapshot.congestion.values():
            for sample in series:
                peer = neighbor_map.get((sample.device, sample.port))
                if peer and not sample.neighbor_device:
                    sample.neighbor_device, sample.neighbor_port = peer

        snapshot.devices = sorted(d for d in devices_seen if d)
        return snapshot

    # ---- Topology ----

    def _load_topology(self, root: Path, topology_path: str | Path | None) -> list[dict[str, str]]:
        candidates: list[Path] = []
        if topology_path:
            candidates.append(Path(topology_path))
        candidates.append(root / "topology.dot")
        candidates.append(root.parent / "topology.dot")
        for cand in candidates:
            if not cand.is_file():
                continue
            try:
                text = cand.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            stripped = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
            stripped = re.sub(r"(?m)(?://|#).*$", " ", stripped)
            links: list[dict[str, str]] = []
            for m in _DOT_EDGE_RE.finditer(stripped):
                g = m.groups()
                a_dev, a_port = g[0] or g[1], g[2] or g[3]
                b_dev, b_port = g[4] or g[5], g[6] or g[7]
                if a_dev and a_port and b_dev and b_port:
                    links.append(
                        {"a_dev": a_dev, "a_port": a_port, "b_dev": b_dev, "b_port": b_port}
                    )
            if links:
                return links
        return []

    # ---- Helper to merge/upsert samples at close timestamps ----

    @staticmethod
    def _upsert_physical(
        snapshot: LLDPqSnapshot, device: str, port: str, ts: float
    ) -> PhysicalPortSample:
        key = f"{device}:{port}"
        series = snapshot.physical.setdefault(key, [])
        for existing in reversed(series):
            if abs(existing.timestamp - ts) <= 120.0:
                return existing
        sample = PhysicalPortSample(
            device=device, port=port, timestamp=ts, device_role=_infer_role(device)
        )
        series.append(sample)
        return sample

    @staticmethod
    def _upsert_congestion(
        snapshot: LLDPqSnapshot, device: str, port: str, ts: float
    ) -> CongestionPortSample:
        key = f"{device}:{port}"
        series = snapshot.congestion.setdefault(key, [])
        for existing in reversed(series):
            if abs(existing.timestamp - ts) <= 120.0:
                return existing
        sample = CongestionPortSample(
            device=device, port=port, timestamp=ts, device_role=_infer_role(device)
        )
        series.append(sample)
        return sample

    @staticmethod
    def _upsert_hw(snapshot: LLDPqSnapshot, device: str, ts: float) -> HardwareControlSample:
        series = snapshot.hardware_control.setdefault(device, [])
        for existing in reversed(series):
            if abs(existing.timestamp - ts) <= 120.0:
                return existing
        sample = HardwareControlSample(
            device=device, timestamp=ts, device_role=_infer_role(device)
        )
        series.append(sample)
        return sample

    # ---- Family A Loaders ----

    def _load_optical(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        shard_dir = root / "optical-history"
        histories: dict[str, list[dict[str, Any]]] = {}
        currents: dict[str, dict[str, Any]] = {}

        if shard_dir.is_dir():
            for path in sorted(shard_dir.glob("*.json")):
                payload = _load_json(path)
                if not isinstance(payload, dict):
                    continue
                if isinstance(payload.get("history"), dict):
                    for k, entries in payload["history"].items():
                        if isinstance(entries, list):
                            histories[str(k)] = [e for e in entries if isinstance(e, dict)]
                if isinstance(payload.get("current"), dict):
                    for k, rec in payload["current"].items():
                        if isinstance(rec, dict):
                            currents[str(k)] = rec
        else:
            monolith = _load_json(root / "optical_history.json")
            if isinstance(monolith, dict):
                if isinstance(monolith.get("optical_history"), dict):
                    for k, entries in monolith["optical_history"].items():
                        if isinstance(entries, list):
                            histories[str(k)] = [e for e in entries if isinstance(e, dict)]
                if isinstance(monolith.get("current_optical_stats"), dict):
                    for k, rec in monolith["current_optical_stats"].items():
                        if isinstance(rec, dict):
                            currents[str(k)] = rec

        for key, entries in histories.items():
            dev, port = _split_port_key(key)
            if not dev or not port:
                continue
            devices.add(dev)
            for entry in entries:
                ts = _epoch(entry.get("timestamp"), ref_now)
                if ts is None:
                    continue
                s = self._upsert_physical(snapshot, dev, port, ts)
                s.rx_power_dbm = _num(entry.get("rx_power_dbm")) if entry.get("rx_power_dbm") is not None else s.rx_power_dbm
                s.tx_power_dbm = _num(entry.get("tx_power_dbm")) if entry.get("tx_power_dbm") is not None else s.tx_power_dbm
                s.bias_current_ma = _num(entry.get("bias_current_ma")) if entry.get("bias_current_ma") is not None else s.bias_current_ma
                s.temperature_c = _num(entry.get("temperature_c")) if entry.get("temperature_c") is not None else s.temperature_c
                s.voltage_v = _num(entry.get("voltage_v")) if entry.get("voltage_v") is not None else s.voltage_v
                s.link_margin_db = _num(entry.get("link_margin_db")) if entry.get("link_margin_db") is not None else s.link_margin_db
                s.link_margin_ref_dbm = _num(entry.get("link_margin_ref_dbm")) if entry.get("link_margin_ref_dbm") is not None else s.link_margin_ref_dbm
                if entry.get("health") or entry.get("health_status"):
                    s.health_status = _norm_grade(entry.get("health_status") or entry.get("health"))

        for key, rec in currents.items():
            dev, port = _split_port_key(key)
            if not dev or not port:
                continue
            devices.add(dev)
            ts = _epoch(rec.get("last_updated") or rec.get("timestamp"), ref_now) or ref_now
            s = self._upsert_physical(snapshot, dev, port, ts)
            if rec.get("rx_power_dbm") is not None:
                s.rx_power_dbm = _num(rec.get("rx_power_dbm"))
            if rec.get("tx_power_dbm") is not None:
                s.tx_power_dbm = _num(rec.get("tx_power_dbm"))
            if rec.get("bias_current_ma") is not None:
                s.bias_current_ma = _num(rec.get("bias_current_ma"))
            if rec.get("temperature_c") is not None:
                s.temperature_c = _num(rec.get("temperature_c"))
            if rec.get("voltage_v") is not None:
                s.voltage_v = _num(rec.get("voltage_v"))
            if rec.get("link_margin_db") is not None:
                s.link_margin_db = _num(rec.get("link_margin_db"))
            if rec.get("health_status"):
                s.health_status = _norm_grade(rec.get("health_status"))
            if isinstance(rec.get("health_causes"), list):
                s.health_causes = [str(c) for c in rec["health_causes"]]
            if rec.get("link_state"):
                s.link_state = str(rec["link_state"])
            s.rx_power_lanes_dbm = _parse_float_list(rec.get("rx_power_lanes_dbm")) or s.rx_power_lanes_dbm
            s.tx_power_lanes_dbm = _parse_float_list(rec.get("tx_power_lanes_dbm")) or s.tx_power_lanes_dbm
            s.bias_current_lanes_ma = _parse_float_list(rec.get("bias_current_lanes_ma")) or s.bias_current_lanes_ma
            bias_thr = rec.get("bias_thresholds_ma")
            if isinstance(bias_thr, dict):
                s.bias_high_warning_ma = _num(bias_thr.get("high_warning"))
                s.bias_high_alarm_ma = _num(bias_thr.get("high_alarm"))

        # Enrich from export/optical.json if present
        exp = _load_json(root / "export" / "optical.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                port = str(row.get("interface") or "").strip()
                if not dev or not port:
                    continue
                devices.add(dev)
                s = self._upsert_physical(snapshot, dev, port, ts)
                if s.rx_power_dbm is None:
                    s.rx_power_dbm = _num(row.get("rx_power_dbm"))
                if s.tx_power_dbm is None:
                    s.tx_power_dbm = _num(row.get("tx_power_dbm"))
                if s.bias_current_ma is None:
                    s.bias_current_ma = _num(row.get("bias_current_ma"))
                if s.temperature_c is None:
                    s.temperature_c = _num(row.get("temperature_c"))
                if s.voltage_v is None:
                    s.voltage_v = _num(row.get("voltage_v"))
                if s.link_margin_db is None:
                    s.link_margin_db = _num(row.get("link_margin_db"))
                if s.health_status == "unknown" and row.get("health"):
                    s.health_status = _norm_grade(row.get("health"))

        if histories or currents or exp:
            snapshot.domain_coverage["optical"] = "loaded"

    def _load_ber(
        self,
        root: Path,
        snapshot: LLDPqSnapshot,
        devices: set[str],
        ref_now: float,
        neighbor_edges: list[tuple[str, str, str, str]] | None = None,
    ) -> None:
        shard_dir = root / "ber-history"
        histories: dict[str, list[dict[str, Any]]] = {}
        currents: dict[str, dict[str, Any]] = {}

        if shard_dir.is_dir():
            for path in sorted(shard_dir.glob("*.json")):
                payload = _load_json(path)
                if not isinstance(payload, dict):
                    continue
                if isinstance(payload.get("history"), dict):
                    for k, entries in payload["history"].items():
                        if isinstance(entries, list):
                            histories[str(k)] = [e for e in entries if isinstance(e, dict)]
                if isinstance(payload.get("current"), dict):
                    for k, rec in payload["current"].items():
                        if isinstance(rec, dict):
                            currents[str(k)] = rec
        else:
            monolith = _load_json(root / "ber_history.json")
            if isinstance(monolith, dict):
                if isinstance(monolith.get("ber_history"), dict):
                    for k, entries in monolith["ber_history"].items():
                        if isinstance(entries, list):
                            histories[str(k)] = [e for e in entries if isinstance(e, dict)]
                if isinstance(monolith.get("current_ber_stats"), dict):
                    for k, rec in monolith["current_ber_stats"].items():
                        if isinstance(rec, dict):
                            currents[str(k)] = rec

        for key, entries in histories.items():
            dev, port = _split_port_key(key)
            if not dev or not port:
                continue
            devices.add(dev)
            prev_sym: int | None = None
            for entry in entries:
                ts = _epoch(entry.get("timestamp"), ref_now)
                if ts is None:
                    continue
                s = self._upsert_physical(snapshot, dev, port, ts)
                if entry.get("raw_ber") is not None:
                    s.raw_ber = _num(entry.get("raw_ber"))
                if entry.get("effective_ber") is not None:
                    s.effective_ber = _num(entry.get("effective_ber"))
                if entry.get("ber_value") is not None or entry.get("frame_error_density") is not None:
                    s.frame_error_density = _num(
                        entry.get("frame_error_density", entry.get("ber_value"))
                    )
                sym = _int(entry.get("symbol_errors"))
                if sym is not None:
                    s.symbol_errors = sym
                    if prev_sym is not None and sym >= prev_sym:
                        s.symbol_error_delta = max(s.symbol_error_delta, sym - prev_sym)
                    prev_sym = sym
                if entry.get("symbol_error_delta") is not None:
                    s.symbol_error_delta = max(s.symbol_error_delta, _int(entry.get("symbol_error_delta")) or 0)
                if entry.get("delta_errors") is not None:
                    s.delta_rx_errors = max(s.delta_rx_errors, _int(entry.get("delta_errors")) or 0)
                if entry.get("fec_uncorrectable_delta") is not None:
                    s.fec_uncorrectable_delta = max(
                        s.fec_uncorrectable_delta, _int(entry.get("fec_uncorrectable_delta")) or 0
                    )
                grade = entry.get("status") or entry.get("grade")
                if grade:
                    s.ber_grade = _norm_grade(grade)

        for key, rec in currents.items():
            dev, port = _split_port_key(key)
            if not dev or not port:
                continue
            devices.add(dev)
            ts = _epoch(rec.get("timestamp"), ref_now) or ref_now
            s = self._upsert_physical(snapshot, dev, port, ts)
            if rec.get("raw_ber") is not None:
                s.raw_ber = _num(rec.get("raw_ber"))
            if rec.get("effective_ber") is not None:
                s.effective_ber = _num(rec.get("effective_ber"))
            if rec.get("frame_error_density") is not None or rec.get("ber_value") is not None:
                s.frame_error_density = _num(
                    rec.get("frame_error_density", rec.get("ber_value"))
                )
            if rec.get("symbol_errors") is not None:
                s.symbol_errors = _int(rec.get("symbol_errors"))
            if rec.get("symbol_error_delta") is not None:
                s.symbol_error_delta = _int(rec.get("symbol_error_delta")) or 0
            s.delta_rx_errors = _int(rec.get("delta_rx_errors")) or s.delta_rx_errors
            s.delta_tx_errors = _int(rec.get("delta_tx_errors")) or s.delta_tx_errors
            s.delta_rx_dropped = _int(rec.get("delta_rx_dropped")) or s.delta_rx_dropped
            s.delta_tx_dropped = _int(rec.get("delta_tx_dropped")) or s.delta_tx_dropped
            s.delta_packets = _int(rec.get("delta_packets")) or s.delta_packets
            grade = rec.get("status") or rec.get("effective_grade") or rec.get("grade")
            if grade:
                s.ber_grade = _norm_grade(grade)

        exp = _load_json(root / "export" / "ber.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                port = str(row.get("interface") or "").strip()
                if not dev or not port:
                    continue
                devices.add(dev)
                s = self._upsert_physical(snapshot, dev, port, ts)
                if s.raw_ber is None:
                    s.raw_ber = _num(row.get("raw_ber"))
                if s.effective_ber is None:
                    s.effective_ber = _num(row.get("effective_ber"))
                if s.frame_error_density is None:
                    s.frame_error_density = _num(row.get("frame_error_density"))
                if s.symbol_error_delta == 0 and row.get("symbol_error_delta") is not None:
                    s.symbol_error_delta = _int(row.get("symbol_error_delta")) or 0
                if s.symbol_errors is None and row.get("symbol_errors") is not None:
                    s.symbol_errors = _int(row.get("symbol_errors"))
                if s.ber_grade == "unknown" and row.get("status"):
                    s.ber_grade = _norm_grade(row.get("status"))
                if neighbor_edges is not None:
                    ndev = str(row.get("neighbor_device") or "").strip()
                    nport = str(row.get("neighbor_port") or "").strip()
                    if ndev and nport:
                        neighbor_edges.append((dev, port, ndev, nport))

        if histories or currents or exp:
            snapshot.domain_coverage["ber"] = "loaded"

    def _load_flaps(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        doc = _load_json(root / "flap_history.json")
        if isinstance(doc, dict):
            ref = _epoch(doc.get("last_update"), ref_now) or ref_now
            hist = doc.get("flapping_hist")
            stats = doc.get("carrier_transitions_stats") or {}
            if isinstance(hist, dict):
                for key, series in hist.items():
                    if not isinstance(series, list):
                        continue
                    dev, port = _split_port_key(str(key))
                    if not dev or not port:
                        continue
                    devices.add(dev)
                    f5m = f1h = f24h = 0
                    for item in series:
                        stamp = count = interval_s = None
                        if isinstance(item, (list, tuple)) and len(item) >= 3:
                            stamp = _num(item[0])
                            count = _int(item[2])
                            if len(item) >= 5:
                                interval_s = _num(item[4])
                        elif isinstance(item, dict):
                            stamp = _num(item.get("timestamp"))
                            count = _int(item.get("flaps") or item.get("count"))
                            interval_s = _num(item.get("interval_seconds"))
                        if stamp is None or count is None or count <= 0:
                            continue
                        age = ref - stamp
                        if age < -300:
                            continue
                        if age <= 300 and (interval_s is None or interval_s <= 600.0):
                            f5m += count
                        if age <= 3600 and (interval_s is None or interval_s <= 4200.0):
                            f1h += count
                        if age <= 86400:
                            f24h += count
                    s = self._upsert_physical(snapshot, dev, port, ref)
                    s.flaps_5m = max(s.flaps_5m, f5m)
                    s.flaps_1h = max(s.flaps_1h, f1h)
                    s.flaps_24h = max(s.flaps_24h, f24h)
                    if isinstance(stats, dict) and key in stats:
                        s.carrier_transitions = _int(stats[key]) or s.carrier_transitions
            snapshot.domain_coverage["flap"] = "loaded"

        exp = _load_json(root / "export" / "flap.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                port = str(row.get("interface") or "").strip()
                if not dev or not port:
                    continue
                devices.add(dev)
                s = self._upsert_physical(snapshot, dev, port, ts)
                s.flaps_5m = max(s.flaps_5m, _int(row.get("flaps_5m")) or 0)
                s.flaps_1h = max(s.flaps_1h, _int(row.get("flaps_1h")) or 0)
                s.flaps_24h = max(s.flaps_24h, _int(row.get("flaps_24h")) or 0)
                s.carrier_transitions = max(
                    s.carrier_transitions, _int(row.get("total_transitions")) or 0
                )
            snapshot.domain_coverage["flap"] = "loaded"

        ev_doc = _load_json(root / "events" / "flap.json")
        if isinstance(ev_doc, dict) and isinstance(ev_doc.get("events"), list):
            ev_ref = _epoch(ev_doc.get("updated_at"), ref_now) or ref_now
            per_port: dict[tuple[str, str], list[int]] = {}
            for ev in ev_doc["events"]:
                if not isinstance(ev, dict):
                    continue
                dev = str(ev.get("device") or "").strip()
                port = str(ev.get("object") or ev.get("interface") or "").strip()
                ts = _epoch(ev.get("ts") or ev.get("timestamp"), ev_ref)
                if not dev or not port or ts is None:
                    continue
                age = ev_ref - ts
                if age < -300 or age > 86400:
                    continue
                devices.add(dev)
                counts = per_port.setdefault((dev, port), [0, 0, 0])
                if age <= 300:
                    counts[0] += 1
                if age <= 3600:
                    counts[1] += 1
                counts[2] += 1
            for (dev, port), (c5m, c1h, c24h) in per_port.items():
                s = self._upsert_physical(snapshot, dev, port, ev_ref)
                s.flaps_5m = max(s.flaps_5m, c5m)
                s.flaps_1h = max(s.flaps_1h, c1h)
                s.flaps_24h = max(s.flaps_24h, c24h)
            if per_port or ev_doc.get("events") is not None:
                snapshot.domain_coverage["flap"] = "loaded"

    def _load_fabric_check(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        exp = _load_json(root / "export" / "fabric-check.json")
        if not isinstance(exp, dict) or not isinstance(exp.get("rows"), list):
            return
        ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
        for row in exp["rows"]:
            if not isinstance(row, dict):
                continue
            check = str(row.get("check") or "").strip().lower()
            endpoints = [
                (str(row.get("device_a") or "").strip(), str(row.get("port_a") or "").strip()),
                (str(row.get("device_b") or "").strip(), str(row.get("port_b") or "").strip()),
            ]
            for dev, port in endpoints:
                if not dev or not port:
                    continue
                devices.add(dev)
                s = self._upsert_physical(snapshot, dev, port, ts)
                if check == "mtu-mismatch":
                    s.mtu_mismatch = True
                elif check == "speed-mismatch":
                    s.speed_mismatch = True
                elif check == "fec-mismatch":
                    s.fec_mismatch = True
                elif check == "autoneg-mismatch":
                    s.autoneg_mismatch = True
                elif check == "config-mtu-mismatch":
                    s.config_mtu_mismatch = True
        snapshot.domain_coverage["fabric-check"] = "loaded"

    # ---- Family B Loaders ----

    def _load_pfc_ecn(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        shard_dir = root / "pfc-ecn-history"
        histories: dict[str, list[dict[str, Any]]] = {}

        if shard_dir.is_dir():
            for path in sorted(shard_dir.glob("*.json")):
                payload = _load_json(path)
                if not isinstance(payload, dict) or not isinstance(payload.get("history"), dict):
                    continue
                for k, entries in payload["history"].items():
                    if isinstance(entries, list):
                        histories[str(k)] = [e for e in entries if isinstance(e, dict)]
        else:
            monolith = _load_json(root / "pfc_ecn_history.json")
            if isinstance(monolith, dict) and isinstance(monolith.get("history"), dict):
                for k, entries in monolith["history"].items():
                    if isinstance(entries, list):
                        histories[str(k)] = [e for e in entries if isinstance(e, dict)]

        for key, entries in histories.items():
            dev, port = _split_port_key(key)
            if not dev or not port:
                continue
            devices.add(dev)
            for rec in entries:
                ts = _epoch(rec.get("timestamp"), ref_now)
                if ts is None:
                    continue
                dur = max(_num(rec.get("sample_duration_seconds")) or 600.0, 1.0)
                deltas = rec.get("deltas") if isinstance(rec.get("deltas"), dict) else {}
                rates = rec.get("rates") if isinstance(rec.get("rates"), dict) else {}
                s = self._upsert_congestion(snapshot, dev, port, ts)
                s.sample_duration_seconds = dur
                s.sample_status = str(rec.get("sample_status") or "analyzed")
                s.signal = _norm_grade(rec.get("signal") or "quiet")
                s.rx_pause_delta = _int(deltas.get("rx_pause_frames")) or 0
                s.tx_pause_delta = _int(deltas.get("tx_pause_frames")) or 0
                s.ecn_marked_delta = _int(deltas.get("ecn_marked_frames")) or 0
                s.rx_pause_rate = _num(rates.get("rx_pause_frames")) if rates.get("rx_pause_frames") is not None else (s.rx_pause_delta / dur)
                s.tx_pause_rate = _num(rates.get("tx_pause_frames")) if rates.get("tx_pause_frames") is not None else (s.tx_pause_delta / dur)
                s.ecn_marked_rate = _num(rates.get("ecn_marked_frames")) if rates.get("ecn_marked_frames") is not None else (s.ecn_marked_delta / dur)
                s.ecn_share_percent = _num(rec.get("ecn_share_percent")) or 0.0
                s.loss_delta = _int(rec.get("loss_delta")) or 0
                s.tx_uc_buffer_discards = _int(deltas.get("tx_uc_buffer_discards")) or 0
                s.wred_discards = _int(deltas.get("wred_discards")) or 0

        exp = _load_json(root / "export" / "pfc-ecn.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                port = str(row.get("interface") or "").strip()
                if not dev or not port:
                    continue
                devices.add(dev)
                s = self._upsert_congestion(snapshot, dev, port, ts)
                if s.rx_pause_delta == 0 and row.get("rx_pause_delta") is not None:
                    s.rx_pause_delta = _int(row.get("rx_pause_delta")) or 0
                if s.rx_pause_rate == 0.0 and row.get("rx_pause_rate") is not None:
                    s.rx_pause_rate = _num(row.get("rx_pause_rate")) or 0.0
                if s.tx_pause_delta == 0 and row.get("tx_pause_delta") is not None:
                    s.tx_pause_delta = _int(row.get("tx_pause_delta")) or 0
                if s.tx_pause_rate == 0.0 and row.get("tx_pause_rate") is not None:
                    s.tx_pause_rate = _num(row.get("tx_pause_rate")) or 0.0
                if s.ecn_marked_delta == 0 and row.get("ecn_marked_delta") is not None:
                    s.ecn_marked_delta = _int(row.get("ecn_marked_delta")) or 0
                if s.ecn_marked_rate == 0.0 and row.get("ecn_marked_rate") is not None:
                    s.ecn_marked_rate = _num(row.get("ecn_marked_rate")) or 0.0
                if s.loss_delta == 0 and row.get("loss_delta") is not None:
                    s.loss_delta = _int(row.get("loss_delta")) or 0
                if s.ecn_share_percent == 0.0 and row.get("ecn_share_percent") is not None:
                    s.ecn_share_percent = _num(row.get("ecn_share_percent")) or 0.0
                if row.get("sample_status"):
                    s.sample_status = _norm_grade(row.get("sample_status"))
                if row.get("signal"):
                    s.signal = _norm_grade(row.get("signal"))

        if histories or exp:
            snapshot.domain_coverage["pfc-ecn"] = "loaded"

    def _load_prometheus_otel(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        """Load optional Prometheus / Cumulus OTEL telemetry matching alert_rules.yaml."""
        for fname in ("prometheus_telemetry.json", "otel_telemetry.json", "telemetry-series.json"):
            payload = _load_json(root / fname)
            if not isinstance(payload, dict):
                continue

            # Format 1: structured {"ports": {"dev:port": [sample_dicts...]}}
            if isinstance(payload.get("ports"), dict):
                for key, records in payload["ports"].items():
                    dev, port = _split_port_key(str(key))
                    if not dev or not port or not isinstance(records, list):
                        continue
                    devices.add(dev)
                    for rec in records:
                        if not isinstance(rec, dict):
                            continue
                        ts = _epoch(rec.get("timestamp"), ref_now) or ref_now
                        c = self._upsert_congestion(snapshot, dev, port, ts)
                        c.rx_buffer_full_rate = max(c.rx_buffer_full_rate, _num(rec.get("rx_buffer_full_rate") or rec.get("cumulus_nvswitch_interface_rx_buffer_full")) or 0.0)
                        c.rx_buffer_almost_full_rate = max(c.rx_buffer_almost_full_rate, _num(rec.get("rx_buffer_almost_full_rate") or rec.get("cumulus_nvswitch_interface_rx_buffer_almost_full")) or 0.0)
                        c.egress_hoq_rate = max(c.egress_hoq_rate, _num(rec.get("egress_hoq_rate") or rec.get("cumulus_nvswitch_interface_discards_egress_hoq")) or 0.0)
                        c.egress_hoq_stall_rate = max(c.egress_hoq_stall_rate, _num(rec.get("egress_hoq_stall_rate") or rec.get("cumulus_nvswitch_interface_discards_egress_hoq_stall")) or 0.0)
                        c.if_in_discards_rate = max(c.if_in_discards_rate, _num(rec.get("if_in_discards_rate") or rec.get("cumulus_nvswitch_interface_if_in_discards")) or 0.0)
                        c.if_out_discards_rate = max(c.if_out_discards_rate, _num(rec.get("if_out_discards_rate") or rec.get("cumulus_nvswitch_interface_if_out_discards")) or 0.0)
                        c.drop_events_rate = max(c.drop_events_rate, _num(rec.get("drop_events_rate") or rec.get("cumulus_nvswitch_interface_ether_stats_drop_events")) or 0.0)
                        c.tx_wait_rate = max(c.tx_wait_rate, _num(rec.get("tx_wait_rate") or rec.get("cumulus_nvswitch_interface_tx_wait")) or 0.0)
                        c.ar_congestion_changes_rate = max(c.ar_congestion_changes_rate, _num(rec.get("ar_congestion_changes_rate") or rec.get("cumulus_nvswitch_ar_congestion_changes_total")) or 0.0)
                        # Also propagate CRC/FCS rates onto Physical family
                        crc = _num(rec.get("crc_errors_rate") or rec.get("cumulus_nvswitch_interface_ether_stats_crc_align_errors")) or 0.0
                        fcs = _num(rec.get("fcs_errors_rate") or rec.get("cumulus_nvswitch_interface_dot3_stats_fcs_errors")) or 0.0
                        if crc > 0 or fcs > 0:
                            p = self._upsert_physical(snapshot, dev, port, ts)
                            p.crc_errors_rate = max(p.crc_errors_rate, crc)
                            p.fcs_errors_rate = max(p.fcs_errors_rate, fcs)

            # Format 2: native Prometheus query_range {"data": {"result": [...]}}
            data_block = payload.get("data") if isinstance(payload.get("data"), dict) else {}
            results = data_block.get("result") if isinstance(data_block.get("result"), list) else []
            for series in results:
                if not isinstance(series, dict):
                    continue
                metric = series.get("metric") if isinstance(series.get("metric"), dict) else {}
                mname = str(metric.get("__name__") or "")
                dev = str(metric.get("net_host_name") or metric.get("host") or "").strip()
                port = str(metric.get("interface") or "").strip()
                if not dev or not port:
                    continue
                devices.add(dev)
                points = series.get("values") or ([series["value"]] if "value" in series else [])
                for pt in points:
                    if not isinstance(pt, (list, tuple)) or len(pt) < 2:
                        continue
                    ts = _epoch(pt[0], ref_now)
                    val = _num(pt[1])
                    if ts is None or val is None:
                        continue
                    if "crc_align_errors" in mname or "fcs_errors" in mname:
                        p = self._upsert_physical(snapshot, dev, port, ts)
                        if "crc" in mname:
                            p.crc_errors_rate = max(p.crc_errors_rate, val)
                        else:
                            p.fcs_errors_rate = max(p.fcs_errors_rate, val)
                        continue
                    c = self._upsert_congestion(snapshot, dev, port, ts)
                    if mname.endswith("rx_buffer_full"):
                        c.rx_buffer_full_rate = max(c.rx_buffer_full_rate, val)
                    elif mname.endswith("rx_buffer_almost_full"):
                        c.rx_buffer_almost_full_rate = max(c.rx_buffer_almost_full_rate, val)
                    elif mname.endswith("discards_egress_hoq_stall"):
                        c.egress_hoq_stall_rate = max(c.egress_hoq_stall_rate, val)
                    elif mname.endswith("discards_egress_hoq"):
                        c.egress_hoq_rate = max(c.egress_hoq_rate, val)
                    elif mname.endswith("if_in_discards"):
                        c.if_in_discards_rate = max(c.if_in_discards_rate, val)
                    elif mname.endswith("if_out_discards"):
                        c.if_out_discards_rate = max(c.if_out_discards_rate, val)
                    elif mname.endswith("ether_stats_drop_events"):
                        c.drop_events_rate = max(c.drop_events_rate, val)
                    elif mname.endswith("tx_wait"):
                        c.tx_wait_rate = max(c.tx_wait_rate, val)
                    elif mname.endswith("dot3_in_pause_frames"):
                        c.rx_pause_rate = max(c.rx_pause_rate, val)
                    elif mname.endswith("dot3_out_pause_frames"):
                        c.tx_pause_rate = max(c.tx_pause_rate, val)
                    elif mname.endswith("performance_marked_packets"):
                        c.ecn_marked_rate = max(c.ecn_marked_rate, val)

            snapshot.domain_coverage["prometheus_otel"] = "loaded"

    # ---- Family C Loaders ----

    def _load_hardware(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        hist_doc = _load_json(root / "hardware_history.json")
        if isinstance(hist_doc, dict) and isinstance(hist_doc.get("hardware_history"), dict):
            for dev, entries in hist_doc["hardware_history"].items():
                if not isinstance(entries, list):
                    continue
                devices.add(str(dev))
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    ts = _epoch(entry.get("timestamp"), ref_now)
                    if ts is None:
                        continue
                    s = self._upsert_hw(snapshot, str(dev), ts)
                    if entry.get("overall_grade"):
                        s.overall_grade = _norm_grade(entry.get("overall_grade"))
                    if entry.get("cpu_temp_c") is not None:
                        s.cpu_temp_c = _num(entry.get("cpu_temp_c"))
                    if entry.get("asic_temp_c") is not None:
                        s.asic_temp_c = _num(entry.get("asic_temp_c"))
                    if entry.get("ambient_temp_c") is not None:
                        s.ambient_temp_c = _num(entry.get("ambient_temp_c"))
                    if entry.get("memory_pct") is not None:
                        s.memory_pct = _num(entry.get("memory_pct"))
                    if entry.get("load_per_core") is not None:
                        s.load_per_core = _num(entry.get("load_per_core"))
                    if entry.get("psu_efficiency") is not None:
                        s.psu_efficiency = _num(entry.get("psu_efficiency"))
                    if isinstance(entry.get("fan_rpms"), dict):
                        s.fan_rpms = {
                            str(fn): float(fv)
                            for fn, fv in entry["fan_rpms"].items()
                            if _num(fv) is not None
                        }
            snapshot.domain_coverage["hardware"] = "loaded"

        exp = _load_json(root / "export" / "hardware.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                if not dev:
                    continue
                devices.add(dev)
                s = self._upsert_hw(snapshot, dev, ts)
                if row.get("model"):
                    s.device_model = str(row.get("model")).strip()
                if row.get("health"):
                    s.overall_grade = _norm_grade(row.get("health"))
                if row.get("cpu_temp_c") is not None:
                    s.cpu_temp_c = _num(row.get("cpu_temp_c"))
                if row.get("asic_temp_c") is not None:
                    s.asic_temp_c = _num(row.get("asic_temp_c"))
                if row.get("memory_pct") is not None:
                    s.memory_pct = _num(row.get("memory_pct"))
                if row.get("load_raw") is not None:
                    s.load_raw = _num(row.get("load_raw"))
                if row.get("load_per_core") is not None:
                    s.load_per_core = _num(row.get("load_per_core"))
                if row.get("cores") is not None:
                    s.cores = _int(row.get("cores"))
                if row.get("psu_efficiency") is not None:
                    s.psu_efficiency = _num(row.get("psu_efficiency"))
                if row.get("psu_in_w") is not None:
                    s.psu_in_w = _num(row.get("psu_in_w"))
                if row.get("psu_out_w") is not None:
                    s.psu_out_w = _num(row.get("psu_out_w"))
                psu_status = _norm_grade(row.get("psu_status"))
                if psu_status:
                    s.psu_status = psu_status
                    if psu_status == "critical":
                        s.psu_failed_count = max(s.psu_failed_count, 1)
                        s.psu_redundancy_ok = False
                psus_str = str(row.get("psus") or "")
                if psus_str:
                    bad_psus = sum(
                        1
                        for part in psus_str.split(";")
                        if "=" in part
                        and part.split("=", 1)[1].strip().lower() in {"bad", "failed", "fault", "critical"}
                    )
                    if bad_psus > 0:
                        s.psu_failed_count = max(s.psu_failed_count, bad_psus)
                        s.psu_redundancy_ok = False
                psu_detail = str(row.get("psu_status_detail") or "").lower()
                if "ps_r_policy_check: bad" in psu_detail:
                    s.psu_redundancy_ok = False
                fan_status = _norm_grade(row.get("fan_status"))
                if fan_status:
                    s.fan_status = fan_status
                    if fan_status == "critical":
                        s.fan_failed_count = max(s.fan_failed_count, 1)
                # Parse fan_states ("FAN1/1=ok; FAN2/1=bad") or fallback space-separated fans ("FAN1/1=EXCELLENT FAN1/2=CRITICAL")
                fan_states = str(row.get("fan_states") or "")
                if fan_states:
                    bad = sum(
                        1 for part in fan_states.split(";")
                        if "=" in part and part.split("=", 1)[1].strip().lower() in {"bad", "failed", "fault", "absent", "critical"}
                    )
                    s.fan_failed_count = max(s.fan_failed_count, bad)
                else:
                    fans_str = str(row.get("fans") or "")
                    if fans_str:
                        bad = sum(
                            1 for part in fans_str.split()
                            if "=" in part and part.split("=", 1)[1].strip().lower() in {"bad", "failed", "fault", "absent", "critical"}
                        )
                        s.fan_failed_count = max(s.fan_failed_count, bad)
            snapshot.domain_coverage["hardware"] = "loaded"

    def _load_sensors(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        """Load per-sensor thermal/power/fan series (BMC Redfish / DGX SXM / switch sensors)."""
        sensor_files: list[Path] = []
        for name in ("hardware_sensors.json", "bmc_sensors.json"):
            p = root / name
            if p.is_file():
                sensor_files.append(p)
        bmc_dir = root / "bmc-sensors"
        if bmc_dir.is_dir():
            sensor_files.extend(sorted(bmc_dir.glob("*.json")))

        loaded_any = False
        for path in sensor_files:
            payload = _load_json(path)
            if not isinstance(payload, dict):
                continue
            readings = payload.get("sensors") or payload.get("readings") or []
            if isinstance(readings, list):
                for rec in readings:
                    if not isinstance(rec, dict):
                        continue
                    dev = str(rec.get("device") or rec.get("host") or payload.get("host") or "").strip()
                    sid = str(rec.get("sensor_id") or rec.get("sensor") or rec.get("name") or "").strip()
                    if not dev or not sid:
                        continue
                    devices.add(dev)
                    ts = _epoch(rec.get("timestamp"), ref_now) or ref_now
                    reading = HardwareSensorReading(
                        device=dev,
                        sensor_id=sid,
                        timestamp=ts,
                        sensor_type=str(rec.get("sensor_type") or "generic"),
                        peer_group=str(rec.get("peer_group") or ""),
                        temp_c=_num(rec.get("temp_c")),
                        tlimit_c=_num(rec.get("tlimit_c")),
                        thermal_margin_c=_num(rec.get("thermal_margin_c")),
                        ambient_temp_c=_num(rec.get("ambient_temp_c")),
                        power_w=_num(rec.get("power_w")),
                        fan_rpm=_num(rec.get("fan_rpm")),
                        fan_baseline_rpm=_num(rec.get("fan_baseline_rpm")),
                        fan_max_rpm=_num(rec.get("fan_max_rpm")),
                        status=_norm_grade(rec.get("status") or "ok"),
                    )
                    snapshot.sensors.setdefault(reading.entity_key, []).append(reading)
                    loaded_any = True
        if loaded_any:
            snapshot.domain_coverage["bmc_sensors"] = "loaded"

    def _load_system_watchdog(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        loaded = False
        doc = _load_json(root / "system-watchdog-state.json")
        if isinstance(doc, dict) and isinstance(doc.get("hosts"), dict):
            loaded = True
            for dev, host_state in doc["hosts"].items():
                if not isinstance(host_state, dict):
                    continue
                events = host_state.get("events")
                if not isinstance(events, list):
                    continue
                devices.add(str(dev))
                reboots = restarts = crit_restarts = 0
                latest_ts = ref_now
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    ts = _num(ev.get("ts"))
                    if ts is None or ref_now - ts > 86400:
                        continue
                    latest_ts = max(latest_ts, ts)
                    kind = str(ev.get("kind") or "")
                    if kind == "reboot":
                        reboots += 1
                    elif kind == "service-restart":
                        cnt = _int(ev.get("count")) or 1
                        restarts += cnt
                        if str(ev.get("unit") or "") in {"frr.service", "switchd.service"}:
                            crit_restarts += cnt
                if reboots or restarts:
                    s = self._upsert_hw(snapshot, str(dev), latest_ts)
                    s.reboots_24h = max(s.reboots_24h, reboots)
                    s.service_restarts_24h = max(s.service_restarts_24h, restarts)
                    s.critical_service_restarts_24h = max(s.critical_service_restarts_24h, crit_restarts)

        ev_doc = _load_json(root / "events" / "system.json")
        if isinstance(ev_doc, dict) and isinstance(ev_doc.get("events"), list):
            loaded = True
            ev_ref = _epoch(ev_doc.get("updated_at"), ref_now) or ref_now
            per_dev: dict[str, list[int]] = {}
            for ev in ev_doc["events"]:
                if not isinstance(ev, dict):
                    continue
                dev = str(ev.get("device") or ev.get("host") or "").strip()
                ts = _epoch(ev.get("ts") or ev.get("timestamp"), ev_ref)
                if not dev or ts is None or ev_ref - ts > 86400:
                    continue
                devices.add(dev)
                bucket = per_dev.setdefault(dev, [0, 0, 0])
                kind = str(ev.get("kind") or "").lower()
                obj = str(ev.get("object") or ev.get("unit") or "").lower()
                if "reboot" in kind:
                    bucket[0] += 1
                elif "restart" in kind:
                    bucket[1] += 1
                    if obj in {"frr.service", "switchd.service"}:
                        bucket[2] += 1
            for dev, (reb, res, cres) in per_dev.items():
                s = self._upsert_hw(snapshot, dev, ev_ref)
                s.reboots_24h = max(s.reboots_24h, reb)
                s.service_restarts_24h = max(s.service_restarts_24h, res)
                s.critical_service_restarts_24h = max(s.critical_service_restarts_24h, cres)

        if loaded:
            snapshot.domain_coverage["system"] = "loaded"

    def _load_bmc(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        for fname in ("bmc_results.json", "bmc-results.json"):
            doc = _load_json(root / fname)
            if not isinstance(doc, dict) or not isinstance(doc.get("rows"), list):
                continue
            ts = _epoch(doc.get("generated_at"), ref_now) or ref_now
            per_switch: dict[str, dict[str, int]] = {}
            for row in doc["rows"]:
                if not isinstance(row, dict):
                    continue
                sw = str(row.get("switch") or "").strip()
                status = str(row.get("status") or "").upper()
                if not sw:
                    continue
                devices.add(sw)
                bucket = per_switch.setdefault(
                    sw, {"MISMATCH": 0, "WRONG_PORT": 0, "PORT_DOWN": 0, "NOT_SEEN": 0, "STALE": 0}
                )
                if status in bucket:
                    bucket[status] += 1
            for sw, counts in per_switch.items():
                s = self._upsert_hw(snapshot, sw, ts)
                s.bmc_mismatch_count += counts["MISMATCH"]
                s.bmc_wrong_port_count += counts["WRONG_PORT"]
                s.bmc_port_down_count += counts["PORT_DOWN"]
                s.bmc_not_seen_count += counts["NOT_SEEN"]
                s.bmc_stale_count += counts["STALE"]
            snapshot.domain_coverage["bmc"] = "loaded"

    def _load_bgp(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        loaded = False
        populated_from_history: set[str] = set()
        doc = _load_json(root / "bgp_history.json")
        if isinstance(doc, dict):
            loaded = True
            hist = doc.get("bgp_history") if isinstance(doc.get("bgp_history"), dict) else {}
            for dev, entries in hist.items():
                if not isinstance(entries, list):
                    continue
                devices.add(str(dev))
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    ts = _epoch(entry.get("timestamp"), ref_now)
                    if ts is None:
                        continue
                    s = self._upsert_hw(snapshot, str(dev), ts)
                    s.bgp_total_neighbors = _int(entry.get("total_neighbors")) or s.bgp_total_neighbors
                    s.bgp_established_neighbors = _int(entry.get("established_count")) or s.bgp_established_neighbors
                    s.bgp_down_neighbors = _int(entry.get("down_count")) or s.bgp_down_neighbors
                    s.bgp_flaps_1h = max(s.bgp_flaps_1h, _int(entry.get("flap_count")) or 0)

            current = doc.get("current_bgp_stats") if isinstance(doc.get("current_bgp_stats"), dict) else {}
            flap_events = doc.get("flap_events") if isinstance(doc.get("flap_events"), dict) else {}
            storms = doc.get("update_storms") if isinstance(doc.get("update_storms"), dict) else {}

            for dev, stats in current.items():
                if not isinstance(stats, dict):
                    continue
                dev_s = str(dev)
                devices.add(dev_s)
                populated_from_history.add(dev_s)
                ts = _epoch(stats.get("last_update"), ref_now) or ref_now
                s = self._upsert_hw(snapshot, dev_s, ts)
                neighbors = stats.get("neighbors") if isinstance(stats.get("neighbors"), list) else []
                s.bgp_total_neighbors = _int(stats.get("total_neighbors")) or len(neighbors)
                s.bgp_established_neighbors = _int(stats.get("established_neighbors")) or sum(
                    1 for n in neighbors if isinstance(n, dict) and _norm_grade(n.get("state")) == "established"
                )
                s.bgp_down_neighbors = _int(stats.get("down_neighbors")) or max(
                    0, s.bgp_total_neighbors - s.bgp_established_neighbors
                )
                msg_rates = [
                    _num(n.get("msg_rcvd_per_min")) or 0.0
                    for n in neighbors
                    if isinstance(n, dict)
                ]
                if msg_rates:
                    s.bgp_msg_rcvd_per_min = max(s.bgp_msg_rcvd_per_min, max(msg_rates))

                f1h = f24h = 0
                for ev in flap_events.get(dev) or []:
                    if not isinstance(ev, dict):
                        continue
                    ev_ts = _num(ev.get("ts"))
                    cnt = _int(ev.get("count")) or 0
                    if ev_ts is None or cnt <= 0:
                        continue
                    age = ref_now - ev_ts
                    if age <= 3600:
                        f1h += cnt
                    if age <= 86400:
                        f24h += cnt
                s.bgp_flaps_1h = max(s.bgp_flaps_1h, f1h)
                s.bgp_flaps_24h = max(s.bgp_flaps_24h, f24h)
                s.bgp_update_storms = max(
                    s.bgp_update_storms,
                    sum(
                        1
                        for ev in (storms.get(dev) or [])
                        if isinstance(ev, dict) and ref_now - (_num(ev.get("ts")) or 0.0) <= 86400
                    ),
                )

        # Fallback / enrichment from export/bgp.json (essential when bgp_history.json is absent or oversize)
        exp = _load_json(root / "export" / "bgp.json")
        if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
            loaded = True
            ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
            per_dev_counts: dict[str, list[int]] = {}
            for row in exp["rows"]:
                if not isinstance(row, dict):
                    continue
                dev = str(row.get("device") or "").strip()
                if not dev or dev in populated_from_history:
                    continue
                devices.add(dev)
                state = _norm_grade(row.get("state"))
                health = _norm_grade(row.get("health"))
                is_est = state == "established" or (not state and health == "healthy")
                bucket = per_dev_counts.setdefault(dev, [0, 0, 0])
                bucket[0] += 1
                if is_est:
                    bucket[1] += 1
                else:
                    bucket[2] += 1
            for dev, (tot, est, down) in per_dev_counts.items():
                s = self._upsert_hw(snapshot, dev, ts)
                if s.bgp_total_neighbors == 0:
                    s.bgp_total_neighbors = tot
                    s.bgp_established_neighbors = est
                    s.bgp_down_neighbors = down

        # Enrich BGP update storms / flap counts from events/bgp.json ringbuffer
        ev_doc = _load_json(root / "events" / "bgp.json")
        if isinstance(ev_doc, dict) and isinstance(ev_doc.get("events"), list):
            loaded = True
            ev_ref = _epoch(ev_doc.get("updated_at"), ref_now) or ref_now
            storms_by_dev: dict[str, int] = {}
            flaps_1h_by_dev: dict[str, int] = {}
            flaps_24h_by_dev: dict[str, int] = {}
            for ev in ev_doc["events"]:
                if not isinstance(ev, dict):
                    continue
                dev = str(ev.get("device") or "").strip()
                ts = _epoch(ev.get("ts") or ev.get("timestamp"), ev_ref)
                if not dev or ts is None:
                    continue
                age = ev_ref - ts
                if age < -300 or age > 86400:
                    continue
                devices.add(dev)
                kind = str(ev.get("kind") or "").lower()
                if "storm" in kind:
                    storms_by_dev[dev] = storms_by_dev.get(dev, 0) + 1
                elif "flap" in kind:
                    flaps_24h_by_dev[dev] = flaps_24h_by_dev.get(dev, 0) + 1
                    if age <= 3600:
                        flaps_1h_by_dev[dev] = flaps_1h_by_dev.get(dev, 0) + 1
            for dev in set(storms_by_dev) | set(flaps_24h_by_dev):
                s = self._upsert_hw(snapshot, dev, ev_ref)
                s.bgp_update_storms = max(s.bgp_update_storms, storms_by_dev.get(dev, 0))
                s.bgp_flaps_1h = max(s.bgp_flaps_1h, flaps_1h_by_dev.get(dev, 0))
                s.bgp_flaps_24h = max(s.bgp_flaps_24h, flaps_24h_by_dev.get(dev, 0))

        if loaded:
            snapshot.domain_coverage["bgp"] = "loaded"

    def _load_evpn_mh(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        exp = _load_json(root / "export" / "evpn-mh.json")
        if not isinstance(exp, dict) or not isinstance(exp.get("rows"), list):
            return
        ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
        for row in exp["rows"]:
            if not isinstance(row, dict):
                continue
            status = _norm_grade(row.get("status"))
            inconsistent = bool(row.get("inconsistent"))
            bypass = bool(row.get("bypass_active"))
            orphan = bool(row.get("orphan"))
            for dev_col, lacp_col in (("device_a", "lacp_a"), ("device_b", "lacp_b")):
                dev = str(row.get(dev_col) or "").strip()
                if not dev:
                    continue
                devices.add(dev)
                s = self._upsert_hw(snapshot, dev, ts)
                s.evpn_mh_total_es += 1
                if status == "critical":
                    s.evpn_mh_critical_es += 1
                elif status == "warning":
                    s.evpn_mh_warning_es += 1
                if inconsistent:
                    s.evpn_mh_inconsistent_es += 1
                if bypass:
                    s.evpn_mh_bypass_es += 1
                if orphan:
                    s.evpn_mh_orphan_es += 1
                lacp = str(row.get(lacp_col) or "").strip().lower()
                if lacp in {"degraded", "down", "bypass", "no members"}:
                    s.lacp_desync_count += 1
        snapshot.domain_coverage["evpn-mh"] = "loaded"

    def _load_routes(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        shard_dir = root / "routes-history"
        loaded = False
        if shard_dir.is_dir():
            for path in sorted(shard_dir.glob("*.json")):
                payload = _load_json(path)
                if not isinstance(payload, dict) or not isinstance(payload.get("history"), list):
                    continue
                dev = str(payload.get("host") or path.stem).strip()
                if not dev:
                    continue
                devices.add(dev)
                prev_total: int | None = None
                prev_vrfs: set[str] = set()
                for rec in payload["history"]:
                    if not isinstance(rec, dict):
                        continue
                    ts = _epoch(rec.get("timestamp"), ref_now)
                    vrfs = rec.get("vrfs")
                    if ts is None or not isinstance(vrfs, dict):
                        continue
                    total = sum(
                        _int(v.get("total")) or 0 for v in vrfs.values() if isinstance(v, dict)
                    )
                    s = self._upsert_hw(snapshot, dev, ts)
                    s.routes_total = total
                    if prev_total is not None:
                        s.routes_delta = total - prev_total
                        if prev_total > 0 and total < prev_total:
                            s.routes_drop_fraction = max(
                                s.routes_drop_fraction, (prev_total - total) / float(prev_total)
                            )
                        lost_vrfs = prev_vrfs - set(vrfs.keys())
                        s.vrf_disappeared_count = max(s.vrf_disappeared_count, len(lost_vrfs))
                    prev_total = total
                    prev_vrfs = set(vrfs.keys())
                    loaded = True

        for ev_path in (root / "routes_events.json", root / "events" / "routes.json"):
            events_doc = _load_json(ev_path)
            if isinstance(events_doc, dict) and isinstance(events_doc.get("events"), list):
                ev_ref = _epoch(events_doc.get("updated_at"), ref_now) or ref_now
                for ev in events_doc["events"]:
                    if not isinstance(ev, dict):
                        continue
                    ts = _epoch(ev.get("ts") or ev.get("timestamp"), ev_ref)
                    dev = str(ev.get("host") or ev.get("device") or "").strip()
                    if not dev or ts is None or ev_ref - ts > 86400:
                        continue
                    devices.add(dev)
                    s = self._upsert_hw(snapshot, dev, ts)
                    kind = str(ev.get("kind") or "")
                    prev = _num(ev.get("prev")) or 0.0
                    curr = _num(ev.get("current")) or 0.0
                    if kind == "route-drop" and prev > 0:
                        s.routes_drop_fraction = max(s.routes_drop_fraction, max(0.0, (prev - curr) / prev))
                    elif kind == "vrf-disappeared":
                        s.vrf_disappeared_count += 1
                loaded = True

        if loaded:
            snapshot.domain_coverage["routes"] = "loaded"

    def _load_duplicate(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        exp = _load_json(root / "export" / "duplicate.json")
        if not isinstance(exp, dict) or not isinstance(exp.get("rows"), list):
            return
        ts = _epoch(exp.get("generated_at"), ref_now) or ref_now
        for row in exp["rows"]:
            if not isinstance(row, dict) or row.get("stale"):
                continue
            ftype = str(row.get("finding_type") or "").strip().lower()
            sev = _norm_grade(row.get("severity"))
            raw_hosts = row.get("hosts")
            host_list = (
                [str(h).strip() for h in raw_hosts if str(h).strip()]
                if isinstance(raw_hosts, list)
                else [h.strip() for h in str(raw_hosts or "").split(",") if h.strip()]
            )
            delta = _int(row.get("delta")) or 0
            ev_count = _int(row.get("events")) or 0
            for dev in host_list:
                devices.add(dev)
                s = self._upsert_hw(snapshot, dev, ts)
                if ftype in {"ip", "duplicate-ip", "dup-ip"} and sev in {"warning", "critical"}:
                    s.dup_ip_active += 1
                elif ftype in {"mac", "duplicate-mac", "dup-mac"}:
                    if sev in {"warning", "critical"}:
                        s.dup_mac_confirmed += 1
                    s.mac_mobility_events += max(ev_count, 1 if delta > 0 else 0)
                    s.max_evpn_seq_delta = max(s.max_evpn_seq_delta, delta)
                    s.mac_move_rate += float(max(delta, ev_count))
        snapshot.domain_coverage["duplicate"] = "loaded"

    def _load_logs(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        doc = _load_json(root / "log_summary.json")
        if not isinstance(doc, dict) or not isinstance(doc.get("device_counts"), dict):
            return
        ts = _epoch(doc.get("generated_at"), ref_now) or ref_now
        for dev, counts in doc["device_counts"].items():
            if not isinstance(counts, dict):
                continue
            devices.add(str(dev))
            s = self._upsert_hw(snapshot, str(dev), ts)
            s.log_critical_count = _int(counts.get("critical")) or 0
            s.log_error_count = _int(counts.get("error")) or 0
            s.log_warning_count = _int(counts.get("warning")) or 0
            s.log_error_velocity = float(s.log_error_count + 2 * s.log_critical_count)
        snapshot.domain_coverage["logs"] = "loaded"

    def _load_config_drift(
        self, root: Path, snapshot: LLDPqSnapshot, devices: set[str], ref_now: float
    ) -> None:
        doc = _load_json(root / "config_drift_history.json")
        events = doc.get("events") if isinstance(doc, dict) and isinstance(doc.get("events"), list) else []
        if not events:
            exp = _load_json(root / "export" / "config-drift.json")
            if isinstance(exp, dict) and isinstance(exp.get("rows"), list):
                events = exp["rows"]
        if not events:
            ev_doc = _load_json(root / "events" / "config-drift.json")
            if isinstance(ev_doc, dict) and isinstance(ev_doc.get("events"), list):
                events = ev_doc["events"]
        if not events:
            return
        for ev in events:
            if not isinstance(ev, dict):
                continue
            dev = str(ev.get("device") or "").strip()
            if not dev:
                continue
            ts = _epoch(ev.get("detected_at") or ev.get("ts"), ref_now) or ref_now
            if ref_now - ts > 86400:
                continue
            devices.add(dev)
            s = self._upsert_hw(snapshot, dev, ts)
            s.config_drift_events_24h += 1
            s.config_lines_changed_24h += (_int(ev.get("lines_added")) or 0) + (_int(ev.get("lines_removed")) or 0)
        snapshot.domain_coverage["config-drift"] = "loaded"


# ---------------------------------------------------------------------------
# FeatureVector Record + Multi-Domain FeatureExtractor
# ---------------------------------------------------------------------------


@dataclass
class ExtractedEntityFeatures:
    """Computed feature vector plus diagnostic context for one entity/family."""

    entity_key: str
    device: str
    port: str | None
    family: str
    domains: list[str]
    feature_names: tuple[str, ...]
    values: list[float]
    peer_zscore: float
    peer_group_size: int
    sample_count: int
    slope_metrics: dict[str, float]
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.feature_names, self.values))


class FeatureExtractor:
    """Computes temporal, peer-group, and cross-domain features from an ``LLDPqSnapshot``."""

    def extract_all(self, snapshot: LLDPqSnapshot) -> list[ExtractedEntityFeatures]:
        out: list[ExtractedEntityFeatures] = []
        out.extend(self.extract_physical(snapshot))
        out.extend(self.extract_congestion(snapshot))
        out.extend(self.extract_hardware_control(snapshot))
        return out

    # ---- Family A: Physical / Optical / BER / Flap ----

    @staticmethod
    def _latest_with(series: Sequence[Any], predicate: Any) -> Any:
        for item in reversed(series):
            if predicate(item):
                return item
        return series[-1]

    def extract_physical(self, snapshot: LLDPqSnapshot) -> list[ExtractedEntityFeatures]:
        # Group latest RX power & bias by peer group (device, or fleet if device has < 3 ports)
        by_device_rx: dict[str, dict[str, float]] = {}
        by_device_bias: dict[str, list[float]] = {}
        all_rx: dict[str, float] = {}
        opt_latest_map: dict[str, PhysicalPortSample] = {}
        for key, series in snapshot.physical.items():
            if not series:
                continue
            opt_lat = self._latest_with(
                series,
                lambda s: s.rx_power_dbm is not None or s.bias_current_ma is not None or s.temperature_c is not None,
            )
            opt_latest_map[key] = opt_lat
            if opt_lat.rx_power_dbm is not None:
                by_device_rx.setdefault(opt_lat.device, {})[key] = opt_lat.rx_power_dbm
                all_rx[key] = opt_lat.rx_power_dbm
            if opt_lat.bias_current_ma is not None and opt_lat.bias_current_ma > 0.0:
                by_device_bias.setdefault(opt_lat.device, []).append(opt_lat.bias_current_ma)

        peer_bias_median: dict[str, float] = {
            dev: statistics.median(vals) for dev, vals in by_device_bias.items() if vals
        }

        peer_stats: dict[str, tuple[float, float, float]] = {}
        peer_sizes: dict[str, int] = {}
        for dev, group in by_device_rx.items():
            effective_group = group if len(group) >= 3 else all_rx
            stats = peer_group_z_and_mad(effective_group, mad_floor=0.5)
            for k in group:
                peer_stats[k] = stats.get(k, (0.0, 0.0, 0.0))
                peer_sizes[k] = len(effective_group)

        extracted: list[ExtractedEntityFeatures] = []
        for key in sorted(snapshot.physical):
            series = snapshot.physical[key]
            if not series:
                continue
            latest = series[-1]
            opt_lat = opt_latest_map[key]
            ber_lat = self._latest_with(
                series,
                lambda s: (
                    s.raw_ber is not None
                    or s.effective_ber is not None
                    or s.symbol_error_delta > 0
                    or s.fec_uncorrectable_delta > 0
                    or s.crc_errors_rate > 0
                    or s.fcs_errors_rate > 0
                    or s.delta_rx_errors > 0
                    or s.delta_tx_errors > 0
                    or s.ber_grade != "unknown"
                ),
            )
            flap_lat = self._latest_with(
                series,
                lambda s: (latest.timestamp - s.timestamp) <= 3600.0
                and (s.flaps_24h > 0 or s.flaps_1h > 0 or s.flaps_5m > 0),
            )
            mm_lat = self._latest_with(
                series,
                lambda s: (latest.timestamp - s.timestamp) <= 3600.0
                and (
                    s.mtu_mismatch
                    or s.speed_mismatch
                    or s.fec_mismatch
                    or s.autoneg_mismatch
                    or s.config_mtu_mismatch
                ),
            )

            rx_pts = [(s.timestamp, s.rx_power_dbm) for s in series if s.rx_power_dbm is not None]
            bias_pts = [(s.timestamp, s.bias_current_ma) for s in series if s.bias_current_ma is not None]
            temp_pts = [(s.timestamp, s.temperature_c) for s in series if s.temperature_c is not None]
            ber_pts = [
                (s.timestamp, safe_log10_ber(s.raw_ber if s.raw_ber is not None else s.effective_ber))
                for s in series
                if s.raw_ber is not None or s.effective_ber is not None
            ]

            rx_short, rx_med, rx_long, rx_accel = windowed_slopes(
                [p[0] for p in rx_pts], [p[1] for p in rx_pts], unit_seconds=86400.0
            )
            rx_slope_24h = rx_med if abs(rx_med) >= abs(rx_short) * 0.5 else rx_short

            bias_short, bias_med, _, _ = windowed_slopes(
                [p[0] for p in bias_pts], [p[1] for p in bias_pts], unit_seconds=86400.0
            )
            bias_slope_24h = max(bias_med, bias_short) if (bias_med > 0 or bias_short > 0) else bias_med

            _, temp_slope_24h, _, _ = windowed_slopes(
                [p[0] for p in temp_pts], [p[1] for p in temp_pts], unit_seconds=86400.0
            )
            ber_short, ber_med, _, _ = windowed_slopes(
                [p[0] for p in ber_pts], [p[1] for p in ber_pts], unit_seconds=86400.0
            )
            ber_slope_24h = max(ber_med, ber_short) if (ber_med > 0 or ber_short > 0) else ber_med

            rx_power = opt_lat.rx_power_dbm if opt_lat.rx_power_dbm is not None else -3.0
            tx_power = opt_lat.tx_power_dbm if opt_lat.tx_power_dbm is not None else -2.0
            if opt_lat.link_margin_db is not None:
                link_margin = opt_lat.link_margin_db
            elif opt_lat.rx_power_dbm is not None:
                ref = opt_lat.rx_low_alarm_dbm if opt_lat.rx_low_alarm_dbm is not None else -14.0
                link_margin = opt_lat.rx_power_dbm - ref
            else:
                link_margin = 10.0

            bias_ma = opt_lat.bias_current_ma if opt_lat.bias_current_ma is not None else 35.0
            mod_temp = opt_lat.temperature_c if opt_lat.temperature_c is not None else 40.0
            volt_dev = abs(opt_lat.voltage_v - 3.3) if opt_lat.voltage_v is not None else 0.0

            log_raw_ber = safe_log10_ber(ber_lat.raw_ber)
            log_eff_ber = safe_log10_ber(ber_lat.effective_ber)

            sym_delta_recent = max(
                ber_lat.symbol_error_delta,
                max((s.symbol_error_delta for s in series[-3:]), default=0),
            )
            fec_uncorr_recent = max(
                ber_lat.fec_uncorrectable_delta,
                max((s.fec_uncorrectable_delta for s in series[-3:]), default=0),
            )
            sym_rate = math.log1p(max(0, sym_delta_recent) + 5 * max(0, fec_uncorr_recent))
            crc_rate = math.log1p(
                max(0.0, ber_lat.crc_errors_rate)
                + max(0.0, ber_lat.fcs_errors_rate)
                + max(0, ber_lat.delta_rx_errors)
                + max(0, ber_lat.delta_tx_errors)
            )
            mismatch_flags = float(
                int(mm_lat.mtu_mismatch)
                + int(mm_lat.speed_mismatch)
                + int(mm_lat.fec_mismatch)
                + int(mm_lat.autoneg_mismatch)
                + int(mm_lat.config_mtu_mismatch)
            )
            _, peer_rx_mad, peer_rx_delta = peer_stats.get(key, (0.0, 0.0, 0.0))

            # Cross-domain interaction: simultaneous optical degradation + BER climb or bias climb
            cross_rx_ber = (
                max(0.0, -rx_slope_24h) * max(0.0, ber_slope_24h)
                + max(0.0, -rx_slope_24h) * max(0.0, bias_slope_24h / 4.0)
                + max(0.0, bias_slope_24h / 5.0) * max(0.0, ber_slope_24h)
            )

            has_optical = opt_lat.rx_power_dbm is not None or opt_lat.bias_current_ma is not None
            has_ber = ber_lat.raw_ber is not None or ber_lat.effective_ber is not None
            domains: list[str] = []
            if has_optical:
                domains.append("optical")
            if has_ber or sym_delta_recent > 0:
                domains.append("ber")
            if flap_lat.flaps_24h > 0 or flap_lat.flaps_1h > 0:
                domains.append("flap")
            if mismatch_flags > 0:
                domains.append("fabric-check")
            if not domains:
                domains.append("optical")

            values = [
                float(rx_power),
                float(tx_power),
                float(link_margin),
                float(bias_ma),
                float(mod_temp),
                float(volt_dev),
                float(rx_slope_24h),
                float(rx_accel),
                float(bias_slope_24h),
                float(temp_slope_24h),
                float(log_raw_ber),
                float(log_eff_ber),
                float(ber_slope_24h),
                float(sym_rate),
                float(crc_rate),
                float(flap_lat.flaps_1h),
                float(flap_lat.flaps_24h),
                float(mismatch_flags),
                float(peer_rx_mad),
                float(cross_rx_ber),
            ]
            extracted.append(
                ExtractedEntityFeatures(
                    entity_key=key,
                    device=latest.device,
                    port=latest.port,
                    family=FAMILY_PHYSICAL,
                    domains=domains,
                    feature_names=PHYSICAL_FEATURE_NAMES,
                    values=values,
                    peer_zscore=float(peer_rx_mad),
                    peer_group_size=peer_sizes.get(key, 1),
                    sample_count=len(series),
                    slope_metrics={
                        "rx_power_slope_db_per_24h": round(rx_slope_24h, 4),
                        "rx_power_long_slope_db_per_24h": round(rx_long, 4),
                        "bias_current_slope_ma_per_24h": round(bias_slope_24h, 4),
                        "log10_ber_slope_per_24h": round(ber_slope_24h, 4),
                        "temp_slope_c_per_24h": round(temp_slope_24h, 4),
                    },
                    context={
                        "health_status": opt_lat.health_status,
                        "ber_grade": ber_lat.ber_grade,
                        "peer_rx_delta_db": round(peer_rx_delta, 3),
                        "peer_bias_median_ma": round(peer_bias_median.get(latest.device, 0.0), 3),
                        "bias_high_warning_ma": opt_lat.bias_high_warning_ma,
                        "has_optical": has_optical,
                        "has_ber": has_ber,
                        "flaps_5m": flap_lat.flaps_5m,
                        "mismatch_details": [
                            name
                            for name, flag in (
                                ("mtu", mm_lat.mtu_mismatch),
                                ("speed", mm_lat.speed_mismatch),
                                ("fec", mm_lat.fec_mismatch),
                                ("autoneg", mm_lat.autoneg_mismatch),
                                ("config-mtu", mm_lat.config_mtu_mismatch),
                            )
                            if flag
                        ],
                    },
                    timestamp=latest.timestamp,
                )
            )
        return extracted

    # ---- Family B: RoCEv2 Congestion (PFC/ECN + Prometheus/OTEL) ----

    def extract_congestion(self, snapshot: LLDPqSnapshot) -> list[ExtractedEntityFeatures]:
        non_analyzed = {"collection_error", "first_sample"}
        # Peer congestion intensity per switch (excluding collection_error / first_sample ports)
        by_device_intensity: dict[str, dict[str, float]] = {}
        all_intensity: dict[str, float] = {}
        for key, series in snapshot.congestion.items():
            if not series:
                continue
            latest = series[-1]
            if latest.sample_status in non_analyzed or latest.signal in non_analyzed:
                continue
            intensity = (
                math.log1p(max(0.0, latest.tx_pause_rate))
                + math.log1p(max(0.0, latest.rx_pause_rate))
                + 0.25 * max(0.0, latest.ecn_share_percent)
                + 2.0 * math.log1p(max(0.0, latest.egress_hoq_rate + latest.egress_hoq_stall_rate))
                + 2.0 * math.log1p(max(0, latest.loss_delta))
            )
            by_device_intensity.setdefault(latest.device, {})[key] = intensity
            all_intensity[key] = intensity

        peer_stats: dict[str, tuple[float, float, float]] = {}
        peer_sizes: dict[str, int] = {}
        for dev, group in by_device_intensity.items():
            effective = group if len(group) >= 3 else all_intensity
            stats = peer_group_z_and_mad(effective, mad_floor=0.75)
            for k in group:
                peer_stats[k] = stats.get(k, (0.0, 0.0, 0.0))
                peer_sizes[k] = len(effective)

        extracted: list[ExtractedEntityFeatures] = []
        for key in sorted(snapshot.congestion):
            series = snapshot.congestion[key]
            if not series:
                continue
            latest = series[-1]
            is_unusable = latest.sample_status in non_analyzed or latest.signal in non_analyzed
            if is_unusable:
                values = [0.0] * len(CONGESTION_FEATURE_NAMES)
                extracted.append(
                    ExtractedEntityFeatures(
                        entity_key=key,
                        device=latest.device,
                        port=latest.port,
                        family=FAMILY_CONGESTION,
                        domains=["pfc-ecn"],
                        feature_names=CONGESTION_FEATURE_NAMES,
                        values=values,
                        peer_zscore=0.0,
                        peer_group_size=peer_sizes.get(key, 1),
                        sample_count=len(series),
                        slope_metrics={
                            "tx_pause_log_slope_per_1h": 0.0,
                            "rx_pause_log_slope_per_1h": 0.0,
                            "pfc_pause_accel": 0.0,
                            "ecn_share_slope_per_1h": 0.0,
                        },
                        context={
                            "sample_status": latest.sample_status,
                            "signal": latest.signal,
                            "rx_pause_rate": 0.0,
                            "tx_pause_rate": 0.0,
                            "ecn_share_percent": 0.0,
                            "loss_delta": 0,
                            "egress_hoq_rate": 0.0,
                            "egress_hoq_stall_rate": 0.0,
                            "rx_buffer_full_rate": 0.0,
                            "neighbor_device": latest.neighbor_device,
                            "neighbor_port": latest.neighbor_port,
                            "culprit_asymmetry": 0.0,
                        },
                        timestamp=latest.timestamp,
                    )
                )
                continue

            valid_series = [
                s for s in series if s.sample_status not in non_analyzed and s.signal not in non_analyzed
            ] or [latest]
            ts_all = [s.timestamp for s in valid_series]
            rx_p_series = [math.log1p(max(0.0, s.rx_pause_rate)) for s in valid_series]
            tx_p_series = [math.log1p(max(0.0, s.tx_pause_rate)) for s in valid_series]
            tot_p_series = [math.log1p(max(0.0, s.rx_pause_rate + s.tx_pause_rate)) for s in valid_series]
            ecn_series = [max(0.0, s.ecn_share_percent) for s in valid_series]

            rx_p_slope_1h = linear_slope(ts_all, rx_p_series, unit_seconds=3600.0)
            tx_p_slope_1h = linear_slope(ts_all, tx_p_series, unit_seconds=3600.0)
            _, _, _, pfc_accel = windowed_slopes(ts_all, tot_p_series, unit_seconds=3600.0)
            ecn_slope_1h = linear_slope(ts_all, ecn_series, unit_seconds=3600.0)

            rx_p_log = math.log1p(max(0.0, latest.rx_pause_rate))
            tx_p_log = math.log1p(max(0.0, latest.tx_pause_rate))
            ecn_rate_log = math.log1p(max(0.0, latest.ecn_marked_rate))
            ecn_share = max(0.0, latest.ecn_share_percent)
            loss_log = math.log1p(max(0, latest.loss_delta) + max(0, latest.tx_uc_buffer_discards) + max(0, latest.wred_discards))
            rx_buf_full_log = math.log1p(max(0.0, latest.rx_buffer_full_rate))
            rx_buf_almost_log = math.log1p(max(0.0, latest.rx_buffer_almost_full_rate))
            hoq_log = math.log1p(max(0.0, latest.egress_hoq_rate + latest.egress_hoq_stall_rate))
            hoq_stall_log = math.log1p(max(0.0, latest.egress_hoq_stall_rate))
            discards_log = math.log1p(
                max(0.0, latest.if_in_discards_rate)
                + max(0.0, latest.if_out_discards_rate)
                + max(0.0, latest.drop_events_rate)
            )
            tx_wait_log = math.log1p(max(0.0, latest.tx_wait_rate))

            # Culprit vs Victim asymmetry:
            # - Culprit / local congestion origin: sends TX pause upstream, exhibits local ECN/HOQ/rx_buffer_full/discards
            # - Victim: receives RX pause from downstream while local HOQ/TX-pause remain quiet
            culprit_drive = tx_p_log + 1.8 * hoq_log + 1.4 * rx_buf_full_log + 0.12 * ecn_share + 1.5 * loss_log
            victim_drive = rx_p_log
            culprit_asym = (culprit_drive - victim_drive) / (culprit_drive + victim_drive + 1.0)

            _, peer_mad, _ = peer_stats.get(key, (0.0, 0.0, 0.0))
            pfc_growth = max(0.0, pfc_accel) + max(0.0, tx_p_slope_1h) + 0.5 * max(0.0, rx_p_slope_1h)
            cross_pfc_hoq = pfc_growth * (1.0 + hoq_log + rx_buf_full_log + loss_log)

            domains = ["pfc-ecn"]
            if (
                latest.rx_buffer_full_rate > 0
                or latest.egress_hoq_rate > 0
                or latest.egress_hoq_stall_rate > 0
                or latest.if_out_discards_rate > 0
                or latest.tx_wait_rate > 0
            ):
                domains.append("prometheus_otel")

            values = [
                float(rx_p_log),
                float(tx_p_log),
                float(rx_p_slope_1h),
                float(tx_p_slope_1h),
                float(pfc_accel),
                float(ecn_rate_log),
                float(ecn_share),
                float(ecn_slope_1h),
                float(loss_log),
                float(rx_buf_full_log),
                float(rx_buf_almost_log),
                float(hoq_log),
                float(hoq_stall_log),
                float(discards_log),
                float(tx_wait_log),
                float(culprit_asym),
                float(peer_mad),
                float(cross_pfc_hoq),
            ]
            extracted.append(
                ExtractedEntityFeatures(
                    entity_key=key,
                    device=latest.device,
                    port=latest.port,
                    family=FAMILY_CONGESTION,
                    domains=domains,
                    feature_names=CONGESTION_FEATURE_NAMES,
                    values=values,
                    peer_zscore=float(peer_mad),
                    peer_group_size=peer_sizes.get(key, 1),
                    sample_count=len(valid_series),
                    slope_metrics={
                        "tx_pause_log_slope_per_1h": round(tx_p_slope_1h, 4),
                        "rx_pause_log_slope_per_1h": round(rx_p_slope_1h, 4),
                        "pfc_pause_accel": round(pfc_accel, 4),
                        "ecn_share_slope_per_1h": round(ecn_slope_1h, 4),
                    },
                    context={
                        "sample_status": latest.sample_status,
                        "signal": latest.signal,
                        "rx_pause_rate": latest.rx_pause_rate,
                        "tx_pause_rate": latest.tx_pause_rate,
                        "ecn_share_percent": ecn_share,
                        "loss_delta": latest.loss_delta,
                        "egress_hoq_rate": latest.egress_hoq_rate,
                        "egress_hoq_stall_rate": latest.egress_hoq_stall_rate,
                        "rx_buffer_full_rate": latest.rx_buffer_full_rate,
                        "neighbor_device": latest.neighbor_device,
                        "neighbor_port": latest.neighbor_port,
                        "culprit_asymmetry": round(culprit_asym, 4),
                    },
                    timestamp=latest.timestamp,
                )
            )
        return extracted

    # ---- Family C: Hardware / BMC / Control Plane ----

    def extract_hardware_control(self, snapshot: LLDPqSnapshot) -> list[ExtractedEntityFeatures]:
        extracted: list[ExtractedEntityFeatures] = []

        # 1) Per-sensor peer-group extraction (catches localized cooling defects e.g. SXM3/SXM4)
        all_sensors: dict[str, list[HardwareSensorReading]] = {
            k: list(v) for k, v in snapshot.sensors.items() if v
        }
        # Also collect sensors embedded inside HardwareControlSample
        for dev, series in snapshot.hardware_control.items():
            for sample in series:
                for sr in sample.sensors:
                    all_sensors.setdefault(sr.entity_key, []).append(sr)
        for series in all_sensors.values():
            series.sort(key=lambda r: r.timestamp)

        if all_sensors:
            extracted.extend(self._extract_sensor_entities(all_sensors))

        # 2) Device-level hardware + BMC + control-plane extraction
        # Peer group for switch temperatures by hardware model (or device_role when model absent)
        temps_by_group: dict[str, dict[str, float]] = {}
        all_dev_temps: dict[str, float] = {}
        hw_latest_map: dict[str, HardwareControlSample] = {}
        for dev, series in snapshot.hardware_control.items():
            if not series:
                continue
            hw_lat = self._latest_with(
                series,
                lambda s: (
                    s.asic_temp_c is not None
                    or s.cpu_temp_c is not None
                    or s.psu_efficiency is not None
                    or s.psu_status != "unknown"
                    or s.fan_status != "unknown"
                    or bool(s.fan_rpms)
                    or bool(s.device_model)
                ),
            )
            hw_latest_map[dev] = hw_lat
            temps = [t for t in (hw_lat.asic_temp_c, hw_lat.cpu_temp_c) if t is not None]
            if temps:
                mx = max(temps)
                grp_key = hw_lat.device_model or hw_lat.device_role
                temps_by_group.setdefault(grp_key, {})[dev] = mx
                all_dev_temps[dev] = mx

        dev_temp_peer: dict[str, tuple[float, float, float]] = {}
        dev_peer_sizes: dict[str, int] = {}
        for grp_key, grp in temps_by_group.items():
            eff = grp if len(grp) >= 3 else all_dev_temps
            stats = peer_group_z_and_mad(eff, mad_floor=2.0)
            for dev in grp:
                dev_temp_peer[dev] = stats.get(dev, (0.0, 0.0, 0.0))
                dev_peer_sizes[dev] = len(eff)

        for dev in sorted(snapshot.hardware_control):
            series = snapshot.hardware_control[dev]
            if not series:
                continue
            latest = series[-1]
            hw_lat = hw_latest_map[dev]
            grade_lat = self._latest_with(series, lambda s: s.overall_grade != "unknown")
            bgp_lat = self._latest_with(
                series,
                lambda s: (
                    s.bgp_total_neighbors > 0
                    or s.bgp_down_neighbors > 0
                    or s.bgp_flaps_1h > 0
                    or s.bgp_flaps_24h > 0
                    or s.bgp_update_storms > 0
                ),
            )
            routes_lat = self._latest_with(
                series,
                lambda s: s.routes_total > 0 or s.routes_drop_fraction > 0 or s.vrf_disappeared_count > 0,
            )
            evpn_lat = self._latest_with(
                series,
                lambda s: (
                    s.evpn_mh_total_es > 0
                    or s.evpn_mh_critical_es > 0
                    or s.evpn_mh_warning_es > 0
                    or s.evpn_mh_inconsistent_es > 0
                    or s.evpn_mh_bypass_es > 0
                    or s.lacp_desync_count > 0
                ),
            )
            dup_lat = self._latest_with(
                series,
                lambda s: s.dup_ip_active > 0 or s.dup_mac_confirmed > 0 or s.mac_move_rate > 0,
            )
            bmc_lat = self._latest_with(
                series,
                lambda s: (
                    s.bmc_mismatch_count > 0
                    or s.bmc_wrong_port_count > 0
                    or s.bmc_port_down_count > 0
                    or s.bmc_sensor_faults > 0
                    or s.bmc_stale_count > 0
                ),
            )
            log_lat = self._latest_with(
                series,
                lambda s: s.log_critical_count > 0 or s.log_error_count > 0 or s.log_error_velocity > 0,
            )
            sys_lat = self._latest_with(
                series,
                lambda s: s.reboots_24h > 0 or s.service_restarts_24h > 0 or s.critical_service_restarts_24h > 0,
            )
            drift_lat = self._latest_with(series, lambda s: s.config_drift_events_24h > 0)

            temp_pts = [
                (s.timestamp, max(t for t in (s.asic_temp_c, s.cpu_temp_c) if t is not None))
                for s in series
                if s.asic_temp_c is not None or s.cpu_temp_c is not None
            ]
            _, temp_slope_24h, _, _ = windowed_slopes(
                [p[0] for p in temp_pts], [p[1] for p in temp_pts], unit_seconds=86400.0
            )
            max_temp = temp_pts[-1][1] if temp_pts else 40.0
            ambient = hw_lat.ambient_temp_c if hw_lat.ambient_temp_c is not None else 24.0
            temp_delta_amb = max(0.0, max_temp - ambient)
            model_upper = hw_lat.device_model.upper()
            default_tlimit = 105.0 if model_upper.startswith(("SN", "MSN", "QM", "MQM")) else 85.0
            if hw_lat.tlimit_margin_c is not None:
                tlimit_margin = hw_lat.tlimit_margin_c
            elif hw_lat.tlimit_c is not None:
                tlimit_margin = hw_lat.tlimit_c - max_temp
            else:
                tlimit_margin = max(0.0, default_tlimit - max_temp)

            power_w = hw_lat.psu_out_w or hw_lat.psu_in_w
            rth = (temp_delta_amb / max(power_w, 25.0)) if (power_w and power_w > 0) else 0.0

            _, peer_temp_mad, peer_temp_delta = dev_temp_peer.get(dev, (0.0, 0.0, 0.0))

            # Fan cohort ratios
            fan_vals = [float(v) for v in hw_lat.fan_rpms.values() if v is not None and math.isfinite(v)]
            fan_min_cohort = hw_lat.fan_min_cohort_ratio if hw_lat.fan_min_cohort_ratio is not None else 1.0
            fan_rpm_ratio = 1.0
            if fan_vals:
                pos_fans = [v for v in fan_vals if v > 0]
                if pos_fans:
                    med_rpm = statistics.median(pos_fans)
                    if hw_lat.fan_min_cohort_ratio is None:
                        fan_min_cohort = min(fan_vals) / max(med_rpm, 1.0)
                    if hw_lat.fan_baseline_rpm and hw_lat.fan_baseline_rpm > 0:
                        fan_rpm_ratio = med_rpm / hw_lat.fan_baseline_rpm
                else:
                    fan_min_cohort = 0.0

            # Cross-feature: fans ramping up while temperature still elevated or climbing
            cross_fan_temp = max(0.0, fan_rpm_ratio - 1.0) * (
                max(0.0, peer_temp_delta) + max(0.0, temp_slope_24h) + max(0.0, max_temp - 55.0) * 0.5
            )

            psu_eff_def = max(0.0, 88.0 - hw_lat.psu_efficiency) if hw_lat.psu_efficiency is not None else 0.0
            psu_fault = 1.0 if (hw_lat.psu_failed_count > 0 or not hw_lat.psu_redundancy_ok) else 0.0
            load_pc = hw_lat.load_per_core if hw_lat.load_per_core is not None else (
                (hw_lat.load_raw / hw_lat.cores) if (hw_lat.load_raw is not None and hw_lat.cores) else 0.2
            )
            mem_pct = hw_lat.memory_pct if hw_lat.memory_pct is not None else 30.0
            bmc_anom = float(
                bmc_lat.bmc_mismatch_count
                + bmc_lat.bmc_wrong_port_count
                + bmc_lat.bmc_port_down_count
                + bmc_lat.bmc_sensor_faults
                + 0.5 * bmc_lat.bmc_stale_count
            )
            bgp_down_ratio = (
                bgp_lat.bgp_down_neighbors / float(max(bgp_lat.bgp_total_neighbors, 1))
                if bgp_lat.bgp_total_neighbors > 0
                else (1.0 if bgp_lat.bgp_down_neighbors > 0 else 0.0)
            )
            bgp_flap_vel = float(
                bgp_lat.bgp_flaps_1h + 0.25 * bgp_lat.bgp_flaps_24h + 3.0 * bgp_lat.bgp_update_storms
            )
            evpn_desync = float(
                evpn_lat.evpn_mh_critical_es
                + evpn_lat.evpn_mh_inconsistent_es
                + evpn_lat.evpn_mh_bypass_es
                + evpn_lat.lacp_desync_count
                + 0.5 * evpn_lat.evpn_mh_warning_es
                + 0.5 * evpn_lat.evpn_mh_orphan_es
            )
            route_drop_max = max((s.routes_drop_fraction for s in series), default=routes_lat.routes_drop_fraction)
            vrf_lost_max = max((s.vrf_disappeared_count for s in series), default=routes_lat.vrf_disappeared_count)
            ecmp_drop_max = max((s.ecmp_width_drop for s in series), default=routes_lat.ecmp_width_drop)
            route_churn = float(
                route_drop_max * 10.0
                + 5.0 * vrf_lost_max
                + float(ecmp_drop_max)
            )
            dup_rate = float(
                3.0 * dup_lat.dup_ip_active
                + 3.0 * dup_lat.dup_mac_confirmed
                + math.log1p(max(0.0, dup_lat.mac_move_rate))
            )
            syslog_vel = float(
                4.0 * log_lat.log_critical_count
                + math.log1p(max(0.0, log_lat.log_error_velocity))
                + 5.0 * sys_lat.critical_service_restarts_24h
                + 3.0 * sys_lat.reboots_24h
                + 1.5 * max(0, sys_lat.service_restarts_24h - sys_lat.critical_service_restarts_24h)
            )

            domains: list[str] = ["hardware"]
            if bmc_anom > 0:
                domains.append("bmc")
            if bgp_down_ratio > 0 or bgp_flap_vel > 0:
                domains.append("bgp")
            if evpn_desync > 0:
                domains.append("evpn-mh")
            if route_churn > 0:
                domains.append("routes")
            if dup_rate > 0:
                domains.append("duplicate")
            if syslog_vel > 0:
                domains.append("logs")
            if (
                sys_lat.reboots_24h > 0
                or sys_lat.service_restarts_24h > 0
                or sys_lat.critical_service_restarts_24h > 0
            ):
                domains.append("system")
            if drift_lat.config_drift_events_24h > 0:
                domains.append("config-drift")

            values = [
                float(max_temp),
                float(tlimit_margin),
                float(temp_delta_amb),
                float(temp_slope_24h),
                float(rth),
                float(peer_temp_mad),
                0.0,  # peer_rth_mad_zscore (primarily populated on sensor peer groups)
                float(fan_rpm_ratio),
                float(fan_min_cohort),
                float(hw_lat.fan_failed_count),
                float(cross_fan_temp),
                float(psu_eff_def),
                float(psu_fault),
                float(load_pc),
                float(mem_pct),
                float(bmc_anom),
                float(bgp_down_ratio),
                float(bgp_flap_vel),
                float(evpn_desync),
                float(route_churn),
                float(dup_rate),
                float(syslog_vel),
            ]
            extracted.append(
                ExtractedEntityFeatures(
                    entity_key=dev,
                    device=dev,
                    port=None,
                    family=FAMILY_HARDWARE_CONTROL,
                    domains=domains,
                    feature_names=HARDWARE_CONTROL_FEATURE_NAMES,
                    values=values,
                    peer_zscore=float(peer_temp_mad),
                    peer_group_size=dev_peer_sizes.get(dev, 1),
                    sample_count=len(series),
                    slope_metrics={"temp_slope_c_per_24h": round(temp_slope_24h, 4)},
                    context={
                        "entity_kind": "device",
                        "device_model": hw_lat.device_model,
                        "overall_grade": grade_lat.overall_grade,
                        "peer_temp_delta_c": round(peer_temp_delta, 2),
                        "bgp_down_neighbors": bgp_lat.bgp_down_neighbors,
                        "bgp_flaps_1h": bgp_lat.bgp_flaps_1h,
                        "bgp_update_storms": bgp_lat.bgp_update_storms,
                        "vrf_disappeared_count": vrf_lost_max,
                        "routes_total": routes_lat.routes_total,
                        "routes_drop_fraction": round(route_drop_max, 3),
                        "dup_ip_active": dup_lat.dup_ip_active,
                        "dup_mac_confirmed": dup_lat.dup_mac_confirmed,
                        "evpn_mh_critical_es": evpn_lat.evpn_mh_critical_es,
                        "lacp_desync_count": evpn_lat.lacp_desync_count,
                        "log_critical_count": log_lat.log_critical_count,
                        "critical_service_restarts_24h": sys_lat.critical_service_restarts_24h,
                    },
                    timestamp=latest.timestamp,
                )
            )
        return extracted

    def _extract_sensor_entities(
        self, sensors_by_key: Mapping[str, list[HardwareSensorReading]]
    ) -> list[ExtractedEntityFeatures]:
        """Extract peer-group thermal/power/fan features per sensor (e.g., SXM0..SXM7)."""
        temp_groups: dict[str, dict[str, float]] = {}
        rth_groups: dict[str, dict[str, float]] = {}

        for key, series in sensors_by_key.items():
            latest = series[-1]
            pg = latest.resolved_peer_group
            if latest.temp_c is not None:
                temp_groups.setdefault(pg, {})[key] = latest.temp_c
                amb = latest.ambient_temp_c if latest.ambient_temp_c is not None else 22.0
                if latest.power_w is not None and latest.power_w > 5.0:
                    rth_groups.setdefault(pg, {})[key] = max(0.0, latest.temp_c - amb) / latest.power_w

        temp_peer_stats: dict[str, tuple[float, float, float]] = {}
        rth_peer_stats: dict[str, tuple[float, float, float]] = {}
        peer_sizes: dict[str, int] = {}

        for pg, grp in temp_groups.items():
            stats = peer_group_z_and_mad(grp, mad_floor=1.5)
            for k in grp:
                temp_peer_stats[k] = stats.get(k, (0.0, 0.0, 0.0))
                peer_sizes[k] = len(grp)

        for pg, grp in rth_groups.items():
            stats = peer_group_z_and_mad(grp, mad_floor=0.025)
            for k in grp:
                rth_peer_stats[k] = stats.get(k, (0.0, 0.0, 0.0))

        extracted: list[ExtractedEntityFeatures] = []
        for key in sorted(sensors_by_key):
            series = sensors_by_key[key]
            latest = series[-1]
            t_pts = [(r.timestamp, r.temp_c) for r in series if r.temp_c is not None]
            _, temp_slope_24h, _, _ = windowed_slopes(
                [p[0] for p in t_pts], [p[1] for p in t_pts], unit_seconds=86400.0
            )
            temp_c = latest.temp_c if latest.temp_c is not None else 35.0
            ambient = latest.ambient_temp_c if latest.ambient_temp_c is not None else 22.0
            temp_delta_amb = max(0.0, temp_c - ambient)
            if latest.thermal_margin_c is not None:
                tlimit_margin = latest.thermal_margin_c
            elif latest.tlimit_c is not None:
                tlimit_margin = latest.tlimit_c - temp_c
            else:
                tlimit_margin = max(0.0, 85.0 - temp_c)

            rth = (
                temp_delta_amb / max(latest.power_w, 10.0)
                if (latest.power_w is not None and latest.power_w > 5.0)
                else 0.0
            )
            _, peer_temp_mad, peer_temp_delta = temp_peer_stats.get(key, (0.0, 0.0, 0.0))
            _, peer_rth_mad, peer_rth_delta = rth_peer_stats.get(key, (0.0, 0.0, 0.0))

            fan_rpm_ratio = 1.0
            if latest.fan_rpm is not None and latest.fan_baseline_rpm and latest.fan_baseline_rpm > 0:
                fan_rpm_ratio = latest.fan_rpm / latest.fan_baseline_rpm
            elif latest.fan_rpm is not None and latest.fan_max_rpm and latest.fan_max_rpm > 0:
                fan_rpm_ratio = latest.fan_rpm / (0.65 * latest.fan_max_rpm)

            # Cooling ineffectiveness: fans running well above baseline while THIS sensor stays hotter than peers or climbs
            cross_fan_temp = max(0.0, fan_rpm_ratio - 1.0) * (
                max(0.0, peer_temp_delta) + max(0.0, temp_slope_24h)
            )
            bmc_fault = 1.0 if latest.status in {"critical", "failed", "fault", "warning"} else 0.0

            values = [
                float(temp_c),
                float(tlimit_margin),
                float(temp_delta_amb),
                float(temp_slope_24h),
                float(rth),
                float(peer_temp_mad),
                float(peer_rth_mad),
                float(fan_rpm_ratio),
                1.0,  # fan_min_cohort_ratio
                0.0,  # fan_failed_count
                float(cross_fan_temp),
                0.0,  # psu_efficiency_deficit
                0.0,  # psu_fault_flag
                0.0,  # load_per_core
                0.0,  # memory_pct
                float(bmc_fault),
                0.0,  # bgp_down_ratio
                0.0,  # bgp_flap_velocity
                0.0,  # evpn_mh_desync_count
                0.0,  # route_churn_score
                0.0,  # dup_mac_ip_rate
                0.0,  # syslog_error_velocity
            ]
            extracted.append(
                ExtractedEntityFeatures(
                    entity_key=key,
                    device=latest.device,
                    port=latest.sensor_id,
                    family=FAMILY_HARDWARE_CONTROL,
                    domains=["hardware", "bmc"],
                    feature_names=HARDWARE_CONTROL_FEATURE_NAMES,
                    values=values,
                    peer_zscore=float(max(peer_temp_mad, peer_rth_mad, key=abs)),
                    peer_group_size=peer_sizes.get(key, 1),
                    sample_count=len(series),
                    slope_metrics={
                        "temp_slope_c_per_24h": round(temp_slope_24h, 4),
                        "thermal_resistance_c_per_w": round(rth, 4),
                    },
                    context={
                        "entity_kind": "sensor",
                        "sensor_type": latest.sensor_type,
                        "peer_group": latest.resolved_peer_group,
                        "peer_temp_delta_c": round(peer_temp_delta, 2),
                        "peer_rth_delta": round(peer_rth_delta, 4),
                        "power_w": latest.power_w,
                        "fan_rpm": latest.fan_rpm,
                        "fan_baseline_rpm": latest.fan_baseline_rpm,
                    },
                    timestamp=latest.timestamp,
                )
            )
        return extracted
