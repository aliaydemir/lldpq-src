"""Typed schemas and LLDPq ai_correlate adapters for the Multi-Domain Predictive Health Engine.

Covers all 12 LLDPq monitoring domains plus BMC and Prometheus/OTEL telemetry,
organized into three predictive domain families:
  - ``physical`` (Family A): optical, ber, flap, fabric-check
  - ``congestion`` (Family B): pfc-ecn, prometheus_otel
  - ``hardware_control`` (Family C): hardware, bmc, bgp, evpn-mh, routes,
    duplicate, logs, config-drift, system (watchdog)

Standard library only; 100% compatible with LLDPq's persisted ``monitor-results/``
JSON artifacts and ``html/ai_correlate.py`` incident bundle contracts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import time
from typing import Any, Mapping, Sequence


FAMILY_PHYSICAL = "physical"
FAMILY_CONGESTION = "congestion"
FAMILY_HARDWARE_CONTROL = "hardware_control"

ALL_FAMILIES: tuple[str, ...] = (
    FAMILY_PHYSICAL,
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
)

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

# All 12 LLDPq monitor.sh domains + BMC + Prometheus/OTEL + system watchdog
LLDPQ_DOMAIN_TO_FAMILY: dict[str, str] = {
    "optical": FAMILY_PHYSICAL,
    "ber": FAMILY_PHYSICAL,
    "flap": FAMILY_PHYSICAL,
    "fabric-check": FAMILY_PHYSICAL,
    "pfc-ecn": FAMILY_CONGESTION,
    "pfc_ecn": FAMILY_CONGESTION,
    "prometheus_otel": FAMILY_CONGESTION,
    "hardware": FAMILY_HARDWARE_CONTROL,
    "bmc": FAMILY_HARDWARE_CONTROL,
    "bgp": FAMILY_HARDWARE_CONTROL,
    "evpn-mh": FAMILY_HARDWARE_CONTROL,
    "routes": FAMILY_HARDWARE_CONTROL,
    "duplicate": FAMILY_HARDWARE_CONTROL,
    "logs": FAMILY_HARDWARE_CONTROL,
    "log": FAMILY_HARDWARE_CONTROL,
    "config-drift": FAMILY_HARDWARE_CONTROL,
    "system": FAMILY_HARDWARE_CONTROL,
}

# Exact LLDPq monitor-results/ artifact registry mapped from lldpq-src
MONITOR_RESULTS_FILES: dict[str, tuple[str, ...]] = {
    "optical": ("optical-history/*.json", "optical_history.json", "export/optical.json"),
    "ber": ("ber-history/*.json", "ber_history.json", "export/ber.json"),
    "flap": ("flap_history.json", "export/flap.json", "events/flap.json"),
    "fabric-check": ("export/fabric-check.json", "summary/fabric-check-summary.json"),
    "pfc-ecn": ("pfc-ecn-history/*.json", "pfc_ecn_history.json", "export/pfc-ecn.json"),
    "prometheus_otel": ("prometheus_telemetry.json", "otel_telemetry.json", "telemetry-series.json"),
    "hardware": (
        "hardware_history.json",
        "export/hardware.json",
        "summary/hardware-summary.json",
        "hardware-data/*_hardware.txt",
        "hardware_sensors.json",
    ),
    "system": ("system-watchdog-state.json", "events/system.json"),
    "bmc": ("bmc_results.json", "bmc-results.json", "bmc_sensors.json", "fabric-tables/*.json"),
    "bgp": ("bgp_history.json", "export/bgp.json", "events/bgp.json"),
    "evpn-mh": ("export/evpn-mh.json", "summary/evpn-mh-summary.json"),
    "routes": ("routes-history/*.json", "routes_events.json", "events/routes.json", "export/routes.json"),
    "duplicate": (
        "export/duplicate.json",
        "summary/duplicate-summary.json",
        "dup-data/dup_seq_state.json",
    ),
    "logs": ("log_summary.json", "export/log.json"),
    "config-drift": ("config_drift_history.json", "export/config-drift.json", "events/config-drift.json"),
    "topology": ("topology.dot", "../topology.dot"),
}


# ---------------------------------------------------------------------------
# Family A — Physical / Optical / BER / Flap / Fabric-Check
# ---------------------------------------------------------------------------


@dataclass
class PhysicalPortSample:
    """Single timestamped telemetry observation for one switch/NIC physical port."""

    device: str
    port: str
    timestamp: float
    # Optical DOM (optical-history/ shards & export/optical.json)
    rx_power_dbm: float | None = None
    tx_power_dbm: float | None = None
    bias_current_ma: float | None = None
    temperature_c: float | None = None
    voltage_v: float | None = None
    link_margin_db: float | None = None
    link_margin_ref_dbm: float | None = None
    rx_power_lanes_dbm: list[float] = field(default_factory=list)
    tx_power_lanes_dbm: list[float] = field(default_factory=list)
    bias_current_lanes_ma: list[float] = field(default_factory=list)
    rx_low_alarm_dbm: float | None = None
    bias_high_warning_ma: float | None = None
    bias_high_alarm_ma: float | None = None
    temp_high_warning_c: float | None = None
    health_status: str = "unknown"
    health_causes: list[str] = field(default_factory=list)
    link_state: str | None = None
    # BER / L1 (ber-history/ shards & export/ber.json)
    raw_ber: float | None = None
    effective_ber: float | None = None
    frame_error_density: float | None = None
    symbol_errors: int | None = None
    symbol_error_delta: int = 0
    fec_uncorrectable_delta: int = 0
    delta_rx_errors: int = 0
    delta_tx_errors: int = 0
    delta_rx_dropped: int = 0
    delta_tx_dropped: int = 0
    delta_packets: int = 0
    crc_errors_rate: float = 0.0
    fcs_errors_rate: float = 0.0
    ber_grade: str = "unknown"
    # Flaps (flap_history.json & export/flap.json)
    flaps_5m: int = 0
    flaps_1h: int = 0
    flaps_24h: int = 0
    carrier_transitions: int = 0
    # Fabric-Check (export/fabric-check.json)
    mtu_mismatch: bool = False
    speed_mismatch: bool = False
    fec_mismatch: bool = False
    autoneg_mismatch: bool = False
    config_mtu_mismatch: bool = False
    # Optional role / peer-group hint
    device_role: str = "switch"

    @property
    def entity_key(self) -> str:
        return f"{self.device}:{self.port}"


# ---------------------------------------------------------------------------
# Family B — AI Fabric RoCEv2 Congestion (PFC/ECN + Prometheus/OTEL)
# ---------------------------------------------------------------------------


@dataclass
class CongestionPortSample:
    """Single timestamped RoCEv2 congestion observation for one switch port."""

    device: str
    port: str
    timestamp: float
    sample_duration_seconds: float = 600.0
    sample_status: str = "analyzed"
    signal: str = "quiet"  # quiet | ecn | pfc | combined | loss
    priority: str = "3"
    # PFC/ECN counters (pfc-ecn-history/ shards & export/pfc-ecn.json)
    rx_pause_delta: int = 0
    rx_pause_rate: float = 0.0
    tx_pause_delta: int = 0
    tx_pause_rate: float = 0.0
    pfc_pause_by_priority: dict[str, float] = field(default_factory=dict)
    ecn_marked_delta: int = 0
    ecn_marked_rate: float = 0.0
    ecn_share_percent: float = 0.0
    loss_delta: int = 0
    tx_uc_buffer_discards: int = 0
    wred_discards: int = 0
    # Prometheus / Cumulus OTEL telemetry (telemetry/config/alert_rules.yaml)
    rx_buffer_full_rate: float = 0.0
    rx_buffer_almost_full_rate: float = 0.0
    egress_hoq_rate: float = 0.0
    egress_hoq_stall_rate: float = 0.0
    if_in_discards_rate: float = 0.0
    if_out_discards_rate: float = 0.0
    drop_events_rate: float = 0.0
    tx_wait_rate: float = 0.0
    ar_congestion_changes_rate: float = 0.0
    # Optional topology context for culprit-vs-victim tracing
    neighbor_device: str | None = None
    neighbor_port: str | None = None
    device_role: str = "switch"

    @property
    def entity_key(self) -> str:
        return f"{self.device}:{self.port}"


# ---------------------------------------------------------------------------
# Family C — Hardware / BMC / Control Plane
# ---------------------------------------------------------------------------


@dataclass
class HardwareSensorReading:
    """Per-sensor thermal/power/fan reading for peer-group variance analysis.

    Models switch ASIC/CPU/inlet sensors as well as BMC/Redfish compute node
    sensors (e.g., 8x SXM GPUs on a DGX/HGX host where SXM3/SXM4 may exhibit
    localized cooling degradation well below hard thermal shutdown limits).
    """

    device: str
    sensor_id: str
    timestamp: float
    sensor_type: str = "generic"  # gpu_sxm | asic | cpu | inlet | psu | dimm | board
    peer_group: str = ""  # defaults to f"{device}:{sensor_type}"
    temp_c: float | None = None
    tlimit_c: float | None = None
    thermal_margin_c: float | None = None
    ambient_temp_c: float | None = None
    power_w: float | None = None
    fan_rpm: float | None = None
    fan_baseline_rpm: float | None = None
    fan_max_rpm: float | None = None
    status: str = "ok"

    @property
    def entity_key(self) -> str:
        return f"{self.device}:{self.sensor_id}"

    @property
    def resolved_peer_group(self) -> str:
        return self.peer_group or f"{self.device}:{self.sensor_type}"


@dataclass
class HardwareControlSample:
    """Single timestamped device-level hardware, BMC, and control-plane snapshot."""

    device: str
    timestamp: float
    device_role: str = "switch"
    device_model: str = ""
    # Hardware (export/hardware.json, hardware_history.json, hardware_fans.py, hardware_environment.py)
    overall_grade: str = "unknown"
    cpu_temp_c: float | None = None
    asic_temp_c: float | None = None
    ambient_temp_c: float | None = None
    tlimit_c: float | None = None
    tlimit_margin_c: float | None = None
    memory_pct: float | None = None
    load_raw: float | None = None
    load_per_core: float | None = None
    cores: int | None = None
    psu_efficiency: float | None = None
    psu_in_w: float | None = None
    psu_out_w: float | None = None
    psu_status: str = "unknown"
    psu_failed_count: int = 0
    psu_redundancy_ok: bool = True
    fan_rpms: dict[str, float] = field(default_factory=dict)
    fan_baseline_rpm: float | None = None
    fan_min_cohort_ratio: float | None = None
    fan_failed_count: int = 0
    fan_status: str = "unknown"
    # System Watchdog (system-watchdog-state.json)
    reboots_24h: int = 0
    service_restarts_24h: int = 0
    critical_service_restarts_24h: int = 0
    # BMC (bmc_results.py & BMC telemetry)
    bmc_mismatch_count: int = 0
    bmc_wrong_port_count: int = 0
    bmc_port_down_count: int = 0
    bmc_not_seen_count: int = 0
    bmc_stale_count: int = 0
    bmc_sensor_faults: int = 0
    # BGP (bgp_history.json & export/bgp.json)
    bgp_total_neighbors: int = 0
    bgp_established_neighbors: int = 0
    bgp_down_neighbors: int = 0
    bgp_flaps_1h: int = 0
    bgp_flaps_24h: int = 0
    bgp_update_storms: int = 0
    bgp_msg_rcvd_per_min: float = 0.0
    # EVPN-MH (export/evpn-mh.json & summary/evpn-mh-summary.json)
    evpn_mh_total_es: int = 0
    evpn_mh_critical_es: int = 0
    evpn_mh_warning_es: int = 0
    evpn_mh_inconsistent_es: int = 0
    evpn_mh_bypass_es: int = 0
    evpn_mh_orphan_es: int = 0
    lacp_desync_count: int = 0
    # Routes (routes-history/<host>.json, routes_events.json, export/routes.json)
    routes_total: int = 0
    routes_delta: int = 0
    routes_drop_fraction: float = 0.0
    vrf_disappeared_count: int = 0
    ecmp_width_drop: int = 0
    # Duplicate IP/MAC (export/duplicate.json, summary/duplicate-summary.json)
    dup_ip_active: int = 0
    dup_mac_confirmed: int = 0
    mac_mobility_events: int = 0
    mac_move_rate: float = 0.0
    max_evpn_seq_delta: int = 0
    # Logs (log_summary.json & export/log.json)
    log_critical_count: int = 0
    log_error_count: int = 0
    log_warning_count: int = 0
    log_error_velocity: float = 0.0
    # Config Drift (config_drift_history.json & export/config-drift.json)
    config_drift_events_24h: int = 0
    config_lines_changed_24h: int = 0
    # Optional embedded per-sensor readings
    sensors: list[HardwareSensorReading] = field(default_factory=list)

    @property
    def entity_key(self) -> str:
        return self.device


# ---------------------------------------------------------------------------
# Unified Snapshot Container
# ---------------------------------------------------------------------------


@dataclass
class LLDPqSnapshot:
    """In-memory multi-domain telemetry bundle loaded from ``monitor-results/``."""

    timestamp: float
    devices: list[str] = field(default_factory=list)
    links: list[dict[str, str]] = field(default_factory=list)
    physical: dict[str, list[PhysicalPortSample]] = field(default_factory=dict)
    congestion: dict[str, list[CongestionPortSample]] = field(default_factory=dict)
    hardware_control: dict[str, list[HardwareControlSample]] = field(default_factory=dict)
    sensors: dict[str, list[HardwareSensorReading]] = field(default_factory=dict)
    domain_coverage: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Predictive Output Schema + LLDPq html/ai_correlate.py Adapter
# ---------------------------------------------------------------------------


@dataclass
class PredictiveRiskSignal:
    """Early-warning failure risk signal emitted per entity and domain family."""

    entity_key: str
    family: str
    risk_score: float  # 0.0 .. 100.0
    severity: str  # INFO | WARNING | CRITICAL
    horizon_hours: int  # 24 | 48 | 72
    confidence: float  # 0.0 .. 1.0
    top_reasons: list[str]
    peer_zscore: float
    slope_metrics: dict[str, float]
    recommended_action: str
    device: str = ""
    port: str | None = None
    domains: list[str] = field(default_factory=list)
    role_classification: str | None = None
    tier_scores: dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.risk_score = round(max(0.0, min(100.0, float(self.risk_score))), 2)
        self.confidence = round(max(0.0, min(1.0, float(self.confidence))), 3)
        self.peer_zscore = round(float(self.peer_zscore), 3)
        if not self.device:
            if ":" in self.entity_key:
                dev, port = self.entity_key.split(":", 1)
                self.device = dev.strip()
                if self.port is None:
                    self.port = port.strip() or None
            else:
                self.device = self.entity_key.strip()
        if self.severity not in SEVERITY_ORDER:
            self.severity = (
                "CRITICAL"
                if self.risk_score >= 70.0
                else ("WARNING" if self.risk_score >= 40.0 else "INFO")
            )
        if self.horizon_hours not in (24, 48, 72):
            self.horizon_hours = 24 if self.risk_score >= 70.0 else (48 if self.risk_score >= 50.0 else 72)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def primary_lldpq_domain(self) -> str:
        """Choose the primary LLDPq domain name recognized by ``ai_correlate.py``."""
        if self.domains:
            first = self.domains[0]
            if first == "pfc-ecn":
                return "pfc_ecn"
            if first == "logs":
                return "log"
            return first
        if self.family == FAMILY_PHYSICAL:
            return "optical"
        if self.family == FAMILY_CONGESTION:
            return "pfc_ecn"
        return "hardware"

    def to_ai_correlate_anomaly(self) -> dict[str, Any]:
        """Convert into an anomaly dict directly consumable by ``ai_correlate.correlate()``.

        Matches the exact schema of ``ai_correlate._anomaly()``:
        ``{domain, device, port, metric, value, status, detail, source}`` where
        ``status`` maps deterministically through ``ai_correlate.severity_for()``.
        """
        domain = self.primary_lldpq_domain()
        sev_lower = self.severity.lower()
        # ai_correlate.severity_for() has domain-specific status rules:
        # - pfc_ecn treats status=="loss" as WARNING, others INFO
        # - bgp treats metric=="session_flaps" as WARNING, non-established as CRITICAL
        # - optical/ber/hardware/predictive treat "critical"->CRITICAL, "warning"->WARNING
        if domain == "pfc_ecn":
            correlate_domain = "predictive_congestion"
            status_word = sev_lower
        elif domain in {"bgp", "flap", "system", "log"}:
            correlate_domain = f"predictive_{domain}"
            status_word = sev_lower
        else:
            correlate_domain = domain
            status_word = sev_lower

        reason_text = "; ".join(self.top_reasons[:3]) if self.top_reasons else "elevated predictive risk"
        role_tag = f" [{self.role_classification}]" if self.role_classification else ""
        detail = (
            f"Predictive {self.family}{role_tag} risk={self.risk_score:.1f}/100 "
            f"(horizon={self.horizon_hours}h, conf={self.confidence:.2f}, "
            f"peer_z={self.peer_zscore:+.2f}): {reason_text}. "
            f"Action: {self.recommended_action}"
        )
        return {
            "domain": correlate_domain,
            "device": self.device,
            "port": self.port,
            "metric": f"predictive_{self.family}_risk",
            "value": round(self.risk_score, 1),
            "status": status_word,
            "detail": detail,
            "source": "fabric_lm_predictive",
        }


def _subject(device: str, port: str | None) -> str:
    return f"{device}:{port}" if port else device


def _endpoint_key(device: str, port: str) -> tuple[str, str]:
    return (str(device or "").casefold(), str(port or "").casefold())


def _render_incident_block(incidents: Sequence[Mapping[str, Any]], max_chars: int = 8000) -> str:
    """Render severity-first prompt block matching ``ai_correlate.render_candidates()``."""
    ordered = sorted(
        incidents,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity")), 9),
            str(item.get("summary_key") or ""),
            str(item.get("id") or ""),
        ),
    )
    if not ordered:
        return ""
    header = f"PREDICTIVE INCIDENT CANDIDATES ({len(ordered)}, early-warning pre-correlation):"
    blocks = [header]
    used = len(header)
    rendered = 0
    for incident in ordered:
        lines = [
            f"[{incident.get('severity')}] {incident.get('kind')} {incident.get('summary')}"
        ]
        evidence = incident.get("evidence") or []
        for item in evidence[:40]:
            subj = _subject(str(item.get("device") or ""), item.get("port"))
            lines.append(
                f"  {item.get('domain')} {subj} {item.get('metric')}={item.get('value')} "
                f"({item.get('status')}) -- {item.get('detail')}"
            )
        if len(evidence) > 40:
            lines.append(f"  ... (+{len(evidence) - 40} more evidence rows)")
        block = "\n".join(lines)
        remaining = len(ordered) - rendered - 1
        marker_room = len(f"\n(+{remaining} more incidents omitted)") if remaining else 0
        if used + 1 + len(block) + marker_room > max_chars:
            break
        blocks.append(block)
        used += 1 + len(block)
        rendered += 1
    omitted = len(ordered) - rendered
    if omitted:
        blocks.append(f"(+{omitted} more incidents omitted)")
    return "\n".join(blocks)


def to_ai_correlate_bundle(
    signals: Sequence[PredictiveRiskSignal],
    *,
    links: Sequence[Mapping[str, Any]] | None = None,
    devices: Sequence[str] | Mapping[str, Any] | None = None,
    min_severity: str = "WARNING",
    generated_at: float | None = None,
    max_prompt_chars: int = 8000,
) -> dict[str, Any]:
    """Emit a deterministic JSON bundle directly consumable by LLDPq's ``ai_correlate.py`` / Ask AI.

    Only signals at or above ``min_severity`` become incident candidates; all
    signals are preserved under ``signals`` and summarized under ``summary``.
    When both ends of an expected link (from ``topology.dot``) exhibit elevated
    risk, they are pre-correlated into a single ``link-degradation`` incident
    identical in structure to ``ai_correlate.correlate()``.
    """
    ts = float(time.time() if generated_at is None else generated_at)
    threshold_rank = SEVERITY_ORDER.get(min_severity.upper(), 1)
    actionable = [
        sig for sig in signals
        if SEVERITY_ORDER.get(sig.severity, 2) <= threshold_rank
    ]

    anomalies = [sig.to_ai_correlate_anomaly() for sig in actionable]

    # Group actionable signals by endpoint (device:port) or device
    endpoint_map: dict[tuple[str, str], list[tuple[PredictiveRiskSignal, dict[str, Any]]]] = {}
    device_only: list[tuple[PredictiveRiskSignal, dict[str, Any]]] = []
    for sig, anom in zip(actionable, anomalies):
        if sig.port:
            endpoint_map.setdefault(_endpoint_key(sig.device, sig.port), []).append((sig, anom))
        else:
            device_only.append((sig, anom))

    incidents: list[dict[str, Any]] = []
    linked_keys: set[tuple[str, str]] = set()

    def _make_incident(
        kind: str,
        pairs: list[tuple[PredictiveRiskSignal, dict[str, Any]]],
        *,
        link: dict[str, str] | None = None,
        summary_override: str | None = None,
    ) -> dict[str, Any]:
        sigs = [p[0] for p in pairs]
        ev = sorted(
            [p[1] for p in pairs],
            key=lambda item: (
                str(item.get("domain") or ""),
                str(item.get("device") or ""),
                str(item.get("port") or ""),
                str(item.get("metric") or ""),
            ),
        )
        endpoints = sorted({_subject(str(item["device"]), item.get("port")) for item in ev})
        dev_list = sorted({str(item["device"]) for item in ev})
        port_list = sorted({_subject(str(item["device"]), item.get("port")) for item in ev if item.get("port")})
        worst_rank = min(SEVERITY_ORDER.get(s.severity, 2) for s in sigs)
        severity = next(name for name, rank in SEVERITY_ORDER.items() if rank == worst_rank)
        summary_key = kind + "|" + ",".join(endpoints)
        identity = summary_key + "|" + ",".join(
            sorted(f"{item['domain']}:{item['metric']}" for item in ev)
        )
        inc_id = "inc-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        max_risk = max(s.risk_score for s in sigs)
        min_horizon = min(s.horizon_hours for s in sigs)
        max_conf = max(s.confidence for s in sigs)
        actions = list(dict.fromkeys(s.recommended_action for s in sigs if s.recommended_action))
        if summary_override is None:
            fams = ", ".join(sorted({s.family for s in sigs}))
            summary_override = (
                f"{' + '.join(endpoints)}: predictive {fams} risk "
                f"{max_risk:.1f}/100 ({min_horizon}h horizon)"
            )
        return {
            "id": inc_id,
            "kind": kind,
            "severity": severity,
            "devices": dev_list,
            "ports": port_list,
            "link": link,
            "evidence": ev,
            "summary": summary_override,
            "summary_key": summary_key,
            "predictive": {
                "max_risk_score": round(max_risk, 2),
                "min_horizon_hours": min_horizon,
                "confidence": round(max_conf, 3),
                "families": sorted({s.family for s in sigs}),
                "recommended_actions": actions,
            },
        }

    # Correlate expected links where both ends show predictive risk
    for raw_link in sorted(
        (item for item in (links or []) if isinstance(item, Mapping)),
        key=lambda item: (
            str(item.get("a_dev")),
            str(item.get("a_port")),
            str(item.get("b_dev")),
            str(item.get("b_port")),
        ),
    ):
        ka = _endpoint_key(str(raw_link.get("a_dev") or ""), str(raw_link.get("a_port") or ""))
        kb = _endpoint_key(str(raw_link.get("b_dev") or ""), str(raw_link.get("b_port") or ""))
        if ka == kb or ka in linked_keys or kb in linked_keys:
            continue
        if ka in endpoint_map and kb in endpoint_map:
            pairs = endpoint_map[ka] + endpoint_map[kb]
            la = _subject(endpoint_map[ka][0][0].device, endpoint_map[ka][0][0].port)
            lb = _subject(endpoint_map[kb][0][0].device, endpoint_map[kb][0][0].port)
            label_a, label_b = sorted((la, lb))
            incidents.append(
                _make_incident(
                    "link-degradation",
                    pairs,
                    link={"a": label_a, "b": label_b},
                    summary_override=(
                        f"Expected link {label_a} <-> {label_b} predicted to degrade on both ends"
                    ),
                )
            )
            linked_keys.update((ka, kb))

    for key in sorted(endpoint_map):
        if key in linked_keys:
            continue
        pairs = endpoint_map[key]
        fams = {p[0].family for p in pairs}
        kind = "device-local"
        if fams == {FAMILY_CONGESTION}:
            kind = "congestion-risk"
        elif fams == {FAMILY_HARDWARE_CONTROL}:
            kind = "hardware-thermal-risk"
        incidents.append(_make_incident(kind, pairs))

    for pair in device_only:
        incidents.append(_make_incident("device-local", [pair]))

    incidents.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity")), 9),
            str(item.get("summary_key") or ""),
            str(item.get("id") or ""),
        )
    )

    by_family: dict[str, dict[str, int]] = {
        fam: {"total": 0, "CRITICAL": 0, "WARNING": 0, "INFO": 0}
        for fam in ALL_FAMILIES
    }
    sev_counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for sig in signals:
        sev_counts[sig.severity] = sev_counts.get(sig.severity, 0) + 1
        fam_bucket = by_family.setdefault(
            sig.family, {"total": 0, "CRITICAL": 0, "WARNING": 0, "INFO": 0}
        )
        fam_bucket["total"] += 1
        fam_bucket[sig.severity] = fam_bucket.get(sig.severity, 0) + 1

    device_count = (
        len(devices)
        if devices is not None
        else len({sig.device for sig in signals if sig.device})
    )
    return {
        "schema_version": 1,
        "generator": "fabric-lm-lldpq-predictive",
        "generated_at": ts,
        "summary": {
            "devices_evaluated": device_count,
            "total_signals": len(signals),
            "actionable_signals": len(actionable),
            "incidents": len(incidents),
            **sev_counts,
            "by_family": by_family,
        },
        "anomalies": anomalies,
        "incidents": incidents,
        "rendered_prompt_block": _render_incident_block(incidents, max_chars=max_prompt_chars),
        "signals": [sig.to_dict() for sig in signals],
    }
