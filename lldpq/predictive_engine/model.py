"""Two-tier hybrid CPU Predictive Health Model for LLDPq.

Combines:
  - **Tier 1 (``DayOneAnomalyScorer``):** Zero-label physics & peer-group scorer
    operational immediately on Day 1 for any LLDPq deployment using peer-group
    MAD Z-scores, thermal resistance (``°C/W``), optical margin & slope,
    ``log10(BER)`` velocity, RoCEv2 PFC/HOQ culprit-vs-victim asymmetry, and
    control-plane churn velocity.
  - **Tier 2 (``PredictiveRiskModel``):** Trainable gradient-boosted classifier
    using ``lightgbm`` if installed, seamlessly falling back to
    ``scikit-learn`` (``HistGradientBoostingClassifier``) or a compact
    pure-Python Newton-boosted depth-2 decision-tree ensemble
    (``NativeBoostedTreeEnsemble``) with zero external dependencies, ``< 5 MB``
    JSON artifact size, and ``< 5 ms`` batch inference latency.

Also provides ``generate_synthetic_trajectories`` (generating real
``LLDPqSnapshot`` objects passed through ``FeatureExtractor`` for zero
train/serve skew) and ``extract_self_supervised_examples`` for hybrid training
from sanitized live ``lldpq`` snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import random
import statistics
import time
from typing import Any, Mapping, Sequence

from .features import (
    CONGESTION_FEATURE_NAMES,
    ExtractedEntityFeatures,
    FEATURE_NAMES_BY_FAMILY,
    FeatureExtractor,
    HARDWARE_CONTROL_FEATURE_NAMES,
    PHYSICAL_FEATURE_NAMES,
)
from .schemas import (
    ALL_FAMILIES,
    CongestionPortSample,
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
    FAMILY_PHYSICAL,
    HardwareControlSample,
    HardwareSensorReading,
    LLDPqSnapshot,
    PhysicalPortSample,
    PredictiveRiskSignal,
)


def _sigmoid(x: float) -> float:
    if x >= 35.0:
        return 1.0
    if x <= -35.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))


def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else (hi if v > hi else v)


# ---------------------------------------------------------------------------
# Tier 1 — Day-One Zero-Label Physics & Peer-Group Scorer
# ---------------------------------------------------------------------------


@dataclass
class Tier1Assessment:
    score: float
    reasons: list[str]
    horizon_hours: int
    recommended_action: str
    role_classification: str | None = None


class DayOneAnomalyScorer:
    """Zero-label physics and peer-group risk scorer operational on Day 1."""

    def score(self, feat: ExtractedEntityFeatures) -> Tier1Assessment:
        if feat.family == FAMILY_PHYSICAL:
            return self._score_physical(feat)
        if feat.family == FAMILY_CONGESTION:
            return self._score_congestion(feat)
        return self._score_hardware_control(feat)

    # ---- Family A: Physical / Optical / BER / Flap ----

    def _score_physical(self, feat: ExtractedEntityFeatures) -> Tier1Assessment:
        f = feat.as_dict()
        ctx = feat.context
        score = 0.0
        reasons: list[str] = []

        rx_dbm = f["rx_power_dbm"]
        margin = f["link_margin_db"]
        bias_ma = f["bias_current_ma"]
        mod_temp = f["module_temp_c"]
        volt_dev = f["voltage_dev_v"]
        rx_slope = f["rx_power_slope_24h"]
        rx_accel = f["rx_power_accel"]
        bias_slope = f["bias_current_slope_24h"]
        log_raw = f["log10_raw_ber"]
        log_eff = f["log10_eff_ber"]
        ber_slope = f["log10_ber_slope_24h"]
        sym_log = f["symbol_error_rate_log1p"]
        crc_log = f["crc_fcs_error_rate_log1p"]
        flaps_1h = f["flaps_1h"]
        flaps_24h = f["flaps_24h"]
        mismatches = f["fabric_mismatch_flags"]
        peer_rx_z = f["peer_rx_mad_zscore"]
        cross = f["cross_rx_drop_x_ber_climb"]

        # 1) Optical power margin & level
        if ctx.get("has_optical"):
            if margin < 3.5:
                pts = _clamp((3.5 - margin) * 14.0, 0.0, 38.0)
                score += pts
                reasons.append(f"low optical link margin ({margin:.2f} dB, RX {rx_dbm:.2f} dBm)")
            elif rx_dbm < -9.5:
                pts = _clamp((-9.5 - rx_dbm) * 7.0, 0.0, 26.0)
                score += pts
                reasons.append(f"degraded optical RX power ({rx_dbm:.2f} dBm)")

            # 2) Optical decay slope & acceleration (fires BEFORE hard threshold!)
            if rx_slope < -0.35:
                pts = _clamp((-rx_slope - 0.35) * 14.5, 0.0, 28.0)
                score += pts
                reasons.append(f"optical RX power sloping down ({rx_slope:.2f} dB/24h)")
            if rx_accel < -0.4:
                score += _clamp((-rx_accel - 0.4) * 8.0, 0.0, 12.0)

            # 3) Laser bias current rise (classic laser aging precursor)
            if bias_slope > 1.0:
                pts = _clamp((bias_slope - 1.0) * 3.4, 0.0, 24.0)
                score += pts
                reasons.append(f"laser bias current rising (+{bias_slope:.2f} mA/24h, now {bias_ma:.1f} mA)")
            bias_warn = ctx.get("bias_high_warning_ma")
            peer_bias_med = float(ctx.get("peer_bias_median_ma") or 0.0)
            if bias_warn is not None and float(bias_warn) > 0.0:
                if bias_ma > float(bias_warn) * 0.85:
                    pts = _clamp((bias_ma - float(bias_warn) * 0.85) * 1.4, 0.0, 18.0)
                    score += pts
                    reasons.append(
                        f"elevated laser bias current ({bias_ma:.1f} mA vs {float(bias_warn):.0f} mA warn)"
                    )
            elif (peer_bias_med <= 0.0 or peer_bias_med < 55.0) and bias_ma > 75.0 * 0.85:
                pts = _clamp((bias_ma - 75.0 * 0.85) * 1.4, 0.0, 18.0)
                score += pts
                reasons.append(f"elevated laser bias current ({bias_ma:.1f} mA)")
            elif peer_bias_med >= 55.0 and bias_ma > max(peer_bias_med * 1.55, peer_bias_med + 90.0):
                pts = _clamp((bias_ma - peer_bias_med * 1.55) * 0.25, 0.0, 16.0)
                score += pts
                reasons.append(
                    f"laser bias outlier vs switch peers ({bias_ma:.1f} mA vs {peer_bias_med:.0f} mA median)"
                )

            if mod_temp > 62.0:
                pts = _clamp((mod_temp - 62.0) * 1.8, 0.0, 20.0)
                score += pts
                reasons.append(f"elevated transceiver temperature ({mod_temp:.1f} °C)")
            if volt_dev > 0.16:
                score += _clamp((volt_dev - 0.16) * 60.0, 0.0, 14.0)
                reasons.append(f"transceiver supply voltage drift (Δ{volt_dev:.2f} V)")

            # Peer-group optical RX outlier (weaker than sibling ports on same switch)
            if peer_rx_z < -3.0 and (ctx.get("peer_rx_delta_db") or 0.0) < -2.0:
                pts = _clamp((-peer_rx_z - 3.0) * 4.5, 0.0, 20.0)
                score += pts
                reasons.append(
                    f"RX power outlier vs switch peers (MAD-Z={peer_rx_z:.1f}, Δ{ctx.get('peer_rx_delta_db', 0.0):.1f} dB)"
                )

        # 4) BER level & log10 velocity (pre-FEC runaway catches faults days early)
        # Align with ber_analyzer.py raw_phy_ber_warning_threshold (1e-6 = 10^-6.0):
        # static 400G/800G PAM4 links routinely sit at 1e-8..3e-7 with zero post-FEC
        # errors, so only penalize static raw BER above 10^-6.5 (~3.2e-7) unless BER
        # is actively climbing.
        if ctx.get("has_ber"):
            if log_raw > -6.5:
                pts = _clamp((log_raw + 6.5) * 12.0, 0.0, 30.0)
                score += pts
                reasons.append(f"elevated pre-FEC raw BER (10^{log_raw:.1f})")
            elif log_raw > -7.5 and ber_slope > 0.30:
                pts = _clamp((log_raw + 7.5) * 8.0 + ber_slope * 6.0, 0.0, 18.0)
                score += pts
                reasons.append(f"rising pre-FEC raw BER (10^{log_raw:.1f}, +{ber_slope:.2f} dec/24h)")
            if log_eff > -11.5:
                pts = _clamp((log_eff + 11.5) * 10.0, 0.0, 38.0)
                score += pts
                reasons.append(f"post-FEC effective BER degradation (10^{log_eff:.1f})")
            if ber_slope > 0.45:
                pts = _clamp((ber_slope - 0.45) * 10.5, 0.0, 26.0)
                score += pts
                reasons.append(f"climbing BER velocity (+{ber_slope:.2f} decades/24h)")

        # 5) Symbol, CRC/FCS errors, link flaps & fabric mismatches
        if sym_log > 1.1:
            pts = _clamp((sym_log - 1.1) * 5.0, 0.0, 22.0)
            score += pts
            reasons.append("rising PHY symbol / uncorrectable FEC errors")
        if crc_log > 0.5:
            pts = _clamp(crc_log * 9.0, 0.0, 28.0)
            score += pts
            reasons.append("CRC/FCS physical frame errors detected")
        if flaps_1h >= 1.0 or flaps_24h >= 3.0:
            flap_cap = 55.0 if (flaps_1h >= 5.0 or flaps_24h >= 20.0) else 32.0
            pts = _clamp(flaps_1h * 11.0 + max(0.0, flaps_24h - 2.0) * 2.5, 0.0, flap_cap)
            score += pts
            reasons.append(f"link carrier instability ({int(flaps_1h)} flaps/1h, {int(flaps_24h)}/24h)")
        if mismatches >= 1.0:
            pts = _clamp(mismatches * 22.0, 0.0, 36.0)
            score += pts
            m_desc = ", ".join(ctx.get("mismatch_details") or ["link attribute"])
            reasons.append(f"fabric-check mismatch ({m_desc})")

        # 6) Cross-domain interaction amplifier (RX drop + BER climb + laser bias climb)
        if cross > 0.45:
            pts = _clamp((cross - 0.45) * 4.5, 0.0, 22.0)
            score += pts
            reasons.append("correlated optical decay + BER/bias escalation")

        score = _clamp(score, 0.0, 100.0)
        if score >= 70.0:
            horizon = 24
            action = (
                "Inspect/clean fiber patch & transceiver optics, verify FEC/link margin on both ends, "
                "and schedule proactive optic/cable replacement before link failure."
            )
        elif score >= 40.0:
            horizon = 48 if (rx_slope < -0.6 or ber_slope > 0.9 or flaps_1h >= 1) else 72
            action = (
                "Track DOM RX/bias and pre-FEC BER over next maintenance window; inspect connector "
                "attenuation and verify far-end TX power."
            )
        else:
            horizon = 72
            action = "No action required; physical link parameters within normal baseline."
            if not reasons:
                reasons.append("optical, BER, and link stability metrics nominal")

        return Tier1Assessment(
            score=score,
            reasons=reasons[:5],
            horizon_hours=horizon,
            recommended_action=action,
        )

    # ---- Family B: AI Fabric RoCEv2 Congestion ----

    def _score_congestion(self, feat: ExtractedEntityFeatures) -> Tier1Assessment:
        f = feat.as_dict()
        ctx = feat.context
        if ctx.get("sample_status") in {"collection_error", "first_sample"} or ctx.get("signal") in {
            "collection_error",
            "first_sample",
        }:
            return Tier1Assessment(
                score=0.0,
                reasons=[
                    f"telemetry sample unavailable ({ctx.get('sample_status') or ctx.get('signal')}); excluded from congestion scoring"
                ],
                horizon_hours=72,
                recommended_action="Verify switch telemetry collection health; no RoCEv2 congestion signal observed.",
                role_classification=None,
            )
        score = 0.0
        reasons: list[str] = []

        rx_p_log = f["rx_pause_rate_log1p"]
        tx_p_log = f["tx_pause_rate_log1p"]
        rx_p_slope = f["rx_pause_slope_1h"]
        tx_p_slope = f["tx_pause_slope_1h"]
        pfc_accel = f["pfc_pause_accel"]
        ecn_share = f["ecn_share_percent"]
        ecn_slope = f["ecn_slope_1h"]
        loss_log = f["loss_delta_log1p"]
        rx_buf_full = f["rx_buffer_full_rate_log1p"]
        rx_buf_almost = f["rx_buffer_almost_full_rate_log1p"]
        hoq_log = f["egress_hoq_rate_log1p"]
        hoq_stall = f["egress_hoq_stall_rate_log1p"]
        discards = f["if_discards_rate_log1p"]
        tx_wait = f["tx_wait_rate_log1p"]
        asym = f["culprit_asymmetry"]
        peer_z = f["peer_congestion_mad_zscore"]
        cross = f["cross_pfc_accel_x_hoq"]

        # Culprit vs Victim attribution
        has_congestion = (
            tx_p_log > 0.5
            or rx_p_log > 0.5
            or hoq_log > 0.2
            or rx_buf_full > 0.2
            or loss_log > 0.1
            or ecn_share >= 3.0
        )
        role_cls: str | None = None
        if has_congestion:
            if tx_p_log > 0.5 and rx_p_log > 0.5 and abs(asym) <= 0.25:
                role_cls = "bidirectional"
            elif asym >= 0.20 or hoq_log > 0.2 or rx_buf_full > 0.2 or loss_log > 0.1:
                role_cls = "culprit"
            elif rx_p_log > 0.5 and asym <= -0.20 and hoq_log <= 0.1 and tx_p_log <= 0.3:
                role_cls = "victim"
            else:
                role_cls = "culprit" if asym >= 0 else "victim"

        # 1) PFC pause frame pressure & acceleration
        if tx_p_log > 0.5:
            pts = _clamp(tx_p_log * 4.2, 0.0, 24.0)
            score += pts
            reasons.append(f"elevated TX PFC pause rate ({ctx.get('tx_pause_rate', 0.0):.1f} frames/s — pushing backpressure upstream)")
        if rx_p_log > 0.5:
            pts = _clamp(rx_p_log * 4.6, 0.0, 28.0)
            score += pts
            reasons.append(f"elevated RX PFC pause rate ({ctx.get('rx_pause_rate', 0.0):.1f} frames/s — throttled by downstream)")
        if tx_p_slope > 0.35 or rx_p_slope > 0.35 or pfc_accel > 0.25:
            pts = _clamp(
                max(0.0, tx_p_slope) * 9.0 + max(0.0, rx_p_slope) * 8.5 + max(0.0, pfc_accel) * 8.0,
                0.0,
                22.0,
            )
            score += pts
            reasons.append(f"accelerating PFC pause onset (accel={pfc_accel:+.2f}/h²)")

        # 2) ECN marking ratio (healthy DCQCN operates at low steady marking; sustained >3-5% signals onset)
        if ecn_share >= 2.5:
            pts = _clamp((ecn_share - 2.0) * 1.15, 0.0, 20.0)
            score += pts
            reasons.append(f"high ECN marking ratio ({ecn_share:.1f}%)")
        if ecn_slope > 1.5:
            score += _clamp((ecn_slope - 1.5) * 2.0, 0.0, 10.0)

        # 3) Buffer saturation, HOQ discards/stalls, and lossless queue drops
        if rx_buf_full > 0.1 or rx_buf_almost > 0.5:
            pts = _clamp(rx_buf_full * 9.0 + rx_buf_almost * 3.0, 0.0, 20.0)
            score += pts
            reasons.append("RX lossless buffer saturation (rx_buffer_full events)")
        if hoq_log > 0.1:
            pts = _clamp(hoq_log * 11.0 + hoq_stall * 8.0, 0.0, 28.0)
            score += pts
            reasons.append("egress HOQ discards/stalls active (head-of-line blocking)")
        if loss_log > 0.1 or discards > 0.5:
            pts = _clamp(loss_log * 9.0 + discards * 4.0, 0.0, 26.0)
            score += pts
            reasons.append(f"lossless queue discards detected (loss_delta={ctx.get('loss_delta', 0)})")
        if tx_wait > 1.0:
            score += _clamp((tx_wait - 1.0) * 3.0, 0.0, 10.0)

        # 4) Peer-group anomaly & cross-domain acceleration * HOQ
        if peer_z >= 3.0 and has_congestion:
            score += _clamp((peer_z - 3.0) * 2.5, 0.0, 12.0)
        if cross > 0.5:
            score += _clamp((cross - 0.5) * 3.2, 0.0, 18.0)
            reasons.append("PFC acceleration coinciding with HOQ/buffer exhaustion")

        # Victims without local HOQ/loss/TX-pause are capped below CRITICAL so root-cause culprit ranks #1
        if role_cls == "victim" and hoq_log <= 0.1 and loss_log <= 0.1 and tx_p_log <= 0.3:
            score = min(score, 62.0)

        score = _clamp(score, 0.0, 100.0)
        neighbor = (
            f"{ctx['neighbor_device']}:{ctx['neighbor_port']}"
            if ctx.get("neighbor_device") and ctx.get("neighbor_port")
            else "downstream hop"
        )
        if role_cls == "culprit" and score >= 40.0:
            horizon = 24 if score >= 70.0 else 48
            action = (
                "Local RoCEv2 congestion culprit: inspect egress queue/DCQCN ECN thresholds, "
                "check attached host NIC / slow receiver for PFC deadlock, and verify adaptive routing."
            )
        elif role_cls == "victim" and score >= 40.0:
            horizon = 48
            action = (
                f"Upstream PFC victim (receiving pause backpressure): trace congestion downstream toward {neighbor} "
                "before modifying local QoS thresholds."
            )
        elif role_cls == "bidirectional" and score >= 40.0:
            horizon = 24 if score >= 70.0 else 48
            action = (
                "Bidirectional PFC propagation detected: isolate congestion hotspot along the spine-leaf "
                "link and verify PFC watchdog timers and ECN Kmin/Kmax settings."
            )
        else:
            horizon = 72
            action = "No action required; RoCEv2 PFC/ECN and buffer telemetry within lossless baseline."
            if not reasons:
                reasons.append("PFC/ECN quiet with zero HOQ or lossless buffer discards")

        return Tier1Assessment(
            score=score,
            reasons=reasons[:5],
            horizon_hours=horizon,
            recommended_action=action,
            role_classification=role_cls,
        )

    # ---- Family C: Hardware / BMC / Control Plane ----

    def _score_hardware_control(self, feat: ExtractedEntityFeatures) -> Tier1Assessment:
        f = feat.as_dict()
        ctx = feat.context
        is_sensor = ctx.get("entity_kind") == "sensor"
        score = 0.0
        reasons: list[str] = []
        role_cls: str | None = None

        max_temp = f["max_temp_c"]
        tlimit_margin = f["tlimit_margin_c"]
        temp_slope = f["temp_slope_24h"]
        rth = f["thermal_resistance_c_per_w"]
        peer_temp_z = f["peer_temp_mad_zscore"]
        peer_rth_z = f["peer_rth_mad_zscore"]
        fan_rpm_ratio = f["fan_rpm_ratio"]
        fan_min_cohort = f["fan_min_cohort_ratio"]
        fan_failed = f["fan_failed_count"]
        cross_fan_temp = f["cross_fan_rpm_x_temp_delta"]
        psu_def = f["psu_efficiency_deficit"]
        psu_fault = f["psu_fault_flag"]
        load_pc = f["load_per_core"]
        mem_pct = f["memory_pct"]
        bmc_anom = f["bmc_anomaly_count"]
        bgp_down = f["bgp_down_ratio"]
        bgp_flap = f["bgp_flap_velocity"]
        evpn_desync = f["evpn_mh_desync_count"]
        route_churn = f["route_churn_score"]
        dup_rate = f["dup_mac_ip_rate"]
        syslog_vel = f["syslog_error_velocity"]

        peer_temp_delta = float(ctx.get("peer_temp_delta_c") or 0.0)
        power_w = ctx.get("power_w")
        # If power telemetry is present and thermal resistance (°C/W) matches peers,
        # elevated temperature is explained by heavier compute load rather than a cooling defect.
        power_explains_temp = (
            is_sensor
            and power_w is not None
            and float(power_w) > 10.0
            and peer_rth_z < 1.5
            and rth < 0.22
        )

        # 1) Peer-group localized cooling defect (catches SXM3/SXM4 +22°C outlier well below 85°C!)
        if peer_temp_z >= 3.5 and peer_temp_delta >= 7.0 and not power_explains_temp:
            pts = _clamp(28.0 + (peer_temp_delta - 7.0) * 1.4 + (peer_temp_z - 3.5) * 1.2, 28.0, 48.0)
            score += pts
            role_cls = "localized_cooling_fault"
            reasons.append(
                f"localized thermal outlier vs peer group (+{peer_temp_delta:.1f} °C above peers, MAD-Z={peer_temp_z:+.1f})"
            )

        if peer_rth_z >= 3.0 and rth > 0.18:
            pts = _clamp(16.0 + (peer_rth_z - 3.0) * 2.2, 16.0, 28.0)
            score += pts
            role_cls = "localized_cooling_fault"
            reasons.append(
                f"elevated thermal resistance ({rth:.3f} °C/W, peer MAD-Z={peer_rth_z:+.1f} — poor TIM/cold-plate contact)"
            )

        if cross_fan_temp >= 2.5 and not power_explains_temp:
            pts = _clamp(12.0 + (cross_fan_temp - 2.5) * 1.6, 12.0, 26.0)
            score += pts
            if role_cls is None:
                role_cls = "cooling_ineffective"
            reasons.append(
                f"fans elevated ({fan_rpm_ratio:.2f}x baseline) without cooling thermal delta"
            )

        # 2) Absolute thermal margin & slope
        if tlimit_margin < 15.0:
            pts = _clamp((15.0 - tlimit_margin) * 3.0, 0.0, 38.0)
            score += pts
            reasons.append(f"narrow thermal headroom (margin {tlimit_margin:.1f} °C, temp {max_temp:.1f} °C)")
        if temp_slope > 2.0:
            pts = _clamp((temp_slope - 2.0) * 4.0, 0.0, 20.0)
            score += pts
            reasons.append(f"sustained temperature climb (+{temp_slope:.1f} °C/24h)")

        # 3) Fan cohort lag / failure (device-level)
        if not is_sensor:
            if fan_failed >= 1.0:
                score += _clamp(42.0 + (fan_failed - 1.0) * 14.0, 42.0, 60.0)
                reasons.append(f"{int(fan_failed)} fan unit(s) reported bad/stopped")
            elif fan_min_cohort < 0.72:
                pts = _clamp((0.72 - fan_min_cohort) * 90.0, 0.0, 34.0)
                score += pts
                reasons.append(f"fan lagging cohort baseline (min ratio {fan_min_cohort:.2f}x)")

            # 4) PSU & host resource health
            if psu_fault > 0.0:
                score += 42.0
                reasons.append("PSU fault or redundancy policy shortage")
            elif psu_def > 5.0:
                score += _clamp((psu_def - 5.0) * 2.2, 0.0, 22.0)
                reasons.append(f"degraded PSU efficiency (-{psu_def:.1f}% below nominal)")

            if load_pc > 0.9:
                score += _clamp((load_pc - 0.9) * 28.0, 0.0, 24.0)
                reasons.append(f"elevated CPU load per core ({load_pc:.2f})")
            if mem_pct > 78.0:
                score += _clamp((mem_pct - 78.0) * 1.4, 0.0, 24.0)
                reasons.append(f"high switch/host memory utilization ({mem_pct:.1f}%)")

        # 5) BMC & Control Plane (BGP, EVPN-MH, Routes, Duplicates, Logs/Watchdog)
        if bmc_anom > 0.0:
            score += _clamp(bmc_anom * 14.0, 0.0, 32.0)
            reasons.append(f"BMC connectivity/sensor anomalies ({int(math.ceil(bmc_anom))})")

        if bgp_down > 0.0:
            score += _clamp(28.0 + bgp_down * 45.0, 28.0, 55.0)
            reasons.append(f"BGP sessions down ({ctx.get('bgp_down_neighbors', 0)} neighbor(s))")
        if bgp_flap >= 2.0:
            score += _clamp(bgp_flap * 4.5, 0.0, 30.0)
            reasons.append(f"BGP session flaps / update storm velocity ({bgp_flap:.1f})")

        if evpn_desync > 0.0:
            score += _clamp(evpn_desync * 15.0, 0.0, 36.0)
            reasons.append("EVPN-MH / LACP multihoming desync or bypass active")

        if route_churn >= 1.5:
            score += _clamp(route_churn * 7.5, 0.0, 42.0)
            reasons.append(
                f"routing table churn/drop (drop={ctx.get('routes_drop_fraction', 0.0)*100:.1f}%, "
                f"vrf_lost={ctx.get('vrf_disappeared_count', 0)})"
            )

        if dup_rate >= 2.0:
            score += _clamp(dup_rate * 5.0, 0.0, 32.0)
            reasons.append("duplicate IP/MAC or high EVPN MAC mobility rate")

        if syslog_vel >= 3.0:
            score += _clamp((syslog_vel - 2.0) * 4.5, 0.0, 28.0)
            reasons.append("elevated critical syslog / watchdog daemon restart velocity")

        score = _clamp(score, 0.0, 100.0)
        if role_cls == "localized_cooling_fault" and score >= 50.0:
            horizon = 24
            action = (
                "Localized cooling defect detected: inspect heatsink/cold-plate mounting, thermal "
                "interface material (TIM), liquid-cooling manifold/quick-disconnects, and BMC sensor seating."
            )
        elif score >= 70.0:
            horizon = 24
            action = (
                "Immediate hardware/control-plane triage: verify fan/PSU state, BGP/EVPN-MH sessions, "
                "routing table integrity, and daemon restart logs."
            )
        elif score >= 40.0:
            horizon = 48
            action = (
                "Investigate developing hardware/control-plane drift during next window; compare against "
                "peer chassis/switches and review syslog error trend."
            )
        else:
            horizon = 72
            action = "No action required; hardware, BMC, and control-plane metrics nominal."
            if not reasons:
                reasons.append("thermal, cooling, BMC, and control-plane metrics within peer baseline")

        return Tier1Assessment(
            score=score,
            reasons=reasons[:5],
            horizon_hours=horizon,
            recommended_action=action,
            role_classification=role_cls,
        )


# ---------------------------------------------------------------------------
# Pure-Python Gradient-Boosted Depth-2 Decision Tree Ensemble (Zero Deps!)
# ---------------------------------------------------------------------------


@dataclass
class _TreeNode:
    """Binary decision node (either split node or leaf)."""

    is_leaf: bool
    value: float = 0.0
    feature_idx: int = -1
    threshold: float = 0.0
    left: "_TreeNode | None" = None
    right: "_TreeNode | None" = None

    def predict_one(self, row: Sequence[float]) -> float:
        node = self
        while not node.is_leaf:
            if row[node.feature_idx] <= node.threshold:
                node = node.left  # type: ignore[assignment]
            else:
                node = node.right  # type: ignore[assignment]
        return node.value

    def mean_leaf_value(self) -> float:
        if self.is_leaf:
            return self.value
        assert self.left is not None and self.right is not None
        return 0.5 * (self.left.mean_leaf_value() + self.right.mean_leaf_value())

    def accumulate_contributions(
        self, row: Sequence[float], lr: float, out: dict[int, float]
    ) -> None:
        node = self
        cur_val = node.mean_leaf_value()
        while not node.is_leaf:
            nxt = node.left if row[node.feature_idx] <= node.threshold else node.right
            assert nxt is not None
            nxt_val = nxt.mean_leaf_value()
            out[node.feature_idx] = out.get(node.feature_idx, 0.0) + lr * (nxt_val - cur_val)
            node = nxt
            cur_val = nxt_val

    def to_dict(self) -> dict[str, Any]:
        if self.is_leaf:
            return {"v": round(self.value, 6)}
        return {
            "f": self.feature_idx,
            "t": round(self.threshold, 6),
            "l": self.left.to_dict() if self.left else {"v": 0.0},
            "r": self.right.to_dict() if self.right else {"v": 0.0},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "_TreeNode":
        if "v" in data:
            return cls(is_leaf=True, value=float(data["v"]))
        return cls(
            is_leaf=False,
            feature_idx=int(data["f"]),
            threshold=float(data["t"]),
            left=cls.from_dict(data["l"]),
            right=cls.from_dict(data["r"]),
        )


class NativeBoostedTreeEnsemble:
    """Compact pure-Python Newton-boosted binary GBDT (depth <= 3) with feature subsampling.

    Trains in < 2 s on ~1.5k rows, executes batch inference in < 1 ms, prevents
    single-feature split collapse via ``colsample_bytree``, and serializes to
    < 40 KB JSON with zero third-party dependencies.
    """

    def __init__(
        self,
        n_estimators: int = 48,
        learning_rate: float = 0.12,
        max_depth: int = 3,
        l2_reg: float = 2.0,
        min_child_hess: float = 1.5,
        max_bins: int = 16,
        colsample_bytree: float = 0.65,
        subsample: float = 0.85,
        seed: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.l2_reg = l2_reg
        self.min_child_hess = min_child_hess
        self.max_bins = max_bins
        self.colsample_bytree = colsample_bytree
        self.subsample = subsample
        self.seed = seed
        self.base_score: float = 0.0
        self.trees: list[_TreeNode] = []
        self.n_features: int = 0

    def fit(
        self,
        X: Sequence[Sequence[float]],
        y: Sequence[int],
        sample_weight: Sequence[float] | None = None,
    ) -> "NativeBoostedTreeEnsemble":
        n = len(X)
        if n == 0:
            self.base_score = 0.0
            self.trees = []
            return self
        self.n_features = len(X[0])
        weights = [float(w) for w in sample_weight] if sample_weight is not None else [1.0] * n
        pos_w = sum(w for w, yi in zip(weights, y) if yi == 1)
        tot_w = max(sum(weights), 1e-6)
        p0 = _clamp(pos_w / tot_w, 1e-4, 1.0 - 1e-4)
        self.base_score = math.log(p0 / (1.0 - p0))

        # Precompute candidate quantile thresholds once per feature
        cand_thresholds: list[list[float]] = []
        cols: list[list[float]] = [[float(X[i][j]) for i in range(n)] for j in range(self.n_features)]
        for j in range(self.n_features):
            uniq = sorted(set(cols[j]))
            if len(uniq) <= 1:
                cand_thresholds.append([])
            elif len(uniq) <= self.max_bins:
                cand_thresholds.append([(uniq[k] + uniq[k + 1]) * 0.5 for k in range(len(uniq) - 1)])
            else:
                step = (len(uniq) - 1) / float(self.max_bins)
                pts = [uniq[int(round(k * step))] for k in range(1, self.max_bins)]
                cand_thresholds.append(sorted(set(pts)))

        preds = [self.base_score] * n
        all_indices = list(range(n))
        all_features = list(range(self.n_features))
        rng = random.Random(self.seed)
        col_k = max(2, int(round(self.n_features * _clamp(self.colsample_bytree, 0.25, 1.0))))
        col_k = min(col_k, self.n_features)
        row_k = max(8, int(round(n * _clamp(self.subsample, 0.4, 1.0))))
        row_k = min(row_k, n)
        self.trees = []

        for _ in range(self.n_estimators):
            grads = [0.0] * n
            hess = [0.0] * n
            for i in range(n):
                p = _sigmoid(preds[i])
                w = weights[i]
                grads[i] = (float(y[i]) - p) * w
                hess[i] = max(p * (1.0 - p), 1e-5) * w

            feat_subset = (
                sorted(rng.sample(all_features, col_k))
                if col_k < self.n_features
                else all_features
            )
            row_subset = (
                rng.sample(all_indices, row_k)
                if row_k < n
                else all_indices
            )
            tree = self._build_node(
                cols, grads, hess, row_subset, cand_thresholds, feat_subset, depth=0
            )
            self.trees.append(tree)
            lr = self.learning_rate
            for i in range(n):
                preds[i] += lr * tree.predict_one(X[i])
        return self

    def _build_node(
        self,
        cols: Sequence[Sequence[float]],
        grads: Sequence[float],
        hess: Sequence[float],
        indices: Sequence[int],
        cand_thresholds: Sequence[Sequence[float]],
        feat_subset: Sequence[int],
        depth: int,
    ) -> _TreeNode:
        g_tot = sum(grads[i] for i in indices)
        h_tot = sum(hess[i] for i in indices)
        leaf_val = _clamp(g_tot / (h_tot + self.l2_reg), -4.0, 4.0)
        if depth >= self.max_depth or len(indices) < 6 or h_tot < 2.0 * self.min_child_hess:
            return _TreeNode(is_leaf=True, value=leaf_val)

        parent_score = (g_tot * g_tot) / (h_tot + self.l2_reg)
        best_gain = 1e-4
        best_feat = -1
        best_thr = 0.0

        for j in feat_subset:
            thrs = cand_thresholds[j]
            if not thrs:
                continue
            col_j = cols[j]
            for thr in thrs:
                g_l = 0.0
                h_l = 0.0
                for i in indices:
                    if col_j[i] <= thr:
                        g_l += grads[i]
                        h_l += hess[i]
                h_r = h_tot - h_l
                if h_l < self.min_child_hess or h_r < self.min_child_hess:
                    continue
                g_r = g_tot - g_l
                gain = 0.5 * (
                    (g_l * g_l) / (h_l + self.l2_reg)
                    + (g_r * g_r) / (h_r + self.l2_reg)
                    - parent_score
                )
                if gain > best_gain:
                    best_gain = gain
                    best_feat = j
                    best_thr = thr

        if best_feat < 0:
            return _TreeNode(is_leaf=True, value=leaf_val)

        col_best = cols[best_feat]
        left_idx = [i for i in indices if col_best[i] <= best_thr]
        right_idx = [i for i in indices if col_best[i] > best_thr]
        if not left_idx or not right_idx:
            return _TreeNode(is_leaf=True, value=leaf_val)

        return _TreeNode(
            is_leaf=False,
            feature_idx=best_feat,
            threshold=best_thr,
            left=self._build_node(cols, grads, hess, left_idx, cand_thresholds, feat_subset, depth + 1),
            right=self._build_node(cols, grads, hess, right_idx, cand_thresholds, feat_subset, depth + 1),
        )

    def predict_proba_one(self, row: Sequence[float]) -> float:
        score = self.base_score
        lr = self.learning_rate
        for tree in self.trees:
            score += lr * tree.predict_one(row)
        return _sigmoid(score)

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        return [self.predict_proba_one(row) for row in X]

    def explain_one(
        self, row: Sequence[float], feature_names: Sequence[str], *, top_k: int = 3
    ) -> list[tuple[str, float]]:
        """Return top positive-contributing ``(feature_name, log_odds_delta)`` pairs."""
        contribs: dict[int, float] = {}
        lr = self.learning_rate
        for tree in self.trees:
            tree.accumulate_contributions(row, lr, contribs)
        ranked = [
            (feature_names[idx], delta)
            for idx, delta in contribs.items()
            if 0 <= idx < len(feature_names) and delta > 0.05
        ]
        ranked.sort(key=lambda pair: -pair[1])
        return ranked[:top_k]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": "native_gbdt",
            "n_features": self.n_features,
            "learning_rate": self.learning_rate,
            "base_score": round(self.base_score, 6),
            "trees": [t.to_dict() for t in self.trees],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeBoostedTreeEnsemble":
        obj = cls(learning_rate=float(data.get("learning_rate", 0.14)))
        obj.n_features = int(data.get("n_features", 0))
        obj.base_score = float(data.get("base_score", 0.0))
        obj.trees = [_TreeNode.from_dict(t) for t in (data.get("trees") or [])]
        return obj


# ---------------------------------------------------------------------------
# Backend Adapter (LightGBM -> scikit-learn -> NativeBoostedTreeEnsemble)
# ---------------------------------------------------------------------------


def detect_available_backend(preferred: str = "auto") -> str:
    """Resolve the best available GBDT backend with graceful fallback."""
    pref = preferred.lower().strip()
    if pref in ("auto", "lightgbm"):
        try:
            import lightgbm  # noqa: F401
            import numpy  # noqa: F401

            return "lightgbm"
        except ImportError:
            if pref == "lightgbm":
                return "native_gbdt"
    if pref in ("auto", "sklearn"):
        try:
            import numpy  # noqa: F401
            from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: F401

            return "sklearn"
        except ImportError:
            if pref == "sklearn":
                return "native_gbdt"
    return "native_gbdt"


class _FamilyClassifier:
    """Uniform wrapper around LightGBM, sklearn HistGBDT, or NativeBoostedTreeEnsemble."""

    def __init__(self, backend: str = "auto", seed: int = 42) -> None:
        self.backend = detect_available_backend(backend)
        self.seed = seed
        self._model: Any = None
        self._native_export: NativeBoostedTreeEnsemble | None = None

    def fit(
        self,
        X: Sequence[Sequence[float]],
        y: Sequence[int],
        sample_weight: Sequence[float] | None = None,
    ) -> "_FamilyClassifier":
        if self.backend == "lightgbm":
            import lightgbm as lgb
            import numpy as np

            clf = lgb.LGBMClassifier(
                n_estimators=50,
                max_depth=3,
                num_leaves=7,
                learning_rate=0.1,
                min_child_samples=10,
                random_state=self.seed,
                verbosity=-1,
                n_jobs=1,
            )
            clf.fit(np.asarray(X, dtype=float), np.asarray(y, dtype=int), sample_weight=sample_weight)
            self._model = clf
            return self

        if self.backend == "sklearn":
            import numpy as np
            from sklearn.ensemble import HistGradientBoostingClassifier

            clf = HistGradientBoostingClassifier(
                max_iter=50,
                max_depth=3,
                learning_rate=0.1,
                min_samples_leaf=10,
                random_state=self.seed,
            )
            clf.fit(np.asarray(X, dtype=float), np.asarray(y, dtype=int), sample_weight=sample_weight)
            self._model = clf
            # Train a portable pure-JSON native twin for zero-dependency JSON export
            self._native_export = NativeBoostedTreeEnsemble(seed=self.seed).fit(X, y, sample_weight=sample_weight)
            return self

        self._model = NativeBoostedTreeEnsemble(seed=self.seed).fit(X, y, sample_weight=sample_weight)
        return self

    def predict_proba(self, X: Sequence[Sequence[float]]) -> list[float]:
        if self._model is None or not X:
            return [0.0] * len(X)
        if self.backend in ("lightgbm", "sklearn"):
            import numpy as np

            probs = self._model.predict_proba(np.asarray(X, dtype=float))
            return [float(row[1]) for row in probs]
        return self._model.predict_proba(X)

    def explain_one(
        self, row: Sequence[float], feature_names: Sequence[str], *, top_k: int = 2
    ) -> list[tuple[str, float]]:
        native = self._model if isinstance(self._model, NativeBoostedTreeEnsemble) else self._native_export
        if native is not None:
            return native.explain_one(row, feature_names, top_k=top_k)
        return []

    def to_dict(self) -> dict[str, Any]:
        if self.backend == "lightgbm" and self._model is not None:
            return {
                "backend": "lightgbm",
                "model_str": self._model.booster_.model_to_string(),
            }
        if self.backend == "sklearn" and self._native_export is not None:
            # Portable JSON serialization via native GBDT twin (no unsafe pickle)
            return self._native_export.to_dict()
        if isinstance(self._model, NativeBoostedTreeEnsemble):
            return self._model.to_dict()
        return {"backend": "untrained"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "_FamilyClassifier":
        backend = str(data.get("backend") or "native_gbdt")
        if backend == "lightgbm" and data.get("model_str"):
            try:
                import lightgbm as lgb

                wrapper = cls(backend="lightgbm")
                booster = lgb.Booster(model_str=str(data["model_str"]))

                class _BoosterProb:
                    def predict_proba(self, arr: Any) -> list[list[float]]:
                        p = booster.predict(arr)
                        return [[1.0 - float(v), float(v)] for v in p]

                wrapper._model = _BoosterProb()
                return wrapper
            except ImportError:
                pass
        wrapper = cls(backend="native_gbdt")
        if data.get("trees") is not None:
            wrapper._model = NativeBoostedTreeEnsemble.from_dict(data)
        return wrapper


# ---------------------------------------------------------------------------
# Two-Tier Hybrid PredictiveRiskModel
# ---------------------------------------------------------------------------


@dataclass
class BaselineCalibration:
    """Per-family normal-operating calibration learned from an anonymized live fabric."""

    family: str
    entity_count: int = 0
    feature_medians: dict[str, float] = field(default_factory=dict)
    feature_mads: dict[str, float] = field(default_factory=dict)
    baseline_score_p95: float = 15.0
    score_offset: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "entity_count": self.entity_count,
            "feature_medians": self.feature_medians,
            "feature_mads": self.feature_mads,
            "baseline_score_p95": round(self.baseline_score_p95, 3),
            "score_offset": round(self.score_offset, 3),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BaselineCalibration":
        return cls(
            family=str(data.get("family") or ""),
            entity_count=int(data.get("entity_count") or 0),
            feature_medians={str(k): float(v) for k, v in (data.get("feature_medians") or {}).items()},
            feature_mads={str(k): float(v) for k, v in (data.get("feature_mads") or {}).items()},
            baseline_score_p95=float(data.get("baseline_score_p95", 15.0)),
            score_offset=float(data.get("score_offset", 0.0)),
        )


class PredictiveRiskModel:
    """Hybrid Tier-1 (physics/peer-group) + Tier-2 (GBDT) multi-domain predictor."""

    SCHEMA_VERSION = 1

    def __init__(self, backend: str = "auto", seed: int = 42) -> None:
        self.backend = detect_available_backend(backend)
        self.seed = seed
        self.tier1 = DayOneAnomalyScorer()
        self.extractor = FeatureExtractor()
        self.classifiers: dict[str, _FamilyClassifier] = {}
        self.calibrations: dict[str, BaselineCalibration] = {}
        self.metadata: dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "backend": self.backend,
            "trained": False,
        }

    @property
    def is_trained(self) -> bool:
        return bool(self.classifiers)

    def fit_family(
        self,
        family: str,
        X: Sequence[Sequence[float]],
        y: Sequence[int],
        sample_weight: Sequence[float] | None = None,
    ) -> "PredictiveRiskModel":
        if family not in FEATURE_NAMES_BY_FAMILY:
            raise ValueError(f"Unknown predictive family: {family}")
        clf = _FamilyClassifier(backend=self.backend, seed=self.seed)
        clf.fit(X, y, sample_weight=sample_weight)
        self.classifiers[family] = clf
        self.metadata["trained"] = True
        self.metadata["trained_at"] = round(time.time(), 3)
        return self

    def calibrate_from_baseline(self, snapshot: LLDPqSnapshot) -> dict[str, BaselineCalibration]:
        """Calibrate per-family baseline distributions from a sanitized live snapshot.

        Computes robust per-feature medians/MADs and checks the 95th-percentile
        score of nominal entities so normal fleet variance does not trigger false
        alarms, while preserving full sensitivity for genuine faults.
        """
        feats = self.extractor.extract_all(snapshot)
        by_family: dict[str, list[ExtractedEntityFeatures]] = {fam: [] for fam in ALL_FAMILIES}
        for feat in feats:
            by_family.setdefault(feat.family, []).append(feat)

        for fam, items in by_family.items():
            if not items:
                continue
            names = FEATURE_NAMES_BY_FAMILY[fam]
            medians: dict[str, float] = {}
            mads: dict[str, float] = {}
            for idx, name in enumerate(names):
                col = [it.values[idx] for it in items]
                med = statistics.median(col)
                mad = statistics.median([abs(v - med) for v in col])
                medians[name] = round(med, 5)
                mads[name] = round(mad, 5)

            # Evaluate uncalibrated baseline scores on nominal entities (tier1 < 35)
            t1_scores = [self.tier1.score(it).score for it in items]
            nominal_scores = sorted(s for s in t1_scores if s < 35.0)
            if nominal_scores:
                p95_idx = min(len(nominal_scores) - 1, int(0.95 * len(nominal_scores)))
                p95 = nominal_scores[p95_idx]
            else:
                p95 = 15.0
            # Small downward offset (capped at 8 pts) only if noisy healthy fabric creeps above 15
            offset = _clamp(p95 - 15.0, 0.0, 8.0)
            self.calibrations[fam] = BaselineCalibration(
                family=fam,
                entity_count=len(items),
                feature_medians=medians,
                feature_mads=mads,
                baseline_score_p95=p95,
                score_offset=offset,
            )
        return self.calibrations

    def predict_features(
        self,
        features: Sequence[ExtractedEntityFeatures],
    ) -> list[PredictiveRiskSignal]:
        """Score a batch of extracted feature vectors into ``PredictiveRiskSignal`` objects."""
        if not features:
            return []

        # Batch Tier-2 probabilities per family for minimum latency
        ml_probs: dict[int, float] = {}
        by_fam_indices: dict[str, list[int]] = {}
        for idx, feat in enumerate(features):
            by_fam_indices.setdefault(feat.family, []).append(idx)

        for fam, idxs in by_fam_indices.items():
            clf = self.classifiers.get(fam)
            if clf is None:
                continue
            X_batch = [features[i].values for i in idxs]
            probs = clf.predict_proba(X_batch)
            for i, p in zip(idxs, probs):
                ml_probs[i] = _clamp(float(p), 0.0, 1.0)

        signals: list[PredictiveRiskSignal] = []
        for idx, feat in enumerate(features):
            t1 = self.tier1.score(feat)
            cal = self.calibrations.get(feat.family)
            offset = cal.score_offset if cal else 0.0

            is_uncollected_congestion = feat.family == FAMILY_CONGESTION and (
                feat.context.get("sample_status") in {"collection_error", "first_sample"}
                or feat.context.get("signal") in {"collection_error", "first_sample"}
            )
            if is_uncollected_congestion:
                final_score = 0.0
                tier_scores = {"tier1_physics": 0.0, "tier2_ml": 0.0} if idx in ml_probs else {"tier1_physics": 0.0}
                agreement = 1.0
            elif idx in ml_probs:
                p2 = ml_probs[idx]
                s2 = 100.0 * p2
                # Blend Tier-1 physics and Tier-2 GBDT:
                # - Confirmed Tier-1 physics/hardware faults (>=40) smoothly retain at least
                #   WARNING visibility and can never be suppressed back into INFO by Tier-2
                # - Subtle multi-feature drifts benefit from Tier-2 early-warning detection
                # - When Tier-1 reports completely nominal telemetry (<12), require strong
                #   ML consensus (>=80) before crossing WARNING so minor noise cannot
                #   produce contradictory "WARNING + metrics nominal" alerts
                blended = 0.50 * t1.score + 0.50 * s2
                if t1.score >= 40.0:
                    blended = max(blended, 40.0 + 0.85 * (t1.score - 40.0))
                elif t1.score < 12.0:
                    if s2 < 75.0:
                        blended = min(blended, 0.55 * t1.score + 0.45 * s2, 38.0)
                    else:
                        blended = min(blended, 0.45 * t1.score + 0.55 * s2)
                final_score = _clamp(blended - (offset if blended < 35.0 else 0.0), 0.0, 100.0)
                tier_scores = {"tier1_physics": round(t1.score, 2), "tier2_ml": round(s2, 2)}
                agreement = 1.0 - abs(t1.score - s2) / 100.0
            else:
                final_score = _clamp(t1.score - (offset if t1.score < 35.0 else 0.0), 0.0, 100.0)
                tier_scores = {"tier1_physics": round(t1.score, 2)}
                agreement = 0.75

            if final_score >= 70.0:
                severity = "CRITICAL"
                horizon = 24
            elif final_score >= 40.0:
                severity = "WARNING"
                horizon = min(t1.horizon_hours, 48) if final_score >= 55.0 else t1.horizon_hours
            else:
                severity = "INFO"
                horizon = 72

            reasons = list(t1.reasons)
            action = t1.recommended_action
            if severity in ("WARNING", "CRITICAL") and t1.score < 20.0 and idx in ml_probs:
                # Never pair an elevated severity with a "metrics nominal / quiet"
                # fallback sentence from Tier-1; surface the driving ML features.
                nominal_markers = (
                    "metrics nominal",
                    "pfc/ecn quiet",
                    "within peer baseline",
                )
                reasons = [
                    r for r in reasons if not any(m in r.lower() for m in nominal_markers)
                ]
                clf = self.classifiers.get(feat.family)
                if clf is not None:
                    fmap = feat.as_dict()
                    for fname, _delta in clf.explain_one(feat.values, feat.feature_names, top_k=2):
                        val = fmap.get(fname, 0.0)
                        reasons.append(f"ML pattern driver: {fname.replace('_', ' ')} ({val:.2f})")
                if not reasons:
                    reasons.append(f"ML ensemble anomaly score ({tier_scores.get('tier2_ml', 0.0):.1f}/100)")
                if action.lower().startswith("no action required"):
                    action = (
                        "Review multi-feature telemetry trend on this entity during the next "
                        "maintenance window; ML precursor model detected an off-baseline pattern."
                    )

            # Confidence grows with multi-sample depth, peer group size, and Tier 1/2 agreement
            depth_factor = min(1.0, 0.45 + 0.11 * min(feat.sample_count, 5))
            peer_factor = 1.0 if feat.peer_group_size >= 4 else (0.9 if feat.peer_group_size >= 2 else 0.8)
            confidence = _clamp(0.45 * agreement + 0.35 * depth_factor + 0.20 * peer_factor, 0.35, 0.99)

            signals.append(
                PredictiveRiskSignal(
                    entity_key=feat.entity_key,
                    device=feat.device,
                    port=feat.port,
                    family=feat.family,
                    domains=list(feat.domains),
                    risk_score=final_score,
                    severity=severity,
                    horizon_hours=horizon,
                    confidence=confidence,
                    top_reasons=reasons[:5],
                    peer_zscore=feat.peer_zscore,
                    slope_metrics=dict(feat.slope_metrics),
                    recommended_action=action,
                    role_classification=t1.role_classification,
                    tier_scores=tier_scores,
                    timestamp=feat.timestamp,
                )
            )

        signals.sort(key=lambda s: (-s.risk_score, s.family, s.entity_key))
        return signals

    def predict_signals(self, snapshot: LLDPqSnapshot) -> list[PredictiveRiskSignal]:
        """Extract features from ``snapshot`` and return ranked ``PredictiveRiskSignal`` list."""
        features = self.extractor.extract_all(snapshot)
        return self.predict_features(features)

    # ---- Compact JSON Serialization + Optional ONNX Export ----

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "metadata": dict(self.metadata),
            "feature_names": {fam: list(names) for fam, names in FEATURE_NAMES_BY_FAMILY.items()},
            "classifiers": {fam: clf.to_dict() for fam, clf in self.classifiers.items()},
            "calibrations": {fam: cal.to_dict() for fam, cal in self.calibrations.items()},
        }

    def save(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return out

    @classmethod
    def load(cls, path: str | Path) -> "PredictiveRiskModel":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        model = cls(backend="native_gbdt")
        model.metadata = dict(payload.get("metadata") or {})
        for fam, cdata in (payload.get("classifiers") or {}).items():
            if isinstance(cdata, Mapping) and cdata.get("backend") != "untrained":
                model.classifiers[str(fam)] = _FamilyClassifier.from_dict(cdata)
        for fam, caldata in (payload.get("calibrations") or {}).items():
            if isinstance(caldata, Mapping):
                model.calibrations[str(fam)] = BaselineCalibration.from_dict(caldata)
        return model

    def export_onnx(self, output_dir: str | Path) -> dict[str, str]:
        """Export trained LightGBM/sklearn classifiers to ONNX when optional exporters exist.

        Returns a map of ``family -> exported_file_path``; gracefully emits a
        JSON descriptor when ``onnxmltools``/``skl2onnx`` are absent.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        exported: dict[str, str] = {}
        for fam, clf in self.classifiers.items():
            n_feat = len(FEATURE_NAMES_BY_FAMILY[fam])
            if clf.backend == "sklearn" and clf._model is not None:
                try:
                    from skl2onnx import convert_sklearn
                    from skl2onnx.common.data_types import FloatTensorType

                    onnx_model = convert_sklearn(
                        clf._model, initial_types=[("features", FloatTensorType([None, n_feat]))]
                    )
                    target = out_dir / f"predictive_{fam}.onnx"
                    target.write_bytes(onnx_model.SerializeToString())
                    exported[fam] = str(target)
                    continue
                except ImportError:
                    pass
            # Fallback portable JSON tree artifact
            target = out_dir / f"predictive_{fam}.json"
            target.write_text(json.dumps(clf.to_dict(), separators=(",", ":")), encoding="utf-8")
            exported[fam] = str(target)
        return exported


# ---------------------------------------------------------------------------
# Physics-Grounded Synthetic Trajectory Generator (Zero Train/Serve Skew)
# ---------------------------------------------------------------------------


@dataclass
class LabeledDataset:
    """Per-family labeled feature matrix with early-warning lead-time metadata."""

    family: str
    feature_names: tuple[str, ...]
    X: list[list[float]] = field(default_factory=list)
    y: list[int] = field(default_factory=list)
    lead_time_hours: list[float] = field(default_factory=list)
    scenarios: list[str] = field(default_factory=list)
    weights: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def generate_synthetic_trajectories(
    *,
    samples_per_family: int = 500,
    seed: int = 42,
) -> dict[str, LabeledDataset]:
    """Generate physics-calibrated healthy and pre-failure trajectories for all 3 families.

    Constructs genuine ``LLDPqSnapshot`` time-series and runs them through
    ``FeatureExtractor`` so feature definitions, slopes, peer MAD-scores, and
    cross-domain interactions match live inference 100%.
    """
    rng = random.Random(seed)
    extractor = FeatureExtractor()
    base_ts = 1_760_000_000.0

    datasets: dict[str, LabeledDataset] = {
        fam: LabeledDataset(family=fam, feature_names=FEATURE_NAMES_BY_FAMILY[fam])
        for fam in ALL_FAMILIES
    }

    # --- Family A: Physical / Optical / BER / Flap ---
    n_pos_a = samples_per_family // 2
    for idx in range(samples_per_family):
        is_pos = idx < n_pos_a
        snap = LLDPqSnapshot(timestamp=base_ts + 48 * 3600)
        dev = f"dev-{(idx % 12) + 1:03d}"
        # Mix legacy SFP/QSFP (-3.5..-1.5 dBm, 35mA) and modern 400G/800G PAM4 OSFP (+0.5..+3.2 dBm, 65..350mA)
        is_osfp = (idx % 2 == 0)
        sib_rx_lo, sib_rx_hi = (0.8, 3.0) if is_osfp else (-3.6, -1.6)
        sib_bias_lo, sib_bias_hi = (65.0, 345.0) if is_osfp else (30.0, 44.0)
        sib_ref_dbm = -9.9 if is_osfp else -14.0
        # 5 healthy sibling ports for realistic peer-group statistics
        for sib in range(1, 6):
            base_rx = rng.uniform(sib_rx_lo, sib_rx_hi)
            base_bias = rng.uniform(sib_bias_lo, sib_bias_hi)
            base_temp = rng.uniform(38.0, 56.0)
            sib_raw_ber_exp = rng.uniform(-12.5, -6.7) if is_osfp else rng.uniform(-12.5, -8.5)
            pts: list[PhysicalPortSample] = []
            for h in range(0, 49, 8):
                rx_v = base_rx + rng.gauss(0.0, 0.12)
                pts.append(
                    PhysicalPortSample(
                        device=dev,
                        port=f"swp{sib}s0",
                        timestamp=base_ts + h * 3600,
                        rx_power_dbm=rx_v,
                        tx_power_dbm=(rng.uniform(0.5, 3.2) if is_osfp else rng.uniform(-2.4, -1.2)) + rng.gauss(0.0, 0.08),
                        bias_current_ma=base_bias + rng.gauss(0.0, 0.25),
                        temperature_c=base_temp + rng.gauss(0.0, 0.6),
                        voltage_v=3.28 + rng.gauss(0.0, 0.025),
                        link_margin_db=rx_v - sib_ref_dbm,
                        raw_ber=10 ** _clamp(sib_raw_ber_exp + rng.gauss(0.0, 0.08), -13.0, -6.6),
                        effective_ber=1e-15,
                        symbol_error_delta=0,
                        health_status="excellent",
                        ber_grade="excellent",
                    )
                )
            snap.physical[f"{dev}:swp{sib}s0"] = pts

        target_port = "swp8s0"
        target_key = f"{dev}:{target_port}"
        pts = []
        if not is_pos:
            # Include healthy 400G/800G PAM4 hard negatives with static pre-FEC raw BER
            # up to ~2.5e-7 (well below LLDPq's 1e-6 warning threshold) and wide TX/bias range.
            is_pam4_hard_neg = is_osfp and (idx % 4 == 0)
            scenario = "healthy_pam4_high_bias_baseline" if is_pam4_hard_neg else "healthy_noisy_optical"
            lead_h = 0.0
            base_rx = rng.uniform(sib_rx_lo - 0.6, sib_rx_hi)
            base_bias = rng.uniform(sib_bias_lo, sib_bias_hi)
            base_temp = rng.uniform(36.0, 58.0)
            base_tx = rng.uniform(0.2, 3.3) if is_osfp else rng.uniform(-2.6, -1.2)
            base_raw_exp = rng.uniform(-8.5, -6.65) if is_pam4_hard_neg else rng.uniform(-12.5, -8.3)
            for h in range(0, 49, 8):
                rx_v = base_rx + rng.gauss(0.0, 0.16)
                pts.append(
                    PhysicalPortSample(
                        device=dev,
                        port=target_port,
                        timestamp=base_ts + h * 3600,
                        rx_power_dbm=rx_v,
                        tx_power_dbm=base_tx + rng.gauss(0.0, 0.08),
                        bias_current_ma=base_bias + rng.gauss(0.0, 0.35),
                        temperature_c=base_temp + rng.gauss(0.0, 0.8),
                        voltage_v=3.28 + rng.gauss(0.0, 0.025),
                        link_margin_db=rx_v - sib_ref_dbm,
                        raw_ber=10 ** _clamp(base_raw_exp + rng.gauss(0.0, 0.08), -13.0, -6.55),
                        effective_ber=1e-15,
                        symbol_error_delta=0,
                        flaps_1h=0,
                        flaps_24h=0,
                        health_status="excellent",
                        ber_grade="excellent",
                    )
                )
        else:
            mode = idx % 6
            if mode == 0:
                # Gradual laser aging + RX decay + BER climb BEFORE hard threshold
                scenario = "laser_aging_precursor"
                lead_h = rng.uniform(24.0, 72.0)
                rx0 = rng.uniform(0.5, 2.0) if is_osfp else rng.uniform(-3.5, -2.0)
                rx_drop = rng.uniform(0.9, 2.4)  # dB / 24h
                bias0 = rng.uniform(sib_bias_lo, sib_bias_hi * 0.9)
                bias_rise = rng.uniform(2.8, 7.5)  # mA / 24h
                ber0 = rng.uniform(-11.2, -9.2)
                ber_rise = rng.uniform(1.2, 2.6)  # decades / 24h
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx0 - rx_drop * d + rng.gauss(0.0, 0.1)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.6 if is_osfp else -2.0) - 0.3 * d,
                            bias_current_ma=bias0 + bias_rise * d + rng.gauss(0.0, 0.2),
                            temperature_c=44.0 + 2.5 * d,
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** _clamp(ber0 + ber_rise * d, -13.0, -4.8),
                            effective_ber=1e-15 if d < 1.5 else 10 ** rng.uniform(-12.0, -10.0),
                            symbol_error_delta=int(max(0, (d - 0.5) * rng.uniform(20, 200))),
                        )
                    )
            elif mode == 1:
                # Dirty/bent fiber connector: low peer RX + pre-FEC BER above 1e-6 warning band
                scenario = "dirty_fiber_connector"
                lead_h = rng.uniform(18.0, 60.0)
                rx_base = rng.uniform(-7.0, -3.5) if is_osfp else rng.uniform(-11.8, -7.8)
                ber0 = rng.uniform(-6.8, -5.8)
                ber_rise = rng.uniform(0.4, 1.5)
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx_base - rng.uniform(0.2, 0.8) * d + rng.gauss(0.0, 0.12)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.7 if is_osfp else -2.0) + rng.gauss(0.0, 0.1),
                            bias_current_ma=rng.uniform(sib_bias_lo, sib_bias_hi) + rng.gauss(0.0, 0.3),
                            temperature_c=45.0 + rng.gauss(0.0, 0.8),
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** _clamp(ber0 + ber_rise * d, -12.0, -4.5),
                            effective_ber=10 ** rng.uniform(-11.2, -8.5) if idx % 3 == 0 else 1e-15,
                            symbol_error_delta=int(rng.uniform(35, 450)),
                            crc_errors_rate=rng.uniform(0.2, 4.0) if idx % 2 == 0 else 0.0,
                        )
                    )
            elif mode == 2:
                # Intermittent carrier flaps + CRC/FCS error escalation
                scenario = "link_flap_crc_onset"
                lead_h = rng.uniform(12.0, 48.0)
                f1 = rng.randint(2, 18)
                f24 = f1 + rng.randint(3, 40)
                rx_base = rng.uniform(sib_rx_lo, sib_rx_hi) if idx % 2 == 0 else -5.2
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx_base - 0.3 * d + rng.gauss(0.0, 0.1)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.7 if is_osfp else -2.1) + rng.gauss(0.0, 0.1),
                            bias_current_ma=rng.uniform(sib_bias_lo, sib_bias_hi) + 1.2 * d,
                            temperature_c=48.0 + 1.5 * d,
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** rng.uniform(-7.0, -5.0),
                            effective_ber=10 ** rng.uniform(-10.8, -8.5) if idx % 2 == 1 else 1e-15,
                            flaps_1h=f1 if h == 48 else 0,
                            flaps_24h=f24 if h >= 24 else 1,
                            crc_errors_rate=rng.uniform(0.8, 8.0) if h >= 32 and idx % 2 == 1 else 0.0,
                        )
                    )
            elif mode == 3:
                # Fabric-check FEC/MTU mismatch driving post-FEC degradation
                scenario = "fabric_mismatch_ber"
                lead_h = rng.uniform(16.0, 54.0)
                rx_base = rng.uniform(sib_rx_lo, sib_rx_hi)
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx_base + rng.gauss(0.0, 0.1)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.7 if is_osfp else -2.0) + rng.gauss(0.0, 0.1),
                            bias_current_ma=rng.uniform(sib_bias_lo, sib_bias_hi),
                            temperature_c=44.0 + rng.gauss(0.0, 0.8),
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** _clamp(-7.2 + 1.1 * d, -12.0, -4.8),
                            effective_ber=10 ** rng.uniform(-10.5, -8.0),
                            fec_mismatch=(idx % 2 == 0),
                            mtu_mismatch=(idx % 2 == 1),
                            symbol_error_delta=int(rng.uniform(40, 300)),
                        )
                    )
            elif mode == 4:
                # Pure optical RX power decay slope + elevated module temp (pre-BER failure)
                scenario = "rx_decay_only_precursor"
                lead_h = rng.uniform(18.0, 60.0)
                rx0 = rng.uniform(0.5, 2.2) if is_osfp else rng.uniform(-3.0, -1.5)
                rx_drop = rng.uniform(1.8, 7.0)  # steep daily RX loss
                mod_t = rng.uniform(58.0, 69.0)
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx0 - rx_drop * d + rng.gauss(0.0, 0.12)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.7 if is_osfp else -1.9) + rng.gauss(0.0, 0.1),
                            bias_current_ma=rng.uniform(sib_bias_lo, sib_bias_hi) + rng.uniform(0.5, 3.0) * d,
                            temperature_c=mod_t + rng.gauss(0.0, 0.5),
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** rng.uniform(-12.0, -8.5),
                            effective_ber=1e-15,
                            flaps_1h=1 if (h == 48 and idx % 2 == 0) else 0,
                            flaps_24h=2 if (h >= 24 and idx % 2 == 0) else 0,
                        )
                    )
            else:
                # Sustained high-flap / bias-drift instability without static BER alarm
                scenario = "bias_flap_instability"
                lead_h = rng.uniform(12.0, 48.0)
                f1 = rng.randint(1, 8)
                f24 = f1 + rng.randint(5, 24)
                rx_base = (sib_rx_lo - rng.uniform(2.5, 5.5)) if idx % 2 == 0 else rng.uniform(sib_rx_lo, sib_rx_hi)
                for h in range(0, 49, 8):
                    d = h / 24.0
                    rx = rx_base - 0.4 * d + rng.gauss(0.0, 0.1)
                    pts.append(
                        PhysicalPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + h * 3600,
                            rx_power_dbm=rx,
                            tx_power_dbm=(1.7 if is_osfp else -1.9) + rng.gauss(0.0, 0.1),
                            bias_current_ma=(sib_bias_hi * 1.15 if is_osfp else 78.0) + rng.uniform(1.5, 4.0) * d,
                            temperature_c=rng.uniform(50.0, 66.0),
                            voltage_v=3.28 + rng.gauss(0.0, 0.025),
                            link_margin_db=rx - sib_ref_dbm,
                            raw_ber=10 ** rng.uniform(-10.0, -5.8),
                            effective_ber=1e-15,
                            flaps_1h=f1 if h == 48 else 0,
                            flaps_24h=f24 if h >= 24 else 1,
                        )
                    )
        snap.physical[target_key] = pts
        for ef in extractor.extract_physical(snap):
            if ef.entity_key == target_key:
                ds = datasets[FAMILY_PHYSICAL]
                ds.X.append(ef.values)
                ds.y.append(1 if is_pos else 0)
                ds.lead_time_hours.append(lead_h)
                ds.scenarios.append(scenario)
                ds.weights.append(1.0)
                break

    # --- Family B: RoCEv2 Congestion ---
    n_pos_b = samples_per_family // 2
    for idx in range(samples_per_family):
        is_pos = idx < n_pos_b
        snap = LLDPqSnapshot(timestamp=base_ts + 6 * 3600)
        dev = f"dev-{(idx % 12) + 1:03d}"
        # For switch-wide PFC storms (pos mode 3), ALL sibling ports also experience
        # heavy congestion so peer_congestion_mad_zscore stays ~0.0 and the tree
        # ensemble learns absolute PFC/ECN/HOQ/loss signals instead of collapsing
        # onto the peer z-score alone.
        is_switch_wide_storm = is_pos and (idx % 4 == 3)
        is_balanced_healthy_ecn = (not is_pos) and (idx % 3 == 2)
        storm_scale = rng.uniform(1.2, 4.5)
        for sib in range(1, 6):
            cpts: list[CongestionPortSample] = []
            for step in range(6):
                if is_switch_wide_storm:
                    ramp = (step / 5.0) ** 1.6
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=f"swp{sib}s0",
                            timestamp=base_ts + step * 3600,
                            tx_pause_rate=storm_scale * (10.0 + 95.0 * ramp) * rng.uniform(0.85, 1.15),
                            rx_pause_rate=storm_scale * (8.0 + 70.0 * ramp) * rng.uniform(0.85, 1.15),
                            ecn_marked_rate=storm_scale * (60.0 + 350.0 * ramp),
                            ecn_share_percent=rng.uniform(5.0, 20.0) * (0.4 + 0.6 * ramp),
                            rx_buffer_full_rate=storm_scale * 2.0 * ramp,
                            egress_hoq_rate=storm_scale * 3.0 * ramp,
                            signal="combined",
                        )
                    )
                elif is_balanced_healthy_ecn:
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=f"swp{sib}s0",
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=0.0,
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(5.0, 45.0),
                            ecn_share_percent=rng.uniform(0.4, 2.2),
                            signal="ecn",
                        )
                    )
                else:
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=f"swp{sib}s0",
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=0.0,
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(0.0, 5.0),
                            ecn_share_percent=rng.uniform(0.0, 0.35),
                            signal="quiet",
                        )
                    )
            snap.congestion[f"{dev}:swp{sib}s0"] = cpts

        target_port = "swp8s0"
        target_key = f"{dev}:{target_port}"
        cpts = []
        if not is_pos:
            neg_mode = idx % 3
            if neg_mode == 0:
                scenario = "healthy_roce_quiet"
                for step in range(6):
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=0.0,
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(0.0, 10.0),
                            ecn_share_percent=rng.uniform(0.0, 0.5),
                            loss_delta=0,
                            signal="quiet",
                        )
                    )
            elif neg_mode == 1:
                # Hard negative: single port with normal working DCQCN ECN (0.6..2.8%)
                # next to 5 quiet siblings (elevated peer_congestion_mad_zscore, zero PFC/loss/HOQ).
                scenario = "healthy_single_port_dcqcn_ecn"
                base_ecn = rng.uniform(0.7, 2.8)
                for step in range(6):
                    ecn = _clamp(base_ecn + rng.gauss(0.0, 0.2), 0.3, 3.2)
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=0.0,
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(12.0, 95.0),
                            ecn_share_percent=ecn,
                            loss_delta=0,
                            rx_buffer_full_rate=0.0,
                            egress_hoq_rate=0.0,
                            signal="ecn",
                        )
                    )
            else:
                scenario = "healthy_balanced_dcqcn_ecn"
                for step in range(6):
                    ecn = rng.uniform(0.4, 2.2)
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=0.0,
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(8.0, 55.0),
                            ecn_share_percent=ecn,
                            loss_delta=0,
                            signal="ecn",
                        )
                    )
            lead_h = 0.0
        else:
            mode = idx % 4
            if mode == 0:
                # Culprit: accelerating TX pause + rising ECN + rx_buffer_full + HOQ onset
                scenario = "pfc_storm_hoq_culprit"
                lead_h = rng.uniform(12.0, 48.0)
                scale = rng.uniform(1.0, 5.0)
                for step in range(6):
                    ramp = (step / 5.0) ** 2
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            tx_pause_rate=scale * (3.0 + 85.0 * ramp),
                            rx_pause_rate=rng.uniform(0.0, 2.0),
                            ecn_marked_rate=scale * (40.0 + 400.0 * ramp),
                            ecn_share_percent=rng.uniform(4.0, 22.0) * (0.3 + 0.7 * ramp),
                            rx_buffer_full_rate=scale * 2.5 * ramp,
                            egress_hoq_rate=scale * 4.0 * ramp,
                            egress_hoq_stall_rate=scale * 1.2 * ramp,
                            tx_wait_rate=scale * 15.0 * ramp,
                            signal="combined",
                        )
                    )
            elif mode == 1:
                # Lossless queue exhaustion / WRED discards
                scenario = "lossless_buffer_exhaustion"
                lead_h = rng.uniform(8.0, 36.0)
                for step in range(6):
                    ramp = step / 5.0
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            tx_pause_rate=25.0 * ramp + rng.uniform(1.0, 8.0),
                            rx_pause_rate=10.0 * ramp,
                            ecn_marked_rate=180.0 * ramp,
                            ecn_share_percent=rng.uniform(6.0, 18.0),
                            loss_delta=int(rng.uniform(5, 350) * ramp),
                            rx_buffer_full_rate=rng.uniform(1.0, 12.0) * ramp,
                            if_out_discards_rate=rng.uniform(1.0, 25.0) * ramp,
                            signal="loss",
                        )
                    )
            elif mode == 2:
                # Downstream congestion propagating as victim RX pause escalation
                scenario = "pfc_victim_propagation"
                lead_h = rng.uniform(18.0, 48.0)
                scale = rng.uniform(1.0, 4.0)
                for step in range(6):
                    ramp = (step / 5.0) ** 1.7
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            rx_pause_rate=scale * (15.0 + 160.0 * ramp),
                            tx_pause_rate=0.0,
                            ecn_marked_rate=rng.uniform(5.0, 30.0),
                            ecn_share_percent=rng.uniform(0.5, 3.0),
                            signal="pfc",
                        )
                    )
            else:
                # Switch-wide PFC storm: all ports on the switch experience heavy PFC/ECN
                # (peer_congestion_mad_zscore ~= 0.0)
                scenario = "switch_wide_pfc_storm"
                lead_h = rng.uniform(10.0, 36.0)
                for step in range(6):
                    ramp = (step / 5.0) ** 1.6
                    cpts.append(
                        CongestionPortSample(
                            device=dev,
                            port=target_port,
                            timestamp=base_ts + step * 3600,
                            tx_pause_rate=storm_scale * (10.0 + 95.0 * ramp),
                            rx_pause_rate=storm_scale * (8.0 + 70.0 * ramp),
                            ecn_marked_rate=storm_scale * (60.0 + 350.0 * ramp),
                            ecn_share_percent=rng.uniform(5.0, 20.0) * (0.4 + 0.6 * ramp),
                            rx_buffer_full_rate=storm_scale * 2.0 * ramp,
                            egress_hoq_rate=storm_scale * 3.0 * ramp,
                            loss_delta=int(rng.uniform(0, 40) * ramp),
                            signal="combined",
                        )
                    )
        snap.congestion[target_key] = cpts
        for ef in extractor.extract_congestion(snap):
            if ef.entity_key == target_key:
                ds = datasets[FAMILY_CONGESTION]
                ds.X.append(ef.values)
                ds.y.append(1 if is_pos else 0)
                ds.lead_time_hours.append(lead_h)
                ds.scenarios.append(scenario)
                ds.weights.append(1.0)
                break

    # --- Family C: Hardware / BMC / Control Plane ---
    n_pos_c = samples_per_family // 2
    for idx in range(samples_per_family):
        is_pos = idx < n_pos_c
        snap = LLDPqSnapshot(timestamp=base_ts + 48 * 3600)
        ds = datasets[FAMILY_HARDWARE_CONTROL]

        if not is_pos:
            if idx % 3 == 0:
                # Healthy 8-sensor multi-accelerator chassis (all 8 peers tightly clustered)
                scenario = "healthy_sensor_peer_group"
                dev = f"node-{(idx % 8) + 1:03d}"
                amb = rng.uniform(20.0, 24.0)
                base_t = rng.uniform(30.0, 38.0)
                base_p = rng.uniform(72.0, 90.0)
                fan_base = 5200.0
                for g in range(8):
                    sid = f"SXM{g}"
                    snap.sensors[f"{dev}:{sid}"] = [
                        HardwareSensorReading(
                            device=dev,
                            sensor_id=sid,
                            timestamp=base_ts + h * 3600,
                            sensor_type="gpu_sxm",
                            peer_group=f"{dev}:gpu_sxm",
                            temp_c=base_t + rng.gauss(0.0, 1.1),
                            tlimit_c=85.0,
                            ambient_temp_c=amb,
                            power_w=base_p + rng.gauss(0.0, 3.5),
                            fan_rpm=fan_base + rng.gauss(0.0, 140.0),
                            fan_baseline_rpm=fan_base,
                        )
                        for h in (0, 24, 48)
                    ]
                target_key = f"{dev}:SXM3"
            else:
                # Healthy switch hardware + control plane including realistic benign
                # background non-critical syslog errors (0..8 errors, 0 critical, 0 restarts)
                scenario = "healthy_switch_control"
                is_high_tlimit = (idx % 2 == 0)
                base_asic = rng.uniform(62.0, 74.0) if is_high_tlimit else rng.uniform(44.0, 54.0)
                tlim = 105.0 if is_high_tlimit else 90.0
                bg_log_errs = rng.randint(0, 8) if (idx % 2 == 1) else 0
                for sib in range(1, 5):
                    sdev = f"dev-{sib:03d}"
                    snap.hardware_control[sdev] = [
                        HardwareControlSample(
                            device=sdev,
                            device_model="SN5610" if is_high_tlimit else "SN4600",
                            timestamp=base_ts + h * 3600,
                            overall_grade="excellent",
                            cpu_temp_c=rng.uniform(34.0, 48.0) + rng.gauss(0.0, 1.2),
                            asic_temp_c=base_asic + rng.gauss(0.0, 1.8),
                            ambient_temp_c=24.0,
                            tlimit_c=tlim,
                            memory_pct=rng.uniform(13.0, 52.0),
                            load_per_core=rng.uniform(0.02, 0.48),
                            psu_efficiency=rng.uniform(89.0, 94.0),
                            psu_redundancy_ok=True,
                            fan_rpms={"FAN1/1": 5200.0, "FAN2/1": 5180.0, "FAN3/1": 5220.0},
                            fan_baseline_rpm=5200.0,
                            bgp_total_neighbors=16,
                            bgp_established_neighbors=16,
                            bgp_down_neighbors=0,
                            routes_total=420,
                            log_critical_count=0,
                            log_error_count=bg_log_errs if (sib == 1 and h == 48) else 0,
                            log_error_velocity=float(bg_log_errs) if (sib == 1 and h == 48) else 0.0,
                        )
                        for h in (0, 24, 48)
                    ]
                target_key = "dev-001"
            lead_h = 0.0
        else:
            mode = idx % 6
            if mode == 0:
                # Localized cooling fault (6 healthy peers + 2 hot peers + elevated chassis fans)
                scenario = "localized_sensor_cooling_fault"
                lead_h = rng.uniform(24.0, 72.0)
                dev = f"node-{(idx % 8) + 1:03d}"
                amb = rng.uniform(20.0, 24.0)
                cool_t = rng.uniform(30.0, 35.0)
                hot_delta = rng.uniform(15.0, 27.0)
                fan_base = 5200.0
                fan_high = rng.uniform(7400.0, 9000.0)
                for g in range(8):
                    sid = f"SXM{g}"
                    is_hot = g in (3, 4)
                    snap.sensors[f"{dev}:{sid}"] = [
                        HardwareSensorReading(
                            device=dev,
                            sensor_id=sid,
                            timestamp=base_ts + h * 3600,
                            sensor_type="gpu_sxm",
                            peer_group=f"{dev}:gpu_sxm",
                            temp_c=(cool_t + hot_delta + 0.8 * (h / 24.0) if is_hot else cool_t) + rng.gauss(0.0, 0.8),
                            tlimit_c=85.0,
                            ambient_temp_c=amb,
                            power_w=(rng.uniform(80.0, 92.0) if is_hot else rng.uniform(74.0, 84.0)),
                            fan_rpm=fan_high,
                            fan_baseline_rpm=fan_base,
                        )
                        for h in (0, 24, 48)
                    ]
                target_key = f"{dev}:SXM3"
            elif mode == 1:
                # Isolated fan failure and/or PSU fault even while chassis temp is still nominal
                scenario = "isolated_fan_psu_fault"
                lead_h = rng.uniform(12.0, 48.0)
                fault_kind = idx % 3
                for sib in range(1, 5):
                    sdev = f"dev-{sib:03d}"
                    is_bad = sib == 1
                    snap.hardware_control[sdev] = [
                        HardwareControlSample(
                            device=sdev,
                            device_model="SN5610",
                            timestamp=base_ts + h * 3600,
                            overall_grade="critical" if is_bad else "excellent",
                            cpu_temp_c=rng.uniform(36.0, 44.0),
                            asic_temp_c=rng.uniform(64.0, 71.0),
                            ambient_temp_c=24.0,
                            tlimit_c=105.0,
                            memory_pct=rng.uniform(15.0, 40.0),
                            load_per_core=rng.uniform(0.03, 0.35),
                            psu_efficiency=rng.uniform(89.0, 93.0),
                            psu_failed_count=rng.randint(1, 2) if (is_bad and fault_kind in (0, 2)) else 0,
                            psu_redundancy_ok=not (is_bad and fault_kind in (0, 2)),
                            fan_failed_count=rng.randint(1, 2) if (is_bad and fault_kind in (0, 1)) else 0,
                            fan_rpms={"FAN1/1": 5200.0, "FAN2/1": 5200.0, "FAN3/1": 5200.0},
                            fan_baseline_rpm=5200.0,
                            bgp_total_neighbors=16,
                            bgp_established_neighbors=16,
                        )
                        for h in (0, 24, 48)
                    ]
                target_key = "dev-001"
            elif mode == 2:
                # Switch fan tray degradation + rising ASIC temp + PSU efficiency dip
                scenario = "fan_thermal_degradation"
                lead_h = rng.uniform(18.0, 60.0)
                for sib in range(1, 5):
                    sdev = f"dev-{sib:03d}"
                    is_bad = sib == 1
                    snap.hardware_control[sdev] = [
                        HardwareControlSample(
                            device=sdev,
                            device_model="SN4600",
                            timestamp=base_ts + h * 3600,
                            overall_grade="warning" if is_bad else "excellent",
                            cpu_temp_c=(56.0 + 4.5 * (h / 24.0)) if is_bad else 42.0,
                            asic_temp_c=(64.0 + 5.0 * (h / 24.0)) if is_bad else 46.0,
                            ambient_temp_c=24.0,
                            tlimit_c=85.0,
                            memory_pct=rng.uniform(15.0, 50.0),
                            load_per_core=rng.uniform(0.03, 0.45),
                            psu_efficiency=rng.uniform(72.0, 81.0) if is_bad else 92.0,
                            fan_rpms=(
                                {"FAN1/1": rng.uniform(1800.0, 3100.0), "FAN2/1": 6200.0, "FAN3/1": 6300.0}
                                if is_bad
                                else {"FAN1/1": 5200.0, "FAN2/1": 5200.0, "FAN3/1": 5200.0}
                            ),
                            fan_baseline_rpm=5200.0,
                            bgp_total_neighbors=16,
                            bgp_established_neighbors=16,
                        )
                        for h in (0, 24, 48)
                    ]
                target_key = "dev-001"
            elif mode == 3:
                # Isolated BGP session down / flaps / update storms (zero syslog required)
                scenario = "bgp_instability"
                lead_h = rng.uniform(12.0, 48.0)
                dev = "dev-001"
                snap.hardware_control[dev] = [
                    HardwareControlSample(
                        device=dev,
                        device_model="SN5610",
                        timestamp=base_ts + h * 3600,
                        cpu_temp_c=40.0,
                        asic_temp_c=rng.uniform(48.0, 68.0),
                        ambient_temp_c=24.0,
                        tlimit_c=105.0,
                        memory_pct=rng.uniform(15.0, 50.0),
                        load_per_core=rng.uniform(0.04, 0.40),
                        psu_efficiency=91.0,
                        fan_rpms={"FAN1/1": 5200.0, "FAN2/1": 5200.0},
                        fan_baseline_rpm=5200.0,
                        bgp_total_neighbors=32,
                        bgp_established_neighbors=24 if h == 48 else 32,
                        bgp_down_neighbors=rng.randint(1, 16) if h == 48 else 0,
                        bgp_flaps_1h=rng.randint(2, 12) if h == 48 else 0,
                        bgp_flaps_24h=rng.randint(4, 24),
                        bgp_update_storms=1 if (h == 48 and idx % 2 == 0) else 0,
                        routes_total=420,
                    )
                    for h in (0, 24, 48)
                ]
                target_key = dev
            elif mode == 4:
                # Isolated EVPN-MH desync / bypass / LACP desync + Route drop / VRF loss
                scenario = "evpn_route_instability"
                lead_h = rng.uniform(12.0, 48.0)
                dev = "dev-001"
                snap.hardware_control[dev] = [
                    HardwareControlSample(
                        device=dev,
                        device_model="SN5610",
                        timestamp=base_ts + h * 3600,
                        cpu_temp_c=41.0,
                        asic_temp_c=rng.uniform(50.0, 68.0),
                        ambient_temp_c=24.0,
                        tlimit_c=105.0,
                        memory_pct=rng.uniform(15.0, 48.0),
                        load_per_core=rng.uniform(0.04, 0.40),
                        psu_efficiency=91.0,
                        fan_rpms={"FAN1/1": 5200.0, "FAN2/1": 5200.0},
                        fan_baseline_rpm=5200.0,
                        bgp_total_neighbors=16,
                        bgp_established_neighbors=16,
                        evpn_mh_critical_es=rng.randint(1, 4) if h == 48 else 0,
                        lacp_desync_count=rng.randint(1, 3) if (h == 48 and idx % 2 == 0) else 0,
                        routes_total=320,
                        routes_drop_fraction=rng.uniform(0.20, 0.50) if (h == 48 and idx % 2 == 1) else 0.0,
                        vrf_disappeared_count=1 if (h == 48 and idx % 4 == 1) else 0,
                    )
                    for h in (0, 24, 48)
                ]
                target_key = dev
            else:
                # Duplicate MAC/IP mobility storm + BMC anomalies + critical syslog / watchdog restarts
                scenario = "dup_mac_bmc_watchdog_storm"
                lead_h = rng.uniform(12.0, 48.0)
                dev = "dev-001"
                snap.hardware_control[dev] = [
                    HardwareControlSample(
                        device=dev,
                        device_model="SN5610",
                        timestamp=base_ts + h * 3600,
                        cpu_temp_c=42.0,
                        asic_temp_c=rng.uniform(48.0, 68.0),
                        ambient_temp_c=24.0,
                        tlimit_c=105.0,
                        memory_pct=rng.uniform(16.0, 52.0),
                        load_per_core=rng.uniform(0.04, 0.45),
                        psu_efficiency=91.0,
                        fan_rpms={"FAN1/1": 5200.0, "FAN2/1": 5200.0},
                        fan_baseline_rpm=5200.0,
                        bmc_mismatch_count=rng.randint(1, 3) if h == 48 else 0,
                        bmc_port_down_count=rng.randint(0, 2) if h == 48 else 0,
                        dup_ip_active=rng.randint(1, 3) if h == 48 else 0,
                        dup_mac_confirmed=rng.randint(1, 2) if h == 48 else 0,
                        mac_move_rate=rng.uniform(15.0, 250.0) if h == 48 else 0.0,
                        log_critical_count=rng.randint(1, 4) if h == 48 else 0,
                        log_error_velocity=rng.uniform(12.0, 40.0) if h == 48 else 0.0,
                        critical_service_restarts_24h=rng.randint(1, 2) if h == 48 else 0,
                    )
                    for h in (0, 24, 48)
                ]
                target_key = dev

        for ef in extractor.extract_hardware_control(snap):
            if ef.entity_key == target_key:
                ds.X.append(ef.values)
                ds.y.append(1 if is_pos else 0)
                ds.lead_time_hours.append(lead_h)
                ds.scenarios.append(scenario)
                ds.weights.append(1.0)
                break

    return datasets


# ---------------------------------------------------------------------------
# Self-Supervised Label Extraction from Sanitized Live LLDPq Snapshots
# ---------------------------------------------------------------------------


def extract_self_supervised_examples(
    snapshot: LLDPqSnapshot,
    *,
    min_prefix_samples: int = 2,
) -> dict[str, LabeledDataset]:
    """Derive historical lead-time training examples from an anonymized live snapshot.

    Whenever an entity's multi-sample series genuinely transitions from a known
    nominal state (``excellent``/``good``/``ok``) into a persisted
    ``WARNING``/``CRITICAL``/``loss``/``down`` grade at timestamp ``t_fail``,
    slices the earlier telemetry-backed prefix ``t < t_fail`` as a positive
    precursor example (preserving same-device peer context and exact observed
    lead time in hours). Continuously healthy entities supply fleet-calibrated
    negative baseline examples with full peer-group statistics.
    """
    extractor = FeatureExtractor()
    datasets: dict[str, LabeledDataset] = {
        fam: LabeledDataset(
            family=fam,
            feature_names=FEATURE_NAMES_BY_FAMILY[fam],
            metadata={"raw_grade_transitions": 0, "skipped_no_telemetry_transitions": 0},
        )
        for fam in ALL_FAMILIES
    }
    bad_grades = {"warning", "critical", "down", "bad", "failed", "loss"}
    healthy_grades = {"excellent", "good", "ok"}
    non_analyzed_cong = {"collection_error", "first_sample"}

    # Pre-index physical series by device for sibling peer-group context during prefix slicing
    phys_by_dev: dict[str, list[tuple[str, list[PhysicalPortSample]]]] = {}
    for k, ser in snapshot.physical.items():
        if ser:
            phys_by_dev.setdefault(ser[-1].device, []).append((k, ser))

    # Extract full-snapshot features ONCE for healthy baseline negatives (preserves true peer MAD-Z!)
    full_phys_feats = {ef.entity_key: ef for ef in extractor.extract_physical(snapshot)}
    full_cong_feats = {ef.entity_key: ef for ef in extractor.extract_congestion(snapshot)}
    full_hw_feats = {ef.entity_key: ef for ef in extractor.extract_hardware_control(snapshot)}

    # Physical self-supervised transitions
    ds_phys = datasets[FAMILY_PHYSICAL]
    for key, series in snapshot.physical.items():
        if len(series) < min_prefix_samples:
            continue
        opt_healthy_seen = 0
        ber_healthy_seen = 0
        flap_healthy_seen = 0
        fail_idx: int | None = None
        fail_kind = ""
        any_bad_ever = False
        for i, s in enumerate(series):
            if s.health_status in bad_grades:
                any_bad_ever = True
                if opt_healthy_seen >= min_prefix_samples:
                    fail_idx = i
                    fail_kind = "optical"
                    break
            elif s.health_status in healthy_grades and (s.rx_power_dbm is not None or s.bias_current_ma is not None):
                opt_healthy_seen += 1

            if s.ber_grade in bad_grades:
                any_bad_ever = True
                if ber_healthy_seen >= min_prefix_samples:
                    fail_idx = i
                    fail_kind = "ber"
                    break
            elif s.ber_grade in healthy_grades:
                ber_healthy_seen += 1

            if s.flaps_1h >= 3:
                any_bad_ever = True
                if flap_healthy_seen >= min_prefix_samples:
                    fail_idx = i
                    fail_kind = "flap"
                    break
            else:
                flap_healthy_seen += 1

        if fail_idx is not None:
            ds_phys.metadata["raw_grade_transitions"] += 1
            prefix = series[:fail_idx]
            t_cut = prefix[-1].timestamp
            lead_h = max(0.15, (series[fail_idx].timestamp - t_cut) / 3600.0)
            sub_phys: dict[str, list[PhysicalPortSample]] = {key: prefix}
            for sib_k, sib_ser in phys_by_dev.get(prefix[-1].device, ()):
                if sib_k == key:
                    continue
                sib_pre = [x for x in sib_ser if x.timestamp <= t_cut]
                if sib_pre:
                    sub_phys[sib_k] = sib_pre
            sub = LLDPqSnapshot(timestamp=t_cut, physical=sub_phys)
            for ef in extractor.extract_physical(sub):
                if ef.entity_key == key:
                    # Skip abrupt step transitions (e.g. sudden cable unplug on a flat
                    # healthy port) that carry zero physical precursor signal so healthy
                    # OSFP operating points are not poisoned as positive labels.
                    ef_d = ef.as_dict()
                    has_precursor_signal = (
                        ef_d["rx_power_slope_24h"] < -0.25
                        or ef_d["bias_current_slope_24h"] > 0.5
                        or ef_d["log10_ber_slope_24h"] > 0.25
                        or ef_d["log10_raw_ber"] > -6.5
                        or ef_d["symbol_error_rate_log1p"] > 0.5
                        or ef_d["flaps_24h"] >= 2.0
                        or ef_d["peer_rx_mad_zscore"] < -2.5
                        or ef_d["link_margin_db"] < 4.5
                    )
                    if not has_precursor_signal:
                        ds_phys.metadata["skipped_no_telemetry_transitions"] += 1
                        break
                    ds_phys.X.append(ef.values)
                    ds_phys.y.append(1)
                    ds_phys.lead_time_hours.append(lead_h)
                    ds_phys.scenarios.append(f"live_self_supervised_{fail_kind}")
                    ds_phys.weights.append(2.0)
                    break
        elif not any_bad_ever and (opt_healthy_seen >= min_prefix_samples or ber_healthy_seen >= min_prefix_samples):
            ef = full_phys_feats.get(key)
            if ef is not None:
                ds_phys.X.append(ef.values)
                ds_phys.y.append(0)
                ds_phys.lead_time_hours.append(0.0)
                ds_phys.scenarios.append("live_healthy_baseline")
                ds_phys.weights.append(1.0)

    # Congestion self-supervised transitions (ignoring collection_error / first_sample rows)
    ds_cong = datasets[FAMILY_CONGESTION]
    for key, series in snapshot.congestion.items():
        analyzed = [
            s for s in series if s.sample_status not in non_analyzed_cong and s.signal not in non_analyzed_cong
        ]
        if len(analyzed) < min_prefix_samples:
            continue
        quiet_seen = 0
        fail_idx = None
        any_bad = False
        for i, s in enumerate(analyzed):
            if s.signal in {"loss", "combined"} or s.loss_delta > 0 or s.egress_hoq_rate > 0:
                any_bad = True
                if quiet_seen >= min_prefix_samples:
                    fail_idx = i
                    break
            else:
                quiet_seen += 1
        if fail_idx is not None:
            ds_cong.metadata["raw_grade_transitions"] += 1
            prefix = analyzed[:fail_idx]
            lead_h = max(0.5, (analyzed[fail_idx].timestamp - prefix[-1].timestamp) / 3600.0)
            sub = LLDPqSnapshot(timestamp=prefix[-1].timestamp, congestion={key: prefix})
            for ef in extractor.extract_congestion(sub):
                ds_cong.X.append(ef.values)
                ds_cong.y.append(1)
                ds_cong.lead_time_hours.append(lead_h)
                ds_cong.scenarios.append("live_self_supervised_congestion")
                ds_cong.weights.append(2.0)
        elif not any_bad:
            ef = full_cong_feats.get(key)
            if ef is not None:
                ds_cong.X.append(ef.values)
                ds_cong.y.append(0)
                ds_cong.lead_time_hours.append(0.0)
                ds_cong.scenarios.append("live_healthy_baseline")
                ds_cong.weights.append(1.0)

    # Hardware / Control-plane self-supervised transitions
    ds_hw = datasets[FAMILY_HARDWARE_CONTROL]
    for dev, series in snapshot.hardware_control.items():
        if len(series) < min_prefix_samples:
            continue
        healthy_seen = 0
        fail_idx = None
        any_bad = False
        for i, s in enumerate(series):
            is_bad = (
                s.overall_grade in bad_grades
                or s.bgp_down_neighbors > 0
                or s.vrf_disappeared_count > 0
                or s.psu_failed_count > 0
                or s.fan_failed_count > 0
            )
            if is_bad:
                any_bad = True
                if healthy_seen >= min_prefix_samples:
                    fail_idx = i
                    break
            elif s.overall_grade in healthy_grades or s.bgp_total_neighbors > 0 or s.asic_temp_c is not None:
                healthy_seen += 1

        if fail_idx is not None:
            ds_hw.metadata["raw_grade_transitions"] += 1
            prefix = series[:fail_idx]
            # Only emit a supervised training row when prefix actually carries numeric sensor/control telemetry
            # (grade-only hardware_history rows without temps/PSU/fans/BGP would otherwise emit all-default vectors).
            has_numeric_telemetry = any(
                p.asic_temp_c is not None
                or p.cpu_temp_c is not None
                or p.psu_efficiency is not None
                or bool(p.fan_rpms)
                or p.memory_pct is not None
                or p.load_per_core is not None
                or p.bgp_total_neighbors > 0
                or p.routes_drop_fraction >= 0.05
                or p.vrf_disappeared_count > 0
                for p in prefix
            )
            if not has_numeric_telemetry:
                ds_hw.metadata["skipped_no_telemetry_transitions"] += 1
                continue
            lead_h = max(0.5, (series[fail_idx].timestamp - prefix[-1].timestamp) / 3600.0)
            sub = LLDPqSnapshot(timestamp=prefix[-1].timestamp, hardware_control={dev: prefix})
            for ef in extractor.extract_hardware_control(sub):
                ds_hw.X.append(ef.values)
                ds_hw.y.append(1)
                ds_hw.lead_time_hours.append(lead_h)
                ds_hw.scenarios.append("live_self_supervised_hw_control")
                ds_hw.weights.append(2.0)
        elif not any_bad and healthy_seen >= min_prefix_samples:
            ef = full_hw_feats.get(dev)
            if ef is not None:
                # Only use switches that carry real hardware/control telemetry as healthy live baselines
                if any(
                    p.asic_temp_c is not None or p.cpu_temp_c is not None or p.bgp_total_neighbors > 0
                    for p in series
                ):
                    ds_hw.X.append(ef.values)
                    ds_hw.y.append(0)
                    ds_hw.lead_time_hours.append(0.0)
                    ds_hw.scenarios.append("live_healthy_baseline")
                    ds_hw.weights.append(1.0)

    return datasets
