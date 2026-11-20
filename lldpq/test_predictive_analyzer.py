#!/usr/bin/env python3
"""Unit & integration tests for LLDPq Multi-Domain Predictive Health."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(ROOT_DIR / "html"))

import ai_correlate  # noqa: E402
import ber_analyzer  # noqa: E402
import generate_hardware_html  # noqa: E402
import predictive_analyzer  # noqa: E402
from predictive_engine import (  # noqa: E402
    ALL_FAMILIES,
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
    FAMILY_PHYSICAL,
    CongestionPortSample,
    FeatureExtractor,
    HardwareControlSample,
    HardwareSensorReading,
    LLDPqSnapshot,
    LLDPqSnapshotLoader,
    PhysicalPortSample,
    PredictiveRiskModel,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class PredictiveAnalyzerTests(unittest.TestCase):
    def test_bundled_model_valid_and_zero_leak(self):
        model_path = SCRIPT_DIR / "predictive_model.json"
        self.assertTrue(model_path.is_file(), "predictive_model.json must exist")
        raw = model_path.read_text(encoding="utf-8")
        # Zero paths, IPs, hostnames, or site tokens inside shipped model weights
        self.assertNotIn("/tmp/", raw)
        self.assertNotIn("/Users/", raw)
        self.assertNotIn("/home/", raw)
        self.assertIsNone(re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw))
        model = PredictiveRiskModel.load(model_path)
        self.assertTrue(model.is_trained)

    def test_subthreshold_optical_early_warning_and_collection_error_exclusion(self):
        now = 1_763_650_000.0
        with tempfile.TemporaryDirectory() as tmp:
            mr = Path(tmp) / "monitor-results"
            out = Path(tmp) / "out"

            # Healthy peer group of 6 ports + 1 port degrading sharply while still "OK"
            opt_rows = []
            ber_rows = []
            for idx in range(1, 7):
                port = f"swp{idx}"
                opt_rows.append({
                    "device": "leaf-01",
                    "interface": port,
                    "health": "OK",
                    "rx_power_dbm": -1.5,
                    "tx_power_dbm": -1.0,
                    "temperature_c": 42.0,
                    "link_margin_db": 9.5,
                    "voltage_v": 3.30,
                    "bias_current_ma": 48.0,
                })
                ber_rows.append({
                    "device": "leaf-01",
                    "interface": port,
                    "status": "OK",
                    "sample_status": "ok",
                    "raw_ber": 1e-12,
                    "effective_ber": 1e-15,
                    "symbol_error_delta": 0,
                })

            # Port swp7: still nominal raw status, but degraded optical RX + BER climb + high bias
            opt_rows.append({
                "device": "leaf-01",
                "interface": "swp7",
                "health": "OK",
                "rx_power_dbm": -8.8,
                "tx_power_dbm": -1.2,
                "temperature_c": 63.0,
                "link_margin_db": 2.1,
                "voltage_v": 3.31,
                "bias_current_ma": 92.0,
            })
            ber_rows.append({
                "device": "leaf-01",
                "interface": "swp7",
                "status": "OK",
                "sample_status": "ok",
                "raw_ber": 4e-6,
                "effective_ber": 1e-12,
                "symbol_error_delta": 5000,
            })
            # Port swp8: collection_error on pfc-ecn must NOT trigger false alarm
            pfc_rows = [
                {
                    "device": "leaf-01",
                    "interface": "swp8",
                    "status": "OK",
                    "sample_status": "collection_error",
                    "rx_pause_rate": 0.0,
                    "tx_pause_rate": 0.0,
                    "ecn_marked_rate": 0.0,
                    "loss_delta": 0,
                }
            ]
            _write_json(mr / "export" / "optical.json", {"rows": opt_rows})
            _write_json(mr / "export" / "ber.json", {"rows": ber_rows})
            _write_json(mr / "export" / "pfc-ecn.json", {"rows": pfc_rows})

            result = predictive_analyzer.analyze_monitor_results(
                mr, output_dir=out, now=now
            )
            self.assertGreaterEqual(result["counts"]["actionable"], 1)
            export_doc = json.loads((out / "export" / "predictive.json").read_text(encoding="utf-8"))
            summary_doc = json.loads((out / "summary" / "predictive-summary.json").read_text(encoding="utf-8"))

            self.assertEqual(export_doc["domain"], "predictive")
            self.assertEqual(summary_doc["domain"], "predictive")
            flagged_ports = {r["port"]: r for r in export_doc["rows"]}
            self.assertIn("swp7", flagged_ports)
            self.assertTrue(flagged_ports["swp7"]["early_warning"])
            self.assertNotIn("swp8", flagged_ports)
            # File permissions must follow shared CLI/www-data convention (0664)
            self.assertEqual(os.stat(out / "export" / "predictive.json").st_mode & 0o777, 0o664)

    def test_localized_thermal_fault_regression(self):
        """Localized multi-sensor cooling fault (dgx-01 SXM3/4 pattern) caught vs healthy peers."""
        base_ts = 1_763_600_000.0
        sensors = []
        for idx in range(8):
            is_fault = idx in (4, 6)
            sensors.append(
                HardwareSensorReading(
                    device="gpu-node-01",
                    sensor_id=f"gpu{idx}",
                    sensor_type="gpu_temp",
                    peer_group="gpu_sxm_cohort",
                    timestamp=base_ts,
                    temp_c=80.0 if is_fault else 44.0,
                    ambient_temp_c=24.0,
                    power_w=465.0,
                    thermal_margin_c=-2.0 if is_fault else 36.0,
                )
            )
        snap = LLDPqSnapshot(
            timestamp=base_ts,
            hardware_control={
                "gpu-node-01": [
                    HardwareControlSample(
                        device="gpu-node-01",
                        timestamp=base_ts,
                        device_model="HGX-H200",
                        asic_temp_c=80.0,
                        ambient_temp_c=24.0,
                        psu_in_w=4000.0,
                        psu_out_w=3720.0,
                        sensors=sensors,
                    )
                ]
            },
        )
        model = PredictiveRiskModel.load(SCRIPT_DIR / "predictive_model.json")
        signals = model.predict_signals(snap)
        by_key = {s.entity_key: s for s in signals}
        self.assertIn("gpu-node-01:gpu6", by_key)
        self.assertIn("gpu-node-01:gpu4", by_key)
        self.assertIn("gpu-node-01:gpu0", by_key)
        self.assertGreaterEqual(by_key["gpu-node-01:gpu6"].risk_score, 70.0)
        self.assertEqual(by_key["gpu-node-01:gpu6"].severity, "CRITICAL")
        self.assertLess(by_key["gpu-node-01:gpu0"].risk_score, 40.0)

    def test_ai_correlate_collect_predictive_and_age_gating(self):
        now = 1_763_650_000.0
        with tempfile.TemporaryDirectory() as tmp:
            mr = Path(tmp) / "monitor-results"
            # Absent file -> empty list, no errors
            self.assertEqual(ai_correlate._collect_predictive(str(mr), now=now), [])

            # Fresh export/predictive.json -> surfaces CRITICAL + WARNING, skips INFO
            _write_json(
                mr / "export" / "predictive.json",
                {
                    "schema_version": 1,
                    "domain": "predictive",
                    "generated_epoch": now - 60.0,
                    "rows": [
                        {
                            "device": "leaf-01",
                            "port": "swp7",
                            "family": FAMILY_PHYSICAL,
                            "severity": "CRITICAL",
                            "risk_score": 84.5,
                            "horizon_hours": 24,
                            "peer_zscore": 6.2,
                            "early_warning": True,
                            "top_reasons": ["RX power -8.8 dBm", "Raw BER climbing"],
                            "recommended_action": "Clean/replace transceiver on swp7",
                        },
                        {
                            "device": "leaf-02",
                            "port": None,
                            "family": FAMILY_HARDWARE_CONTROL,
                            "severity": "INFO",
                            "risk_score": 12.0,
                            "horizon_hours": 72,
                            "peer_zscore": 0.1,
                            "early_warning": False,
                            "top_reasons": [],
                            "recommended_action": "No action",
                        },
                    ],
                },
            )
            fresh = ai_correlate._collect_predictive(str(mr), now=now)
            self.assertEqual(len(fresh), 1)
            self.assertEqual(fresh[0]["domain"], "predictive")
            self.assertEqual(fresh[0]["device"], "leaf-01")
            self.assertEqual(fresh[0]["port"], "swp7")
            self.assertEqual(ai_correlate.severity_for(fresh[0]), "CRITICAL")
            self.assertIn("EARLY PRECURSOR", fresh[0]["detail"])

            # Stale export (> STALE_RECORD_SECONDS old) -> suppressed
            stale = ai_correlate._collect_predictive(
                str(mr), now=now + ai_correlate.STALE_RECORD_SECONDS + 120.0
            )
            self.assertEqual(stale, [])

    def test_monitor_sh_syntax_and_ui_wiring(self):
        monitor_sh = SCRIPT_DIR / "monitor.sh"
        res = subprocess.run(
            ["bash", "-n", str(monitor_sh)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"monitor.sh syntax error: {res.stderr}")
        index_html = (ROOT_DIR / "html" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="/predictive.html"', index_html)
        pred_html = (ROOT_DIR / "html" / "predictive.html").read_text(encoding="utf-8")
        # Standard LLDPq analysis page contract: table-filter, sortable headers,
        # clickable summary cards, dark autofill override, lifecycle-scope wiring.
        for token in (
            "/css/table-filter.css?v=20260716-tf-3",
            "/css/table-filter.js?v=20260821-tf-6",
            "input:-webkit-autofill",
            'id="predictive-table"',
            'class="sortable',
            'data-card-filter="severity:CRITICAL"',
            'data-card-filter="early"',
            "color: #76b900;",
        ):
            self.assertIn(token, pred_html, f"missing UI standard token: {token}")
        ls_js = (ROOT_DIR / "html" / "lifecycle-scope.js").read_text(encoding="utf-8")
        self.assertIn("'/predictive.html'", ls_js)
        self.assertIn("updatePredictive", ls_js)

    def test_model_split_diversity_no_single_feature_collapse(self):
        doc = json.loads((SCRIPT_DIR / "predictive_model.json").read_text(encoding="utf-8"))
        for fam in ALL_FAMILIES:
            names = doc["feature_names"][fam]
            used = set()

            def walk(node):
                if "f" in node:
                    used.add(names[node["f"]])
                    walk(node["l"])
                    walk(node["r"])

            for tree in doc["classifiers"][fam]["trees"]:
                walk(tree)
            self.assertGreaterEqual(
                len(used), 5,
                f"family {fam} collapsed onto too few features: {sorted(used)}",
            )

    def test_false_positive_and_blindspot_regressions(self):
        """Guard against PAM4 BER FP, normal DCQCN ECN FP, switch-wide PFC storm,
        minor syslog FP, isolated fan/PSU + EVPN-MH detection, resolved 12h-old
        faults staying pinned, and false early_warning on BGP-down switches.
        """
        model = PredictiveRiskModel.load(SCRIPT_DIR / "predictive_model.json")
        ext = FeatureExtractor()
        now = 1_763_650_000.0

        def score_one(snap, key):
            feats = ext.extract_all(snap)
            sigs = {s.entity_key: s for s in model.predict_features(feats)}
            raw_map = predictive_analyzer._build_raw_status_map(snap)
            sig = sigs[key]
            raw_st = raw_map.get((sig.family, key), "unknown")
            early = predictive_analyzer._is_early_warning(sig, raw_st)
            return sig, raw_st, early

        # 1) Healthy 400G/800G PAM4 port (raw_ber=2e-7, bias=320mA, eff_ber=1e-15) -> INFO
        s_pam4 = LLDPqSnapshot(timestamp=now)
        for p in range(1, 7):
            s_pam4.physical[f"dev-a:swp{p}s0"] = [
                PhysicalPortSample(
                    device="dev-a", port=f"swp{p}s0", timestamp=now - 3600 * h,
                    rx_power_dbm=1.8, tx_power_dbm=2.1, bias_current_ma=320.0,
                    temperature_c=48.0, link_margin_db=11.7,
                    raw_ber=2e-7 if p == 1 else 1e-10, effective_ber=1e-15,
                    health_status="excellent", ber_grade="excellent",
                )
                for h in (24, 12, 0)
            ]
        sig, _, early = score_one(s_pam4, "dev-a:swp1s0")
        self.assertEqual(sig.severity, "INFO")
        self.assertFalse(early)

        # 2) Single-port normal DCQCN ECN 1.1% vs 5 quiet peers -> INFO
        s_ecn = LLDPqSnapshot(timestamp=now)
        for p in range(1, 7):
            s_ecn.congestion[f"dev-a:swp{p}s0"] = [
                CongestionPortSample(
                    device="dev-a", port=f"swp{p}s0", timestamp=now - 600 * k,
                    rx_pause_rate=0.0, tx_pause_rate=0.0,
                    ecn_marked_rate=25.0 if p == 1 else 0.0,
                    ecn_share_percent=1.1 if p == 1 else 0.0,
                    signal="ecn" if p == 1 else "quiet",
                )
                for k in (5, 4, 3, 2, 1, 0)
            ]
        sig, _, _ = score_one(s_ecn, "dev-a:swp1s0")
        self.assertEqual(sig.severity, "INFO")

        # 3) Switch-wide ALL-port PFC storm (peer_z = 0.0) -> CRITICAL with high Tier-2
        s_storm = LLDPqSnapshot(timestamp=now)
        for p in range(1, 7):
            s_storm.congestion[f"dev-a:swp{p}s0"] = [
                CongestionPortSample(
                    device="dev-a", port=f"swp{p}s0", timestamp=now - 600 * (5 - k),
                    rx_pause_rate=20.0 + 40.0 * k, tx_pause_rate=30.0 + 50.0 * k,
                    ecn_marked_rate=100.0 + 80.0 * k, ecn_share_percent=12.0,
                    egress_hoq_rate=5.0 * k, signal="combined",
                )
                for k in range(6)
            ]
        sig, raw_st, early = score_one(s_storm, "dev-a:swp1s0")
        self.assertEqual(sig.severity, "CRITICAL")
        self.assertGreaterEqual(sig.tier_scores["tier2_ml"], 70.0)
        self.assertEqual(raw_st, "critical")
        self.assertFalse(early)

        # 4) Healthy switch + 4 minor non-critical syslog errors -> INFO
        s_log = LLDPqSnapshot(timestamp=now)
        for d in range(1, 5):
            s_log.hardware_control[f"dev-{d}"] = [
                HardwareControlSample(
                    device=f"dev-{d}", device_model="SN5610", timestamp=now,
                    overall_grade="excellent", cpu_temp_c=40.0, asic_temp_c=66.0,
                    tlimit_c=105.0, memory_pct=18.0, load_per_core=0.08,
                    psu_efficiency=92.0, bgp_total_neighbors=16, bgp_established_neighbors=16,
                    log_critical_count=0,
                    log_error_count=4 if d == 1 else 0,
                    log_error_velocity=4.0 if d == 1 else 0.0,
                )
            ]
        sig, _, _ = score_one(s_log, "dev-1")
        self.assertEqual(sig.severity, "INFO")

        # 5) Isolated 2 fans failed + PSU fault (temp normal) -> CRITICAL & Tier-2 agrees
        s_fan = LLDPqSnapshot(timestamp=now)
        for d in range(1, 5):
            s_fan.hardware_control[f"dev-{d}"] = [
                HardwareControlSample(
                    device=f"dev-{d}", device_model="SN5610", timestamp=now,
                    overall_grade="critical" if d == 1 else "excellent",
                    cpu_temp_c=40.0, asic_temp_c=67.0, tlimit_c=105.0,
                    memory_pct=18.0, load_per_core=0.08, psu_efficiency=91.0,
                    fan_failed_count=2 if d == 1 else 0,
                    psu_failed_count=1 if d == 1 else 0,
                    psu_redundancy_ok=(d != 1),
                )
            ]
        sig, raw_st, early = score_one(s_fan, "dev-1")
        self.assertEqual(sig.severity, "CRITICAL")
        self.assertGreaterEqual(sig.tier_scores["tier2_ml"], 65.0)
        self.assertEqual(raw_st, "critical")
        self.assertFalse(early)

        # 6) Resolved 12h-old fault (now healthy) -> INFO (must not stay pinned CRITICAL!)
        s_old = LLDPqSnapshot(timestamp=now)
        s_old.hardware_control["dev-1"] = [
            HardwareControlSample(
                device="dev-1", device_model="SN5610", timestamp=now - 12 * 3600,
                overall_grade="critical", cpu_temp_c=42.0, asic_temp_c=66.0,
                bgp_total_neighbors=16, bgp_down_neighbors=8,
                evpn_mh_critical_es=2, dup_ip_active=2,
                routes_total=200, routes_drop_fraction=0.4, vrf_disappeared_count=1,
                log_critical_count=3, log_error_velocity=15.0,
            ),
            HardwareControlSample(
                device="dev-1", device_model="SN5610", timestamp=now,
                overall_grade="excellent", cpu_temp_c=40.0, asic_temp_c=65.0,
                tlimit_c=105.0, memory_pct=18.0, load_per_core=0.06, psu_efficiency=92.0,
                bgp_total_neighbors=16, bgp_established_neighbors=16, bgp_down_neighbors=0,
                routes_total=400, routes_drop_fraction=0.0, vrf_disappeared_count=0,
            ),
        ]
        sig, _, _ = score_one(s_old, "dev-1")
        self.assertEqual(sig.severity, "INFO")

        # 7) BGP 2 neighbors down + HW excellent -> raw_status=critical, early_warning=False
        s_bgp = LLDPqSnapshot(timestamp=now)
        s_bgp.hardware_control["dev-1"] = [
            HardwareControlSample(
                device="dev-1", device_model="SN5610", timestamp=now,
                overall_grade="excellent", cpu_temp_c=40.0, asic_temp_c=66.0,
                tlimit_c=105.0, memory_pct=18.0, load_per_core=0.06, psu_efficiency=92.0,
                bgp_total_neighbors=16, bgp_established_neighbors=14, bgp_down_neighbors=2,
            )
        ]
        sig, raw_st, early = score_one(s_bgp, "dev-1")
        self.assertIn(sig.severity, ("WARNING", "CRITICAL"))
        self.assertEqual(raw_st, "critical")
        self.assertFalse(early)

    def test_enriched_histories_roundtrip_into_snapshot_loader(self):
        """History enrichments in ber_analyzer and generate_hardware_html feed predictive slopes."""
        # BER slim record preserves raw_ber & effective_ber
        slim = ber_analyzer.BERAnalyzer._history_record({
            "timestamp": 1_763_650_000.0,
            "ber_value": 0.0,
            "grade": "excellent",
            "sample_status": "analyzed",
            "raw_ber": 2.5e-7,
            "effective_ber": 1e-15,
            "symbol_errors": 42,
        })
        self.assertAlmostEqual(slim["raw_ber"], 2.5e-7)
        self.assertAlmostEqual(slim["effective_ber"], 1e-15)

        # Hardware history preserves numeric telemetry and feeds temp_slope_24h + fan_rpms
        now = 1_763_650_000.0
        with tempfile.TemporaryDirectory() as tmp:
            mr = Path(tmp) / "monitor-results"
            mr.mkdir(parents=True)
            hist_path = mr / "hardware_history.json"
            generate_hardware_html.update_hardware_history(
                {"dev-1": ("GOOD", now - 12 * 3600)},
                history_path=str(hist_path),
                now=now - 12 * 3600,
                device_metrics={
                    "dev-1": {
                        "cpu_temp_c": 42.0,
                        "asic_temp_c": 60.0,
                        "memory_pct": 22.0,
                        "load_per_core": 0.15,
                        "psu_efficiency": 91.5,
                        "fan_rpms": {"FAN1/1": 5200, "FAN2/1": 5210},
                    }
                },
            )
            generate_hardware_html.update_hardware_history(
                {"dev-1": ("GOOD", now)},
                history_path=str(hist_path),
                now=now,
                device_metrics={
                    "dev-1": {
                        "cpu_temp_c": 46.0,
                        "asic_temp_c": 66.0,
                        "memory_pct": 24.0,
                        "load_per_core": 0.18,
                        "psu_efficiency": 90.0,
                        "fan_rpms": {"FAN1/1": 3400, "FAN2/1": 6200},
                    }
                },
            )
            snap = LLDPqSnapshotLoader().load(mr)
            feats = {ef.entity_key: ef for ef in FeatureExtractor().extract_hardware_control(snap)}
            self.assertIn("dev-1", feats)
            fdict = feats["dev-1"].as_dict()
            self.assertGreater(fdict["temp_slope_24h"], 10.0)
            self.assertLess(fdict["fan_min_cohort_ratio"], 0.80)

    def test_ai_correlate_single_kind_classifies_predictive_as_device_local(self):
        kind = ai_correlate._single_kind([{"domain": "predictive", "device": "dev-1"}])
        self.assertEqual(kind, "device-local")


if __name__ == "__main__":
    unittest.main()
