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
import predictive_analyzer  # noqa: E402
from predictive_engine import (  # noqa: E402
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
    FAMILY_PHYSICAL,
    FeatureExtractor,
    HardwareControlSample,
    HardwareSensorReading,
    LLDPqSnapshot,
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
            # File permissions must be nginx-readable (0644)
            self.assertEqual(os.stat(out / "export" / "predictive.json").st_mode & 0o777, 0o644)

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
        self.assertTrue((ROOT_DIR / "html" / "predictive.html").is_file())


if __name__ == "__main__":
    unittest.main()
