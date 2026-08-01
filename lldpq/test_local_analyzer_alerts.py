#!/usr/bin/env python3
"""Fabric-wide stateful alerts for the local analyzers
(config-drift / routes / fabric-check) and their AI-context wiring."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts


def _checker(tmp):
    checker = object.__new__(check_alerts.LLDPqAlerts)
    checker.monitor_results = Path(tmp)
    checker.had_error = False
    checker.config = {"frequency": {"send_recovery": True}}
    return checker


def _write_summary(tmp, name, payload):
    summary_dir = Path(tmp) / "summary"
    summary_dir.mkdir(exist_ok=True)
    (summary_dir / name).write_text(json.dumps(payload), encoding="utf-8")


class LocalAnalyzerAlertTests(unittest.TestCase):
    def _run(self, checker, method, *, state="UNKNOWN", should_send=True):
        sent = {}

        def capture(title, message, severity, device, key, new_state):
            sent.update(title=title, message=message, severity=severity,
                        device=device, key=key, state=new_state)
            return True

        recorded = {}

        def record(device, key, new_state):
            recorded.update(device=device, key=key, state=new_state)
            return True

        with (
            mock.patch.object(checker, "get_alert_state",
                              create=True, return_value=state),
            mock.patch.object(checker, "should_send_alert",
                              create=True, return_value=should_send),
            mock.patch.object(checker, "send_stateful_notification",
                              create=True, side_effect=capture),
            mock.patch.object(checker, "record_state_without_delivery",
                              create=True, side_effect=record),
        ):
            result = method()
        return result, sent, recorded

    def test_route_drops_alert_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_summary(tmp, "routes-summary.json", {
                "route_drops_24h": 2, "vrfs_disappeared_24h": 1,
                "devices_stale": 0, "total_routes": 60973,
            })
            checker = _checker(tmp)
            ok, sent, _ = self._run(checker, checker.check_routes_alerts)
            self.assertTrue(ok)
            self.assertEqual(sent["severity"], "CRITICAL")
            self.assertEqual(sent["key"], "routes")
            self.assertIn("Route drops (24h): 2", sent["message"])

    def test_route_ok_first_run_baselines_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_summary(tmp, "routes-summary.json", {
                "route_drops_24h": 0, "vrfs_disappeared_24h": 0,
                "devices_stale": 0, "total_routes": 100,
            })
            checker = _checker(tmp)
            ok, sent, recorded = self._run(
                checker, checker.check_routes_alerts, state="UNKNOWN")
            self.assertTrue(ok)
            self.assertEqual(sent, {})
            self.assertEqual(recorded["key"], "routes")

    def test_config_drift_alert_warns_and_never_sends_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_summary(tmp, "config-drift-summary.json", {
                "changed_24h": 3, "devices_missing": 1,
            })
            checker = _checker(tmp)
            ok, sent, _ = self._run(checker, checker.check_config_drift_alerts)
            self.assertTrue(ok)
            self.assertEqual(sent["severity"], "WARNING")
            self.assertIn("Configuration changed on 3 device(s)",
                          sent["message"])

            _write_summary(tmp, "config-drift-summary.json", {
                "changed_24h": 0, "devices_missing": 0,
            })
            ok, sent, recorded = self._run(
                checker, checker.check_config_drift_alerts, state="WARNING:3:1")
            self.assertTrue(ok)
            self.assertEqual(sent, {}, "config drift must not send recovery")
            self.assertEqual(recorded["key"], "config_drift")

    def test_fabric_check_severity_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_summary(tmp, "fabric-check-summary.json", {
                "mtu_mismatches": 0, "speed_mismatches": 0,
                "fec_mismatches": 1, "autoneg_mismatches": 0,
                "config_mtu_mismatches": 2,
            })
            checker = _checker(tmp)
            ok, sent, _ = self._run(checker, checker.check_fabric_check_alerts)
            self.assertTrue(ok)
            self.assertEqual(sent["severity"], "CRITICAL")
            self.assertIn("FEC mismatches: 1", sent["message"])

            _write_summary(tmp, "fabric-check-summary.json", {
                "mtu_mismatches": 0, "speed_mismatches": 0,
                "fec_mismatches": 0, "autoneg_mismatches": 1,
                "config_mtu_mismatches": 0,
            })
            ok, sent, _ = self._run(checker, checker.check_fabric_check_alerts)
            self.assertTrue(ok)
            self.assertEqual(sent["severity"], "WARNING")

    def test_missing_summary_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = _checker(tmp)
            ok, _, _ = self._run(checker, checker.check_routes_alerts)
            self.assertFalse(ok)
            self.assertTrue(checker.had_error)


class ImmediateAlertGatingTests(unittest.TestCase):
    def test_local_analyzers_gate_on_the_manifest(self):
        source = (SCRIPT_DIR / "check_alerts.py").read_text(encoding="utf-8")
        for domain, method in (
                ("config-drift", "check_config_drift_alerts"),
                ("routes", "check_routes_alerts"),
                ("fabric-check", "check_fabric_check_alerts")):
            self.assertIn(f'("{domain}", self.{method}),', source)
        # Absent from a (pre-upgrade / scoped) manifest is not an error.
        self.assertIn("if domain not in manifest_analyses:", source)
        self.assertIn("if domain in manifest_skipped:", source)


class AiContextWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (SCRIPT_DIR.parent / "html" / "ai-api.sh").read_text(
            encoding="utf-8")

    def test_summary_sections_for_the_local_analyzers(self):
        self.assertIn("CONFIG DRIFT:", self.source)
        self.assertIn("RECENT CONFIG CHANGES:", self.source)
        self.assertIn("ROUTES:", self.source)
        self.assertIn("RECENT ROUTE EVENTS:", self.source)
        self.assertIn("FABRIC CHECK:", self.source)

    def test_source_freshness_entries(self):
        for key, filename in (
                ("config_drift", "config-drift-summary.json"),
                ("routes", "routes-summary.json"),
                ("fabric_check", "fabric-check-summary.json")):
            self.assertIn(f"'{key}': _source_freshness(", self.source)
            self.assertIn(filename, self.source)


if __name__ == "__main__":
    unittest.main()
