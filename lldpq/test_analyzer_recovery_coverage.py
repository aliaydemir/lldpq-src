#!/usr/bin/env python3
"""Real analyzer outputs must not turn missing telemetry into recovery."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_alerts
import process_fabric_check_data as fabric
import process_flap_data as flap
import process_routes_data as routes


def checker(root):
    obj = object.__new__(check_alerts.LLDPqAlerts)
    obj.monitor_results = Path(root)
    obj.config = {"frequency": {"send_recovery": True}}
    obj.had_error = False
    obj._flap_history_loaded = False
    obj._flap_history_index = None
    obj._flap_history_error = None
    return obj


class AnalyzerRecoveryCoverageTests(unittest.TestCase):
    def test_old_route_scan_cannot_recover_even_when_hosts_say_current(self):
        now = int(time.time())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tables = root / "fabric-tables"
            tables.mkdir()
            (tables / "summary.json").write_text(json.dumps({
                "timestamp": datetime.fromtimestamp(now - 5400, timezone.utc).isoformat(),
            }))
            (tables / "Leaf1.json").write_text(json.dumps({
                "routes": {"default": [{"protocol": "bgp"}] * 100},
                "_collection": {"status": "current"},
            }))
            with patch.object(routes, "load_managed_devices", return_value=["Leaf1"]):
                analyzer = routes.RoutesAnalyzer(str(root), now=now)
            analyzer.analyze()
            analyzer.export_html(str(root / "routes-analysis.html"))
            obj = checker(root)
            with (
                patch.object(obj, "get_alert_state", return_value="CRITICAL"),
                patch.object(obj, "send_stateful_notification") as notify,
                patch.object(obj, "record_state_without_delivery") as record,
            ):
                self.assertFalse(obj.check_routes_alerts())
            notify.assert_not_called()
            record.assert_not_called()

    def test_missing_fabric_sidecar_cannot_clear_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(fabric, "load_managed_devices", return_value=["Leaf1"]):
                analyzer = fabric.FabricCheckAnalyzer(
                    str(root), sidecar_path=str(root / "absent-sidecar.json"),
                    configs_dir=str(root / "configs"), now=int(time.time()))
            analyzer.analyze()
            analyzer.export_html(str(root / "fabric-check-analysis.html"))
            obj = checker(root)
            with (
                patch.object(obj, "get_alert_state", return_value="CRITICAL"),
                patch.object(obj, "send_stateful_notification") as notify,
                patch.object(obj, "record_state_without_delivery") as record,
            ):
                self.assertFalse(obj.check_fabric_check_alerts())
            notify.assert_not_called()
            record.assert_not_called()

    def _flap_case(self, raw_content, age, count, *, send_recovery=True, coverage=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        raw = root / "flap-data"
        raw.mkdir()
        (raw / "leaf1_carrier_transitions.txt").write_text(raw_content)
        now = time.time()
        (root / "flap_history.json").write_text(json.dumps({
            "flapping_hist": {"leaf1:swp1": [[now-age, 140, count, now-age-600, 600]]},
            "prev_cumulative": {"leaf1:swp1": 140},
            "prev_sample_time": {"leaf1:swp1": now-age},
            "carrier_transitions_stats": {"leaf1:swp1": 140},
        }))
        with (
            patch.object(flap, "read_asset_snapshot", return_value=({"leaf1": "OK"}, 1., True)),
            patch.object(flap, "is_current_collection", return_value=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertTrue(flap.process_carrier_transition_files(str(raw)))
        if coverage is not None:
            history_file = root / "flap_history.json"
            history = json.loads(history_file.read_text())
            history["collection_coverage"] = coverage
            history_file.write_text(json.dumps(history))
        obj = checker(root)
        obj.config["frequency"]["send_recovery"] = send_recovery
        with (
            patch.object(obj, "get_asset_stats", return_value={"statuses": {"leaf1": "successful"}}),
            patch.object(obj, "get_device_bgp_status", return_value="unknown"),
            patch.object(obj, "get_device_bgp_flap_counts", return_value=None),
            patch.object(obj, "get_device_bgp_update_storms", return_value=None),
            patch.object(obj, "check_processed_network_alerts", return_value=True),
            patch.object(obj, "should_send_alert", return_value=True),
            patch.object(obj, "send_stateful_notification", return_value=True) as notify,
            patch.object(obj, "record_state_without_delivery", return_value=True) as record,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            status = obj.get_device_flap_status("leaf1")
            obj.check_network_alerts("leaf1")
        return status, notify, record

    def test_unavailable_counters_and_expired_events_never_recover(self):
        for send_recovery in (True, False):
            with self.subTest(send_recovery=send_recovery):
                status, notify, record = self._flap_case(
                    "swp1:unavailable\n", 7200, 20, send_recovery=send_recovery)
                self.assertEqual(status, "unknown")
                notify.assert_not_called()
                record.assert_not_called()

    def test_partial_host_does_not_recover_when_other_port_is_readable(self):
        status, notify, record = self._flap_case("swp1:unavailable\nswp2:12\n", 7200, 20)
        self.assertEqual(status, "unknown")
        notify.assert_not_called()
        record.assert_not_called()

    def test_partial_host_keeps_observed_unhealthy_findings(self):
        status, notify, record = self._flap_case("swp1:140\nswp2:unavailable\n", 60, 20)
        self.assertEqual(status, "critical")
        self.assertEqual(notify.call_args.args[2], "CRITICAL")
        record.assert_not_called()

    def test_complete_current_counter_read_can_recover(self):
        status, notify, _ = self._flap_case("swp1:140\n", 7200, 20)
        self.assertEqual(status, "stable")
        self.assertEqual(notify.call_args.args[2], "RECOVERED")

    def test_one_missing_host_does_not_block_other_hosts_recovery(self):
        status, notify, _ = self._flap_case("swp1:140\n", 7200, 20, coverage={
            "expected_devices": 2, "current_devices": 1,
            "unavailable_devices": ["leaf2"],
        })
        self.assertEqual(status, "stable")
        self.assertEqual(notify.call_args.args[2], "RECOVERED")

    def test_history_without_coverage_cannot_prove_recovery(self):
        status, notify, record = self._flap_case("swp1:140\n", 7200, 20, coverage={})
        self.assertEqual(status, "unknown")
        notify.assert_not_called()
        record.assert_not_called()


if __name__ == "__main__":
    unittest.main()
