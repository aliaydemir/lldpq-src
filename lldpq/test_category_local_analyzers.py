#!/usr/bin/env python3
"""Regression tests for analyzer-local collection command failures."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import duplicate_analyzer
import process_ber_data
import process_bgp_data
import process_flap_data


class CategoryLocalAnalyzerTests(unittest.TestCase):
    def _result_tree(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        result_dir.mkdir()
        return result_dir

    @staticmethod
    def _snapshot(statuses):
        return statuses, 1.0, True

    @staticmethod
    def _seed_stale_ber_state(result_dir):
        stale_record = {
            "timestamp": time.time(),
            "ber_value": 0.0,
            "grade": "excellent",
            "sample_status": "analyzed",
            "rx_packets": 1000,
            "tx_packets": 1000,
            "rx_errors": 0,
            "tx_errors": 0,
            "total_packets": 2000,
            "delta_errors": 0,
            "delta_bytes": 1000,
            "delta_packets": 2000,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 60,
        }
        (result_dir / "ber_history.json").write_text(json.dumps({
            "ber_history": {"leaf1:swp99": [stale_record]},
            "current_ber_stats": {"leaf1:swp99": stale_record},
        }))
        baseline = {
            "leaf1": {
                "swp99": {
                    "rx_errors": 0,
                    "tx_errors": 0,
                    "rx_bytes": 1000,
                    "tx_bytes": 1000,
                    "rx_packets": 1000,
                    "tx_packets": 1000,
                    "timestamp": time.time() - 60,
                }
            }
        }
        (result_dir / "ber_baseline.json").write_text(json.dumps(baseline))
        return baseline

    def test_bgp_and_evpn_markers_publish_unavailable_coverage(self):
        result_dir = self._result_tree()
        bgp_dir = result_dir / "bgp-data"
        evpn_dir = result_dir / "evpn-data"
        bgp_dir.mkdir()
        evpn_dir.mkdir()
        (bgp_dir / "leaf1_bgp.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY\n"
        )
        (evpn_dir / "leaf1_evpn.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:EVPN_VNI\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_bgp_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_bgp_data, "is_current_collection", return_value=True),
        ):
            analyzer = process_bgp_data.process_bgp_data_files(str(bgp_dir))

        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.current_bgp_stats["leaf1"]["data_status"], "unknown")
        self.assertEqual(analyzer.collection_coverage["current_bgp_devices"], 0)
        self.assertEqual(analyzer.collection_coverage["current_evpn_devices"], 0)
        report = (result_dir / "bgp-analysis.html").read_text()
        self.assertIn('data-collection-status="unavailable"', report)

    def test_evpn_failure_does_not_downgrade_current_bgp_section(self):
        result_dir = self._result_tree()
        bgp_dir = result_dir / "bgp-data"
        evpn_dir = result_dir / "evpn-data"
        bgp_dir.mkdir()
        evpn_dir.mkdir()
        (bgp_dir / "leaf1_bgp.txt").write_text("No BGP neighbors configured\n")
        (evpn_dir / "leaf1_evpn.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_bgp_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_bgp_data, "is_current_collection", return_value=True),
        ):
            analyzer = process_bgp_data.process_bgp_data_files(str(bgp_dir))

        self.assertEqual(analyzer.current_bgp_stats["leaf1"]["data_status"], "current")
        self.assertEqual(analyzer.collection_coverage["current_bgp_devices"], 1)
        self.assertEqual(analyzer.collection_coverage["current_evpn_devices"], 0)
        report = (result_dir / "bgp-analysis.html").read_text()
        self.assertIn('data-collection-status="partial"', report)

    def test_duplicate_fdb_and_neigh_markers_are_reported_as_partial(self):
        result_dir = self._result_tree()
        dup_dir = result_dir / "dup-data"
        dup_dir.mkdir()
        (dup_dir / "leaf1_dup.txt").write_text("")
        (dup_dir / "leaf1_fdb.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:FDB\n"
        )
        (dup_dir / "leaf1_neigh.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:NEIGH\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(duplicate_analyzer, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(duplicate_analyzer, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(duplicate_analyzer, "canonical", side_effect=lambda value: value),
        ):
            analyzer = duplicate_analyzer.DuplicateAnalyzer(str(result_dir))
            analyzer.parse_all()

        sources = analyzer.collection_meta["leaf1"]["sources"]
        self.assertEqual(sources["FDB_LOCAL"], "ERROR")
        self.assertEqual(sources["NEIGH"], "ERROR")
        self.assertTrue(analyzer.coverage["partial"])
        self.assertIn("leaf1:FDB_LOCAL_ERROR", analyzer.coverage["failures"])
        self.assertIn("leaf1:NEIGH_ERROR", analyzer.coverage["failures"])

    def test_link_inventory_marker_publishes_partial_flap_report(self):
        result_dir = self._result_tree()
        flap_dir = result_dir / "flap-data"
        flap_dir.mkdir()
        (flap_dir / "leaf1_carrier_transitions.txt").write_text(
            "=== CARRIER TRANSITIONS ===\n"
            "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_flap_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_flap_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_flap_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_flap_data, "is_current_collection", return_value=True),
        ):
            success = process_flap_data.process_carrier_transition_files(str(flap_dir))

        self.assertTrue(success)
        report = (result_dir / "link-flap-analysis.html").read_text()
        self.assertIn('data-collection-status="unavailable"', report)
        self.assertIn('data-current-devices="0"', report)

    def test_interface_counter_marker_publishes_partial_ber_report(self):
        result_dir = self._result_tree()
        ber_dir = result_dir / "ber-data"
        ber_dir.mkdir()
        (ber_dir / "leaf1_interface_errors.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_ber_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_ber_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_ber_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_ber_data, "is_current_collection", return_value=True),
        ):
            success = process_ber_data.process_ber_data_files(str(ber_dir))

        self.assertTrue(success)
        report = (result_dir / "ber-analysis.html").read_text()
        self.assertIn('data-coverage-status="partial"', report)
        self.assertIn('data-coverage-current="0"', report)
        self.assertIn('data-coverage-expected="1"', report)
        saved = json.loads((result_dir / "ber_history.json").read_text())
        self.assertEqual(saved["current_ber_stats"], {})

    def test_ber_marker_clears_preloaded_current_but_preserves_history_baseline(self):
        result_dir = self._result_tree()
        ber_dir = result_dir / "ber-data"
        ber_dir.mkdir()
        (ber_dir / "leaf1_interface_errors.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS\n"
        )
        baseline = self._seed_stale_ber_state(result_dir)
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_ber_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_ber_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_ber_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_ber_data, "is_current_collection", return_value=True),
        ):
            success = process_ber_data.process_ber_data_files(str(ber_dir))

        self.assertTrue(success)
        saved = json.loads((result_dir / "ber_history.json").read_text())
        self.assertEqual(saved["current_ber_stats"], {})
        self.assertIn("leaf1:swp99", saved["ber_history"])
        self.assertEqual(
            json.loads((result_dir / "ber_baseline.json").read_text()), baseline
        )
        report = (result_dir / "ber-analysis.html").read_text()
        self.assertNotIn("swp99", report)
        self.assertIn('data-coverage-current="0"', report)

    def test_missing_ber_host_clears_preloaded_current_snapshot(self):
        result_dir = self._result_tree()
        ber_dir = result_dir / "ber-data"
        ber_dir.mkdir()
        self._seed_stale_ber_state(result_dir)
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_ber_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_ber_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_ber_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_ber_data, "is_current_collection", return_value=True),
        ):
            success = process_ber_data.process_ber_data_files(str(ber_dir))

        self.assertTrue(success)
        saved = json.loads((result_dir / "ber_history.json").read_text())
        self.assertEqual(saved["current_ber_stats"], {})
        self.assertIn("leaf1:swp99", saved["ber_history"])
        report = (result_dir / "ber-analysis.html").read_text()
        self.assertNotIn("swp99", report)
        self.assertIn('data-coverage-current="0"', report)


if __name__ == "__main__":
    unittest.main()
