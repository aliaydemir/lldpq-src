#!/usr/bin/env python3
"""Regression tests for partial optical collection publication."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical


class OpticalCollectionIsolationTests(unittest.TestCase):
    def _run(self, statuses, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        data_dir = result_dir / "optical-data"
        data_dir.mkdir(parents=True)
        for hostname, content in files.items():
            (data_dir / f"{hostname}_optical.txt").write_text(content)

        snapshot = (statuses, 1.0, True)
        with (
            mock.patch.object(optical, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(optical, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(optical, "is_current_collection", return_value=True),
        ):
            success = optical.process_optical_data_files(str(data_dir))
        return success, result_dir

    def test_timeout_becomes_unknown_row_and_partial_host_coverage(self):
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp17"
        success, result_dir = self._run(
            {"leaf1": "OK"},
            {"leaf1": "\n".join((
                "=== OPTICAL DIAGNOSTICS ===",
                "--- Interface: swp17",
                "Interface state: up",
                marker,
                "No transceiver data",
                "",
            ))},
        )

        self.assertTrue(success)
        history = json.loads((result_dir / "optical_history.json").read_text())
        self.assertEqual(
            history["current_optical_stats"]["leaf1:swp17"]["health_status"],
            "unknown",
        )
        report = (result_dir / "optical-analysis.html").read_text()
        self.assertIn('data-coverage-status="partial"', report)
        self.assertIn('data-coverage-failed-hosts="1"', report)
        self.assertIn("Optical diagnostics timed out for swp17", report)
        self.assertIn("leaf1", report)

    def test_missing_timeout_tool_becomes_unknown_row_with_visible_reason(self):
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TOOL_UNAVAILABLE:swp18"
        success, result_dir = self._run(
            {"leaf1": "OK"},
            {"leaf1": "\n".join((
                "=== OPTICAL DIAGNOSTICS ===",
                "--- Interface: swp18",
                "Interface state: up",
                marker,
                "No transceiver data",
                "",
            ))},
        )

        self.assertTrue(success)
        history = json.loads((result_dir / "optical_history.json").read_text())
        self.assertEqual(
            history["current_optical_stats"]["leaf1:swp18"]["health_status"],
            "unknown",
        )
        report = (result_dir / "optical-analysis.html").read_text()
        self.assertIn('data-coverage-status="partial"', report)
        self.assertIn("Bounded optical diagnostics are unavailable for swp18", report)

    def test_missing_host_generates_partial_report_instead_of_failing_analyzer(self):
        success, result_dir = self._run(
            {"leaf1": "OK", "leaf2": "OK"},
            {"leaf1": "=== OPTICAL DIAGNOSTICS ===\n"},
        )

        self.assertTrue(success)
        report = (result_dir / "optical-analysis.html").read_text()
        self.assertIn('data-coverage-status="partial"', report)
        self.assertIn('data-coverage-current="1"', report)
        self.assertIn('data-coverage-expected="2"', report)
        self.assertIn("leaf2", report)
        self.assertIn("No current optical collection was published", report)

    def test_link_inventory_failure_is_device_level_coverage_gap(self):
        success, result_dir = self._run(
            {"leaf1": "OK"},
            {"leaf1": (
                "=== OPTICAL DIAGNOSTICS ===\n"
                "__LLDPQ_COLLECTION_ERROR__:OPTICAL_LINK_INVENTORY\n"
            )},
        )

        self.assertTrue(success)
        report = (result_dir / "optical-analysis.html").read_text()
        self.assertIn("Physical interface inventory was unavailable", report)
        self.assertIn('data-coverage-missing-hosts="1"', report)


if __name__ == "__main__":
    unittest.main()
