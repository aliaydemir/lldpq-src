#!/usr/bin/env python3
"""Regression tests for host-local PFC/ECN collection failures."""

import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_pfc_ecn_data as analyzer


ERROR_PORT = """\
__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1
__LLDPQ_PFC_ECN_PORT_START__:swp1
__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:124
PFC/ECN command timed out
__LLDPQ_PFC_ECN_PORT_END__:swp1
"""


class _SummaryParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.summary = None

    def handle_starttag(self, _tag, attrs):
        values = dict(attrs)
        if values.get("data-analysis-summary") == "pfc-ecn":
            self.summary = values


def _summary(report: str):
    parser = _SummaryParser()
    parser.feed(report)
    parser.close()
    if parser.summary is None:
        raise AssertionError("PFC/ECN summary metadata is missing")
    return parser.summary


class PfcEcnCollectionIsolationTests(unittest.TestCase):
    def _process(self, statuses, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        data_dir = result_dir / "pfc-ecn-data"
        data_dir.mkdir(parents=True)
        for hostname, content in files.items():
            (data_dir / f"{hostname}_pfc_ecn.txt").write_text(
                content, encoding="utf-8"
            )

        snapshot = (dict(statuses), 0.0, True)
        with (
            mock.patch.object(analyzer, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(analyzer, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(
                analyzer, "asset_snapshot_is_authoritative", return_value=True
            ),
            mock.patch.object(analyzer, "is_current_collection", return_value=True),
        ):
            result = analyzer.process_pfc_ecn_data_files(str(data_dir))

        report_path = result_dir / "pfc-ecn-analysis.html"
        report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
        return result, report

    def test_empty_inventory_publishes_partial_report(self):
        result, report = self._process(
            {"leaf1": "OK"},
            {"leaf1": "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:EMPTY:0\n"},
        )

        self.assertTrue(result)
        summary = _summary(report)
        self.assertEqual(summary["data-collection-status"], "partial")
        self.assertEqual(summary["data-coverage-status"], "partial")
        self.assertEqual(summary["data-coverage-expected"], "1")
        self.assertEqual(summary["data-coverage-current"], "0")
        self.assertEqual(summary["data-coverage-failed-hosts"], "leaf1")
        self.assertIn("leaf1: no physical port records", report)

    def test_missing_host_does_not_suppress_valid_host_report(self):
        result, report = self._process(
            {"leaf1": "OK", "leaf2": "OK"},
            {"leaf1": ERROR_PORT},
        )

        self.assertTrue(result)
        summary = _summary(report)
        self.assertEqual(summary["data-coverage-status"], "partial")
        self.assertEqual(summary["data-coverage-expected"], "2")
        self.assertEqual(summary["data-coverage-current"], "1")
        self.assertEqual(summary["data-coverage-failed-hosts"], "leaf2")
        self.assertIn("leaf2: current collection missing", report)
        self.assertIn('data-device="leaf1"', report)
        self.assertIn("Collection failed", report)

    def test_explicit_inventory_error_is_host_local_and_visible(self):
        result, report = self._process(
            {"leaf1": "OK"},
            {"leaf1": "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:ERROR:0\n"},
        )

        self.assertTrue(result)
        summary = _summary(report)
        self.assertEqual(summary["data-coverage-current"], "0")
        self.assertEqual(summary["data-coverage-failed-hosts"], "leaf1")
        self.assertIn("collector reported an inventory error", report)

    def test_declared_count_mismatch_remains_fatal(self):
        malformed = ERROR_PORT.replace(
            "INVENTORY_STATUS__:OK:1", "INVENTORY_STATUS__:OK:2"
        )
        result, report = self._process({"leaf1": "OK"}, {"leaf1": malformed})

        self.assertFalse(result)
        self.assertEqual(report, "")


if __name__ == "__main__":
    unittest.main()
