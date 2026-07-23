#!/usr/bin/env python3
"""Focused tests for the PFC/ECN dashboard summary contract."""

import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_pfc_ecn_data as analyzer


BASE_COUNTERS = {
    "ecn_marked_frames": 100,
    "tx_frames": 1000,
    "tx_uc_buffer_discards": 4,
    "wred_discards": 5,
    "rx_pause_frames": 200,
    "tx_pause_frames": 300,
}


class SummaryMetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.summary = None

    def handle_starttag(self, _tag, attrs):
        values = dict(attrs)
        if values.get("data-analysis-summary") == "pfc-ecn":
            self.summary = values


def summary_metadata(report):
    parser = SummaryMetadataParser()
    parser.feed(report)
    parser.close()
    if parser.summary is None:
        raise AssertionError("PFC/ECN summary metadata is missing")
    return parser.summary


class PfcEcnDashboardContractTests(unittest.TestCase):
    def test_complete_interval_publishes_raw_numeric_metrics(self):
        current = dict(BASE_COUNTERS)
        current.update({
            "ecn_marked_frames": 110,
            "tx_frames": 1100,
            "tx_uc_buffer_discards": 5,
            "rx_pause_frames": 205,
            "tx_pause_frames": 303,
        })
        record = analyzer.build_port_record(
            "leaf1", "swp1", current,
            {"timestamp": 1000, "counters": BASE_COUNTERS}, 1010,
        )
        report = analyzer.render_report(
            [record], expected_hosts=1, current_hosts=1
        )
        summary = summary_metadata(report)

        self.assertEqual(summary["data-collection-status"], "current")
        self.assertEqual(summary["data-coverage-status"], "complete")
        self.assertEqual(summary["data-interval-status"], "complete")
        self.assertEqual(summary["data-total-ports"], "1")
        self.assertEqual(summary["data-ready-ports"], "1")
        self.assertEqual(summary["data-ecn-active-ports"], "1")
        self.assertEqual(summary["data-pfc-rx-active-ports"], "1")
        self.assertEqual(summary["data-pfc-tx-active-ports"], "1")
        self.assertEqual(summary["data-discard-ready-ports"], "1")
        self.assertEqual(summary["data-discard-active-ports"], "1")

    def test_unready_rows_do_not_publish_interval_activity(self):
        current = dict(BASE_COUNTERS)
        current.update({
            "ecn_marked_frames": 120,
            "rx_pause_frames": 210,
            "tx_pause_frames": 2,
        })
        reset = analyzer.build_port_record(
            "leaf1", "swp1", current,
            {"timestamp": 1000, "counters": BASE_COUNTERS}, 1010,
        )
        self.assertEqual(reset["sample_status"], "counter_reset")

        report = analyzer.render_report(
            [reset], expected_hosts=1, current_hosts=1
        )
        summary = summary_metadata(report)
        self.assertEqual(summary["data-ready-ports"], "0")
        self.assertEqual(summary["data-interval-status"], "unavailable")
        self.assertEqual(summary["data-ecn-active-ports"], "0")
        self.assertEqual(summary["data-pfc-rx-active-ports"], "0")
        self.assertEqual(summary["data-pfc-tx-active-ports"], "0")
        self.assertEqual(summary["data-discard-ready-ports"], "0")
        self.assertEqual(summary["data-discard-active-ports"], "0")
        self.assertIn('data-ecn-active="0"', report)
        self.assertIn('data-rx-active="0"', report)
        self.assertIn('data-tx-active="0"', report)
        self.assertIn('data-loss-active="0"', report)

    def test_partial_or_unknown_device_coverage_cannot_claim_complete_interval(self):
        record = analyzer.build_port_record(
            "leaf1", "swp1", BASE_COUNTERS,
            {"timestamp": 1000, "counters": BASE_COUNTERS}, 1010,
        )
        partial = summary_metadata(analyzer.render_report(
            [record], expected_hosts=2, current_hosts=1
        ))
        self.assertEqual(partial["data-coverage-status"], "partial")
        self.assertEqual(partial["data-interval-status"], "partial")

        unknown = summary_metadata(analyzer.render_report([record]))
        self.assertEqual(unknown["data-collection-status"], "partial")
        self.assertEqual(unknown["data-coverage-status"], "partial")
        self.assertEqual(unknown["data-interval-status"], "partial")
        self.assertNotIn("data-coverage-current", unknown)
        self.assertNotIn("data-coverage-expected", unknown)

    def test_missing_discard_counter_never_becomes_authoritative_zero(self):
        current = dict(BASE_COUNTERS)
        current["wred_discards"] = None
        record = analyzer.build_port_record(
            "leaf1", "swp1", current,
            {"timestamp": 1000, "counters": BASE_COUNTERS}, 1010,
        )
        self.assertEqual(record["sample_status"], "analyzed")
        self.assertIsNone(record["loss_delta"])
        summary = summary_metadata(analyzer.render_report(
            [record], expected_hosts=1, current_hosts=1
        ))
        self.assertEqual(summary["data-ready-ports"], "1")
        self.assertEqual(summary["data-discard-ready-ports"], "0")
        self.assertEqual(summary["data-discard-active-ports"], "0")

    def test_unavailable_collection_preserves_coverage_diagnostics(self):
        report = analyzer.render_report(
            [], expected_hosts=2, current_hosts=0,
            collection_unavailable=True,
        )
        summary = summary_metadata(report)
        self.assertEqual(summary["data-collection-status"], "unavailable")
        self.assertEqual(summary["data-coverage-status"], "unavailable")
        self.assertEqual(summary["data-coverage-current"], "0")
        self.assertEqual(summary["data-coverage-expected"], "2")
        self.assertEqual(summary["data-interval-status"], "unavailable")
        self.assertEqual(summary["data-discard-ready-ports"], "0")
        self.assertIn('data-collection-status="unavailable"', report)

    def test_detail_report_accepts_dashboard_filter_links(self):
        report = analyzer.render_report([])
        self.assertIn("new URLSearchParams(window.location.search)", report)
        self.assertIn("item.dataset.cardFilter === requested", report)
        self.assertIn("applyRequestedCardFilter();", report)

    def test_detail_panels_fetch_per_device_history_shards(self):
        record = analyzer.build_port_record(
            "leaf1", "swp1", BASE_COUNTERS,
            {"timestamp": 1000, "counters": BASE_COUNTERS}, 1010,
        )
        report = analyzer.render_report(
            [record], expected_hosts=1, current_hosts=1
        )
        # The browser resolves the shard URL relative to the report, which the
        # analyzer writes next to the shard directory under monitor-results/.
        # The path must come from the same constant the shard writer uses.
        self.assertIn(f"fetch('{analyzer.HISTORY_DIR_NAME}/'", report)
        self.assertIn(
            f"const PFC_DETAIL_SAMPLES = {analyzer.HISTORY_DETAIL_SAMPLES};",
            report,
        )
        # Rows must stay wired to the async panel loader: the device attribute
        # selects the shard, the port key selects the trail inside it.
        self.assertIn('data-device="leaf1"', report)
        self.assertIn('data-port-key="leaf1:swp1"', report)
        self.assertIn('onclick="togglePfcDetails(this)"', report)
        # The fabric-wide inline history blob must not come back; at scale it
        # alone made the page unloadable.
        self.assertNotIn("pfc-history-data", report)


if __name__ == "__main__":
    unittest.main()
