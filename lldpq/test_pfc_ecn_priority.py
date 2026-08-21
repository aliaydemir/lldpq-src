#!/usr/bin/env python3
"""Tests for the configurable PFC/ECN lossless priority.

RoCE fabrics do not all run their lossless class on priority 3.  When the
analyzer reads a priority the fabric does not use, every counter is absent and
the page reports "data missing" on every port — including during a real PFC
storm.  These tests pin the override, the default, and the diagnostic that
tells an operator which priority the switches actually reported.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_pfc_ecn_data as analyzer


def payload_for(priority):
    """NVUE-shaped counter payload keyed on a single priority."""
    egress = {}
    pfc = {}
    for group, field in analyzer.COUNTER_PATHS.values():
        target = egress if group == "egress-queue-stats" else pfc
        target[field] = 1234
    return {
        "interface": {
            "swp1": {
                "counters": {
                    "qos": {
                        "egress-queue-stats": {str(priority): egress},
                        "pfc-stats": {str(priority): pfc},
                    }
                }
            }
        }
    }


class ConfiguredPriorityTests(unittest.TestCase):
    def test_defaults_to_three_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PFC_ECN_PRIORITY", None)
            self.assertEqual(analyzer.configured_priority(), "3")

    def test_environment_override_is_honored(self):
        for priority in ("0", "4", "7"):
            with self.subTest(priority=priority):
                with mock.patch.dict(
                    os.environ, {"PFC_ECN_PRIORITY": priority}
                ):
                    self.assertEqual(analyzer.configured_priority(), priority)

    def test_surrounding_whitespace_is_tolerated(self):
        with mock.patch.dict(os.environ, {"PFC_ECN_PRIORITY": " 4 "}):
            self.assertEqual(analyzer.configured_priority(), "4")

    def test_invalid_value_falls_back_and_reports_why(self):
        for bad in ("8", "-1", "three", "3,4"):
            with self.subTest(value=bad):
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, {"PFC_ECN_PRIORITY": bad}):
                    with redirect_stderr(stderr):
                        resolved = analyzer.configured_priority()
                self.assertEqual(resolved, "3")
                self.assertIn("PFC_ECN_PRIORITY", stderr.getvalue())


class ExtractCountersPriorityTests(unittest.TestCase):
    def test_counters_are_read_from_the_configured_priority(self):
        counters = analyzer.extract_counters(payload_for(4), "4")
        self.assertTrue(
            all(value == 1234 for value in counters.values()),
            f"expected every counter to be read, got {counters}",
        )

    def test_other_priorities_are_not_read(self):
        counters = analyzer.extract_counters(payload_for(4), "3")
        self.assertTrue(
            all(value is None for value in counters.values()),
            "priority 3 must not pick up priority 4 counters",
        )

    def test_default_priority_still_reads_priority_three(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PFC_ECN_PRIORITY", None)
            counters = analyzer.extract_counters(payload_for(3))
        self.assertTrue(all(value == 1234 for value in counters.values()))

    def test_list_shaped_groups_match_on_selector(self):
        payload = {
            "egress-queue-stats": [
                {"switch-priority": 4, "ecn-marked-frames": 7, "tx-frames": 9},
            ],
        }
        counters = analyzer.extract_counters(payload, "4")
        self.assertEqual(counters["ecn_marked_frames"], 7)
        self.assertIsNone(analyzer.extract_counters(payload, "3")["ecn_marked_frames"])


class ObservedPrioritiesTests(unittest.TestCase):
    def test_reports_the_priorities_present_in_the_payload(self):
        self.assertEqual(analyzer.observed_priorities(payload_for(4)), {"4"})

    def test_collects_from_both_counter_groups(self):
        payload = {
            "counters": {
                "egress-queue-stats": {"2": {"tx-frames": 1}},
                "pfc-stats": {"5": {"rx-pause-frames": 1}},
            }
        }
        self.assertEqual(analyzer.observed_priorities(payload), {"2", "5"})

    def test_ignores_non_priority_keys(self):
        payload = {"egress-queue-stats": {"total": {"tx-frames": 1}}}
        self.assertEqual(analyzer.observed_priorities(payload), set())


class FamilyBaselineTests(unittest.TestCase):
    """Counter families keep and advance their baselines independently.

    A sample that carries only one family (a switch answering pfc-stats but
    not egress-queue-stats, or vice versa) must not erase the other family's
    baseline, and a returning family must not demote the family that had a
    baseline all along to first_sample.
    """

    FULL = {
        "ecn_marked_frames": 50,
        "tx_frames": 500,
        "tx_uc_buffer_discards": 1,
        "wred_discards": 2,
        "rx_pause_frames": 102,
        "tx_pause_frames": 203,
    }

    def test_pfc_only_baseline_keeps_pause_deltas_on_full_sample(self):
        record = analyzer.build_port_record(
            "leaf1", "swp1", dict(self.FULL),
            {
                "timestamp": 1000,
                "counters": {"rx_pause_frames": 100, "tx_pause_frames": 200},
            },
            1600,
        )
        # Only the newly-returning ECN family is on its first sample; the
        # PFC family that had a baseline keeps its valid deltas.
        self.assertEqual(record["sample_status"], "analyzed")
        self.assertTrue(record["pfc_ready"])
        self.assertFalse(record["ecn_ready"])
        self.assertEqual(record["deltas"]["rx_pause_frames"], 2)
        self.assertEqual(record["deltas"]["tx_pause_frames"], 3)
        self.assertIsNone(record["deltas"]["ecn_marked_frames"])
        self.assertEqual(record["signal"], "pfc")

    def test_one_family_sample_merges_into_the_baseline_per_family(self):
        baseline = analyzer._advance_baseline(
            None, "leaf1", "swp1", self.FULL, 1000
        )
        pfc_only = {name: None for name in analyzer.COUNTER_PATHS}
        pfc_only.update({"rx_pause_frames": 105, "tx_pause_frames": 210})
        merged = analyzer._advance_baseline(
            baseline, "leaf1", "swp1", pfc_only, 1600
        )
        # The unmeasured ECN family keeps its previous value and timestamp.
        self.assertEqual(merged["counters"]["ecn_marked_frames"], 50)
        self.assertEqual(merged["counter_timestamps"]["ecn_marked_frames"], 1000)
        self.assertEqual(merged["counters"]["rx_pause_frames"], 105)
        self.assertEqual(merged["counter_timestamps"]["rx_pause_frames"], 1600)

        full = dict(self.FULL)
        full.update({
            "ecn_marked_frames": 62,
            "tx_frames": 620,
            "rx_pause_frames": 110,
            "tx_pause_frames": 220,
        })
        record = analyzer.build_port_record("leaf1", "swp1", full, merged, 2200)
        self.assertEqual(record["sample_status"], "analyzed")
        self.assertTrue(record["ecn_ready"])
        self.assertTrue(record["pfc_ready"])
        # Deltas and rates span each family's own baseline window.
        self.assertEqual(record["deltas"]["ecn_marked_frames"], 12)
        self.assertAlmostEqual(record["rates"]["ecn_marked_frames"], 12 / 1200)
        self.assertEqual(record["deltas"]["rx_pause_frames"], 5)
        self.assertAlmostEqual(record["rates"]["rx_pause_frames"], 5 / 600)

    def test_legacy_baseline_without_counter_timestamps_still_loads(self):
        record = analyzer.build_port_record(
            "leaf1", "swp1", dict(self.FULL),
            {
                "timestamp": 1000,
                "counters": {
                    "ecn_marked_frames": 40,
                    "tx_frames": 400,
                    "tx_uc_buffer_discards": 1,
                    "wred_discards": 2,
                    "rx_pause_frames": 100,
                    "tx_pause_frames": 200,
                },
            },
            1600,
        )
        self.assertEqual(record["sample_status"], "analyzed")
        self.assertEqual(record["deltas"]["ecn_marked_frames"], 10)
        self.assertEqual(record["deltas"]["rx_pause_frames"], 2)
        self.assertAlmostEqual(record["rates"]["rx_pause_frames"], 2 / 600)


class PriorityReportingTests(unittest.TestCase):
    def _record(self):
        return analyzer.build_port_record(
            "leaf1", "swp1", {name: None for name in analyzer.COUNTER_PATHS},
            None, 1000,
        )

    def test_report_labels_follow_the_configured_priority(self):
        report = analyzer.render_report([self._record()], lossless_priority="4")
        self.assertIn("TC4", report)
        self.assertIn("SP4", report)
        self.assertNotIn("TC3", report)
        self.assertNotIn("SP3", report)

    def test_mismatched_priority_is_named_in_a_banner(self):
        report = analyzer.render_report(
            [self._record()],
            lossless_priority="3",
            unmatched_priorities={"4"},
        )
        self.assertIn("PFC_ECN_PRIORITY", report)
        self.assertIn("priority 4", report)

    def test_no_banner_when_the_configured_priority_is_the_one_seen(self):
        report = analyzer.render_report(
            [self._record()],
            lossless_priority="3",
            unmatched_priorities={"3"},
        )
        self.assertNotIn("PFC_ECN_PRIORITY</code> in", report)


if __name__ == "__main__":
    unittest.main()
