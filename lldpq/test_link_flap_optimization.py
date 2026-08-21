#!/usr/bin/env python3
"""Regression tests for batched cleanup, atomic flap-history writes, and
slow-cadence severity grading."""

from __future__ import annotations

import collections
import json
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts
from link_flap_analyzer import FlapStatus, LinkFlapAnalyzer


class LinkFlapOptimizationTests(unittest.TestCase):
    def analyzer(self, root: str) -> LinkFlapAnalyzer:
        return LinkFlapAnalyzer(root)

    def seed(self, analyzer: LinkFlapAnalyzer, now: float) -> None:
        analyzer.flapping_hist["leaf:swp1"] = collections.deque([
            (now - 90000, 10, 1),
            (now - 60, 12, 1),
        ], maxlen=1000)
        analyzer.carrier_transitions_lookback["leaf:swp1"] = collections.deque([
            (now - 500, 10),
            (now - 20, 12),
        ], maxlen=100)
        analyzer.prev_cumulative["leaf:swp1"] = 12
        analyzer.prev_sample_time["leaf:swp1"] = now - 20

    def test_per_update_and_single_final_cleanup_have_same_state(self):
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root:
            old_style = self.analyzer(first_root)
            batched = self.analyzer(second_root)
            self.seed(old_style, now)
            self.seed(batched, now)
            with mock.patch("link_flap_analyzer.time.time", return_value=now):
                for analyzer in (old_style, batched):
                    analyzer.update_carrier_transitions("leaf:swp1", 16)
                    analyzer.update_carrier_transitions("leaf:swp2", 2)
            # Simulate the former final state (cleanup after every update) and
            # the new final state (one cleanup before persistence).
            old_style._cleanup_old_entries(now)
            old_style._cleanup_old_entries(now)
            batched._cleanup_old_entries(now)

            self.assertEqual(old_style.flapping_hist, batched.flapping_hist)
            self.assertEqual(
                old_style.carrier_transitions_lookback,
                batched.carrier_transitions_lookback,
            )
            self.assertEqual(old_style.prev_cumulative, batched.prev_cumulative)
            self.assertEqual(old_style.prev_sample_time, batched.prev_sample_time)

    def test_update_does_not_run_global_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            analyzer = self.analyzer(root)
            with mock.patch.object(analyzer, "_cleanup_old_entries") as cleanup:
                analyzer.update_carrier_transitions("leaf:swp1", 2)
            cleanup.assert_not_called()

    def test_save_prunes_and_writes_compact_valid_json(self):
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as root:
            analyzer = self.analyzer(root)
            self.seed(analyzer, now)
            with mock.patch("link_flap_analyzer.time.time", return_value=now):
                analyzer.save_flap_history()
            path = Path(root) / "flap_history.json"
            text = path.read_text(encoding="utf-8")
            parsed = json.loads(text)
            self.assertTrue(text.endswith("\n"))
            self.assertNotIn("\n  ", text)
            self.assertEqual(len(parsed["flapping_hist"]["leaf:swp1"]), 1)
            self.assertEqual(
                len(parsed["carrier_transitions_lookback"]["leaf:swp1"]), 1
            )

    def test_failed_replace_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "flap_history.json"
            path.write_text('{"old":true}\n', encoding="utf-8")
            with mock.patch(
                "link_flap_analyzer.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    LinkFlapAnalyzer._atomic_json_write(
                        str(path), {"new": True}
                    )
            self.assertEqual(path.read_text(encoding="utf-8"), '{"old":true}\n')

    def test_fchown_permission_error_is_swallowed(self):
        # An ownership mismatch on the existing history (mixed-owner
        # monitor-results) must not fail the write like _atomic_text_write.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "flap_history.json"
            path.write_text('{"old":true}\n', encoding="utf-8")
            with mock.patch(
                "link_flap_analyzer.os.fchown",
                side_effect=PermissionError("simulated ownership mismatch"),
            ):
                LinkFlapAnalyzer._atomic_json_write(str(path), {"new": True})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")), {"new": True}
            )

    def test_save_flap_history_returns_a_bool(self):
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as root:
            analyzer = self.analyzer(root)
            self.seed(analyzer, now)
            with mock.patch("link_flap_analyzer.time.time", return_value=now):
                self.assertTrue(analyzer.save_flap_history())
            with mock.patch.object(
                analyzer, "_atomic_json_write",
                side_effect=OSError("simulated write failure"),
            ):
                self.assertFalse(analyzer.save_flap_history())


class SlowCadenceSeverityTests(unittest.TestCase):
    """Severity must not read only the 1h bucket that a slow poll cadence
    makes permanently unreachable (interval-fit rule)."""

    PORT = "leaf:swp1"

    def _analyzer(self, root: str) -> LinkFlapAnalyzer:
        analyzer = LinkFlapAnalyzer(root)
        analyzer.thresholds = {
            "warning_flaps_per_hour": 10,
            "critical_flaps_per_hour": 20,
        }
        return analyzer

    def _run_cycles(self, analyzer, now, interval, delta, cycles=6):
        transitions = 0
        for cycle in range(cycles):
            transitions += delta
            cycle_time = now - (cycles - 1 - cycle) * interval
            with mock.patch(
                "link_flap_analyzer.time.time", return_value=cycle_time
            ):
                analyzer.update_carrier_transitions(self.PORT, transitions)

    def _report_cells(self, analyzer, root, now):
        output = str(Path(root) / "link-flap-analysis.html")
        with mock.patch("link_flap_analyzer.time.time", return_value=now):
            analyzer.export_flap_data_for_web(output)
        report = Path(output).read_text(encoding="utf-8")
        row = report.split(f'data-port-key="{self.PORT}"', 1)[1]
        row = row.split("</tr>", 1)[0]
        return re.findall(r'<td data-value="(\d+)">([^<]*)</td>', row)

    def test_hourly_cadence_grades_from_rate_equivalent(self):
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as root:
            analyzer = self._analyzer(root)
            # Five detected deltas of 100 flaps each, one-hour poll interval.
            self._run_cycles(analyzer, now, interval=3600.0, delta=200)
            graded_at = now + 30
            with mock.patch(
                "link_flap_analyzer.time.time", return_value=graded_at
            ):
                counters = analyzer.calculate_flapping_rate(self.PORT)
                status = analyzer.get_port_flap_status(self.PORT)
                threshold_hit = analyzer.check_flapping()
                anomalies = analyzer.detect_flap_anomalies()
            # The displayed bucket keeps its refuse-to-overclaim contract...
            self.assertEqual(0, counters["flap_1_hr"])
            self.assertEqual(500, counters["flap_12_hrs"])
            # ...but severity grades from the 12h rate-equivalent (500/12/h).
            self.assertEqual(FlapStatus.CRITICAL, status)
            self.assertTrue(threshold_hit)
            (anomaly,) = anomalies
            self.assertEqual("critical", anomaly["severity"])
            self.assertEqual(41.7, anomaly["details"]["flap_count_1hr"])
            # The unmeasurable 1h cell renders the em-dash, not a literal 0.
            cells = self._report_cells(analyzer, root, graded_at)
            self.assertEqual(("0", "&mdash;"), cells[3])
            self.assertEqual(("500", "500"), cells[4])

    def test_ten_minute_cadence_behavior_is_unchanged(self):
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as root:
            analyzer = self._analyzer(root)
            # Five detected deltas of 25 flaps each, ten-minute poll interval.
            self._run_cycles(analyzer, now, interval=600.0, delta=50)
            graded_at = now + 30
            with mock.patch(
                "link_flap_analyzer.time.time", return_value=graded_at
            ):
                counters = analyzer.calculate_flapping_rate(self.PORT)
                status = analyzer.get_port_flap_status(self.PORT)
            self.assertEqual(125, counters["flap_1_hr"])
            self.assertEqual(FlapStatus.CRITICAL, status)
            cells = self._report_cells(analyzer, root, graded_at)
            self.assertEqual(("125", "125"), cells[3])

    def test_quiet_hour_at_fast_cadence_stays_ok(self):
        # Old flaps at a measurable cadence must never trigger the fallback:
        # a genuine quiet last hour keeps grading OK.
        now = 2_000_000.0
        with tempfile.TemporaryDirectory() as root:
            analyzer = self._analyzer(root)
            self._run_cycles(analyzer, now - 18000, interval=600.0, delta=50)
            with mock.patch(
                "link_flap_analyzer.time.time", return_value=now
            ):
                counters = analyzer.calculate_flapping_rate(self.PORT)
                status = analyzer.get_port_flap_status(self.PORT)
            self.assertEqual(0, counters["flap_1_hr"])
            self.assertEqual(125, counters["flap_12_hrs"])
            self.assertEqual(FlapStatus.OK, status)


class CheckAlertsSlowCadenceMirrorTests(unittest.TestCase):
    """check_alerts.get_device_flap_counts must agree with the report."""

    def _checker(self, tmp, entries):
        checker = object.__new__(check_alerts.LLDPqAlerts)
        checker.monitor_results = Path(tmp)
        checker.had_error = False
        checker._flap_history_loaded = False
        checker._flap_history_index = None
        checker._flap_history_error = None
        (Path(tmp) / "flap_history.json").write_text(json.dumps({
            "flapping_hist": {"leaf1:swp1": entries},
            "last_update": time.time(),
        }), encoding="utf-8")
        return checker

    def _counts(self, checker):
        stats = {"statuses": {"leaf1": "successful"}}
        with (
            mock.patch.object(checker, "get_asset_stats",
                              create=True, return_value=stats),
            mock.patch.object(checker, "get_data_max_age_seconds",
                              create=True, return_value=3600.0),
        ):
            return checker.get_device_flap_counts("leaf1", window_seconds=3600)

    def test_hourly_cadence_uses_the_rate_equivalent(self):
        base = time.time() - 30
        entries = [
            [base - offset * 3600.0, 200, 100, base - (offset + 1) * 3600.0,
             3600.0]
            for offset in range(5)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, entries)
            self.assertEqual({"swp1": 41.7}, self._counts(checker))
            self.assertFalse(checker.had_error)

    def test_fast_cadence_counts_are_unchanged(self):
        base = time.time() - 30
        entries = [
            [base - offset * 600.0, 50, 25, base - (offset + 1) * 600.0,
             600.0]
            for offset in range(3)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, entries)
            self.assertEqual({"swp1": 75}, self._counts(checker))
            self.assertFalse(checker.had_error)


if __name__ == "__main__":
    unittest.main()
