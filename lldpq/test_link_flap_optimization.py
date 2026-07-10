#!/usr/bin/env python3
"""Regression tests for batched cleanup and atomic flap-history writes."""

from __future__ import annotations

import collections
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lldpq.link_flap_analyzer import LinkFlapAnalyzer


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
            with mock.patch("lldpq.link_flap_analyzer.time.time", return_value=now):
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
            with mock.patch("lldpq.link_flap_analyzer.time.time", return_value=now):
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
                "lldpq.link_flap_analyzer.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    LinkFlapAnalyzer._atomic_json_write(
                        str(path), {"new": True}
                    )
            self.assertEqual(path.read_text(encoding="utf-8"), '{"old":true}\n')


if __name__ == "__main__":
    unittest.main()
