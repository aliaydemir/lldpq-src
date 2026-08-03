#!/usr/bin/env python3
"""Regression tests for unreadable carrier counters.

``carrier_changes`` is cumulative, and the analyzer derives flaps from the
delta against the previous cycle.  Reporting a failed read as 0 therefore
looked like a counter reset: the port re-baselined at 0 and the next
successful read was billed as thousands of flaps that never happened.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_flap_data
from link_flap_analyzer import LinkFlapAnalyzer


class PhantomFlapBurstTests(unittest.TestCase):
    """The behaviour that made a zeroed sample dangerous."""

    def test_a_zero_sample_between_two_healthy_reads_invents_flaps(self):
        with tempfile.TemporaryDirectory() as root:
            analyzer = LinkFlapAnalyzer(root)
            analyzer.update_carrier_transitions("leaf1:swp1", 5000)
            analyzer.update_carrier_transitions("leaf1:swp1", 0)
            analyzer.update_carrier_transitions("leaf1:swp1", 5002)
            invented = sum(
                entry[2] for entry in analyzer.flapping_hist["leaf1:swp1"]
            )
        self.assertGreater(
            invented, 1000,
            "guard test: a zeroed sample must be shown to be destructive",
        )

    def test_skipping_the_failed_read_preserves_the_real_delta(self):
        with tempfile.TemporaryDirectory() as root:
            analyzer = LinkFlapAnalyzer(root)
            analyzer.update_carrier_transitions("leaf1:swp1", 5000)
            # The unreadable cycle is never handed to the analyzer.
            analyzer.update_carrier_transitions("leaf1:swp1", 5002)
            counted = sum(
                entry[2] for entry in analyzer.flapping_hist["leaf1:swp1"]
            )
        self.assertEqual(counted, 1)


class UnavailableRowHandlingTests(unittest.TestCase):
    def _flap_dir(self, contents):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        result_dir.mkdir()
        flap_dir = result_dir / "flap-data"
        flap_dir.mkdir()
        (flap_dir / "leaf1_carrier_transitions.txt").write_text(contents)
        return flap_dir

    def _run(self, contents):
        flap_dir = self._flap_dir(contents)
        snapshot = ({"leaf1": "OK"}, 1.0, True)
        with (
            mock.patch.object(
                process_flap_data, "read_asset_snapshot", return_value=snapshot
            ),
            mock.patch.object(
                process_flap_data, "asset_snapshot_is_valid", return_value=True
            ),
            mock.patch.object(
                process_flap_data,
                "asset_snapshot_is_authoritative",
                return_value=True,
            ),
            mock.patch.object(
                process_flap_data, "is_current_collection", return_value=True
            ),
            mock.patch.object(
                LinkFlapAnalyzer, "update_carrier_transitions", autospec=True
            ) as update,
            mock.patch.object(
                LinkFlapAnalyzer, "set_collection_coverage", autospec=True
            ) as coverage,
        ):
            result = process_flap_data.process_carrier_transition_files(
                str(flap_dir)
            )
        samples = [(call.args[1], call.args[2]) for call in update.call_args_list]
        expected_hosts, current_hosts = coverage.call_args.args[1:3]
        return result, samples, set(expected_hosts) - set(current_hosts)

    def test_unavailable_rows_are_not_sampled(self):
        result, samples, failed_hosts = self._run("swp1:unavailable\nswp2:41\n")
        self.assertEqual(samples, [("leaf1:swp2", 41)])
        self.assertTrue(
            result,
            "one unreadable counter must not roll back every domain",
        )
        self.assertIn("leaf1", failed_hosts)

    def test_a_normal_collection_is_unaffected(self):
        result, samples, failed_hosts = self._run("swp1:12\nswp2:41\n")
        self.assertEqual(samples, [("leaf1:swp1", 12), ("leaf1:swp2", 41)])
        self.assertTrue(result)
        self.assertEqual(failed_hosts, set())

    def test_zero_remains_a_legitimate_reading(self):
        result, samples, failed_hosts = self._run("swp1:0\n")
        self.assertEqual(
            samples, [("leaf1:swp1", 0)],
            "a port that genuinely never flapped still reports 0",
        )
        self.assertTrue(result)
        self.assertEqual(failed_hosts, set())


class CollectorContractTests(unittest.TestCase):
    """The collector must not substitute 0 for a failed read."""

    def test_monitor_reports_unavailable_instead_of_zero(self):
        source = (SCRIPT_DIR / "monitor.sh").read_text()
        match = re.search(
            r'read -r carrier_count < "[^"]*carrier_changes"[^\n]*\n',
            source,
        )
        self.assertIsNotNone(match, "carrier counter read was not found")
        read_line = match.group(0)
        self.assertNotIn('carrier_count="0"', read_line)
        self.assertIn('carrier_count="unavailable"', read_line)

    def test_non_numeric_and_empty_reads_are_normalized(self):
        source = (SCRIPT_DIR / "monitor.sh").read_text()
        self.assertRegex(
            source, r"\*\[!0-9\]\*\)\s*carrier_count=\"unavailable\""
        )
        self.assertIn(
            '[ -n "$carrier_count" ] || carrier_count="unavailable"', source
        )


if __name__ == "__main__":
    unittest.main()
