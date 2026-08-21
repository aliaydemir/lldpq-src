#!/usr/bin/env python3
"""Contracts for optical unknown coverage and aggregate health behavior."""

from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from optical_analyzer import OpticalAnalyzer

ROOT = SCRIPT_DIR.parent
SOURCE = (ROOT / "html/start.html").read_text(encoding="utf-8")


class OpticalDashboardHealthTests(unittest.TestCase):
    def test_unknown_and_unplugged_have_visible_cards(self):
        for element_id in ("optical-unplugged", "optical-unknown"):
            self.assertEqual(SOURCE.count(f'id="{element_id}"'), 1)
            self.assertIn(f"updateDashboardCard('{element_id}'", SOURCE)

    def test_partial_report_does_not_block_all_health_domains(self):
        assignment = SOURCE.split(
            "const blockingAnalysisProblems =", 1
        )[1].split(";", 1)[0]
        self.assertIn("unavailableAnalyses", assignment)
        self.assertIn("pipelineNotCurrent", assignment)
        self.assertNotIn("partialAnalyses", assignment)
        self.assertIn(
            "data?.coveragePartial && !allowPartial", SOURCE
        )

    def test_optical_unknown_is_excluded_from_comparable_denominator(self):
        comparable = SOURCE.split(
            "const opticalComparablePorts =", 1
        )[1].split(";", 1)[0]
        self.assertIn("opticalData.unplugged", comparable)
        self.assertIn("opticalData.unknown", comparable)
        self.assertIn(
            "opticalData.coverageCollected", SOURCE
        )
        self.assertIn(
            "opticalData, opticalHostCoverageComplete", SOURCE
        )


class OpticalWorstLaneSelectionTests(unittest.TestCase):
    """The named worst RX lane agrees with link_margin_db's source lane.

    The hard RX window (-14..+7 dBm) is asymmetric relative to the boundaries
    that actually trigger next (margin floor, high-power warning): ranking
    healthy lanes by the nearest hard bound named a bright-but-safe lane
    worst while link_margin_db was taken from the dimmest lane.
    """

    @staticmethod
    def _sample(lane_rx_dbm):
        lines = [
            "cable-type                  : Optical module",
            "temperature                 : 43.94 degrees C",
            "voltage                     : 3.3015 V",
        ]
        for lane, rx_dbm in sorted(lane_rx_dbm.items()):
            milliwatts = 10 ** (rx_dbm / 10)
            lines.append(f"ch-{lane}-rx-power : {milliwatts:.4f} mW / {rx_dbm:.2f} dBm")
            lines.append(f"ch-{lane}-tx-power : 1.2589 mW / 1.00 dBm")
            lines.append(f"ch-{lane}-tx-bias-current : 70.000 mA")
        return "\n".join(lines) + "\n"

    def test_worst_lane_matches_link_margin_source_on_asymmetric_window(self):
        # Lane 1 is high but safe: +3.0 dBm, 2 dB below the 5 dBm warning.
        # Lane 2 has the least margin: 4.5 dB, 1.5 dB above the 3 dB floor.
        # Nearest-hard-bound ranking named lane 1 (4 dB to +7 critical high).
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        analyzer = OpticalAnalyzer(tmp.name, load_history=False)
        analyzer.update_optical_stats(
            "switch-a:swp1", self._sample({1: 3.0, 2: -9.5})
        )
        stats = analyzer.current_optical_stats["switch-a:swp1"]

        self.assertEqual(stats["rx_power_lane"], 2)
        self.assertEqual(stats["rx_power_dbm"], -9.5)
        self.assertAlmostEqual(
            stats["link_margin_db"],
            analyzer.calculate_link_margin(stats["rx_power_dbm"]),
            msg="the displayed worst lane is the lane the margin comes from",
        )
        # Grading iterates every lane and must not move with the pick.
        self.assertEqual(stats["health_status"], "good")


if __name__ == "__main__":
    unittest.main()
