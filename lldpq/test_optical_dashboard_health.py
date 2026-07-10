#!/usr/bin/env python3
"""Contracts for optical unknown coverage and aggregate health behavior."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
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


if __name__ == "__main__":
    unittest.main()
