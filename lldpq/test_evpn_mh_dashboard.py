#!/usr/bin/env python3
"""Static contracts for the homepage EVPN-MH summary integration."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "html/start.html").read_text(encoding="utf-8")


class EvpnMhDashboardTests(unittest.TestCase):
    def test_section_is_between_evpn_and_duplicate(self):
        evpn = SOURCE.index("<!-- EVPN Summary Section -->")
        evpn_mh = SOURCE.index("<!-- EVPN Multi-Homing Analysis Section -->")
        duplicate = SOURCE.index("<!-- Duplicate Address Analysis Section -->")
        self.assertLess(evpn, evpn_mh)
        self.assertLess(evpn_mh, duplicate)
        for element_id in (
            "evpn-mh-total", "evpn-mh-healthy", "evpn-mh-inactive",
            "evpn-mh-bypass", "evpn-mh-inconsistent", "evpn-mh-orphan",
        ):
            self.assertEqual(SOURCE.count(f'id="{element_id}"'), 1)

    def test_manifest_fetch_and_cards_use_report_contract(self):
        # EVPN-MH moved to the skippable set: a manifest is valid when the
        # analysis either completed or is recorded as skipped (SKIP_EVPN_MH).
        self.assertIn(
            "const skippableAnalyses = "
            "['optical', 'duplicate', 'evpn-mh', 'pfc-ecn'];",
            SOURCE,
        )
        self.assertIn(
            "'evpn-mh': 'monitor-results/evpn-mh-analysis.html'", SOURCE
        )
        self.assertIn("fetchRawDataSummary('evpn-mh', pipelineState)", SOURCE)
        self.assertIn("evpnData, evpnMhData", SOURCE)
        for metric in (
            "totalEs", "healthyEs", "inactiveEs", "bypassEs",
            "bypassIssueEs", "criticalEs", "warningEs",
            "inconsistentEs", "orphanEs",
        ):
            self.assertIn(f"metadataNumber('{metric}')", SOURCE)
        for element_id in (
            "evpn-mh-total", "evpn-mh-healthy", "evpn-mh-inactive",
            "evpn-mh-bypass", "evpn-mh-inconsistent", "evpn-mh-orphan",
        ):
            self.assertIn(f"updateDashboardCard('{element_id}'", SOURCE)

    def test_open_issues_are_partitioned_without_overlap(self):
        breakdown = SOURCE.split("const criticalBreakdown = {", 1)[1].split(
            "};", 1
        )[0]
        for label in (
            "EVPN-MH Critical", "EVPN-MH Warning",
            "EVPN-MH Bypass Active", "EVPN-MH Inactive / Down",
        ):
            self.assertIn(label, breakdown)
        self.assertNotIn("EVPN-MH Orphan", breakdown)
        self.assertNotIn("EVPN-MH Inconsistent", breakdown)
        critical_sources = SOURCE.split(
            "const CRITICAL_SOURCES = new Set([", 1
        )[1].split("]);", 1)[0]
        self.assertIn("'EVPN-MH Critical'", critical_sources)
        self.assertNotIn("'EVPN-MH Warning'", critical_sources)
        self.assertIn(
            "evpnMhData.total - (evpnMhData.critical || 0)", SOURCE
        )


if __name__ == "__main__":
    unittest.main()
