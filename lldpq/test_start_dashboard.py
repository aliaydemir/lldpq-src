#!/usr/bin/env python3
"""Static contracts for the homepage PFC/ECN summary integration."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
START_HTML = ROOT / "html" / "start.html"


class StartDashboardPfcEcnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = START_HTML.read_text(encoding="utf-8")

    def test_section_is_immediately_after_ber_with_six_cards(self):
        ber = self.source.index("<!-- BER Analysis Section -->")
        pfc = self.source.index("<!-- PFC/ECN Analysis Section -->")
        self.assertLess(ber, pfc)
        between = self.source[ber:pfc]
        self.assertEqual(between.count('class="analysis-section"'), 1)

        for element_id in (
            "pfc-total", "pfc-ready", "pfc-ecn", "pfc-rx", "pfc-tx",
            "pfc-discards",
        ):
            self.assertEqual(self.source.count(f'id="{element_id}"'), 1)

        self.assertIn("pfc-ecn-analysis.html?filter=ecn", self.source)
        self.assertIn("pfc-ecn-analysis.html?filter=rx", self.source)
        self.assertIn("pfc-ecn-analysis.html?filter=tx", self.source)
        self.assertIn("pfc-ecn-analysis.html?filter=loss", self.source)

    def test_manifest_and_fetch_batch_require_current_pfc_report(self):
        # PFC/ECN moved to the skippable set: a manifest is valid when the
        # analysis either completed or is recorded as skipped (SKIP_PFC_ECN).
        self.assertIn(
            "const skippableAnalyses = "
            "['optical', 'duplicate', 'evpn-mh', 'pfc-ecn'];",
            self.source,
        )
        self.assertIn("'pfc': 'monitor-results/pfc-ecn-analysis.html'", self.source)
        self.assertIn("pfcData, flapData, hardwareData", self.source)
        self.assertIn("fetchRawDataSummary('pfc', pipelineState)", self.source)
        self.assertIn("reportMeta?.dataset?.analysisSummary === 'pfc-ecn'", self.source)

    def test_all_six_card_values_are_updated(self):
        for element_id in (
            "pfc-total", "pfc-ready", "pfc-ecn", "pfc-rx", "pfc-tx",
            "pfc-discards",
        ):
            self.assertIn(f"updateDashboardCard('{element_id}'", self.source)
        for metric in (
            "totalPorts", "readyPorts", "ecnActivePorts", "pfcRxActivePorts",
            "pfcTxActivePorts", "discardReadyPorts", "discardActivePorts",
        ):
            self.assertIn(f"metadataNumber('{metric}')", self.source)
        self.assertIn("pfcData.discardReadyPorts === pfcData.readyPorts", self.source)
        self.assertIn("const pfcScopeWarning = pfcCoverageMissing === null", self.source)
        self.assertIn("Observed ports · partial coverage", self.source)
        self.assertIn("All collected ports have a usable interval", self.source)
        self.assertIn("pfcData.signalPartial ? 1 : pfcData.notReady", self.source)
        self.assertIn("'pfc-ecn', pfcSignalState, 0,", self.source)
        self.assertIn("pfcData.signalPartial ? 1 : 0, 'info'", self.source)

    def test_issue_semantics_do_not_grade_ecn_or_pfc_activity(self):
        breakdown = self.source.split("const criticalBreakdown = {", 1)[1].split("};", 1)[0]
        self.assertIn("'PFC Data Not Ready'", breakdown)
        self.assertIn("'PFC Discarding Ports'", breakdown)
        self.assertNotIn("ECN Active", breakdown)
        self.assertNotIn("PFC RX Active", breakdown)
        self.assertNotIn("PFC TX Active", breakdown)

        critical_sources = self.source.split("const CRITICAL_SOURCES = new Set([", 1)[1].split("]);", 1)[0]
        self.assertIn("'PFC Discarding Ports'", critical_sources)
        self.assertNotIn("'PFC Data Not Ready'", critical_sources)
        self.assertNotIn("addHealthDomain(pfcData", self.source)
        self.assertIn("berData, pfcData, flapData", self.source)


if __name__ == "__main__":
    unittest.main()
