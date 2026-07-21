#!/usr/bin/env python3
"""Kernel drop counters flow through the BER delta machinery.

/proc/net/dev drop columns were parsed but discarded between parse and
analysis; they now ride the same reset-safe baseline/delta path as the
error counters and surface as the Δ Drop (RX/TX) table column.
"""

import tempfile
import unittest

from ber_analyzer import BERAnalyzer


def _stats(errors=0, dropped=0, packets=200000, bytes_=300000000):
    return {
        'rx_errors': errors, 'tx_errors': errors,
        'rx_bytes': bytes_, 'tx_bytes': bytes_,
        'rx_packets': packets, 'tx_packets': packets,
        'rx_dropped': dropped, 'tx_dropped': dropped,
    }


class BerDropDeltaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = BERAnalyzer(data_dir=self.tmp.name)

    def test_drop_deltas_reach_delta_details(self):
        self.analyzer.calculate_delta_ber("tor-a", "swp1", _stats(dropped=100))
        self.analyzer.calculate_delta_ber(
            "tor-a", "swp1", _stats(dropped=175, packets=500000)
        )

        details = self.analyzer._last_delta_details["tor-a:swp1"]
        self.assertEqual(75, details['delta_rx_dropped'])
        self.assertEqual(75, details['delta_tx_dropped'])
        baseline = self.analyzer.baseline_data["tor-a"]["swp1"]
        self.assertEqual(175, baseline['rx_dropped'])
        self.assertEqual(175, baseline['tx_dropped'])

    def test_legacy_baseline_without_drop_keys_reads_zero_not_reset(self):
        self.analyzer.calculate_delta_ber("tor-a", "swp1", _stats())
        # Simulate a pre-upgrade baseline file: no drop keys persisted.
        del self.analyzer.baseline_data["tor-a"]["swp1"]['rx_dropped']
        del self.analyzer.baseline_data["tor-a"]["swp1"]['tx_dropped']

        _density, is_baseline, *_rest = self.analyzer.calculate_delta_ber(
            "tor-a", "swp1", _stats(dropped=999, packets=500000)
        )

        self.assertFalse(is_baseline)
        details = self.analyzer._last_delta_details["tor-a:swp1"]
        self.assertEqual(0, details['delta_rx_dropped'])
        self.assertEqual(0, details['delta_tx_dropped'])

    def test_export_rows_stay_inside_the_export_registry(self):
        # The live pipeline failed with "ber export row 0 carries keys outside
        # the registry" when a new analyzer field missed export_artifacts.py:
        # exercise the real normalize path against real export rows.
        import os
        from export_artifacts import normalize_rows

        self.analyzer.calculate_delta_ber("tor-a", "swp1", _stats())
        self.analyzer.calculate_delta_ber(
            "tor-a", "swp1", _stats(dropped=7, packets=500000)
        )
        self.analyzer.export_ber_data_for_web(
            os.path.join(self.tmp.name, "ber-analysis.html")
        )

        normalized = normalize_rows("ber", self.analyzer.export_rows)
        if normalized:
            self.assertIn("delta_rx_dropped", normalized[0])

    def test_drop_counter_reset_re_baselines(self):
        self.analyzer.calculate_delta_ber("tor-a", "swp1", _stats(dropped=500))
        self.analyzer.calculate_delta_ber(
            "tor-a", "swp1", _stats(dropped=800, packets=500000)
        )

        _density, is_baseline, *_rest = self.analyzer.calculate_delta_ber(
            "tor-a", "swp1", _stats(dropped=3, packets=700000)
        )

        self.assertTrue(is_baseline)
        self.assertTrue(
            self.analyzer._last_delta_details["tor-a:swp1"]['counter_reset']
        )
        self.assertEqual(
            3, self.analyzer.baseline_data["tor-a"]["swp1"]['rx_dropped']
        )


if __name__ == "__main__":
    unittest.main()
