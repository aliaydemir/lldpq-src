#!/usr/bin/env python3
"""Counter-less platforms must still grade plausible PHY BER on idle links.

Some platforms' l1-show output lacks the phy_symbol_errors counter entirely.
On those ports an idle-but-live degraded link can never prove activity via a
symbol advance, so the link-active gate would leave a genuinely degraded link
UNKNOWN indefinitely. Without a counter a stale snapshot cannot be
distinguished from a live reading anyway, so the analyzer grades any plausible
(below the invalid floor) PHY BER on counter-less ports while the invalid-floor
guard still discards the admin-down 1.0e+00 sentinel.
"""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ber_analyzer


def _analyzer(raw_map, extras_map):
    a = ber_analyzer.BERAnalyzer(data_dir="/tmp/lldpq-nonexistent-berdir")
    a._parse_raw_phy_ber_for_device = lambda h: dict(raw_map)
    a._parse_l1_extras_for_device = lambda h: dict(extras_map)
    return a


class CounterlessPlatformBERTests(unittest.TestCase):

    def test_counterless_platform_idle_degraded_link_graded(self):
        """No symbol counter at all + plausible bad raw BER => still graded."""
        a = _analyzer(
            {"swp9": 1e-3},  # plausible-but-bad pre-FEC BER
            {"swp9": {"effective_ber": 1e-9}},  # platform reports no counter
        )
        port = "leaf04:swp9"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "insufficient_traffic",  # no L2 traffic
            "delta_packets": 0,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertEqual(info["status"], ber_analyzer.BERGrade.CRITICAL.value)

    def test_counterless_platform_sentinel_still_unknown(self):
        """No symbol counter + 1.0e+00 sentinel => discarded, stays UNKNOWN."""
        a = _analyzer(
            {"swp10": 1.0},  # coef=1, mag=0 => 1.0e+00 admin-down sentinel
            {},  # no l1 extras at all
        )
        port = "leaf04:swp10"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "insufficient_traffic",
            "delta_packets": 0,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertIsNone(info["raw_ber"])
        self.assertEqual(info["status"], ber_analyzer.BERGrade.UNKNOWN.value)

    def test_platform_with_counter_keeps_stale_ber_ungraded(self):
        """Ports WITH a symbol counter keep the strict link-active gate."""
        a = _analyzer(
            {"swp13": 1e-3},  # plausible-but-stale value on a dead PHY
            {"swp13": {"effective_ber": 1e-9, "symbol_errors": 42}},
        )
        port = "leaf01:swp13"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "insufficient_traffic",
            "delta_packets": 0,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        # Prior identical symbol count => no symbol advance => link not active.
        a.ber_history = {port: [{"timestamp": 700.0, "symbol_errors": 42}]}
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertEqual(info["status"], ber_analyzer.BERGrade.UNKNOWN.value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
