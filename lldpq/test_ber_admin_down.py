#!/usr/bin/env python3
"""Admin-down / link-down ports must not be graded from stale L1 BER snapshots.

An admin-down or link-down interface keeps reporting its last l1-show snapshot,
which is frequently the degenerate raw_ber_coef=1 / magnitude=0 => 1.0e+00 "no
measurement" sentinel. Grading that as a real pre-FEC bit-error condition marks
an idle port CRITICAL forever. The analyzer must:
  * discard physically impossible readings (BER at or above the invalid floor), and
  * only let PHY BER / symbol metrics drive health when the sample proves the
    link was actually receiving (traffic, new errors, or an advancing FEC
    symbol counter).
A genuinely degraded ACTIVE link must still be graded CRITICAL.
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


class AdminDownBERTests(unittest.TestCase):

    def test_admin_down_degenerate_sentinel_not_critical(self):
        """No traffic + raw BER 1.0e+00 sentinel => ungraded, not CRITICAL."""
        a = _analyzer(
            {"swp13": 1.0},  # coef=1, mag=0 => 1.0e+00
            {"swp13": {"effective_ber": 1.5e-254, "symbol_errors": 0}},
        )
        port = "p10-oob-spine-02:swp13"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "insufficient_traffic",
            "delta_packets": 0,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 848535,
        }
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertNotEqual(info["status"], ber_analyzer.BERGrade.CRITICAL.value)
        self.assertEqual(info["status"], ber_analyzer.BERGrade.UNKNOWN.value)
        # The degenerate sentinel is discarded, so it renders N/A, not 1.00e+00.
        self.assertIsNone(info["raw_ber"])
        self.assertEqual(info["severity_reasons"], [])

    def test_idle_port_with_plausible_stale_ber_not_graded(self):
        """A plausible but stale raw BER on a dead PHY stays ungraded."""
        a = _analyzer(
            {"swp13": 1e-3},  # plausible-but-bad value, but link is idle/down
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

    def test_active_degraded_link_still_critical(self):
        """Traffic flowing + bad pre-FEC BER must remain CRITICAL."""
        a = _analyzer(
            {"swp1": 1e-3},
            {"swp1": {"effective_ber": 1e-9, "symbol_errors": 5000}},
        )
        port = "leaf01:swp1"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "analyzed",
            "delta_packets": 50000,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        a.ber_history = {port: [{"timestamp": 700.0, "symbol_errors": 0}]}
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertEqual(info["status"], ber_analyzer.BERGrade.CRITICAL.value)

    def test_idle_but_up_link_with_symbol_advance_is_graded(self):
        """A PHY that advances its FEC symbol counter with no L2 traffic is live."""
        a = _analyzer(
            {"swp5": 1e-3},  # bad pre-FEC BER
            {"swp5": {"effective_ber": 1e-9, "symbol_errors": 8000}},
        )
        port = "leaf02:swp5"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "insufficient_traffic",  # no L2 traffic this window
            "delta_packets": 0,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        # Symbol counter advanced (0 -> 8000) => link is physically receiving.
        a.ber_history = {port: [{"timestamp": 700.0, "symbol_errors": 0}]}
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertEqual(info["status"], ber_analyzer.BERGrade.CRITICAL.value)

    def test_active_link_rejects_impossible_ber(self):
        """Even with traffic, a >=1.0 BER reading is discarded as invalid."""
        a = _analyzer(
            {"swp7": 1.0},  # impossible for a link passing traffic
            {"swp7": {"effective_ber": 2.0, "symbol_errors": 0}},
        )
        port = "leaf03:swp7"
        stats = {
            "timestamp": 1000.0,
            "ber_value": 0.0,
            "sample_status": "analyzed",
            "delta_packets": 50000,
            "delta_rx_errors": 0,
            "delta_tx_errors": 0,
            "sample_duration_seconds": 300,
        }
        a.ber_history = {port: [{"timestamp": 700.0, "symbol_errors": 0}]}
        a.current_ber_stats = {port: stats}
        info = a._analyze_port(port, stats)
        self.assertIsNone(info["raw_ber"])
        self.assertIsNone(info["effective_ber"])
        # No valid L1 evidence and no frame-density errors => not CRITICAL.
        self.assertNotEqual(info["status"], ber_analyzer.BERGrade.CRITICAL.value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
