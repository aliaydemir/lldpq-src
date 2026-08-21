#!/usr/bin/env python3
"""Per-file containment and trend-gate contracts for the BER analyzer.

monitor.sh rolls back every domain's analysis state when one analyzer exits
non-zero, so one device's empty/unparseable counter file must degrade that
host to partial coverage (flap-analyzer precedent) instead of failing the
run.  Trend detection must not flag a worsening anomaly on a port whose
absolute error density is nowhere near the warning zone: healthy ports hold
a zero baseline, so a single errored frame would otherwise yield an
astronomical relative ratio.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_ber_data
from ber_analyzer import BERAnalyzer

PROC_NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  swp1: 300000000 200000 0 0 0 0 0 0 300000000 200000 0 0 0 0 0 0
"""


class BerPerFileContainmentTests(unittest.TestCase):
    def _result_tree(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        result_dir.mkdir()
        return result_dir

    def test_empty_device_file_degrades_to_partial_coverage(self):
        result_dir = self._result_tree()
        ber_dir = result_dir / "ber-data"
        ber_dir.mkdir()
        (ber_dir / "leaf1_interface_errors.txt").write_text(PROC_NET_DEV)
        (ber_dir / "leaf2_interface_errors.txt").write_text("")
        snapshot = ({"leaf1": "OK", "leaf2": "OK"}, 1.0, True)

        with (
            mock.patch.object(process_ber_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_ber_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_ber_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_ber_data, "is_current_collection", return_value=True),
        ):
            success = process_ber_data.process_ber_data_files(str(ber_dir))

        # One bad device file must not fail the run; leaf2 degrades the
        # cycle to partial coverage while leaf1's artifacts publish.
        self.assertTrue(success)
        summary = json.loads(
            (result_dir / "summary" / "ber-summary.json").read_text())
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(summary["coverage_expected"], 2)
        self.assertEqual(summary["coverage_current"], 1)
        report = result_dir / "ber-analysis.html"
        self.assertTrue(report.is_file())
        self.assertGreater(report.stat().st_size, 0)


class BerTrendGateTests(unittest.TestCase):
    def _analyzer(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return BERAnalyzer(temporary.name), Path(temporary.name)

    @staticmethod
    def _history(densities):
        now = time.time()
        return [
            {
                "timestamp": now - 60 * (len(densities) - index),
                "ber_value": value,
                "grade": "excellent" if value == 0.0 else "good",
                "sample_status": "analyzed",
            }
            for index, value in enumerate(densities)
        ]

    def test_zero_baseline_single_errored_frame_not_worsening(self):
        analyzer, _tmp = self._analyzer()
        # Nine clean samples plus one errored frame over ~100 GB: density
        # 1.25e-12 sits six decades under the 1e-6 warning threshold.
        history = self._history([0.0] * 9 + [1.25e-12])
        analyzer.ber_history = {"leaf1:swp1": history}
        analyzer.current_ber_stats = {"leaf1:swp1": dict(history[-1])}

        trend = analyzer.get_ber_trend("leaf1:swp1")
        self.assertNotEqual(trend["trend"], "worsening")
        anomaly_types = [
            anomaly["type"] for anomaly in analyzer.detect_ber_anomalies()
        ]
        self.assertNotIn("LINK_ERROR_TREND_WORSENING", anomaly_types)

    def test_rising_density_near_warning_zone_flags_worsening(self):
        analyzer, tmp = self._analyzer()
        # 0 -> 5e-7 crosses the trend density floor (one decade below the
        # 1e-6 GOOD/WARNING boundary): a genuine early-warning trend.
        history = self._history([0.0] * 5 + [5e-7] * 5)
        analyzer.ber_history = {"leaf1:swp1": history}
        analyzer.current_ber_stats = {"leaf1:swp1": dict(history[-1])}

        trend = analyzer.get_ber_trend("leaf1:swp1")
        self.assertEqual(trend["trend"], "worsening")
        self.assertEqual(trend["confidence"], "high")
        # The ratio is normalized against the density floor, not ~1e-15.
        self.assertAlmostEqual(trend["change_ratio"], 5.0)

        summary = analyzer.get_ber_summary()
        anomalies = analyzer.detect_ber_anomalies(summary)
        anomaly_types = [anomaly["type"] for anomaly in anomalies]
        self.assertIn("LINK_ERROR_TREND_WORSENING", anomaly_types)

        output = tmp / "ber-analysis.html"
        analyzer.export_ber_data_for_web(
            str(output), summary=summary, anomalies=anomalies)
        report = output.read_text()
        # change_ratio is a relative delta, rendered as a signed percentage.
        self.assertIn("error density +500% vs baseline", report)
        self.assertNotIn("error density ×", report)


if __name__ == "__main__":
    unittest.main()
