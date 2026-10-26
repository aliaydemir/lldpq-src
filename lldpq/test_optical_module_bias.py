#!/usr/bin/env python3
"""Regression coverage for module-specific TX bias limits and lane flags.

An MMS4X00-NM-T reports roughly 339 mA with 480/500 mA high warning/alarm
limits.  The former universal 100 mA high limit incorrectly made it critical.
Use the actual diagnostic spellings and values, without customer identifiers.
"""

from pathlib import Path
import json
import sys
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from optical_analyzer import OpticalAnalyzer


MODULE_LIMITS = {
    "high_alarm": 500.0,
    "low_alarm": 100.0,
    "high_warning": 480.0,
    "low_warning": 120.0,
}


def sample(bias=None, *, limits=MODULE_LIMITS, flags=None, dark_lanes=()):
    """CMIS ethtool output, preserving its distinct Channel/Chan spellings."""
    if bias is None:
        bias = {lane: 338.992 if lane <= 4 else 336.064
                for lane in range(1, 9)}
    lines = [
        "Identifier : 0x19 (OSFP 8X Pluggable Transceiver)",
        "Vendor name : NVIDIA",
        "Vendor PN : MMS4X00-NM-T",
        "Revision compliance : Rev. 5.1",
        "Module temperature : 43.18 degrees C / 109.72 degrees F",
        "Module voltage : 3.2703 V",
    ]
    for lane, value in sorted(bias.items()):
        lines.append(f"Laser tx bias current (Channel {lane}) : {value} mA")
        tx = "0.0000 mW / -inf dBm" if lane in dark_lanes else "1.6211 mW / 2.10 dBm"
        rx = "0.0000 mW / -inf dBm" if lane in dark_lanes else "1.6300 mW / 2.12 dBm"
        lines.extend([
            f"Transmit avg optical power (Channel {lane}) : {tx}",
            f"Rcvr signal avg optical power (Channel {lane}) : {rx}",
        ])
    for (lane, kind), on in (flags or {}).items():
        lines.append(
            f"Laser bias current {kind.replace('_', ' ')} (Chan {lane})"
            f" : {'On' if on else 'Off'}"
        )
    for kind, value in (limits or {}).items():
        lines.append(
            f"Laser bias current {kind.replace('_', ' ')} threshold : {value} mA"
        )
    return "\n".join(lines) + "\n"


class OpticalModuleBiasTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.analyzer = OpticalAnalyzer(self.directory.name, load_history=False)

    def grade(self, output, port="switch-a:swp61"):
        self.assertTrue(self.analyzer.update_optical_stats(port, output))
        return self.analyzer.current_optical_stats[port]

    def test_reported_osfp_is_normal_at_339_ma(self):
        flags = {(lane, kind): False
                 for lane in range(1, 9) for kind in MODULE_LIMITS}
        stats = self.grade(sample(flags=flags))
        self.assertIn(stats["health_status"], ("good", "excellent"))
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertAlmostEqual(stats["bias_current_ma"], 338.992)
        self.assertEqual(stats["bias_current_lane_ids"], list(range(1, 9)))
        self.assertEqual(stats["bias_thresholds_ma"], MODULE_LIMITS)
        self.assertEqual(self.analyzer.detect_optical_anomalies(), [])

    def test_numeric_limits_detect_both_warning_and_alarm_directions(self):
        for current, expected in ((501, "critical"), (490, "warning"),
                                  (110, "warning"), (99, "critical"),
                                  (500, "critical"), (480, "warning"),
                                  (120, "warning"), (100, "critical")):
            with self.subTest(current_ma=current):
                stats = self.grade(sample({1: current}))
                self.assertEqual(stats["health_status"], expected)
                self.assertEqual(stats["bias_assessment"]["status"], expected)

    def test_low_bias_alarm_is_not_hidden_by_a_higher_healthy_lane(self):
        stats = self.grade(sample({1: 339, 2: 99}))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["bias_current_lane"], 2)
        self.assertEqual(stats["bias_current_ma"], 99)

    def test_worst_low_bias_lane_is_the_furthest_below_its_limit(self):
        stats = self.grade(sample({1: 1, 2: 99}))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["bias_current_lane"], 1)
        self.assertEqual(stats["bias_current_ma"], 1)

    def test_alarm_message_explains_value_module_limit_and_lane(self):
        self.grade(sample({1: 339, 2: 501}))
        anomalies = self.analyzer.detect_optical_anomalies()
        messages = " ".join(item["message"] for item in anomalies)
        self.assertIn("bias", messages.lower())
        self.assertIn("501", messages)
        self.assertIn("500", messages)
        self.assertIn("mA", messages)
        self.assertRegex(messages.lower(), r"(?:lane\s+|channel\s+|\bl)2\b")
        self.assertFalse(any(item["type"] == "CRITICAL_OPTICAL_PARAMETER"
                             for item in anomalies))

    def test_old_sff_non_channel_bias_syntax_uses_module_limits(self):
        output = sample({1: 339}).replace(
            "Laser tx bias current (Channel 1)", "Laser bias current"
        )
        stats = self.grade(output)
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertNotEqual(stats["health_status"], "critical")

    def test_alarm_flags_work_without_numeric_thresholds(self):
        for kind, expected in (("high_alarm", "critical"),
                               ("low_alarm", "critical"),
                               ("high_warning", "warning"),
                               ("low_warning", "warning")):
            with self.subTest(kind=kind):
                stats = self.grade(sample(
                    {1: 339}, limits=None, flags={(1, kind): True}
                ))
                self.assertEqual(stats["health_status"], expected)
                self.assertEqual(stats["bias_assessment"]["status"], expected)

    def test_flags_only_sample_still_reports_the_hardware_alarm(self):
        for kind, expected in (("high_alarm", "critical"),
                               ("low_warning", "warning")):
            with self.subTest(kind=kind):
                stats = self.grade(
                    f"Laser bias current {kind.replace('_', ' ')} (Chan 1) : On\n"
                )
                self.assertEqual(stats["health_status"], expected)
                self.assertEqual(stats["bias_assessment"]["status"], expected)
                self.assertIsNone(stats["bias_current_ma"])

    def test_off_flags_do_not_override_a_numeric_alarm(self):
        flags = {(1, kind): False for kind in MODULE_LIMITS}
        stats = self.grade(sample({1: 501}, flags=flags))
        self.assertEqual(stats["health_status"], "critical")

    def test_on_alarm_flag_is_not_ignored_when_reading_is_in_range(self):
        stats = self.grade(sample(
            {1: 339}, flags={(1, "high_alarm"): True}
        ))
        self.assertEqual(stats["health_status"], "critical")

    def test_sff_non_channel_flags_are_not_lost(self):
        output = sample({1: 30}, limits=None).replace(
            "Laser tx bias current (Channel 1)", "Laser bias current"
        ) + "Laser bias current high alarm : On\n"
        self.assertEqual(self.grade(output)["health_status"], "critical")

    def test_complete_off_flags_are_valid_evidence_without_numeric_limits(self):
        flags = {(1, kind): False for kind in MODULE_LIMITS}
        stats = self.grade(sample({1: 339}, limits=None, flags=flags))
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertIn(stats["health_status"], ("good", "excellent"))

    def test_one_off_flag_does_not_imply_the_unreported_flags_are_off(self):
        stats = self.grade(sample(
            {1: 339}, limits=None, flags={(1, "high_alarm"): False}
        ))
        self.assertEqual(stats["bias_assessment"]["status"], "unknown")
        self.assertIn(stats["health_status"], ("good", "excellent"))

    def test_no_limits_or_flags_leaves_only_bias_assessment_unknown(self):
        stats = self.grade(sample({1: 339}, limits=None))
        self.assertEqual(stats["bias_assessment"]["status"], "unknown")
        self.assertIn(stats["health_status"], ("good", "excellent"))
        self.assertEqual(self.analyzer.detect_optical_anomalies(), [])

    def test_partial_high_limit_never_reintroduces_universal_100_ma(self):
        for current, expected in ((339, False), (501, True)):
            with self.subTest(current_ma=current):
                stats = self.grade(sample(
                    {1: current}, limits={"high_alarm": 500}
                ))
                self.assertEqual(stats["health_status"] == "critical", expected)
                self.assertEqual(stats["bias_assessment"]["status"],
                                 "critical" if expected else "unknown")

    def test_equal_same_direction_warning_and_alarm_limits_remain_valid(self):
        stats = self.grade(sample(
            {1: 501}, limits={"high_warning": 500, "high_alarm": 500}
        ))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["bias_thresholds_ma"],
                         {"high_warning": 500, "high_alarm": 500})

    def test_invalid_limit_tables_are_not_used_to_create_alarms(self):
        invalid_tables = (
            {"high_alarm": "NaN", "low_alarm": "-inf"},
            {"high_alarm": -1},
            {"low_alarm": 500, "high_alarm": 100},
            dict.fromkeys(MODULE_LIMITS, 0),
        )
        for limits in invalid_tables:
            with self.subTest(limits=limits):
                stats = self.grade(sample({1: 339}, limits=limits))
                self.assertEqual(stats["bias_assessment"]["status"], "unknown")
                self.assertIn(stats["health_status"], ("good", "excellent"))

    def test_breakout_ignores_other_channels_numeric_and_flag_alarms(self):
        output = sample({1: 339, 2: 501}, flags={(2, "high_alarm"): True})
        own = self.grade(output, "switch-a:swp61s0")
        other = self.grade(output, "switch-a:swp61s1")
        self.assertIn(own["health_status"], ("good", "excellent"))
        self.assertEqual(own["bias_assessment"]["status"], "normal")
        self.assertEqual(own["bias_current_lane_ids"], [1])
        self.assertEqual(other["health_status"], "critical")

    def test_already_scoped_breakout_reading_keeps_its_physical_lane_flag(self):
        # A single returned measurement is already interface-scoped even
        # when its physical channel differs from the swpNsM suffix.
        flags = {(lane, "high_alarm"): lane == 8 for lane in range(1, 9)}
        stats = self.grade(sample({8: 339}, flags=flags), "switch-a:swp61s0")
        self.assertEqual(stats["bias_current_lane_ids"], [8])
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["bias_assessment"]["status"], "critical")
        self.assertEqual(stats["bias_assessment"]["events"][0]["lane"], 8)

    def test_flags_only_breakout_does_not_inherit_another_lanes_alarm(self):
        flags = {(lane, kind): lane == 2 and kind == "high_alarm"
                 for lane in (1, 2) for kind in MODULE_LIMITS}
        output = sample({}, limits=None, flags=flags)
        own = self.grade(output, "switch-a:swp61s0")
        other = self.grade(output, "switch-a:swp61s1")
        self.assertEqual(own["health_status"], "unknown")
        self.assertEqual(own["bias_assessment"]["status"], "normal")
        self.assertEqual(other["health_status"], "critical")

    def test_unfamiliar_breakout_flag_numbering_does_not_hide_an_alarm(self):
        # No channel matches swp61s0's expected lane1. Preserve evidence in
        # the same way as existing measurement-lane selection.
        flags = {(lane, kind): lane == 7 and kind == "high_alarm"
                 for lane in (7, 8) for kind in MODULE_LIMITS}
        stats = self.grade(sample({}, limits=None, flags=flags),
                           "switch-a:swp61s0")
        self.assertEqual(stats["health_status"], "critical")

    def test_unlit_spare_lanes_do_not_cause_low_bias_alarms(self):
        stats = self.grade(sample(
            {1: 339, 2: 0}, dark_lanes=(2,),
            flags={(2, "low_alarm"): True},
        ))
        self.assertEqual(stats["inactive_lanes"], [2])
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertIn(stats["health_status"], ("good", "excellent"))

    def test_other_optical_faults_remain_critical_without_bias_limits(self):
        output = sample({1: 339}, limits=None).replace(
            "1.6300 mW / 2.12 dBm", "0.0100 mW / -20.00 dBm"
        )
        stats = self.grade(output)
        self.assertEqual(stats["bias_assessment"]["status"], "unknown")
        self.assertEqual(stats["health_status"], "critical")
        self.assertTrue(any(item["type"] == "LOW_OPTICAL_POWER"
                            for item in self.analyzer.detect_optical_anomalies()))

    def test_bias_evidence_survives_history_round_trip(self):
        self.grade(sample({1: 501}))
        self.assertTrue(self.analyzer.save_optical_history())
        restored = OpticalAnalyzer(self.directory.name)
        stats = restored.current_optical_stats["switch-a:swp61"]
        self.assertEqual(stats["bias_thresholds_ma"], MODULE_LIMITS)
        self.assertEqual(stats["bias_assessment"]["status"], "critical")
        messages = " ".join(item["message"]
                            for item in restored.detect_optical_anomalies())
        self.assertIn("501", messages)
        self.assertIn("500", messages)

    def test_web_detail_exposes_the_limits_used_for_the_verdict(self):
        self.grade(sample({1: 501}))
        output = Path(self.directory.name) / "optical.html"
        self.analyzer.export_optical_data_for_web(str(output))
        detail = json.loads((Path(self.directory.name) / "optical-details"
                             / "switch-a.json").read_text())
        port = detail["ports"]["switch-a:swp61"]
        self.assertEqual(port["bias_thresholds_ma"], MODULE_LIMITS)
        self.assertEqual(port["bias_assessment"]["status"], "critical")
        self.assertNotIn("Maximum laser bias current", output.read_text())


if __name__ == "__main__":
    unittest.main()
