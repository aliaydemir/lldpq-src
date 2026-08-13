#!/usr/bin/env python3
"""Grades a pluggable on the lanes it actually lights, not on its cage.

A QSFP-DD cage answers for eight diagnostic channels whether or not the module
is wired for eight optical lanes.  A 400G module using four of them reports the
rest as 0 mW / -inf dBm, floored to -40 dBm here, and grading those next to the
live lanes made the worst lane of a healthy port -40 dBm: uplinks passing
traffic at 400G were reported CRITICAL with "replace the cable", while their
real lanes sat at a comfortable +2.8 to +3.5 dBm.

Laser bias current is what tells the two kinds of dark lane apart, and the
distinction has to survive the fix.  A lane with no light and no bias current
was never driven and is not part of the port's health.  A lane drawing bias
with no light is a lit laser whose light never arrived, which is a real fault
and stays CRITICAL — as does a module that is dark on every lane it has.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts
import export_artifacts
from optical_analyzer import OpticalAnalyzer


# How a collector renders a channel carrying no light.  Every spelling seen
# from NVUE/ethtool builds, plus the contradictory one a driver could emit by
# formatting 0 mW into a finite dBm column.
DARK_INF = "0.0000 mW / -inf dBm"
DARK_FLOORED = "0.0000 mW / -40.00 dBm"
DARK_ZERO_DBM = "0.0000 mW / 0.00 dBm"

LASER_OFF = "0.000 mA"
LASER_ON = "70.000 mA"


def lit(dbm):
    """A channel carrying light, rendered the way the collector renders it."""
    return f"{10 ** (dbm / 10):.4f} mW / {dbm:.2f} dBm"


def nvue_sample(lanes, temperature=43.94, voltage=3.3015):
    """NVUE transceiver output for one port.

    *lanes* maps a lane number to the fields the collector reported for it
    ("rx", "tx", "bias"); an omitted field is a field the sample does not
    carry at all.  Lane numbers are data, never assumed to start at 1 or to
    run to any particular width.
    """
    lines = [
        "cable-type                  : Optical module",
        "identifier                  : QSFP-DD Double Density 8X Pluggable "
        "Transceiver INF-8628",
        f"temperature                 : {temperature} degrees C",
        f"voltage                     : {voltage} V",
    ]
    for lane in sorted(lanes):
        for field, name in (("rx", "rx-power"), ("tx", "tx-power"),
                            ("bias", "tx-bias-current")):
            if field in lanes[lane]:
                lines.append(f"ch-{lane}-{name} : {lanes[lane][field]}")
    return "\n".join(lines) + "\n"


def ethtool_sample(lanes, temperature=43.94, voltage=3.3015):
    """The same content in the ethtool -m spelling the collector also emits."""
    lines = [
        "\tIdentifier                                : 0x18 (QSFP-DD)",
        "\tTransceiver type                          : 400G Base-DR4",
        f"\tModule temperature                        : {temperature} degrees C",
        f"\tModule voltage                            : {voltage} V",
    ]
    for lane in sorted(lanes):
        readings = lanes[lane]
        if "rx" in readings:
            lines.append(
                f"\tRcvr signal avg optical power(Channel {lane})"
                f"    : {readings['rx']}"
            )
        if "tx" in readings:
            lines.append(
                f"\tTransmit avg optical power (Channel {lane})"
                f"   : {readings['tx']}"
            )
        if "bias" in readings:
            lines.append(
                f"\tLaser bias current (Channel {lane})"
                f"           : {readings['bias']}"
            )
    return "\n".join(lines) + "\n"


def _lane(rx, tx, bias):
    """One channel; a None field is one the sample does not report."""
    readings = {"rx": rx, "tx": tx, "bias": bias}
    return {field: value for field, value in readings.items()
            if value is not None}


def in_service(readings, first_lane=1, bias=LASER_ON):
    """Lanes carrying light: *readings* is a list of (rx dBm, tx dBm)."""
    return {
        lane: _lane(lit(rx), lit(tx), bias)
        for lane, (rx, tx) in enumerate(readings, start=first_lane)
    }


def unlit(lane_numbers, dark=DARK_INF, bias=LASER_OFF):
    return {lane: _lane(dark, dark, bias) for lane in lane_numbers}


# The switch the customer reported: four optical lanes in service in an
# eight-channel cage, the other four never lit.
REPORTED_LIT = [(2.77, 1.72), (3.03, 2.27), (3.10, 2.37), (3.47, 2.04)]
REPORTED_PORT = {**in_service(REPORTED_LIT), **unlit(range(5, 9))}


def grade(lanes, port="switch-a:swp1", render=nvue_sample, **kwargs):
    """Run one sample through the real collection path; return the stats."""
    analyzer = OpticalAnalyzer("monitor-results", load_history=False)
    analyzer.update_optical_stats(port, render(lanes, **kwargs))
    return analyzer, analyzer.current_optical_stats[port]


class UnlitLaneGradingTests(unittest.TestCase):
    def test_the_reported_four_lane_module_is_not_critical(self):
        _analyzer, stats = grade(REPORTED_PORT)
        self.assertNotIn(
            stats["health_status"], ("critical", "down"),
            "a port whose live lanes are all near +3 dBm is healthy",
        )
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertEqual(
            stats["rx_power_lanes_dbm"], [rx for rx, _tx in REPORTED_LIT],
            "only the lanes in service are graded",
        )
        self.assertGreater(
            stats["link_margin_db"], 0,
            "margin is taken from the worst lane actually in service",
        )

    def test_a_dark_lane_still_drawing_bias_stays_critical(self):
        broken = 3
        lanes = in_service(REPORTED_LIT)
        lanes[broken]["rx"] = DARK_INF
        _analyzer, stats = grade({**lanes, **unlit(range(5, 9))})
        self.assertEqual(
            stats["health_status"], "critical",
            "a driven laser with no light back is a fault, not a spare lane",
        )
        self.assertEqual(stats["rx_power_lane"], broken)
        self.assertNotIn(broken, stats["inactive_lanes"])

    def test_a_module_dark_on_every_lane_is_still_reported(self):
        _analyzer, stats = grade(unlit(range(1, 9)))
        self.assertEqual(
            stats["health_status"], "down",
            "a module with no light anywhere must not be graded away",
        )
        self.assertEqual(stats["inactive_lanes"], [])
        self.assertEqual(len(stats["rx_power_lanes_dbm"]), 8)

    def test_a_dark_link_on_a_partly_equipped_module_is_still_reported(self):
        # The lanes in service went dark with their lasers still driven: the
        # link is down, and setting the spare channels aside must not turn
        # that into a port with nothing to say.
        lanes = {**unlit(range(1, 5), bias=LASER_ON), **unlit(range(5, 9))}
        _analyzer, stats = grade(lanes)
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertEqual(stats["rx_power_lane_ids"], [1, 2, 3, 4])

    def test_a_single_lane_module_with_no_light_is_still_reported(self):
        _analyzer, stats = grade(unlit([1]))
        self.assertEqual(
            stats["health_status"], "down",
            "one lane is the whole port; it has no healthy peer to hide it",
        )
        self.assertEqual(stats["inactive_lanes"], [])

    def test_an_unlit_lane_is_recognised_however_it_is_spelled(self):
        for label, dark in (("-inf dBm", DARK_INF),
                            ("floored -40 dBm", DARK_FLOORED),
                            ("0 mW with a finite dBm", DARK_ZERO_DBM)):
            with self.subTest(spelling=label):
                _analyzer, stats = grade({
                    **in_service(REPORTED_LIT),
                    **unlit(range(5, 9), dark=dark),
                })
                self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
                self.assertNotIn(stats["health_status"], ("critical", "down"))

    def test_a_lane_reported_as_bias_only_is_not_graded_as_dark(self):
        # Some builds emit the bias line for an unequipped channel and no
        # power lines at all; there is nothing to grade and nothing to flag.
        _analyzer, stats = grade({
            **in_service(REPORTED_LIT),
            **{lane: {"bias": LASER_OFF} for lane in range(5, 9)},
        })
        self.assertNotIn(stats["health_status"], ("critical", "down"))
        self.assertEqual(stats["inactive_lanes"], [])

    def test_the_worst_lane_label_names_only_assessed_lanes(self):
        # The lanes in service are the high-numbered ones here: which lanes a
        # module lights is read from the sample, never assumed.
        lanes = {**unlit(range(1, 5)),
                 **in_service(REPORTED_LIT, first_lane=5)}
        _analyzer, stats = grade(lanes)
        self.assertEqual(stats["inactive_lanes"], [1, 2, 3, 4])
        for metric in ("rx_power_lane", "tx_power_lane", "bias_current_lane"):
            self.assertIn(
                stats[metric], range(5, 9),
                f"{metric} named a lane that was excluded from grading",
            )
        self.assertEqual(stats["rx_power_lane_ids"], [5, 6, 7, 8])

    def test_the_ethtool_channel_spelling_is_handled_the_same(self):
        _analyzer, stats = grade(REPORTED_PORT, render=ethtool_sample)
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertNotIn(stats["health_status"], ("critical", "down"))

    def test_a_genuinely_low_lane_is_still_critical(self):
        # The exclusion is about lanes that were never lit, not about weak
        # ones: light below the receive threshold is still a failure.
        lanes = in_service([(2.77, 1.72), (-21.0, 2.27)])
        _analyzer, stats = grade({**lanes, **unlit(range(5, 9))})
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["rx_power_lane"], 2)


class NoBiasDataTests(unittest.TestCase):
    """The fallback: without bias evidence, only a lit peer excuses a dark lane.

    A platform that reports no laser bias still must not call a port CRITICAL
    purely because one channel is dark while the others are healthy, and it
    still must report a module that is dark everywhere.
    """

    def test_a_dark_lane_beside_lit_peers_is_not_critical(self):
        _analyzer, stats = grade({
            **in_service(REPORTED_LIT, bias=None),
            **unlit(range(5, 9), bias=None),
        })
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertNotIn(stats["health_status"], ("critical", "down"))

    def test_a_module_dark_on_every_lane_is_still_down(self):
        _analyzer, stats = grade(unlit(range(1, 9), bias=None))
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["inactive_lanes"], [])


class DownstreamConsumerTests(unittest.TestCase):
    """The verdict has to reach every consumer, not just the row's badge."""

    def setUp(self):
        self.analyzer, self.stats = grade(REPORTED_PORT)

    def test_the_summary_counters_do_not_carry_the_port(self):
        summary = self.analyzer.get_optical_summary()
        self.assertEqual(summary["total_ports"], 1)
        for bucket in ("critical_ports", "down_ports", "unplugged_ports",
                       "unknown_ports", "warning_ports"):
            self.assertEqual(summary[bucket], [], f"{bucket} claimed the port")

    def test_no_anomaly_asks_for_the_cable_to_be_replaced(self):
        self.assertEqual(self.analyzer.detect_optical_anomalies(), [])

    def test_the_export_row_names_the_lanes_that_were_not_graded(self):
        summary = self.analyzer.get_optical_summary()
        rows = self.analyzer.build_export_rows(
            summary, self.analyzer.detect_optical_anomalies()
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertNotIn(row["health"], ("critical", "down"))
        self.assertEqual(row["anomalies"], "")
        self.assertEqual(row["inactive_lanes"], "5 6 7 8")
        self.assertNotIn("-40", row["rx_lanes"])
        # The new column has to be part of the published contract.
        export_artifacts.normalize_rows("optical", rows)

    def test_the_report_row_shows_a_lane_it_assessed(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "optical-analysis.html"
        self.analyzer.export_optical_data_for_web(str(output))

        page = output.read_text(encoding="utf-8")
        row = page.split('data-port="switch-a:swp1"', 1)[1].split("</tr>", 1)[0]
        self.assertNotIn("-40.00", row)
        self.assertNotIn("(L5)", row)
        self.assertNotIn("Check fiber connection", row)

        detail = json.loads(
            (output.parent / "optical-details" / "switch-a.json")
            .read_text(encoding="utf-8")
        )
        port = detail["ports"]["switch-a:swp1"]
        self.assertEqual(port["inactive_lanes"], [5, 6, 7, 8])
        self.assertEqual(port["rx_lane_ids"], [1, 2, 3, 4])

    def test_per_device_alerting_sees_the_healthy_verdict(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.analyzer.data_dir = str(root)
        self.assertIsNone(self.analyzer.write_history_shard("switch-a"))

        checker = object.__new__(check_alerts.LLDPqAlerts)
        checker.monitor_results = root
        checker.had_error = False
        self.assertNotIn(
            checker.get_device_optical_status("switch-a"),
            ("critical", "down"),
        )
        self.assertFalse(checker.had_error)


if __name__ == "__main__":
    unittest.main()
