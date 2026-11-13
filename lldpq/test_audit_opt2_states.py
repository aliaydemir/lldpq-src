#!/usr/bin/env python3
"""What a row says when a monitor is missing, the link is down or a flag is set.

* A monitor the module does not implement was graded as a measurement.
  SFF-8636 makes transmit power monitoring optional, ethtool prints the
  lines anyway (0.0000 mW), and a working link-up port became CRITICAL with
  'TX power out of range: -40.00 dBm'.  The same on the receive side gave
  DOWN while the link was up, and 0.0000 V gave CRITICAL.
* Every port whose operstate is down got the sentence 'No receive light on
  the selected active optical lane', also with light on all lanes, and the
  module alarm that took the link down was not listed at all.
* ethtool tests a CMIS channel flag against the channel index, so the flag
  of lane 1 is printed for channels 2, 4, 6 and 8: four CRITICAL lanes whose
  values sit inside the limits, half of them on the sibling sub-port.

Every dump is run through the real per-device worker as the collector
writes it ("Interface state: <operstate>" first).
"""

from __future__ import annotations

import shutil
import unittest

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import HEALTHY, OpticalFileTestCase
from optical_analyzer import OpticalAnalyzer


def sr4(rx=fx.SR4_RX, tx=fx.SR4_TX, bias=fx.SR4_BIAS, **kwargs):
    """A 40G QSFP+ SR4: the module family that may not monitor Tx power."""
    return fx.qsfp(identifier="0x0d (QSFP+)",
                   connector="0x0c (MPO Parallel Optic)",
                   types=["40G Ethernet: 40G Base-SR4"],
                   technology="0x00 (850 nm VCSEL)", rx=rx, tx=tx, bias=bias,
                   **kwargs)


NO_TX = [None] * 4
NO_RX = [None] * 4


class UnimplementedMonitorTests(OpticalFileTestCase):
    def test_tx_power_printed_as_zero_on_a_link_up_port_is_not_a_reading(self):
        stats = self.rows([("swp1", "up", sr4(tx=NO_TX))])["swp1"]
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertIsNone(stats["tx_power_dbm"])
        self.assertIsNone(stats["tx_power_lane"])
        self.assertEqual(stats["tx_power_lanes_dbm"], [])
        self.assertEqual(stats["not_monitored"], ["tx_power"])
        # The receive side and the bias are graded as before.
        self.assertEqual(stats["rx_power_lanes_dbm"], fx.SR4_RX)
        self.assertEqual(stats["bias_current_lanes_ma"], fx.SR4_BIAS)
        self.assertEqual(self.anomalies(), [])

    def test_the_row_and_its_detail_say_not_monitored(self):
        self.rows([("swp1", "up", sr4(tx=NO_TX))])
        page, details = self.publish()
        row = page.split('data-port="leaf1:swp1"', 1)[1].split("</tr>", 1)[0]
        self.assertNotIn("-40.00", row)
        self.assertEqual(details["leaf1:swp1"]["not_monitored"], ["tx_power"])
        self.assertEqual(details["leaf1:swp1"]["tx_lanes"], [])
        self.assertEqual(self.export_rows()["swp1"]["tx_power_dbm"], None)
        if not shutil.which("node"):
            self.skipTest("Node.js runs the page script")
        panel = self.render_panel(page, "leaf1:swp1", details["leaf1:swp1"])
        self.assertIn("Not monitored by this module, not graded: TX power",
                      panel)
        healthy = self.render_panel(page, "leaf1:swp2", {"health": "good"})
        self.assertNotIn("Not monitored", healthy)

    def test_one_dark_tx_lane_among_lit_ones_stays_critical(self):
        stats = self.rows([("swp1", "up", sr4(
            tx=fx.with_lane(fx.SR4_TX, 3, None)))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["tx_power_lane"], 3)
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(self.messages(),
                         ["TX power out of range: -40.00 dBm"])

    def test_no_receive_power_on_a_link_up_port_is_not_down(self):
        stats = self.rows([("swp1", "up", sr4(rx=NO_RX))])["swp1"]
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertIsNone(stats["rx_power_dbm"])
        self.assertIsNone(stats["link_margin_db"])
        self.assertEqual(stats["not_monitored"], ["rx_power"])
        self.assertEqual(self.anomalies(), [])

    def test_neither_side_monitored_on_a_link_up_port_is_unknown(self):
        stats = self.rows([("swp1", "up", sr4(rx=NO_RX, tx=NO_TX))])["swp1"]
        self.assertEqual(stats["health_status"], "unknown")
        self.assertEqual(stats["not_monitored"], ["tx_power", "rx_power"])

    def test_bias_with_receive_light_proves_a_missing_tx_monitor(self):
        # Only for a block without any link state: the lasers draw bias and
        # the peer's light arrives.
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(analyzer.update_optical_stats(
            "leaf1:swp1", sr4(tx=NO_TX)))
        stats = analyzer.current_optical_stats["leaf1:swp1"]
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertIsNone(stats["tx_power_dbm"])
        self.assertEqual(stats["not_monitored"], ["tx_power"])
        self.assertEqual(analyzer.detect_optical_anomalies(), [])

    def test_on_a_link_down_port_the_same_readings_stay_readings(self):
        # Bias, no transmit light and receive light on a port whose link is
        # down is what a failed transmitter looks like: nothing is hidden.
        stats = self.rows([("swp1", "down", sr4(tx=NO_TX))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["tx_power_lanes_dbm"], [-40.0] * 4)
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "TX reads no light on any lane while the lasers draw 6.6 to "
            "6.9 mA (failed transmitter or TX power not monitored)"])

    def test_lasers_switched_off_are_a_dark_side_not_a_missing_monitor(self):
        stats = self.rows([("swp1", "down", sr4(tx=NO_TX, bias=0.0))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["not_monitored"], [])

    def test_no_receive_light_on_a_down_port_stays_a_reading(self):
        stats = self.rows([("swp1", "down", sr4(rx=NO_RX))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["rx_power_dbm"], -40.0)
        self.assertEqual(stats["not_monitored"], [])

    def test_without_a_link_state_no_receive_light_is_still_down(self):
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(analyzer.update_optical_stats(
            "leaf1:swp1", sr4(rx=NO_RX)))
        stats = analyzer.current_optical_stats["leaf1:swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["rx_power_dbm"], -40.0)

    def test_a_sub_port_is_judged_from_the_whole_module(self):
        # s1's four transmitters are dark while s0's work: the monitor is
        # implemented, so s1's reading is a fault even with its link up.
        tx = fx.TWIN_TX[:4] + [None] * 4
        rows = self.rows([("swp6s0", "up", fx.cmis(tx=tx)),
                          ("swp6s1", "up", fx.cmis(tx=tx))])
        self.assertIn(rows["swp6s0"]["health_status"], HEALTHY)
        self.assertEqual(rows["swp6s1"]["health_status"], "critical")
        self.assertEqual(rows["swp6s1"]["tx_power_dbm"], -40.0)
        self.assertEqual(rows["swp6s1"]["not_monitored"], [])
        # No transmitter of the module reports: not monitored on both.
        tx = [None] * 8
        rows = self.rows([("swp6s0", "up", fx.cmis(tx=tx)),
                          ("swp6s1", "up", fx.cmis(tx=tx))])
        for interface in ("swp6s0", "swp6s1"):
            self.assertIn(rows[interface]["health_status"], HEALTHY)
            self.assertEqual(rows[interface]["not_monitored"], ["tx_power"])

    def test_a_link_up_sub_port_without_receive_light_is_not_down(self):
        # The module does monitor receive power (s1 reads it); s0's dark
        # receivers are a fault of a port whose link is up, not a DOWN row.
        rx = [None] * 4 + fx.TWIN_RX[4:]
        rows = self.rows([("swp6s0", "up", fx.cmis(rx=rx)),
                          ("swp6s1", "up", fx.cmis(rx=rx))])
        self.assertEqual(rows["swp6s0"]["health_status"], "critical")
        self.assertEqual(rows["swp6s0"]["rx_power_dbm"], -40.0)
        self.assertIn(rows["swp6s1"]["health_status"], HEALTHY)

    def test_zero_volts_and_zero_degrees_are_not_read(self):
        stats = self.rows([("swp1", "up", sr4(
            temperature=0.0, voltage=0.0))])["swp1"]
        self.assertIsNone(stats["temperature_c"])
        self.assertIsNone(stats["voltage_v"])
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertEqual(self.anomalies(), [])
        # A real reading next to zero is still read.
        stats = self.rows([("swp1", "up", sr4(
            temperature=0.5, voltage=3.3))])["swp1"]
        self.assertEqual(stats["temperature_c"], 0.5)
        self.assertEqual(stats["voltage_v"], 3.3)


# The twin-port module of the downstream report: channel 6 has a dead
# laser, the peer keeps transmitting on every lane.
C1_RX = [-4.1, -4.2, -4.0, -4.3, -4.5, -4.6, -4.4, -4.7]
C1_TABLES = dict(fx.TWIN, bias=fx.limits(120.0, 110.0, 15.0, 10.0),
                 rx_power=fx.limits(4.0, 3.0, -9.0, -11.0))
C1_DUMP = fx.cmis(C1_RX, fx.with_lane(fx.TWIN_TX, 6, None),
                  bias=fx.with_lane([60.0] * 8, 6, 0.4),
                  flags={(6, "low_alarm"): True}, tables=C1_TABLES)
BIAS_LANE_6 = ("Laser bias lane 6: 0.400 mA; module low alarm threshold: "
               "10.000 mA; module flag is On")
TX_LANE_6 = ("TX power -40.00 dBm on lane 6 is below the module's low alarm "
             "-4.90 dBm")


class LinkDownRowTests(OpticalFileTestCase):
    def down(self, dump, interface="swp1"):
        stats = self.rows([(interface, "down", dump)])[interface]
        self.assertEqual(stats["health_status"], "down",
                         "the DOWN badge of an operstate-down port stays")
        return stats

    def test_light_on_every_lane_is_said_so(self):
        self.down(fx.cmis())
        self.assertEqual(
            [(item["type"], item["severity"], item["message"])
             for item in self.anomalies()],
            [("OPTICAL_LINK_DOWN", "warning",
              "Link down, light present on all lanes")])

    def test_a_lane_below_the_module_alarm_is_named(self):
        self.down(fx.cmis(fx.with_lane(fx.TWIN_RX, 2, -16.0)))
        self.assertEqual(self.messages(), [
            "Link down, lane 2 at -16.0 dBm",
            "RX power -16.00 dBm on lane 2 is below the module's low alarm "
            "-8.40 dBm",
        ])
        self.assertEqual([item["severity"] for item in self.anomalies()],
                         ["warning", "critical"])

    def test_a_lane_below_the_generic_limit_is_named(self):
        self.down(fx.cmis(fx.with_lane(fx.TWIN_RX, 2, -16.0), tables=None))
        self.assertEqual(self.messages(), [
            "Link down, lane 2 at -16.0 dBm",
            "RX power too low: -16.00 dBm (threshold: -14.0 dBm)",
        ])

    def test_a_dark_lane_next_to_lit_ones_is_named(self):
        self.down(sr4(rx=fx.with_lane(fx.SR4_RX, 3, None)))
        self.assertEqual(self.messages(), [
            "Link down, lane 3 without light",
            "RX power too low: -40.00 dBm (threshold: -14.0 dBm)",
        ])

    def test_no_receive_light_is_said_only_when_no_lane_has_light(self):
        self.down(fx.cmis([None] * 8))
        self.assertEqual(self.messages(),
                         ["Link down, no receive light on any lane"])

    def test_a_single_lane_port_with_light(self):
        self.down(fx.SFP_10G_SR)
        self.assertEqual(self.messages(), ["Link down, receive light present"])

    def test_without_a_link_state_the_sentence_is_the_plain_one(self):
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(analyzer.update_optical_stats(
            "leaf1:swp1", fx.cmis([None] * 8)))
        self.assertEqual(
            [(item["type"], item["message"])
             for item in analyzer.detect_optical_anomalies()],
            [("OPTICAL_LINK_DOWN", "No receive light on any lane")])

    def test_what_to_check_follows_the_readings(self):
        cases = (
            (fx.cmis(), "Check the peer port and the link settings on both "
                        "ends (admin state, speed, FEC)"),
            (fx.cmis(fx.with_lane(fx.TWIN_RX, 2, -16.0)),
             "Check fiber connection, clean connectors, or replace cable"),
            (fx.cmis([None] * 8),
             "Check fiber connection, peer state, and transceiver"),
            # A lane above the module's high alarm (6.5 dBm).
            (fx.cmis(fx.with_lane(fx.TWIN_RX, 2, 7.0)),
             "Verify the far-end optic type and attenuate the link if it is "
             "too short"),
        )
        for dump, action in cases:
            with self.subTest(action):
                self.down(dump)
                self.assertEqual(self.anomalies()[0]["action"], action)
                page, _details = self.publish()
                row = page.split('data-port="leaf1:swp1"', 1)[1]
                self.assertIn(f"<td>{action}</td>", row.split("</tr>", 1)[0])

    def test_a_bias_alarm_is_listed_on_the_down_row(self):
        stats = self.down(fx.cmis(bias=fx.with_lane([212.7] * 8, 4, 405.0),
                                  flags={(4, "high_alarm"): True}))
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "Laser bias lane 4: 405.000 mA; module high alarm threshold: "
            "400.000 mA; module flag is On",
        ])
        self.assertEqual(stats["bias_assessment"]["status"], "critical")
        self.assertEqual(stats["health_causes"], ["bias_current"])

    def test_a_temperature_alarm_is_listed_on_the_down_row(self):
        self.down(fx.cmis(temperature=85.0))
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "Module temperature 85.00°C is above the module's high alarm "
            "80.00°C",
        ])
        stats = self.down(fx.cmis(temperature=75.0, tables=None))
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "SFP temperature too high: 75.0°C (threshold: 70.0°C)",
        ])
        self.assertEqual(stats["health_causes"], ["temperature"])

    def test_a_module_warning_is_not_a_cause_of_the_outage(self):
        # 72 C is beyond the module's high warning (70 C), not its alarm.
        self.down(fx.cmis(temperature=72.0))
        self.assertEqual(self.messages(),
                         ["Link down, light present on all lanes"])
        stats = self.rows([("swp1", "up", fx.cmis(temperature=72.0))])["swp1"]
        self.assertEqual(stats["health_status"], "warning")

    def test_the_dead_laser_that_took_the_link_down_is_named(self):
        rows = self.rows([("swp6s0", "up", C1_DUMP),
                          ("swp6s1", "down", C1_DUMP)])
        self.assertIn(rows["swp6s0"]["health_status"], HEALTHY)
        stats = rows["swp6s1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["rx_power_lanes_dbm"], C1_RX[4:])
        self.assertEqual(self.messages("leaf1:swp6s1"), [
            "Link down, light present on all lanes", BIAS_LANE_6, TX_LANE_6])
        self.assertEqual(
            [item["severity"] for item in self.anomalies()],
            ["warning", "critical", "critical"])
        self.assertEqual(stats["bias_assessment"]["status"], "critical")
        self.assertEqual(stats["health_causes"], ["bias_current", "tx_power"])

    def test_the_cause_reaches_the_detail_file_the_export_and_the_shard(self):
        self.rows([("swp6s0", "up", C1_DUMP), ("swp6s1", "down", C1_DUMP)])
        _page, details = self.publish()
        self.assertEqual(
            [item["message"] for item in details["leaf1:swp6s1"]["anomalies"]],
            ["Link down, light present on all lanes", BIAS_LANE_6, TX_LANE_6])
        cell = self.export_rows()["swp6s1"]["anomalies"]
        self.assertTrue(
            cell.startswith("WARNING: Link down, light present on all lanes"))
        self.assertIn("CRITICAL: TX power -40.00 dBm on lane 6", cell)
        shard = self.shard()
        # The state the alerts read is unchanged.
        self.assertEqual(
            shard["current"]["leaf1:swp6s1"]["health_status"], "down")
        self.assertEqual(shard["history"]["leaf1:swp6s1"][-1]["health"], "down")
        summary = self.parent.get_optical_summary()
        self.assertEqual([item["port"] for item in summary["down_ports"]],
                         ["leaf1:swp6s1"])
        self.assertEqual(summary["critical_ports"], [])

    def test_a_parked_port_lists_no_alarm(self):
        # Shut on this side: lasers off, the module flags low bias on every
        # lane, the peer still transmits.
        parked = fx.cmis(tx=[None] * 8, bias=0.0, flags={
            (channel, kind): True for channel in range(1, 9)
            for kind in ("low_alarm", "low_warning")})
        stats = self.down(parked)
        self.assertEqual(self.messages(),
                         ["Link down, light present on all lanes"])
        self.assertEqual(stats["bias_assessment"]["status"], "unknown")
        self.assertEqual(stats["bias_assessment"]["events"], [])
        self.assertEqual(stats["health_causes"], [])
        _page, details = self.publish()
        self.assertEqual(
            details["leaf1:swp1"]["bias_assessment"]["status"], "unknown")
        # Dark on both sides as well.
        self.down(fx.cmis([None] * 8, [None] * 8, bias=0.0, flags={
            (channel, "low_alarm"): True for channel in range(1, 9)}))
        self.assertEqual(self.messages(),
                         ["Link down, no receive light on any lane"])

    def test_a_single_lane_port_with_its_laser_off_lists_no_alarm(self):
        tables = {"bias": fx.limits(17.0, 14.0, 2.0, 1.0)}
        stats = self.down(fx.sfp(
            connector="0x07 (LC)", types=["10G Ethernet: 10G Base-SR"],
            dom=(-2.4, None, 0.0, 30.0, 3.3), tables=tables,
            flags={("Laser bias current", "low_alarm"): True}))
        self.assertEqual(self.messages(), ["Link down, receive light present"])
        self.assertEqual(stats["bias_assessment"]["events"], [])

    def test_the_same_readings_on_a_link_up_port_are_critical(self):
        stats = self.rows([("swp1", "up", fx.cmis(
            fx.with_lane(fx.TWIN_RX, 2, -16.0)))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(), [
            "RX power -16.00 dBm on lane 2 is below the module's low alarm "
            "-8.40 dBm"])

    def test_the_legend_defines_down_by_the_link_state(self):
        self.down(fx.cmis())
        page, _details = self.publish()
        legend = page[page.index("Optical Health Thresholds"):]
        row = legend[legend.index("<tr><td>Down</td>"):]
        row = row[:row.index("</tr>")]
        self.assertNotIn("No receive light on every selected", row)
        self.assertIn("The port's link is down while its module still "
                      "answers", row)
        self.assertIn("light is present on all lanes", row)
        self.assertIn("A port whose link is up is never Down", row)


class CmisFlagTests(OpticalFileTestCase):
    IN_RANGE = ("Laser bias lane {lane}: 212.700 mA; module low alarm "
                "threshold: 10.000 mA; module flag set, value in range")

    def test_the_flag_of_lane_one_is_not_four_critical_lanes(self):
        flags = fx.buggy_cmis_flags(1)
        self.assertEqual(sorted(channel for (channel, _kind), on
                                in flags.items() if on), [2, 4, 6, 8])
        stats = self.rows([("swp1", "up", fx.cmis(flags=flags))])["swp1"]
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(stats["bias_assessment"]["status"], "warning")
        self.assertEqual(self.messages(), [
            self.IN_RANGE.format(lane=lane) for lane in (2, 4, 6, 8)])
        self.assertEqual({item["severity"] for item in self.anomalies()},
                         {"warning"})

    def test_the_sibling_sub_port_does_not_turn_critical(self):
        dump = fx.cmis(flags=fx.buggy_cmis_flags(1))
        rows = self.rows([("swp3s0", "up", dump), ("swp3s1", "up", dump)])
        for interface, lanes in (("swp3s0", (2, 4)), ("swp3s1", (6, 8))):
            self.assertEqual(rows[interface]["health_status"], "warning")
            self.assertEqual(
                self.messages(f"leaf1:{interface}"),
                [self.IN_RANGE.format(lane=lane) for lane in lanes])

    def test_every_cmis_identifier_is_recognised(self):
        for identifier in (fx.OSFP, fx.QSFP_DD, fx.QSFP112):
            with self.subTest(identifier):
                stats = self.rows([("swp1", "up", fx.cmis(
                    identifier=identifier,
                    flags={(3, "high_alarm"): True}))])["swp1"]
                self.assertEqual(stats["health_status"], "warning")
                self.assertEqual(stats["bias_current_lane"], 3)

    def test_a_flag_with_the_value_beyond_the_limit_is_critical(self):
        stats = self.rows([("swp1", "up", fx.cmis(
            bias=fx.with_lane([212.7] * 8, 6, 405.0),
            flags={(6, "high_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(), [
            "Laser bias lane 6: 405.000 mA; module high alarm threshold: "
            "400.000 mA; module flag is On"])

    def test_an_alarm_flag_with_the_value_beyond_the_warning_limit(self):
        stats = self.rows([("swp1", "up", fx.cmis(
            bias=fx.with_lane([212.7] * 8, 6, 390.0),
            flags={(6, "high_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(), [
            "Laser bias lane 6: 390.000 mA; module high warning threshold: "
            "380.000 mA"])

    def test_a_flag_without_a_valid_limit_counts_as_before(self):
        # No bias table: the flag is all the evidence there is.
        stats = self.rows([("swp1", "up", fx.cmis(
            tables=dict(fx.TWIN, bias=None),
            flags={(6, "high_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(), [
            "Laser bias lane 6: 212.700 mA; module high alarm threshold: "
            "unavailable; module flag is On"])

    def test_sff_8636_flags_behave_as_before(self):
        tables = {"bias": fx.limits(12.0, 10.0, 2.0, 1.0)}
        stats = self.rows([("swp1", "up", fx.qsfp(
            connector="0x0c (MPO Parallel Optic)",
            types=["100G Ethernet: 100G Base-SR4"],
            technology="0x00 (850 nm VCSEL)", rx=fx.SR4_RX, tx=fx.SR4_TX,
            bias=fx.SR4_BIAS, tables=tables,
            flags={(2, "low_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(), [
            "Laser bias lane 2: 6.800 mA; module low alarm threshold: "
            "1.000 mA; module flag is On"])

    def test_sff_8472_flags_behave_as_before(self):
        tables = {"bias": fx.limits(17.0, 14.0, 2.0, 1.0)}
        stats = self.rows([("swp1", "up", fx.sfp(
            connector="0x07 (LC)", types=["10G Ethernet: 10G Base-SR"],
            dom=(-2.4, -2.2, 6.0, 36.0, 3.29), tables=tables,
            flags={("Laser bias current", "high_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(), [
            "Laser bias lane 1: 6.000 mA; module high alarm threshold: "
            "17.000 mA; module flag is On"])

    def test_the_detail_row_explains_the_flag(self):
        self.rows([("swp1", "up", fx.cmis(flags=fx.buggy_cmis_flags(1)))])
        _page, details = self.publish()
        assessment = details["leaf1:swp1"]["bias_assessment"]
        self.assertEqual(assessment["status"], "warning")
        self.assertEqual(assessment["reason"],
                         "Module bias flag set while the measured bias is "
                         "inside the module limits.")
        self.assertEqual([event["lane"] for event in assessment["events"]],
                         [2, 4, 6, 8])


if __name__ == "__main__":
    unittest.main()
