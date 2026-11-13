#!/usr/bin/env python3
"""Review fixes for the optical grading: tables, dead transmitters, DOWN rows.

* A module table that is ordered but physically meaningless (an unprogrammed
  -128 / +128 C, 0 / 6.5535 V or 0.0001 / 6.5535 mW table) decided its metric
  and switched the generic alarm off: 110 C, 2.6 V and a receive lane at
  -30 dBm were EXCELLENT.
* On a port whose link is down, bias with receive light and no transmit light
  was read as "TX not monitored": the reading that shows a dead transmitter
  was hidden.  A bias of 0.4 mA with the module's low-bias alarm raised
  counted as a driven laser.
* A DOWN row said "light present on all lanes" while a lane was set aside as
  dead, or while every transmitter of the port was dark at full bias.
* Voltage and low temperature graded by the generic limits had no finding of
  their own, so a DOWN row could not list them.
* A malformed temperature or voltage number aborted the whole device file.

Every dump runs through the real per-device worker in the collector's
format.  All module values are invented.
"""

from __future__ import annotations

import re
import shutil
import unittest

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import HEALTHY, OpticalFileTestCase
from optical_analyzer import OpticalAnalyzer


METRICS = ["rx_power", "tx_power", "temperature", "voltage"]
PEER_ACTION = ("Check the peer port and the link settings on both ends "
               "(admin state, speed, FEC)")
FIBRE_ACTION = "Check fiber connection, peer state, and transceiver"


def sr4(rx=fx.SR4_RX, tx=fx.SR4_TX, bias=fx.SR4_BIAS, **kwargs):
    """A QSFP28 SR4 whose dump names no media standard."""
    return fx.qsfp(connector="0x0c (MPO Parallel Optic)",
                   types=["100G Ethernet: 100G Base-SR4"],
                   technology="0x00 (850 nm VCSEL)", rx=rx, tx=tx, bias=bias,
                   **kwargs)


def sfp_plus(rx, tx, bias, *, tables=None, flags=None):
    return fx.sfp(connector="0x07 (LC)", types=["10G Ethernet: 10G Base-SR"],
                  dom=(rx, tx, bias, 36.0, 3.29), tables=tables, flags=flags)


SFP_TABLES = {
    "bias": fx.limits(17.0, 14.0, 2.0, 1.0),
    "tx_power": fx.limits(-0.97, -1.97, -9.5, -10.5),
    "temperature": fx.limits(90.0, 85.0, -5.0, -10.0),
    "voltage": fx.limits(3.6, 3.5, 3.1, 3.0),
    "rx_power": fx.limits(2.04, 1.04, -16.99, -20.0),
}
LOW_BIAS_FLAG = {("Laser bias current", "low_alarm"): True}

# Unprogrammed tables: the extremes of the field, in order.
TEMPERATURE_128 = fx.limits(128.0, 128.0, -128.0, -128.0)
VOLTAGE_FULL_RANGE = fx.limits(6.5535, 6.5535, 0.0, 0.0)
POWER_FULL_RANGE = fx.limits(8.16, 8.16, -40.0, -40.0)


class ImplausibleTableTests(OpticalFileTestCase):
    """An unprogrammed table grades nothing; the generic rules stay on."""

    def grade(self, dump, state="up"):
        stats = self.rows([("swp1", state, dump)])["swp1"]
        return stats, self.messages()

    def test_unprogrammed_temperature_table_does_not_hide_a_hot_module(self):
        for temperature in (95.0, 110.0):
            with self.subTest(temperature=temperature):
                stats, messages = self.grade(sr4(
                    temperature=temperature,
                    tables={"temperature": TEMPERATURE_128}))
                self.assertEqual(stats["health_status"], "critical")
                self.assertEqual(messages, [
                    f"SFP temperature too high: {temperature:.1f}°C "
                    "(threshold: 70.0°C)"])
                self.assertEqual(stats["module_limits"]["decided"], [])
                self.assertEqual(stats["module_limits"]["thresholds"], {})
                self.assertEqual(stats["module_limits"]["ignored"],
                                 {"temperature": TEMPERATURE_128})

    def test_one_unprogrammed_side_is_enough(self):
        # The low side is real, the high side is the field's maximum.
        stats, messages = self.grade(sr4(
            temperature=95.0,
            tables={"temperature": fx.limits(128.0, 128.0, 0.0, -5.0)}))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(
            messages, ["SFP temperature too high: 95.0°C (threshold: 70.0°C)"])

    def test_unprogrammed_voltage_table_does_not_hide_a_bad_supply(self):
        for voltage in (2.6, 4.1):
            with self.subTest(voltage=voltage):
                stats, messages = self.grade(sr4(
                    voltage=voltage, tables={"voltage": VOLTAGE_FULL_RANGE}))
                self.assertEqual(stats["health_status"], "critical")
                self.assertEqual(messages, [
                    f"Module voltage out of range: {voltage:.4f} V "
                    "(limits: 3.0 to 3.6 V)"])
                self.assertEqual(stats["module_limits"]["decided"], [])

    def test_unprogrammed_power_tables_do_not_hide_a_weak_or_hot_lane(self):
        tables = {"rx_power": POWER_FULL_RANGE, "tx_power": POWER_FULL_RANGE}
        cases = (
            (dict(rx=fx.with_lane(fx.SR4_RX, 2, -20.0)),
             "RX power too low: -20.00 dBm (threshold: -14.0 dBm)"),
            (dict(rx=fx.with_lane(fx.SR4_RX, 2, -30.0)),
             "RX power too low: -30.00 dBm (threshold: -14.0 dBm)"),
            (dict(tx=fx.with_lane(fx.SR4_TX, 2, -15.0)),
             "TX power out of range: -15.00 dBm"),
            (dict(tx=fx.with_lane(fx.SR4_TX, 2, 7.5)),
             "TX power out of range: 7.50 dBm"),
        )
        for lanes, message in cases:
            with self.subTest(message):
                stats, messages = self.grade(sr4(tables=tables, **lanes))
                self.assertEqual(stats["health_status"], "critical")
                self.assertEqual(messages, [message])
                self.assertEqual(stats["module_limits"]["decided"], [])
                self.assertEqual(sorted(stats["module_limits"]["ignored"]),
                                 ["rx_power", "tx_power"])
        # The weak lane is the displayed one and the margin is the generic one.
        stats, _messages = self.grade(sr4(
            tables=tables, rx=fx.with_lane(fx.SR4_RX, 2, -20.0)))
        self.assertEqual(stats["rx_power_lane"], 2)
        self.assertAlmostEqual(stats["link_margin_db"], -6.0)

    def test_limits_on_the_bounds_decide_and_just_beyond_them_do_not(self):
        # temperature -45..125 C, voltage 2.5..4.0 V, power above -40 up to
        # +10 dBm (high alarm, high warning, low warning, low alarm).
        inside = {
            "temperature": fx.limits(125.0, 120.0, -40.0, -45.0),
            "voltage": fx.limits(4.0, 3.9, 2.6, 2.5),
            "rx_power": fx.limits(10.0, 9.0, -38.0, -39.99),
            "tx_power": fx.limits(10.0, 9.0, -38.0, -39.99),
        }
        stats, _messages = self.grade(sr4(tables=inside))
        self.assertEqual(stats["module_limits"]["decided"], METRICS)
        self.assertNotIn("ignored", stats["module_limits"])
        beyond = (
            ("temperature", fx.limits(125.01, 120.0, -40.0, -45.0)),
            ("temperature", fx.limits(125.0, 120.0, -40.0, -45.01)),
            ("voltage", fx.limits(4.0001, 3.9, 2.6, 2.5)),
            ("voltage", fx.limits(4.0, 3.9, 2.6, 2.4999)),
            ("rx_power", fx.limits(10.01, 9.0, -38.0, -39.99)),
            ("rx_power", fx.limits(10.0, 9.0, -38.0, -40.0)),
            ("tx_power", fx.limits(10.01, 9.0, -38.0, -39.99)),
            ("tx_power", fx.limits(10.0, 9.0, -38.0, -40.0)),
        )
        for metric, table in beyond:
            with self.subTest(metric=metric, table=table):
                stats, _messages = self.grade(sr4(
                    tables=dict(inside, **{metric: table})))
                self.assertEqual(
                    stats["module_limits"]["decided"],
                    [name for name in METRICS if name != metric])
                self.assertEqual(sorted(stats["module_limits"]["ignored"]),
                                 [metric])

    def test_tables_of_real_module_classes_all_decide(self):
        commercial = fx.limits(75.0, 70.0, 0.0, -5.0)
        supply = fx.limits(3.63, 3.465, 3.135, 2.97)
        classes = {
            "10G SR SFP+": {
                "temperature": commercial, "voltage": supply,
                "tx_power": fx.limits(1.0, 0.0, -7.3, -9.3),
                "rx_power": fx.limits(1.0, 0.0, -9.9, -13.9)},
            "1G EZX 160 km, industrial": {
                "temperature": fx.limits(95.0, 90.0, -40.0, -45.0),
                "voltage": fx.limits(3.6, 3.5, 3.1, 3.0),
                "tx_power": fx.limits(6.0, 5.0, -1.0, -2.0),
                "rx_power": fx.limits(-7.0, -8.0, -34.0, -36.0)},
            "10G ZR": {
                "temperature": commercial, "voltage": supply,
                "tx_power": fx.limits(5.0, 4.0, 0.0, -1.0),
                "rx_power": fx.limits(-6.0, -7.0, -24.0, -27.0)},
            "100G LR4": {
                "temperature": commercial, "voltage": supply,
                "tx_power": fx.limits(5.5, 4.5, -4.3, -7.3),
                "rx_power": fx.limits(5.5, 4.5, -10.6, -13.6)},
            "400G DR4 / twin-port": {
                key: fx.TWIN[key] for key in METRICS},
            "400ZR coherent": {
                "temperature": fx.limits(80.0, 75.0, -5.0, -10.0),
                "voltage": fx.limits(3.6, 3.5, 3.1, 3.0),
                "tx_power": fx.limits(-6.0, -8.0, -12.0, -14.0),
                "rx_power": fx.limits(3.0, 0.0, -18.0, -23.0)},
            "amplified ZR+": {
                "temperature": fx.limits(80.0, 75.0, -5.0, -10.0),
                "voltage": fx.limits(3.6, 3.5, 3.1, 3.0),
                "tx_power": fx.limits(8.0, 6.0, -4.0, -6.0),
                "rx_power": fx.limits(3.0, 0.0, -18.0, -23.0)},
            "wide supply, hot industrial": {
                "temperature": fx.limits(110.0, 105.0, -40.0, -45.0),
                "voltage": fx.limits(3.9, 3.7, 2.9, 2.7),
                "tx_power": fx.limits(1.0, 0.0, -7.3, -9.3),
                "rx_power": fx.limits(1.0, 0.0, -9.9, -13.9)},
            "warning equal to alarm": {
                "temperature": fx.limits(85.0, 85.0, -5.0, -5.0),
                "voltage": fx.limits(3.6, 3.6, 3.0, 3.0),
                "tx_power": fx.limits(3.0, 3.0, -8.0, -8.0),
                "rx_power": fx.limits(3.0, 3.0, -12.0, -12.0)},
        }
        for name, tables in classes.items():
            with self.subTest(name):
                stats, _messages = self.grade(sr4(tables=tables))
                self.assertEqual(stats["module_limits"]["decided"], METRICS)
                self.assertNotIn("ignored", stats["module_limits"])

    def test_an_implausible_limit_of_a_partial_table_raises_nothing(self):
        # A lone high alarm of -50 C would put every module beyond it.
        stats, messages = self.grade(sr4(tables={
            "temperature": {"high_alarm": -50.0}}))
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertEqual(messages, [])
        self.assertEqual(stats["module_limits"]["thresholds"], {})
        self.assertEqual(stats["module_limits"]["ignored"],
                         {"temperature": {"high_alarm": -50.0}})

    def test_four_equal_limits_are_no_table(self):
        # Inconsistent, not implausible: the values are in range, but a
        # table without room between low and high grades nothing.
        cases = (
            ("rx_power", fx.limits(2.0, 2.0, 2.0, 2.0)),
            ("tx_power", fx.limits(1.5, 1.5, 1.5, 1.5)),
            ("temperature", fx.limits(70.0, 70.0, 70.0, 70.0)),
            ("voltage", fx.limits(3.5, 3.5, 3.5, 3.5)),
        )
        for metric, table in cases:
            with self.subTest(metric):
                stats, messages = self.grade(fx.cmis(
                    tables=dict(fx.TWIN, **{metric: table})))
                self.assertIn(stats["health_status"], HEALTHY)
                self.assertEqual(messages, [])
                self.assertNotIn(metric, stats["module_limits"]["decided"])
                self.assertNotIn(metric, stats["module_limits"]["thresholds"])
                self.assertNotIn("ignored", stats["module_limits"])

    def test_a_zero_volt_limit_is_unset(self):
        # The low side printed as 0.0000 V: a partial table, like 0 mW for
        # power.  The generic rules stay on and the printed high limits can
        # still raise.
        table = {"voltage": fx.limits(3.6, 3.5, 0.0, 0.0)}
        stats, messages = self.grade(sr4(voltage=3.55, tables=table))
        self.assertEqual(stats["module_limits"]["thresholds"],
                         {"voltage": {"high_alarm": 3.6, "high_warning": 3.5}})
        self.assertEqual(stats["module_limits"]["decided"], [])
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(messages, [
            "Module voltage 3.5500 V is above the module's high warning "
            "3.5000 V"])
        stats, messages = self.grade(sr4(voltage=2.6, tables=table))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(messages, [
            "Module voltage out of range: 2.6000 V (limits: 3.0 to 3.6 V)"])

    def test_the_detail_panel_says_the_table_was_ignored(self):
        self.rows([("swp1", "up", sr4(
            temperature=95.0, tables={"temperature": TEMPERATURE_128}))])
        page, details = self.publish()
        self.assertEqual(details["leaf1:swp1"]["module_limits"]["ignored"],
                         {"temperature": TEMPERATURE_128})
        legend = page[page.index("Optical Health Thresholds"):]
        self.assertIn("complete, consistent and physically plausible", legend)
        if not shutil.which("node"):
            self.skipTest("Node.js runs the page script")
        panel = self.render_panel(page, "leaf1:swp1", details["leaf1:swp1"])
        self.assertIn(
            "Temperature: generic limits (module table ignored: implausible; "
            "it prints low alarm -128.00 C, low warning -128.00 C, high "
            "warning 128.00 C, high alarm 128.00 C)", panel)
        self.assertIn(
            "Voltage: generic limits (the module prints no valid table)",
            panel)


class LimitBoundaryTests(OpticalFileTestCase):
    """A reading exactly on a low limit is not beyond it."""

    def grade(self, dump):
        stats = self.rows([("swp1", "up", dump)])["swp1"]
        return stats["health_status"], self.messages()

    def test_exactly_on_a_low_alarm_is_only_beyond_the_warning(self):
        tables = dict(fx.TWIN, temperature=fx.limits(80.0, 70.0, 5.0, -5.0))
        cases = (
            (fx.cmis(fx.with_lane(fx.TWIN_RX, 3, -8.4), tables=tables),
             "RX power -8.40 dBm on lane 3 is below the module's low warning "
             "-7.40 dBm"),
            (fx.cmis(tx=fx.with_lane(fx.TWIN_TX, 3, -4.9), tables=tables),
             "TX power -4.90 dBm on lane 3 is below the module's low warning "
             "-3.90 dBm"),
            (fx.cmis(temperature=-5.0, tables=tables),
             "Module temperature -5.00°C is below the module's low warning "
             "5.00°C"),
            (fx.cmis(voltage=3.1, tables=tables),
             "Module voltage 3.1000 V is below the module's low warning "
             "3.1350 V"),
        )
        for dump, message in cases:
            with self.subTest(message):
                health, messages = self.grade(dump)
                self.assertEqual(health, "warning")
                self.assertIn(message, messages)
                self.assertFalse(
                    [text for text in messages if "low alarm" in text
                     and "RX low alarm" not in text], messages)

    def test_exactly_on_a_low_warning_is_healthy(self):
        tables = dict(fx.TWIN, temperature=fx.limits(80.0, 70.0, 5.0, -5.0))
        # The margin knob would warn first for RX; it is switched off here
        # so that the module's low warning is the limit under test.
        self.worker.thresholds["link_margin_min_db"] = 0.0
        self.parent.thresholds["link_margin_min_db"] = 0.0
        cases = (
            fx.cmis(fx.with_lane(fx.TWIN_RX, 3, -7.4), tables=tables),
            fx.cmis(tx=fx.with_lane(fx.TWIN_TX, 3, -3.9), tables=tables),
            fx.cmis(temperature=5.0, tables=tables),
            fx.cmis(voltage=3.135, tables=tables),
        )
        for number, dump in enumerate(cases):
            with self.subTest(case=number):
                health, messages = self.grade(dump)
                self.assertEqual(health, "good")
                self.assertEqual(messages, [])

    def test_a_partial_table_warns_where_the_generic_rule_is_silent(self):
        # TX 2.60 dBm: inside the generic range and its warning band, but
        # above the high warning the module does print.
        table = {"tx_power": {"high_alarm": 3.5, "high_warning": 2.5}}
        health, messages = self.grade(sr4(
            tx=fx.with_lane(fx.SR4_TX, 2, 2.6), tables=table))
        self.assertEqual(health, "warning")
        self.assertEqual(messages, [
            "TX power 2.60 dBm on lane 2 is above the module's high warning "
            "2.50 dBm"])
        health, messages = self.grade(sr4(
            tx=fx.with_lane(fx.SR4_TX, 2, 2.6)))
        self.assertEqual(health, "good")
        self.assertEqual(messages, [])

    def test_a_module_alarm_outranks_an_in_range_bias_flag(self):
        # CMIS: the flag of lane 2 is set while its bias is in range (a
        # warning); lane 3 receives less than the module's low alarm.
        health, messages = self.grade(fx.cmis(
            fx.with_lane(fx.TWIN_RX, 3, -9.0),
            flags={(2, "high_alarm"): True}))
        self.assertEqual(health, "critical")
        self.assertEqual(messages, [
            "Laser bias lane 2: 212.700 mA; module high alarm threshold: "
            "400.000 mA; module flag set, value in range",
            "RX power -9.00 dBm on lane 3 is below the module's low alarm "
            "-8.40 dBm"])


class DeadTransmitterTests(OpticalFileTestCase):
    """Bias, receive light and no transmit light on a port that is down."""

    def page_row(self, interface="swp1"):
        page, _details = self.publish()
        row = page.split(f'data-port="leaf1:{interface}"', 1)[1]
        row = row.split("</tr>", 1)[0]
        return [re.sub(r"<[^>]+>", "", cell).strip()
                for cell in re.findall(r"<td>(.*?)</td>", row, re.S)]

    def test_a_laser_that_is_off_keeps_its_transmit_reading(self):
        # 0.4 mA with the module's low-bias alarm raised: the laser is off.
        # Nothing is alarmed (a shut port looks the same), nothing is hidden.
        stats = self.rows([("swp1", "down", sfp_plus(
            -2.4, None, 0.4, tables=SFP_TABLES, flags=LOW_BIAS_FLAG))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["tx_power_lane"], 1)
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(stats["lane_evidence"]["driven_lanes"], [])
        self.assertEqual(self.messages(), ["Link down, receive light present"])
        row = self.page_row()
        self.assertEqual(row[2:5], ["DOWN", "-2.40 (L1)", "-40.00 (L1)"])
        self.assertEqual(row[-1], PEER_ACTION)
        export = self.export_rows()["swp1"]
        self.assertEqual(export["tx_power_dbm"], -40.0)
        self.assertEqual(export["tx_lanes"], "-40.0")

    def test_a_driven_laser_without_transmit_light_is_named(self):
        stats = self.rows([("swp1", "down", sfp_plus(
            -2.4, None, 6.0, tables=SFP_TABLES))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["not_monitored"], [])
        findings = [(item["severity"], item["type"], item["message"],
                     item["action"]) for item in self.anomalies()]
        self.assertEqual(findings, [
            ("warning", "OPTICAL_LINK_DOWN",
             "Link down, receive light present",
             OpticalAnalyzer.DARK_TRANSMITTER_ACTION),
            ("warning", "TX_DARK_LASER_DRIVEN",
             "TX reads no light while the laser draws 6.0 mA (failed "
             "transmitter or TX power not monitored)",
             OpticalAnalyzer.DARK_TRANSMITTER_ACTION),
        ])
        # Ambiguous evidence is a note, not a cause.
        self.assertEqual(stats["health_causes"], [])
        self.assertEqual(self.page_row()[-1],
                         OpticalAnalyzer.DARK_TRANSMITTER_ACTION)

    def test_all_lanes_of_a_qsfp_that_prints_a_tx_table(self):
        # The table alone does not prove that transmit power is monitored.
        stats = self.rows([("swp1", "down", sr4(
            rx=[-1.0] * 4, tx=[None] * 4, bias=6.5,
            tables={"tx_power": fx.limits(5.4, 2.4, -8.4, -11.4)}))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["tx_power_lanes_dbm"], [-40.0] * 4)
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "TX reads no light on any lane while the lasers draw 6.5 mA "
            "(failed transmitter or TX power not monitored)"])
        self.assertEqual(stats["health_causes"], [])

    def test_bias_under_the_module_low_limit_is_not_a_driven_laser(self):
        # No flag line at all: the limit alone says the laser is off.
        dump = sfp_plus(-2.4, None, 0.8, tables=SFP_TABLES)
        stats = self.rows([("swp1", "down", dump)])["swp1"]
        self.assertEqual(stats["lane_evidence"]["driven_lanes"], [])
        self.assertEqual(self.messages(), ["Link down, receive light present"])

    def test_without_a_link_state_a_laser_that_is_off_is_no_evidence(self):
        # 0.4 mA with the low-bias alarm raised does not prove a missing
        # transmit monitor: the dark transmitter stays a reading.
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(analyzer.update_optical_stats("leaf1:swp1", sfp_plus(
            -2.4, None, 0.4, tables=SFP_TABLES, flags=LOW_BIAS_FLAG)))
        stats = analyzer.current_optical_stats["leaf1:swp1"]
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        self.assertEqual(stats["health_status"], "critical")
        # The same dump with a laser in its normal range: not monitored.
        self.assertTrue(analyzer.update_optical_stats("leaf1:swp2", sfp_plus(
            -2.4, None, 6.0, tables=SFP_TABLES)))
        stats = analyzer.current_optical_stats["leaf1:swp2"]
        self.assertEqual(stats["not_monitored"], ["tx_power"])
        self.assertIn(stats["health_status"], HEALTHY)

    def test_dark_both_ways_with_bias_keeps_the_transmit_reading(self):
        dump = sr4(rx=[None] * 4, tx=[None] * 4)
        stats = self.rows([("swp1", "down", dump)])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(stats["tx_power_dbm"], -40.0)
        # Without a collected state as well: no receive light, no excuse.
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(analyzer.update_optical_stats("leaf1:swp1", dump))
        stats = analyzer.current_optical_stats["leaf1:swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["not_monitored"], [])
        self.assertEqual(stats["tx_power_dbm"], -40.0)

    def test_a_sub_port_dark_at_full_bias_next_to_a_working_sibling(self):
        # Twin-port module split 2x: s1's link is down, its four
        # transmitters read no light while each laser draws 200 mA, and the
        # sibling's lanes show that the module does monitor transmit power.
        dump = fx.cmis([2.0] * 8, [1.5] * 4 + [None] * 4, bias=200.0)
        rows = self.rows([("swp1s0", "up", dump), ("swp1s1", "down", dump)])
        stats = rows["swp1s1"]
        self.assertIn(rows["swp1s0"]["health_status"], HEALTHY)
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(stats["lane_evidence"]["driven_lanes"], [5, 6, 7, 8])
        self.assertTrue(stats["lane_evidence"]["module_tx_light"])
        findings = [(item["severity"], item["type"], item["message"],
                     item["action"])
                    for item in self.anomalies()
                    if item["port"] == "leaf1:swp1s1"]
        self.assertEqual(findings, [
            ("warning", "OPTICAL_LINK_DOWN",
             "Link down, light present on all lanes",
             OpticalAnalyzer.DOWN_TRANSMITTER_ACTION)] + [
            ("critical", "MODULE_TX_POWER_LOW",
             f"TX power -40.00 dBm on lane {lane} is below the module's low "
             "alarm -4.90 dBm", OpticalAnalyzer.DOWN_TRANSMITTER_ACTION)
            for lane in (5, 6, 7, 8)])
        self.assertEqual(stats["health_causes"], ["tx_power"])
        row = self.page_row("swp1s1")
        self.assertEqual(row[2:5], ["DOWN", "2.00 (L5)", "-40.00 (L5)"])
        self.assertEqual(row[-1], OpticalAnalyzer.DOWN_TRANSMITTER_ACTION)

    def test_the_same_without_module_tables(self):
        dump = fx.cmis([2.0] * 8, [1.5] * 4 + [None] * 4, bias=200.0,
                       tables=None)
        stats = self.rows([("swp1s0", "up", dump),
                           ("swp1s1", "down", dump)])["swp1s1"]
        self.assertEqual(self.messages("leaf1:swp1s1"), [
            "Link down, light present on all lanes",
            "TX power out of range: -40.00 dBm"])
        self.assertEqual(stats["health_causes"], ["tx_power"])

    def test_only_the_driven_lanes_of_the_sub_port_are_listed(self):
        # Lane 7's laser is off (its low-bias flag is raised) and lane 8
        # draws nothing: neither is evidence of a failed transmitter.
        bias = [200.0] * 6 + [0.4, 0.0]
        dump = fx.cmis([2.0] * 8, [1.5] * 4 + [None] * 4, bias=bias,
                       flags={(7, "low_alarm"): True})
        stats = self.rows([("swp1s0", "up", dump),
                           ("swp1s1", "down", dump)])["swp1s1"]
        self.assertEqual(stats["lane_evidence"]["driven_lanes"], [5, 6])
        self.assertEqual(
            [message for message in self.messages("leaf1:swp1s1")
             if message.startswith("TX power")],
            [f"TX power -40.00 dBm on lane {lane} is below the module's low "
             "alarm -4.90 dBm" for lane in (5, 6)])

    def test_a_dark_lane_next_to_lit_ones_keeps_the_transceiver_advice(self):
        # Lane 3 transmits nothing while its laser draws bias and the
        # other lanes transmit: the port is plainly enabled.
        stats = self.rows([("swp1", "down", sr4(
            tx=fx.with_lane(fx.SR4_TX, 3, None)))])["swp1"]
        transceiver = ("Inspect or replace the transceiver and verify "
                       "module compatibility")
        self.assertEqual(
            [(item["severity"], item["message"], item["action"])
             for item in self.anomalies()],
            [("warning", "Link down, light present on all lanes",
              transceiver),
             ("critical", "TX power out of range: -40.00 dBm", transceiver)])
        self.assertEqual(stats["health_causes"], ["tx_power"])
        self.assertEqual(self.page_row()[-1], transceiver)

    def test_a_parked_sub_port_lists_no_transmit_alarm(self):
        # Lasers off on s1 (no bias): what a shut port looks like.
        dump = fx.cmis([2.0] * 8, [1.5] * 4 + [None] * 4,
                       bias=[200.0] * 4 + [0.0] * 4)
        stats = self.rows([("swp1s0", "up", dump),
                           ("swp1s1", "down", dump)])["swp1s1"]
        self.assertEqual(self.messages("leaf1:swp1s1"),
                         ["Link down, light present on all lanes"])
        self.assertEqual(stats["health_causes"], [])
        self.assertEqual(self.page_row("swp1s1")[-1], PEER_ACTION)


class LinkDownSentenceTests(OpticalFileTestCase):
    """The sentence of a DOWN row names the lanes that were set aside."""

    def down(self, dump, interface="swp1"):
        stats = self.rows([(interface, "down", dump)])[interface]
        anomaly = self.anomalies()[0]
        self.assertEqual(anomaly["type"], "OPTICAL_LINK_DOWN")
        return stats, anomaly["message"], anomaly["action"]

    def test_a_lane_dead_both_ways_is_named(self):
        stats, message, action = self.down(sr4(
            rx=fx.with_lane(fx.SR4_RX, 3, None),
            tx=fx.with_lane(fx.SR4_TX, 3, None),
            bias=fx.with_lane(fx.SR4_BIAS, 3, 0.0)))
        self.assertEqual(stats["inactive_lanes"], [3])
        self.assertEqual(
            message, "Link down, light present on lanes 1, 2, 4; lane 3 "
                     "without light and without laser bias")
        self.assertEqual(action, FIBRE_ACTION)
        self.assertEqual(
            self.parent.get_recommended_action(
                {"port": "leaf1:swp1", "health": "down"}), FIBRE_ACTION)
        self.assertEqual(self.export_rows()["swp1"]["inactive_lanes"], "3")

    def test_two_lanes_and_a_weak_one(self):
        _stats, message, action = self.down(sr4(
            rx=[-16.0, None, -1.5, None], tx=[-0.8, None, -1.0, None],
            bias=[6.7, 0.0, 6.6, 0.0]))
        self.assertEqual(
            message, "Link down, lane 1 at -16.0 dBm; lanes 2, 4 without "
                     "light and without laser bias")
        self.assertEqual(
            action, "Check fiber connection, clean connectors, or replace "
                    "cable")

    def test_a_dead_channel_of_a_down_sub_port_is_named(self):
        # Twin-port module split 2x, channel 2 dead; the sibling is fine.
        dump = fx.cmis(fx.with_lane(fx.TWIN_RX, 2, None),
                       fx.with_lane(fx.TWIN_TX, 2, None),
                       bias=fx.with_lane([212.7] * 8, 2, 0.0))
        rows = self.rows([("swp1s0", "down", dump), ("swp1s1", "up", dump)])
        self.assertIn(rows["swp1s1"]["health_status"], HEALTHY)
        self.assertEqual(self.messages("leaf1:swp1s0"), [
            "Link down, light present on lanes 1, 3, 4; lane 2 without "
            "light and without laser bias"])

    def test_spare_channels_of_a_wider_cage_are_not_blamed(self):
        # A four-lane module in an eight-channel cage: the upper half of
        # the channels was never equipped.
        rx = fx.TWIN_RX[:4] + [None] * 4
        tx = fx.TWIN_TX[:4] + [None] * 4
        dump = fx.cmis(rx, tx, bias=[60.0] * 4 + [0.0] * 4, tables=None)
        stats, message, action = self.down(dump)
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertIsNone(stats["lane_evidence"]["declared_lanes"])
        self.assertEqual(message, "Link down, light present on all lanes")
        self.assertEqual(action, PEER_ACTION)
        # One lane fewer in service: the dead one is named with the rest.
        rx[3] = tx[3] = None
        dump = fx.cmis(rx, tx, bias=[60.0] * 3 + [0.0] * 5, tables=None)
        _stats, message, action = self.down(dump)
        self.assertEqual(
            message, "Link down, light present on lanes 1, 2, 3; lanes 4, "
                     "5, 6, 7, 8 without light and without laser bias")
        self.assertEqual(action, FIBRE_ACTION)

    def test_the_lower_half_or_an_uneven_split_is_not_a_spare_set(self):
        cases = (
            # Channels 1-4 dark and undriven, 5-8 lit.
            ([None] * 4 + fx.TWIN_RX[4:], [None] * 4 + fx.TWIN_TX[4:],
             [0.0] * 4 + [60.0] * 4,
             "Link down, light present on lanes 5, 6, 7, 8; lanes 1, 2, 3, "
             "4 without light and without laser bias"),
            # Two of eight set aside.
            (fx.TWIN_RX[:6] + [None] * 2, fx.TWIN_TX[:6] + [None] * 2,
             [60.0] * 6 + [0.0] * 2,
             "Link down, light present on lanes 1, 2, 3, 4, 5, 6; lanes 7, "
             "8 without light and without laser bias"),
        )
        for rx, tx, bias, expected in cases:
            with self.subTest(expected):
                _stats, message, action = self.down(
                    fx.cmis(rx, tx, bias=bias, tables=None))
                self.assertEqual(message, expected)
                self.assertEqual(action, FIBRE_ACTION)

    def test_the_media_text_says_which_lanes_the_module_has(self):
        # An SR4 that prints its standard, lane 4 dead: four lanes are
        # declared and three are in service, so the dead one is named.
        _stats, message, _action = self.down(fx.qsfp(
            connector="0x0c (MPO Parallel Optic)",
            types=["100G Ethernet: 100G Base-SR4"],
            technology="0x00 (850 nm VCSEL)",
            rx=fx.with_lane(fx.SR4_RX, 4, None),
            tx=fx.with_lane(fx.SR4_TX, 4, None),
            bias=fx.with_lane(fx.SR4_BIAS, 4, 0.0)))
        self.assertEqual(
            message, "Link down, light present on lanes 1, 2, 3; lane 4 "
                     "without light and without laser bias")
        # A module that declares two lanes and lights two of four channels
        # that are not the lower half: all it has is in service.
        dump = fx.qsfp(
            connector="0x0c (MPO Parallel Optic)",
            types=["100G Ethernet: 100G Base-SR2"],
            technology="0x00 (850 nm VCSEL)",
            rx=[-1.2, None, -1.5, None], tx=[-0.8, None, -1.0, None],
            bias=[6.7, 0.0, 6.6, 0.0])
        stats, message, action = self.down(dump)
        self.assertEqual(stats["lane_evidence"]["declared_lanes"], 2)
        self.assertEqual(stats["inactive_lanes"], [2, 4])
        self.assertEqual(message, "Link down, light present on all lanes")
        self.assertEqual(action, PEER_ACTION)

    def test_a_link_up_row_is_not_touched(self):
        stats = self.rows([("swp1", "up", sr4(
            rx=fx.with_lane(fx.SR4_RX, 3, None),
            tx=fx.with_lane(fx.SR4_TX, 3, None),
            bias=fx.with_lane(fx.SR4_BIAS, 3, 0.0)))])["swp1"]
        self.assertIn(stats["health_status"], HEALTHY)
        self.assertEqual(self.messages(), [])


class GenericModuleConditionTests(OpticalFileTestCase):
    """Voltage, low temperature and high RX graded by the generic limits."""

    CASES = (
        (dict(voltage=2.6), "VOLTAGE_OUT_OF_RANGE", "voltage",
         "Module voltage out of range: 2.6000 V (limits: 3.0 to 3.6 V)"),
        (dict(voltage=3.9), "VOLTAGE_OUT_OF_RANGE", "voltage",
         "Module voltage out of range: 3.9000 V (limits: 3.0 to 3.6 V)"),
        (dict(temperature=-5.0), "LOW_TEMPERATURE", "temperature",
         "SFP temperature too low: -5.0°C (threshold: 0.0°C)"),
        (dict(temperature=75.0), "HIGH_TEMPERATURE", "temperature",
         "SFP temperature too high: 75.0°C (threshold: 70.0°C)"),
        (dict(rx=fx.with_lane(fx.SR4_RX, 2, 8.0)), "HIGH_OPTICAL_POWER",
         "rx_power", "RX power too high: 8.00 dBm (threshold: 7.0 dBm)"),
    )

    def test_a_link_up_row_names_value_and_limit(self):
        for change, kind, cause, message in self.CASES:
            with self.subTest(kind=kind, change=change):
                stats = self.rows([("swp1", "up", sr4(**change))])["swp1"]
                self.assertEqual(stats["health_status"], "critical")
                self.assertEqual(
                    [(item["severity"], item["type"], item["message"])
                     for item in self.anomalies()],
                    [("critical", kind, message)])
                self.assertEqual(stats["health_causes"], [cause])

    def test_a_link_down_row_lists_the_cause(self):
        for change, kind, cause, message in self.CASES:
            with self.subTest(kind=kind, change=change):
                stats = self.rows([("swp1", "down", sr4(**change))])["swp1"]
                self.assertEqual(stats["health_status"], "down")
                findings = [(item["severity"], item["type"], item["message"])
                            for item in self.anomalies()]
                self.assertEqual(findings[0][1], "OPTICAL_LINK_DOWN")
                self.assertEqual(findings[1:], [("critical", kind, message)])
                self.assertEqual(stats["health_causes"], [cause])
                shard = self.shard()["current"]["leaf1:swp1"]
                self.assertEqual(shard["health_causes"], [cause])

    def test_module_conditions_are_one_finding_per_cage(self):
        dump = fx.cmis(voltage=2.9, temperature=-3.0, tables=None)
        self.rows([("swp3s0", "up", dump), ("swp3s1", "up", dump)])
        named = " (one module in swp3, sub-ports swp3s0, swp3s1)"
        self.assertEqual(
            [(item["type"], item["message"], item["ports"])
             for item in self.anomalies()],
            [("LOW_TEMPERATURE",
              "SFP temperature too low: -3.0°C (threshold: 0.0°C)" + named,
              ["leaf1:swp3s0", "leaf1:swp3s1"]),
             ("VOLTAGE_OUT_OF_RANGE",
              "Module voltage out of range: 2.9000 V (limits: 3.0 to 3.6 V)"
              + named, ["leaf1:swp3s0", "leaf1:swp3s1"])])

    def test_a_reading_a_module_limit_names_is_not_named_twice(self):
        # Incomplete tables (one side unset) keep the generic rules on; a
        # reading beyond a limit they do print is one finding, not two.
        cases = (
            (dict(voltage=2.95, tables={
                "voltage": fx.limits(0.0, 0.0, 3.135, 3.1)}),
             ["Module voltage 2.9500 V is below the module's low alarm "
              "3.1000 V"]),
            (dict(temperature=-8.0, tables={
                "temperature": {"low_alarm": -5.0, "low_warning": 0.0}}),
             ["Module temperature -8.00°C is below the module's low alarm "
              "-5.00°C"]),
            (dict(rx=fx.with_lane(fx.SR4_RX, 2, 8.0), tables={
                "rx_power": fx.limits(6.5, 5.5, None, None)}),
             ["RX power 8.00 dBm on lane 2 is above the module's high alarm "
              "6.50 dBm"]),
            # Only beyond the module's warning: the generic limit is what
            # makes the port critical, so it is named as well.
            (dict(rx=fx.with_lane(fx.SR4_RX, 2, 8.0), tables={
                "rx_power": fx.limits(9.0, 5.5, None, None)}),
             ["RX power 8.00 dBm on lane 2 is above the module's high "
              "warning 5.50 dBm",
              "RX power too high: 8.00 dBm (threshold: 7.0 dBm)"]),
        )
        for change, messages in cases:
            with self.subTest(messages[0]):
                stats = self.rows([("swp1", "up", sr4(**change))])["swp1"]
                self.assertEqual(stats["health_status"], "critical")
                self.assertEqual(self.messages(), messages)

    def test_a_dark_lane_is_named_before_a_bright_one(self):
        # Lane 1 is dark (the displayed lane), lane 2 is far too bright:
        # the finding follows the displayed lane.
        self.rows([("swp1", "up", sr4(
            rx=[None, 8.0, -1.5, -1.1], tx=fx.SR4_TX))])
        self.assertEqual(self.messages(), [
            "RX power too low: -40.00 dBm (threshold: -14.0 dBm)"])
        # Voltage inside the generic range is no finding at all.
        self.rows([("swp1", "up", sr4(voltage=3.55))])
        self.assertEqual(self.messages(), [])

    def test_the_general_sentence_is_left_for_stats_without_evidence(self):
        # Stats reloaded from a shard carry no module limits (they are not
        # persisted): a port the module's own table made critical still
        # gets a finding.
        self.rows([("swp1", "up", fx.cmis(fx.with_lane(fx.TWIN_RX, 3, -9.0)))])
        reloaded = OpticalAnalyzer(str(self.root))
        stats = reloaded.current_optical_stats["leaf1:swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertNotIn("module_limits", stats)
        self.assertEqual(
            [item["message"] for item in reloaded.detect_optical_anomalies()],
            ["A voltage, bias, high-RX, or lane threshold is critical"])


class MalformedNumberTests(OpticalFileTestCase):
    """One unreadable number costs that value, not the device's rows."""

    BAD_TEMPERATURE = sr4().replace("38.00 degrees C", "1.2.3 degrees C")
    BAD_VOLTAGE = sr4().replace("3.2900 V", "3.2.9 V")

    def test_the_fixtures_are_malformed(self):
        self.assertIn("Module temperature", self.BAD_TEMPERATURE)
        self.assertIn(": 1.2.3 degrees C", self.BAD_TEMPERATURE)
        self.assertIn(": 3.2.9 V", self.BAD_VOLTAGE)

    def test_every_kind_of_block_keeps_the_file_alive(self):
        cases = (
            ("unknown", self.BAD_TEMPERATURE, "unknown"),
            ("down", "status : unplugged\n" + self.BAD_TEMPERATURE,
             "unplugged"),
            ("up", self.BAD_TEMPERATURE, HEALTHY),
            ("down", self.BAD_TEMPERATURE, "down"),
            ("up", self.BAD_VOLTAGE, HEALTHY),
        )
        for state, body, expected in cases:
            with self.subTest(state=state, expected=expected):
                rows = self.rows([("swp1", "up", sr4()), ("swp2", state, body)])
                self.assertIn(rows["swp1"]["health_status"], HEALTHY)
                if isinstance(expected, tuple):
                    self.assertIn(rows["swp2"]["health_status"], expected)
                else:
                    self.assertEqual(rows["swp2"]["health_status"], expected)

    def test_the_value_is_missing_and_the_rest_is_graded(self):
        rows = self.rows([("swp1", "up", self.BAD_TEMPERATURE),
                          ("swp2", "up", self.BAD_VOLTAGE)])
        self.assertIsNone(rows["swp1"]["temperature_c"])
        self.assertEqual(rows["swp1"]["voltage_v"], 3.29)
        self.assertEqual(rows["swp1"]["rx_power_lanes_dbm"], fx.SR4_RX)
        self.assertIsNone(rows["swp2"]["voltage_v"])
        self.assertEqual(rows["swp2"]["temperature_c"], 38.0)


class RowActionTests(OpticalFileTestCase):
    def test_a_reading_the_module_accepts_does_not_choose_the_advice(self):
        # A 1G SFP whose receiver is fine at -15 dBm by its own table (low
        # alarm -20) while the module is beyond its temperature alarm: the
        # advice is about cooling, not about the fibre.
        dump = fx.sfp(connector="0x07 (LC)",
                      types=["Ethernet: 1000BASE-LX"],
                      dom=(-15.0, -5.0, 6.0, 95.0, 3.29), tables=SFP_TABLES)
        stats = self.rows([("swp1", "up", dump)])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["health_causes"], ["temperature"])
        self.assertEqual(
            self.parent.get_recommended_action(
                {"port": "leaf1:swp1", "health": "critical",
                 "rx_power_dbm": stats["rx_power_dbm"],
                 "temperature_c": stats["temperature_c"]}),
            "Check cooling, reduce load, or replace SFP module")


class DownRowRuleTests(OpticalFileTestCase):
    """Rules of DOWN rows no earlier test pinned."""

    def test_module_low_alarms_are_listed(self):
        cases = (
            (dict(voltage=3.05), "voltage",
             "Module voltage 3.0500 V is below the module's low alarm "
             "3.1000 V"),
            (dict(temperature=-12.0), "temperature",
             "Module temperature -12.00°C is below the module's low alarm "
             "-10.00°C"),
        )
        for change, cause, message in cases:
            with self.subTest(cause):
                stats = self.rows([("swp1", "down",
                                    fx.cmis(**change))])["swp1"]
                self.assertEqual(self.messages(), [
                    "Link down, light present on all lanes", message])
                self.assertEqual(stats["health_causes"], [cause])

    def test_a_parked_port_without_tables_lists_no_power_finding(self):
        dump = sr4(rx=[None] * 4, tx=[None] * 4, bias=0.0)
        stats = self.rows([("swp1", "down", dump)])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(self.messages(),
                         ["Link down, no receive light on any lane"])
        self.assertEqual(stats["health_causes"], [])

    def test_an_in_range_flag_is_not_a_laser_that_is_off(self):
        # CMIS: lane 1's laser is dead (0.4 mA, low alarm), and the flag is
        # printed on the other lanes as well although their bias is in
        # range.  Those lanes are driven, so the dead laser is listed.
        flags = {(lane, "low_alarm"): True for lane in range(1, 9)}
        stats = self.rows([("swp1", "down", fx.cmis(
            tx=fx.with_lane(fx.TWIN_TX, 1, None),
            bias=fx.with_lane([212.7] * 8, 1, 0.4), flags=flags))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertIn(
            "Laser bias lane 1: 0.400 mA; module low alarm threshold: "
            "10.000 mA; module flag is On", self.messages())
        self.assertEqual(stats["bias_assessment"]["status"], "critical")
        self.assertEqual(stats["health_causes"], ["bias_current", "tx_power"])

    def test_the_generic_transmit_finding_names_the_worst_lane(self):
        # Lane 1 is weak, lane 3 transmits nothing: the dark lane is named.
        self.rows([("swp1", "down", sr4(tx=[-12.0, -0.6, None, -0.9]))])
        self.assertEqual(self.messages(), [
            "Link down, light present on all lanes",
            "TX power out of range: -40.00 dBm"])

    def test_a_warning_is_no_cause_of_a_down_row(self):
        # CMIS flag set while the bias is in range: a warning-level event.
        stats = self.rows([("swp1", "down", fx.cmis(
            flags={(2, "high_alarm"): True}))])["swp1"]
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual(
            [(item["severity"], item["type"]) for item in self.anomalies()],
            [("warning", "OPTICAL_LINK_DOWN"), ("warning", "LASER_BIAS_HIGH")])
        self.assertEqual(stats["health_causes"], [])

    def test_every_down_operstate_is_a_down_row(self):
        for state in ("down", "lowerlayerdown", "dormant"):
            with self.subTest(state):
                stats = self.rows([("swp1", state, sr4())])["swp1"]
                self.assertEqual(stats["health_status"], "down")
                self.assertEqual(stats["link_state"], "down")
                self.assertEqual(self.messages(),
                                 ["Link down, light present on all lanes"])

    def test_an_identifier_byte_alone_marks_a_cmis_dump(self):
        # ethtool builds without a name for the byte print it alone.
        flagged = fx.cmis(flags={(2, "high_alarm"): True})
        named = fx.line("Identifier", fx.OSFP)
        self.assertIn(named, flagged)
        for byte in ("0x18", "0x19", "0x1b", "0x1e", "0x1f", "0x20"):
            with self.subTest(byte):
                dump = flagged.replace(named, fx.line("Identifier", byte))
                stats = self.rows([("swp1", "up", dump)])["swp1"]
                self.assertEqual(stats["health_status"], "warning")
                self.assertEqual(self.messages(), [
                    "Laser bias lane 2: 212.700 mA; module high alarm "
                    "threshold: 400.000 mA; module flag set, value in range"])
        # Any other byte is graded by the flag, as SFF-8636 flags are.
        for byte in ("0x11", "0x0d"):
            with self.subTest(byte):
                dump = flagged.replace(named, fx.line("Identifier", byte))
                stats = self.rows([("swp1", "up", dump)])["swp1"]
                self.assertEqual(stats["health_status"], "critical")


class MergedFindingTests(OpticalFileTestCase):
    """One module, read once per sub-port a moment apart."""

    def test_the_merged_finding_names_the_worst_reading(self):
        self.rows([("swp1s0", "up", fx.cmis(temperature=85.0)),
                   ("swp1s1", "up", fx.cmis(temperature=85.5))])
        message = ("Module temperature 85.50°C is above the module's high "
                   "alarm 80.00°C (one module in swp1, sub-ports swp1s0, "
                   "swp1s1)")
        self.assertEqual(self.messages(), [message])
        export = self.export_rows()
        self.assertEqual(export["swp1s0"]["temperature_c"], 85.0)
        self.assertEqual(export["swp1s1"]["temperature_c"], 85.5)
        for interface in ("swp1s0", "swp1s1"):
            self.assertEqual(export[interface]["anomalies"],
                             "CRITICAL: " + message)
        self.assertEqual(self.anomalies()[0]["port"], "leaf1:swp1s0")

    def test_the_worst_of_a_low_reading_is_the_lowest(self):
        self.rows([("swp1s0", "up", fx.cmis(voltage=3.04)),
                   ("swp1s1", "up", fx.cmis(voltage=3.05)),
                   ("swp1s2", "up", fx.cmis(voltage=3.03)),
                   ("swp1s3", "up", fx.cmis(voltage=3.06))])
        self.assertEqual(self.messages(), [
            "Module voltage 3.0300 V is below the module's low alarm "
            "3.1000 V (one module in swp1, sub-ports swp1s0, swp1s1, "
            "swp1s2, swp1s3)"])

    def test_generic_findings_too(self):
        self.rows([("swp1s0", "up", fx.cmis(temperature=75.0, tables=None)),
                   ("swp1s1", "up", fx.cmis(temperature=76.5, tables=None))])
        self.assertEqual(self.messages(), [
            "SFP temperature too high: 76.5°C (threshold: 70.0°C) (one "
            "module in swp1, sub-ports swp1s0, swp1s1)"])


class NotMonitoredNoteTests(OpticalFileTestCase):
    """The detail row says which evidence set the side aside."""

    def test_the_note_names_the_link_state(self):
        if not shutil.which("node"):
            self.skipTest("Node.js runs the page script")
        self.rows([("swp1", "up", sr4(tx=[None] * 4))])
        page, details = self.publish()
        self.assertEqual(details["leaf1:swp1"]["link_state"], "up")
        panel = self.render_panel(page, "leaf1:swp1", details["leaf1:swp1"])
        self.assertIn(
            "Not monitored by this module, not graded: TX power (reads no "
            "light on every lane although the link is up).", panel)
        # No collected state: the lasers and the receive light are the
        # evidence.
        detail = dict(details["leaf1:swp1"], link_state=None)
        panel = self.render_panel(page, "leaf1:swp1", detail)
        self.assertIn(
            "(reads no light on every lane although the lasers draw bias "
            "and the port receives light).", panel)
        self.assertNotIn("the port is in use", panel)


if __name__ == "__main__":
    unittest.main()
