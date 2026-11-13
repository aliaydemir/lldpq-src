#!/usr/bin/env python3
"""RX/TX power, temperature and voltage are graded by the module's own limits.

``ethtool -m`` prints five threshold tables for CMIS, SFF-8636 and SFF-8472
modules alike (sff_show_thresholds): 'Laser bias current', 'Laser output
power' (TX), 'Module temperature', 'Module voltage' and 'Laser rx power', each
with a high alarm / low alarm / high warning / low warning 'threshold' line.
Only the bias table was read.  The other four metrics were graded by fixed
generic values, so a healthy twin-port module at 60 C was WARNING, a TX lane
at 4.1 dBm was CRITICAL, and an RX lane 0.6 dB under the module's own low
alarm was GOOD and not even the lane the row displayed.

The dumps below are built with ethtool's print formats ("\\t%-41s : %s",
"%.4f mW / %.2f dBm", "%.2f degrees C / %.2f degrees F", "%.4f V",
"%.3f mA").  All module values are invented.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
from optical_analyzer import OpticalAnalyzer, SIDECAR_ONLY_STAT_KEYS


UNSET = object()        # a limit the module leaves at 0 mW: "-inf dBm"
KINDS = (("high_alarm", "high alarm"), ("low_alarm", "low alarm"),
         ("high_warning", "high warning"), ("low_warning", "low warning"))
HEALTHY = ("good", "excellent")


def line(label, value):
    return "\t%-41s : %s" % (label, value)


def power(dbm):
    if dbm is None or dbm is UNSET:
        return "0.0000 mW / -inf dBm"
    return "%.4f mW / %.2f dBm" % (10 ** (dbm / 10.0), dbm)


def celsius(value):
    return "%.2f degrees C / %.2f degrees F" % (value, value * 1.8 + 32)


def volts(value):
    return "%.4f V" % value


def milliamps(value):
    return "%.3f mA" % value


def limits(high_alarm, high_warning, low_warning, low_alarm):
    return {"high_alarm": high_alarm, "high_warning": high_warning,
            "low_warning": low_warning, "low_alarm": low_alarm}


# The twin-port module of the report: limits as high alarm / high warning /
# low warning / low alarm.
TWIN = {
    "bias": limits(400.0, 380.0, 15.0, 10.0),
    "tx_power": limits(6.0, 5.0, -3.9, -4.9),
    "temperature": limits(80.0, 70.0, 0.0, -10.0),
    "voltage": limits(3.5, 3.465, 3.135, 3.1),
    "rx_power": limits(6.5, 5.5, -7.4, -8.4),
}
PARSED_TWIN = {metric: TWIN[metric] for metric in
               ("rx_power", "tx_power", "temperature", "voltage")}
HEALTHY_RX = [1.04, 1.50, 2.60, 2.00, 1.20, 1.90, 2.20, 2.40]
HEALTHY_TX = [0.98, 1.20, 2.00, 1.50, 1.10, 1.70, 1.30, 1.90]


def threshold_lines(tables):
    """The block sff_show_thresholds prints, in its order.

    A value given as a string is printed as it stands (malformed output).
    """
    out = []
    for metric, label, render in (
            ("bias", "Laser bias current", milliamps),
            ("tx_power", "Laser output power", power),
            ("temperature", "Module temperature", celsius),
            ("voltage", "Module voltage", volts),
            ("rx_power", "Laser rx power", power)):
        table = (tables or {}).get(metric)
        if not table:
            continue
        for key, words in KINDS:
            if key not in table:
                continue
            value = table[key]
            out.append(line(f"{label} {words} threshold",
                            value if isinstance(value, str) else render(value)))
    return out


def cmis(rx=HEALTHY_RX, tx=HEALTHY_TX, *, temperature=45.0, voltage=3.2734,
         bias=212.7, tables=TWIN):
    """A CMIS dump (cmis.c): eight channels unless told otherwise."""
    out = [
        line("Identifier", "0x19 (OSFP 8X Pluggable Transceiver)"),
        line("Connector", "0x28 (MPO 1x12)"),
        line("Vendor name", "ACME"),
    ]
    if temperature is not None:
        out.append(line("Module temperature", celsius(temperature)))
    if voltage is not None:
        out.append(line("Module voltage", volts(voltage)))
    biases = bias if isinstance(bias, list) else [bias] * len(rx)
    for channel, value in enumerate(biases, start=1):
        out.append(line(f"Laser tx bias current (Channel {channel})",
                        milliamps(value)))
    for channel, value in enumerate(tx, start=1):
        out.append(line(f"Transmit avg optical power (Channel {channel})",
                        power(value)))
    for channel, value in enumerate(rx, start=1):
        out.append(line(f"Rcvr signal avg optical power (Channel {channel})",
                        power(value)))
    return "\n".join(out + threshold_lines(tables)) + "\n"


def sff8636(rx, tx, *, temperature=38.0, voltage=3.29, bias=6.5, tables=None):
    """An SFF-8636 dump (qsfp.c): no blank before "(Channel" on RX."""
    out = [
        line("Identifier", "0x11 (QSFP28)"),
        line("Connector", "0x0c (MPO Parallel Optic)"),
        line("Transceiver type", "100G Ethernet: 100G Base-SR4"),
        line("Vendor name", "ACME"),
        line("Module temperature", celsius(temperature)),
        line("Module voltage", volts(voltage)),
        line("Alarm/warning flags implemented", "Yes"),
    ]
    for channel in range(1, len(rx) + 1):
        out.append(line(f"Laser tx bias current (Channel {channel})",
                        milliamps(bias)))
    for channel, value in enumerate(tx, start=1):
        out.append(line(f"Transmit avg optical power (Channel {channel})",
                        power(value)))
    for channel, value in enumerate(rx, start=1):
        out.append(line(f"Rcvr signal avg optical power(Channel {channel})",
                        power(value)))
    return "\n".join(out + threshold_lines(tables)) + "\n"


def sff8472(rx, tx, *, temperature=30.0, voltage=3.3, bias=6.0, tables=None):
    """An SFF-8472 dump (sfpdiag.c): one unnumbered lane, flags, limits."""
    out = [
        line("Identifier", "0x03 (SFP)"),
        line("Connector", "0x07 (LC)"),
        line("Vendor name", "ACME"),
        line("Optical diagnostics support", "Yes"),
        line("Laser bias current", milliamps(bias)),
        line("Laser output power", power(tx)),
        line("Receiver signal average optical power", power(rx)),
        line("Module temperature", celsius(temperature)),
        line("Module voltage", volts(voltage)),
        line("Alarm/warning flags implemented", "Yes"),
    ]
    for label in ("Laser bias current", "Laser output power",
                  "Module temperature", "Module voltage", "Laser rx power"):
        for _key, words in KINDS:
            out.append(line(f"{label} {words}", "Off"))
    return "\n".join(out + threshold_lines(tables)) + "\n"


# The 1G SFP of the report: its receiver works far below the generic floor.
SFP = {
    "bias": limits(17.0, 14.0, 2.0, 1.0),
    "tx_power": limits(-0.97, -1.97, -9.5, -10.5),
    "temperature": limits(90.0, 85.0, -5.0, -10.0),
    "voltage": limits(3.6, 3.5, 3.1, 3.0),
    "rx_power": limits(2.04, 1.04, -16.99, -20.0),
}


def with_lane(values, lane, value):
    out = list(values)
    out[lane - 1] = value
    return out


def device_file(blocks):
    out = ["=== OPTICAL DIAGNOSTICS ==="]
    for interface, state, body in blocks:
        out += [f"--- Interface: {interface}", f"Interface state: {state}",
                body.rstrip("\n")]
    return "\n".join(out) + "\n"


class ModuleLimitTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.analyzer = OpticalAnalyzer(str(self.root), load_history=False)

    def grade(self, dump, port="leaf1:swp1"):
        """(stats, anomalies, row action) of one dump on a clean analyzer."""
        self.analyzer.current_optical_stats = {}
        self.analyzer.optical_history = {}
        self.assertTrue(self.analyzer.update_optical_stats(port, dump))
        stats = self.analyzer.current_optical_stats[port]
        anomalies = self.analyzer.detect_optical_anomalies()
        row = next(item for item in self.analyzer._ordered_ports(
            self.analyzer.get_optical_summary()) if item["port"] == port)
        return stats, anomalies, self.analyzer.get_recommended_action(row)

    def health(self, dump):
        return self.grade(dump)[0]["health_status"]

    @staticmethod
    def messages(anomalies):
        return [item["message"] for item in anomalies]


class ThresholdParsingTests(ModuleLimitTestCase):
    def test_all_five_tables_are_read_from_a_cmis_dump(self):
        parsed = self.analyzer.parse_optical_data(
            cmis(temperature=60.06))
        self.assertEqual(parsed["module_thresholds"], PARSED_TWIN)
        self.assertEqual(parsed["bias_thresholds_ma"], TWIN["bias"])
        # A threshold line is never taken for the measurement it limits.
        self.assertEqual(parsed["temperature_c"], 60.06)
        self.assertEqual(parsed["voltage_v"], 3.2734)
        self.assertEqual(parsed["_rx_power_lanes_dbm"], HEALTHY_RX)
        self.assertEqual(parsed["_tx_power_lanes_dbm"], HEALTHY_TX)

    def test_sff_8636_spellings(self):
        tables = {
            "bias": limits(10.0, 9.5, 1.0, 0.5),
            "tx_power": limits(5.4, 2.4, -8.4, -11.4),
            "temperature": limits(75.0, 70.0, 0.0, -5.0),
            "voltage": limits(3.63, 3.465, 3.135, 2.97),
            "rx_power": limits(5.4, 2.4, -10.3, -13.3),
        }
        dump = sff8636([-1.0, -1.1, -1.2, -1.3], [-0.5, -0.6, -0.7, -0.8],
                       tables=tables)
        self.assertIn("Rcvr signal avg optical power(Channel 1)", dump)
        parsed = self.analyzer.parse_optical_data(dump)
        self.assertEqual(parsed["module_thresholds"], {
            metric: tables[metric] for metric in
            ("rx_power", "tx_power", "temperature", "voltage")})
        self.assertEqual(parsed["_rx_power_lanes_dbm"],
                         [-1.0, -1.1, -1.2, -1.3])
        stats, anomalies, _action = self.grade(dump)
        self.assertEqual(stats["health_status"], "excellent")
        self.assertEqual(stats["module_limits"]["decided"],
                         ["rx_power", "tx_power", "temperature", "voltage"])
        self.assertEqual(anomalies, [])

    def test_sff_8472_spellings(self):
        dump = sff8472(-6.0, -5.0, tables=SFP)
        parsed = self.analyzer.parse_optical_data(dump)
        self.assertEqual(parsed["module_thresholds"], {
            metric: SFP[metric] for metric in
            ("rx_power", "tx_power", "temperature", "voltage")})
        self.assertEqual(parsed["bias_thresholds_ma"], SFP["bias"])
        # The flag lines share the labels and are not limits or readings.
        self.assertEqual(parsed["rx_power_dbm"], -6.0)
        self.assertEqual(parsed["tx_power_dbm"], -5.0)
        self.assertEqual(parsed["temperature_c"], 30.0)
        self.assertEqual(parsed["voltage_v"], 3.3)

    def test_a_dump_without_tables_has_no_module_limits(self):
        parsed = self.analyzer.parse_optical_data(cmis(tables=None))
        self.assertEqual(parsed["module_thresholds"], {})


class ReportedCasesTests(ModuleLimitTestCase):
    def test_reported_healthy_module_is_healthy(self):
        stats, anomalies, action = self.grade(cmis(temperature=60.06))
        self.assertEqual(stats["health_status"], "excellent")
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertEqual(anomalies, [])
        self.assertEqual(action, "")

    def test_rx_lane_under_the_low_alarm_is_critical_and_displayed(self):
        stats, anomalies, action = self.grade(
            cmis(with_lane(HEALTHY_RX, 3, -9.0)))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (3, -9.0))
        self.assertEqual(self.messages(anomalies), [
            "RX power -9.00 dBm on lane 3 is below the module's low alarm "
            "-8.40 dBm"])
        self.assertEqual(anomalies[0]["severity"], "critical")
        self.assertEqual(
            action, "Check fiber connection, clean connectors, or replace cable")

    def test_rx_lane_under_the_low_warning_is_warning_and_displayed(self):
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 3, -7.9)))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (3, -7.9))
        self.assertIn(
            "RX power -7.90 dBm on lane 3 is below the module's low warning "
            "-7.40 dBm", self.messages(anomalies))


class EveryLimitTests(ModuleLimitTestCase):
    """Each metric, each side, warning and alarm; the generic rule is off."""

    def dump_with(self, metric, value, tables=TWIN):
        if metric == "rx_power":
            return cmis(with_lane(HEALTHY_RX, 5, value), tables=tables)
        if metric == "tx_power":
            return cmis(tx=with_lane(HEALTHY_TX, 5, value), tables=tables)
        return cmis(tables=tables, **{metric: value})

    def test_beyond_a_module_limit(self):
        cases = (
            # metric, value, health, text of the reading and of the limit
            ("rx_power", -9.0, "critical", "RX power -9.00 dBm on lane 5 is below the module's low alarm -8.40 dBm"),
            ("rx_power", -7.9, "warning", "RX power -7.90 dBm on lane 5 is below the module's low warning -7.40 dBm"),
            ("rx_power", 5.8, "warning", "RX power 5.80 dBm on lane 5 is above the module's high warning 5.50 dBm"),
            ("rx_power", 6.8, "critical", "RX power 6.80 dBm on lane 5 is above the module's high alarm 6.50 dBm"),
            ("tx_power", -6.0, "critical", "TX power -6.00 dBm on lane 5 is below the module's low alarm -4.90 dBm"),
            ("tx_power", -4.2, "warning", "TX power -4.20 dBm on lane 5 is below the module's low warning -3.90 dBm"),
            ("tx_power", 5.4, "warning", "TX power 5.40 dBm on lane 5 is above the module's high warning 5.00 dBm"),
            ("tx_power", 6.3, "critical", "TX power 6.30 dBm on lane 5 is above the module's high alarm 6.00 dBm"),
            ("temperature", -11.0, "critical", "Module temperature -11.00°C is below the module's low alarm -10.00°C"),
            ("temperature", -2.0, "warning", "Module temperature -2.00°C is below the module's low warning 0.00°C"),
            ("temperature", 72.0, "warning", "Module temperature 72.00°C is above the module's high warning 70.00°C"),
            ("temperature", 81.0, "critical", "Module temperature 81.00°C is above the module's high alarm 80.00°C"),
            ("voltage", 3.05, "critical", "Module voltage 3.0500 V is below the module's low alarm 3.1000 V"),
            ("voltage", 3.12, "warning", "Module voltage 3.1200 V is below the module's low warning 3.1350 V"),
            ("voltage", 3.48, "warning", "Module voltage 3.4800 V is above the module's high warning 3.4650 V"),
            ("voltage", 3.55, "critical", "Module voltage 3.5500 V is above the module's high alarm 3.5000 V"),
        )
        for metric, value, expected, text in cases:
            with self.subTest(metric=metric, value=value):
                stats, anomalies, _action = self.grade(
                    self.dump_with(metric, value))
                self.assertEqual(stats["health_status"], expected)
                named = [item for item in anomalies if item["message"] == text]
                self.assertEqual(len(named), 1, self.messages(anomalies))
                self.assertEqual(named[0]["severity"], expected)
                self.assertEqual(named[0]["type"].split("_")[0], "MODULE")
                self.assertEqual(
                    named[0]["lane"],
                    5 if metric in ("rx_power", "tx_power") else None)
                # Never the generic texts on a module-graded metric.
                for generic in ("RX power too low", "TX power out of range",
                                "SFP temperature too high",
                                "near its limit", "is critical"):
                    self.assertFalse(
                        any(generic in message
                            for message in self.messages(anomalies)), generic)

    def test_a_reading_on_a_limit_is_not_beyond_it(self):
        self.assertEqual(self.health(cmis(tx=with_lane(HEALTHY_TX, 5, 5.0))),
                         "good")
        self.assertEqual(self.health(cmis(tx=with_lane(HEALTHY_TX, 5, 6.0))),
                         "warning")
        self.assertEqual(self.health(cmis(temperature=70.0)), "good")
        self.assertEqual(self.health(cmis(temperature=80.0)), "warning")

    def test_generic_rules_are_not_applied_to_a_module_graded_metric(self):
        # What each reading is today without the module's table ...
        generic = (
            ("tx_power", 3.2, "warning"), ("tx_power", 4.1, "critical"),
            ("temperature", 60.06, "warning"), ("temperature", 70.5, "critical"),
            ("temperature", -1.0, "critical"),
        )
        for metric, value, expected in generic:
            with self.subTest(source="generic", metric=metric, value=value):
                self.assertEqual(
                    self.health(self.dump_with(metric, value, tables=None)),
                    expected)
        # ... and with it.
        module = (
            ("tx_power", 3.2, "excellent"), ("tx_power", 4.1, "good"),
            ("temperature", 60.06, "excellent"), ("temperature", 70.5, "warning"),
            ("temperature", -1.0, "warning"),
        )
        for metric, value, expected in module:
            with self.subTest(source="module", metric=metric, value=value):
                self.assertEqual(self.health(self.dump_with(metric, value)),
                                 expected)

    def test_wide_module_limits_replace_the_generic_floor_and_window(self):
        # 1G SFP: -15 dBm is 5 dB above its low alarm, not "too low".
        stats, anomalies, _action = self.grade(sff8472(-15.0, -5.0, tables=SFP))
        self.assertEqual(stats["health_status"], "good")
        self.assertEqual(anomalies, [])
        self.assertAlmostEqual(stats["link_margin_db"], 5.0)
        # 72 C is under its 85 C warning; 2.97 V would be generic critical
        # on a module that allows it.
        self.assertEqual(self.health(sff8472(-6.0, -5.0, temperature=72.0,
                                             tables=SFP)), "excellent")
        wide = dict(SFP, voltage=limits(3.63, 3.6, 2.9, 2.85))
        self.assertEqual(self.health(sff8472(-6.0, -5.0, voltage=2.97,
                                             tables=wide)), "excellent")

    def test_high_side_alarms_the_generic_rules_missed(self):
        stats, anomalies, _action = self.grade(sff8472(3.0, -5.0, tables=SFP))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(anomalies), [
            "RX power 3.00 dBm on lane 1 is above the module's high alarm "
            "2.04 dBm"])
        stats, anomalies, _action = self.grade(sff8472(-6.0, -0.5, tables=SFP))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(anomalies), [
            "TX power -0.50 dBm on lane 1 is above the module's high alarm "
            "-0.97 dBm"])


class HealthyBandTests(ModuleLimitTestCase):
    def test_good_when_close_to_a_module_warning_limit(self):
        cases = (
            # RX: margin under link_margin_min_db + 3 dB (low alarm -8.4).
            (cmis(with_lane(HEALTHY_RX, 4, -2.5)), "good"),
            (cmis(with_lane(HEALTHY_RX, 4, -2.3)), "excellent"),
            # RX: within 1 dB of the high warning 5.5.
            (cmis(with_lane(HEALTHY_RX, 4, 4.6)), "good"),
            (cmis(with_lane(HEALTHY_RX, 4, 4.4)), "excellent"),
            # TX: within 1 dB of a warning limit (-3.9 / 5.0).
            (cmis(tx=with_lane(HEALTHY_TX, 4, -3.0)), "good"),
            (cmis(tx=with_lane(HEALTHY_TX, 4, -2.8)), "excellent"),
            (cmis(tx=with_lane(HEALTHY_TX, 4, 4.1)), "good"),
            (cmis(tx=with_lane(HEALTHY_TX, 4, 3.9)), "excellent"),
            # Temperature: within 5 C of a warning limit (0 / 70).
            (cmis(temperature=65.5), "good"),
            (cmis(temperature=64.5), "excellent"),
            (cmis(temperature=4.5), "good"),
            (cmis(temperature=5.5), "excellent"),
            # Voltage: within 0.05 V of a warning limit (3.135 / 3.465).
            (cmis(voltage=3.42), "good"),
            (cmis(voltage=3.41), "excellent"),
            (cmis(voltage=3.18), "good"),
            (cmis(voltage=3.19), "excellent"),
        )
        for index, (dump, expected) in enumerate(cases):
            with self.subTest(case=index):
                stats, anomalies, _action = self.grade(dump)
                self.assertEqual(stats["health_status"], expected)
                self.assertEqual(anomalies, [])


class LinkMarginTests(ModuleLimitTestCase):
    def test_margin_counts_from_the_module_low_alarm(self):
        stats, _anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -4.0)))
        # Per lane, the row shows the minimum: -4.0 - (-8.4).
        self.assertAlmostEqual(stats["link_margin_db"], 4.4)
        self.assertEqual(stats["health_status"], "good")

    def test_margin_knob_still_warns_above_the_module_low_warning(self):
        stats, anomalies, action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -5.5)))
        self.assertAlmostEqual(stats["link_margin_db"], 2.9)
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (2, -5.5))
        self.assertEqual(self.messages(anomalies), [
            "Low link margin: 2.90 dB above the module's RX low alarm "
            "-8.40 dBm (threshold: 3.0 dB)"])
        self.assertEqual(action, "Monitor closely, schedule proactive maintenance")

    def test_margin_knob_moves_the_warning(self):
        low_lane = cmis(with_lane(HEALTHY_RX, 2, -7.0))
        self.assertEqual(self.health(low_lane), "warning")
        self.analyzer.thresholds["link_margin_min_db"] = 0.0
        # 1.4 dB above the low alarm and above the low warning: healthy,
        # in the band under margin + 3 dB.
        self.assertEqual(self.health(low_lane), "good")
        # The module's low warning still decides without any margin.
        self.assertEqual(self.health(cmis(with_lane(HEALTHY_RX, 2, -7.9))),
                         "warning")
        self.analyzer.thresholds["link_margin_min_db"] = 6.0
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -3.0)))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(anomalies), [
            "Low link margin: 5.40 dB above the module's RX low alarm "
            "-8.40 dBm (threshold: 6.0 dB)"])

    def test_without_a_module_table_the_margin_is_generic(self):
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -11.5), tables=None))
        self.assertAlmostEqual(stats["link_margin_db"], 2.5)
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(anomalies), [
            "Low link margin: 2.50 dB (threshold: 3.0 dB)"])


class DisplayedLaneTests(ModuleLimitTestCase):
    """The row shows the lane that explains the badge."""

    def test_lane_under_the_module_alarm_beats_brighter_peers(self):
        # Generic ranking showed a +3 dBm peer: 2 dB under the generic
        # ceiling looked worse than 2.5 dB above the generic floor.
        stats, _anomalies, _action = self.grade(
            cmis([3.0, 3.0, -8.5, 3.0, 3.0, 3.0, 3.0, 3.0]))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (3, -8.5))

    def test_lane_under_the_module_low_warning_is_displayed(self):
        for peers in (2.0, 3.0):
            with self.subTest(peers=peers):
                stats, _anomalies, _action = self.grade(
                    cmis(with_lane([peers] * 8, 6, -7.6)))
                self.assertEqual(stats["health_status"], "warning")
                self.assertEqual(
                    (stats["rx_power_lane"], stats["rx_power_dbm"]), (6, -7.6))

    def test_tx_lane_beyond_a_module_limit_is_displayed(self):
        for value, expected in ((-6.0, "critical"), (-4.2, "warning"),
                                (5.4, "warning"), (6.3, "critical")):
            with self.subTest(tx=value):
                stats, _anomalies, _action = self.grade(
                    cmis(tx=with_lane([1.5] * 8, 7, value)))
                self.assertEqual(stats["health_status"], expected)
                self.assertEqual(
                    (stats["tx_power_lane"], stats["tx_power_dbm"]), (7, value))

    def test_lane_that_makes_the_port_good_is_displayed(self):
        # Low margin band; the other lanes sit closer to the high warning.
        stats, _anomalies, _action = self.grade(
            cmis(with_lane([3.5] * 8, 4, -2.5)))
        self.assertEqual(stats["health_status"], "good")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (4, -2.5))
        stats, _anomalies, _action = self.grade(
            cmis(tx=with_lane([1.5] * 8, 2, 4.3)))
        self.assertEqual(stats["health_status"], "good")
        self.assertEqual((stats["tx_power_lane"], stats["tx_power_dbm"]),
                         (2, 4.3))

    def test_lane_under_the_margin_is_displayed(self):
        stats, _anomalies, _action = self.grade(
            cmis(with_lane([4.0] * 8, 8, -5.6)))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (8, -5.6))

    def test_lane_beyond_a_limit_of_a_partial_table_is_displayed(self):
        # High side unset: the generic rules stay and rank a +3 dBm peer
        # first, but the low alarm the module does print makes the badge.
        partial = dict(TWIN, rx_power=limits(UNSET, UNSET, -7.4, -8.4))
        stats, anomalies, _action = self.grade(
            cmis([3.0, 3.0, -8.5, 3.0, 3.0, 3.0, 3.0, 3.0], tables=partial))
        self.assertEqual(stats["module_limits"]["decided"],
                         ["tx_power", "temperature", "voltage"])
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (3, -8.5))
        self.assertEqual(self.messages(anomalies), [
            "RX power -8.50 dBm on lane 3 is below the module's low alarm "
            "-8.40 dBm"])
        # Generic margin: the table is not complete.
        self.assertAlmostEqual(stats["link_margin_db"], 5.5)


class InvalidAndPartialTableTests(ModuleLimitTestCase):
    INVALID = {
        "rx_power": (
            limits(6.5, 5.5, -8.4, -7.4),          # low alarm above warning
            limits(-9.0, -9.5, -7.4, -8.4),        # high side under the low
            limits("nan mW / nan dBm", 5.5, -8.4, -7.4),
        ),
        "tx_power": (
            limits(5.0, 6.0, -3.9, -4.9),          # warning above the alarm
            limits(-5.0, -5.5, -3.9, -4.9),
        ),
        "temperature": (
            limits(0.0, 0.0, 0.0, 0.0),            # table not programmed
            limits(70.0, 80.0, 0.0, -10.0),
            limits(-20.0, -30.0, 0.0, -10.0),
        ),
        "voltage": (
            limits(0.0, 0.0, 0.0, 0.0),
            limits(3.465, 3.5, 3.135, 3.1),
            limits(3.0, 2.9, 3.135, 3.1),
        ),
    }

    def test_an_invalid_table_falls_back_for_its_metric_only(self):
        for metric, tables in self.INVALID.items():
            for index, table in enumerate(tables):
                with self.subTest(metric=metric, table=index):
                    dump = cmis(temperature=60.06,
                                tables=dict(TWIN, **{metric: table}))
                    stats, _anomalies, _action = self.grade(dump)
                    module = stats["module_limits"]
                    self.assertNotIn(metric, module["thresholds"])
                    self.assertEqual(
                        module["decided"],
                        [name for name in ("rx_power", "tx_power",
                                           "temperature", "voltage")
                         if name != metric])
                    # 60.06 C is the generic "near its limit" warning only
                    # when temperature is the metric that fell back.
                    self.assertEqual(
                        stats["health_status"],
                        "warning" if metric == "temperature" else "excellent")

    def test_generic_rules_grade_the_metric_that_fell_back(self):
        bad_tx = dict(TWIN, tx_power=self.INVALID["tx_power"][0])
        stats, anomalies, _action = self.grade(
            cmis(tx=with_lane(HEALTHY_TX, 2, 4.1), tables=bad_tx))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(anomalies),
                         ["TX power out of range: 4.10 dBm"])
        bad_rx = dict(TWIN, rx_power=self.INVALID["rx_power"][0])
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -9.0), tables=bad_rx))
        # As today: 5 dB above the generic -14 dBm floor.
        self.assertEqual(stats["health_status"], "good")
        self.assertAlmostEqual(stats["link_margin_db"], 5.0)
        self.assertEqual(anomalies, [])
        bad_voltage = dict(TWIN, voltage=self.INVALID["voltage"][0])
        self.assertEqual(
            self.health(cmis(voltage=2.95, tables=bad_voltage)), "critical")

    def test_some_tables_valid_some_absent(self):
        tables = {name: TWIN[name] for name in ("bias", "rx_power", "tx_power")}
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -7.9), temperature=72.0,
                 tables=tables))
        self.assertEqual(stats["module_limits"]["decided"],
                         ["rx_power", "tx_power"])
        # Temperature has no table: the generic 70 C maximum decides.
        self.assertEqual(stats["health_status"], "critical")
        self.assertIn("SFP temperature too high: 72.0°C (threshold: 70.0°C)",
                      self.messages(anomalies))
        self.assertIn(
            "RX power -7.90 dBm on lane 2 is below the module's low warning "
            "-7.40 dBm", self.messages(anomalies))
        stats, anomalies, _action = self.grade(
            cmis(temperature=60.06, tables=tables))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(anomalies), [
            "An optical power or temperature value is near its limit"])

    def test_a_partial_table_keeps_the_generic_rules(self):
        # Low side left unset by the module (0 mW / -inf dBm).
        partial = dict(TWIN, rx_power=limits(6.5, 5.5, UNSET, UNSET))
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, -9.0), tables=partial))
        module = stats["module_limits"]
        self.assertEqual(module["thresholds"]["rx_power"],
                         {"high_alarm": 6.5, "high_warning": 5.5})
        self.assertNotIn("rx_power", module["decided"])
        self.assertEqual(stats["health_status"], "good")
        self.assertAlmostEqual(stats["link_margin_db"], 5.0)
        self.assertEqual(anomalies, [])
        # The generic +5 dBm warning stays although the module warns at 5.5.
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, 5.2), tables=partial))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(anomalies), [
            "An optical power or temperature value is near its limit"])

    def test_a_limit_of_a_partial_table_can_still_prove_a_fault(self):
        # Like the bias table: 6.8 dBm is a generic warning, and beyond the
        # high alarm the module does print.
        partial = dict(TWIN, rx_power=limits(6.5, 5.5, UNSET, UNSET))
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 2, 6.8), tables=partial))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(anomalies), [
            "RX power 6.80 dBm on lane 2 is above the module's high alarm "
            "6.50 dBm"])
        only_alarm = dict(TWIN, temperature={"high_alarm": 68.0})
        stats, anomalies, _action = self.grade(
            cmis(temperature=69.0, tables=only_alarm))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(self.messages(anomalies), [
            "Module temperature 69.00°C is above the module's high alarm "
            "68.00°C"])


class LaneSelectionTests(ModuleLimitTestCase):
    def test_lanes_out_of_service_are_not_graded_by_module_limits(self):
        # Eight channels printed, four equipped: 5-8 are exact zeros.
        rx = [2.0, 2.1, 2.2, 2.3, None, None, None, None]
        tx = [1.5, 1.6, 1.7, 1.8, None, None, None, None]
        stats, anomalies, _action = self.grade(
            cmis(rx, tx, bias=[212.7] * 4 + [0.0] * 4,
                 tables=dict(TWIN, bias=None)))
        self.assertEqual(stats["inactive_lanes"], [5, 6, 7, 8])
        self.assertEqual(stats["health_status"], "excellent")
        self.assertEqual(anomalies, [])

    def test_a_driven_lane_without_light_stays_critical(self):
        stats, anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 3, None)))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["rx_power_lane"], 3)
        self.assertEqual(self.messages(anomalies), [
            "RX power -40.00 dBm on lane 3 is below the module's low alarm "
            "-8.40 dBm"])

    def test_a_dark_lane_is_critical_under_any_module_low_alarm(self):
        deep = dict(TWIN, rx_power=limits(6.5, 5.5, -34.0, -40.0))
        stats, _anomalies, _action = self.grade(
            cmis(with_lane(HEALTHY_RX, 3, None), tables=deep))
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["rx_power_lane"], 3)

    def test_no_light_at_all_is_down_not_a_module_alarm(self):
        stats, anomalies, _action = self.grade(cmis([None] * 8))
        self.assertEqual(stats["health_status"], "down")
        self.assertEqual([item["type"] for item in anomalies],
                         ["OPTICAL_LINK_DOWN"])

    def test_module_warning_without_power_readings(self):
        dump = "\n".join([
            line("Identifier", "0x03 (SFP)"),
            line("Module temperature", celsius(72.0)),
            line("Module voltage", volts(3.3)),
        ] + threshold_lines({"temperature": TWIN["temperature"]})) + "\n"
        stats, anomalies, _action = self.grade(dump)
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(self.messages(anomalies), [
            "Module temperature 72.00°C is above the module's high warning "
            "70.00°C"])
        # In range there is still no optical path to call healthy.
        self.assertEqual(self.health(dump.replace("72.00 degrees C",
                                                  "45.00 degrees C")),
                         "unknown")


class RowActionTests(ModuleLimitTestCase):
    def test_action_follows_the_limit_that_decided(self):
        # 72 C is inside the module's limits; the TX alarm is the fault.
        _stats, _anomalies, action = self.grade(
            cmis(tx=with_lane(HEALTHY_TX, 2, 6.3), temperature=72.0))
        self.assertEqual(action,
                         "Investigate critical optical parameters immediately")
        _stats, _anomalies, action = self.grade(cmis(temperature=81.0))
        self.assertEqual(action,
                         "Check cooling, reduce load, or replace SFP module")


class BreakoutSubPortTests(unittest.TestCase):
    """Rows of a split cage, through the per-device worker path."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "optical-data").mkdir()
        self.analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        patcher = mock.patch.object(
            optical, "_parse_worker_analyzer", self.analyzer)
        patcher.start()
        self.addCleanup(patcher.stop)

    def classify(self, blocks, hostname="leaf1"):
        sample = self.root / "optical-data" / f"{hostname}_optical.txt"
        sample.write_text(device_file(blocks))
        ops, _failures, shard_error = optical._classify_optical_file(
            str(sample), hostname)
        self.assertIsNone(shard_error)
        return {op[1].split(":", 1)[1]: op[2]
                for op in ops if op[0] == "update"}

    def test_each_sub_port_is_graded_on_its_own_channels(self):
        # Twin-port module split in two: s0 owns 1-4, s1 owns 5-8.
        dump = cmis(with_lane(HEALTHY_RX, 6, -9.0),
                    with_lane(HEALTHY_TX, 2, -4.2), temperature=60.06)
        rows = self.classify([("swp1s0", "up", dump), ("swp1s1", "up", dump)])
        first, second = rows["swp1s0"], rows["swp1s1"]
        self.assertEqual(first["rx_power_lane_ids"], [1, 2, 3, 4])
        self.assertEqual(second["rx_power_lane_ids"], [5, 6, 7, 8])
        # The RX alarm belongs to s1 and names its channel ...
        self.assertEqual(second["health_status"], "critical")
        self.assertEqual((second["rx_power_lane"], second["rx_power_dbm"]),
                         (6, -9.0))
        self.assertEqual(
            [(event["metric"], event["lane"], event["kind"])
             for event in second["module_limits"]["events"]],
            [("rx_power", 6, "alarm")])
        # ... and the TX warning to s0, which keeps its own margin.
        self.assertEqual(first["health_status"], "warning")
        self.assertEqual((first["tx_power_lane"], first["tx_power_dbm"]),
                         (2, -4.2))
        self.assertEqual(
            [(event["metric"], event["lane"], event["kind"])
             for event in first["module_limits"]["events"]],
            [("tx_power", 2, "warning")])
        self.assertAlmostEqual(first["link_margin_db"], 1.04 + 8.4)
        self.assertAlmostEqual(second["link_margin_db"], -9.0 + 8.4)
        # The module's table grades both rows.
        for row in (first, second):
            self.assertEqual(row["module_limits"]["thresholds"], PARSED_TWIN)
            self.assertEqual(
                row["module_limits"]["decided"],
                ["rx_power", "tx_power", "temperature", "voltage"])

    def test_healthy_split_module_is_healthy_on_every_row(self):
        dump = cmis(temperature=60.06)
        rows = self.classify([("swp1s0", "up", dump), ("swp1s1", "up", dump)])
        self.assertEqual(
            {name: row["health_status"] for name, row in rows.items()},
            {"swp1s0": "excellent", "swp1s1": "excellent"})

    def test_module_limits_stay_out_of_the_shard(self):
        dump = cmis(with_lane(HEALTHY_RX, 6, -9.0))
        self.classify([("swp1s0", "up", dump), ("swp1s1", "up", dump)])
        shard = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text())
        self.assertEqual(sorted(shard["current"]),
                         ["leaf1:swp1s0", "leaf1:swp1s1"])
        for stats in shard["current"].values():
            self.assertNotIn("module_limits", stats)
            self.assertFalse(SIDECAR_ONLY_STAT_KEYS & set(stats))
        self.assertEqual(shard["current"]["leaf1:swp1s1"]["health_status"],
                         "critical")
        for entry in shard["history"]["leaf1:swp1s1"]:
            self.assertEqual(sorted(entry), sorted([
                "timestamp", "health", "rx_power_dbm", "tx_power_dbm",
                "temperature_c", "link_margin_db", "link_margin_ref_dbm",
                "rx_power_lane", "tx_power_lane", "bias_current_lane",
                "rx_power_lane_ids"]))


class ReportTests(ModuleLimitTestCase):
    EXPORT_COLUMNS = [
        "device", "interface", "health", "rx_power_dbm", "tx_power_dbm",
        "temperature_c", "link_margin_db", "voltage_v", "bias_current_ma",
        "rx_lanes", "tx_lanes", "bias_lanes", "inactive_lanes", "anomalies",
        # Lane identities, appended by the breakout export fix (C7).
        "rx_lane_ids", "tx_lane_ids", "bias_lane_ids",
        "rx_power_lane", "tx_power_lane", "bias_current_lane",
    ]

    def export(self, ports):
        for port, dump in ports.items():
            self.assertTrue(self.analyzer.update_optical_stats(port, dump))
        output = self.root / "optical-analysis.html"
        self.analyzer.export_optical_data_for_web(str(output))
        details = json.loads(
            (self.root / "optical-details" / "leaf1.json").read_text())
        return output.read_text(), details["ports"]

    def test_detail_sidecar_names_the_limits_that_decided(self):
        _page, ports = self.export({
            "leaf1:swp1": cmis(with_lane(HEALTHY_RX, 3, -9.0)),
            "leaf1:swp2": cmis(tables=None),
        })
        module = ports["leaf1:swp1"]["module_limits"]
        self.assertEqual(module["thresholds"], PARSED_TWIN)
        self.assertEqual(module["decided"],
                         ["rx_power", "tx_power", "temperature", "voltage"])
        self.assertEqual(module["events"], [{
            "metric": "rx_power", "lane": 3, "value": -9.0,
            "threshold": -8.4, "direction": "low", "kind": "alarm",
            "severity": "critical"}])
        self.assertEqual(
            [item["message"] for item in ports["leaf1:swp1"]["anomalies"]],
            ["RX power -9.00 dBm on lane 3 is below the module's low alarm "
             "-8.40 dBm"])
        self.assertEqual(ports["leaf1:swp2"]["module_limits"],
                         {"thresholds": {}, "decided": [], "events": []})

    def test_export_columns_are_the_published_schema(self):
        self.assertTrue(self.analyzer.update_optical_stats(
            "leaf1:swp1", cmis(with_lane(HEALTHY_RX, 3, -9.0))))
        rows = self.analyzer.build_export_rows(
            self.analyzer.get_optical_summary(),
            self.analyzer.detect_optical_anomalies())
        self.assertEqual(list(rows[0]), self.EXPORT_COLUMNS)
        self.assertEqual(
            rows[0]["anomalies"],
            "CRITICAL: RX power -9.00 dBm on lane 3 is below the module's "
            "low alarm -8.40 dBm")
        self.assertIn("module_limits", SIDECAR_ONLY_STAT_KEYS)

    def test_legend_describes_the_module_rule(self):
        page, _ports = self.export({"leaf1:swp1": cmis()})
        self.assertNotIn("until module-specific limits are collected", page)
        legend = page[page.index("Optical Health Thresholds"):]
        legend = legend[:legend.index("</table>")]
        self.assertIn(
            "graded by the limits the module prints for itself", legend)
        self.assertIn("beyond an alarm limit is Critical", legend)
        self.assertIn("beyond a warning limit is Warning", legend)
        self.assertIn("Counted from the module's RX power low alarm", legend)
        self.assertIn("otherwise from the generic -14.0 dBm RX sensitivity",
                      legend)
        for fallback in ("used when the module prints no valid RX power table",
                         "used when the module prints no valid TX power table",
                         "used when the module prints no valid temperature table",
                         "used when the module prints no valid voltage table"):
            self.assertIn(fallback, legend)

    @unittest.skipUnless(shutil.which("node"), "Node.js runs the page script")
    def test_detail_panel_says_which_limits_graded_the_port(self):
        partial = dict(TWIN, rx_power=limits(6.5, 5.5, UNSET, UNSET),
                       temperature=None)
        page, ports = self.export({
            "leaf1:swp1": cmis(with_lane(HEALTHY_RX, 3, -9.0)),
            "leaf1:swp2": cmis(tables=partial),
        })
        panels = {name: self.render_panel(page, name, data)
                  for name, data in ports.items()}
        first = panels["leaf1:swp1"]
        self.assertIn("RX power -9.00 dBm on lane 3 is below the module's low "
                      "alarm -8.40 dBm", first)
        self.assertIn("Limits used for grading:", first)
        self.assertIn(
            "RX power: module limits: low alarm -8.40 dBm, low warning "
            "-7.40 dBm, high warning 5.50 dBm, high alarm 6.50 dBm<br>", first)
        self.assertIn(
            "TX power: module limits: low alarm -4.90 dBm, low warning "
            "-3.90 dBm, high warning 5.00 dBm, high alarm 6.00 dBm<br>", first)
        self.assertIn(
            "Temperature: module limits: low alarm -10.00 C, low warning "
            "0.00 C, high warning 70.00 C, high alarm 80.00 C<br>", first)
        self.assertIn(
            "Voltage: module limits: low alarm 3.1000 V, low warning "
            "3.1350 V, high warning 3.4650 V, high alarm 3.5000 V<br>", first)
        second = panels["leaf1:swp2"]
        self.assertIn(
            "RX power: generic limits; the module prints only high warning "
            "5.50 dBm, high alarm 6.50 dBm, which can still raise an alarm<br>",
            second)
        self.assertIn(
            "Temperature: generic limits (the module prints no valid table)<br>",
            second)
        self.assertIn("TX power: module limits: ", second)

    def test_detail_panel_of_a_row_without_readings_lists_no_limits(self):
        if not shutil.which("node"):
            self.skipTest("Node.js runs the page script")
        page, _ports = self.export({"leaf1:swp1": cmis()})
        panel = self.render_panel(page, "leaf1:swp9", {"health": "unplugged"})
        self.assertNotIn("Limits used for grading", panel)

    @staticmethod
    def page_function(page, name):
        start = page.index(f"function {name}(")
        depth = 0
        for index in range(page.index("{", start), len(page)):
            if page[index] == "{":
                depth += 1
            elif page[index] == "}":
                depth -= 1
                if depth == 0:
                    return page[start:index + 1]
        raise AssertionError(f"{name} is not closed")

    def render_panel(self, page, port, data):
        script = "\n".join(
            self.page_function(page, name)
            for name in ("esc", "laneText", "renderDetailPanel")
        ) + """
const data = JSON.parse(require('fs').readFileSync(0, 'utf8'));
let rendered = '';
const document = { createElement: () => ({}) };
const row = {
    dataset: { port: data.port },
    classList: { add() {} },
    after(detail) { rendered = detail.innerHTML; },
};
renderDetailPanel(row, data.detail);
process.stdout.write(rendered);
"""
        result = subprocess.run(
            ["node", "-e", script],
            input=json.dumps({"port": port, "detail": data}),
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout


class GenericPathUnchangedTests(ModuleLimitTestCase):
    """A dump that prints no such table is graded exactly as before."""

    def test_generic_grading_of_a_dump_without_tables(self):
        cases = (
            # RX lane 2, health, link margin, anomaly messages, action
            ({"rx": -9.0}, "good", 5.0, [], "Continue regular monitoring"),
            ({"rx": -7.9}, "excellent", 6.1, [], ""),
            ({"rx": -11.01}, "warning", 2.99,
             ["Low link margin: 2.99 dB (threshold: 3.0 dB)"],
             "Monitor closely, schedule proactive maintenance"),
            ({"rx": -14.01}, "critical", -0.01,
             ["RX power too low: -14.01 dBm (threshold: -14.0 dBm)"],
             "Check fiber connection, clean connectors, or replace cable"),
            ({"rx": 5.2}, "warning", 15.04,
             ["An optical power or temperature value is near its limit"],
             "Monitor optical parameters regularly"),
            # The texts of the three generic critical conditions that only
            # had the catch-all sentence now name value and limit; grading
            # and action are as before.
            ({"rx": 7.2}, "critical", 15.04,
             ["RX power too high: 7.20 dBm (threshold: 7.0 dBm)"],
             "Investigate critical optical parameters immediately"),
            ({"tx": -6.0}, "excellent", 15.04, [], ""),
            ({"tx": 3.2}, "warning", 15.04,
             ["An optical power or temperature value is near its limit"],
             "Monitor optical parameters regularly"),
            ({"tx": 4.1}, "critical", 15.04,
             ["TX power out of range: 4.10 dBm"],
             "Investigate critical optical parameters immediately"),
            ({"temperature": 60.06}, "warning", 15.04,
             ["An optical power or temperature value is near its limit"],
             "Monitor optical parameters regularly"),
            ({"temperature": 70.5}, "critical", 15.04,
             ["SFP temperature too high: 70.5°C (threshold: 70.0°C)"],
             "Check cooling, reduce load, or replace SFP module"),
            ({"voltage": 3.55}, "good", 15.04, [],
             "Continue regular monitoring"),
            ({"voltage": 2.95}, "critical", 15.04,
             ["Module voltage out of range: 2.9500 V (limits: 3.0 to 3.6 V)"],
             "Investigate critical optical parameters immediately"),
            ({"temperature": -0.5}, "critical", 15.04,
             ["SFP temperature too low: -0.5°C (threshold: 0.0°C)"],
             "Investigate critical optical parameters immediately"),
        )
        for change, health, margin, messages, expected_action in cases:
            with self.subTest(change=change):
                arguments = {"tables": None}
                if "rx" in change:
                    arguments["rx"] = with_lane(HEALTHY_RX, 2, change["rx"])
                if "tx" in change:
                    arguments["tx"] = with_lane(HEALTHY_TX, 2, change["tx"])
                for key in ("temperature", "voltage"):
                    if key in change:
                        arguments[key] = change[key]
                stats, anomalies, action = self.grade(cmis(**arguments))
                self.assertEqual(stats["health_status"], health)
                self.assertAlmostEqual(stats["link_margin_db"], margin)
                self.assertEqual(self.messages(anomalies), messages)
                self.assertEqual(action, expected_action)
                self.assertEqual(
                    stats["module_limits"],
                    {"thresholds": {}, "decided": [], "events": []})

    def test_generic_displayed_lane_of_a_dump_without_tables(self):
        # Unchanged, including the ranking that shows a healthy peer while a
        # lane sags inside the generic window.
        stats, _anomalies, _action = self.grade(
            cmis([3.0, 3.0, -8.5, 3.0, 3.0, 3.0, 3.0, 3.0], tables=None))
        self.assertEqual(stats["health_status"], "good")
        self.assertEqual((stats["rx_power_lane"], stats["rx_power_dbm"]),
                         (1, 3.0))
        self.assertAlmostEqual(stats["link_margin_db"], 5.5)

    def test_bias_only_tables_leave_the_other_metrics_generic(self):
        stats, _anomalies, _action = self.grade(
            cmis(temperature=60.06, tables={"bias": TWIN["bias"]}))
        self.assertEqual(stats["health_status"], "warning")
        self.assertEqual(stats["bias_assessment"]["status"], "normal")
        self.assertEqual(stats["module_limits"]["decided"], [])


class MarginConfigurationTests(unittest.TestCase):
    """_load_network_thresholds against a notifications.yaml of its own."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # The analyzer reads notifications.yaml next to its own file first.
        shutil.copy(SCRIPT_DIR / "optical_analyzer.py", self.root)
        spec = importlib.util.spec_from_file_location(
            "test_audit_opt1_analyzer_copy", self.root / "optical_analyzer.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        (self.root / "results").mkdir()

    def build(self, config):
        (self.root / "notifications.yaml").write_text(config)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            analyzer = self.module.OpticalAnalyzer(
                str(self.root / "results"), load_history=False)
        return analyzer.thresholds["link_margin_min_db"], output.getvalue()

    def test_null_or_non_mapping_sections_keep_the_default(self):
        for config in (
                "thresholds:\n  network:\n",          # every key commented out
                "thresholds:\n",
                "thresholds:\n  network: 5\n",
                "thresholds: [1, 2]\n",
                "thresholds:\n  network:\n    - optical_power_margin\n",
                "- thresholds\n- network\n",
                "just text\n",
                ""):
            with self.subTest(config=config):
                self.assertEqual(self.build(config), (3.0, ""))

    def test_configured_margin_is_used(self):
        for text, expected in (("5", 5.0), ("0", 0.0), ("2.5", 2.5),
                               ("'4'", 4.0)):
            with self.subTest(value=text):
                config = ("thresholds:\n  network:\n"
                          f"    optical_power_margin: {text}\n")
                self.assertEqual(self.build(config), (expected, ""))

    def test_ignored_margin_keeps_the_default_and_is_logged_once(self):
        for text in ("-10", "'3 dB'", ".nan", ".inf", "[3]"):
            with self.subTest(value=text):
                self.module._REPORTED_IGNORED_MARGINS.clear()
                config = ("thresholds:\n  network:\n"
                          f"    optical_power_margin: {text}\n")
                margin, output = self.build(config)
                self.assertEqual(margin, 3.0)
                self.assertEqual(len(output.splitlines()), 1, output)
                self.assertIn("optical_power_margin", output)
                self.assertIn("notifications.yaml", output)
                self.assertIn("Using 3.0 dB", output)
                # The parent, its workers' analyzers and the migration all
                # read the same file: one line per run.
                self.assertEqual(self.build(config), (3.0, ""))

    def test_parse_workers_do_not_repeat_the_message(self):
        config = "thresholds:\n  network:\n    optical_power_margin: -10\n"
        with mock.patch.object(self.module.multiprocessing, "parent_process",
                               return_value=object()):
            self.assertEqual(self.build(config), (3.0, ""))

    def test_margin_from_the_file_grades_a_module_limited_port(self):
        (self.root / "notifications.yaml").write_text(
            "thresholds:\n  network:\n    optical_power_margin: 0\n")
        analyzer = self.module.OpticalAnalyzer(
            str(self.root / "results"), load_history=False)
        self.assertTrue(analyzer.update_optical_stats(
            "leaf1:swp1", cmis(with_lane(HEALTHY_RX, 2, -7.0))))
        self.assertEqual(
            analyzer.current_optical_stats["leaf1:swp1"]["health_status"],
            "good")


SETUP_SPEC = importlib.util.spec_from_file_location(
    "test_audit_opt1_setup_safety", ROOT / "html" / "setup_safety.py")
SETUP = importlib.util.module_from_spec(SETUP_SPEC)
SETUP_SPEC.loader.exec_module(SETUP)


def notifications_payload(optical):
    return {
        "enabled": False, "server_url": "", "slack_enabled": False,
        "webhook": "", "channel": "#lldpq", "mode": "summary",
        "min_interval": "30",
        "t_hardware": True, "t_network": True, "t_system": True,
        "t_topology": True, "t_log": True,
        "thresholds": {"bgp": "5", "flap_warn": "10", "flap_crit": "20",
                       "optical": optical, "cpu": "85", "asic": "105",
                       "disk": "95"},
    }


class SetupOpticalMarginTests(unittest.TestCase):
    EXISTING = (SCRIPT_DIR / "notifications.yaml").read_text()

    def test_setup_refuses_a_margin_outside_0_to_30(self):
        for value in ("-10", "-0.5", -3, "30.5", "31", 100):
            with self.subTest(value=value):
                with self.assertRaises(SETUP.SetupSafetyError) as raised:
                    SETUP.render_notifications(
                        self.EXISTING, notifications_payload(value))
                self.assertEqual(
                    str(raised.exception),
                    "thresholds.optical must be between 0 and 30")

    def test_setup_stores_a_margin_from_0_to_30(self):
        import yaml
        for value, expected in (("0", 0), ("3", 3), ("2.5", 2.5), (30, 30)):
            with self.subTest(value=value):
                rendered = SETUP.render_notifications(
                    self.EXISTING, notifications_payload(value))
                network = yaml.safe_load(rendered)["thresholds"]["network"]
                self.assertEqual(network["optical_power_margin"], expected)

    def test_setup_field_is_labelled_in_db_and_bounded(self):
        page = (ROOT / "html" / "setup.html").read_text()
        field = re.search(
            r'<label[^>]*>([^<]*)<input[^>]*id="thr-optical"[^>]*>', page)
        self.assertIsNotNone(field)
        self.assertEqual(field.group(1), "Optical margin (dB)")
        self.assertIn('min="0"', field.group(0))
        self.assertIn('max="30"', field.group(0))

    def test_shipped_configuration_names_the_unit(self):
        entry = next(text for text in self.EXISTING.splitlines()
                     if text.strip().startswith("optical_power_margin:"))
        comment = entry.split("#", 1)[1]
        self.assertEqual(comment.split(" - ")[0].strip(), "dB")


if __name__ == "__main__":
    unittest.main()
