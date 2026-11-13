#!/usr/bin/env python3
"""A breakout sub-port is graded on the module channels it owns.

``ethtool -m`` on a breakout sub-interface returns the DOM of the whole
module, identical for every sibling.  Keeping only channel M+1 for swpNsM is
right only when every sub-port owns one lane: a twin-port 2x400G module split
2x gives channels 1-4 to s0 and 5-8 to s1, yet the page showed channel 1 for
s0, channel 2 (a lane of s0) for s1, and graded channels 3-8 on no row.

The block size is told from the cage: its sub-ports share the module's
channels equally and in order, and a link-up sub-port's channels must be in
service.  All module values below are invented.
"""

from __future__ import annotations

import contextlib
import io
import itertools
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
from optical_analyzer import OpticalAnalyzer


ABSENT = object()            # the dump prints no line for this value
UNLIT = "0.0000 mW / -inf dBm"
OSFP = "0x19 (OSFP 8X Pluggable Transceiver)"
QSFP_DD = "0x18 (QSFP-DD Double Density 8X Pluggable Transceiver)"
QSFP28 = "0x11 (QSFP28)"
HEALTHY = ("good", "excellent")
BIAS_KINDS = ("high_alarm", "low_alarm", "high_warning", "low_warning")


def power(dbm):
    return UNLIT if dbm is None else f"{10 ** (dbm / 10):.4f} mW / {dbm:.2f} dBm"


def module(channels, *, identifier=OSFP, flags=None, media=None):
    """One ``ethtool -m`` dump.

    channels: {channel: (rx dBm, tx dBm, bias mA)}; None is an unlit power
    reading (0 mW / -inf dBm), ABSENT leaves the line out.
    """
    lines = [f"Identifier : {identifier}"]
    if media:
        lines.append(f"Transceiver type : {media}")
    lines += [
        "Vendor name : ACME",
        "Module temperature : 43.18 degrees C / 109.72 degrees F",
        "Module voltage : 3.2703 V",
    ]
    for channel, (rx, tx, bias) in sorted(channels.items()):
        if bias is not ABSENT:
            lines.append(
                f"Laser tx bias current (Channel {channel}) : {bias:.3f} mA")
        if tx is not ABSENT:
            lines.append(
                f"Transmit avg optical power (Channel {channel}) : {power(tx)}")
        if rx is not ABSENT:
            lines.append(
                f"Rcvr signal avg optical power (Channel {channel}) : {power(rx)}")
    for (channel, kind), on in (flags or {}).items():
        lines.append(f"Laser bias current {kind.replace('_', ' ')} "
                     f"(Chan {channel}) : {'On' if on else 'Off'}")
    return "\n".join(lines) + "\n"


def lit(rx_values, first=1, bias=330.0):
    """Lit channels; every channel gets its own rx, tx and bias value."""
    return {channel: (rx, round(rx - 0.5, 2), bias + channel)
            for channel, rx in enumerate(rx_values, start=first)}


def placeholders(channels):
    """Channels the module prints but does not have: exact zeros."""
    return {channel: (None, None, 0.0) for channel in channels}


def device_file(blocks):
    """blocks: [(interface, operstate, block body)] in collector order.

    An operstate of None leaves the "Interface state" line out.
    """
    out = ["=== OPTICAL DIAGNOSTICS ==="]
    for interface, state, body in blocks:
        out.append(f"--- Interface: {interface}")
        if state is not None:
            out.append(f"Interface state: {state}")
        out.append(body.rstrip("\n"))
    return "\n".join(out) + "\n"


# Twin-port 2x400G module: eight media lanes, every channel distinct so a row
# that shows a sibling's lane is caught by its value.
TWIN_RX = [2.1, 2.2, 2.3, 2.4, 1.1, 1.2, 1.3, 1.4]
TWIN_PORT = lit(TWIN_RX)
# 400G-DR4 in a QSFP-DD cage: 8 host lanes, 4 media lanes.  The CMIS dump
# still prints eight channels; 5-8 are exact zeros.
DR4 = {**lit([2.1, 2.2, 2.3, 2.4], bias=60.0), **placeholders(range(5, 9))}
# SFF-8636 dump: four channels.
SR4 = lit([-1.0, -1.1, -1.2, -1.3], bias=6.0)
NO_DATA = "No transceiver data\n"


class BreakoutCageTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "optical-data").mkdir()
        optical._parse_worker_analyzer = OpticalAnalyzer(
            str(self.root), load_history=False
        )
        self.analyzer = optical._parse_worker_analyzer

    def classify_ops(self, blocks, hostname="leaf1"):
        sample = self.root / "optical-data" / f"{hostname}_optical.txt"
        sample.write_text(device_file(blocks))
        ops, failures, shard_error = optical._classify_optical_file(
            str(sample), hostname
        )
        self.assertIsNone(shard_error)
        return ops, failures

    def classify(self, blocks, hostname="leaf1"):
        """{interface: current stats} of the rows the device file produced."""
        ops, _failures = self.classify_ops(blocks, hostname)
        return {op[1].split(":", 1)[1]: op[2]
                for op in ops if op[0] == "update"}

    def assert_lanes(self, stats, expected):
        """expected: {interface: [channel, ...]} for rx, tx and bias alike."""
        for interface, channels in expected.items():
            for metric in ("rx_power", "tx_power", "bias_current"):
                self.assertEqual(
                    stats[interface][f"{metric}_lane_ids"], channels,
                    f"{interface} {metric}",
                )


class TwinPortSplitTests(BreakoutCageTestCase):
    """The reported case: 8 channels, two sub-ports, four channels each."""

    def both_up(self, channels=TWIN_PORT, **kwargs):
        dump = module(channels, **kwargs)
        return self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])

    def test_each_sub_port_owns_four_channels_for_every_metric(self):
        stats = self.both_up()
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})
        self.assertEqual(stats["swp6s0"]["rx_power_lanes_dbm"], TWIN_RX[:4])
        self.assertEqual(stats["swp6s1"]["rx_power_lanes_dbm"], TWIN_RX[4:])
        for interface in ("swp6s0", "swp6s1"):
            self.assertIn(stats[interface]["health_status"], HEALTHY)
            self.assertEqual(stats[interface]["inactive_lanes"], [])

    def test_the_displayed_lane_is_one_of_the_sub_ports_own(self):
        stats = self.both_up()
        # The brightest receive lane is the one nearest a limit.
        self.assertEqual(stats["swp6s0"]["rx_power_lane"], 4)
        self.assertEqual(stats["swp6s0"]["rx_power_dbm"], 2.4)
        self.assertEqual(stats["swp6s0"]["tx_power_lane"], 4)
        self.assertEqual(stats["swp6s0"]["bias_current_lane"], 4)
        self.assertEqual(stats["swp6s1"]["rx_power_lane"], 8)
        self.assertEqual(stats["swp6s1"]["rx_power_dbm"], 1.4)
        self.assertEqual(stats["swp6s1"]["tx_power_lane"], 8)
        self.assertEqual(stats["swp6s1"]["tx_power_dbm"], 0.9)
        self.assertEqual(stats["swp6s1"]["bias_current_lane"], 8)
        self.assertEqual(stats["swp6s1"]["bias_current_ma"], 338.0)

    def test_s1_no_longer_shows_channel_two(self):
        # Channel 2 belongs to s0; the page used to print it on the s1 row.
        stats = self.both_up()
        self.assertNotEqual(stats["swp6s1"]["rx_power_lane"], 2)
        self.assertNotEqual(stats["swp6s1"]["rx_power_dbm"], TWIN_RX[1])
        self.assertNotIn(2, stats["swp6s1"]["rx_power_lane_ids"])
        self.assertNotIn(2, stats["swp6s1"]["bias_current_lane_ids"])

    def test_a_fault_on_channel_six_is_reported_on_s1_only(self):
        faulty = dict(TWIN_PORT)
        faulty[6] = (-20.0, 0.7, 336.0)
        stats = self.both_up(faulty)
        self.assertIn(stats["swp6s0"]["health_status"], HEALTHY)
        self.assertEqual(stats["swp6s1"]["health_status"], "critical")
        self.assertEqual(stats["swp6s1"]["rx_power_lane"], 6)
        self.assertEqual(stats["swp6s1"]["rx_power_dbm"], -20.0)

    def test_a_fault_on_channel_two_is_reported_on_s0_only(self):
        faulty = dict(TWIN_PORT)
        faulty[2] = (-20.0, 1.7, 332.0)
        stats = self.both_up(faulty)
        self.assertEqual(stats["swp6s0"]["health_status"], "critical")
        self.assertEqual(stats["swp6s0"]["rx_power_lane"], 2)
        self.assertIn(stats["swp6s1"]["health_status"], HEALTHY)

    def test_a_dark_channel_is_a_fault_not_a_reason_to_shrink_the_block(self):
        # Channel 3 lost its receive light while both links stay up.  Every
        # live channel still has to be owned by someone, so s0 keeps four
        # channels and reports the dark one; one channel per sub-port would
        # have hidden it on no row at all.
        faulty = dict(TWIN_PORT)
        faulty[3] = (None, 1.8, 333.0)
        stats = self.both_up(faulty)
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})
        self.assertEqual(stats["swp6s0"]["health_status"], "critical")
        self.assertEqual(stats["swp6s0"]["rx_power_lane"], 3)
        self.assertEqual(stats["swp6s0"]["rx_power_dbm"], -40.0)
        self.assertIn(stats["swp6s1"]["health_status"], HEALTHY)

    def test_a_bias_alarm_flag_on_channel_six_lands_on_s1_only(self):
        flags = {(channel, kind): channel == 6 and kind == "high_alarm"
                 for channel in range(1, 9) for kind in BIAS_KINDS}
        stats = self.both_up(flags=flags)
        self.assertEqual(stats["swp6s0"]["bias_assessment"]["status"], "normal")
        self.assertIn(stats["swp6s0"]["health_status"], HEALTHY)
        self.assertEqual(stats["swp6s1"]["bias_assessment"]["status"], "critical")
        self.assertEqual(stats["swp6s1"]["health_status"], "critical")
        self.assertEqual(
            [event["lane"]
             for event in stats["swp6s1"]["bias_assessment"]["events"]], [6])
        self.assertEqual(stats["swp6s1"]["bias_current_lane"], 6)

    def test_a_down_sub_port_with_unlit_channels_still_owns_its_block(self):
        # s1 is admin down: its laser is off and channels 5-8 read zero.
        dump = module({**lit(TWIN_RX[:4]), **placeholders(range(5, 9))})
        stats = self.classify([("swp6s0", "up", dump),
                               ("swp6s1", "down", dump)])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})
        self.assertIn(stats["swp6s0"]["health_status"], HEALTHY)
        self.assertEqual(stats["swp6s1"]["health_status"], "down")

    def test_a_module_without_rx_monitoring_is_not_refuted_by_it(self):
        # Every channel reads 0 mW on the receive side: that is the module
        # not reporting rx power, not eight unplugged fibres.
        no_rx = {channel: (None, tx, bias)
                 for channel, (_rx, tx, bias) in TWIN_PORT.items()}
        stats = self.both_up(no_rx)
        self.assertEqual(stats["swp6s0"]["tx_power_lane_ids"], [1, 2, 3, 4])
        self.assertEqual(stats["swp6s1"]["tx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(stats["swp6s1"]["bias_current_lane_ids"], [5, 6, 7, 8])
        # With s1 shut (lasers off) only s0's four channels are alive; their
        # "dark" receivers must not argue for two channels per sub-port.
        dump = module({**{channel: no_rx[channel] for channel in range(1, 5)},
                       **placeholders(range(5, 9))})
        stats = self.classify([("swp6s0", "up", dump),
                               ("swp6s1", "down", dump)], hostname="leaf2")
        self.assertEqual(stats["swp6s0"]["tx_power_lane_ids"], [1, 2, 3, 4])
        self.assertEqual(stats["swp6s1"]["tx_power_lane_ids"], [5, 6, 7, 8])

    def test_a_module_without_tx_monitoring_is_not_refuted_by_it(self):
        # No transmit power and no bias current on any channel: the module
        # does not report its transmit side.  s1 is down without light.
        no_tx = {channel: (rx, None, 0.0)
                 for channel, (rx, _tx, _bias) in lit(TWIN_RX[:4]).items()}
        dump = module({**no_tx, **placeholders(range(5, 9))})
        stats = self.classify([("swp6s0", "up", dump),
                               ("swp6s1", "down", dump)])
        self.assertEqual(stats["swp6s0"]["rx_power_lane_ids"], [1, 2, 3, 4])
        self.assertEqual(stats["swp6s0"]["rx_power_lanes_dbm"], TWIN_RX[:4])
        self.assertEqual(stats["swp6s1"]["rx_power_lane_ids"], [5, 6, 7, 8])


class OtherSplitTests(BreakoutCageTestCase):
    def test_eight_channels_split_8x_give_one_channel_each(self):
        dump = module(TWIN_PORT)
        stats = self.classify(
            [(f"swp6s{index}", "up", dump) for index in range(8)])
        self.assert_lanes(stats, {f"swp6s{index}": [index + 1]
                                  for index in range(8)})
        self.assertEqual(stats["swp6s5"]["rx_power_dbm"], TWIN_RX[5])

    def test_eight_lit_channels_split_4x_give_two_channels_each(self):
        dump = module(TWIN_PORT)
        stats = self.classify(
            [(f"swp6s{index}", "up", dump) for index in range(4)])
        self.assert_lanes(stats, {"swp6s0": [1, 2], "swp6s1": [3, 4],
                                  "swp6s2": [5, 6], "swp6s3": [7, 8]})

    def test_four_media_lanes_in_an_eight_channel_dump_split_4x(self):
        # Host-lane arithmetic (8 cage lanes / 4 sub-ports = 2) is wrong for
        # this module: sub-port k sits on media lane k+1.
        dump = module(DR4, identifier=QSFP_DD)
        stats = self.classify(
            [(f"swp3s{index}", "up", dump) for index in range(4)])
        self.assert_lanes(stats, {f"swp3s{index}": [index + 1]
                                  for index in range(4)})
        for index in range(4):
            self.assertIn(stats[f"swp3s{index}"]["health_status"], HEALTHY)

    def test_four_media_lanes_split_4x_with_one_fibre_unplugged(self):
        # Only s0 is up; s1 lost its fibre, so channel 2 receives nothing
        # while its laser keeps running.  One link-up sub-port is enough to
        # rule out two channels per sub-port.
        channels = dict(DR4)
        channels[2] = (None, 1.7, 62.0)
        dump = module(channels, identifier=QSFP_DD)
        stats = self.classify(
            [("swp3s0", "up", dump)]
            + [(f"swp3s{index}", "down", dump) for index in (1, 2, 3)])
        self.assert_lanes(stats, {f"swp3s{index}": [index + 1]
                                  for index in range(4)})
        self.assertIn(stats["swp3s0"]["health_status"], HEALTHY)
        self.assertEqual(stats["swp3s1"]["health_status"], "down")

    def test_four_channel_dump_split_2x_gives_two_channels_each(self):
        dump = module(SR4, identifier=QSFP28)
        stats = self.classify([("swp9s0", "up", dump), ("swp9s1", "up", dump)])
        self.assert_lanes(stats, {"swp9s0": [1, 2], "swp9s1": [3, 4]})

    def test_four_channel_dump_split_4x_gives_one_channel_each(self):
        dump = module(SR4, identifier=QSFP28)
        stats = self.classify(
            [(f"swp9s{index}", "up", dump) for index in range(4)])
        self.assert_lanes(stats, {f"swp9s{index}": [index + 1]
                                  for index in range(4)})

    def test_channel_numbers_above_eight_are_shared_the_same_way(self):
        # A second CMIS bank: channels 9-16.
        sixteen = lit([round(1.0 + 0.1 * step, 1) for step in range(16)])
        dump = module(sixteen)
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assert_lanes(stats, {"swp6s0": list(range(1, 9)),
                                  "swp6s1": list(range(9, 17))})
        stats = self.classify(
            [(f"swp6s{index}", "up", dump) for index in range(8)],
            hostname="leaf2")
        self.assert_lanes(stats, {"swp6s0": [1, 2], "swp6s5": [11, 12],
                                  "swp6s7": [15, 16]})

    def test_thirty_two_channels_split_2x(self):
        thirty_two = lit([1.5] * 32)
        dump = module(thirty_two)
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assert_lanes(stats, {"swp6s0": list(range(1, 17)),
                                  "swp6s1": list(range(17, 33))})

    def test_the_plan_reads_the_lanes_as_collected(self):
        # A media string that declares a single optical lane reduces a
        # standalone sample to lane 1.  Four sub-ports sharing four lit
        # channels must still get one channel each, not lane 1 four times.
        dump = module(lit([2.1, 2.2, 2.3, 2.4], bias=60.0),
                      identifier=QSFP28, media="100G Base-DR")
        stats = self.classify(
            [(f"swp3s{index}", "up", dump) for index in range(4)])
        self.assert_lanes(stats, {f"swp3s{index}": [index + 1]
                                  for index in range(4)})

    def test_a_metric_without_a_reading_on_an_owned_channel_has_no_value(self):
        # The dump prints no bias current for channels 5-8.  s1 then has no
        # bias value at all; it must not borrow the bias of s0's channels.
        channels = dict(TWIN_PORT)
        for channel in range(5, 9):
            rx, tx, _bias = channels[channel]
            channels[channel] = (rx, tx, ABSENT)
        dump = module(channels)
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assertEqual(stats["swp6s1"]["rx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(stats["swp6s1"]["tx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(stats["swp6s1"]["bias_current_lane_ids"], [])
        self.assertEqual(stats["swp6s1"]["bias_current_lanes_ma"], [])
        self.assertIsNone(stats["swp6s1"]["bias_current_ma"])
        self.assertIsNone(stats["swp6s1"]["bias_current_lane"])
        self.assertEqual(stats["swp6s0"]["bias_current_lane_ids"], [1, 2, 3, 4])

    def test_six_printed_channels_split_2x_still_share_eight(self):
        # The channel count is rounded up to a power of two: four channels
        # per sub-port, of which the dump shows s1 only two.
        dump = module(lit(TWIN_RX[:6]))
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4], "swp6s1": [5, 6]})

    def test_operstate_is_compared_whatever_its_case(self):
        dump = module(DR4, identifier=QSFP_DD)
        stats = self.classify(
            [(f"swp3s{index}", "UP", dump) for index in range(4)])
        self.assert_lanes(stats, {f"swp3s{index}": [index + 1]
                                  for index in range(4)})


class CollectorShapeTests(BreakoutCageTestCase):
    def test_siblings_far_apart_in_the_file_are_planned_together(self):
        # Link-up ports are collected first, so a down sibling sits at the
        # end of the file with other ports in between.
        twin = module({**lit(TWIN_RX[:4]), **placeholders(range(5, 9))})
        single = module(lit([-1.5], bias=7.0), identifier=QSFP28)
        whole = module(SR4, identifier=QSFP28)
        stats = self.classify([
            ("swp6s0", "up", twin),
            ("swp7", "up", single),
            ("swp8", "up", whole),
            ("swp30", "down", NO_DATA),
            ("swp6s1", "down", twin),
        ])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8],
                                  "swp7": [1],
                                  "swp8": [1, 2, 3, 4]})

    def test_two_cages_in_one_file_are_planned_separately(self):
        twin = module(TWIN_PORT)
        four = module(SR4, identifier=QSFP28)
        stats = self.classify(
            [("swp6s0", "up", twin), ("swp6s1", "up", twin)]
            + [(f"swp7s{index}", "up", four) for index in range(4)])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8],
                                  "swp7s0": [1], "swp7s3": [4]})

    def test_a_sibling_without_lanes_still_counts_as_a_sub_port(self):
        # s2 returned no lanes, yet it makes this a four-way split: the two
        # sub-ports that answered own two channels each, not four.
        dump = module(TWIN_PORT)
        copper = ("Identifier : 0x11 (QSFP28)\n"
                  "Transceiver type : 100G Base-CR4\n"
                  "Vendor name : ACME\n")
        timeout = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp6s2\n" + NO_DATA
        silent = {
            "no transceiver data": ("down", NO_DATA),
            "collection error marker": ("up", timeout),
            "dac": ("up", copper),
            "too short": (None, "n/a"),
        }
        for number, (label, (state, body)) in enumerate(silent.items()):
            with self.subTest(label):
                ops, failures = self.classify_ops([
                    ("swp6s0", "up", dump),
                    ("swp6s1", "up", dump),
                    ("swp6s2", state, body),
                ], hostname=f"leaf{number}")
                stats = {op[1].split(":", 1)[1]: op[2]
                         for op in ops if op[0] == "update"}
                self.assertEqual(set(stats), {"swp6s0", "swp6s1"})
                self.assert_lanes(stats, {"swp6s0": [1, 2], "swp6s1": [3, 4]})
                if label == "collection error marker":
                    self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp6s2")])
                    self.assertIn(
                        ("state", f"leaf{number}:swp6s2", "unknown"),
                        [op[:3] for op in ops])

    def test_a_sibling_without_lanes_still_reports_its_link_state(self):
        # s0 answered with no lanes, but its link is up, and channel 2 is
        # dark in the dump of its siblings: s0 cannot own channels 1-2, so
        # this is one channel per sub-port.  Without s0's state nothing
        # would decide and the down sub-ports would get two channels each.
        dump = module({**DR4, 2: (None, 1.7, 62.0)}, identifier=QSFP_DD)
        copper = ("Identifier : 0x11 (QSFP28)\n"
                  "Transceiver type : 100G Base-CR4\n"
                  "Vendor name : ACME\n")
        timeout = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp3s0\n" + NO_DATA
        silent = {"failed read": timeout, "no transceiver data": NO_DATA,
                  "dac": copper}
        for number, (label, body) in enumerate(silent.items()):
            with self.subTest(label):
                stats = self.classify(
                    [("swp3s0", "up", body)]
                    + [(f"swp3s{index}", "down", dump) for index in (1, 2, 3)],
                    hostname=f"leaf{number}")
                self.assertEqual(set(stats), {"swp3s1", "swp3s2", "swp3s3"})
                self.assert_lanes(stats, {"swp3s1": [2], "swp3s2": [3],
                                          "swp3s3": [4]})

    def test_a_failed_read_contributes_no_lanes(self):
        # A read that timed out half way may leave a truncated or garbled
        # dump behind its marker.  It is not evidence about the module.
        dump = module(TWIN_PORT)
        garbled = module(lit([1.5] * 16))
        ops, failures = self.classify_ops([
            ("swp6s0", "up", dump),
            ("swp6s1", "up",
             "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp6s1\n" + garbled),
        ])
        self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp6s1")])
        stats = {op[1].split(":", 1)[1]: op[2]
                 for op in ops if op[0] == "update"}
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4]})
        self.assertIn(("state", "leaf1:swp6s1", "unknown"),
                      [op[:3] for op in ops])

    def test_a_flags_only_block_in_a_planned_cage_keeps_its_own_flags(self):
        # s1's dump carries alarm flags but no readings; the cage is planned
        # from s0.  Only the flags of channels 5-8 are s1's.
        for alarm_channel, expected in ((2, "normal"), (6, "critical")):
            with self.subTest(alarm_channel=alarm_channel):
                flags = {(channel, kind):
                         channel == alarm_channel and kind == "high_alarm"
                         for channel in range(1, 9) for kind in BIAS_KINDS}
                stats = self.classify([
                    ("swp6s0", "up", module(TWIN_PORT)),
                    ("swp6s1", "up", module({}, flags=flags)),
                ], hostname=f"leaf{alarm_channel}")
                self.assertEqual(
                    stats["swp6s1"]["bias_assessment"]["status"], expected)
                self.assertEqual(
                    [event["lane"] for event
                     in stats["swp6s1"]["bias_assessment"]["events"]],
                    [6] if expected == "critical" else [])

    def test_a_lone_s0_block_does_not_take_the_whole_module(self):
        stats = self.classify([("swp6s0", "up", module(TWIN_PORT))])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4]})

    def test_unfamiliar_channel_numbering_keeps_every_reading(self):
        # Neither channel falls in s0's block: nothing may be hidden.
        dump = module(lit([2.1, 2.2], first=11))
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assert_lanes(stats, {"swp6s0": [11, 12], "swp6s1": [11, 12]})

    def test_a_block_that_owns_nothing_keeps_its_flags_too(self):
        flags = {(channel, kind): channel == 12 and kind == "high_alarm"
                 for channel in (11, 12) for kind in BIAS_KINDS}
        dump = module(lit([2.1, 2.2], first=11), flags=flags)
        stats = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        for interface in ("swp6s0", "swp6s1"):
            self.assertEqual(
                stats[interface]["bias_assessment"]["status"], "critical")
            self.assertEqual(
                [event["lane"] for event
                 in stats[interface]["bias_assessment"]["events"]], [12])

    def test_a_sub_port_number_too_long_to_read_leaves_the_cage_unplanned(self):
        # No interface is named like this; a corrupted file can be.  A
        # sub-port number above the channel count leaves the cage without a
        # plan, and that must hold for a number Python refuses to convert
        # (more than 4300 digits) too: the file must not fail, and the
        # other ports of the device keep their rows.
        dump = module(TWIN_PORT)
        for number, digits in enumerate((30, 4000, 5000)):
            with self.subTest(digits=digits):
                stats = self.classify([
                    ("swp6s" + "9" * digits, "down", NO_DATA),
                    ("swp6s0", "up", dump),
                    ("swp6s1", "up", dump),
                    ("swp7s0", "up", dump),
                    ("swp7s1", "up", dump),
                    ("swp8", "up", dump),
                ], hostname=f"leaf{number}")
                self.assert_lanes(stats, {"swp6s0": [1], "swp6s1": [2],
                                          "swp7s0": [1, 2, 3, 4],
                                          "swp7s1": [5, 6, 7, 8],
                                          "swp8": list(range(1, 9))})

    def test_a_long_run_of_empty_lines_is_read_in_linear_time(self):
        # A failed read can leave anything behind its marker.  The state
        # line was searched for with a pattern that restarted on every one
        # of the empty lines: seconds for this block, where it is
        # milliseconds when each line is looked at once.
        failed = ("__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp6s0\n"
                  + "\n" * 60000 + NO_DATA)
        sample = self.root / "optical-data" / "leaf1_optical.txt"
        sample.write_text(device_file([("swp6s0", None, failed),
                                       ("swp6s1", "up", module(TWIN_PORT))]))
        started = time.process_time()
        ops, failures, _shard_error = optical._classify_optical_file(
            str(sample), "leaf1")
        self.assertLess(time.process_time() - started, 0.5)
        self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp6s0")])
        self.assertEqual([op[:3] for op in ops if op[0] == "state"],
                         [("state", "leaf1:swp6s0", "unknown")])

    def test_the_state_line_is_found_behind_empty_and_indented_lines(self):
        # ... and it is still found wherever it sits in the block.
        dump = module({**DR4, 2: (None, 1.7, 62.0)}, identifier=QSFP_DD)
        stats = self.classify(
            [("swp3s0", None, "\n\n \t Interface  State : UP\n" + NO_DATA)]
            + [(f"swp3s{index}", "down", dump) for index in (1, 2, 3)])
        self.assert_lanes(stats, {"swp3s1": [2], "swp3s2": [3], "swp3s3": [4]})

    def test_an_already_scoped_block_keeps_its_own_channels(self):
        # A driver that returns only the sub-port's own channels.
        stats = self.classify([
            ("swp6s0", "up", module(lit(TWIN_RX[:4]))),
            ("swp6s1", "up", module(lit(TWIN_RX[4:], first=5))),
        ])
        self.assert_lanes(stats, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})


class NoPlanTests(BreakoutCageTestCase):
    """Cages that give nothing to plan from keep the channel M+1 rule."""

    def planned(self, blocks):
        """Run the file; return (stats, lanes_per_subport passed per row)."""
        with mock.patch.object(
                self.analyzer, "update_optical_stats",
                wraps=self.analyzer.update_optical_stats) as update:
            stats = self.classify(blocks)
        plans = {call.args[0].split(":", 1)[1]:
                 call.kwargs.get("lanes_per_subport")
                 for call in update.call_args_list}
        return stats, plans

    def test_more_sub_ports_than_channels_keep_todays_rule(self):
        dump = module(SR4, identifier=QSFP28)
        stats, plans = self.planned(
            [(f"swp9s{index}", "up", dump) for index in range(8)])
        self.assertEqual(set(plans.values()), {None})
        self.assert_lanes(stats, {"swp9s0": [1], "swp9s3": [4],
                                  "swp9s4": [1, 2, 3, 4],
                                  "swp9s7": [1, 2, 3, 4]})

    def test_a_flags_only_cage_keeps_todays_rule(self):
        # Alarm flags say nothing about how many lanes a sub-port has.
        flags = {(channel, kind): channel == 2 and kind == "high_alarm"
                 for channel in range(1, 5) for kind in BIAS_KINDS}
        dump = module({}, flags=flags)
        stats, plans = self.planned(
            [("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.assertEqual(plans, {"swp6s0": None, "swp6s1": None})
        self.assertEqual(stats["swp6s0"]["bias_assessment"]["status"], "normal")
        self.assertEqual(stats["swp6s1"]["bias_assessment"]["status"], "critical")
        self.assertEqual(
            stats["swp6s1"]["bias_assessment"]["events"][0]["lane"], 2)

    def test_a_cage_that_cannot_be_planned_keeps_its_rows(self):
        # Whatever goes wrong while planning costs the cage its plan only.
        dump = module(TWIN_PORT)
        printed = io.StringIO()
        with mock.patch.object(self.analyzer, "plan_breakout_lanes",
                               side_effect=RuntimeError("odd input")), \
                contextlib.redirect_stdout(printed):
            stats = self.classify([("swp6s1", "up", dump),
                                   ("swp6s0", "up", dump),
                                   ("swp7", "up", dump)])
        self.assert_lanes(stats, {"swp6s0": [1], "swp6s1": [2],
                                  "swp7": list(range(1, 9))})
        # The fall back to channel M+1 is said once, naming the device, the
        # cage's sub-ports and what went wrong.
        warnings = printed.getvalue().splitlines()
        self.assertEqual(len(warnings), 1)
        for expected in ("leaf1", "swp6s0, swp6s1", "RuntimeError",
                         "channel M+1"):
            self.assertIn(expected, warnings[0])

    def test_a_planned_cage_prints_nothing(self):
        dump = module(TWIN_PORT)
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump),
                           ("swp9s0", "up", module(SR4, identifier=QSFP28)),
                           ("swp9s8", "down", NO_DATA)])
        self.assertEqual(printed.getvalue(), "")

    def test_a_call_without_cage_context_keeps_channel_m_plus_one(self):
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        self.assertTrue(
            analyzer.update_optical_stats("h:swp6s1", module(TWIN_PORT)))
        stats = analyzer.current_optical_stats["h:swp6s1"]
        self.assertEqual(stats["rx_power_lane_ids"], [2])
        self.assertEqual(stats["rx_power_dbm"], TWIN_RX[1])
        self.assertEqual(stats["bias_current_lane_ids"], [2])


class PlanRuleTests(BreakoutCageTestCase):
    """plan_breakout_lanes on parsed blocks, one rule at a time."""

    def plan(self, members):
        """members: {suffix: (operstate, dump text or None)}."""
        return self.analyzer.plan_breakout_lanes({
            index: {
                "state": state,
                "params": (self.analyzer.parse_optical_data(dump)
                           if dump is not None else None),
            }
            for index, (state, dump) in members.items()
        })

    def test_no_measured_block_means_no_plan(self):
        self.assertIsNone(self.plan({0: ("up", None), 1: ("down", None)}))
        self.assertIsNone(self.analyzer.plan_breakout_lanes({}))

    def test_more_sub_ports_than_channels_means_no_plan(self):
        dump = module(SR4, identifier=QSFP28)
        self.assertIsNone(self.plan({index: ("up", dump)
                                     for index in range(8)}))
        single = module(lit([-1.5], bias=7.0), identifier=QSFP28)
        self.assertIsNone(self.plan({0: ("up", single), 1: ("up", single)}))

    def test_a_fully_lit_module_is_shared_out_whole(self):
        dump = module(TWIN_PORT)
        self.assertEqual(self.plan({0: ("up", dump), 1: ("up", dump)}), 4)
        self.assertEqual(self.plan({0: ("down", dump), 1: ("down", dump)}), 4)
        self.assertEqual(
            self.plan({index: ("down", dump) for index in range(4)}), 2)

    def test_the_channel_count_is_rounded_up_to_a_power_of_two(self):
        # Six printed channels are shared out as eight, three as four.
        six = module(lit(TWIN_RX[:6]))
        self.assertEqual(self.plan({0: ("up", six), 1: ("up", six)}), 4)
        three = module(lit(TWIN_RX[:3]), identifier=QSFP28)
        self.assertEqual(self.plan({0: ("up", three), 1: ("up", three)}), 2)

    # --- every live channel is owned by a sub-port -------------------------
    # In each cage below a smaller block would be refuted less (or not at
    # all) and would win, were it not that it leaves a live channel on no
    # row.

    def test_a_channel_that_only_transmits_is_live(self):
        # s1's fibres are dark while its state still reads up.  Its lasers
        # run, so channels 5-8 stay on s1's row.
        dark_rx = {
            "laser and bias on": (None, 0.9, 335.0),
            "bias only": (None, ABSENT, 335.0),
            "laser power only": (None, 0.9, ABSENT),
        }
        for label, reading in dark_rx.items():
            with self.subTest(label):
                dump = module({**lit(TWIN_RX[:4]),
                               **{channel: reading for channel in range(5, 9)}})
                self.assertEqual(
                    self.plan({0: ("up", dump), 1: ("up", dump)}), 4)

    def test_a_channel_that_only_receives_is_live(self):
        # No transmit monitoring at all; channel 3 lost its light.
        channels = {channel: (rx, None, 0.0)
                    for channel, rx in enumerate(TWIN_RX, start=1)}
        channels[3] = (None, None, 0.0)
        dump = module(channels)
        self.assertEqual(self.plan({0: ("up", dump), 1: ("up", dump)}), 4)

    def test_the_highest_live_channel_counts_not_how_many_are_live(self):
        # Channels 2-3 are dead, 1 and 4 alive: channel 4 needs a row.
        dump = module({**SR4, 2: (None, None, 0.0), 3: (None, None, 0.0)},
                      identifier=QSFP28)
        self.assertEqual(self.plan({0: ("up", dump), 1: ("up", dump)}), 2)

    def test_a_channel_live_in_any_block_counts(self):
        # Each dump reports its own half; only s1's shows channels 5-8.
        first = module(lit(TWIN_RX[:4]))
        second = module({**lit(TWIN_RX[4:], first=5), 6: (None, 0.7, 336.0)})
        self.assertEqual(self.plan({0: ("up", first), 1: ("up", second)}), 4)

    def test_a_reading_exactly_at_the_floor_is_not_live(self):
        # -35.00 dBm is dark and 0.100 mA is a laser that is off: channel 8
        # is not alive, so nothing asks for two channels per sub-port.
        at_the_floor = {
            "receive power": (-35.0, None, 0.0),
            "transmit power": (None, -35.0, 0.0),
            "bias current": (None, None, 0.1),
        }
        for label, reading in at_the_floor.items():
            with self.subTest(label):
                dump = module({**DR4, 8: reading}, identifier=QSFP_DD)
                self.assertEqual(
                    self.plan({index: ("up", dump) for index in range(4)}), 1)

    def test_the_highest_suffix_counts_missing_siblings(self):
        # Only s3 answered: it is still one of four sub-ports.
        dump = module(TWIN_PORT)
        self.assertEqual(self.plan({3: ("up", dump)}), 2)
        self.assertEqual(self.plan({1: ("up", dump)}), 4)

    def test_a_link_up_sub_port_must_have_its_channels_in_service(self):
        dump = module(DR4, identifier=QSFP_DD)
        self.assertEqual(
            self.plan({index: ("up", dump) for index in range(4)}), 1)
        # Without a link-up sub-port nothing decides: widest block.
        self.assertEqual(
            self.plan({index: ("down", dump) for index in range(4)}), 2)

    def test_only_a_link_up_sub_port_refutes(self):
        dump = module(DR4, identifier=QSFP_DD)
        for state in (None, "", "unknown", "lowerlayerdown", "dormant",
                      "testing", "notpresent"):
            with self.subTest(state=state):
                self.assertEqual(
                    self.plan({index: (state, dump) for index in range(4)}), 2)
        for state in ("UP", " up "):
            with self.subTest(state=state):
                self.assertEqual(
                    self.plan({index: (state, dump) for index in range(4)}), 1)

    def test_fewer_contradictions_beat_more(self):
        # Channel 1 is dark.  One channel per sub-port is contradicted once
        # (s0), two channels per sub-port five times (s0, and s2 and s3 on
        # the module's unused channels).
        dump = module({**DR4, 1: (None, 1.6, 61.0)}, identifier=QSFP_DD)
        self.assertEqual(
            self.plan({index: ("up", dump) for index in range(4)}), 1)

    def test_the_channel_below_a_block_does_not_refute_it(self):
        # Channels 1 and 3 are dark and only s1 is up.  With one channel per
        # sub-port s1 sits on channel 2 and nothing contradicts it; dark
        # channel 1, just below, is not s1's.
        dump = module({**DR4, 1: (None, 1.6, 61.0), 3: (None, 1.8, 63.0)},
                      identifier=QSFP_DD)
        self.assertEqual(
            self.plan({0: ("down", dump), 1: ("up", dump),
                       2: ("down", dump), 3: ("down", dump)}), 1)

    def test_a_reading_exactly_at_the_floor_refutes(self):
        at_the_floor = {
            # Channel 2 receives exactly -35.00 dBm; its laser runs.
            "receive power": (
                {**DR4, 2: (-35.0, 1.7, 62.0)},
                {0: "up", 1: "down", 2: "down", 3: "down"}),
            # No receive monitoring; channels 3-4 transmit exactly
            # -35.00 dBm at exactly 0.100 mA.
            "transmit power and bias": (
                {1: (ABSENT, 1.6, 61.0), 2: (ABSENT, 1.7, 62.0),
                 3: (ABSENT, -35.0, 0.1), 4: (ABSENT, -35.0, 0.1)},
                {0: "up", 1: "up"}),
        }
        for label, (channels, states) in at_the_floor.items():
            with self.subTest(label):
                dump = module(channels, identifier=QSFP_DD)
                self.assertEqual(
                    self.plan({index: (state, dump)
                               for index, state in states.items()}), 1)

    def test_a_side_seen_alive_in_any_block_counts(self):
        # A DOM side counts as monitored when any dump of the cage shows it
        # alive, not only the first one.  s1 is up; channel 3 is out of
        # service in its own dump, so s1 cannot own channels 3-4.
        rx_only = {channel: (rx, ABSENT, ABSENT)
                   for channel, (rx, _tx, _bias) in DR4.items()}
        tx_only = {channel: (ABSENT, tx, bias)
                   for channel, (_rx, tx, bias) in DR4.items()}
        cases = {
            "receive side": (tx_only, {**DR4, 3: (None, 1.8, 63.0)}),
            "transmit side": (rx_only, {**tx_only, 3: (ABSENT, None, 0.0)}),
        }
        for label, (first, own) in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    self.plan({0: ("down", module(first, identifier=QSFP_DD)),
                               1: ("up", module(own, identifier=QSFP_DD)),
                               2: ("down", None), 3: ("down", None)}), 1)

    def test_an_unlit_transmit_side_refutes_like_a_dark_receiver(self):
        # The module reports no receive power at all.  Channels 3-4 are not
        # driven, so a link-up s1 cannot be sitting on them.
        dead = {
            "laser and bias off": (ABSENT, None, 0.0),
            "laser off, no bias printed": (ABSENT, None, ABSENT),
            "bias off, no power printed": (ABSENT, ABSENT, 0.0),
        }
        for label, reading in dead.items():
            with self.subTest(label):
                driven = tuple(ABSENT if value is ABSENT else live
                               for value, live in zip(reading, (ABSENT, 1.6, 61.0)))
                dump = module({1: driven, 2: driven, 3: reading, 4: reading},
                              identifier=QSFP28)
                self.assertEqual(
                    self.plan({0: ("up", dump), 1: ("up", dump)}), 1)

    def test_a_transmitter_that_still_draws_bias_does_not_refute(self):
        # Channel 3 shows no output power but its laser is driven: every
        # transmit value that exists must be off before the lane refutes.
        channels = {**lit(TWIN_RX[:4]), **placeholders(range(5, 9)),
                    3: (2.3, None, 333.0)}
        dump = module(channels)
        self.assertEqual(self.plan({0: ("up", dump), 1: ("down", dump)}), 4)

    def test_a_missing_value_never_refutes(self):
        missing = {
            "no receive power printed": (ABSENT, 1.8, 333.0),
            "no transmit values printed": (2.3, ABSENT, ABSENT),
        }
        for label, reading in missing.items():
            with self.subTest(label):
                channels = {**lit(TWIN_RX[:4]), **placeholders(range(5, 9)),
                            3: reading}
                dump = module(channels)
                self.assertEqual(
                    self.plan({0: ("up", dump), 1: ("down", dump)}), 4)

    def test_ties_go_to_the_larger_block(self):
        cases = {
            "nothing refuted": {**lit(TWIN_RX[:4]),
                                **placeholders(range(5, 9))},
            # Channel 1 is dark for two and for four channels alike.
            "equally refuted": {**lit(TWIN_RX[:4]),
                                **placeholders(range(5, 9)),
                                1: (None, 1.6, 331.0)},
        }
        for label, channels in cases.items():
            with self.subTest(label):
                dump = module(channels)
                self.assertEqual(
                    self.plan({0: ("up", dump), 1: ("down", dump)}), 4)

    def test_a_sub_port_is_judged_against_its_own_dump(self):
        # Sibling dumps are read one after another.  s1 was up when its own
        # dump showed channel 3 dark, so s1 cannot own channels 3-4; the
        # older dump of s0, where channel 3 was still lit, does not count.
        earlier = module(DR4, identifier=QSFP_DD)
        own = module({**DR4, 3: (None, 1.8, 63.0)}, identifier=QSFP_DD)
        self.assertEqual(self.plan({0: ("down", earlier), 1: ("up", own),
                                    2: ("down", None), 3: ("down", None)}), 1)

    def test_a_sub_port_without_a_dump_is_judged_against_a_siblings(self):
        # s0 is up but its own read failed; channel 2 is dark in the dump of
        # its siblings, so s0 does not own channels 1-2.
        dump = module({**DR4, 2: (None, 1.7, 62.0)}, identifier=QSFP_DD)
        self.assertEqual(self.plan({0: ("up", None), 1: ("down", dump),
                                    2: ("down", dump), 3: ("down", dump)}), 1)


class PlumbingTests(BreakoutCageTestCase):
    def test_every_block_is_parsed_exactly_once(self):
        twin = module({**lit(TWIN_RX[:4]), **placeholders(range(5, 9))})
        other = module(SR4, identifier=QSFP28)
        flags_only = module({}, flags={(channel, kind): False
                                       for channel in range(1, 5)
                                       for kind in BIAS_KINDS})
        with mock.patch.object(
                self.analyzer, "parse_optical_data",
                wraps=self.analyzer.parse_optical_data) as parse:
            stats = self.classify([
                ("swp6s0", "up", twin),
                ("swp7", "up", other),
                ("swp6s1", "down", twin),      # DOWN path, breakout
                ("swp8", "down", other),       # DOWN path, plain port
                ("swp9", "down", NO_DATA),
                ("swp5s0", "up", other),
                ("swp5s1", "down", NO_DATA),   # nothing to parse
                ("swp4s0", "up", other),
                ("swp4s1", "up", flags_only),  # parsed, but no readings
            ])
        self.assertEqual(
            set(stats), {"swp4s0", "swp4s1", "swp5s0", "swp6s0", "swp6s1",
                         "swp7", "swp8"})
        self.assertEqual(parse.call_count, 7)
        self.assertEqual(stats["swp8"]["health_status"], "down")

    def test_the_plan_is_honoured_without_a_cached_parse(self):
        self.assertTrue(self.analyzer.update_optical_stats(
            "h:swp6s1", module(TWIN_PORT), lanes_per_subport=4))
        stats = self.analyzer.current_optical_stats["h:swp6s1"]
        self.assertEqual(stats["rx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(stats["bias_current_lane_ids"], [5, 6, 7, 8])

    def test_plain_lane_lists_are_enough_to_plan(self):
        # A hand-built sample without the parser's internal key.
        def sample():
            return {"_rx_power_lane_ids": list(range(1, 9)),
                    "_rx_power_lanes_dbm": list(TWIN_RX)}
        self.assertEqual(self.analyzer.plan_breakout_lanes(
            {0: {"state": "up", "params": sample()},
             1: {"state": "up", "params": sample()}}), 4)
        params = sample()
        self.analyzer._select_breakout_lane("h:swp6s1", params, 4)
        self.assertEqual(params["_rx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(params["_rx_power_lanes_dbm"], TWIN_RX[4:])

    def test_planning_an_oversized_cage_takes_linear_time(self):
        # No module has thousands of sub-ports; a corrupted file can.  Each
        # reported channel is looked at once per block size, not once per
        # link-up sub-port, which took seconds here.
        size = 16384
        siblings = {index: {"state": "up", "params": None}
                    for index in range(size)}
        siblings[0]["params"] = {
            "_rx_power_lane_ids": list(range(1, size + 1)),
            "_rx_power_lanes_dbm": [1.5] * size,
        }
        started = time.process_time()
        self.assertEqual(self.analyzer.plan_breakout_lanes(siblings), 1)
        self.assertLess(time.process_time() - started, 0.5)

    def test_the_plan_does_not_leak_into_the_next_device(self):
        # The pooled worker analyzer is reused for every device.
        dump = module(TWIN_PORT)
        before = set(vars(self.analyzer))
        first = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)],
                              hostname="leaf1")
        second = self.classify(
            [(f"swp6s{index}", "up", dump) for index in range(8)],
            hostname="leaf2")
        third = self.classify([("swp6s0", "up", dump), ("swp6s1", "up", dump)],
                              hostname="leaf3")
        self.assert_lanes(first, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})
        self.assert_lanes(second, {f"swp6s{index}": [index + 1]
                                   for index in range(8)})
        self.assert_lanes(third, {"swp6s0": [1, 2, 3, 4],
                                  "swp6s1": [5, 6, 7, 8]})
        self.assertEqual(set(vars(self.analyzer)), before,
                         "the plan must stay local to one device file")

    def test_internal_parse_keys_do_not_reach_stats_or_history(self):
        dump = module(TWIN_PORT)
        ops, _failures = self.classify_ops(
            [("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        shard = (self.root / "optical-history" / "leaf1.json").read_text()
        self.assertNotIn("_unfiltered_lane_readings", shard)
        for _kind, _port, stats_entry, history_entry in ops:
            for record in (stats_entry, history_entry):
                self.assertEqual(
                    [key for key in record if key.startswith("_")], [])


class DocumentedLimitTests(BreakoutCageTestCase):
    """The known limit the README states is the one the code has."""

    def test_the_readme_describes_the_undecided_cage_as_it_is_shown(self):
        readme = (SCRIPT_DIR.parent / "README.md").read_text(encoding="utf-8")
        opening = "A breakout sub-port (`swpNsM`) is graded only on"
        self.assertEqual(readme.count(opening), 1)
        start = readme.index(opening)
        prose = re.sub(r"\s*\n\s*", " ",
                       readme[start:readme.index("\n\n", start)])
        self.assertIn(
            "Known limit: only a link-up sub-port whose wider block would "
            "include an out-of-service channel can rule that block out. "
            "Until one does, for example while every sub-port is down, the "
            "widest block the dump allows is used: the channels the module "
            "prints divided by the number of sub-ports. A 400G-DR4 split "
            "into 4x100G prints eight channels, so until then it is shown "
            "with two channels per sub-port (the third and fourth sub-port "
            "on the unused channels 5-8); a link on the third or fourth "
            "sub-port settles it.", prose)
        # The live channels are only a lower bound; they do not pick the
        # block, as the guide once said.
        self.assertNotIn("live channels is used", prose)

        one_each = {f"swp3s{index}": [index + 1] for index in range(4)}
        two_each = {"swp3s0": [1, 2], "swp3s1": [3, 4],
                    "swp3s2": [5, 6], "swp3s3": [7, 8]}
        dump = module(DR4, identifier=QSFP_DD)
        for number, states in enumerate(
                itertools.product(("up", "down"), repeat=4)):
            with self.subTest(states=states):
                stats = self.classify(
                    [(f"swp3s{index}", state, dump)
                     for index, state in enumerate(states)],
                    hostname=f"leaf{number}")
                self.assert_lanes(
                    stats, one_each if "up" in states[2:] else two_each)
        # The first two sub-ports settle it as well once a channel of their
        # wider block is out of service: the fourth sub-port is shut, its
        # laser off, so the second cannot be sitting on channels 3-4.
        shut = module({**DR4, 4: (None, None, 0.0)}, identifier=QSFP_DD)
        stats = self.classify(
            [(f"swp3s{index}", state, shut)
             for index, state in enumerate(("up", "up", "down", "down"))],
            hostname="leaf-shut")
        self.assert_lanes(stats, one_each)


class ConsumerTests(BreakoutCageTestCase):
    """Everything downstream shows the owned channels."""

    def setUp(self):
        super().setUp()
        dump = module(TWIN_PORT)
        self.ops, _failures = self.classify_ops(
            [("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        self.shard = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text())
        self.parent = OpticalAnalyzer(str(self.root), load_history=False)
        optical._merge_optical_ops(self.parent, "leaf1", self.ops)

    def test_history_shard_entry_names_an_owned_lane(self):
        entry = self.shard["history"]["leaf1:swp6s1"][-1]
        self.assertEqual(entry["rx_power_lane"], 8)
        self.assertEqual(entry["rx_power_dbm"], 1.4)
        self.assertEqual(entry["tx_power_lane"], 8)
        self.assertEqual(entry["bias_current_lane"], 8)
        self.assertEqual(
            self.shard["history"]["leaf1:swp6s0"][-1]["rx_power_lane"], 4)

    def test_shard_current_carries_the_owned_lane_values(self):
        current = self.shard["current"]["leaf1:swp6s1"]
        self.assertEqual(current["rx_power_lanes_dbm"], TWIN_RX[4:])
        self.assertEqual(current["bias_current_lanes_ma"],
                         [335.0, 336.0, 337.0, 338.0])
        self.assertEqual(
            self.shard["current"]["leaf1:swp6s0"]["rx_power_lanes_dbm"],
            TWIN_RX[:4])

    def test_detail_sidecar_labels_the_owned_lanes(self):
        self.parent.export_optical_data_for_web(
            str(self.root / "optical-analysis.html"))
        detail = json.loads(
            (self.root / "optical-details" / "leaf1.json").read_text())
        port = detail["ports"]["leaf1:swp6s1"]
        self.assertEqual(port["rx_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(port["tx_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(port["bias_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(port["rx_lanes"], TWIN_RX[4:])
        self.assertEqual(port["rx_lane"], 8)
        self.assertEqual(
            detail["ports"]["leaf1:swp6s0"]["rx_lane_ids"], [1, 2, 3, 4])

    def test_export_row_lists_the_owned_lane_values(self):
        summary = self.parent.get_optical_summary()
        rows = {row["interface"]: row for row in self.parent.build_export_rows(
            summary, self.parent.detect_optical_anomalies())}
        self.assertEqual(rows["swp6s1"]["rx_lanes"], "1.1 1.2 1.3 1.4")
        self.assertEqual(rows["swp6s0"]["rx_lanes"], "2.1 2.2 2.3 2.4")
        self.assertEqual(rows["swp6s1"]["rx_power_dbm"], 1.4)
        self.assertEqual(rows["swp6s1"]["inactive_lanes"], "")

    def test_report_row_labels_an_owned_lane(self):
        output = self.root / "optical-analysis.html"
        self.parent.export_optical_data_for_web(str(output))
        page = output.read_text()
        row = page.split('data-port="leaf1:swp6s1"', 1)[1].split("</tr>", 1)[0]
        self.assertIn("<td>1.40 (L8)</td>", row)
        self.assertIn("<td>0.90 (L8)</td>", row)
        self.assertIn("<td>338.00 (L8)</td>", row)
        self.assertNotRegex(row, r"\(L[1-4]\)")
        row = page.split('data-port="leaf1:swp6s0"', 1)[1].split("</tr>", 1)[0]
        self.assertIn("<td>2.40 (L4)</td>", row)


if __name__ == "__main__":
    unittest.main()
