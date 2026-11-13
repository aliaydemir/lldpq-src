#!/usr/bin/env python3
"""A VLAN sub-interface block must not stand in for its parent port.

The collector's inventory lets sub-interfaces such as ``swp6.100`` through;
``ethtool -m`` answers them with "No transceiver data".  The optical file was
keyed by the first word of the interface name, so that block was filed under
``swp6`` and replaced the parent's module readings: the parent's optical row
disappeared (or, with a down sub-interface, turned into "unplugged").

A sub-interface has no module of its own.  Whatever its block holds, it is
never a row, a state or a breakout sibling, and the parent port reads exactly
as it does in a file without that block.  All module values are invented.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
import process_transceiver_data as transceiver
from optical_analyzer import OpticalAnalyzer


DOM_SAMPLE = """\
        Identifier                                : 0x11 (QSFP28)
        Transceiver type                          : 100G Base-SR4
        Vendor name                               : ACME
        Vendor PN                                 : QSFP-100G-SR4
        Vendor SN                                 : SN0001
        Module temperature                        : 31.50 degrees C
        Module voltage                            : 3.2800 V
        Receiver signal average optical power (Channel 1) : 0.6982 mW / -1.56 dBm
        Transmit avg optical power (Channel 1)    : 0.7521 mW / -1.24 dBm
        Laser bias current (Channel 1)            : 7.500 mA
"""
# What a sub-interface block would hold if a driver ever answered it.
OTHER_DOM = (DOM_SAMPLE
             .replace("QSFP-100G-SR4", "GHOST-PN")
             .replace("ACME", "OTHER")
             .replace("0.6982 mW / -1.56 dBm", "0.0100 mW / -20.00 dBm"))
NO_DATA = "No transceiver data\n"


def block(interface, state, body):
    return f"--- Interface: {interface}\nInterface state: {state}\n{body}"


def twin_port_dump():
    lines = ["Identifier : 0x19 (OSFP 8X Pluggable Transceiver)",
             "Vendor name : ACME",
             "Module temperature : 43.18 degrees C / 109.72 degrees F",
             "Module voltage : 3.2703 V"]
    for channel in range(1, 9):
        lines += [
            f"Laser tx bias current (Channel {channel}) : {330 + channel}.000 mA",
            f"Transmit avg optical power (Channel {channel}) : 1.4125 mW / 1.50 dBm",
            f"Rcvr signal avg optical power (Channel {channel}) : 1.5849 mW / 2.00 dBm",
        ]
    return "\n".join(lines) + "\n"


def _history_entry(ts):
    return {"timestamp": ts, "health": "good", "rx_power_dbm": -1.5,
            "tx_power_dbm": -1.2, "temperature_c": 30.0, "link_margin_db": 10.0,
            "rx_power_lane": None, "tx_power_lane": None,
            "bias_current_lane": None}


def comparable(ops):
    """Ops without the wall-clock fields two runs can never share."""
    cleaned = []
    for op in ops:
        if op[0] != "update":
            cleaned.append(op)
            continue
        stats = {key: value for key, value in op[2].items()
                 if key != "last_updated"}
        history = {key: value for key, value in op[3].items()
                   if key != "timestamp"}
        cleaned.append((op[0], op[1], stats, history))
    return cleaned


class SubinterfaceBlockTests(unittest.TestCase):
    def classify(self, body, history=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "optical-data").mkdir()
        sample = self.root / "optical-data" / "leaf1_optical.txt"
        sample.write_text("=== OPTICAL DIAGNOSTICS ===\n" + body)
        if history is not None:
            seeder = OpticalAnalyzer(str(self.root), load_history=False)
            seeder.optical_history = history
            assert seeder.save_optical_history()
        optical._parse_worker_analyzer = OpticalAnalyzer(
            str(self.root), load_history=False
        )
        ops, failures, shard_error = optical._classify_optical_file(
            str(sample), "leaf1"
        )
        self.assertIsNone(shard_error)
        return ops, failures

    def shard(self):
        return json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text())

    def assert_no_trace_of(self, ops, port_name):
        self.assertNotIn(port_name, [op[1] for op in ops])
        shard = self.shard()
        self.assertNotIn(port_name, shard["current"])
        self.assertNotIn(port_name, shard["history"])

    # --- the parser key ----------------------------------------------------
    def test_blocks_are_keyed_by_the_whole_interface_name(self):
        port_data = optical._parse_optical_diagnostics_content(
            block("swp6", "up", DOM_SAMPLE)
            + block("swp6.100", "up", NO_DATA)
            + block("swp6s1.100", "up", NO_DATA)
        )
        self.assertEqual(list(port_data), ["swp6", "swp6.100", "swp6s1.100"])
        self.assertIn("Vendor PN", port_data["swp6"])
        self.assertNotIn("Vendor PN", port_data["swp6.100"])

    def test_the_key_is_the_whole_name_whatever_follows_the_port(self):
        # The collector's inventory matches names by their prefix, so any
        # name that starts like a port can reach the file.  None of them
        # may be filed under the port.
        parent = block("swp6", "up", DOM_SAMPLE)
        expected, _failures = self.classify(parent)
        for name in ("swp6-v0", "swp6:1", "swp6.100.200"):
            with self.subTest(name):
                port_data = optical._parse_optical_diagnostics_content(
                    parent + block(name, "up", NO_DATA))
                self.assertEqual(list(port_data), ["swp6", name])
                self.assertIn("Vendor PN", port_data["swp6"])
                for body in (parent + block(name, "down", NO_DATA),
                             block(name, "down", NO_DATA) + parent):
                    ops, failures = self.classify(body)
                    self.assertEqual(failures, [])
                    self.assertEqual(comparable(ops), comparable(expected))

    # --- the parent keeps its row ------------------------------------------
    def test_the_parent_keeps_its_row_in_either_block_order(self):
        parent = block("swp6", "up", DOM_SAMPLE)
        expected, _failures = self.classify(parent)
        self.assertEqual([op[0] for op in expected], ["update"])
        orders = {
            "sub-interface after the parent":
                parent + block("swp6.100", "up", NO_DATA),
            "sub-interface before the parent":
                block("swp6.100", "up", NO_DATA) + parent,
            "several sub-interfaces":
                block("swp6.100", "up", NO_DATA) + parent
                + block("swp6.200", "up", NO_DATA),
        }
        for label, body in orders.items():
            with self.subTest(label):
                ops, failures = self.classify(body)
                self.assertEqual(failures, [])
                self.assertEqual(comparable(ops), comparable(expected))
                stats = ops[0][2]
                self.assertEqual(ops[0][1], "leaf1:swp6")
                self.assertEqual(stats["rx_power_dbm"], -1.56)
                self.assertEqual(stats["tx_power_dbm"], -1.24)
                self.assertEqual(stats["bias_current_ma"], 7.5)
                self.assertEqual(stats["health_status"], "excellent")
                self.assertEqual(list(self.shard()["current"]), ["leaf1:swp6"])
                self.assert_no_trace_of(ops, "leaf1:swp6.100")

    def test_a_breakout_parent_keeps_its_row_and_its_channels(self):
        dump = twin_port_dump()
        siblings = block("swp6s0", "up", dump) + block("swp6s1", "up", dump)
        expected, _failures = self.classify(siblings)
        ops, failures = self.classify(
            siblings + block("swp6s1.100", "up", NO_DATA)
            + block("swp6s0.100", "up", NO_DATA)
            + block("swp6s2.100", "up", NO_DATA))
        self.assertEqual(failures, [])
        self.assertEqual(comparable(ops), comparable(expected))
        stats = {op[1]: op[2] for op in ops}
        self.assertEqual(set(stats), {"leaf1:swp6s0", "leaf1:swp6s1"})
        # The sub-interfaces are no breakout siblings either: still a 2x
        # split, four channels each.
        self.assertEqual(stats["leaf1:swp6s0"]["rx_power_lane_ids"], [1, 2, 3, 4])
        self.assertEqual(stats["leaf1:swp6s1"]["rx_power_lane_ids"], [5, 6, 7, 8])
        self.assertEqual(stats["leaf1:swp6s1"]["bias_current_ma"], 338.0)

    # --- nothing exists for the sub-interface ------------------------------
    def test_a_down_sub_interface_does_not_unplug_the_parent(self):
        # "No transceiver data" on a down port with optical history means
        # the module was pulled.  That is the sub-interface's block, not the
        # parent's, and the parent has a module answering.
        history = {"leaf1:swp6": [_history_entry(1.0)]}
        ops, _failures = self.classify(
            block("swp6", "up", DOM_SAMPLE)
            + block("swp6.100", "down", NO_DATA),
            history=history,
        )
        self.assertEqual([(op[0], op[1]) for op in ops],
                         [("update", "leaf1:swp6")])
        self.assertEqual(ops[0][2]["health_status"], "excellent")
        self.assertEqual(len(self.shard()["history"]["leaf1:swp6"]), 2)

    def test_whatever_the_block_holds_it_is_never_a_row_or_a_state(self):
        bodies = {
            "module readings": ("up", OTHER_DOM),
            "state unknown": ("unknown", NO_DATA),
            "status unplugged": ("down", "status : unplugged\n"),
            "down with readings": ("down", OTHER_DOM),
            "unreadable sensors": ("up", "temperature                 : 0.0\n"
                                         "voltage                     : 0.0\n"),
        }
        parent = block("swp6", "up", DOM_SAMPLE)
        expected, _failures = self.classify(parent)
        for label, (state, body) in bodies.items():
            with self.subTest(label):
                ops, failures = self.classify(
                    parent + block("swp6.100", state, body))
                self.assertEqual(failures, [])
                self.assertEqual(comparable(ops), comparable(expected))
                self.assertEqual(ops[0][2]["rx_power_dbm"], -1.56)
                self.assert_no_trace_of(ops, "leaf1:swp6.100")

    def test_a_double_tagged_sub_interface_is_never_a_row(self):
        parent = block("swp6", "up", DOM_SAMPLE)
        expected, _failures = self.classify(parent)
        ops, failures = self.classify(
            parent + block("swp6.100.200", "up", OTHER_DOM))
        self.assertEqual(failures, [])
        self.assertEqual(comparable(ops), comparable(expected))
        self.assert_no_trace_of(ops, "leaf1:swp6.100.200")

    def test_a_vlan_on_a_breakout_sub_port_is_never_a_row(self):
        dump = twin_port_dump()
        siblings = block("swp6s0", "up", dump) + block("swp6s1", "up", dump)
        expected, _failures = self.classify(siblings)
        bodies = {
            "module readings": ("up", OTHER_DOM),
            "status unplugged": ("down", "status : unplugged\n"),
            "state unknown": ("unknown", "Module voltage : 3.2800 V\n"),
        }
        for label, (state, body) in bodies.items():
            with self.subTest(label):
                ops, failures = self.classify(
                    siblings + block("swp6s1.100", state, body))
                self.assertEqual(failures, [])
                self.assertEqual(comparable(ops), comparable(expected))
                self.assert_no_trace_of(ops, "leaf1:swp6s1.100")

    def test_a_sub_interface_history_key_is_not_kept_alive(self):
        # Complete collection: the file is the authority on which ports
        # exist, and a sub-interface is not one of them.
        history = {
            "leaf1:swp6": [_history_entry(1.0)],
            "leaf1:swp6.100": [_history_entry(1.0)],
            "leaf1:swp7": [_history_entry(1.0)],
        }
        self.classify(
            block("swp6", "up", DOM_SAMPLE) + block("swp6.100", "up", NO_DATA),
            history=history,
        )
        self.assertEqual(list(self.shard()["history"]), ["leaf1:swp6"])
        self.assertEqual(len(self.shard()["history"]["leaf1:swp6"]), 2)

    def test_pruning_matches_a_file_without_the_sub_interface_block(self):
        # The parent's block is gone from a complete collection: the port
        # was removed.  A leftover sub-interface block must not keep the
        # parent's history alive under the parent's name.
        history = {"leaf1:swp6": [_history_entry(1.0)],
                   "leaf1:swp7": [_history_entry(1.0)]}
        other = block("swp7", "up", DOM_SAMPLE)
        self.classify(other, history=dict(history))
        without = self.shard()["history"]
        self.classify(other + block("swp6.100", "up", NO_DATA),
                      history=dict(history))
        self.assertEqual(list(self.shard()["history"]), list(without))
        self.assertEqual(list(without), ["leaf1:swp7"])

    # --- collection failure markers ----------------------------------------
    def test_a_failure_marker_keeps_the_collection_incomplete_without_a_row(self):
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp6.100\n"
        history = {"leaf1:swp6": [_history_entry(1.0)],
                   "leaf1:swp9": [_history_entry(1.0)]}
        shapes = {
            "marker inside the block":
                block("swp6", "up", DOM_SAMPLE)
                + block("swp6.100", "up", marker + NO_DATA),
            "marker without a block":
                block("swp6", "up", DOM_SAMPLE) + marker,
        }
        for label, body in shapes.items():
            with self.subTest(label):
                ops, failures = self.classify(body, history=dict(history))
                # Still an incomplete collection, exactly as before ...
                self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp6.100")])
                # ... so nothing is pruned (swp9 is absent from the file) ...
                self.assertEqual(sorted(self.shard()["history"]),
                                 ["leaf1:swp6", "leaf1:swp9"])
                # ... but the sub-interface is not a port, and the parent is
                # graded from its own block.
                self.assertEqual([(op[0], op[1]) for op in ops],
                                 [("update", "leaf1:swp6")])
                self.assertEqual(ops[0][2]["health_status"], "excellent")
                self.assert_no_trace_of(ops, "leaf1:swp6.100")

    def test_a_parent_failure_marker_still_reports_the_parent(self):
        # The parent's own failed read is reported from the parent's block.
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp6\n"
        parent = block("swp6", "up", marker + NO_DATA)
        expected, _failures = self.classify(parent)
        ops, failures = self.classify(
            parent + block("swp6.100", "up", "Module voltage : 3.2800 V\n"))
        self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp6")])
        self.assertEqual([op[:3] for op in ops],
                         [("state", "leaf1:swp6", "unknown")])
        self.assertEqual(ops, expected)

    def test_a_port_marker_without_a_block_still_reports_the_port(self):
        # Only a sub-interface's marker is kept from becoming a row.
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp7\n"
        ops, failures = self.classify(block("swp6", "up", DOM_SAMPLE) + marker)
        self.assertEqual(failures, [("OPTICAL_TIMEOUT", "swp7")])
        self.assertEqual([op[:3] for op in ops if op[0] == "state"],
                         [("state", "leaf1:swp7", "unknown")])
        self.assertEqual([op[:2] for op in ops if op[0] == "update"],
                         [("update", "leaf1:swp6")])


class VendorInfoTests(unittest.TestCase):
    def parse(self, body):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        sample = Path(temporary.name) / "leaf1_optical.txt"
        sample.write_text("=== OPTICAL DIAGNOSTICS ===\n" + body)
        return transceiver.parse_optical_vendor_info(str(sample))

    def assert_parent_entry(self, modules, interface="swp6"):
        self.assertEqual(modules[interface]["vendor"], "ACME")
        self.assertEqual(modules[interface]["part_number"], "QSFP-100G-SR4")
        self.assertEqual(modules[interface]["serial"], "SN0001")
        self.assertEqual(modules[interface]["identifier"], "QSFP28")

    def test_a_sub_interface_block_never_changes_the_parent_entry(self):
        # ethtool answers a sub-interface with "No transceiver data"; should
        # a driver ever return fields for it, they still describe no module
        # of its own.
        parent = block("swp6", "up", DOM_SAMPLE)
        expected = self.parse(parent)
        self.assertEqual(list(expected), ["swp6"])
        self.assert_parent_entry(expected)
        bodies = {
            "no transceiver data, after the parent":
                parent + block("swp6.100", "up", NO_DATA),
            "no transceiver data, before the parent":
                block("swp6.100", "up", NO_DATA) + parent,
            "vendor fields, after the parent":
                parent + block("swp6.100", "up", OTHER_DOM),
            "vendor fields, before the parent":
                block("swp6.100", "up", OTHER_DOM) + parent,
        }
        for label, body in bodies.items():
            with self.subTest(label):
                self.assertEqual(self.parse(body), expected)

    def test_a_breakout_parent_keeps_its_module_entry(self):
        modules = self.parse(
            block("swp7s0", "up", DOM_SAMPLE)
            + block("swp7s1", "up", DOM_SAMPLE)
            + block("swp7s1.100", "up", OTHER_DOM)
        )
        self.assertEqual(list(modules), ["swp7s0", "swp7s1"])
        self.assert_parent_entry(modules, "swp7s1")

    def test_the_key_is_the_whole_name_whatever_follows_the_port(self):
        parent = block("swp6", "up", DOM_SAMPLE)
        for name in ("swp6-v0", "swp6:1", "swp6.100.200"):
            other = block(name, "up", OTHER_DOM)
            for label, body in (("after the parent", parent + other),
                                ("before the parent", other + parent)):
                with self.subTest(name=name, order=label):
                    self.assert_parent_entry(self.parse(body))


if __name__ == "__main__":
    unittest.main()
