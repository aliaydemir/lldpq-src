#!/usr/bin/env python3
"""One physical transceiver is counted once, however many ports it serves.

``ethtool -m`` answers every breakout sibling of a cage (``swp3s0`` ..
``swp3s3``) with the same module, so the optical file holds one block per
sub-port.  The inventory keeps one row per port, but counted every row as a
module: a cage split 4x was four modules in ``total_modules``, weighed four
times in the firmware distribution and four times in the status counts.

Every row now names the module it belongs to (device, cage ``swp<N>`` and the
serial when one is printed) and the module totals are taken per module; the
number of ports is published next to them.  The firmware file has the
collector's format, one ``swp<N>|FW Version : ...`` line per cage.  All
vendor, part and serial values are invented.
"""

from __future__ import annotations

import ast
import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_transceiver_data as transceiver


PART = "PN-EXAMPLE-DR4"


def block(interface, serial, part_number=PART):
    lines = [
        f"--- Interface: {interface}",
        "Interface state: up",
        "\tIdentifier                                : 0x19 (OSFP 8X Pluggable Transceiver)",
        "\tVendor name                               : ACME",
        f"\tVendor PN                                 : {part_number}",
        "\tVendor rev                                : A3",
    ]
    if serial:
        lines.append(f"\tVendor SN                                 : {serial}")
    lines.append("\tConnector                                 : 0x28 (MPO 2x12)")
    return "\n".join(lines) + "\n"


def split(cage, ways, serial, part_number=PART):
    """The blocks of one module in a cage split ``ways`` times."""
    return "".join(
        block(f"{cage}s{index}", serial, part_number) for index in range(ways))


def firmware(**cages):
    return "".join(
        f"{cage}|FW Version                     : {version}\n"
        for cage, version in cages.items())


class InventoryCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "monitor-results"
        (self.root / "optical-data").mkdir(parents=True)
        (self.root / "transceiver-data").mkdir()

    def host(self, name, optical, fw=None):
        (self.root / "optical-data" / f"{name}_optical.txt").write_text(optical)
        if fw is not None:
            (self.root / "transceiver-data" / f"{name}_transceiver.txt").write_text(fw)

    def run_inventory(self):
        """Run the real processor; the scratch hosts are in no devices.yaml."""
        output = io.StringIO()
        with mock.patch.object(transceiver, "_inventory_hostnames",
                               return_value=None), \
                contextlib.redirect_stdout(output):
            transceiver.process_transceiver_data(
                str(self.root / "optical-data"),
                str(self.root / "transceiver-data"),
                str(self.root))
        self.stdout = output.getvalue()
        inventory = json.loads(
            (self.root / "transceiver_inventory.json").read_text())
        return inventory["modules"], inventory["summary"]

    def four_modules_on_fifteen_ports(self):
        self.host(
            "leaf1",
            split("swp1", 2, "SN-EX-0001") + split("swp2", 4, "SN-EX-0002")
            + split("swp3", 8, "SN-EX-0003") + block("swp4", "SN-EX-0004"),
            firmware(swp1="46.120.10000", swp2="46.120.10000",
                     swp3="46.120.10000", swp4="46.171.12345"))


class ModuleCountTests(InventoryCase):
    def test_breakout_siblings_are_one_module(self):
        self.four_modules_on_fifteen_ports()
        rows, summary = self.run_inventory()

        self.assertEqual(summary["total_modules"], 4)
        self.assertEqual(summary["total_ports"], 15)
        self.assertEqual(
            summary["fw_versions"],
            {PART: {"46.120.10000": 3, "46.171.12345": 1}})
        self.assertEqual(summary["status_counts"], {"ok": 4})
        self.assertEqual(summary["unique_models"], 1)
        self.assertEqual(summary["devices_with_modules"], 1)
        self.assertEqual(summary["mixed_fw_models"], [PART])
        self.assertEqual(len(rows), 15)
        self.assertIn("4 modules on 15 ports across 1 devices", self.stdout)

    def test_rows_stay_per_port_and_name_their_module(self):
        self.four_modules_on_fifteen_ports()
        rows, _summary = self.run_inventory()

        by_port = {row["port"]: row for row in rows}
        self.assertEqual(
            sorted(by_port),
            sorted(["swp1s0", "swp1s1", "swp4"]
                   + [f"swp2s{i}" for i in range(4)]
                   + [f"swp3s{i}" for i in range(8)]))
        self.assertEqual(by_port["swp1s0"]["module"], "leaf1/swp1/SN-EX-0001")
        self.assertEqual(by_port["swp1s1"]["module"], "leaf1/swp1/SN-EX-0001")
        self.assertEqual(
            {by_port[f"swp3s{i}"]["module"] for i in range(8)},
            {"leaf1/swp3/SN-EX-0003"})
        self.assertEqual(by_port["swp4"]["module"], "leaf1/swp4/SN-EX-0004")
        # Every sub-port row still carries the module's identity and firmware.
        self.assertEqual(by_port["swp2s3"]["serial"], "SN-EX-0002")
        self.assertEqual(by_port["swp2s3"]["fw_version"], "46.120.10000")

    def test_a_split_module_weighs_once_in_the_firmware_distribution(self):
        # One module split 4x on the old firmware, three unsplit ones on the
        # new: the new version is the majority, three modules to one.
        self.host(
            "leaf1",
            split("swp3", 4, "SN-EX-0001") + block("swp5", "SN-EX-0002")
            + block("swp6", "SN-EX-0003") + block("swp7", "SN-EX-0004"),
            firmware(swp3="4.0.0", swp5="4.0.1", swp6="4.0.1", swp7="4.0.1"))
        _rows, summary = self.run_inventory()

        self.assertEqual(summary["fw_versions"],
                         {PART: {"4.0.0": 1, "4.0.1": 3}})
        self.assertEqual(summary["total_modules"], 4)
        self.assertEqual(summary["total_ports"], 7)

    def test_a_module_is_one_firmware_reading_whatever_its_ports_say(self):
        # Not the collector's format: one line per sub-port.  The module is
        # still one module, read from its first port that has a version.
        self.host(
            "leaf1", split("swp3", 4, "SN-EX-0001"),
            "swp3s1|FW Version : 4.0.1\nswp3s3|FW Version : 4.0.2\n")
        rows, summary = self.run_inventory()

        # The first port reads 4.0.1, the last one 4.0.2.
        self.assertEqual([row["fw_version"] for row in rows],
                         ["4.0.1", "4.0.1", "4.0.1", "4.0.2"])
        self.assertEqual(summary["total_modules"], 1)
        self.assertEqual(summary["fw_versions"], {PART: {"4.0.1": 1}})
        self.assertEqual(summary["status_counts"], {"ok": 1})
        self.assertEqual(len(rows), 4)

    def test_status_counts_are_per_module(self):
        self.host("leaf1", split("swp1", 4, "SN-EX-0001") + block("swp2", "SN-EX-0002"),
                  "# failed mlxlink timeout\n")
        # No firmware file at all: the host was not reached.
        self.host("leaf2", split("swp1", 2, "SN-EX-0003"))
        self.host("leaf3", split("swp1", 8, "SN-EX-0004"),
                  firmware(swp1="4.0.1"))
        rows, summary = self.run_inventory()

        self.assertEqual(summary["status_counts"],
                         {"failed": 2, "unreachable": 1, "ok": 1})
        self.assertEqual(summary["total_modules"], 4)
        self.assertEqual(summary["total_ports"], 15)
        self.assertEqual(sum(summary["status_counts"].values()),
                         summary["total_modules"])
        self.assertEqual({row["fw_status"] for row in rows
                          if row["device"] == "leaf1"}, {"failed"})


class ModuleIdentityTests(InventoryCase):
    def test_two_serials_in_one_cage_are_two_modules(self):
        self.host(
            "leaf1",
            block("swp5s0", "SN-EX-000A") + block("swp5s1", "SN-EX-000A")
            + block("swp5s2", "SN-EX-000B") + block("swp5s3", "SN-EX-000B"),
            firmware(swp5="4.0.1"))
        rows, summary = self.run_inventory()

        self.assertEqual(summary["total_modules"], 2)
        self.assertEqual(summary["total_ports"], 4)
        self.assertEqual(
            [row["module"] for row in rows],
            ["leaf1/swp5/SN-EX-000A", "leaf1/swp5/SN-EX-000A",
             "leaf1/swp5/SN-EX-000B", "leaf1/swp5/SN-EX-000B"])
        self.assertEqual(summary["fw_versions"], {PART: {"4.0.1": 2}})

    def test_modules_without_a_serial_are_told_apart_by_their_cage(self):
        self.host(
            "leaf1",
            split("swp2", 4, "") + split("swp7", 2, "") + block("swp8", ""),
            firmware(swp2="4.0.1", swp7="4.0.1", swp8="4.0.1"))
        rows, summary = self.run_inventory()

        self.assertEqual(summary["total_modules"], 3)
        self.assertEqual(summary["total_ports"], 7)
        self.assertEqual({row["module"] for row in rows},
                         {"leaf1/swp2", "leaf1/swp7", "leaf1/swp8"})
        self.assertEqual(summary["fw_versions"], {PART: {"4.0.1": 3}})

    def test_a_repeated_serial_does_not_merge_cages_or_devices(self):
        # Some modules ship with the same serial; the cage keeps them apart.
        self.host("leaf1", split("swp1", 2, "SN-EX-SAME") + split("swp2", 2, "SN-EX-SAME"),
                  firmware(swp1="4.0.1", swp2="4.0.1"))
        self.host("leaf2", split("swp1", 2, "SN-EX-SAME"),
                  firmware(swp1="4.0.1"))
        rows, summary = self.run_inventory()

        self.assertEqual(summary["total_modules"], 3)
        self.assertEqual(summary["total_ports"], 6)
        self.assertEqual(
            {row["module"] for row in rows},
            {"leaf1/swp1/SN-EX-SAME", "leaf1/swp2/SN-EX-SAME",
             "leaf2/swp1/SN-EX-SAME"})

    def test_two_digit_cages_are_not_merged_with_their_prefix(self):
        self.host("leaf1", split("swp1", 2, "") + split("swp10", 2, "")
                  + split("swp11", 4, ""),
                  firmware(swp1="4.0.0", swp10="4.0.1", swp11="4.0.1"))
        rows, summary = self.run_inventory()

        self.assertEqual(summary["total_modules"], 3)
        self.assertEqual({row["module"] for row in rows},
                         {"leaf1/swp1", "leaf1/swp10", "leaf1/swp11"})
        self.assertEqual(summary["fw_versions"],
                         {PART: {"4.0.0": 1, "4.0.1": 2}})


class ModuleTotalConsumerTests(InventoryCase):
    """Readers of the existing keys get the per-module numbers."""

    def test_public_export_counts_modules_and_keeps_one_row_per_port(self):
        self.four_modules_on_fifteen_ports()
        _rows, summary = self.run_inventory()

        export = json.loads((self.root / "transceiver-export.json").read_text())
        self.assertEqual(export["counts"], summary)
        self.assertEqual(export["counts"]["total_modules"], 4)
        self.assertEqual(export["counts"]["total_ports"], 15)
        self.assertEqual(export["counts"]["status_counts"], {"ok": 4})
        self.assertEqual(export["row_count"], 15)
        self.assertEqual(len({row["port"] for row in export["rows"]}), 15)
        self.assertEqual(len({row["serial"] for row in export["rows"]}), 4)
        with open(self.root / "transceiver-export.csv", newline="") as handle:
            table = list(csv.DictReader(handle))
        self.assertEqual(len(table), 15)
        self.assertEqual(table[0]["port"], "swp1s0")

    def test_ask_ai_summary_reports_modules_not_ports(self):
        self.four_modules_on_fifteen_ports()
        self.run_inventory()

        context = _ai_transceiver_context(self.root.parent)
        self.assertIn("SUMMARY: 4 modules on 15 ports, 1 models", context)
        self.assertIn("status={'ok': 4}", context)
        # The per-port lines are still all there.
        self.assertEqual(context.count("leaf1/swp"), 15)

    def test_ask_ai_summary_of_an_inventory_written_before_the_fix(self):
        # The inventory is rebuilt only by the on-demand transceiver scan, so
        # after an upgrade the file still has per-port totals, no port count
        # and no module on its rows.  The summary is taken from the rows.
        self.four_modules_on_fifteen_ports()
        self.host("leaf2", split("swp1", 2, "") + block("swp2", "SN-EX-0009"),
                  "# failed mlxlink timeout\n")
        self.run_inventory()
        path = self.root / "transceiver_inventory.json"
        inventory = json.loads(path.read_text())
        current = _ai_transceiver_context(self.root.parent)
        self.assertIn("SUMMARY: 6 modules on 18 ports, 1 models", current)
        self.assertIn("status={'ok': 4, 'failed': 2}", current)

        for row in inventory["modules"]:
            del row["module"]
        del inventory["summary"]["total_ports"]
        inventory["summary"]["total_modules"] = 18
        inventory["summary"]["status_counts"] = {"ok": 15, "failed": 3}
        path.write_text(json.dumps(inventory))

        old = _ai_transceiver_context(self.root.parent)
        self.assertEqual(old, current)

    def test_ask_ai_summary_takes_the_first_row_with_a_version_for_a_module(self):
        # Hand-written rows in the old format: the module's first row has no
        # firmware and no status of its own.
        path = self.root / "transceiver_inventory.json"
        row = lambda port, **fields: dict(  # noqa: E731
            {"device": "leaf1", "port": port, "vendor": "ACME",
             "part_number": PART, "serial": "SN-EX-0001", "fw_version": ""},
            **fields)
        path.write_text(json.dumps({
            "modules": [
                row("swp3s0", fw_status="no_data"),
                row("swp3s1", fw_version="4.0.1", fw_status="ok"),
                row("swp3s2", fw_version="4.0.2", fw_status="failed"),
                row("eth7", serial=""),
                # Two serials in one cage are two modules.
                row("swp5s0", serial="SN-EX-000A"),
                row("swp5s1", serial="SN-EX-000B"),
                # A row that names its module is taken at its word.
                row("swp9s0", module="leaf1/swp9/left"),
                row("swp9s1", module="leaf1/swp9/right"),
            ],
            "summary": {"total_modules": 8, "unique_models": 1,
                        "mixed_fw_models": [], "status_counts": {"ok": 8}},
        }))
        context = _ai_transceiver_context(self.root.parent)
        # swp3 is one module and speaks through swp3s1; eth7 is its own cage
        # and a row without a status counts as ok.
        self.assertIn("SUMMARY: 6 modules on 8 ports, 1 models", context)
        self.assertIn("status={'ok': 6}", context)


def _ai_transceiver_context(lldpq_dir):
    """Run build_transceiver_context() of the Ask-AI CGI on ``lldpq_dir``."""
    script = (SCRIPT_DIR.parent / "html" / "ai-api.sh").read_text(encoding="utf-8")
    marker = "python3 << 'PYTHON_SCRIPT'"
    source = script[script.index(marker) + len(marker):
                    script.rindex("\nPYTHON_SCRIPT")]
    wanted = {"_mr_path", "_load_json_file", "build_transceiver_context"}
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name in wanted]
    assert {node.name for node in nodes} == wanted
    namespace = {"os": os, "json": json, "re": re, "LLDPQ_DIR": str(lldpq_dir),
                 "WEB_ROOT": str(lldpq_dir / "no-web-root")}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "ai-api.sh", "exec"),
         namespace)
    return namespace["build_transceiver_context"]()


if __name__ == "__main__":
    unittest.main()
