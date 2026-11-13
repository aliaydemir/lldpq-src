#!/usr/bin/env python3
"""Review fixes for what the optical results feed: history, exports, AI lists.

* A port whose module stopped printing DOM values appended an empty UNKNOWN
  sample every run.  After 100 runs the readings that proved the port
  optical had scrolled out of its history: the row vanished and the
  module's later removal was not reported.
* ``link_margin_db`` counts from the module's RX low alarm since module
  limits grade a port.  The history kept the old samples on the generic
  -14 dBm, and Ask-AI insights read the step as a margin that dropped on
  every such port at the upgrade.
* The CSV formula guard exempted every text cell made of digits and signs.
  The LLDP page's Download CSV guards such a cell, so the headless LLDP CSV
  was no longer byte-identical to it.
* One hot module in a breakout cage was still one entry per sub-port in the
  AI incident list.
* The transceiver export had no column for the ``module`` key of its rows,
  and a restored backup accepted an optical margin Setup refuses.

Plus the classification, visibility and export rules of the earlier round
that no test pinned.  Dumps run through the real per-device worker; all
module values are invented.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import HEALTHY, NO_DATA, OpticalFileTestCase

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(ROOT / "html"))

import ai_correlate  # noqa: E402
import ai_insights  # noqa: E402
import backup_import  # noqa: E402
import export_artifacts  # noqa: E402
import lldp_export  # noqa: E402
import process_transceiver_data as transceiver  # noqa: E402
from lldp_report import parse_lldp_report  # noqa: E402
from optical_analyzer import OpticalAnalyzer, SIDECAR_ONLY_STAT_KEYS  # noqa: E402


LLDP_HTML = (ROOT / "html" / "lldp.html").read_text(encoding="utf-8")


def sr4(rx=fx.SR4_RX, tx=fx.SR4_TX, bias=fx.SR4_BIAS, **kwargs):
    return fx.qsfp(connector="0x0c (MPO Parallel Optic)",
                   types=["100G Ethernet: 100G Base-SR4"],
                   technology="0x00 (850 nm VCSEL)", rx=rx, tx=tx, bias=bias,
                   **kwargs)


SFP_LIMITS = {
    "bias": fx.limits(17.0, 14.0, 2.0, 1.0),
    "tx_power": fx.limits(-0.97, -1.97, -9.5, -10.5),
    "temperature": fx.limits(90.0, 85.0, -5.0, -10.0),
    "voltage": fx.limits(3.6, 3.5, 3.1, 3.0),
    "rx_power": fx.limits(2.04, 1.04, -16.99, -20.0),
}

# The same module once its monitors are gone: qsfp.c prints 0.00 C and
# 0.0000 V and stops.
NO_MONITORS = sr4(rx=None, temperature=0.0, voltage=0.0)


class HistoryKeepsItsReadingsTests(OpticalFileTestCase):
    def test_a_port_without_readings_keeps_its_row_and_its_history(self):
        self.assertIn(self.rows([("swp1", "up", sr4())])["swp1"]
                      ["health_status"], HEALTHY)
        for collection in range(1, 102):
            rows = self.rows([("swp1", "up", NO_MONITORS)])
            self.assertEqual(
                {name: stats["health_status"] for name, stats in rows.items()},
                {"swp1": "unknown"}, f"collection {collection}")
        history = self.shard()["history"]["leaf1:swp1"]
        self.assertEqual(len(history), 1)
        self.assertIn(history[0]["health"], HEALTHY)
        self.assertEqual(history[0]["rx_power_dbm"], -0.9)
        # The module is pulled: still an expected module, so it is reported.
        rows = self.rows([("swp1", "down", NO_DATA)])
        self.assertEqual(rows["swp1"]["health_status"], "unplugged")

    def test_a_sample_with_a_reading_is_still_appended(self):
        # No power side, but a temperature: UNKNOWN, and a sample.
        temperature_only = sr4(rx=None, temperature=41.0, voltage=3.3)
        for _collection in range(3):
            rows = self.rows([("swp1", "up", temperature_only)])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        history = self.shard()["history"]["leaf1:swp1"]
        self.assertEqual([entry["health"] for entry in history],
                         ["unknown"] * 3)
        self.assertEqual([entry["temperature_c"] for entry in history],
                         [41.0] * 3)

    def test_a_graded_row_without_those_readings_is_still_a_sample(self):
        # Only a voltage, and a bad one: CRITICAL is a state worth keeping.
        bad_supply = sr4(rx=None, temperature=0.0, voltage=2.6)
        rows = self.rows([("swp1", "up", bad_supply)])
        self.assertEqual(rows["swp1"]["health_status"], "critical")
        self.assertEqual(
            [entry["health"]
             for entry in self.shard()["history"]["leaf1:swp1"]],
            ["critical"])
        rows = self.rows([("swp1", "down", NO_DATA)])
        self.assertEqual(rows["swp1"]["health_status"], "unplugged")

    def test_a_port_that_only_ever_had_empty_rows_has_no_history_key(self):
        # A voltage reading alone is a row, not a sample.
        voltage_only = sr4(rx=None, temperature=0.0, voltage=3.3)
        rows = self.rows([("swp1", "up", voltage_only)])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        self.assertEqual(self.shard()["history"], {})


class MarginReferenceTests(OpticalFileTestCase):
    """Every history sample says what its link margin counts from."""

    def insights(self):
        now = time.time() + 1
        events, coverage = ai_insights._extract_optical(
            self.root / "optical-history", now - 86400, now, 7 * 86400)
        # The shards were read: an unreadable store would also be silent.
        self.assertIn(coverage.get("status"), ("loaded", "partial"), coverage)
        self.assertEqual(
            coverage.get("samples"),
            sum(len(entries) for entries in self.shard()["history"].values()))
        return [event["summary"] for event in events]

    def history(self, interface="swp1"):
        return self.shard()["history"][f"leaf1:{interface}"]

    def rewrite_as_written_before_module_limits(self):
        """Make the stored samples what the earlier release wrote.

        It counted every margin from the generic -14 dBm and stored
        neither the reference nor the graded lanes with the sample.
        """
        path = self.root / "optical-history" / "leaf1.json"
        shard = json.loads(path.read_text())
        for entries in shard["history"].values():
            for entry in entries:
                del entry["rx_power_lane_ids"]
                reference = entry.pop("link_margin_ref_dbm")
                entry["link_margin_db"] = round(
                    entry["link_margin_db"] + reference + 14.0, 6)
        path.write_text(json.dumps(shard))

    def test_the_sample_names_the_reference(self):
        self.rows([("swp1", "up", fx.cmis()), ("swp2", "up", sr4()),
                   ("swp3", "up", sr4(rx=None, temperature=41.0,
                                      voltage=3.3))])
        module, generic, without = (self.history(name)[-1]
                                    for name in ("swp1", "swp2", "swp3"))
        self.assertEqual(module["link_margin_ref_dbm"], -8.4)
        self.assertAlmostEqual(module["link_margin_db"], 1.04 + 8.4)
        self.assertEqual(generic["link_margin_ref_dbm"], -14.0)
        self.assertAlmostEqual(generic["link_margin_db"], -1.5 + 14.0)
        self.assertIsNone(without["link_margin_db"])
        self.assertIsNone(without["link_margin_ref_dbm"])

    def test_the_sample_lists_the_receive_lanes_it_graded(self):
        dump = fx.cmis()
        self.rows([("swp6s0", "up", dump), ("swp6s1", "up", dump),
                   ("swp1", "up", sr4(rx=fx.with_lane(fx.SR4_RX, 3, None),
                                      tx=fx.with_lane(fx.SR4_TX, 3, None),
                                      bias=fx.with_lane(fx.SR4_BIAS, 3, 0.0))),
                   ("swp2", "up", sr4(rx=None, temperature=41.0,
                                      voltage=3.3)),
                   # Transmit power not monitored: the receive lanes count.
                   ("swp3", "up", sr4(tx=[None] * 4))])
        self.assertEqual(
            {name: self.history(name)[-1]["rx_power_lane_ids"]
             for name in ("swp6s0", "swp6s1", "swp1", "swp2", "swp3")},
            {"swp6s0": [1, 2, 3, 4], "swp6s1": [5, 6, 7, 8],
             "swp1": [1, 2, 4], "swp2": [], "swp3": [1, 2, 3, 4]})

    def test_a_uniform_drop_of_a_multi_lane_module_is_reported(self):
        # The brightest lane is the displayed one while the module is
        # healthy and the dimmest one after the drop: only the lane list
        # tells the reader that both samples grade the same lanes.
        self.rows([("swp1", "up", sr4())])
        self.rows([("swp1", "up", sr4(
            rx=[value - 4.0 for value in fx.SR4_RX]))])
        history = self.history()
        self.assertNotEqual(history[0]["rx_power_lane"],
                            history[1]["rx_power_lane"])
        summaries = self.insights()
        self.assertEqual(len(summaries), 1)
        self.assertIn("link margin 12.5→8.5 dB", summaries[0])

    def test_the_upgrade_is_no_margin_drop(self):
        # A healthy twin-port module (RX low alarm -8.4 dBm) and an SR4
        # whose table has its low alarm at -10.3 dBm; nothing changes on
        # the links.
        sr4_tables = {"rx_power": fx.limits(3.4, 2.4, -9.3, -10.3)}
        blocks = [("swp1", "up", fx.cmis()),
                  ("swp2", "up", sr4(tables=sr4_tables))]
        self.rows(blocks)
        self.rows(blocks)
        self.rewrite_as_written_before_module_limits()
        self.assertEqual(
            [round(entry["link_margin_db"], 2) for entry in self.history()],
            [15.04, 15.04])
        self.assertNotIn("link_margin_ref_dbm", self.history()[0])
        # The first collection after the upgrade.
        self.rows(blocks)
        for interface, reference, margin in (("swp1", -8.4, 9.44),
                                             ("swp2", -10.3, 8.8)):
            history = self.history(interface)
            self.assertEqual(len(history), 3)
            self.assertEqual(
                [entry["link_margin_ref_dbm"] for entry in history],
                [reference] * 3)
            for entry in history:
                self.assertAlmostEqual(entry["link_margin_db"], margin)
        self.assertEqual(self.insights(), [])

    def test_a_real_drop_across_the_upgrade_is_still_reported(self):
        # A single-lane module (RX low alarm -20 dBm) that loses 4.5 dB in
        # the collection after the upgrade.
        def sfp(rx):
            return fx.sfp(connector="0x07 (LC)",
                          types=["10G Ethernet: 10G Base-SR"],
                          dom=(rx, -2.2, 6.0, 36.0, 3.29), tables=SFP_LIMITS)
        self.rows([("swp1", "up", sfp(-5.0))])
        self.rows([("swp1", "up", sfp(-5.0))])
        self.rewrite_as_written_before_module_limits()
        self.assertEqual(
            [round(entry["link_margin_db"], 2) for entry in self.history()],
            [9.0, 9.0])
        self.rows([("swp1", "up", sfp(-9.5))])
        self.assertEqual(
            [round(entry["link_margin_db"], 2) for entry in self.history()],
            [15.0, 15.0, 10.5])
        summaries = self.insights()
        self.assertEqual(len(summaries), 1)
        self.assertIn("Rx power -5.0→-9.5 dBm", summaries[0])
        self.assertIn("link margin 15.0→10.5 dB", summaries[0])

    def test_a_module_with_other_limits_moves_the_series_with_it(self):
        self.rows([("swp1", "up", fx.cmis())])
        other = dict(fx.TWIN, rx_power=fx.limits(6.5, 5.5, -9.3, -10.3))
        self.rows([("swp1", "up", fx.cmis(tables=other))])
        history = self.history()
        self.assertEqual([entry["link_margin_ref_dbm"] for entry in history],
                         [-10.3, -10.3])
        for entry in history:
            self.assertAlmostEqual(entry["link_margin_db"], 1.04 + 10.3)
        self.assertEqual(self.insights(), [])

    def test_a_series_on_one_reference_is_left_as_it_is(self):
        for _collection in range(3):
            self.rows([("swp1", "up", sr4())])
        history = self.history()
        self.assertEqual([entry["link_margin_ref_dbm"] for entry in history],
                         [-14.0] * 3)
        self.assertEqual([entry["link_margin_db"] for entry in history],
                         [-1.5 + 14.0] * 3)


class CsvGuardTests(unittest.TestCase):
    """Only the optical lane lists skip the formula guard."""

    SIGNED = ("-1", "+20", "-5", "-5 -6", "+5", "- 5", "--5", "+1-2",
              "-1.2 -0.9 -1.5", "-.5")
    OTHER = ("=1+1", "+SUM(A1)", "-1e5", "@x", "@5", "-", "+", "-.", "-5,6",
             "plain", "12", "1.5", "", "n/a", " -7 ", 'a"b', "a,b")

    def test_text_that_looks_numeric_keeps_the_guard_by_default(self):
        for cell in self.SIGNED:
            with self.subTest(cell):
                self.assertEqual(export_artifacts.csv_field(cell),
                                 "'" + cell)
                self.assertEqual(
                    export_artifacts.spreadsheet_safe_value(cell), "'" + cell)

    def test_only_the_optical_lane_lists_are_exempt(self):
        self.assertEqual(
            export_artifacts.NUMERIC_LIST_COLUMNS,
            {"optical": frozenset({
                "rx_lanes", "tx_lanes", "bias_lanes", "inactive_lanes",
                "rx_lane_ids", "tx_lane_ids", "bias_lane_ids"})})
        row = dict.fromkeys(export_artifacts.EXPORT_SCHEMAS["optical"])
        row.update(device="-1", interface="+20", rx_lanes="-1.2 -0.9",
                   tx_lanes="=1+1", anomalies="-5")
        with tempfile.TemporaryDirectory() as directory:
            export_artifacts.write_export(directory, "optical", [row], {},
                                          None)
            text = (Path(directory) / "export" / "optical.csv").read_text()
        table = next(csv.DictReader(io.StringIO(text)))
        self.assertEqual(table["rx_lanes"], "-1.2 -0.9")
        # A lane column that holds anything but numbers keeps the guard,
        # and so does numeric-looking text in every other column.
        self.assertEqual(table["tx_lanes"], "'=1+1")
        self.assertEqual(table["device"], "'-1")
        self.assertEqual(table["interface"], "'+20")
        self.assertEqual(table["anomalies"], "'-5")

    def test_no_other_domain_has_an_exempt_column(self):
        for domain in export_artifacts.EXPORT_SCHEMAS:
            if domain == "optical":
                continue
            with self.subTest(domain):
                row = dict.fromkeys(export_artifacts.EXPORT_SCHEMAS[domain],
                                    "-5")
                with tempfile.TemporaryDirectory() as directory:
                    export_artifacts.write_export(directory, domain, [row],
                                                  {}, None)
                    text = (Path(directory) / "export"
                            / f"{domain}.csv").read_text()
                self.assertEqual(
                    set(text.splitlines()[1].split(",")), {"'-5"})

    @unittest.skipUnless(shutil.which("node"), "Node.js runs the page script")
    def test_the_default_guard_is_the_guard_of_the_lldp_page(self):
        start = LLDP_HTML.index(
            "function spreadsheetSafeValue(value, blankMissing = false)")
        end = LLDP_HTML.index("function canonicalConnectionRow(connection)")
        script = (
            "const displayValue = v => v == null || ['', 'none', 'n/a']"
            ".includes(String(v).trim().toLowerCase()) ? 'N/A' "
            ": String(v).trim();\n"
            + LLDP_HTML[start:end]
            + "\nconst cells = JSON.parse(require('fs').readFileSync(0, "
              "'utf8'));\n"
              "process.stdout.write(JSON.stringify(cells.map(c => "
              "csvField(c))));")
        cells = list(self.SIGNED + self.OTHER)
        result = subprocess.run(["node", "-e", script],
                                input=json.dumps(cells), capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            dict(zip(cells, json.loads(result.stdout))),
            {cell: export_artifacts.csv_field(cell) for cell in cells})

    LLDP_REPORT = (
        "Created on 2026-07-16 10-40-03\n"
        "========== leaf-01 ==========\n"
        "Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status\n"
        "----------\n"
        "swp1 Pass spine-01 swp10 spine-01 swp10 UP\n")
    # Operator-supplied workbook text that looks like signed numbers.
    P2P_DESIGN = {"connections": [{
        "source_name": "leaf-01", "source_port": "swp1",
        "dest_name": "spine-01", "dest_port": "swp10",
        "sheet_name": "-1", "row_number": 8, "seq": "+20",
    }]}

    def test_the_headless_lldp_csv_guards_operator_text(self):
        text = lldp_export.build_csv(parse_lldp_report(self.LLDP_REPORT),
                                     p2p_design=self.P2P_DESIGN)
        lines = text.split("\r\n")
        self.assertTrue(lines[0].endswith(",P2P Sheet,P2P Line,P2P SEQ"))
        self.assertTrue(lines[1].endswith(",'-1,8,'+20"), lines[1])

    @unittest.skipUnless(shutil.which("node"), "Node.js runs the page script")
    def test_the_headless_lldp_csv_is_the_page_download_byte_for_byte(self):
        def block(start, end):
            return LLDP_HTML.split(start, 1)[1].split(end, 1)[0]
        functions = "function connectionLocationValues(connection)" + block(
            "function connectionLocationValues(connection)",
            "async function loadDeviceLocations()")
        functions += "const CSV_HEADERS" + block(
            "const CSV_HEADERS", "function renderedConnectionsInTableOrder()")
        report = parse_lldp_report(self.LLDP_REPORT)
        records = [
            dict(localDevice=row.local_device, localPort=row.local_port,
                 portStatus=row.port_status,
                 expectedDevice=row.expected_device,
                 expectedPort=row.expected_port,
                 actualDevice=row.actual_device, actualPort=row.actual_port,
                 renderedStatus=status, renderedHealth=health)
            for row, status, health in lldp_export.classified_rows(report)]
        script = """
const input = JSON.parse(require('fs').readFileSync(0,'utf8'));
const deviceLocations = {};
const deviceAliasLc = {}, portAliasLc = {};
const displayValue = v => v == null || ['', 'none', 'n/a'].includes(String(v).trim().toLowerCase()) ? 'N/A' : String(v).trim();
const aliasedLabel = (v, m) => m[displayValue(v).toLowerCase()] || displayValue(v);
const determineLLDPStatus = c => ({status:c.renderedStatus,health:c.renderedHealth});
const activeP2pDesignFor = c => c.localPort === 'swp1' ? input.design : null;
""" + functions + "\nprocess.stdout.write(buildLLDPCSV(input.records));"
        # Bytes, not text: the line ends are part of the comparison.
        result = subprocess.run(
            ["node", "-e", script],
            input=json.dumps({
                "records": records,
                "design": self.P2P_DESIGN["connections"][0]}).encode(),
            capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        page_csv = result.stdout.decode()
        self.assertIn(",'-1,8,'+20", page_csv)
        self.assertEqual(
            page_csv,
            lldp_export.build_csv(report, p2p_design=self.P2P_DESIGN))


def transceiver_block(interface, serial):
    return "\n".join([
        f"--- Interface: {interface}",
        "Interface state: up",
        fx.line("Identifier", fx.OSFP),
        fx.line("Vendor name", "ACME"),
        fx.line("Vendor PN", "PN-EXAMPLE-DR4"),
        fx.line("Vendor rev", "A3"),
        fx.line("Vendor SN", serial),
        fx.line("Connector", "0x28 (MPO 2x12)"),
    ]) + "\n"


class TransceiverModuleColumnTests(unittest.TestCase):
    BEFORE = ("device", "port", "identifier", "vendor", "part_number",
              "serial", "vendor_rev", "connector", "fw_version",
              "cable_byte130", "fw_status", "fw_status_detail")

    def test_the_column_is_appended(self):
        self.assertEqual(export_artifacts.EXPORT_SCHEMAS["transceiver"],
                         self.BEFORE + ("module",))

    def test_the_published_export_names_the_module_of_every_row(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monitor-results"
            (root / "optical-data").mkdir(parents=True)
            (root / "transceiver-data").mkdir()
            (root / "optical-data" / "leaf1_optical.txt").write_text(
                transceiver_block("swp1s0", "SN-EX-0001")
                + transceiver_block("swp1s1", "SN-EX-0001")
                + transceiver_block("swp4", "SN-EX-0004"))
            with mock.patch.object(transceiver, "_inventory_hostnames",
                                   return_value=None), \
                    contextlib.redirect_stdout(io.StringIO()):
                transceiver.process_transceiver_data(
                    str(root / "optical-data"),
                    str(root / "transceiver-data"), str(root))
            payload = json.loads(
                (root / "transceiver-export.json").read_text())
            text = (root / "transceiver-export.csv").read_text()
        self.assertEqual(payload["columns"],
                         list(self.BEFORE + ("module",)))
        self.assertEqual(
            {row["port"]: row["module"] for row in payload["rows"]},
            {"swp1s0": "leaf1/swp1/SN-EX-0001",
             "swp1s1": "leaf1/swp1/SN-EX-0001",
             "swp4": "leaf1/swp4/SN-EX-0004"})
        # Rows are per port; the column lets a reader count modules.
        self.assertEqual(payload["row_count"], 3)
        self.assertEqual(len({row["module"] for row in payload["rows"]}),
                         payload["counts"]["total_modules"])
        table = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(text.splitlines()[0],
                         ",".join(self.BEFORE + ("module",)))
        self.assertEqual([row["module"] for row in table],
                         [row["module"] for row in payload["rows"]])


class BackupMarginRangeTests(unittest.TestCase):
    """A restored notifications.yaml gets the range Setup accepts."""

    def validate(self, text):
        return backup_import.validate_config_for_bundle(
            "notifications.yaml", text.encode(), lldpq_dir=str(SCRIPT_DIR))

    @staticmethod
    def config(value):
        return ("thresholds:\n  network:\n"
                f"    optical_power_margin: {value}\n")

    def test_a_margin_outside_0_to_30_is_refused(self):
        for value in ("-10", "-0.5", "-3", "30.5", "31", "100"):
            with self.subTest(value):
                with self.assertRaises(backup_import.BackupImportError) as error:
                    self.validate(self.config(value))
                self.assertEqual(
                    str(error.exception),
                    "thresholds.network.optical_power_margin must be "
                    "between 0 and 30")

    def test_a_margin_from_0_to_30_is_accepted(self):
        for value in ("0", "3", "2.5", "30"):
            with self.subTest(value):
                self.assertTrue(self.validate(self.config(value)))

    def test_the_shipped_file_is_accepted(self):
        self.assertTrue(self.validate(
            (SCRIPT_DIR / "notifications.yaml").read_text()))


DR4_RX = [2.1, 2.2, 2.3, 2.4]
DR4_TX = [1.6, 1.7, 1.8, 1.9]


def dr4(rx=DR4_RX, **kwargs):
    kwargs.setdefault("tables", None)
    return fx.cmis(rx, DR4_TX, identifier=fx.QSFP_DD, bias=60.0, **kwargs)


def cage(dump, name="swp3", ways=4, state="up"):
    return [(f"{name}s{index}", state, dump) for index in range(ways)]


class AiIncidentListTests(OpticalFileTestCase):
    """One module of a breakout cage is one entry for the AI incident list."""

    def collected(self):
        return [(item["device"], item["port"], item["detail"])
                for item in ai_correlate._collect_optical(str(self.root))]

    def test_a_hot_module_is_one_entry(self):
        self.rows(cage(dr4(temperature=61.0)))
        self.assertEqual(self.collected(), [
            ("leaf1", "swp3s0",
             "Optical health warning (rx=2.1dBm tx=1.6dBm margin=16.1dB "
             "temp=61.0C); one module in swp3, sub-ports swp3s0, swp3s1, "
             "swp3s2, swp3s3")])

    def test_a_bad_supply_is_one_entry_and_sub_ports_are_in_numeric_order(self):
        self.rows(cage(dr4(voltage=2.9), name="swp7", ways=12))
        collected = self.collected()
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0][1], "swp7s0")
        self.assertTrue(collected[0][2].endswith(
            "; one module in swp7, sub-ports " + ", ".join(
                f"swp7s{index}" for index in range(12))), collected[0][2])
        self.assertIn("voltage=2.90V", collected[0][2])

    def test_a_lane_fault_stays_an_entry_of_its_sub_port(self):
        # Channel 3 of the module is weak: sub-port swp3s2 alone.
        self.rows(cage(dr4(fx.with_lane(DR4_RX, 3, -16.0))))
        self.assertEqual([port for _device, port, _detail in self.collected()],
                         ["swp3s2"])
        # A hot module with a weak lane: the lane's sub-port keeps its own
        # entry, the other three are the module's.
        self.rows(cage(dr4(fx.with_lane(DR4_RX, 3, -16.0), temperature=75.0)))
        collected = self.collected()
        self.assertEqual([port for _device, port, _detail in collected],
                         ["swp3s0", "swp3s2"])
        self.assertTrue(collected[0][2].endswith(
            "; one module in swp3, sub-ports swp3s0, swp3s1, swp3s3"))
        self.assertNotIn("one module", collected[1][2])

    def test_down_links_stay_per_port(self):
        # Each sub-port's link is its own, whatever the module reads.
        self.rows(cage(dr4(temperature=75.0), state="down"))
        collected = self.collected()
        self.assertEqual([port for _device, port, _detail in collected],
                         ["swp3s0", "swp3s1", "swp3s2", "swp3s3"])
        for _device, _port, detail in collected:
            self.assertNotIn("one module", detail)
            self.assertIn("temp=75.0C", detail)

    def test_unsplit_ports_and_separate_cages_are_separate_entries(self):
        self.classify(cage(dr4(temperature=61.0), ways=2)
                      + cage(dr4(temperature=61.0), name="swp4", ways=2)
                      + [("swp9", "up", dr4(temperature=61.0))])
        self.classify(cage(dr4(temperature=61.0), ways=2), hostname="leaf2")
        collected = self.collected()
        self.assertEqual(
            [(device, port) for device, port, _detail in collected],
            [("leaf1", "swp3s0"), ("leaf1", "swp4s0"), ("leaf1", "swp9"),
             ("leaf2", "swp3s0")])
        self.assertNotIn("one module", collected[2][2])

    def test_records_without_causes_stay_per_port(self):
        # A shard written before the causes were stored: nothing says the
        # state is the module's, so nothing is merged.
        self.rows(cage(dr4(temperature=61.0), ways=2))
        path = self.root / "optical-history" / "leaf1.json"
        shard = json.loads(path.read_text())
        for record in shard["current"].values():
            del record["health_causes"]
        path.write_text(json.dumps(shard))
        self.assertEqual(self.collected(), [
            ("leaf1", "swp3s0", "Optical health warning (rx=2.2dBm "
                                "tx=1.7dBm margin=16.1dB)"),
            ("leaf1", "swp3s1", "Optical health warning (rx=2.4dBm "
                                "tx=1.9dBm margin=16.3dB)")])
        for record in shard["current"].values():
            record["health_causes"] = []
        path.write_text(json.dumps(shard))
        self.assertEqual(len(self.collected()), 2)

    def test_a_single_listed_sub_port_is_not_renamed(self):
        self.rows([("swp3s0", "up", dr4(temperature=61.0))])
        collected = self.collected()
        self.assertEqual([(device, port) for device, port, _detail
                          in collected], [("leaf1", "swp3s0")])
        self.assertTrue(collected[0][2].endswith(" temp=61.0C)"),
                        collected[0][2])

    def test_damaged_causes_do_not_cost_the_domain(self):
        self.rows(cage(dr4(temperature=61.0), ways=2))
        path = self.root / "optical-history" / "leaf1.json"
        shard = json.loads(path.read_text())
        shard["current"]["leaf1:swp3s0"]["health_causes"] = [["temperature"]]
        shard["current"]["leaf1:swp3s1"]["health_causes"] = "temperature"
        path.write_text(json.dumps(shard))
        self.assertEqual([port for _device, port, _detail in self.collected()],
                         ["swp3s0", "swp3s1"])


def cable(rx, tx, bias, types=("Active Cable",)):
    """An SFP cable assembly that prints the active copper compliance line."""
    return fx.sfp(connector="0x23 (No separable connector)",
                  types=list(types), compliance=fx.ACTIVE_CU,
                  dom=(rx, tx, bias, 39.0, 3.3))


class ClassificationRuleTests(OpticalFileTestCase):
    """Copper against optical and the rules for rows without readings."""

    def test_any_one_sign_of_light_makes_a_cable_optical(self):
        cases = {
            "laser bias only": cable(None, None, 5.8),
            "transmit light only": cable(None, -1.9, 0.0),
            "receive light only": cable(-2.6, None, 0.0),
        }
        for label, dump in cases.items():
            with self.subTest(label):
                self.assertIsNotNone(self.worker.parse_optical_data(dump))
                self.assertEqual(set(self.rows([("swp1", "up", dump)])),
                                 {"swp1"})
        # No light and no bias: the active copper cable it claims to be.
        dark = cable(None, None, 0.0)
        self.assertIsNone(self.worker.parse_optical_data(dark))
        self.assertEqual(self.rows([("swp1", "up", dark)]), {})

    def test_active_optical_in_the_type_decides_without_light(self):
        # ethtool's name for the SFP56 / QSFP56 AOC codes holds no 'AOC'.
        dump = cable(None, None, 0.0, types=(
            "Active Cable",
            "Extended: Active Optical Cable with 50GAUI, 100GAUI-2 or "
            "200GAUI-4 C2M. Providing a worst BER of 10-6 or below"))
        self.assertIn("Active Cu cmplnce.", dump)
        self.assertIsNotNone(self.worker.parse_optical_data(dump))
        self.assertEqual(set(self.rows([("swp1", "up", dump)])), {"swp1"})

    def test_the_marker_and_the_indicators_are_matched_as_whole_words(self):
        # A module whose lasers are off (link down): its descriptor lines
        # alone decide.  None of these names copper.
        dark = sr4(rx=[None] * 4, tx=[None] * 4, bias=0.0)
        self.assertIsNotNone(self.worker.parse_optical_data(dark))
        for label, extra in (
                ("'dac' inside a word",
                 fx.line("Transceiver type", "Extended: Mandacom optics")),
                ("'RJ45' inside a word",
                 fx.line("Connector", "0x99 (XRJ450 family)")),
                ("a serial line", fx.line("Serial number", "DAC-RJ45-0001")),
                ("a date line", fx.line("Date code", "DAC240101"))):
            with self.subTest(label):
                self.assertIsNotNone(
                    self.worker.parse_optical_data(dark + extra + "\n"))
        # These do, also as NVUE spells them.
        for extra in (fx.line("cable-type", "Passive copper"),
                      fx.line("cable-type", "Active copper"),
                      fx.line("Transceiver type", "10G DAC"),
                      fx.line("Connector", "0x22 (RJ45)")):
            with self.subTest(extra):
                self.assertIsNone(
                    self.worker.parse_optical_data(dark + extra + "\n"))

    def test_the_optical_cable_marker_is_read_in_any_case(self):
        for marker in ("100g aoc", "100G AOC", "ACTIVE OPTICAL CABLE",
                       "active  optical cable"):
            with self.subTest(marker):
                dump = cable(None, None, 0.0, types=("Active Cable", marker))
                self.assertIsNotNone(self.worker.parse_optical_data(dump))
        # Inside a word it is no marker.
        dump = cable(None, None, 0.0, types=("Active Cable", "Xaocy"))
        self.assertIsNone(self.worker.parse_optical_data(dump))

    def test_an_unplugged_entry_is_no_optical_history(self):
        seeder = OpticalAnalyzer(str(self.root), load_history=False)
        seeder.optical_history = {"leaf1:swp1": [
            {"timestamp": 1.0, "health": "unplugged", "rx_power_dbm": None,
             "tx_power_dbm": None, "temperature_c": None},
        ]}
        self.assertTrue(seeder.save_optical_history())
        self.assertEqual(self.rows([("swp1", "down", NO_DATA)]), {})

    def test_a_temperature_alone_is_optical_history(self):
        # An UNKNOWN sample that carries a reading proves the module.
        rows = self.rows([("swp1", "up", sr4(rx=None, temperature=41.0,
                                             voltage=3.3))])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        history = self.shard()["history"]["leaf1:swp1"]
        self.assertEqual(
            [(entry["health"], entry["rx_power_dbm"], entry["tx_power_dbm"],
              entry["temperature_c"]) for entry in history],
            [("unknown", None, None, 41.0)])
        rows = self.rows([("swp1", "down", NO_DATA)])
        self.assertEqual(rows["swp1"]["health_status"], "unplugged")

    def test_no_data_is_unreadable_only_while_the_link_is_up(self):
        self.rows([("swp1", "up", sr4())])
        for state in ("unknown", "dormant", "testing"):
            with self.subTest(state):
                self.assertEqual(self.rows([("swp1", state, NO_DATA)]), {})
        rows = self.rows([("swp1", "up", NO_DATA)])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        self.assertEqual([item["type"] for item in self.anomalies()],
                         ["OPTICAL_DOM_UNREADABLE"])

    def test_a_timeout_row_has_no_finding(self):
        self.rows([("swp1", "up", sr4())])
        marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp1\n"
        rows = self.rows([("swp1", "up", marker)])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        self.assertNotIn("note", rows["swp1"])
        self.assertEqual(self.anomalies(), [])

    def test_one_dom_value_or_flag_is_enough_for_a_row(self):
        identity = [fx.line("Identifier", "0x03 (SFP)"),
                    fx.line("Connector", "0x07 (LC)"),
                    fx.line("Vendor name", "ACME")]
        cases = {
            "a bias flag": fx.line("Laser bias current low alarm", "On"),
            "a voltage": fx.line("Module voltage", fx.volts(3.3)),
            "a temperature": fx.line("Module temperature", fx.celsius(41.0)),
        }
        # A port of its own for every case: none of them has history.
        for number, (label, extra) in enumerate(cases.items(), start=1):
            with self.subTest(label):
                dump = "\n".join(identity + [extra]) + "\n"
                self.assertEqual(
                    set(self.rows([(f"swp{number}", "up", dump)])),
                    {f"swp{number}"})
        self.assertEqual(
            self.rows([("swp9", "up", "\n".join(identity) + "\n")]), {})

    def test_row_evidence_is_not_written_to_the_shard(self):
        # A row with a note, one with a side that is not monitored and a
        # link-down row: none of that evidence is persisted.
        self.rows([("swp1", "up", sr4())])
        rows = self.rows([("swp1", "up", NO_DATA),
                          ("swp2", "up", sr4(tx=[None] * 4)),
                          ("swp3", "down", sr4())])
        self.assertIn("note", rows["swp1"])
        self.assertEqual(rows["swp2"]["not_monitored"], ["tx_power"])
        self.assertEqual(rows["swp3"]["link_state"], "down")
        self.assertIn("lane_evidence", rows["swp3"])
        current = self.shard()["current"]
        self.assertEqual(sorted(current),
                         ["leaf1:swp1", "leaf1:swp2", "leaf1:swp3"])
        for port, stats in current.items():
            for key in ("note", "link_state", "not_monitored",
                        "lane_evidence"):
                self.assertNotIn(key, stats, port)
            self.assertFalse(SIDECAR_ONLY_STAT_KEYS & set(stats), port)

    def test_an_unknown_row_has_no_causes(self):
        # No power side at all; the temperature is in the generic warning
        # band, which only a graded port is held against.
        rows = self.rows([("swp1", "up", sr4(rx=None, temperature=65.0,
                                             voltage=3.3))])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        self.assertEqual(rows["swp1"]["health_causes"], [])


class ModuleFindingAndLaneColumnTests(OpticalFileTestCase):
    def test_two_conditions_of_one_module_are_two_findings(self):
        dump = fx.cmis(temperature=85.0, voltage=3.05)
        self.rows([("swp3s0", "up", dump), ("swp3s1", "up", dump)])
        named = " (one module in swp3, sub-ports swp3s0, swp3s1)"
        temperature = ("Module temperature 85.00°C is above the module's "
                       "high alarm 80.00°C" + named)
        voltage = ("Module voltage 3.0500 V is below the module's low alarm "
                   "3.1000 V" + named)
        self.assertEqual(
            [(item["type"], item["message"], item["ports"])
             for item in self.anomalies()],
            [("MODULE_TEMPERATURE_HIGH", temperature,
              ["leaf1:swp3s0", "leaf1:swp3s1"]),
             ("MODULE_VOLTAGE_LOW", voltage,
              ["leaf1:swp3s0", "leaf1:swp3s1"])])
        export = self.export_rows()
        for interface in ("swp3s0", "swp3s1"):
            self.assertEqual(
                export[interface]["anomalies"],
                f"CRITICAL: {temperature}; CRITICAL: {voltage}")
        self.assertEqual(self.parent.get_finding_counts()["critical_findings"],
                         1)

    def test_one_severity_per_finding(self):
        # Read a moment apart, one sub-port sees the module just under its
        # high alarm and the other just over it: a warning and a critical
        # finding, each on its own row.
        self.rows([("swp3s0", "up", fx.cmis(temperature=79.9)),
                   ("swp3s1", "up", fx.cmis(temperature=80.1))])
        self.assertEqual(
            [(item["severity"], item["message"], item["ports"])
             for item in self.anomalies()],
            [("warning", "Module temperature 79.90°C is above the module's "
                         "high warning 70.00°C", ["leaf1:swp3s0"]),
             ("critical", "Module temperature 80.10°C is above the module's "
                          "high alarm 80.00°C", ["leaf1:swp3s1"])])
        self.assertEqual(self.parent.get_finding_counts(), {
            "critical_findings": 1, "warning_findings": 1,
            "unplugged_modules": 0})

    def test_an_unsplit_port_is_no_cage(self):
        self.rows([("swp3", "up", fx.cmis(temperature=85.0)),
                   ("swp30", "up", fx.cmis(temperature=85.0))])
        anomalies = self.anomalies()
        self.assertEqual([item["port"] for item in anomalies],
                         ["leaf1:swp3", "leaf1:swp30"])
        for item in anomalies:
            self.assertNotIn("cage", item)
            self.assertNotIn("ports", item)
            self.assertNotIn("one module", item["message"])

    def test_a_cage_with_one_listed_sub_port_is_not_named(self):
        self.rows([("swp3s0", "up", fx.cmis(temperature=85.0))])
        self.assertEqual(self.messages(), [
            "Module temperature 85.00°C is above the module's high alarm "
            "80.00°C"])

    def test_each_side_has_its_own_lane_columns(self):
        # Transmit power is not monitored and only two bias channels are
        # printed: the three sides list different channels.
        self.rows([("swp1", "up", sr4(tx=[None] * 4, bias=[6.9, 6.7]))])
        row = self.export_rows()["swp1"]
        self.assertEqual(row["rx_lane_ids"], "1 2 3 4")
        self.assertEqual(row["tx_lane_ids"], "")
        self.assertEqual(row["bias_lane_ids"], "1 2")
        self.assertEqual(row["rx_lanes"], "-1.2 -0.9 -1.5 -1.1")
        self.assertEqual(row["tx_lanes"], "")
        self.assertEqual(row["bias_lanes"], "6.9 6.7")
        self.assertEqual(row["rx_power_lane"], 2)
        self.assertIsNone(row["tx_power_lane"])
        self.assertEqual(row["bias_current_lane"], 1)
        self.assertIsNone(row["tx_power_dbm"])
        # A breakout sub-port: every side names its own channels.
        dump = fx.cmis(bias=fx.with_lane([212.7] * 8, 7, 230.0),
                       tx=fx.with_lane(fx.TWIN_TX, 6, 4.5))
        self.rows([("swp6s0", "up", dump), ("swp6s1", "up", dump)])
        row = self.export_rows()["swp6s1"]
        self.assertEqual(row["tx_lane_ids"], "5 6 7 8")
        self.assertEqual(row["bias_lane_ids"], "5 6 7 8")
        self.assertEqual(row["tx_power_lane"], 6)
        self.assertEqual(row["bias_current_lane"], 7)


class CopperFastPathTests(OpticalFileTestCase):
    """Copper is told with a few substring tests, with the same answer."""

    COPPER = (fx.SFP_10G_DAC, fx.SFP_10G_DAC_NO_DOM_PAGE,
              fx.SFP_10G_DAC_NO_SEPARABLE, fx.SFP_10G_ACC, fx.SFP_25G_DAC,
              fx.SFP_1000BASE_T, fx.SFP_10GBASE_T, fx.QSFP_40G_DAC,
              fx.QSFP28_DAC, fx.QSFP28_DAC_WITH_SENSOR, fx.CMIS_DAC)
    OPTICAL = (fx.SFP28_AOC, fx.SFP_10G_AOC, fx.SFP_10G_SR, fx.QSFP28_SR4,
               fx.QSFP28_AOC, fx.QSFP_40G_AOC, fx.CMIS_AOC, fx.cmis())

    @staticmethod
    def names_copper_line_by_line(analyzer, dump):
        """The rule as it was written before: every line, three searches."""
        copper = False
        for text in dump.split("\n"):
            if analyzer.IDENTITY_LINE_RE.match(text):
                continue
            if analyzer.ACTIVE_OPTICAL_RE.search(text):
                return False
            copper = copper or bool(analyzer.COPPER_INDICATOR_RE.search(text))
        return copper

    def variants(self):
        for dump in self.COPPER + self.OPTICAL:
            yield dump
            yield dump.upper()
            yield dump.lower()
            yield dump.replace("Passive Cable", "Passive \t  Cable").replace(
                "Cu cmplnce", "Cu   cmplnce").replace(
                "Copper cable", "Copper\tcable")
            yield dump.replace("\n", "\r\n")
            # A vendor line that names copper, and one that names an AOC.
            yield dump + fx.line("Vendor PN", "DAC-TWINAX-RJ45") + "\n"
            yield dump + fx.line("Vendor PN", "AOC-10M") + "\n"
            # Descriptor lines that do.
            yield dump + fx.line("Transceiver type", "40G Base-CR4") + "\n"
            yield dump + fx.line("Transceiver type", "100G AOC") + "\n"
            yield (dump + fx.line("Transceiver type", "40G Base-CR4") + "\n"
                   + fx.line("Transceiver type", "Active Optical Cable")
                   + "\n")
            yield dump + fx.line("Cable", "dacron sleeve, AOCX") + "\n"

    def test_the_answer_is_the_one_of_the_line_by_line_rule(self):
        count = 0
        for dump in self.variants():
            count += 1
            self.assertEqual(
                self.worker._names_copper(dump),
                self.names_copper_line_by_line(self.worker, dump), dump)
        self.assertGreater(count, 200)

    def test_a_copper_block_is_answered_before_the_line_pass(self):
        with mock.patch.object(OpticalAnalyzer, "_lit_or_driven",
                               side_effect=AssertionError("line pass ran")):
            for dump in self.COPPER:
                self.assertIsNone(self.worker.parse_optical_data(dump))
        # A copper block that does print a number is still parsed in full,
        # with the same answer.
        with_limit = fx.QSFP28_DAC + fx.line(
            "Laser bias current high alarm threshold", "13.000 mA") + "\n"
        with mock.patch.object(OpticalAnalyzer, "_lit_or_driven",
                               return_value=False) as full:
            self.assertIsNone(self.worker.parse_optical_data(with_limit))
        self.assertEqual(full.call_count, 1)

    def test_a_reading_that_is_not_zero_sends_a_cable_to_the_full_parse(self):
        found = self.worker._prints_nonzero_reading
        for text in ("6.500 mA", "0.100 mA", "0.0001 mW", "10 mA", ".5 mA",
                     "0.6166mW", "inf mW", "1.5 MW", "x : 0.000 mA\ny : 2 mA",
                     "0.0000 mW / -inf dBm\n\t7.5\tmW", "105 mA", "1.0.5 mW"):
            with self.subTest(text):
                self.assertTrue(found(text))
        for text in ("0.000 mA", "0.0000 mW / -inf dBm", "0 mA", "3m", "4db",
                     "25500Mbps", "850.000nm", "17.00W", "0.00m",
                     "Power class : 6\n\tMax power : 17.00W",
                     "5 dBm, 0.0 mA", "mA", "mW 5"):
            with self.subTest(text):
                self.assertFalse(found(text))

    def test_only_lines_that_can_name_copper_are_searched(self):
        analyzer = self.worker
        self.assertEqual(
            list(analyzer._descriptor_lines(fx.QSFP28_SR4.lower(),
                                            analyzer.COPPER_TOKENS)),
            [fx.line("Length (Copper or Active cable)", "0m").lower()])
        self.assertEqual(
            list(analyzer._descriptor_lines(fx.cmis().lower(),
                                            analyzer.COPPER_TOKENS)), [])
        # Every alternative of the indicator holds one of the tokens.
        for text in ("passive copper", "active  copper", "copper cable",
                     "copper pigtail", "rj45", "rj-45", "passive cable",
                     "cu cmplnce", "base-cr", "base-t", "twinax", "dac"):
            with self.subTest(text):
                self.assertTrue(analyzer.COPPER_INDICATOR_RE.search(text))
                self.assertTrue(any(token in text
                                    for token in analyzer.COPPER_TOKENS))
        for text in ("aoc", "active optical", "active \t optical"):
            with self.subTest(text):
                self.assertTrue(analyzer.ACTIVE_OPTICAL_RE.search(text))
                self.assertTrue(any(token in text for token in
                                    analyzer.ACTIVE_OPTICAL_TOKENS))


if __name__ == "__main__":
    unittest.main()
