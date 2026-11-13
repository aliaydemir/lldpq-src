#!/usr/bin/env python3
"""The public optical export names the lane behind every value.

/optical/export_json and /optical/export_csv listed the lane values of a
row without their channel numbers.  A breakout sub-port does not start at
channel 1, so a script mapped the faulty value of channel 6 to "lane 2", and
nothing said which lane the headline Rx/Tx/bias value came from.  In CSV the
formula guard put an apostrophe in front of every lane list whose first
value is negative, and the anomalies cell joined its items with '; ' while
one bias message contains '; ' itself.

The schema is append-only: the six new columns are the last six.
"""

from __future__ import annotations

import csv
import io
import json
import unittest
from unittest import mock

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import OpticalFileTestCase
import export_artifacts
import process_optical_data as optical


COLUMNS_BEFORE = (
    "device", "interface", "health", "rx_power_dbm", "tx_power_dbm",
    "temperature_c", "link_margin_db", "voltage_v", "bias_current_ma",
    "rx_lanes", "tx_lanes", "bias_lanes", "anomalies", "inactive_lanes",
)
NEW_COLUMNS = (
    "rx_lane_ids", "tx_lane_ids", "bias_lane_ids",
    "rx_power_lane", "tx_power_lane", "bias_current_lane",
)
# Channel 6 receives too little; channel 6 belongs to the second sub-port.
TWIN_FAULT = fx.cmis(fx.with_lane(fx.TWIN_RX, 6, -12.5), tables=None)


class LaneIdentityTests(OpticalFileTestCase):
    def test_the_schema_grows_at_the_end_only(self):
        columns = export_artifacts.EXPORT_SCHEMAS["optical"]
        self.assertEqual(columns[:len(COLUMNS_BEFORE)], COLUMNS_BEFORE)
        self.assertEqual(columns[len(COLUMNS_BEFORE):], NEW_COLUMNS)

    def test_a_breakout_row_names_its_channels(self):
        self.rows([("swp6s0", "up", TWIN_FAULT), ("swp6s1", "up", TWIN_FAULT)])
        row = self.export_rows()["swp6s1"]
        self.assertEqual(row["rx_lanes"], "1.2 -12.5 2.2 2.4")
        self.assertEqual(row["rx_lane_ids"], "5 6 7 8")
        self.assertEqual(row["tx_lane_ids"], "5 6 7 8")
        self.assertEqual(row["bias_lane_ids"], "5 6 7 8")
        # The headline value and the channel it was read on.
        self.assertEqual(row["rx_power_dbm"], -12.5)
        self.assertEqual(row["rx_power_lane"], 6)
        self.assertEqual(row["tx_power_lane"], 8)
        self.assertIn(row["bias_current_lane"], (5, 6, 7, 8))
        # Value and channel pair up by position.
        pairs = dict(zip(row["rx_lane_ids"].split(), row["rx_lanes"].split()))
        self.assertEqual(pairs["6"], "-12.5")
        first = self.export_rows()["swp6s0"]
        self.assertEqual(first["rx_lane_ids"], "1 2 3 4")

    def test_lanes_out_of_service_are_not_among_the_ids(self):
        rx = fx.TWIN_RX[:4] + [None] * 4
        tx = fx.TWIN_TX[:4] + [None] * 4
        self.rows([("swp1", "up", fx.cmis(rx, tx, bias=[60.0] * 4 + [0.0] * 4,
                                          tables=None))])
        row = self.export_rows()["swp1"]
        self.assertEqual(row["rx_lane_ids"], "1 2 3 4")
        self.assertEqual(row["inactive_lanes"], "5 6 7 8")
        self.assertEqual(len(row["rx_lanes"].split()), 4)

    def test_a_row_without_readings_has_empty_lane_columns(self):
        self.rows([("swp9", "up", fx.QSFP28_SR4)])
        self.rows([("swp9", "down", fx.NO_DATA)])
        row = self.export_rows()["swp9"]
        self.assertEqual(row["health"], "unplugged")
        for column in ("rx_lane_ids", "tx_lane_ids", "bias_lane_ids"):
            self.assertEqual(row[column], "")
        for column in ("rx_power_lane", "tx_power_lane", "bias_current_lane"):
            self.assertIsNone(row[column])

    def test_the_rows_are_within_the_registry(self):
        self.rows([("swp6s0", "up", TWIN_FAULT), ("swp6s1", "up", TWIN_FAULT)])
        rows = list(self.export_rows().values())
        normalized = export_artifacts.normalize_rows("optical", rows)
        self.assertEqual(list(normalized[0]),
                         list(COLUMNS_BEFORE + NEW_COLUMNS))
        self.assertEqual(set(rows[0]), set(COLUMNS_BEFORE + NEW_COLUMNS))


class CsvCellTests(OpticalFileTestCase):
    def test_a_lane_list_is_not_prefixed(self):
        self.rows([("swp1", "up", fx.QSFP28_SR4)])
        rows = export_artifacts.normalize_rows(
            "optical", list(self.export_rows().values()))
        text = export_artifacts.render_csv(
            export_artifacts.EXPORT_SCHEMAS["optical"], rows,
            export_artifacts.NUMERIC_LIST_COLUMNS["optical"])
        parsed = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(parsed[0]["rx_lanes"], "-1.2 -0.9 -1.5 -1.1")
        self.assertEqual(parsed[0]["tx_lanes"], "-0.8 -0.6 -1.0 -0.9")
        self.assertEqual(parsed[0]["rx_lane_ids"], "1 2 3 4")
        self.assertEqual(
            [float(value) for value in parsed[0]["rx_lanes"].split()],
            fx.SR4_RX)
        self.assertNotIn("'", text)

    def test_numbers_signs_dots_and_blanks_are_not_guarded(self):
        # In a list-of-numbers column (the optical lane lists) only.
        for cell in ("-1.2 -0.9 -1.5", "-5", "+1.5", "-0.5 +0.5", "1 2 3",
                     "- 5", "-.5"):
            with self.subTest(cell):
                self.assertEqual(
                    export_artifacts.csv_field(cell, numeric_list=True), cell)
                self.assertEqual(
                    export_artifacts.spreadsheet_safe_value(
                        cell, numeric_list=True), cell)

    def test_everything_else_keeps_the_guard(self):
        # Also inside a list-of-numbers column: the exemption is for cells
        # that hold nothing but numbers.
        for cell in ("=1+1", "+SUM(A1)", "-1+cmd", "@cmd", "-", "+", "- -",
                     "-5a", "-1e3", "=5", "-5|6", "+1,2", "@5", "-5\t6",
                     "-1 @2"):
            for numeric_list in (False, True):
                with self.subTest(cell, numeric_list=numeric_list):
                    self.assertTrue(
                        export_artifacts.csv_field(cell, numeric_list)
                        .lstrip('"').startswith("'"), cell)

    def test_a_very_long_cell_keeps_the_guard(self):
        cell = "-" + "1 " * 200_000 + "x"
        self.assertEqual(
            export_artifacts.spreadsheet_safe_value(cell, numeric_list=True),
            "'" + cell)


class AnomalyCellTests(OpticalFileTestCase):
    def test_the_cell_splits_back_into_its_items(self):
        # Three findings on one row; the bias message holds two semicolons.
        dump = fx.cmis(fx.with_lane(fx.TWIN_RX, 2, -16.0),
                       bias=fx.with_lane([212.7] * 8, 4, 405.0),
                       flags={(4, "high_alarm"): True}, temperature=85.0)
        self.rows([("swp1", "up", dump)])
        messages = self.messages()
        self.assertEqual(len(messages), 3)
        self.assertTrue(any(";" in message for message in messages))
        cell = self.export_rows()["swp1"]["anomalies"]
        items = cell.split("; ")
        self.assertEqual(len(items), 3)
        self.assertEqual(items, [
            "CRITICAL: Laser bias lane 4: 405.000 mA, module high alarm "
            "threshold: 400.000 mA, module flag is On",
            "CRITICAL: RX power -16.00 dBm on lane 2 is below the module's "
            "low alarm -8.40 dBm",
            "CRITICAL: Module temperature 85.00°C is above the module's high "
            "alarm 80.00°C",
        ])
        self.assertEqual(cell.count(";"), 2)
        for item in items:
            severity, _separator, message = item.partition(": ")
            self.assertIn(severity, ("CRITICAL", "WARNING"))
            self.assertTrue(message)

    def test_the_page_keeps_the_message_as_it_is(self):
        self.rows([("swp1", "up", fx.cmis(
            bias=fx.with_lane([212.7] * 8, 4, 405.0),
            flags={(4, "high_alarm"): True}))])
        _page, details = self.publish()
        self.assertEqual(
            [item["message"] for item in details["leaf1:swp1"]["anomalies"]],
            ["Laser bias lane 4: 405.000 mA; module high alarm threshold: "
             "400.000 mA; module flag is On"])


class PublishedExportTests(OpticalFileTestCase):
    """The files /optical/export_json and /optical/export_csv serve."""

    def test_json_and_csv_written_by_the_real_run(self):
        data_dir = self.root / "optical-data"
        (data_dir / "leaf1_optical.txt").write_text(fx.device_file([
            ("swp1", "up", fx.QSFP28_SR4),
            ("swp2", "up", fx.SFP_10G_DAC),
            ("swp3", "up", fx.QSFP28_AOC),
            ("swp6s0", "up", TWIN_FAULT),
            ("swp6s1", "up", TWIN_FAULT),
        ]))
        snapshot = ({"leaf1": "OK"}, 0.0, True)
        with mock.patch.object(optical, "read_asset_snapshot",
                               return_value=snapshot), \
                mock.patch.object(optical, "asset_snapshot_is_valid",
                                  return_value=True), \
                mock.patch.object(optical, "is_current_collection",
                                  return_value=True), \
                mock.patch.dict("os.environ",
                                {"OPTICAL_PARSE_MAX_PARALLEL": "1"}), \
                mock.patch("builtins.print"):
            self.assertTrue(optical.process_optical_data_files(str(data_dir)))

        payload = json.loads((self.root / "export" / "optical.json").read_text())
        self.assertEqual(payload["columns"],
                         list(COLUMNS_BEFORE + NEW_COLUMNS))
        rows = {row["interface"]: row for row in payload["rows"]}
        # The copper cable is no optical port; the optical cable is one.
        self.assertEqual(set(rows), {"swp1", "swp3", "swp6s0", "swp6s1"})
        self.assertEqual(rows["swp6s1"]["rx_lane_ids"], "5 6 7 8")
        self.assertEqual(rows["swp6s1"]["rx_power_lane"], 6)
        self.assertEqual(payload["counts"]["unknown"], 0)

        text = (self.root / "export" / "optical.csv").read_text()
        table = {row["interface"]: row
                 for row in csv.DictReader(io.StringIO(text))}
        self.assertEqual(text.splitlines()[0],
                         ",".join(COLUMNS_BEFORE + NEW_COLUMNS))
        self.assertEqual(table["swp1"]["rx_lanes"], "-1.2 -0.9 -1.5 -1.1")
        self.assertEqual(table["swp6s1"]["rx_lane_ids"], "5 6 7 8")
        self.assertEqual(table["swp6s1"]["rx_power_lane"], "6")


if __name__ == "__main__":
    unittest.main()
