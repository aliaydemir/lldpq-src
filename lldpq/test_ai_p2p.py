#!/usr/bin/env python3
"""Tests for the P2P cabling-design workbook parser (html/ai_p2p.py)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_p2p  # noqa: E402

SFERICAL_XLSX = Path(
    "/Users/ali/Downloads/Sferical AI P2P v2.4_2_1_pwr_shlvs_moved-PNY-BNDL_w_bndl_checker.xlsx"
)
IRIS_XLSM = Path("/Users/ali/Works/G42-DC/P2P_C42_Iris_v1.3.xlsm")


# ---------------------------------------------------------------------------
# Synthetic mini-xlsx fixture builder (zipfile + hand-rolled sheet XML)
# ---------------------------------------------------------------------------

def _col_letter(idx):
    letters = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        letters = chr(ord("A") + rem) + letters
    return letters


def build_xlsx(path, sheets, string_mode="shared"):
    """Write a minimal xlsx. `sheets` is [(name, rows)]; rows are lists whose
    None entries are omitted entirely (sparse cells rely on r= references).
    Numeric python values become number cells; strings become shared or
    inline string cells depending on `string_mode`."""
    shared = []
    shared_index = {}

    def cell_xml(ref, value):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return '<c r="%s"><v>%s</v></c>' % (ref, value)
        text = str(value)
        if string_mode == "inline":
            return '<c r="%s" t="inlineStr"><is><t>%s</t></is></c>' % (ref, escape(text))
        if text not in shared_index:
            shared_index[text] = len(shared)
            shared.append(text)
        return '<c r="%s" t="s"><v>%d</v></c>' % (ref, shared_index[text])

    sheet_xmls = []
    for _name, rows in sheets:
        parts = ['<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>']
        for row_num, row in enumerate(rows, start=1):
            cells = []
            for col_idx, value in enumerate(row):
                if value is None:
                    continue  # sparse: cell entirely absent from the XML
                cells.append(cell_xml("%s%d" % (_col_letter(col_idx), row_num), value))
            parts.append('<row r="%d">%s</row>' % (row_num, "".join(cells)))
        parts.append("</sheetData></worksheet>")
        sheet_xmls.append("".join(parts))

    with zipfile.ZipFile(path, "w") as zf:
        sheet_tags = []
        rel_tags = []
        for i, (name, _rows) in enumerate(sheets, start=1):
            sheet_tags.append(
                '<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(name, {'"': "&quot;"}), i, i)
            )
            rel_tags.append(
                '<Relationship Id="rId%d" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                'Target="worksheets/sheet%d.xml"/>' % (i, i)
            )
        zf.writestr(
            "xl/workbook.xml",
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            "<sheets>%s</sheets></workbook>" % "".join(sheet_tags),
        )
        zf.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s'
            "</Relationships>" % "".join(rel_tags),
        )
        if shared:
            items = "".join("<si><t>%s</t></si>" % escape(s) for s in shared)
            zf.writestr(
                "xl/sharedStrings.xml",
                '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" '
                'uniqueCount="%d">%s</sst>' % (len(shared), len(shared), items),
            )
        for i, xml in enumerate(sheet_xmls, start=1):
            zf.writestr("xl/worksheets/sheet%d.xml" % i, xml)


# Split two-row header with prefix columns (Sferical family), 'nae' typo on
# the dest name header and float artifacts in numeric cells.
PREFIXED_SHEET_ROWS = [
    [None, None, None, None, "Source", None, None, None, None, "Dest",
     None, None, None, None, None, None, "label", "source"],
    ["MVP", "Bundle_ID", "SEQ", None, "rack", "U", "name", "HCA/port", "Transceiver",
     "rack", "U", "nae", "port", "Transceiver", "Cable Length", "Cable Type", "hostname", "Rack U Port"],
    ["Y", "00337 - 1R7->1R7", 2885, None, "1R7", 31.0, "CLEAF-01", "41/1", "MMA4Z00-NS-T",
     "1R7", 37.0, "SPINE-01", "1/1", "MMA4Z00-NS-T", 7.0, "MFP7E10-N07", "CLEAF-01", "1R7_31_41/1"],
    # merged bundle cell (empty) + sparse rack cells -> forward fill, r= alignment
    ["Y", None, 2886, None, "1R7", 31.0, "CLEAF-01", "41/2", "N/A",
     "1R7", 37.0, "SPINE-01", "1/2", "N/A", 7.0, "MFP7E10-N07", "CLEAF-01", "1R7_31_41/2"],
    # duplicate of row 3 in reverse direction (dedup check for expected_links)
    ["Y", None, 2887, None, "1R7", 37.0, "SPINE-01", "1/1", "MMA4Z00-NS-T",
     "1R7", 31.0, "CLEAF-01", "41/1", "MMA4Z00-NS-T", 7.0, "MFP7E10-N07", "SPINE-01", "1R7_37_1/1"],
]

# Split two-row header without prefix columns (Iris OOB family), includes a
# bmc row inside a compute-named sheet and tbd/customer-provided peers.
PLAIN_SHEET_ROWS = [
    ["SOURCE", None, None, None, "DESTINATION", None, None, None, None, None],
    ["RACK", "U", "NAME", "HCA/PORT", "RACK", "U", "NAME", "PORT", "CABLE LENGTH", "CABLE TYPE"],
    ["P1-C-01", 6, "p1-xdr-r1-leaf1", "bmc", "P1-C-01", 46, "p1-oob-gpu-leaf33", 1, None, "CAT6 CABLE"],
    ["P1-A-01", 11, "P1-GPU-A01ru11", 1, "P1-C-01", 6, "p1-xdr-r1-leaf1", "1/1", 10.0, "SMF MPO12 APC"],
    ["P1-A-01", 11, "P1-GPU-A01ru11", 2, "TBD", "TBD", "tbd", "TBD", None, None],
    ["P1-A-01", 12, "P1-GPU-A01ru12", 1, None, None, "Customer-provided router", "TBD", None, None],
    [None, None, None, None, None, None, None, None, None, None],
]

BOM_SHEET_ROWS = [
    ["Bill of Materials"],
    ["Part Number", "Description", "Qty"],
    ["MFP7E10-N07", "Fiber cable 7m", 42],
]


def build_fixture(path, string_mode="shared"):
    build_xlsx(
        path,
        [
            ("BOM", BOM_SHEET_ROWS),
            ("COMPUTE FABRIC", [["COMPUTE FABRIC SECTION"]]),
            ("SU1-GB300-LEAF", PLAIN_SHEET_ROWS),
            ("Converged Ethernet", [["Converged Ethernet"]]),
            ("CLeaf to Spine", PREFIXED_SHEET_ROWS),
        ],
        string_mode=string_mode,
    )


class WorkbookReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "mini.xlsx"

    def test_read_workbook_shared_strings_numbers_and_sparse_cells(self):
        build_fixture(self.path)
        book = ai_p2p.read_workbook(self.path)
        self.assertEqual(
            list(book),
            ["BOM", "COMPUTE FABRIC", "SU1-GB300-LEAF", "Converged Ethernet", "CLeaf to Spine"],
        )
        rows = book["CLeaf to Spine"]
        # sparse cell (index 3 omitted from XML) must stay aligned via r= refs
        self.assertEqual(rows[1][2], "SEQ")
        self.assertIsNone(rows[1][3])
        self.assertEqual(rows[1][4], "rack")
        self.assertEqual(rows[2][6], "CLEAF-01")
        self.assertEqual(rows[2][5], "31.0")  # raw float artifact preserved by reader

    def test_read_workbook_inline_strings(self):
        build_fixture(self.path, string_mode="inline")
        book = ai_p2p.read_workbook(self.path)
        self.assertEqual(book["CLeaf to Spine"][2][6], "CLEAF-01")
        self.assertEqual(book["SU1-GB300-LEAF"][1][2], "NAME")


class HeaderSniffTest(unittest.TestCase):
    def test_prefixed_split_header_is_sniffed_with_typo_tolerance(self):
        idx, col_map = ai_p2p.sniff_header(PREFIXED_SHEET_ROWS)
        self.assertEqual(idx, 1)
        self.assertEqual(col_map["source_rack"], 4)
        self.assertEqual(col_map["source_name"], 6)
        self.assertEqual(col_map["source_port"], 7)   # 'HCA/port'
        self.assertEqual(col_map["dest_name"], 11)    # 'nae' typo
        self.assertEqual(col_map["dest_port"], 12)
        self.assertEqual(col_map["cable_length"], 14)
        self.assertEqual(col_map["cable_type"], 15)
        self.assertEqual(col_map["seq"], 2)
        self.assertEqual(col_map["bundle_id"], 1)
        # helper columns after the dest section must not leak into the map
        self.assertNotIn(16, col_map.values())
        self.assertNotIn(17, col_map.values())

    def test_plain_split_header_without_prefix_columns(self):
        idx, col_map = ai_p2p.sniff_header(PLAIN_SHEET_ROWS)
        self.assertEqual(idx, 1)
        self.assertEqual(col_map["source_rack"], 0)
        self.assertEqual(col_map["source_port"], 3)
        self.assertEqual(col_map["dest_rack"], 4)
        self.assertEqual(col_map["dest_port"], 7)
        self.assertEqual(col_map["cable_length"], 8)
        self.assertNotIn("source_transceiver", col_map)

    def test_flat_single_row_header(self):
        rows = [
            ["Cable#", "SEQ", "SourceRack", "SourceRU", "SourceHostname",
             "Source Customer Name_lowercase", "SourcePhysicalPort", "SourceTransceiver",
             "DestRack", "DestRU", "DestHostname", "DestPhysicalPort", "DestTransceiver",
             "CableLength", "CablePartNo"],
        ]
        idx, col_map = ai_p2p.sniff_header(rows)
        self.assertEqual(idx, 0)
        self.assertEqual(col_map["source_name"], 4)  # not the customer-name column
        self.assertEqual(col_map["source_port"], 6)
        self.assertEqual(col_map["dest_name"], 10)
        self.assertEqual(col_map["cable_length"], 13)
        self.assertEqual(col_map["cable_part"], 14)

    def test_non_data_tab_fails_the_sniff(self):
        idx, col_map = ai_p2p.sniff_header(BOM_SHEET_ROWS)
        self.assertEqual(idx, -1)
        self.assertEqual(col_map, {})


class ParseWorkbookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fixture.xlsx"
        build_fixture(self.path)
        self.result = ai_p2p.parse_workbook(self.path)

    def _sheet(self, name):
        return [r for r in self.result["connections"] if r["sheet_name"] == name]

    def test_top_level_shape(self):
        for key in ("format", "source_file", "generated_at", "total_connections",
                    "connections", "skipped_sheets", "warnings"):
            self.assertIn(key, self.result)
        self.assertEqual(self.result["source_file"], "fixture.xlsx")
        self.assertEqual(self.result["total_connections"], len(self.result["connections"]))

    def test_non_data_tabs_are_skipped_naturally(self):
        self.assertEqual(
            self.result["skipped_sheets"],
            ["BOM", "COMPUTE FABRIC", "Converged Ethernet"],
        )

    def test_canonical_record_mapping_and_float_cleanup(self):
        records = self._sheet("CLeaf to Spine")
        first = records[0]
        self.assertEqual(first["source_rack"], "1R7")
        self.assertEqual(first["source_ru"], "31")           # 31.0 -> 31
        self.assertEqual(first["source_name"], "CLEAF-01")
        self.assertEqual(first["source_port"], "41/1")
        self.assertEqual(first["source_transceiver"], "MMA4Z00-NS-T")
        self.assertEqual(first["dest_name"], "SPINE-01")
        self.assertEqual(first["dest_port"], "1/1")
        self.assertEqual(first["cable_length"], "7")         # 7.0 -> 7
        self.assertEqual(first["cable_type"], "MFP7E10-N07")
        self.assertEqual(first["seq"], "2885")
        self.assertEqual(first["bundle_id"], "00337 - 1R7->1R7")
        self.assertEqual(first["row_number"], 3)

    def test_bundle_id_forward_fill_across_merged_rows(self):
        records = self._sheet("CLeaf to Spine")
        self.assertEqual(records[1]["seq"], "2886")
        self.assertEqual(records[1]["bundle_id"], "00337 - 1R7->1R7")

    def test_network_classification_uses_sheet_name_and_section(self):
        compute = self._sheet("SU1-GB300-LEAF")
        gpu_rows = [r for r in compute if r["source_port"] not in ("bmc",)]
        self.assertTrue(all(r["network_type"] == "ib" for r in gpu_rows))
        self.assertTrue(all(r["connection_type"] == "compute" for r in gpu_rows))
        converged = self._sheet("CLeaf to Spine")
        self.assertTrue(all(r["network_type"] == "eth" for r in converged))
        self.assertTrue(all(r["connection_type"] == "converged" for r in converged))

    def test_bmc_rows_are_never_classified_as_compute(self):
        bmc = [r for r in self._sheet("SU1-GB300-LEAF") if r["source_port"] == "bmc"]
        self.assertEqual(len(bmc), 1)
        self.assertEqual(bmc[0]["connection_type"], "oob")
        self.assertEqual(bmc[0]["network_type"], "eth")

    def test_unresolved_rows_kept_with_warning_flag(self):
        records = self._sheet("SU1-GB300-LEAF")
        unresolved = [r for r in records if r.get("unresolved")]
        self.assertEqual(len(unresolved), 2)
        peers = {r["dest_name"] for r in unresolved}
        self.assertEqual(peers, {"tbd", "Customer-provided router"})
        self.assertTrue(any("unresolved" in w for w in self.result["warnings"]))

    def test_lookup_is_case_and_port_format_tolerant(self):
        hits = ai_p2p.lookup(self.result, "cleaf-01", port="swp41s0")  # == 41/1
        # the fixture has the row plus its reversed duplicate: both must match
        self.assertEqual(len(hits), 2)
        for hit in hits:
            self.assertEqual(hit["peer_device"], "SPINE-01")
            self.assertEqual(hit["peer_port"], "1/1")
            self.assertEqual(hit["cable_type"], "MFP7E10-N07")
            self.assertEqual(hit["cable_length"], "7")
            self.assertEqual(hit["network_type"], "eth")
        # device-only lookup returns every design row touching the device
        self.assertEqual(len(ai_p2p.lookup(self.result, "CLEAF-01")), 3)

    def test_expected_links_dedupes_and_excludes_unresolved(self):
        links = ai_p2p.expected_links(self.result)
        pairs = {(l["a_dev"], l["a_port"], l["b_dev"], l["b_port"]) for l in links}
        # reversed duplicate row collapsed into one link
        self.assertEqual(len([p for p in pairs if "CLEAF-01" in (p[0], p[2]) and "41/1" in (p[1], p[3])]), 1)
        # unresolved tbd/customer rows are excluded from link truth
        for link in links:
            self.assertNotIn("tbd", (link["a_dev"].lower(), link["b_dev"].lower()))
            self.assertNotIn("Customer-provided router", (link["a_dev"], link["b_dev"]))
        ib_links = ai_p2p.expected_links(self.result, network_type="ib")
        self.assertTrue(ib_links)
        self.assertTrue(all(l["meta"]["network_type"] == "ib" for l in ib_links))
        self.assertTrue(all("meta" in l for l in links))

    def test_inline_string_workbook_parses_identically(self):
        path = Path(self.tmp.name) / "inline.xlsx"
        build_fixture(path, string_mode="inline")
        result = ai_p2p.parse_workbook(path)
        self.assertEqual(result["total_connections"], self.result["total_connections"])
        self.assertEqual(
            [r["source_name"] for r in result["connections"]],
            [r["source_name"] for r in self.result["connections"]],
        )


class ArtifactJsonIngestionTest(unittest.TestCase):
    ARTIFACT = {
        "format": "generic",
        "source_file": "example.xlsx",
        "total_connections": 2,
        "connections_by_type": {
            "cl-cs": [
                {
                    "source_rack": "1R7", "source_ru": "31", "source_name": "CLEAF-01",
                    "source_port": "41/1", "source_transceiver": "MMA4Z00-NS-T",
                    "dest_rack": "1R7", "dest_ru": "37", "dest_name": "SPINE-01",
                    "dest_port": "1/1", "cable_length": "7",
                    "sheet_name": "CLeaf to Spine", "network_type": "eth", "row_number": 3,
                },
            ],
            "oob": [
                {
                    "source_name": "OOB-SW-01", "source_port": "1",
                    "dest_name": "tbd", "dest_port": "TBD",
                    "sheet_name": "Other OOB", "network_type": "eth", "row_number": 9,
                },
            ],
        },
    }

    def test_connections_by_type_layout_is_normalized(self):
        result = ai_p2p.load_connections(self.ARTIFACT)
        self.assertEqual(result["total_connections"], 2)
        by_name = {r["source_name"]: r for r in result["connections"]}
        rec = by_name["CLEAF-01"]
        self.assertEqual(rec["connection_type"], "cl-cs")  # taken from the dict key
        self.assertEqual(rec["dest_transceiver"], "")      # missing key filled
        self.assertEqual(rec["cable_length"], "7")
        self.assertTrue(by_name["OOB-SW-01"].get("unresolved"))
        links = ai_p2p.expected_links(result)
        self.assertEqual(len(links), 1)

    def test_artifact_json_file_and_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "connections.json"
            path.write_text(json.dumps(self.ARTIFACT), encoding="utf-8")
            from_file = ai_p2p.load_connections(str(path))
        from_string = ai_p2p.load_connections(json.dumps(self.ARTIFACT))
        self.assertEqual(from_file["total_connections"], 2)
        self.assertEqual(from_string["total_connections"], 2)
        self.assertEqual(
            ai_p2p.lookup(from_file, "spine-01", port="swp1s0")[0]["peer_device"],
            "CLEAF-01",
        )

    def test_canonical_dict_round_trips(self):
        canonical = ai_p2p.load_connections(self.ARTIFACT)
        again = ai_p2p.load_connections(canonical)
        self.assertEqual(again["total_connections"], canonical["total_connections"])

    def test_load_connections_rejects_unknown_layouts(self):
        with self.assertRaises(ValueError):
            ai_p2p.load_connections({"foo": "bar"})


class RealWorkbookIntegrationTest(unittest.TestCase):
    """Runs only when the real validation workbooks are present (CI safety)."""

    def test_sferical_workbook(self):
        if not SFERICAL_XLSX.exists():
            self.skipTest("Sferical validation workbook not available")
        result = ai_p2p.parse_workbook(SFERICAL_XLSX)
        self.assertGreater(result["total_connections"], 1000)
        sheets = {r["sheet_name"] for r in result["connections"]}
        self.assertIn("CLeaf to Spine", sheets)
        self.assertIn("GB300 & UFM to CL", sheets)
        # design-truth spot check: CLEAF-01 41/1 <-> SPINE-01 1/1
        rows = [
            r for r in result["connections"]
            if r["sheet_name"] == "CLeaf to Spine"
            and r["source_name"] == "CLEAF-01" and r["source_port"] == "41/1"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dest_name"], "SPINE-01")
        self.assertEqual(rows[0]["dest_port"], "1/1")
        # lookup wiring against the same fabric
        hits = ai_p2p.lookup(result, "CLEAF-01", port="swp41s0")
        self.assertTrue(any(h["peer_device"] == "SPINE-01" and h["peer_port"] == "1/1" for h in hits))
        # non-data tabs skipped naturally
        for name in ("Change Log", "Floor plan", "Naming Convention"):
            self.assertIn(name, result["skipped_sheets"])

    def test_iris_workbook(self):
        if not IRIS_XLSM.exists():
            self.skipTest("Iris validation workbook not available")
        result = ai_p2p.parse_workbook(IRIS_XLSM)
        self.assertGreater(result["total_connections"], 1000)
        sheets = {r["sheet_name"] for r in result["connections"]}
        self.assertIn("CLEAF - CSPINE", sheets)
        self.assertIn("OOB", sheets)
        oob = [r for r in result["connections"] if r["sheet_name"] == "OOB"]
        self.assertTrue(all(r["network_type"] == "eth" for r in oob))
        # Power-shelf rows inside the OOB sheet are power-plane intent, not
        # OOB switching fabric; everything else must stay oob.
        self.assertTrue(all(r["connection_type"] in ("oob", "power") for r in oob))
        power = [r for r in oob if r["connection_type"] == "power"]
        self.assertTrue(power)
        self.assertTrue(all(
            "pwrshelf" in (r["source_name"] + r["dest_name"]).lower()
            for r in power
        ))
        for name in ("BOM", "FLOOR PLAN", "HOSTNAMES", "PORT MAPPING"):
            self.assertIn(name, result["skipped_sheets"])

    def test_sferical_matches_reference_artifact_scale(self):
        reference = Path("/Users/ali/Repo/p2p-parser/p2p-examples/sferical/connections.json")
        if not SFERICAL_XLSX.exists() or not reference.exists():
            self.skipTest("Sferical workbook or reference artifact not available")
        mine = ai_p2p.parse_workbook(SFERICAL_XLSX)
        ref = ai_p2p.load_connections(str(reference))
        self.assertGreater(ref["total_connections"], 0)
        ratio = mine["total_connections"] / ref["total_connections"]
        self.assertGreater(ratio, 0.8)
        self.assertLess(ratio, 1.2)


if __name__ == "__main__":
    unittest.main()
