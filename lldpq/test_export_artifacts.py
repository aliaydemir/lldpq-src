#!/usr/bin/env python3
"""Public export contract tests.

Covers the shared exporter (schema registry, CSV semantics incl. the
spreadsheet-formula guard, atomic 0664 publication with sidecars), the LLDP
export's byte-parity with lldp.html's Download CSV (golden file over every
classification branch), and monitor.sh's transaction contract for the new
export artifacts (legacy_v5 snapshot recovery, per-scope validation and
overlay coverage).

The LLDP byte-parity is two-sided, because the page's Download CSV follows
its "P2P" display-alias toggle: the toggle-off download is pinned against
GOLDEN_CSV / no query parameter, and the toggle-on download against
GOLDEN_ALIASED_CSV / ?p2p=1.  Both goldens run through the real CGI as well,
so the shell that parses the parameter and loads display-aliases.json is
covered end to end and not just the library underneath it.
"""

import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(ROOT / "html"))

import analysis_sidecar
import export_artifacts
import lldp_export
from lldp_report import parse_lldp_report

MONITOR = SCRIPT_DIR / "monitor.sh"
CONFIG_HELPER = ROOT / "bin" / "lldpq-config"
LLDP_EXPORT_CGI = ROOT / "html" / "lldp-export-api.sh"
EXPORT_CGIS = tuple(
    ROOT / "html" / name
    for name in ("export-api.sh", "lldp-export-api.sh", "ai-export-api.sh")
)
NGINX_SITE = ROOT / "etc/nginx/sites-available/lldpq"
LLDP_HTML = (ROOT / "html/lldp.html").read_text(encoding="utf-8")
LLDP_EXPORT_API = (ROOT / "html/lldp-export-api.sh").read_text(encoding="utf-8")

# Domains that existed when the export feature landed (legacy_v6 boundary).
LEGACY_EXPORT_DOMAIN_FILES = tuple(
    f"export/{domain}.{suffix}"
    for domain in (
        "bgp", "evpn-mh", "duplicate", "flap", "optical",
        "ber", "pfc-ecn", "hardware", "log",
    )
    for suffix in ("json", "csv")
)
EXPORT_DOMAIN_FILES = LEGACY_EXPORT_DOMAIN_FILES + tuple(
    f"export/{domain}.{suffix}"
    for domain in ("config-drift", "routes", "fabric-check")
    for suffix in ("json", "csv")
)
# Everything the config-drift/routes/fabric-check analyzers added on top of
# the legacy_v6 schema (which itself is legacy_v5 + the legacy export files).
NEW_ANALYZER_ARTIFACTS = (
    "config-drift-analysis.html", "config_drift_history.json",
    "config-drift-data/",
    "routes-analysis.html", "routes_events.json", "routes-history/",
    "fabric-check-analysis.html",
    "summary/config-drift-summary.json", "summary/routes-summary.json",
    "summary/fabric-check-summary.json",
    "export/config-drift.json", "export/config-drift.csv",
    "export/routes.json", "export/routes.csv",
    "export/fabric-check.json", "export/fabric-check.csv",
)

# Added when the BER history was sharded per device and the optical detail
# sidecars were split out of the report page.
SHARD_ERA_ARTIFACTS = ("ber-history/", "optical-details/")


class SchemaRegistryTests(unittest.TestCase):
    def test_unknown_domain_rejected(self):
        with self.assertRaises(export_artifacts.ExportContractError):
            export_artifacts.normalize_rows("nope", [])

    def test_unknown_row_key_rejected(self):
        with self.assertRaises(export_artifacts.ExportContractError):
            export_artifacts.normalize_rows(
                "flap", [{"device": "d", "bogus_column": 1}]
            )

    def test_missing_keys_become_none_in_column_order(self):
        rows = export_artifacts.normalize_rows("flap", [{"device": "leaf-01"}])
        self.assertEqual(
            list(rows[0]), list(export_artifacts.EXPORT_SCHEMAS["flap"])
        )
        self.assertEqual(rows[0]["device"], "leaf-01")
        self.assertIsNone(rows[0]["total_transitions"])

    def test_content_coercion_never_raises(self):
        row = {
            "device": ["a", "b"],          # list -> space-joined
            "interface": float("nan"),      # NaN -> None (strict JSON)
            "status": Path("x"),            # arbitrary object -> str
            "flaps_24h": True,              # bool passes through
        }
        normalized = export_artifacts.normalize_rows("flap", [row])[0]
        self.assertEqual(normalized["device"], "a b")
        self.assertIsNone(normalized["interface"])
        self.assertEqual(normalized["status"], "x")
        self.assertIs(normalized["flaps_24h"], True)


class CsvSemanticsTests(unittest.TestCase):
    """Ports of displayValue/spreadsheetSafeValue/csvField (lldp.html)."""

    def test_missing_sentinels(self):
        for value in (None, "", "  ", "none", "N/A", "n/a"):
            self.assertEqual(export_artifacts.display_value(value), "N/A")

    def test_formula_injection_guard(self):
        self.assertEqual(export_artifacts.csv_field("=1+1"), "'=1+1")
        self.assertEqual(export_artifacts.csv_field("@cmd"), "'@cmd")
        self.assertEqual(export_artifacts.csv_field("+x"), "'+x")
        # Leading whitespace is trimmed first (JS String.trim in displayValue),
        # so the guard prefixes the trimmed text.
        self.assertEqual(export_artifacts.csv_field(" =x"), "'=x")

    def test_numeric_cells_are_never_formula_guarded(self):
        # Real numbers are not injection vectors; guarding them corrupts
        # negative telemetry (optical dBm, deltas) into strings.
        self.assertEqual(export_artifacts.csv_field(-5), "-5")
        self.assertEqual(export_artifacts.csv_field(-3.51), "-3.51")
        self.assertEqual(export_artifacts.csv_field(0), "0")
        # Untrusted text that merely looks numeric stays guarded.
        self.assertEqual(export_artifacts.csv_field("-5"), "'-5")

    def test_quoting(self):
        self.assertEqual(export_artifacts.csv_field("a,b"), '"a,b"')
        self.assertEqual(export_artifacts.csv_field('he"y'), '"he""y"')
        self.assertEqual(export_artifacts.csv_field("plain"), "plain")

    def test_render_csv_crlf_and_order(self):
        text = export_artifacts.render_csv(
            ("device", "status"),
            [{"device": "leaf-01", "status": None}],
        )
        self.assertEqual(text, "device,status\r\nleaf-01,N/A\r\n")

    def test_booleans_render_json_spelled(self):
        # JSON true/false <-> CSV 'true'/'false' (not Python's str(True));
        # JSON null <-> CSV 'N/A' stays as-is for existing consumers.
        self.assertEqual(export_artifacts.display_value(True), "true")
        self.assertEqual(export_artifacts.display_value(False), "false")
        self.assertEqual(export_artifacts.csv_field(True), "true")
        self.assertEqual(export_artifacts.csv_field(False), "false")
        text = export_artifacts.render_csv(
            ("esi", "orphan"),
            [{"esi": "es-1", "orphan": True}, {"esi": "es-2", "orphan": False}],
        )
        self.assertEqual(text, "esi,orphan\r\nes-1,true\r\nes-2,false\r\n")


class HttpExportContractTests(unittest.TestCase):
    def test_dynamic_405_advertises_allowed_methods(self):
        environment = dict(os.environ)
        environment["REQUEST_METHOD"] = "POST"
        for script in EXPORT_CGIS:
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["bash", str(script)],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                headers, body = result.stdout.split("\n\n", 1)
                self.assertIn("Status: 405 Method Not Allowed", headers)
                self.assertIn("Allow: GET, HEAD", headers)
                self.assertIn("Cache-Control: no-store", headers)
                payload = json.loads(body)
                self.assertFalse(payload["success"])

    def test_static_export_cache_header_applies_to_missing_artifacts(self):
        source = NGINX_SITE.read_text(encoding="utf-8")
        export_section = source.split(
            "# ── Public machine-readable exports", 1
        )[1]
        cache_line = (
            'add_header Cache-Control '
            '"no-store, no-cache, must-revalidate, max-age=0" always;'
        )
        # monitor JSON/CSV + transceiver JSON/CSV
        self.assertEqual(export_section.count(cache_line), 4)

    def test_gzip_covers_reports_and_exports_but_not_binary_fallback(self):
        source = NGINX_SITE.read_text(encoding="utf-8")
        self.assertIn("gzip on;", source)
        gzip_types_line = next(
            line.strip() for line in source.splitlines()
            if line.strip().startswith("gzip_types ")
        )
        for mime in ("text/plain", "text/csv", "application/json"):
            self.assertIn(mime, gzip_types_line)
        # Provisioning serves multi-GB OS images (*.bin/*.img/*.iso and the
        # extensionless onie-installer aliases) statically as octet-stream;
        # on-the-fly gzip would throttle those downloads to compression speed
        # and break byte-range resume. Never compress the fallback type.
        self.assertNotIn("application/octet-stream", gzip_types_line)
        # .ini reports (lldp_results.ini, hstr/) have no mime.types mapping;
        # they only compress because this location maps them to text/plain.
        self.assertIn(r"location ~* \.ini$", source)
        # nginx matches gzip_types against the exact content-type string, so
        # a parameterized default_type would silently disable compression for
        # the fabric-scale exports; charset must come from the directive.
        self.assertNotIn('default_type "application/json; charset=utf-8";', source)
        self.assertNotIn('default_type "text/csv; charset=utf-8";', source)
        export_section = source.split(
            "# ── Public machine-readable exports", 1
        )[1]
        self.assertEqual(export_section.count("charset utf-8;"), 4)


class WriteExportTests(unittest.TestCase):
    def test_writes_payload_csv_mode_and_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_artifacts.write_export(
                tmp, "flap",
                [{"device": "leaf-01", "interface": "swp1",
                  "status": "critical", "flaps_24h": 12}],
                {"total_ports": 1}, "current",
                generated_at=1234567890, extra={"note": "x"},
            )
            json_path = Path(tmp) / "export" / "flap.json"
            csv_path = Path(tmp) / "export" / "flap.csv"
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], export_artifacts.SCHEMA_VERSION)
            self.assertEqual(payload["domain"], "flap")
            self.assertEqual(payload["generated_at"], 1234567890)
            self.assertEqual(payload["collection_status"], "current")
            self.assertEqual(payload["counts"], {"total_ports": 1})
            self.assertEqual(
                payload["columns"], list(export_artifacts.EXPORT_SCHEMAS["flap"])
            )
            self.assertEqual(payload["extra"], {"note": "x"})
            self.assertEqual(payload["rows"][0]["flaps_24h"], 12)

            # newline="" preserves CRLF; read_text would translate it away.
            with open(csv_path, encoding="utf-8", newline="") as handle:
                csv_text = handle.read()
            self.assertTrue(csv_text.startswith(",".join(payload["columns"])))
            self.assertTrue(csv_text.endswith("\r\n"))

            for path in (json_path, csv_path):
                # Web-served artifacts: the 0664 floor is the contract that
                # keeps nginx able to read what mkstemp created as 0600.
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o664)
                self.assertTrue(analysis_sidecar.sidecar_matches(path))

    def test_basename_and_subdir_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_artifacts.write_export(
                tmp, "transceiver", [], {}, None,
                subdir=None, basename="transceiver-export",
            )
            self.assertTrue((Path(tmp) / "transceiver-export.json").is_file())
            self.assertTrue((Path(tmp) / "transceiver-export.csv").is_file())

    def test_contract_error_leaves_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(export_artifacts.ExportContractError):
                export_artifacts.write_export(
                    tmp, "flap", [{"bogus": 1}], {}, None
                )
            self.assertFalse((Path(tmp) / "export" / "flap.json").exists())


GOLDEN_INI = """Created on 2026-07-16 10-40-03
========== leaf-01 ==========
Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status
----------
swp1 Pass spine-01 swp10 spine-01 swp10 UP
swp2 No-Info spine-01 swp11 None None UP
swp3 No-Info spine-01 swp12 None None DOWN
swp4 Fail spine-01 swp13 None None DOWN
swp5 Fail spine-01 swp14 spine-01 swp15 UP
swp6 Fail spine-01 swp16 spine-02 swp16 UP
swp7 Fail spine-01 swp17 None None UP
None Pass spine-01 swp18 spine-01 swp18 UP
swp9 Fail exp,dev =swp19 act"dev @swp20 UP
"""

# Hand-written expectation mirroring lldp.html's Download CSV of the freshly
# loaded (problems-first) table: FAILED, NO INFO, WARNING, SUCCESS — stable
# within each bucket.
GOLDEN_CSV = (
    "Local Device,Local Port,Port Status,Expected Neighbor,Expected Port,"
    "Active Neighbor,Active Port,Status,Connection Health,"
    "P2P Sheet,P2P Line,P2P SEQ\r\n"
    "leaf-01,swp4,DOWN,spine-01,swp13,N/A,N/A,FAILED,Local Port is DOWN,,,\r\n"
    "leaf-01,N/A,UP,spine-01,swp18,spine-01,swp18,FAILED,Local Port Not Defined,,,\r\n"
    "leaf-01,swp2,UP,spine-01,swp11,N/A,N/A,NO INFO,No LLDP Response Received,,,\r\n"
    "leaf-01,swp3,DOWN,spine-01,swp12,N/A,N/A,NO INFO,Local Port is DOWN,,,\r\n"
    "leaf-01,swp5,UP,spine-01,swp14,spine-01,swp15,WARNING,"
    '"Port Mismatch: Expected swp14, Got swp15",,,\r\n'
    "leaf-01,swp6,UP,spine-01,swp16,spine-02,swp16,WARNING,"
    '"Wrong Device: Expected spine-01, Got spine-02",,,\r\n'
    "leaf-01,swp7,UP,spine-01,swp17,N/A,N/A,WARNING,Unexpected Connection,,,\r\n"
    'leaf-01,swp9,UP,"exp,dev",\'=swp19,"act""dev",\'@swp20,WARNING,'
    '"Wrong Device: Expected exp,dev, Got act""dev",,,\r\n'
    "leaf-01,swp1,UP,spine-01,swp10,spine-01,swp10,SUCCESS,"
    "LLDP Connection Verified,,,\r\n"
)


# The alias file behind GOLDEN_ALIASED_CSV.  Every entry earns its place: the
# casing differences prove the lookup is case-insensitive, the cross-namespace
# entries would surface immediately if the device and interface maps were ever
# interchanged, and the punctuation exercises the formula guard and RFC-4180
# escaping on operator-supplied text.
GOLDEN_ALIASES = {
    "devices": {
        "LEAF-01": "RACK-A-LEAF",     # file casing differs from the report's
        "spine-01": "CORE-A",
        "swp1": "PORT-NAME-IN-THE-DEVICE-MAP",
    },
    "interfaces": {
        "SWP1": "M1",                 # file casing differs from the report's
        "swp4": "=M4",                # a label that looks like a formula
        "swp9": "M,9",                # a label that needs RFC-4180 quoting
        "swp10": "M10",
        "leaf-01": "DEVICE-NAME-IN-THE-PORT-MAP",
    },
}

# GOLDEN_CSV as lldp.html downloads it with "P2P: On": same rows in the same
# order, the six device/port columns relabeled.  spine-02 and most ports have
# no alias and keep the report's own name; the missing sentinels stay N/A.
GOLDEN_ALIASED_CSV = (
    "Local Device,Local Port,Port Status,Expected Neighbor,Expected Port,"
    "Active Neighbor,Active Port,Status,Connection Health,"
    "P2P Sheet,P2P Line,P2P SEQ\r\n"
    "RACK-A-LEAF,'=M4,DOWN,CORE-A,swp13,N/A,N/A,FAILED,Local Port is DOWN,,,\r\n"
    "RACK-A-LEAF,N/A,UP,CORE-A,swp18,CORE-A,swp18,FAILED,"
    "Local Port Not Defined,,,\r\n"
    "RACK-A-LEAF,swp2,UP,CORE-A,swp11,N/A,N/A,NO INFO,"
    "No LLDP Response Received,,,\r\n"
    "RACK-A-LEAF,swp3,DOWN,CORE-A,swp12,N/A,N/A,NO INFO,"
    "Local Port is DOWN,,,\r\n"
    "RACK-A-LEAF,swp5,UP,CORE-A,swp14,CORE-A,swp15,WARNING,"
    '"Port Mismatch: Expected swp14, Got swp15",,,\r\n'
    "RACK-A-LEAF,swp6,UP,CORE-A,swp16,spine-02,swp16,WARNING,"
    '"Wrong Device: Expected spine-01, Got spine-02",,,\r\n'
    "RACK-A-LEAF,swp7,UP,CORE-A,swp17,N/A,N/A,WARNING,"
    "Unexpected Connection,,,\r\n"
    'RACK-A-LEAF,"M,9",UP,"exp,dev",\'=swp19,"act""dev",\'@swp20,WARNING,'
    '"Wrong Device: Expected exp,dev, Got act""dev",,,\r\n'
    "RACK-A-LEAF,M1,UP,CORE-A,M10,CORE-A,M10,SUCCESS,"
    "LLDP Connection Verified,,,\r\n"
)

# JS alias map -> display-aliases.json section, asserted against lldp.html's
# own wiring by AliasedColumnContractTests rather than trusted here.
BROWSER_ALIAS_MAPS = {"deviceAliasLc": "devices", "portAliasLc": "interfaces"}


def _csv_rows(text):
    return list(csv.reader(io.StringIO(text, newline="")))


def _source_between(source, start, end):
    return source.split(start, 1)[1].split(end, 1)[0]


def _extract_function(source: str, name: str) -> str:
    start = source.index("\n%s() {" % name) + 1
    end = source.index("\n}", start) + 2
    return source[start:end]


def _require(needle, haystack=LLDP_HTML, label="html/lldp.html"):
    """Locate a marker, reporting one line instead of dumping the file.

    lldp.html is a few hundred KB; a bare assertIn buries the real message.
    """
    if needle not in haystack:
        raise AssertionError(f"{label} no longer contains: {needle!r}")


class LLDPExportGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = parse_lldp_report(GOLDEN_INI)

    def test_csv_matches_download_csv_semantics(self):
        self.assertEqual(lldp_export.build_csv(self.report), GOLDEN_CSV)

    def test_absent_design_keeps_blank_p2p_columns(self):
        rows = _csv_rows(lldp_export.build_csv(self.report))
        self.assertEqual(
            rows[0][-3:], ["P2P Sheet", "P2P Line", "P2P SEQ"]
        )
        self.assertTrue(all(row[-3:] == ["", "", ""] for row in rows[1:]))

    def test_matched_design_adds_sheet_line_and_seq(self):
        design = {"connections": [{
            "source_name": "leaf-01", "source_port": "swp5",
            "dest_name": "spine-01", "dest_port": "swp14",
            "sheet_name": "GB300-9-16", "row_number": 184, "seq": "2778",
            "connection_type": "general", "network_type": "eth",
        }]}
        rows = _csv_rows(lldp_export.build_csv(self.report, p2p_design=design))
        matched = next(row for row in rows[1:] if row[1] == "swp5")
        self.assertEqual(matched[-3:], ["GB300-9-16", "184", "2778"])

    def test_unmatched_design_keeps_p2p_columns_blank(self):
        design = {"connections": [{
            "source_name": "other-device", "source_port": "swp1",
            "dest_name": "peer-device", "dest_port": "swp2",
            "sheet_name": "Other", "row_number": 9, "seq": "10",
            "connection_type": "general", "network_type": "eth",
        }]}
        rows = _csv_rows(lldp_export.build_csv(self.report, p2p_design=design))
        self.assertTrue(all(row[-3:] == ["", "", ""] for row in rows[1:]))

    def test_formula_like_quoted_sheet_is_guarded_and_rfc4180_escaped(self):
        design = {"connections": [{
            "source_name": "leaf-01", "source_port": "swp9",
            "dest_name": "peer-device", "dest_port": "swp2",
            "sheet_name": '=Rack,"Plan"', "row_number": 184, "seq": "2778",
            "connection_type": "general", "network_type": "eth",
        }]}
        text = lldp_export.build_csv(self.report, p2p_design=design)
        matched = next(row for row in _csv_rows(text)[1:] if row[1] == "swp9")
        self.assertEqual(matched[-3:], ['\'=Rack,"Plan"', "184", "2778"])
        self.assertIn('"\'=Rack,""Plan"""', text)

    def test_malformed_design_gracefully_degrades_to_blank_columns(self):
        rows = _csv_rows(
            lldp_export.build_csv(self.report, p2p_design={"not": "a design"})
        )
        self.assertTrue(all(row[-3:] == ["", "", ""] for row in rows[1:]))

    def test_headless_export_uses_precise_three_part_port_match(self):
        report = parse_lldp_report(
            """Created on 2026-08-19 10-00-00
========== leaf-01 ==========
Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status
----------
swp3s4 Pass right swp49 right swp49 UP
"""
        )

        def design_row(peer, port, sheet, line, seq):
            return {
                "source_name": "leaf-01", "source_port": port,
                "dest_name": peer, "dest_port": "49",
                "sheet_name": sheet, "row_number": line, "seq": seq,
                "connection_type": "general", "network_type": "eth",
            }

        design = {"connections": [
            design_row("wrong", "3/3/1", "Wrong", 11, "111"),
            design_row("right", "3/2/1", "Right", 22, "222"),
            design_row("proof", "1/1/4", "Proof", 33, "333"),
        ]}
        rows = _csv_rows(lldp_export.build_csv(report, p2p_design=design))
        self.assertEqual(rows[1][-3:], ["Right", "22", "222"])

    def test_payload_counts_match_report_counts(self):
        payload = lldp_export.build_payload(self.report)
        self.assertEqual(
            payload["counts"],
            self.report.counts.as_dict(include_total=True),
        )
        self.assertEqual(
            payload["counts"],
            {"successful": 1, "failed": 2, "warnings": 4, "no_info": 2,
             "total": 9},
        )

    def test_payload_shape_and_null_semantics(self):
        payload = lldp_export.build_payload(self.report)
        self.assertEqual(payload["domain"], "lldp_results")
        self.assertEqual(payload["created"], "2026-07-16 10-40-03")
        self.assertEqual(
            payload["columns"],
            list(export_artifacts.EXPORT_SCHEMAS["lldp_results"]),
        )
        by_port = {row["local_port"]: row for row in payload["rows"]}
        # Missing sentinels are null in JSON (automation), "N/A" in CSV (UI).
        self.assertIsNone(by_port["swp2"]["actual_device"])
        self.assertEqual(by_port["swp1"]["status"], "SUCCESS")
        self.assertEqual(by_port["swp1"]["lldp_status"], "Pass")
        missing_local = [r for r in payload["rows"] if r["local_port"] is None]
        self.assertEqual(len(missing_local), 1)
        self.assertEqual(missing_local[0]["status"], "FAILED")

    def test_rows_sorted_problems_first(self):
        payload = lldp_export.build_payload(self.report)
        statuses = [row["status"] for row in payload["rows"]]
        order = {"FAILED": 0, "NO INFO": 1, "WARNING": 2, "SUCCESS": 3}
        self.assertEqual(statuses, sorted(statuses, key=order.__getitem__))


class LLDPAliasedExportGoldenTests(unittest.TestCase):
    """The ?p2p=1 rendering: the page's Download CSV with the toggle ON."""

    @classmethod
    def setUpClass(cls):
        cls.report = parse_lldp_report(GOLDEN_INI)

    def _aliased(self, aliases=None):
        return lldp_export.build_csv(
            self.report,
            aliases=GOLDEN_ALIASES if aliases is None else aliases,
        )

    def test_csv_matches_toggled_download_semantics(self):
        self.assertEqual(self._aliased(), GOLDEN_ALIASED_CSV)

    def test_header_and_column_count_are_identical_in_both_modes(self):
        plain = _csv_rows(lldp_export.build_csv(self.report))
        aliased = _csv_rows(self._aliased())
        self.assertEqual(aliased[0], plain[0])
        self.assertEqual(aliased[0], list(lldp_export.CSV_HEADERS))
        self.assertEqual(len(aliased), len(plain))
        for index, (left, right) in enumerate(zip(plain, aliased)):
            self.assertEqual(len(left), len(right), f"row {index} width")
            self.assertEqual(len(right), len(lldp_export.CSV_HEADERS))

    def test_the_toggle_changes_only_the_declared_columns(self):
        plain = _csv_rows(lldp_export.build_csv(self.report))
        aliased = _csv_rows(self._aliased())
        allowed = set(lldp_export.ALIASED_CSV_COLUMNS)
        touched = set()
        for row_index, (left, right) in enumerate(zip(plain, aliased)):
            differing = {
                column for column, (a, b) in enumerate(zip(left, right))
                if a != b
            }
            self.assertLessEqual(
                differing, allowed,
                f"row {row_index} changed outside the aliased columns",
            )
            touched |= differing
        # ...and the golden really exercises every one of them, so a column
        # silently dropping out of the aliasing cannot pass unnoticed.
        self.assertEqual(touched, allowed)

    def test_device_and_port_namespaces_are_not_interchanged(self):
        text = self._aliased()
        self.assertNotIn("PORT-NAME-IN-THE-DEVICE-MAP", text)
        self.assertNotIn("DEVICE-NAME-IN-THE-PORT-MAP", text)
        for row in _csv_rows(text)[1:]:
            self.assertEqual(row[0], "RACK-A-LEAF")

    def test_case_insensitive_alias_matching(self):
        # 'LEAF-01'/'SWP1' in the file, 'leaf-01'/'swp1' in the report.
        row = next(r for r in _csv_rows(self._aliased())[1:] if r[7] == "SUCCESS")
        self.assertEqual(row[0], "RACK-A-LEAF")
        self.assertEqual(row[1], "M1")

    def test_value_without_an_alias_keeps_its_canonical_rendering(self):
        rows = _csv_rows(self._aliased())[1:]
        row = next(r for r in rows if r[5] == "spine-02")
        self.assertEqual(row[1], "swp6")     # no alias -> report's own name
        self.assertEqual(row[4], "swp16")
        missing = next(r for r in rows if r[1] == "swp2")
        self.assertEqual(missing[5], "N/A")  # missing sentinel, not a label
        self.assertEqual(missing[6], "N/A")

    def test_a_label_that_looks_like_a_formula_stays_guarded_and_escaped(self):
        text = self._aliased()
        rows = _csv_rows(text)
        formula = next(r for r in rows[1:] if r[4] == "swp13")
        self.assertEqual(formula[1], "'=M4")
        quoted = next(r for r in rows[1:] if r[4] == "'=swp19")
        self.assertEqual(quoted[1], "M,9")
        self.assertIn("'=M4", text)
        self.assertIn('"M,9"', text)

    def test_status_and_health_columns_never_carry_labels(self):
        # The health message embeds the report's names on purpose: it is
        # evidence about the wiring, not a field label.
        row = next(
            r for r in _csv_rows(self._aliased())[1:]
            if r[8].startswith("Wrong Device")
        )
        self.assertEqual(
            row[8], "Wrong Device: Expected spine-01, Got spine-02"
        )
        self.assertEqual(row[2], "UP")
        self.assertEqual(row[7], "WARNING")

    def test_p2p_design_columns_are_unchanged_by_the_toggle(self):
        design = {"connections": [{
            "source_name": "leaf-01", "source_port": "swp5",
            "dest_name": "spine-01", "dest_port": "swp14",
            "sheet_name": "GB300-9-16", "row_number": 184, "seq": "2778",
            "connection_type": "general", "network_type": "eth",
        }]}
        # Relabel the very device:port the design is keyed on: the join must
        # still hit, because it reads the report's names, not the labels.
        aliases = {
            "devices": {"leaf-01": "RACK-A"},
            "interfaces": {"swp5": "M5"},
        }
        plain = _csv_rows(lldp_export.build_csv(self.report, p2p_design=design))
        aliased = _csv_rows(
            lldp_export.build_csv(
                self.report, p2p_design=design, aliases=aliases
            )
        )
        matched = next(row for row in aliased[1:] if row[1] == "M5")
        self.assertEqual(matched[0], "RACK-A")
        self.assertEqual(matched[-3:], ["GB300-9-16", "184", "2778"])
        self.assertEqual(
            [row[-3:] for row in aliased], [row[-3:] for row in plain]
        )

    def test_absent_or_unusable_alias_data_degrades_to_the_canonical_export(self):
        plain = lldp_export.build_csv(self.report)
        for aliases in (
            None,                                   # no opt-in at all
            {},                                     # the installed default
            {"interfaces": {}, "devices": {}},
            {"devices": None, "interfaces": "nope"},  # malformed sections
            ["devices", "interfaces"],              # malformed document
            "",
            {"devices": {"leaf-01": ""}},           # empty label -> fall back
            {"devices": {"": "X"}},                 # empty real name
            {"devices": {"leaf-01": None}},         # non-string label
            {"nonsense": {"leaf-01": "X"}},         # unknown section only
        ):
            with self.subTest(aliases=aliases):
                self.assertEqual(lldp_export.build_csv(
                    self.report, aliases=aliases), plain)

    def test_a_label_for_the_missing_sentinel_applies_as_it_does_on_screen(self):
        # aliasedLabel looks up displayValue(v), so an 'N/A' key relabels the
        # empty cells too.  Pinned because the browser cannot help doing this
        # and the two sides have to agree even on the quirk.
        rows = _csv_rows(
            lldp_export.build_csv(
                self.report,
                aliases={"interfaces": {"n/a": "UNPATCHED"}},
            )
        )
        no_local_port = next(
            row for row in rows[1:] if row[8] == "Local Port Not Defined"
        )
        self.assertEqual(no_local_port[1], "UNPATCHED")
        no_neighbor = next(row for row in rows[1:] if row[4] == "swp13")
        self.assertEqual(no_neighbor[6], "UNPATCHED")
        # The device columns read the other namespace and stay untouched.
        self.assertEqual(no_neighbor[5], "N/A")

    def test_only_the_declared_indices_are_aliased(self):
        """Probe every column at once: what build_csv does is the contract."""
        report = parse_lldp_report(
            """Created on 2026-08-21 00-00-00
========== c0 ==========
Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status
----------
c1 Pass c3 c4 c5 c6 UP
"""
        )
        canonical = _csv_rows(lldp_export.build_csv(report))[1]
        # Every canonical cell has a label in BOTH namespaces, so any column
        # reading the wrong map — or reading one it should not — shows up.
        aliases = {
            namespace: {cell: f"{namespace}:{cell}" for cell in canonical}
            for namespace in lldp_export.ALIAS_NAMESPACES
        }
        expected = [
            f"{lldp_export.ALIASED_CSV_COLUMNS[index]}:{cell}"
            if index in lldp_export.ALIASED_CSV_COLUMNS else cell
            for index, cell in enumerate(canonical)
        ]
        self.assertEqual(
            _csv_rows(lldp_export.build_csv(report, aliases=aliases))[1],
            expected,
        )


class LLDPBrowserP2PExportContractTests(unittest.TestCase):
    def test_browser_and_headless_csv_headers_are_equal(self):
        match = re.search(
            r"const CSV_HEADERS = Object\.freeze\(\[(.*?)\]\);",
            LLDP_HTML,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        browser_headers = re.findall(r"'([^']+)'", match.group(1))
        self.assertEqual(browser_headers, list(lldp_export.CSV_HEADERS))

    def test_csv_metadata_join_is_independent_of_display_toggle(self):
        canonical = _source_between(
            LLDP_HTML,
            "function canonicalConnectionRow(connection)",
            "function buildLLDPCSV(connections)",
        )
        join = _source_between(
            LLDP_HTML,
            "function activeP2pDesignFor(conn)",
            "function kvRow(label, value, cls)",
        )
        self.assertIn("activeP2pDesignFor(connection)", canonical)
        self.assertIn(
            "lookupByDevicePort(p2pIndex, conn.localDevice, conn.localPort)",
            join,
        )
        # The device/port columns follow the toggle, but the design join that
        # fills P2P Sheet/Line/SEQ must keep keying on the report's own names.
        self.assertNotIn("p2pNamesOn", join)
        self.assertNotIn("aliasedLabel", join)
        for cell in ("design.sheet_name", "design.row_number", "design.seq"):
            self.assertIn(cell, canonical)
        self.assertNotIn("aliasedLabel(design", canonical)

    def test_download_waits_for_the_aliases_before_it_can_be_clicked(self):
        # download-csv ships disabled and only setP2pDesignStatus re-enables it
        # (pinned above), and the design fetch that settles that status is
        # chained behind loadDisplayAliases.  So the labels are always in place
        # before the first click is possible, and the CSV cannot disagree with
        # the table it was generated from.
        boot = _source_between(
            LLDP_HTML,
            "window.addEventListener('load', function() {",
            "// ===== Topology Editor Functions =====",
        )
        chained = _source_between(
            boot, "loadDisplayAliases().then(() => {", "});"
        )
        self.assertIn("loadP2pDesign();", chained)
        self.assertIn("loadLLDPData();", chained)
        self.assertNotIn("loadP2pDesign();", boot.split("loadDisplayAliases")[0])

    def test_failed_design_load_reenables_download(self):
        button = re.search(
            r'<button id="download-csv"[^>]*>', LLDP_HTML
        ).group(0)
        setter = _source_between(
            LLDP_HTML,
            "function setP2pDesignStatus(status)",
            "function escHtml(v)",
        )
        loader = _source_between(
            LLDP_HTML,
            "function loadP2pDesign()",
            "function loadTransceiverInventory()",
        )
        download = _source_between(
            LLDP_HTML,
            "function downloadCSV()",
            "// ===== Device Search Functions =====",
        )
        self.assertIn("disabled", button)
        self.assertIn("button.disabled = loading", setter)
        self.assertIn("setP2pDesignStatus('loading')", loader)
        self.assertGreaterEqual(loader.count("setP2pDesignStatus('ready')"), 2)
        self.assertGreaterEqual(loader.count("setP2pDesignStatus('absent')"), 2)
        self.assertIn("if (p2pDesignStatus === 'loading') return;", download)

    def test_installed_cgi_loads_active_design_best_effort(self):
        self.assertIn(
            'P2P_DESIGN_FILE="$WEB_ROOT/monitor-results/active-p2p.json"',
            LLDP_EXPORT_API,
        )
        self.assertIn(
            'PYTHONPATH="$LLDPQ_DIR:$WEB_ROOT${PYTHONPATH:+:$PYTHONPATH}"',
            LLDP_EXPORT_API,
        )
        self.assertIn(
            'ai_p2p.load_connections(os.environ["P2P_DESIGN_FILE"])',
            LLDP_EXPORT_API,
        )
        self.assertIn("p2p_design=load_active_p2p()", LLDP_EXPORT_API)


class AliasedColumnContractTests(unittest.TestCase):
    """The page and the headless export must alias the very same columns.

    Three descriptions of one contract — the rendered cells, the browser's CSV
    row, and lldp_export.ALIASED_CSV_COLUMNS — so none of them can drift on
    its own and quietly relabel a column in only one of the two downloads.
    """

    def _rendered_columns(self):
        """{cell index: JS alias map} from the setAliasedCell calls."""
        return {
            int(index): name
            for index, name in re.findall(
                r"setAliasedCell\(row\.insertCell\((\d+)\),"
                r"\s*connection\.\w+,\s*(\w+)\)",
                LLDP_HTML,
            )
        }

    def _csv_columns(self):
        """{column index: JS alias map} from canonicalConnectionRow's array."""
        array = _source_between(
            _source_between(
                LLDP_HTML,
                "function canonicalConnectionRow(connection)",
                "function buildLLDPCSV(connections)",
            ),
            "const row = [",
            "];",
        )
        columns = {}
        for index, element in enumerate(array.split(",\n")):
            match = re.search(r"aliasedLabel\([^,]+,\s*(\w+)\)", element)
            if match:
                columns[index] = match.group(1)
        return columns

    def test_the_page_exports_exactly_the_columns_it_renders_aliased(self):
        rendered = self._rendered_columns()
        self.assertEqual(len(rendered), 6, "setAliasedCell calls not found")
        self.assertEqual(self._csv_columns(), rendered)

    def test_the_headless_export_declares_the_same_columns(self):
        self.assertEqual(
            {
                index: BROWSER_ALIAS_MAPS[name]
                for index, name in self._csv_columns().items()
            },
            dict(lldp_export.ALIASED_CSV_COLUMNS),
        )

    def test_each_js_map_still_carries_the_namespace_it_is_matched_to(self):
        # BROWSER_ALIAS_MAPS is only meaningful while lldp.html keeps wiring
        # each display-aliases.json section to that map, case-folded.
        _require("portAliasMap = (d.interfaces && typeof d.interfaces === 'object')")
        _require("deviceAliasMap = (d.devices && typeof d.devices === 'object')")
        _require("portAliasLc[k.toLowerCase()] = portAliasMap[k]")
        _require("deviceAliasLc[k.toLowerCase()] = deviceAliasMap[k]")
        self.assertEqual(
            set(BROWSER_ALIAS_MAPS.values()),
            set(lldp_export.ALIAS_NAMESPACES),
        )

    def test_a_label_cannot_bypass_the_browser_formula_guard(self):
        # An alias is operator-supplied text, so every exported cell has to
        # keep going through csvField/spreadsheetSafeValue.
        builder = _source_between(
            LLDP_HTML,
            "function buildLLDPCSV(connections)",
            "function renderedConnectionsInTableOrder()",
        )
        self.assertIn(
            ".map((value, index) => csvField(value, index >= p2pColumnStart))",
            builder,
        )
        guard = _source_between(
            LLDP_HTML,
            "function spreadsheetSafeValue(value, blankMissing = false)",
            "function canonicalConnectionRow(connection)",
        )
        self.assertIn(r"/^\s*[=+\-@]/.test(text) ? `'${text}` : text", guard)
        self.assertIn(r'/[",\r\n]/.test(text)', guard)
        self.assertIn(r'text.replace(/"/g,', guard)


def _cgi_environment(**overrides):
    """A CGI env that a developer's own shell variables cannot perturb."""
    environment = {
        key: value for key, value in os.environ.items()
        if key not in (
            "QUERY_STRING", "REQUEST_METHOD",
            "LLDPQ_EXPORT_FORMAT", "LLDPQ_CONFIG_HELPER",
        )
    }
    environment.update(overrides)
    return environment


class LLDPExportQueryParameterTests(unittest.TestCase):
    """p2p=1 is the only accepted spelling; anything else stays canonical."""

    @classmethod
    def setUpClass(cls):
        cls.function = _extract_function(
            LLDP_EXPORT_API, "p2p_aliases_requested"
        )

    def _requested(self, query):
        script = self.function + (
            "\nif p2p_aliases_requested; then echo ON; else echo OFF; fi\n"
        )
        environment = _cgi_environment()
        if query is not None:
            environment["QUERY_STRING"] = query
        result = subprocess.run(
            ["bash", "-c", script], env=environment,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_the_opt_in_is_recognised_anywhere_in_the_query(self):
        for query in ("p2p=1", "p2p=1&x=2", "x=2&p2p=1", "a=b&p2p=1&c=d",
                      "p2p=1&"):
            with self.subTest(query=query):
                self.assertEqual(self._requested(query), "ON")

    def test_an_absent_or_empty_query_stays_canonical(self):
        self.assertEqual(self._requested(None), "OFF")
        self.assertEqual(self._requested(""), "OFF")

    def test_near_misses_and_hostile_values_stay_canonical(self):
        # The separator anchors reject every partial key or value, and the
        # value is only ever matched, never expanded or executed, so shell
        # and SQL punctuation are just characters that fail to match.
        for query in (
            "p2p=0", "p2p=true", "p2p=yes", "p2p=on", "p2p=01", "p2p=10",
            "p2p=1x", "p2p =1", "xp2p=1", "foo=p2p=1", "P2P=1", "p2p",
            "p2p=", "p2p=1%0A", "p2p=$(echo 1)", "p2p=`echo 1`",
            "p2p=1;echo pwned", "p2p=1' OR '1'='1", "p2p=1\np2p=1",
            "../../etc/passwd&p2p=2", "p2p=" + "1" * 4096,
        ):
            with self.subTest(query=query):
                self.assertEqual(self._requested(query), "OFF")


class LLDPExportCgiTests(unittest.TestCase):
    """The installed CGI end to end: parameter, alias file, both goldens."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.web = root / "web"
        self.web.mkdir()
        # PYTHONPATH carries WEB_ROOT exactly as the installed tree does, and
        # ai_p2p.py lives beside the CGI there.
        shutil.copy2(ROOT / "html" / "ai_p2p.py", self.web / "ai_p2p.py")
        (self.web / "lldp_results.ini").write_text(GOLDEN_INI, encoding="utf-8")
        config = root / "lldpq.conf"
        config.write_text(
            f"LLDPQ_DIR={SCRIPT_DIR}\nWEB_ROOT={self.web}\n", encoding="utf-8"
        )
        self.helper = root / "helper"
        self.helper.write_text(
            "#!/usr/bin/env bash\n"
            f'exec "{CONFIG_HELPER}" "$@" --config "{config}"\n',
            encoding="utf-8",
        )
        self.helper.chmod(0o755)

    def _write_aliases(self, content):
        (self.web / "display-aliases.json").write_text(
            content, encoding="utf-8"
        )

    def _get(self, query=None, export_format="csv"):
        environment = _cgi_environment(
            LLDPQ_CONFIG_HELPER=str(self.helper),
            LLDPQ_EXPORT_FORMAT=export_format,
            REQUEST_METHOD="GET",
        )
        if query is not None:
            environment["QUERY_STRING"] = query
        result = subprocess.run(
            ["bash", str(LLDP_EXPORT_CGI)], env=environment,
            capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        # Bytes, not text: the CSV's CRLF line endings are part of the contract.
        headers, body = result.stdout.split(b"\n\n", 1)
        self.assertIn(b"Status: 200 OK", headers)
        return headers.decode("utf-8"), body.decode("utf-8")

    def test_a_default_request_serves_the_canonical_golden(self):
        self._write_aliases(json.dumps(GOLDEN_ALIASES))
        headers, body = self._get()
        self.assertEqual(body, GOLDEN_CSV)
        self.assertIn('filename="LLDP_Report_2026-07-16_10-40-03.csv"', headers)

    def test_the_opt_in_serves_the_aliased_golden(self):
        self._write_aliases(json.dumps(GOLDEN_ALIASES))
        headers, body = self._get("p2p=1")
        self.assertEqual(body, GOLDEN_ALIASED_CSV)
        self.assertIn(
            'filename="LLDP_Report_P2P_2026-07-16_10-40-03.csv"', headers
        )

    def test_a_hostile_query_serves_the_canonical_bytes_and_filename(self):
        self._write_aliases(json.dumps(GOLDEN_ALIASES))
        for query in ("p2p=2", "p2p=1x", "foo=p2p=1", "p2p=1;echo pwned",
                      "p2p=../../etc/passwd"):
            with self.subTest(query=query):
                headers, body = self._get(query)
                self.assertEqual(body, GOLDEN_CSV)
                self.assertIn(
                    'filename="LLDP_Report_2026-07-16_10-40-03.csv"', headers
                )

    def test_an_unusable_alias_file_degrades_to_the_canonical_bytes(self):
        for content in ("", "{", "[]", "null", '{"devices": 3}', "\x00"):
            with self.subTest(content=content):
                self._write_aliases(content)
                _headers, body = self._get("p2p=1")
                self.assertEqual(body, GOLDEN_CSV)

    def test_a_missing_alias_file_degrades_to_the_canonical_bytes(self):
        # The installer and docker-entrypoint.sh both create the file; a
        # hand-managed web root must still not turn the export into a 500.
        self.assertFalse((self.web / "display-aliases.json").exists())
        headers, body = self._get("p2p=1")
        self.assertEqual(body, GOLDEN_CSV)
        # The filename reports the rendering that was asked for; that nothing
        # is configured to relabel is what makes the bytes canonical.
        self.assertIn(
            'filename="LLDP_Report_P2P_2026-07-16_10-40-03.csv"', headers
        )

    def test_the_json_export_has_no_alias_mode(self):
        self._write_aliases(json.dumps(GOLDEN_ALIASES))
        _headers, canonical = self._get(export_format="json")
        _headers, opted_in = self._get("p2p=1", export_format="json")
        self.assertEqual(canonical, opted_in)
        self.assertNotIn("RACK-A-LEAF", canonical)
        self.assertIn("leaf-01", canonical)


def _extract_array(source: str, name: str) -> list[str]:
    match = re.search(rf"\n{name}=\((.*?)\n\)", source, re.DOTALL)
    if match is None:
        raise AssertionError(f"array {name} not found in monitor.sh")
    body = re.sub(r"#[^\n]*", "", match.group(1))
    return body.split()


class MonitorExportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MONITOR.read_text(encoding="utf-8")
        cls.current = _extract_array(cls.source, "analysis_artifacts")
        cls.legacy_v5 = _extract_array(cls.source, "analysis_artifacts_legacy_v5")

    def test_current_schema_adds_exactly_the_export_files(self):
        legacy_v6 = _extract_array(self.source, "analysis_artifacts_legacy_v6")
        # legacy_v6 must be the frozen export-era schema: legacy_v5 plus the
        # legacy export pairs, nothing else.
        self.assertEqual(
            set(legacy_v6) - set(self.legacy_v5),
            set(LEGACY_EXPORT_DOMAIN_FILES),
        )
        self.assertEqual(set(self.legacy_v5) - set(legacy_v6), set())
        self.assertEqual(
            len(legacy_v6),
            len(self.legacy_v5) + len(LEGACY_EXPORT_DOMAIN_FILES),
        )
        # legacy_v7 must be the frozen pre-shard schema: legacy_v6 plus the
        # config-drift/routes/fabric-check analyzer artifacts, nothing else.
        legacy_v7 = _extract_array(self.source, "analysis_artifacts_legacy_v7")
        self.assertEqual(
            set(legacy_v7) - set(legacy_v6),
            set(NEW_ANALYZER_ARTIFACTS),
        )
        self.assertEqual(set(legacy_v6) - set(legacy_v7), set())
        self.assertEqual(
            len(legacy_v7), len(legacy_v6) + len(NEW_ANALYZER_ARTIFACTS)
        )
        # legacy_v8 must be the frozen pre-optical-shard schema: legacy_v7
        # plus the BER shard directory and optical detail sidecars.
        legacy_v8 = _extract_array(self.source, "analysis_artifacts_legacy_v8")
        self.assertEqual(
            set(legacy_v8) - set(legacy_v7),
            set(SHARD_ERA_ARTIFACTS),
        )
        self.assertEqual(set(legacy_v7) - set(legacy_v8), set())
        self.assertEqual(
            len(legacy_v8), len(legacy_v7) + len(SHARD_ERA_ARTIFACTS)
        )
        # The current schema adds exactly the optical history shard
        # directory on top of legacy_v8.
        self.assertEqual(
            set(self.current) - set(legacy_v8),
            {"optical-history/"},
        )
        self.assertEqual(set(legacy_v8) - set(self.current), set())
        self.assertEqual(len(self.current), len(legacy_v8) + 1)

    def test_validation_and_overlays_cover_every_export_pair(self):
        validate = _extract_function(self.source, "validate_analysis_outputs")
        overlays = _extract_function(self.source, "select_scope_web_overlays")
        for relative in EXPORT_DOMAIN_FILES:
            self.assertIn(relative, validate, f"{relative} missing from validation")
            self.assertIn(relative, overlays, f"{relative} missing from overlays")

    def test_skip_optical_purges_export_pair_from_stage(self):
        publish = _extract_function(self.source, "publish_full_monitor_results")
        for name in ("export/optical.json", "export/optical.csv",
                     "export/optical.json.sha256", "export/optical.csv.sha256"):
            self.assertIn(name, publish, f"{name} not purged on SKIP_OPTICAL")

    def _run_manifest_validation(self, artifacts, statuses=None):
        """Build a synthetic rollback bundle and run the real bash matcher."""
        statuses = statuses or {}
        with tempfile.TemporaryDirectory() as tmp:
            backup_dir = Path(tmp) / "analysis-backup"
            files_dir = backup_dir / "files"
            files_dir.mkdir(parents=True)
            manifest_lines = []
            for relative in artifacts:
                status = statuses.get(relative, "present")
                manifest_lines.append(f"{status}\t{relative}")
                if status != "present":
                    continue
                target = files_dir / relative.rstrip("/")
                if relative.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("x", encoding="utf-8")
            (backup_dir / "manifest").write_text(
                "\n".join(manifest_lines) + "\n", encoding="utf-8"
            )

            arrays = "\n".join(
                re.search(
                    rf"\n({name}=\(.*?\n\))", self.source, re.DOTALL
                ).group(1)
                for name in (
                    "analysis_artifacts",
                    "analysis_artifacts_legacy_v1",
                    "analysis_artifacts_legacy_v2",
                    "analysis_artifacts_legacy_v3",
                    "analysis_artifacts_legacy_v4",
                    "analysis_artifacts_legacy_v5",
                )
            )
            script = (
                f"analysis_backup_dir={backup_dir}\n"
                + arrays + "\n"
                + _extract_function(self.source, "validate_analysis_backup_manifest")
                + "\nif validate_analysis_backup_manifest; then echo VALID;"
                " else echo INVALID; fi\n"
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_current_manifest_validates(self):
        self.assertEqual(self._run_manifest_validation(self.current), "VALID")

    def test_pre_export_snapshot_still_recovers_via_legacy_v5(self):
        self.assertEqual(self._run_manifest_validation(self.legacy_v5), "VALID")

    def test_partial_manifest_rejected(self):
        partial = [
            relative for relative in self.current
            if relative != "export/bgp.csv"
        ]
        self.assertEqual(self._run_manifest_validation(partial), "INVALID")


if __name__ == "__main__":
    unittest.main()
