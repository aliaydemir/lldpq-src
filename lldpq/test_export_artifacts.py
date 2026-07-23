#!/usr/bin/env python3
"""Public export contract tests.

Covers the shared exporter (schema registry, CSV semantics incl. the
spreadsheet-formula guard, atomic 0664 publication with sidecars), the LLDP
export's byte-parity with lldp.html's Download CSV (golden file over every
classification branch), and monitor.sh's transaction contract for the new
export artifacts (legacy_v5 snapshot recovery, per-scope validation and
overlay coverage).
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
ROOT = SCRIPT_DIR.parent

import analysis_sidecar
import export_artifacts
import lldp_export
from lldp_report import parse_lldp_report

MONITOR = SCRIPT_DIR / "monitor.sh"
EXPORT_CGIS = tuple(
    ROOT / "html" / name
    for name in ("export-api.sh", "lldp-export-api.sh", "ai-export-api.sh")
)
NGINX_SITE = ROOT / "etc/nginx/sites-available/lldpq"

EXPORT_DOMAIN_FILES = tuple(
    f"export/{domain}.{suffix}"
    for domain in (
        "bgp", "evpn-mh", "duplicate", "flap", "optical",
        "ber", "pfc-ecn", "hardware", "log",
    )
    for suffix in ("json", "csv")
)


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
    "Active Neighbor,Active Port,Status,Connection Health\r\n"
    "leaf-01,swp4,DOWN,spine-01,swp13,N/A,N/A,FAILED,Local Port is DOWN\r\n"
    "leaf-01,N/A,UP,spine-01,swp18,spine-01,swp18,FAILED,Local Port Not Defined\r\n"
    "leaf-01,swp2,UP,spine-01,swp11,N/A,N/A,NO INFO,No LLDP Response Received\r\n"
    "leaf-01,swp3,DOWN,spine-01,swp12,N/A,N/A,NO INFO,Local Port is DOWN\r\n"
    "leaf-01,swp5,UP,spine-01,swp14,spine-01,swp15,WARNING,"
    '"Port Mismatch: Expected swp14, Got swp15"\r\n'
    "leaf-01,swp6,UP,spine-01,swp16,spine-02,swp16,WARNING,"
    '"Wrong Device: Expected spine-01, Got spine-02"\r\n'
    "leaf-01,swp7,UP,spine-01,swp17,N/A,N/A,WARNING,Unexpected Connection\r\n"
    'leaf-01,swp9,UP,"exp,dev",\'=swp19,"act""dev",\'@swp20,WARNING,'
    '"Wrong Device: Expected exp,dev, Got act""dev"\r\n'
    "leaf-01,swp1,UP,spine-01,swp10,spine-01,swp10,SUCCESS,"
    "LLDP Connection Verified\r\n"
)


class LLDPExportGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = parse_lldp_report(GOLDEN_INI)

    def test_csv_matches_download_csv_semantics(self):
        self.assertEqual(lldp_export.build_csv(self.report), GOLDEN_CSV)

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


def _extract_array(source: str, name: str) -> list[str]:
    match = re.search(rf"\n{name}=\((.*?)\n\)", source, re.DOTALL)
    if match is None:
        raise AssertionError(f"array {name} not found in monitor.sh")
    body = re.sub(r"#[^\n]*", "", match.group(1))
    return body.split()


def _extract_function(source: str, name: str) -> str:
    start = source.index("\n%s() {" % name) + 1
    end = source.index("\n}", start) + 2
    return source[start:end]


class MonitorExportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MONITOR.read_text(encoding="utf-8")
        cls.current = _extract_array(cls.source, "analysis_artifacts")
        cls.legacy_v5 = _extract_array(cls.source, "analysis_artifacts_legacy_v5")

    def test_current_schema_adds_exactly_the_export_files(self):
        self.assertEqual(
            set(self.current) - set(self.legacy_v5),
            set(EXPORT_DOMAIN_FILES),
        )
        # legacy_v5 must be the frozen pre-export schema: nothing else differs.
        self.assertEqual(set(self.legacy_v5) - set(self.current), set())
        self.assertEqual(
            len(self.current), len(self.legacy_v5) + len(EXPORT_DOMAIN_FILES)
        )

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
