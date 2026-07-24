#!/usr/bin/env python3
"""Analyzer-level skip toggles (SKIP_DUPLICATE / SKIP_EVPN_MH / SKIP_PFC_ECN).

Follows the SKIP_OPTICAL contract end to end: remote collection gated with
markers intact, analyzer not started, stage artifacts purged with a skipped
placeholder, manifest records the skip, and alert/dashboard consumers accept
a manifest whose skipped analyzers are absent from `analyses`.
"""

import contextlib
import io
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MONITOR = SCRIPT_DIR / "monitor.sh"
CHECK_ALERTS = SCRIPT_DIR / "check_alerts.py"
START_HTML = SCRIPT_DIR.parent / "html" / "start.html"

ANALYZER_SKIPS = {
    "SKIP_DUPLICATE": "duplicate",
    "SKIP_EVPN_MH": "evpn-mh",
    "SKIP_PFC_ECN": "pfc-ecn",
}


def _extract_function(source, name):
    """First function body up to the first line-start closing brace."""
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}", source,
                      re.S | re.M)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(1)


class AnalyzerSkipStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MONITOR.read_text(encoding="utf-8")

    def test_flags_default_and_normalize(self):
        for key in ANALYZER_SKIPS:
            self.assertIn(f'{key}="${{{key}:-false}}"', self.source)
            self.assertIn(f'{key}="$(normalize_bool "${{{key}:-false}}")"',
                          self.source)

    def test_scoped_run_refuses_a_disabled_analyzer(self):
        for key, scope in ANALYZER_SKIPS.items():
            pattern = (f'"$MONITOR_SCOPE" == "{scope}" && "${key}" == "true"')
            self.assertEqual(self.source.count(pattern), 2,
                             f"both scope guards must refuse --only {scope}")

    def test_remote_script_receives_the_flags(self):
        for key in ANALYZER_SKIPS:
            self.assertIn(f'{key}="\'"${key}"\'"', self.source,
                          f"{key} must be embedded into the remote script")

    def test_remote_sections_gate_on_the_flags(self):
        # Section markers stay; only the body is skipped (optical pattern).
        self.assertEqual(
            self.source.count('if [ "$SKIP_DUPLICATE" != "true" ]; then'), 3,
            "DUP_DATA + FDB_DATA + NEIGH_DATA bodies",
        )
        self.assertEqual(
            self.source.count('if [ "$SKIP_EVPN_MH" != "true" ]; then'), 1)
        self.assertEqual(
            self.source.count('if [ "$SKIP_PFC_ECN" != "true" ]; then'), 1)

    def test_analyzers_do_not_start_when_skipped(self):
        for key, scope in ANALYZER_SKIPS.items():
            self.assertIn(
                f'if scope_selected {scope} && [[ "${key}" != "true" ]]; then',
                self.source,
            )

    def test_validate_outputs_require_artifacts_only_when_enabled(self):
        for key in ANALYZER_SKIPS:
            self.assertIn(f'if [[ "${key}" != "true" ]]; then', self.source)

    def test_publish_purges_stage_artifacts_and_writes_placeholder(self):
        publish = _extract_function(self.source, "publish_full_monitor_results")
        purged = (
            "duplicate-analysis.html", "summary/duplicate-summary.json",
            "export/duplicate.json", "export/duplicate.json.sha256",
            "export/duplicate.csv", "export/duplicate.csv.sha256",
            "dup-data/dup_seq_state.json", "dup-data/dup_ip_state.json",
            "evpn-mh-analysis.html", "summary/evpn-mh-summary.json",
            "export/evpn-mh.json", "export/evpn-mh.json.sha256",
            "export/evpn-mh.csv", "export/evpn-mh.csv.sha256",
            "pfc-ecn-analysis.html", "pfc_ecn_baseline.json",
            "summary/pfc-ecn-summary.json",
            "export/pfc-ecn.json", "export/pfc-ecn.json.sha256",
            "export/pfc-ecn.csv", "export/pfc-ecn.csv.sha256",
        )
        for name in purged:
            self.assertIn(name, publish, f"{name} not purged when skipped")
        self.assertEqual(publish.count('data-analysis-status="skipped"'), 4,
                         "optical + duplicate + evpn-mh + pfc-ecn placeholders")

    def test_manifest_records_every_skipped_analyzer(self):
        for key, scope in ANALYZER_SKIPS.items():
            self.assertIn(f'[[ "${key}" == "true" ]] && skipped_list+="{scope},"',
                          self.source)
        self.assertIn(
            '"skipped": [item for item in sys.argv[4].split(",") if item],',
            self.source,
        )

    def test_dashboard_accepts_skipped_analyzers(self):
        dashboard = START_HTML.read_text(encoding="utf-8")
        self.assertIn(
            "const skippableAnalyses = ['optical', 'duplicate', 'evpn-mh', 'pfc-ecn'];",
            dashboard,
        )
        self.assertIn("manifest.skipped.includes('duplicate')", dashboard)
        self.assertIn("{ 'evpn-mh': 'evpn-mh', 'pfc': 'pfc-ecn' }", dashboard)


class AnalyzerSkipFunctionalTests(unittest.TestCase):
    def test_scoped_duplicate_run_exits_2_when_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            # macOS test hosts have no flock binary; the guard under test sits
            # after the lock acquisition, so a no-op stub is faithful enough.
            stub_bin = Path(tmp) / "bin"
            stub_bin.mkdir()
            flock = stub_bin / "flock"
            flock.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            flock.chmod(0o755)
            result = subprocess.run(
                ["bash", str(MONITOR), "--only", "duplicate"],
                cwd=SCRIPT_DIR,
                env={"PATH": f"{stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                     "HOME": tmp,
                     "TMPDIR": tmp,
                     "SKIP_DUPLICATE": "true",
                     "LLDPQ_MONITOR_LOCK_FILE": str(Path(tmp) / "lock"),
                     "LLDPQ_CONFIG_HELPER": "/nonexistent-helper"},
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("duplicate collection is disabled by SKIP_DUPLICATE",
                      result.stderr)


class AlertManifestSkipTests(unittest.TestCase):
    def _load_manifest(self, analyses, skipped):
        import check_alerts

        checker = object.__new__(check_alerts.LLDPqAlerts)
        with tempfile.TemporaryDirectory() as tmp:
            monitor_results = Path(tmp)
            checker.monitor_results = monitor_results
            checker.had_error = False
            manifest = {
                "status": "current",
                "pipeline_complete": True,
                "pipeline_id": "20260724T000000Z-1-1",
                "analyses": analyses,
                "skipped": skipped,
                "device_count": 1,
                "completed_at": "2026-07-24T00:00:00+00:00",
            }
            (monitor_results / ".lldpq-current.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                checker.load_run_manifest()
            return output.getvalue()

    BASE_ANALYSES = ["bgp", "flap", "ber", "hardware", "log", "optical"]

    def test_missing_duplicate_fails_without_skip_record(self):
        output = self._load_manifest(
            self.BASE_ANALYSES + ["evpn-mh", "pfc-ecn"], [])
        self.assertIn("missing completed analyses: duplicate", output)

    def test_skipped_analyzers_are_not_required(self):
        output = self._load_manifest(
            self.BASE_ANALYSES, ["duplicate", "evpn-mh", "pfc-ecn"])
        self.assertNotIn("missing completed analyses", output)


if __name__ == "__main__":
    unittest.main()
