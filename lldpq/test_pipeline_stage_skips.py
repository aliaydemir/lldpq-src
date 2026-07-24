#!/usr/bin/env python3
"""Stage-skip toggles in bin/lldpq (SKIP_ASSETS/LLDP/MONITOR/FABRIC_SCAN/ALERTS).

Static pins lock the gating shape (verbose-only notices, withheld pipeline
identity, stale-marker suppression); functional runs drive the real script
with stub stages through a stub config helper. Scenarios that would reach
wait_until_not_running are avoided on purpose: its pgrep -f pattern can match
unrelated developer processes (an editor with assets.sh open) and hang.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LLDPQ_BIN = SCRIPT_DIR.parent / "bin" / "lldpq"
FABRIC_SCAN = SCRIPT_DIR / "fabric-scan.sh"
SEARCH_API = SCRIPT_DIR.parent / "html" / "search-api.sh"

STAGE_SKIP_KEYS = (
    "SKIP_ASSETS", "SKIP_LLDP", "SKIP_MONITOR", "SKIP_FABRIC_SCAN",
    "SKIP_ALERTS",
)


class StageSkipStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LLDPQ_BIN.read_text(encoding="utf-8")

    def test_every_stage_flag_is_normalized(self):
        self.assertIn("normalize_bool()", self.source)
        for key in STAGE_SKIP_KEYS:
            self.assertIn(
                f'{key}="$(normalize_bool "${{{key}:-false}}")"', self.source,
                f"{key} must normalize to a strict true/false",
            )

    def test_skip_notices_are_verbose_only(self):
        # The scheduled cron line has no output redirect; unconditional stdout
        # would become recurring cron mail.
        self.assertIn('log_notice() {', self.source)
        self.assertIn('[[ "$QUIET" == "true" ]] || echo "$1"', self.source)
        for key in STAGE_SKIP_KEYS:
            self.assertIn(f"({key}=true)", self.source,
                          f"{key} skip notice missing")
        self.assertNotIn('echo "Asset discovery skipped', self.source.replace(
            'log_notice "Asset discovery skipped', ''))

    def test_pipeline_identity_withheld_when_sources_are_skipped(self):
        # A run that did not refresh assets/LLDP must publish under the
        # incomplete-pipeline contract or the manifest mtime check fails.
        self.assertIn(
            'if [[ "$SKIP_ASSETS" == "true" || "$SKIP_LLDP" == "true" ]]; then',
            self.source,
        )
        self.assertIn("unset LLDPQ_PIPELINE_ID LLDPQ_PIPELINE_STARTED_AT",
                      self.source)

    def test_skip_monitor_suppresses_pre_monitor_stale_marking(self):
        # With the monitor stage skipped the published reports belong to an
        # older generation; an assets/LLDP failure must not stale them.
        self.assertEqual(
            self.source.count(
                'if [[ "$SKIP_MONITOR" != "true" ]]; then'), 4,
            "collecting marker + assets/LLDP failures + raw-inputs invariant",
        )

    def test_skip_fabric_scan_counts_as_success(self):
        self.assertIn('if [[ "$SKIP_FABRIC_SCAN" == "true" ]]; then',
                      self.source)
        self.assertIn("fabric_status=0", self.source)

    def test_skip_alerts_gates_both_alert_invocations(self):
        # Pinned strings stay intact for test_post_pipeline_scheduling.
        pre = self.source.index(
            "run_command python3 ./check_alerts.py --assets-only")
        self.assertIn('if [[ "$SKIP_ALERTS" == "true" ]]; then',
                      self.source[:pre])
        post_gate = self.source.rindex('if [[ "$SKIP_ALERTS" == "true" ]]; then')
        self.assertIn("run_command python3 ./check_alerts.py",
                      self.source[post_gate:])

    def test_fabric_scan_self_gate_with_force_escape(self):
        scan = FABRIC_SCAN.read_text(encoding="utf-8")
        self.assertIn("SKIP_FABRIC_SCAN", scan)
        self.assertIn("LLDPQ_FABRIC_SCAN_FORCE", scan)
        self.assertIn("fabric scan disabled by configuration", scan)
        api = SEARCH_API.read_text(encoding="utf-8")
        self.assertIn("env LLDPQ_FABRIC_SCAN_FORCE=1", api)


class StageSkipFunctionalTests(unittest.TestCase):
    def _write_stub(self, path, body):
        path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _make_tree(self, conf_extra):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        lldpq_dir = root / "lldpq"
        web_root = root / "www"
        witness = root / "witness"
        for directory in (lldpq_dir, web_root, witness):
            directory.mkdir()
        helper = root / "lldpq-config"
        run_user = os.environ.get("USER", "nobody")
        lines = [
            f"echo 'LLDPQ_DIR={lldpq_dir}'",
            f"echo 'LLDPQ_USER={run_user}'",
            f"echo 'WEB_ROOT={web_root}'",
        ] + [f"echo '{line}'" for line in conf_extra]
        self._write_stub(helper, "\n".join(lines) + "\n")
        for stage in ("assets.sh", "check-lldp.sh", "monitor.sh",
                      "fabric-scan.sh"):
            name = stage.replace(".sh", "")
            self._write_stub(
                lldpq_dir / stage,
                f"echo \"pipeline_id=$LLDPQ_PIPELINE_ID\" > '{witness}/{name}'\n"
                # A real monitor clears the report-state marker on success.
                + ("rm -f monitor-results/.lldpq-stale\n"
                   if stage == "monitor.sh" else ""),
            )
        (lldpq_dir / "check_alerts.py").write_text(
            f"open(r'{witness}/alerts', 'a').write('ran\\n')\n",
            encoding="utf-8",
        )
        return root, lldpq_dir, witness

    def _run(self, root, lldpq_dir, verbose=False):
        env = dict(os.environ)
        env.update({
            "LLDPQ_CONFIG_HELPER": str(root / "lldpq-config"),
            "LLDPQ_MONITOR_LOCK_FILE": str(root / "lock"),
            # Point at a non-executable path so the detached AI launch is
            # skipped deterministically.
            "LLDPQ_AI_ANALYZER": str(root / "missing-analyzer"),
        })
        args = ["bash", str(LLDPQ_BIN)] + (["-"] if verbose else [])
        return subprocess.run(
            args, cwd=lldpq_dir, env=env,
            capture_output=True, text=True, timeout=60,
        )

    def test_all_stage_skips_run_touches_nothing_and_exits_zero(self):
        root, lldpq_dir, witness = self._make_tree([
            "SKIP_ASSETS=true", "SKIP_LLDP=true", "SKIP_MONITOR=true",
            "SKIP_FABRIC_SCAN=true", "SKIP_ALERTS=true",
        ])
        result = self._run(root, lldpq_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "", "quiet run must stay silent")
        self.assertEqual(list(witness.iterdir()), [],
                         "no stage may run when every stage is skipped")
        self.assertFalse(
            (lldpq_dir / "monitor-results" / ".lldpq-stale").exists(),
            "a fully skipped run must not touch the report-state marker",
        )

    def test_all_stage_skips_verbose_prints_each_notice(self):
        root, lldpq_dir, _ = self._make_tree([
            "SKIP_ASSETS=true", "SKIP_LLDP=true", "SKIP_MONITOR=true",
            "SKIP_FABRIC_SCAN=true", "SKIP_ALERTS=true",
        ])
        result = self._run(root, lldpq_dir, verbose=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for key in STAGE_SKIP_KEYS:
            self.assertIn(f"({key}=true)", result.stdout)

    def test_monitor_runs_without_pipeline_identity_when_sources_skipped(self):
        root, lldpq_dir, witness = self._make_tree([
            "SKIP_ASSETS=true", "SKIP_LLDP=true",
            "SKIP_FABRIC_SCAN=true", "SKIP_ALERTS=true",
        ])
        result = self._run(root, lldpq_dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((witness / "monitor").read_text(encoding="utf-8"),
                         "pipeline_id=\n",
                         "identity must be withheld for a partial run")
        self.assertFalse((witness / "assets").exists())
        self.assertFalse((witness / "check-lldp").exists())
        self.assertFalse((witness / "alerts").exists())


if __name__ == "__main__":
    unittest.main()
