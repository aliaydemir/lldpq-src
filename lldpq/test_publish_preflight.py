#!/usr/bin/env python3
"""Publish disk pre-flight contract.

A full run must refuse up front (marker reason=disk_full) when WEB_ROOT's
filesystem cannot hold the publish staging copy, instead of wasting the whole
collection on an ENOSPC minutes later. Estimation failures stay fail-open;
the publish path itself still fails closed on real ENOSPC.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MONITOR = SCRIPT_DIR / "monitor.sh"

FUNCTIONS = (
    "publish_web_report_marker",
    "write_report_state_marker",
    "mark_reports_stale",
    "estimate_publish_requirement_kb",
    "available_kb_for_path",
    "preflight_publish_disk_space",
)


def _extract(source: str, name: str) -> str:
    start = source.index("\n%s() {" % name) + 1
    end = source.index("\n}", start) + 2
    return source[start:end]


class PublishPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = MONITOR.read_text(encoding="utf-8")
        cls.functions = "\n".join(_extract(source, name) for name in FUNCTIONS)

    def _run_preflight(self, avail_kb, du_fails=False):
        root = Path(self.tmp.name)
        script_dir = root / "app"
        (script_dir / "monitor-results").mkdir(parents=True)
        (script_dir / "monitor-results" / "big.bin").write_bytes(b"x" * 1024 * 1024)
        web_root = root / "web"
        web_root.mkdir()

        shims = root / "bin"
        shims.mkdir()
        (shims / "df").write_text(
            "#!/bin/sh\n"
            "echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n"
            "echo \"overlay 1000000 900000 ${FAKE_AVAIL_KB} 99% /\"\n",
            encoding="utf-8",
        )
        (shims / "df").chmod(0o755)
        if du_fails:
            (shims / "du").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            (shims / "du").chmod(0o755)

        assignments = "\n".join((
            'set -u',
            'SCRIPT_DIR="%s"' % script_dir,
            'WEB_ROOT="%s"' % web_root,
            'stale_marker="%s/.lldpq-stale"' % script_dir,
            'status_marker_relative=".lldpq-stale"',
            'scoped_run=false',
            'MONITOR_SCOPE=""',
            'LLDPQ_PIPELINE_ID="preflight-test"',
        ))
        env = dict(os.environ)
        env["PATH"] = str(shims) + os.pathsep + env.get("PATH", "")
        env["FAKE_AVAIL_KB"] = str(avail_kb)
        result = subprocess.run(
            ["/bin/bash", "-c",
             assignments + "\n" + self.functions + "\npreflight_publish_disk_space"],
            env=env, check=False, capture_output=True, text=True,
        )
        marker = script_dir / ".lldpq-stale"
        failures = script_dir / "monitor-failures.log"
        return result, marker, failures

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_insufficient_space_refuses_with_disk_full_reason(self):
        result, marker, failures = self._run_preflight(avail_kb=10)

        self.assertEqual(1, result.returncode, result.stderr)
        content = marker.read_text(encoding="utf-8")
        self.assertIn("status=stale", content)
        self.assertIn("reason=disk_full:", content)
        self.assertIn("pipeline_id=preflight-test", content)
        self.assertIn("disk_full", failures.read_text(encoding="utf-8"))
        self.assertIn("last-known-good web reports were preserved", result.stderr)

    def test_sufficient_space_passes_without_marker(self):
        result, marker, _failures = self._run_preflight(avail_kb=999999999)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(marker.exists())

    def test_estimation_failure_is_fail_open(self):
        result, marker, _failures = self._run_preflight(avail_kb=10, du_fails=True)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
