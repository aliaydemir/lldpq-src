#!/usr/bin/env python3
"""Regression contracts for post-pipeline scheduling and lock priority."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "docker/docker-entrypoint.sh").read_text(encoding="utf-8")
LLDPQ = (ROOT / "bin/lldpq").read_text(encoding="utf-8")
AI_ANALYZER = ROOT / "bin/lldpq-ai-analyze"
AI_ANALYZER_TEXT = AI_ANALYZER.read_text(encoding="utf-8")


class PostPipelineSchedulingTests(unittest.TestCase):
    def test_scheduled_fabric_scan_yields_lock_priority_for_thirty_seconds(self):
        native = (
            'echo "* * * * * $user /bin/sleep 30 && cd $q_install '
            '&& ./fabric-scan.sh >/dev/null 2>&1"'
        )
        docker = (
            "* * * * * lldpq /bin/sleep 30 && cd /home/lldpq/lldpq "
            "&& ./fabric-scan.sh > /dev/null 2>&1"
        )
        self.assertIn(native, INSTALL)
        self.assertIn(docker, ENTRYPOINT)
        self.assertNotIn(
            'echo "* * * * * $user cd $q_install && ./fabric-scan.sh',
            INSTALL,
        )
        self.assertNotIn(
            "* * * * * lldpq cd /home/lldpq/lldpq && ./fabric-scan.sh",
            ENTRYPOINT,
        )

    def test_fixed_clock_ai_cron_is_replaced_by_post_pipeline_trigger(self):
        self.assertNotIn(
            'echo "7 * * * * $user /usr/local/bin/lldpq-ai-analyze"',
            INSTALL,
        )
        self.assertNotIn(
            "7 * * * * lldpq /usr/local/bin/lldpq-ai-analyze",
            ENTRYPOINT,
        )
        launch = 'nohup "$AI_ANALYZER" --if-due >/dev/null 2>&1 9>&- &'
        self.assertIn(launch, LLDPQ)
        self.assertIn('if [[ $fabric_status -eq 0 && -x "$AI_ANALYZER" ]]', LLDPQ)
        self.assertLess(LLDPQ.index("run_command ./fabric-scan.sh"), LLDPQ.index(launch))
        self.assertLess(
            LLDPQ.index("run_command python3 ./check_alerts.py"),
            LLDPQ.index(launch),
        )
        self.assertIn('data.get("persisted") is True', AI_ANALYZER_TEXT)

    def test_if_due_throttles_attempts_but_manual_cli_can_force_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            web = root / "web"
            state.mkdir()
            web.mkdir()
            count = root / "count"
            (web / "ai-api.sh").write_text(
                """#!/bin/bash
printf 'run\\n' >> "$TEST_RUN_COUNT"
printf 'Content-Type: application/json\\n\\n'
printf '{"success":true,"persisted":true}\\n'
""",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment.update({
                "AI_PROVIDER": "contract-test",
                "AI_MODEL": "contract-test",
                "AI_STATE_DIR": str(state),
                "WEB_ROOT": str(web),
                "TEST_RUN_COUNT": str(count),
                "LLDPQ_CONFIG_HELPER": str(root / "missing-config-helper"),
                "AI_ANALYSIS_MIN_INTERVAL_SECONDS": "3600",
            })

            first = subprocess.run(
                ["bash", str(AI_ANALYZER), "--if-due"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            second = subprocess.run(
                ["bash", str(AI_ANALYZER), "--if-due"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            forced = subprocess.run(
                ["bash", str(AI_ANALYZER)],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            stamp = state / "last-autonomous-attempt"
            stamp_text = stamp.read_text(encoding="utf-8").strip()
            stamp_mode = stamp.stat().st_mode & 0o777
            stamp.unlink()
            (state / "analysis.json").write_text(
                '{"analysis":"recent manual report"}\n', encoding="utf-8"
            )
            after_manual = subprocess.run(
                ["bash", str(AI_ANALYZER), "--if-due"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(forced.returncode, 0, forced.stderr)
            self.assertEqual(after_manual.returncode, 0, after_manual.stderr)
            self.assertEqual(count.read_text(encoding="utf-8"), "run\nrun\n")
            self.assertRegex(stamp_text, r"^\d+$")
            self.assertEqual(stamp_mode, 0o660)
            self.assertFalse(stamp.exists())


if __name__ == "__main__":
    unittest.main()
