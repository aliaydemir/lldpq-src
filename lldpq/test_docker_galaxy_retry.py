#!/usr/bin/env python3
"""Regression contracts for transient Ansible Galaxy failures during image builds."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "docker" / "install-ansible-collections.sh"
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")


class GalaxyRetryFunctionalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.count = self.root / "count"
        self.calls = self.root / "calls"
        self.sleeps = self.root / "sleeps"
        (self.bin / "ansible-galaxy").write_text(
            """#!/bin/sh
count=0
[ ! -f "$COUNT_FILE" ] || count=$(cat "$COUNT_FILE")
count=$((count + 1))
printf '%s\\n' "$count" > "$COUNT_FILE"
printf '%s\\n' "$*" >> "$CALLS_FILE"
[ "$count" -gt "$FAIL_UNTIL" ]
""",
            encoding="utf-8",
        )
        (self.bin / "sleep").write_text(
            """#!/bin/sh
printf '%s\\n' "$1" >> "$SLEEPS_FILE"
""",
            encoding="utf-8",
        )
        for command in ("ansible-galaxy", "sleep"):
            (self.bin / command).chmod(0o755)

    def run_installer(self, *, fail_until, attempts=4, delay=2, timeout=180):
        env = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "COUNT_FILE": str(self.count),
            "CALLS_FILE": str(self.calls),
            "SLEEPS_FILE": str(self.sleeps),
            "FAIL_UNTIL": str(fail_until),
            "ANSIBLE_GALAXY_MAX_ATTEMPTS": str(attempts),
            "ANSIBLE_GALAXY_RETRY_DELAY": str(delay),
            "ANSIBLE_GALAXY_TIMEOUT": str(timeout),
        }
        return subprocess.run(
            ["/bin/sh", str(INSTALLER)],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

    def test_transient_failures_retry_then_succeed(self):
        result = self.run_installer(fail_until=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.count.read_text(encoding="utf-8").strip(), "3")
        self.assertEqual(
            self.sleeps.read_text(encoding="utf-8").splitlines(), ["2", "4"]
        )

    def test_every_attempt_uses_the_extended_timeout_and_exact_collections(self):
        result = self.run_installer(fail_until=1, timeout=240)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (
            "collection install --timeout 240 "
            "nvidia.nvue community.general ansible.netcommon"
        )
        self.assertEqual(
            self.calls.read_text(encoding="utf-8").splitlines(),
            [expected, expected],
        )

    def test_persistent_failure_stops_after_the_configured_limit(self):
        result = self.run_installer(fail_until=99, attempts=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.count.read_text(encoding="utf-8").strip(), "3")
        self.assertIn("failed after 3 attempts", result.stderr)

    def test_invalid_retry_settings_fail_before_network_access(self):
        result = self.run_installer(fail_until=0, attempts=0)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.count.exists())


class GalaxyRetryDockerfileTests(unittest.TestCase):
    def test_dockerfile_runs_the_retry_helper(self):
        self.assertEqual(
            DOCKERFILE.count(
                "COPY docker/install-ansible-collections.sh "
                "/usr/local/sbin/install-ansible-collections"
            ),
            1,
        )
        self.assertEqual(
            DOCKERFILE.count("&& /usr/local/sbin/install-ansible-collections"),
            1,
        )

    def test_dockerfile_has_no_unprotected_galaxy_install(self):
        offenders = [
            line
            for line in DOCKERFILE.splitlines()
            if line.startswith("RUN ansible-galaxy collection install")
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
