#!/usr/bin/env python3
"""Contracts for PEP-668-safe installer Python dependencies."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "install.sh").read_text(encoding="utf-8")


class InstallerPythonPackageTests(unittest.TestCase):
    def test_ruamel_and_requests_use_os_packages(self):
        self.assertIn("python3-ruamel.yaml", SOURCE)
        self.assertIn("python3-requests", SOURCE)
        self.assertNotRegex(
            SOURCE,
            re.compile(r"pip\s+install[^\n]*(?:ruamel\.yaml|requests)"),
        )

    def test_exact_runtime_user_is_verified_before_update(self):
        self.assertIn(
            'sudo -H -u "$LLDPQ_USER" python3 -c \'import ruamel.yaml\'',
            SOURCE,
        )
        self.assertIn(
            'sudo -H -u "$LLDPQ_USER" python3 -c \'import requests\'',
            SOURCE,
        )
        self.assertIn(
            "sudo apt-get install -y python3-ruamel.yaml", SOURCE
        )

    def test_offline_failure_recommends_os_package_without_mutation(self):
        self.assertIn(
            "sudo apt-get install python3-ruamel.yaml", SOURCE
        )
        self.assertIn(
            "No package download was attempted and the existing runtime was not changed.",
            SOURCE,
        )


if __name__ == "__main__":
    unittest.main()
