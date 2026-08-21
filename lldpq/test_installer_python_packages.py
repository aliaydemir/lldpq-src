#!/usr/bin/env python3
"""Contracts for PEP-668-safe installer Python dependencies."""

from pathlib import Path
import os
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "install.sh").read_text(encoding="utf-8")
SYSTEM_PATH = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def _path_setup() -> str:
    match = re.search(
        r'^PATH="/usr/local/sbin:.*?\nexport PATH$',
        SOURCE,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError("install.sh no longer defines its trusted system PATH")
    return match.group(0)


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


class InstallerSystemPathTests(unittest.TestCase):
    """Service binaries must be found even when a user's PATH omits sbin."""

    def _resolved_path(self, initial_path: str) -> list[str]:
        result = subprocess.run(
            ["/bin/bash", "-c", _path_setup() + '\nprintf "%s" "$PATH"\n'],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PATH": initial_path},
        )
        return result.stdout.split(":")

    def test_trusted_system_directories_are_prepended_in_fixed_order(self):
        resolved = self._resolved_path("/customer/custom/bin")
        self.assertEqual(resolved[: len(SYSTEM_PATH)], list(SYSTEM_PATH))

    def test_operator_path_is_retained_after_trusted_directories(self):
        resolved = self._resolved_path("/customer/bin:/opt/tool/bin")
        self.assertEqual(resolved[-2:], ["/customer/bin", "/opt/tool/bin"])

    def test_empty_invoking_path_does_not_create_an_empty_component(self):
        self.assertEqual(self._resolved_path(""), list(SYSTEM_PATH))

    def test_path_is_normalized_before_strict_mode_and_dependency_checks(self):
        path_setup = SOURCE.index(_path_setup())
        self.assertLess(path_setup, SOURCE.index("set -e"))
        self.assertLess(path_setup, SOURCE.index("ensure_update_runtime_dependencies()"))


class InstallerBackupHelperTests(unittest.TestCase):
    """The privileged recovery helper must never be installed unvalidated."""

    @staticmethod
    def _install_block() -> str:
        start = SOURCE.find('echo "  - Installing root-owned backup/import helper"')
        end = SOURCE.find('echo "  - Installing root-owned authentication users helper"')
        if start < 0 or end < 0 or end <= start:
            raise AssertionError("backup helper install block is missing or malformed")
        return SOURCE[start:end]

    def test_source_is_compiled_before_any_privileged_install(self):
        block = self._install_block()
        compile_check = block.find(
            "compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], \"exec\")"
        )
        privileged_install = block.find("sudo install -o root -g root")
        self.assertGreaterEqual(compile_check, 0, "backup helper has no syntax check")
        self.assertGreater(privileged_install, compile_check)

    def test_helper_is_staged_then_atomically_renamed(self):
        block = self._install_block()
        self.assertEqual(
            block.count(
                '_backup_helper_stage="${LLDPQ_BACKUP_IMPORT_HELPER}.lldpq-new"'
            ),
            1,
        )
        self.assertEqual(
            block.count(
                'sudo mv -fT -- "$_backup_helper_stage" "$LLDPQ_BACKUP_IMPORT_HELPER"'
            ),
            1,
        )

    def test_installed_helper_identity_and_content_are_verified(self):
        block = self._install_block()
        self.assertIn('0:0:755:1', block)
        self.assertIn(
            'sudo cmp -s -- lldpq/backup_import.py "$LLDPQ_BACKUP_IMPORT_HELPER"',
            block,
        )

    def test_source_is_never_installed_directly_over_the_live_helper(self):
        block = self._install_block()
        direct = re.compile(
            r"sudo install[^\n]*\n[ \t]*"
            r"lldpq/backup_import\.py[ \t]+"
            r'"\$LLDPQ_BACKUP_IMPORT_HELPER"'
        )
        self.assertIsNone(
            direct.search(block),
            "backup helper must be installed through its sibling stage",
        )


if __name__ == "__main__":
    unittest.main()
