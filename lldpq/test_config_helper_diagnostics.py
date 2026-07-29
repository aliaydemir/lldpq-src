#!/usr/bin/env python3
"""Regression tests for runtime configuration failure diagnostics.

Every shell entrypoint collapses a config helper failure into one generic
line: "required runtime configuration is missing or unreadable".  The helper
itself distinguishes a missing file, an unreadable file and a missing key, so
discarding its stderr left an operator with no way to tell a wrong-user
permission problem apart from a truncated config.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_HELPER = REPO_ROOT / "bin" / "lldpq-config"

ENTRYPOINTS = (
    REPO_ROOT / "bin" / "lldpq",
    REPO_ROOT / "bin" / "lldpq-trigger",
    REPO_ROOT / "bin" / "get-conf",
    REPO_ROOT / "lldpq" / "assets.sh",
    REPO_ROOT / "lldpq" / "fabric-scan.sh",
)


def _helper_shim(directory: Path, config: Path) -> Path:
    """Wrap the real helper so it reads a test config instead of /etc."""
    shim = directory / "helper"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        f'exec "{CONFIG_HELPER}" "$@" --config "{config}"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)
    return shim


def _run_lldpq(shim: Path) -> subprocess.CompletedProcess:
    environment = dict(os.environ, LLDPQ_CONFIG_HELPER=str(shim))
    return subprocess.run(
        [str(REPO_ROOT / "bin" / "lldpq"), "-"],
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )


class HelperDiagnosticsReachTheOperatorTests(unittest.TestCase):
    """The helper's specific reason must survive the entrypoint wrapper."""

    def test_missing_config_names_the_missing_file(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            shim = _helper_shim(directory, directory / "absent.conf")
            result = _run_lldpq(shim)
        self.assertEqual(result.returncode, 1)
        self.assertIn("required config is missing", result.stderr)
        self.assertIn("absent.conf", result.stderr)

    def test_unreadable_config_is_distinguishable_from_a_missing_one(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses the permission bits under test")
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            config = directory / "lldpq.conf"
            config.write_text(
                "LLDPQ_DIR=/opt/lldpq\nLLDPQ_USER=lldpq\nWEB_ROOT=/var/www/html\n",
                encoding="utf-8",
            )
            config.chmod(0o000)
            shim = _helper_shim(directory, config)
            result = _run_lldpq(shim)
        self.assertEqual(result.returncode, 1)
        self.assertIn("required config is unreadable", result.stderr)

    def test_missing_key_names_the_key(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            config = directory / "lldpq.conf"
            config.write_text(
                "LLDPQ_DIR=/opt/lldpq\nLLDPQ_USER=lldpq\n", encoding="utf-8"
            )
            shim = _helper_shim(directory, config)
            result = _run_lldpq(shim)
        self.assertEqual(result.returncode, 1)
        self.assertIn("required key(s) missing or empty: WEB_ROOT", result.stderr)


class EntrypointContractTests(unittest.TestCase):
    """No entrypoint may silence the helper it depends on."""

    def test_no_entrypoint_discards_helper_stderr(self):
        pattern = re.compile(r"--require-config[^)]*?2>\s*/dev/null", re.DOTALL)
        for path in ENTRYPOINTS:
            with self.subTest(entrypoint=path.name):
                self.assertIsNone(
                    pattern.search(path.read_text(encoding="utf-8")),
                    f"{path.name} sends the config helper's diagnosis to /dev/null",
                )


if __name__ == "__main__":
    unittest.main()
