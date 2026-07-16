#!/usr/bin/env python3
"""Regression checks for shared Fabric API command-lock permissions."""

from __future__ import annotations

import grp
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FABRIC_API = (ROOT / "html" / "fabric-api.sh").read_text(encoding="utf-8")
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "docker" / "docker-entrypoint.sh").read_text(encoding="utf-8")
RUNTIME_PREAMBLE_START = FABRIC_API.index(
    'FABRIC_LOCK_DIR="${FABRIC_LOCK_DIR:-'
)
RUNTIME_PREAMBLE_END = FABRIC_API.index(
    "acquire_lock() {", RUNTIME_PREAMBLE_START
)
RUNTIME_PREAMBLE = FABRIC_API[
    RUNTIME_PREAMBLE_START:RUNTIME_PREAMBLE_END
]


class FabricLockPermissionTests(unittest.TestCase):
    def test_runtime_preamble_declares_shared_group_contract(self) -> None:
        self.assertIn('chmod 2770 "$FABRIC_LOCK_DIR"', RUNTIME_PREAMBLE)
        self.assertNotIn('chmod 700 "$FABRIC_LOCK_DIR"', RUNTIME_PREAMBLE)
        self.assertIn(
            'chgrp "$FABRIC_LOCK_GROUP" "$FABRIC_LOCK_DIR"', RUNTIME_PREAMBLE
        )
        self.assertIn(
            '(umask 0007; : >>"$FABRIC_LOCK_FILE")', RUNTIME_PREAMBLE
        )
        self.assertIn('chmod 660 "$FABRIC_LOCK_FILE"', RUNTIME_PREAMBLE)

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "setgid directory behavior is a GNU/Linux runtime contract",
    )
    def test_runtime_preamble_applies_shared_modes_on_linux(self) -> None:
        # Keep the functional probe inside the repository so sandboxed test
        # runners that restrict writes outside the workspace can chmod it.
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            lock_dir = Path(temporary) / "locks"
            group = grp.getgrgid(os.getgid()).gr_name
            environment = dict(
                os.environ,
                FABRIC_LOCK_DIR=str(lock_dir),
                FABRIC_LOCK_GROUP=group,
            )
            subprocess.run(
                ["bash", "-c", RUNTIME_PREAMBLE],
                env=environment,
                check=True,
            )

            lock_file = lock_dir / "fabric-api.lock"
            self.assertEqual(stat.S_IMODE(lock_dir.stat().st_mode), 0o2770)
            self.assertEqual(stat.S_IMODE(lock_file.stat().st_mode), 0o660)
            self.assertEqual(lock_file.stat().st_gid, lock_dir.stat().st_gid)

    def test_python_command_locks_use_group_shared_mode(self) -> None:
        mode_contract = "mode = 0o660 if _using_secure_lock_dir else 0o600"
        self.assertEqual(FABRIC_API.count(mode_contract), 2)
        self.assertEqual(
            FABRIC_API.count(
                "_lock_dir = os.environ.get('FABRIC_LOCK_DIR') or '/tmp'"
            ),
            2,
        )

    def test_native_update_migrates_legacy_lock_permissions(self) -> None:
        self.assertIn(
            'sudo install -d -o "$LLDPQ_USER" -g www-data -m 2770 '
            '"$WEB_ROOT/.locks"',
            INSTALL,
        )
        self.assertIn(
            'find "$WEB_ROOT/.locks" -mindepth 1 -maxdepth 1 '
            "-type f -name '*.lock'",
            INSTALL,
        )
        self.assertIn('-exec chown "$LLDPQ_USER:www-data" {} +', INSTALL)
        self.assertIn("-exec chmod 660 {} +", INSTALL)

    def test_docker_startup_matches_native_lock_contract(self) -> None:
        self.assertIn("FABRIC_LOCK_DIR=/var/www/html/.locks", ENTRYPOINT)
        self.assertIn(
            'install -d -o lldpq -g www-data -m 2770 "$FABRIC_LOCK_DIR"',
            ENTRYPOINT,
        )
        self.assertIn("-exec chown lldpq:www-data {} +", ENTRYPOINT)
        self.assertIn("-exec chmod 660 {} +", ENTRYPOINT)


if __name__ == "__main__":
    unittest.main()
