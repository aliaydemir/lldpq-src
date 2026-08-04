#!/usr/bin/env python3
"""Checks the installer validates DHCP configs where dhcpd is allowed to read.

On Debian/Ubuntu dhcpd runs under an AppArmor profile that permits only a small
set of paths, and /tmp is not one of them.  Validating a candidate parked in
/tmp therefore fails on permissions rather than syntax, which stopped an update
at "Generated DHCP config failed validation" with no reason printed.  The
installer now stages every candidate next to the real configuration and repeats
whatever the validator said.

The fake validator below stands in for that confinement: it refuses to read any
file outside the directories a stock profile allows.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "install.sh"


class DhcpValidationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.conf_dir = self.tmp / "etc" / "dhcp"
        self.conf_dir.mkdir(parents=True)
        self.conf = self.conf_dir / "dhcpd.conf"
        self.hosts = self.conf_dir / "dhcpd.hosts"

    def tearDown(self):
        self._tmp.cleanup()

    # ---------- fake validators ----------
    def write_validator(self, body: str) -> Path:
        path = self.tmp / "fake-dhcpd"
        path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

    def confined_validator(self) -> Path:
        """Accepts syntax, but only for files it is allowed to read."""
        return self.write_validator(f"""
            conf=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -cf) conf="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            allowed="{self.conf_dir}"
            check_readable() {{
                case "$1" in
                    "$allowed"/*) return 0 ;;
                esac
                echo "Can't open $1: Permission denied" >&2
                return 1
            }}
            check_readable "$conf" || exit 1
            # An include the profile forbids is just as fatal as the config
            while read -r line; do
                case "$line" in
                    include*)
                        inc=$(sed 's/.*include *"//; s/".*//' <<< "$line")
                        check_readable "$inc" || exit 1
                        ;;
                esac
            done < "$conf"
            exit 0
        """)

    def syntax_error_validator(self) -> Path:
        """Readable everywhere, but always reports a real parse error."""
        return self.write_validator("""
            echo "/etc/dhcp/dhcpd.conf line 42: semicolon expected." >&2
            echo "Configuration file errors encountered -- exiting" >&2
            exit 1
        """)

    # ---------- harness ----------
    def run_prepare(self, validator: Path, replace_foreign="false"):
        script = f"""
            set -e
            export LLDPQ_INSTALL_LIB_ONLY=true
            export LLDPQ_TEST_NO_SUDO=true
            source '{INSTALL_SH}'
            export DHCPD_VALIDATOR='{validator}'
            status=0
            prepare_default_dhcp_config \\
                '{self.conf}' '{self.hosts}' '{replace_foreign}' \\
                '' '' '192.168.100.10' || status=$?
            echo "STATUS=$status"
        """
        return subprocess.run(["bash", "-c", script], capture_output=True,
                              text=True, cwd=str(ROOT))

    def leftovers(self):
        return sorted(p.name for p in self.conf_dir.iterdir()
                      if p.name.startswith(".lldpq-validate"))

    # ---------- the failure that stopped the update ----------
    def test_a_confined_validator_no_longer_blocks_a_valid_config(self):
        result = self.run_prepare(self.confined_validator())
        self.assertIn("STATUS=0", result.stdout,
                      msg=f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertNotIn("failed validation", result.stderr)
        self.assertTrue(self.conf.is_file())

    def test_the_activated_config_includes_the_real_hosts_path(self):
        """The placeholder used during validation must never be activated."""
        self.run_prepare(self.confined_validator())
        activated = self.conf.read_text(encoding="utf-8")
        self.assertIn(f'include "{self.hosts}";', activated)
        self.assertNotIn(".lldpq-validate-hosts", activated)

    def test_validation_leaves_nothing_behind_on_success(self):
        self.run_prepare(self.confined_validator())
        self.assertEqual(self.leftovers(), [])

    # ---------- a real syntax error must still stop the install ----------
    def test_a_genuine_syntax_error_still_refuses_to_activate(self):
        result = self.run_prepare(self.syntax_error_validator())
        self.assertNotIn("STATUS=0", result.stdout)
        self.assertIn("failed validation", result.stderr)
        self.assertFalse(self.conf.exists(),
                         "a config that failed validation was activated")

    def test_the_validator_reason_is_repeated_to_the_operator(self):
        """Without this the operator sees a verdict with no evidence."""
        result = self.run_prepare(self.syntax_error_validator())
        self.assertIn("semicolon expected", result.stderr)

    def test_validation_leaves_nothing_behind_on_failure(self):
        self.run_prepare(self.syntax_error_validator())
        self.assertEqual(self.leftovers(), [])

    # ---------- surrounding behaviour must not drift ----------
    def test_a_foreign_config_is_still_preserved_without_opt_in(self):
        self.conf.write_text("subnet 10.0.0.0 netmask 255.255.255.0 {}\n",
                             encoding="utf-8")
        result = self.run_prepare(self.confined_validator())
        self.assertIn("STATUS=11", result.stdout)
        self.assertIn("subnet 10.0.0.0", self.conf.read_text(encoding="utf-8"))

    def test_an_existing_lldpq_config_is_kept_and_revalidated_in_place(self):
        self.conf.write_text(
            "# /etc/dhcp/dhcpd.conf - Generated by LLDPq\n"
            f'include "{self.hosts}";\n', encoding="utf-8")
        self.hosts.touch()
        result = self.run_prepare(self.confined_validator())
        self.assertIn("STATUS=10", result.stdout,
                      msg=f"stdout={result.stdout}\nstderr={result.stderr}")

    def test_a_missing_validator_refuses_to_activate_anything(self):
        result = self.run_prepare(self.tmp / "not-installed")
        self.assertNotIn("STATUS=0", result.stdout)
        self.assertIn("validator not found", result.stderr)
        self.assertFalse(self.conf.exists())

    def test_an_existing_hosts_file_is_used_as_its_own_include(self):
        """No placeholder is needed, so none may be created."""
        self.hosts.write_text("# reservations\n", encoding="utf-8")
        result = self.run_prepare(self.confined_validator())
        self.assertIn("STATUS=0", result.stdout)
        self.assertEqual(self.hosts.read_text(encoding="utf-8"), "# reservations\n")
        self.assertEqual(self.leftovers(), [])


if __name__ == "__main__":
    unittest.main()
