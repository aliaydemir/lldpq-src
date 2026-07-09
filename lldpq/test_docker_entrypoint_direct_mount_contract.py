#!/usr/bin/env python3
"""Regression contract for crash-safe Docker startup configuration writes."""

import fcntl
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = ROOT / "docker" / "docker-entrypoint.sh"


class DockerEntrypointDirectMountContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = ENTRYPOINT.read_text(encoding="utf-8")
        opener = "<<'PYTHON_SET_LLDPQ_CONF'\n"
        start = cls.source.index(opener) + len(opener)
        end = cls.source.index("\nPYTHON_SET_LLDPQ_CONF\n", start)
        cls.set_conf_program = cls.source[start:end]
        isc_opener = "<<'PYTHON_SET_ISC_DHCP_DEFAULT'\n"
        isc_start = cls.source.index(isc_opener) + len(isc_opener)
        isc_end = cls.source.index(
            "\nPYTHON_SET_ISC_DHCP_DEFAULT\n", isc_start
        )
        cls.set_isc_default_program = cls.source[isc_start:isc_end]

    def _run_set_conf(
        self, path: Path, lock: Path, key: str, value: str, *,
        direct: bool, only_if_missing: bool = False,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                self.set_conf_program,
                str(path),
                key,
                value,
                "true" if direct else "false",
                "true" if only_if_missing else "false",
                str(lock),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def _fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        config = root / "lldpq.conf"
        config.write_text(
            "LLDPQ_DIR=/home/lldpq/lldpq\n"
            "LLDPQ_USER=lldpq\n"
            "WEB_ROOT=/var/www/html\n"
            "ANSIBLE_DIR=NoNe\n",
            encoding="utf-8",
        )
        config.chmod(0o660)
        lock = root / "lldpq.conf.lock"
        lock.write_text("", encoding="utf-8")
        lock.chmod(0o660)
        return config, lock

    def _run_set_isc_default(
        self, path: Path, interface: str, *, direct: bool
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-c",
                self.set_isc_default_program,
                str(path),
                interface,
                "true" if direct else "false",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_direct_file_mount_change_fails_without_touching_live_inode(self):
        config, lock = self._fixture()
        before = config.read_bytes(), config.stat().st_ino, config.stat().st_mode

        result = self._run_set_conf(
            config, lock, "ANSIBLE_DIR", "/home/lldpq/ansible", direct=True
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("legacy single-file Docker mount", result.stderr)
        self.assertIn("lldpq-system-config", result.stderr)
        self.assertEqual(
            (config.read_bytes(), config.stat().st_ino, config.stat().st_mode), before
        )

    def test_direct_file_mount_unchanged_value_is_a_true_noop(self):
        config, lock = self._fixture()
        before = config.read_bytes(), config.stat().st_ino, config.stat().st_mode

        result = self._run_set_conf(
            config, lock, "ANSIBLE_DIR", "NoNe", direct=True
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (config.read_bytes(), config.stat().st_ino, config.stat().st_mode), before
        )

    def test_normal_target_is_atomically_replaced_with_preserved_mode(self):
        config, lock = self._fixture()
        before_inode = config.stat().st_ino

        result = self._run_set_conf(
            config, lock, "ANSIBLE_DIR", "/home/lldpq/ansible", direct=False
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(config.stat().st_ino, before_inode)
        self.assertEqual(config.stat().st_mode & 0o7777, 0o660)
        self.assertIn("ANSIBLE_DIR=/home/lldpq/ansible\n", config.read_text())
        self.assertIn("os.fsync(handle.fileno())", self.set_conf_program)
        self.assertIn("os.replace(temporary, path)", self.set_conf_program)
        self.assertIn("os.fsync(directory_descriptor)", self.set_conf_program)

    def test_default_mode_preserves_existing_value_and_atomically_adds_missing(self):
        config, lock = self._fixture()
        config.write_text(
            config.read_text() + "AUTO_BASE_CONFIG=false\n", encoding="utf-8"
        )
        preserved_inode = config.stat().st_ino

        preserved = self._run_set_conf(
            config, lock, "AUTO_BASE_CONFIG", "true",
            direct=False, only_if_missing=True,
        )
        self.assertEqual(preserved.returncode, 0, preserved.stderr)
        self.assertEqual(config.stat().st_ino, preserved_inode)
        self.assertIn("AUTO_BASE_CONFIG=false\n", config.read_text())

        added = self._run_set_conf(
            config, lock, "AUTO_ZTP_DISABLE", "true",
            direct=False, only_if_missing=True,
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        self.assertNotEqual(config.stat().st_ino, preserved_inode)
        self.assertIn("AUTO_ZTP_DISABLE=true\n", config.read_text())

    def test_set_conf_waits_for_shared_configuration_lock(self):
        config, lock = self._fixture()
        descriptor = os.open(lock, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                self.set_conf_program,
                str(config),
                "ANSIBLE_DIR",
                "/home/lldpq/ansible",
                "false",
                "false",
                str(lock),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                process.communicate(timeout=0.1)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            descriptor = None
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        finally:
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_defaults_and_initial_dhcp_follow_safe_source_order(self):
        defaults = self.source.index(
            '# Default post-provision settings in lldpq.conf (if not present)'
        )
        defaults_end = self.source.index("\n\n_docker_dhcp_is_managed", defaults)
        defaults_source = self.source[defaults:defaults_end]
        self.assertIn(
            '_set_lldpq_conf_value "$key" "${key_val#*=}" true', defaults_source
        )
        self.assertNotIn(">> /etc/lldpq.conf", defaults_source)

        install_start = self.source.index("_install_docker_dhcp_config() {")
        install_end = self.source.index(
            "\n_migrate_managed_dhcp_server_references()", install_start
        )
        install_source = self.source[install_start:install_end]
        preflight = install_source.index(
            "if _is_direct_mount /etc/dhcp/dhcpd.conf; then"
        )
        backup = install_source.index('if [ "$backup_existing" = "true" ]')
        self.assertLess(preflight, backup)
        self.assertIn('cmp -s "$temp_file" /etc/dhcp/dhcpd.conf', install_source)
        self.assertIn("The live file was not modified", install_source)
        self.assertNotIn('cp "$temp_file" /etc/dhcp/dhcpd.conf', install_source)
        self.assertIn('sync -f "$staged_file"', install_source)
        self.assertIn('sync -f "$(dirname "$target_file")"', install_source)

    def test_isc_defaults_direct_mount_is_noop_or_fails_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "isc-dhcp-server"
            target.write_text('INTERFACES="eth0"\n', encoding="utf-8")
            target.chmod(0o664)
            before = target.read_bytes(), target.stat().st_ino, target.stat().st_mode

            unchanged = self._run_set_isc_default(target, "eth0", direct=True)
            self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
            self.assertEqual(
                (target.read_bytes(), target.stat().st_ino, target.stat().st_mode),
                before,
            )

            changed = self._run_set_isc_default(target, "eno1", direct=True)
            self.assertNotEqual(changed.returncode, 0)
            self.assertIn("legacy single-file Docker mount", changed.stderr)
            self.assertIn("lldpq-system-config", changed.stderr)
            self.assertEqual(
                (target.read_bytes(), target.stat().st_ino, target.stat().st_mode),
                before,
            )

    def test_isc_defaults_normal_target_is_durably_atomically_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "isc-dhcp-server"
            target.write_text('INTERFACES="eth0"\n', encoding="utf-8")
            target.chmod(0o664)
            before_inode = target.stat().st_ino

            result = self._run_set_isc_default(target, "eno1", direct=False)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), b'INTERFACES="eno1"\n')
            self.assertNotEqual(target.stat().st_ino, before_inode)
            self.assertEqual(target.stat().st_mode & 0o7777, 0o664)
            self.assertIn("os.fsync(handle.fileno())", self.set_isc_default_program)
            self.assertIn("os.replace(temporary, path)", self.set_isc_default_program)
            self.assertIn(
                "os.fsync(directory_descriptor)", self.set_isc_default_program
            )

    def test_both_isc_default_branches_use_common_safe_helper(self):
        self.assertEqual(self.source.count('_set_isc_dhcp_interfaces "$interface"'), 1)
        self.assertEqual(self.source.count("_set_isc_dhcp_interfaces eth0"), 1)
        self.assertNotRegex(
            self.source,
            r"(?:printf|echo)[^\n]*> /etc/default/isc-dhcp-server",
        )
        helper_start = self.source.index("_set_isc_dhcp_interfaces() {")
        helper_end = self.source.index("\n}\n\n# ─── Ansible", helper_start)
        helper = self.source[helper_start:helper_end]
        self.assertLess(
            helper.index("if direct_mount:"),
            helper.index("tempfile.mkstemp"),
        )


if __name__ == "__main__":
    unittest.main()
