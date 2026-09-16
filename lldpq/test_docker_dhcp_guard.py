#!/usr/bin/env python3
"""Regression coverage for Docker's separate DHCP start guard."""

from __future__ import annotations

import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import textwrap
import types
import unittest
from unittest import mock


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("LLDPQ_DHCP_TEST_ROOT", DEFAULT_ROOT))
ENTRYPOINT_PATH = ROOT / "docker" / "docker-entrypoint.sh"
PROVISION_PATH = ROOT / "html" / "provision-api.sh"
DOCKERFILE_PATH = ROOT / "docker" / "Dockerfile"
INSTALL_PATH = ROOT / "install.sh"
DOCKER_DOC_PATH = ROOT / "DOCKER.md"

ENTRYPOINT = ENTRYPOINT_PATH.read_text(encoding="utf-8")
PROVISION = PROVISION_PATH.read_text(encoding="utf-8")
DOCKERFILE = DOCKERFILE_PATH.read_text(encoding="utf-8")
INSTALL = INSTALL_PATH.read_text(encoding="utf-8") if INSTALL_PATH.exists() else ""
DOCKER_DOC = DOCKER_DOC_PATH.read_text(encoding="utf-8")

GUARD_PATH = "/usr/local/libexec/lldpq-dhcpd-guard"
SYSTEM_DHCPD = "/usr/sbin/dhcpd"
LEGACY_DHCPD = "/usr/libexec/lldpq-dhcpd/dhcpd"


def require_text(haystack: str, needle: str, label: str) -> None:
    if needle not in haystack:
        raise AssertionError(f"{label}: missing {needle!r}")


def reject_text(haystack: str, needle: str, label: str) -> None:
    if needle in haystack:
        raise AssertionError(f"{label}: unexpectedly contains {needle!r}")


def guard_function_source() -> str:
    start_marker = "_is_legacy_lldpq_dhcp_guard() {"
    start = ENTRYPOINT.find(start_marker)
    if start < 0:
        raise AssertionError("separate DHCP guard installer functions are missing")
    end = ENTRYPOINT.find("\n_configure_dhcp_runtime\n", start)
    if end < 0:
        raise AssertionError("separate DHCP guard installer boundary is missing")
    return ENTRYPOINT[start:end]


def embedded_python() -> str:
    opener = "python3 << 'PYTHON_SCRIPT'\n"
    start = PROVISION.find(opener)
    end = PROVISION.rfind("\nPYTHON_SCRIPT")
    if start < 0 or end < 0:
        raise AssertionError("Provision embedded Python block is missing")
    return PROVISION[start + len(opener):end]


def python_function_source(name: str) -> str:
    source = embedded_python()
    tree = ast.parse(source, filename=str(PROVISION_PATH))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            if segment:
                return segment
    raise AssertionError(f"Provision function {name} is missing")


def load_python_function(name: str, namespace: dict) -> object:
    source = python_function_source(name)
    exec(compile(source, str(PROVISION_PATH), "exec"), namespace)
    return namespace[name]


def docker_root_sudoers_commands() -> list[str]:
    matches = re.findall(
        r'echo "www-data ALL=\(root\) NOPASSWD:\s*([^"]+)"'
        r"\s*>\s*/etc/sudoers\.d/www-data-provision",
        DOCKERFILE,
    )
    if len(matches) != 1:
        raise AssertionError(
            f"Docker web sudoers policy count is {len(matches)}, expected 1"
        )
    return [item.strip() for item in matches[0].split(",")]


class GuardFixture:
    def __init__(self, testcase: unittest.TestCase):
        self.testcase = testcase
        self.temporary = tempfile.TemporaryDirectory()
        testcase.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.real_dir = self.root / "real"
        self.real_dir.mkdir()
        self.real = self.real_dir / "dhcpd"
        self.guard = self.root / "lldpq-dhcpd-guard"
        self.state = self.root / "docker-dhcp-runtime.env"
        self.dhcp_dir = self.root / "etc-dhcp"
        self.dhcp_dir.mkdir()
        self.persistent_dir = self.root / "persistent-system-config"
        self.persistent_dir.mkdir()
        self.source_config = self.persistent_dir / "dhcpd.conf"
        self.source_hosts = self.persistent_dir / "dhcpd.hosts"
        self.source_config.touch()
        self.source_hosts.touch()
        self.config = self.dhcp_dir / "dhcpd.conf"
        self.hosts = self.dhcp_dir / "dhcpd.hosts"
        self.config.symlink_to(self.source_config)
        self.hosts.symlink_to(self.source_hosts)
        self.runtime_config = self.dhcp_dir / ".lldpq-runtime.conf"
        self.runtime_hosts = self.dhcp_dir / ".lldpq-runtime.hosts"
        self.calls = self.root / "dhcpd.calls"
        self.interface = "test0"
        self.server_ip = "192.0.2.10"
        self._write_fake_ip()
        self._write_fake_dhcpd()
        self.write_state()
        self.write_config()
        self.hosts.write_text("# reservations\n", encoding="utf-8")
        self._render_guard()

    def _write_executable(self, path: Path, body: str) -> None:
        path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def _write_fake_ip(self) -> None:
        self._write_executable(
            self.bin / "ip",
            f"""
            if [ "$*" = "-o -4 addr show dev {self.interface}" ]; then
                echo "2: {self.interface} inet {self.server_ip}/24 scope global {self.interface}"
                exit 0
            fi
            exit 1
            """,
        )

    def _write_fake_dhcpd(self) -> None:
        self._write_executable(
            self.real,
            f"""
            printf '<%s>' "$@" >> '{self.calls}'
            printf '\\n' >> '{self.calls}'
            if [ "${{1:-}}" = "-t" ] && [ "${{FAIL_DHCP_SYNTAX:-false}}" = "true" ]; then
                exit 1
            fi
            exit 0
            """,
        )

    def write_state(
        self,
        *,
        enabled: str = "true",
        mode: str = "host",
        interface: str | None = None,
        server_ip: str | None = None,
    ) -> None:
        self.state.write_text(
            f"DHCP_RUNTIME_ENABLED={enabled}\n"
            f"DHCP_RUNTIME_MODE={mode}\n"
            f"DHCP_RUNTIME_INTERFACE={self.interface if interface is None else interface}\n"
            f"DHCP_RUNTIME_SERVER_IP={self.server_ip if server_ip is None else server_ip}\n",
            encoding="utf-8",
        )

    def write_config(self, *, option_ip: str | None = None) -> None:
        target = self.server_ip if option_ip is None else option_ip
        self.config.write_text(
            f"option www-server {target};\n"
            f'option default-url "http://{target}/";\n'
            f'option cumulus-provision-url "http://{target}/ztp.sh";\n'
            f'include "{self.hosts}";\n',
            encoding="utf-8",
        )

    def _render_guard(
        self,
        *,
        default_config: Path | None = None,
        provisioning_hosts: Path | None = None,
        max_input_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        command = (
            guard_function_source()
            + '\n_render_dhcp_start_guard "$1" "$2" "$3" "$4" "$5" '
            '"$6" "$7" "$8" "$9" "${10}"\n'
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                command,
                "render-guard",
                str(self.guard),
                str(self.real),
                str(self.state),
                str(default_config or self.config),
                str(provisioning_hosts or self.hosts),
                str(self.runtime_config),
                str(self.runtime_hosts),
                str(os.geteuid()),
                str(os.getegid()),
                str(max_input_bytes),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"guard rendering failed: {(result.stderr or result.stdout).strip()[:300]}"
            )
        self.guard.chmod(0o755)

    def run(self, *arguments: str, extra_env: dict[str, str] | None = None):
        environment = os.environ.copy()
        environment["PATH"] = str(self.bin) + os.pathsep + environment.get("PATH", "")
        environment.update(extra_env or {})
        return subprocess.run(
            [str(self.guard), *arguments],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def recorded_calls(self) -> list[str]:
        if not self.calls.exists():
            return []
        return self.calls.read_text(encoding="utf-8").splitlines()


class DockerDhcpGuardFunctionalTests(unittest.TestCase):
    def test_disabled_mode_refuses_before_executing_dhcpd(self):
        fixture = GuardFixture(self)
        fixture.write_state(enabled="false", mode="disabled")

        result = fixture.run(
            "-d", "-cf", str(fixture.config), fixture.interface
        )

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("disabled in Docker bridge/monitoring mode", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])

    def test_wrong_interface_is_refused(self):
        fixture = GuardFixture(self)

        result = fixture.run("-d", "-cf", str(fixture.config), "other0")

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("expected 'test0'", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])

    def test_missing_provisioning_ip_is_refused(self):
        fixture = GuardFixture(self)
        fixture.write_state(server_ip="")

        result = fixture.run(
            "-d", "-cf", str(fixture.config), fixture.interface
        )

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("provisioning server state is incomplete", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])

    def test_unassigned_provisioning_ip_is_refused(self):
        fixture = GuardFixture(self)
        fixture.write_state(server_ip="192.0.2.11")

        result = fixture.run(
            "-d", "-cf", str(fixture.config), fixture.interface
        )

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("is no longer assigned", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])

    def test_invalid_config_is_refused_after_direct_syntax_check(self):
        fixture = GuardFixture(self)

        result = fixture.run(
            "-d",
            "-cf",
            str(fixture.config),
            fixture.interface,
            extra_env={"FAIL_DHCP_SYNTAX": "true"},
        )

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("invalid DHCP configuration", result.stderr)
        self.assertEqual(
            fixture.recorded_calls(),
            [f"<-t><-cf><{fixture.runtime_config}>"],
        )

    def test_provisioning_option_mismatch_is_refused(self):
        fixture = GuardFixture(self)
        fixture.write_config(option_ip="192.0.2.99")

        result = fixture.run(
            "-d", "-cf", str(fixture.config), fixture.interface
        )

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("invalid DHCP provisioning override", result.stderr)
        self.assertEqual(
            fixture.recorded_calls(),
            [f"<-t><-cf><{fixture.runtime_config}>"],
        )

    def test_symlinked_sources_are_copied_to_regular_runtime_snapshots(self):
        fixture = GuardFixture(self)
        source_config = (
            b"# bytes before the managed include stay exact\r\n"
            + f'include\t"{fixture.hosts}" ; # managed\r\n'.encode()
            + b"# bytes after it also stay exact\r\n"
        )
        source_hosts = b"# reservations\r\nhost leaf { fixed-address 192.0.2.20; }\r\n"
        fixture.config.write_bytes(source_config)
        fixture.hosts.write_bytes(source_hosts)

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 0, result.stderr[:300])
        self.assertTrue(fixture.config.is_symlink())
        self.assertTrue(fixture.hosts.is_symlink())
        self.assertFalse(fixture.runtime_config.is_symlink())
        self.assertFalse(fixture.runtime_hosts.is_symlink())
        self.assertTrue(stat.S_ISREG(os.lstat(fixture.runtime_config).st_mode))
        self.assertTrue(stat.S_ISREG(os.lstat(fixture.runtime_hosts).st_mode))
        self.assertEqual(
            stat.S_IMODE(fixture.runtime_config.stat().st_mode), 0o644
        )
        self.assertEqual(
            stat.S_IMODE(fixture.runtime_hosts.stat().st_mode), 0o644
        )
        self.assertEqual(fixture.runtime_config.stat().st_uid, os.geteuid())
        self.assertEqual(fixture.runtime_config.stat().st_gid, os.getegid())
        self.assertEqual(fixture.runtime_hosts.stat().st_uid, os.geteuid())
        self.assertEqual(fixture.runtime_hosts.stat().st_gid, os.getegid())
        self.assertEqual(fixture.runtime_hosts.read_bytes(), source_hosts)
        expected_config = source_config.replace(
            os.fsencode(str(fixture.hosts)),
            os.fsencode(str(fixture.runtime_hosts)),
            1,
        )
        self.assertEqual(fixture.runtime_config.read_bytes(), expected_config)
        self.assertEqual(fixture.config.read_bytes(), source_config)
        self.assertEqual(fixture.hosts.read_bytes(), source_hosts)

    def test_direct_source_paths_outside_runtime_directory_are_supported(self):
        fixture = GuardFixture(self)
        fixture.source_config.write_text(
            f'include "{fixture.source_hosts}";\n', encoding="utf-8"
        )
        fixture.source_hosts.write_text("# direct source\n", encoding="utf-8")
        fixture._render_guard(
            default_config=fixture.source_config,
            provisioning_hosts=fixture.source_hosts,
        )

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 0, result.stderr[:300])
        self.assertEqual(
            fixture.recorded_calls(),
            [f"<-t><-cf><{fixture.runtime_config}>"],
        )
        self.assertEqual(
            fixture.runtime_hosts.read_text(encoding="utf-8"),
            "# direct source\n",
        )
        self.assertIn(
            f'include "{fixture.runtime_hosts}";',
            fixture.runtime_config.read_text(encoding="utf-8"),
        )

    def test_valid_host_mode_replaces_only_config_value_in_start_args(self):
        fixture = GuardFixture(self)
        arguments = (
            "-4",
            "-d",
            "-q",
            "-cf",
            str(fixture.config),
            "--no-pid",
            fixture.interface,
        )

        result = fixture.run(*arguments)

        self.assertEqual(result.returncode, 0, result.stderr[:300])
        expected_start = list(arguments)
        expected_start[expected_start.index("-cf") + 1] = str(
            fixture.runtime_config
        )
        self.assertEqual(
            fixture.recorded_calls(),
            [
                f"<-t><-cf><{fixture.runtime_config}>",
                "".join(f"<{argument}>" for argument in expected_start),
            ],
        )
        self.assertTrue(fixture.runtime_config.exists())
        self.assertTrue(fixture.runtime_hosts.exists())

    def test_validate_only_works_while_disabled_and_never_starts_daemon(self):
        fixture = GuardFixture(self)
        fixture.write_state(enabled="false", mode="disabled")

        result = fixture.run(
            "--lldpq-validate-only", "-cf", str(fixture.config)
        )

        self.assertEqual(result.returncode, 0, result.stderr[:300])
        self.assertEqual(
            fixture.recorded_calls(),
            [f"<-t><-cf><{fixture.runtime_config}>"],
        )
        self.assertNotIn("--lldpq-validate-only", fixture.recorded_calls()[0])

    def test_invalid_missing_and_multiple_managed_includes_fail_closed(self):
        cases = {
            "missing": "# no include\n",
            "invalid": f'include "{self.id()}.other";\n',
            "multiple": None,
        }
        for label, content in cases.items():
            with self.subTest(label=label):
                fixture = GuardFixture(self)
                if content is None:
                    content = (
                        f'include "{fixture.hosts}";\n'
                        f'include "{fixture.hosts}";\n'
                    )
                fixture.config.write_text(content, encoding="utf-8")

                result = fixture.run("--lldpq-validate-only")

                self.assertEqual(result.returncode, 78, result.stderr[:300])
                self.assertIn("managed hosts include", result.stderr)
                self.assertEqual(fixture.recorded_calls(), [])
                self.assertFalse(fixture.runtime_config.exists())
                self.assertFalse(fixture.runtime_hosts.exists())

    def test_missing_source_hosts_fails_before_runtime_activation(self):
        fixture = GuardFixture(self)
        fixture.source_hosts.unlink()

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("source hosts", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])
        self.assertFalse(fixture.runtime_config.exists())
        self.assertFalse(fixture.runtime_hosts.exists())

    def test_oversized_source_fails_before_runtime_activation(self):
        fixture = GuardFixture(self)
        fixture._render_guard(max_input_bytes=64)

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("source config is too large", result.stderr)
        self.assertEqual(fixture.recorded_calls(), [])
        self.assertFalse(fixture.runtime_config.exists())
        self.assertFalse(fixture.runtime_hosts.exists())

    def test_runtime_symlink_is_refused_without_modifying_its_target(self):
        fixture = GuardFixture(self)
        victim = fixture.root / "victim"
        victim.write_bytes(b"must stay unchanged\n")
        fixture.runtime_config.symlink_to(victim)

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("unsafe runtime target", result.stderr)
        self.assertTrue(fixture.runtime_config.is_symlink())
        self.assertEqual(victim.read_bytes(), b"must stay unchanged\n")
        self.assertEqual(fixture.recorded_calls(), [])

    def test_runtime_nonregular_target_fails_before_any_activation(self):
        fixture = GuardFixture(self)
        fixture.runtime_hosts.mkdir()

        result = fixture.run("--lldpq-validate-only")

        self.assertEqual(result.returncode, 78, result.stderr[:300])
        self.assertIn("unsafe runtime target", result.stderr)
        self.assertTrue(fixture.runtime_hosts.is_dir())
        self.assertFalse(fixture.runtime_config.exists())
        self.assertEqual(fixture.recorded_calls(), [])

    def test_each_validation_atomically_replaces_and_retains_snapshots(self):
        fixture = GuardFixture(self)
        first = fixture.run("--lldpq-validate-only")
        self.assertEqual(first.returncode, 0, first.stderr[:300])
        first_config_inode = fixture.runtime_config.stat().st_ino
        first_hosts_inode = fixture.runtime_hosts.stat().st_ino
        fixture.hosts.write_bytes(b"# changed reservations\n")

        second = fixture.run("--lldpq-validate-only")

        self.assertEqual(second.returncode, 0, second.stderr[:300])
        self.assertNotEqual(fixture.runtime_config.stat().st_ino, first_config_inode)
        self.assertNotEqual(fixture.runtime_hosts.stat().st_ino, first_hosts_inode)
        self.assertEqual(
            fixture.runtime_hosts.read_bytes(), b"# changed reservations\n"
        )


class DockerDhcpGuardInstallerTests(unittest.TestCase):
    def _tool(self, directory: Path, name: str, body: str) -> Path:
        path = directory / name
        path.write_text("#!/bin/bash\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)
        return path

    def _run_installer(
        self,
        root: Path,
        system_dhcpd: Path,
        helper: Path,
        legacy_dhcpd: Path,
    ) -> subprocess.CompletedProcess:
        tools = root / "tools"
        tools.mkdir(exist_ok=True)
        chown_log = root / "chown.calls"
        self._tool(
            tools,
            "chown",
            f"""
            printf '%s\\n' "$*" >> '{chown_log}'
            exit 0
            """,
        )
        self._tool(tools, "sync", "exit 0\n")
        environment = os.environ.copy()
        environment["PATH"] = str(tools) + os.pathsep + environment.get("PATH", "")
        config = root / "dhcpd.conf"
        hosts = root / "dhcpd.hosts"
        state = root / "runtime.env"
        config.touch(exist_ok=True)
        hosts.touch(exist_ok=True)
        state.touch(exist_ok=True)
        command = (
            guard_function_source()
            + '\n_install_dhcp_start_guard "$1" "$2" "$3" "$4" "$5" "$6"\n'
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                command,
                "install-guard",
                str(system_dhcpd),
                str(helper),
                str(legacy_dhcpd),
                str(state),
                str(config),
                str(hosts),
            ],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )

    def test_normal_image_keeps_original_binary_inode_bytes_and_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system_dhcpd = root / "usr" / "sbin" / "dhcpd"
            system_dhcpd.parent.mkdir(parents=True)
            system_dhcpd.write_bytes(b"\x7fELF fake distro dhcpd\n")
            system_dhcpd.chmod(0o755)
            helper = root / "usr" / "local" / "libexec" / "lldpq-dhcpd-guard"
            legacy = root / "usr" / "libexec" / "lldpq-dhcpd" / "dhcpd"
            before = (
                system_dhcpd.stat().st_ino,
                system_dhcpd.read_bytes(),
                stat.S_IMODE(system_dhcpd.stat().st_mode),
            )

            result = self._run_installer(root, system_dhcpd, helper, legacy)

            self.assertEqual(result.returncode, 0, result.stderr[:300])
            self.assertEqual(
                (
                    system_dhcpd.stat().st_ino,
                    system_dhcpd.read_bytes(),
                    stat.S_IMODE(system_dhcpd.stat().st_mode),
                ),
                before,
            )
            self.assertFalse(legacy.exists())
            self.assertTrue(helper.is_file())
            self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o755)
            self.assertRegex(
                (root / "chown.calls").read_text(encoding="utf-8"),
                rf"(?m)^root:root {re.escape(str(helper.parent))}/"
                r"\.lldpq-dhcpd-guard\.",
            )

    def test_known_old_layout_restores_real_binary_before_installing_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system_dhcpd = root / "usr" / "sbin" / "dhcpd"
            system_dhcpd.parent.mkdir(parents=True)
            system_dhcpd.write_text(
                "#!/bin/bash\n"
                "# LLDPq Docker DHCP runtime guard. Generated by docker-entrypoint.sh.\n"
                f"REAL_DHCPD={LEGACY_DHCPD}\n"
                "RUNTIME_STATE=/run/lldpq/docker-dhcp-runtime.env\n"
                'exec -a dhcpd "$REAL_DHCPD" "$@"\n',
                encoding="utf-8",
            )
            system_dhcpd.chmod(0o755)
            legacy = root / "usr" / "libexec" / "lldpq-dhcpd" / "dhcpd"
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(b"\x7fELF restored distro dhcpd\n")
            legacy.chmod(0o755)
            helper = root / "usr" / "local" / "libexec" / "lldpq-dhcpd-guard"

            result = self._run_installer(root, system_dhcpd, helper, legacy)

            self.assertEqual(result.returncode, 0, result.stderr[:300])
            self.assertEqual(system_dhcpd.read_bytes(), legacy.read_bytes())
            self.assertEqual(stat.S_IMODE(system_dhcpd.stat().st_mode), 0o755)
            self.assertTrue(helper.is_file())
            restored_inode = system_dhcpd.stat().st_ino

            repeated = self._run_installer(root, system_dhcpd, helper, legacy)

            self.assertEqual(repeated.returncode, 0, repeated.stderr[:300])
            self.assertEqual(system_dhcpd.stat().st_ino, restored_inode)
            self.assertEqual(system_dhcpd.read_bytes(), legacy.read_bytes())

    def test_unknown_wrapper_is_refused_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system_dhcpd = root / "usr" / "sbin" / "dhcpd"
            system_dhcpd.parent.mkdir(parents=True)
            original = b"#!/bin/sh\nexec /opt/vendor/dhcpd \"$@\"\n"
            system_dhcpd.write_bytes(original)
            system_dhcpd.chmod(0o755)
            legacy = root / "usr" / "libexec" / "lldpq-dhcpd" / "dhcpd"
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(b"\x7fELF possible replacement\n")
            legacy.chmod(0o755)
            helper = root / "usr" / "local" / "libexec" / "lldpq-dhcpd-guard"

            result = self._run_installer(root, system_dhcpd, helper, legacy)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown wrapper", result.stderr.lower())
            self.assertEqual(system_dhcpd.read_bytes(), original)
            self.assertFalse(helper.exists())

    def test_invalid_legacy_binary_leaves_known_wrapper_in_place(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            system_dhcpd = root / "usr" / "sbin" / "dhcpd"
            system_dhcpd.parent.mkdir(parents=True)
            wrapper = (
                "#!/bin/bash\n"
                "# LLDPq Docker DHCP runtime guard. Generated by docker-entrypoint.sh.\n"
                f"REAL_DHCPD={LEGACY_DHCPD}\n"
                'exec -a dhcpd "$REAL_DHCPD" "$@"\n'
            )
            system_dhcpd.write_text(wrapper, encoding="utf-8")
            system_dhcpd.chmod(0o755)
            legacy = root / "usr" / "libexec" / "lldpq-dhcpd" / "dhcpd"
            legacy.parent.mkdir(parents=True)
            legacy.write_text("not executable\n", encoding="utf-8")
            helper = root / "usr" / "local" / "libexec" / "lldpq-dhcpd-guard"

            result = self._run_installer(root, system_dhcpd, helper, legacy)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(system_dhcpd.read_text(encoding="utf-8"), wrapper)
            self.assertFalse(helper.exists())

    def test_helper_installation_is_atomic_root_owned_and_mode_0755(self):
        source = guard_function_source()
        require_text(source, "_is_elf_executable", "distro ELF validation")
        require_text(source, 'mktemp "$helper_directory/.lldpq-dhcpd-guard.', "atomic helper stage")
        require_text(source, 'chown root:root "$staged_guard"', "helper owner")
        require_text(source, 'chmod 0755 "$staged_guard"', "helper mode")
        require_text(source, 'mv -f "$staged_guard" "$guard_path"', "helper activation")
        self.assertLess(
            source.index('chmod 0755 "$staged_guard"'),
            source.index('mv -f "$staged_guard" "$guard_path"'),
        )

    def test_runtime_snapshots_default_to_fixed_root_owned_0644_files(self):
        source = guard_function_source()
        with tempfile.TemporaryDirectory() as temporary:
            rendered = Path(temporary) / "guard"
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    source + '\n_render_dhcp_start_guard "$1"\n',
                    "render-default-guard",
                    str(rendered),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr[:300])
            guard = rendered.read_text(encoding="utf-8")
        require_text(
            guard,
            "RUNTIME_CONFIG=/etc/dhcp/.lldpq-runtime.conf",
            "runtime config path",
        )
        require_text(
            guard,
            "RUNTIME_HOSTS=/etc/dhcp/.lldpq-runtime.hosts",
            "runtime hosts path",
        )
        require_text(guard, "RUNTIME_OWNER_UID=0", "runtime owner uid")
        require_text(guard, "RUNTIME_OWNER_GID=0", "runtime owner gid")
        require_text(guard, "os.fchmod(handle.fileno(), 0o644)", "runtime mode")
        require_text(
            guard,
            "os.fchown(handle.fileno(), owner_uid, owner_gid)",
            "runtime owner",
        )
        require_text(guard, "os.fsync(handle.fileno())", "runtime file fsync")
        require_text(guard, "os.replace(temporary, target)", "runtime rename")
        require_text(guard, "os.fsync(directory_descriptor)", "runtime dir fsync")
        require_text(
            guard,
            'python3 - "$RUNTIME_CONFIG" "$RUNTIME_HOSTS"',
            "runtime provisioning checks",
        )
        reject_text(
            guard,
            'python3 - "$config" "$PROVISIONING_HOSTS" \\\n'
            '    "$DHCP_RUNTIME_SERVER_IP"',
            "persistent provisioning checks",
        )


class DockerDhcpLifecycleContractTests(unittest.TestCase):
    def test_only_fully_staged_etc_dhcp_candidates_call_original_binary_directly(self):
        require_text(
            ENTRYPOINT,
            f'{GUARD_PATH} --lldpq-validate-only \\\n'
            '            -cf "$temp_file"',
            "generated config with persistent hosts include",
        )
        require_text(
            ENTRYPOINT,
            f'{SYSTEM_DHCPD} -t -cf "$validation_candidate"',
            "migration candidate validation",
        )
        reject_text(
            ENTRYPOINT,
            f'{SYSTEM_DHCPD} -t -cf "$temp_file"',
            "candidate whose hosts include resolves through persistent storage",
        )
        reject_text(
            ENTRYPOINT,
            f"{SYSTEM_DHCPD} -t -cf /etc/dhcp/dhcpd.conf",
            "persistent symlink validation",
        )
        reject_text(
            ENTRYPOINT,
            f'{SYSTEM_DHCPD} -t -cf "$config"',
            "persistent migration validation",
        )
        bad = [
            line.strip()
            for line in ENTRYPOINT.splitlines()
            if re.search(r"(^|[! (])dhcpd -t -cf", line)
            and not line.lstrip().startswith("#")
            and "echo " not in line
        ]
        self.assertEqual(bad, [], f"PATH-selected dhcpd validation calls: {bad}")

    def test_entrypoint_persistent_checks_use_guard_validate_only(self):
        normalized = ENTRYPOINT.replace("\\\n", " ")
        call_pattern = (
            re.escape(GUARD_PATH)
            + r"\s+--lldpq-validate-only\s+-cf\s+"
        )
        calls = re.findall(call_pattern + r'(?:"\$config"|/etc/dhcp/dhcpd\.conf)',
                           normalized)
        self.assertEqual(len(calls), 3, calls)
        self.assertRegex(
            normalized,
            call_pattern + r'"\$config"',
            "post-migration persistent validation",
        )
        self.assertEqual(
            len(re.findall(call_pattern + r"/etc/dhcp/dhcpd\.conf", normalized)),
            2,
        )

    def test_entrypoint_validation_candidates_stay_in_apparmor_allowed_directory(self):
        require_text(
            ENTRYPOINT,
            "mktemp /etc/dhcp/.lldpq-dhcp-render.",
            "rendered config validation path",
        )
        require_text(
            ENTRYPOINT,
            "mktemp /etc/dhcp/.lldpq-dhcp-validation.",
            "migration config validation path",
        )
        require_text(
            ENTRYPOINT,
            "mktemp /etc/dhcp/.lldpq-dhcp-hosts-validation.",
            "migration hosts validation path",
        )
        reject_text(ENTRYPOINT, "mktemp /tmp/lldpq-dhcp", "confined validation path")

    def test_entrypoint_autostart_uses_guard_not_raw_binary(self):
        start = ENTRYPOINT.find("# DHCP server: start only")
        end = ENTRYPOINT.find("# ─── SSH Server Setup", start)
        if start < 0 or end < 0:
            self.fail("entrypoint DHCP autostart block is missing")
        block = ENTRYPOINT[start:end]
        require_text(
            block,
            f'{GUARD_PATH} -d -cf /etc/dhcp/dhcpd.conf "$DHCP_IFACE"',
            "entrypoint guarded autostart",
        )
        self.assertRegex(
            block.replace("\\\n", " "),
            re.escape(GUARD_PATH)
            + r"\s+--lldpq-validate-only\s+-cf\s+"
            + r"/etc/dhcp/dhcpd\.conf",
            "entrypoint guarded pre-autostart validation",
        )
        reject_text(block, '\n    dhcpd -d ', "entrypoint raw autostart")

    def test_guard_executes_system_binary_without_relocation(self):
        source = guard_function_source()
        with tempfile.TemporaryDirectory() as temporary:
            rendered = Path(temporary) / "guard"
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    source + '\n_render_dhcp_start_guard "$1"\n',
                    "render-default-guard",
                    str(rendered),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr[:300])
            guard = rendered.read_text(encoding="utf-8")
        require_text(guard, f"REAL_DHCPD={SYSTEM_DHCPD}", "guard real binary")
        require_text(
            guard,
            'exec "$REAL_DHCPD" "${final_arguments[@]}"',
            "guard final exec",
        )
        reject_text(guard, LEGACY_DHCPD, "guard relocated binary")

    def test_docker_validation_ignores_path_lookup(self):
        @contextmanager
        def unlocked():
            yield

        function = load_python_function(
            "validate_dhcp_config_candidate",
            {
                "os": os,
                "re": re,
                "subprocess": types.SimpleNamespace(),
                "shutil": types.SimpleNamespace(which=lambda _name: "/tmp/path/dhcpd"),
                "DHCP_VALIDATION_CONF_NAME": ".candidate.conf",
                "DHCP_VALIDATION_HOSTS_NAME": ".candidate.hosts",
                "dhcp_validation_lock": unlocked,
            },
        )
        commands = []

        namespace = function.__globals__
        namespace["dhcp_validation_lock"] = unlocked
        namespace["_stage_validation_file"] = lambda _path, _content: None
        namespace["_discard_validation_file"] = lambda _path: None
        namespace["subprocess"] = types.SimpleNamespace(
            run=lambda command, **_kwargs: (
                commands.append(command)
                or types.SimpleNamespace(returncode=0, stdout="", stderr="")
            )
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "LLDPQ_DHCP_MODE": "host",
                    "DHCP_CONF_FILE": "/etc/dhcp/dhcpd.conf",
                },
                clear=False,
            ),
            mock.patch.object(os.path, "exists", return_value=True),
        ):
            function("valid\n")

        self.assertEqual(commands[0][0], SYSTEM_DHCPD)

    def test_provision_recovers_docker_mode_from_root_owned_runtime_state(self):
        require_text(
            PROVISION,
            'source "$DOCKER_DHCP_RUNTIME_STATE"',
            "Provision Docker runtime state",
        )
        require_text(
            PROVISION,
            'LLDPQ_DHCP_MODE="${DHCP_RUNTIME_MODE:-disabled}"',
            "Provision Docker mode recovery",
        )
        require_text(
            PROVISION,
            "export LLDPQ_DHCP_MODE DHCP_INTERFACE PROVISION_SERVER_IP",
            "Provision Docker environment export",
        )

    def _run_restart(self, mode: str, euid: int):
        commands = []
        popen_commands = []

        def run(command, **_kwargs):
            commands.append(command)
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")

        class Process:
            returncode = None

            @staticmethod
            def poll():
                return None

        fake_subprocess = types.SimpleNamespace(
            run=run,
            Popen=lambda command, **_kwargs: (
                popen_commands.append(command) or Process()
            ),
            DEVNULL=subprocess.DEVNULL,
        )
        namespace = {
            "os": os,
            "subprocess": fake_subprocess,
            "time": types.SimpleNamespace(sleep=lambda _seconds: None),
            "read_isc_dhcp_interface": lambda: "test0",
            "DOCKER_DHCP_GUARD": GUARD_PATH,
        }
        function = load_python_function("restart_dhcp", namespace)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {
                "LLDPQ_DHCP_MODE": mode,
                "DHCP_LOG_FILE": str(Path(temporary) / "dhcpd.log"),
                "DHCP_CONF_FILE": str(Path(temporary) / "dhcpd.conf"),
            },
            clear=False,
        ), mock.patch.object(os, "geteuid", return_value=euid):
            result = function()
        return result, commands, popen_commands

    def test_provision_docker_fallback_uses_guard_directly_when_root(self):
        result, commands, starts = self._run_restart("host", 0)
        self.assertTrue(result[0], result)
        self.assertEqual(
            starts[0][:2],
            [GUARD_PATH, "-d"],
        )
        self.assertEqual(commands[0], ["pkill", "-x", "dhcpd"])
        self.assertFalse(any("systemctl" in command for command in commands))

    def test_provision_nonroot_compatibility_sudos_only_the_guard(self):
        result, _commands, starts = self._run_restart("host", 33)
        self.assertTrue(result[0], result)
        self.assertEqual(starts[0][:3], ["sudo", GUARD_PATH, "-d"])
        self.assertNotIn(SYSTEM_DHCPD, starts[0])

    def test_service_control_does_not_try_systemd_start_in_docker(self):
        calls = []

        class Response(Exception):
            def __init__(self, payload):
                super().__init__()
                self.payload = payload

        fake_subprocess = types.SimpleNamespace(
            run=lambda command, **_kwargs: (
                calls.append(command)
                or types.SimpleNamespace(returncode=1, stdout="", stderr="")
            )
        )
        namespace = {
            "json": json,
            "os": os,
            "subprocess": fake_subprocess,
            "POST_DATA": '{"action":"start"}',
            "restart_dhcp": lambda: (True, "started"),
            "persist_docker_dhcp_desired_state": lambda _running: None,
            "result_json": lambda payload: (_ for _ in ()).throw(Response(payload)),
            "error_json": lambda message: (_ for _ in ()).throw(Response({"error": message})),
            "dhcp_is_running": lambda: False,
            "stop_dhcp_best_effort": lambda: None,
        }
        function = load_python_function(
            "_action_dhcp_service_control_locked", namespace
        )
        with mock.patch.dict(os.environ, {"LLDPQ_DHCP_MODE": "host"}, clear=False):
            with self.assertRaises(Response) as caught:
                function()
        self.assertTrue(caught.exception.payload.get("success"))
        self.assertFalse(any("systemctl" in command for command in calls))

    def test_native_systemctl_and_direct_fallback_are_preserved(self):
        restart = python_function_source("restart_dhcp")
        control = python_function_source("_action_dhcp_service_control_locked")
        require_text(
            restart,
            "['sudo', 'systemctl', 'restart', svc]",
            "native restart",
        )
        require_text(
            control,
            "['sudo', 'systemctl', action, svc]",
            "native service control",
        )
        require_text(
            restart,
            "['sudo', 'dhcpd', '-d', '-cf', conf, iface]",
            "native direct fallback",
        )
        require_text(INSTALL, SYSTEM_DHCPD, "native installer sudoers")

    def test_docker_sudoers_allows_guard_and_not_raw_dhcpd(self):
        commands = docker_root_sudoers_commands()
        if GUARD_PATH not in commands:
            self.fail("Docker web sudoers is missing the DHCP start guard")
        if SYSTEM_DHCPD in commands:
            self.fail("Docker web sudoers still allows raw dhcpd")

    def test_documented_cumulus_monitoring_command_stays_disabled(self):
        block = re.search(
            r"### On a Cumulus switch.*?```bash\n(.*?)```",
            DOCKER_DOC,
            re.DOTALL,
        )
        if block is None:
            self.fail("Cumulus Docker command block is missing")
        command = block.group(1)
        require_text(command, "--network host", "Cumulus host networking")
        require_text(command, "-e LLDPQ_DHCP_MODE=disabled", "Cumulus DHCP mode")
        require_text(command, "-e DHCP_AUTOSTART=false", "Cumulus DHCP autostart")


if __name__ == "__main__":
    unittest.main()
