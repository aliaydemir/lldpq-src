#!/usr/bin/env python3
"""Checks the telemetry step leaves an existing Docker's storage driver alone.

Both copies of the step - `./install.sh --enable-telemetry` and the question a
fresh install asks - ended with:

    if [[ ! -f /etc/docker/daemon.json ]]; then
        echo '{"storage-driver": "vfs"}' | sudo tee /etc/docker/daemon.json
        sudo systemctl restart docker
    fi

The only condition was the missing file, which is also the default state of a
Docker that somebody else installed and is using. Switching its storage driver
restarts every container and, afterwards, shows none of the existing images
and containers until the file is removed again.

The vfs file exists for a Docker that this run installed on a VM without
overlay support; nothing can be lost there. A Docker that was already present
is now left alone and gets one warning line naming the manual step.

The blocks are cut out of install.sh and run with stand-in curl, docker and
sudo; /etc/docker and the downloaded installer are redirected into a temporary
directory, so nothing here needs Docker or root.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
UNINSTALL = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")

VFS_MARKER = '{"storage-driver": "vfs"}'
OPERATOR_CONFIG = '{"data-root": "/srv/docker"}\n'

# Anchors chosen to exist both before and after the fix, so a regression fails
# on an assertion rather than on a missing slice.
SITES = {
    "--enable-telemetry": 'echo "Enabling Streaming Telemetry..."',
    "fresh install": 'echo "  Checking Docker installation..."',
}
_DETECTION_END = "if ! command -v docker-compose &> /dev/null"
_DRIVER_START = "if [[ ! -f /etc/docker/daemon.json ]]"
_DRIVER_END = 'if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]'


def _site_block(anchor: str) -> str:
    """Docker detection/installation plus the storage-driver step of one copy.

    The docker-compose download and the /etc/lldpq.conf edit between the two
    are left out: they do not take part in the decision.
    """
    start = INSTALL.index(anchor)
    detection = INSTALL[start:INSTALL.index(_DETECTION_END, start)]
    driver_start = INSTALL.index(_DRIVER_START, start)
    driver = INSTALL[driver_start:INSTALL.index(_DRIVER_END, driver_start)]
    return detection + driver


# `sudo` is a shell function so the block can run unprivileged: every call is
# recorded, and only the harmless ones act (inside the temporary directory).
SUDO_SHIM = """
sudo() {
    printf '%s\\n' "$*" >> "$SUDO_LOG"
    case "$1" in
        mkdir|tee|sh) "$@" ;;
    esac
}
"""

# "Downloads" a Docker installer that only leaves a trace when it is run.
FAKE_CURL = """#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "-o" ] && out="$2"
    shift
done
printf '%s\\n' 'echo installed >> "$INSTALLER_LOG"' > "$out"
"""

FAKE_DOCKER = """#!/bin/sh
echo "Docker version 27.0.0, build stand-in"
"""

FAKE_WHOAMI = """#!/bin/sh
echo lldpq-test-user
"""


class FakeHost:
    """A PATH holding nothing but the stand-ins and the few real tools used."""

    def __init__(self, docker_present: bool):
        self._tmp = tempfile.TemporaryDirectory(prefix="lldpq-docker-storage-")
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.docker_etc = self.root / "etc-docker"
        self.daemon_json = self.docker_etc / "daemon.json"
        self.installer = self.root / "get-docker.sh"
        self.sudo_log = self.root / "sudo.log"
        self.installer_log = self.root / "installer.log"
        self._add("curl", FAKE_CURL)
        self._add("whoami", FAKE_WHOAMI)
        if docker_present:
            self._add("docker", FAKE_DOCKER)
        for tool in ("sh", "rm", "mkdir", "tee"):
            (self.bin / tool).symlink_to(shutil.which(tool))

    def _add(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def close(self) -> None:
        self._tmp.cleanup()

    def script(self, anchor: str) -> str:
        block = _site_block(anchor)
        block = block.replace("/etc/docker", "@DOCKER_ETC@")
        block = block.replace("/tmp/get-docker.sh", "@INSTALLER@")
        # Nothing may be left that points at the machine running the test.
        for real_path in ("/etc/", "/tmp/", "/var/", "/usr/"):
            if real_path in block:
                raise AssertionError(f"block still names {real_path}")
        block = block.replace("@DOCKER_ETC@", str(self.docker_etc))
        block = block.replace("@INSTALLER@", str(self.installer))
        # install.sh runs under `set -e`.
        return SUDO_SHIM + "set -e\n" + block

    def run(self, anchor: str, **overrides: str) -> subprocess.CompletedProcess:
        env = {
            key: value
            for key, value in os.environ.items()
            if key != "_docker_installed_now"
        }
        env.update(
            PATH=str(self.bin),
            SUDO_LOG=str(self.sudo_log),
            INSTALLER_LOG=str(self.installer_log),
            LLDPQ_USER="lldpq-test-user",
        )
        env.update(overrides)
        return subprocess.run(
            [BASH, "-c", self.script(anchor)],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def sudo_calls(self) -> list[str]:
        if not self.sudo_log.exists():
            return []
        return self.sudo_log.read_text(encoding="utf-8").splitlines()


class DockerStorageDriverTests(unittest.TestCase):
    def host(self, docker_present: bool) -> FakeHost:
        host = FakeHost(docker_present)
        self.addCleanup(host.close)
        return host

    def assert_docker_untouched(self, host: FakeHost) -> None:
        calls = host.sudo_calls()
        self.assertEqual(
            [call for call in calls if call.endswith("restart docker")],
            [],
            "the Docker service was restarted",
        )
        self.assertEqual(
            [call for call in calls if call.startswith(("mkdir", "tee"))],
            [],
            "something was written below /etc/docker",
        )

    # ---------- the blocks themselves ----------
    def test_install_sh_stays_valid_shell(self):
        subprocess.run([BASH, "-n", str(ROOT / "install.sh")], check=True)

    def test_both_copies_are_located_unambiguously(self):
        for site, anchor in SITES.items():
            with self.subTest(site=site):
                self.assertEqual(INSTALL.count(anchor), 1)
                self.assertIn("get.docker.com", _site_block(anchor))
                self.assertEqual(_site_block(anchor).count("sudo tee "), 1)
        # No third copy of the step anywhere else in the installer.
        self.assertEqual(INSTALL.count("sudo tee /etc/docker/"), len(SITES))

    # ---------- Docker installed by this run: unchanged behaviour ----------
    def test_a_docker_installed_by_this_run_still_gets_the_vfs_driver(self):
        for site, anchor in SITES.items():
            with self.subTest(site=site):
                host = self.host(docker_present=False)
                result = host.run(anchor)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    host.installer_log.read_text(encoding="utf-8"), "installed\n"
                )
                self.assertEqual(
                    host.daemon_json.read_text(encoding="utf-8"), VFS_MARKER + "\n"
                )
                self.assertEqual(
                    host.sudo_calls().count("systemctl restart docker"), 1
                )
                self.assertIn("Configuring Docker storage driver...", result.stdout)
                self.assertNotIn("already installed", result.stdout)

    # ---------- Docker that was already there: the defect ----------
    def test_an_existing_docker_keeps_its_storage_driver_and_keeps_running(self):
        for site, anchor in SITES.items():
            with self.subTest(site=site):
                host = self.host(docker_present=True)
                result = host.run(anchor)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Docker found: Docker version", result.stdout)
                self.assertFalse(host.installer_log.exists())
                self.assertFalse(
                    host.docker_etc.exists(), "daemon.json was created anyway"
                )
                self.assert_docker_untouched(host)
                self.assertNotIn("Configuring Docker storage driver", result.stdout)

    def test_the_operator_is_told_the_manual_step_in_one_line(self):
        for site, anchor in SITES.items():
            with self.subTest(site=site):
                host = self.host(docker_present=True)
                result = host.run(anchor)
                warnings = [
                    line for line in result.stdout.splitlines() if "[!]" in line
                ]
                self.assertEqual(len(warnings), 1, result.stdout)
                warning = warnings[0]
                self.assertIn("already installed", warning)
                self.assertIn("without overlay support", warning)
                self.assertIn('"storage-driver": "vfs"', warning)
                self.assertIn(str(host.daemon_json), warning)
                self.assertIn("sudo systemctl restart docker", warning)

    def test_the_decision_cannot_be_inherited_from_the_environment(self):
        for site, anchor in SITES.items():
            with self.subTest(site=site):
                host = self.host(docker_present=True)
                result = host.run(anchor, _docker_installed_now="true")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(host.docker_etc.exists())
                self.assert_docker_untouched(host)

    # ---------- an existing daemon.json was never touched; keep it so ----------
    def test_an_existing_daemon_json_is_never_rewritten(self):
        for site, anchor in SITES.items():
            for docker_present in (True, False):
                with self.subTest(site=site, docker_present=docker_present):
                    host = self.host(docker_present)
                    host.docker_etc.mkdir()
                    host.daemon_json.write_text(OPERATOR_CONFIG, encoding="utf-8")
                    result = host.run(anchor)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        host.daemon_json.read_text(encoding="utf-8"),
                        OPERATOR_CONFIG,
                    )
                    self.assert_docker_untouched(host)
                    self.assertNotIn("[!] Docker was already", result.stdout)

    # ---------- uninstall.sh --remove-docker still recognises the file ----------
    def test_the_written_file_is_the_one_uninstall_removes(self):
        self.assertEqual(
            INSTALL.count(
                f"echo '{VFS_MARKER}' | sudo tee /etc/docker/daemon.json > /dev/null"
            ),
            len(SITES),
        )
        self.assertEqual(
            UNINSTALL.count(
                f"""[[ "$(cat /etc/docker/daemon.json 2>/dev/null)" == '{VFS_MARKER}' ]]"""
            ),
            1,
            "uninstall.sh no longer matches the file install.sh writes",
        )


if __name__ == "__main__":
    unittest.main()
