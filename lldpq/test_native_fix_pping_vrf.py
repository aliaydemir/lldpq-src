#!/usr/bin/env python3
"""`pping -v <vrf>` on a host without Cumulus' `vrf` command.

pping built every VRF ping as

    timeout 0.3 vrf task exec <vrf> ping -c1 <ip>

`vrf` is a Cumulus Linux command. The Docker image carries iproute2 only, so
the shell answered "command not found", pping discarded that with the rest of
ping's output and printed every device as "DOWN !!!" - a full outage report
for a fabric that was reachable.

Now `vrf task exec` is used where `vrf` exists, `ip vrf exec` (directly as
root, otherwise through `sudo -n`) where it does not, and a VRF that cannot be
entered at all ends the run with one error line before any host is pinged.

The script runs for real against stand-in vrf, ip, sudo, timeout and ping
binaries that record how they were called; nothing here needs Linux, a VRF or
root.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PPING = ROOT / "bin" / "pping"
BASH = shutil.which("bash")

HOST = "10.0.0.1"
# bash 3.2 (macOS) prints the colour codes with a literal "\e".
ANSI = re.compile(r"(?:\x1b|\\e)\[[0-9;]*m")

# Every stand-in logs its own argument vector, then hands over to the command
# it was given - the way the real one does - so the log shows the whole chain.
FAKE_TIMEOUT = """#!/bin/bash
echo "timeout $*" >> "$CALL_LOG"
shift
exec "$@"
"""

FAKE_VRF = """#!/bin/bash
echo "vrf $*" >> "$CALL_LOG"
[ "$1 $2" = "task exec" ] || exit 2
shift 3
exec "$@"
"""

# Entering a VRF needs root and an existing VRF; the only one here is `mgmt`.
FAKE_IP = """#!/bin/bash
echo "ip $*" >> "$CALL_LOG"
[ "$1 $2" = "vrf exec" ] || exit 2
[ "${FAKE_ROOT:-0}" = 1 ] || { echo "Operation not permitted" >&2; exit 255; }
[ "$3" = "mgmt" ] || { echo "Invalid VRF name" >&2; exit 1; }
shift 3
exec "$@"
"""

FAKE_SUDO = """#!/bin/bash
echo "sudo $*" >> "$CALL_LOG"
[ "${FAKE_SUDO_ALLOWED:-1}" = 1 ] || { echo "sudo: a password is required" >&2; exit 1; }
[ "$1" = "-n" ] && shift
FAKE_ROOT=1 exec "$@"
"""

# Hosts listed in FAKE_UNREACHABLE do not answer.
FAKE_PING = """#!/bin/bash
echo "ping $*" >> "$CALL_LOG"
for target in ${FAKE_UNREACHABLE:-}; do
    [ "${!#}" = "$target" ] && exit 1
done
exit 0
"""


class FakeHost:
    """A PATH holding nothing but the stand-ins and the real tools pping uses."""

    def __init__(self, vrf_command: bool):
        self._tmp = tempfile.TemporaryDirectory(prefix="lldpq-pping-vrf-")
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.call_log = self.root / "calls.log"
        stand_ins = {
            "timeout": FAKE_TIMEOUT,
            "ip": FAKE_IP,
            "sudo": FAKE_SUDO,
            "ping": FAKE_PING,
        }
        if vrf_command:
            stand_ins["vrf"] = FAKE_VRF
        for name, body in stand_ins.items():
            path = self.bin / name
            path.write_text(body.replace("#!/bin/bash", f"#!{BASH}"), encoding="utf-8")
            path.chmod(0o755)
        for tool in ("date", "mktemp", "cut", "rm", "sort", "true"):
            (self.bin / tool).symlink_to(shutil.which(tool))

    def close(self) -> None:
        self._tmp.cleanup()

    def pping(self, *arguments: str, **overrides: str) -> subprocess.CompletedProcess:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("FAKE_", "LLDPQ_"))
        }
        env.update(PATH=str(self.bin), HOME=str(self.root), CALL_LOG=str(self.call_log))
        env.update(overrides)
        # stdin at EOF answers the closing "[P] again / [Q] exit" prompt.
        return subprocess.run(
            [BASH, str(PPING), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )

    def calls(self) -> list[str]:
        if not self.call_log.exists():
            return []
        return self.call_log.read_text(encoding="utf-8").splitlines()


def plain(text: str) -> str:
    return ANSI.sub("", text)


class PpingVrfTests(unittest.TestCase):
    def host(self, vrf_command: bool) -> FakeHost:
        host = FakeHost(vrf_command)
        self.addCleanup(host.close)
        return host

    def test_pping_stays_valid_shell(self):
        subprocess.run([BASH, "-n", str(PPING)], check=True)

    # ---------- Cumulus: unchanged ----------
    def test_the_cumulus_vrf_command_is_used_where_it_exists(self):
        host = self.host(vrf_command=True)
        result = host.pping("-v", "mgmt", HOST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            host.calls(),
            [
                f"timeout 0.3 vrf task exec mgmt ping -c1 {HOST}",
                f"vrf task exec mgmt ping -c1 {HOST}",
                f"ping -c1 {HOST}",
            ],
        )
        self.assertIn(f"{HOST} [{HOST}] is UP", plain(result.stdout))

    # ---------- the Docker image: no `vrf` command ----------
    def test_root_pings_through_ip_vrf_exec(self):
        host = self.host(vrf_command=False)
        result = host.pping("-v", "mgmt", HOST, FAKE_ROOT="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            host.calls(),
            [
                "ip vrf exec mgmt true",
                f"ip vrf exec mgmt timeout 0.3 ping -c1 {HOST}",
                f"timeout 0.3 ping -c1 {HOST}",
                f"ping -c1 {HOST}",
            ],
        )
        output = plain(result.stdout)
        self.assertIn(f"{HOST} [{HOST}] is UP", output)
        self.assertNotIn("DOWN !!!", output)
        self.assertIn("Hosts UP: 1, Hosts DOWN: 0", output)

    def test_another_user_enters_the_vrf_through_sudo(self):
        host = self.host(vrf_command=False)
        result = host.pping("-v", "mgmt", HOST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            host.calls(),
            [
                "ip vrf exec mgmt true",
                "sudo -n ip vrf exec mgmt true",
                "ip vrf exec mgmt true",
                f"sudo -n ip vrf exec mgmt timeout 0.3 ping -c1 {HOST}",
                f"ip vrf exec mgmt timeout 0.3 ping -c1 {HOST}",
                f"timeout 0.3 ping -c1 {HOST}",
                f"ping -c1 {HOST}",
            ],
        )
        output = plain(result.stdout)
        self.assertIn(f"{HOST} [{HOST}] is UP", output)
        self.assertNotIn("DOWN !!!", output)

    def test_the_result_is_still_the_answer_of_ping(self):
        host = self.host(vrf_command=False)
        result = host.pping(
            "-v", "mgmt", "10.0.0.1", "10.0.0.2", FAKE_ROOT="1", FAKE_UNREACHABLE="10.0.0.2"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = plain(result.stdout)
        self.assertIn("10.0.0.1 [10.0.0.1] is UP", output)
        self.assertIn("10.0.0.2 [10.0.0.2] is DOWN !!!", output)
        self.assertIn("Hosts UP: 1, Hosts DOWN: 1", output)

    # ---------- a VRF that cannot be entered ----------
    def assert_one_error_line_and_no_ping(self, host, result, vrf):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "", "something was reported before the error")
        lines = plain(result.stderr).splitlines()
        self.assertEqual(len(lines), 1, result.stderr)
        self.assertTrue(lines[0].startswith("Error: "), lines[0])
        self.assertIn(f"VRF '{vrf}'", lines[0])
        self.assertIn(f"ip vrf exec {vrf}", lines[0])
        self.assertEqual([call for call in host.calls() if "ping" in call], [])

    def test_no_way_into_the_vrf_is_one_error_not_a_list_of_down_hosts(self):
        host = self.host(vrf_command=False)
        result = host.pping("-v", "mgmt", HOST, FAKE_SUDO_ALLOWED="0")
        self.assert_one_error_line_and_no_ping(host, result, "mgmt")
        self.assertEqual(
            host.calls(), ["ip vrf exec mgmt true", "sudo -n ip vrf exec mgmt true"]
        )

    def test_an_unknown_vrf_is_one_error_not_a_list_of_down_hosts(self):
        host = self.host(vrf_command=False)
        result = host.pping("-v", "nosuch", "10.0.0.1", "10.0.0.20", FAKE_ROOT="1")
        self.assert_one_error_line_and_no_ping(host, result, "nosuch")

    # ---------- without -v nothing changes ----------
    def test_without_v_no_vrf_command_runs(self):
        host = self.host(vrf_command=False)
        result = host.pping(HOST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            host.calls(), [f"timeout 0.3 ping -c1 {HOST}", f"ping -c1 {HOST}"]
        )
        self.assertIn(f"{HOST} [{HOST}] is UP", plain(result.stdout))


if __name__ == "__main__":
    unittest.main()
