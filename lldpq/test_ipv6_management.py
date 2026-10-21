"""Exercise management transports without connecting to a switch."""
import ast
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or "/bin/bash"


def shell_function(source, name):
    match = re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{.*?^\}", source)
    if not match:
        raise AssertionError("Missing function: " + name)
    return match.group(0)


class CollectorIPv6Tests(unittest.TestCase):
    def test_ping_family_and_scope_without_changing_ipv4_or_dns_arguments(self):
        for filename, function, variable in (
            ("monitor.sh", "ping_test", "PING"),
            ("fabric-scan.sh", "is_reachable", "PING_BIN"),
            ("assets.sh", "process_one", "ASSETS_PING_BIN"),
        ):
            source = (ROOT / "lldpq" / filename).read_text()
            for address in ("192.0.2.3", "switch.example", "2001:db8::3", "fe80::3%eth0"):
                with self.subTest(script=filename, address=address), tempfile.TemporaryDirectory() as tmp:
                    log = Path(tmp) / "ping-args"
                    env = dict(os.environ, ARG_LOG=str(log), ADDRESS=address)
                    script = (
                        "set -euo pipefail\n"
                        "capture_ping() { printf '%s\\n' \"$@\" > \"$ARG_LOG\"; }\n"
                        "collect_over_ssh() { return 0; }\n"
                        f"{variable}=capture_ping\n"
                        + shell_function(source, function)
                        + f'\n{function} "$ADDRESS" cumulus leaf /unused\n'
                    )
                    result = subprocess.run([BASH, "-c", script], env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = log.read_text().splitlines()
                    self.assertEqual(args[-1], address)
                    self.assertEqual("-6" in args, ":" in address)
                    self.assertEqual(args.count(address), 1)

    def test_assets_use_selected_ipv6_address_even_when_eth0_has_ipv4(self):
        source = (ROOT / "lldpq" / "assets.sh").read_text()
        for address, expected in (("2001:db8::10", "2001:db8::10"),
                                  ("fe80::10%enp1s0", "fe80::10%enp1s0"),
                                  ("192.0.2.10", "192.0.2.20")):
            with self.subTest(address=address), tempfile.TemporaryDirectory() as tmp:
                row = Path(tmp) / "row"
                argv = Path(tmp) / "ssh-args"
                env = dict(os.environ, ADDRESS=address, ROW=str(row), ARG_LOG=str(argv))
                script = """set -euo pipefail
ASSETS_TIMEOUT_BIN=timeout_stub
ASSETS_SSH_BIN=ssh_stub
ASSETS_SSH_DEADLINE=60
ASSETS_SSH_CONNECT_TIMEOUT=5
ASSETS_SERVER_ALIVE_INTERVAL=10
ASSETS_SERVER_ALIVE_COUNT_MAX=2
timeout_stub() { shift 3; "$@"; }
ssh_stub() {
  printf '%s\\n' "$@" > "$ARG_LOG"
  echo 'remote-host 192.0.2.20 aa:bb:cc:dd:ee:ff SERIAL MODEL 5.9 1d'
}
remote_info() { :; }
"""
                for name in ("write_row", "collect_over_ssh"):
                    script += shell_function(source, name) + "\n"
                script += 'collect_over_ssh "$ADDRESS" cumulus leaf "$ROW" now\n'
                result = subprocess.run([BASH, "-c", script], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                fields = row.read_text().split()
                self.assertEqual(fields[0:2], ["leaf", expected])
                self.assertEqual(fields[7], "OK")
                self.assertIn("cumulus@" + address, argv.read_text().splitlines())

    def test_ssh_control_socket_name_does_not_expand_long_ipv6_literal(self):
        # OpenSSH %C hashes host, user and port into a bounded socket filename.
        source = (ROOT / "lldpq" / "monitor.sh").read_text()
        self.assertIn("ControlPath=~/.ssh/cm-%C", source)


class IPv6DiagnosticCommandsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "html" / "fabric-api.sh").read_text()
        start = source.index("ALLOWED_PATTERNS = [")
        end = source.index("\n]", start) + 2
        cls.patterns = ast.literal_eval(source[start:end].split("=", 1)[1].strip())
        start = source.index("def validate_ip_command(")
        end = source.index("\ndef validate_bridge_command(", start)
        namespace = {}
        exec(source[start:end], namespace)
        cls.validate = staticmethod(namespace["validate_ip_command"])

    def test_read_only_ipv4_and_ipv6_commands_are_allowed(self):
        for command in ("ip addr show", "ip -br addr show", "ip -6 addr show",
                        "sudo ip -6 neigh show", "ip -6 route get 2001:db8::1",
                        "ip -br -6 addr show", "ip -4 --brief addr show"):
            with self.subTest(command=command):
                self.assertTrue(any(re.match(p, command) for p in self.patterns))
                self.assertTrue(self.validate(command.removeprefix("sudo ").split()))

    def test_address_family_flag_does_not_authorize_mutations(self):
        for command in ("ip -6 addr add 2001:db8::2/64 dev eth0", "ip -6 route flush table main",
                        "ip -6 neigh del 2001:db8::1 dev eth0", "ip -6 link set eth0 down",
                        "ip -6", "ip -batch /tmp/commands"):
            with self.subTest(command=command):
                self.assertFalse(self.validate(command.split()))


class ConsoleIPv6Tests(unittest.TestCase):
    def test_ipv6_destinations_are_one_ssh_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            conf = folder / "lldpq.conf"
            conf.write_text(f"LLDPQ_DIR={folder}\nLLDPQ_USER=lldpq\nANSIBLE_DIR=none\n")
            addresses = ("192.0.2.3", "2001:db8::3", "fe80::3%eth0")
            (folder / "devices.yaml").write_text("defaults:\n  username: cumulus\ndevices:\n" +
                "".join(f'  "{ip}": leaf{index} @oob\n' for index, ip in enumerate(addresses)))
            with patch.dict(os.environ, LLDPQ_CONF=str(conf), LLDPQ_SESSIONS_DIR=str(folder)):
                spec = importlib.util.spec_from_file_location("console_ipv6_under_test", ROOT / "lldpq" / "console-pty.py")
                module = importlib.util.module_from_spec(spec)
                with patch.dict(sys.modules, {spec.name: module}):
                    spec.loader.exec_module(module)
                    for index, ip in enumerate(addresses):
                        label, argv = module.resolve_target(f"leaf{index}")
                        self.assertIn(ip, label)
                        self.assertEqual(argv[-1], "cumulus@" + ip)


if __name__ == "__main__":
    unittest.main()
