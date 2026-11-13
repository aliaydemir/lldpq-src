#!/usr/bin/env python3
"""Search -> LLDP lists a device's neighbors in natural port order.

search-api.sh?action=get-lldp sorted the entries by the raw port string, so
swp10..swp19 landed between swp1 and swp2 and the breakout sub-ports after
them (swp1, swp10, swp11, swp1s0, swp2).  search.html renders the entries in
the order it receives them.

The real parser of get_lldp_neighbors is extracted from the CGI and fed
lldpctl-style JSON on stdin, exactly as the shell function runs it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = (ROOT / "html" / "search-api.sh").read_text(encoding="utf-8")


def lldp_parser_source():
    """The python source inside get_lldp_neighbors' 3<<'PYTHON' heredoc."""
    start = API.index("\nget_lldp_neighbors() {\n")
    opener = "3<<'PYTHON'\n"
    body_start = API.index(opener, start) + len(opener)
    return API[body_start:API.index("\nPYTHON\n", body_start)]


def lldpctl_json(ports):
    """lldpctl -f json shaped output for (local port, neighbor) pairs."""
    interfaces = []
    for index, (port, neighbor) in enumerate(ports):
        interfaces.append({
            "name": port,
            "chassis": [{
                "name": [{"value": neighbor}],
                "mgmt-ip": [{"value": f"192.0.2.{index + 1}"}],
            }],
            "port": [{"id": [{"value": f"port{index + 1}"}]}],
        })
    return json.dumps({"lldp": [{"interface": interfaces}]})


class LldpNeighborOrderTests(unittest.TestCase):
    def run_parser(self, payload, search=""):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(lldp_parser_source())
            parser_path = handle.name
        try:
            result = subprocess.run(
                [sys.executable, parser_path, search],
                input=payload, capture_output=True, text=True, check=False,
            )
        finally:
            os.unlink(parser_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def local_ports(self, ports, search=""):
        data = self.run_parser(
            lldpctl_json([(port, f"peer-{port}") for port in ports]), search)
        self.assertTrue(data["success"], data)
        self.assertEqual(data["total"], len(data["entries"]))
        return [entry["local_port"] for entry in data["entries"]]

    def test_ports_are_listed_in_natural_order(self):
        natural = ["eth0", "swp1", "swp1s0", "swp1s1", "swp2", "swp3",
                   "swp10", "swp11", "swp20", "swp32", "swp32s3"]
        # The same set arrives in text order, reversed and already natural.
        for arrival in (sorted(natural), natural[::-1], natural):
            with self.subTest(arrival=arrival):
                self.assertEqual(self.local_ports(arrival), natural)

    def test_the_documented_example_order(self):
        self.assertEqual(
            self.local_ports(["swp10", "swp2", "swp1s0", "swp1"]),
            ["swp1", "swp1s0", "swp2", "swp10"],
        )

    def test_sub_ports_and_subinterfaces_sort_by_number(self):
        self.assertEqual(
            self.local_ports(["swp5s10", "swp5s2", "swp5.100", "swp5.20", "swp5"]),
            ["swp5", "swp5.20", "swp5.100", "swp5s2", "swp5s10"],
        )

    def test_names_without_or_starting_with_digits_do_not_break_the_sort(self):
        self.assertEqual(
            self.local_ports(["swp2", "mgmt", "1/1/10", "1/1/2", "eth0"]),
            ["1/1/2", "1/1/10", "eth0", "mgmt", "swp2"],
        )

    def test_search_filter_keeps_natural_order(self):
        self.assertEqual(
            self.local_ports(["swp10", "swp1", "swp2", "eth0"], search="SWP"),
            ["swp1", "swp2", "swp10"],
        )

    def test_entry_fields_follow_their_port(self):
        data = self.run_parser(lldpctl_json([("swp10", "spine-02"),
                                             ("swp9", "spine-01")]))
        self.assertEqual(data["entries"], [
            {"local_port": "swp9", "neighbor": "spine-01",
             "remote_port": "port2", "mgmt_ip": "192.0.2.2"},
            {"local_port": "swp10", "neighbor": "spine-02",
             "remote_port": "port1", "mgmt_ip": "192.0.2.1"},
        ])

    def test_invalid_payload_is_still_reported(self):
        data = self.run_parser("not json")
        self.assertFalse(data["success"])
        self.assertIn("Invalid LLDP response", data["error"])

    def test_interface_name_that_is_not_a_string_does_not_fail_the_list(self):
        # The sort key reads the name as text; one odd entry must not turn
        # the whole list into "Invalid LLDP response".
        for odd in (None, 5):
            with self.subTest(name=odd):
                payload = json.loads(lldpctl_json(
                    [("swp10", "peer-a"), ("placeholder", "peer-b"), ("swp2", "peer-c")]))
                payload["lldp"][0]["interface"][1]["name"] = odd
                data = self.run_parser(json.dumps(payload))
                self.assertTrue(data["success"], data)
                self.assertEqual(
                    [entry["local_port"] for entry in data["entries"]],
                    [odd, "swp2", "swp10"])

    def test_order_ignores_the_case_of_the_name(self):
        self.assertEqual(
            self.local_ports(["swp10", "SWP3", "bond1", "Eth0", "swp2"]),
            ["bond1", "Eth0", "swp2", "SWP3", "swp10"],
        )


class LldpShellFunctionTests(unittest.TestCase):
    """get_lldp_neighbors itself, with the SSH hop replaced by a fixture."""

    def test_shell_function_returns_natural_order(self):
        start = API.index("\nget_lldp_neighbors() {\n") + 1
        end_marker = "\nPYTHON\n}\n"
        function = API[start:API.index(end_marker, start) + len(end_marker)]
        ports = ["swp1", "swp10", "swp11", "swp1s0", "swp2", "swp20", "swp3"]
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "lldpctl.json"
            fixture.write_text(
                lldpctl_json([(port, f"peer-{port}") for port in ports]),
                encoding="utf-8")
            script = (
                'get_ssh_target() { printf "%s" "cumulus@192.0.2.1"; }\n'
                # Stands in for `sudo -u <user> timeout 30 ssh ... lldpctl`.
                'sudo() { cat "$LLDP_FIXTURE"; }\n'
                'LLDPQ_USER=collector\n'
                + function +
                'get_lldp_neighbors leaf-01 ""\n'
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True,
                check=False,
                env=dict(os.environ, LLDP_FIXTURE=str(fixture),
                         PATH=f"{Path(sys.executable).parent}{os.pathsep}"
                              f"{os.environ.get('PATH', '')}"),
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["success"], data)
        self.assertEqual(
            [entry["local_port"] for entry in data["entries"]],
            ["swp1", "swp1s0", "swp2", "swp3", "swp10", "swp11", "swp20"],
        )


if __name__ == "__main__":
    unittest.main()
