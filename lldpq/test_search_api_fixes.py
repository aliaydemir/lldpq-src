#!/usr/bin/env python3
"""Contracts for search-api.sh audit fixes (query parsing, MAC bond ports,
ARP remote exit status, route table ECMP accounting) and the related UI
wiring in search.html and tracepath.html."""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def extract_function(text, name, end_marker="\n}\n"):
    """Return the body of a top-level bash function (name() { ... }).

    Functions whose heredoc python contains column-0 braces must be
    extracted with the heredoc terminator as the end marker.
    """
    marker = f"\n{name}() {{\n"
    start = text.index(marker)
    end = text.index(end_marker, start)
    return text[start + 1:end + len(end_marker)]


def extract_heredoc_function(text, name):
    return extract_function(text, name, end_marker="\nPYTHON\n}\n")


def extract_python_heredoc(func_text):
    """Return the python source inside a 3<<'PYTHON' heredoc."""
    start = func_text.index("3<<'PYTHON'\n") + len("3<<'PYTHON'\n")
    end = func_text.index("\nPYTHON", start)
    return func_text[start:end]


def extract_remote_script(func_text):
    """Return the single-quoted remote script passed to ssh."""
    marker = '"$ssh_target" \''
    start = func_text.index(marker) + len(marker)
    end = func_text.index("' 2>/dev/null)", start)
    return func_text[start:end]


class SearchApiFixesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = (ROOT / "html/search-api.sh").read_text(encoding="utf-8")
        cls.search_html = (ROOT / "html/search.html").read_text(encoding="utf-8")
        cls.tracepath_html = (ROOT / "html/tracepath.html").read_text(encoding="utf-8")

    # ── trace-path-ip query parsing ──

    def _run_get_query_param(self, query_string, key):
        func = extract_function(self.api, "get_query_param")
        script = func + f"\nQUERY_STRING={shlex.quote(query_string)} get_query_param {shlex.quote(key)}\n"
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.rstrip("\n")

    def test_query_params_are_key_anchored_in_both_orders(self):
        for qs in (
            "action=trace-path-ip&source_ip=1.1.1.1&dest_ip=2.2.2.2&vrf=red&dst_vrf=blue",
            "action=trace-path-ip&dst_vrf=blue&vrf=red&dest_ip=2.2.2.2&source_ip=1.1.1.1",
        ):
            self.assertEqual(self._run_get_query_param(qs, "vrf"), "red")
            self.assertEqual(self._run_get_query_param(qs, "dst_vrf"), "blue")
            self.assertEqual(self._run_get_query_param(qs, "source_ip"), "1.1.1.1")
            self.assertEqual(self._run_get_query_param(qs, "dest_ip"), "2.2.2.2")

    def test_empty_vrf_is_not_corrupted_by_dst_vrf(self):
        for qs in (
            "source_ip=1.1.1.1&dest_ip=2.2.2.2&vrf=&dst_vrf=blue",
            "dst_vrf=blue&vrf=&source_ip=1.1.1.1&dest_ip=2.2.2.2",
            "dst_vrf=blue&source_ip=1.1.1.1&dest_ip=2.2.2.2",
        ):
            self.assertEqual(self._run_get_query_param(qs, "vrf"), "")
            self.assertEqual(self._run_get_query_param(qs, "dst_vrf"), "blue")

    def test_query_param_values_are_url_decoded(self):
        self.assertEqual(
            self._run_get_query_param("vrf=Tenant%2D1", "vrf"), "Tenant-1"
        )

    def test_trace_path_ip_dispatch_uses_exact_parser(self):
        dispatch = self.api[self.api.index('"trace-path-ip")'):]
        dispatch = dispatch[:dispatch.index(";;")]
        for key in ("source_ip", "dest_ip", "vrf", "dst_vrf"):
            self.assertIn(f"$(get_query_param {key})", dispatch)
        self.assertNotIn("grep -oE 'vrf=", dispatch)

    # ── live get-mac bond_ports enrichment ──

    def _run_mac_parser(self, payload, search=""):
        func = extract_heredoc_function(self.api, "get_mac_table")
        parser = extract_python_heredoc(func)
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(parser)
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

    def test_live_mac_table_includes_bond_ports(self):
        payload = (
            "aa:bb:cc:dd:ee:01 dev bond10 vlan 100 master br_default\n"
            "aa:bb:cc:dd:ee:02 dev swp5 vlan 200 master br_default\n"
            "---BOND_MAP---\n"
            "bond10:swp1 swp2\n"
        )
        data = self._run_mac_parser(payload)
        self.assertTrue(data["success"], data)
        by_iface = {entry["interface"]: entry for entry in data["entries"]}
        self.assertEqual(by_iface["bond10"].get("bond_ports"), ["swp1", "swp2"])
        self.assertNotIn("bond_ports", by_iface["swp5"])
        self.assertEqual(data["warnings"], [])

    def test_live_mac_table_tolerates_missing_bond_map(self):
        payload = "aa:bb:cc:dd:ee:01 dev bond10 vlan 100 master br_default\n"
        data = self._run_mac_parser(payload)
        self.assertTrue(data["success"], data)
        self.assertEqual(len(data["entries"]), 1)
        self.assertNotIn("bond_ports", data["entries"][0])

    def test_live_mac_remote_script_collects_bond_map(self):
        func = extract_heredoc_function(self.api, "get_mac_table")
        remote = extract_remote_script(func)
        self.assertIn('echo "---BOND_MAP---"', remote)
        self.assertIn("/sys/class/net/*/bonding/slaves", remote)
        self.assertTrue(remote.rstrip().endswith("exit 0"))

    # ── get-arp remote script exit status ──

    def test_arp_remote_script_exits_zero_on_success(self):
        func = extract_heredoc_function(self.api, "get_arp_table")
        remote = extract_remote_script(func)
        self.assertTrue(remote.rstrip().endswith("exit 0"))

        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = Path(tmp) / "sbin"
            stub_dir.mkdir()
            stub_ip = stub_dir / "ip"
            stub_ip.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            stub_ip.chmod(0o755)

            # A regular "master" file makes readlink fail, so the final loop
            # iteration ends with a failed test — the historical false-failure.
            net_dir = Path(tmp) / "net" / "eth0"
            net_dir.mkdir(parents=True)
            (net_dir / "master").write_text("", encoding="utf-8")

            script = remote.replace("/usr/sbin/ip", str(stub_ip))
            script = script.replace(
                "/sys/class/net/*/master", str(Path(tmp) / "net") + "/*/master"
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("---VRF_MAP---", result.stdout)
        self.assertIn("---IFACE_VRF---", result.stdout)

    def test_arp_remote_script_still_signals_neigh_failure(self):
        func = extract_heredoc_function(self.api, "get_arp_table")
        remote = extract_remote_script(func)
        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = Path(tmp) / "sbin"
            stub_dir.mkdir()
            stub_ip = stub_dir / "ip"
            stub_ip.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub_ip.chmod(0o755)
            script = remote.replace("/usr/sbin/ip", str(stub_ip))
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False
            )
        self.assertEqual(result.returncode, 41, result.stdout)

    # ── route table ECMP accounting for skipped kernel routes ──

    def _run_route_parser(self, payload, search=""):
        func = extract_heredoc_function(self.api, "get_route_table")
        parser = extract_python_heredoc(func)
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(parser)
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

    def test_skipped_kernel_route_does_not_inflate_previous_ecmp(self):
        payload = (
            "VRF default:\n"
            "B>* 10.0.0.0/24 [20/0] via 10.1.1.1, swp1, weight 1, 01w0d01h\n"
            "  *                    via 10.1.1.2, swp2, weight 1, 01w0d01h\n"
            "K>* 10.9.9.9/32 [0/0] via 10.1.1.1, swp1, 00:01:01\n"
            "  *                   via 10.1.1.2, swp2, 00:01:01\n"
            "B>* 10.0.1.0/24 [20/0] via 10.1.1.1, swp1, weight 1, 01w0d01h\n"
        )
        data = self._run_route_parser(payload)
        self.assertTrue(data["success"], data)
        routes = {r["prefix"]: r for r in data["vrf_tables"]["default"]}
        self.assertNotIn("10.9.9.9/32", routes)
        self.assertEqual(routes["10.0.0.0/24"]["ecmp"], 2)
        self.assertEqual(routes["10.0.1.0/24"]["ecmp"], 1)

    # ── UI contracts ──

    def test_search_page_route_renderer_keeps_warnings(self):
        renderer = self.search_html[self.search_html.index("function renderRouteTable"):]
        renderer = renderer[:renderer.index("// ============ LLDP NEIGHBORS")]
        self.assertIn("let html = renderDataWarnings(data);", renderer)
        self.assertIn("html += '<table class=\"data-table\" id=\"routeTable0\">", renderer)
        self.assertNotIn("html = '<table", renderer)

    def test_search_page_has_run_scan_button_and_live_filter(self):
        self.assertIn('id="runScanBtn"', self.search_html)
        self.assertIn("action=run-scan", self.search_html)
        self.assertIn("function runFabricScan()", self.search_html)
        self.assertIn("function applyLiveFilter(tab)", self.search_html)

    def test_tracepath_supports_url_params_and_dst_vrf_detection(self):
        self.assertIn("function applyUrlParams()", self.tracepath_html)
        self.assertIn("params.get('source_ip')", self.tracepath_html)
        self.assertIn("params.get('dst_vrf')", self.tracepath_html)
        self.assertIn("async function detectDstVrfs()", self.tracepath_html)
        self.assertIn("function cancelDstVrfDetection()", self.tracepath_html)


if __name__ == "__main__":
    unittest.main()
