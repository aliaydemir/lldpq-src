#!/usr/bin/env python3
"""Contracts for search-api.sh audit fixes (query parsing, MAC bond ports,
ARP remote exit status, route table ECMP accounting, run-scan launch
truthfulness) and the related UI wiring in search.html and tracepath.html."""

import json
import os
import re
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


def extract_stdin_python_heredoc(func_text):
    """Return the python source inside a <<'PYTHON' heredoc fed to python3 -."""
    start = func_text.index("<<'PYTHON'\n") + len("<<'PYTHON'\n")
    end = func_text.index("\nPYTHON", start)
    return func_text[start:end]


def extract_python_def(source, name):
    """Return one top-level def from extracted python heredoc source."""
    start = source.index(f"\ndef {name}(")
    end = source.find("\ndef ", start + 1)
    if end < 0:
        end = len(source)
    return source[start:end]


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

    # ── live get-mac alignment with the cached fabric-scan parser ──

    def test_live_mac_parser_keeps_physical_permanent_as_static(self):
        payload = (
            "aa:bb:cc:dd:ee:01 dev swp7 vlan 100 master br_default permanent\n"
            "aa:bb:cc:dd:ee:02 dev br_default vlan 1 master br_default permanent\n"
            "aa:bb:cc:dd:ee:03 dev swp5 vlan 200 master br_default\n"
            "aa:bb:cc:dd:ee:04 dev br_default self\n"
        )
        data = self._run_mac_parser(payload)
        self.assertTrue(data["success"], data)
        by_iface = {entry["interface"]: entry for entry in data["entries"]}
        # Permanent entry on a physical port survives, tagged static —
        # matching the cached parser in lldpq/fabric-scan.sh.
        self.assertEqual(by_iface["swp7"]["type"], "static")
        self.assertEqual(by_iface["swp5"]["type"], "dynamic")
        # Bridge-local rows (the switch's own MACs) are still dropped.
        self.assertEqual(set(by_iface), {"swp7", "swp5"})

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

    def test_route_parser_keeps_sharp_and_unknown_codes(self):
        payload = (
            "VRF default:\n"
            "B>* 10.0.0.0/24 [20/0] via 10.1.1.1, swp1, weight 1, 01w0d01h\n"
            "D>* 10.7.7.7/32 [150/0] via 10.1.1.1, swp1, weight 1, 01w0d01h\n"
            "F>* 10.8.8.8/32 [200/0] via 10.1.1.1, swp1, weight 1, 01w0d01h\n"
        )
        data = self._run_route_parser(payload)
        self.assertTrue(data["success"], data)
        routes = {r["prefix"]: r for r in data["vrf_tables"]["default"]}
        # D routes were mapped to SHARP but excluded from the parse regex.
        self.assertEqual(routes["10.7.7.7/32"]["protocol"], "SHARP")
        # Codes without a route_codes mapping are kept as-is, not dropped.
        self.assertEqual(routes["10.8.8.8/32"]["protocol"], "F")

    # ── legacy trace-path nexthop VRF scoping ──

    def _load_find_device_by_nexthop(self):
        func = extract_heredoc_function(self.api, "trace_path")
        source = extract_stdin_python_heredoc(func)
        namespace = {}
        exec(
            "import ipaddress\n"
            + extract_python_def(source, "prefix_match")
            + extract_python_def(source, "find_device_by_nexthop"),
            namespace,
        )
        return namespace["find_device_by_nexthop"]

    def test_find_device_by_nexthop_prefers_requested_vrf(self):
        find_device_by_nexthop = self._load_find_device_by_nexthop()
        all_data = {
            "wrong-tenant-leaf": {"routes": {"blue": [
                {"prefix": "172.16.1.0/24", "protocol": "connected", "nexthop": "connected"},
            ]}},
            "right-tenant-leaf": {"routes": {"red": [
                {"prefix": "172.16.1.0/24", "protocol": "connected", "nexthop": "connected"},
            ]}},
        }
        self.assertEqual(
            find_device_by_nexthop("172.16.1.2", all_data, set(), "red"),
            "right-tenant-leaf",
        )

    def test_find_device_by_nexthop_never_hops_via_other_tenant_vrf(self):
        find_device_by_nexthop = self._load_find_device_by_nexthop()
        all_data = {
            "wrong-tenant-leaf": {"routes": {"blue": [
                {"prefix": "172.16.1.0/24", "protocol": "connected", "nexthop": "connected"},
            ]}},
        }
        self.assertIsNone(find_device_by_nexthop("172.16.1.2", all_data, set(), "red"))

    def test_find_device_by_nexthop_resolves_evpn_underlay_via_default(self):
        find_device_by_nexthop = self._load_find_device_by_nexthop()
        all_data = {
            "vtep-leaf": {"routes": {"default": [
                {"prefix": "10.10.10.1/32", "protocol": "local", "nexthop": "connected"},
            ]}},
        }
        self.assertEqual(
            find_device_by_nexthop("10.10.10.1", all_data, set(), "red"),
            "vtep-leaf",
        )

    # ── graph tracer host classification ──

    def _load_build_host_set(self):
        func = extract_heredoc_function(self.api, "trace_path_ip")
        source = extract_stdin_python_heredoc(func)
        namespace = {}
        exec(extract_python_def(source, "build_host_set"), namespace)
        return namespace["build_host_set"]

    def test_build_host_set_does_not_prefix_match_device_names(self):
        build_host_set = self._load_build_host_set()
        all_data = {"leaf-1": {"bonds": {"bond10": "swp31 swp32"}}}
        # leaf-1 has no LLDP section; leaf-10 must NOT be borrowed for it.
        port_neighbors = {"leaf-10": {"swp31": "spine-1", "swp32": "spine-2"}}
        self.assertEqual(build_host_set(all_data, port_neighbors), set())

    def test_build_host_set_exact_match_still_finds_hosts(self):
        build_host_set = self._load_build_host_set()
        all_data = {"leaf-1": {"bonds": {"bond10": "swp31 swp32"}}}
        port_neighbors = {
            "leaf-1": {"swp31": "server-1", "swp1": "spine-1"},
            "leaf-10": {"swp31": "spine-2"},
        }
        self.assertEqual(build_host_set(all_data, port_neighbors), {"server-1"})

    # ── dispatch hygiene ──

    def test_trace_path_dispatch_uses_exact_parser(self):
        dispatch = self.api[self.api.index('"trace-path")'):]
        dispatch = dispatch[:dispatch.index(";;")]
        for key in ("ip", "vrf", "source"):
            self.assertIn(f"$(get_query_param {key})", dispatch)
        self.assertNotIn("grep -oE", dispatch)

    def test_caller_less_actions_are_removed(self):
        for action in (
            '"get-all-mac")',
            '"get-all-arp")',
            '"get-bond-members")',
            '"search-cached-vtep")',
            '"search-cached-lldp")',
            '"detect-vrfs")',
        ):
            self.assertNotIn(action, self.api)

    # ── run-scan launch truthfulness ──

    def _run_scan_launcher(self, *, pgrep_rc=1, ps_rc=1, launch_rc=0):
        """Run run_fabric_scan with stubbed pgrep/ps/sudo/sleep.

        launch_rc is what the backgrounded sudo stub exits with, i.e. the
        status fabric-scan.sh would propagate (75 = self-gated on a lock).
        """
        func = extract_function(self.api, "run_fabric_scan")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "fabric-scan.sh").write_text("#!/bin/bash\n", encoding="utf-8")
            script = (
                f"LLDPQ_DIR={shlex.quote(tmp)}\n"
                "LLDPQ_USER=nobody\n"
                f"pgrep() {{ return {pgrep_rc}; }}\n"
                f"ps() {{ return {ps_rc}; }}\n"
                "sleep() { :; }\n"
                f"sudo() {{ return {launch_rc}; }}\n"
                + func
                + "\nrun_fabric_scan\n"
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, check=False
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_run_scan_reports_self_gated_scan_as_busy_not_started(self):
        # fabric-scan.sh exits 75 when the pipeline lock or another scan is
        # held; that is a no-op, not a launch failure.
        data = self._run_scan_launcher(launch_rc=75)
        self.assertFalse(data["success"])
        self.assertIs(data["started"], False)
        self.assertEqual(data["reason"], "busy")
        self.assertNotIn("failed to launch", data["error"])

    def test_run_scan_reports_real_launch_failure(self):
        data = self._run_scan_launcher(launch_rc=1)
        self.assertFalse(data["success"])
        self.assertIs(data["started"], False)
        self.assertEqual(data["reason"], "launch-failed")

    def test_run_scan_reports_live_launch_as_started(self):
        data = self._run_scan_launcher(ps_rc=0)
        self.assertTrue(data["success"])
        self.assertIs(data["started"], True)

    def test_run_scan_instant_clean_exit_is_not_a_failure(self):
        data = self._run_scan_launcher(launch_rc=0)
        self.assertTrue(data["success"])
        self.assertIs(data["started"], True)

    def test_run_scan_already_running_branch_reports_reason(self):
        data = self._run_scan_launcher(pgrep_rc=0)
        self.assertFalse(data["success"])
        self.assertIs(data["started"], False)
        self.assertEqual(data["reason"], "already-running")

    def _run_scan_pgrep_pattern(self):
        func = extract_function(self.api, "run_fabric_scan")
        marker = "local scan_pattern='"
        start = func.index(marker) + len(marker)
        return func[start:func.index("'", start)]

    def test_run_scan_uses_anchored_pgrep_pattern(self):
        func = extract_function(self.api, "run_fabric_scan")
        self.assertIn('pgrep -f "$scan_pattern"', func)
        self.assertNotIn('pgrep -f "fabric-scan.sh"', func)

    def test_run_scan_pgrep_pattern_matches_only_live_scan_processes(self):
        pattern = self._run_scan_pgrep_pattern()
        for cmdline in (
            "bash /opt/lldpq/fabric-scan.sh",
            "bash ./fabric-scan.sh",
            "sudo -u lldpq nohup env LLDPQ_FABRIC_SCAN_FORCE=1 bash /opt/lldpq/fabric-scan.sh",
        ):
            self.assertIsNotNone(re.search(pattern, cmdline), cmdline)
        for cmdline in (
            # cron's sh -c wrapper sleeps 30s before dispatch; matching it
            # made run-scan claim "already in progress" with no scan running.
            "/bin/sh -c /bin/sleep 30 && cd /opt/lldpq && ./fabric-scan.sh >/dev/null 2>&1",
            "tail -f /tmp/fabric-scan.log",
            "vi /opt/lldpq/fabric-scan.sh.bak",
            "bash /opt/lldpq/fabric-scanXsh",
        ):
            self.assertIsNone(re.search(pattern, cmdline), cmdline)

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
