#!/usr/bin/env python3
"""Regression tests for fabric-api.sh backend integrity fixes.

Covers heredoc-embedded python bodies and source contracts:
- .yml host_vars coverage: list-vtep-devices, the subnet-leak scans and the
  get-available-vrfs / get-vrf-report enumerations must see *.yml files (and
  process a host only once when both extensions exist).
- create_port_profile: a non-numeric access_vlan must produce a JSON error
  body instead of an empty CGI response.
- list-external-peers: a null-valued interface stanza (``swp10:``) must not
  blank the whole response.
- Source pins: dead refresh-assets branch removed, TELEMETRY_MAX_PARALLEL
  parse guarded, get-device-data arm evals lldpq-config.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import textwrap
import unittest
import tempfile
from pathlib import Path

from ruamel.yaml import YAML


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "html" / "fabric-api.sh"
SCRIPT_TEXT = SCRIPT_PATH.read_text(encoding="utf-8")


def _bash_single_quoted_var(name):
    """Extract the value of a NAME='...' bash assignment (no inner quotes)."""
    marker = name + "='"
    start = SCRIPT_TEXT.index(marker) + len(marker)
    end = SCRIPT_TEXT.index("'", start)
    return SCRIPT_TEXT[start:end]


def _heredoc_body(marker, opener="python3 << PYTHON\n"):
    """Extract the python heredoc body of a case branch/function by marker."""
    start_pos = SCRIPT_TEXT.index(marker)
    open_pos = SCRIPT_TEXT.index(opener, start_pos)
    body_start = open_pos + len(opener)
    body_end = SCRIPT_TEXT.index("\nPYTHON\n", body_start)
    body = SCRIPT_TEXT[body_start:body_end]
    # Expand the shared defs exactly as the unquoted heredoc would
    for var in (
        "LLDPQ_JSON_EXCEPTHOOK_DEF",
        "LLDPQ_MODE_FLOOR_DEF",
        "LLDPQ_ATOMIC_WRITE_DEF",
        "LLDPQ_VALIDATORS_DEF",
        "LLDPQ_REF_SCAN_DEF",
    ):
        body = body.replace("$" + var, _bash_single_quoted_var(var))
    if "$LLDPQ" in body:
        raise AssertionError("unexpanded bash variable left in heredoc body")
    return body


LIST_VTEP_DEVICES_BODY = _heredoc_body(
    "    list-vtep-devices)", opener="python3 << 'PYTHON'\n")
LIST_EXTERNAL_PEERS_BODY = _heredoc_body(
    "    list-external-peers)", opener="python3 << 'PYTHON'\n")
GET_ALL_LEAKED_SUBNETS_BODY = _heredoc_body(
    '"get-all-leaked-subnets")', opener="python3 << 'PYTHON'\n")
GET_AVAILABLE_VRFS_BODY = _heredoc_body(
    "get_available_vrfs() {", opener="python3 << 'PYTHON'\n")
GET_VRF_REPORT_BODY = _heredoc_body(
    "get_vrf_report() {", opener="python3 << 'PYTHON'\n")
CREATE_PORT_PROFILE_BODY = _heredoc_body("create_port_profile() {")


def run_action(body, post_data, ansible_dir):
    """Exec a heredoc body with POST_DATA/ANSIBLE_DIR set; return its JSON."""
    saved = {k: os.environ.get(k) for k in ("POST_DATA", "ANSIBLE_DIR")}
    os.environ["POST_DATA"] = json.dumps(post_data)
    os.environ["ANSIBLE_DIR"] = str(ansible_dir)
    stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout):
            try:
                exec(compile(body, str(SCRIPT_PATH), "exec"), {"__name__": "__main__"})
            except SystemExit:
                pass
    finally:
        for key, val in saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
    out = stdout.getvalue().strip()
    return json.loads(out.splitlines()[-1])


class YmlHostVarsCoverageTest(unittest.TestCase):
    """.yml host_vars must be scanned; a both-extension host only once."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.host_vars = self.ansible_dir / "inventory" / "host_vars"
        self.host_vars.mkdir(parents=True)
        self.group_all = self.ansible_dir / "inventory" / "group_vars" / "all"
        self.group_all.mkdir(parents=True)

    def test_yml_only_device_listed_by_list_vtep_devices(self):
        (self.host_vars / "dev-yml.yml").write_text(textwrap.dedent("""\
            vtep:
              state: true
        """))
        result = run_action(LIST_VTEP_DEVICES_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        hostnames = [d["hostname"] for d in result["devices"]]
        self.assertIn("dev-yml", hostnames)

    def test_both_extension_device_processed_once_yaml_wins(self):
        # .yaml is first-seen and must win over a stale .yml twin
        (self.host_vars / "dev-both.yaml").write_text(textwrap.dedent("""\
            vtep:
              state: true
        """))
        (self.host_vars / "dev-both.yml").write_text(textwrap.dedent("""\
            vtep:
              state: false
        """))
        result = run_action(LIST_VTEP_DEVICES_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        hostnames = [d["hostname"] for d in result["devices"]]
        self.assertEqual(hostnames.count("dev-both"), 1, result)

    def test_both_extension_device_counted_once_by_get_available_vrfs(self):
        # .yaml is first-seen and must win over a stale .yml twin
        (self.host_vars / "dev-both.yaml").write_text(textwrap.dedent("""\
            vrfs:
              BLUE:
                l3vni: 4001
        """))
        (self.host_vars / "dev-both.yml").write_text(textwrap.dedent("""\
            vrfs:
              BLUE:
                l3vni: 9999
        """))
        result = run_action(GET_AVAILABLE_VRFS_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        blue = next(v for v in result["vrfs"] if v["name"] == "BLUE")
        self.assertEqual(blue["device_count"], 1, result)
        self.assertEqual(blue["devices"], ["dev-both"], result)
        self.assertEqual(blue["l3vni"], 4001, result)

    def test_both_extension_device_listed_once_by_get_vrf_report(self):
        (self.host_vars / "dev-both.yaml").write_text(textwrap.dedent("""\
            vrfs:
              BLUE:
                l3vni: 4001
        """))
        (self.host_vars / "dev-both.yml").write_text(textwrap.dedent("""\
            vrfs:
              BLUE:
                l3vni: 9999
        """))
        result = run_action(GET_VRF_REPORT_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        blue = result["vrfs"]["BLUE"]
        self.assertEqual(blue["devices"], ["dev-both"], result)
        self.assertEqual(blue["l3vni"], 4001, result)
        self.assertEqual(result["device_count"], 1, result)

    def test_yml_only_device_seen_by_leak_scan(self):
        (self.group_all / "bgp_profiles.yaml").write_text(textwrap.dedent("""\
            bgp_profiles:
              TENANT_BLUE:
                ipv4_unicast_af:
                  route_import:
                    from_vrf:
                      - RED
                    route_map: BLUE_IMPORT
        """))
        # 'type' bookkeeping key + empty prefix-list body exercise the
        # get-all-leaked-subnets shape guards (previously a wholesale crash)
        (self.host_vars / "leaf-yml.yml").write_text(textwrap.dedent("""\
            vrfs:
              BLUE:
                bgp:
                  bgp_profile: TENANT_BLUE
            policies:
              prefix_list:
                BLUE_IMPORT:
                  type: ipv4
                  10:
                    match: 10.10.0.0/24
                    max_prefix_len: 32
                EMPTY_LIST:
        """))
        result = run_action(GET_ALL_LEAKED_SUBNETS_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        leaked = result.get("leaked_subnets", {})
        self.assertIn("10.10.0.0/24", leaked, result)
        self.assertEqual(leaked["10.10.0.0/24"]["target_vrf"], "BLUE")


class CreatePortProfileValidationTest(unittest.TestCase):
    """Non-numeric VLANs must yield a JSON error body, not an empty one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.group_all = self.ansible_dir / "inventory" / "group_vars" / "all"
        self.group_all.mkdir(parents=True)

    def test_non_numeric_access_vlan_returns_json_error(self):
        result = run_action(CREATE_PORT_PROFILE_BODY, {
            "profile_name": "P1",
            "sw_port_mode": "access",
            "access_vlan": "1x",
        }, self.ansible_dir)
        self.assertFalse(result.get("success"), result)
        self.assertIn("VLAN", result.get("error", ""))
        self.assertFalse((self.group_all / "sw_port_profiles.yaml").exists())

    def test_out_of_range_native_vlan_returns_json_error(self):
        result = run_action(CREATE_PORT_PROFILE_BODY, {
            "profile_name": "P2",
            "sw_port_mode": "trunk",
            "native_vlan": "5000",
        }, self.ansible_dir)
        self.assertFalse(result.get("success"), result)
        self.assertIn("VLAN", result.get("error", ""))

    def test_valid_access_vlan_still_creates_profile(self):
        result = run_action(CREATE_PORT_PROFILE_BODY, {
            "profile_name": "P3",
            "sw_port_mode": "access",
            "access_vlan": "100",
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        yaml = YAML()
        with open(self.group_all / "sw_port_profiles.yaml") as f:
            data = yaml.load(f)
        self.assertEqual(data["sw_port_profiles"]["P3"]["access_vlan"], 100)


class ListExternalPeersNullGuardTest(unittest.TestCase):
    """A null interface stanza must not blank the whole peer listing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.host_vars = self.ansible_dir / "inventory" / "host_vars"
        self.host_vars.mkdir(parents=True)
        self.group_all = self.ansible_dir / "inventory" / "group_vars" / "all"
        self.group_all.mkdir(parents=True)
        (self.group_all / "bgp_profiles.yaml").write_text(textwrap.dedent("""\
            bgp_profiles:
              OVERLAY_BORDER:
                peer_groups:
                  External:
                    fabric_exit: true
                    peers:
                      192.0.2.2: {}
        """))
        (self.host_vars / "dev1.yaml").write_text(textwrap.dedent("""\
            vrfs:
              extvrf:
                bgp:
                  bgp_profile: OVERLAY_BORDER
            interfaces:
              swp1:
                subinterfaces:
                  1002:
                    ip: 192.0.2.3/31
                    vlan: 1002
                    vrf: extvrf
        """))

    def test_null_interface_stanza_degrades_gracefully(self):
        # Hand-edited house style: key present, value null
        (self.host_vars / "dev2.yaml").write_text(textwrap.dedent("""\
            vrfs:
              extvrf:
                bgp:
                  bgp_profile: OVERLAY_BORDER
            interfaces:
              swp10:
        """))
        result = run_action(LIST_EXTERNAL_PEERS_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        dev1_peers = [p for p in result["peers"] if p["device"] == "dev1"]
        self.assertEqual(len(dev1_peers), 1, result)
        self.assertEqual(dev1_peers[0]["local_ip"], "192.0.2.3")
        # The null stanza is skipped per-entry, not surfaced as a load error
        self.assertNotIn("errors", result)
        hostnames = [d["hostname"] for d in result["devices"]]
        self.assertIn("dev2", hostnames)

    def test_null_vrf_and_subif_entries_skip(self):
        (self.host_vars / "dev3.yaml").write_text(textwrap.dedent("""\
            vrfs:
              brokenvrf:
            interfaces:
              swp2:
                subinterfaces:
                  2001:
        """))
        result = run_action(LIST_EXTERNAL_PEERS_BODY, {}, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        self.assertEqual(
            [p["device"] for p in result["peers"]], ["dev1"], result)


class SourceContractTest(unittest.TestCase):
    """Pins on fabric-api.sh source the behavioral tests cannot reach."""

    def test_refresh_assets_branch_removed(self):
        self.assertNotIn("refresh-assets)", SCRIPT_TEXT)

    def test_telemetry_max_parallel_parse_is_guarded(self):
        guarded = (
            "try:\n"
            "    max_workers = int(lldpq_conf.get('TELEMETRY_MAX_PARALLEL', '25') or 25)\n"
            "except ValueError:"
        )
        self.assertEqual(SCRIPT_TEXT.count(guarded), 2)
        # No unguarded parse left behind
        self.assertEqual(
            SCRIPT_TEXT.count("int(lldpq_conf.get('TELEMETRY_MAX_PARALLEL'"), 2)

    def test_get_device_data_arm_evals_lldpq_config(self):
        start = SCRIPT_TEXT.index("    get-device-data)")
        arm_prelude = SCRIPT_TEXT[start:SCRIPT_TEXT.index("python3 << 'PYTHON'", start)]
        self.assertIn("/usr/local/bin/lldpq-config", arm_prelude)
        self.assertIn("export MONITOR_DATA_MAX_AGE_MINUTES", arm_prelude)

    def test_port_profile_mutators_include_json_excepthook(self):
        for func in ("create_port_profile() {",
                     "update_port_profile() {",
                     "delete_port_profile() {"):
            start = SCRIPT_TEXT.index(func)
            prelude = SCRIPT_TEXT[start:SCRIPT_TEXT.index("import json", start)]
            self.assertIn("$LLDPQ_JSON_EXCEPTHOOK_DEF", prelude, func)


if __name__ == "__main__":
    unittest.main()
