#!/usr/bin/env python3
"""Warns when an uploaded IPAM design hands a host a switch's own address.

A VRR pair configures three addresses per VLAN: the shared virtual IP and one
per switch. On a real fabric a control-node BMC was allocated the even switch's
SVI address, which nothing objected to at design time, went into production, and
only appeared much later as a duplicate-IP warning that took a live debugging
session to trace back to the spreadsheet.

The check runs where an upload is parsed, reading the same vlan_profiles.yaml the
fabric is generated from, so it needs no new source of truth.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "html" / "inventory-api.sh"

VLAN_PROFILES = textwrap.dedent("""\
    vlan_profiles:
      VLAN_7:
        vrr:
          state: true
        vlans:
          7:
            description: CTRL Nodes Management
            l2vni: 100007
            vrr_vip: 10.2.243.62/26
            even_ip: 10.2.243.60/26
            odd_ip:  10.2.243.61/26
            vrr_vmac: 44:38:39:fb:00:07
      VLAN_100:
        vrr:
          state: true
        vlans:
          100:
            l2vni: 200100
            vrr_vip: 10.2.235.254/22
            even_ip: 10.2.235.252/22
            odd_ip:  10.2.235.253/22
    """)


def extract_python_block(path):
    """The CGI wraps its implementation in a single here-doc."""
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^python3 << 'PYTHON_END'\n(.*?)^PYTHON_END$",
                      text, re.S | re.M)
    if not match:
        raise AssertionError("inventory-api.sh python block not found")
    return match.group(1)


class FabricAddressCollisionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block = extract_python_block(API)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ansible = Path(self._tmp.name) / "ansible"
        profiles = self.ansible / "inventory" / "group_vars" / "all"
        profiles.mkdir(parents=True)
        (profiles / "vlan_profiles.yaml").write_text(VLAN_PROFILES,
                                                     encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def run_check(self, design, *, ansible_dir=None):
        """Run the two helpers, lifted verbatim out of the CGI, in isolation."""
        source = textwrap.dedent("""\
            import ipaddress
            import json
            import os
            ANSIBLE_DIR = os.environ.get('ANSIBLE_DIR', '')
            """) + self.extract_functions(
                "fabric_owned_addresses",
                "warn_on_fabric_owned_addresses") + textwrap.dedent("""
            design = json.loads(%r)
            warn_on_fabric_owned_addresses(design)
            print("OWNED=" + json.dumps(sorted(fabric_owned_addresses())))
            print("WARNINGS=" + json.dumps(design.get("warnings") or []))
            """) % json.dumps(design)
        env = dict(os.environ)
        env["ANSIBLE_DIR"] = (str(self.ansible) if ansible_dir is None
                              else ansible_dir)
        result = subprocess.run(["python3", "-c", source], env=env,
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        owned = json.loads(
            re.search(r"^OWNED=(.*)$", result.stdout, re.M).group(1))
        warnings = json.loads(
            re.search(r"^WARNINGS=(.*)$", result.stdout, re.M).group(1))
        return owned, warnings

    @classmethod
    def extract_functions(cls, *names):
        """Exact source of the named top-level functions, via the parse tree."""
        lines = cls.block.splitlines(keepends=True)
        found = {}
        for node in ast.parse(cls.block).body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                found[node.name] = "".join(
                    lines[node.lineno - 1:node.end_lineno])
        missing = [n for n in names if n not in found]
        if missing:
            raise AssertionError("not found in inventory-api.sh: %s" % missing)
        return "\n".join(found[n] for n in names) + "\n"

    # ---------- reading the fabric's own addresses ----------
    def test_all_three_vrr_addresses_are_recognised(self):
        owned, _ = self.run_check({"hosts": []})
        self.assertEqual(
            ["10.2.235.252", "10.2.235.253", "10.2.235.254",
             "10.2.243.60", "10.2.243.61", "10.2.243.62"],
            owned)

    def test_no_ansible_directory_disables_the_check_quietly(self):
        owned, warnings = self.run_check(
            {"hosts": [{"hostname": "UFM-01",
                        "assignments": [{"role_or_interface": "bmc",
                                         "ip": "10.2.243.60"}]}]},
            ansible_dir="")
        self.assertEqual([], owned)
        self.assertEqual([], warnings)

    def test_ansible_dir_set_to_none_is_also_tolerated(self):
        owned, _ = self.run_check({"hosts": []}, ansible_dir="NoNe")
        self.assertEqual([], owned)

    # ---------- the mistake that reached production ----------
    def test_a_bmc_on_the_even_switch_address_is_reported(self):
        _owned, warnings = self.run_check({"hosts": [
            {"hostname": "UFM-01", "assignments": [
                {"role_or_interface": "bmc", "ip": "10.2.243.60"}]},
        ]})
        self.assertEqual(1, len(warnings))
        self.assertIn("UFM-01", warnings[0])
        self.assertIn("10.2.243.60", warnings[0])
        self.assertIn("even_ip", warnings[0])
        self.assertIn("VLAN 7", warnings[0])

    def test_both_switch_addresses_are_reported_together(self):
        _owned, warnings = self.run_check({"hosts": [
            {"hostname": "UFM-01", "assignments": [
                {"role_or_interface": "bmc", "ip": "10.2.243.60"}]},
            {"hostname": "UFM-02", "assignments": [
                {"role_or_interface": "bmc", "ip": "10.2.243.61"}]},
        ]})
        self.assertEqual(1, len(warnings))
        self.assertIn("2 address(es)", warnings[0])
        self.assertIn("UFM-02", warnings[0])
        self.assertIn("odd_ip", warnings[0])

    def test_the_shared_virtual_ip_is_caught_too(self):
        _owned, warnings = self.run_check({"hosts": [
            {"hostname": "Ctrl Node-01", "assignments": [
                {"role_or_interface": "eth0", "ip": "10.2.243.62"}]},
        ]})
        self.assertIn("vrr_vip", warnings[0])

    # ---------- what must not be flagged ----------
    def test_an_ordinary_host_address_is_not_flagged(self):
        _owned, warnings = self.run_check({"hosts": [
            {"hostname": "Ctrl Node-01", "assignments": [
                {"role_or_interface": "eth0", "ip": "10.2.243.10"},
                {"role_or_interface": "bmc", "ip": "10.2.243.36"}]},
        ]})
        self.assertEqual([], warnings)

    def test_a_design_without_hosts_is_left_alone(self):
        _owned, warnings = self.run_check({"subnets": []})
        self.assertEqual([], warnings)

    def test_existing_warnings_are_preserved(self):
        _owned, warnings = self.run_check({
            "warnings": ["3 row(s) with blank/tbd IP skipped"],
            "hosts": [{"hostname": "UFM-01", "assignments": [
                {"role_or_interface": "bmc", "ip": "10.2.243.60"}]}],
        })
        self.assertEqual(2, len(warnings))
        self.assertIn("blank/tbd", warnings[0])

    def test_a_malformed_profile_file_does_not_break_an_upload(self):
        path = (self.ansible / "inventory" / "group_vars" / "all"
                / "vlan_profiles.yaml")
        path.write_text("vlan_profiles: [unbalanced\n", encoding="utf-8")
        owned, warnings = self.run_check({"hosts": [
            {"hostname": "UFM-01", "assignments": [
                {"role_or_interface": "bmc", "ip": "10.2.243.60"}]}]})
        self.assertEqual([], owned)
        self.assertEqual([], warnings)

    def test_the_cgi_still_parses_as_shell(self):
        subprocess.run(["bash", "-n", str(API)], check=True)



if __name__ == "__main__":
    unittest.main()
