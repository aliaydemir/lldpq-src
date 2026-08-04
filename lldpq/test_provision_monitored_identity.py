#!/usr/bin/env python3
"""Checks that a DHCP-free fabric can still authorize a device mutation.

Upgrade and base-config targets are picked from devices.yaml, but identity for
the fail-closed on-device guard used to come only from DHCP records.  A site
that never ran LLDPq's DHCP/ZTP therefore had every target rejected with
"no longer matches the current inventory".  These tests pin the supplement that
closes that gap without loosening the guard itself.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROVISION_API = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")
_BODY = PROVISION_API[
    PROVISION_API.index("python3 << 'PYTHON_SCRIPT'\n"):
    PROVISION_API.rindex("\nPYTHON_SCRIPT\n")
]
_TREE = ast.parse(_BODY)

FUNCTIONS = (
    "is_valid_provision_hostname",
    "normalize_inventory_bindings",
    "normalize_identity_mac",
    "normalize_identity_serial",
    "remote_identity_guard_shell",
    "_devices_yaml_targets",
    "_monitored_device_macs",
    "supplement_with_monitored_devices",
    "_load_canonical_inventory_bindings_unlocked",
    "canonicalize_inventory_target",
)


def load_module(lldpq_dir: Path, web_root: Path):
    """Exec just the inventory helpers, isolated from the CGI dispatcher."""
    import ipaddress
    import os
    import re
    import shlex

    namespace = {
        "os": os, "json": json, "re": re, "ipaddress": ipaddress, "shlex": shlex,
        "LLDPQ_DIR": str(lldpq_dir),
        "WEB_ROOT": str(web_root),
        "INVENTORY_FILE": str(web_root / "inventory.json"),
        # No DHCP anywhere: exactly the customer situation under test
        "get_dhcp_hosts_path": lambda: str(web_root / "absent-dhcpd.hosts"),
        "parse_dhcp_hosts": lambda path: [],
    }
    for name in FUNCTIONS:
        exec(compile(extract_function(name), "provision-api.sh", "exec"), namespace)
    return namespace


def extract_function(name: str) -> str:
    """Slice one top-level def by its parsed span.

    Line heuristics are not enough: remote_identity_guard_shell() embeds a
    triple-quoted shell script whose lines start at column zero.
    """
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            lines = _BODY.splitlines()[node.lineno - 1:node.end_lineno]
            return "\n".join(lines) + "\n"
    raise AssertionError(f"{name}() not found in provision-api.sh")


class MonitoredIdentityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.lldpq = root / "lldpq"
        self.web = root / "www"
        self.lldpq.mkdir()
        self.web.mkdir()
        self.write_devices({"192.168.100.39": "OOB-LF-10 @leaf"})
        self.write_device_cache({
            "OOB-LF-10": {"ip": "192.168.100.39", "mac": "AA:BB:CC:DD:EE:01",
                          "serial": "MT2210X-90210"},
        })
        self.api = load_module(self.lldpq, self.web)

    def tearDown(self):
        self._tmp.cleanup()

    # ---------- fixtures ----------
    def write_devices(self, devices):
        lines = ["defaults:", "  username: cumulus", "", "devices:"]
        for ip, value in devices.items():
            lines.append(f"  {ip}: {value}")
        (self.lldpq / "devices.yaml").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")

    def write_device_cache(self, cache):
        (self.web / "device-cache.json").write_text(json.dumps(cache),
                                                    encoding="utf-8")

    def write_inventory(self, bindings):
        (self.web / "inventory.json").write_text(
            json.dumps({"bindings": bindings}), encoding="utf-8")

    def load(self, include_monitored=True):
        return self.api["_load_canonical_inventory_bindings_unlocked"](
            include_monitored=include_monitored)

    def canonicalize(self, hostname, ip):
        return self.api["canonicalize_inventory_target"](
            {"hostname": hostname, "ip": ip}, self.load())

    # ---------- the reported failure ----------
    def test_monitored_device_authorizes_without_any_dhcp_record(self):
        canonical = self.canonicalize("OOB-LF-10", "192.168.100.39")
        self.assertEqual(canonical["expected_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(canonical["hostname"], "OOB-LF-10")

    def test_target_is_matched_case_insensitively(self):
        canonical = self.canonicalize("oob-lf-10", "192.168.100.39")
        self.assertEqual(canonical["expected_mac"], "aa:bb:cc:dd:ee:01")

    def test_unknown_device_is_still_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.canonicalize("not-a-switch", "192.168.100.77")
        self.assertIn("no longer matches the current inventory", str(ctx.exception))

    def test_device_without_a_collected_mac_reports_the_real_gap(self):
        """The message must name the missing identity, not deny the device."""
        self.write_device_cache({"OOB-LF-10": {"ip": "192.168.100.39", "mac": "NA"}})
        with self.assertRaises(ValueError) as ctx:
            self.canonicalize("OOB-LF-10", "192.168.100.39")
        self.assertIn("no inventory MAC or serial", str(ctx.exception))

    # ---------- the serial trap ----------
    def test_serial_is_never_imported_from_the_asset_cache(self):
        """assets.sh turns spaces into '-'; the on-box guard compares raw output,
        so an imported serial could fail a device its MAC already identifies."""
        binding = next(b for b in self.load() if b["hostname"] == "OOB-LF-10")
        self.assertEqual(binding["serial"], "")
        guard = self.api["remote_identity_guard_shell"](binding["mac"],
                                                        binding["serial"])
        self.assertIn("EXPECTED_SERIAL=''", guard)
        self.assertIn("aa:bb:cc:dd:ee:01", guard)

    def test_guard_stays_fail_closed_without_identity(self):
        guard = self.api["remote_identity_guard_shell"]("", "")
        self.assertIn("exit 42", guard)
        self.assertNotIn("LLDPQ_IDENTITY_OK", guard)

    # ---------- DHCP records stay authoritative ----------
    def test_existing_binding_is_never_overwritten(self):
        self.write_inventory([{
            "hostname": "OOB-LF-10", "ip": "192.168.100.39",
            "mac": "11:22:33:44:55:66", "serial": "REAL-SERIAL", "dhcp": True,
        }])
        canonical = self.canonicalize("OOB-LF-10", "192.168.100.39")
        self.assertEqual(canonical["expected_mac"], "11:22:33:44:55:66")
        self.assertEqual(canonical["expected_serial"], "REAL-SERIAL")
        self.assertEqual(len([b for b in self.load()
                              if b["hostname"] == "OOB-LF-10"]), 1)

    def test_binding_matched_by_ip_alone_is_not_duplicated(self):
        self.write_inventory([{
            "hostname": "renamed-later", "ip": "192.168.100.39",
            "mac": "11:22:33:44:55:66", "dhcp": True,
        }])
        self.assertEqual([b["hostname"] for b in self.load()], ["renamed-later"])

    def test_placeholder_binding_gains_the_collected_mac(self):
        self.write_inventory([{
            "hostname": "OOB-LF-10", "ip": "192.168.100.39",
            "mac": "-", "serial": "", "dhcp": False,
        }])
        canonical = self.canonicalize("OOB-LF-10", "192.168.100.39")
        self.assertEqual(canonical["expected_mac"], "aa:bb:cc:dd:ee:01")

    # ---------- robustness ----------
    def test_a_mac_claimed_twice_is_left_ambiguous_rather_than_raising(self):
        self.write_devices({"192.168.100.39": "OOB-LF-10 @leaf",
                            "192.168.100.40": "OOB-LF-11 @leaf"})
        self.write_device_cache({
            "OOB-LF-10": {"mac": "AA:BB:CC:DD:EE:01"},
            "OOB-LF-11": {"mac": "AA:BB:CC:DD:EE:01"},   # stale duplicate
        })
        bindings = {b["hostname"]: b["mac"] for b in self.load()}
        self.assertEqual(bindings["OOB-LF-10"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(bindings["OOB-LF-11"], "-")

    def test_unusable_devices_yaml_rows_are_skipped_quietly(self):
        self.write_devices({
            "192.168.100.39": "OOB-LF-10 @leaf",
            "not-an-ip": "bad-address @leaf",
            "192.168.100.41": '""',
        })
        hostnames = [b["hostname"] for b in self.load()]
        self.assertEqual(hostnames, ["OOB-LF-10"])

    def test_unparsable_devices_yaml_degrades_instead_of_raising(self):
        (self.lldpq / "devices.yaml").write_text("devices: [unbalanced\n",
                                                 encoding="utf-8")
        self.assertEqual(self.load(), [])

    def test_dict_style_devices_yaml_is_supported(self):
        (self.lldpq / "devices.yaml").write_text(textwrap.dedent("""\
            devices:
              192.168.100.39:
                hostname: OOB-LF-10
                role: leaf
        """), encoding="utf-8")
        self.assertEqual([b["hostname"] for b in self.load()], ["OOB-LF-10"])

    def test_missing_asset_cache_does_not_break_the_load(self):
        (self.web / "device-cache.json").unlink()
        binding = next(b for b in self.load() if b["hostname"] == "OOB-LF-10")
        self.assertEqual(binding["mac"], "-")

    def test_corrupt_asset_cache_is_ignored(self):
        (self.web / "device-cache.json").write_text("{not json", encoding="utf-8")
        self.assertEqual([b["hostname"] for b in self.load()], ["OOB-LF-10"])

    # ---------- unchanged for every existing caller ----------
    def test_discovery_path_sees_the_unsupplemented_inventory(self):
        self.assertEqual(self.load(include_monitored=False), [])

    def test_supplement_marks_its_own_rows(self):
        binding = next(b for b in self.load() if b["hostname"] == "OOB-LF-10")
        self.assertEqual(binding["inv_status"], "monitored")
        self.assertFalse(binding["dhcp"])


if __name__ == "__main__":
    unittest.main()
