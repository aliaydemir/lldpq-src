#!/usr/bin/env python3
"""Mixed monitoring inventories must not block IPv4 legacy-job reconciliation."""

import ast
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

try:
    import ruamel.yaml  # noqa: F401 — the installer's actual inventory parser
    HAS_RUAMEL = True
except ImportError:
    HAS_RUAMEL = False


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(HAS_RUAMEL, "installer requires ruamel.yaml")
class InstallerMixedInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.devices = self.root / "devices.yaml"
        self.inventory = self.root / "inventory.json"
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        block = source.split("\nimport concurrent.futures\n", 1)[1].split("\nPYTHON\n", 1)[0]
        names = {"strict_object", "read_stable_regular", "load_authorized_targets", "authorize_probe_target"}
        tree = ast.parse(block)
        functions = ast.Module(body=[node for node in tree.body
                                    if isinstance(node, ast.FunctionDef) and node.name in names], type_ignores=[])
        self.namespace = {
            "ipaddress": ipaddress, "json": json, "os": os, "pwd": pwd,
            "re": re, "shutil": shutil, "stat": stat, "subprocess": subprocess, "sys": sys,
            "devices_file": str(self.devices), "inventory_file": str(self.inventory),
            "service_user": pwd.getpwuid(os.geteuid()).pw_name,
        }
        exec(compile(functions, str(ROOT / "install.sh"), "exec"), self.namespace)
        self.write_inventory()

    def write_inventory(self, device_address="2001:db8::10", binding_address="2001:db8::10"):
        # JSON is also valid YAML; the installer still uses its real ruamel
        # subprocess to parse this file before validating the target list.
        self.devices.write_text(json.dumps({"devices": {
            "192.0.2.10": "legacy-leaf @leaf", device_address: "ipv6-monitor @oob",
        }}), encoding="utf-8")
        self.inventory.write_text(json.dumps({"bindings": [
            {"ip": "192.0.2.10", "hostname": "legacy-leaf", "mac": "02:00:00:00:00:10"},
            {"ip": binding_address, "hostname": "ipv6-monitor"},
        ]}), encoding="utf-8")

    def test_monitoring_ipv6_is_skipped_and_existing_ipv4_stays_authorized(self):
        for address in ("2001:db8::10", "fd00::10", "fe80::10%eth0"):
            with self.subTest(address=address):
                self.write_inventory(address, address)
                configured, bindings = self.namespace["load_authorized_targets"]()
                self.assertEqual(set(configured), {"192.0.2.10"})
                self.assertEqual(set(bindings), {"192.0.2.10"})
                target = self.namespace["authorize_probe_target"](
                    {"ip": "192.0.2.10", "hostname": "legacy-leaf", "username": "cumulus"},
                    configured, bindings)
                self.assertEqual(target["expected_mac"], "020000000010")

    def test_legacy_probe_does_not_gain_ipv6_mutation_authority(self):
        with self.assertRaisesRegex(ValueError, "legacy device IP is invalid"):
            self.namespace["authorize_probe_target"](
                {"ip": "2001:db8::10", "hostname": "ipv6-monitor"}, {}, {})

    def test_malformed_inventory_addresses_still_fail(self):
        for address in ("192.0.2.999", "2001:::10"):
            with self.subTest(address=address, source="devices"):
                self.write_inventory(device_address=address)
                with self.assertRaisesRegex(ValueError, "invalid devices.yaml IP"):
                    self.namespace["load_authorized_targets"]()
            with self.subTest(address=address, source="inventory"):
                self.write_inventory(binding_address=address)
                with self.assertRaisesRegex(ValueError, "inventory.json contains an invalid IP"):
                    self.namespace["load_authorized_targets"]()


if __name__ == "__main__":
    unittest.main()
