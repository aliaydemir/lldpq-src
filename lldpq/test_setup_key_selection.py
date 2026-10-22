"""Exercise SSH Setup actions with the real inventory parser and mocked SSH.

The fan-out and per-device commands are the production handlers. Only key
storage/locks and external SSH processes are replaced; no switch is contacted.
"""

import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SETUP_API = ROOT / "html/setup-api.sh"
SOURCE = SETUP_API.read_text().split("python3 << 'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
TREE = ast.parse(SOURCE)
FUNCTIONS = compile(ast.Module(body=[
    node for node in TREE.body if isinstance(node, ast.FunctionDef)
    and node.name in ("load_devices", "select_key_devices", "setup_device")
], type_ignores=[]), str(SETUP_API), "exec")
HANDLERS = {}
for node in TREE.body:
    if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name) and node.test.left.id == "action"
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value in ("verify", "list-key-devices")):
        HANDLERS[node.test.comparators[0].value] = compile(
            ast.Module(body=[node], type_ignores=[]), str(SETUP_API), "exec")
HANDLERS["setup"] = compile(SOURCE.split(
    "# ─── Action: Generate new key + distribute with password ───\n", 1)[1], str(SETUP_API), "exec")


class SetupKeySelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for filename in ("parse_devices.py", "addressing.py"):
            shutil.copyfile(ROOT / "lldpq" / filename, self.directory / filename)
        self.inventory = self.directory / "devices.yaml"
        self.inventory.write_text("""defaults:
  username: cumulus
devices:
  192.0.2.10: SWITCH-V4
  '2001:0DB8:0:0:0:0:0:20': SWITCH-V6
  'fe80::30%eth0': SWITCH-LINKLOCAL
  oob-alias:
    hostname: SWITCH-ALIAS
    username: admin
""")
        self.addresses = ["192.0.2.10", "2001:db8::20", "fe80::30%eth0", "oob-alias"]
        self.commands = []
        self.key_auth = True
        self.key_lock = mock.Mock()
        self.key_provider = mock.Mock(return_value=("/test/collector.pub", False, None))
        self.key_validator = mock.Mock(return_value=("ssh-ed25519 test-key", None))
        self.release_lock = mock.Mock()
        self.namespace = {
            "json": json, "sys": sys, "os": os, "importlib": importlib,
            "subprocess": SimpleNamespace(run=self.run_process, TimeoutExpired=subprocess.TimeoutExpired),
            "ThreadPoolExecutor": ThreadPoolExecutor, "as_completed": as_completed,
            "devices_yaml": str(self.inventory), "lldpq_user": "collector",
            "ensure_ssh_key_lock": self.key_lock, "ensure_ssh_key": self.key_provider,
            "validate_ssh_key_pair": self.key_validator,
            "release_configuration_lock": self.release_lock,
        }
        exec(FUNCTIONS, self.namespace)

    def run_process(self, argv, **kwargs):
        if argv[:2] == [sys.executable, str(self.directory / "parse_devices.py")]:
            return subprocess.run(argv, **kwargs)
        self.commands.append((argv, kwargs))
        self.assertEqual(argv[:4], ["sudo", "-n", "-u", "collector"])
        self.assertIn(argv[4], ("ssh", "/usr/bin/bash"))
        returncode = 1 if argv[4] == "ssh" and argv[-1] == "true" and not self.key_auth else 0
        return subprocess.CompletedProcess(argv, returncode, stdout="", stderr="")

    def call(self, action, **request):
        self.commands.clear()
        for method in (self.key_lock, self.key_provider, self.key_validator, self.release_lock):
            method.reset_mock()
        self.namespace.update(action=action, post_data={"action": action, **request})
        if action == "setup":
            self.namespace["post_data"].setdefault("password", "test password")
        output = io.StringIO()
        with redirect_stdout(output):
            try:
                exec(HANDLERS[action], self.namespace)
            except SystemExit as stopped:
                self.assertEqual(stopped.code, 0)
        return json.loads(output.getvalue())

    def assert_no_key_operations(self, *, locked=False):
        self.assertEqual(self.commands, [])
        if locked:
            self.key_lock.assert_called_once_with()
        else:
            self.key_lock.assert_not_called()
        for method in (self.key_provider, self.key_validator, self.release_lock):
            method.assert_not_called()

    def contacted(self):
        return {argument for argv, _kwargs in self.commands for argument in argv
                if argument.startswith(("cumulus@", "admin@"))}

    def test_list_uses_canonical_inventory_without_key_or_ssh_operations(self):
        result = self.call("list-key-devices")
        self.assertTrue(result["success"], result)
        self.assertEqual([device["ip"] for device in result["devices"]], self.addresses)
        self.assertEqual(result["devices"][-1], {
            "ip": "oob-alias", "hostname": "SWITCH-ALIAS", "username": "admin"})
        self.assertTrue(all(set(device) == {"ip", "hostname", "username"} for device in result["devices"]))
        self.assert_no_key_operations()

    def test_list_reports_broken_inventory_without_key_or_ssh_operations(self):
        self.inventory.write_text("devices: [invalid]\n")
        result = self.call("list-key-devices")
        self.assertFalse(result["success"], result)
        self.assert_no_key_operations()

    def test_verify_only_selected_ipv4_ipv6_scoped_and_alias_devices(self):
        for address in self.addresses:
            with self.subTest(address=address):
                result = self.call("verify", selected_devices=[address])
                self.assertTrue(result["success"], result)
                self.assertEqual((result["total"], result["trusted"], result["sudo_ok"]), (1, 1, 1))
                self.assertEqual(result["results"][0]["ip"], address)
                username = "admin" if address == "oob-alias" else "cumulus"
                self.assertEqual(self.contacted(), {username + "@" + address})
                self.assertEqual(len(self.commands), 2)

    def test_distribution_only_sends_key_and_checks_sudo_on_selected_device(self):
        self.key_auth = False
        for address in self.addresses:
            with self.subTest(address=address):
                result = self.call("setup", selected_devices=[address])
                self.assertTrue(result["success"], result)
                self.assertEqual((result["total"], result["send_key_ok"], result["sudo_fix_ok"]), (1, 1, 1))
                self.assertTrue(result["all_ready"])
                self.assertEqual(result["results"][0]["ip"], address)
                username = "admin" if address == "oob-alias" else "cumulus"
                self.assertEqual(self.contacted(), {username + "@" + address})
                copies = [(argv, kwargs) for argv, kwargs in self.commands if argv[4] == "/usr/bin/bash"]
                self.assertEqual(len(copies), 1)
                self.assertEqual(copies[0][1]["input"], "test password\n")
                self.assertNotIn("test password", " ".join(copies[0][0]))

    def test_equivalent_ipv6_selection_deduplicates_before_fanout(self):
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action, selected_devices=["2001:0DB8:0:0:0:0:0:20", "2001:db8::20"])
                self.assertTrue(result["success"], result)
                self.assertEqual(result["total"], 1)
                self.assertEqual(self.contacted(), {"cumulus@2001:db8::20"})

    def test_missing_selection_preserves_legacy_all_device_operation(self):
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action)
                self.assertTrue(result["success"], result)
                self.assertEqual(result["total"], len(self.addresses))
                self.assertEqual({row["ip"] for row in result["results"]}, set(self.addresses))
                self.assertEqual(len(self.contacted()), len(self.addresses))

    def test_legacy_retry_is_canonical_and_scoped_to_requested_devices(self):
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action, retry_devices=["2001:0DB8::20", "192.0.2.10"])
                self.assertTrue(result["success"], result)
                self.assertEqual(result["total"], 2)
                self.assertEqual(self.contacted(), {"cumulus@2001:db8::20", "cumulus@192.0.2.10"})

    def test_invalid_or_partially_unknown_selection_never_creates_keys_or_contacts_devices(self):
        invalid = ([], None, "192.0.2.10", {}, [10], [True], [""], ["invalid address"],
                   ["2001:xyz::1"], ["fe80::30"], ["192.0.2.99"],
                   ["192.0.2.10", "192.0.2.99"], ["192.0.2.10", "invalid address"])
        for action in ("verify", "setup"):
            for field in ("selected_devices", "retry_devices"):
                for values in invalid:
                    with self.subTest(action=action, field=field, values=values):
                        result = self.call(action, **{field: values})
                        self.assertFalse(result["success"], result)
                        self.assert_no_key_operations(locked=True)

    def test_ambiguous_selection_fields_never_create_keys_or_contact_devices(self):
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action, selected_devices=["192.0.2.10"], retry_devices=["2001:db8::20"])
                self.assertFalse(result["success"], result)
                self.assertIn("not both", result["error"])
                self.assert_no_key_operations(locked=True)

    def test_inventory_is_reloaded_and_stale_selection_is_rejected(self):
        self.assertTrue(self.call("list-key-devices")["success"])
        self.inventory.write_text("devices:\n  192.0.2.10: SWITCH-V4\n")
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action, selected_devices=["192.0.2.10", "2001:db8::20"])
                self.assertFalse(result["success"], result)
                self.assertIn("reload the device list", result["error"])
                self.assert_no_key_operations(locked=True)

    def test_inventory_is_read_after_waiting_for_key_lock(self):
        def change_inventory_while_waiting():
            self.inventory.write_text("devices:\n  192.0.2.10: SWITCH-V4\n")

        for action in ("verify", "setup"):
            with self.subTest(action=action):
                self.inventory.write_text("devices:\n  '2001:db8::20': SWITCH-V6\n")
                self.key_lock.side_effect = change_inventory_while_waiting
                result = self.call(action, selected_devices=["2001:db8::20"])
                self.assertFalse(result["success"], result)
                self.assertIn("reload the device list", result["error"])
                self.assert_no_key_operations(locked=True)

    def test_key_failure_still_stops_selected_operations(self):
        self.key_provider.return_value = (None, False, "incomplete key pair")
        for action in ("verify", "setup"):
            with self.subTest(action=action):
                result = self.call(action, selected_devices=["192.0.2.10"])
                self.assertFalse(result["success"], result)
                self.assertIn("incomplete key pair", result["error"])
                self.assertEqual(self.commands, [])
                self.release_lock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
