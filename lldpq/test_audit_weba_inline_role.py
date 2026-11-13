#!/usr/bin/env python3
"""The web back ends read the devices.yaml inline role like parse_devices.py.

`192.0.2.12: bleaf-01 @border-leaf` is a valid entry: the canonical parser
(lldpq/parse_devices.py) accepts letters, digits, '_', '.' and '-' in the
role, and the provisioning UI writes such roles itself.  Four web back ends
matched the role with `\\w+` instead, so a role holding '-' or '.' was not
recognised and the whole string 'bleaf-01 @border-leaf' became the hostname:

- fabric-api.sh list-devices (the device pickers of ten pages),
- ai-api.sh build_fabric_summary (the Ask-AI device inventory),
- provision-api.sh run_subnet_scan (discovery hostname and role),
- provision-api.sh action_list_roles (the role drop-down).

Every test runs the real embedded Python of the CGI against a temporary
devices.yaml and compares it with what parse_devices returns for that file.
"""

from __future__ import annotations

import ast
import contextlib
import fcntl
import io
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lldpq"))

import parse_devices  # noqa: E402


DEVICES_YAML = (
    "defaults:\n"
    "  username: cumulus\n"
    "devices:\n"
    "  192.0.2.11: leaf-01 @leaf\n"
    "  192.0.2.12: bleaf-01 @border-leaf\n"
    "  192.0.2.13: sspine-01 @super-spine\n"
    "  192.0.2.14: leaf-02 @leaf.pod1\n"
    "  192.0.2.15: spine-01 @spine_a\n"
    "  192.0.2.16: Edge-01 @Edge-Router.B\n"
    "  192.0.2.17: oob-01\n"
)

# The roles the old `\w+` expression could not read.
PUNCTUATED_ROLES = {"border-leaf", "super-spine", "leaf.pod1", "edge-router.b"}


def canonical_devices(path):
    """ip -> (hostname, role) exactly as the collectors see the file."""
    config = parse_devices.load_devices_yaml(str(path))
    return {
        str(ip): (hostname, role)
        for ip, _username, hostname, role in parse_devices.get_all_devices(config)
    }


def embedded_python(script_name):
    """The main `python3 << 'PYTHON_SCRIPT'` body of a CGI and its AST."""
    text = (ROOT / "html" / script_name).read_text(encoding="utf-8")
    opener = "python3 << 'PYTHON_SCRIPT'\n"
    body = text[text.index(opener) + len(opener):text.rindex("\nPYTHON_SCRIPT\n")]
    return body, ast.parse(body)


def extract_def(body, tree, name):
    """Slice one top-level def out of a CGI's embedded Python."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return "\n".join(body.splitlines()[node.lineno - 1:node.end_lineno]) + "\n"
    raise AssertionError(f"{name} not found")


class Emitted(BaseException):
    """A CGI response.  Not an Exception, so no `except Exception` swallows it."""

    def __init__(self, payload):
        super().__init__(payload)
        self.payload = payload


class InlineRoleFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.lldpq_dir = self.root / "lldpq"
        self.lldpq_dir.mkdir()
        self.web_root = self.root / "www"
        self.web_root.mkdir()
        self.devices_file = self.lldpq_dir / "devices.yaml"
        self.devices_file.write_text(DEVICES_YAML, encoding="utf-8")
        self.canonical = canonical_devices(self.devices_file)


class FixtureTests(InlineRoleFixture):
    def test_fixture_exercises_punctuated_roles(self):
        roles = {role for _hostname, role in self.canonical.values()}
        self.assertTrue(PUNCTUATED_ROLES <= roles, roles)
        self.assertEqual(self.canonical["192.0.2.12"], ("bleaf-01", "border-leaf"))
        self.assertEqual(self.canonical["192.0.2.17"], ("oob-01", None))


class FabricApiListDevicesTests(InlineRoleFixture):
    """fabric-api.sh?action=list-devices without an Ansible inventory."""

    def list_devices(self, inventory_file=""):
        text = (ROOT / "html" / "fabric-api.sh").read_text(encoding="utf-8")
        start = text.index("\nlist_devices() {\n")
        opener = "python3 << 'PYTHON'\n"
        body_start = text.index(opener, start) + len(opener)
        body = text[body_start:text.index("\nPYTHON\n", body_start)]
        result = subprocess.run(
            [sys.executable, "-"], input=body, capture_output=True, text=True,
            check=False,
            env=dict(os.environ, INVENTORY_FILE=inventory_file,
                     DEVICES_YAML=str(self.devices_file)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_groups_match_parse_devices(self, payload):
        self.assertTrue(payload["success"], payload)
        self.assertEqual(payload["source"], "devices.yaml")
        expected = {}
        for ip, (hostname, role) in self.canonical.items():
            expected.setdefault(role or "all", []).append(
                {"hostname": hostname, "ip": ip})
        self.assertEqual(payload["devices"], expected)

    def test_groups_and_hostnames_match_parse_devices(self):
        payload = self.list_devices()
        self.assert_groups_match_parse_devices(payload)
        # The defect: these devices were listed under 'all' with the role
        # tag glued to the name.
        self.assertEqual(payload["devices"]["all"],
                         [{"hostname": "oob-01", "ip": "192.0.2.17"}])
        self.assertEqual(payload["devices"]["border-leaf"],
                         [{"hostname": "bleaf-01", "ip": "192.0.2.12"}])
        names = [device["hostname"] for group in payload["devices"].values()
                 for device in group]
        self.assertFalse([name for name in names if "@" in name], names)

    def test_missing_ansible_inventory_falls_back_the_same_way(self):
        payload = self.list_devices(str(self.root / "inventory" / "hosts"))
        self.assert_groups_match_parse_devices(payload)


class AskAiInventoryTests(InlineRoleFixture):
    """ai-api.sh build_fabric_summary: the Ask-AI device inventory."""

    def build(self):
        body, tree = embedded_python("ai-api.sh")
        namespace = {
            "os": os, "re": re, "json": json, "time": time,
            "LLDPQ_DIR": str(self.lldpq_dir), "WEB_ROOT": str(self.web_root),
            # Only the inventory section is under test; the later sections
            # tolerate their missing data sources.
            "build_collection_metadata": lambda devices, health: {},
            "format_collection_metadata": lambda metadata: "",
        }
        exec(compile(extract_def(body, tree, "build_fabric_summary"),
                     "ai-api.sh", "exec"), namespace)
        return namespace["build_fabric_summary"]()

    def test_devices_and_roles_match_parse_devices(self):
        summary, devices, _health, _metadata = self.build()
        self.assertEqual(
            {ip: (info["hostname"], info["role"]) for ip, info in devices.items()},
            {ip: (hostname, role or "unknown")
             for ip, (hostname, role) in self.canonical.items()},
        )
        self.assertEqual(devices["192.0.2.12"],
                         {"hostname": "bleaf-01", "role": "border-leaf",
                          "ip": "192.0.2.12"})
        inventory_line = summary.splitlines()[0]
        self.assertTrue(inventory_line.startswith("DEVICE INVENTORY: 7 devices"),
                        inventory_line)
        for role in PUNCTUATED_ROLES:
            self.assertIn(f"1 {role}", inventory_line)
        self.assertIn("1 unknown", inventory_line)


class ProvisionFixture(InlineRoleFixture):
    def setUp(self):
        super().setUp()
        self.body, self.tree = embedded_python("provision-api.sh")
        self.inventory = self.web_root / "inventory.json"
        self.api = {
            "os": os, "re": re, "json": json, "time": time, "shlex": shlex,
            "socket": socket, "subprocess": subprocess, "ipaddress": ipaddress,
            "ThreadPoolExecutor": ThreadPoolExecutor, "as_completed": as_completed,
            "LLDPQ_DIR": str(self.lldpq_dir),
            "INVENTORY_FILE": str(self.inventory),
            "result_json": lambda payload: (_ for _ in ()).throw(Emitted(payload)),
        }

    def load(self, *names):
        for name in names:
            exec(compile(extract_def(self.body, self.tree, name),
                         "provision-api.sh", "exec"), self.api)


class ProvisionRoleDropdownTests(ProvisionFixture):
    """provision-api.sh?action=list-roles."""

    def list_roles(self):
        self.load("action_list_roles")
        try:
            self.api["action_list_roles"]()
        except Emitted as response:
            return response.payload
        self.fail("action_list_roles returned without emitting a response")

    def test_roles_match_parse_devices(self):
        payload = self.list_roles()
        self.assertTrue(payload["success"], payload)
        self.assertEqual(
            payload["roles"],
            sorted({role for _hostname, role in self.canonical.values() if role}),
        )
        self.assertTrue(PUNCTUATED_ROLES <= set(payload["roles"]), payload)

    def test_inventory_roles_are_still_merged(self):
        self.inventory.write_text(json.dumps({"bindings": [
            {"hostname": "leaf-09", "ip": "192.0.2.99", "role": "Storage-Leaf"},
        ]}), encoding="utf-8")
        self.assertIn("storage-leaf", self.list_roles()["roles"])

    def test_role_written_by_update_role_is_offered_again(self):
        # The provisioning UI accepts and writes such a role itself.
        def atomic_write_text(path, content, mode=0o664):
            Path(path).write_text(content, encoding="utf-8")

        self.api.update({
            "fcntl": fcntl, "io": io,
            "POST_DATA": json.dumps({"hostname": "oob-01", "role": "Mgmt-Sw.1"}),
            "INVENTORY_LOCK_FILE": str(self.web_root / ".inventory.lock"),
            "error_json": lambda message: (_ for _ in ()).throw(
                Emitted({"success": False, "error": message})),
            "atomic_write_text": atomic_write_text,
            "inventory_revision": lambda: "rev0",
        })
        self.load("action_update_role")
        with self.assertRaises(Emitted) as response:
            self.api["action_update_role"]()
        self.assertTrue(response.exception.payload["success"],
                        response.exception.payload)
        self.assertIn("192.0.2.17: oob-01 @mgmt-sw.1",
                      self.devices_file.read_text(encoding="utf-8"))
        self.assertEqual(canonical_devices(self.devices_file)["192.0.2.17"],
                         ("oob-01", "mgmt-sw.1"))
        self.assertIn("mgmt-sw.1", self.list_roles()["roles"])


class ProvisionDiscoveryTests(ProvisionFixture):
    """provision-api.sh run_subnet_scan: hostname and role of unbound addresses."""

    def scan(self):
        self.api.update({
            "DISCOVERY_RANGE": "", "LLDPQ_USER": "collector",
            "BASE_STATE_FILE": "/base-state", "LEGACY_BASE_MARKER": "/legacy-base",
            "ZTP_STATE_FILE": "/ztp-state", "FILE_DEPLOY_MAP": {"base": ("unused",)},
            "DISCOVERY_CACHE_FILE": str(self.web_root / "discovery-cache.json"),
            "read_lldpq_conf_key": lambda key, default="": (
                "192.0.2.11-192.0.2.18" if key == "DISCOVERY_RANGE" else "true"),
            # No inventory binding: the names can only come from devices.yaml.
            "load_canonical_inventory_bindings": lambda: [],
            "base_config_manifest": lambda files: (["base"], "manifest"),
            "evaluate_device_identity": lambda *args: (True, ""),
            "atomic_write_text": lambda path, content, mode=0o664:
                Path(path).write_text(content, encoding="utf-8"),
        })
        self.load("ip_range_to_list", "is_valid_provision_hostname",
                  "normalize_identity_mac", "run_subnet_scan")
        commands = []

        def fake_run(command, **kwargs):
            commands.append(command)
            if command[0] == "ping":
                return subprocess.CompletedProcess(command, 1, "", "")
            if command[:2] == ["ip", "neigh"]:
                return subprocess.CompletedProcess(command, 0, "", "")
            if "ssh" in command:
                return subprocess.CompletedProcess(
                    command, 255, "", "connection timed out")
            raise AssertionError(command)

        @contextlib.contextmanager
        def closed_port(address, **kwargs):
            raise OSError("blocked")
            yield  # pragma: no cover

        with mock.patch("subprocess.run", side_effect=fake_run), \
                mock.patch("socket.create_connection", side_effect=closed_port):
            return self.api["run_subnet_scan"](apply_post_provision=False), commands

    def test_hostname_and_role_match_parse_devices(self):
        result, commands = self.scan()
        self.assertTrue(result["success"], result)
        entries = {entry["ip"]: entry for entry in result["entries"]}
        self.assertEqual(
            {ip: (entries[ip]["hostname"], entries[ip]["role"])
             for ip in self.canonical},
            {ip: (hostname, role or "")
             for ip, (hostname, role) in self.canonical.items()},
        )
        self.assertEqual(
            (entries["192.0.2.12"]["hostname"], entries["192.0.2.12"]["role"]),
            ("bleaf-01", "border-leaf"),
        )
        # An address devices.yaml does not know stays anonymous.
        self.assertEqual(
            (entries["192.0.2.18"]["hostname"], entries["192.0.2.18"]["role"]),
            ("", ""),
        )
        # Nothing but the mocked probes ran.
        self.assertTrue(all(command[0] in ("ping", "ip", "sudo")
                            for command in commands), commands)


class ProvisionDeviceListTests(ProvisionFixture):
    """provision-api.sh readers that split the entry at '@': the Base Config
    device list (list-devices) and the OS upgrade candidates."""

    def canonical_roles(self):
        return {ip: (hostname, role or "ungrouped")
                for ip, (hostname, role) in self.canonical.items()}

    def emitted(self, name):
        self.api["error_json"] = lambda message: (_ for _ in ()).throw(
            Emitted({"success": False, "error": message}))
        self.load(name)
        try:
            self.api[name]()
        except Emitted as response:
            self.assertTrue(response.payload["success"], response.payload)
            return response.payload
        self.fail(f"{name} returned without emitting a response")

    def test_base_config_device_list_matches_parse_devices(self):
        payload = self.emitted("action_list_devices")
        self.assertEqual(
            {device["ip"]: (device["hostname"], device["role"])
             for device in payload["devices"]},
            self.canonical_roles())
        # The role tag is case-insensitive: one group, in lower case.
        self.assertEqual(
            [device["hostname"] for device in payload["groups"]["edge-router.b"]],
            ["Edge-01"])
        self.assertNotIn("Edge-Router.B", payload["groups"])

    def test_upgrade_candidates_match_parse_devices(self):
        self.api.update({
            "sys": sys,
            "get_device_version": lambda device: dict(device, reachable=False),
            "list_os_image_objects": lambda: [],
            "get_server_ip": lambda: "192.0.2.1",
        })
        with contextlib.redirect_stdout(io.StringIO()):
            payload = self.emitted("action_upgrade_candidates")
        self.assertEqual(
            {device["ip"]: (device["hostname"], device["role"])
             for device in payload["devices"]},
            self.canonical_roles())


class GeneratedDevicesYamlTests(unittest.TestCase):
    """ai_generate reads the existing devices.yaml to diff a generated one."""

    def test_existing_inline_role_is_read_in_lower_case(self):
        sys.path.insert(0, str(ROOT / "html"))
        import ai_generate
        _defaults, devices = ai_generate._parse_existing_devices(DEVICES_YAML)
        self.assertEqual(
            {device["ip"]: (device["hostname"], device["role"]) for device in devices},
            {"192.0.2.11": ("leaf-01", "leaf"),
             "192.0.2.12": ("bleaf-01", "border-leaf"),
             "192.0.2.13": ("sspine-01", "super-spine"),
             "192.0.2.14": ("leaf-02", "leaf.pod1"),
             "192.0.2.15": ("spine-01", "spine_a"),
             "192.0.2.16": ("Edge-01", "edge-router.b"),
             "192.0.2.17": ("oob-01", "")})


class CanonicalExpressionTests(unittest.TestCase):
    """No web back end reads the inline role with a narrower character class."""

    SCRIPTS = ("fabric-api.sh", "ai-api.sh", "provision-api.sh", "search-api.sh")

    def test_inline_role_expressions_use_the_canonical_class(self):
        canonical = re.search(
            r"@\((\[[^\]]+\]\+)\)",
            (ROOT / "lldpq" / "parse_devices.py").read_text(encoding="utf-8"),
        ).group(1)
        self.assertEqual(canonical, "[A-Za-z0-9_.-]+")
        for name in self.SCRIPTS:
            text = (ROOT / "html" / name).read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if not re.search(r"re\.\w+\(r['\"]\^.*\\s\+@", line):
                    continue
                with self.subTest(script=name, line=number):
                    self.assertIn(f"@({canonical})$", line)


if __name__ == "__main__":
    unittest.main()
