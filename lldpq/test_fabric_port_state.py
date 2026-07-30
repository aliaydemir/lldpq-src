#!/usr/bin/env python3
"""Checks for the fabric-wide port/profile inventory action.

The migration page's Current State panel is the only consumer, so the payload
shape (ports as compact rows, vlan_profiles carrying raw `vlans`) is a contract
with `profileInfo()` in fabric-migration.html.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
FABRIC_API = (ROOT / "html" / "fabric-api.sh").read_text(encoding="utf-8")

_START = FABRIC_API.index("get_fabric_port_state() {")
_END = FABRIC_API.index("\nPYTHON\n}\n", _START) + len("\nPYTHON\n}\n")
FUNCTION = FABRIC_API[_START:_END]


def run_action(ansible_dir: Path) -> dict:
    result = subprocess.run(
        ["bash", "-c", FUNCTION + "\nget_fabric_port_state"],
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "ANSIBLE_DIR": str(ansible_dir)},
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def build_inventory(root: Path) -> None:
    host_vars = root / "inventory" / "host_vars"
    group_all = root / "inventory" / "group_vars" / "all"
    host_vars.mkdir(parents=True)
    group_all.mkdir(parents=True)

    (group_all / "sw_port_profiles.yaml").write_text(textwrap.dedent("""\
        sw_port_profiles:
          Tenant-1:
            sw_port_mode: access
            access_vlan: 30
          Tenant-4:
            sw_port_mode: access
            access_vlan: 70
    """), encoding="utf-8")

    (group_all / "vlan_profiles.yaml").write_text(textwrap.dedent("""\
        vlan_profiles:
          SVI-30:
            vlans:
              30:
                vrf: vpn60030
                description: tenant one
          SVI-70:
            vlans:
              70:
                vrf: vpn60070
    """), encoding="utf-8")

    (host_vars / "leaf-01.yaml").write_text(textwrap.dedent("""\
        interfaces:
          swp1:
            description: A01-37-S1-DGX-01:C18
            sw_port_profile: Tenant-4
          swp2:
            description: uplink to spine
            ip: 10.0.0.1/31
          swp3:
            description: unassigned endpoint
          swp4s0:
            description: breakout child
            sw_port_profile: Tenant-1
        bonds:
          bond_1_1_1:
            description: GB300-1-01-Tray-01:M1
            sw_port_profile: Tenant-4
            bond_members:
              - swp5
    """), encoding="utf-8")

    (host_vars / "leaf-02.yml").write_text(textwrap.dedent("""\
        interfaces:
          swp1:
            description: A03-11-S1-DGX-02:C18
            sw_port_profile: Tenant-1
    """), encoding="utf-8")

    # No profiled port at all: must not inflate device_count
    (host_vars / "spine-01.yaml").write_text(textwrap.dedent("""\
        interfaces:
          swp1:
            description: to leaf-01
            ip: 10.0.0.0/31
    """), encoding="utf-8")


class FabricPortStateTests(unittest.TestCase):
    def test_only_profiled_ports_are_returned(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            build_inventory(root)
            data = run_action(root)

        self.assertTrue(data["success"])
        ports = {(row[0], row[1]): row for row in data["ports"]}
        self.assertEqual(
            set(ports),
            {
                ("leaf-01", "swp1"),
                ("leaf-01", "swp4s0"),
                ("leaf-01", "bond_1_1_1"),
                ("leaf-02", "swp1"),
            },
        )
        # device_count only counts devices that actually carry a profile
        self.assertEqual(data["device_count"], 2)
        self.assertEqual(
            ports[("leaf-01", "swp1")],
            ["leaf-01", "swp1", "A01-37-S1-DGX-01:C18", "Tenant-4"],
        )
        self.assertNotIn("parse_errors", data)

    def test_profile_tables_resolve_vlan_and_vrf(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            build_inventory(root)
            data = run_action(root)

        self.assertEqual(data["port_profiles"]["Tenant-4"]["access_vlan"], 70)
        # profileInfo() looks up vp.vlans[access_vlan].vrf, so the raw map must
        # survive the round trip.
        svi70 = data["vlan_profiles"]["SVI-70"]
        self.assertEqual(svi70["vrf"], "vpn60070")
        self.assertEqual(svi70["vlans"]["70"]["vrf"], "vpn60070")
        self.assertEqual(
            data["vlan_profiles"]["SVI-30"]["description"], "tenant one"
        )

    def test_unreadable_host_vars_is_reported_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            root = Path(temporary)
            build_inventory(root)
            (root / "inventory" / "host_vars" / "leaf-03.yaml").write_text(
                "interfaces: [unbalanced\n", encoding="utf-8"
            )
            data = run_action(root)

        self.assertTrue(data["success"])
        self.assertIn("leaf-03.yaml", data["parse_errors"])
        self.assertIn("leaf-03.yaml", data["warning"])
        # The healthy devices still come back
        self.assertEqual(len(data["ports"]), 4)

    def test_missing_inventory_returns_empty_success(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            data = run_action(Path(temporary))

        self.assertTrue(data["success"])
        self.assertEqual(data["ports"], [])
        self.assertEqual(data["device_count"], 0)
        self.assertEqual(data["port_profiles"], {})
        self.assertEqual(data["vlan_profiles"], {})

    def test_action_is_dispatched(self) -> None:
        self.assertIn('"get-fabric-port-state")\n        get_fabric_port_state', FABRIC_API)


if __name__ == "__main__":
    unittest.main()
