#!/usr/bin/env python3
"""Fabric Exit edit dialog: moving an external peer to another port.

The dialog (html/fabric-exit.html) posts the selected swpX.VLAN as "interface"
and the saved one as "original_interface". update-external-peer must then drop
the previous subinterface in the same write; otherwise the old swpX.VLAN stays
in host_vars with the same IP in the same VRF.

The action's Python is taken verbatim from html/fabric-api.sh, through the
harness of test_fabric_api_interface_edit.py.
"""

from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from ruamel.yaml import YAML

from test_fabric_api_interface_edit import UPDATE_EXTERNAL_PEER_BODY, run_action


HOST_VARS = """\
    vrfs:
      RED:
        bgp:
          bgp_profile: BORDER
    interfaces:
      swp1:
        description: fw
        subinterfaces:
          {key}:
            ip: 192.0.2.1/29
            vlan: 1002
            vrf: RED
          2000:
            ip: 198.51.100.3/31
            vlan: 2000
            vrf: RED
      swp10:
        description: spare
"""
OTHER_SUBIF = {"ip": "198.51.100.3/31", "vlan": 2000, "vrf": "RED"}
MOVED_SUBIF = {"ip": "192.0.2.1/29", "vlan": 1002, "vrf": "RED"}


class ExternalPeerInterfaceMoveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.host_file = self.ansible_dir / "inventory" / "host_vars" / "border-01.yaml"
        self.host_file.parent.mkdir(parents=True)
        group_all = self.ansible_dir / "inventory" / "group_vars" / "all"
        group_all.mkdir(parents=True)
        (group_all / "bgp_profiles.yaml").write_text(textwrap.dedent("""\
            bgp_profiles:
              BORDER:
                peer_groups:
                  External:
                    fabric_exit: true
                    peers:
                      192.0.2.2: {}
        """))

    def _save(self, key, interface, original_interface):
        self.host_file.write_text(textwrap.dedent(HOST_VARS.format(key=key)))
        # The fields savePeerEdit() posts
        result = run_action(UPDATE_EXTERNAL_PEER_BODY, {
            "device": "border-01",
            "vrf": "RED",
            "original_peer": "192.0.2.2",
            "interface": interface,
            "original_interface": original_interface,
            "local_ip": "192.0.2.1/29",
            "remote_peer": "192.0.2.2",
            "weight": None,
            "policy_name": None,
            "policy_direction": None,
            "soft_reconfiguration": False,
            "bfd_enabled": False,
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        with open(self.host_file) as f:
            return YAML().load(f)["interfaces"]

    @staticmethod
    def _subifs(port):
        return {key: dict(cfg) for key, cfg in (port.get("subinterfaces") or {}).items()}

    def test_move_drops_the_previous_subinterface(self):
        interfaces = self._save("1002", "swp10.1002", "swp1.1002")
        # Only the peer's VLAN left swp1; its other link and the port itself stay
        self.assertEqual(self._subifs(interfaces["swp1"]), {2000: OTHER_SUBIF})
        self.assertEqual(interfaces["swp1"]["description"], "fw")
        # Same ip (prefix kept), vlan and vrf on the new port
        self.assertEqual(self._subifs(interfaces["swp10"]), {1002: MOVED_SUBIF})
        self.assertEqual(interfaces["swp10"]["description"], "spare")

    def test_move_drops_a_previous_subinterface_with_a_quoted_key(self):
        interfaces = self._save("'1002'", "swp10.1002", "swp1.1002")
        self.assertEqual(self._subifs(interfaces["swp1"]), {2000: OTHER_SUBIF})
        self.assertEqual(self._subifs(interfaces["swp10"]), {1002: MOVED_SUBIF})

    def test_unchanged_interface_removes_nothing(self):
        interfaces = self._save("1002", "swp1.1002", "swp1.1002")
        self.assertEqual(self._subifs(interfaces["swp1"]), {1002: MOVED_SUBIF, 2000: OTHER_SUBIF})
        self.assertEqual(self._subifs(interfaces["swp10"]), {})


if __name__ == "__main__":
    unittest.main()
