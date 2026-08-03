#!/usr/bin/env python3
"""Tests for the Ask-AI read-only command policy."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

from ai_command_policy import validate_ai_readonly_command  # noqa: E402


class ReadOnlyPolicyTest(unittest.TestCase):
    def assert_allowed(self, command):
        ok, reason = validate_ai_readonly_command(command)
        self.assertTrue(ok, "%r should be allowed (%s)" % (command, reason))

    def assert_rejected(self, command):
        ok, _reason = validate_ai_readonly_command(command)
        self.assertFalse(ok, "%r should be rejected" % command)

    def test_existing_diagnostics_stay_allowed(self):
        for command in (
            "nv show interface",
            "sudo vtysh -c 'show bgp l2vpn evpn summary'",
            "ethtool -m swp1",
            "ethtool -S swp1",
            "ip -6 route show",
            "ip link show swp1",
            "cat /proc/net/bonding/bond0",
            "sudo l1-show swp1",
        ):
            self.assert_allowed(command)

    def test_kb_runbook_readonly_forms_are_allowed(self):
        # The KB runbooks instruct these exact read-only forms (ber-fec and
        # mtu-fabric sections); the policy must accept what the KB teaches.
        self.assert_allowed("ethtool --show-fec swp1")
        self.assert_allowed("sudo ethtool --show-fec swp1s2")
        self.assert_allowed("ip -d link show swp1")
        self.assert_allowed("cat /sys/class/net/swp1/mtu")
        self.assert_allowed("cat /sys/class/net/swp1s0/mtu")

    def test_new_forms_stay_tight(self):
        self.assert_rejected("ethtool --show-fec")
        self.assert_rejected("ethtool --show-fec -w")
        self.assert_rejected("ethtool --show-fec swp1 swp2")
        self.assert_rejected("ip -d")
        self.assert_rejected("ip -d route flush 10.0.0.0/8")
        self.assert_rejected("cat /sys/class/net/../mtu")
        self.assert_rejected("cat /sys/class/net/.hidden/mtu")
        self.assert_rejected("cat /sys/class/net/swp1/address")
        self.assert_rejected("cat /sys/class/net/swp1/mtu /etc/passwd")
        self.assert_rejected("cat /etc/passwd")

    def test_ping_remains_rejected(self):
        # The mtu-fabric runbook presents ping as an operator-manual step;
        # the model-facing policy never runs it.
        self.assert_rejected("ping -M do -s 8972 10.0.0.1")
        self.assert_rejected("ping 10.0.0.1")

    def test_shell_composition_is_rejected(self):
        self.assert_rejected("ethtool --show-fec swp1; reboot")
        self.assert_rejected("cat /sys/class/net/swp1/mtu > /tmp/x")


if __name__ == "__main__":
    unittest.main()
