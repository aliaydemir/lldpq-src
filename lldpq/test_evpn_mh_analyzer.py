#!/usr/bin/env python3
"""Focused EVPN-MH correlation and HTML contract regressions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from process_evpn_mh_data import (
    correlate_snapshots,
    parse_snapshot,
    render_report,
)
from collection_bundle import SECTIONS


ROOT = Path(__file__).resolve().parents[1]


def snapshot(host, *, df, remote=True, oper=True, bypass=False):
    esi = "03:44:38:39:ff:06:08:00:00:24"
    bond = "bond_1_14_18"
    member = "swp18s1"
    flags = {
        "local": "on",
        "ready-for-bgp": "on",
        "bridge-port": "on",
    }
    if df:
        flags["designated-forward"] = "on"
    else:
        flags["non-designated-forward"] = "on"
    if remote:
        flags["remote"] = "on"
    if oper:
        flags["oper-up"] = "on"
    partner_state = (
        ["active"] if bypass
        else ["active", "aggregating", "in_sync", "collecting", "distributing"]
    )
    return {
        "errors": [],
        "esi": {
            esi: {
                "df-preference": 50000 if host.endswith("06") else 40000,
                "flags": flags,
                "local-interface": bond,
                "mac-count": 0 if bypass else 1,
                "vni-count": 1,
                "remote-vtep": {"172.31.2.16": {}} if remote else {},
            }
        },
        "bgp_esi": {
            esi: {
                "inconsistent-vni-count": 0,
                "originator-ip": "172.31.2.14",
                "rd": "172.31.2.14:55",
            }
        },
        "bgp_es_evi": {
            esi: [{"vni": 200215, "flags": "LR", "vteps": "172.31.2.16(V)"}]
        },
        "interfaces": {
            bond: {
                "description": "GB300-1-14-Tray-18",
                "type": "bond",
                "bond": {
                    "mode": "lacp",
                    "lacp-bypass": "enabled",
                    "member": {member: {}},
                },
                "evpn": {
                    "multihoming": {
                        "segment": {
                            "state": "enabled",
                            "local-id": 36,
                            "mac-address": "44:38:39:ff:06:08",
                            "df-preference": 50000 if host.endswith("06") else 40000,
                        }
                    }
                },
                "bridge": {"domain": {"br_default": {"access": 215}}},
            }
        },
        "links": [
            {
                "ifname": bond,
                "operstate": "UP" if oper else "DOWN",
                "ifalias": "GB300-1-14-Tray-18",
                "linkinfo": {
                    "info_kind": "bond",
                    "info_data": {
                        "ad_info": {
                            "actor_key": 33,
                            "partner_key": 1 if bypass else 33,
                            "partner_mac": (
                                "00:00:00:00:00:00"
                                if bypass else "d2:5d:45:3f:1a:31"
                            ),
                        }
                    },
                },
            },
            {
                "ifname": member,
                "master": bond,
                "linkinfo": {
                    "info_slave_kind": "bond",
                    "info_slave_data": {
                        "state": "ACTIVE",
                        "mii_status": "UP",
                        "ad_actor_oper_port_state_str": [
                            "active", "aggregating", "in_sync",
                            "collecting", "distributing",
                        ],
                        "ad_partner_oper_port_state_str": partner_state,
                    },
                },
            },
        ],
        "bypass": {(bond, member): 1 if bypass else 0},
    }


class EvpnMhAnalyzerTests(unittest.TestCase):
    def test_bypass_dual_df_is_not_a_conflict(self):
        rows = correlate_snapshots({
            "tan-leaf-06": snapshot("tan-leaf-06", df=True, remote=False, bypass=True),
            "tan-leaf-08": snapshot("tan-leaf-08", df=True, remote=False, bypass=True),
        })
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "bypass")
        self.assertTrue(rows[0]["bypass_active"])
        self.assertIn("LACP bypass active", rows[0]["reason"])

    def test_active_remote_dual_df_without_bypass_is_critical(self):
        rows = correlate_snapshots({
            "tan-leaf-06": snapshot("tan-leaf-06", df=True),
            "tan-leaf-08": snapshot("tan-leaf-08", df=True),
        })
        self.assertEqual(rows[0]["status"], "critical")
        self.assertIn("both active remote PEs are DF", rows[0]["reason"])

    def test_normal_pair_is_healthy(self):
        rows = correlate_snapshots({
            "tan-leaf-06": snapshot("tan-leaf-06", df=True),
            "tan-leaf-08": snapshot("tan-leaf-08", df=False),
        })
        self.assertEqual(rows[0]["status"], "healthy")
        self.assertEqual(len(rows[0]["attachments"]), 2)

    def test_runtime_member_and_ifalias_fallback(self):
        left = snapshot("tan-leaf-06", df=True)
        right = snapshot("tan-leaf-08", df=False)
        left["interfaces"] = {}
        right["interfaces"] = {}
        rows = correlate_snapshots({"tan-leaf-06": left, "tan-leaf-08": right})
        self.assertEqual(rows[0]["status"], "healthy")
        self.assertEqual(rows[0]["attachments"][0]["members"], ["swp18s1"])
        self.assertEqual(
            rows[0]["attachments"][0]["description"], "GB300-1-14-Tray-18"
        )

    def test_parse_snapshot_contract(self):
        content = """__LLDPQ_EVPN_MH_COLLECTION_UTC__:2026-07-10T01:02:03Z
=== EVPN MH ESI JSON ===
{"03:44:38:39:ff:06:08:00:00:24":{"local-interface":"bond1"}}
__LLDPQ_EVPN_MH_COVERAGE__:ESI:OK
__LLDPQ_EVPN_MH_LOCAL_ESI__:1
=== EVPN MH BYPASS STATE ===
bond1|swp1|1
__LLDPQ_EVPN_MH_COVERAGE__:BYPASS:OK
"""
        parsed = parse_snapshot(content)
        self.assertEqual(parsed["local_count"], 1)
        self.assertEqual(parsed["coverage"]["ESI"], "OK")
        self.assertEqual(parsed["bypass"][("bond1", "swp1")], 1)

    def test_device_first_html_and_shared_scripts(self):
        rows = correlate_snapshots({
            "tan-leaf-06": snapshot("tan-leaf-06", df=True),
            "tan-leaf-08": snapshot("tan-leaf-08", df=False),
        })
        page = render_report(
            rows,
            coverage_status="current",
            coverage_failures={},
            generated_at=datetime.now(timezone.utc),
        )
        self.assertLess(page.index(">Device<span"), page.index(">Peer Device<span"))
        self.assertIn('id="deviceSearch"', page)
        self.assertIn('id="run-analysis"', page)
        self.assertIn("/p2p-alias.js", page)
        self.assertIn("/css/analysis-guard.js", page)
        self.assertIn('data-analysis-summary="evpn-mh"', page)
        self.assertIn('data-critical-es="0"', page)
        self.assertIn('data-warning-es="0"', page)
        self.assertIn('data-bypass-issue-es="0"', page)
        self.assertIn('id="evpn-mh-table"', page)
        self.assertEqual(page.count('class="sortable"'), 10)
        self.assertIn("function sortTable(column,header)", page)


class EvpnMhIntegrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")
        cls.trigger = (ROOT / "html/trigger-monitor.sh").read_text(encoding="utf-8")
        cls.daemon = (ROOT / "bin/lldpq-trigger").read_text(encoding="utf-8")
        cls.index = (ROOT / "html/index.html").read_text(encoding="utf-8")
        cls.guard = (ROOT / "html/css/analysis-guard.js").read_text(encoding="utf-8")
        cls.lifecycle = (ROOT / "html/lifecycle-scope.js").read_text(encoding="utf-8")

    def test_collection_bundle_and_bounded_sources(self):
        self.assertIn("EVPN_MH_DATA", SECTIONS)
        self.assertLess(SECTIONS.index("EVPN_MH_DATA"), SECTIONS.index("DUP_DATA"))
        for command in (
            "nv show evpn multihoming -o json",
            "nv show evpn multihoming esi -o json",
            "nv show evpn multihoming bgp-info esi -o json",
            'sudo vtysh -c "show evpn es-evi"',
            'sudo vtysh -c "show bgp l2vpn evpn es-evi"',
            "nv show interface --applied -o json",
            "ip -d -j link show",
        ):
            self.assertIn(f"_lldpq_run_bounded {command}", self.monitor)

    def test_scope_round_trip_contract(self):
        self.assertIn("evpn-mh) SCOPE_CODE=9", self.trigger)
        self.assertIn("9) MONITOR_REQUEST_SCOPE=evpn-mh", self.daemon)
        self.assertIn("all|bgp|evpn-mh|duplicate", self.daemon)
        self.assertIn("all|bgp|evpn-mh|duplicate", self.monitor)
        self.assertIn("'evpn-mh': true", self.guard)
        self.assertIn("'evpn-mh-analysis.html': { scope: 'evpn-mh'", self.guard)

    def test_menu_order_and_lifecycle_contract(self):
        bgp = self.index.index("/monitor-results/bgp-analysis.html")
        evpn_mh = self.index.index("/monitor-results/evpn-mh-analysis.html")
        duplicate = self.index.index("/monitor-results/duplicate-analysis.html")
        self.assertLess(bgp, evpn_mh)
        self.assertLess(evpn_mh, duplicate)
        self.assertIn("/evpn-mh-analysis.html", self.lifecycle)
        self.assertIn("function updateEvpnMh()", self.lifecycle)
        self.assertIn("#evpn-mh-table", self.lifecycle)


if __name__ == "__main__":
    unittest.main()
