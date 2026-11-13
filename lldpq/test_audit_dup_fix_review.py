#!/usr/bin/env python3
"""Audit review follow-up: the duplicate analyzer's edge / transit rule.

The review of the FDB edge-port fix found four things, each covered here:

  * an uplink into a network that does not speak LLDP (or advertises a port
    name the analyzer does not know) was still an edge port, so the gateway MAC
    and each switch's hosts as seen through the other's uplink stayed CRITICAL.
    Fan-out closes it: a port whose MACs another monitored switch holds on two
    different ports faces a segment;
  * DAD and mobility rows lost "Local On" when the owning port was a transit
    port, and showed the owning switch as the conflicting VTEP;
  * duplicate-IP rows listed trunk ports as owners, and took a gateway SVI MAC
    learned by the L2 switch below it for an endpoint;
  * the WARNING class "seen on several switches" was counted nowhere.

Every test drives the real analyzer end to end (parse_all + export_html) over
collector-format files. All names and addresses are invented.
"""

import json
import os
import re
import time
import unittest
from datetime import datetime, timedelta, timezone

from duplicate_analyzer import (
    FDB_SEGMENT_MIN_MACS,
    LLDP_EVIDENCE_MAX_AGE_SEC,
    DuplicateAnalyzer,
    _is_switch_port,
)

import test_audit_dup_fdb_edge_ports as base

VLAN = base.VLAN
GATEWAY = base.GATEWAY
mac = base.mac
fdb = base.fdb
link = base.link

DUP = "0c:42:a1:de:ad:01"


def neigh(address, lladdr, state="REACHABLE", vlan=VLAN):
    return "%s dev vlan%s lladdr %s %s" % (address, vlan, lladdr, state)


def cells(row):
    return re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)


class ReviewFixture(base.FabricFixture):
    """The base fixture plus neighbour tables, VTEP addresses, FRR duplicate
    ARP rows and per-switch collection times."""

    def setUp(self):
        super().setUp()
        self.neighbors = {}       # switch -> `ip -4 neigh show` lines
        self.vteps = {}           # switch -> its own VTEP address
        self.arp_sections = {}    # switch -> FRR duplicate ARP section lines
        self.collected = {}       # switch -> collection time (aware datetime)

    def _write_inputs(self):
        super()._write_inputs()
        for name in self.switches:
            path = self.dup_dir / (name + "_dup.txt")
            text = path.read_text()
            if name in self.vteps:
                text = text.replace(
                    "=== DUP SELF ===\n",
                    "=== DUP SELF ===\n%s\n" % self.vteps[name])
            if name in self.arp_sections:
                text = text.replace(
                    "=== DUP ARP ===\n",
                    "=== DUP ARP ===\n%s\n" % "\n".join(self.arp_sections[name]))
            if name in self.collected:
                text = re.sub(
                    r"__LLDPQ_DUP_COLLECTION_UTC__:\S+",
                    "__LLDPQ_DUP_COLLECTION_UTC__:"
                    + self.collected[name].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    text)
            path.write_text(text)
            lines = self.neighbors.get(name, [])
            (self.dup_dir / (name + "_neigh.txt")).write_text(
                "".join(line + "\n" for line in lines))

    def analyze_with_stale(self, stale):
        """Like analyze(), for a fabric where some collections are old."""
        for name in stale:
            self.collected[name] = datetime.now(timezone.utc) - timedelta(hours=3)
        self._write_inputs()
        analyzer = DuplicateAnalyzer(str(self.root / "monitor-results"))
        analyzer.parse_all()
        self.assertEqual(
            set(self.switches) - set(stale), analyzer.coverage["fdb_current"])
        return analyzer

    def ip_rows(self, analyzer):
        table = self.report(analyzer).split('id="ipt"', 1)[1].split("</table>", 1)[0]
        body = table.split("<tbody>", 1)[1]
        return [row for row in re.findall(r"<tr[^>]*>.*?</tr>", body, re.S)
                if "class='empty" not in row]

    def exported(self, finding_type):
        export = self.root / "monitor-results" / "export" / "duplicate.json"
        rows = json.loads(export.read_text(encoding="utf-8"))["rows"]
        return [row for row in rows if row["finding_type"] == finding_type]

    def one_ip_row(self, analyzer):
        (row,) = self.ip_rows(analyzer)
        (exported,) = self.exported("ip")
        return row, exported


class FanOutTests(ReviewFixture):
    """Two monitored switches, each with one uplink into the same VLAN of an
    unmonitored network; the sidecar is current and covers both switches."""

    def build(self):
        self.switch("oob-sw-01", fdb(mac(1), "swp7"),
                    fdb(mac(2), "swp49"), fdb(GATEWAY, "swp49"))
        self.switch("oob-sw-02", fdb(mac(2), "swp9"),
                    fdb(mac(1), "swp49"), fdb(GATEWAY, "swp49"))

    def covered(self, uplinks=None):
        neighbors = {
            "oob-sw-01": {"swp7": link("srv-a", "eno1")},
            "oob-sw-02": {"swp9": link("srv-b", "eno1")},
        }
        for name, port in (uplinks or {}).items():
            neighbors[name]["swp49"] = link("upstream-" + name[-2:], port)
        return self.lldp(neighbors)

    def test_lldp_silent_uplinks_are_not_edge_ports(self):
        self.build()
        self.covered()

        analyzer = self.analyze()

        # The sidecar is current and covers both switches, so before the
        # fan-out test both uplinks were proven "edge" ports.
        self.assertEqual("ok", analyzer.lldp_state)
        self.assertEqual({"oob-sw-01", "oob-sw-02"}, analyzer.lldp_hosts)
        self.assertEqual(
            {("oob-sw-01", "swp49", VLAN), ("oob-sw-02", "swp49", VLAN)},
            analyzer.fdb_fanout_ports)
        self.assertEqual("transit", analyzer._fdb_port_role("oob-sw-01", "swp49", VLAN))
        self.assertEqual("edge", analyzer._fdb_port_role("oob-sw-01", "swp7", VLAN))
        self.assert_no_mac_finding(analyzer)

    def test_upstream_port_names_outside_the_known_list(self):
        # What the LLDP parser yields for vendors whose port names say nothing.
        for first, second in (
                ("port1", "port2"),                              # FortiGate
                ("ether1", "ether2"),                            # MikroTik
                ("24", "23"),                                    # bare numbers
                ("TenGigabitEthernet", "TenGigabitEthernet"),    # cut at the space
                ("to-oob-sw-01", "to-oob-sw-02"),                # a port description
        ):
            with self.subTest(upstream_ports=(first, second)):
                self.build()
                self.covered({"oob-sw-01": first, "oob-sw-02": second})

                self.assert_no_mac_finding(self.analyze())

    def test_several_vlans_each_below_the_segment_bound(self):
        # 18 MACs behind each uplink, six per VLAN: the count never sees it.
        rows = {"oob-sw-01": [], "oob-sw-02": []}
        for index, vlan in enumerate(("20", "30", "40")):
            first, second = mac(1 + index), mac(101 + index)
            beyond = [GATEWAY] + [mac(200 + index * 10 + n) for n in range(4)]
            rows["oob-sw-01"] += [fdb(first, "swp7", vlan), fdb(second, "swp49", vlan)]
            rows["oob-sw-02"] += [fdb(second, "swp9", vlan), fdb(first, "swp49", vlan)]
            for name in rows:
                rows[name] += [fdb(address, "swp49", vlan) for address in beyond]
        for name, lines in rows.items():
            self.switch(name, *lines)
        self.covered()

        analyzer = self.analyze()

        for vlan in ("20", "30", "40"):
            self.assertEqual(6, analyzer.fdb_port_macs[("oob-sw-01", "swp49", vlan)])
        self.assertLess(6, FDB_SEGMENT_MIN_MACS)
        self.assert_no_mac_finding(analyzer)

    def test_real_duplicate_beside_the_uplinks_is_still_confirmed(self):
        # One MAC on a host port of each switch: neither port fans out.
        self.build()
        self.switches["oob-sw-01"].append(fdb(DUP, "swp8"))
        self.switches["oob-sw-02"].append(fdb(DUP, "swp10"))
        self.covered()

        analyzer = self.analyze()

        self.assertEqual([DUP], [rec["mac"] for rec in analyzer.mac_dups.values()])
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual("CRITICAL", rec["severity"])
        self.assertEqual({"oob-sw-01": "swp8", "oob-sw-02": "swp10"}, rec["local"])
        self.assertEqual(1, analyzer.summary()["confirmed_mac_total"])

    def test_hypervisor_port_seen_behind_one_port_is_still_an_attachment_point(self):
        fabric = {
            "leaf-01": {"swp51": link("spine-01", "swp1")},
            "leaf-02": {"swp51": link("spine-01", "swp2")},
        }
        guests = [mac(index) for index in range(1, 6)]
        with self.subTest("the other switch holds only the duplicated MAC"):
            self.switch("leaf-01", fdb(DUP, "swp5"),
                        *[fdb(address, "swp5") for address in guests])
            self.switch("leaf-02", fdb(DUP, "swp9"))
            self.lldp(fabric)

            analyzer = self.analyze()

            self.assertEqual(set(), analyzer.fdb_fanout_ports)
            rec = analyzer.mac_dups[(VLAN, DUP)]
            self.assertTrue(rec["confirmed_conflict"])
            self.assertEqual({"leaf-01": "swp5", "leaf-02": "swp9"}, rec["local"])
            self.assertEqual(1, len(analyzer.mac_dups))
        with self.subTest("a cloned hypervisor: every MAC behind one port"):
            self.switch("leaf-01", *[fdb(address, "swp5") for address in guests])
            self.switch("leaf-02", *[fdb(address, "swp9") for address in guests])
            self.lldp(fabric)

            analyzer = self.analyze()

            self.assertEqual(set(), analyzer.fdb_fanout_ports)
            self.assertEqual(
                sorted(guests), sorted(rec["mac"] for rec in analyzer.mac_dups.values()))
            for rec in analyzer.mac_dups.values():
                self.assertTrue(rec["confirmed_conflict"], rec["mac"])
                self.assertEqual({"leaf-01": "swp5", "leaf-02": "swp9"}, rec["local"])
            self.assertEqual(len(guests), analyzer.summary()["confirmed_mac_total"])

    def test_multi_mac_port_whose_macs_fan_out_is_a_transit_port(self):
        # The declared cost of the rule. An L2 tier: the guests of leaf-01's
        # port reach leaf-02 over its trunk, one of them also sits on a
        # leaf-02 host port. Two ports of leaf-02 hold MACs of the one
        # leaf-01 port, so that port is not taken for an attachment point.
        guests = [mac(index) for index in range(1, 4)]
        self.switch("leaf-01", fdb(DUP, "swp5"),
                    *[fdb(address, "swp5") for address in guests])
        self.switch("leaf-02", fdb(DUP, "swp9"),
                    *[fdb(address, "swp49") for address in guests])
        self.switch("agg-01", fdb(DUP, "swp2"),
                    *[fdb(address, "swp1") for address in guests])
        self.lldp({
            "leaf-01": {"swp49": link("agg-01", "swp1")},
            "leaf-02": {"swp49": link("agg-01", "swp2")},
            "agg-01": {"swp1": link("leaf-01", "swp49"),
                       "swp2": link("leaf-02", "swp49")},
        })

        analyzer = self.analyze()

        self.assertIn(("leaf-01", "swp5", VLAN), analyzer.fdb_fanout_ports)
        self.assert_no_mac_finding(analyzer)

    def test_fan_out_is_judged_per_vlan(self):
        # The uplinks fan out in VLAN 20. In VLAN 30 the same uplink holds one
        # MAC, which says nothing either way: without LLDP data it is listed
        # as seen on two switches, exactly as the count test leaves it.
        self.build()
        self.switches["oob-sw-01"].append(fdb(mac(200), "swp49", vlan="30"))
        self.switches["oob-sw-02"].append(fdb(mac(200), "swp9", vlan="30"))

        analyzer = self.analyze()

        self.assertEqual(
            {("oob-sw-01", "swp49", VLAN), ("oob-sw-02", "swp49", VLAN)},
            analyzer.fdb_fanout_ports)
        self.assert_seen_not_confirmed(analyzer, [mac(200)])
        self.assertEqual({"30"}, {rec["vlan"] for rec in analyzer.mac_dups.values()})

    def test_switch_with_a_stale_collection_is_not_a_fan_out_witness(self):
        # sw-03 holds the two MACs of sw-01's port on two ports, but its FDB
        # is three hours old and proves nothing about this collection.
        other = mac(1)
        self.switch("oob-sw-01", fdb(DUP, "swp7"), fdb(other, "swp7"))
        self.switch("oob-sw-02", fdb(DUP, "swp9"))
        self.switch("oob-sw-03", fdb(DUP, "swp1"), fdb(other, "swp2"))
        self.lldp({
            "oob-sw-01": {"eth0": link("mgmt-01", "swp1")},
            "oob-sw-02": {"eth0": link("mgmt-01", "swp2")},
            "oob-sw-03": {"eth0": link("mgmt-01", "swp3")},
        })

        analyzer = self.analyze_with_stale(["oob-sw-03"])

        self.assertEqual(set(), analyzer.fdb_fanout_ports)
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual({"oob-sw-01": "swp7", "oob-sw-02": "swp9"}, rec["local"])

    def test_one_mac_listed_on_two_ports_does_not_make_a_fan_out(self):
        # leaf-01 lists the duplicated MAC twice, on its host port and on its
        # uplink, and the other MAC of leaf-02's port on the uplink only.
        # Both MACs share the uplink, so leaf-02's port does not fan out.
        other = mac(1)
        for rows in ((fdb(DUP, "swp7"), fdb(DUP, "swp49")),
                     (fdb(DUP, "swp49"), fdb(DUP, "swp7"))):
            with self.subTest(order=[row.split()[2] for row in rows]):
                self.switch("leaf-01", *rows, fdb(other, "swp49"))
                self.switch("leaf-02", fdb(DUP, "swp9"), fdb(other, "swp9"))
                self.switch("agg-01", fdb(DUP, "swp2"), fdb(other, "swp2"))
                self.lldp({
                    "leaf-01": {"swp49": link("agg-01", "swp1")},
                    "leaf-02": {"swp49": link("agg-01", "swp2")},
                    "agg-01": {"swp1": link("leaf-01", "swp49"),
                               "swp2": link("leaf-02", "swp49")},
                })

                analyzer = self.analyze()

                self.assertNotIn(("leaf-02", "swp9", VLAN), analyzer.fdb_fanout_ports)
                self.assertEqual([DUP], [rec["mac"] for rec in analyzer.mac_dups.values()])
                rec = analyzer.mac_dups[(VLAN, DUP)]
                self.assertTrue(rec["confirmed_conflict"])
                self.assertEqual({"leaf-01": "swp7", "leaf-02": "swp9"}, rec["local"])

    def test_thresholds_dialog_states_fan_out_and_its_limits(self):
        self.build()
        self.covered()

        report = self.report(self.analyze())

        self.assertIn("another monitored switch holds", report)
        self.assertIn("<code>port1</code>", report)
        self.assertIn("a single MAC of the VLAN", report)
        self.assertIn("upstream of two chained switches", report)
        self.assertIn("(bonds excepted)", report)


class LocalOnTests(ReviewFixture):
    """A row that exists for another reason (FRR DAD, mobility) says where the
    MAC is LOCAL, whatever the role of the port."""

    FABRIC = {
        "leaf-01": {"swp51": link("spine-01", "swp1")},
        "leaf-02": {"swp51": link("spine-01", "swp2")},
        "leaf-03": {"swp51": link("spine-01", "swp3")},
    }

    def fabric(self, extra=None):
        neighbors = {name: dict(ports) for name, ports in self.FABRIC.items()}
        for name, ports in (extra or {}).items():
            neighbors.setdefault(name, {}).update(ports)
        self.vteps = {"leaf-01": "10.0.0.1", "leaf-02": "10.0.0.2",
                      "leaf-03": "10.0.0.3"}
        return self.lldp(neighbors)

    def flagged_remote_on_leaf_03(self, *vteps):
        # leaf-03 holds the FRR duplicate flag for a MAC behind other VTEPs.
        self.mac_sections["leaf-03"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            *["%s remote %s 5/4" % (DUP, vtep) for vtep in vteps],
        ]

    def dad_row(self, analyzer):
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])
        (row,) = self.mac_rows(analyzer)
        (exported,) = self.exported("mac")
        self.assertEqual("dad", exported["kind"])
        return cells(row), exported

    def test_dual_homed_bond_with_many_macs(self):
        guests = [mac(100 + index) for index in range(FDB_SEGMENT_MIN_MACS + 4)]
        for name in ("leaf-01", "leaf-02"):
            self.switch(name, fdb(DUP, "bond5"),
                        *[fdb(address, "bond5") for address in guests])
        self.switch("leaf-03", fdb(mac(1), "swp3"))
        self.flagged_remote_on_leaf_03("10.0.0.1", "10.0.0.2")
        self.fabric()

        analyzer = self.analyze()

        self.assertLessEqual(
            FDB_SEGMENT_MIN_MACS, analyzer.fdb_port_macs[("leaf-01", "bond5", VLAN)])
        row, exported = self.dad_row(analyzer)
        self.assertEqual("leaf-01 leaf-02", exported["hosts"])
        self.assertEqual("leaf-01:bond5 leaf-02:bond5", exported["local_ports"])
        self.assertIsNone(exported["vteps"])
        self.assertEqual("leaf-01:bond5<br>leaf-02:bond5", row[3])
        self.assertEqual("&mdash;", row[4])

    def test_single_homed_port_with_many_macs(self):
        guests = [mac(100 + index) for index in range(FDB_SEGMENT_MIN_MACS + 4)]
        self.switch("leaf-01", fdb(DUP, "swp5"),
                    *[fdb(address, "swp5") for address in guests])
        self.switch("leaf-02", fdb(mac(2), "swp8"))
        self.switch("leaf-03", fdb(mac(1), "swp3"))
        self.flagged_remote_on_leaf_03("10.0.0.1")
        self.fabric()

        analyzer = self.analyze()

        self.assertEqual("transit", analyzer._fdb_port_role("leaf-01", "swp5", VLAN))
        row, exported = self.dad_row(analyzer)
        self.assertEqual("leaf-01", exported["hosts"])
        self.assertEqual("leaf-01:swp5", exported["local_ports"])
        self.assertIsNone(exported["vteps"])
        self.assertEqual("leaf-01:swp5", row[3])
        self.assertEqual("&mdash;", row[4])

    def test_port_whose_lldp_neighbor_is_a_switch(self):
        self.switch("leaf-01", fdb(DUP, "swp10"), fdb(mac(3), "swp10"))
        self.switch("leaf-02", fdb(mac(2), "swp8"))
        self.switch("leaf-03", fdb(mac(1), "swp3"))
        self.flagged_remote_on_leaf_03("10.0.0.1")
        self.fabric({"leaf-01": {"swp10": link("access-sw", "Ethernet48")}})

        analyzer = self.analyze()

        self.assertEqual("transit", analyzer._fdb_port_role("leaf-01", "swp10", VLAN))
        row, exported = self.dad_row(analyzer)
        self.assertEqual("leaf-01", exported["hosts"])
        self.assertEqual("leaf-01:swp10", exported["local_ports"])
        self.assertIsNone(exported["vteps"])
        self.assertEqual("leaf-01:swp10", row[3])
        self.assertEqual("&mdash;", row[4])

    def test_switch_with_a_stale_collection_is_not_listed(self):
        # leaf-02's FDB also has the MAC, but its collection is three hours
        # old: only what this collection saw is listed.
        self.switch("leaf-01", fdb(DUP, "swp10"), fdb(mac(3), "swp10"))
        self.switch("leaf-02", fdb(DUP, "swp8"))
        self.switch("leaf-03", fdb(mac(1), "swp3"))
        self.flagged_remote_on_leaf_03("10.0.0.1")
        self.fabric({"leaf-01": {"swp10": link("access-sw", "Ethernet48")}})

        analyzer = self.analyze_with_stale(["leaf-02"])

        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual({"leaf-01": "swp10"}, rec["local"])

    def test_lag_to_an_access_switch_that_fans_out(self):
        # The leaf reaches an L2 access switch over a LAG. The bond is a
        # transit port by fan-out; the leaf is still where its VTEP has the MAC.
        self.switch("leaf-01", fdb(DUP, "bond1"), fdb(mac(3), "bond1"))
        self.switch("access-01", fdb(DUP, "swp5"), fdb(mac(3), "swp6"))
        self.switch("leaf-03", fdb(mac(1), "swp3"))
        self.flagged_remote_on_leaf_03("10.0.0.1")
        self.fabric({"access-01": {"eth0": link("mgmt-01", "swp9")}})

        analyzer = self.analyze()

        self.assertEqual("transit", analyzer._fdb_port_role("leaf-01", "bond1", VLAN))
        row, exported = self.dad_row(analyzer)
        self.assertEqual("access-01:swp5 leaf-01:bond1", exported["local_ports"])
        self.assertIsNone(exported["vteps"])
        self.assertEqual("&mdash;", row[4])

    def test_trunk_is_not_an_owner_of_a_confirmed_conflict_frr_also_flags(self):
        # The record exists before the FDB rule runs (FRR flags the MAC on
        # leaf-01), so the early port fill sees the trunk sighting too.
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp7"))
        self.switch("agg-01", fdb(DUP, "swp1"))
        self.mac_sections["leaf-01"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            "%s local active swp7 5/4" % DUP,
        ]
        self.lldp({
            "leaf-01": {"swp49": link("agg-01", "swp1")},
            "leaf-02": {"swp49": link("agg-01", "swp2")},
            "agg-01": {"swp1": link("leaf-01", "swp49"),
                       "swp2": link("leaf-02", "swp49")},
        })

        analyzer = self.analyze()

        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual({"leaf-01": "swp7", "leaf-02": "swp7"}, rec["local"])
        (row,) = self.mac_rows(analyzer)
        self.assertNotIn("agg-01", row)
        (exported,) = self.exported("mac")
        self.assertEqual("leaf-01:swp7 leaf-02:swp7", exported["local_ports"])

    def test_bond_is_exempt_from_the_segment_bound(self):
        # A confirmed conflict on two host ports; the same MAC also sits on a
        # dual-homed hypervisor bond with many guests. A bond is never counted
        # as an attachment point, and the count must not hide it either.
        guests = [mac(100 + index) for index in range(FDB_SEGMENT_MIN_MACS + 4)]
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        self.switch("leaf-03", fdb(DUP, "bond5"),
                    *[fdb(address, "bond5") for address in guests])
        self.fabric()

        analyzer = self.analyze()

        self.assertEqual("edge", analyzer._fdb_port_role("leaf-03", "bond5", VLAN))
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual(2, rec["physical_local_count"])
        self.assertEqual(
            {"leaf-01": "swp7", "leaf-02": "swp9", "leaf-03": "bond5"}, rec["local"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("Confirmed MAC conflict: LOCAL on edge ports of 2 switches", row)
        self.assertNotIn("not verified", row)

    def test_dad_flagged_mac_the_fdb_cannot_verify_stays_a_dad_row(self):
        # FRR flags the MAC and the FDB has it on swp ports of two switches,
        # with no LLDP data to show they are edge ports.
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        for name, port in (("leaf-01", "swp7"), ("leaf-02", "swp9")):
            self.mac_sections[name] = [
                "VNI %s #MACs (local and remote) 1" % VLAN,
                "%s local active %s 5/4" % (DUP, port),
            ]

        analyzer = self.analyze()

        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["fdb_unverified"])
        self.assertFalse(rec["confirmed_conflict"])
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])
        summary = analyzer.summary()
        self.assertEqual(1, summary["mac_dad_total"])
        self.assertEqual(0, summary["mac_fdb_observed_total"])
        self.assertEqual(0, summary["confirmed_mac_total"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("data-kind='dad'", row)
        note = cells(row)[6]
        self.assertIn("FRR MAC DAD flag", note)
        # The FDB sighting stays on the row, in the unconfirmed wording.
        self.assertIn("also seen on 2 switches (FDB only): edge ports not verified", note)
        self.assertNotIn("onfirmed", note)
        (exported,) = self.exported("mac")
        self.assertEqual("leaf-01:swp7 leaf-02:swp9", exported["local_ports"])


class DuplicateIpOwnerTests(ReviewFixture):
    """Owner (local) of a duplicate-IP row, and the endpoint / switch
    interface split, follow the same edge / transit rule as the MAC rows."""

    A, B = "0c:42:a1:00:00:0a", "0c:42:a1:00:00:0b"
    SVI_1, SVI_2 = "44:38:39:22:01:01", "44:38:39:22:01:02"
    HOST_IP, GATEWAY_IP = "10.0.20.5", "10.0.20.1"

    def access_under_aggregation(self):
        # Shape (a): both claimants on the access switch; the aggregation
        # switch sees them through its downlink.
        self.switch("oob-leaf-01", fdb(self.A, "swp7"), fdb(self.B, "swp8"))
        self.switch("oob-agg-01", fdb(self.A, "swp1"), fdb(self.B, "swp1"))
        self.neighbors = {
            "oob-leaf-01": [neigh(self.HOST_IP, self.A)],
            "oob-agg-01": [neigh(self.HOST_IP, self.B)],
        }

    def trunk(self):
        return self.lldp({
            "oob-leaf-01": {"swp49": link("oob-agg-01", "swp1")},
            "oob-agg-01": {"swp1": link("oob-leaf-01", "swp49")},
        })

    def test_aggregation_downlink_is_not_an_owner(self):
        for evidence in ("lldp", "fan-out"):
            with self.subTest(trunk_known_by=evidence):
                self.access_under_aggregation()
                if evidence == "lldp":
                    self.trunk()

                row, exported = self.one_ip_row(self.analyze())

                self.assertEqual("arp-observed", exported["kind"])
                self.assertEqual("WARNING", exported["severity"])
                self.assertEqual(2, exported["mac_count"])
                self.assertEqual("oob-leaf-01", exported["hosts"])
                self.assertEqual(
                    "oob-leaf-01:swp7 oob-leaf-01:swp8", exported["local_ports"])
                self.assertEqual("oob-leaf-01:swp7<br>oob-leaf-01:swp8", cells(row)[5])
                self.assertNotIn("oob-agg-01", row)

    def test_uplinks_into_an_unmonitored_network_are_not_owners(self):
        # Shape (b): one claimant on each switch, each seen through the
        # other's uplink. Two devices, two ports.
        for evidence in ("lldp", "fan-out"):
            with self.subTest(uplinks_known_by=evidence):
                self.switch("oob-sw-01", fdb(self.A, "swp7"), fdb(self.B, "swp49"),
                            fdb(GATEWAY, "swp49"))
                self.switch("oob-sw-02", fdb(self.B, "swp9"), fdb(self.A, "swp49"),
                            fdb(GATEWAY, "swp49"))
                self.neighbors = {
                    "oob-sw-01": [neigh(self.HOST_IP, self.A)],
                    "oob-sw-02": [neigh(self.HOST_IP, self.B)],
                }
                neighbors = {
                    "oob-sw-01": {"swp7": link("srv-a", "eno1")},
                    "oob-sw-02": {"swp9": link("srv-b", "eno1")},
                }
                if evidence == "lldp":
                    neighbors["oob-sw-01"]["swp49"] = link("core-a", "Ethernet1/1")
                    neighbors["oob-sw-02"]["swp49"] = link("core-b", "Ethernet1/2")
                self.lldp(neighbors)

                row, exported = self.one_ip_row(self.analyze())

                self.assertEqual("oob-sw-01 oob-sw-02", exported["hosts"])
                self.assertEqual("oob-sw-01:swp7 oob-sw-02:swp9", exported["local_ports"])
                self.assertEqual("oob-sw-01:swp7<br>oob-sw-02:swp9", cells(row)[5])

    def test_claimant_on_a_bond_makes_the_other_uplink_fan_out(self):
        # One claimant is a LAG-attached host. The other switch sees it and
        # the gateway through its uplink; sw-02 holds those two MACs on a
        # bond and on a swp port, which is fan-out all the same.
        self.switch("oob-sw-01", fdb(self.B, "swp7"), fdb(self.A, "swp49"),
                    fdb(GATEWAY, "swp49"))
        self.switch("oob-sw-02", fdb(self.A, "bond3"), fdb(self.B, "swp49"),
                    fdb(GATEWAY, "swp49"))
        self.neighbors = {
            "oob-sw-01": [neigh(self.HOST_IP, self.B)],
            "oob-sw-02": [neigh(self.HOST_IP, self.A)],
        }
        self.lldp({
            "oob-sw-01": {"swp7": link("srv-b", "eno1")},
            "oob-sw-02": {"eth0": link("mgmt-01", "swp2")},
        })

        analyzer = self.analyze()
        _row, exported = self.one_ip_row(analyzer)

        self.assertIn(("oob-sw-01", "swp49", VLAN), analyzer.fdb_fanout_ports)
        self.assertEqual("oob-sw-01:swp7 oob-sw-02:bond3", exported["local_ports"])

    def test_management_port_of_a_monitored_switch_is_an_endpoint(self):
        # An OOB access port whose LLDP neighbour is the eth0 of a monitored
        # leaf. eth0 is not a bridge port: nothing lies beyond it, the MAC
        # seen there is the device itself, and it is using a gateway address.
        eth0 = "44:38:39:00:aa:01"
        self.switch("oob-sw-01", fdb(eth0, "swp5"))
        self.switch("leaf-01")
        self.neighbors = {
            "oob-sw-01": [neigh(self.GATEWAY_IP, eth0)],
            "leaf-01": [neigh(self.GATEWAY_IP, self.SVI_1)],
        }
        self.lldp({
            "oob-sw-01": {"swp5": link("leaf-01", "eth0")},
            "leaf-01": {"eth0": link("oob-sw-01", "swp5")},
        })

        analyzer = self.analyze()
        _row, exported = self.one_ip_row(analyzer)

        self.assertEqual("edge", analyzer._fdb_port_role("oob-sw-01", "swp5", VLAN))
        self.assertTrue(exported["note"].startswith(
            "Confirmed - an endpoint is using a fabric gateway/SVI address"),
            exported["note"])
        self.assertEqual("oob-sw-01:swp5", exported["local_ports"])
        self.assertEqual(0, analyzer.summary()["ip_gateway_expected"])

    def gateway_pair_over_an_access_switch(self, leaf_rows, peer_state="REACHABLE",
                                           spell=str):
        # Two aggregation switches answer for the gateway address with their
        # own SVI MACs; the L2 access switch below learns them on its uplinks.
        # `spell` is how the collection spells the switch names; the sidecar
        # always has them in lower case.
        self.switch(spell("oob-leaf-01"), *leaf_rows, fdb(self.A, "swp7"))
        self.switch(spell("oob-agg-01"), fdb(self.A, "swp1"))
        self.switch(spell("oob-agg-02"), fdb(self.A, "swp1"))
        self.neighbors = {
            spell("oob-leaf-01"): [neigh(self.GATEWAY_IP, self.SVI_1)],
            spell("oob-agg-01"): [neigh(self.GATEWAY_IP, self.SVI_2, peer_state)],
            spell("oob-agg-02"): [neigh(self.GATEWAY_IP, self.SVI_1, peer_state)],
        }
        return self.lldp({
            "oob-leaf-01": {"swp49": link("oob-agg-01", "swp1"),
                            "swp50": link("oob-agg-02", "swp1")},
            "oob-agg-01": {"swp1": link("oob-leaf-01", "swp49")},
            "oob-agg-02": {"swp1": link("oob-leaf-01", "swp50")},
        })

    def assert_expected_gateway(self, analyzer):
        row, exported = self.one_ip_row(analyzer)
        self.assertEqual("gateway", exported["kind"])
        self.assertEqual("OK", exported["severity"])
        self.assertTrue(exported["note"].startswith(
            "Expected - anycast/VRR gateway address answered by switch "
            "interfaces on 2 switches"), exported["note"])
        self.assertIsNone(exported["hosts"])
        self.assertIsNone(exported["local_ports"])
        self.assertIn("expected-row", row)
        self.assertEqual("&mdash;", cells(row)[5])
        summary = analyzer.summary()
        self.assertEqual(1, summary["ip_gateway_expected"])
        self.assertEqual(0, summary["ip_endpoint_on_svi"])
        self.assertEqual(0, summary["ip_arp_observed"])

    def test_gateway_svi_macs_seen_through_uplinks_are_switch_interfaces(self):
        for state in ("REACHABLE", "STALE"):
            with self.subTest(peer_entry=state):
                self.gateway_pair_over_an_access_switch(
                    [fdb(self.SVI_1, "swp49"), fdb(self.SVI_2, "swp50")], state)

                self.assert_expected_gateway(self.analyze())

    def test_gateway_switch_names_spelled_in_another_case(self):
        self.gateway_pair_over_an_access_switch(
            [fdb(self.SVI_1, "swp49"), fdb(self.SVI_2, "swp50")], spell=str.upper)

        self.assert_expected_gateway(self.analyze())

    def test_gateway_uplinks_reported_by_the_far_end_only(self):
        # The access switch's own capture has its management neighbour only;
        # the aggregation switches report the two links.
        self.gateway_pair_over_an_access_switch(
            [fdb(self.SVI_1, "swp49"), fdb(self.SVI_2, "swp50")])
        self.lldp({
            "oob-leaf-01": {"eth0": link("mgmt-01", "swp3")},
            "oob-agg-01": {"swp1": link("OOB-LEAF-01", "swp49")},
            "oob-agg-02": {"swp1": link("OOB-LEAF-01", "swp50")},
        })

        self.assert_expected_gateway(self.analyze())

    def test_one_gateway_svi_mac_on_an_uplink_is_not_an_endpoint(self):
        # The access switch currently holds only one of the two SVI MACs.
        self.gateway_pair_over_an_access_switch([fdb(self.SVI_1, "swp49")])

        self.assert_expected_gateway(self.analyze())

    def test_mac_behind_an_unmonitored_switch_is_still_an_endpoint(self):
        # Two claimants beyond uplinks whose LLDP neighbours are switches
        # outside the inventory: nothing lists what is attached there, so
        # they are devices, not switch interfaces, and the row keeps the way
        # to them.
        for name, port in (("oob-sw-01", "Ethernet1/1"), ("oob-sw-02", "Ethernet1/2")):
            self.switch(name, fdb(self.A, "swp49"), fdb(self.B, "swp49"))
        self.neighbors = {
            "oob-sw-01": [neigh(self.HOST_IP, self.A)],
            "oob-sw-02": [neigh(self.HOST_IP, self.B)],
        }
        self.lldp({
            "oob-sw-01": {"swp49": link("core-a", "Ethernet1/1")},
            "oob-sw-02": {"swp49": link("core-b", "Ethernet1/2")},
        })

        analyzer = self.analyze()
        row, exported = self.one_ip_row(analyzer)

        self.assertEqual("transit", analyzer._fdb_port_role("oob-sw-01", "swp49", VLAN))
        self.assertEqual("arp-observed", exported["kind"])
        self.assertEqual("WARNING", exported["severity"])
        self.assertIn("2 distinct MACs claim it", exported["note"])
        self.assertEqual("oob-sw-01:swp49 oob-sw-02:swp49", exported["local_ports"])
        self.assertEqual(0, analyzer.summary()["ip_gateway_expected"])

    def test_link_to_a_switch_with_a_stale_collection_proves_nothing(self):
        # The same gateway pair, but the aggregation switches' collections are
        # three hours old: their FDBs cannot show the MACs are their own.
        self.gateway_pair_over_an_access_switch(
            [fdb(self.SVI_1, "swp49"), fdb(self.SVI_2, "swp50")])

        analyzer = self.analyze_with_stale(["oob-agg-01", "oob-agg-02"])
        _row, exported = self.one_ip_row(analyzer)

        self.assertEqual("arp-observed", exported["kind"])
        self.assertEqual("WARNING", exported["severity"])
        self.assertEqual(0, analyzer.summary()["ip_gateway_expected"])

    def test_endpoint_behind_a_segment_sized_port_still_squats_on_a_gateway(self):
        # The MAC count makes the port a transit port for the MAC rule; it
        # must not turn the device behind it into a switch interface.
        others = [mac(100 + index) for index in range(1, FDB_SEGMENT_MIN_MACS)]
        self.switch("oob-leaf-01", fdb(self.A, "swp9"),
                    *[fdb(address, "swp9") for address in others])
        self.switch("oob-agg-01")
        self.neighbors = {
            "oob-leaf-01": [neigh(self.GATEWAY_IP, self.A)],
            "oob-agg-01": [neigh(self.GATEWAY_IP, self.SVI_1)],
        }
        self.lldp({
            "oob-leaf-01": {"eth0": link("mgmt-01", "swp1")},
            "oob-agg-01": {"eth0": link("mgmt-01", "swp2")},
        })

        analyzer = self.analyze()
        _row, exported = self.one_ip_row(analyzer)

        self.assertEqual("transit", analyzer._fdb_port_role("oob-leaf-01", "swp9", VLAN))
        self.assertEqual("WARNING", exported["severity"])
        self.assertTrue(exported["note"].startswith(
            "Confirmed - an endpoint is using a fabric gateway/SVI address"),
            exported["note"])
        self.assertEqual("oob-leaf-01:swp9", exported["local_ports"])
        self.assertEqual(1, analyzer.summary()["ip_endpoint_on_svi"])

    def test_claimant_listed_on_its_host_port_and_on_the_uplink(self):
        # The access switch lists the squatting endpoint twice: on its host
        # port and, in the row that comes last, on the uplink to the switch
        # that owns the gateway address. The host port is where it is.
        self.switch("oob-leaf-01", fdb(self.A, "swp7"), fdb(self.A, "swp49"))
        self.switch("oob-agg-01")
        self.neighbors = {
            "oob-leaf-01": [neigh(self.GATEWAY_IP, self.A)],
            "oob-agg-01": [neigh(self.GATEWAY_IP, self.SVI_1)],
        }
        self.trunk()

        analyzer = self.analyze()
        _row, exported = self.one_ip_row(analyzer)

        self.assertEqual({"oob-leaf-01": "swp49"}, analyzer.fdb_local[(VLAN, self.A)])
        self.assertEqual("WARNING", exported["severity"])
        self.assertTrue(exported["note"].startswith(
            "Confirmed - an endpoint is using a fabric gateway/SVI address"),
            exported["note"])
        self.assertEqual("oob-leaf-01:swp7", exported["local_ports"])

    def test_trunk_port_remembered_from_an_earlier_collection_is_dropped(self):
        # The owner memory of the previous collection still holds the
        # aggregation downlink. It must not come back as an owner.
        self.access_under_aggregation()
        self.trunk()
        now = time.time()
        state = self.dup_dir / "dup_ip_state.json"
        state.write_text(json.dumps({
            "%s|%s" % (VLAN, self.HOST_IP): {
                "ports": {"oob-agg-01": "swp1", "oob-leaf-01": "swp7"},
                "macs": {self.A: now, self.B: now}, "ts": now,
            },
        }))

        _row, exported = self.one_ip_row(self.analyze())

        self.assertEqual("oob-leaf-01:swp7 oob-leaf-01:swp8", exported["local_ports"])
        remembered = json.loads(state.read_text())["%s|%s" % (VLAN, self.HOST_IP)]
        self.assertEqual(["oob-leaf-01"], sorted(remembered["ports"]))

    def test_switch_that_reaches_the_owner_over_a_trunk_is_not_the_other_vtep(self):
        # An EVPN leaf with an L2 access switch below it. The claimant sits on
        # the access switch; the leaf holds the MAC on its trunk only, and
        # another leaf reports the address as a duplicate behind that VTEP.
        self.switch("leaf-01", fdb(self.A, "swp10"))
        self.switch("access-01", fdb(self.A, "swp5"))
        self.switch("leaf-02", fdb(mac(1), "swp3"))
        self.vteps = {"leaf-01": "10.0.0.1", "leaf-02": "10.0.0.2"}
        self.arp_sections["leaf-02"] = [
            "VNI %s #ARP (IPv4 and IPv6, local and remote) 1" % VLAN,
            "%s remote active %s 10.0.0.1 5/4" % (self.HOST_IP, self.A),
        ]
        self.lldp({
            "leaf-01": {"swp10": link("access-01", "swp49")},
            "access-01": {"swp49": link("leaf-01", "swp10")},
            "leaf-02": {"swp51": link("spine-01", "swp2")},
        })

        row, exported = self.one_ip_row(self.analyze())

        self.assertEqual("confirmed", exported["kind"])
        self.assertEqual("access-01:swp5", exported["local_ports"])
        self.assertIsNone(exported["vteps"])
        self.assertEqual("&mdash;", cells(row)[6])

    def test_owner_port_shown_for_an_ip_dad_participant_does_not_depend_on_set_order(self):
        # leaf-03 holds two MACs of the address on two ports. Which of them
        # the MAC row of a third claimant shows for leaf-03 must be the same
        # in every run, so the test feeds the ports in the order that used to
        # pick the other one.
        third = "0c:42:a1:00:00:0c"
        self.switch("leaf-01", fdb(self.A, "swp7"))
        self.switch("leaf-02", fdb(mac(1), "swp3"))
        self.switch("leaf-03", fdb(self.B, "swp2"), fdb(third, "bond2"))
        self.vteps = {"leaf-01": "10.0.0.1", "leaf-02": "10.0.0.2",
                      "leaf-03": "10.0.0.3"}
        self.arp_sections["leaf-02"] = [
            "VNI %s #ARP (IPv4 and IPv6, local and remote) 1" % VLAN,
            "%s remote active %s 10.0.0.1 5/4" % (self.HOST_IP, self.A),
        ]
        self.mac_sections["leaf-02"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            "%s remote 10.0.0.3 5/4" % self.A,
        ]
        self.neighbors = {
            "leaf-01": [neigh(self.HOST_IP, self.A)],
            "leaf-03": [neigh(self.HOST_IP, self.B), neigh(self.HOST_IP, third)],
        }
        self.lldp({
            "leaf-01": {"swp51": link("spine-01", "swp1")},
            "leaf-02": {"swp51": link("spine-01", "swp2")},
            "leaf-03": {"swp51": link("spine-01", "swp3")},
        })
        analyzer = self.analyze()
        record = analyzer.ip_dups[(VLAN, self.HOST_IP)]
        self.assertEqual(
            {"leaf-01:swp7", "leaf-03:swp2", "leaf-03:bond2"}, set(record["ports"]))

        shown = set()
        for order in (["leaf-03:bond2", "leaf-03:swp2", "leaf-01:swp7"],
                      ["leaf-03:swp2", "leaf-03:bond2", "leaf-01:swp7"]):
            record["ports"] = list(order)
            (row,) = [row for row in self.mac_rows(analyzer) if self.A in row]
            shown.add(cells(row)[4])

        self.assertEqual({"leaf-03:swp2"}, shown)


class SeenOnSeveralSwitchesCountTests(ReviewFixture):
    """The WARNING class has a card, a machine attribute and a summary key."""

    def duplicate_without_lldp(self):
        self.switch("leaf-01", fdb(DUP, "swp7"), fdb(mac(1), "swp8"))
        self.switch("leaf-02", fdb(DUP, "swp7"), fdb(mac(2), "swp8"))

    def card(self, report, label):
        match = re.search(
            r"<div class='summary-card ([^']*)'([^>]*)><div class='metric'>([^<]*)</div>"
            r"<div class='metric-label'>%s</div>" % re.escape(label), report)
        self.assertIsNotNone(match, label)
        return match.group(1), match.group(2), match.group(3)

    def summary_json(self):
        path = self.root / "monitor-results" / "summary" / "duplicate-summary.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_rows_are_counted_on_a_card_and_in_the_machine_summaries(self):
        self.duplicate_without_lldp()

        analyzer = self.analyze()
        report = self.report(analyzer)

        self.assert_seen_not_confirmed(analyzer, [DUP])
        classes, click, metric = self.card(report, "MAC SEEN ON SEVERAL SWITCHES")
        self.assertEqual("1", metric)
        self.assertIn("card-warning", classes)
        self.assertNotIn("noclick", classes)
        self.assertIn("cardFilter('fdb-observed', this)", click)
        self.assertIn('data-mac-fdb-observed-total="1"', report)
        self.assertIn('data-confirmed-mac-total="0"', report)
        self.assertEqual(1, self.summary_json()["mac_fdb_observed_total"])
        self.assertEqual(0, self.summary_json()["confirmed_mac_total"])
        export = self.root / "monitor-results" / "export" / "duplicate.json"
        counts = json.loads(export.read_text(encoding="utf-8"))["counts"]
        self.assertEqual(1, counts["mac_fdb_observed_total"])
        # The confirmed card is not fed by these rows.
        _classes, _click, confirmed = self.card(report, "CONFIRMED MAC CONFLICTS")
        self.assertEqual("0", confirmed)

    def test_page_can_filter_to_the_rows(self):
        self.duplicate_without_lldp()

        report = self.report(self.analyze())

        self.assertIn("kind==='fdb-observed'&&rowKind==='fdb-observed'", report)
        self.assertIn("kind==='mac'||kind==='fdb-observed'||", report)
        self.assertIn("'fdb-observed':'MACs seen on several switches", report)
        self.assertIn(
            "MAC Findings &mdash; Confirmed Conflicts / Seen on Several Switches / "
            "DAD / Mobility", report)

    def test_card_is_idle_when_there_is_no_such_row(self):
        self.switch("leaf-01", fdb(mac(1), "swp8"))
        self.switch("leaf-02", fdb(mac(2), "swp8"))

        report = self.report(self.analyze())

        classes, click, metric = self.card(report, "MAC SEEN ON SEVERAL SWITCHES")
        self.assertEqual("0", metric)
        self.assertIn("card-excellent", classes)
        self.assertIn("noclick", classes)
        self.assertEqual("", click)
        self.assertIn('data-mac-fdb-observed-total="0"', report)
        self.assertEqual(0, self.summary_json()["mac_fdb_observed_total"])


class EvidenceDetailTests(ReviewFixture):
    """Decided values and guards the first round left without a test."""

    FABRIC = {
        "leaf-01": {"swp51": link("spine-01", "swp1")},
        "leaf-02": {"swp51": link("spine-01", "swp2")},
        "leaf-03": {"swp51": link("spine-01", "swp3")},
    }

    def test_decided_bounds(self):
        self.assertEqual(16, FDB_SEGMENT_MIN_MACS)
        self.assertEqual(24 * 3600, LLDP_EVIDENCE_MAX_AGE_SEC)

    def test_switch_port_names(self):
        for name in ("swp1", "swp1s0", "Ethernet12", "Ethernet1/49", "Gi1/0/24",
                     "ge-0/0/12", "1/1/49"):
            self.assertTrue(_is_switch_port(name), name)
        for name in ("Ethernet", "Ethernet-uplink", "eth0", "port1", "ether1",
                     "eno1", "enp1s0f0", "p0", "vmnic0", "24", "swp", "", None):
            self.assertFalse(_is_switch_port(name), name)

    def three_host_ports(self):
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        self.switch("leaf-03", fdb(DUP, "swp3"))

    def test_switch_with_a_stale_collection_is_not_an_owner(self):
        self.three_host_ports()
        self.lldp(self.FABRIC)

        analyzer = self.analyze_with_stale(["leaf-03"])

        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual(2, rec["physical_local_count"])
        self.assertEqual({"leaf-01": "swp7", "leaf-02": "swp9"}, rec["local"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("LOCAL on edge ports of 2 switches", row)
        self.assertNotIn("leaf-03", row)
        self.assertNotIn("not verified", row)

    def test_owner_on_a_switch_without_lldp_data_is_listed_but_not_counted(self):
        self.three_host_ports()
        self.lldp({name: self.FABRIC[name] for name in ("leaf-01", "leaf-02")})

        analyzer = self.analyze()

        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual("CRITICAL", rec["severity"])
        self.assertEqual(2, rec["physical_local_count"])
        self.assertEqual(3, rec["fdb_seen_count"])
        self.assertEqual(["leaf-03"], rec["fdb_unverified_hosts"])
        self.assertEqual(
            {"leaf-01": "swp7", "leaf-02": "swp9", "leaf-03": "swp3"}, rec["local"])
        (row,) = self.mac_rows(analyzer)
        # Three ports listed, two proven: the text says both.
        self.assertIn("Confirmed MAC conflict: LOCAL on edge ports of 2 switches "
                      "(1 more switch not verified)", row)
        (exported,) = self.exported("mac")
        self.assertIn("(1 more switch not verified)", exported["note"])

    def routed_hypervisor(self, *leaf_01_rows):
        self.switch("leaf-01", *leaf_01_rows)
        self.switch("leaf-02", fdb(DUP, "swp9"))
        self.lldp({name: self.FABRIC[name] for name in ("leaf-01", "leaf-02")})

    def test_row_overwritten_by_a_later_one_still_counts_toward_the_bound(self):
        # One MAC below the bound on swp5, plus a MAC the switch lists on swp5
        # first and on swp6 afterwards: sixteen MACs were learned on swp5.
        guests = [mac(index) for index in range(1, FDB_SEGMENT_MIN_MACS - 1)]
        moved = mac(500)
        self.routed_hypervisor(
            fdb(DUP, "swp5"), *[fdb(address, "swp5") for address in guests],
            fdb(moved, "swp5"), fdb(moved, "swp6"))

        analyzer = self.analyze()

        self.assertEqual({"leaf-01": "swp6"}, analyzer.fdb_local[(VLAN, moved)])
        self.assertEqual(
            FDB_SEGMENT_MIN_MACS, analyzer.fdb_port_macs[("leaf-01", "swp5", VLAN)])
        self.assert_no_mac_finding(analyzer)

    def test_port_listed_again_is_counted_once(self):
        # The switch lists the MAC on swp5, on swp49, and on swp5 again. With
        # fourteen guests swp5 holds fifteen MACs, one below the bound.
        guests = [mac(index) for index in range(1, FDB_SEGMENT_MIN_MACS - 1)]
        self.routed_hypervisor(
            fdb(DUP, "swp5"), fdb(DUP, "swp49"), fdb(DUP, "swp5"),
            *[fdb(address, "swp5") for address in guests])

        analyzer = self.analyze()

        self.assertEqual({"leaf-01": {"swp49"}}, analyzer.fdb_other_ports[(VLAN, DUP)])
        self.assertEqual(
            FDB_SEGMENT_MIN_MACS - 1,
            analyzer.fdb_port_macs[("leaf-01", "swp5", VLAN)])
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual({"leaf-01": "swp5", "leaf-02": "swp9"}, rec["local"])

    def test_a_switch_s_own_capture_outranks_what_a_far_end_says_about_its_port(self):
        # leaf-01 hears a server on swp7. Another switch's capture names
        # "leaf-01 / swp7" as its neighbour (a stale or mis-cabled entry):
        # that must not turn the host port into an inter-switch link.
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        self.lldp({
            "leaf-01": {"swp7": link("gpu-srv-01", "enp1s0f0"),
                        "swp51": link("spine-01", "swp1")},
            "leaf-02": {"swp51": link("spine-01", "swp2")},
            "spine-09": {"swp3": link("leaf-01", "swp7")},
        })

        analyzer = self.analyze()

        self.assertEqual("edge", analyzer._fdb_port_role("leaf-01", "swp7", VLAN))
        rec = analyzer.mac_dups[(VLAN, DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual({"leaf-01": "swp7", "leaf-02": "swp9"}, rec["local"])

    def test_created_stamp_far_in_the_future_cannot_date_the_sidecar(self):
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        fabric = {name: self.FABRIC[name] for name in ("leaf-01", "leaf-02")}

        # An hour ahead is the repeated hour of a DST change: the stamp is
        # still what dates the file, whatever the file time says.
        sidecar = self.lldp(fabric, created=datetime.now() + timedelta(hours=1))
        old = time.time() - LLDP_EVIDENCE_MAX_AGE_SEC - 7200
        os.utime(sidecar, (old, old))
        self.assertEqual("ok", self.analyze().lldp_state)

        # A stamp from a broken clock says nothing; the file time decides.
        sidecar = self.lldp(fabric, created=datetime.now() + timedelta(days=30))
        self.assertEqual("ok", self.analyze().lldp_state)
        old = time.time() - LLDP_EVIDENCE_MAX_AGE_SEC - 7200
        os.utime(sidecar, (old, old))

        analyzer = self.analyze()

        self.assertEqual("stale", analyzer.lldp_state)
        self.assert_seen_not_confirmed(analyzer, [DUP])

        # Nor does a file time from that clock.
        ahead = time.time() + 30 * 86400
        os.utime(sidecar, (ahead, ahead))
        self.assertEqual("stale", self.analyze().lldp_state)

    def test_stale_note_says_known_links_are_still_excluded(self):
        self.switch("leaf-01", fdb(DUP, "swp7"))
        self.switch("leaf-02", fdb(DUP, "swp9"))
        self.lldp({name: self.FABRIC[name] for name in ("leaf-01", "leaf-02")},
                  created=datetime.now() - timedelta(
                      seconds=LLDP_EVIDENCE_MAX_AGE_SEC + 7200))

        (row,) = self.mac_rows(self.analyze())

        self.assertIn(
            "LLDP neighbor data is stale (older than %d hours; the inter-switch "
            "links it lists are still excluded)" % (LLDP_EVIDENCE_MAX_AGE_SEC // 3600),
            row)


if __name__ == "__main__":
    unittest.main()
