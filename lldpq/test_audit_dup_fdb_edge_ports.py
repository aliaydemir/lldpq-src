#!/usr/bin/env python3
"""Audit regression: the FDB MAC rule must tell edge ports from transit ports.

A MAC behind an inter-switch link is LOCAL (not extern_learn) on a swp port at
both ends of the link, so "LOCAL on swp ports of two switches" described every
host behind an L2 trunk as a CRITICAL confirmed MAC conflict. Two shapes were
reproduced: an access switch under an aggregation switch, and two monitored
switches that each uplink into the same VLAN of an unmonitored network.

Every test drives the real analyzer end to end (parse_all + export_html) over
collector-format files: assets.ini, <host>_dup.txt with the coverage markers,
<host>_fdb.txt in `bridge fdb show` format, and the LLDP neighbour sidecar in
the shape lldp-validate.py writes. All names and addresses are invented.
"""

import json
import os
import re
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import duplicate_analyzer
from duplicate_analyzer import (
    FDB_SEGMENT_MIN_MACS,
    LLDP_EVIDENCE_MAX_AGE_SEC,
    STALE_AGE_SEC,
    DuplicateAnalyzer,
)

VLAN = "20"
GATEWAY = "00:1c:73:aa:bb:01"
UPSTREAM = "48:b0:2d:00:00:99"


def mac(index):
    return "0c:42:a1:00:%02x:%02x" % (index // 256, index % 256)


def fdb(address, port, vlan=VLAN):
    return "%s dev %s vlan %s master br_default" % (address, port, vlan)


def link(device, port):
    return {"device": device, "port": port}


class FabricFixture(unittest.TestCase):
    """Collector-format input tree for the real DuplicateAnalyzer."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dup_dir = self.root / "monitor-results" / "dup-data"
        self.dup_dir.mkdir(parents=True)
        self.switches = {}
        self.mac_sections = {}
        self.mobility_sections = {}
        # The analyzer must read only this tree: no inherited inventory
        # overrides, no topology.dot spelling from the machine running it.
        environment = mock.patch.dict(os.environ, {}, clear=False)
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("LLDPQ_ASSETS_FILE", "LLDPQ_DEVICES_FILE",
                     "LLDPQ_COLLECTION_STATUS_FILE", "DUP_DATA_MAX_AGE_MINUTES"):
            os.environ.pop(name, None)
        spelling = mock.patch.object(
            duplicate_analyzer, "canonical", side_effect=lambda value: value)
        spelling.start()
        self.addCleanup(spelling.stop)

    def switch(self, name, *rows):
        self.switches[name] = list(rows) + [
            # What a VLAN-aware bridge also prints; never a learned host.
            "1c:34:da:00:00:01 dev swp1 master br_default permanent",
            "1c:34:da:00:00:02 dev br_default vlan %s master br_default permanent" % VLAN,
        ]

    def lldp(self, neighbors, created=None):
        created = created or datetime.now()
        path = self.root / "lldp-results" / "lldp_neighbors.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({
            "version": 1,
            "created": created.strftime("%Y-%m-%d %H-%M-%S"),
            "neighbors": neighbors,
            "ports": {},
        }), encoding="utf-8")
        return path

    def _write_inputs(self):
        names = sorted(self.switches)
        assets = [
            "Created on " + datetime.now().strftime("%Y-%m-%d %H-%M-%S"), "",
            "DEVICE-NAME IP ETH0-MAC SERIAL MODEL RELEASE UPTIME STATUS LAST-SEEN",
        ]
        for index, name in enumerate(names):
            assets.append("%s 192.0.2.%d 44:38:39:00:00:%02x SN%d SN2201 5.9.1 1d OK now"
                          % (name, 10 + index, index, index))
        (self.root / "assets.ini").write_text("\n".join(assets) + "\n")
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for name in names:
            (self.dup_dir / (name + "_dup.txt")).write_text("\n".join([
                "__LLDPQ_DUP_COLLECTION_UTC__:" + stamp,
                "__LLDPQ_DUP_COVERAGE__:COLLECTION_TIMESTAMP:OK",
                "=== DUP VNI MAP ===",
                "__LLDPQ_DUP_COVERAGE__:VNI_MAP:OK",
                "=== DUP CONFIG ===",
                "__LLDPQ_DUP_COVERAGE__:CONFIG:OK",
                "=== DUP SELF ===",
                "__LLDPQ_DUP_COVERAGE__:SELF:OK",
                "=== DUP ARP ===",
                "__LLDPQ_DUP_COVERAGE__:ARP_DUPLICATES:OK",
                "=== DUP MAC ===",
                *self.mac_sections.get(name, []),
                "__LLDPQ_DUP_COVERAGE__:MAC_DUPLICATES:OK",
                "=== DUP LOG ===",
                "__LLDPQ_DUP_COVERAGE__:FRR_LOG:OK",
                "=== DUP MACMOB ===",
                *self.mobility_sections.get(name, []),
                "__LLDPQ_DUP_COVERAGE__:MAC_MOBILITY:OK",
                "=== DUP ARPMOB ===",
                "__LLDPQ_DUP_COVERAGE__:ARP_MOBILITY:OK",
                "=== DUP IFALIAS ===",
                "__LLDPQ_DUP_COVERAGE__:IFALIAS:OK", "",
            ]))
            (self.dup_dir / (name + "_fdb.txt")).write_text(
                "\n".join(self.switches[name]) + "\n")
            (self.dup_dir / (name + "_neigh.txt")).write_text("")

    def analyze(self):
        self._write_inputs()
        analyzer = DuplicateAnalyzer(str(self.root / "monitor-results"))
        analyzer.parse_all()
        # The fixture itself must be a complete, current collection, or an
        # empty result would prove nothing.
        self.assertEqual([], analyzer.coverage["failures"])
        self.assertEqual(set(self.switches), analyzer.coverage["fdb_current"])
        return analyzer

    def report(self, analyzer):
        output = self.root / "monitor-results" / "duplicate-analysis.html"
        analyzer.export_html(str(output))
        return output.read_text(encoding="utf-8")

    def mac_rows(self, analyzer):
        table = self.report(analyzer).split('id="mact"', 1)[1].split("</table>", 1)[0]
        body = table.split("<tbody>", 1)[1]
        return [row for row in re.findall(r"<tr[^>]*>.*?</tr>", body, re.S)
                if "class='empty" not in row]

    def exported_mac_rows(self):
        export = self.root / "monitor-results" / "export" / "duplicate.json"
        rows = json.loads(export.read_text(encoding="utf-8"))["rows"]
        return [row for row in rows if row["finding_type"] == "mac"]

    def assert_no_mac_finding(self, analyzer):
        self.assertEqual({}, analyzer.mac_dups)
        summary = analyzer.summary()
        self.assertEqual(0, summary["confirmed_mac_total"])
        self.assertEqual(0, summary["mac_fdb_observed_total"])
        report = self.report(analyzer)
        self.assertIn('data-confirmed-mac-total="0"', report)
        self.assertIn('data-collection-status="current"', report)
        self.assertEqual([], self.mac_rows(analyzer))
        self.assertEqual([], self.exported_mac_rows())

    def assert_seen_not_confirmed(self, analyzer, addresses):
        """Every address is a WARNING 'seen on several switches' row."""
        self.assertEqual(
            sorted(addresses), sorted(rec["mac"] for rec in analyzer.mac_dups.values()))
        for rec in analyzer.mac_dups.values():
            self.assertFalse(rec["confirmed_conflict"], rec["mac"])
            self.assertEqual("WARNING", rec["severity"], rec["mac"])
            self.assertEqual("fdb_observed_mac", rec["incident_type"], rec["mac"])
        summary = analyzer.summary()
        self.assertEqual(0, summary["confirmed_mac_total"])
        self.assertEqual(0, summary["confirmed_mac_active"])
        self.assertEqual(len(addresses), summary["mac_fdb_observed_total"])
        self.assertIn('data-confirmed-mac-total="0"', self.report(analyzer))
        rows = self.mac_rows(analyzer)
        self.assertEqual(len(addresses), len(rows))
        for row in rows:
            self.assertIn("data-kind='fdb-observed'", row)
            self.assertIn("badge-orange", row)
            self.assertRegex(row, r"Seen on \d+ switches")
            self.assertNotIn("onfirmed", row)
        for row in self.exported_mac_rows():
            self.assertEqual("WARNING", row["severity"])
            self.assertEqual("fdb-observed", row["kind"])
            self.assertNotIn("onfirmed", row["note"])


class AccessSwitchUnderAggregationTests(FabricFixture):
    """Shape (a): hosts on an access switch, one plain swp uplink to an
    aggregation switch that also has its own upstream port."""

    def build(self):
        self.switch(
            "oob-leaf-01",
            fdb(mac(1), "swp7"), fdb(mac(2), "swp8"), fdb(mac(3), "swp9"),
            fdb(UPSTREAM, "swp49"),
        )
        self.switch(
            "oob-agg-01",
            fdb(mac(1), "swp1"), fdb(mac(2), "swp1"), fdb(mac(3), "swp1"),
            fdb(UPSTREAM, "swp32"),
        )

    def test_trunk_between_managed_switches_is_not_a_conflict(self):
        self.build()
        self.lldp({
            "oob-leaf-01": {"swp49": link("oob-agg-01", "swp1")},
            "oob-agg-01": {"swp1": link("oob-leaf-01", "swp49")},
        })

        self.assert_no_mac_finding(self.analyze())

    def test_three_tier_chain_is_not_a_conflict(self):
        self.build()
        self.switch(
            "oob-core-01",
            fdb(mac(1), "swp5"), fdb(mac(2), "swp5"), fdb(mac(3), "swp5"),
            fdb(UPSTREAM, "swp6"),
        )
        self.lldp({
            "oob-leaf-01": {"swp49": link("oob-agg-01", "swp1")},
            "oob-agg-01": {"swp1": link("oob-leaf-01", "swp49"),
                           "swp32": link("oob-core-01", "swp5")},
            "oob-core-01": {"swp5": link("oob-agg-01", "swp32")},
        })

        self.assert_no_mac_finding(self.analyze())

    def test_link_reported_by_one_end_only_is_still_a_trunk(self):
        # The access switch hears its management neighbour but not the
        # aggregation switch; the aggregation switch reports the link, under
        # the name the access switch announces itself with.
        self.build()
        self.lldp({
            "oob-leaf-01": {"eth0": link("oob-mgmt-01", "swp3")},
            "oob-agg-01": {"swp1": link("OOB-LEAF-01", "swp49")},
        })

        self.assert_no_mac_finding(self.analyze())

    def test_without_lldp_data_it_is_seen_on_two_switches_not_confirmed(self):
        self.build()

        analyzer = self.analyze()

        self.assertEqual("missing", analyzer.lldp_state)
        # The aggregation downlink gives itself away without LLDP: its three
        # MACs sit on three ports of the access switch (fan-out), so the hosts
        # get no row. The upstream MAC is one MAC on one port at each end,
        # which no FDB shape can tell from a duplicate.
        self.assert_seen_not_confirmed(analyzer, [UPSTREAM])
        for row in self.mac_rows(analyzer):
            self.assertIn("Seen on 2 switches", row)
            self.assertIn("no LLDP neighbor data", row)

    def test_unreadable_sidecar_counts_as_no_lldp_data(self):
        self.build()
        self.lldp({}).write_text("{ not json", encoding="utf-8")

        analyzer = self.analyze()

        self.assertEqual("missing", analyzer.lldp_state)
        self.assert_seen_not_confirmed(analyzer, [UPSTREAM])


class UplinksIntoUnmonitoredNetworkTests(FabricFixture):
    """Shape (b): two monitored switches that are not connected to each
    other; each has one uplink into the same VLAN of an unmonitored network."""

    def build(self):
        self.switch("oob-sw-01", fdb(mac(1), "swp7"),
                    fdb(mac(2), "swp49"), fdb(GATEWAY, "swp49"))
        self.switch("oob-sw-02", fdb(mac(2), "swp9"),
                    fdb(mac(1), "swp49"), fdb(GATEWAY, "swp49"))

    def test_gateway_and_each_others_hosts_are_not_confirmed_without_lldp(self):
        self.build()

        analyzer = self.analyze()

        # Each uplink holds two MACs that the other switch has on two
        # different ports, so both are transit ports by fan-out: no row.
        self.assertEqual("missing", analyzer.lldp_state)
        self.assert_no_mac_finding(analyzer)

    def test_unmonitored_switch_neighbor_makes_the_uplink_transit(self):
        # The upstream switches are not in the inventory; the sidecar only
        # records the port name they advertise.
        for sw1_port, sw2_port in (
                ("swp12", "swp13"),                  # Cumulus outside the inventory
                ("Ethernet12", "Ethernet13"),        # EOS / SONiC
                ("Ethernet1/12", "Ethernet1/13"),    # NX-OS
                ("ge-0/0/12", "xe-0/0/13"),          # Junos
                ("Gi1/0/12", "1/1/13"),              # IOS / AOS-CX
        ):
            with self.subTest(upstream_ports=(sw1_port, sw2_port)):
                self.build()
                self.lldp({
                    "oob-sw-01": {"swp49": link("core-a", sw1_port)},
                    "oob-sw-02": {"swp49": link("core-b", sw2_port)},
                })

                self.assert_no_mac_finding(self.analyze())

    def test_fdb_shape_alone_recognises_the_uplinks(self):
        # A realistic access VLAN: each uplink carries every MAC that lives
        # beyond it. No LLDP data at all.
        hosts = FDB_SEGMENT_MIN_MACS
        first = [mac(index) for index in range(1, hosts + 1)]
        second = [mac(index) for index in range(101, 101 + hosts)]
        self.switch(
            "oob-sw-01",
            *[fdb(address, "swp%d" % (index + 1)) for index, address in enumerate(first)],
            *[fdb(address, "swp49") for address in second],
            fdb(GATEWAY, "swp49"),
        )
        self.switch(
            "oob-sw-02",
            *[fdb(address, "swp%d" % (index + 1)) for index, address in enumerate(second)],
            *[fdb(address, "swp49") for address in first],
            fdb(GATEWAY, "swp49"),
        )

        analyzer = self.analyze()

        self.assertEqual("missing", analyzer.lldp_state)
        self.assert_no_mac_finding(analyzer)

    def test_segment_count_is_per_vlan(self):
        # The same uplink carries only two MACs in VLAN 30: the count that
        # makes it a transit port in VLAN 20 says nothing about VLAN 30.
        hosts = FDB_SEGMENT_MIN_MACS
        self.switch(
            "oob-sw-01",
            *[fdb(mac(index), "swp49") for index in range(1, hosts + 1)],
            fdb(mac(200), "swp49", vlan="30"), fdb(mac(201), "swp7", vlan="30"),
        )
        self.switch(
            "oob-sw-02",
            *[fdb(mac(index), "swp%d" % index) for index in range(1, hosts + 1)],
            fdb(mac(200), "swp9", vlan="30"), fdb(mac(201), "swp49", vlan="30"),
        )

        analyzer = self.analyze()

        self.assert_seen_not_confirmed(analyzer, [mac(200), mac(201)])
        self.assertEqual({"30"}, {rec["vlan"] for rec in analyzer.mac_dups.values()})


class RealDuplicateTests(FabricFixture):
    """The same MAC attached at edge ports of two switches stays CRITICAL."""

    DUP = "0c:42:a1:de:ad:01"

    def trunks(self, extra=None):
        neighbors = {
            "leaf-01": {"swp49": link("agg-01", "swp1")},
            "leaf-02": {"swp49": link("agg-01", "swp2")},
            "agg-01": {"swp1": link("leaf-01", "swp49"),
                       "swp2": link("leaf-02", "swp49")},
        }
        for device, ports in (extra or {}).items():
            neighbors.setdefault(device, {}).update(ports)
        return self.lldp(neighbors)

    def assert_confirmed(self, analyzer, owners):
        self.assertEqual([self.DUP], [rec["mac"] for rec in analyzer.mac_dups.values()])
        rec = next(iter(analyzer.mac_dups.values()))
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual("CRITICAL", rec["severity"])
        self.assertEqual("confirmed_mac_conflict", rec["incident_type"])
        self.assertEqual(owners, rec["local"])
        self.assertEqual(len(owners), rec["physical_local_count"])
        summary = analyzer.summary()
        self.assertEqual(1, summary["confirmed_mac_total"])
        self.assertEqual(1, summary["confirmed_mac_active"])
        self.assertEqual(0, summary["mac_fdb_observed_total"])
        self.assertIn('data-confirmed-mac-total="1"', self.report(analyzer))
        (row,) = self.mac_rows(analyzer)
        self.assertIn("data-kind='confirmed'", row)
        self.assertIn("badge-red", row)
        self.assertIn("Confirmed MAC conflict: LOCAL on edge ports of %d switches"
                      % len(owners), row)
        (exported,) = self.exported_mac_rows()
        self.assertEqual("CRITICAL", exported["severity"])
        self.assertEqual("confirmed", exported["kind"])
        self.assertEqual(
            " ".join(sorted("%s:%s" % item for item in owners.items())),
            exported["local_ports"])
        return row

    def test_duplicate_on_two_edge_ports_also_seen_through_a_trunk(self):
        # Both access switches hold the MAC on a host port; the aggregation
        # switch additionally sees it through its downlink.
        self.switch("leaf-01", fdb(self.DUP, "swp7"), fdb(mac(1), "swp8"))
        self.switch("leaf-02", fdb(self.DUP, "swp7"), fdb(mac(1), "swp49"))
        self.switch("agg-01", fdb(self.DUP, "swp1"), fdb(mac(1), "swp1"))
        self.trunks()

        row = self.assert_confirmed(
            self.analyze(), {"leaf-01": "swp7", "leaf-02": "swp7"})

        # The trunk port is not an owner of the conflict.
        self.assertNotIn("agg-01", row)

    def test_sidecar_device_names_in_another_case_still_match(self):
        # The sidecar is keyed by the inventory spelling, the analyzer by the
        # displayed (topology.dot) spelling; they may differ in case only.
        self.switch("leaf-01", fdb(self.DUP, "swp7"), fdb(mac(1), "swp8"))
        self.switch("leaf-02", fdb(self.DUP, "swp7"), fdb(mac(1), "swp49"))
        self.switch("agg-01", fdb(self.DUP, "swp1"), fdb(mac(1), "swp1"))
        self.lldp({
            "LEAF-01": {"swp49": link("AGG-01", "swp1")},
            "LEAF-02": {"swp49": link("AGG-01", "swp2")},
            "AGG-01": {"swp1": link("LEAF-01", "swp49"),
                       "swp2": link("LEAF-02", "swp49")},
        })

        self.assert_confirmed(
            self.analyze(), {"leaf-01": "swp7", "leaf-02": "swp7"})

    def test_analyzer_device_names_in_another_case_still_match(self):
        self.switch("LEAF-01", fdb(self.DUP, "swp7"), fdb(mac(1), "swp8"))
        self.switch("LEAF-02", fdb(self.DUP, "swp7"), fdb(mac(1), "swp49"))
        self.switch("AGG-01", fdb(self.DUP, "swp1"), fdb(mac(1), "swp1"))
        self.trunks()

        self.assert_confirmed(
            self.analyze(), {"LEAF-01": "swp7", "LEAF-02": "swp7"})

    def test_duplicate_survives_a_second_row_on_the_uplink(self):
        # One of the two switches lists the MAC twice: on the host port and
        # on its uplink. Whichever row comes last must not hide the host port.
        for rows in ((fdb(self.DUP, "swp7"), fdb(self.DUP, "swp49")),
                     (fdb(self.DUP, "swp49"), fdb(self.DUP, "swp7"))):
            with self.subTest(order=[row.split()[2] for row in rows]):
                self.switch("leaf-01", *rows)
                self.switch("leaf-02", fdb(self.DUP, "swp9"))
                self.switch("agg-01", fdb(self.DUP, "swp2"))
                self.trunks()

                self.assert_confirmed(
                    self.analyze(), {"leaf-01": "swp7", "leaf-02": "swp9"})

    def test_duplicate_between_endpoints_that_speak_lldp(self):
        # A server NIC, and the management port of a managed switch: both are
        # LLDP neighbours, neither is a bridge port.
        self.switch("leaf-01", fdb(self.DUP, "swp7"))
        self.switch("leaf-02", fdb(self.DUP, "swp9"))
        self.switch("agg-01", fdb(self.DUP, "swp1"))
        self.trunks({
            "leaf-01": {"swp7": link("gpu-srv-01", "enp1s0f0")},
            "leaf-02": {"swp9": link("agg-01", "eth0")},
        })

        self.assert_confirmed(
            self.analyze(), {"leaf-01": "swp7", "leaf-02": "swp9"})

    def test_port_with_a_few_macs_is_still_an_attachment_point(self):
        # A hypervisor port: several VM MACs, one of them duplicated on
        # another switch. One MAC below the segment bound. Routed fabric:
        # the other switches do not hold the guests, so nothing fans out and
        # the MAC count alone decides.
        guests = [mac(index) for index in range(1, FDB_SEGMENT_MIN_MACS - 1)]
        self.switch("leaf-01", fdb(self.DUP, "swp5"),
                    *[fdb(address, "swp5") for address in guests])
        self.switch("leaf-02", fdb(self.DUP, "swp9"))
        self.switch("agg-01")
        self.trunks()

        analyzer = self.analyze()

        self.assertEqual(
            FDB_SEGMENT_MIN_MACS - 1,
            analyzer.fdb_port_macs[("leaf-01", "swp5", VLAN)])
        self.assert_confirmed(analyzer, {"leaf-01": "swp5", "leaf-02": "swp9"})

    def test_port_at_the_segment_bound_is_not_an_attachment_point(self):
        # The documented limit of the FDB shape: a port holding the bound is
        # taken to carry a segment, whatever LLDP says about it. Same routed
        # fabric as above, so only the count can make the port transit.
        guests = [mac(index) for index in range(1, FDB_SEGMENT_MIN_MACS)]
        self.switch("leaf-01", fdb(self.DUP, "swp5"),
                    *[fdb(address, "swp5") for address in guests])
        self.switch("leaf-02", fdb(self.DUP, "swp9"))
        self.switch("agg-01")
        self.trunks()

        analyzer = self.analyze()

        self.assertEqual(
            FDB_SEGMENT_MIN_MACS, analyzer.fdb_port_macs[("leaf-01", "swp5", VLAN)])
        self.assert_no_mac_finding(analyzer)

    def test_bond_attachment_is_still_excluded(self):
        # Dual-homed host on a bond of both switches, and a host that one
        # switch holds on a bond and the other on a swp port.
        self.switch("leaf-01", fdb(self.DUP, "bond1"), fdb(mac(1), "bond2"))
        self.switch("leaf-02", fdb(self.DUP, "bond1"), fdb(mac(1), "swp9"))
        self.switch("agg-01")
        self.trunks()

        self.assert_no_mac_finding(self.analyze())


class EvidenceLimitTests(FabricFixture):
    """What the analyzer may claim when the port roles cannot be shown."""

    DUP = "0c:42:a1:de:ad:02"

    def duplicate_on_two_host_ports(self):
        self.switch("leaf-01", fdb(self.DUP, "swp7"), fdb(mac(1), "swp8"))
        self.switch("leaf-02", fdb(self.DUP, "swp7"), fdb(mac(1), "swp49"))
        self.switch("agg-01", fdb(self.DUP, "swp1"), fdb(mac(1), "swp1"))

    def trunks(self):
        return {
            "leaf-01": {"swp49": link("agg-01", "swp1")},
            "leaf-02": {"swp49": link("agg-01", "swp2")},
            "agg-01": {"swp1": link("leaf-01", "swp49"),
                       "swp2": link("leaf-02", "swp49")},
        }

    def test_stale_lldp_data_keeps_trunks_out_but_cannot_confirm(self):
        # Two hours past the limit (and two inside it in the next test): the
        # sidecar stamp is local wall-clock time, an hour off across a DST change.
        self.duplicate_on_two_host_ports()
        self.lldp(self.trunks(), created=datetime.now() - timedelta(
            seconds=LLDP_EVIDENCE_MAX_AGE_SEC + 7200))

        analyzer = self.analyze()

        self.assertEqual("stale", analyzer.lldp_state)
        # mac(1) is one host behind two trunks: still no row. The real
        # duplicate is listed, on its two host ports only, but not confirmed.
        self.assert_seen_not_confirmed(analyzer, [self.DUP])
        rec = next(iter(analyzer.mac_dups.values()))
        self.assertEqual({"leaf-01": "swp7", "leaf-02": "swp7"}, rec["local"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("LLDP neighbor data is stale", row)
        self.assertNotIn("agg-01", row)

    def test_lldp_data_just_inside_the_age_limit_still_confirms(self):
        self.duplicate_on_two_host_ports()
        self.lldp(self.trunks(), created=datetime.now() - timedelta(
            seconds=LLDP_EVIDENCE_MAX_AGE_SEC - 7200))

        analyzer = self.analyze()

        self.assertEqual("ok", analyzer.lldp_state)
        rec = analyzer.mac_dups[(VLAN, self.DUP)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual("CRITICAL", rec["severity"])

    def test_sidecar_without_a_created_stamp_is_aged_by_its_file_time(self):
        self.duplicate_on_two_host_ports()
        sidecar = self.lldp(self.trunks())
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        del payload["created"]
        sidecar.write_text(json.dumps(payload), encoding="utf-8")

        self.assertEqual("ok", self.analyze().lldp_state)

        old = time.time() - LLDP_EVIDENCE_MAX_AGE_SEC - 7200
        os.utime(sidecar, (old, old))

        self.assertEqual("stale", self.analyze().lldp_state)

    def test_switch_without_lldp_data_cannot_confirm(self):
        # LLDP answered on leaf-01 and agg-01 only.
        self.duplicate_on_two_host_ports()
        neighbors = self.trunks()
        del neighbors["leaf-02"]
        self.lldp(neighbors)

        analyzer = self.analyze()

        self.assert_seen_not_confirmed(analyzer, [self.DUP])
        rec = next(iter(analyzer.mac_dups.values()))
        self.assertEqual(["leaf-02"], rec["fdb_unverified_hosts"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("LLDP has no neighbor data for leaf-02", row)

    def test_seen_on_several_switches_row_does_not_age_out(self):
        # The FDB shows it in every collection; a week of that is not a
        # quiesced finding to collapse under "Show aged".
        self.duplicate_on_two_host_ports()
        state = self.dup_dir / "dup_seq_state.json"
        state.write_text(json.dumps({
            "mac:%s|%s" % (VLAN, self.DUP): {
                "seq": 0, "ts": time.time() - STALE_AGE_SEC - 3600},
        }))

        analyzer = self.analyze()

        self.assert_seen_not_confirmed(analyzer, [self.DUP, mac(1)])
        rec = analyzer.mac_dups[(VLAN, self.DUP)]
        self.assertGreaterEqual(rec["quiet_age"], STALE_AGE_SEC)
        self.assertFalse(rec["stale"])
        self.assertNotIn("stale-row", "".join(self.mac_rows(analyzer)))

    def test_dad_flagged_mac_behind_a_trunk_is_not_a_confirmed_conflict(self):
        # An EVPN leaf with an L2 access switch under it: FRR flags the MAC
        # on the leaf, where it is local on the trunk to the access switch.
        self.switch("leaf-01", fdb(self.DUP, "swp10"))
        self.switch("access-01", fdb(self.DUP, "swp3"))
        self.mac_sections["leaf-01"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            "%s local active swp10 5/4" % self.DUP,
        ]
        self.lldp({
            "leaf-01": {"swp10": link("access-01", "swp49")},
            "access-01": {"swp49": link("leaf-01", "swp10")},
        })

        analyzer = self.analyze()

        rec = analyzer.mac_dups[(VLAN, self.DUP)]
        self.assertFalse(rec["confirmed_conflict"])
        self.assertFalse(rec["fdb_unverified"])
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])
        self.assertEqual(0, analyzer.summary()["confirmed_mac_total"])
        (row,) = self.mac_rows(analyzer)
        self.assertIn("data-kind='dad'", row)
        self.assertNotIn("Confirmed MAC conflict", row)

    def test_flat_mobility_does_not_drop_the_seen_on_several_switches_row(self):
        # A flat, low mobility sequence is ordinary churn and is normally
        # dropped from the page; the FDB sighting on two switches is not.
        self.switch("leaf-01", fdb(self.DUP, "swp7"))
        self.switch("leaf-02", fdb(self.DUP, "swp7"))
        self.mobility_sections["leaf-01"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            "%s local swp7 %s 12/11" % (self.DUP, VLAN),
        ]

        analyzer = self.analyze()

        self.assert_seen_not_confirmed(analyzer, [self.DUP])
        rec = analyzer.mac_dups[(VLAN, self.DUP)]
        self.assertTrue(rec["mobility"])
        self.assertFalse(rec["mobility_only"])

    def test_active_mobility_is_not_relabelled_by_the_fdb_sighting(self):
        # The same MAC is also moving at the DAD rate on leaf-01: that stays
        # the finding, and stays CRITICAL, with or without port roles.
        self.switch("leaf-01", fdb(self.DUP, "swp7"))
        self.switch("leaf-02", fdb(self.DUP, "swp7"))
        self.mobility_sections["leaf-01"] = [
            "VNI %s #MACs (local and remote) 1" % VLAN,
            "%s local swp7 %s 60/59" % (self.DUP, VLAN),
        ]
        (self.dup_dir / "dup_seq_state.json").write_text(json.dumps({
            "__mac_observer_state_version__": 1,
            "mac-observer:%s|%s|leaf-01" % (VLAN, self.DUP): {
                "seq": 20, "observed_at": time.time() - 120, "ts": time.time() - 120},
        }))

        analyzer = self.analyze()

        rec = analyzer.mac_dups[(VLAN, self.DUP)]
        self.assertTrue(rec["sequence_active"])
        self.assertEqual("mac_mobility_active", rec["incident_type"])
        self.assertEqual("CRITICAL", rec["severity"])
        self.assertFalse(rec["confirmed_conflict"])
        summary = analyzer.summary()
        self.assertEqual(1, summary["mac_mobility_active"])
        self.assertEqual(0, summary["confirmed_mac_total"])
        self.assertEqual(0, summary["mac_fdb_observed_total"])

    def test_thresholds_dialog_states_the_rule(self):
        self.duplicate_on_two_host_ports()

        report = self.report(self.analyze())

        self.assertNotIn("__SEGMENT_MIN__", report)
        self.assertNotIn("__LLDP_MAX_AGE_H__", report)
        self.assertIn("%d or more MACs in the VLAN" % FDB_SEGMENT_MIN_MACS, report)
        self.assertIn("older than %d hours" % (LLDP_EVIDENCE_MAX_AGE_SEC // 3600), report)
        self.assertIn("<b>Seen on several switches</b>", report)


if __name__ == "__main__":
    unittest.main()
