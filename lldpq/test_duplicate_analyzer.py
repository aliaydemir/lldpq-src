#!/usr/bin/env python3
"""Regression tests for duplicate IP/MAC severity and summary classification."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import duplicate_analyzer as duplicate_module
from duplicate_analyzer import ACTIVE_WINDOW_SEC, DuplicateAnalyzer


class DuplicateIpSeverityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"tor-a", "tor-b"},
            "current": {"tor-a", "tor-b"},
            "failures": [],
            "partial": False,
        }

    def add_ip(self, ip, *, hosts=("tor-a",), recency=None, delta=0,
               seq=100, flagged=True):
        rec = self.analyzer._blank_ip("8", "100008", ip)
        rec.update({
            "seq": seq,
            "flagged": flagged,
            "recency": recency,
            "delta": delta,
        })
        rec["macs"].add("00:11:22:33:44:55")
        rec["authoritative_hosts"].update(hosts)
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[("100008", ip)] = rec
        if hosts:
            self.analyzer.authoritative_ip_pairs[("100008", ip)] = set(hosts)
        return rec

    def test_current_authoritative_old_flat_is_quiesced(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )

        self.assertEqual("WARNING", rec["severity"])

    def test_parsed_flat_frr_row_is_quiesced_after_finalize(self):
        self.analyzer.vni_to_vlan["100008"] = "8"
        self.analyzer.prev_state["ip:100008|10.2.240.88"] = {
            "seq": 100,
            "ts": time.time() - (ACTIVE_WINDOW_SEC + 1),
        }
        self.analyzer._parse_arp_dup("tor-a", [
            "VNI 100008 #ARP (IPv4 and IPv6, local and remote) 1",
            "10.2.240.88 local active 00:11:22:33:44:55 100/99",
        ])

        self.analyzer._finalize()

        rec = self.analyzer.ip_dups[("100008", "10.2.240.88")]
        self.assertEqual(0, rec["delta"])
        self.assertEqual("WARNING", rec["severity"])
        self.assertEqual(0, self.analyzer.summary()["ip_active"])
        self.assertEqual(1, self.analyzer.summary()["ip_quiesced"])

    def test_recent_authoritative_is_critical(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC - 1,
            delta=0,
        )

        self.assertEqual("CRITICAL", rec["severity"])

    def test_climbing_sequence_is_critical(self):
        rec = self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=1,
        )

        self.assertEqual("CRITICAL", rec["severity"])

    def test_summary_splits_active_and_quiesced(self):
        self.add_ip("10.2.240.88", recency=10, delta=0)
        self.add_ip(
            "10.2.241.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )

        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_active"])
        self.assertEqual(1, summary["confirmed_ip_active"])
        self.assertEqual(1, summary["ip_quiesced"])
        self.assertEqual(2, summary["ip_total"])

    def test_same_ip_from_two_current_hosts_is_counted_once(self):
        self.add_ip(
            "10.2.240.88",
            hosts=("tor-a", "tor-b"),
            recency=10,
            delta=0,
        )

        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_active"])
        self.assertEqual(1, summary["ip_total"])

    def test_non_authoritative_context_is_excluded_from_summary(self):
        rec = self.add_ip(
            "10.2.242.88",
            hosts=(),
            recency=10,
            delta=0,
            flagged=False,
            seq=0,
        )

        self.assertEqual("CRITICAL", rec["severity"])
        summary = self.analyzer.summary()
        self.assertEqual(0, summary["ip_active"])
        self.assertEqual(0, summary["ip_quiesced"])
        self.assertEqual(0, summary["ip_total"])
        self.assertEqual(0, summary["vlans"])

    def test_html_marks_latched_frr_record_as_quiesced(self):
        self.add_ip(
            "10.2.240.88",
            recency=ACTIVE_WINDOW_SEC + 1,
            delta=0,
        )
        output = Path(self.tmp.name) / "duplicate-analysis.html"

        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")

        self.assertIn('data-confirmed-ip-active="0"', report)
        self.assertIn('data-ip-quiesced="1"', report)
        self.assertIn("quiesced / latched", report)
        self.assertIn(
            'clear evpn dup-addr vni &lt;VNI&gt; ip &lt;IP_ADDRESS&gt;',
            report,
        )
        self.assertIn(
            'clear evpn dup-addr vni &lt;VNI&gt; mac &lt;MAC_ADDRESS&gt;',
            report,
        )

    def test_ip_positive_remains_available_when_mac_coverage_is_missing(self):
        self.analyzer.coverage.update({
            "mac_current": set(),
            "mac_dad_current": set(),
            "mac_mobility_current": set(),
            "fdb_current": set(),
            "failures": ["tor-a:MAC_MOBILITY_ERROR"],
            "partial": True,
        })
        self.add_ip("10.2.240.88", recency=10, delta=0)
        output = Path(self.tmp.name) / "duplicate-ip-partial.html"

        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")

        self.assertIn('data-collection-status="partial"', report)
        self.assertIn('data-confirmed-ip-active="1"', report)


class DuplicateMacClassificationTests(unittest.TestCase):
    VLAN = "15"
    VNI = "100015"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"tor-a", "tor-b"},
            "current": {"tor-a", "tor-b"},
            "failures": [],
            "partial": False,
        }
        self.analyzer.vni_to_vlan[self.VNI] = self.VLAN
        # Keep the policy explicit: fewer than five moves in a collection
        # interval is a mobility signal, not an active duplicate incident.
        for host in self.analyzer.coverage["current"]:
            self.analyzer.dup_config[host] = {
                "enabled": True,
                "max_moves": 5,
                "time": 180,
            }

    def add_mac_mobility(self, mac, *, seq, prev_seq, host="tor-a",
                         port="swp31", quiet_age=ACTIVE_WINDOW_SEC + 1):
        self.analyzer.prev_state["mac:%s|%s" % (self.VNI, mac)] = {
            "seq": prev_seq,
            "ts": time.time() - quiet_age,
        }
        self.analyzer.mac_mob[(self.VNI, mac)] = {
            "seq": seq,
            "hosts": {host},
            "vteps": set(),
            "ports": {host: port},
            "vni": self.VNI,
        }

    def add_dad_flag(self, mac, *, host="tor-a", port="swp31", seq=100):
        self.analyzer.prev_state["mac:%s|%s" % (self.VNI, mac)] = {
            "seq": seq,
            "ts": time.time() - (ACTIVE_WINDOW_SEC + 1),
        }
        self.analyzer._parse_mac_dup(host, [
            "VNI %s #MACs (local and remote) 1" % self.VNI,
            "%s local active %s %d/%d" % (mac, port, seq, seq - 1),
        ])

    def add_fdb_conflict(self, mac):
        self.analyzer.fdb_local[(self.VLAN, mac)] = {
            "tor-a": "swp31",
            "tor-b": "swp32",
        }

    def mac_table_html(self):
        output = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")
        return report.split('id="mact"', 1)[1].split("</table>", 1)[0]

    def test_small_single_owner_mobility_delta_is_not_a_critical_duplicate(self):
        mac = "00:02:99:33:dc:db"
        self.add_mac_mobility(mac, seq=1297, prev_seq=1295)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertEqual(2, rec["delta"])
        self.assertFalse(rec["confirmed_conflict"])
        self.assertFalse(rec["dad_flagged"])
        self.assertTrue(rec["mobility_only"])
        self.assertFalse(rec["sequence_active"])
        self.assertEqual("mac_mobility_historical", rec["incident_type"])
        self.assertNotEqual("CRITICAL", rec["severity"])
        table = self.mac_table_html()
        self.assertIn("MAC mobility", table)
        self.assertNotIn("Duplicate device", table)

    def test_current_single_owner_mac_dad_flag_is_not_simultaneous_conflict(self):
        mac = "00:11:22:33:44:55"
        self.add_dad_flag(mac)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertFalse(rec["confirmed_conflict"])
        self.assertTrue(rec["dad_flagged"])
        self.assertFalse(rec["mobility_only"])
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])
        summary = self.analyzer.summary()
        self.assertEqual(0, summary["mac_total"])
        self.assertEqual(0, summary["confirmed_mac_total"])
        self.assertEqual(1, summary["mac_dad_total"])

    def test_two_physical_fdb_owners_are_confirmed_critical_conflict(self):
        mac = "00:11:22:33:44:66"
        self.add_fdb_conflict(mac)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertFalse(rec["dad_flagged"])
        self.assertFalse(rec["mobility_only"])
        self.assertEqual("confirmed_mac_conflict", rec["incident_type"])
        self.assertEqual("CRITICAL", rec["severity"])
        summary = self.analyzer.summary()
        self.assertEqual(1, summary["mac_total"])
        self.assertEqual(1, summary["confirmed_mac_total"])

    def test_valid_fdb_conflict_survives_unrelated_mobility_coverage_failure(self):
        mac = "00:11:22:33:44:67"
        self.analyzer.coverage.update({
            "mac_current": set(),
            "mac_dad_current": set(),
            "mac_mobility_current": set(),
            "fdb_current": {"tor-a", "tor-b"},
        })
        self.add_fdb_conflict(mac)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["confirmed_conflict"])
        self.assertEqual("CRITICAL", rec["severity"])

    def test_fdb_positive_remains_available_when_ip_coverage_is_missing(self):
        mac = "00:11:22:33:44:68"
        self.analyzer.coverage.update({
            "current": set(),
            "mac_current": set(),
            "mac_dad_current": set(),
            "mac_mobility_current": set(),
            "fdb_current": {"tor-a", "tor-b"},
            "failures": ["tor-a:ARP_DUPLICATES_ERROR"],
            "partial": True,
        })
        self.add_fdb_conflict(mac)
        self.analyzer._finalize()
        output = Path(self.tmp.name) / "duplicate-fdb-partial.html"

        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")

        self.assertIn('data-collection-status="partial"', report)
        self.assertIn('data-confirmed-mac-total="1"', report)

    def test_valid_dad_finding_survives_unrelated_fdb_coverage_failure(self):
        mac = "00:11:22:33:44:56"
        self.analyzer.coverage.update({
            "mac_current": set(),
            "mac_dad_current": {"tor-a"},
            "mac_mobility_current": set(),
            "fdb_current": set(),
        })
        self.add_dad_flag(mac)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["dad_flagged"])
        self.assertEqual("dad_flagged_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])

    def test_hidden_mobility_only_ip_does_not_make_mac_duplicate_device(self):
        mac = "00:02:99:33:dc:db"
        ip = "192.0.2.123"
        self.add_mac_mobility(mac, seq=1297, prev_seq=1295)
        self.analyzer.prev_state["ip:%s|%s" % (self.VNI, ip)] = {
            "seq": 1295,
            "ts": time.time() - (ACTIVE_WINDOW_SEC + 1),
        }
        self.analyzer.ip_mob[(self.VNI, ip)] = {
            "seq": 1297,
            "macs": {mac},
            "vteps": set(),
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        ip_rec = self.analyzer.ip_dups[(self.VNI, ip)]
        mac_rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertFalse(self.analyzer._is_confirmed_ip(ip_rec))
        self.assertNotEqual("ip_conflict_participant", mac_rec["incident_type"])
        self.assertNotEqual("duplicate", mac_rec["classification"])
        self.assertEqual("mac_mobility_historical", mac_rec["incident_type"])
        self.assertNotIn("Duplicate device", self.mac_table_html())

    def test_summary_separates_confirmed_dad_and_mobility_findings(self):
        self.add_fdb_conflict("00:11:22:33:44:01")
        self.add_dad_flag("00:11:22:33:44:02")
        self.add_mac_mobility(
            "00:11:22:33:44:03", seq=1002, prev_seq=1000,
            host="tor-a", port="swp33",
        )
        self.add_mac_mobility(
            "00:11:22:33:44:04", seq=1006, prev_seq=1000,
            host="tor-b", port="swp34",
        )

        self.analyzer._finalize()

        summary = self.analyzer.summary()
        self.assertEqual(1, summary["mac_total"])
        self.assertEqual(1, summary["confirmed_mac_total"])
        self.assertEqual(1, summary["mac_dad_total"])
        self.assertEqual(2, summary["mac_mobility_total"])
        self.assertEqual(1, summary["mac_mobility_active"])
        self.assertEqual(1, summary["mac_mobility_settled"])

        output = Path(self.tmp.name) / "duplicate-summary.html"
        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")
        self.assertIn('data-confirmed-mac-total="1"', report)
        self.assertIn('data-mac-dad-total="1"', report)
        self.assertIn('data-mac-mobility-active="1"', report)
        self.assertIn('data-mac-mobility-total="2"', report)
        self.assertIn("CONFIRMED MAC CONFLICTS", report)
        self.assertIn("MAC DAD FINDINGS", report)
        self.assertIn("ACTIVE MAC MOBILITY", report)
        self.assertIn("MAC MOBILITY SIGNALS", report)
        self.assertNotIn("MAC DUPLICATES", report)

    def test_high_flat_single_owner_sequence_is_historical_not_critical(self):
        mac = "00:11:22:33:44:77"
        self.add_mac_mobility(mac, seq=20000, prev_seq=20000)

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertEqual(0, rec["delta"])
        self.assertFalse(rec["confirmed_conflict"])
        self.assertFalse(rec["dad_flagged"])
        self.assertTrue(rec["mobility_only"])
        self.assertFalse(rec["sequence_active"])
        self.assertEqual("mac_mobility_historical", rec["incident_type"])
        self.assertNotEqual("CRITICAL", rec["severity"])
        summary = self.analyzer.summary()
        self.assertEqual(0, summary["mac_total"])
        self.assertEqual(0, summary["confirmed_mac_total"])
        self.assertEqual(1, summary["mac_mobility_total"])
        self.assertEqual(0, summary["mac_mobility_active"])
        self.assertEqual(1, summary["mac_mobility_settled"])

    def test_same_observer_policy_rate_can_activate_mobility(self):
        mac = "00:11:22:33:44:88"
        observed_at = self.analyzer.analysis_now.timestamp()
        state_key = self.analyzer._mac_observer_state_key(self.VNI, mac, "tor-a")
        self.analyzer.prev_state[state_key] = {
            "seq": 1000,
            "observed_at": observed_at - 120,
            "ts": observed_at - 120,
        }
        self.analyzer.mac_mob[(self.VNI, mac)] = {
            "seq": 1006,
            "seq_by_host": {"tor-a": 1006},
            "hosts": {"tor-a"},
            "vteps": set(),
            "ports": {"tor-a": "swp31"},
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertEqual(6, rec["delta"])
        self.assertTrue(rec["sequence_active"])
        self.assertEqual("mac_mobility_active", rec["incident_type"])
        self.assertEqual("CRITICAL", rec["severity"])

    def test_different_observer_does_not_create_a_false_delta(self):
        mac = "00:11:22:33:44:89"
        observed_at = self.analyzer.analysis_now.timestamp()
        old_key = self.analyzer._mac_observer_state_key(self.VNI, mac, "tor-a")
        self.analyzer.prev_state[old_key] = {
            "seq": 20000,
            "observed_at": observed_at - 120,
            "ts": observed_at - 120,
        }
        self.analyzer.prev_state["__mac_observer_state_version__"] = 1
        # This aggregate remains for quiet-age accounting, but must never be
        # mistaken for a migration baseline after observer state is versioned.
        self.analyzer.prev_state["mac:%s|%s" % (self.VNI, mac)] = {
            "seq": 20000,
            "ts": observed_at - 120,
        }
        self.analyzer.mac_mob[(self.VNI, mac)] = {
            "seq": 20002,
            "seq_by_host": {"tor-b": 20002},
            "hosts": {"tor-b"},
            "vteps": set(),
            "ports": {"tor-b": "swp32"},
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertIsNone(rec["delta"])
        self.assertFalse(rec["sequence_active"])
        self.assertEqual("WARNING", rec["severity"])

    def test_temporarily_absent_observer_state_is_carried_forward(self):
        mac = "00:11:22:33:44:8a"
        observed_at = self.analyzer.analysis_now.timestamp()
        key = self.analyzer._mac_observer_state_key(self.VNI, mac, "tor-a")
        self.analyzer.prev_state["__mac_observer_state_version__"] = 1
        self.analyzer.prev_state[key] = {
            "seq": 1234,
            "observed_at": observed_at - 120,
            "ts": observed_at - 120,
        }

        self.analyzer._finalize()

        self.assertEqual(self.analyzer.prev_state[key], self.analyzer.new_state[key])
        self.assertEqual(1, self.analyzer.new_state["__mac_observer_state_version__"])

    def test_two_bond_attachments_are_not_a_confirmed_conflict(self):
        mac = "00:11:22:33:44:90"
        self.analyzer.fdb_local[(self.VLAN, mac)] = {
            "tor-a": "bond0",
            "tor-b": "bond0",
        }

        self.analyzer._finalize()

        self.assertNotIn((self.VNI, mac), self.analyzer.mac_dups)
        self.assertNotIn((self.VLAN, mac), self.analyzer.mac_dups)
        self.assertEqual(0, self.analyzer.summary()["confirmed_mac_total"])

    def test_current_authoritative_ip_can_mark_mac_as_participant(self):
        mac = "00:11:22:33:44:91"
        ip = "192.0.2.91"
        self.add_mac_mobility(mac, seq=1297, prev_seq=1295)
        ip_rec = self.analyzer._blank_ip(self.VLAN, self.VNI, ip)
        ip_rec["macs"].add(mac)
        ip_rec["authoritative_macs"].add(mac)
        ip_rec["authoritative_hosts"].add("tor-a")
        self.analyzer.ip_dups[(self.VNI, ip)] = ip_rec

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["participates_in_ip_conflict"])
        self.assertEqual("ip-conflict-participant", rec["classification"])
        self.assertIn("Participant in current authoritative IP DAD finding", self.mac_table_html())

    def test_recent_dad_event_with_flat_sequence_is_settled_warning(self):
        mac = "00:11:22:33:44:92"
        observed_at = self.analyzer.analysis_now.timestamp()
        self.analyzer.prev_state["__mac_observer_state_version__"] = 1
        state_key = self.analyzer._mac_observer_state_key(self.VNI, mac, "tor-a")
        self.analyzer.prev_state[state_key] = {
            "seq": 100,
            "observed_at": observed_at - 600,
            "ts": observed_at - 7200,
        }
        self.add_dad_flag(mac)
        self.analyzer.log_events_mac[(self.VNI, mac)] = {
            "count": 3, "latest": self.analyzer.analysis_now,
            "vteps": {"10.0.0.13"}, "ips": set(),
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["dad_event"])
        self.assertEqual(0, rec["delta"])
        self.assertFalse(rec["dad_event_active"])
        self.assertEqual("dad_event_mac", rec["incident_type"])
        self.assertEqual("WARNING", rec["severity"])
        self.assertEqual("settled", rec["activity"])
        self.assertIn("sequence settled", self.mac_table_html())

    def test_recent_dad_event_with_unknown_delta_stays_critical(self):
        mac = "00:11:22:33:44:93"
        self.analyzer.prev_state["__mac_observer_state_version__"] = 1
        self.add_dad_flag(mac)
        self.analyzer.log_events_mac[(self.VNI, mac)] = {
            "count": 3, "latest": self.analyzer.analysis_now,
            "vteps": {"10.0.0.13"}, "ips": set(),
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VNI, mac)]
        self.assertTrue(rec["dad_event"])
        self.assertIsNone(rec["delta"])
        self.assertTrue(rec["dad_event_active"])
        self.assertEqual("CRITICAL", rec["severity"])
        self.assertEqual("active", rec["activity"])

    def test_mac_coverage_is_partial_when_fdb_source_fails(self):
        now = self.analyzer.analysis_now
        good_sources = {
            "COLLECTION_TIMESTAMP": "OK",
            "ARP_DUPLICATES": "OK",
            "MAC_DUPLICATES": "OK",
            "MAC_MOBILITY": "OK",
            "FDB_LOCAL": "OK",
        }
        self.analyzer.collection_meta = {
            "tor-a": {
                "timestamp": now,
                "sources": dict(good_sources),
                "samples": {},
                "arp_section_present": True,
            },
            "tor-b": {
                "timestamp": now,
                "sources": dict(good_sources, FDB_LOCAL="ERROR"),
                "samples": {},
                "arp_section_present": True,
            },
        }
        snapshot = ({"tor-a": "OK", "tor-b": "OK"}, time.time(), True)
        with mock.patch.object(duplicate_module, "read_asset_snapshot", return_value=snapshot), \
                mock.patch.object(duplicate_module, "asset_snapshot_is_valid", return_value=True):
            self.analyzer._finalize_coverage()

        self.assertEqual({"tor-a", "tor-b"}, self.analyzer.coverage["current"])
        self.assertEqual({"tor-a"}, self.analyzer.coverage["mac_current"])
        self.assertEqual({"tor-a", "tor-b"}, self.analyzer.coverage["mac_dad_current"])
        self.assertEqual({"tor-a", "tor-b"}, self.analyzer.coverage["mac_mobility_current"])
        self.assertEqual({"tor-a"}, self.analyzer.coverage["fdb_current"])
        self.assertTrue(self.analyzer.coverage["partial"])
        self.assertIn("tor-b:FDB_LOCAL_ERROR", self.analyzer.coverage["failures"])
        self.assertEqual(1, self.analyzer.summary()["coverage_current"])

    def test_overall_coverage_counts_same_hosts_not_minimum_set_size(self):
        self.analyzer.coverage.update({
            "current": {"tor-a"},
            "mac_current": {"tor-b"},
        })

        self.assertEqual(0, self.analyzer.summary()["coverage_current"])


class VniVlanResolutionTests(unittest.TestCase):
    """One EVPN finding = one row: a per-observer VLAN (or an L3 leaf's
    VLAN 0) must never split or mislabel a VNI-scoped duplicate."""

    VNI_LINE_LEAF = ("100008     L2   vxlan48               235      356      "
                     "17              vpn60030        0          br_default")
    VNI_LINE_TOR = ("100008     L2   vxlan48               270      0        "
                    "17              default         8          br_default")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"a-leaf-01", "z-tor-01"},
            "current": {"a-leaf-01", "z-tor-01"},
            "failures": [],
            "partial": False,
        }

    def test_vlan_zero_never_masks_the_real_vlan(self):
        self.analyzer._parse_vni_map([self.VNI_LINE_TOR])
        self.analyzer._parse_vni_map([self.VNI_LINE_LEAF])

        self.assertEqual("8", self.analyzer._vlan_of("100008"))

    def test_observers_with_and_without_vlan_mapping_share_one_record(self):
        mac = "3c:6d:66:15:b7:95"
        self.analyzer._parse_vni_map([self.VNI_LINE_LEAF])
        self.analyzer._parse_vni_map([self.VNI_LINE_TOR])
        # L3-gateway leaf only sees the MAC remote (no local VLAN mapping)
        self.analyzer._parse_mac_dup("a-leaf-01", [
            "VNI 100008 #MACs (local and remote) 1",
            "%s remote 10.0.0.13 972396/972395" % mac,
        ])
        self.analyzer._parse_mac_dup("z-tor-01", [
            "VNI 100008 #MACs (local and remote) 1",
            "%s local active swp31 972395/972394" % mac,
        ])

        self.analyzer._finalize()

        self.assertEqual([("100008", mac)], list(self.analyzer.mac_dups))
        rec = self.analyzer.mac_dups[("100008", mac)]
        self.assertEqual("8", rec["vlan"])
        self.assertEqual({"a-leaf-01", "z-tor-01"}, rec["flagged_hosts"])
        self.assertEqual({"z-tor-01": "swp31"}, rec["local"])
        self.assertIn("10.0.0.13", rec["vteps"])

    def test_parse_all_resolves_vlan_regardless_of_host_order(self):
        # The leaf file sorts (and parses) before the tor file; the VNI map
        # pre-pass must still label the finding with the tor's real VLAN.
        mac = "3c:6d:66:15:b7:95"
        dup_dir = Path(self.tmp.name) / "dup-data"
        (dup_dir / "a-leaf-01_dup.txt").write_text(
            "=== DUP VNI MAP ===\n%s\n"
            "__LLDPQ_DUP_COVERAGE__:VNI_MAP:OK\n"
            "=== DUP MAC ===\n"
            "VNI 100008 #MACs (local and remote) 1\n"
            "%s remote 10.0.0.13 972396/972395\n"
            "__LLDPQ_DUP_COVERAGE__:MAC_DUPLICATES:OK\n"
            % (self.VNI_LINE_LEAF, mac), encoding="utf-8")
        (dup_dir / "z-tor-01_dup.txt").write_text(
            "=== DUP VNI MAP ===\n%s\n"
            "__LLDPQ_DUP_COVERAGE__:VNI_MAP:OK\n"
            "=== DUP MAC ===\n"
            "VNI 100008 #MACs (local and remote) 1\n"
            "%s local active swp31 972395/972394\n"
            "__LLDPQ_DUP_COVERAGE__:MAC_DUPLICATES:OK\n"
            % (self.VNI_LINE_TOR, mac), encoding="utf-8")

        self.analyzer.parse_all()

        self.assertEqual([("100008", mac)], list(self.analyzer.mac_dups))
        self.assertEqual("8", self.analyzer.mac_dups[("100008", mac)]["vlan"])

    def test_unmapped_kernel_finding_shows_no_fake_vni(self):
        # Cross-device ARP finding on a VLAN with no known EVPN mapping:
        # the VLAN number must not be echoed into the VNI cell.
        for host, mac in (("a-leaf-01", "aa:bb:cc:dd:ee:01"),
                          ("z-tor-01", "aa:bb:cc:dd:ee:02")):
            self.analyzer._parse_neigh(host,
                "10.3.147.252 dev vlan210 lladdr %s REACHABLE" % mac)
        self.analyzer._merge_arp_conflicts()
        self.analyzer._finalize()

        self.assertIn(("210", "10.3.147.252"), self.analyzer.ip_dups)
        output = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")
        self.assertIn("vlan 210", report)
        self.assertIn("VNI &mdash;", report)

    def test_reverse_map_resolves_arp_only_finding_to_real_vni(self):
        self.analyzer._parse_vni_map([
            "200210     L2   vxlan48               1        1        "
            "1               default         210        br_default",
        ])
        for host, mac in (("a-leaf-01", "aa:bb:cc:dd:ee:01"),
                          ("z-tor-01", "aa:bb:cc:dd:ee:02")):
            self.analyzer._parse_neigh(host,
                "10.3.147.252 dev vlan210 lladdr %s REACHABLE" % mac)
        self.analyzer._merge_arp_conflicts()

        rec = self.analyzer.ip_dups[("200210", "10.3.147.252")]
        self.assertEqual("210", rec["vlan"])
        self.assertEqual("200210", rec["vni"])

    def test_kernel_evidence_folds_into_the_vni_record(self):
        # FDB/ARP evidence only knows VLAN 8; it must join the VNI 100008
        # record instead of opening a parallel VLAN-keyed row.
        mac = "3c:6d:66:15:b7:95"
        self.analyzer.coverage["fdb_current"] = {"a-leaf-01", "z-tor-01"}
        self.analyzer._parse_vni_map([self.VNI_LINE_TOR])
        self.analyzer._parse_mac_dup("z-tor-01", [
            "VNI 100008 #MACs (local and remote) 1",
            "%s local active swp31 972395/972394" % mac,
        ])
        self.analyzer.fdb_local[("8", mac)] = {"z-tor-01": "swp31"}

        self.analyzer._finalize()

        self.assertEqual([("100008", mac)], list(self.analyzer.mac_dups))


class ApipaCountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)

    def test_headline_counts_unique_endpoints_not_sightings(self):
        # EVPN syncs each APIPA neighbour to every VTEP: 2 endpoints seen by
        # 3 switches = 6 sightings but only 2 DHCP-failed devices.
        for host in ("tor-a", "tor-b", "tor-c"):
            self.analyzer._parse_neigh(host, "\n".join(
                "169.254.10.%d dev vlan8 lladdr aa:bb:cc:dd:ee:%02x REACHABLE"
                % (i, i) for i in (1, 2)))

        summary = self.analyzer.summary()
        self.assertEqual(2, summary["apipa_total"])
        self.assertEqual(6, summary["apipa_sightings"])

        output = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(output))
        report = output.read_text(encoding="utf-8")
        self.assertIn("2 unique endpoint(s), 6 sighting(s)", report)

    def test_same_endpoint_on_many_devs_counts_once(self):
        # The same 169.254 endpoint surfaces on the vlan SVI, the VRR sub-if
        # and physical/breakout ports across switches: still ONE endpoint.
        for host, dev in (("tor-a", "vlan8"), ("tor-a", "vlan8-v0"),
                          ("tor-b", "swp51"), ("tor-c", "swp43s1")):
            self.analyzer._parse_neigh(host,
                "169.254.10.1 dev %s lladdr aa:bb:cc:dd:ee:01 REACHABLE" % dev)

        summary = self.analyzer.summary()
        self.assertEqual(1, summary["apipa_total"])
        self.assertEqual(4, summary["apipa_sightings"])


if __name__ == "__main__":
    unittest.main()
