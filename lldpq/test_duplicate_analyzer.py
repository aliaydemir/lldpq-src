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
        self.analyzer.ip_dups[("8", ip)] = rec
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

        rec = self.analyzer.ip_dups[("8", "10.2.240.88")]
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
        self.analyzer.mac_mob[(self.VLAN, mac)] = {
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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
        self.analyzer.ip_mob[(self.VLAN, ip)] = {
            "seq": 1297,
            "macs": {mac},
            "vteps": set(),
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        ip_rec = self.analyzer.ip_dups[(self.VLAN, ip)]
        mac_rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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
        self.analyzer.mac_mob[(self.VLAN, mac)] = {
            "seq": 1006,
            "seq_by_host": {"tor-a": 1006},
            "hosts": {"tor-a"},
            "vteps": set(),
            "ports": {"tor-a": "swp31"},
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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
        self.analyzer.mac_mob[(self.VLAN, mac)] = {
            "seq": 20002,
            "seq_by_host": {"tor-b": 20002},
            "hosts": {"tor-b"},
            "vteps": set(),
            "ports": {"tor-b": "swp32"},
            "vni": self.VNI,
        }

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
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
        self.analyzer.ip_dups[(self.VLAN, ip)] = ip_rec

        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(self.VLAN, mac)]
        self.assertTrue(rec["participates_in_ip_conflict"])
        self.assertEqual("ip-conflict-participant", rec["classification"])
        self.assertIn("Participant in current authoritative IP DAD finding", self.mac_table_html())

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


if __name__ == "__main__":
    unittest.main()
