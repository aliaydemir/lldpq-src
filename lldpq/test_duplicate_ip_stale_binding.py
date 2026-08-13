#!/usr/bin/env python3
"""A binding the switch stopped refreshing is not a claim on the address.

Keeping the claim count to the present collection (test_duplicate_ip_claim_window)
left one loose end: the neighbour tables are a sample of this cycle, but not
every entry in them is live. A STALE entry means the switch has not heard from
that endpoint within its reachability window and has not re-ARPed for it yet, so
the MAC may well be the party that already lost the address. Counting it reports
two endpoints fighting over an address only one of them is answering for, which
on a live fabric put 56 addresses in the contested column that had a single
endpoint replying (a split of 356/68 where 300/124 is the truth).

So a MAC counts as a claimant when this collection supports it with anything a
switch is actually maintaining -- an FRR duplicate row, the EVPN ARP cache, or a
neighbour entry that is REACHABLE / DELAY / PROBE / PERMANENT / NOARP (the state
EVPN-synced entries carry). STALE-only bindings, and entries with no usable
binding at all, are kept as evidence instead: they still resolve the device's
port, they show under the MAC list as "+N stale binding", and the note says the
switches disagree while only one MAC is answering. An entry whose state cannot
be parsed is trusted, so an unfamiliar output format cannot quietly empty the
column.

These tests fail if a stale binding is counted as a claimant again, if the same
binding stops counting once it goes REACHABLE, or if excluding it loses the
evidence instead of relocating it.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from duplicate_analyzer import DuplicateAnalyzer

VLAN = "100"
VNI = "130100"
OBSERVER = "leaf-01"
PEER = "leaf-02"
INCUMBENT = "02:00:00:00:00:01"
CONTENDER = "02:00:00:00:00:02"


class StaleBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = self.new_analyzer()

    def new_analyzer(self):
        analyzer = DuplicateAnalyzer(self.tmp.name)
        analyzer.coverage = {
            "expected": {OBSERVER, PEER}, "current": {OBSERVER, PEER},
            "failures": [], "partial": False,
        }
        analyzer.vni_to_vlan[VNI] = VLAN
        return analyzer

    # ---------- fixtures ----------
    def add_finding(self, ip, claimant=INCUMBENT, *, analyzer=None):
        """An address FRR currently reports as duplicate, naming the MAC that
        tripped detection -- never the incumbent it displaced."""
        analyzer = analyzer or self.analyzer
        rec = analyzer._blank_ip(VLAN, VNI, ip)
        rec["flagged"] = True
        rec["macs"].add(claimant)
        rec["authoritative_macs"].add(claimant)
        rec["authoritative_hosts"].add(OBSERVER)
        analyzer.ip_dups[(VNI, ip)] = rec
        return rec

    def neigh_line(self, ip, mac, state):
        return "%s dev vlan%s lladdr %s %s" % (ip, VLAN, mac, state)

    def observe(self, host, *lines, analyzer=None):
        """Feed one switch's 'ip -4 neigh show' output through the parser, so
        the state reaching the analyzer is the one the switch actually printed."""
        (analyzer or self.analyzer)._parse_neigh(host, "\n".join(lines) + "\n")

    def render(self):
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(out))
        return out.read_text(encoding="utf-8")

    def row(self, page, ip):
        table = page.split('id="ipt"', 1)[1].split("</table>", 1)[0]
        rows = [r for r in re.findall(r"<tr [^>]*>.*?</tr>", table)
                if ">%s</td>" % ip in r]
        self.assertEqual(1, len(rows), "expected one row for %s" % ip)
        return rows[0]

    # ---------- the gate itself ----------
    def test_a_stale_only_second_mac_leaves_a_single_claimant(self):
        ip = "192.0.2.10"
        rec = self.add_finding(ip)
        self.observe(OBSERVER, self.neigh_line(ip, INCUMBENT, "REACHABLE"))
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))

        self.analyzer._finalize()

        self.assertEqual({INCUMBENT}, rec["macs"])
        self.assertTrue(self.analyzer._is_single_mac_ip(rec))
        self.assertFalse(self.analyzer._is_multi_mac_ip(rec))

    def test_the_same_binding_reachable_makes_two_claimants(self):
        """The paired case: only the state differs, and it must be the state
        that decides -- otherwise the gate is just dropping the second MAC."""
        ip = "192.0.2.11"
        rec = self.add_finding(ip)
        self.observe(OBSERVER, self.neigh_line(ip, INCUMBENT, "REACHABLE"))
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "REACHABLE"))

        self.analyzer._finalize()

        self.assertEqual({INCUMBENT, CONTENDER}, rec["macs"])
        self.assertTrue(self.analyzer._is_multi_mac_ip(rec))
        self.assertEqual(set(), self.analyzer._stale_binding_macs(rec))

    def test_one_switch_still_hearing_from_it_is_enough(self):
        """Only the switch nearest the endpoint keeps a fresh entry; the far
        side ages its copy out. That is one live endpoint, not none."""
        ip = "192.0.2.12"
        rec = self.add_finding(ip)
        self.observe(OBSERVER, self.neigh_line(ip, CONTENDER, "STALE"))
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "REACHABLE"))

        self.analyzer._finalize()

        self.assertIn(CONTENDER, rec["macs"])
        self.assertEqual(set(), self.analyzer._stale_binding_macs(rec))

    def test_the_states_a_switch_maintains_all_count(self):
        """DELAY/PROBE are mid-verification, PERMANENT is configured, and NOARP
        is what EVPN installs for a remotely learned neighbour -- all of them
        are bindings the switch is holding now."""
        ip = "192.0.2.20"
        for state in ("DELAY", "PROBE", "PERMANENT", "NOARP"):
            analyzer = self.new_analyzer()
            rec = self.add_finding(ip, analyzer=analyzer)
            self.observe(PEER, self.neigh_line(ip, CONTENDER, state),
                         analyzer=analyzer)

            analyzer._finalize()

            self.assertEqual({INCUMBENT, CONTENDER}, rec["macs"],
                             "%s must count as a present binding" % state)

    def test_an_evpn_synced_entry_carries_its_flags_before_the_state(self):
        """Real output puts flags between the MAC and the state, so a parser
        that reads the next word after the lladdr sees "extern_learn"."""
        ip = "192.0.2.30"
        rec = self.add_finding(ip)
        self.observe(PEER, "%s dev vlan%s lladdr %s extern_learn NOARP "
                           "proto zebra" % (ip, VLAN, CONTENDER))

        self.analyzer._finalize()

        self.assertEqual({INCUMBENT, CONTENDER}, rec["macs"])

    def test_an_unreadable_state_is_trusted(self):
        """A binding is evidence; an output format we cannot classify must not
        silently subtract from the count."""
        ip = "192.0.2.31"
        rec = self.add_finding(ip)
        self.observe(PEER, "%s dev vlan%s lladdr %s" % (ip, VLAN, CONTENDER))

        self.analyzer._finalize()

        self.assertEqual({INCUMBENT, CONTENDER}, rec["macs"])

    def test_a_stale_entry_does_not_veto_a_stronger_source(self):
        """FRR's duplicate row and the EVPN ARP cache outrank the kernel's
        ageing copy of the same binding."""
        ip = "192.0.2.32"
        rec = self.add_finding(ip)
        self.analyzer.ip_mob[(VNI, ip)] = {
            "seq": 12, "macs": {CONTENDER}, "vteps": set(), "vni": VNI,
        }
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))

        self.analyzer._finalize()

        self.assertEqual({INCUMBENT, CONTENDER}, rec["macs"])
        self.assertEqual(set(), self.analyzer._stale_binding_macs(rec))

    # ---------- the excluded binding is not lost ----------
    def test_the_stale_binding_stays_available_as_evidence(self):
        ip = "192.0.2.40"
        rec = self.add_finding(ip)
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))
        self.analyzer.fdb_local[(VLAN, CONTENDER)] = {"leaf-09": "swp7"}

        self.analyzer._finalize()

        self.assertEqual({CONTENDER}, self.analyzer._stale_binding_macs(rec))
        self.assertIn(CONTENDER, self.analyzer._evidence_macs(rec))
        self.assertIn("leaf-09:swp7", rec["ports"])
        # It is a present-cycle binding, not something remembered from before.
        self.assertEqual(set(), self.analyzer._historical_macs(rec))

    def test_the_stale_binding_survives_into_the_next_collection(self):
        """It is something this cycle saw, so it decays on the same clock as a
        claimant instead of disappearing the moment the entry ages out."""
        ip = "192.0.2.43"
        self.add_finding(ip)
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))
        self.analyzer._finalize()

        later = self.new_analyzer()
        later.prev_ip_state = self.analyzer.new_ip_state
        rec = self.add_finding(ip, analyzer=later)
        later._finalize()

        self.assertEqual({CONTENDER}, later._historical_macs(rec))
        self.assertEqual({INCUMBENT}, rec["macs"])

    def test_the_row_reports_the_stale_binding_apart_from_the_count(self):
        ip = "192.0.2.41"
        self.add_finding(ip)
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))

        self.analyzer._finalize()
        row = self.row(self.render(), ip)

        self.assertIn("data-mac-count='1'", row)
        self.assertIn("+1 stale binding", row)
        self.assertIn("hold it only in a stale entry", row)

    def test_the_export_reports_the_stale_binding_in_its_own_field(self):
        ip = "192.0.2.42"
        self.add_finding(ip)
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))
        self.analyzer._finalize()
        self.render()

        payload = json.loads(
            (Path(self.tmp.name) / "export" / "duplicate.json")
            .read_text(encoding="utf-8"))
        row = [r for r in payload["rows"]
               if r["finding_type"] == "ip" and r["address"] == ip][0]

        self.assertEqual(1, row["mac_count"])
        self.assertEqual(1, row["stale_binding_mac_count"])
        self.assertEqual(CONTENDER, row["stale_binding_macs"])
        self.assertEqual(0, row["historical_mac_count"])

    def test_a_cross_device_row_says_which_side_is_answering(self):
        """No FRR row here: the switches simply disagree. The row is still
        worth listing, but it must not claim two endpoints are answering."""
        ip = "192.0.2.50"
        self.observe(OBSERVER, self.neigh_line(ip, INCUMBENT, "REACHABLE"))
        self.observe(PEER, self.neigh_line(ip, CONTENDER, "STALE"))
        self.analyzer._merge_arp_conflicts()

        self.analyzer._finalize()
        rec = self.analyzer.ip_dups[(VNI, ip)]
        row = self.row(self.render(), ip)

        self.assertTrue(self.analyzer._is_arp_observed_ip(rec))
        self.assertEqual({INCUMBENT}, rec["macs"])
        self.assertIn("switches disagree on this address", row)
        self.assertIn("1 MAC claims it in this collection", row)
        self.assertNotIn("2 distinct MACs", row)


if __name__ == "__main__":
    unittest.main()
