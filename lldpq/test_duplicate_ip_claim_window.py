#!/usr/bin/env python3
"""Keeps older evidence out of the "who claims this address" count.

On a live fabric the duplicate-IP page reported one address as claimed by 425
distinct MACs, and classed 424 of 426 rows as contested by two or more MACs
with only two rows left as single-MAC. The address really had 43 claimants at
that moment. Three things had been merged into the one MAC set the page
counted: zebra-log contenders spanning the whole collected log window (hours),
MACs carried over from previous collections, and -- the dominant term -- a
persisted memory that re-saved its own merged output under a fresh timestamp
every cycle, so it never expired and grew for as long as the finding lasted.
382 of those 425 MACs came from that memory alone.

An operator reads that number as "this many machines are fighting over this
address right now", so it must be assembled only from the collection being
rendered: the FRR duplicate rows, the switches' neighbour tables and the EVPN
ARP cache. The older evidence still earns its keep -- it locates the devices
involved when one collection catches only one end of a flap -- so it is kept
in a separate set, named as history on the page, and bounded by a window that
expires per MAC.

These tests fail if any of that evidence reaches the headline count, the
summary split, the section header or the export again, and if the retained
memory starts growing without bound a second time.
"""

import json
import re
import tempfile
import time
import unittest
from pathlib import Path

from duplicate_analyzer import DuplicateAnalyzer, IP_EVIDENCE_TTL_SEC

VLAN = "100"
VNI = "130100"
OBSERVER = "leaf-01"


def mac(index):
    """Distinct, locally-administered MACs; the value itself is irrelevant."""
    return "02:00:00:%02x:%02x:%02x" % (
        index // 65536 % 256, index // 256 % 256, index % 256)


def macs(count, offset=0):
    return [mac(offset + n) for n in range(count)]


class ClaimWindowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = self.new_analyzer()

    def new_analyzer(self):
        """A fresh analyzer over the same directory: the next collection cycle,
        reading back whatever state the previous one persisted."""
        analyzer = DuplicateAnalyzer(self.tmp.name)
        analyzer.coverage = {
            "expected": {OBSERVER}, "current": {OBSERVER},
            "failures": [], "partial": False,
        }
        analyzer.vni_to_vlan[VNI] = VLAN
        return analyzer

    # ---------- fixtures ----------
    def add_finding(self, ip, claimants, *, analyzer=None):
        """An address FRR currently reports as duplicate, with *claimants*
        naming the MACs its duplicate rows carry."""
        analyzer = analyzer or self.analyzer
        rec = analyzer._blank_ip(VLAN, VNI, ip)
        rec["flagged"] = True
        rec["macs"].update(claimants)
        rec["authoritative_macs"].update(claimants)
        rec["authoritative_hosts"].add(OBSERVER)
        analyzer.ip_dups[(VNI, ip)] = rec
        return rec

    def add_log_history(self, ip, contenders, *, analyzer=None):
        """Zebra "detected as duplicate" events: every MAC that tripped DAD on
        this address anywhere in the collected log window."""
        analyzer = analyzer or self.analyzer
        analyzer.log_events[(VNI, ip)] = {
            "count": 4 * len(contenders), "latest": None,
            "macs": set(contenders), "vteps": set(),
        }

    def add_remembered(self, ip, earlier, *, age=0.0, analyzer=None):
        """MACs the previous collections left behind for this address."""
        analyzer = analyzer or self.analyzer
        seen = time.time() - age
        analyzer.prev_ip_state["%s|%s" % (VLAN, ip)] = {
            "ports": {}, "macs": {m: seen for m in earlier}, "ts": seen,
        }

    def add_neighbour(self, ip, mac_hosts, *, analyzer=None):
        """This cycle's neighbour tables: which switches bind which MAC."""
        analyzer = analyzer or self.analyzer
        for address, hosts in mac_hosts.items():
            analyzer.arp_pairs.setdefault((VLAN, ip), {})[address] = set(hosts)

    def render(self, analyzer=None):
        analyzer = analyzer or self.analyzer
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        (analyzer or self.analyzer).export_html(str(out))
        return out.read_text(encoding="utf-8")

    def row(self, page, ip):
        table = page.split('id="ipt"', 1)[1].split("</table>", 1)[0]
        rows = [r for r in re.findall(r"<tr [^>]*>.*?</tr>", table)
                if ">%s</td>" % ip in r]
        self.assertEqual(1, len(rows), "expected one row for %s" % ip)
        return rows[0]

    def export_row(self, ip):
        payload = json.loads(
            (Path(self.tmp.name) / "export" / "duplicate.json")
            .read_text(encoding="utf-8"))
        return [r for r in payload["rows"]
                if r["finding_type"] == "ip" and r["address"] == ip][0]

    # ---------- the count itself ----------
    def test_log_contenders_are_not_claimants(self):
        """The log window is hours deep; on a churning address it names far
        more MACs than are answering for it at any one moment."""
        rec = self.add_finding("192.0.2.10", macs(1))
        self.add_log_history("192.0.2.10", macs(20, offset=100))

        self.analyzer._finalize()

        self.assertEqual(1, len(rec["macs"]))
        self.assertEqual(20, len(self.analyzer._historical_macs(rec)))
        self.assertTrue(self.analyzer._is_single_mac_ip(rec))
        self.assertFalse(self.analyzer._is_multi_mac_ip(rec))

    def test_remembered_macs_are_not_claimants(self):
        rec = self.add_finding("192.0.2.11", macs(1))
        self.add_remembered("192.0.2.11", macs(400, offset=1000))

        self.analyzer._finalize()

        self.assertEqual(1, len(rec["macs"]))
        self.assertEqual(400, len(self.analyzer._historical_macs(rec)))
        self.assertTrue(self.analyzer._is_single_mac_ip(rec))

    def test_the_summary_split_counts_only_present_claimants(self):
        """The shape of the live failure: every row grown past two MACs by
        history alone, leaving the single-MAC counter empty."""
        for offset in range(5):
            ip = "192.0.2.%d" % (20 + offset)
            self.add_finding(ip, macs(1, offset=offset))
            self.add_log_history(ip, macs(9, offset=200 + 10 * offset))
            self.add_remembered(ip, macs(50, offset=2000 + 100 * offset))
        contested = "192.0.2.30"
        self.add_finding(contested, macs(3, offset=50))

        self.analyzer._finalize()
        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_multi_mac"])
        self.assertEqual(5, summary["ip_single_mac"])

    def test_the_present_collection_supplies_the_second_claimant(self):
        """FRR's duplicate list names the MAC that tripped detection on each
        switch, not the incumbent it displaced, so a real conflict is often
        one FRR MAC plus another one the neighbour tables hold."""
        rec = self.add_finding("192.0.2.40", [mac(1)])
        self.add_neighbour("192.0.2.40", {
            mac(1): [OBSERVER], mac(2): [OBSERVER, "leaf-02"],
        })

        self.analyzer._finalize()

        self.assertEqual({mac(1), mac(2)}, rec["macs"])
        self.assertTrue(self.analyzer._is_multi_mac_ip(rec))

    def test_the_evpn_arp_cache_counts_as_a_present_binding(self):
        """It is the same sample as the neighbour tables, one layer up: what
        the control plane binds to the address in this cycle."""
        rec = self.add_finding("192.0.2.41", [mac(1)])
        self.analyzer.ip_mob[(VNI, "192.0.2.41")] = {
            "seq": 42, "macs": {mac(1), mac(3)}, "vteps": set(), "vni": VNI,
        }

        self.analyzer._finalize()

        self.assertEqual({mac(1), mac(3)}, rec["macs"])

    # ---------- what the page says ----------
    def test_the_row_counts_claimants_and_names_the_history_apart(self):
        self.add_finding("192.0.2.50", macs(2))
        self.add_log_history("192.0.2.50", macs(30, offset=300))
        self.analyzer._finalize()

        row = self.row(self.render(), "192.0.2.50")

        self.assertIn("data-mac-count='2'", row)
        self.assertIn("2 distinct MACs claim it in this collection", row)
        self.assertIn("+30 seen earlier", row)
        self.assertNotIn("32", row)

    def test_a_single_claimant_row_reports_its_history_as_history(self):
        self.add_finding("192.0.2.51", macs(1))
        self.add_remembered("192.0.2.51", macs(7, offset=400))
        self.analyzer._finalize()

        row = self.row(self.render(), "192.0.2.51")

        self.assertIn("Endpoint mobility", row)
        self.assertIn("no second claimant in this collection", row)
        self.assertIn("7 other MAC(s) held it in the last %dh"
                      % (IP_EVIDENCE_TTL_SEC // 3600), row)

    def test_the_widest_claim_is_ranked_on_present_claimants(self):
        """Ranking on retained evidence promoted whichever address had simply
        been in the list longest, not the one most devices are claiming."""
        self.add_finding("192.0.2.60", macs(4))
        self.add_finding("192.0.2.61", macs(3, offset=60))
        self.add_remembered("192.0.2.61", macs(90, offset=3000))
        self.analyzer._finalize()

        header = [line for line in self.render().splitlines()
                  if "Duplicate IPs (per VLAN / VNI)" in line][0]

        self.assertIn("192.0.2.60", header)
        self.assertIn("claimed in this collection by 4 distinct MACs", header)
        self.assertNotIn("192.0.2.61", header)

    def test_the_export_separates_the_two_sets(self):
        self.add_finding("192.0.2.70", macs(2))
        self.add_log_history("192.0.2.70", macs(11, offset=500))
        self.analyzer._finalize()
        self.render()

        row = self.export_row("192.0.2.70")

        self.assertEqual(2, row["mac_count"])
        self.assertEqual(2, len(row["macs"].split()))
        self.assertEqual(11, row["historical_mac_count"])
        self.assertEqual(11, len(row["historical_macs"].split()))

    # ---------- the memory stays bounded ----------
    def test_the_memory_does_not_grow_when_the_claimants_do_not(self):
        """The live failure was a ratchet: each cycle wrote back its own merged
        output under a fresh stamp, so nothing ever expired."""
        claimants = macs(2)
        for cycle in range(6):
            analyzer = self.new_analyzer()
            ip = "192.0.2.80"
            self.add_finding(ip, claimants, analyzer=analyzer)
            # a different contender trips DAD on every cycle
            self.add_log_history(ip, macs(3, offset=600 + 10 * cycle),
                                 analyzer=analyzer)
            analyzer._finalize()

        remembered = analyzer.new_ip_state["%s|192.0.2.80" % VLAN]["macs"]
        self.assertEqual(set(claimants), set(remembered))

    def test_a_mac_that_stops_claiming_expires_from_the_memory(self):
        rec = self.add_finding("192.0.2.81", [mac(1)])
        self.add_remembered("192.0.2.81", [mac(2)],
                            age=IP_EVIDENCE_TTL_SEC - 60)
        self.analyzer._finalize()
        self.assertIn(mac(2), self.analyzer._historical_macs(rec))

        analyzer = self.new_analyzer()
        rec = self.add_finding("192.0.2.81", [mac(1)], analyzer=analyzer)
        self.add_remembered("192.0.2.81", [mac(2)],
                            age=IP_EVIDENCE_TTL_SEC + 60, analyzer=analyzer)
        analyzer._finalize()

        self.assertEqual(set(), analyzer._historical_macs(rec))
        self.assertNotIn(mac(2),
                         analyzer.new_ip_state["%s|192.0.2.81" % VLAN]["macs"])

    def test_state_written_before_the_per_mac_stamps_still_loads(self):
        """Upgrading must not throw away the memory of a running fabric."""
        rec = self.add_finding("192.0.2.82", [mac(1)])
        self.analyzer.prev_ip_state["%s|192.0.2.82" % VLAN] = {
            "ports": {}, "macs": [mac(2), mac(3)], "ts": time.time(),
        }

        self.analyzer._finalize()

        self.assertEqual({mac(2), mac(3)},
                         self.analyzer._historical_macs(rec))

    # ---------- the memory still earns its keep ----------
    def test_history_still_locates_the_other_end_of_a_flap(self):
        """The whole reason the older evidence is retained: one collection
        rarely catches both devices, so the contender's port comes from the
        MACs this cycle no longer sees."""
        rec = self.add_finding("192.0.2.90", [mac(1)])
        self.add_log_history("192.0.2.90", [mac(2)])
        self.analyzer.fdb_local[(VLAN, mac(2))] = {"leaf-09": "swp7"}

        self.analyzer._finalize()

        self.assertIn("leaf-09:swp7", rec["ports"])
        self.assertNotIn(mac(2), rec["macs"])


if __name__ == "__main__":
    unittest.main()
