#!/usr/bin/env python3
"""Tells a contested address apart from an endpoint that only moves.

The duplicate-IP table listed every finding the same way, so on a real fabric
roughly three hundred rows all read as "duplicate" and had to be triaged by
hand against raw switch output. Splitting them by how many distinct MACs answer
for each address settles it: two or more MACs means two devices claim one
address, while a single MAC means one endpoint moved often enough to trip
FRR's duplicate-address detection, which is not an address conflict at all.

That single field also surfaced two unrelated problems that the flat list hid:
one address answered by nineteen MACs and reported by fifty switches (a pile of
devices left on one factory-default address in a single broadcast domain), and a
group of addresses each answered by four to six MACs on a handful of leaves
(overlapping IPAM in an overlay). Both are reproduced below by shape, because
the shape is what the page has to make visible.

Anycast/VRR gateway addresses are answered by several switch interfaces by
design and belong to neither class; the tests keep them out of both counters.

The count is of the claimants in the collection being rendered. Two companion
files hold the tests that keep everything else out of it:
test_duplicate_ip_claim_window for evidence from earlier collections, and
test_duplicate_ip_stale_binding for bindings this collection has but no switch
is refreshing.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from duplicate_analyzer import DuplicateAnalyzer, IP_CLUSTER_MIN_MACS

MAC_COUNT_HEADER = "Claiming MACs (now)"

# A factory default left in place: one address, many devices, seen fabric-wide.
DEFAULT_ADDRESS = "192.0.2.123"
DEFAULT_ADDRESS_MACS = 19
DEFAULT_ADDRESS_SWITCHES = 50
# Overlapping IPAM in an overlay: a block of addresses, a few claimants each,
# concentrated on the leaves that carry the workload.
OVERLAY_MACS = (4, 5, 6, 5, 4)
OVERLAY_SWITCHES = 8


def mac(index):
    """Distinct, locally-administered MACs; the value itself is irrelevant."""
    return "02:00:00:%02x:%02x:%02x" % (
        index // 65536 % 256, index // 256 % 256, index % 256)


def switches(count, offset=0):
    return ["switch-%02d" % (offset + n) for n in range(1, count + 1)]


class MacCountTriageTests(unittest.TestCase):
    VLAN = "123"
    VNI = "700123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.hosts = switches(DEFAULT_ADDRESS_SWITCHES + OVERLAY_SWITCHES)
        self.analyzer.coverage = {
            "expected": set(self.hosts),
            "current": set(self.hosts),
            "failures": [],
            "partial": False,
        }
        self.analyzer.vni_to_vlan[self.VNI] = self.VLAN
        self.next_mac = 0

    # ---------- fixtures ----------
    def new_macs(self, count):
        macs = [mac(self.next_mac + n) for n in range(count)]
        self.next_mac += count
        return macs

    def add_frr_finding(self, ip, mac_count, *, hosts=None, vlan=None,
                        vni=None):
        """An address FRR reports as duplicate, answered by *mac_count* MACs."""
        rec = self.analyzer._blank_ip(vlan or self.VLAN, vni or self.VNI, ip)
        rec.update({"seq": 0, "flagged": True, "recency": None, "delta": 0})
        macs = self.new_macs(mac_count)
        rec["macs"].update(macs)
        rec["authoritative_macs"].update(macs)
        rec["authoritative_hosts"].update(hosts or self.hosts[:1])
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[(rec["vni"], ip)] = rec
        return rec

    def add_gateway(self, ip):
        """A VRR/anycast address: two switch interfaces, no endpoint behind a
        port, no FRR duplicate row."""
        rec = self.analyzer._blank_ip(self.VLAN, self.VNI, ip)
        rec.update({"seq": 0, "flagged": False, "recency": None, "delta": 0})
        rec["arp_observed"] = True
        rec["macs"].update(self.new_macs(2))
        rec["arp_hosts"].update(self.hosts[:2])
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[(self.VNI, ip)] = rec
        return rec

    def add_default_address_cluster(self):
        return self.add_frr_finding(
            DEFAULT_ADDRESS, DEFAULT_ADDRESS_MACS,
            hosts=switches(DEFAULT_ADDRESS_SWITCHES))

    def add_overlay_cluster(self):
        hosts = switches(OVERLAY_SWITCHES, offset=DEFAULT_ADDRESS_SWITCHES)
        return [
            self.add_frr_finding("198.51.100.%d" % (10 + index), count,
                                 hosts=hosts, vlan="44", vni="700044")
            for index, count in enumerate(OVERLAY_MACS)
        ]

    # ---------- rendering helpers ----------
    def render(self):
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(out))
        return out.read_text(encoding="utf-8")

    def ip_table(self, page):
        return page.split('id="ipt"', 1)[1].split("</table>", 1)[0]

    def ip_rows(self, page):
        return re.findall(r"<tr [^>]*>.*?</tr>", self.ip_table(page))

    def ip_row(self, page, ip):
        rows = [row for row in self.ip_rows(page) if ">%s</td>" % ip in row]
        self.assertEqual(1, len(rows), "expected one row for %s" % ip)
        return rows[0]

    def ip_headers(self, page):
        head = self.ip_table(page).split("<thead>", 1)[1].split("</thead>", 1)[0]
        return re.findall(r"<th>(.*?)</th>", head)

    def mac_count_cell(self, page, row):
        column = self.ip_headers(page).index(MAC_COUNT_HEADER)
        return re.findall(r"<td[^>]*>(.*?)</td>", row)[column]

    def mac_count_cells(self, page):
        """The claiming-MAC-count cell of every rendered row, as written."""
        return [self.mac_count_cell(page, row) for row in self.ip_rows(page)]

    # ---------- classification ----------
    def test_several_macs_on_one_address_is_a_duplicate_address(self):
        rec = self.add_frr_finding("192.0.2.10", 2)
        self.assertTrue(self.analyzer._is_multi_mac_ip(rec))
        self.assertFalse(self.analyzer._is_single_mac_ip(rec))

    def test_one_mac_on_one_address_is_mobility_only(self):
        rec = self.add_frr_finding("192.0.2.11", 1)
        self.assertTrue(self.analyzer._is_single_mac_ip(rec))
        self.assertFalse(self.analyzer._is_multi_mac_ip(rec))

    def test_a_gateway_address_is_neither_class(self):
        rec = self.add_gateway("192.0.2.62")
        self.assertFalse(self.analyzer._is_multi_mac_ip(rec))
        self.assertFalse(self.analyzer._is_single_mac_ip(rec))

    def test_context_the_table_does_not_show_is_not_classified(self):
        """Mobility/log context is not a listed finding, so it cannot be
        triaged as one either."""
        rec = self.analyzer._blank_ip(self.VLAN, self.VNI, "192.0.2.12")
        rec["macs"].update(self.new_macs(2))
        rec["mobility"] = True
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[(self.VNI, "192.0.2.12")] = rec

        self.assertFalse(self.analyzer._is_multi_mac_ip(rec))
        self.assertFalse(self.analyzer._is_single_mac_ip(rec))
        self.assertEqual(0, self.analyzer.summary()["ip_multi_mac"])

    # ---------- summary counters ----------
    def test_the_counters_split_the_findings(self):
        self.add_default_address_cluster()
        self.add_overlay_cluster()
        for offset in range(3):
            self.add_frr_finding("192.0.2.%d" % (20 + offset), 1)

        summary = self.analyzer.summary()

        self.assertEqual(1 + len(OVERLAY_MACS), summary["ip_multi_mac"])
        self.assertEqual(3, summary["ip_single_mac"])

    def test_a_gateway_row_inflates_neither_counter(self):
        self.add_gateway("192.0.2.62")
        self.add_frr_finding("192.0.2.13", 2)

        summary = self.analyzer.summary()

        self.assertEqual(1, summary["ip_multi_mac"])
        self.assertEqual(0, summary["ip_single_mac"])
        self.assertEqual(1, summary["ip_gateway_expected"])

    def test_the_two_counters_and_the_gateways_account_for_every_row(self):
        self.add_default_address_cluster()
        self.add_overlay_cluster()
        self.add_frr_finding("192.0.2.14", 1)
        self.add_gateway("192.0.2.62")
        page = self.render()

        summary = self.analyzer.summary()

        self.assertEqual(
            len(self.ip_rows(page)),
            summary["ip_multi_mac"] + summary["ip_single_mac"]
            + summary["ip_gateway_expected"])

    def test_the_counters_reach_the_machine_summary(self):
        self.add_overlay_cluster()
        self.add_frr_finding("192.0.2.15", 1)
        page = self.render()

        self.assertIn('data-ip-multi-mac="%d"' % len(OVERLAY_MACS), page)
        self.assertIn('data-ip-single-mac="1"', page)

        summary = json.loads(
            (Path(self.tmp.name) / "summary" / "duplicate-summary.json")
            .read_text(encoding="utf-8"))
        self.assertEqual(len(OVERLAY_MACS), summary["ip_multi_mac"])
        self.assertEqual(1, summary["ip_single_mac"])

    # ---------- what the operator reads ----------
    def test_a_multi_mac_row_names_the_class_and_the_count(self):
        self.add_frr_finding("192.0.2.16", 4)
        row = self.ip_row(self.render(), "192.0.2.16")

        self.assertIn("duplicate address", row)
        self.assertIn("4 distinct MACs claim it", row)

    def test_a_single_mac_row_never_reads_as_a_conflict(self):
        self.add_frr_finding("192.0.2.17", 1)
        row = self.ip_row(self.render(), "192.0.2.17")

        self.assertIn("Endpoint mobility", row)
        self.assertNotIn("duplicate address", row.lower())
        self.assertNotIn("conflict", row.lower())

    def test_a_single_mac_row_still_says_the_flag_is_latched(self):
        """The quiesced/latched wording is what tells an operator the FRR flag
        is still set and has to be cleared."""
        self.add_frr_finding("192.0.2.18", 1)
        self.assertIn("quiesced / latched", self.ip_row(self.render(), "192.0.2.18"))

    def test_the_gateway_note_is_unchanged(self):
        self.add_gateway("192.0.2.62")
        page = self.render()
        row = self.ip_row(page, "192.0.2.62")

        self.assertIn("anycast/VRR gateway address", row)
        self.assertIn("data-kind='gateway'", row)
        self.assertIn("expected-row", row)
        self.assertIn("Show expected (1)", page)

    # ---------- the column and its sort ----------
    def test_every_row_carries_its_distinct_mac_count(self):
        self.add_default_address_cluster()
        self.add_frr_finding("192.0.2.19", 1)
        page = self.render()

        cluster = self.ip_row(page, DEFAULT_ADDRESS)
        self.assertEqual(str(DEFAULT_ADDRESS_MACS),
                         self.mac_count_cell(page, cluster))
        self.assertIn("data-mac-count='%d'" % DEFAULT_ADDRESS_MACS, cluster)

        single = self.ip_row(page, "192.0.2.19")
        self.assertEqual("1", self.mac_count_cell(page, single))
        self.assertIn("data-mac-count='1'", single)

    def test_the_column_is_sorted_as_a_number(self):
        """A text sort puts "6" above "19" and buries the worst cluster."""
        self.add_default_address_cluster()
        self.add_overlay_cluster()
        self.add_frr_finding("192.0.2.21", 1)
        page = self.render()

        numeric = re.search(
            r"var num\s*=\s*/([^/]+)/i\.test\(th\.innerText\)", page).group(1)
        self.assertTrue(re.search(numeric, MAC_COUNT_HEADER, re.I),
                        "the %s header is not sorted numerically"
                        % MAC_COUNT_HEADER)

        cells = self.mac_count_cells(page)
        self.assertEqual(str(DEFAULT_ADDRESS_MACS),
                         sorted(cells, key=int, reverse=True)[0])
        self.assertNotEqual(sorted(cells, key=int, reverse=True)[0],
                            sorted(cells, reverse=True)[0])

    def test_the_cell_carries_a_numeric_sort_key(self):
        self.add_default_address_cluster()
        row = self.ip_row(self.render(), DEFAULT_ADDRESS)

        self.assertIn("<td class='mono' data-sort='%d'>%d</td>"
                      % (DEFAULT_ADDRESS_MACS, DEFAULT_ADDRESS_MACS), row)

    # ---------- the strongest cluster ----------
    def test_the_widest_claim_is_named_above_the_table(self):
        self.add_default_address_cluster()
        self.add_overlay_cluster()
        page = self.render()
        header = [line for line in page.splitlines()
                  if "Duplicate IPs (per VLAN / VNI)" in line][0]

        self.assertIn(DEFAULT_ADDRESS, header)
        self.assertIn("%d distinct MACs" % DEFAULT_ADDRESS_MACS, header)
        self.assertIn("reported by %d switch(es)" % DEFAULT_ADDRESS_SWITCHES,
                      header)
        self.assertIn("vlan %s / VNI %s" % (self.VLAN, self.VNI), header)

    def test_an_ordinary_pair_is_not_announced_as_a_cluster(self):
        for offset in range(4):
            self.add_frr_finding("192.0.2.%d" % (30 + offset),
                                 IP_CLUSTER_MIN_MACS - 1)

        self.assertNotIn("widest claim", self.render())

    def test_the_overlay_cluster_is_reported_per_address(self):
        """Each overlapping-IPAM address stands on its own; the count is what
        groups them, so every row has to carry it."""
        self.add_overlay_cluster()
        page = self.render()

        for index, count in enumerate(OVERLAY_MACS):
            row = self.ip_row(page, "198.51.100.%d" % (10 + index))
            self.assertIn("data-mac-count='%d'" % count, row)
            self.assertIn("%d distinct MACs claim it" % count, row)

    # ---------- machine export ----------
    def test_the_export_carries_the_count_per_finding(self):
        self.add_default_address_cluster()
        self.render()

        payload = json.loads(
            (Path(self.tmp.name) / "export" / "duplicate.json")
            .read_text(encoding="utf-8"))
        rows = {row["address"]: row for row in payload["rows"]
                if row["finding_type"] == "ip"}

        self.assertIn("mac_count", payload["columns"])
        self.assertEqual(DEFAULT_ADDRESS_MACS,
                         rows[DEFAULT_ADDRESS]["mac_count"])


if __name__ == "__main__":
    unittest.main()
