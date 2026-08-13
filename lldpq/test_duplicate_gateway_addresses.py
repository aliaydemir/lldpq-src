#!/usr/bin/env python3
"""Separates anycast gateway addresses from endpoints squatting on them.

A VRR pair repeats one SVI address on every switch carrying the VLAN, so
several switch interfaces legitimately answer for it. Judged by MAC count alone
that looks exactly like a duplicate, and on a real fabric those rows filled the
page while describing intended configuration.

The bridge FDB tells the two apart: a responder behind a swp/bond port is
plugged into the fabric, a responder behind no port is a routed interface. When
every responder is a routed interface the address is a gateway; when one of them
sits behind an access port, a device is using an address the fabric owns, which
is a genuine and self-evidencing conflict.

What kind of thing a responder is does not depend on how recently it spoke, so
this question is asked over every MAC the collection binds to the address, the
ones held only in a STALE neighbour entry included. Asking it over the live
claimants instead put real gateway addresses back in the default view of a
healthy fabric: a VRR peer's SVI is idle by nature, its entry is STALE most of
the time, and without it the pair looked like a single responder.
"""

import tempfile
import unittest
from pathlib import Path

from duplicate_analyzer import DuplicateAnalyzer, SEQ_WARN


SWITCH_A = "20:4d:52:48:b3:ff"
SWITCH_B = "20:4d:52:4e:d1:ff"
ENDPOINT = "7c:c2:55:92:51:e8"
ENDPOINT_2 = "28:01:cd:11:22:33"


class GatewayAddressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"leaf-01", "leaf-02"},
            "current": {"leaf-01", "leaf-02"},
            "failures": [],
            "partial": False,
        }

    def add_arp_row(self, ip, macs, *, seq=0, behind_ports=None, stale=()):
        """One cross-device ARP observation; behind_ports maps MAC -> host:port.

        *stale* names responders this collection holds only in a STALE
        neighbour entry, which is where the analyzer puts them: present
        evidence, but not counted as a live claim.
        """
        rec = self.analyzer._blank_ip("7", "100007", ip)
        rec.update({"seq": seq, "flagged": False, "recency": None, "delta": 0})
        rec["arp_observed"] = True
        rec["macs"].update(m for m in macs if m not in stale)
        rec["stale_macs"].update(stale)
        for mac, (host, port) in (behind_ports or {}).items():
            self.analyzer.fdb_local.setdefault(("7", mac), {})[host] = port
        rec["severity"] = self.analyzer._ip_sev(rec)
        self.analyzer.ip_dups[("100007", ip)] = rec
        return rec

    # ---------- classification ----------
    def test_two_switch_interfaces_are_a_gateway_address(self):
        rec = self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        self.assertTrue(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))

    def test_an_endpoint_on_a_switch_address_is_a_real_conflict(self):
        rec = self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        self.assertTrue(self.analyzer._is_endpoint_on_svi_ip(rec))
        self.assertFalse(self.analyzer._is_router_only_ip(rec))

    def test_two_endpoints_remain_a_classic_duplicate(self):
        """Neither new class may swallow the ordinary host-versus-host case."""
        rec = self.add_arp_row(
            "10.2.243.30", [ENDPOINT, ENDPOINT_2],
            behind_ports={
                ENDPOINT: ("leaf-01", "swp8"),
                ENDPOINT_2: ("leaf-02", "swp9"),
            },
        )
        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))
        self.assertEqual("WARNING", rec["severity"])

    def test_a_single_responder_is_neither_class(self):
        rec = self.add_arp_row("10.2.243.31", [SWITCH_A])
        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))

    # ---------- a quiet responder is still a responder ----------
    def test_an_idle_vrr_peer_still_makes_it_a_gateway_address(self):
        """The regression: the peer SVI answers for the address by design but
        rarely speaks, so its neighbour entry sits in STALE and it stopped
        counting as a claimant. It is still one of the two switch interfaces,
        and the row must stay out of the default view."""
        rec = self.add_arp_row("10.2.235.253", [SWITCH_A, SWITCH_B],
                               stale=[SWITCH_B])

        self.assertEqual(1, len(rec["macs"]), "the claim count is unchanged")
        self.assertTrue(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))
        self.assertEqual("OK", rec["severity"])

    def test_a_quiet_squatter_is_still_an_endpoint_on_an_svi_address(self):
        """The mirror case, and the one that matters more: an endpoint that
        took a gateway address and then went quiet is what a device losing the
        ARP race looks like. Missing it loses a real conflict."""
        rec = self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
            stale=[ENDPOINT],
        )

        self.assertEqual(1, len(rec["macs"]))
        self.assertTrue(self.analyzer._is_endpoint_on_svi_ip(rec))
        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertEqual("WARNING", rec["severity"])

    def test_two_endpoints_stay_a_classic_duplicate_when_one_is_quiet(self):
        """Neither class may capture host-versus-host just because one host
        stopped answering."""
        rec = self.add_arp_row(
            "10.2.243.30", [ENDPOINT, ENDPOINT_2],
            behind_ports={
                ENDPOINT: ("leaf-01", "swp8"),
                ENDPOINT_2: ("leaf-02", "swp9"),
            },
            stale=[ENDPOINT_2],
        )

        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))

    def test_a_lone_switch_interface_is_still_not_a_gateway(self):
        """One responder cannot be an anycast pair, whatever state it is in."""
        rec = self.add_arp_row("10.2.243.31", [SWITCH_A], stale=[SWITCH_A])
        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertFalse(self.analyzer._is_endpoint_on_svi_ip(rec))

    def test_the_gateway_note_counts_the_interfaces_not_the_claimants(self):
        self.add_arp_row("10.2.235.253", [SWITCH_A, SWITCH_B],
                         stale=[SWITCH_B])
        page = self.render()

        self.assertIn("anycast/VRR gateway address answered by switch "
                      "interfaces on 2 switches", page)
        self.assertNotIn("switches disagree on this address", page)

    def test_an_idle_peer_does_not_reopen_the_default_view(self):
        self.add_arp_row("10.2.235.253", [SWITCH_A, SWITCH_B],
                         stale=[SWITCH_B])
        page = self.render()
        row = [line for line in page.splitlines()
               if "10.2.235.253" in line and "<tr" in line]

        self.assertTrue(row, "gateway row not rendered")
        self.assertIn("expected-row", row[0])
        self.assertIn("data-kind='gateway'", row[0])

    def test_the_quiet_squatter_note_says_it_went_quiet(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
            stale=[ENDPOINT],
        )
        page = self.render()

        self.assertIn("endpoint is using a fabric", page)
        self.assertIn(ENDPOINT, page)
        self.assertIn("its binding is stale", page)

    # ---------- severity ----------
    def test_a_gateway_address_no_longer_spends_a_warning(self):
        rec = self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        self.assertEqual("OK", rec["severity"])

    def test_a_real_conflict_keeps_its_warning(self):
        rec = self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        self.assertEqual("WARNING", rec["severity"])

    def test_a_moving_gateway_address_is_still_reported(self):
        """Demotion covers a settled address, not one whose sequence climbed."""
        rec = self.add_arp_row(
            "10.2.243.60", [SWITCH_A, SWITCH_B], seq=SEQ_WARN + 1)
        self.assertEqual("WARNING", rec["severity"])

    def test_an_frr_flagged_row_is_never_demoted(self):
        """FRR's own duplicate finding outranks this inference."""
        rec = self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        rec["flagged"] = True
        self.assertFalse(self.analyzer._is_router_only_ip(rec))
        self.assertEqual("WARNING", self.analyzer._ip_sev(rec))

    # ---------- summary counters ----------
    def test_gateway_rows_are_counted_apart_from_observations(self):
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        summary = self.analyzer.summary()
        self.assertEqual(1, summary["ip_gateway_expected"])
        self.assertEqual(0, summary["ip_arp_observed"])
        self.assertEqual(0, summary["ip_endpoint_on_svi"])

    def test_a_real_conflict_is_counted_and_still_observed(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        summary = self.analyzer.summary()
        self.assertEqual(1, summary["ip_endpoint_on_svi"])
        self.assertEqual(1, summary["ip_arp_observed"])
        self.assertEqual(0, summary["ip_gateway_expected"])

    def test_gateway_rows_do_not_inflate_vlans_with_findings(self):
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        self.assertEqual(0, self.analyzer.summary()["vlans"])

    def test_a_real_conflict_does_count_its_vlan(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        self.assertEqual(1, self.analyzer.summary()["vlans"])

    # ---------- what the operator reads ----------
    def render(self):
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(out))
        return out.read_text(encoding="utf-8")

    def test_the_gateway_note_says_it_is_expected(self):
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        page = self.render()
        self.assertIn("anycast/VRR gateway address", page)
        self.assertNotIn("not FRR-confirmed", page)

    def test_the_conflict_note_names_the_endpoint_and_the_action(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        page = self.render()
        self.assertIn("endpoint is using a fabric", page)
        self.assertIn(ENDPOINT, page)
        self.assertIn("move the endpoint off this address", page)

    def test_a_gateway_row_is_tagged_so_filters_can_skip_it(self):
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        self.assertIn("data-kind='gateway'", self.render())

    # ---------- collapsed out of the default view ----------
    def test_a_gateway_row_is_collapsed_like_an_aged_row(self):
        """The page is read to find problems, not to be told nothing is wrong."""
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        page = self.render()
        self.assertIn("expected-row", page)
        self.assertIn(
            "body:not(.show-expected) tr.expected-row { display:none !important; }",
            page)

    def test_a_toggle_offers_the_collapsed_rows_with_a_count(self):
        self.add_arp_row("10.2.243.60", [SWITCH_A, SWITCH_B])
        self.add_arp_row("10.2.235.252", [SWITCH_A, SWITCH_B])
        page = self.render()
        self.assertIn("Show expected (2)", page)
        self.assertIn("var EXPECTED_COUNT = 2;", page)

    def test_no_toggle_appears_when_there_is_nothing_to_reveal(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        page = self.render()
        self.assertNotIn("id='expectedBtn'", page)
        self.assertIn("var EXPECTED_COUNT = 0;", page)

    def test_a_real_conflict_is_never_collapsed(self):
        self.add_arp_row(
            "10.2.243.60", [SWITCH_A, ENDPOINT],
            behind_ports={ENDPOINT: ("leaf-02", "swp8")},
        )
        page = self.render()
        row = [line for line in page.splitlines()
               if "10.2.243.60" in line and "<tr" in line]
        self.assertTrue(row, "conflict row not rendered")
        self.assertNotIn("expected-row", row[0])


if __name__ == "__main__":
    unittest.main()
