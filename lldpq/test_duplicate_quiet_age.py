#!/usr/bin/env python3
"""Says how long a row has been quiet, on the rows that are not aged yet.

Three rows reading "Historical MAC mobility (flat); not a simultaneous
conflict" sat in the default view and nobody could tell why "Show aged" did not
hold them. Both words are right and they measure different windows: "flat"
means the EVPN sequence did not move between the last two collections, "aged"
means it has not moved for STALE_AGE_SEC. Only the second window was written
down anywhere, and only once a row had crossed it.

So every row that has not crossed it now carries its own quiet age. The
phrasing is about the measurement, not the endpoint: the clock starts when this
tool first sees the entry, so a switch that rebooted this morning reports a few
hours of quiet on a MAC that has been settled for months, and the suffix must
not be readable as "this MAC is only N hours old".

These tests fail if the two markers ever appear on one row, if a row with
nothing to report invents a figure, or if a silence shorter than a day is
rounded down to "0d".
"""

import re
import tempfile
import time
import unittest
from pathlib import Path

from duplicate_analyzer import (
    DuplicateAnalyzer, SEQ_STORM, SEQ_WARN, STALE_AGE_SEC,
)

VLAN = "15"
VNI = "100015"
MAC = "00:02:99:33:dc:db"
IP = "10.2.240.90"
QUIET = "no movement observed for"


class QuietAgeMarkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = DuplicateAnalyzer(self.tmp.name)
        self.analyzer.coverage = {
            "expected": {"tor-a", "tor-b"}, "current": {"tor-a", "tor-b"},
            "failures": [], "partial": False,
        }
        self.analyzer.vni_to_vlan[VNI] = VLAN

    # ---------- fixtures ----------
    def add_ip(self, *, quiet_age, seq=SEQ_WARN + 1):
        """A settled duplicate address whose sequence has not moved since the
        state file was written *quiet_age* seconds ago."""
        rec = self.analyzer._blank_ip(VLAN, VNI, IP)
        rec.update({"seq": seq, "flagged": True})
        rec["authoritative_hosts"].add("tor-a")
        self.analyzer.ip_dups[(VNI, IP)] = rec
        if quiet_age is not None:
            self.analyzer.prev_state["ip:%s|%s" % (VNI, IP)] = {
                "seq": seq, "ts": time.time() - quiet_age,
            }
        return rec

    def add_mac(self, *, quiet_age, seq=SEQ_STORM + 1):
        """The same for a MAC row, in the shape that prompted this: a single
        owner whose sequence is high enough to keep as history but has not
        moved, which is what "Historical MAC mobility (flat)" describes."""
        if quiet_age is not None:
            self.analyzer.prev_state["mac:%s|%s" % (VNI, MAC)] = {
                "seq": seq, "ts": time.time() - quiet_age,
            }
        self.analyzer.mac_mob[(VNI, MAC)] = {
            "seq": seq, "hosts": {"tor-a"}, "vteps": set(),
            "ports": {"tor-a": "swp31"}, "vni": VNI,
        }

    def table(self, table_id):
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(out))
        page = out.read_text(encoding="utf-8")
        return page.split('id="%s"' % table_id, 1)[1].split("</table>", 1)[0]

    def ip_note(self):
        return re.findall(r"<td[^>]*>(.*?)</td>", self.table("ipt"))[-1]

    def mac_note(self):
        return re.findall(r"<td[^>]*>(.*?)</td>", self.table("mact"))[-1]

    # ---------- the duplicate IP table ----------
    def test_a_quiet_but_not_yet_aged_address_reports_its_silence(self):
        rec = self.add_ip(quiet_age=6 * 86400)
        self.analyzer._finalize()

        self.assertFalse(rec["stale"], "six days has not reached the threshold")
        note = self.ip_note()
        self.assertIn("%s 6d" % QUIET, note)
        self.assertNotIn("aged", note)

    def test_an_aged_address_keeps_the_marker_it_already_had(self):
        """One marker per row: the aged suffix already says the same thing,
        and it is the one that explains why the row is collapsed."""
        rec = self.add_ip(quiet_age=STALE_AGE_SEC + 86400)
        self.analyzer._finalize()

        self.assertTrue(rec["stale"])
        note = self.ip_note()
        self.assertIn("(aged 8d)", note)
        self.assertNotIn(QUIET, note)

    def test_a_row_with_no_quiet_clock_says_nothing(self):
        """Exercised directly: the analyzer stamps a clock for every record it
        builds, so an unset one means the persisted state was unreadable.
        There is nothing to report then, and nothing must be invented."""
        rec = self.add_ip(quiet_age=None)
        rec["quiet_age"] = None

        self.assertEqual("", self.analyzer._quiet_marker(rec))

    # ---------- the MAC findings table ----------
    def test_a_flat_mac_row_says_how_long_it_has_been_flat(self):
        """The row that started this: 'flat' compares two collections, so on
        its own it never explains why 'Show aged' does not hold the row."""
        self.add_mac(quiet_age=3 * 86400)
        self.analyzer._finalize()

        note = self.mac_note()
        self.assertIn("flat", note)
        self.assertIn("%s 3d" % QUIET, note)
        self.assertNotIn("aged", note)

    def test_an_aged_mac_row_keeps_the_aged_suffix_alone(self):
        self.add_mac(quiet_age=STALE_AGE_SEC + 2 * 86400)
        self.analyzer._finalize()

        rec = self.analyzer.mac_dups[(VNI, MAC)]
        self.assertTrue(rec["stale"])
        note = self.mac_note()
        self.assertIn("(aged 9d)", note)
        self.assertNotIn(QUIET, note)

    # ---------- how the figure reads ----------
    def test_a_silence_shorter_than_a_day_is_counted_in_hours(self):
        """Truncating to days would print "0d" for most of the first day and
        read as "no data" rather than "five hours"."""
        self.add_ip(quiet_age=5 * 3600 + 600)
        self.analyzer._finalize()

        self.assertIn("%s 5h" % QUIET, self.ip_note())

    def test_a_silence_shorter_than_an_hour_does_not_round_to_zero(self):
        self.add_ip(quiet_age=90)
        self.analyzer._finalize()

        self.assertIn("%s &lt;1h" % QUIET, self.ip_note())
        self.assertNotIn("for 0", self.ip_note())

    def test_the_marker_is_dim_like_the_aged_one(self):
        """Context under a finding, not part of the finding."""
        self.add_ip(quiet_age=2 * 86400)
        self.analyzer._finalize()

        self.assertIn("<span class='dim'>(%s 2d)</span>" % QUIET,
                      self.ip_note())

    # ---------- the caveat is written down ----------
    def test_the_modal_warns_that_the_clock_starts_at_first_sighting(self):
        """A short figure can mean a recent first sighting, not recent churn,
        and the page has to say so where the aged rule is explained."""
        self.add_ip(quiet_age=2 * 86400)
        self.analyzer._finalize()
        out = Path(self.tmp.name) / "duplicate-analysis.html"
        self.analyzer.export_html(str(out))
        page = out.read_text(encoding="utf-8")

        self.assertIn("no movement observed for N", page)
        self.assertIn("clock starts when this tool first sees", page)
        self.assertIn("a recent first sighting rather than recent churn", page)


if __name__ == "__main__":
    unittest.main()
