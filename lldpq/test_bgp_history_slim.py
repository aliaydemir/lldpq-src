#!/usr/bin/env python3
"""History snapshots carry counters only.

The full per-neighbor dicts live solely in current_bgp_stats (down_since
carryover, web export); embedding them in every history snapshot grew the
fabric-wide bgp_history.json to GB scale and OOM-killed the analyzer.
"""

import json
import tempfile
import unittest
from pathlib import Path

from bgp_analyzer import BGPAnalyzer

ESTABLISHED_SUMMARY = """
IPv4 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65001 vrf-id 0

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
swp1            4      65002     100     100        0    0    0 01:02:03            5        5 leaf01
"""

DOWN_SUMMARY = """
IPv4 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65001 vrf-id 0

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
swp1            4      65002     100     100        0    0    0    never       Active        0 leaf01
"""


class BgpHistorySlimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_history_entries_carry_counters_only(self):
        analyzer = BGPAnalyzer(self.tmp.name)
        analyzer.update_bgp_stats("tor-a", ESTABLISHED_SUMMARY)

        (entry,) = analyzer.bgp_history["tor-a"]
        self.assertNotIn("neighbors", entry)
        self.assertEqual(1, entry["total_neighbors"])
        self.assertEqual(1, entry["established_count"])
        self.assertEqual(0, entry["down_count"])
        # The full dicts must still be available for the web export.
        self.assertEqual(
            "swp1",
            analyzer.current_bgp_stats["tor-a"]["neighbors"][0]["neighbor_name"],
        )

    def test_legacy_embedded_neighbors_trimmed_on_load(self):
        legacy = {
            "bgp_history": {
                "tor-a": [{
                    "timestamp": "2099-01-01T00:00:00+00:00",
                    "total_neighbors": 2,
                    "established_count": 2,
                    "down_count": 0,
                    "neighbors": [{"neighbor_name": "swp%d" % i} for i in range(200)],
                }],
            },
            "current_bgp_stats": {},
        }
        path = Path(self.tmp.name) / "bgp_history.json"
        path.write_text(json.dumps(legacy), encoding="utf-8")

        analyzer = BGPAnalyzer(self.tmp.name)

        (entry,) = analyzer.bgp_history["tor-a"]
        self.assertNotIn("neighbors", entry)
        self.assertEqual(2, entry["total_neighbors"])

        analyzer.save_bgp_history()
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn("neighbors", saved["bgp_history"]["tor-a"][0])

    def test_down_since_carryover_survives_in_current_stats(self):
        analyzer = BGPAnalyzer(self.tmp.name)
        analyzer.update_bgp_stats("tor-a", DOWN_SUMMARY)
        first = analyzer.current_bgp_stats["tor-a"]["neighbors"][0]["down_since"]
        self.assertIsNotNone(first)

        analyzer.update_bgp_stats("tor-a", DOWN_SUMMARY)
        second = analyzer.current_bgp_stats["tor-a"]["neighbors"][0]["down_since"]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
