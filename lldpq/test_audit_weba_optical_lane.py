#!/usr/bin/env python3
"""The Ask-AI timeline compares optical samples only when they share a lane.

The optical history stores one Rx value per port: the reading of the worst
lane of the row (`rx_power_lane`), with `link_margin_db` taken over the same
lanes.  The worst lane is not a fixed lane.  It moves when a breakout plan
changes the lanes a sub-port owns, when the analyzer starts assigning lanes
differently after an upgrade, and when two lanes of one row trade places.
The ">= 3 dB drop" rule of the timeline compared consecutive samples anyway
and reported 'Rx power -1.2→-4.7 dBm' for ports where nothing had changed.

Decision pinned here: the Rx-drop and margin-drop rules compare two samples
only when both describe the same lane.  A changed lane restarts the
comparison at the new sample and is not an event by itself; samples without a
lane are compared as before.  The health rule is independent of the lane.

Every test runs the real html/ai_insights.py over a history written to a
temporary directory, both in the per-device shard layout and in the
pre-shard monolith.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "html"))

import ai_insights  # noqa: E402
from ai_insights import build_timeline  # noqa: E402


NOW = 1_800_000_000.0
STEP = 600.0
NO_LANE = object()


def sample(index, rx, lane=NO_LANE, margin=None, health="excellent"):
    """One optical history entry; `index` counts collection runs from the oldest."""
    entry = {
        "timestamp": NOW - 3000 + index * STEP,
        "health": health,
        "rx_power_dbm": rx,
        "tx_power_dbm": 1.0,
        "temperature_c": 43.0,
        "link_margin_db": margin,
    }
    if lane is not NO_LANE:
        entry["rx_power_lane"] = lane
    return entry


class OpticalLaneFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.web = Path(self._tmp.name) / "web"
        self.monitor = self.web / "monitor-results"
        self.monitor.mkdir(parents=True)

    def write_shards(self, history):
        shard_dir = self.monitor / "optical-history"
        shard_dir.mkdir(exist_ok=True)
        (shard_dir / "leaf1.json").write_text(json.dumps({
            "version": 1, "host": "leaf1", "updated_at": NOW - 5,
            "history": history, "current": {},
        }), encoding="utf-8")
        return shard_dir

    def write_monolith(self, history):
        path = self.monitor / "optical_history.json"
        path.write_text(json.dumps({"optical_history": history}),
                        encoding="utf-8")
        return path

    def extract(self, path):
        events, coverage = ai_insights._extract_optical(
            path, NOW - 3600, NOW, 1800)
        self.assertEqual(coverage["source"], "optical")
        self.assertEqual(coverage["samples"], self.sample_count, coverage)
        return [(event["subject"], event["severity"], event["summary"])
                for event in sorted(events, key=lambda item: item["ts"])]

    def optical_events(self, history):
        """Events of the shard layout; the monolith must agree."""
        self.sample_count = sum(len(series) for series in history.values())
        from_shards = self.extract(self.write_shards(history))
        from_monolith = self.extract(self.write_monolith(history))
        self.assertEqual(from_shards, from_monolith)
        return from_shards


class LaneChangeIsNotADropTests(OpticalLaneFixture):
    def test_upgrade_step_to_another_lane_is_not_reported(self):
        # Twin-port module split 2x: the sub-port used to show lane 2 of the
        # first fibre pair and now shows lane 8 of its own, lossier pair.
        events = self.optical_events({"leaf1:swp6s1": [
            sample(0, -1.2, 2, 12.8), sample(1, -1.2, 2, 12.8),
            sample(2, -1.2, 2, 12.8),
            sample(3, -4.7, 8, 9.3), sample(4, -4.7, 8, 9.3),
        ]})
        self.assertEqual(events, [])

    def test_two_lanes_trading_the_worst_place_are_not_reported(self):
        # 0.2 dB of noise on lane 8 flips which lane is "worst" every run.
        series = []
        for index in range(6):
            series.append(sample(index, -4.7, 8, 9.3) if index % 2 == 0
                          else sample(index, -1.4, 5, 9.5))
        self.assertEqual(self.optical_events({"leaf1:swp6s1": series}), [])
        # The same happens on an unsplit four-lane port.
        self.assertEqual(self.optical_events({"leaf1:swp10": [
            sample(0, -4.7, 4, 9.3), sample(1, -1.4, 1, 9.5),
            sample(2, -4.7, 4, 9.3), sample(3, -1.4, 1, 9.5),
        ]}), [])

    def test_plan_flip_reports_the_link_state_without_invented_numbers(self):
        # The cage alternates between two breakout plans: s1 gains and loses
        # lanes, s2 goes down while its lane is still lit.
        events = self.optical_events({
            "leaf1:swp3s1": [
                sample(0, -1.2, 2, 12.8), sample(1, -4.8, 4, 9.2),
                sample(2, -1.2, 2, 12.8), sample(3, -4.8, 4, 9.2),
            ],
            "leaf1:swp3s2": [
                sample(0, -4.6, 3, 9.4),
                sample(1, -40.0, 5, -26.0, health="down"),
                sample(2, -4.6, 3, 9.4),
                sample(3, -40.0, 5, -26.0, health="down"),
            ],
        })
        self.assertEqual(events, [
            ("swp3s2", "critical",
             "Optical state changed on swp3s2: health excellent→down"),
            ("swp3s2", "info",
             "Optical state changed on swp3s2: health down→excellent"),
            ("swp3s2", "critical",
             "Optical state changed on swp3s2: health excellent→down"),
        ])

    def test_health_change_across_a_lane_change_keeps_its_severity(self):
        events = self.optical_events({"leaf1:swp7": [
            sample(0, -2.0, 1, 12.0, health="good"),
            sample(1, -9.5, 3, 4.5, health="warning"),
        ]})
        self.assertEqual(events, [
            ("swp7", "warning",
             "Optical state changed on swp7: health good→warning"),
        ])

    def test_comparison_restarts_at_the_new_lane(self):
        # The step to lane 8 is silent; the later 3.3 dB fall of lane 8 is
        # measured from lane 8's own first sample, not from lane 2.
        events = self.optical_events({"leaf1:swp6s1": [
            sample(0, -1.2, 2, 12.8),
            sample(1, -4.7, 8, 9.3),
            sample(2, -8.0, 8, 6.0),
        ]})
        self.assertEqual(events, [
            ("swp6s1", "warning",
             "Optical state changed on swp6s1: Rx power -4.7→-8.0 dBm; "
             "link margin 9.3→6.0 dB"),
        ])
        # Small movement on the new lane is not measured against the level
        # the old lane had.
        self.assertEqual(self.optical_events({"leaf1:swp6s1": [
            sample(0, -1.2, 2, 12.8),
            sample(1, -4.7, 8, 9.3),
            sample(2, -4.9, 8, 9.1),
        ]}), [])

    def test_lane_zero_is_a_lane(self):
        self.assertEqual(self.optical_events({"leaf1:swp8": [
            sample(0, -1.0, 0, 13.0), sample(1, -4.5, 1, 9.5),
        ]}), [])
        self.assertEqual(self.optical_events({"leaf1:swp8": [
            sample(0, -1.0, 0, 13.0), sample(1, -4.5, 0, 9.5),
        ]}), [
            ("swp8", "warning",
             "Optical state changed on swp8: Rx power -1.0→-4.5 dBm; "
             "link margin 13.0→9.5 dB"),
        ])


class SameLaneDropIsStillReportedTests(OpticalLaneFixture):
    def test_drop_on_the_same_lane(self):
        events = self.optical_events({"leaf1:swp9": [
            sample(0, -2.0, 3, 12.0), sample(1, -2.1, 3, 11.9),
            sample(2, -5.5, 3, 8.5),
        ]})
        self.assertEqual(events, [
            ("swp9", "warning",
             "Optical state changed on swp9: Rx power -2.1→-5.5 dBm; "
             "link margin 11.9→8.5 dB"),
        ])

    def test_margin_drop_of_another_lane_under_the_same_worst_lane(self):
        # The named worst lane is unchanged; a dimmer lane lost 3 dB.
        events = self.optical_events({"leaf1:swp9": [
            sample(0, 2.4, 1, 9.0), sample(1, 2.4, 1, 6.0),
        ]})
        self.assertEqual(events, [
            ("swp9", "warning",
             "Optical state changed on swp9: link margin 9.0→6.0 dB"),
        ])

    def test_samples_without_a_lane_are_compared_as_before(self):
        for label, old_lane, new_lane in (
            ("both absent", NO_LANE, NO_LANE),
            ("both null", None, None),
            ("older sample has none", NO_LANE, 4),
            ("older sample is null", None, 4),
            ("newer sample has none", 4, None),
        ):
            with self.subTest(label):
                events = self.optical_events({"leaf1:swp1": [
                    sample(0, -3.0, old_lane, 11.0),
                    sample(1, -7.0, new_lane, 7.0),
                ]})
                self.assertEqual(events, [
                    ("swp1", "warning",
                     "Optical state changed on swp1: Rx power -3.0→-7.0 dBm; "
                     "link margin 11.0→7.0 dB"),
                ])

    def test_small_changes_on_the_same_lane_stay_silent(self):
        self.assertEqual(self.optical_events({"leaf1:swp9": [
            sample(0, -2.0, 3, 12.0), sample(1, -4.9, 3, 9.1),
        ]}), [])


class TimelineTests(OpticalLaneFixture):
    """The same rule as the operator meets it, through build_timeline."""

    def optical_timeline(self, history):
        self.write_shards(history)
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW)
        coverage = next(row for row in timeline["coverage"]
                        if row["source"] == "optical")
        events = [event for event in timeline["events"]
                  if event["category"] == "optical"]
        return events, coverage

    def test_lane_flips_leave_the_timeline_empty(self):
        events, coverage = self.optical_timeline({
            "leaf1:swp6s0": [sample(index, -2.0, 1, 11.8) for index in range(5)],
            "leaf1:swp6s1": [
                sample(0, -1.2, 2, 12.8), sample(1, -1.2, 2, 12.8),
                sample(2, -4.7, 8, 9.3), sample(3, -1.4, 5, 9.5),
                sample(4, -4.7, 8, 9.3),
            ],
        })
        self.assertEqual(events, [])
        self.assertEqual(coverage["samples"], 10)
        self.assertEqual(coverage["events"], 0)

    def test_a_real_drop_reaches_the_timeline(self):
        events, coverage = self.optical_timeline({"leaf1:swp6s1": [
            sample(0, -1.2, 2, 12.8), sample(1, -4.7, 8, 9.3),
            sample(2, -4.7, 8, 9.3), sample(3, -8.1, 8, 5.9),
        ]})
        self.assertEqual(
            [(event["device"], event["subject"], event["severity"],
              event["summary"]) for event in events],
            [("leaf1", "swp6s1", "warning",
              "Optical state changed on swp6s1: Rx power -4.7→-8.1 dBm; "
              "link margin 9.3→5.9 dB")],
        )
        self.assertEqual(coverage["events"], 1)


if __name__ == "__main__":
    unittest.main()
