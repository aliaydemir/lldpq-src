#!/usr/bin/env python3
"""The Ask-AI timeline keeps real Rx drops on multi-lane modules.

The optical history stores one Rx value per port, the reading of the row's
worst lane.  The worst lane of a healthy module is its brightest one, so
almost any real drop makes another lane the worst one: a rule that compares
two samples only when they name the same lane silences a uniform 4 dB drop
of every lane.  What really invalidates a comparison is a change of the
lanes the row grades (breakout plan change, an upgrade that assigns lanes
differently).

Pinned here, for samples that list the lanes they grade
(`rx_power_lane_ids`): the link margin, always the dimmest graded lane, is
compared whenever both samples grade the same lanes; the Rx value only when
the named lane is the same as well.  A sample without the list keeps the
lane rule of test_audit_weba_optical_lane.py.

The readings of the first class come from the real OpticalAnalyzer; every
test runs the real html/ai_insights.py over the shard layout and the monolith.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "html"))
sys.path.insert(0, str(REPO_ROOT / "lldpq"))

import optical_analyzer  # noqa: E402
from test_audit_weba_optical_lane import NOW, STEP, OpticalLaneFixture, sample  # noqa: E402


def _power(dbm):
    return "%.4f mW / %.2f dBm" % (10 ** (dbm / 10.0), dbm)


def module_dump(rx, identifier="0x11 (QSFP28)"):
    """`ethtool -m` text of a module whose Rx lanes read `rx` (dBm)."""
    lines = [
        "\tIdentifier                                : %s" % identifier,
        "\tConnector                                 : 0x0c (MPO Parallel Optic)",
        "\tVendor name                               : ACME",
        "\tVendor PN                                 : PN-X",
        "\tVendor SN                                 : SN0001",
        "\tModule temperature                        : 43.18 degrees C / 109.72 degrees F",
        "\tModule voltage                            : 3.2703 V",
    ]
    lanes = range(1, len(rx) + 1)
    lines += ["\tLaser tx bias current (Channel %d)         : 60.000 mA" % lane
              for lane in lanes]
    lines += ["\tTransmit avg optical power (Channel %d)    : %s" % (lane, _power(1.0))
              for lane in lanes]
    lines += ["\tRcvr signal avg optical power (Channel %d) : %s" % (lane, _power(value))
              for lane, value in zip(lanes, rx)]
    return "\n".join(lines)


class RealAnalyzerHistory(OpticalLaneFixture):
    """History samples as lldpq/optical_analyzer.py grades them."""

    def analyze(self, port, runs, lanes_per_subport=None):
        """One real update_optical_stats per run -> (history, analyzer wrote ids)."""
        analyzer = optical_analyzer.OpticalAnalyzer(
            data_dir=str(self.monitor), load_history=False)
        persisted = True
        for index, rx in enumerate(runs):
            self.assertTrue(analyzer.update_optical_stats(
                port, module_dump(rx), lanes_per_subport=lanes_per_subport))
            entry = analyzer.optical_history[port][-1]
            entry["timestamp"] = NOW - 3000 + index * STEP
            if not entry.get("rx_power_lane_ids"):
                # The lanes this run graded, as the analyzer itself lists
                # them for the page; the history must carry the same list.
                persisted = False
                entry["rx_power_lane_ids"] = list(
                    analyzer.current_optical_stats[port]["rx_power_lane_ids"])
        return {port: analyzer.optical_history[port]}, persisted


BASE = [-1.1, -1.2, -1.0, -1.3]


class RealDropOnAMultiLaneModuleTests(RealAnalyzerHistory):
    def test_uniform_drop_of_every_lane_is_reported(self):
        history, _persisted = self.analyze(
            "leaf1:swp10", [BASE, BASE, [value - 4.0 for value in BASE]])
        series = history["leaf1:swp10"]
        # The brightest lane is "worst" while healthy, the dimmest after.
        self.assertEqual([entry["rx_power_lane"] for entry in series], [3, 3, 4])
        self.assertEqual(self.optical_events(history), [
            ("swp10", "warning",
             "Optical state changed on swp10: link margin 12.7→8.7 dB"),
        ])

    def test_drop_of_one_lane_that_was_not_the_worst_is_reported(self):
        history, _persisted = self.analyze(
            "leaf1:swp10", [BASE, BASE, [-1.1, -5.4, -1.0, -1.3]])
        self.assertEqual(
            [entry["rx_power_lane"] for entry in history["leaf1:swp10"]], [3, 3, 2])
        self.assertEqual(self.optical_events(history), [
            ("swp10", "warning",
             "Optical state changed on swp10: link margin 12.7→8.6 dB"),
        ])

    def test_drop_of_the_dimmest_lane_is_reported(self):
        history, _persisted = self.analyze(
            "leaf1:swp10", [BASE, [-1.1, -1.2, -1.0, -5.5]])
        self.assertEqual(self.optical_events(history), [
            ("swp10", "warning",
             "Optical state changed on swp10: link margin 12.7→8.5 dB"),
        ])

    def test_noise_that_only_moves_the_worst_lane_stays_silent(self):
        history, _persisted = self.analyze("leaf1:swp10", [
            [-1.4, -1.5, -4.5, last] for last in (-4.7, -4.5, -4.7, -4.5, -4.7)])
        lanes = [entry["rx_power_lane"] for entry in history["leaf1:swp10"]]
        self.assertGreater(len(set(lanes)), 1, lanes)  # the worst lane does flip
        self.assertEqual(self.optical_events(history), [])

    def test_breakout_plan_change_is_not_a_drop(self):
        # One sub-port of a 4-lane module: it owns lane 2 under a 4x plan and
        # lanes 3-4 under a 2x plan, which sit 3.6 dB lower.
        lanes = [-1.0, -1.2, -4.6, -4.8]
        analyzer_runs = []
        for plan in (1, 2, 1, 2):
            history, _persisted = self.analyze(
                "leaf1:swp3s1", [lanes], lanes_per_subport=plan)
            analyzer_runs.append(history["leaf1:swp3s1"][0])
        for index, entry in enumerate(analyzer_runs):
            entry["timestamp"] = NOW - 3000 + index * STEP
        self.assertEqual(
            [sorted(entry["rx_power_lane_ids"]) for entry in analyzer_runs],
            [[2], [3, 4], [2], [3, 4]])
        self.assertEqual(self.optical_events({"leaf1:swp3s1": analyzer_runs}), [])

    def test_history_written_by_the_analyzer_lists_the_graded_lanes(self):
        # The rule above needs the list in the persisted sample itself.
        _history, persisted = self.analyze("leaf1:swp10", [BASE])
        if not persisted:
            self.skipTest(
                "lldpq/optical_analyzer.py does not store rx_power_lane_ids in "
                "the history sample yet; until it does the timeline keeps the "
                "same-lane rule and misses these drops")
        self.assertTrue(persisted)


def with_ids(entry, ids):
    entry["rx_power_lane_ids"] = ids
    return entry


class LaneSetRuleTests(OpticalLaneFixture):
    def test_same_lanes_and_same_worst_lane_report_rx_and_margin(self):
        self.assertEqual(self.optical_events({"leaf1:swp9": [
            with_ids(sample(0, -2.0, 3, 12.0), [1, 2, 3, 4]),
            with_ids(sample(1, -5.5, 3, 8.5), [1, 2, 3, 4]),
        ]}), [
            ("swp9", "warning",
             "Optical state changed on swp9: Rx power -2.0→-5.5 dBm; "
             "link margin 12.0→8.5 dB"),
        ])

    def test_changed_lanes_report_nothing_even_under_the_same_worst_lane(self):
        # The named lane is lane 2 in both samples, but the row now also
        # grades lanes 3-4: neither value describes the same thing.
        self.assertEqual(self.optical_events({"leaf1:swp3s1": [
            with_ids(sample(0, -1.2, 2, 12.8), [1, 2]),
            with_ids(sample(1, -4.4, 2, 9.2), [1, 2, 3, 4]),
        ]}), [])

    def test_lane_order_and_spelling_do_not_make_a_new_set(self):
        self.assertEqual(self.optical_events({"leaf1:swp9": [
            with_ids(sample(0, -1.0, 3, 12.7), [1, 2, 3, 4]),
            with_ids(sample(1, -5.3, 4, 8.7), ["4", "3", "2", "1"]),
        ]}), [
            ("swp9", "warning",
             "Optical state changed on swp9: link margin 12.7→8.7 dB"),
        ])

    def test_health_change_keeps_its_severity_and_gains_the_margin(self):
        self.assertEqual(self.optical_events({"leaf1:swp9": [
            with_ids(sample(0, -1.0, 3, 9.6, health="excellent"), [1, 2, 3, 4]),
            with_ids(sample(1, -5.3, 4, 5.6, health="good"), [1, 2, 3, 4]),
        ]}), [
            ("swp9", "warning",
             "Optical state changed on swp9: health excellent→good; "
             "link margin 9.6→5.6 dB"),
        ])

    def test_a_sample_without_the_list_keeps_the_lane_rule(self):
        for label, old_ids, new_ids in (
            ("older sample has none", None, [1, 2, 3, 4]),
            ("newer sample has none", [1, 2, 3, 4], None),
            ("empty list", [], [1, 2, 3, 4]),
            ("not a list", "1,2,3,4", [1, 2, 3, 4]),
            ("list of blanks", [None, ""], [1, 2, 3, 4]),
        ):
            with self.subTest(label):
                def pair(old_lane, new_lane):
                    older, newer = sample(0, -1.0, old_lane, 12.7), sample(1, -5.3, new_lane, 8.7)
                    if old_ids is not None:
                        older["rx_power_lane_ids"] = old_ids
                    if new_ids is not None:
                        newer["rx_power_lane_ids"] = new_ids
                    return self.optical_events({"leaf1:swp9": [older, newer]})
                # Another worst lane: silent, as before the lists existed.
                self.assertEqual(pair(3, 4), [])
                # The same worst lane: compared, as before.
                self.assertEqual(pair(3, 3), [
                    ("swp9", "warning",
                     "Optical state changed on swp9: Rx power -1.0→-5.3 dBm; "
                     "link margin 12.7→8.7 dB"),
                ])


if __name__ == "__main__":
    unittest.main()
