#!/usr/bin/env python3
"""The cage is the unit of a DOM read in the optical collector.

Every ``swp<N>s<M>`` of one cage answers from the same module EEPROM, but the
collector read the module once per sibling.  A module that never answers was
therefore four (or eight) consecutive timeouts on its own: enough for the
guard that means "the EEPROM bus is hung from here on", so one sick module in
a 4x cage aborted the section and every later port of the switch was
published as unvisited.  The same module in an unsplit port cost one row.

The remote script is run as the collector sends it, against a stand-in sysfs
tree, modules and clock (see ``test_audit_col_inventory``).
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
import test_audit_col_inventory as collector
from test_audit_col_inventory import Port


def cages(split=None, states=None):
    """Sixteen cages in front-panel order; ``split`` maps cage to width."""
    ports = {}
    for number in range(1, 17):
        width = (split or {}).get(number)
        names = (
            [f"swp{number}s{sub}" for sub in range(width)]
            if width else [f"swp{number}"]
        )
        for name in names:
            ports[name] = Port(state=(states or {}).get(name, "up"))
    return ports


def dump(cage):
    return [
        "\tIdentifier                                : 0x18 (QSFP-DD)",
        "\tVendor name                               : ACME",
        f"\tVendor SN                                 : SN-{cage}",
    ]


def blocks(run):
    """Interface -> the lines of its block, in the order printed."""
    body = collector.section(run.stdout, "OPTICAL_DATA")
    found = {}
    for chunk in body.split("--- Interface: ")[1:]:
        name, _, rest = chunk.partition("\n")
        found[name] = rest.splitlines()
    return found


def markers(run):
    return re.findall(
        r"^__LLDPQ_COLLECTION_ERROR__:(OPTICAL_[A-Z_]+):(\S+)$",
        collector.section(run.stdout, "OPTICAL_DATA"),
        re.M,
    )


def timed_out(name, state="up"):
    return [
        f"Interface state: {state}",
        f"__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:{name}",
        "No transceiver data",
    ]


def unvisited(name, state="up"):
    return [
        f"Interface state: {state}",
        f"__LLDPQ_COLLECTION_ERROR__:OPTICAL_BUDGET:{name}",
        "No transceiver data",
    ]


def healthy(cage, state="up"):
    return [f"Interface state: {state}"] + dump(cage)


class HungModuleTests(unittest.TestCase):
    """One module that never answers, in a switch of sixteen cages."""

    def assert_only_cage_five_is_lost(self, run, siblings):
        found = blocks(run)
        self.assertEqual(
            markers(run), [("OPTICAL_TIMEOUT", name) for name in siblings]
        )
        for name in siblings:
            self.assertEqual(found[name], timed_out(name))
        for number in (*range(1, 5), *range(6, 17)):
            self.assertEqual(found[f"swp{number}"], healthy(f"swp{number}"))
        # One read and its single retry, whatever the cage is split into:
        # 5 s + 1 s pause + 5 s.
        first = siblings[0]
        self.assertEqual(
            run.ethtool_calls,
            [f"swp{n}" for n in range(1, 5)] + [first, first]
            + [f"swp{n}" for n in range(6, 17)],
        )
        self.assertEqual(run.clock, 11)

    def test_unsplit_port_is_read_exactly_as_before(self):
        run = collector.run_collector(
            self, "optical", cages(), dom={"swp5": "hang"}
        )

        self.assert_only_cage_five_is_lost(run, ["swp5"])

    def test_cage_split_in_four_costs_one_read_and_aborts_nothing(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "hang"}
        )

        self.assert_only_cage_five_is_lost(
            run, [f"swp5s{sub}" for sub in range(4)]
        )

    def test_cage_split_in_eight_costs_one_read_and_aborts_nothing(self):
        run = collector.run_collector(
            self, "optical", cages({5: 8}), dom={"swp5": "hang"}
        )

        self.assert_only_cage_five_is_lost(
            run, [f"swp5s{sub}" for sub in range(8)]
        )

    def test_cage_split_in_two_is_read_once(self):
        run = collector.run_collector(
            self, "optical", cages({5: 2}), dom={"swp5": "hang"}
        )

        self.assert_only_cage_five_is_lost(run, ["swp5s0", "swp5s1"])

    def test_analyzer_reads_one_failure_per_sibling_and_no_unvisited_port(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "hang"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "leaf1_optical.txt"
            sample.write_text(
                collector.section(run.stdout, "OPTICAL_DATA"), encoding="utf-8"
            )
            port_data, failures = optical.read_optical_diagnostics_file(
                str(sample)
            )

        self.assertEqual(list(port_data), list(blocks(run)))
        self.assertEqual(len(port_data), 19)
        self.assertEqual(
            failures,
            [("OPTICAL_TIMEOUT", f"swp5s{sub}") for sub in range(4)],
        )


class CageReplayTests(unittest.TestCase):
    """Siblings replay the cage, each under its own header and state."""

    # swp5s0 and swp5s2 carry traffic and are read with the link-up ports;
    # swp5s1 and swp5s3 come last, after every other port of the switch.
    STATES = {"swp5s1": "down", "swp5s3": "down"}

    def test_healthy_module_is_read_once_and_printed_for_every_sibling(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES)
        )
        found = blocks(run)

        self.assertEqual(list(found)[-2:], ["swp5s1", "swp5s3"])
        self.assertEqual(found["swp5s0"], healthy("swp5"))
        self.assertEqual(found["swp5s2"], healthy("swp5"))
        self.assertEqual(found["swp5s1"], healthy("swp5", "down"))
        self.assertEqual(found["swp5s3"], healthy("swp5", "down"))
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0"],
        )
        self.assertEqual(len(run.ethtool_calls), 16)
        self.assertEqual(markers(run), [])

    def test_timed_out_cage_gives_a_distant_sibling_its_own_marker(self):
        states = {name: "down" for name in ("swp5s1", "swp5s2", "swp5s3")}
        run = collector.run_collector(
            self, "optical", cages({5: 4}, states), dom={"swp5": "hang"}
        )
        found = blocks(run)

        self.assertEqual(list(found)[-3:], ["swp5s1", "swp5s2", "swp5s3"])
        self.assertEqual(found["swp5s0"], timed_out("swp5s0"))
        for name in ("swp5s1", "swp5s2", "swp5s3"):
            self.assertEqual(found[name], timed_out(name, "down"))
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0", "swp5s0"],
        )
        self.assertEqual(run.clock, 11)

    def test_transient_timeout_is_retried_and_the_answer_is_shared(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "once"}
        )
        found = blocks(run)

        # 5 s for the read that timed out, 1 s pause, an instant retry.
        self.assertEqual(run.clock, 6)
        self.assertEqual(markers(run), [])
        self.assertEqual(found["swp5s0"], healthy("swp5"))
        self.assertEqual(found["swp5s2"], healthy("swp5"))
        self.assertEqual(found["swp5s1"], healthy("swp5", "down"))
        self.assertEqual(found["swp5s3"], healthy("swp5", "down"))
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0", "swp5s0"],
        )

    def test_empty_cage_is_asked_twice_by_its_first_sibling_only(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "empty"}
        )
        found = blocks(run)

        for name in ("swp5s0", "swp5s2"):
            self.assertEqual(
                found[name], ["Interface state: up", "No transceiver data"]
            )
        for name in ("swp5s1", "swp5s3"):
            self.assertEqual(
                found[name], ["Interface state: down", "No transceiver data"]
            )
        # The instant error is confirmed once before it is filed for the
        # cage (see test_audit_collector_fix_cage); no other sibling asks.
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0", "swp5s0"],
        )
        self.assertEqual(len(run.ethtool_calls), 17)
        self.assertEqual(markers(run), [])

    def test_siblings_print_exactly_what_the_reading_sibling_printed(self):
        # The filed dump is replayed as text: a backslash in an EEPROM
        # string must reach every sibling the way it reached the first.
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "odd"}
        )
        found = blocks(run)

        self.assertEqual(len(found["swp5s0"]), 5)
        self.assertIn("Vendor PN", found["swp5s0"][-1])
        self.assertIn("\\", found["swp5s0"][-1])
        for name in ("swp5s1", "swp5s2", "swp5s3"):
            self.assertEqual(found[name][1:], found["swp5s0"][1:])
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0"],
        )

    def test_timed_out_cage_replays_what_the_module_printed_before_it_hung(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "partial"}
        )
        found = blocks(run)

        for name in ("swp5s0", "swp5s1", "swp5s2", "swp5s3"):
            state = self.STATES.get(name, "up")
            self.assertEqual(
                found[name],
                [
                    f"Interface state: {state}",
                    f"__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:{name}",
                    dump("swp5")[0],
                ],
            )
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            ["swp5s0", "swp5s0"],
        )


class SickDomGuardTests(unittest.TestCase):
    """Both abort guards count a cage once, and still work across cages."""

    def test_three_hung_modules_do_not_make_a_streak_of_four(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}),
            dom={"swp5": "hang", "swp6": "hang", "swp7": "hang"},
        )
        found = blocks(run)

        self.assertEqual(
            markers(run),
            [("OPTICAL_TIMEOUT", f"swp5s{sub}") for sub in range(4)]
            + [("OPTICAL_TIMEOUT", "swp6"), ("OPTICAL_TIMEOUT", "swp7")],
        )
        for number in range(8, 17):
            self.assertEqual(found[f"swp{number}"], healthy(f"swp{number}"))

    def test_four_hung_modules_abort_and_mark_every_unvisited_interface(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4, 12: 2}),
            dom={name: "hang" for name in ("swp5", "swp6", "swp7", "swp8")},
        )
        found = blocks(run)

        self.assertEqual(
            [name for reason, name in markers(run)
             if reason == "OPTICAL_TIMEOUT"],
            ["swp5s0", "swp5s1", "swp5s2", "swp5s3", "swp6", "swp7", "swp8"],
        )
        tail = ["swp9", "swp10", "swp11", "swp12s0", "swp12s1",
                "swp13", "swp14", "swp15", "swp16"]
        self.assertEqual(
            [name for reason, name in markers(run)
             if reason == "OPTICAL_BUDGET"],
            tail,
        )
        for name in tail:
            self.assertEqual(found[name], unvisited(name))
        # Only the first timeout of the streak is retried, and nothing is
        # read once the section is abandoned.
        self.assertEqual(
            run.ethtool_calls,
            ["swp1", "swp2", "swp3", "swp4",
             "swp5s0", "swp5s0", "swp6", "swp7", "swp8"],
        )

    def test_crawling_read_adds_its_time_once_per_cage(self):
        # 15 s of a read that then fails with an ordinary error: three such
        # reads pass the 40 s limit, one cage must not.
        run = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "fail 15"}
        )
        found = blocks(run)

        self.assertEqual(markers(run), [])
        for sub in range(4):
            self.assertEqual(
                found[f"swp5s{sub}"],
                ["Interface state: up", "No transceiver data"],
            )
        for number in range(6, 17):
            self.assertEqual(found[f"swp{number}"], healthy(f"swp{number}"))
        self.assertEqual(run.clock, 15)

    def test_spent_budget_marks_unread_cages_and_replays_read_ones(self):
        ports = {
            "swp1s0": Port(),
            "swp1s1": Port(state="down"),
            "swp1s2": Port(state="down"),
            "swp1s3": Port(state="down"),
            "swp2": Port(),
            "swp3": Port(),
            "swp4s0": Port(),
            "swp4s1": Port(state="down"),
        }
        # 12 s for the device: swp2 takes 11 s (read, pause, retry) and swp3
        # the last one.
        run = collector.run_collector(
            self, "optical", ports,
            dom={"swp2": "hang", "swp3": "hang"}, budget=12,
        )
        found = blocks(run)

        self.assertEqual(run.clock, 12)
        self.assertEqual(
            markers(run),
            [("OPTICAL_TIMEOUT", "swp2"), ("OPTICAL_TIMEOUT", "swp3"),
             ("OPTICAL_BUDGET", "swp4s0"), ("OPTICAL_BUDGET", "swp4s1")],
        )
        # The module of cage 1 was read while there was budget; its link-down
        # siblings are visited after it ran out and need none.
        self.assertEqual(found["swp1s0"], healthy("swp1"))
        for name in ("swp1s1", "swp1s2", "swp1s3"):
            self.assertEqual(found[name], healthy("swp1", "down"))
        self.assertEqual(found["swp4s0"], unvisited("swp4s0"))
        self.assertEqual(found["swp4s1"], unvisited("swp4s1", "down"))
        self.assertEqual(
            run.ethtool_calls, ["swp1s0", "swp2", "swp2", "swp3"]
        )


class ReplayAfterAbortTests(unittest.TestCase):
    """A replay reads nothing, so it is neither stopped by an abandoned
    sweep nor counted as a healthy read."""

    def test_sibling_of_a_read_cage_replays_after_the_section_was_abandoned(self):
        ports = cages({1: 4, 7: 2}, {"swp1s3": "down", "swp7s1": "down"})
        run = collector.run_collector(
            self, "optical", ports,
            dom={name: "hang" for name in ("swp2", "swp3", "swp4", "swp5")},
        )
        found = blocks(run)

        # Four hung modules abandon the sweep after swp5 ...
        self.assertEqual(found["swp6"], unvisited("swp6"))
        # ... cage 1 was read before that, so its link-down sibling replays,
        self.assertEqual(found["swp1s3"], healthy("swp1", "down"))
        # and cage 7 was never read, so both siblings are unvisited.
        self.assertEqual(found["swp7s0"], unvisited("swp7s0"))
        self.assertEqual(found["swp7s1"], unvisited("swp7s1", "down"))
        self.assertEqual(
            run.ethtool_calls,
            ["swp1s0", "swp2", "swp2", "swp3", "swp4", "swp5"],
        )

    def test_replayed_success_does_not_reset_the_timeout_streak(self):
        ports = {
            "swp1s0": Port(), "swp1s1": Port(state="down"),
            "swp2": Port(), "swp3": Port(), "swp4": Port(),
            "swp5": Port(state="down"), "swp6": Port(state="down"),
        }
        run = collector.run_collector(
            self, "optical", ports,
            dom={name: "hang" for name in ("swp2", "swp3", "swp4", "swp5")},
        )
        found = blocks(run)

        # swp1s1 is replayed between the third and the fourth hung module;
        # only a real read may clear the streak, so swp5 is not retried and
        # swp6 is left unvisited.
        self.assertEqual(
            list(found),
            ["swp1s0", "swp2", "swp3", "swp4", "swp1s1", "swp5", "swp6"],
        )
        self.assertEqual(found["swp1s1"], healthy("swp1", "down"))
        self.assertEqual(
            run.ethtool_calls,
            ["swp1s0", "swp2", "swp2", "swp3", "swp4", "swp5"],
        )
        self.assertEqual(found["swp6"], unvisited("swp6", "down"))


class UnwritableCacheTests(unittest.TestCase):
    """A cage whose outcome could not be filed stays unread."""

    def assert_every_sibling_read_for_itself(self, run):
        found = blocks(run)
        for sub in range(4):
            self.assertEqual(found[f"swp5s{sub}"], healthy("swp5"))
        self.assertEqual(
            [name for name in run.ethtool_calls if name.startswith("swp5s")],
            [f"swp5s{sub}" for sub in range(4)],
        )
        self.assertEqual(markers(run), [])

    def test_failed_dump_write_leaves_every_sibling_to_read_for_itself(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}),
            blocked=["optical-cage-swp5.output"],
        )

        self.assert_every_sibling_read_for_itself(run)

    def test_failed_status_write_leaves_every_sibling_to_read_for_itself(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}),
            blocked=["optical-cage-swp5.status"],
        )

        self.assert_every_sibling_read_for_itself(run)


if __name__ == "__main__":
    unittest.main()
