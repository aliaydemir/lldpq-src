#!/usr/bin/env python3
"""What one cage read may and may not decide for the siblings of the cage.

Since the module of a breakout cage is read once and the outcome is replayed
for every ``swp<N>s<M>`` of the cage, three cases need a rule of their own:

* a link-down sibling whose netdev has no device link is never read itself,
  but must still replay what a link-up sibling has read;
* an instant error without data is what an empty cage returns and also what
  a transient EEPROM access error looks like, so it is confirmed once before
  it is filed for the whole cage;
* a read that the remaining budget cut short says nothing about the module
  and is not filed as the timeout of the cage.

The remote script is run as the collector sends it (see
``test_audit_col_inventory``).
"""

import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
import test_audit_col_inventory as collector
from test_audit_col_inventory import Port
from test_audit_col_optical_cage import (
    blocks,
    cages,
    healthy,
    markers,
    timed_out,
    unvisited,
)


NO_DATA = "No transceiver data"


def cage_calls(run, cage="swp5"):
    return [name for name in run.ethtool_calls if name.startswith(cage + "s")]


class SiblingWithoutDeviceLinkTests(unittest.TestCase):
    """Netdevs without a device link: only link-up ports are read."""

    @staticmethod
    def ports(states):
        """Four unsplit ports and cage 5 split in four, no device links."""
        ports = {f"swp{number}": Port(device=False) for number in range(1, 5)}
        for sub in range(4):
            name = f"swp5s{sub}"
            ports[name] = Port(state=states.get(name, "up"), device=False)
        return ports

    DOWN = {"swp5s0": "down", "swp5s3": "down"}

    def test_link_down_sibling_replays_the_dump_a_link_up_sibling_read(self):
        run = collector.run_collector(self, "optical", self.ports(self.DOWN))
        found = blocks(run)

        self.assertEqual(found["swp5s1"], healthy("swp5"))
        self.assertEqual(found["swp5s2"], healthy("swp5"))
        self.assertEqual(found["swp5s0"], healthy("swp5", "down"))
        self.assertEqual(found["swp5s3"], healthy("swp5", "down"))
        self.assertEqual(cage_calls(run), ["swp5s1"])
        self.assertEqual(markers(run), [])

    def test_link_down_sibling_replays_the_timeout_of_the_cage(self):
        run = collector.run_collector(
            self, "optical", self.ports(self.DOWN), dom={"swp5": "hang"}
        )
        found = blocks(run)

        self.assertEqual(found["swp5s1"], timed_out("swp5s1"))
        self.assertEqual(found["swp5s2"], timed_out("swp5s2"))
        self.assertEqual(found["swp5s0"], timed_out("swp5s0", "down"))
        self.assertEqual(found["swp5s3"], timed_out("swp5s3", "down"))
        self.assertEqual(cage_calls(run), ["swp5s1", "swp5s1"])
        self.assertEqual(run.clock, 11)

    def test_analyzer_sees_the_timeout_on_every_sibling(self):
        run = collector.run_collector(
            self, "optical", self.ports(self.DOWN), dom={"swp5": "hang"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "leaf1_optical.txt"
            sample.write_text(
                collector.section(run.stdout, "OPTICAL_DATA"), encoding="utf-8"
            )
            _, failures = optical.read_optical_diagnostics_file(str(sample))

        self.assertCountEqual(
            failures,
            [("OPTICAL_TIMEOUT", f"swp5s{sub}") for sub in range(4)],
        )

    def test_cage_with_no_link_up_sibling_is_still_not_read(self):
        states = {f"swp5s{sub}": "down" for sub in range(4)}
        run = collector.run_collector(self, "optical", self.ports(states))
        found = blocks(run)

        for sub in range(4):
            self.assertEqual(
                found[f"swp5s{sub}"], ["Interface state: down", NO_DATA]
            )
        self.assertEqual(cage_calls(run), [])

    def test_link_down_unsplit_port_is_still_not_read(self):
        ports = self.ports({})
        ports["swp6"] = Port(state="down", device=False)
        run = collector.run_collector(self, "optical", ports)

        self.assertEqual(
            blocks(run)["swp6"], ["Interface state: down", NO_DATA]
        )
        self.assertNotIn("swp6", run.ethtool_calls)


class InstantErrorTests(unittest.TestCase):
    """An instant error without data is confirmed before it is filed."""

    STATES = {"swp5s3": "down"}

    def test_one_instant_error_does_not_blank_the_cage(self):
        # The first read fails at once, as a transient EEPROM access error
        # does; the module answers the next one.
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "glitch"}
        )
        found = blocks(run)

        for name in ("swp5s0", "swp5s1", "swp5s2"):
            self.assertEqual(found[name], healthy("swp5"))
        # A link-down sibling without data reads as an unplugged module.
        self.assertEqual(found["swp5s3"], healthy("swp5", "down"))
        self.assertEqual(cage_calls(run), ["swp5s0", "swp5s0"])
        self.assertEqual(len(run.ethtool_calls), 17)
        self.assertEqual(markers(run), [])
        self.assertEqual(run.clock, 0)

    def test_second_answer_that_hangs_is_the_timeout_of_the_cage(self):
        # Instant error, then the module stops answering: the second read
        # is an ordinary timeout with its pause and its single retry.
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES),
            dom={"swp5": "glitch hang"},
        )
        found = blocks(run)

        for name in ("swp5s0", "swp5s1", "swp5s2"):
            self.assertEqual(found[name], timed_out(name))
        self.assertEqual(found["swp5s3"], timed_out("swp5s3", "down"))
        self.assertEqual(cage_calls(run), ["swp5s0", "swp5s0", "swp5s0"])
        self.assertEqual(run.clock, 11)
        for number in range(6, 17):
            self.assertEqual(found[f"swp{number}"], healthy(f"swp{number}"))

    def test_error_within_a_second_is_asked_again_a_slower_one_is_not(self):
        # The collector clock counts whole seconds: a read that crawled for
        # two of them before it failed is a sick module, not a glitch, and
        # must count once in the failed-read time.
        quick = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "fail 1"}
        )
        slow = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "fail 2"}
        )

        self.assertEqual(cage_calls(quick), ["swp5s0", "swp5s0"])
        self.assertEqual(quick.clock, 2)
        self.assertEqual(cage_calls(slow), ["swp5s0"])
        self.assertEqual(slow.clock, 2)
        for run in (quick, slow):
            self.assertEqual(markers(run), [])
            for sub in range(4):
                self.assertEqual(
                    blocks(run)[f"swp5s{sub}"],
                    ["Interface state: up", NO_DATA],
                )

    def test_timeout_of_a_one_second_read_is_not_an_instant_error(self):
        # With a 1 s port timeout a hung read ends within the second an
        # instant error may take. It still is a timeout: one pause and one
        # retry, not an immediate second ask on top of them.
        run = collector.run_collector(
            self, "optical", cages({5: 4}), dom={"swp5": "hang"},
            port_timeout=1,
        )
        found = blocks(run)

        self.assertEqual(cage_calls(run), ["swp5s0", "swp5s0"])
        self.assertEqual(run.clock, 3)
        for sub in range(4):
            self.assertEqual(
                found[f"swp5s{sub}"], timed_out(f"swp5s{sub}")
            )

    def test_dump_that_came_with_an_error_status_is_not_asked_for_again(self):
        run = collector.run_collector(
            self, "optical", cages({5: 4}, self.STATES), dom={"swp5": "noisy"}
        )
        found = blocks(run)

        self.assertEqual(cage_calls(run), ["swp5s0"])
        for name in ("swp5s0", "swp5s1", "swp5s2"):
            self.assertEqual(found[name], healthy("swp5"))
        self.assertEqual(found["swp5s3"], healthy("swp5", "down"))
        self.assertEqual(markers(run), [])

    def test_unsplit_port_is_asked_once_as_before(self):
        run = collector.run_collector(
            self, "optical", cages(), dom={"swp5": "glitch"}
        )

        self.assertEqual(run.ethtool_calls.count("swp5"), 1)
        self.assertEqual(
            blocks(run)["swp5"], ["Interface state: up", NO_DATA]
        )
        self.assertEqual(len(run.ethtool_calls), 16)

    def test_second_ask_never_runs_without_budget(self):
        # 12 s for the device. swp2 uses 11 s (read, pause, retry); the
        # first read of cage 3 fails after the last second, which leaves
        # nothing for a second ask: `timeout 0s` would mean no limit at all.
        ports = {
            "swp1": Port(), "swp2": Port(),
            "swp3s0": Port(), "swp3s1": Port(),
        }
        run = collector.run_collector(
            self, "optical", ports,
            dom={"swp2": "hang", "swp3": "fail 1"}, budget=12,
        )
        found = blocks(run)

        self.assertEqual(
            run.ethtool_calls, ["swp1", "swp2", "swp2", "swp3s0"]
        )
        self.assertEqual(run.clock, 12)
        self.assertEqual(found["swp3s0"], ["Interface state: up", NO_DATA])
        self.assertEqual(found["swp3s1"], ["Interface state: up", NO_DATA])
        self.assertEqual(markers(run), [("OPTICAL_TIMEOUT", "swp2")])

    def test_second_ask_gets_what_is_left_of_the_budget(self):
        # 13 s: two are left for cage 3. Its first read fails after one of
        # them, so the second ask is limited to the last one. The module
        # does not answer it; that is the budget speaking, not the module,
        # and the sibling is unvisited.
        ports = {
            "swp1": Port(), "swp2": Port(),
            "swp3s0": Port(), "swp3s1": Port(),
        }
        run = collector.run_collector(
            self, "optical", ports,
            dom={"swp2": "hang", "swp3": "fail 1 hang"}, budget=13,
        )
        found = blocks(run)

        self.assertEqual(
            run.ethtool_calls, ["swp1", "swp2", "swp2", "swp3s0", "swp3s0"]
        )
        self.assertEqual(run.clock, 13)
        self.assertEqual(found["swp3s0"], timed_out("swp3s0"))
        self.assertEqual(found["swp3s1"], unvisited("swp3s1"))


class ReadCutShortByTheBudgetTests(unittest.TestCase):
    """A timeout of a shortened read is not the timeout of the cage."""

    def test_siblings_are_unvisited_when_the_budget_cut_the_read_short(self):
        ports = {
            "swp1": Port(), "swp4": Port(),
            "swp5s0": Port(), "swp5s1": Port(),
            "swp5s2": Port(), "swp5s3": Port(state="down"),
            "swp6": Port(),
        }
        # 13 s for the device: swp4 takes 11 s (read, pause, retry), so the
        # module of cage 5 gets 2 s instead of its 5 s.
        run = collector.run_collector(
            self, "optical", ports,
            dom={"swp4": "hang", "swp5": "hang"}, budget=13,
        )
        found = blocks(run)

        self.assertEqual(run.clock, 13)
        self.assertEqual(
            run.ethtool_calls, ["swp1", "swp4", "swp4", "swp5s0"]
        )
        self.assertEqual(found["swp5s0"], timed_out("swp5s0"))
        self.assertEqual(found["swp5s1"], unvisited("swp5s1"))
        self.assertEqual(found["swp5s2"], unvisited("swp5s2"))
        self.assertEqual(found["swp5s3"], unvisited("swp5s3", "down"))
        self.assertEqual(found["swp6"], unvisited("swp6"))

    def test_full_length_timeout_at_the_end_of_the_budget_is_still_filed(self):
        ports = {
            "swp1": Port(), "swp4": Port(),
            "swp5s0": Port(), "swp5s1": Port(),
            "swp5s2": Port(), "swp5s3": Port(state="down"),
            "swp6": Port(),
        }
        # 16 s: the module of cage 5 gets its full 5 s and does not answer.
        # No budget is left for a retry, nor for swp6.
        run = collector.run_collector(
            self, "optical", ports,
            dom={"swp4": "hang", "swp5": "hang"}, budget=16,
        )
        found = blocks(run)

        self.assertEqual(run.clock, 16)
        self.assertEqual(
            run.ethtool_calls, ["swp1", "swp4", "swp4", "swp5s0"]
        )
        self.assertEqual(found["swp5s0"], timed_out("swp5s0"))
        self.assertEqual(found["swp5s1"], timed_out("swp5s1"))
        self.assertEqual(found["swp5s2"], timed_out("swp5s2"))
        self.assertEqual(found["swp5s3"], timed_out("swp5s3", "down"))
        self.assertEqual(found["swp6"], unvisited("swp6"))

    def test_shortened_read_that_answers_is_filed_like_any_other(self):
        ports = {
            "swp1": Port(), "swp4": Port(),
            "swp5s0": Port(), "swp5s1": Port(state="down"),
        }
        run = collector.run_collector(
            self, "optical", ports, dom={"swp4": "hang"}, budget=13,
        )
        found = blocks(run)

        self.assertEqual(found["swp5s0"], healthy("swp5"))
        self.assertEqual(found["swp5s1"], healthy("swp5", "down"))
        self.assertEqual(
            run.ethtool_calls, ["swp1", "swp4", "swp4", "swp5s0"]
        )


if __name__ == "__main__":
    unittest.main()
