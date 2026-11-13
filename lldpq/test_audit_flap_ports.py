#!/usr/bin/env python3
"""Regression tests for the port set of the Link Flap report.

Two defects shared one root: nothing ever removed a port from the persisted
flap state, and the carrier file was trusted to name only physical ports.

* A port that left the switch (breakout reconfiguration, deleted
  sub-interface) kept its row, its last counter and - while its events sat in
  the grading window - its WARNING/CRITICAL status until the whole device was
  retired.
* A VLAN sub-interface (swp6.100) copies its parent's carrier state, so one
  flapping uplink was billed once per sub-interface on the page, in the
  export, in the summary and on the timeline.

A port leaves the report when two complete carrier listings in a row do not
name it: one listing alone can be a switch that is re-creating its ports
(switchd restart, breakout being applied). A sub-interface name is never a
port and goes with the first complete listing.

Every test drives the real process_carrier_transition_files over real
assets.ini / devices.yaml / carrier files and reads the published artifacts.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_flap_data
from link_flap_analyzer import LinkFlapAnalyzer


STATE_MAPS = (
    "flapping_hist", "carrier_transitions_lookback", "prev_cumulative",
    "prev_sample_time", "carrier_transitions_stats",
    "pending_transition_start",
)
ASSET_HEADER = (
    "DEVICE-NAME IP ETH0-MAC SERIAL MODEL RELEASE UPTIME STATUS LAST-SEEN"
)
ISOLATED_ENVIRONMENT = (
    "LLDPQ_ASSETS_FILE", "LLDPQ_DEVICES_FILE", "LLDPQ_COLLECTION_STATUS_FILE",
    "LLDPQ_PIPELINE_ID", "LINK_FLAPS_PER_HOUR", "LINK_FLAPS_CRITICAL",
    "MONITOR_DATA_MAX_AGE_MINUTES", "ASSET_TIMESTAMP_TOLERANCE_SECONDS",
)


class FlapSiteTestCase(unittest.TestCase):
    """A throwaway installation: inventory, asset snapshot, carrier files."""

    HOSTS = ("auditflap-a",)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.results = self.root / "monitor-results"
        self.flap_dir = self.results / "flap-data"
        self.flap_dir.mkdir(parents=True)

        notifications = self.root / "notifications.yaml"
        notifications.write_text(
            "thresholds:\n  network:\n"
            "    link_flaps_per_hour: 10\n    link_flaps_critical: 20\n",
            encoding="utf-8",
        )
        (self.root / "devices.yaml").write_text(
            "devices:\n" + "".join(
                f"  192.0.2.{index + 11}: {host}\n"
                for index, host in enumerate(self.HOSTS)
            ),
            encoding="utf-8",
        )
        environment = mock.patch.dict(
            os.environ, {"LLDPQ_NOTIFICATIONS_FILE": str(notifications)}
        )
        environment.start()
        self.addCleanup(environment.stop)
        for name in ISOLATED_ENVIRONMENT:
            os.environ.pop(name, None)

    # -- inputs -----------------------------------------------------------

    def _write_assets(self):
        created = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
        rows = "".join(
            f"{host} 192.0.2.{index + 11} 44:38:39:00:00:{index + 1:02x} "
            f"SN{index + 1} SN5600 5.9.1 1d OK now\n"
            for index, host in enumerate(self.HOSTS)
        )
        (self.root / "assets.ini").write_text(
            f"Created on {created}\n\n{ASSET_HEADER}\n{rows}", encoding="utf-8"
        )

    def carrier_file(self, host):
        return self.flap_dir / f"{host}_carrier_transitions.txt"

    def cycle(self, files):
        """One monitor cycle. *files* maps host -> carrier rows; a host
        mapped to None was not collected (its previous file goes stale)."""
        self._write_assets()
        for host, rows in files.items():
            path = self.carrier_file(host)
            if rows is None:
                if path.exists():
                    stale = time.time() - 600
                    os.utime(path, (stale, stale))
                continue
            path.write_text(
                "=== CARRIER TRANSITIONS ===\n" + "".join(
                    f"{row}\n" for row in rows
                ),
                encoding="utf-8",
            )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = process_flap_data.process_carrier_transition_files(
                str(self.flap_dir)
            )
        self.assertTrue(result, output.getvalue())
        return output.getvalue()

    def write_history(self, ports, now=None, coverage_hosts=None):
        """Persist flap_history.json exactly as save_flap_history lays it
        out. *ports* maps port -> (counter, flaps billed in the last hour,
        pending) for state written before this change."""
        now = time.time() if now is None else now
        history = {name: {} for name in STATE_MAPS}
        for port, (counter, flaps, pending) in ports.items():
            history["flapping_hist"][port] = (
                [[now - 300, counter, flaps, now - 900, 600.0]] if flaps else []
            )
            history["carrier_transitions_lookback"][port] = [
                [now - 300, counter]
            ]
            history["prev_cumulative"][port] = counter
            history["prev_sample_time"][port] = now - 300
            history["carrier_transitions_stats"][port] = counter
            if pending:
                history["pending_transition_start"][port] = now - 900
        hosts = sorted(coverage_hosts or self.HOSTS)
        history["collection_coverage"] = {
            "expected_devices": len(hosts),
            "current_devices": len(hosts),
            "unavailable_devices": [],
        }
        history["last_update"] = now - 300
        (self.results / "flap_history.json").write_text(
            json.dumps(history, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    # -- published artifacts ------------------------------------------------

    def history(self):
        return json.loads(
            (self.results / "flap_history.json").read_text(encoding="utf-8")
        )

    def history_ports(self):
        """Port keys present in ANY persisted per-port map."""
        history = self.history()
        ports = set()
        for name in STATE_MAPS:
            ports.update(history[name])
        return ports

    def assert_port_gone_from_every_map(self, port):
        history = self.history()
        for name in STATE_MAPS + ("absent_since",):
            self.assertNotIn(port, history[name], f"{port} left in {name}")

    def summary(self):
        return json.loads(
            (self.results / "summary" / "flap-summary.json").read_text(
                encoding="utf-8"
            )
        )

    def export_json(self):
        return json.loads(
            (self.results / "export" / "flap.json").read_text(encoding="utf-8")
        )

    def export_rows(self):
        """{'host:interface': row} from the JSON export."""
        return {
            f"{row['device']}:{row['interface']}": row
            for row in self.export_json()["rows"]
        }

    def csv_ports(self):
        with open(self.results / "export" / "flap.csv", newline="",
                  encoding="utf-8") as handle:
            return {
                f"{row['device']}:{row['interface']}"
                for row in csv.DictReader(handle)
            }

    def html_ports(self):
        report = (self.results / "link-flap-analysis.html").read_text(
            encoding="utf-8"
        )
        return set(re.findall(r'data-port-key="([^"]+)"', report))

    def timeline_objects(self):
        path = self.results / "events" / "flap.json"
        events = json.loads(path.read_text(encoding="utf-8"))["events"]
        return sorted(
            (event["device"], event["object"]) for event in events
        )

    def assert_reported_ports(self, expected):
        """Every published surface lists exactly *expected*."""
        expected = set(expected)
        self.assertEqual(self.history_ports(), expected)
        self.assertEqual(set(self.export_rows()), expected)
        self.assertEqual(self.csv_ports(), expected)
        self.assertEqual(self.html_ports(), expected)
        self.assertEqual(self.summary()["total_ports"], len(expected))
        self.assertEqual(self.export_json()["counts"]["total_ports"],
                         len(expected))


class RemovedPortTests(FlapSiteTestCase):
    """Carrier files read without a collection-error marker are the
    authority on which ports exist: a port that two of them in a row do not
    name is removed. An incomplete file prunes nothing."""

    HOSTS = ("auditflap-a", "auditflap-b")
    A = "auditflap-a"
    B = "auditflap-b"

    def test_a_breakout_split_drops_the_parent_port_everywhere(self):
        self.cycle({self.A: ["swp1:2", "swp6:14"], self.B: ["swp6:5"]})
        self.cycle({self.A: ["swp1:2", "swp6:38"], self.B: ["swp6:5"]})
        self.assertEqual(self.export_rows()[f"{self.A}:swp6"]["status"],
                         "warning")
        self.assertEqual(self.summary()["problematic_ports"], 1)

        split = {
            self.A: ["swp1:2", "swp6s0:0", "swp6s1:0", "swp6s2:0", "swp6s3:0"],
            self.B: ["swp6:5"],
        }
        # The first listing without swp6 only notes its absence.
        output = self.cycle(split)
        self.assertIn(
            f"1 port(s) of {self.A} are missing from this carrier listing; "
            "kept until the next complete collection confirms it", output,
        )
        self.assertNotIn("no longer present", output)
        self.assertIn(f"{self.A}:swp6", self.history()["absent_since"])
        self.assertEqual(self.export_rows()[f"{self.A}:swp6"]["status"],
                         "warning")

        # The second one confirms it.
        output = self.cycle(split)

        self.assert_port_gone_from_every_map(f"{self.A}:swp6")
        self.assert_reported_ports({
            f"{self.A}:swp1", f"{self.A}:swp6s0", f"{self.A}:swp6s1",
            f"{self.A}:swp6s2", f"{self.A}:swp6s3",
            # Same interface name on another host: not this file's business.
            f"{self.B}:swp6",
        })
        summary = self.summary()
        self.assertEqual(summary["problematic_ports"], 0)
        self.assertEqual(summary["warning_ports"], 0)
        self.assertEqual(summary["stable_ports"], 6)
        self.assertEqual(summary["stability_percent"], 100.0)
        self.assertEqual(summary["collection_status"], "current")
        self.assertIn("Total ports monitored: 6", output)
        self.assertIn("Warning ports: 0", output)
        self.assertIn(
            f"Removed 1 port(s) no longer present on {self.A} "
            "from the flap history", output,
        )
        self.assertNotIn(f"no longer present on {self.B}", output)

        # Nothing is left to remove on the next cycle.
        output = self.cycle(split)
        self.assertNotIn("no longer present", output)
        self.assertNotIn("missing from this carrier listing", output)
        self.assertEqual(self.history()["absent_since"], {})

    def test_a_breakout_merge_drops_the_sub_ports(self):
        self.cycle({
            self.A: ["swp1:2", "swp6s0:4", "swp6s1:4", "swp6s2:0", "swp6s3:0"],
            self.B: ["swp1:0"],
        })
        for _listing in range(2):
            self.cycle({self.A: ["swp1:2", "swp6:0"], self.B: ["swp1:0"]})
        self.assert_reported_ports(
            {f"{self.A}:swp1", f"{self.A}:swp6", f"{self.B}:swp1"}
        )

    def test_a_returning_name_starts_from_a_new_baseline(self):
        # Pruned state must not come back as a delta: 38 -> (gone) -> 2 is a
        # new port, not a counter that moved.
        self.cycle({self.A: ["swp1:2", "swp6:38"], self.B: ["swp1:0"]})
        for _listing in range(2):
            self.cycle({self.A: ["swp1:2", "swp6s0:0"], self.B: ["swp1:0"]})
        self.assert_port_gone_from_every_map(f"{self.A}:swp6")
        self.cycle({self.A: ["swp1:2", "swp6:40"], self.B: ["swp1:0"]})
        row = self.export_rows()[f"{self.A}:swp6"]
        self.assertEqual(row["flaps_24h"], 0)
        self.assertEqual(row["total_transitions"], 40)
        self.assertEqual(self.timeline_objects(), [])

    def test_an_unavailable_row_counts_as_present_and_keeps_its_baseline(self):
        self.cycle({
            self.A: ["swp1:5000", "swp2:10", "swp3:7"], self.B: ["swp1:0"],
        })
        # swp1's counter could not be read; swp3 is no longer listed at all.
        for _listing in range(2):
            self.cycle({
                self.A: ["swp1:unavailable", "swp2:10"], self.B: ["swp1:0"],
            })
        history = self.history()
        self.assertEqual(history["prev_cumulative"][f"{self.A}:swp1"], 5000)
        self.assertEqual(
            history["carrier_transitions_stats"][f"{self.A}:swp1"], 5000
        )
        self.assert_port_gone_from_every_map(f"{self.A}:swp3")
        self.assert_reported_ports(
            {f"{self.A}:swp1", f"{self.A}:swp2", f"{self.B}:swp1"}
        )
        # The unreadable counter is still a coverage gap for that host.
        self.assertEqual(self.summary()["collection_status"], "partial")

        self.cycle({self.A: ["swp1:5002", "swp2:10"], self.B: ["swp1:0"]})
        row = self.export_rows()[f"{self.A}:swp1"]
        self.assertEqual(row["flaps_24h"], 1, "the real delta is one flap")

    def test_a_file_of_unavailable_rows_alone_still_prunes(self):
        self.cycle({self.A: ["swp1:3", "swp6:14"], self.B: ["swp1:0"]})
        for _listing in range(2):
            self.cycle({self.A: ["swp1:unavailable"], self.B: ["swp1:0"]})
        self.assert_port_gone_from_every_map(f"{self.A}:swp6")
        self.assertEqual(
            self.history()["prev_cumulative"][f"{self.A}:swp1"], 3
        )

    def test_an_incomplete_file_prunes_nothing(self):
        incomplete = {
            "inventory marker": [
                "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY", "swp1:2",
            ],
            "unknown marker": [
                "swp1:2", "__LLDPQ_COLLECTION_ERROR__:SOMETHING_NEW",
            ],
            "row without a counter": ["swp1:2", "swp7"],
            "non-numeric counter": ["swp1:2", "swp7:many"],
            "negative counter": ["swp1:2", "swp7:-4"],
            "unnamed unavailable row": ["swp1:2", ":unavailable"],
            "no port rows at all": [],
            "sub-interface rows only": ["swp6.100:14"],
        }
        for label, rows in incomplete.items():
            with self.subTest(label):
                self.write_history({
                    f"{self.A}:swp1": (2, 0, False),
                    f"{self.A}:swp6": (38, 12, True),
                    f"{self.B}:swp1": (0, 0, False),
                })
                self.cycle({self.A: rows, self.B: ["swp1:0"]})
                history = self.history()
                for name in STATE_MAPS:
                    self.assertIn(f"{self.A}:swp6", history[name], name)
                # ... and it is no evidence that the port is absent either.
                self.assertEqual(history["absent_since"], {})
                row = self.export_rows()[f"{self.A}:swp6"]
                self.assertEqual(row["status"], "warning")
                self.assertEqual(row["flaps_1h"], 12)
                self.assertEqual(row["total_transitions"], 38)
                self.assertEqual(self.summary()["collection_status"],
                                 "partial")

        # Control: the same history with marker-free files does prune.
        self.write_history({
            f"{self.A}:swp1": (2, 0, False),
            f"{self.A}:swp6": (38, 12, True),
            f"{self.B}:swp1": (0, 0, False),
        })
        for _listing in range(2):
            self.cycle({self.A: ["swp1:2"], self.B: ["swp1:0"]})
        self.assert_port_gone_from_every_map(f"{self.A}:swp6")

    def test_a_key_that_is_not_host_and_interface_is_left_alone(self):
        # Only "host:interface" keys are that host's ports; a malformed key
        # that happens to equal the host name is not this prune's to judge.
        self.write_history({
            f"{self.A}:swp1": (2, 0, False),
            f"{self.A}:swp6": (38, 0, False),
            self.A: (9, 0, False),
            f"{self.B}:swp1": (0, 0, False),
        })
        for _listing in range(2):
            self.cycle({self.A: ["swp1:2"], self.B: ["swp1:0"]})
        history = self.history()
        self.assertIn(self.A, history["carrier_transitions_stats"])
        self.assertNotIn(f"{self.A}:swp6", history["carrier_transitions_stats"])

    def test_a_host_without_a_current_file_keeps_its_ports(self):
        self.cycle({self.A: ["swp1:2", "swp6:14"], self.B: ["swp1:0"]})
        # auditflap-a was not collected this cycle (a hard flap does that).
        self.cycle({self.A: None, self.B: ["swp1:0"]})
        self.assert_reported_ports(
            {f"{self.A}:swp1", f"{self.A}:swp6", f"{self.B}:swp1"}
        )
        self.assertEqual(self.summary()["collection_status"], "partial")


class HostNameBoundaryTests(FlapSiteTestCase):
    """The prune is per host, and a dot in a HOST name is not a
    sub-interface."""

    HOSTS = ("auditflap-1", "auditflap-10", "auditflap-a.lab.example")

    def test_only_the_reconfigured_host_loses_ports(self):
        fqdn = "auditflap-a.lab.example"
        self.cycle({
            "auditflap-1": ["swp1:2", "swp6:14"],
            "auditflap-10": ["swp1:2", "swp6:14"],
            fqdn: ["swp1:2", "swp6:14"],
        })
        for _listing in range(2):
            self.cycle({
                "auditflap-1": ["swp1:2", "swp6s0:0"],
                "auditflap-10": ["swp1:2", "swp6:14"],
                fqdn: ["swp1:2", "swp6:38"],
            })
        self.assert_reported_ports({
            "auditflap-1:swp1", "auditflap-1:swp6s0",
            "auditflap-10:swp1", "auditflap-10:swp6",
            f"{fqdn}:swp1", f"{fqdn}:swp6",
        })
        self.assertEqual(self.export_rows()[f"{fqdn}:swp6"]["flaps_1h"], 12)
        self.assertEqual(self.timeline_objects(), [(fqdn, "swp6")])
        self.assertEqual(self.summary()["collection_status"], "current")


class SubInterfaceTests(FlapSiteTestCase):
    """A name containing '.' (VLAN sub-interface) is never a flap port."""

    A = "auditflap-a"

    def test_one_physical_flap_is_billed_once(self):
        self.cycle({self.A: [
            "swp1:2", "swp6:14", "swp6.100:14", "swp6.200:14", "swp6s1.300:3",
        ]})
        self.assert_reported_ports({f"{self.A}:swp1", f"{self.A}:swp6"})

        # swp6 bounces 12 times; the 8021q children copy its carrier.
        output = self.cycle({self.A: [
            "swp1:2", "swp6:38", "swp6.100:38", "swp6.200:38", "swp6s1.300:3",
        ]})

        self.assert_reported_ports({f"{self.A}:swp1", f"{self.A}:swp6"})
        rows = self.export_rows()
        self.assertEqual(rows[f"{self.A}:swp6"]["status"], "warning")
        self.assertEqual(rows[f"{self.A}:swp6"]["flaps_1h"], 12)
        summary = self.summary()
        self.assertEqual(summary["problematic_ports"], 1)
        self.assertEqual(summary["warning_ports"], 1)
        self.assertEqual(summary["stable_ports"], 1)
        self.assertEqual(summary["stability_percent"], 50.0)
        self.assertEqual(self.timeline_objects(), [(self.A, "swp6")])
        self.assertIn("Warning ports: 1", output)
        self.assertNotIn("swp6.100", output)

    def test_sub_interface_rows_are_not_a_collection_problem(self):
        # Whatever such a row holds, it neither becomes a port nor turns a
        # complete collection into a partial one.
        self.cycle({self.A: [
            "swp1:2", "swp6.100:unavailable", "swp6.200:many", "swp6.300:-1",
        ]})
        self.assert_reported_ports({f"{self.A}:swp1"})
        summary = self.summary()
        self.assertEqual(summary["collection_status"], "current")
        self.assertEqual(summary["coverage_current"], 1)

    def test_history_written_by_the_old_code_is_cleaned(self):
        old_history = {
            f"{self.A}:swp1": (2, 0, False),
            f"{self.A}:swp6": (38, 12, True),
            f"{self.A}:swp6.100": (38, 12, True),
            f"{self.A}:swp6.200": (38, 12, True),
            f"{self.A}:swp6s1.300": (3, 0, False),
        }
        carrier_files = {
            # The fixed collector no longer lists sub-interfaces ...
            "new collector": ["swp1:2", "swp6:62"],
            # ... but a file collected before the upgrade still does.
            "old collector": [
                "swp1:2", "swp6:62", "swp6.100:62", "swp6.200:62",
                "swp6s1.300:3",
            ],
        }
        for label, rows in carrier_files.items():
            with self.subTest(label):
                events = self.results / "events" / "flap.json"
                if events.exists():
                    events.unlink()
                self.write_history(old_history)

                output = self.cycle({self.A: rows})

                for port in old_history:
                    if "." in port.split(":", 1)[1]:
                        self.assert_port_gone_from_every_map(port)
                self.assert_reported_ports(
                    {f"{self.A}:swp1", f"{self.A}:swp6"}
                )
                # The parent keeps its own history and gains this cycle's.
                row = self.export_rows()[f"{self.A}:swp6"]
                self.assertEqual(row["status"], "critical")
                self.assertEqual(row["flaps_1h"], 24)
                self.assertEqual(row["total_transitions"], 62)
                summary = self.summary()
                self.assertEqual(summary["critical_ports"], 1)
                self.assertEqual(summary["warning_ports"], 0)
                self.assertEqual(summary["problematic_ports"], 1)
                self.assertEqual(summary["stability_percent"], 50.0)
                self.assertEqual(summary["collection_status"], "current")
                self.assertEqual(self.timeline_objects(), [(self.A, "swp6")])
                self.assertIn("Critical ports: 1", output)

    def test_state_persisted_by_the_old_row_loop_is_cleaned(self):
        # The old row loop handed every name in the file to the analyzer.
        # Replay exactly that to persist the state it left behind: one
        # physical flap burst on swp6, billed three times.
        analyzer = LinkFlapAnalyzer(str(self.results))
        for counter in (14, 38):
            for interface in ("swp6", "swp6.100", "swp6.200"):
                analyzer.update_carrier_transitions(
                    f"{self.A}:{interface}", counter
                )
            analyzer.update_carrier_transitions(f"{self.A}:swp1", 2)
        analyzer.set_collection_coverage({self.A}, {self.A})
        self.assertTrue(analyzer.save_flap_history())
        self.assertEqual(
            self.history()["flapping_hist"][f"{self.A}:swp6.100"][0][2], 12,
            "guard: the old state must bill the sub-interface",
        )

        self.cycle({self.A: ["swp1:2", "swp6:38"]})

        self.assert_reported_ports({f"{self.A}:swp1", f"{self.A}:swp6"})
        rows = self.export_rows()
        self.assertEqual(rows[f"{self.A}:swp6"]["status"], "warning")
        self.assertEqual(rows[f"{self.A}:swp6"]["flaps_1h"], 12)
        self.assertEqual(rows[f"{self.A}:swp6"]["total_transitions"], 38)
        summary = self.summary()
        self.assertEqual(summary["total_ports"], 2)
        self.assertEqual(summary["warning_ports"], 1)
        self.assertEqual(summary["problematic_ports"], 1)
        self.assertEqual(summary["stability_percent"], 50.0)
        self.assertEqual(self.timeline_objects(), [])

    def test_old_sub_interface_rows_wait_for_a_complete_file(self):
        # The complete-file prune owns the removal: an incomplete file prunes
        # nothing, but a sub-interface row in it still adds no sample,
        # baseline or event.
        port = f"{self.A}:swp6.100"
        self.write_history({
            f"{self.A}:swp1": (2, 0, False),
            f"{self.A}:swp6": (38, 0, False),
            port: (38, 0, False),
        })
        before = self.history()

        self.cycle({self.A: [
            "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY",
            "swp1:2", "swp6:62", "swp6.100:62",
        ]})

        history = self.history()
        self.assertEqual(history["prev_cumulative"][port], 38)
        self.assertEqual(
            history["prev_sample_time"][port],
            before["prev_sample_time"][port],
        )
        self.assertEqual(history["carrier_transitions_stats"][port], 38)
        self.assertEqual(history["flapping_hist"][port], [])
        self.assertEqual(self.timeline_objects(), [(self.A, "swp6")])
        self.assertEqual(self.export_rows()[port]["flaps_24h"], 0)

        # The next complete file removes it.
        self.cycle({self.A: ["swp1:2", "swp6:62"]})
        self.assert_port_gone_from_every_map(port)
        self.assert_reported_ports({f"{self.A}:swp1", f"{self.A}:swp6"})


if __name__ == "__main__":
    unittest.main()
