#!/usr/bin/env python3
"""Link Flap: a port leaves the report only when two listings agree.

Removing every port that one complete carrier file did not name had a cost
that only showed in a sequence. While switchd restarts or a breakout is
applied a switch lists fewer ports for a moment; a collection that caught it
erased the WARNING/CRITICAL flap state of the missing ports for good, and in
immediate mode a green "Link Flaps Stabilized" was sent for ports that were
still flapping.

* A port is removed when two complete files in a row do not name it. Until
  then it keeps its row, its counter, its flap history and its status.
* Only an interface name followed by VLAN ids is a sub-interface. Any other
  text with a dot in it is a damaged row again: it marks the collection
  incomplete, so nothing is removed on its account.

Every test drives the real process_carrier_transition_files; the alert test
reads its history through the real LLDPqAlerts.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts  # noqa: E402
import process_flap_data  # noqa: E402
from test_audit_flap_ports import STATE_MAPS, FlapSiteTestCase  # noqa: E402


NOTIFICATIONS = """notifications:
  enabled: true
  slack:
    enabled: false
alert_types:
  network_alerts: true
frequency:
  min_interval_minutes: 0
  retry_interval_minutes: 0
  send_recovery: true
thresholds:
  network:
    link_flaps_per_hour: 10
    link_flaps_critical: 20
"""
A = "auditflap-a"
PORTS = [f"swp{number}" for number in range(1, 9)]
# What a collection in the middle of a switchd restart sees: two of the
# eight ports, their counters restarted.
SHORT_LISTING = ["swp1:1", "swp2:1"]
MISSING = [f"{A}:swp{number}" for number in range(3, 9)]


class ShortListingTests(FlapSiteTestCase):
    def flapping(self):
        """Eight ports; swp3 flaps 30 times (critical), swp4 12 (warning)."""
        self.cycle({A: [f"{port}:4" for port in PORTS]})
        counters = dict.fromkeys(PORTS, 4)
        counters.update(swp3=64, swp4=28)
        self.cycle({A: [f"{port}:{count}" for port, count in counters.items()]})
        self.assert_flap_state_is_intact(total_transitions=(64, 28))

    def assert_flap_state_is_intact(self, total_transitions):
        rows = self.export_rows()
        self.assertEqual(len(rows), 8)
        for port, status, flaps, total in (
            ("swp3", "critical", 30, total_transitions[0]),
            ("swp4", "warning", 12, total_transitions[1]),
        ):
            row = rows[f"{A}:{port}"]
            self.assertEqual(
                (row["status"], row["flaps_1h"], row["flaps_24h"],
                 row["total_transitions"]),
                (status, flaps, flaps, total), port,
            )
        summary = self.summary()
        self.assertEqual(
            (summary["total_ports"], summary["critical_ports"],
             summary["warning_ports"], summary["stable_ports"]),
            (8, 1, 1, 6),
        )
        self.assertEqual(summary["collection_status"], "current")

    def test_one_short_listing_keeps_every_port_and_its_status(self):
        self.flapping()

        output = self.cycle({A: SHORT_LISTING})

        self.assertIn(
            f"6 port(s) of {A} are missing from this carrier listing; "
            "kept until the next complete collection confirms it", output,
        )
        self.assertNotIn("no longer present", output)
        self.assertEqual(sorted(self.history()["absent_since"]), MISSING)
        self.assert_flap_state_is_intact(total_transitions=(64, 28))
        self.assert_reported_ports({f"{A}:{port}" for port in PORTS})

        # All eight are back, with restarted counters.
        output = self.cycle({A: [f"{port}:1" for port in PORTS]})

        self.assertNotIn("missing from this carrier listing", output)
        self.assertNotIn("no longer present", output)
        self.assertEqual(self.history()["absent_since"], {})
        # Still graded from the flaps that did happen; the restarted
        # counters are a new baseline, not new flaps.
        self.assert_flap_state_is_intact(total_transitions=(1, 1))
        self.assertEqual(self.timeline_objects(), [(A, "swp3"), (A, "swp4")])

    def test_second_listing_without_the_ports_removes_them(self):
        self.flapping()
        self.cycle({A: SHORT_LISTING})

        output = self.cycle({A: SHORT_LISTING})

        self.assertIn(
            f"Removed 6 port(s) no longer present on {A} from the flap history",
            output,
        )
        self.assertNotIn("missing from this carrier listing", output)
        for port in MISSING:
            self.assert_port_gone_from_every_map(port)
        self.assert_reported_ports({f"{A}:swp1", f"{A}:swp2"})
        self.assertEqual(self.summary()["problematic_ports"], 0)

    def immediate_flap_alert(self):
        """The real per-device link-flap alert: (state, deliveries)."""
        (self.root / "notifications.yaml").write_text(NOTIFICATIONS)
        with contextlib.redirect_stdout(io.StringIO()):
            alerts = check_alerts.LLDPqAlerts(str(self.root))
            self.assertTrue(alerts.config)
            delivered = []
            send = alerts.send_notification

            def record(title, message, severity, device, alert_type=""):
                delivered.append((severity, title, message))
                return send(title, message, severity, device, alert_type)

            alerts.send_notification = record
            # Only the link-flap part of the network alerts is under test.
            alerts.get_device_bgp_status = lambda device: "stale"
            alerts.get_device_bgp_flap_counts = (
                lambda device, window_seconds=3600: None
            )
            alerts.get_device_bgp_update_storms = (
                lambda device, window_seconds=3600: None
            )
            alerts.check_processed_network_alerts = lambda device: True
            alerts.check_network_alerts(A)
        return alerts.get_alert_state(A, "link_flaps"), delivered

    def test_short_listing_does_not_report_the_flaps_as_stabilized(self):
        self.flapping()
        self.assertEqual(self.immediate_flap_alert(), ("CRITICAL", [(
            "CRITICAL", "⚡ Critical Link Flapping",
            "Interfaces with excessive flaps: swp3: 30",
        )]))

        self.cycle({A: SHORT_LISTING})
        self.assertEqual(self.immediate_flap_alert(), ("CRITICAL", []))

        self.cycle({A: [f"{port}:1" for port in PORTS]})
        self.assertEqual(self.immediate_flap_alert(), ("CRITICAL", []))

    def test_port_listed_again_starts_the_count_over(self):
        self.cycle({A: ["swp1:2", "swp6:14"]})
        self.cycle({A: ["swp1:2"]})
        self.assertEqual(list(self.history()["absent_since"]), [f"{A}:swp6"])
        # It is listed again, then missing once more: one listing, not two.
        self.cycle({A: ["swp1:2", "swp6:14"]})
        self.assertEqual(self.history()["absent_since"], {})
        output = self.cycle({A: ["swp1:2"]})
        self.assertNotIn("no longer present", output)
        self.assert_reported_ports({f"{A}:swp1", f"{A}:swp6"})

        self.cycle({A: ["swp1:2"]})
        self.assert_port_gone_from_every_map(f"{A}:swp6")

    def test_incomplete_file_that_names_the_port_clears_its_absence(self):
        self.cycle({A: ["swp1:2", "swp6:14"]})
        self.cycle({A: ["swp1:2"]})
        # The inventory marker makes the file incomplete, but swp6 is there.
        self.cycle({A: [
            "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY", "swp1:2", "swp6:14",
        ]})
        self.assertEqual(self.history()["absent_since"], {})
        self.cycle({A: ["swp1:2"]})
        self.assert_reported_ports({f"{A}:swp1", f"{A}:swp6"})

    def test_unreadable_counter_counts_as_listed(self):
        self.cycle({A: ["swp1:2", "swp6:14"]})
        self.cycle({A: ["swp1:2"]})
        self.cycle({A: ["swp1:2", "swp6:unavailable"]})
        self.assertEqual(self.history()["absent_since"], {})
        self.assertEqual(self.history()["prev_cumulative"][f"{A}:swp6"], 14)

    def test_file_that_proves_nothing_neither_confirms_nor_clears(self):
        not_proof = {
            "incomplete file without the port": [
                "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY", "swp1:2",
            ],
            "host not collected": None,
        }
        for label, rows in not_proof.items():
            with self.subTest(label):
                history = self.results / "flap_history.json"
                if history.exists():
                    history.unlink()
                self.cycle({A: ["swp1:2", "swp6:14"]})
                self.cycle({A: ["swp1:2"]})
                self.cycle({A: rows})
                persisted = self.history()
                self.assertEqual(list(persisted["absent_since"]),
                                 [f"{A}:swp6"])
                for name in STATE_MAPS:
                    if name != "pending_transition_start":
                        self.assertIn(f"{A}:swp6", persisted[name], name)
                # The next complete listing is the second one.
                self.cycle({A: ["swp1:2"]})
                self.assert_port_gone_from_every_map(f"{A}:swp6")


class RetiredHostTests(FlapSiteTestCase):
    HOSTS = ("auditflap-a", "auditflap-b")

    def test_retired_host_takes_its_absence_notes_along(self):
        other = "auditflap-b"
        self.cycle({A: ["swp1:2"], other: ["swp1:2", "swp6:14"]})
        self.cycle({A: ["swp1:2"], other: ["swp1:2"]})
        self.assertEqual(list(self.history()["absent_since"]), [f"{other}:swp6"])

        # The switch leaves the inventory.
        self.HOSTS = (A,)
        (self.root / "devices.yaml").write_text(
            f"devices:\n  192.0.2.11: {A}\n", encoding="utf-8"
        )
        self.cycle({A: ["swp1:2"]})
        self.assertEqual(self.history()["absent_since"], {})
        self.assertEqual(self.history_ports(), {f"{A}:swp1"})


class SubInterfaceNameTests(FlapSiteTestCase):
    def test_only_an_interface_name_with_vlan_ids_is_a_sub_interface(self):
        verdicts = {
            name: process_flap_data._is_subinterface(name)
            for name in (
                "swp6.100", "swp1s0.300", "swp6.100.200", "bond1.20",
                "peerlink.4094", "bond-uplink.7", "eth1.5",
                "swp6", "swp1s0", "bond1", "", ".", ".100", "swp6.",
                "swp6.10a", "swp6.-1", "6.100", "./collect.sh", "bash.rc",
                "swp 6.100", "swp6..100",
            )
        }
        self.assertEqual(
            {name for name, sub_interface in verdicts.items() if sub_interface},
            {"swp6.100", "swp1s0.300", "swp6.100.200", "bond1.20",
             "peerlink.4094", "bond-uplink.7", "eth1.5"},
        )

    def test_dotted_garbage_row_marks_the_collection_incomplete(self):
        for garbage in ("./collect.sh: line 3: read error",
                        "ip.link: command failed"):
            with self.subTest(garbage=garbage):
                self.write_history({
                    f"{A}:swp1": (2, 0, False),
                    f"{A}:swp6": (38, 12, True),
                    f"{A}:swp7": (0, 0, False),
                })
                output = self.cycle({A: ["swp1:2", garbage]})

                self.assertNotIn("no longer present", output)
                self.assertNotIn("missing from this carrier listing", output)
                history = self.history()
                self.assertEqual(history["absent_since"], {})
                for name in STATE_MAPS:
                    self.assertIn(f"{A}:swp6", history[name], name)
                self.assertEqual(
                    self.export_rows()[f"{A}:swp6"]["status"], "warning"
                )
                self.assertNotEqual(self.summary()["collection_status"],
                                    "current")

    def test_stacked_vlan_sub_interface_is_never_a_port(self):
        self.cycle({A: ["swp1:2", "swp6:14", "swp6.100.200:14"]})
        self.cycle({A: ["swp1:2", "swp6:38", "swp6.100.200:38"]})
        self.assert_reported_ports({f"{A}:swp1", f"{A}:swp6"})
        self.assertEqual(self.timeline_objects(), [(A, "swp6")])
        self.assertEqual(self.summary()["collection_status"], "current")

    def test_persisted_sub_interface_goes_with_the_first_complete_listing(self):
        self.write_history({
            f"{A}:swp1": (2, 0, False),
            f"{A}:swp6": (38, 12, True),
            f"{A}:swp6.100": (38, 12, True),
            f"{A}:swp7": (0, 0, False),
        })
        output = self.cycle({A: ["swp1:2", "swp6:38"]})
        # The sub-interface can never be listed again and goes at once; the
        # physical port swp7 waits for the second listing.
        self.assert_port_gone_from_every_map(f"{A}:swp6.100")
        self.assertIn(f"Removed 1 port(s) no longer present on {A}", output)
        self.assertIn(f"1 port(s) of {A} are missing", output)
        self.assert_reported_ports(
            {f"{A}:swp1", f"{A}:swp6", f"{A}:swp7"}
        )


if __name__ == "__main__":
    unittest.main()
