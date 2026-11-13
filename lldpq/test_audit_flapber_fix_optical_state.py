#!/usr/bin/env python3
"""Immediate-mode optical alert: when a degradation may be called cleared.

A switch with a degrading optic next to a link-down port has a combined
alert state, and its end is announced as a green "Optical Warning Cleared" /
"Optical Critical Cleared". That recovery was decided from the number of
link-down ports alone, so it was also sent when the degraded port had merely
stopped answering, timed out or been pulled, when it went down in the run in
which another link came back, and while another port newly failed.

* The state records which ports were degraded and which were otherwise
  impaired. "Cleared" needs every degraded port healthy again and no port
  newly down, unreadable or unplugged; a degraded port stays on record until
  it is seen healthy. Anything else is the plain warning of what is left.
* An unplugged or unreadable port next to a warning forms a combined state as
  a link-down one does: the warning alerts at once and its end is a recovery,
  not a second "module is unplugged" / "diagnostics are incomplete" warning.

Shard fixtures (health per port) run through the real
check_processed_network_alerts; nothing is delivered because the Slack
channel is disabled in the throwaway notifications.yaml.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from test_audit_beralert_alerts import HOST, AlertSiteTestCase  # noqa: E402


LINK_DOWN = ("WARNING", "Optical Warning", "reports a monitored optical link is down")
UNPLUGGED = ("WARNING", "Optical Warning",
             "reports an expected optical module is unplugged")
UNREADABLE = ("WARNING", "Optical Warning",
              "reports current diagnostics are incomplete or unknown")
CRITICAL = ("CRITICAL", "Optical Critical", "reports a critical condition")


class OpticalStateTestCase(AlertSiteTestCase):
    def setUp(self):
        super().setUp()
        # Shard era without a BER shard: the BER domain stays silent.
        (self.results / "ber-history").mkdir()

    def publish(self, **ports):
        shard_dir = self.results / "optical-history"
        shard_dir.mkdir(exist_ok=True)
        (shard_dir / f"{HOST}.json").write_text(json.dumps({
            "version": 1, "host": HOST, "history": {},
            "current": {
                f"{HOST}:{name}": {"health_status": health}
                for name, health in ports.items()
            },
        }))

    def run_once(self, _options=None, **ports):
        """One alert run: (state name, [(severity, title, text)])."""
        self.publish(**ports)
        alerts = self.immediate(**(_options or {}))
        return (
            alerts.get_alert_state(HOST, "optical_health").partition(":")[0],
            [(severity, title, message.replace("Processed Optical analysis ", ""))
             for severity, title, message in alerts.delivered],
        )

    def recorded_ports(self):
        """[degraded, otherwise impaired] ports of the persisted state."""
        state = self.checker().get_alert_state(HOST, "optical_health")
        return json.loads(state.partition(":")[2])

    def assert_never_green(self, deliveries):
        self.assertFalse(
            [item for item in deliveries if item[0] == "RECOVERED"], deliveries
        )


class DegradedPortThatDidNotRecoverTests(OpticalStateTestCase):
    """The degraded port is gone, not healthy: no recovery is announced."""

    def test_degraded_port_that_stops_answering_or_is_pulled_is_not_cleared(self):
        cases = {
            "critical, then unreadable": ("critical", "unknown", "CRITICAL+DOWN"),
            "critical, then pulled": ("critical", "unplugged", "CRITICAL+DOWN"),
            "warning, then unreadable": ("warning", "unknown", "WARNINGS+DOWN"),
            "warning, then pulled": ("warning", "unplugged", "WARNINGS+DOWN"),
        }
        for label, (degraded, afterwards, combined) in cases.items():
            with self.subTest(label):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                # A twin-port module (two port rows) next to a link-down port.
                self.run_once(swp6s0="excellent", swp6s1="excellent",
                              swp10="down")
                state, _ = self.run_once(swp6s0="excellent", swp6s1=degraded,
                                         swp10="down")
                self.assertEqual(state, combined)
                self.assertEqual(self.recorded_ports(), [["swp6s1"], ["swp10"]])

                state, deliveries = self.run_once(
                    swp6s0=afterwards, swp6s1=afterwards, swp10="down"
                )
                self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))
                # ... and nothing follows while the picture stays the same.
                self.assertEqual(
                    self.run_once(swp6s0=afterwards, swp6s1=afterwards,
                                  swp10="down"),
                    ("DOWN", []),
                )

    def test_degraded_port_going_down_while_another_link_returns(self):
        # The number of down links is the same before and after.
        for degraded in ("warning", "critical"):
            with self.subTest(degraded=degraded):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                self.run_once(swp1=degraded, swp2="down", swp3="excellent")
                state, deliveries = self.run_once(
                    swp1="down", swp2="excellent", swp3="excellent"
                )
                self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

    def test_degraded_port_missing_from_the_report_is_not_cleared(self):
        # An unexpected module that is pulled leaves no row at all.
        self.run_once(swp1="warning", swp2="down")
        state, deliveries = self.run_once(swp2="down")
        self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

    def test_degraded_port_stays_on_record_until_it_is_healthy(self):
        self.run_once(swp1="warning", swp2="down", swp3="warning")
        # swp1 stops answering while swp3 keeps the warning: same state, no
        # alert, and swp1 is still recorded as degraded.
        state, deliveries = self.run_once(
            swp1="unknown", swp2="down", swp3="warning"
        )
        self.assertEqual((state, deliveries), ("WARNINGS+DOWN", []))
        self.assertEqual(self.recorded_ports(),
                         [["swp1", "swp3"], ["swp1", "swp2"]])

        state, deliveries = self.run_once(
            swp1="unknown", swp2="down", swp3="excellent"
        )
        self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

    def test_recorded_port_that_recovers_later_lets_the_warning_clear(self):
        self.run_once(swp1="warning", swp2="down", swp3="warning")
        self.run_once(swp1="unknown", swp2="down", swp3="warning")
        # swp1 answers again and is healthy; swp3 still warns.
        state, deliveries = self.run_once(
            swp1="excellent", swp2="down", swp3="warning"
        )
        self.assertEqual((state, deliveries), ("WARNINGS+DOWN", []))
        self.assertEqual(self.recorded_ports(), [["swp3"], ["swp2"]])

        state, deliveries = self.run_once(
            swp1="excellent", swp2="down", swp3="excellent"
        )
        self.assertEqual(state, "DOWN")
        self.assertEqual(
            [(severity, title) for severity, title, _ in deliveries],
            [("RECOVERED", "Optical Warning Cleared")],
        )

    def test_critical_port_dying_under_a_second_critical_is_not_cleared(self):
        # Link changes under a critical are recorded without an alert, so
        # the state must remember that the port which went down was critical.
        state, deliveries = self.run_once(swp1="critical", swp2="critical")
        self.assertEqual((state, deliveries), ("CRITICAL", [CRITICAL]))
        self.assertEqual(self.recorded_ports(), [["swp1", "swp2"], []])

        state, deliveries = self.run_once(swp1="down", swp2="critical")
        self.assertEqual((state, deliveries), ("CRITICAL+DOWN", []))
        self.assertEqual(self.recorded_ports(), [["swp1", "swp2"], ["swp1"]])

        state, deliveries = self.run_once(swp1="down", swp2="excellent")
        self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

    def test_warning_port_failing_under_a_second_warning_is_not_cleared(self):
        self.run_once(swp1="warning", swp2="warning")
        state, deliveries = self.run_once(swp1="unplugged", swp2="warning")
        self.assertEqual(state, "WARNINGS+UNPLUGGED")
        self.assertEqual(
            [text for _, _, text in deliveries],
            ["reports a warning condition; "
             "an expected optical module is also unplugged"],
        )
        state, deliveries = self.run_once(swp1="unplugged", swp2="excellent")
        self.assertEqual((state, deliveries), ("UNPLUGGED", [UNPLUGGED]))


class NothingElseGotWorseTests(OpticalStateTestCase):
    """A recovery is not announced in a run in which another port failed."""

    def test_cleared_warning_with_a_newly_failed_port_is_a_warning(self):
        for failure in ("unplugged", "unknown", "down"):
            with self.subTest(failure=failure):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                self.run_once(swp1="warning", swp2="down", swp3="excellent")
                state, deliveries = self.run_once(
                    swp1="excellent", swp2="down", swp3=failure
                )
                self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

    def test_port_that_was_already_impaired_does_not_block_the_recovery(self):
        self.run_once(swp1="warning", swp2="down", swp3="unplugged",
                      swp4="unknown")
        self.assertEqual(self.recorded_ports(),
                         [["swp1"], ["swp2", "swp3", "swp4"]])
        # The unreadable port answers again; nothing new is impaired.
        state, deliveries = self.run_once(
            swp1="excellent", swp2="down", swp3="unplugged", swp4="good"
        )
        self.assertEqual(state, "DOWN")
        self.assertEqual(deliveries, [(
            "RECOVERED", "Optical Warning Cleared",
            "no longer reports a warning condition; "
            "a monitored optical link is still down",
        )])

    def test_other_condition_changing_kind_is_not_a_recovery(self):
        # The link returned, but the warning's end leaves a module that was
        # unplugged all along and never announced behind the link-down state.
        self.run_once(swp1="warning", swp2="down", swp3="unplugged")
        state, deliveries = self.run_once(
            swp1="excellent", swp2="excellent", swp3="unplugged"
        )
        self.assertEqual((state, deliveries), ("UNPLUGGED", [UNPLUGGED]))

    def test_link_down_warning_is_delivered_with_recoveries_disabled(self):
        quiet = {"send_recovery": False}
        self.run_once(quiet, swp1="warning", swp2="down")
        # The warning port died: a warning, not a recovery, so it is sent.
        state, deliveries = self.run_once(quiet, swp1="down", swp2="down")
        self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))

        # A real recovery stays silent with recoveries disabled.
        self.run_once(quiet, swp1="warning", swp2="down")
        state, deliveries = self.run_once(quiet, swp1="excellent", swp2="down")
        self.assertEqual((state, deliveries), ("DOWN", []))

    def test_state_without_a_readable_port_record_is_never_cleared(self):
        for record in ("WARNINGS+DOWN:1", "WARNINGS+DOWN", "WARNINGS+DOWN:{",
                       'WARNINGS+DOWN:[["swp1"]]', "WARNINGS+DOWN:[1,2]"):
            with self.subTest(record=record):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                self.checker().set_alert_state(HOST, "optical_health", record)
                state, deliveries = self.run_once(swp1="excellent", swp2="down")
                self.assertEqual((state, deliveries), ("DOWN", [LINK_DOWN]))


class UnpluggedAndUnreadableTests(OpticalStateTestCase):
    """A warning next to an unplugged or unreadable port behaves as it does
    next to a link-down one."""

    CONDITIONS = {
        "unplugged": ("UNPLUGGED", "WARNINGS+UNPLUGGED", UNPLUGGED,
                      "an expected optical module is {}unplugged"),
        "unknown": ("WARNING_UNKNOWN", "WARNINGS+UNKNOWN", UNREADABLE,
                    "current diagnostics are {}incomplete or unknown"),
    }

    def test_warning_next_to_the_condition_is_announced_and_cleared(self):
        for health, (plain, combined, first, text) in self.CONDITIONS.items():
            with self.subTest(health=health):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                self.assertEqual(self.run_once(swp1="excellent", swp2=health),
                                 (plain, [first]))
                self.assertEqual(self.run_once(swp1="warning", swp2=health), (
                    combined, [(
                        "WARNING", "Optical Warning",
                        "reports a warning condition; " + text.format("also "),
                    )],
                ))
                self.assertEqual(self.recorded_ports(), [["swp1"], ["swp2"]])
                self.assertEqual(self.run_once(swp1="warning", swp2=health),
                                 (combined, []))
                self.assertEqual(self.run_once(swp1="excellent", swp2=health), (
                    plain, [(
                        "RECOVERED", "Optical Warning Cleared",
                        "no longer reports a warning condition; "
                        + text.format("still "),
                    )],
                ))
                self.assertEqual(
                    self.run_once(swp1="excellent", swp2="excellent"),
                    ("OK", [("RECOVERED", "Optical Recovered", "is healthy")]),
                )

    def test_critical_next_to_the_condition_is_cleared(self):
        for health, (plain, _combined, _first, text) in self.CONDITIONS.items():
            with self.subTest(health=health):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                self.run_once(swp1="excellent", swp2=health)
                state, deliveries = self.run_once(swp1="critical", swp2=health)
                self.assertEqual(
                    (state, deliveries),
                    (f"CRITICAL+{health.upper()}", [CRITICAL]),
                )
                self.assertEqual(self.run_once(swp1="excellent", swp2=health), (
                    plain, [(
                        "RECOVERED", "Optical Critical Cleared",
                        "no longer reports a critical condition; "
                        + text.format("still "),
                    )],
                ))

    def test_new_warning_does_not_wait_out_the_repeat_interval(self):
        throttled = {"min_interval": 30}
        for health, (plain, combined, first, _text) in self.CONDITIONS.items():
            with self.subTest(health=health):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                # The condition's own alert has just been delivered.
                self.assertEqual(
                    self.run_once(throttled, swp1="excellent", swp2=health),
                    (plain, [first]),
                )
                state, deliveries = self.run_once(
                    throttled, swp1="warning", swp2=health
                )
                self.assertEqual(state, combined)
                self.assertEqual(
                    [(severity, title) for severity, title, _ in deliveries],
                    [("WARNING", "Optical Warning")],
                )

    def test_combined_states_rank_between_a_warning_and_a_critical(self):
        rank = self.checker()._state_severity_rank
        for combined in ('WARNINGS+UNPLUGGED:[["swp1"],["swp2"]]',
                         'WARNINGS+UNKNOWN:[["swp1"],["swp2"]]',
                         'WARNINGS+DOWN:[["swp1"],["swp2"]]'):
            with self.subTest(combined=combined):
                self.assertGreater(rank(combined), rank("UNPLUGGED"))
                self.assertGreater(rank(combined), rank("WARNING_UNKNOWN"))
                self.assertGreater(rank(combined), rank('WARNINGS:[["swp1"],[]]'))
                self.assertLess(rank(combined), rank('CRITICAL:[["swp1"],[]]'))
        self.assertEqual(rank('CRITICAL+UNPLUGGED:[["swp1"],["swp2"]]'),
                         rank("CRITICAL"))


class StateFormatTests(OpticalStateTestCase):
    def test_state_written_before_the_port_record_is_adopted_silently(self):
        # The last commit stored the bare name; the same condition must not
        # be announced again only because the record gained its ports.
        for bare, health in (("WARNINGS", "warning"), ("CRITICAL", "critical")):
            with self.subTest(bare=bare):
                self.checker().set_alert_state(HOST, "optical_health", bare)
                state, deliveries = self.run_once(swp1=health, swp2="excellent")
                self.assertEqual((state, deliveries), (bare, []))
                self.assertEqual(self.recorded_ports(), [["swp1"], []])

    def test_ber_states_carry_no_port_record(self):
        # Only the optical domain knows its ports; the BER state stays bare.
        alerts = self.checker()
        self.assertTrue(alerts._notify_processed_health(
            HOST, "ber_health", "BER", "warnings"
        ))
        self.assertEqual(alerts.get_alert_state(HOST, "ber_health"), "WARNINGS")
        self.assertTrue(alerts._notify_processed_health(
            HOST, "ber_health", "BER", "critical"
        ))
        self.assertEqual(alerts.get_alert_state(HOST, "ber_health"), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
