#!/usr/bin/env python3
"""Regression tests for the BER and optical alert decisions.

* An unused or down port made every Network Health Summary a WARNING with a
  "ports awaiting a complete traffic sample" line, and in immediate mode it
  kept every switch in a permanent "BER Warning" that never recovered.
  Ports that really are collecting a sample are shown in the BER block; they
  open no issue, because their count is not part of the change signature and
  a WARNING raised for them could never be taken back by a later run.
* The summary was re-sent whenever a port or device moved between the
  healthy bands (excellent <-> good) or between graded, idle and awaiting.
* In immediate mode one link-down optic fixed the device state at DOWN, so a
  degrading lane on another port raised no alert and its recovery was never
  announced.
* The summary called N unplugged breakout sub-ports "N expected modules".

The BER tests drive the real process_ber_data_files and read its report and
history shard through the real LLDPqAlerts; nothing is delivered because the
Slack channel is disabled in the throwaway notifications.yaml.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts
import process_ber_data


PROC_NET_DEV_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|"
    "bytes    packets errs drop fifo colls carrier compressed\n"
)
ISOLATED_ENVIRONMENT = (
    "LLDPQ_ASSETS_FILE", "LLDPQ_DEVICES_FILE", "LLDPQ_COLLECTION_STATUS_FILE",
    "LLDPQ_PIPELINE_ID", "MONITOR_DATA_MAX_AGE_MINUTES",
)
NOTIFICATIONS = """notifications:
  enabled: true
  slack:
    enabled: false
alert_types:
  network_alerts: true
frequency:
  min_interval_minutes: {min_interval}
  retry_interval_minutes: 0
  send_recovery: {send_recovery}
"""
HOST = "auditalert-a"
BUSY = 1_000_000
HEALTHY_COVERAGE = {
    "collection_status": "current", "coverage_partial": False,
    "coverage_expected": 1, "coverage_current": 1,
}
HEALTHY_REPORTS = {
    "hardware": dict(excellent=1, good=0, warnings=0, critical=0, unknown=0),
    "bgp": dict(established=4, down=0, warnings=0, critical=0, stale=0,
                unknown=0),
    "link-flap": dict(stable=10, warnings=0, critical=0),
    "optical": dict(excellent=4, good=0, warnings=0, critical=0, down=0,
                    unplugged=0, unknown=0),
    "ber": dict(excellent=4, good=0, warnings=0, critical=0, unknown=0, idle=0),
}


def proc_net_dev(ports):
    """ports: {interface: (rx_packets, tx_packets, rx_errors, tx_errors)}"""
    lines = [
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0",
        "  eth0: 5000 50 0 0 0 0 0 0 5000 50 0 0 0 0 0 0",
    ]
    for name, (rx_packets, tx_packets, rx_errors, tx_errors) in ports.items():
        lines.append(
            f"{name:>6}: {rx_packets * 1000} {rx_packets} {rx_errors} 0 0 0 0 0 "
            f"{tx_packets * 1000} {tx_packets} {tx_errors} 0 0 0 0 0"
        )
    return PROC_NET_DEV_HEADER + "\n".join(lines) + "\n"


class AlertSiteTestCase(unittest.TestCase):
    """A throwaway installation: notifications.yaml, results, alert states."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.results = self.root / "monitor-results"
        self.results.mkdir()
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in ISOLATED_ENVIRONMENT:
            os.environ.pop(name, None)

    def checker(self, *, min_interval=0, send_recovery=True):
        """A fresh alert run over the persisted states, deliveries recorded."""
        (self.root / "notifications.yaml").write_text(NOTIFICATIONS.format(
            min_interval=min_interval,
            send_recovery="true" if send_recovery else "false",
        ))
        with contextlib.redirect_stdout(io.StringIO()):
            alerts = check_alerts.LLDPqAlerts(str(self.root))
        self.assertTrue(alerts.config)
        alerts.delivered = []
        send = alerts.send_notification

        def record(title, message, severity, device, alert_type=""):
            alerts.delivered.append((severity, title, message))
            return send(title, message, severity, device, alert_type)

        alerts.send_notification = record
        return alerts

    def collect_ber(self, ports):
        data = self.results / "ber-data"
        data.mkdir(exist_ok=True)
        (data / f"{HOST}_interface_errors.txt").write_text(proc_net_dev(ports))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            success = process_ber_data.process_ber_data_files(str(data))
        self.assertTrue(success, output.getvalue())

    def summary(self, reports=None, real=()):
        """Run the real summary; reports not named in ``real`` are stubbed."""
        alerts = self.checker()
        alerts.run_manifest = {"pipeline_complete": True, "skipped": []}
        read_report = alerts.get_stats_from_html
        stubbed = {
            name: dict(HEALTHY_COVERAGE, **values)
            for name, values in HEALTHY_REPORTS.items()
        }
        for name, values in (reports or {}).items():
            stubbed[name].update(values)

        def stats(filename):
            for name in real:
                if filename.startswith(name):
                    return read_report(filename)
            for name, values in stubbed.items():
                if filename.startswith(name):
                    return dict(values)
            raise AssertionError(filename)

        alerts.get_stats_from_html = stats
        alerts.get_log_stats_from_json = lambda: dict(
            HEALTHY_COVERAGE, critical=0, warnings=0, errors=0, info=3
        )
        alerts.get_asset_stats = lambda devices: {
            "successful": 1, "failed": 0, "unknown": 0, "stale": 0,
            "unreachable": 0,
        }
        alerts.get_lldp_stats_from_ini = lambda: {
            "successful": 4, "failed": 0, "warnings": 0, "no_info": 0,
        }
        alerts.get_duplicate_stats = lambda: {
            "active": 0, "quiesced": 0, "coverage_expected": 1,
            "coverage_current": 1, "coverage_failures": 0,
            "coverage_partial": False,
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            success = alerts.send_summary_alert([HOST], include_schedule=False)
        self.assertTrue(success, output.getvalue())
        self.assertFalse(alerts.had_error, output.getvalue())
        return alerts.delivered

    def forget_summary_state(self):
        for state in (self.root / "alert-states").glob("network_summary_*"):
            state.unlink()

    @staticmethod
    def open_issues(message):
        if "Open Issues:" not in message:
            return []
        block = message.split("Open Issues:", 1)[1].split("─", 1)[0]
        return [line for line in block.splitlines() if line.strip()]

    def immediate(self, **options):
        alerts = self.checker(**options)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(alerts.check_processed_network_alerts(HOST))
        self.assertFalse(alerts.had_error)
        return alerts


class IdlePortSummaryTests(AlertSiteTestCase):
    def _collect(self, second_port):
        for cycle in (1, 2):
            self.collect_ber({
                "swp1": (cycle * BUSY, cycle * BUSY, 0, 0),
                "swp2": tuple(cycle * value for value in second_port),
                "swp3": (0, 0, 0, 0),  # unused port
            })

    def test_idle_port_does_not_open_a_summary_issue(self):
        self._collect(second_port=(BUSY, BUSY, 0, 0))
        stats = self.checker().get_stats_from_html("ber-analysis.html")
        self.assertEqual((stats["unknown"], stats["idle"]), (1, 1))

        (severity, _title, message), = self.summary(real=("ber",))
        self.assertEqual(severity, "INFO")
        self.assertEqual(self.open_issues(message), [])
        self.assertNotIn("awaiting a complete traffic sample", message)
        self.assertIn("Awaiting Sample: 0     Idle: 1", message)

    def test_port_still_collecting_a_sample_is_shown_without_an_issue(self):
        self._collect(second_port=(100, 100, 0, 0))
        stats = self.checker().get_stats_from_html("ber-analysis.html")
        self.assertEqual((stats["unknown"], stats["idle"]), (2, 1))

        (severity, _title, message), = self.summary(real=("ber",))
        self.assertEqual(severity, "INFO")
        self.assertEqual(self.open_issues(message), [])
        self.assertNotIn("awaiting a complete traffic sample", message)
        self.assertIn("Awaiting Sample: 1     Idle: 1", message)

    def test_report_without_the_idle_count_keeps_the_former_reading(self):
        self._collect(second_port=(BUSY, BUSY, 0, 0))
        report = self.results / "ber-analysis.html"
        page = report.read_text(encoding="utf-8")
        self.assertIn(' data-ber-idle="1"', page)
        report.write_text(page.replace(' data-ber-idle="1"', ""), encoding="utf-8")

        stats = self.checker().get_stats_from_html("ber-analysis.html")
        self.assertEqual((stats["unknown"], stats["idle"]), (1, 0))
        (severity, _title, message), = self.summary(real=("ber",))
        self.assertEqual(severity, "INFO")
        self.assertIn("Awaiting Sample: 1     Idle: 0", message)


class IdlePortImmediateTests(AlertSiteTestCase):
    def setUp(self):
        super().setUp()
        # Shard era without an optical shard: the optical domain stays silent.
        (self.results / "optical-history").mkdir()

    def test_device_with_an_unused_port_recovers_and_stays_ok(self):
        def ports(cycle):
            return {
                "swp1": (cycle * BUSY, cycle * BUSY, 0, 0),
                "swp2": (cycle * BUSY, cycle * BUSY, 0, 0),
                "swp3": (0, 0, 0, 0),  # unused port
            }

        self.collect_ber(ports(1))
        first = self.immediate()
        # Every port is establishing its baseline: reported as before.
        self.assertEqual(first.get_device_ber_status(HOST), "unknown")
        self.assertEqual(first.get_alert_state(HOST, "ber_health"),
                         "WARNING_UNKNOWN")

        self.collect_ber(ports(2))
        second = self.immediate()
        self.assertEqual(second.get_device_ber_status(HOST), "excellent")
        self.assertEqual(second.get_alert_state(HOST, "ber_health"), "OK")
        self.assertEqual(
            [(severity, title) for severity, title, _ in second.delivered],
            [("RECOVERED", "BER Recovered")],
        )

        self.collect_ber(ports(3))
        third = self.immediate()
        self.assertEqual(third.delivered, [])
        self.assertEqual(third.get_alert_state(HOST, "ber_health"), "OK")

    def test_port_still_collecting_a_sample_keeps_the_device_unknown(self):
        for cycle in (1, 2):
            self.collect_ber({
                "swp1": (cycle * BUSY, cycle * BUSY, 0, 0),
                "swp2": (cycle * 100, cycle * 100, 0, 0),
                "swp3": (0, 0, 0, 0),
            })
            alerts = self.immediate()
        self.assertEqual(alerts.get_device_ber_status(HOST), "unknown")
        self.assertEqual(alerts.get_alert_state(HOST, "ber_health"),
                         "WARNING_UNKNOWN")

    def test_warning_recovers_when_the_port_goes_quiet(self):
        # 16000 errored frames in 8e9 received bits: density 2e-6 (warning).
        self.collect_ber({"swp1": (BUSY, BUSY, 0, 0)})
        self.immediate()
        self.collect_ber({"swp1": (2 * BUSY, 2 * BUSY, 16000, 0)})
        warned = self.immediate()
        self.assertEqual(warned.get_device_ber_status(HOST), "warnings")
        self.assertEqual(warned.get_alert_state(HOST, "ber_health"), "WARNINGS")

        # The link went down: no packets and no new errors since.
        self.collect_ber({"swp1": (2 * BUSY, 2 * BUSY, 16000, 0)})
        quiet = self.immediate()
        self.assertEqual(quiet.get_device_ber_status(HOST), "ok")
        self.assertEqual(quiet.get_alert_state(HOST, "ber_health"), "OK")
        self.assertEqual(
            [(severity, title) for severity, title, _ in quiet.delivered],
            [("RECOVERED", "BER Recovered")],
        )

    def test_device_without_a_history_shard_stays_not_applicable(self):
        # A shard that exists but holds no live port is covered in
        # test_audit_flapber_fix_ber.py (BerRecoveryWordingTests).
        (self.results / "ber-history").mkdir()
        alerts = self.immediate()
        self.assertEqual(alerts.get_device_ber_status(HOST), "not_applicable")
        self.assertEqual(alerts.delivered, [])


class SummarySignatureTests(AlertSiteTestCase):
    def assert_resends(self, expected, reports):
        delivered = self.summary(reports)
        self.assertEqual(len(delivered), 1 if expected else 0, reports)
        return delivered

    def test_healthy_band_moves_do_not_resend_the_summary(self):
        self.assert_resends(True, {})
        for reports in (
            {"optical": dict(excellent=2, good=2)},
            {"optical": dict(excellent=0, good=4)},
            {"hardware": dict(excellent=0, good=1)},
            {"ber": dict(excellent=1, good=3)},
            {"ber": dict(excellent=2, good=0, unknown=2, idle=2)},
            {"ber": dict(excellent=3, good=0, unknown=1, idle=0)},
            {"ber": dict(excellent=4, good=0, unknown=0, idle=0)},
        ):
            with self.subTest(reports=reports):
                self.assert_resends(False, reports)

    def test_actionable_changes_still_resend_the_summary(self):
        self.assert_resends(True, {})
        for reports in (
            {"optical": dict(excellent=3, warnings=1)},
            {"optical": dict(excellent=3, critical=1)},
            {"optical": dict(excellent=3, down=1)},
            {"optical": dict(excellent=3, unplugged=1)},
            {"optical": dict(excellent=3, unknown=1)},
            {"hardware": dict(excellent=0, warnings=1)},
            {"hardware": dict(excellent=0, critical=1)},
            {"hardware": dict(excellent=0, unknown=1)},
            {"ber": dict(excellent=3, warnings=1)},
            {"ber": dict(excellent=3, critical=1)},
            {"ber": dict(coverage_partial=True)},
        ):
            with self.subTest(reports=reports):
                self.assert_resends(True, reports)
                # ... and once more when the condition clears.
                self.assert_resends(True, {})

    def test_awaiting_ports_neither_resend_nor_open_an_issue(self):
        self.assert_resends(True, {})
        awaiting = dict(excellent=3, unknown=1, idle=0)
        self.assert_resends(False, {"ber": awaiting})

        (severity, _title, message), = self.assert_resends(True, {
            "ber": awaiting, "optical": dict(excellent=3, warnings=1),
        })
        self.assertEqual(severity, "WARNING")
        self.assertEqual(self.open_issues(message), [
            "[WARNING] Optical: 1 ports with warnings",
        ])
        self.assertIn("Awaiting Sample: 1     Idle: 0", message)

    def test_unchanged_unhealthy_summary_keeps_its_repeat_rules(self):
        unhealthy = {"optical": dict(excellent=3, warnings=1)}
        self.assert_resends(True, unhealthy)
        self.assert_resends(False, unhealthy)

        alerts = self.checker()
        signature = alerts.get_alert_state("network_summary", "last_summary")
        self.assertFalse(alerts.should_send_summary_alert(
            signature, include_schedule=False
        ))
        with mock.patch.object(alerts, "due_summary_slot",
                               return_value="2026-11-13 09:00"):
            self.assertTrue(alerts.should_send_summary_alert(signature))
            alerts.set_alert_state(
                "network_summary", "last_summary_time", "2026-11-13 09:00"
            )
            self.assertFalse(alerts.should_send_summary_alert(signature))


class UnpluggedWordingTests(AlertSiteTestCase):
    def test_unplugged_sub_ports_are_counted_as_ports(self):
        # One module pulled from a 4x breakout cage empties four port rows.
        (severity, _title, message), = self.summary(
            {"optical": dict(excellent=0, unplugged=4)}
        )
        self.assertEqual(severity, "WARNING")
        self.assertEqual(self.open_issues(message), [
            "[WARNING] Optical: 4 ports with an expected module unplugged",
        ])
        self.assertNotIn("expected modules unplugged", message)


class OpticalDeviceStateTests(AlertSiteTestCase):
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

    @staticmethod
    def state(name, degraded, impaired=()):
        """A degraded state as persisted: its name and the ports behind it,
        [degraded, otherwise impaired (down, unknown, unplugged)]."""
        return name + ":" + json.dumps(
            [sorted(degraded), sorted(impaired)], separators=(",", ":")
        )

    def run_sequence(self, lane_health, **other_ports):
        """Per run: (device grade, alert state, [(severity, title, text)])."""
        observed = []
        for health in lane_health:
            self.publish(swp6s0=health, swp6s1="excellent", **other_ports)
            alerts = self.immediate()
            observed.append((
                alerts.get_device_optical_status(HOST),
                alerts.get_alert_state(HOST, "optical_health"),
                [(severity, title,
                  message.replace("Processed Optical analysis ", ""))
                 for severity, title, message in alerts.delivered],
            ))
        return observed

    LANE = ("excellent", "warning", "warning", "critical", "warning",
            "excellent")
    LINK_DOWN = ("WARNING", "Optical Warning",
                 "reports a monitored optical link is down")
    WARNING_AND_DOWN = (
        "WARNING", "Optical Warning",
        "reports a warning condition; a monitored optical link is also down",
    )
    CRITICAL = ("CRITICAL", "Optical Critical", "reports a critical condition")
    WARNING_CLEARED = (
        "RECOVERED", "Optical Warning Cleared",
        "no longer reports a warning condition; "
        "a monitored optical link is still down",
    )

    def test_degrading_lane_is_alerted_next_to_a_link_down_port(self):
        warning = self.state("WARNINGS+DOWN", ["swp6s0"], ["swp10"])
        critical = self.state("CRITICAL+DOWN", ["swp6s0"], ["swp10"])
        self.assertEqual(self.run_sequence(self.LANE, swp10="down"), [
            ("down", "DOWN", [self.LINK_DOWN]),
            ("warnings+down", warning, [self.WARNING_AND_DOWN]),
            ("warnings+down", warning, []),
            ("critical", critical, [self.CRITICAL]),
            ("warnings+down", warning, [self.WARNING_AND_DOWN]),
            ("down", "DOWN", [self.WARNING_CLEARED]),
        ])

    def test_sequence_without_a_down_port_is_unchanged(self):
        warning = ("WARNING", "Optical Warning", "reports a warning condition")
        warnings = self.state("WARNINGS", ["swp6s0"])
        self.assertEqual(self.run_sequence(self.LANE), [
            ("excellent", "OK", []),
            ("warnings", warnings, [warning]),
            ("warnings", warnings, []),
            ("critical", self.state("CRITICAL", ["swp6s0"]), [self.CRITICAL]),
            ("warnings", warnings, [warning]),
            ("excellent", "OK", [
                ("RECOVERED", "Optical Recovered", "is healthy"),
            ]),
        ])

    def test_critical_still_outranks_everything(self):
        self.publish(swp1="critical", swp2="warning", swp3="down",
                     swp4="unplugged", swp5="unknown", swp6="good")
        alerts = self.immediate()
        self.assertEqual(alerts.get_device_optical_status(HOST), "critical")
        self.assertEqual(alerts.delivered, [(
            "CRITICAL", "Optical Critical",
            "Processed Optical analysis reports a critical condition",
        )])
        # The state names the worst other condition next to the critical
        # port and records the degraded and the otherwise impaired ports.
        state = alerts.get_alert_state(HOST, "optical_health")
        self.assertEqual(state, self.state(
            "CRITICAL+DOWN", ["swp1", "swp2"], ["swp3", "swp4", "swp5"]
        ))
        rank = check_alerts.LLDPqAlerts._state_severity_rank
        combined = self.state("WARNINGS+DOWN", ["swp2"], ["swp3"])
        self.assertEqual(rank(state), rank("CRITICAL"))
        self.assertGreater(rank(state), rank(combined))
        self.assertGreater(rank(combined), rank("DOWN"))
        self.assertGreater(rank(combined), rank("WARNINGS"))
        self.assertEqual(rank(self.state("WARNINGS", ["swp2"])), rank("DOWN"))
        self.assertEqual(rank("WARNINGS"), rank("DOWN"))
        self.assertGreater(rank("DOWN"), rank("OK"))

    def test_critical_cleared_next_to_a_down_link_is_announced(self):
        # A repaired optic goes straight from critical to healthy.
        observed = self.run_sequence(
            ("excellent", "critical", "excellent"), swp10="down"
        )
        self.assertEqual(observed, [
            ("down", "DOWN", [self.LINK_DOWN]),
            ("critical", self.state("CRITICAL+DOWN", ["swp6s0"], ["swp10"]),
             [self.CRITICAL]),
            ("down", "DOWN", [(
                "RECOVERED", "Optical Critical Cleared",
                "no longer reports a critical condition; "
                "a monitored optical link is still down",
            )]),
        ])

    def test_critical_port_going_down_is_a_link_down_warning(self):
        for other_ports in ({"swp10": "down"}, {}):
            with self.subTest(other_ports=other_ports):
                for state in (self.root / "alert-states").glob("*"):
                    state.unlink()
                observed = self.run_sequence(("critical", "down"), **other_ports)
                self.assertEqual(observed[0][2], [self.CRITICAL])
                self.assertEqual(observed[1], ("down", "DOWN", [self.LINK_DOWN]))

    def test_links_changing_under_a_critical_stay_silent(self):
        self.publish(swp1="critical", swp2="excellent")
        self.assertEqual(
            self.immediate().get_alert_state(HOST, "optical_health"),
            self.state("CRITICAL", ["swp1"]),
        )
        for health, expected in (
            ("down", self.state("CRITICAL+DOWN", ["swp1"], ["swp2"])),
            ("unplugged", self.state("CRITICAL+UNPLUGGED", ["swp1"], ["swp2"])),
            ("excellent", self.state("CRITICAL", ["swp1"])),
        ):
            with self.subTest(health=health):
                self.publish(swp1="critical", swp2=health)
                alerts = self.immediate()
                self.assertEqual(alerts.delivered, [])
                self.assertEqual(
                    alerts.get_alert_state(HOST, "optical_health"), expected
                )

    def test_a_warning_forms_a_combined_grade_with_the_worst_other_condition(self):
        for ports, expected in (
            (dict(swp1="warning", swp2="good", swp3="excellent"), "warnings"),
            (dict(swp1="warning", swp2="unplugged", swp3="good"),
             "warnings+unplugged"),
            (dict(swp1="warning", swp2="unplugged", swp3="unknown"),
             "warnings+unknown"),
            (dict(swp1="down", swp2="warning", swp3="unplugged"),
             "warnings+down"),
            (dict(swp1="down", swp2="warning", swp3="unknown"),
             "warnings+down"),
            # No warning: the plain grades stand.
            (dict(swp1="down", swp2="unplugged", swp3="unknown"), "down"),
            (dict(swp1="down", swp2="good", swp3="excellent"), "down"),
            (dict(swp1="good", swp2="unplugged", swp3="unknown"), "unknown"),
            (dict(swp1="good", swp2="unplugged", swp3="excellent"),
             "unplugged"),
        ):
            with self.subTest(ports=ports):
                self.publish(**ports)
                self.assertEqual(
                    self.checker().get_device_optical_status(HOST), expected
                )

    def test_warning_port_going_down_is_not_announced_as_a_recovery(self):
        # The degrading optic dies: the warning is gone because its port is
        # now the second link that is down.
        observed = self.run_sequence(("warning", "down"), swp10="down")
        self.assertEqual(observed, [
            ("warnings+down",
             self.state("WARNINGS+DOWN", ["swp6s0"], ["swp10"]),
             [self.WARNING_AND_DOWN]),
            ("down", "DOWN", [self.LINK_DOWN]),
        ])

    def test_down_links_next_to_a_warning_change_without_an_alert(self):
        self.publish(swp1="warning", swp2="down", swp3="excellent")
        self.immediate()
        self.publish(swp1="warning", swp2="down", swp3="down")
        second_link = self.immediate()
        self.assertEqual(second_link.delivered, [])
        self.assertEqual(
            second_link.get_alert_state(HOST, "optical_health"),
            self.state("WARNINGS+DOWN", ["swp1"], ["swp2", "swp3"]),
        )

        # Both links were already down when the warning cleared.
        self.publish(swp1="excellent", swp2="down", swp3="down")
        cleared = self.immediate()
        self.assertEqual(
            [(severity, title) for severity, title, _ in cleared.delivered],
            [("RECOVERED", "Optical Warning Cleared")],
        )
        self.assertEqual(cleared.get_alert_state(HOST, "optical_health"), "DOWN")

    def test_link_restored_and_full_recovery_leave_the_combined_state(self):
        self.publish(swp1="warning", swp2="down")
        self.immediate()
        self.publish(swp1="warning", swp2="excellent")
        restored = self.immediate()
        self.assertEqual(restored.get_alert_state(HOST, "optical_health"),
                         self.state("WARNINGS", ["swp1"]))
        self.assertEqual([title for _, title, _ in restored.delivered],
                         ["Optical Warning"])

        self.publish(swp1="warning", swp2="down")
        self.immediate()
        self.publish(swp1="excellent", swp2="excellent")
        recovered = self.immediate()
        self.assertEqual(recovered.get_alert_state(HOST, "optical_health"), "OK")
        self.assertEqual([title for _, title, _ in recovered.delivered],
                         ["Optical Recovered"])

    def test_cleared_warning_is_silent_when_recoveries_are_disabled(self):
        self.publish(swp1="warning", swp2="down")
        self.immediate(send_recovery=False)
        self.publish(swp1="excellent", swp2="down")
        alerts = self.immediate(send_recovery=False)
        self.assertEqual(alerts.delivered, [])
        self.assertEqual(alerts.get_alert_state(HOST, "optical_health"), "DOWN")

    def test_new_warning_does_not_wait_out_the_repeat_interval(self):
        # The link-down alert has just been delivered; a degrading lane on
        # another port is an escalation, as it is on a switch without it.
        self.publish(swp1="excellent", swp2="down")
        self.immediate(min_interval=30)
        self.publish(swp1="warning", swp2="down")
        warned = self.immediate(min_interval=30)
        self.assertEqual(
            [(severity, title) for severity, title, _ in warned.delivered],
            [("WARNING", "Optical Warning")],
        )
        self.assertEqual(warned.get_alert_state(HOST, "optical_health"),
                         self.state("WARNINGS+DOWN", ["swp1"], ["swp2"]))

        self.publish(swp1="critical", swp2="down")
        escalated = self.immediate(min_interval=30)
        self.assertEqual(
            [(severity, title) for severity, title, _ in escalated.delivered],
            [("CRITICAL", "Optical Critical")],
        )

    def test_recovery_keeps_the_repeat_interval_and_is_not_lost(self):
        self.publish(swp1="critical", swp2="down")
        self.immediate(min_interval=30)
        # Back to a warning, then healthy, inside the interval: nothing yet.
        for health in ("warning", "excellent"):
            self.publish(swp1=health, swp2="down")
            throttled = self.immediate(min_interval=30)
            self.assertEqual(throttled.delivered, [])
            self.assertEqual(
                throttled.get_alert_state(HOST, "optical_health"),
                self.state("CRITICAL+DOWN", ["swp1"], ["swp2"]),
            )

        marker = self.root / "alert-states" / f"{HOST}_optical_health.timestamp"
        marker.write_text(str(time.time() - 31 * 60))
        due = self.immediate(min_interval=30)
        self.assertEqual(
            [(severity, title) for severity, title, _ in due.delivered],
            [("RECOVERED", "Optical Critical Cleared")],
        )
        self.assertEqual(due.get_alert_state(HOST, "optical_health"), "DOWN")


if __name__ == "__main__":
    unittest.main()
