#!/usr/bin/env python3
"""System watchdog: reboot and service-restart blind-spot detection.

A switch that reboots and returns within the 10-minute cycle triggers
nothing else — carrier_transitions and BGP counters reset and their
analyzers silently re-baseline.  The SYS_WATCHDOG sub-section (nested
inside HARDWARE_DATA; collection_bundle.py validates a fixed top-level
layout) carries /proc/uptime and systemd NRestarts so the hardware-side
processor can surface those events.
"""

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
sys.path.insert(0, str(SCRIPT_DIR.parent / "html"))

import ai_correlate
import check_alerts
import collection_bundle
import generate_hardware_html as ghh


def watchdog_section(uptime="900000.42", services=(("frr.service", 2),
                                                   ("switchd.service", 0)),
                     uptime_error=False, services_error=False):
    lines = ["===SYS_WATCHDOG_START==="]
    if uptime_error:
        lines.append("__LLDPQ_SYS_WATCHDOG_ERROR__:UPTIME")
    else:
        lines.append(f"UPTIME_SECONDS:{uptime}")
    if services_error:
        lines.append("__LLDPQ_SYS_WATCHDOG_ERROR__:SERVICES")
    else:
        lines.append("SERVICE_RESTARTS:")
        blocks = [
            f"Id={unit}\nNRestarts={count}" for unit, count in services
        ]
        lines.append("\n\n".join(blocks))
    lines.append("===SYS_WATCHDOG_END===")
    return "\n".join(lines) + "\n"


RAW_SAMPLE = (
    "HARDWARE_HEALTH:\n"
    "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:OK\n"
    "fan1: 5000 RPM\n"
    "CPU_CORES: 4\n"
    + watchdog_section()
)


class ParseSysWatchdogTests(unittest.TestCase):
    def test_pre_upgrade_raw_file_has_no_section(self):
        self.assertIsNone(ghh.parse_sys_watchdog("HARDWARE_HEALTH:\nMem: x\n"))

    def test_uptime_and_service_blocks_are_parsed(self):
        sample = ghh.parse_sys_watchdog(RAW_SAMPLE)
        self.assertAlmostEqual(900000.42, sample["uptime_seconds"])
        self.assertEqual(
            {"frr.service": 2, "switchd.service": 0}, sample["services"])

    def test_error_markers_leave_fields_none(self):
        sample = ghh.parse_sys_watchdog(watchdog_section(uptime_error=True))
        self.assertIsNone(sample["uptime_seconds"])
        self.assertEqual({"frr.service": 2, "switchd.service": 0},
                         sample["services"])

        sample = ghh.parse_sys_watchdog(watchdog_section(services_error=True))
        self.assertAlmostEqual(900000.42, sample["uptime_seconds"])
        self.assertIsNone(sample["services"])

    def test_malformed_uptime_is_ignored(self):
        sample = ghh.parse_sys_watchdog(watchdog_section(uptime="broken"))
        self.assertIsNone(sample["uptime_seconds"])

    def test_missing_units_simply_produce_absent_entries(self):
        sample = ghh.parse_sys_watchdog(
            watchdog_section(services=(("frr.service", 1),)))
        self.assertEqual({"frr.service": 1}, sample["services"])


class WatchdogDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = str(Path(self.tmp.name) / "watchdog-state.json")

    def _update(self, samples, expected=None):
        return ghh.update_system_watchdog(
            samples,
            expected if expected is not None else set(samples),
            state_path=self.state_path,
        )

    def test_first_sight_baselines_without_events(self):
        now = time.time()
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 120.0,
                       "services": {"frr.service": 5}}, now),
        })
        self.assertEqual([], timeline)
        self.assertEqual([], hosts["leaf1"]["events"])
        self.assertEqual(120.0, hosts["leaf1"]["uptime_seconds"])
        self.assertEqual({"frr.service": 5}, hosts["leaf1"]["services"])

    def test_reboot_detected_and_service_events_suppressed(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 90000.0,
                       "services": {"frr.service": 3}}, now - 600),
        })
        # Uptime 120s < elapsed 600s - 120s skew: the box restarted, and the
        # boot-reset NRestarts delta must be subsumed by the reboot event.
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 120.0,
                       "services": {"frr.service": 5}}, now),
        })
        kinds = [event["kind"] for event in hosts["leaf1"]["events"]]
        self.assertEqual(["reboot"], kinds)
        (event,) = timeline
        self.assertEqual("device-reboot", event["kind"])
        self.assertEqual("warning", event["severity"])
        self.assertIn("uptime 2m", event["detail"])
        self.assertIn(
            "counter resets expected (carrier/BGP/service baselines)",
            event["detail"])
        # The service baseline still advances for the next cycle.
        self.assertEqual({"frr.service": 5}, hosts["leaf1"]["services"])

    def test_skew_margin_prevents_false_reboot(self):
        now = time.time()
        self._update({"leaf1": ({"uptime_seconds": 100.0,
                                 "services": {}}, now - 600)})
        # Uptime within (elapsed - 120s): clock skew, not a restart.
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 500.0, "services": {}}, now),
        })
        self.assertEqual([], timeline)
        self.assertEqual([], hosts["leaf1"]["events"])

    def test_absent_uptime_never_produces_or_advances(self):
        now = time.time()
        self._update({"leaf1": ({"uptime_seconds": 90000.0,
                                 "services": {}}, now - 600)})
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": None, "services": {}}, now),
        })
        self.assertEqual([], timeline)
        # The uptime baseline keeps the previous sample's wall clock, so a
        # real reboot is still caught on the next good sample.
        self.assertEqual(int(now - 600), hosts["leaf1"]["wall_ts"])

    def test_stale_host_keeps_baselines_untouched(self):
        now = time.time()
        first, _ = self._update({
            "leaf1": ({"uptime_seconds": 90000.0,
                       "services": {"frr.service": 3}}, now - 600),
        }, expected={"leaf1", "leaf2"})
        # leaf1 produced no current sample this cycle (unreachable/stale):
        # nothing about it may move.
        hosts, timeline = self._update(
            {}, expected={"leaf1", "leaf2"})
        self.assertEqual(first["leaf1"], hosts["leaf1"])
        self.assertEqual([], timeline)

    def test_retired_host_is_pruned_from_state(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 1.0, "services": {}}, now),
            "gone": ({"uptime_seconds": 1.0, "services": {}}, now),
        })
        hosts, _ = self._update(
            {"leaf1": ({"uptime_seconds": 2.0, "services": {}}, now)},
            expected={"leaf1"},
        )
        self.assertNotIn("gone", hosts)
        saved = json.loads(Path(self.state_path).read_text())
        self.assertNotIn("gone", saved["hosts"])

    def test_empty_expected_set_never_wipes_baselines(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 1.0, "services": {}}, now),
        })
        # A broken inventory view for one cycle must not drop every
        # baseline (that would re-baseline the fabric and miss detections).
        hosts, _ = self._update({}, expected=set())
        self.assertIn("leaf1", hosts)

    def test_service_restart_delta_and_decrease(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 90000.0,
                       "services": {"frr.service": 3, "nvued.service": 1}},
                      now - 600),
        })
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 90600.0,
                       "services": {"frr.service": 5, "nvued.service": 2}},
                      now),
        })
        events = {e["object"]: e for e in timeline}
        self.assertEqual(2, len(events))
        self.assertEqual("critical", events["frr.service"]["severity"])
        self.assertIn("frr.service x2", events["frr.service"]["detail"])
        self.assertEqual("warning", events["nvued.service"]["severity"])

        # delta < 0 (package reinstall / systemd reload): re-baseline only.
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 91200.0,
                       "services": {"frr.service": 1, "nvued.service": 2}},
                      now + 600),
        })
        self.assertEqual([], timeline)
        self.assertEqual(1, hosts["leaf1"]["services"]["frr.service"])

    def test_new_unit_is_baselined_silently(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 90000.0,
                       "services": {"frr.service": 3}}, now - 600),
        })
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 90600.0,
                       "services": {"frr.service": 3, "clagd.service": 7}},
                      now),
        })
        self.assertEqual([], timeline)
        self.assertEqual(7, hosts["leaf1"]["services"]["clagd.service"])

    def test_state_round_trip_and_permission_floor(self):
        now = time.time()
        self._update({
            "leaf1": ({"uptime_seconds": 5.0,
                       "services": {"frr.service": 1}}, now),
        })
        mode = os.stat(self.state_path).st_mode & 0o777
        # Web-served results tree: never below the nginx-readable floor.
        self.assertEqual(0o644, mode & 0o644)
        saved = json.loads(Path(self.state_path).read_text())
        self.assertEqual(1, saved["version"])
        self.assertEqual(
            {"frr.service": 1}, saved["hosts"]["leaf1"]["services"])
        # A reload sees the same baseline (round trip through JSON).
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 305.0,
                       "services": {"frr.service": 1}}, now + 300),
        })
        self.assertEqual([], timeline)

    def test_corrupt_state_file_is_rebuilt(self):
        Path(self.state_path).write_text("{not json", encoding="utf-8")
        hosts, timeline = self._update({
            "leaf1": ({"uptime_seconds": 5.0, "services": {}}, time.time()),
        })
        self.assertEqual([], timeline)
        self.assertIn("leaf1", hosts)

    def test_annotations_from_recent_events(self):
        now = time.time()
        host_state = {"events": [
            {"ts": now - 600, "kind": "reboot", "uptime_seconds": 120.0},
            {"ts": now - 600, "kind": "service-restart",
             "unit": "frr.service", "count": 2},
            {"ts": now - 25 * 3600, "kind": "service-restart",
             "unit": "clagd.service", "count": 9},
        ]}
        reboot_text, restarts_text = ghh.sys_watchdog_annotations(
            host_state, now=now)
        self.assertEqual("Rebooted 10m ago", reboot_text)
        self.assertEqual("frr.service x2", restarts_text)

        self.assertEqual(
            (None, None), ghh.sys_watchdog_annotations({"events": []}))
        self.assertEqual((None, None), ghh.sys_watchdog_annotations(None))


class CollectionBundleNestingTests(unittest.TestCase):
    """The nested sub-markers must survive the strict bundle validation."""

    def test_watchdog_lines_stay_inside_hardware_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_lines = []
            outputs = {}
            for section in collection_bundle.SECTIONS:
                bundle_lines.append(f"==={section}_START===")
                if section == "HARDWARE_DATA":
                    bundle_lines.append(RAW_SAMPLE.rstrip("\n"))
                    # The private failure marker must not fail the bundle
                    # the way a __LLDPQ_COLLECTION_ERROR__ line would.
                    bundle_lines.append("__LLDPQ_SYS_WATCHDOG_ERROR__:UPTIME")
                bundle_lines.append(f"==={section}_END===")
                outputs[section] = os.path.join(tmp, f"{section}.txt")
            raw = os.path.join(tmp, "bundle.raw")
            Path(raw).write_text("\n".join(bundle_lines) + "\n",
                                 encoding="utf-8")
            collection_bundle.split_collection_bundle(raw, outputs)
            hardware = Path(outputs["HARDWARE_DATA"]).read_text()
            self.assertIn("===SYS_WATCHDOG_START===", hardware)
            self.assertIn("UPTIME_SECONDS:900000.42", hardware)
            self.assertIn("__LLDPQ_SYS_WATCHDOG_ERROR__:UPTIME", hardware)


class WatchdogAlertTests(unittest.TestCase):
    def _checker(self, tmp, host_state, config_overrides=None):
        checker = object.__new__(check_alerts.LLDPqAlerts)
        checker.monitor_results = Path(tmp)
        checker.had_error = False
        checker.config = {
            "alert_types": {"system_alerts": True},
            "frequency": {"send_recovery": True},
        }
        if config_overrides:
            checker.config.update(config_overrides)
        checker._watchdog_loaded = False
        checker._watchdog_hosts = None
        checker._watchdog_error = None
        if host_state is not None:
            (Path(tmp) / "system-watchdog-state.json").write_text(
                json.dumps({"version": 1, "hosts": {"leaf1": host_state}}),
                encoding="utf-8")
        return checker

    def _run(self, checker, last_state="OK"):
        sent = []

        def capture(title, message, severity, device, key, new_state):
            sent.append({"title": title, "message": message,
                         "severity": severity, "device": device,
                         "key": key, "state": new_state})
            return True

        silent = []

        def record_silent(device, key, new_state):
            silent.append({"device": device, "key": key,
                           "state": new_state})
            return True

        with (
            mock.patch.object(checker, "get_alert_state",
                              create=True, return_value=last_state),
            mock.patch.object(checker, "should_send_alert",
                              create=True, return_value=True),
            mock.patch.object(checker, "send_stateful_notification",
                              create=True, side_effect=capture),
            mock.patch.object(checker, "record_state_without_delivery",
                              create=True, side_effect=record_silent),
        ):
            checker.check_system_watchdog_alerts("leaf1")
        return sent, silent

    def test_reboot_is_one_shot_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            checker = self._checker(tmp, {
                "wall_ts": now - 60,
                "events": [{"ts": now - 60, "kind": "reboot",
                            "uptime_seconds": 130.0}],
            })
            sent, _ = self._run(checker)
            (reboot,) = [a for a in sent if a["key"] == "device_reboot"]
            self.assertEqual("WARNING", reboot["severity"])
            self.assertIn("Device rebooted (uptime 2m)", reboot["message"])
            self.assertIn(
                "counter resets expected (carrier/BGP/service baselines)",
                reboot["message"])
            # Next clean cycle transitions back through the state machine.
            (recovered,) = [a for a in sent
                            if a["key"] == "service_restart"]
            self.assertEqual("RECOVERED", recovered["severity"])

    def test_frr_restart_is_critical_nvued_is_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            checker = self._checker(tmp, {
                "wall_ts": now - 60,
                "events": [
                    {"ts": now - 60, "kind": "service-restart",
                     "unit": "frr.service", "count": 2},
                    {"ts": now - 60, "kind": "service-restart",
                     "unit": "nvued.service", "count": 1},
                ],
            })
            sent, _ = self._run(checker)
            (restart,) = [a for a in sent if a["key"] == "service_restart"]
            self.assertEqual("CRITICAL", restart["severity"])
            self.assertIn("frr.service x2", restart["message"])
            self.assertIn("nvued.service x1", restart["message"])

            checker = self._checker(tmp, {
                "wall_ts": now - 60,
                "events": [{"ts": now - 60, "kind": "service-restart",
                            "unit": "nvued.service", "count": 1}],
            })
            sent, _ = self._run(checker)
            (restart,) = [a for a in sent if a["key"] == "service_restart"]
            self.assertEqual("WARNING", restart["severity"])

    def test_previous_cycle_events_auto_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            # wall_ts advanced past the events: they belonged to an already
            # alerted cycle, so both alert types return to OK/RECOVERED.
            checker = self._checker(tmp, {
                "wall_ts": now - 60,
                "events": [{"ts": now - 660, "kind": "reboot",
                            "uptime_seconds": 130.0}],
            })
            self.assertEqual([], checker.get_device_watchdog_events("leaf1"))
            sent, _ = self._run(checker, last_state="WARNING")
            self.assertEqual(
                {"RECOVERED"}, {a["severity"] for a in sent})

    def test_new_alert_types_baseline_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            checker = self._checker(tmp, {"wall_ts": now - 60, "events": []})
            sent, silent = self._run(checker, last_state="UNKNOWN")
            self.assertEqual([], sent)
            self.assertEqual(
                {"device_reboot", "service_restart"},
                {item["key"] for item in silent})

    def test_stale_state_asserts_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            checker = self._checker(tmp, {
                "wall_ts": now - 7200,
                "events": [{"ts": now - 7200, "kind": "reboot",
                            "uptime_seconds": 130.0}],
            })
            self.assertIsNone(checker.get_device_watchdog_events("leaf1"))
            sent, silent = self._run(checker)
            self.assertEqual([], sent)
            self.assertEqual([], silent)
            self.assertFalse(checker.had_error)

    def test_pre_upgrade_installation_without_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, None)
            self.assertIsNone(checker.get_device_watchdog_events("leaf1"))
            sent, silent = self._run(checker)
            self.assertEqual([], sent)
            self.assertFalse(checker.had_error)


class AiCorrelateWatchdogTests(unittest.TestCase):
    def test_fresh_events_surface_and_stale_are_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            (Path(tmp) / "system-watchdog-state.json").write_text(
                json.dumps({"version": 1, "hosts": {
                    "leaf1": {"wall_ts": now - 300, "events": [
                        {"ts": now - 300, "kind": "reboot",
                         "uptime_seconds": 240.0},
                        {"ts": now - 300, "kind": "service-restart",
                         "unit": "frr.service", "count": 2},
                        {"ts": now - 3 * 3600, "kind": "service-restart",
                         "unit": "clagd.service", "count": 5},
                    ]},
                }}), encoding="utf-8")
            anomalies = ai_correlate._collect_system_watchdog(tmp, now)
            by_metric = {(a["metric"], a["port"]): a for a in anomalies}
            self.assertEqual(2, len(anomalies))
            reboot = by_metric[("reboot", None)]
            self.assertEqual("leaf1", reboot["device"])
            self.assertIn("uptime 4m", reboot["detail"])
            restart = by_metric[("service_restart", "frr.service")]
            self.assertEqual(2, restart["value"])
            for anomaly in anomalies:
                # The module never invents CRITICAL for a condition that
                # already recovered (device back up, service running).
                self.assertEqual(
                    "WARNING", ai_correlate.severity_for(anomaly))

    def test_absent_state_file_contributes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                [], ai_correlate._collect_system_watchdog(tmp, time.time()))


if __name__ == "__main__":
    unittest.main()
