#!/usr/bin/env python3
"""BGP session flap detection (counter deltas + uptime fallback).

A session that drops and re-establishes BETWEEN 10-minute samples looks
Established at both reads; only the monotonic connectionsDropped counter
(or, on counterless FRR builds, an uptime regression) makes it visible.
The flap sidecar keys in bgp_history.json must stay slim: 3 ints per peer
baseline, sparse events only, and counters-only history snapshots.
"""

import json
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
import process_bgp_data
from bgp_analyzer import BGPAnalyzer

ESTABLISHED_SUMMARY = """
IPv4 Unicast Summary:
BGP router identifier 10.0.0.1, local AS number 65001 vrf-id 0

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
swp1            4      65002     100     100        0    0    0 01:02:03            5        5 leaf01
"""


def summary_json(state="Established", uptime="01:02:03", uptime_msec=3723000,
                 dropped=None, established=None, vrf="default", peer="swp1",
                 msg_rcvd=None):
    entry = {
        "remoteAs": 65002,
        "state": state,
        "peerUptime": uptime,
        "peerUptimeMsec": uptime_msec,
    }
    if dropped is not None:
        entry["connectionsDropped"] = dropped
    if established is not None:
        entry["connectionsEstablished"] = established
    if msg_rcvd is not None:
        entry["msgRcvd"] = msg_rcvd
    return json.dumps({
        vrf: {
            "ipv4Unicast": {
                "routerId": "10.0.0.1",
                "as": 65001,
                "vrfName": vrf,
                "peers": {peer: entry},
                "totalPeers": 1,
            },
        },
    })


class SplitBgpSectionsTests(unittest.TestCase):
    def test_pre_upgrade_raw_file_has_no_json(self):
        summary, json_text = process_bgp_data.split_bgp_sections(
            ESTABLISHED_SUMMARY)
        self.assertEqual(ESTABLISHED_SUMMARY, summary)
        self.assertIsNone(json_text)

    def test_json_sub_section_is_split_out_of_the_summary(self):
        raw = (
            ESTABLISHED_SUMMARY
            + "===BGP_JSON_START===\n"
            + summary_json(dropped=0, established=1) + "\n"
            + "===BGP_JSON_END===\n"
        )
        summary, json_text = process_bgp_data.split_bgp_sections(raw)
        self.assertNotIn("===BGP_JSON_START===", summary)
        self.assertNotIn("connectionsDropped", summary)
        self.assertIn("swp1            4", summary)
        self.assertEqual(0, json.loads(json_text)["default"]["ipv4Unicast"]
                         ["peers"]["swp1"]["connectionsDropped"])

    def test_error_marker_and_empty_section_yield_none(self):
        for body in ("__LLDPQ_BGP_JSON_ERROR__\n", ""):
            raw = (
                ESTABLISHED_SUMMARY
                + "===BGP_JSON_START===\n" + body + "===BGP_JSON_END===\n"
            )
            summary, json_text = process_bgp_data.split_bgp_sections(raw)
            self.assertIsNone(json_text)
            self.assertIn("swp1            4", summary)


class BgpFlapDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = BGPAnalyzer(self.tmp.name)

    def test_counter_delta_records_flap_event_and_anomaly(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        # First sight establishes the baseline without any flap.
        self.assertNotIn("tor-a", self.analyzer.flap_events)
        self.assertEqual(
            {"dropped": 0, "established": 1},
            {key: value for key, value in
             self.analyzer.flap_baselines["tor-a"]["default|swp1"].items()
             if key != "ts"},
        )

        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=2, established=3))
        (event,) = self.analyzer.flap_events["tor-a"]
        self.assertEqual(2, event["count"])
        self.assertEqual("default", event["vrf"])
        self.assertEqual("swp1", event["neighbor"])
        self.assertNotIn("estimated", event)

        neighbor = self.analyzer.current_bgp_stats["tor-a"]["neighbors"][0]
        self.assertEqual(2, neighbor["flaps_24h"])
        self.assertFalse(neighbor["flaps_estimated"])
        self.assertEqual(
            2, self.analyzer.bgp_history["tor-a"][-1]["flap_count"])

        anomalies = [a for a in self.analyzer.detect_bgp_anomalies()
                     if a["type"] == "BGP_SESSION_FLAPS"]
        (anomaly,) = anomalies
        self.assertEqual("tor-a", anomaly["device"])
        self.assertEqual("swp1", anomaly["neighbor"])
        self.assertEqual("default", anomaly["details"]["vrf"])
        self.assertEqual(2, anomaly["details"]["count"])
        # Default thresholds: warning at 1/h, critical at 3/h.
        self.assertEqual("warning", anomaly["severity"])

        timeline = [e for e in self.analyzer.cycle_events
                    if e["kind"] == "bgp-session-flap"]
        (timeline_event,) = timeline
        self.assertEqual("tor-a", timeline_event["device"])
        self.assertIn("BGP session flap: tor-a vrf default swp1 (2 drops)",
                      timeline_event["detail"])

    def test_counter_delta_at_critical_threshold(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=3, established=4))
        (anomaly,) = [a for a in self.analyzer.detect_bgp_anomalies()
                      if a["type"] == "BGP_SESSION_FLAPS"]
        self.assertEqual("critical", anomaly["severity"])

    def test_counter_reset_rebaselines_without_flap(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=5, established=6))
        # FRR restart / clear bgp: dropped decreases -> re-baseline only.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=1, established=1))
        self.assertNotIn("tor-a", self.analyzer.flap_events)
        self.assertEqual(
            1, self.analyzer.flap_baselines["tor-a"]["default|swp1"]["dropped"])
        self.assertEqual(
            0, self.analyzer.bgp_history["tor-a"][-1]["flap_count"])

        # The rebased counter keeps working for real flaps afterwards.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=2, established=2))
        (event,) = self.analyzer.flap_events["tor-a"]
        self.assertEqual(1, event["count"])

    def test_uptime_fallback_records_estimated_flap(self):
        # Counterless FRR build: no connections* fields in the JSON.
        baseline_time = time.time() - 600
        self.analyzer.update_bgp_flap_stats(
            "tor-a",
            summary_json(uptime="02:00:00", uptime_msec=7200000),
            now=baseline_time)
        self.assertNotIn("dropped",
                         self.analyzer.flap_baselines["tor-a"]["default|swp1"])

        # Established at both samples, but uptime (120s) is far shorter than
        # the elapsed 600s poll interval: at least one reset happened.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(uptime="00:02:00", uptime_msec=120000))
        (event,) = self.analyzer.flap_events["tor-a"]
        self.assertEqual(1, event["count"])
        self.assertTrue(event["estimated"])
        neighbor = self.analyzer.current_bgp_stats["tor-a"]["neighbors"][0]
        self.assertEqual(1, neighbor["flaps_24h"])
        self.assertTrue(neighbor["flaps_estimated"])

    def test_uptime_fallback_skew_margin_prevents_false_flap(self):
        baseline_time = time.time() - 600
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(uptime="02:00:00", uptime_msec=7200000),
            now=baseline_time)
        # Uptime within (elapsed - 60s skew margin): not a reset.
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(uptime="00:09:30", uptime_msec=570000))
        self.assertNotIn("tor-a", self.analyzer.flap_events)

    def test_admin_down_and_never_established_are_skipped(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        # Admin shutdown increments dropped, but admin actions are not flaps:
        # the baseline advances silently.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(
                state="Idle (Admin)", uptime="never", uptime_msec=0,
                dropped=1, established=1))
        self.assertNotIn("tor-a", self.analyzer.flap_events)
        # Re-enable: no delta against the silently advanced baseline.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=1, established=2))
        self.assertNotIn("tor-a", self.analyzer.flap_events)

        # A peer that never established cannot flap.
        for _ in range(2):
            self.analyzer.update_bgp_stats(
                "tor-b", ESTABLISHED_SUMMARY,
                bgp_json_data=summary_json(
                    state="Active", uptime="never", uptime_msec=0,
                    dropped=0, established=0))
        self.assertNotIn("tor-b", self.analyzer.flap_events)

    def test_first_run_new_peer_and_absent_json_do_not_flap(self):
        # Rolling upgrade: raw file without the JSON section.
        self.analyzer.update_bgp_stats("tor-a", ESTABLISHED_SUMMARY)
        self.assertNotIn("tor-a", self.analyzer.flap_events)
        self.assertNotIn("tor-a", self.analyzer.flap_baselines)

        # First JSON sighting of a peer only records the baseline, even with
        # a non-zero lifetime drop counter.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=7, established=8))
        self.assertNotIn("tor-a", self.analyzer.flap_events)

        # A later cycle without JSON must not advance the baseline.
        before = dict(self.analyzer.flap_baselines["tor-a"]["default|swp1"])
        self.analyzer.update_bgp_stats("tor-a", ESTABLISHED_SUMMARY)
        self.assertEqual(
            before, self.analyzer.flap_baselines["tor-a"]["default|swp1"])

    def test_disappeared_peer_baselines_are_pruned(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1, peer="swp9"))
        self.assertEqual(["default|swp9"],
                         list(self.analyzer.flap_baselines["tor-a"]))

    def test_flap_events_pruned_to_window_and_capped(self):
        now = time.time()
        self.analyzer.bgp_history["tor-a"] = [{
            "timestamp": now, "total_neighbors": 1,
            "established_count": 1, "down_count": 0,
        }]
        self.analyzer.flap_events["tor-a"] = (
            [{"ts": now - 25 * 3600, "vrf": "default",
              "neighbor": "swp1", "count": 1}]
            + [{"ts": now - 300 + index * 0.001, "vrf": "default",
                "neighbor": "swp1", "count": 1} for index in range(250)]
        )
        self.analyzer.flap_baselines["gone-host"] = {
            "default|swp1": {"dropped": 1, "established": 1, "ts": int(now)},
        }
        self.analyzer.cleanup_old_history()

        events = self.analyzer.flap_events["tor-a"]
        self.assertEqual(200, len(events))
        self.assertTrue(all(now - event["ts"] <= 24 * 3600
                            for event in events))
        # Baselines for hosts whose history expired are dropped with them.
        self.assertNotIn("gone-host", self.analyzer.flap_baselines)

    def test_slim_contract_history_snapshots_stay_counters_only(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=2, established=3))
        for entry in self.analyzer.bgp_history["tor-a"]:
            self.assertNotIn("neighbors", entry)
            self.assertEqual(
                {"timestamp", "total_neighbors", "established_count",
                 "down_count", "warning_neighbors", "critical_neighbors",
                 "flap_count"},
                set(entry),
            )
            self.assertIsInstance(entry["flap_count"], int)
        # Baselines stay at 3 small scalars per peer, fabric-wide.
        baseline = self.analyzer.flap_baselines["tor-a"]["default|swp1"]
        self.assertEqual({"dropped", "established", "ts"}, set(baseline))
        self.assertTrue(all(isinstance(value, int)
                            for value in baseline.values()))

        self.analyzer.save_bgp_history()
        saved = json.loads(
            (Path(self.tmp.name) / "bgp_history.json").read_text())
        self.assertEqual(baseline, saved["flap_baselines"]["tor-a"]["default|swp1"])
        self.assertEqual(1, len(saved["flap_events"]["tor-a"]))

        # Reload round-trip: flaps_24h stays visible for the web/alert side.
        reloaded = BGPAnalyzer(self.tmp.name)
        self.assertEqual(
            2, reloaded.current_bgp_stats["tor-a"]["neighbors"][0]["flaps_24h"])

    def test_web_export_renders_flap_column_and_respects_registry(self):
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1))
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=3, established=4))
        output_file = str(Path(self.tmp.name) / "bgp-analysis.html")
        # Must not raise ExportContractError: flaps_24h stays out of the
        # machine-export rows (the registry has no such column).
        self.analyzer.export_bgp_data_for_web(output_file)

        report = Path(output_file).read_text(encoding="utf-8")
        self.assertIn("Flaps (24h)", report)
        self.assertIn('data-type="flaps"', report)
        self.assertIn('<span class="badge badge-red">3</span>', report)
        self.assertIn('id="bgp-flaps-24h">3<', report)

        export = json.loads(
            (Path(self.tmp.name) / "export" / "bgp.json").read_text())
        self.assertEqual(1, export["row_count"])
        self.assertNotIn("flaps_24h", export["rows"][0])
        self.assertEqual(3, export["counts"]["flaps_24h"])

    def test_hostname_wrapped_text_neighbor_matches_json_key(self):
        wrapped = ESTABLISHED_SUMMARY.replace(
            "swp1     ", "leaf01(swp1)")
        self.analyzer.update_bgp_stats(
            "tor-a", wrapped,
            bgp_json_data=summary_json(dropped=0, established=1))
        self.analyzer.update_bgp_stats(
            "tor-a", wrapped,
            bgp_json_data=summary_json(dropped=1, established=2))
        neighbor = self.analyzer.current_bgp_stats["tor-a"]["neighbors"][0]
        self.assertEqual("leaf01(swp1)", neighbor["neighbor_name"])
        self.assertEqual(1, neighbor["flaps_24h"])


class BgpUpdateStormTests(unittest.TestCase):
    """Update storms extend the flap baselines with an optional msg_rcvd."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.analyzer = BGPAnalyzer(self.tmp.name)

    def _baseline(self, msg_rcvd=100, age=600, **kwargs):
        self.analyzer.update_bgp_flap_stats(
            "tor-a",
            summary_json(dropped=0, established=1, msg_rcvd=msg_rcvd,
                         **kwargs),
            now=time.time() - age)

    def test_rate_over_warning_records_storm_and_anomaly(self):
        self._baseline(msg_rcvd=100, age=600)
        # 360 messages over ~10 minutes = ~36/min: over warning (30),
        # under critical (120).
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1,
                                       msg_rcvd=460))
        (storm,) = self.analyzer.update_storms["tor-a"]
        self.assertEqual("warning", storm["severity"])
        self.assertAlmostEqual(36.0, storm["rate"], delta=0.5)
        self.assertEqual("default", storm["vrf"])
        self.assertEqual("swp1", storm["neighbor"])

        (anomaly,) = [a for a in self.analyzer.detect_bgp_anomalies()
                      if a["type"] == "BGP_UPDATE_STORM"]
        self.assertEqual("tor-a", anomaly["device"])
        self.assertEqual("swp1", anomaly["neighbor"])
        self.assertEqual("warning", anomaly["severity"])
        self.assertEqual("default", anomaly["details"]["vrf"])
        self.assertEqual(30, anomaly["details"]["storm_warning"])
        self.assertEqual(120, anomaly["details"]["storm_critical"])

        (timeline_event,) = [e for e in self.analyzer.cycle_events
                             if e["kind"] == "bgp-update-storm"]
        self.assertEqual("warning", timeline_event["severity"])
        self.assertIn("msgs/min received", timeline_event["detail"])

        # The per-neighbor rate reaches the row-details panel only.
        neighbor = self.analyzer.current_bgp_stats["tor-a"]["neighbors"][0]
        self.assertAlmostEqual(36.0, neighbor["msg_rcvd_per_min"], delta=0.5)

    def test_rate_over_critical(self):
        self._baseline(msg_rcvd=0, age=600)
        # 1300 messages over 10 minutes = 130/min: over the 120/min default.
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1,
                                       msg_rcvd=1300))
        (storm,) = self.analyzer.update_storms["tor-a"]
        self.assertEqual("critical", storm["severity"])
        (anomaly,) = [a for a in self.analyzer.detect_bgp_anomalies()
                      if a["type"] == "BGP_UPDATE_STORM"]
        self.assertEqual("critical", anomaly["severity"])

    def test_keepalive_noise_stays_quiet(self):
        self._baseline(msg_rcvd=100, age=600)
        # ~0.2 msgs/min keepalive noise: rate recorded, no storm.
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(dropped=0, established=1, msg_rcvd=102))
        self.assertNotIn("tor-a", self.analyzer.update_storms)
        self.assertAlmostEqual(
            0.2, self.analyzer.cycle_msg_rates["tor-a"]["default|swp1"],
            delta=0.1)

    def test_flap_cycle_skips_storm_evaluation(self):
        self._baseline(msg_rcvd=100, age=600)
        # The flap consumed the interval; a huge delta is session churn,
        # not a storm rate, and only re-baselines msg_rcvd.
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(dropped=2, established=3, msg_rcvd=9000))
        self.assertIn("tor-a", self.analyzer.flap_events)
        self.assertNotIn("tor-a", self.analyzer.update_storms)
        self.assertEqual(
            9000,
            self.analyzer.flap_baselines["tor-a"]["default|swp1"]["msg_rcvd"])

    def test_counter_reset_rebaselines_without_storm(self):
        self._baseline(msg_rcvd=5000, age=600)
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(dropped=0, established=1, msg_rcvd=10))
        self.assertNotIn("tor-a", self.analyzer.update_storms)
        self.assertEqual(
            10,
            self.analyzer.flap_baselines["tor-a"]["default|swp1"]["msg_rcvd"])

    def test_short_elapsed_window_skips_evaluation(self):
        self._baseline(msg_rcvd=100, age=60)
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(dropped=0, established=1, msg_rcvd=5000))
        self.assertNotIn("tor-a", self.analyzer.update_storms)
        self.assertNotIn("tor-a", self.analyzer.cycle_msg_rates)

    def test_first_sight_and_pre_upgrade_baseline_skip(self):
        # First sight: baseline only, even with a huge lifetime counter.
        self.analyzer.update_bgp_flap_stats(
            "tor-a", summary_json(dropped=0, established=1, msg_rcvd=999999))
        self.assertNotIn("tor-a", self.analyzer.update_storms)

        # Pre-upgrade baseline without msg_rcvd: self-describing skip, the
        # key is added for the next cycle.
        self.analyzer.flap_baselines["tor-b"] = {
            "default|swp1": {"dropped": 0, "established": 1,
                             "ts": int(time.time() - 600)},
        }
        self.analyzer.update_bgp_flap_stats(
            "tor-b", summary_json(dropped=0, established=1, msg_rcvd=99999))
        self.assertNotIn("tor-b", self.analyzer.update_storms)
        self.assertEqual(
            99999,
            self.analyzer.flap_baselines["tor-b"]["default|swp1"]["msg_rcvd"])

    def test_threshold_defaults_when_notification_keys_absent(self):
        # Setup UI may drop unknown notification keys: code defaults must
        # match the shipped notifications.yaml values.
        config = Path(self.tmp.name) / "notifications.yaml"
        config.write_text(
            "thresholds:\n  network:\n    bgp_down_minutes: 5\n",
            encoding="utf-8")
        with mock.patch.dict(
            "os.environ", {"LLDPQ_NOTIFICATIONS_FILE": str(config)}
        ):
            analyzer = BGPAnalyzer(self.tmp.name)
        self.assertEqual(30, analyzer.thresholds["bgp_update_storm_warning"])
        self.assertEqual(
            120, analyzer.thresholds["bgp_update_storm_critical"])

    def test_configured_thresholds_are_loaded(self):
        config = Path(self.tmp.name) / "notifications.yaml"
        config.write_text(
            "thresholds:\n  network:\n"
            "    bgp_update_storm_warning: 5\n"
            "    bgp_update_storm_critical: 50\n",
            encoding="utf-8")
        with mock.patch.dict(
            "os.environ", {"LLDPQ_NOTIFICATIONS_FILE": str(config)}
        ):
            analyzer = BGPAnalyzer(self.tmp.name)
        self.assertEqual(5, analyzer.thresholds["bgp_update_storm_warning"])
        self.assertEqual(50, analyzer.thresholds["bgp_update_storm_critical"])

    def test_storms_survive_save_and_stay_out_of_export_rows(self):
        self._baseline(msg_rcvd=0, age=600)
        self.analyzer.update_bgp_stats(
            "tor-a", ESTABLISHED_SUMMARY,
            bgp_json_data=summary_json(dropped=0, established=1,
                                       msg_rcvd=1300))
        self.analyzer.save_bgp_history()
        saved = json.loads(
            (Path(self.tmp.name) / "bgp_history.json").read_text())
        self.assertEqual(1, len(saved["update_storms"]["tor-a"]))

        output_file = str(Path(self.tmp.name) / "bgp-analysis.html")
        # Must not raise ExportContractError: the storm rate stays out of
        # the machine-export rows (the registry has no such column).
        self.analyzer.export_bgp_data_for_web(output_file)
        report = Path(output_file).read_text(encoding="utf-8")
        self.assertIn("Updates RX (msgs/min)", report)
        export = json.loads(
            (Path(self.tmp.name) / "export" / "bgp.json").read_text())
        self.assertNotIn("msg_rate_per_min", export["rows"][0])


class BgpFlapAlertTests(unittest.TestCase):
    def _checker(self, tmp, flap_events, data_status="current"):
        checker = object.__new__(check_alerts.LLDPqAlerts)
        checker.monitor_results = Path(tmp)
        checker.had_error = False
        checker.config = {
            "alert_types": {"network_alerts": True},
            "thresholds": {"network": {
                "bgp_flaps_warning": 1, "bgp_flaps_critical": 3}},
            "frequency": {"send_recovery": True},
        }
        checker._bgp_history_loaded = False
        checker._bgp_current_stats = None
        checker._bgp_flap_events = None
        checker._bgp_history_error = None
        (Path(tmp) / "bgp_history.json").write_text(json.dumps({
            "current_bgp_stats": {
                "leaf1": {
                    "neighbors": [], "total_neighbors": 1,
                    "established_neighbors": 1, "down_neighbors": 0,
                    "warning_neighbors": 0, "critical_neighbors": 0,
                    "data_status": data_status,
                },
            },
            "flap_events": flap_events,
        }), encoding="utf-8")
        return checker

    def _run_network_alerts(self, checker):
        sent = []

        def capture(title, message, severity, device, key, new_state):
            sent.append({"title": title, "message": message,
                         "severity": severity, "device": device,
                         "key": key, "state": new_state})
            return True

        with (
            mock.patch.object(checker, "get_device_bgp_status",
                              create=True, return_value="stale"),
            mock.patch.object(checker, "get_device_flap_counts",
                              create=True, return_value=None),
            mock.patch.object(checker, "check_processed_network_alerts",
                              create=True, return_value=True),
            mock.patch.object(checker, "should_send_alert",
                              create=True, return_value=True),
            mock.patch.object(checker, "send_stateful_notification",
                              create=True, side_effect=capture),
            mock.patch.object(checker, "record_state_without_delivery",
                              create=True, return_value=True),
        ):
            checker.check_network_alerts("leaf1")
        return [item for item in sent if item["key"] == "bgp_session_flaps"]

    def test_critical_threshold_lists_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "default",
                 "neighbor": "swp3", "count": 4},
            ]})
            self.assertEqual(
                {"default/swp3": 4},
                checker.get_device_bgp_flap_counts("leaf1"))
            (alert,) = self._run_network_alerts(checker)
            self.assertEqual("CRITICAL", alert["severity"])
            self.assertIn("default/swp3: 4", alert["message"])

    def test_warning_threshold_and_old_events_age_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "vrf-red",
                 "neighbor": "swp3", "count": 1},
                {"ts": time.time() - 7200, "vrf": "vrf-red",
                 "neighbor": "swp3", "count": 50},
            ]})
            self.assertEqual(
                {"vrf-red/swp3": 1},
                checker.get_device_bgp_flap_counts("leaf1"))
            (alert,) = self._run_network_alerts(checker)
            self.assertEqual("WARNING", alert["severity"])
            self.assertIn("vrf-red/swp3: 1", alert["message"])

    def test_stale_collection_skips_flap_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "default",
                 "neighbor": "swp3", "count": 4},
            ]}, data_status="stale")
            self.assertIsNone(checker.get_device_bgp_flap_counts("leaf1"))
            self.assertEqual([], self._run_network_alerts(checker))

    def test_pre_upgrade_history_without_flap_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": []})
            payload = json.loads(
                (Path(tmp) / "bgp_history.json").read_text())
            del payload["flap_events"]
            (Path(tmp) / "bgp_history.json").write_text(json.dumps(payload))
            self.assertEqual({}, checker.get_device_bgp_flap_counts("leaf1"))
            self.assertFalse(checker.had_error)


class BgpStormAlertTests(unittest.TestCase):
    def _checker(self, tmp, update_storms, data_status="current",
                 thresholds=None):
        checker = object.__new__(check_alerts.LLDPqAlerts)
        checker.monitor_results = Path(tmp)
        checker.had_error = False
        checker.config = {
            "alert_types": {"network_alerts": True},
            "thresholds": {"network": (
                thresholds if thresholds is not None else
                {"bgp_update_storm_warning": 30,
                 "bgp_update_storm_critical": 120}
            )},
            "frequency": {"send_recovery": True},
        }
        checker._bgp_history_loaded = False
        checker._bgp_current_stats = None
        checker._bgp_flap_events = None
        checker._bgp_update_storms = None
        checker._bgp_history_error = None
        (Path(tmp) / "bgp_history.json").write_text(json.dumps({
            "current_bgp_stats": {
                "leaf1": {
                    "neighbors": [], "total_neighbors": 1,
                    "established_neighbors": 1, "down_neighbors": 0,
                    "warning_neighbors": 0, "critical_neighbors": 0,
                    "data_status": data_status,
                },
            },
            "flap_events": {},
            "update_storms": update_storms,
        }), encoding="utf-8")
        return checker

    def _run_network_alerts(self, checker):
        sent = []

        def capture(title, message, severity, device, key, new_state):
            sent.append({"title": title, "message": message,
                         "severity": severity, "device": device,
                         "key": key, "state": new_state})
            return True

        with (
            mock.patch.object(checker, "get_device_bgp_status",
                              create=True, return_value="stale"),
            mock.patch.object(checker, "get_device_flap_counts",
                              create=True, return_value=None),
            mock.patch.object(checker, "check_processed_network_alerts",
                              create=True, return_value=True),
            mock.patch.object(checker, "should_send_alert",
                              create=True, return_value=True),
            mock.patch.object(checker, "send_stateful_notification",
                              create=True, side_effect=capture),
            mock.patch.object(checker, "record_state_without_delivery",
                              create=True, return_value=True),
        ):
            checker.check_network_alerts("leaf1")
        return [item for item in sent if item["key"] == "bgp_update_storm"]

    def test_critical_rate_lists_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "default",
                 "neighbor": "swp3", "rate": 150.0, "severity": "critical"},
            ]})
            self.assertEqual(
                {"default/swp3": 150.0},
                checker.get_device_bgp_update_storms("leaf1"))
            (alert,) = self._run_network_alerts(checker)
            self.assertEqual("CRITICAL", alert["severity"])
            self.assertIn("default/swp3: 150/min", alert["message"])

    def test_warning_rate_and_old_storms_age_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "vrf-red",
                 "neighbor": "swp3", "rate": 45.0, "severity": "warning"},
                {"ts": time.time() - 7200, "vrf": "vrf-red",
                 "neighbor": "swp3", "rate": 500.0, "severity": "critical"},
            ]})
            self.assertEqual(
                {"vrf-red/swp3": 45.0},
                checker.get_device_bgp_update_storms("leaf1"))
            (alert,) = self._run_network_alerts(checker)
            self.assertEqual("WARNING", alert["severity"])
            self.assertIn("vrf-red/swp3: 45/min", alert["message"])

    def test_threshold_defaults_when_config_keys_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "default",
                 "neighbor": "swp3", "rate": 45.0, "severity": "warning"},
            ]}, thresholds={})
            (alert,) = self._run_network_alerts(checker)
            # 45/min sits between the 30/120 code defaults.
            self.assertEqual("WARNING", alert["severity"])

    def test_stale_collection_skips_storm_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": [
                {"ts": time.time() - 120, "vrf": "default",
                 "neighbor": "swp3", "rate": 150.0, "severity": "critical"},
            ]}, data_status="stale")
            self.assertIsNone(checker.get_device_bgp_update_storms("leaf1"))
            self.assertEqual([], self._run_network_alerts(checker))

    def test_pre_upgrade_history_without_update_storms(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = self._checker(tmp, {"leaf1": []})
            payload = json.loads(
                (Path(tmp) / "bgp_history.json").read_text())
            del payload["update_storms"]
            (Path(tmp) / "bgp_history.json").write_text(json.dumps(payload))
            self.assertEqual(
                {}, checker.get_device_bgp_update_storms("leaf1"))
            self.assertFalse(checker.had_error)


class AiCorrelateFlapTests(unittest.TestCase):
    def test_fresh_flap_events_surface_and_stale_are_gated(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = time.time()
            (Path(tmp) / "bgp_history.json").write_text(json.dumps({
                "current_bgp_stats": {},
                "flap_events": {
                    "leaf1": [
                        {"ts": now - 300, "vrf": "default",
                         "neighbor": "swp3", "count": 2},
                        {"ts": now - 3 * 3600, "vrf": "default",
                         "neighbor": "swp9", "count": 9},
                    ],
                },
            }), encoding="utf-8")
            anomalies = ai_correlate._collect_bgp(tmp, now)
            flaps = [a for a in anomalies if a["metric"] == "session_flaps"]
            (anomaly,) = flaps
            self.assertEqual("leaf1", anomaly["device"])
            self.assertEqual("swp3", anomaly["port"])
            self.assertEqual(2, anomaly["value"])
            self.assertEqual("WARNING", ai_correlate.severity_for(anomaly))


if __name__ == "__main__":
    unittest.main()
