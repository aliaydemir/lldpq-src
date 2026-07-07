#!/usr/bin/env python3
"""Focused contract tests for Ask-AI evidence and timeline helpers."""

import json
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "html"))

import ai_insights  # noqa: E402
from ai_insights import build_evidence, build_timeline, timeline_prompt_context  # noqa: E402


NOW = 1_800_000_000.0


class AskAiInsightsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.web = self.root / "web"
        self.web.mkdir()
        self.monitor = self.web / "monitor-results"
        self.monitor.mkdir()

    def write_monitor(self, name, value):
        (self.monitor / name).write_text(json.dumps(value), encoding="utf-8")

    def write_web(self, name, value):
        (self.web / name).write_text(json.dumps(value), encoding="utf-8")

    def populate_history(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {
                        "timestamp": NOW - 200,
                        "established_count": 8,
                        "down_count": 0,
                        "warning_neighbors": 0,
                        "critical_neighbors": 0,
                    },
                    {
                        "timestamp": NOW - 100,
                        "established_count": 7,
                        "down_count": 1,
                        "warning_neighbors": 0,
                        "critical_neighbors": 1,
                    },
                ]
            }
        })
        self.write_monitor("optical_history.json", {
            "optical_history": {
                "leaf01:swp1": [
                    {"timestamp": NOW - 210, "health": "good", "rx_power_dbm": -3.0},
                    {"timestamp": NOW - 90, "health": "warning", "rx_power_dbm": -7.0},
                ]
            }
        })
        self.write_monitor("ber_history.json", {
            "ber_history": {
                "leaf01:swp1": [
                    {
                        "timestamp": NOW - 220,
                        "grade": "excellent",
                        "delta_errors": 0,
                        "sample_status": "analyzed",
                    },
                    {
                        "timestamp": NOW - 80,
                        "grade": "critical",
                        "delta_errors": 4,
                        "sample_status": "analyzed",
                        "ber_value": 1e-7,
                    },
                ]
            }
        })
        self.write_monitor("flap_history.json", {
            "flapping_hist": {"leaf01:swp1": [[NOW - 70, 20, 2, NOW - 370, 300]]}
        })
        self.write_monitor("pfc_ecn_history.json", {
            "history": {
                "leaf01:swp1": [
                    {
                        "timestamp": NOW - 180,
                        "sample_status": "analyzed",
                        "signal": "quiet",
                        "loss_delta": 0,
                    },
                    {
                        "timestamp": NOW - 60,
                        "sample_status": "analyzed",
                        "signal": "loss",
                        "loss_delta": 3,
                    },
                ]
            }
        })
        self.write_monitor("log_summary.json", {
            "timestamp": NOW - 50,
            "totals": {"critical": 1},
            "recent_messages": {"leaf01": ["SECRET raw log must never enter timeline"]},
        })
        self.write_web("fabric-scan-cache.json", {
            # Browser-authored cache uses Date.now() epoch milliseconds.
            "timestamp": (NOW - 95) * 1000,
            "pendingDevices": ["leaf01"],
        })

    def test_builds_multi_source_timeline_and_noncausal_correlation(self):
        self.populate_history()
        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
        )

        self.assertEqual(timeline["window"], "1h")
        self.assertEqual(
            {event["category"] for event in timeline["events"]},
            {"bgp", "optical", "ber", "link", "pfc_ecn", "config"},
        )
        self.assertTrue(all(event["device"] == "leaf01" for event in timeline["events"]))
        self.assertTrue(timeline["correlations"])
        correlation = timeline["correlations"][0]
        self.assertGreaterEqual(len(correlation["categories"]), 2)
        self.assertIn("causality is not established", correlation["note"])
        self.assertNotIn("SECRET", json.dumps(timeline))
        log_coverage = next(row for row in timeline["coverage"] if row["source"] == "logs")
        self.assertEqual(log_coverage["status"], "unsupported")

        prompt = timeline_prompt_context(timeline)
        self.assertIn("UNTRUSTED OBSERVATION METADATA", prompt)
        self.assertIn("Correlation is not causation", prompt)
        self.assertNotIn("SECRET raw log", prompt)

    def test_fail_closed_for_malformed_ambiguous_and_future_timestamps(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {"timestamp": "2027-01-15T12:00:00", "down_count": 0},
                    {"timestamp": NOW + 10_000, "down_count": 1},
                ]
            }
        })
        (self.monitor / "optical_history.json").write_text("{not-json", encoding="utf-8")
        self.write_web("fabric-scan-cache.json", {
            "timestamp": NOW + 10_000,
            "pendingDevices": ["leaf01"],
        })

        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
        )

        self.assertEqual(timeline["events"], [])
        statuses = {row["source"]: row["status"] for row in timeline["coverage"]}
        self.assertEqual(statuses["bgp"], "empty")
        self.assertEqual(statuses["optical"], "invalid")
        self.assertEqual(statuses["config"], "invalid")
        self.assertEqual(statuses["ber"], "missing")

    def test_event_fields_are_bounded_single_line_and_control_free(self):
        hostile = "leaf01\n\x00" + ("x" * 300)
        self.write_web("fabric-scan-cache.json", {
            "timestamp": NOW - 10,
            "pendingDevices": [hostile],
        })
        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
        )
        event = timeline["events"][0]
        for key in ("device", "subject", "summary", "source"):
            self.assertNotIn("\n", event[key])
            self.assertNotIn("\x00", event[key])
        self.assertLessEqual(len(event["device"]), 96)
        self.assertLessEqual(len(event["summary"]), 280)

    def test_keeps_newest_events_when_capped_and_reports_truncation(self):
        rows = [{
            "timestamp": NOW - 500 + index,
            "sample_status": "analyzed",
            "signal": "quiet" if index % 2 == 0 else "ecn",
            "loss_delta": 0,
        } for index in range(10)]
        self.write_monitor("pfc_ecn_history.json", {"history": {"leaf01:swp1": rows}})
        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
            max_events=3,
        )
        self.assertTrue(timeline["truncated"])
        self.assertEqual(len(timeline["events"]), 3)
        self.assertEqual(
            [event["ts"] for event in timeline["events"]],
            [NOW - 495, NOW - 493, NOW - 491],
        )

    def test_modern_ber_schema_detects_combined_grade_and_error_onset(self):
        self.write_monitor("ber_history.json", {
            "ber_history": {
                "leaf01:swp9": [
                    {
                        "timestamp": NOW - 50,
                        "effective_grade": "excellent",
                        "frame_grade": "excellent",
                        "delta_rx_errors": 0,
                        "delta_tx_errors": 0,
                        "sample_status": "analyzed",
                    },
                    {
                        "timestamp": NOW - 40,
                        "status": "critical",
                        "frame_grade": "warning",
                        "delta_rx_errors": 2,
                        "delta_tx_errors": 3,
                        "sample_status": "analyzed",
                        "effective_ber": 1e-9,
                    },
                ]
            }
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        events = [event for event in timeline["events"] if event["category"] == "ber"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertIn("grade excellent→critical", events[0]["summary"])
        self.assertIn("5 new interface error events", events[0]["summary"])
        self.assertIn("effective PHY BER", events[0]["summary"])

    def test_modern_ber_component_only_degradation_is_not_missed(self):
        history = {}
        for index, key in enumerate(("raw_grade", "effective_grade", "symbol_grade"), 1):
            history["leaf01:swp%d" % index] = [
                {"timestamp": NOW - 20, key: "excellent", "sample_status": "analyzed"},
                {"timestamp": NOW - 10, key: "critical", "sample_status": "analyzed"},
            ]
        self.write_monitor("ber_history.json", {"ber_history": history})
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        events = [event for event in timeline["events"] if event["category"] == "ber"]
        self.assertEqual(len(events), 3)
        self.assertTrue(all(event["severity"] == "critical" for event in events))

    def test_repeated_congestion_samples_do_not_spam_and_nonloss_is_info(self):
        self.write_monitor("pfc_ecn_history.json", {
            "history": {
                "leaf01:swp2": [
                    {"timestamp": NOW - 50, "sample_status": "analyzed", "signal": "quiet"},
                    {"timestamp": NOW - 40, "sample_status": "analyzed", "signal": "pfc"},
                    {"timestamp": NOW - 30, "sample_status": "analyzed", "signal": "pfc"},
                    {"timestamp": NOW - 20, "sample_status": "analyzed", "signal": "combined"},
                ]
            }
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        events = [event for event in timeline["events"] if event["category"] == "pfc_ecn"]
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event["severity"] == "info" for event in events))

    def test_flap_history_does_not_invent_unpersisted_critical_threshold(self):
        self.write_monitor("flap_history.json", {
            "flapping_hist": {"leaf01:swp3": [[NOW - 10, 100, 99, NOW - 20, 10]]}
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        event = next(event for event in timeline["events"] if event["category"] == "link")
        self.assertEqual(event["severity"], "warning")

    def test_flap_interval_must_be_fully_inside_requested_window(self):
        self.write_monitor("flap_history.json", {
            "flapping_hist": {
                "leaf01:swp3": [[NOW - 10, 100, 2, NOW - 3610, 3600]]
            }
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        self.assertFalse(any(event["category"] == "link" for event in timeline["events"]))

    def test_current_complete_empty_flap_history_proves_zero_retained_events(self):
        self.write_monitor("flap_history.json", {
            "flapping_hist": {},
            "last_update": NOW - 5,
            "collection_coverage": {
                "expected_devices": 2,
                "current_devices": 2,
                "unavailable_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        flap = next(row for row in timeline["coverage"] if row["source"] == "flaps")
        self.assertEqual(flap["status"], "partial")
        self.assertEqual(flap["events"], 0)
        self.assertIn("no retained flap events", flap["detail"])
        self.assertIn("No retained baseline", flap["detail"])

    def test_bounded_retention_marks_long_window_partial(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {"timestamp": NOW - 3600, "down_count": 0},
                    {"timestamp": NOW - 60, "down_count": 1},
                ]
            },
            "collection_coverage": {
                "expected_devices": 1,
                "current_bgp_devices": 1,
                "unavailable_bgp_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="24h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "partial")
        self.assertGreater(bgp["covers_from"], timeline["from"])

        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="7d", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "partial")
        self.assertIn("retention", bgp["detail"])

    def test_bgp_down_increase_is_warning_without_producer_critical_grade(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {
                        "timestamp": NOW - 20,
                        "down_count": 0,
                        "critical_neighbors": 0,
                    },
                    {
                        "timestamp": NOW - 10,
                        "down_count": 1,
                        "critical_neighbors": 0,
                    },
                ]
            },
            "collection_coverage": {
                "expected_devices": 1,
                "current_bgp_devices": 1,
                "unavailable_bgp_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp_event = next(event for event in timeline["events"] if event["category"] == "bgp")
        self.assertEqual(bgp_event["severity"], "warning")

    def test_common_coverage_begins_at_latest_series_baseline(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {"timestamp": NOW - 3700, "down_count": 0},
                    {"timestamp": NOW - 10, "down_count": 0},
                ],
                "leaf02": [
                    {"timestamp": NOW - 100, "down_count": 0},
                    {"timestamp": NOW - 10, "down_count": 0},
                ],
            },
            "collection_coverage": {
                "expected_devices": 2,
                "current_bgp_devices": 2,
                "unavailable_bgp_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "partial")
        self.assertEqual(bgp["covers_from"], NOW - 100)

    def test_right_edge_freshness_gap_marks_history_stale(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {"timestamp": NOW - 3700, "down_count": 0},
                    {"timestamp": NOW - 1900, "down_count": 1},
                ]
            },
            "collection_coverage": {
                "expected_devices": 1,
                "current_bgp_devices": 1,
                "unavailable_bgp_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "stale")
        self.assertEqual(bgp["covers_to"], NOW - 1900)

    def test_common_coverage_end_uses_stalest_series(self):
        self.write_monitor("bgp_history.json", {
            "bgp_history": {
                "leaf01": [
                    {"timestamp": NOW - 3700, "down_count": 0},
                    {"timestamp": NOW - 10, "down_count": 0},
                ],
                "leaf02": [
                    {"timestamp": NOW - 3700, "down_count": 0},
                    {"timestamp": NOW - 1900, "down_count": 0},
                ],
            },
            "collection_coverage": {
                "expected_devices": 2,
                "current_bgp_devices": 2,
                "unavailable_bgp_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "stale")
        self.assertEqual(bgp["latest_timestamp"], NOW - 10)
        self.assertEqual(bgp["covers_to"], NOW - 1900)

    def test_flap_source_freshness_uses_producer_poll_not_last_event(self):
        self.write_monitor("flap_history.json", {
            "flapping_hist": {
                "leaf01:swp1": [[NOW - 2700, 10, 1, NOW - 2800, 100]]
            },
            "last_update": NOW - 5,
            "collection_coverage": {
                "expected_devices": 1,
                "current_devices": 1,
                "unavailable_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        flap = next(row for row in timeline["coverage"] if row["source"] == "flaps")
        self.assertNotEqual(flap["status"], "stale")
        self.assertEqual(flap["latest_timestamp"], NOW - 5)
        self.assertEqual(flap["covers_to"], NOW - 5)

    def test_fresh_flap_poll_does_not_hide_incomplete_device_coverage(self):
        self.write_monitor("flap_history.json", {
            "flapping_hist": {
                "leaf01:swp1": [[NOW - 10, 10, 1, NOW - 3700, 3690]]
            },
            "last_update": NOW - 5,
            "collection_coverage": {
                "expected_devices": 2,
                "current_devices": 1,
                "unavailable_devices": ["leaf02"],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        flap = next(row for row in timeline["coverage"] if row["source"] == "flaps")
        self.assertEqual(flap["status"], "partial")
        self.assertIn("incomplete", flap["detail"])

    def test_series_and_sample_limits_are_disclosed_as_truncation(self):
        optical = {
            "leaf%05d:swp1" % index: [{"timestamp": NOW - 1, "health": "good"}]
            for index in range(10_001)
        }
        self.write_monitor("optical_history.json", {"optical_history": optical})
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        source = next(row for row in timeline["coverage"] if row["source"] == "optical")
        self.assertTrue(source["truncated"])
        self.assertTrue(timeline["truncated"])
        self.assertIn("series limit", source["detail"])

        samples = [
            {"timestamp": NOW - 1100 + index, "grade": "good"}
            for index in range(1001)
        ]
        self.write_monitor("ber_history.json", {"ber_history": {"leaf01:swp1": samples}})
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        source = next(row for row in timeline["coverage"] if row["source"] == "ber")
        self.assertTrue(source["truncated"])
        self.assertIn("sample limit", source["detail"])

        flap_samples = [
            [NOW - 1100 + index, index * 2, 1, NOW - 1101 + index, 1]
            for index in range(1001)
        ]
        self.write_monitor("flap_history.json", {
            "flapping_hist": {"leaf01:swp1": flap_samples},
            "last_update": NOW - 1,
            "collection_coverage": {
                "expected_devices": 1,
                "current_devices": 1,
                "unavailable_devices": [],
            },
        })
        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
            max_events=500,
        )
        source = next(row for row in timeline["coverage"] if row["source"] == "flaps")
        self.assertEqual(source["samples"], 1000)
        self.assertTrue(source["truncated"])
        self.assertIn("sample limit", source["detail"])

    def test_evidence_redacts_paths_credentials_and_raw_output(self):
        metadata = {
            "complete": True,
            "sources": {
                "bgp": {
                    "path": "/private/secret/bgp_history.json",
                    "required": True,
                    "available": True,
                    "current": True,
                    "complete": True,
                    "age_seconds": 20,
                    "coverage": {"expected_devices": 2, "current_devices": 2},
                }
            },
        }
        tools = [{
            "device": "leaf01",
            "command": (
                "show /etc/shadow token=super-secret community public "
                "password 7 typed-secret"
            ),
            "ok": True,
            "output": "raw output must not appear",
        }]
        result = build_evidence(metadata, tools, now=NOW)
        serialized = json.dumps(result)

        self.assertEqual(result["confidence"]["level"], "high")
        self.assertEqual(result["records"][0]["coverage"], "2/2")
        self.assertNotIn("/private/secret", serialized)
        self.assertNotIn("/etc/shadow", serialized)
        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("public", serialized)
        self.assertNotIn("typed-secret", serialized)
        self.assertNotIn("raw output must not appear", serialized)
        self.assertIn("[redacted]", serialized)
        self.assertIn("[path]", serialized)
        tool_record = next(record for record in result["records"] if record["kind"] == "command")
        self.assertEqual(tool_record["observed_at"], NOW)
        self.assertEqual(tool_record["age_seconds"], 0)

    def test_unknown_live_tool_prevents_high_confidence(self):
        metadata = {
            "complete": True,
            "sources": {
                "bgp": {
                    "required": True,
                    "available": True,
                    "current": True,
                    "complete": True,
                    "age_seconds": 1,
                }
            },
        }
        result = build_evidence(
            metadata,
            [{"dispatch": "all", "command": "show version"}],
            now=NOW,
        )
        self.assertEqual(result["confidence"]["level"], "medium")
        self.assertFalse(result["confidence"]["complete"])

    def test_incomplete_collection_lowers_confidence_and_timeline_is_evidence(self):
        metadata = {
            "complete": False,
            "sources": {
                "bgp": {
                    "required": True,
                    "available": True,
                    "current": False,
                    "complete": False,
                    "age_seconds": 9999,
                }
            },
        }
        timeline = {
            "window": "1h",
            "to": NOW,
            "events": [],
            "correlations": [],
            "coverage": [{"source": "bgp", "status": "stale"}],
            "truncated": False,
        }
        result = build_evidence(metadata, timeline=timeline, now=NOW)
        self.assertEqual(result["confidence"]["level"], "low")
        self.assertFalse(result["confidence"]["complete"])
        self.assertEqual(result["records"][-1]["kind"], "timeline")
        self.assertEqual(result["records"][-1]["status"], "warning")
        self.assertEqual(result["records"][-1]["observed_at"], None)

    def test_timeline_confidence_requires_current_historical_coverage(self):
        metadata = {
            "complete": True,
            "sources": {
                "bgp": {
                    "required": True,
                    "available": True,
                    "current": True,
                    "complete": True,
                    "age_seconds": 1,
                }
            },
        }
        partial = {
            "window": "1h",
            "to": NOW,
            "events": [],
            "correlations": [],
            "coverage": [
                {"source": "bgp", "status": "ok"},
                {"source": "optical", "status": "missing"},
                {"source": "logs", "status": "unsupported"},
            ],
            "truncated": False,
        }
        result = build_evidence(metadata, timeline=partial, now=NOW)
        self.assertEqual(result["confidence"]["level"], "medium")
        self.assertFalse(result["confidence"]["complete"])

        unusable = dict(partial)
        unusable["coverage"] = [
            {"source": "bgp", "status": "stale"},
            {"source": "optical", "status": "empty"},
        ]
        result = build_evidence(metadata, timeline=unusable, now=NOW)
        self.assertEqual(result["confidence"]["level"], "low")

    def test_prompt_smallest_allowed_limit_remains_valid_json(self):
        timeline = {
            "window": "1h",
            "from": NOW - 3600,
            "to": NOW,
            "events": [],
            "correlations": [],
            "coverage": [
                {
                    "source": "bgp",
                    "status": "missing",
                    "samples": 0,
                    "events": 0,
                    "detail": "x" * 160,
                }
                for _ in range(20)
            ],
            "truncated": False,
        }
        output = timeline_prompt_context(timeline, max_chars=1000)
        prefix, serialized = output.split("\n", 1)
        self.assertIn("UNTRUSTED", prefix)
        parsed = json.loads(serialized)
        self.assertTrue(parsed["truncated"])
        self.assertLessEqual(len(output), 1000)

    def test_per_source_candidates_are_bounded_before_public_cap(self):
        history = {}
        for port in ("swp1", "swp2"):
            history["leaf01:" + port] = [{
                "timestamp": NOW - 2000 + index,
                "sample_status": "analyzed",
                "signal": "quiet" if index % 2 == 0 else "ecn",
            } for index in range(1000)]
        self.write_monitor("pfc_ecn_history.json", {"history": history})
        timeline = build_timeline(
            monitor_dir=self.monitor,
            web_root=self.web,
            window="1h",
            now=NOW,
            max_events=500,
        )
        pfc = next(row for row in timeline["coverage"] if row["source"] == "pfc_ecn")
        self.assertEqual(pfc["events"], 1000)
        self.assertTrue(timeline["truncated"])
        self.assertEqual(len(timeline["events"]), 500)

    def test_constructed_history_over_64_mib_streams_with_bounded_heap(self):
        path = self.monitor / "bgp_history.json"
        samples = [
            {"timestamp": NOW - 3700, "down_count": 0, "critical_neighbors": 0},
            {"timestamp": NOW - 10, "down_count": 1, "critical_neighbors": 0},
        ]
        coverage = {
            "expected_devices": 1,
            "current_bgp_devices": 1,
            "unavailable_bgp_devices": [],
        }
        # Construct incrementally: neither the test nor the implementation
        # ever materializes the 65 MiB JSON document as one Python object.
        chunk = b"x" * (1024 * 1024)
        with path.open("wb") as stream:
            stream.write(b'{"bgp_history":{"leaf01":')
            stream.write(json.dumps(samples).encode("utf-8"))
            stream.write(b'},"padding":"')
            for _ in range(65):
                stream.write(chunk)
            stream.write(
                b'","private":"token=stream-secret /private/hidden",'
                b'"collection_coverage":'
            )
            stream.write(json.dumps(coverage).encode("utf-8"))
            stream.write(b"}")
        self.assertGreater(path.stat().st_size, 64 * 1024 * 1024)

        tracemalloc.start()
        try:
            timeline = build_timeline(
                monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
            )
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        events = [event for event in timeline["events"] if event["category"] == "bgp"]
        self.assertEqual(bgp["status"], "ok")
        self.assertEqual(bgp["expected_devices"], 1)
        self.assertEqual(bgp["current_devices"], 1)
        self.assertEqual(len(events), 1)
        self.assertLess(peak, 16 * 1024 * 1024)
        serialized = json.dumps(timeline)
        self.assertNotIn("stream-secret", serialized)
        self.assertNotIn("/private/hidden", serialized)

    def test_malformed_late_series_discards_earlier_streamed_events(self):
        path = self.monitor / "bgp_history.json"
        path.write_text(
            '{"bgp_history":{'
            '"leaf01":[{"timestamp":%s,"down_count":0},'
            '{"timestamp":%s,"down_count":1}],'
            '"token=must-not-leak":[{"timestamp":1},]}}' % (NOW - 20, NOW - 10),
            encoding="utf-8",
        )
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "invalid")
        self.assertFalse(any(event["category"] == "bgp" for event in timeline["events"]))
        self.assertNotIn("must-not-leak", json.dumps(timeline))

    def test_oversized_series_and_sample_are_partial_not_empty(self):
        optical = {
            "optical_history": {
                "leaf01:swp1": [
                    {
                        "timestamp": NOW - 20,
                        "health": "good",
                        "padding": "x" * 700,
                    },
                    {"timestamp": NOW - 10, "health": "warning"},
                ]
            }
        }
        self.write_monitor("optical_history.json", optical)
        with mock.patch.object(ai_insights, "MAX_SERIES_BYTES", 512):
            timeline = build_timeline(
                monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
            )
        source = next(row for row in timeline["coverage"] if row["source"] == "optical")
        self.assertEqual(source["status"], "partial")
        self.assertTrue(source["truncated"])
        self.assertIn("oversized series", source["detail"])
        self.assertFalse(any(event["category"] == "optical" for event in timeline["events"]))

        self.write_monitor("pfc_ecn_history.json", {
            "history": {
                "leaf01:swp1": [
                    {
                        "timestamp": NOW - 20,
                        "sample_status": "analyzed",
                        "signal": "quiet",
                        "private": "token=oversized-secret " + ("y" * 500),
                    },
                    {
                        "timestamp": NOW - 10,
                        "sample_status": "analyzed",
                        "signal": "pfc",
                    },
                ]
            }
        })
        with mock.patch.object(ai_insights, "MAX_SAMPLE_BYTES", 128):
            timeline = build_timeline(
                monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
            )
        source = next(row for row in timeline["coverage"] if row["source"] == "pfc_ecn")
        self.assertEqual(source["status"], "partial")
        self.assertTrue(source["truncated"])
        self.assertIn("oversized samples", source["detail"])
        self.assertNotIn("oversized-secret", json.dumps(timeline))

    def test_stream_parser_rejects_ambiguous_or_nonfinite_json(self):
        cases = (
            b'{"bgp_history":{},"junk":"\\q"}',
            b'{"bgp_history":{},"junk":1e999}',
            b'{"bgp_history":{},"bgp_history":{}}',
        )
        path = self.monitor / "bgp_history.json"
        for payload in cases:
            with self.subTest(payload=payload):
                path.write_bytes(payload)
                timeline = build_timeline(
                    monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
                )
                bgp = next(
                    row for row in timeline["coverage"] if row["source"] == "bgp"
                )
                self.assertEqual(bgp["status"], "invalid")

        path.write_bytes(b'{"bgp_history":{},"junk":"\xff"}')
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "invalid")

    def test_stream_parser_handles_chunk_boundaries_and_detects_mutation(self):
        self.write_monitor("pfc_ecn_history.json", {
            "history": {
                "leafé:swp1": [
                    {"timestamp": NOW - 20, "sample_status": "analyzed", "signal": "quiet"},
                    {"timestamp": NOW - 10, "sample_status": "analyzed", "signal": "pfc"},
                ]
            },
            "ignored": {"braces": "a}b[c\\\"d"},
        })
        with mock.patch.object(ai_insights, "JSON_READ_CHUNK_BYTES", 7):
            timeline = build_timeline(
                monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
            )
        event = next(event for event in timeline["events"] if event["category"] == "pfc_ecn")
        self.assertEqual(event["device"], "leafé")

        self.write_monitor("bgp_history.json", {"bgp_history": {}})
        real_fstat = ai_insights.os.fstat
        calls = 0

        def changing_fstat(fd):
            nonlocal calls
            calls += 1
            result = real_fstat(fd)
            if calls == 2:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_size=result.st_size,
                    st_dev=result.st_dev,
                    st_ino=result.st_ino,
                    st_mtime_ns=result.st_mtime_ns + 1,
                )
            return result

        with mock.patch.object(ai_insights.os, "fstat", side_effect=changing_fstat):
            timeline = build_timeline(
                monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
            )
        bgp = next(row for row in timeline["coverage"] if row["source"] == "bgp")
        self.assertEqual(bgp["status"], "invalid")

    def test_sparse_source_over_absolute_cap_is_rejected_without_reading(self):
        target_samples = 58 * 128 * 288
        self.assertLess(target_samples, ai_insights.MAX_TOTAL_DECODED_SAMPLES)
        self.assertLess(
            target_samples * 1065,
            ai_insights.MAX_HISTORY_SOURCE_BYTES,
        )
        path = self.monitor / "optical_history.json"
        with path.open("wb") as stream:
            stream.truncate(ai_insights.MAX_HISTORY_SOURCE_BYTES + 1)
        timeline = build_timeline(
            monitor_dir=self.monitor, web_root=self.web, window="1h", now=NOW
        )
        optical = next(
            row for row in timeline["coverage"] if row["source"] == "optical"
        )
        self.assertEqual(optical["status"], "invalid")

    def test_configured_published_tree_never_falls_back_to_live_history(self):
        live = self.root / "live-monitor-results"
        live.mkdir()
        (live / "bgp_history.json").write_text(
            json.dumps({"bgp_history": {}}), encoding="utf-8"
        )
        absent_root = self.root / "publication-not-created"
        empty_root = self.root / "empty-publication"
        (empty_root / "monitor-results").mkdir(parents=True)
        for web_root in (absent_root, empty_root):
            with self.subTest(web_root=web_root.name):
                timeline = build_timeline(
                    monitor_dir=live, web_root=web_root, window="1h", now=NOW
                )
                bgp = next(
                    row for row in timeline["coverage"] if row["source"] == "bgp"
                )
                self.assertEqual(bgp["status"], "missing")

    def test_confidence_uses_worst_collection_tool_and_timeline_signal(self):
        metadata = {
            "complete": False,
            "sources": {
                "bgp": {
                    "required": True,
                    "available": True,
                    "current": False,
                    "complete": False,
                }
            },
        }
        timeline = {
            "window": "1h",
            "to": NOW,
            "events": [],
            "correlations": [],
            "coverage": [
                {"source": "bgp", "status": "ok"},
                {"source": "optical", "status": "missing"},
            ],
            "truncated": False,
        }
        result = build_evidence(
            metadata,
            [{"device": "leaf01", "command": "show bgp", "ok": False}],
            timeline,
            now=NOW,
        )
        confidence = result["confidence"]
        self.assertEqual(confidence["level"], "low")
        self.assertIn("collection coverage", confidence["reason"])
        self.assertIn("live check", confidence["reason"])
        self.assertIn("Timeline coverage", confidence["reason"])

        complete_metadata = {
            "complete": True,
            "sources": {
                "bgp": {
                    "required": True,
                    "available": True,
                    "current": True,
                    "complete": True,
                }
            },
        }
        result = build_evidence(
            complete_metadata,
            [{"dispatch": "all", "command": "show bgp"}],
            timeline,
            now=NOW,
        )
        self.assertEqual(result["confidence"]["level"], "low")
        self.assertIn("no success/failure status", result["confidence"]["reason"])
        self.assertIn("Timeline coverage", result["confidence"]["reason"])

    def test_argument_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            build_timeline(monitor_dir=self.monitor, window="30d", now=NOW)
        with self.assertRaises(ValueError):
            build_timeline(monitor_dir=self.monitor, window="1h", now=NOW, max_events=501)
        with self.assertRaises(ValueError):
            timeline_prompt_context({}, max_chars=100)


if __name__ == "__main__":
    unittest.main()
