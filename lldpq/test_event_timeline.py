#!/usr/bin/env python3
"""Tests for the Timeline event sidecars (analysis_events) and their
analyzer emitters, plus the timeline.html page wiring."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lldpq"))

import analysis_events


def _event(ts, device="Leaf1", kind="link-flap", severity="warning",
           obj="swp1", detail="d"):
    return {"ts": ts, "severity": severity, "device": device,
            "object": obj, "kind": kind, "detail": detail}


class PublishEventsTests(unittest.TestCase):
    NOW = 1_800_000_000

    def _read(self, tmp, domain="flap"):
        path = Path(tmp) / "events" / ("%s.json" % domain)
        return json.loads(path.read_text())

    def test_merge_dedup_and_sort(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(analysis_events.publish_events(
                tmp, "flap", [_event(self.NOW - 100), _event(self.NOW - 50)],
                now=self.NOW))
            # Re-submitting the same events (overlapping log windows) must
            # not duplicate them; a new event merges in sorted order.
            self.assertTrue(analysis_events.publish_events(
                tmp, "flap",
                [_event(self.NOW - 100), _event(self.NOW - 75)],
                now=self.NOW))
            payload = self._read(tmp)
            self.assertEqual(payload["domain"], "flap")
            self.assertEqual([e["ts"] for e in payload["events"]],
                             [self.NOW - 100, self.NOW - 75, self.NOW - 50])

    def test_cap_retention_and_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = [_event(self.NOW - i, detail="e%d" % i)
                      for i in range(10)]
            events.append(_event(self.NOW - analysis_events.RETENTION_SEC
                                 - 10, detail="ancient"))
            events.append(_event(self.NOW + 200000, detail="future"))
            events.append({"ts": "bogus"})
            events.append(_event(self.NOW, device="", detail="no-device"))
            self.assertTrue(analysis_events.publish_events(
                tmp, "flap", events, cap=5, now=self.NOW))
            payload = self._read(tmp)
            self.assertEqual(len(payload["events"]), 5)
            details = {e["detail"] for e in payload["events"]}
            self.assertNotIn("ancient", details)
            self.assertNotIn("future", details)
            severities = {e["severity"] for e in payload["events"]}
            self.assertLessEqual(severities,
                                 {"critical", "warning", "info"})

    def test_never_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("not a directory")
            # events/ cannot be created under a regular file.
            self.assertFalse(analysis_events.publish_events(
                str(blocker), "flap", [_event(self.NOW)], now=self.NOW))


class EmitterWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.flap_analyzer = (ROOT / "lldpq/link_flap_analyzer.py").read_text(
            encoding="utf-8")
        cls.flap_process = (ROOT / "lldpq/process_flap_data.py").read_text(
            encoding="utf-8")
        cls.bgp = (ROOT / "lldpq/bgp_analyzer.py").read_text(encoding="utf-8")
        cls.log = (ROOT / "lldpq/process_log_data.py").read_text(
            encoding="utf-8")
        cls.routes = (ROOT / "lldpq/process_routes_data.py").read_text(
            encoding="utf-8")
        cls.drift = (ROOT / "lldpq/process_config_drift_data.py").read_text(
            encoding="utf-8")

    def test_flap_emitter(self):
        self.assertIn("self.cycle_events = []", self.flap_analyzer)
        self.assertIn('"kind": "link-flap"', self.flap_analyzer)
        self.assertIn(
            'analysis_events.publish_events(\n        result_dir, "flap",'
            " flap_analyzer.cycle_events)", self.flap_process)

    def test_bgp_emitter(self):
        self.assertIn("self.cycle_events = []", self.bgp)
        self.assertIn('"kind": "bgp-neighbors-down"', self.bgp)
        self.assertIn('"kind": "bgp-neighbors-recovered"', self.bgp)
        self.assertIn('analysis_events.publish_events(\n            '
                      'self.data_dir, "bgp", self.cycle_events)', self.bgp)

    def test_log_emitter_only_iso_stamped(self):
        self.assertIn("parse_timestamp_to_datetime", self.log)
        self.assertIn('analysis_events.publish_events(self.data_dir, "log"',
                      self.log)

    def test_routes_and_drift_emitters_pass_analyzer_now(self):
        self.assertIn('analysis_events.publish_events(self.result_dir, '
                      '"routes"', self.routes)
        self.assertIn("], now=self.now)", self.routes)
        self.assertIn('analysis_events.publish_events(self.result_dir, '
                      '"config-drift"', self.drift)
        self.assertIn("], now=self.now)", self.drift)


class TimelinePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = (ROOT / "html/timeline.html").read_text(encoding="utf-8")
        cls.index = (ROOT / "html/index.html").read_text(encoding="utf-8")

    def test_menu_item_under_dashboard(self):
        fabric = self.index.index('href="start.html"')
        timeline = self.index.index('href="timeline.html"')
        search = self.index.index('href="search.html"')
        self.assertLess(fabric, timeline)
        self.assertLess(timeline, search)

    def test_fetches_every_event_domain(self):
        for domain in ("routes", "config-drift", "flap", "bgp", "log"):
            self.assertIn("domain: '%s'" % domain, self.page)
        self.assertIn("/monitor-results/events/", self.page)
        self.assertIn('id="tlt"', self.page)
        self.assertIn("data-filterable", self.page)
        self.assertIn("table-filter.js?v=", self.page)
        self.assertIn('id="activitySvg"', self.page)

    def test_sparkline_helpers_embedded(self):
        routes_src = (ROOT / "lldpq/process_routes_data.py").read_text(
            encoding="utf-8")
        pfc_src = (ROOT / "lldpq/process_pfc_ecn_data.py").read_text(
            encoding="utf-8")
        self.assertIn("function rtSpark(values, width, height)", routes_src)
        self.assertIn("rtHistoryShard(device)", routes_src)
        self.assertIn("function pfcSpark(values, width, height) {{", pfc_src)
        self.assertIn("pfcSpark(ecnSeries)", pfc_src)


if __name__ == "__main__":
    unittest.main()
