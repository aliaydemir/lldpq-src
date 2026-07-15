#!/usr/bin/env python3
"""Tests for the deterministic cross-domain correlation engine."""

from __future__ import annotations

import json
import os
import random
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_correlate  # noqa: E402


NOW = time.time()


def write_json(directory, name, payload):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.mr_dir = os.path.join(self.root, "monitor-results")
        os.makedirs(self.mr_dir)

    def populate_default(self):
        """Realistic multi-domain fixture matching the producers' schemas."""
        write_json(self.mr_dir, "bgp_history.json", {
            "current_bgp_stats": {
                "Leaf1": {
                    "neighbors": [
                        {"neighbor_name": "Spine1(swp49)", "neighbor_ip": "Spine1",
                         "interface": "swp49", "state": "idle"},
                        {"neighbor_name": "Spine2(swp50)", "neighbor_ip": "Spine2",
                         "interface": "swp50", "state": "established"},
                    ],
                    "total_neighbors": 2, "down_neighbors": 1,
                },
            },
            "collection_coverage": {
                "expected_devices": 4, "current_bgp_devices": 4,
                "unavailable_bgp_devices": [],
            },
        })
        write_json(self.mr_dir, "optical_history.json", {
            "current_optical_stats": {
                "Leaf1:swp49": {"health_status": "critical",
                                "rx_power_dbm": -15.2, "tx_power_dbm": -1.1,
                                "link_margin_db": 0.4},
                "Spine1:swp1": {"health_status": "warning",
                                "rx_power_dbm": -11.0, "tx_power_dbm": -1.0,
                                "link_margin_db": 2.5},
                "Leaf2:swp10": {"health_status": "good",
                                "rx_power_dbm": -3.0},
            },
        })
        write_json(self.mr_dir, "ber_history.json", {
            "current_ber_stats": {
                "Spine1:swp1": {"status": "warning", "effective_ber": 2.5e-9,
                                "frame_grade": "warning"},
            },
        })
        write_json(self.mr_dir, "flap_history.json", {
            "flapping_hist": {
                "Leaf1:swp49": [[NOW - 120, 24, 3, NOW - 420, 300]],
            },
            "last_update": NOW,
        })
        write_json(self.mr_dir, "pfc_ecn_history.json", {
            "version": 1,
            "history": {
                "Leaf2:swp5": [
                    {"sample_status": "analyzed", "signal": "loss",
                     "loss_delta": 12, "timestamp": NOW - 60},
                ],
            },
        })
        write_json(self.mr_dir, "hardware_history.json", {
            "hardware_history": {
                "Leaf2": [{"overall_grade": "GOOD"}, {"overall_grade": "CRITICAL"}],
            },
        })
        write_json(self.mr_dir, "log_summary.json", {
            "totals": {"critical": 2, "error": 1, "warning": 5},
            "device_counts": {
                "Leaf2": {"critical": 2, "error": 0, "warning": 1},
                "Spine2": {"critical": 0, "error": 1, "warning": 2},
            },
        })
        with open(os.path.join(self.root, "topology.dot"), "w", encoding="utf-8") as handle:
            handle.write(
                '/* expected wiring */\n'
                'graph "TEST" {\n'
                '  "Leaf1":"swp49" -- "Spine1":"swp1"  // uplink\n'
                '  "Leaf1":"swp50" -- "Spine2":"swp1"\n'
                '  "Leaf2":"swp5" -- "Spine1":"swp2"\n'
                '}\n'
            )


class CollectAnomaliesTest(FixtureCase):
    def test_reads_producer_grades_across_domains(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        domains = {(item["domain"], item["device"], item["port"]) for item in anomalies}
        self.assertIn(("bgp", "Leaf1", "swp49"), domains)
        self.assertIn(("optical", "Leaf1", "swp49"), domains)
        self.assertIn(("optical", "Spine1", "swp1"), domains)
        self.assertIn(("ber", "Spine1", "swp1"), domains)
        self.assertIn(("flap", "Leaf1", "swp49"), domains)
        self.assertIn(("pfc_ecn", "Leaf2", "swp5"), domains)
        self.assertIn(("hardware", "Leaf2", None), domains)
        self.assertIn(("log", "Leaf2", None), domains)
        self.assertIn(("log", "Spine2", None), domains)
        # Healthy states are never anomalies.
        self.assertNotIn(("optical", "Leaf2", "swp10"), domains)
        for item in anomalies:
            for field in ("domain", "device", "metric", "value", "status",
                          "detail", "source"):
                self.assertIn(field, item)

    def test_missing_files_are_tolerated_silently(self):
        self.assertEqual(ai_correlate.collect_anomalies(self.mr_dir), [])
        missing = os.path.join(self.root, "does-not-exist")
        self.assertEqual(ai_correlate.collect_anomalies(missing), [])

    def test_pfc_ecn_shard_directory_takes_precedence_over_monolith(self):
        # A leftover monolith must be ignored once the shard store exists.
        write_json(self.mr_dir, "pfc_ecn_history.json", {
            "version": 1,
            "history": {
                "Stale1:swp9": [
                    {"sample_status": "analyzed", "signal": "loss",
                     "loss_delta": 5, "timestamp": NOW - 60},
                ],
            },
        })
        shard_dir = os.path.join(self.mr_dir, "pfc-ecn-history")
        os.makedirs(shard_dir)
        write_json(shard_dir, "Leaf2.json", {
            "version": 1,
            "host": "Leaf2",
            "history": {
                "Leaf2:swp5": [
                    {"sample_status": "analyzed", "signal": "loss",
                     "loss_delta": 12, "timestamp": NOW - 60},
                ],
            },
        })
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        domains = {(item["domain"], item["device"], item["port"]) for item in anomalies}
        self.assertIn(("pfc_ecn", "Leaf2", "swp5"), domains)
        self.assertNotIn(("pfc_ecn", "Stale1", "swp9"), domains)

    def test_partial_and_malformed_files_do_not_hide_other_domains(self):
        self.populate_default()
        with open(os.path.join(self.mr_dir, "optical_history.json"), "w",
                  encoding="utf-8") as handle:
            handle.write("{not-json")
        write_json(self.mr_dir, "ber_history.json", {"current_ber_stats": "bogus"})
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        domains = {item["domain"] for item in anomalies}
        self.assertNotIn("optical", domains)
        self.assertNotIn("ber", domains)
        self.assertIn("bgp", domains)
        self.assertIn("hardware", domains)


class ExpectedLinksTest(FixtureCase):
    def test_loads_links_next_to_monitor_results(self):
        self.populate_default()
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        self.assertIn(
            {"a_dev": "Leaf1", "a_port": "swp49", "b_dev": "Spine1", "b_port": "swp1"},
            links,
        )
        self.assertEqual(len(links), 3)

    def test_commented_examples_are_not_edges(self):
        self.populate_default()
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        self.assertNotIn(
            {"a_dev": "Hostname1", "a_port": "Interface1",
             "b_dev": "Hostname2", "b_port": "Interface2"},
            links,
        )

    def test_absent_topology_returns_empty(self):
        self.assertEqual(ai_correlate.load_expected_links(mr_dir=self.mr_dir), [])
        self.assertEqual(
            ai_correlate.load_expected_links(topology_path="/nonexistent/topology.dot"),
            [],
        )


class CorrelateTest(FixtureCase):
    def universe(self):
        return ["Leaf1", "Leaf2", "Spine1", "Spine2", "Core1", "Core2"]

    def test_multi_domain_same_port_joins_into_one_incident(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        incidents = ai_correlate.correlate(anomalies, [], devices=self.universe())
        leaf1_port = [
            incident for incident in incidents
            if incident["ports"] == ["Leaf1:swp49"]
        ]
        self.assertEqual(len(leaf1_port), 1)
        evidence_domains = {item["domain"] for item in leaf1_port[0]["evidence"]}
        self.assertEqual(evidence_domains, {"bgp", "optical", "flap"})
        self.assertEqual(leaf1_port[0]["severity"], "CRITICAL")

    def test_two_end_link_join_produces_link_degradation(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        incidents = ai_correlate.correlate(anomalies, links, devices=self.universe())
        link_incidents = [
            incident for incident in incidents
            if incident["kind"] == "link-degradation"
        ]
        self.assertEqual(len(link_incidents), 1)
        incident = link_incidents[0]
        self.assertEqual(incident["link"], {"a": "Leaf1:swp49", "b": "Spine1:swp1"})
        self.assertEqual(incident["devices"], ["Leaf1", "Spine1"])
        self.assertEqual(
            {item["domain"] for item in incident["evidence"]},
            {"bgp", "optical", "flap", "ber"},
        )
        # Both endpoint groups were consumed by the link incident.
        for other in incidents:
            if other is incident:
                continue
            self.assertNotIn("Leaf1:swp49", other["ports"])
            self.assertNotIn("Spine1:swp1", other["ports"])

    def test_fabric_wide_grouping_collapses_shared_type(self):
        anomalies = []
        for device in ("Leaf1", "Leaf2", "Spine1"):
            anomalies.append({
                "domain": "optical", "device": device, "port": "swp1",
                "metric": "health_status", "value": "warning",
                "status": "warning", "detail": "Optical health warning",
                "source": "optical_history.json",
            })
        incidents = ai_correlate.correlate(
            anomalies, [], devices=["Leaf1", "Leaf2", "Spine1", "Spine2"]
        )
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["kind"], "fabric-wide")
        self.assertEqual(len(incidents[0]["evidence"]), 3)
        self.assertEqual(
            incidents[0]["devices"], ["Leaf1", "Leaf2", "Spine1"]
        )

    def test_fabric_wide_needs_share_and_minimum_devices(self):
        # Two of six devices (33%) must not be fabric-wide.
        anomalies = [
            {"domain": "optical", "device": device, "port": "swp1",
             "metric": "health_status", "value": "warning", "status": "warning",
             "detail": "", "source": "optical_history.json"}
            for device in ("Leaf1", "Leaf2")
        ]
        incidents = ai_correlate.correlate(anomalies, [], devices=self.universe())
        self.assertTrue(all(item["kind"] != "fabric-wide" for item in incidents))
        self.assertEqual(len(incidents), 2)

    def test_severity_mapping_uses_analyzer_vocabulary(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        incidents = ai_correlate.correlate(anomalies, [], devices=self.universe())
        by_key = {incident["summary_key"]: incident for incident in incidents}
        # hardware CRITICAL + 2 critical logs on the same device stay separate
        # single-evidence incidents, each mapped to CRITICAL.
        self.assertEqual(by_key["device-local|Leaf2"]["severity"], "CRITICAL")
        # optical warning + ber warning joined on Spine1:swp1 -> WARNING.
        self.assertEqual(by_key["device-local|Spine1:swp1"]["severity"], "WARNING")
        # pfc loss signal -> WARNING per the producers' signal vocabulary.
        self.assertEqual(by_key["device-local|Leaf2:swp5"]["severity"], "WARNING")
        # log errors (no criticals) -> WARNING.
        self.assertEqual(by_key["device-local|Spine2"]["severity"], "WARNING")
        # BGP session not established -> CRITICAL.
        self.assertEqual(by_key["device-local|Leaf1:swp49"]["severity"], "CRITICAL")

    def test_incident_contract_and_ordering(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        incidents = ai_correlate.correlate(anomalies, links, devices=self.universe())
        self.assertTrue(incidents)
        ranks = [ai_correlate.SEVERITY_ORDER[item["severity"]] for item in incidents]
        self.assertEqual(ranks, sorted(ranks))
        for incident in incidents:
            for field in ("id", "kind", "severity", "devices", "ports", "link",
                          "evidence", "summary", "summary_key"):
                self.assertIn(field, incident)
            self.assertIn(incident["kind"], {
                "link-degradation", "device-local", "protocol",
                "fabric-wide", "other",
            })
            self.assertIn(incident["severity"], {"CRITICAL", "WARNING", "INFO"})
            self.assertTrue(incident["evidence"])
            self.assertEqual(len(incident["summary"].splitlines()), 1)

    def test_summary_key_stable_across_runs_and_input_order(self):
        self.populate_default()
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        first = ai_correlate.correlate(anomalies, links, devices=self.universe())
        shuffled = list(ai_correlate.collect_anomalies(self.mr_dir))
        random.Random(7).shuffle(shuffled)
        second = ai_correlate.correlate(shuffled, links, devices=self.universe())
        self.assertEqual(
            [(item["id"], item["summary_key"]) for item in first],
            [(item["id"], item["summary_key"]) for item in second],
        )


class RenderCandidatesTest(FixtureCase):
    def build_incidents(self):
        self.populate_default()
        anomalies = ai_correlate.collect_anomalies(self.mr_dir)
        links = ai_correlate.load_expected_links(mr_dir=self.mr_dir)
        return ai_correlate.correlate(anomalies, links)

    def test_render_contains_severity_first_evidence_lines(self):
        incidents = self.build_incidents()
        text = ai_correlate.render_candidates(incidents)
        self.assertTrue(text.startswith("INCIDENT CANDIDATES"))
        self.assertIn("[CRITICAL]", text)
        self.assertIn("optical Leaf1:swp49 health_status=critical (critical)", text)
        first_critical = text.index("[CRITICAL]")
        first_warning = text.index("[WARNING]")
        self.assertLess(first_critical, first_warning)
        self.assertNotIn("omitted", text)

    def test_render_truncates_whole_incidents_with_marker(self):
        incidents = self.build_incidents()
        full = ai_correlate.render_candidates(incidents)
        limit = len(full) - 10
        text = ai_correlate.render_candidates(incidents, max_chars=limit)
        self.assertLessEqual(len(text), limit)
        marker = re.search(r"\(\+(\d+) more incidents omitted\)", text)
        self.assertIsNotNone(marker)
        rendered = len(re.findall(r"(?m)^\[(?:CRITICAL|WARNING|INFO)\]", text))
        self.assertEqual(rendered + int(marker.group(1)), len(incidents))
        # No evidence line may appear after its incident was cut: every
        # rendered incident keeps all of its evidence lines.
        blocks = re.split(r"(?m)^(?=\[)", text)
        for block in blocks[1:]:
            header = block.splitlines()[0]
            self.assertRegex(header, r"^\[(?:CRITICAL|WARNING|INFO)\]")

    def test_render_empty_and_no_marker_when_everything_fits(self):
        self.assertEqual(ai_correlate.render_candidates([]), "")
        incidents = self.build_incidents()
        text = ai_correlate.render_candidates(incidents, max_chars=100000)
        self.assertNotIn("omitted", text)


class CliTest(FixtureCase):
    def test_cli_prints_incident_json(self):
        self.populate_default()
        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = ai_correlate.main(["ai_correlate.py", self.mr_dir])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertIsInstance(payload, list)
        self.assertTrue(any(item["kind"] == "link-degradation" for item in payload))

    def test_cli_usage_error(self):
        import io
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            self.assertEqual(ai_correlate.main(["ai_correlate.py"]), 2)


if __name__ == "__main__":
    unittest.main()
