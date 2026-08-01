#!/usr/bin/env python3
"""Tests for the config-drift / routes / fabric-check analyzers and their
pipeline, trigger, menu, dashboard and nginx wiring."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lldpq"))

import export_artifacts
import process_config_drift_data as config_drift
import process_fabric_check_data as fabric_check
import process_routes_data as routes


def _load_lldp_validate():
    spec = importlib.util.spec_from_file_location(
        "lldp_validate_under_test", ROOT / "lldpq/lldp-validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExportSchemaTests(unittest.TestCase):
    def test_new_domains_registered(self):
        for domain in ("config-drift", "routes", "fabric-check"):
            self.assertIn(domain, export_artifacts.EXPORT_SCHEMAS)
        self.assertEqual(
            export_artifacts.EXPORT_SCHEMAS["fabric-check"][0], "check")
        self.assertIn("routes_delta", export_artifacts.EXPORT_SCHEMAS["routes"])
        self.assertIn(
            "lines_added", export_artifacts.EXPORT_SCHEMAS["config-drift"])


class ConfigDriftAnalyzerTests(unittest.TestCase):
    def _analyzer(self, tmp, now):
        analyzer = config_drift.ConfigDriftAnalyzer(
            os.path.join(tmp, "monitor-results"),
            configs_dir=os.path.join(tmp, "configs"), now=now)
        analyzer.managed_devices = ["Leaf1", "Leaf2"]
        return analyzer

    def _run(self, tmp, now):
        analyzer = self._analyzer(tmp, now)
        analyzer.analyze()
        analyzer.export_html(
            os.path.join(tmp, "monitor-results",
                         "config-drift-analysis.html"))
        analyzer.save_state()
        return analyzer

    def test_baseline_then_drift_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            configs = Path(tmp) / "configs"
            configs.mkdir()
            (configs / "Leaf1.txt").write_text(
                "nv set interface swp1 link mtu 9216\n")
            (configs / "Leaf2.txt").write_text(
                "nv set system hostname Leaf2\n")

            first = self._run(tmp, now=1_000_000_000)
            counts = first.summary_counts()
            self.assertEqual(counts["baselines_created"], 2)
            self.assertEqual(counts["new_events"], 0)
            self.assertEqual(first.collection_status(), "current")

            (configs / "Leaf1.txt").write_text(
                "nv set interface swp1 link mtu 9000\n")
            second = self._run(tmp, now=1_000_000_600)
            counts = second.summary_counts()
            self.assertEqual(counts["new_events"], 1)
            self.assertEqual(counts["changed_24h"], 1)

            history = json.loads(
                (Path(tmp) / "monitor-results" /
                 "config_drift_history.json").read_text())
            event = history["events"][0]
            self.assertEqual(event["host"], "Leaf1")
            self.assertEqual(event["type"], "modified")
            self.assertEqual((event["added"], event["removed"]), (1, 1))
            sidecar = json.loads(
                (Path(tmp) / "monitor-results" / "events" /
                 "config-drift.json").read_text())
            self.assertEqual(sidecar["events"][0]["kind"], "config-modified")

            page = (Path(tmp) / "monitor-results" /
                    "config-drift-analysis.html").read_text()
            self.assertIn('data-analysis-summary="config-drift"', page)
            self.assertIn("table-filter.js?v=", page)
            self.assertIn("analysis-guard.js?v=", page)
            export = json.loads(
                (Path(tmp) / "monitor-results" / "export" /
                 "config-drift.json").read_text())
            self.assertEqual(export["domain"], "config-drift")
            self.assertEqual(export["row_count"], 1)

    def test_missing_configs_dir_still_produces_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = self._run(tmp, now=1_000_000_000)
            self.assertEqual(analyzer.collection_status(), "unavailable")
            result_dir = Path(tmp) / "monitor-results"
            for relative in ("config-drift-analysis.html",
                             "config_drift_history.json",
                             "summary/config-drift-summary.json",
                             "export/config-drift.json",
                             "export/config-drift.csv"):
                self.assertTrue((result_dir / relative).is_file(), relative)
            self.assertTrue((result_dir / "config-drift-data").is_dir())

    def test_unreachable_device_creates_no_false_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            configs = Path(tmp) / "configs"
            configs.mkdir()
            (configs / "Leaf1.txt").write_text("nv set system hostname X\n")
            self._run(tmp, now=1_000_000_000)
            # Same content on the next run: no event.
            second = self._run(tmp, now=1_000_000_600)
            self.assertEqual(second.summary_counts()["new_events"], 0)


class RoutesAnalyzerTests(unittest.TestCase):
    def _snapshot(self, tmp, host, count, vrfs=("default",), status="current"):
        tables = Path(tmp) / "monitor-results" / "fabric-tables"
        tables.mkdir(parents=True, exist_ok=True)
        payload = {
            "arp": [{"ip": "10.0.0.1", "mac": "aa", "interface": "vlan1",
                     "vrf": vrfs[0], "state": "REACHABLE"}],
            "routes": {
                vrf: [
                    {"prefix": "10.%d.0.0/24" % i, "nexthop": "10.0.0.1",
                     "interface": "swp1", "protocol": "bgp", "metric": "20"}
                    for i in range(count)
                ] for vrf in vrfs
            },
            "_collection": {"status": status, "error": None},
        }
        (tables / ("%s.json" % host)).write_text(json.dumps(payload))

    def _run(self, tmp, now):
        analyzer = routes.RoutesAnalyzer(
            os.path.join(tmp, "monitor-results"), now=now)
        analyzer.managed_devices = ["Leaf1"]
        analyzer.analyze()
        analyzer.export_html(
            os.path.join(tmp, "monitor-results", "routes-analysis.html"))
        analyzer.save_state()
        return analyzer

    def test_drop_and_vrf_loss_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._snapshot(tmp, "Leaf1", 100, vrfs=("default", "tenant-a"))
            first = self._run(tmp, now=2_000_000_000)
            self.assertEqual(first.summary_counts()["route_drops_24h"], 0)
            self.assertEqual(first.summary_counts()["total_routes"], 200)

            self._snapshot(tmp, "Leaf1", 40, vrfs=("default",))
            second = self._run(tmp, now=2_000_000_600)
            counts = second.summary_counts()
            self.assertEqual(counts["route_drops_24h"], 1)
            self.assertEqual(counts["vrfs_disappeared_24h"], 1)

            shard = json.loads(
                (Path(tmp) / "monitor-results" / "routes-history" /
                 "Leaf1.json").read_text())
            self.assertEqual(len(shard["history"]), 2)
            sidecar = json.loads(
                (Path(tmp) / "monitor-results" / "events" /
                 "routes.json").read_text())
            self.assertEqual({event["kind"] for event in sidecar["events"]},
                             {"route-drop", "vrf-disappeared"})
            page = (Path(tmp) / "monitor-results" /
                    "routes-analysis.html").read_text()
            self.assertIn('data-analysis-summary="routes"', page)
            self.assertIn("VRF disappeared", page)
            # Row-expand detail panel: real device/VRF rows carry fetch
            # attributes and the client machinery is embedded.
            self.assertIn("data-device='Leaf1' data-vrf='default'", page)
            self.assertIn("toggleRouteDetails", page)
            self.assertIn("var RT_TABLES_DIR = 'fabric-tables';", page)
            self.assertIn("tr.detail-row td", page)
            # Sorting must drop open detail panels before re-appending rows.
            self.assertIn("removeDetailRows();\n  var rows", page)

    def test_missing_scan_still_produces_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = self._run(tmp, now=2_000_000_000)
            self.assertEqual(analyzer.collection_status(), "unavailable")
            result_dir = Path(tmp) / "monitor-results"
            self.assertTrue((result_dir / "routes-history").is_dir())
            for relative in ("routes-analysis.html", "routes_events.json",
                             "summary/routes-summary.json",
                             "export/routes.json", "export/routes.csv"):
                self.assertTrue((result_dir / relative).is_file(), relative)


class FabricCheckAnalyzerTests(unittest.TestCase):
    SIDECAR = {
        "version": 1, "created": "2026-07-31 09-12-33",
        "neighbors": {
            "Leaf1": {"swp49": {"device": "Spine1", "port": "swp1"},
                      "swp50": {"device": "Spine2", "port": "swp1"}},
            "Spine1": {"swp1": {"device": "Leaf1", "port": "swp49"}},
            "Spine2": {"swp1": {"device": "Leaf1", "port": "swp50"}},
        },
        "ports": {
            "Leaf1": {"swp49": {"oper": "UP", "speed": 400000, "mtu": 9216},
                      "swp50": {"oper": "UP", "speed": 400000, "mtu": 9216}},
            "Spine1": {"swp1": {"oper": "UP", "speed": 400000, "mtu": 1500}},
            "Spine2": {"swp1": {"oper": "UP", "speed": 100000, "mtu": 9216}},
        },
    }

    def _run(self, tmp, sidecar_payload, config_lines=""):
        sidecar_path = Path(tmp) / "lldp_neighbors.json"
        sidecar_path.write_text(json.dumps(sidecar_payload))
        configs = Path(tmp) / "configs"
        configs.mkdir(exist_ok=True)
        if config_lines:
            (configs / "Leaf1.txt").write_text(config_lines)
        analyzer = fabric_check.FabricCheckAnalyzer(
            os.path.join(tmp, "monitor-results"),
            sidecar_path=str(sidecar_path), configs_dir=str(configs),
            now=3_000_000_000)
        analyzer.managed_devices = ["Leaf1", "Spine1", "Spine2"]
        analyzer.analyze()
        analyzer.export_html(
            os.path.join(tmp, "monitor-results",
                         "fabric-check-analysis.html"))
        return analyzer

    def test_detects_all_three_check_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = self._run(
                tmp, self.SIDECAR,
                config_lines="nv set interface swp49-50 link mtu 9000\n")
            counts = analyzer.summary_counts()
            self.assertEqual(counts["mtu_mismatches"], 1)
            self.assertEqual(counts["speed_mismatches"], 1)
            self.assertEqual(counts["config_mtu_mismatches"], 2)
            self.assertEqual(counts["links_checked"], 2)
            self.assertEqual(analyzer.collection_status(), "current")
            checks = [finding["check"] for finding in analyzer.findings]
            self.assertEqual(checks.count("mtu-mismatch"), 1)
            page = (Path(tmp) / "monitor-results" /
                    "fabric-check-analysis.html").read_text()
            self.assertIn('data-analysis-summary="fabric-check"', page)

    def test_legacy_sidecar_reports_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy = {"version": 1, "created": "x",
                      "neighbors": self.SIDECAR["neighbors"]}
            analyzer = self._run(tmp, legacy)
            self.assertEqual(analyzer.sidecar_state, "legacy")
            self.assertEqual(analyzer.collection_status(), "unavailable")
            page = (Path(tmp) / "monitor-results" /
                    "fabric-check-analysis.html").read_text()
            self.assertIn("predates port-attribute", page)

    def test_interface_range_expansion(self):
        self.assertEqual(fabric_check.expand_interface_spec("swp1-3"),
                         ["swp1", "swp2", "swp3"])
        self.assertEqual(fabric_check.expand_interface_spec("swp1s0-1,swp5"),
                         ["swp1s0", "swp1s1", "swp5"])
        self.assertEqual(fabric_check.expand_interface_spec("swp10"),
                         ["swp10"])
        self.assertEqual(
            fabric_check.parse_configured_mtus(
                "nv set interface swp1,swp3 link mtu 9216\n"
                "nv set system hostname X\n"),
            {"swp1": 9216, "swp3": 9216})


class LldpSidecarEnrichmentTests(unittest.TestCase):
    RAW = """=========================================Leaf1=========================================

Interface:    swp1, via: LLDP
  Chassis:
    SysName:      Spine1
  Port:
    PortID:       ifname swp5

===PORT_STATUS_START===
swp1 UP
swp2 DOWN
===PORT_STATUS_END===

===PORT_SPEED_START===
swp1 400000
===PORT_SPEED_END===

===PORT_MTU_START===
swp1 9216
swp2 9216
===PORT_MTU_END===
"""

    def test_parse_and_sidecar_ports_map(self):
        module = _load_lldp_validate()
        with tempfile.TemporaryDirectory() as tmp:
            raw_path = Path(tmp) / "Leaf1_lldp_result.ini"
            raw_path.write_text(self.RAW)
            neighbors, port_status, port_attrs = module.parse_lldp_output(
                str(raw_path), ("Leaf1", "Spine1"))
            self.assertEqual(port_status,
                             {"swp1": "UP", "swp2": "DOWN"})
            self.assertEqual(port_attrs["swp1"],
                             {"speed": 400000, "mtu": 9216})
            self.assertEqual(port_attrs["swp2"], {"mtu": 9216})

            resolver = module.DeviceNameResolver(("Leaf1", "Spine1"))
            destination = Path(tmp) / "lldp_neighbors.json"
            module.write_neighbors_sidecar(
                str(destination), {"Leaf1": neighbors}, resolver,
                "2026-07-31 00-00-00",
                {"Leaf1": port_status}, {"Leaf1": port_attrs})
            payload = json.loads(destination.read_text())
            self.assertEqual(payload["version"], 1)
            self.assertEqual(payload["neighbors"]["Leaf1"]["swp1"],
                             {"device": "Spine1", "port": "swp5"})
            self.assertEqual(payload["ports"]["Leaf1"]["swp1"],
                             {"oper": "UP", "speed": 400000, "mtu": 9216})
            self.assertEqual(payload["ports"]["Leaf1"]["swp2"],
                             {"oper": "DOWN", "mtu": 9216})

    def test_check_lldp_emits_port_mtu_section(self):
        source = (ROOT / "lldpq/check-lldp.sh").read_text(encoding="utf-8")
        self.assertIn("===PORT_MTU_START===", source)
        self.assertIn("===PORT_MTU_END===", source)
        self.assertIn('mtu=\\$(cat \\"\\$port/mtu\\"', source)


class WiringContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")
        cls.trigger = (ROOT / "html/trigger-monitor.sh").read_text(
            encoding="utf-8")
        cls.daemon = (ROOT / "bin/lldpq-trigger").read_text(encoding="utf-8")
        cls.index = (ROOT / "html/index.html").read_text(encoding="utf-8")
        cls.guard = (ROOT / "html/css/analysis-guard.js").read_text(
            encoding="utf-8")
        cls.start = (ROOT / "html/start.html").read_text(encoding="utf-8")
        cls.nginx = (ROOT / "etc/nginx/sites-available/lldpq").read_text(
            encoding="utf-8")

    def test_monitor_scope_and_invocations(self):
        self.assertIn(
            "all|bgp|evpn-mh|duplicate|flap|optical|ber|pfc-ecn|hardware|logs"
            "|config-drift|routes|fabric-check)", self.monitor)
        for scope, key, script in (
                ("config-drift", "SKIP_CONFIG_DRIFT",
                 "process_config_drift_data.py"),
                ("routes", "SKIP_ROUTES", "process_routes_data.py"),
                ("fabric-check", "SKIP_FABRIC_CHECK",
                 "process_fabric_check_data.py")):
            self.assertIn(
                'if scope_selected %s && [[ "$%s" != "true" ]]; then\n'
                "    start_analysis %s python3 %s"
                % (scope, key, scope, script), self.monitor)

    def test_monitor_validate_and_overlays(self):
        for token in ("config-drift-analysis.html", "routes-analysis.html",
                      "fabric-check-analysis.html", "routes-history/",
                      "config-drift-data/", "routes_events.json",
                      "config_drift_history.json"):
            self.assertIn(token, self.monitor)
        # Scoped web overlays exist for each new scope.
        for scope in ("config-drift)", "routes)", "fabric-check)"):
            self.assertIn(scope, self.monitor)

    def test_scope_round_trip_codes(self):
        self.assertIn("config-drift) SCOPE_CODE=10", self.trigger)
        self.assertIn("routes) SCOPE_CODE=11", self.trigger)
        self.assertIn("fabric-check) SCOPE_CODE=12", self.trigger)
        self.assertIn("10) MONITOR_REQUEST_SCOPE=config-drift", self.daemon)
        self.assertIn("11) MONITOR_REQUEST_SCOPE=routes", self.daemon)
        self.assertIn("12) MONITOR_REQUEST_SCOPE=fabric-check", self.daemon)
        self.assertIn("config-drift|routes|fabric-check) return 0", self.daemon)

    def test_menu_order(self):
        # Config-Drift lives in DEVICES right under Configs; Fabric-Check
        # lives in WIRING right under Problems; Routes heads ANALYSIS.
        configs = self.index.index('href="dev-conf.html"')
        config_drift = self.index.index(
            "/monitor-results/config-drift-analysis.html")
        console = self.index.index('href="console.html"')
        problems = self.index.index('href="lldp-problem.html"')
        fabric = self.index.index(
            "/monitor-results/fabric-check-analysis.html")
        archive = self.index.index('href="archive.html"')
        routes_item = self.index.index("/monitor-results/routes-analysis.html")
        bgp = self.index.index("/monitor-results/bgp-analysis.html")
        self.assertLess(configs, config_drift)
        self.assertLess(config_drift, console)
        self.assertLess(problems, fabric)
        self.assertLess(fabric, archive)
        self.assertLess(routes_item, bgp)

    def test_analysis_guard_registration(self):
        self.assertIn("'config-drift': true", self.guard)
        self.assertIn("routes: true", self.guard)
        self.assertIn("'fabric-check': true", self.guard)
        self.assertIn(
            "'config-drift-analysis.html': { scope: 'config-drift'",
            self.guard)
        self.assertIn("'routes-analysis.html': { scope: 'routes'", self.guard)
        self.assertIn(
            "'fabric-check-analysis.html': { scope: 'fabric-check'",
            self.guard)

    def test_start_dashboard_wiring(self):
        for token in (
                "'config-drift': 'config-drift'",
                "'routes': 'routes'",
                "'fabric-check': 'fabric-check'",
                "fetchRawDataSummary('config-drift', pipelineState)",
                "fetchRawDataSummary('routes', pipelineState)",
                "fetchRawDataSummary('fabric-check', pipelineState)",
                'id="cd-changed-24h"', 'id="routes-anomalies"',
                'id="fc-mtu-mismatch"'):
            self.assertIn(token, self.start)
        # The new analyzers must NOT gate manifest validity: pre-upgrade
        # manifests stay accepted.
        self.assertNotIn("'config-drift'\n        ];", self.start)

    def test_nginx_export_domains(self):
        self.assertEqual(self.nginx.count(
            "bgp|evpn-mh|duplicate|flap|optical|ber|pfc-ecn|hardware|log"
            "|config-drift|routes|fabric-check"), 2)


if __name__ == "__main__":
    unittest.main()
