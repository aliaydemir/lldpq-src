#!/usr/bin/env python3
"""Per-domain dashboard summary JSON files must mirror the HTML reports.

Each analyzer additionally publishes monitor-results/summary/<domain>-summary.json
so the dashboard can read headline numbers without downloading and DOM-parsing
the full analysis pages.  These tests assert the JSON is written and carries
the exact same headline numbers/collection status the HTML report embeds.
"""

import json
import os
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import duplicate_analyzer
import process_ber_data
import process_bgp_data
import process_evpn_mh_data
import process_flap_data
import process_hardware_data
import process_optical_data
import process_pfc_ecn_data


class _AttrParser(HTMLParser):
    """Collect the first tag carrying a marker attribute (machine summary)."""

    def __init__(self, marker, value=None):
        super().__init__()
        self.marker = marker
        self.value = value
        self.attrs = None

    def handle_starttag(self, _tag, attrs):
        if self.attrs is not None:
            return
        values = dict(attrs)
        if self.marker in values and (
            self.value is None or values[self.marker] == self.value
        ):
            self.attrs = values


def report_attrs(report, marker, value=None):
    parser = _AttrParser(marker, value)
    parser.feed(report)
    parser.close()
    if parser.attrs is None:
        raise AssertionError(f"report has no element with {marker}={value}")
    return parser.attrs


def metric_by_id(report, element_id):
    match = re.search(
        r'id="%s"[^>]*>([^<]*)<' % re.escape(element_id), report
    )
    if not match:
        raise AssertionError(f"report has no metric element #{element_id}")
    return match.group(1).strip()


def load_summary(result_dir, domain):
    path = Path(result_dir) / "summary" / f"{domain}-summary.json"
    if not path.is_file():
        raise AssertionError(f"summary JSON was not written: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload["domain"] != domain:
        raise AssertionError(f"summary JSON has wrong domain: {payload}")
    if not isinstance(payload["generated_at"], int):
        raise AssertionError("summary JSON generated_at must be an epoch int")
    return payload


class SummaryJsonTests(unittest.TestCase):
    def _result_tree(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        result_dir.mkdir()
        return result_dir

    @staticmethod
    def _snapshot(statuses):
        return statuses, 1.0, True

    def test_bgp_and_evpn_summary_json_match_report(self):
        result_dir = self._result_tree()
        bgp_dir = result_dir / "bgp-data"
        evpn_dir = result_dir / "evpn-data"
        bgp_dir.mkdir()
        evpn_dir.mkdir()
        (bgp_dir / "leaf1_bgp.txt").write_text("No BGP neighbors configured\n")
        (evpn_dir / "leaf1_evpn.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_bgp_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_bgp_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_bgp_data, "is_current_collection", return_value=True),
        ):
            analyzer = process_bgp_data.process_bgp_data_files(str(bgp_dir))

        self.assertIsNotNone(analyzer)
        report = (result_dir / "bgp-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "bgp")

        summary = load_summary(result_dir, "bgp")
        self.assertEqual(
            summary["collection_status"], meta["data-collection-status"]
        )
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(
            summary["coverage_expected"], int(meta["data-expected-devices"])
        )
        self.assertEqual(
            summary["coverage_current"], int(meta["data-current-bgp-devices"])
        )
        self.assertEqual(
            summary["warning_neighbors"], int(meta["data-warning-neighbors"])
        )
        self.assertEqual(
            summary["critical_neighbors"], int(meta["data-critical-neighbors"])
        )
        self.assertEqual(
            summary["total_devices"], int(metric_by_id(report, "total-devices"))
        )
        self.assertEqual(
            summary["total_neighbors"],
            int(metric_by_id(report, "total-neighbors")),
        )
        self.assertEqual(
            summary["established_neighbors"],
            int(metric_by_id(report, "established-neighbors")),
        )
        self.assertEqual(
            summary["problem_neighbors"],
            int(metric_by_id(report, "down-neighbors")),
        )
        self.assertEqual(
            summary["stale_devices"], int(metric_by_id(report, "stale-devices"))
        )
        self.assertEqual(
            summary["unknown_devices"],
            int(metric_by_id(report, "unknown-devices")),
        )
        self.assertEqual(metric_by_id(report, "health-ratio"), "N/A")
        self.assertIsNone(summary["health_percent"])

        evpn = load_summary(result_dir, "evpn")
        self.assertEqual(evpn["collection_status"], meta["data-collection-status"])
        self.assertEqual(
            evpn["coverage_current"], int(meta["data-current-evpn-devices"])
        )
        self.assertEqual(
            evpn["route_coverage"], meta["data-evpn-route-coverage"]
        )
        for field, element_id in (
            ("total_vnis", "evpn-total-vnis"),
            ("l2_vnis", "evpn-l2-vnis"),
            ("l3_vnis", "evpn-l3-vnis"),
            ("type2_routes", "evpn-type2-routes"),
            ("type5_routes", "evpn-type5-routes"),
        ):
            self.assertEqual(evpn[field], int(metric_by_id(report, element_id)))

    def test_evpn_mh_summary_json_matches_report(self):
        result_dir = self._result_tree()
        data_dir = result_dir / "evpn-mh-data"
        data_dir.mkdir()
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_evpn_mh_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_evpn_mh_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_evpn_mh_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_evpn_mh_data, "is_current_collection", return_value=True),
        ):
            success = process_evpn_mh_data.process_evpn_mh_data_files(str(data_dir))

        self.assertTrue(success)
        report = (result_dir / "evpn-mh-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "evpn-mh")

        summary = load_summary(result_dir, "evpn-mh")
        self.assertEqual(summary["collection_status"], meta["data-coverage-status"])
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(
            summary["coverage_partial"],
            meta["data-coverage-partial"] == "true",
        )
        for field, attribute in (
            ("total_es", "data-total-es"),
            ("healthy_es", "data-healthy-es"),
            ("inactive_es", "data-inactive-es"),
            ("bypass_es", "data-bypass-es"),
            ("bypass_issue_es", "data-bypass-issue-es"),
            ("critical_es", "data-critical-es"),
            ("warning_es", "data-warning-es"),
            ("inconsistent_es", "data-inconsistent-es"),
            ("orphan_es", "data-orphan-es"),
        ):
            self.assertEqual(summary[field], int(meta[attribute]))

    def test_optical_summary_json_matches_report(self):
        result_dir = self._result_tree()
        data_dir = result_dir / "optical-data"
        data_dir.mkdir()
        (data_dir / "leaf1_optical.txt").write_text(
            "=== OPTICAL DIAGNOSTICS ===\n"
        )
        snapshot = self._snapshot({"leaf1": "OK", "leaf2": "OK"})

        with (
            mock.patch.object(process_optical_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_optical_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_optical_data, "is_current_collection", return_value=True),
        ):
            success = process_optical_data.process_optical_data_files(str(data_dir))

        self.assertTrue(success)
        report = (result_dir / "optical-analysis.html").read_text()
        body = report_attrs(report, "data-coverage-status")

        summary = load_summary(result_dir, "optical")
        self.assertEqual(summary["collection_status"], body["data-coverage-status"])
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(
            summary["coverage_expected"], int(body["data-coverage-expected"])
        )
        self.assertEqual(
            summary["coverage_current"], int(body["data-coverage-current"])
        )
        self.assertEqual(
            summary["coverage_collected"], int(body["data-coverage-collected"])
        )
        self.assertEqual(summary["total_ports"], int(body["data-optical-total"]))
        self.assertEqual(summary["unplugged"], int(body["data-optical-unplugged"]))
        self.assertEqual(summary["unknown"], int(body["data-optical-unknown"]))
        for field, element_id in (
            ("total_ports", "total-ports"),
            ("excellent", "excellent-ports"),
            ("good", "good-ports"),
            ("warning", "warning-ports"),
            ("critical", "critical-ports"),
            ("down", "down-ports"),
            ("unplugged", "unplugged-ports"),
            ("unknown", "unknown-ports"),
        ):
            self.assertEqual(
                summary[field], int(metric_by_id(report, element_id))
            )

    def test_ber_summary_json_matches_report(self):
        result_dir = self._result_tree()
        ber_dir = result_dir / "ber-data"
        ber_dir.mkdir()
        (ber_dir / "leaf1_interface_errors.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_ber_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_ber_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_ber_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_ber_data, "is_current_collection", return_value=True),
        ):
            success = process_ber_data.process_ber_data_files(str(ber_dir))

        self.assertTrue(success)
        report = (result_dir / "ber-analysis.html").read_text()
        body = report_attrs(report, "data-coverage-status")

        summary = load_summary(result_dir, "ber")
        self.assertEqual(summary["collection_status"], body["data-coverage-status"])
        self.assertEqual(summary["collection_status"], "partial")
        self.assertEqual(
            summary["coverage_expected"], int(body["data-coverage-expected"])
        )
        self.assertEqual(
            summary["coverage_current"], int(body["data-coverage-current"])
        )
        for field, element_id in (
            ("total_ports", "total-ports"),
            ("excellent", "excellent-ports"),
            ("good", "good-ports"),
            ("warning", "warning-ports"),
            ("critical", "critical-ports"),
            ("unknown", "unknown-ports"),
        ):
            self.assertEqual(
                summary[field], int(metric_by_id(report, element_id))
            )

    def test_flap_summary_json_matches_report(self):
        result_dir = self._result_tree()
        flap_dir = result_dir / "flap-data"
        flap_dir.mkdir()
        (flap_dir / "leaf1_carrier_transitions.txt").write_text(
            "=== CARRIER TRANSITIONS ===\nswp1: 4\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_flap_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_flap_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_flap_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_flap_data, "is_current_collection", return_value=True),
        ):
            success = process_flap_data.process_carrier_transition_files(str(flap_dir))

        self.assertTrue(success)
        report = (result_dir / "link-flap-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "flap")

        summary = load_summary(result_dir, "flap")
        self.assertEqual(
            summary["collection_status"], meta["data-collection-status"]
        )
        self.assertEqual(summary["collection_status"], "current")
        self.assertEqual(
            summary["coverage_expected"], int(meta["data-expected-devices"])
        )
        self.assertEqual(
            summary["coverage_current"], int(meta["data-current-devices"])
        )
        self.assertEqual(
            summary["critical_ports"], int(meta["data-critical-ports"])
        )
        self.assertEqual(
            summary["warning_ports"], int(meta["data-warning-ports"])
        )
        self.assertEqual(
            summary["total_devices"], int(metric_by_id(report, "total-devices"))
        )
        self.assertEqual(
            summary["total_ports"], int(metric_by_id(report, "total-ports"))
        )
        self.assertEqual(
            summary["stable_ports"], int(metric_by_id(report, "stable-ports"))
        )
        self.assertEqual(
            summary["problematic_ports"],
            int(metric_by_id(report, "problematic-ports")),
        )
        self.assertEqual(
            f"{summary['stability_percent']:.1f}%",
            metric_by_id(report, "stability-ratio"),
        )

    def test_pfc_ecn_summary_json_matches_report(self):
        result_dir = self._result_tree()
        data_dir = result_dir / "pfc-ecn-data"
        data_dir.mkdir()
        (data_dir / "leaf1_pfc_ecn.txt").write_text(
            "__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1\n"
            "__LLDPQ_PFC_ECN_PORT_START__:swp1\n"
            "__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:124\n"
            "PFC/ECN command timed out\n"
            "__LLDPQ_PFC_ECN_PORT_END__:swp1\n"
        )
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(process_pfc_ecn_data, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(process_pfc_ecn_data, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(process_pfc_ecn_data, "asset_snapshot_is_authoritative", return_value=True),
            mock.patch.object(process_pfc_ecn_data, "is_current_collection", return_value=True),
        ):
            success = process_pfc_ecn_data.process_pfc_ecn_data_files(str(data_dir))

        self.assertTrue(success)
        report = (result_dir / "pfc-ecn-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "pfc-ecn")

        summary = load_summary(result_dir, "pfc-ecn")
        for field, attribute in (
            ("collection_status", "data-collection-status"),
            ("coverage_status", "data-coverage-status"),
            ("interval_status", "data-interval-status"),
        ):
            self.assertEqual(summary[field], meta[attribute])
        self.assertEqual(
            summary["coverage_expected"], int(meta["data-coverage-expected"])
        )
        self.assertEqual(
            summary["coverage_current"], int(meta["data-coverage-current"])
        )
        for field, attribute in (
            ("total_ports", "data-total-ports"),
            ("ready_ports", "data-ready-ports"),
            ("ecn_active_ports", "data-ecn-active-ports"),
            ("pfc_rx_active_ports", "data-pfc-rx-active-ports"),
            ("pfc_tx_active_ports", "data-pfc-tx-active-ports"),
            ("discard_ready_ports", "data-discard-ready-ports"),
            ("discard_active_ports", "data-discard-active-ports"),
        ):
            self.assertEqual(summary[field], int(meta[attribute]))

    def test_hardware_summary_json_matches_report(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        previous_cwd = os.getcwd()
        self.addCleanup(os.chdir, previous_cwd)
        os.chdir(temporary.name)
        data_dir = Path("monitor-results/hardware-data")
        data_dir.mkdir(parents=True)
        (data_dir / "leaf1_hardware.txt").write_text(
            "=== HARDWARE HEALTH ===\n"
        )

        import generate_hardware_html

        snapshot = self._snapshot({"leaf1": "OK"})
        with (
            mock.patch.object(generate_hardware_html, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(generate_hardware_html, "read_collection_outcomes", return_value=None),
            mock.patch.object(generate_hardware_html, "is_current_collection", return_value=True),
        ):
            generate_hardware_html.generate_hardware_html()

        report = Path("monitor-results/hardware-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "hardware")

        summary = load_summary("monitor-results", "hardware")
        self.assertEqual(
            summary["collection_status"], meta["data-collection-status"]
        )
        self.assertEqual(
            summary["coverage_expected"], int(meta["data-coverage-expected"])
        )
        self.assertEqual(
            summary["coverage_current"], int(meta["data-coverage-current"])
        )
        self.assertEqual(
            summary["coverage_partial"],
            meta["data-coverage-partial"] == "true",
        )
        self.assertEqual(summary["unknown"], int(meta["data-unknown-devices"]))
        for field, element_id in (
            ("total_devices", "total-devices"),
            ("excellent", "excellent-devices"),
            ("good", "good-devices"),
            ("warning", "warning-devices"),
            ("critical", "critical-devices"),
            ("unknown", "unknown-devices"),
        ):
            self.assertEqual(
                summary[field], int(metric_by_id(report, element_id))
            )

        # The wrapper keeps the JSON status equal to the unavailable banner.
        process_hardware_data.mark_summary_collection_unavailable(
            "monitor-results/summary/hardware-summary.json"
        )
        patched = load_summary("monitor-results", "hardware")
        self.assertEqual(patched["collection_status"], "unavailable")
        self.assertEqual(patched["total_devices"], summary["total_devices"])

    def test_duplicate_summary_json_matches_report(self):
        result_dir = self._result_tree()
        dup_dir = result_dir / "dup-data"
        dup_dir.mkdir()
        (dup_dir / "leaf1_dup.txt").write_text("")
        (dup_dir / "leaf1_fdb.txt").write_text("")
        (dup_dir / "leaf1_neigh.txt").write_text("")
        snapshot = self._snapshot({"leaf1": "OK"})

        with (
            mock.patch.object(duplicate_analyzer, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(duplicate_analyzer, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(duplicate_analyzer, "canonical", side_effect=lambda value: value),
        ):
            analyzer = duplicate_analyzer.DuplicateAnalyzer(str(result_dir))
            analyzer.parse_all()
            analyzer.export_html(str(result_dir / "duplicate-analysis.html"))

        report = (result_dir / "duplicate-analysis.html").read_text()
        meta = report_attrs(report, "data-analysis-summary", "duplicate")

        summary = load_summary(result_dir, "duplicate")
        self.assertEqual(
            summary["collection_status"], meta["data-collection-status"]
        )
        self.assertEqual(
            summary["coverage_partial"],
            meta["data-coverage-partial"] == "true",
        )
        for field, attribute in (
            ("confirmed_ip_active", "data-confirmed-ip-active"),
            ("ip_quiesced", "data-ip-quiesced"),
            ("ip_arp_observed", "data-ip-arp-observed"),
            ("confirmed_mac_total", "data-confirmed-mac-total"),
            ("mac_dad_total", "data-mac-dad-total"),
            ("mac_mobility_active", "data-mac-mobility-active"),
            ("mac_mobility_total", "data-mac-mobility-total"),
            ("coverage_expected", "data-coverage-expected"),
            ("coverage_current", "data-coverage-current"),
            ("coverage_ip_current", "data-coverage-ip-current"),
            ("coverage_mac_current", "data-coverage-mac-current"),
            ("coverage_mac_evidence_current", "data-coverage-mac-evidence-current"),
            ("coverage_failures", "data-coverage-failures"),
        ):
            self.assertEqual(summary[field], int(meta[attribute]))

    def test_monitor_publishes_and_snapshots_summary_artifacts(self):
        monitor = (SCRIPT_DIR / "monitor.sh").read_text()
        artifacts = monitor.split("analysis_artifacts=(", 1)[1].split(")", 1)[0]
        outputs = monitor.split("validate_analysis_outputs() {", 1)[1]
        for domain in (
            "bgp", "evpn", "evpn-mh", "flap", "optical", "ber",
            "pfc-ecn", "hardware", "duplicate",
        ):
            relative = f"summary/{domain}-summary.json"
            self.assertIn(relative, artifacts)
            self.assertIn(relative, outputs)
        self.assertIn("analysis_artifacts_legacy_v3=(", monitor)
        self.assertIn('"$stage_dir/summary/optical-summary.json"', monitor)


if __name__ == "__main__":
    unittest.main()
