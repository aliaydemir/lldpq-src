#!/usr/bin/env python3
"""Contracts for per-generation collection outcomes and partial analyzers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from lldpq.collection_freshness import read_collection_outcomes
from lldpq import process_hardware_data
from lldpq import process_log_data


ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")


def manifest(path: Path, pipeline: str, statuses):
    devices = {
        host: {"status": status, "code": 0, "reason": "test"}
        for host, status in statuses.items()
    }
    counts = {
        status: sum(value == status for value in statuses.values())
        for status in ("current", "unavailable", "failed")
    }
    path.write_text(json.dumps({
        "version": 1,
        "pipeline_id": pipeline,
        "expected_devices": len(devices),
        "counts": counts,
        "devices": devices,
    }), encoding="utf-8")


class CollectionOutcomeTests(unittest.TestCase):
    def test_manifest_is_generation_bound_and_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            manifest(path, "pipeline-1", {
                "leaf1": "current", "leaf2": "unavailable"
            })
            with mock.patch.dict(os.environ, {
                "LLDPQ_COLLECTION_STATUS_FILE": str(path),
                "LLDPQ_PIPELINE_ID": "pipeline-1",
            }):
                self.assertEqual(read_collection_outcomes(), {
                    "leaf1": "current", "leaf2": "unavailable"
                })
            with mock.patch.dict(os.environ, {
                "LLDPQ_COLLECTION_STATUS_FILE": str(path),
                "LLDPQ_PIPELINE_ID": "other-pipeline",
            }):
                with self.assertRaisesRegex(ValueError, "invalid collection"):
                    read_collection_outcomes()

    def test_hardware_unavailable_device_is_partial_not_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "monitor-results/hardware-data"
            data.mkdir(parents=True)
            (data / "leaf1_hardware.txt").write_text("current", encoding="utf-8")
            snapshot = ({"leaf1": "OK", "leaf2": "OK"}, 0.0, True)
            previous = os.getcwd()
            os.chdir(root)
            try:
                with (
                    mock.patch.object(
                        process_hardware_data, "read_asset_snapshot",
                        return_value=snapshot,
                    ),
                    mock.patch.object(
                        process_hardware_data, "asset_snapshot_is_valid",
                        return_value=True,
                    ),
                    mock.patch.object(
                        process_hardware_data, "read_collection_outcomes",
                        return_value={
                            "leaf1": "current", "leaf2": "unavailable"
                        },
                    ),
                    mock.patch.object(
                        process_hardware_data, "is_current_collection",
                        return_value=True,
                    ),
                    mock.patch.object(
                        process_hardware_data.subprocess, "run",
                        return_value=SimpleNamespace(
                            returncode=0, stdout="generated", stderr=""
                        ),
                    ),
                ):
                    self.assertEqual(process_hardware_data.main(), 0)
            finally:
                os.chdir(previous)

    def test_log_unavailable_device_is_partial_not_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log_dir = root / "log-data"
            log_dir.mkdir()
            (log_dir / "leaf1_logs.txt").write_text("current", encoding="utf-8")
            analyzer = process_log_data.LogAnalyzer(str(root))
            snapshot = ({"leaf1": "OK", "leaf2": "OK"}, 0.0, True)
            with (
                mock.patch.object(
                    process_log_data, "read_asset_snapshot",
                    return_value=snapshot,
                ),
                mock.patch.object(
                    process_log_data, "asset_snapshot_is_valid",
                    return_value=True,
                ),
                mock.patch.object(
                    process_log_data, "read_collection_outcomes",
                    return_value={"leaf1": "current", "leaf2": "unavailable"},
                ),
                mock.patch.object(
                    process_log_data, "is_current_collection",
                    return_value=True,
                ),
                mock.patch.object(
                    analyzer, "process_device_logs", return_value=True
                ),
                mock.patch.object(analyzer, "generate_html_report"),
                mock.patch.object(analyzer, "save_summary_data"),
            ):
                self.assertTrue(analyzer.run_analysis())
            self.assertEqual(analyzer.current_devices, {"leaf1"})
            self.assertEqual(analyzer.expected_devices, {"leaf1", "leaf2"})

    def test_monitor_diagnostics_and_retry_contracts(self):
        self.assertIn("build_collection_status_manifest", MONITOR)
        self.assertIn("LLDPQ_COLLECTION_STATUS_FILE", MONITOR)
        self.assertIn(".pipeline-inputs/collection_status.json", MONITOR)
        self.assertIn('2>"$ssh_error_file"', MONITOR)
        self.assertIn("last marker:", MONITOR)
        optical = MONITOR.split(
            "# SECTION 4: Optical Transceiver Data", 1
        )[1].split("===OPTICAL_DATA_END===", 1)[0]
        self.assertIn("Retry once", optical)
        self.assertEqual(optical.count("sudo ethtool -m"), 2)
        self.assertIn("_optical_retry_limit", optical)


if __name__ == "__main__":
    unittest.main()
