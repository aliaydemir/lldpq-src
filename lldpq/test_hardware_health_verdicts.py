#!/usr/bin/env python3
"""Tests for the two hardware verdicts that could hide a real failure.

A switch whose fans had all stopped was graded UNKNOWN rather than CRITICAL,
because an all-zero fan set was read as absent telemetry.  A thermal sensor
that could not be read reported 0.0 C, which graded EXCELLENT — the report
claimed the hottest component in the box was healthy when it was never read.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import generate_hardware_html as hardware


class FanGradingTests(unittest.TestCase):
    def test_a_fan_tray_that_has_entirely_stopped_is_critical(self):
        overall, details = hardware.grade_fans_relative({
            "Chassis Fan Drawer-1 Tach 1": 0,
            "Chassis Fan Drawer-2 Tach 1": 0,
            "PSU-1(L) Fan 1": 0,
        })
        self.assertEqual(overall, "CRITICAL")
        self.assertTrue(all(fan["grade"] == "CRITICAL" for fan in details))

    def test_a_single_stopped_fan_among_healthy_peers_is_critical(self):
        overall, _ = hardware.grade_fans_relative({
            "Chassis Fan Drawer-1 Tach 1": 0,
            "Chassis Fan Drawer-2 Tach 1": 8000,
        })
        self.assertEqual(overall, "CRITICAL")

    def test_healthy_fans_are_still_excellent(self):
        overall, _ = hardware.grade_fans_relative({
            "Chassis Fan Drawer-1 Tach 1": 8000,
            "Chassis Fan Drawer-2 Tach 1": 8100,
        })
        self.assertEqual(overall, "EXCELLENT")

    def test_a_lagging_fan_is_still_graded_against_its_cohort(self):
        overall, _ = hardware.grade_fans_relative({
            "Chassis Fan Drawer-1 Tach 1": 8000,
            "Chassis Fan Drawer-2 Tach 1": 8000,
            "Chassis Fan Drawer-3 Tach 1": 3000,
        })
        self.assertEqual(overall, "CRITICAL")

    def test_no_fan_readings_at_all_remains_unknown(self):
        overall, details = hardware.grade_fans_relative({})
        self.assertIsNone(
            overall, "a platform without fan sensors is not a failed platform"
        )
        self.assertEqual(details, [])

    def test_non_numeric_readings_are_ignored(self):
        overall, details = hardware.grade_fans_relative({
            "Chassis Fan Drawer-1 Tach 1": "N/A",
            "Chassis Fan Drawer-2 Tach 1": 8000,
        })
        self.assertEqual(overall, "EXCELLENT")
        self.assertEqual(len(details), 1)


class TemperatureParsingTests(unittest.TestCase):
    def _parse(self, body):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        data_dir = Path(temporary.name) / "monitor-results" / "hardware-data"
        data_dir.mkdir(parents=True)
        (data_dir / "leaf1_hardware.txt").write_text(body)

        # The helper resolves the raw file relative to the working directory.
        previous = os.getcwd()
        os.chdir(temporary.name)
        self.addCleanup(os.chdir, previous)
        return hardware.parse_temperature_from_hardware_file("leaf1")

    def test_a_zero_reading_is_treated_as_missing(self):
        cpu, asic = self._parse("HW_MGMT_ASIC: 0.0\nHW_MGMT_CPU: 0.0\n")
        self.assertIsNone(asic, "0.0 C means the sensor was not read")
        self.assertIsNone(cpu)

    def test_a_real_reading_is_kept(self):
        cpu, asic = self._parse("HW_MGMT_ASIC: 54.0\nHW_MGMT_CPU: 41.5\n")
        self.assertEqual(asic, 54.0)
        self.assertEqual(cpu, 41.5)

    def test_a_dead_sensor_does_not_mask_a_live_one(self):
        _cpu, asic = self._parse(
            "HW_MGMT_ASIC: 0.0\nTHERMAL_ZONE_ASIC: 61.0\n"
        )
        self.assertEqual(
            asic, 61.0, "the working sensor must survive the dead one"
        )

    def test_negative_readings_are_rejected(self):
        cpu, asic = self._parse("HW_MGMT_ASIC: -5.0\nHW_MGMT_CPU: -1.0\n")
        self.assertIsNone(asic)
        self.assertIsNone(cpu)


class CollectorContractTests(unittest.TestCase):
    """The collector must not publish an unread sensor as 0.0."""

    def setUp(self):
        self.source = (SCRIPT_DIR / "monitor.sh").read_text()

    def test_asic_temperature_requires_a_positive_reading(self):
        self.assertIn(
            'if [ -n "$asic_raw" ] && [ "$asic_raw" -gt 0 ]; then', self.source
        )

    def test_cpu_temperature_requires_a_positive_reading(self):
        self.assertIn(
            'if [ -n "$cpu_raw" ] && [ "$cpu_raw" -gt 0 ]; then', self.source
        )


class CollectionUnavailableExportTests(unittest.TestCase):
    """An all-unreachable run must publish 'unavailable', never 'partial'.

    process_hardware_data used to patch only the HTML and the summary JSON
    after the fact, so export/hardware.{json,csv} kept the generator's
    'partial'/'current' coverage while every sibling domain said 'unavailable'.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "monitor-results" / "hardware-data").mkdir(parents=True)
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        # The generator must see the fixture, not a live install's manifest.
        env_guard = mock.patch.dict(os.environ)
        env_guard.start()
        self.addCleanup(env_guard.stop)
        os.environ.pop("LLDPQ_COLLECTION_STATUS_FILE", None)
        os.environ.pop("LLDPQ_ASSETS_FILE", None)

    def read_export(self):
        export = self.root / "monitor-results" / "export" / "hardware.json"
        return json.loads(export.read_text(encoding="utf-8"))

    def assert_sidecar_matches(self, artifact):
        sidecar = artifact.with_name(artifact.name + ".sha256")
        digest, name = sidecar.read_text(encoding="utf-8").split()
        self.assertEqual(name, artifact.name)
        self.assertEqual(
            digest, hashlib.sha256(artifact.read_bytes()).hexdigest()
        )

    def test_the_export_publishes_unavailable_for_an_all_unreachable_run(self):
        hardware.generate_hardware_html(collection_unavailable=True)
        self.assertEqual(
            self.read_export()["collection_status"], "unavailable"
        )

    def test_the_export_digest_sidecars_match_the_published_content(self):
        hardware.generate_hardware_html(collection_unavailable=True)
        export_dir = self.root / "monitor-results" / "export"
        self.assert_sidecar_matches(export_dir / "hardware.json")
        self.assert_sidecar_matches(export_dir / "hardware.csv")

    def test_the_summary_says_unavailable_without_post_hoc_patching(self):
        hardware.generate_hardware_html(collection_unavailable=True)
        summary = json.loads(
            (self.root / "monitor-results" / "summary"
             / "hardware-summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(summary["collection_status"], "unavailable")

    def test_a_reachable_run_keeps_its_computed_coverage_status(self):
        hardware.generate_hardware_html()
        self.assertEqual(self.read_export()["collection_status"], "current")

    def test_the_command_line_flag_reaches_the_export(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "generate_hardware_html.py"),
             "--collection-unavailable"],
            capture_output=True, text=True, cwd=self.root, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.read_export()["collection_status"], "unavailable"
        )

    def test_process_hardware_data_forwards_the_verdict(self):
        source = (SCRIPT_DIR / "process_hardware_data.py").read_text()
        self.assertIn(
            'generator_cmd.append("--collection-unavailable")', source
        )
        self.assertIn("if all_devices_unavailable:", source)


class CsvExportContractTests(unittest.TestCase):
    """The CSV export must exclude rows the table-filter funnels hid.

    table-filter.js hides rows via the tf-hidden class, never via
    style.display, so both the row filter and the '# Rows exported' count
    in downloadCSV must check that class or the export silently includes
    devices the operator filtered out.
    """

    def setUp(self):
        self.source = (SCRIPT_DIR / "generate_hardware_html.py").read_text(
            encoding="utf-8"
        )

    def test_the_row_filter_excludes_tf_hidden_rows(self):
        self.assertIn(
            "if (row.style.display !== 'none' && "
            "!row.classList.contains('tf-hidden')) {",
            self.source,
        )

    def test_the_exported_count_excludes_tf_hidden_rows(self):
        self.assertIn(
            "r => r.style.display !== 'none' && "
            "!r.classList.contains('tf-hidden')).length;",
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
