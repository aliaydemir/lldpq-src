#!/usr/bin/env python3
"""Contracts for per-generation collection outcomes and partial analyzers."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from assets_api import AssetReportError, load_assets_payload
from collection_freshness import (
    AssetStatusMap,
    _read_collection_outcomes_cached,
    is_current_collection,
    parse_created_timestamp,
    read_asset_snapshot,
    read_collection_outcomes,
)
import process_hardware_data
import process_log_data


ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")
CHECK_LLDP = (ROOT / "lldpq/check-lldp.sh").read_text(encoding="utf-8")
FABRIC_SCAN = (ROOT / "lldpq/fabric-scan.sh").read_text(encoding="utf-8")
HARDWARE_HTML = (ROOT / "lldpq/generate_hardware_html.py").read_text(
    encoding="utf-8"
)


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
    def test_shell_status_writer_uses_locked_file_not_stdout(self):
        match = re.search(
            r"(?ms)^record_collection_status\(\) \{.*?^\}$",
            MONITOR,
        )
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as temporary:
            status_file = Path(temporary) / "status.tsv"
            script = (
                match.group(0)
                + f'\ncollection_status_file="{status_file}"\n'
                + "record_collection_status leaf1 current 0 ok\n"
            )
            completed = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                status_file.read_text(encoding="utf-8"),
                "leaf1\tcurrent\t0\tok\n",
            )

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

    def test_manifest_unavailable_rejects_preserved_raw_as_current(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "leaf1.txt"
            raw.write_text("old-but-fresh", encoding="utf-8")
            status = root / "status.json"
            manifest(status, "pipeline-1", {"leaf1": "unavailable"})
            statuses = AssetStatusMap(
                {"leaf1": "OK"}, snapshot_valid=True, authoritative=True
            )
            _read_collection_outcomes_cached.cache_clear()
            with mock.patch.dict(os.environ, {
                "LLDPQ_COLLECTION_STATUS_FILE": str(status),
                "LLDPQ_PIPELINE_ID": "pipeline-1",
            }):
                self.assertFalse(is_current_collection(
                    str(raw), "leaf1", (statuses, 0.0, True)
                ))

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
        handshake = MONITOR.index('printf "__LLDPQ_REMOTE_CONNECTED__')
        snapshots = MONITOR.index("_lldpq_snapshot_dir=$(mktemp", handshake)
        self.assertLess(handshake, snapshots)
        self.assertNotIn("ssh $SSH_OPTS -q", MONITOR)
        self.assertIn("COLLECTION_FAILURE_KIND=ssh-unavailable", MONITOR)
        optical = MONITOR.split(
            "# SECTION 4: Optical Transceiver Data", 1
        )[1].split("===OPTICAL_DATA_END===", 1)[0]
        self.assertIn("Retry once", optical)
        self.assertEqual(optical.count("sudo ethtool -m"), 2)
        self.assertIn("_optical_retry_limit", optical)
        self.assertIn(
            ".pipeline-inputs/collection_status.json", MONITOR.split(
                "analysis_artifacts=(", 1
            )[1].split(")", 1)[0]
        )
        scoped = MONITOR.split(
            "Scoped collection could not reach", 1
        )[1].split("fi", 1)[0]
        self.assertIn('"$availability_reason"', scoped)
        self.assertIn("return $?", scoped)
        self.assertIn(
            'read_collection_outcomes()', HARDWARE_HTML
        )
        self.assertIn(
            "len(collection_outcomes)", HARDWARE_HTML
        )
        validation = MONITOR.index(
            'if ! validate_analysis_outputs "$analysis_output_marker"; then'
        )
        install = MONITOR.index(
            "if ! install_collection_status_manifest; then"
        )
        manifest_write = MONITOR.index("if ! write_current_manifest; then")
        publication = MONITOR.index("if ! publish_monitor_results; then")
        self.assertLess(validation, install)
        self.assertLess(install, manifest_write)
        self.assertLess(manifest_write, publication)
        install_failure = MONITOR[install:manifest_write]
        self.assertIn("rollback_analysis_state", install_failure)

    def test_missing_ssh_handshake_is_unavailable_even_when_ping_works(self):
        match = re.search(r"(?ms)^process_device\(\) \{.*?^\}", MONITOR)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as temporary:
            unreachable = Path(temporary) / "unreachable"
            script = match.group(0) + f"""
scoped_run=false
unreachable_hosts_file="{unreachable}"
ping_test() {{ return 0; }}
execute_commands_optimized() {{
    COLLECTION_FAILURE_KIND=ssh-unavailable
    return 255
}}
record_collection_status() {{
    printf 'STATUS:%s:%s:%s:%s\\n' "$1" "$2" "$3" "$4"
}}
clear_current_device_artifacts() {{ return 0; }}
write_unreachable_device_report() {{ return 0; }}
process_device 192.0.2.10 user leaf1
"""
            completed = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(
                "STATUS:leaf1:unavailable:255:ssh-no-session",
                completed.stdout,
            )
            self.assertEqual(
                unreachable.read_text(encoding="utf-8"),
                "192.0.2.10 leaf1\n",
            )

    def test_started_remote_collection_failure_remains_fatal(self):
        match = re.search(r"(?ms)^process_device\(\) \{.*?^\}", MONITOR)
        self.assertIsNotNone(match)
        script = match.group(0) + """
scoped_run=false
unreachable_hosts_file=/dev/null
ping_test() { return 1; }
execute_commands_optimized() {
    COLLECTION_FAILURE_KIND=ssh
    return 255
}
record_collection_status() {
    printf 'STATUS:%s:%s:%s:%s\\n' "$1" "$2" "$3" "$4"
}
clear_current_device_artifacts() { return 0; }
write_unreachable_device_report() { return 0; }
process_device 192.0.2.10 user leaf1
"""
        completed = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 255, completed.stderr)
        self.assertIn("STATUS:leaf1:failed:255:ssh", completed.stdout)

    def test_scheduled_fabric_scan_shares_pipeline_lock(self):
        inherited = FABRIC_SCAN.index("global_lock_is_inherited=false")
        pipeline_lock = FABRIC_SCAN.index('exec 9>"$GLOBAL_LOCK_FILE"')
        fabric_lock = FABRIC_SCAN.index('exec 8>"$LOCK_FILE"')
        self.assertLess(inherited, pipeline_lock)
        self.assertLess(pipeline_lock, fabric_lock)
        self.assertIn("LLDPQ_MONITOR_LOCK_HELD", FABRIC_SCAN)
        self.assertIn("scheduled fabric scan skipped", FABRIC_SCAN)
        partial = FABRIC_SCAN.split(
            'if [[ ${#scan_failures[@]} -gt 0 ]]', 1
        )[1].split("fi", 1)[0]
        self.assertIn("partial coverage", partial)
        self.assertNotIn("exit 1", partial)

    def test_lldp_cleanup_reaps_collectors_before_removing_stage(self):
        cleanup = CHECK_LLDP.split("cleanup_check_lldp() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertLess(cleanup.index('kill "$pid"'), cleanup.index("rm -f"))
        self.assertLess(cleanup.index('wait "$pid"'), cleanup.index("rm -f"))
        self.assertIn('tmp.${BASHPID:-$$}', CHECK_LLDP)
        self.assertIn('collection_pids+=("$!")', CHECK_LLDP)


class AssetSnapshotDstTests(unittest.TestCase):
    """assets.sh writes naive local 'Created on' times, ambiguous during the
    DST fall-back hour: fold-aware parsing must keep the repeated hour's
    second-pass snapshots current instead of blacking out every host."""

    AMBIGUOUS_LOCAL = "2026-11-01 01-30-00"

    def setUp(self):
        original = os.environ.get("TZ")
        os.environ["TZ"] = "America/New_York"
        time.tzset()

        def restore():
            if original is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original
            time.tzset()

        self.addCleanup(restore)
        ambiguous = datetime.strptime(self.AMBIGUOUS_LOCAL, "%Y-%m-%d %H-%M-%S")
        self.first_pass = ambiguous.timestamp()
        self.second_pass = ambiguous.replace(fold=1).timestamp()
        # Guard: the zone must really repeat this hour (fold=1 is EST).
        self.assertEqual(3600.0, self.second_pass - self.first_pass)

    def write_assets(self, directory):
        assets = Path(directory) / "assets.ini"
        assets.write_text(
            f"Created on {self.AMBIGUOUS_LOCAL}\n"
            "\n"
            "DEVICE-NAME IP ETH0-MAC SERIAL MODEL RELEASE UPTIME "
            "STATUS LAST-SEEN\n"
            "switch01 10.0.0.1 aa:bb:cc:dd:ee:ff MT12345 MSN3700 "
            "5.9.2 1_day OK 2026-11-01_01:29\n",
            encoding="utf-8",
        )
        return assets

    def environment(self, assets):
        return {
            "LLDPQ_ASSETS_FILE": str(assets),
            "LLDPQ_DEVICES_FILE": str(assets.parent / "devices.yaml"),
            "ASSET_TIMESTAMP_TOLERANCE_SECONDS": "120",
            "MONITOR_DATA_MAX_AGE_MINUTES": "30",
        }

    def test_parse_created_timestamp_prefers_closer_fold(self):
        self.assertEqual(self.first_pass, parse_created_timestamp(
            self.AMBIGUOUS_LOCAL, self.first_pass + 30, 120.0
        ))
        self.assertEqual(self.second_pass, parse_created_timestamp(
            self.AMBIGUOUS_LOCAL, self.second_pass - 30, 120.0
        ))
        self.assertIsNone(parse_created_timestamp(
            self.AMBIGUOUS_LOCAL, self.second_pass + 7200, 120.0
        ))
        self.assertIsNone(parse_created_timestamp(
            "garbage", self.first_pass, 120.0
        ))

    def test_second_pass_snapshot_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets = self.write_assets(temporary)
            os.utime(assets, (self.second_pass, self.second_pass))
            with (
                mock.patch.dict(os.environ, self.environment(assets)),
                mock.patch("time.time", return_value=self.second_pass + 60),
            ):
                statuses, _mtime, available = read_asset_snapshot()
            self.assertTrue(available)
            self.assertTrue(statuses.snapshot_valid)
            self.assertEqual({"switch01": "OK"}, dict(statuses))

    def test_skew_beyond_both_folds_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets = self.write_assets(temporary)
            skewed = self.second_pass + 7200.0
            os.utime(assets, (skewed, skewed))
            with (
                mock.patch.dict(os.environ, self.environment(assets)),
                mock.patch("time.time", return_value=skewed + 60),
            ):
                statuses, _mtime, available = read_asset_snapshot()
            self.assertTrue(available)
            self.assertFalse(statuses.snapshot_valid)
            self.assertEqual({}, dict(statuses))

    def test_assets_api_accepts_second_pass_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            assets = self.write_assets(temporary)
            devices = Path(temporary) / "devices.yaml"
            devices.write_text(
                'devices:\n  10.0.0.1: "switch01 @cumulus"\n',
                encoding="utf-8",
            )
            os.utime(assets, (self.second_pass, self.second_pass))
            os.utime(devices, (self.second_pass - 60, self.second_pass - 60))
            with mock.patch.dict(os.environ, {
                "ASSET_TIMESTAMP_TOLERANCE_SECONDS": "120",
            }):
                payload = load_assets_payload(
                    assets, devices, now=self.second_pass + 60,
                )
                self.assertTrue(payload["success"])
                self.assertEqual(1, payload["total"])

                skewed = self.second_pass + 7200.0
                os.utime(assets, (skewed, skewed))
                with self.assertRaisesRegex(
                    AssetReportError, "does not match its publication time"
                ):
                    load_assets_payload(assets, devices, now=skewed + 60)


if __name__ == "__main__":
    unittest.main()
