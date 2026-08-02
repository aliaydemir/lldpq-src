#!/usr/bin/env python3
"""Per-device optical history shards (optical-history/) and their consumers.

Mirrors the PFC/BER shard contract with one structural difference: the
parse workers own the whole shard lifecycle (load, append, unplugged
decision, write), so the parent process never holds the fabric-wide
history.  The parent only reconciles: retired-host pruning and emptying the
persisted current snapshot of devices without a current collection.
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

import analysis_sidecar
import process_optical_data as optical
from optical_analyzer import OpticalAnalyzer


DOM_SAMPLE = """\
        Identifier                                : 0x11 (QSFP28)
        Transceiver type                          : 100G Base-SR4
        Vendor name                               : ACME
        Vendor PN                                 : QSFP-100G-SR4
        Module temperature                        : 31.50 degrees C
        Module voltage                            : 3.2800 V
        Receiver signal average optical power (Channel 1) : 0.6982 mW / -1.56 dBm
        Transmit avg optical power (Channel 1)    : 0.7521 mW / -1.24 dBm
        Laser bias current (Channel 1)            : 7.500 mA
"""

LEAF1_FILE = (
    "=== OPTICAL DIAGNOSTICS ===\n"
    "--- Interface: swp1\n"
    "Interface state: up\n" + DOM_SAMPLE
)


def _history_entry(ts, health="good"):
    return {
        "timestamp": ts,
        "health": health,
        "rx_power_dbm": -1.5,
        "tx_power_dbm": -1.2,
        "temperature_c": 30.0,
        "link_margin_db": 10.0,
        "rx_power_lane": None,
        "tx_power_lane": None,
        "bias_current_lane": None,
    }


class OpticalShardWorkerTests(unittest.TestCase):
    """The parse worker persists the device shard itself."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "optical-data").mkdir()

    def _classify(self, hostname, body):
        sample = self.root / "optical-data" / f"{hostname}_optical.txt"
        sample.write_text(body)
        optical._parse_worker_analyzer = OpticalAnalyzer(
            str(self.root), load_history=False
        )
        return optical._classify_optical_file(str(sample), hostname)

    def test_worker_writes_the_shard_with_history_and_current(self):
        ops, _failures, shard_error = self._classify("leaf1", LEAF1_FILE)
        self.assertIsNone(shard_error)
        self.assertEqual([op[0] for op in ops], ["update"])

        shard_path = self.root / "optical-history" / "leaf1.json"
        payload = json.loads(shard_path.read_text())
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["host"], "leaf1")
        self.assertIn("updated_at", payload)
        self.assertEqual(len(payload["history"]["leaf1:swp1"]), 1)
        self.assertEqual(
            payload["current"]["leaf1:swp1"]["health_status"], "excellent"
        )
        # Validation handshake sidecar published by the atomic writer.
        self.assertTrue(analysis_sidecar.sidecar_path(shard_path).exists())

    def test_second_run_appends_history_and_replaces_current(self):
        self._classify("leaf1", LEAF1_FILE)
        _ops, _failures, shard_error = self._classify("leaf1", LEAF1_FILE)
        self.assertIsNone(shard_error)
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        self.assertEqual(len(payload["history"]["leaf1:swp1"]), 2)
        self.assertEqual(len(payload["current"]), 1)

    def test_reprocessing_the_same_collection_file_is_idempotent(self):
        # A broken-pool retry (or a re-analysis without new collection)
        # feeds the exact same file to the worker again; the recorded
        # source_mtime must keep the duplicate append out of the history.
        sample = self.root / "optical-data" / "leaf1_optical.txt"
        self._classify("leaf1", LEAF1_FILE)
        first = (self.root / "optical-history" / "leaf1.json").read_text()
        mtime = sample.stat().st_mtime

        optical._parse_worker_analyzer = OpticalAnalyzer(
            str(self.root), load_history=False
        )
        ops, _failures, shard_error = optical._classify_optical_file(
            str(sample), "leaf1"
        )
        self.assertIsNone(shard_error)
        # The parent's current snapshot is still rebuilt from the ops.
        self.assertEqual([op[0] for op in ops], ["update"])
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        self.assertEqual(len(payload["history"]["leaf1:swp1"]), 1)
        self.assertEqual(payload["source_mtime"], mtime)
        self.assertEqual(
            (self.root / "optical-history" / "leaf1.json").read_text(), first,
            "an already-merged file must not rewrite the shard",
        )

    def test_shard_current_carries_no_raw_data(self):
        self._classify("leaf1", LEAF1_FILE)
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        for record in payload["current"].values():
            self.assertNotIn(
                "raw_data", record,
                "raw evidence belongs to optical-details/, not the shard",
            )
        # The in-memory current keeps raw_data: detail sidecars are built
        # from it.
        worker = optical._parse_worker_analyzer
        self.assertIn("raw_data", worker.current_optical_stats["leaf1:swp1"])

    def test_complete_collection_prunes_removed_port_history(self):
        seeder = OpticalAnalyzer(str(self.root), load_history=False)
        seeder.optical_history = {
            "leaf1:swp1": [_history_entry(1.0)],
            "leaf1:swp99": [_history_entry(1.0)],
        }
        self.assertTrue(seeder.save_optical_history())

        self._classify("leaf1", LEAF1_FILE)  # complete file lists only swp1
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        self.assertIn("leaf1:swp1", payload["history"])
        self.assertNotIn(
            "leaf1:swp99", payload["history"],
            "a port absent from a complete collection was reconfigured away",
        )

    def test_incomplete_collection_preserves_all_history(self):
        seeder = OpticalAnalyzer(str(self.root), load_history=False)
        seeder.optical_history = {"leaf1:swp99": [_history_entry(1.0)]}
        self.assertTrue(seeder.save_optical_history())

        body = LEAF1_FILE + (
            "__LLDPQ_COLLECTION_ERROR__:OPTICAL_BUDGET:swp2\n"
        )
        self._classify("leaf1", body)
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        self.assertIn(
            "leaf1:swp99", payload["history"],
            "an aborted collection must never prune history",
        )

    def test_state_rows_reach_the_persisted_current_snapshot(self):
        body = (
            "=== OPTICAL DIAGNOSTICS ===\n"
            "--- Interface: swp2\n"
            "Interface state: unknown\n" + DOM_SAMPLE
        )
        ops, _failures, shard_error = self._classify("leaf1", body)
        self.assertIsNone(shard_error)
        self.assertEqual([op[0] for op in ops], ["state"])
        payload = json.loads(
            (self.root / "optical-history" / "leaf1.json").read_text()
        )
        self.assertEqual(
            payload["current"]["leaf1:swp2"]["health_status"], "unknown"
        )

    def test_device_without_optical_state_writes_no_shard(self):
        body = (
            "=== OPTICAL DIAGNOSTICS ===\n"
            "--- Interface: swp3\n"
            "Interface state: up\n"
            "Passive copper cable, no diagnostics available here today\n"
        )
        ops, _failures, shard_error = self._classify("dacleaf", body)
        self.assertIsNone(shard_error)
        self.assertEqual(ops, [])
        self.assertFalse(
            (self.root / "optical-history" / "dacleaf.json").exists(),
            "all-DAC devices must not create empty shard files",
        )

    def test_unsafe_hostname_is_refused(self):
        analyzer = OpticalAnalyzer(str(self.root), load_history=False)
        error = analyzer.write_history_shard("../evil")
        self.assertIn("unsafe", error)


class OpticalShardAnalyzerRunTests(unittest.TestCase):
    """Full analyzer runs: migration, reconcile, prune."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.result_dir = Path(temporary.name) / "monitor-results"
        self.data_dir = self.result_dir / "optical-data"
        self.data_dir.mkdir(parents=True)

    def _run(self, statuses, files):
        for hostname, content in files.items():
            (self.data_dir / f"{hostname}_optical.txt").write_text(content)
        snapshot = (statuses, 1.0, True)
        with (
            mock.patch.object(optical, "read_asset_snapshot",
                              return_value=snapshot),
            mock.patch.object(optical, "asset_snapshot_is_valid",
                              return_value=True),
            mock.patch.object(optical, "is_current_collection",
                              return_value=True),
        ):
            return optical.process_optical_data_files(str(self.data_dir))

    def test_monolith_migrates_and_retires(self):
        now = time.time()
        monolith = self.result_dir / "optical_history.json"
        monolith.write_text(json.dumps({
            "optical_history": {
                "leaf1:swp1": [_history_entry(now - 300)],
                "leaf9:swp5": [_history_entry(now - 300)],
            },
            "current_optical_stats": {
                "leaf1:swp1": {"health_status": "good"},
                "leaf9:swp5": {"health_status": "critical"},
            },
            "last_update": now - 300,
        }))
        analysis_sidecar.publish_digest(str(monolith), "0" * 64)

        # leaf9 stays in inventory but is unreachable this run: its shard
        # must survive the prune with history intact and current emptied.
        self.assertTrue(self._run(
            {"leaf1": "OK", "leaf9": "FAILED"}, {"leaf1": LEAF1_FILE}
        ))

        self.assertFalse(monolith.exists(), "monolith must be retired")
        self.assertFalse(
            analysis_sidecar.sidecar_path(monolith).exists(),
            "monolith sidecar must be retired with it",
        )
        leaf1 = json.loads(
            (self.result_dir / "optical-history" / "leaf1.json").read_text()
        )
        # Migrated history plus this run's fresh sample.
        self.assertEqual(len(leaf1["history"]["leaf1:swp1"]), 2)
        self.assertEqual(
            leaf1["current"]["leaf1:swp1"]["health_status"], "excellent"
        )
        # An uncollected device keeps its migrated history, but its persisted
        # current snapshot is emptied — exactly what the rebuilt-from-scratch
        # monolith used to publish for it.
        leaf9 = json.loads(
            (self.result_dir / "optical-history" / "leaf9.json").read_text()
        )
        self.assertEqual(len(leaf9["history"]["leaf9:swp5"]), 1)
        self.assertEqual(leaf9["current"], {})

    def test_corrupt_monolith_is_retired_once(self):
        monolith = self.result_dir / "optical_history.json"
        monolith.write_text("{not-json")
        self.assertTrue(self._run({"leaf1": "OK"}, {"leaf1": LEAF1_FILE}))
        self.assertFalse(monolith.exists())

    def test_retired_devices_shard_is_pruned(self):
        stale = self.result_dir / "optical-history"
        stale.mkdir(parents=True)
        (stale / "gone-leaf.json").write_text(json.dumps({
            "version": 1, "host": "gone-leaf",
            "history": {}, "current": {},
        }))
        self.assertTrue(self._run({"leaf1": "OK"}, {"leaf1": LEAF1_FILE}))
        self.assertFalse((stale / "gone-leaf.json").exists())
        self.assertTrue((stale / "leaf1.json").exists())

    def test_shard_directory_exists_even_without_optical_devices(self):
        self.assertTrue(self._run({"leaf1": "OK"}, {
            "leaf1": "=== OPTICAL DIAGNOSTICS ===\n",
        }))
        self.assertTrue((self.result_dir / "optical-history").is_dir())


class OpticalShardReconcileUnitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.analyzer = OpticalAnalyzer(str(self.root), load_history=False)

    def test_clear_stale_shard_current_preserves_history(self):
        shard_dir = self.root / "optical-history"
        shard_dir.mkdir()
        (shard_dir / "leaf2.json").write_text(json.dumps({
            "version": 1, "updated_at": 1.0, "host": "leaf2",
            "history": {"leaf2:swp1": [_history_entry(1.0)]},
            "current": {"leaf2:swp1": {"health_status": "good"}},
        }))
        self.assertTrue(self.analyzer.clear_stale_shard_current({"leaf1"}))
        payload = json.loads((shard_dir / "leaf2.json").read_text())
        self.assertEqual(payload["current"], {})
        self.assertEqual(len(payload["history"]["leaf2:swp1"]), 1)
        self.assertGreater(payload["updated_at"], 1.0)

    def test_clear_stale_skips_processed_and_already_empty_shards(self):
        shard_dir = self.root / "optical-history"
        shard_dir.mkdir()
        (shard_dir / "leaf1.json").write_text(json.dumps({
            "version": 1, "updated_at": 1.0, "host": "leaf1",
            "history": {}, "current": {"leaf1:swp1": {}},
        }))
        (shard_dir / "leaf2.json").write_text(json.dumps({
            "version": 1, "updated_at": 1.0, "host": "leaf2",
            "history": {}, "current": {},
        }))
        self.assertTrue(self.analyzer.clear_stale_shard_current(set()))
        processed = json.loads((shard_dir / "leaf1.json").read_text())
        self.assertEqual(processed["current"], {})
        untouched = json.loads((shard_dir / "leaf2.json").read_text())
        self.assertEqual(untouched["updated_at"], 1.0,
                         "an already-empty shard must not be rewritten")

    def test_save_optical_history_skips_unsafe_hosts_loudly(self):
        self.analyzer.optical_history = {
            "leaf1:swp1": [_history_entry(1.0)],
            "../evil:swp1": [_history_entry(1.0)],
        }
        self.assertTrue(self.analyzer.save_optical_history())
        shard_dir = self.root / "optical-history"
        self.assertTrue((shard_dir / "leaf1.json").exists())
        self.assertEqual(
            sorted(p.name for p in shard_dir.glob("*.json")),
            ["leaf1.json"],
        )

    def test_load_optical_history_merges_shards(self):
        shard_dir = self.root / "optical-history"
        shard_dir.mkdir()
        for host in ("leaf1", "leaf2"):
            (shard_dir / f"{host}.json").write_text(json.dumps({
                "version": 1, "updated_at": 1.0, "host": host,
                "history": {f"{host}:swp1": [_history_entry(1.0)]},
                "current": {f"{host}:swp1": {"health_status": "good"}},
            }))
        loader = OpticalAnalyzer(str(self.root))
        self.assertEqual(len(loader.optical_history), 2)
        self.assertEqual(len(loader.current_optical_stats), 2)
        self.assertFalse(loader._legacy_history_loaded)


class OpticalShardConsumerContractTests(unittest.TestCase):
    """Every monolith reader resolves shards first and falls back."""

    def _read(self, relative):
        return (SCRIPT_DIR.parent / relative).read_text()

    def test_check_alerts_reads_the_device_shard_first(self):
        source = self._read("lldpq/check_alerts.py")
        self.assertIn('"optical-history" / f"{device}.json"', source)
        self.assertIn('optical_data.get("current", {})', source)
        # Shard era without a shard file means no optical ports on record.
        self.assertIn(
            '(self.monitor_results / "optical-history").is_dir()', source
        )

    def test_ai_api_merges_shards_with_monolith_fallback(self):
        source = self._read("html/ai-api.sh")
        self.assertIn("def _load_optical_current_stats(hosts=None):", source)
        self.assertIn(
            "stats = _load_optical_current_stats(set(hosts) if hosts else None)",
            source,
        )
        self.assertIn("_mr_path('optical-history')", source)
        # Freshness follows the shard directory once it exists.
        self.assertIn(
            "os.path.join(_mr_path('optical-history'), '*.json')", source
        )

    def test_ai_insights_streams_shards(self):
        source = self._read("html/ai_insights.py")
        self.assertIn("def _optical_history_source(", source)
        self.assertIn(
            '("optical", _extract_optical, _optical_history_source(monitor, web)),',
            source,
        )
        optical_extract = source.split("def _extract_optical(", 1)[1]
        optical_extract = optical_extract.split("def _extract_", 1)[0]
        # Shard directories go through the shared per-shard streaming merge
        # (one bad shard must not blank the source); the monolith fallback
        # still streams the single file directly.
        self.assertIn("_stream_history_shards(", optical_extract)
        self.assertIn('_stream_history(\n            path, "optical_history"',
                      optical_extract)
        shard_helper = source.split("def _stream_history_shards(", 1)[1]
        shard_helper = shard_helper.split("\ndef ", 1)[0]
        self.assertIn('_stream_history(\n            shard, "history"',
                      shard_helper)

    def test_ai_correlate_merges_shards(self):
        source = self._read("html/ai_correlate.py")
        self.assertIn("def _load_optical_current_stats(mr_dir):", source)
        self.assertIn('os.path.join(mr_dir, "optical-history")', source)
        self.assertIn('"optical-history/",', source)

    def test_fabric_api_prefers_the_device_shard(self):
        source = self._read("html/fabric-api.sh")
        self.assertIn(
            "os.path.join(monitor_dir, 'optical-history')", source
        )
        self.assertIn(
            "os.path.join('optical-history', device + '.json')", source
        )
        self.assertIn("'current_optical_stats': shard_payload.get('current')",
                      source)

    def test_monitor_registers_the_shard_directory(self):
        source = self._read("lldpq/monitor.sh")
        self.assertIn("    optical-history/\n", source)
        # The monolith stays listed so the one-time migration remains inside
        # the rollback transaction.
        self.assertIn(
            "optical-analysis.html optical_history.json optical-details/",
            source,
        )
        self.assertIn('"$stage_dir/optical-history" \\', source)
        self.assertIn(
            "optical-analysis.html optical-history optical-data", source
        )
        self.assertIn(
            "optical-analysis.html optical-history/ optical-details/", source
        )


if __name__ == "__main__":
    unittest.main()
