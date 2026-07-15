#!/usr/bin/env python3
"""Regression tests for the per-device PFC/ECN history shard store."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import analysis_sidecar
import process_pfc_ecn_data as analyzer
import validate_analysis_json


RAW_PORT = """\
__LLDPQ_PFC_ECN_INVENTORY_STATUS__:OK:1
__LLDPQ_PFC_ECN_PORT_START__:swp1
__LLDPQ_PFC_ECN_PORT_STATUS__:swp1:ERROR:124
PFC/ECN command timed out
__LLDPQ_PFC_ECN_PORT_END__:swp1
"""


class PfcEcnHistoryShardTests(unittest.TestCase):
    def setUp(self):
        # Deterministic, spawn-free test runs.
        self._env = mock.patch.dict(
            os.environ, {"PFC_ECN_SHARD_MAX_PARALLEL": "1"}
        )
        self._env.start()
        self.addCleanup(self._env.stop)

    def _run(self, result_dir: Path, statuses):
        data_dir = result_dir / "pfc-ecn-data"
        snapshot = (dict(statuses), 0.0, True)
        with (
            mock.patch.object(analyzer, "read_asset_snapshot", return_value=snapshot),
            mock.patch.object(analyzer, "asset_snapshot_is_valid", return_value=True),
            mock.patch.object(
                analyzer, "asset_snapshot_is_authoritative", return_value=True
            ),
            mock.patch.object(analyzer, "is_current_collection", return_value=True),
        ):
            return analyzer.process_pfc_ecn_data_files(str(data_dir))

    def _result_tree(self, hosts):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        result_dir = Path(temporary.name) / "monitor-results"
        data_dir = result_dir / "pfc-ecn-data"
        data_dir.mkdir(parents=True)
        for hostname in hosts:
            (data_dir / f"{hostname}_pfc_ecn.txt").write_text(
                RAW_PORT, encoding="utf-8"
            )
        return result_dir

    def test_fresh_run_writes_per_device_shards_with_sidecars(self):
        result_dir = self._result_tree(["leaf1", "leaf2"])
        self.assertTrue(self._run(result_dir, {"leaf1": "OK", "leaf2": "OK"}))

        shard_dir = result_dir / "pfc-ecn-history"
        self.assertFalse((result_dir / "pfc_ecn_history.json").exists())
        for hostname in ("leaf1", "leaf2"):
            shard = shard_dir / f"{hostname}.json"
            state = json.loads(shard.read_text(encoding="utf-8"))
            self.assertEqual(state["host"], hostname)
            self.assertEqual(len(state["history"][f"{hostname}:swp1"]), 1)
            self.assertTrue(analysis_sidecar.sidecar_matches(shard))

        # The whole shard directory validates as one contract entry.
        results = validate_analysis_json.validate_json_files(
            result_dir, ["pfc-ecn-history/"], max_workers=1
        )
        self.assertIsNone(results[0][2])

    def test_second_run_appends_to_existing_shard(self):
        result_dir = self._result_tree(["leaf1"])
        self.assertTrue(self._run(result_dir, {"leaf1": "OK"}))
        self.assertTrue(self._run(result_dir, {"leaf1": "OK"}))
        shard = result_dir / "pfc-ecn-history" / "leaf1.json"
        state = json.loads(shard.read_text(encoding="utf-8"))
        self.assertEqual(len(state["history"]["leaf1:swp1"]), 2)

    def test_legacy_monolith_migrates_into_shards(self):
        result_dir = self._result_tree(["leaf1"])
        legacy_record = {
            "timestamp": time.time() - 60,
            "sample_status": "analyzed",
            "signal": "none",
            "deltas": {},
        }
        (result_dir / "pfc_ecn_history.json").write_text(
            json.dumps({
                "version": 1,
                "history": {
                    "leaf1:swp1": [legacy_record],
                    # leaf2 was collected in the past but is absent from this
                    # run; its shard must still be created by the migration.
                    "leaf2:swp7": [dict(legacy_record)],
                    # A host no longer in the inventory must be dropped.
                    "ghost:swp9": [dict(legacy_record)],
                },
            }),
            encoding="utf-8",
        )
        self.assertTrue(self._run(result_dir, {"leaf1": "OK", "leaf2": "OK"}))

        shard_dir = result_dir / "pfc-ecn-history"
        self.assertFalse((result_dir / "pfc_ecn_history.json").exists())
        leaf1 = json.loads((shard_dir / "leaf1.json").read_text(encoding="utf-8"))
        self.assertEqual(len(leaf1["history"]["leaf1:swp1"]), 2)
        leaf2 = json.loads((shard_dir / "leaf2.json").read_text(encoding="utf-8"))
        self.assertEqual(len(leaf2["history"]["leaf2:swp7"]), 1)
        self.assertFalse((shard_dir / "ghost.json").exists())

    def test_retired_host_shard_is_removed(self):
        result_dir = self._result_tree(["leaf1"])
        shard_dir = result_dir / "pfc-ecn-history"
        shard_dir.mkdir()
        (shard_dir / "retired.json").write_text(
            json.dumps({"version": 1, "host": "retired", "history": {}}),
            encoding="utf-8",
        )
        self.assertTrue(self._run(result_dir, {"leaf1": "OK"}))
        self.assertFalse((shard_dir / "retired.json").exists())
        self.assertTrue((shard_dir / "leaf1.json").exists())

    def test_old_samples_age_out_of_shards(self):
        result_dir = self._result_tree(["leaf1"])
        shard_dir = result_dir / "pfc-ecn-history"
        shard_dir.mkdir()
        (shard_dir / "leaf1.json").write_text(
            json.dumps({
                "version": 1,
                "host": "leaf1",
                "history": {
                    "leaf1:swp1": [
                        {"timestamp": time.time() - 2 * analyzer.HISTORY_SECONDS},
                        {"timestamp": time.time() - 60},
                    ],
                },
            }),
            encoding="utf-8",
        )
        self.assertTrue(self._run(result_dir, {"leaf1": "OK"}))
        state = json.loads(
            (shard_dir / "leaf1.json").read_text(encoding="utf-8")
        )
        stamps = [
            entry["timestamp"] for entry in state["history"]["leaf1:swp1"]
        ]
        self.assertEqual(len(stamps), 2)
        self.assertTrue(
            all(stamp >= time.time() - analyzer.HISTORY_SECONDS - 1 for stamp in stamps)
        )


if __name__ == "__main__":
    unittest.main()
