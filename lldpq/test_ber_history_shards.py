#!/usr/bin/env python3
"""Per-device BER history shards (ber-history/) and their consumers.

Mirrors the PFC/ECN shard contract: slim per-sample records, one-time
monolith migration inside the analyzer transaction, retired-host pruning,
and shard-first fallback readers in check_alerts / ai-api / ai_insights /
ai_correlate.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from ber_analyzer import BERAnalyzer


def _record(ts, **extra):
    base = {
        "timestamp": ts,
        "ber_value": 0.0,
        "grade": "excellent",
        "sample_status": "analyzed",
        "rx_packets": 1000,
        "tx_packets": 1000,
        "rx_errors": 0,
        "tx_errors": 0,
        "total_packets": 2000,
        "delta_rx_errors": 0,
        "delta_tx_errors": 0,
        "sample_duration_seconds": 60,
    }
    base.update(extra)
    return base


class BerShardFunctionalTests(unittest.TestCase):
    def _tmp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return temporary.name

    def test_save_writes_only_dirty_hosts_with_slim_records(self):
        tmp = self._tmp()
        analyzer = BERAnalyzer(tmp)
        now = time.time()
        analyzer.ber_history = {
            "leaf1:swp1": [
                _record(now - 100, symbol_errors=42,
                        delta_rx_errors=3, delta_tx_errors=1),
                # Combined status equal to the frame grade stays implicit.
                _record(now - 70, grade="good", effective_grade="good"),
                # An L1-escalated combined status differing from the frame
                # grade is persisted so ai_insights can see the transition.
                _record(now - 40, grade="good", effective_grade="critical"),
            ],
            "leaf2:swp9": [_record(now - 50)],
        }
        analyzer.current_ber_stats = {
            "leaf1:swp1": _record(now, effective_grade="excellent"),
        }
        self.assertTrue(analyzer.save_ber_history())
        shard_dir = Path(tmp) / "ber-history"
        names = sorted(p.name for p in shard_dir.glob("*.json"))
        # leaf2 carries no current-run evidence: its shard is not rewritten.
        self.assertEqual(names, ["leaf1.json"])
        shard = json.loads((shard_dir / "leaf1.json").read_text())
        rows = shard["history"]["leaf1:swp1"]
        self.assertEqual(
            set(rows[0]),
            {"timestamp", "ber_value", "grade", "sample_status",
             "symbol_errors", "delta_errors"},
        )
        self.assertEqual(rows[0]["symbol_errors"], 42)
        self.assertEqual(rows[0]["delta_errors"], 4)
        # status is additive and conditional: only a combined status that
        # differs from the frame grade is persisted.
        self.assertEqual(
            set(rows[1]),
            {"timestamp", "ber_value", "grade", "sample_status"},
        )
        self.assertEqual(
            set(rows[2]),
            {"timestamp", "ber_value", "grade", "sample_status", "status"},
        )
        self.assertEqual(rows[2]["status"], "critical")
        # The current record stays complete for the detail panel.
        self.assertEqual(
            shard["current"]["leaf1:swp1"]["effective_grade"], "excellent")
        # Producer digest sidecar rides every shard.
        self.assertTrue((shard_dir / "leaf1.json.sha256").exists())

    def test_reload_round_trip_from_shards(self):
        tmp = self._tmp()
        analyzer = BERAnalyzer(tmp)
        now = time.time()
        analyzer.ber_history = {"leaf1:swp1": [_record(now - 10)]}
        analyzer.current_ber_stats = {"leaf1:swp1": _record(now)}
        self.assertTrue(analyzer.save_ber_history())
        reloaded = BERAnalyzer(tmp)
        self.assertIn("leaf1:swp1", reloaded.ber_history)
        self.assertIn("leaf1:swp1", reloaded.current_ber_stats)

    def test_malformed_shard_entries_are_dropped_not_fatal(self):
        tmp = self._tmp()
        now = time.time()
        shard_dir = Path(tmp) / "ber-history"
        shard_dir.mkdir()
        (shard_dir / "leaf1.json").write_text(json.dumps({
            "history": {
                "leaf1:swp1": [
                    {"ber_value": 0.0},          # missing timestamp
                    "not-a-dict",
                    {"timestamp": "yesterday"},  # unparseable timestamp
                    _record(now - 30),
                ],
                "leaf1:swp2": "not-a-list",
            },
            "current": {},
        }))
        (shard_dir / "leaf2.json").write_text(json.dumps({
            "history": {"leaf2:swp1": [_record(now - 10)]},
            "current": {},
        }))
        # Construction runs cleanup_old_history on the loaded shards: shape
        # corruption must stay contained per entry/port, not raise out of
        # BERAnalyzer() and fail the whole analyzer run.
        analyzer = BERAnalyzer(tmp)
        self.assertEqual(len(analyzer.ber_history["leaf1:swp1"]), 1)
        self.assertNotIn("leaf1:swp2", analyzer.ber_history)
        self.assertIn("leaf2:swp1", analyzer.ber_history)

    def test_legacy_monolith_migrates_and_retires(self):
        tmp = self._tmp()
        now = time.time()
        monolith = {
            "ber_history": {
                "leaf1:swp1": [_record(now - 10)],
                "leaf9:swp2": [_record(now - 20)],
            },
            "current_ber_stats": {"leaf1:swp1": _record(now - 10)},
        }
        (Path(tmp) / "ber_history.json").write_text(json.dumps(monolith))
        analyzer = BERAnalyzer(tmp)
        self.assertTrue(analyzer._legacy_history_loaded)
        self.assertTrue(analyzer.save_ber_history())
        self.assertFalse((Path(tmp) / "ber_history.json").exists(),
                         "monolith must retire after migration")
        names = sorted(
            p.name for p in (Path(tmp) / "ber-history").glob("*.json"))
        self.assertEqual(names, ["leaf1.json", "leaf9.json"])

    def test_unsafe_hostname_refused(self):
        tmp = self._tmp()
        analyzer = BERAnalyzer(tmp)
        analyzer.current_ber_stats = {"../evil:swp1": _record(time.time())}
        self.assertFalse(analyzer.save_ber_history())

    def test_prune_removes_retired_host_shards(self):
        tmp = self._tmp()
        analyzer = BERAnalyzer(tmp)
        now = time.time()
        analyzer.current_ber_stats = {
            "leaf1:swp1": _record(now),
            "leaf2:swp1": _record(now),
        }
        self.assertTrue(analyzer.save_ber_history())
        self.assertTrue(analyzer.prune_history_shards({"leaf1"}))
        names = sorted(
            p.name for p in (Path(tmp) / "ber-history").glob("*.json"))
        self.assertEqual(names, ["leaf1.json"])

    def test_clear_stale_shard_current_keeps_history(self):
        tmp = self._tmp()
        analyzer = BERAnalyzer(tmp)
        now = time.time()
        analyzer.ber_history = {"leaf2:swp1": [_record(now - 60)]}
        analyzer.current_ber_stats = {
            "leaf1:swp1": _record(now),
            "leaf2:swp1": _record(now),
        }
        self.assertTrue(analyzer.save_ber_history())
        # leaf2 misses the next collection: its persisted current must be
        # emptied while its history survives.
        self.assertTrue(analyzer.clear_stale_shard_current({"leaf1"}))
        shard_dir = Path(tmp) / "ber-history"
        leaf2 = json.loads((shard_dir / "leaf2.json").read_text())
        self.assertEqual(leaf2["current"], {})
        self.assertIn("leaf2:swp1", leaf2["history"])
        leaf1 = json.loads((shard_dir / "leaf1.json").read_text())
        self.assertIn("leaf1:swp1", leaf1["current"])


class BerShardConsumerContractTests(unittest.TestCase):
    """Every reader of the former monolith must be shard-first."""

    def test_check_alerts_reads_the_device_shard_first(self):
        source = (SCRIPT_DIR / "check_alerts.py").read_text(encoding="utf-8")
        self.assertIn('"ber-history" / f"{device}.json"', source)
        self.assertIn('payload.get("current", {})', source)

    def test_ai_api_merges_shards_with_monolith_fallback(self):
        source = (SCRIPT_DIR.parent / "html" / "ai-api.sh").read_text(
            encoding="utf-8")
        self.assertIn("def _load_ber_current_stats(hosts=None):", source)
        self.assertEqual(source.count("_load_ber_current_stats("), 3)
        self.assertIn("os.path.isdir(_mr_path('ber-history'))", source)

    def test_ai_insights_streams_shards(self):
        source = (SCRIPT_DIR.parent / "html" / "ai_insights.py").read_text(
            encoding="utf-8")
        self.assertIn("def _ber_history_source(", source)
        # Pin the shard-first source wiring, not the tuple arity.
        self.assertIn('("ber", _extract_ber, _ber_history_source(monitor, web)',
                      source)

    def test_ai_correlate_merges_shards(self):
        source = (SCRIPT_DIR.parent / "html" / "ai_correlate.py").read_text(
            encoding="utf-8")
        self.assertIn("def _load_ber_current_stats(mr_dir):", source)
        self.assertIn('os.path.join(mr_dir, "ber-history")', source)

    def test_monitor_registers_the_shard_directory(self):
        source = (SCRIPT_DIR / "monitor.sh").read_text(encoding="utf-8")
        self.assertIn("ber-history/", source)
        # Scoped BER runs overlay the shard directory, not the monolith.
        self.assertIn(
            "ber-analysis.html ber_baseline.json ber-data ber-history",
            source,
        )


if __name__ == "__main__":
    unittest.main()
