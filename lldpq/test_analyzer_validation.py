#!/usr/bin/env python3
"""Fail-closed and timing contracts for parallel analyzer JSON validation."""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lldpq import validate_analysis_json


ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")


class AnalyzerValidationTests(unittest.TestCase):
    def test_valid_and_invalid_json_are_fully_parsed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "valid.json").write_text('{"ok":[1,2,3]}\n', encoding="utf-8")
            (root / "invalid.json").write_text('{"broken":\n', encoding="utf-8")
            results = validate_analysis_json.validate_json_files(
                root, ["valid.json", "invalid.json"], max_workers=2
            )
        self.assertEqual([item[0] for item in results], ["valid.json", "invalid.json"])
        self.assertIsNone(results[0][2])
        self.assertIsNotNone(results[1][2])

    def test_cli_reports_all_errors_and_timings_in_input_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("second.json", "first.json"):
                (root / name).write_text("{bad", encoding="utf-8")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = validate_analysis_json.main([
                    str(root), "second.json", "first.json"
                ])
        self.assertEqual(status, 1)
        self.assertLess(stdout.getvalue().index("second.json"), stdout.getvalue().index("first.json"))
        self.assertIn("Invalid analysis JSON second.json", stderr.getvalue())
        self.assertIn("Invalid analysis JSON first.json", stderr.getvalue())

    def test_worker_limit_is_bounded(self):
        worker_counts = []

        class ImmediateFuture:
            def __init__(self, value):
                self.value = value

            def result(self):
                return self.value

        class FakeExecutor:
            def __init__(self, max_workers):
                worker_counts.append(max_workers)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def submit(self, function, *args):
                return ImmediateFuture(function(*args))

        with mock.patch.object(
            validate_analysis_json, "ProcessPoolExecutor", FakeExecutor
        ):
            results = validate_analysis_json.validate_json_files(
                Path("/tmp"), [], max_workers=8
            )
            self.assertEqual(results, [])
            results = validate_analysis_json.validate_json_files(
                Path("/tmp"), ["a.json", "b.json", "c.json"], max_workers=8
            )
        self.assertEqual(worker_counts, [2])
        self.assertEqual([item[0] for item in results], [
            "a.json", "b.json", "c.json"
        ])

    def test_process_pool_failure_falls_back_to_full_sequential_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one.json").write_text('{"ok":1}', encoding="utf-8")
            (root / "two.json").write_text('{"ok":2}', encoding="utf-8")
            with mock.patch.object(
                validate_analysis_json,
                "ProcessPoolExecutor",
                side_effect=PermissionError("simulated constrained runtime"),
            ):
                results = validate_analysis_json.validate_json_files(
                    root, ["one.json", "two.json"], max_workers=2
                )
        self.assertEqual([item[0] for item in results], ["one.json", "two.json"])
        self.assertTrue(all(item[2] is None for item in results))

    def test_monitor_preserves_precheck_and_rollback_contract(self):
        self.assertIn('[[ ! -f "$path" || ! -s "$path" || "$path" -ot "$marker" ]]', MONITOR)
        self.assertIn('python3 "$SCRIPT_DIR/validate_analysis_json.py"', MONITOR)
        failure = MONITOR.split(
            'if ! validate_analysis_outputs "$analysis_output_marker"; then', 1
        )[1].split("fi", 1)[0]
        self.assertIn("rollback_analysis_state", failure)
        self.assertIn('mark_reports_stale "analysis outputs were incomplete"', failure)
        self.assertIn("exit 1", failure)


if __name__ == "__main__":
    unittest.main()
