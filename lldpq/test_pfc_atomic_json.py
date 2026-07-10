#!/usr/bin/env python3
"""Regression tests for memory-bounded atomic PFC state serialization."""

from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest import mock

from lldpq.process_pfc_ecn_data import _atomic_json


class PfcAtomicJsonTests(unittest.TestCase):
    def test_streams_compact_json_without_json_dumps_buffer(self):
        value = {
            "version": 1,
            "history": {
                f"leaf:swp{index}": [{"timestamp": index, "value": index}]
                for index in range(500)
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            with mock.patch(
                "lldpq.process_pfc_ecn_data.json.dumps",
                side_effect=AssertionError("full JSON buffer must not be built"),
            ):
                _atomic_json(path, value)
            text = path.read_text(encoding="utf-8")
        self.assertEqual(json.loads(text), value)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\n  ", text)

    def test_failed_replace_preserves_previous_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            original = '{"old":true}\n'
            path.write_text(original, encoding="utf-8")
            os.chmod(path, 0o640)
            with mock.patch(
                "lldpq.process_pfc_ecn_data.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    _atomic_json(path, {"new": True})
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
