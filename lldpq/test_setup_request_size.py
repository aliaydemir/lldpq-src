#!/usr/bin/env python3
"""Exercise the real Setup request reader without invoking its action dispatch."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SETUP_API = ROOT / "html" / "setup-api.sh"
REQUEST_LIMIT = 64 * 1024 * 1024


def private_request_reader():
    lines = SETUP_API.read_text().splitlines()
    start = lines.index("python3 << 'PYTHON'") + 1
    end = lines.index("PYTHON", start)
    tree = ast.parse("\n".join(lines[start:end]))
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "read_private_request_json"
    ]
    if len(functions) != 1:
        raise AssertionError("expected exactly one private request reader")
    namespace = {"os": os, "stat": stat, "json": json}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SETUP_API), "exec"), namespace)
    return namespace["read_private_request_json"]


class SetupRequestSizeTests(unittest.TestCase):
    def setUp(self):
        self.reader = private_request_reader()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.request = Path(self.temporary.name) / "request.json"

    def _write_padded_request(self, size):
        # Whitespace exercises the byte limit without constructing a giant
        # decoded JSON value or running any Setup action.
        payload = b'{"action":"test-only"}'
        with self.request.open("wb") as output:
            output.write(payload)
            remaining = size - len(payload)
            chunk = b" " * (1024 * 1024)
            while remaining:
                written = output.write(chunk[:min(remaining, len(chunk))])
                remaining -= written
        self.request.chmod(0o600)
        self.assertEqual(self.request.stat().st_size, size)

    def test_shell_request_limit_matches_python_boundary(self):
        matches = re.findall(r"^MAX_JSON_BYTES=(\d+)$", SETUP_API.read_text(), re.MULTILINE)
        self.assertEqual(matches, [str(REQUEST_LIMIT)])

    def test_exactly_64_mib_is_accepted_and_private_buffer_is_unlinked(self):
        self._write_padded_request(REQUEST_LIMIT)
        with mock.patch.dict(os.environ, {"POST_DATA_FILE": str(self.request)}):
            self.assertEqual(self.reader(), {"action": "test-only"})
        self.assertFalse(self.request.exists())

    def test_one_byte_over_64_mib_is_rejected_and_private_buffer_is_unlinked(self):
        self._write_padded_request(REQUEST_LIMIT + 1)
        with mock.patch.dict(os.environ, {"POST_DATA_FILE": str(self.request)}):
            with self.assertRaisesRegex(ValueError, "JSON request exceeds the 64 MiB limit"):
                self.reader()
        self.assertFalse(self.request.exists())

    def test_full_32_mib_backup_fits_after_base64_and_json_envelope(self):
        # Read the actual bundle bound without loading privileged restore code.
        source = ROOT / "lldpq" / "backup_import.py"
        constants = [
            node for node in ast.parse(source.read_text()).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "MAX_BUNDLE_BYTES"
                    for target in node.targets)
        ]
        self.assertEqual(len(constants), 1)
        namespace = {}
        exec(compile(ast.Module(body=constants, type_ignores=[]), str(source), "exec"), namespace)
        bundle_bytes = namespace["MAX_BUNDLE_BYTES"]
        self.assertEqual(bundle_bytes, 32 * 1024 * 1024)
        base64_bytes = 4 * ((bundle_bytes + 2) // 3)
        envelope_bytes = len(json.dumps({"action": "backup-import", "data": ""}, separators=(",", ":")).encode())
        self.assertLessEqual(base64_bytes + envelope_bytes, REQUEST_LIMIT)


if __name__ == "__main__":
    unittest.main()
