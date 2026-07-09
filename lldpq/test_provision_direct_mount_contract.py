#!/usr/bin/env python3
"""Contracts for Provision's legacy direct-file mount preflight."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "html" / "provision-api.sh"


def embedded_python() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    opener = "python3 << 'PYTHON_SCRIPT'\n"
    start = text.index(opener) + len(opener)
    end = text.rindex("\nPYTHON_SCRIPT")
    return text[start:end]


def load_functions(*names, namespace=None):
    source = embedded_python()
    tree = ast.parse(source, filename=str(SCRIPT))
    selected = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in names
    ]
    if {node.name for node in selected} != set(names):
        raise AssertionError("Provision helper function is missing")
    module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(module)
    values = dict(namespace or {})
    exec(compile(module, str(SCRIPT), "exec"), values)
    return values


class ProvisionDirectMountContractTests(unittest.TestCase):
    def test_embedded_python_is_syntactically_valid(self):
        compile(embedded_python(), str(SCRIPT), "exec")

    def test_mount_detection_requires_exact_decoded_file_mountpoint(self):
        values = load_functions(
            "_mountinfo_path",
            "is_direct_file_mount",
            namespace={"os": os, "stat": stat},
        )
        metadata = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o640)
        mountinfo = (
            "30 20 0:1 / /home/lldpq/lldpq rw - overlay overlay rw\n"
            "31 30 0:2 / /home/lldpq/lldpq/devices\\040file.yaml rw "
            "- ext4 /dev/root rw\n"
        )
        with (
            mock.patch.object(os, "stat", return_value=metadata),
            mock.patch.object(os.path, "realpath", side_effect=lambda value: value),
            mock.patch("builtins.open", mock.mock_open(read_data=mountinfo)),
        ):
            self.assertTrue(values["is_direct_file_mount"](
                "/home/lldpq/lldpq/devices file.yaml"
            ))
            self.assertFalse(values["is_direct_file_mount"](
                "/home/lldpq/lldpq/devices file.yaml/child"
            ))

    def test_transaction_rejects_changing_direct_mount_before_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "transaction.json"
            snapshot_calls = []

            def snapshot(path):
                snapshot_calls.append(path)
                return {"exists": True, "content": b"old"}

            values = load_functions(
                "begin_provision_transaction",
                namespace={
                    "os": os,
                    "PROVISION_TRANSACTION_FILE": str(marker),
                    "is_direct_file_mount": lambda _path: True,
                    "snapshot_file": snapshot,
                    "direct_file_mount_error": lambda path: RuntimeError(
                        "direct mount: " + path
                    ),
                },
            )

            with self.assertRaisesRegex(RuntimeError, "direct mount"):
                values["begin_provision_transaction"](
                    "inventory-save",
                    [("/home/lldpq/lldpq/devices.yaml", "new", 0o664)],
                    None,
                    None,
                )

            self.assertEqual(
                snapshot_calls, ["/home/lldpq/lldpq/devices.yaml"]
            )
            self.assertFalse(marker.exists())

    def test_atomic_writer_has_direct_mount_noop_or_fail_preflight(self):
        source = embedded_python()
        tree = ast.parse(source, filename=str(SCRIPT))
        writer = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "atomic_write_text"
        )
        rendered = ast.get_source_segment(source, writer) or ""
        self.assertIn("is_direct_file_mount(normalized_path)", rendered)
        self.assertIn("raise direct_file_mount_error(logical_path)", rendered)


if __name__ == "__main__":
    unittest.main()
