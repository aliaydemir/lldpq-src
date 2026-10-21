"""Large topology export/restore regression tests, including exact size limits."""

import base64
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import backup_import
import test_bmc_api as backup_fixture


REPO = Path(__file__).resolve().parent.parent


def topology_bytes(size):
    prefix = b'graph {\n"leaf":"swp1" -- "server":"eth0";\n# '
    suffix = b'\n}\n'
    return prefix + b'x' * (size - len(prefix) - len(suffix)) + suffix


def bundle_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            backup_import.add_regular_tar_member(archive, name, content)
    return buffer.getvalue()


def parse_bundle(files):
    return backup_import._parse_bundle(
        bundle_bytes(files), {name: str(REPO / "lldpq") for name in files},
        set(), set(), lambda _value: True, str(REPO / "lldpq"),
    )


class TopologyBackupSizeTest(unittest.TestCase):
    def test_one_byte_over_topology_limit_fails_collection_export_and_import(self):
        content = topology_bytes(backup_import.MAX_TOPOLOGY_BYTES + 1)
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "topology.dot"
            target.write_bytes(content)
            with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
                backup_import.collect_managed_config_files([("topology.dot", root)], (root,))
        with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
            backup_import.validate_config_for_bundle("topology.dot", content, lldpq_dir=str(REPO / "lldpq"))
        with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
            parse_bundle({"topology.dot": content})

    def test_other_config_files_keep_two_mib_limit(self):
        prefix = b'version: 1\ndefault_state: commissioning\nswitches: {}\n# '
        for size in (backup_import.MAX_CONFIG_BYTES, backup_import.MAX_CONFIG_BYTES + 1):
            content = prefix + b'x' * (size - len(prefix))
            with self.subTest(size=size), tempfile.TemporaryDirectory() as root:
                target = Path(root) / "tracking.yaml"
                target.write_bytes(content)
                if size == backup_import.MAX_CONFIG_BYTES:
                    self.assertEqual(
                        backup_import.collect_managed_config_files([("tracking.yaml", root)], (root,)),
                        [("tracking.yaml", content)],
                    )
                    self.assertTrue(backup_import.validate_config_for_bundle(
                        "tracking.yaml", content, lldpq_dir=str(REPO / "lldpq"),
                    ))
                    entries, _ = parse_bundle({"tracking.yaml": content})
                    self.assertEqual(entries[0]["content"], content)
                else:
                    with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
                        backup_import.collect_managed_config_files([("tracking.yaml", root)], (root,))
                    with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
                        backup_import.validate_config_for_bundle(
                            "tracking.yaml", content, lldpq_dir=str(REPO / "lldpq"),
                        )
                    with self.assertRaisesRegex(backup_import.BackupImportError, "too large"):
                        parse_bundle({"tracking.yaml": content})

    def test_graphviz_checks_syntax_without_laying_out_the_graph(self):
        valid = 'graph {\n"leaf":"swp1" -- "server":"eth0";\n}\n'
        with mock.patch.object(backup_import.shutil, "which", return_value="/fixture/dot"), \
                mock.patch.object(backup_import.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "", "")
            backup_import._validate_project_topology_dot(valid, "/fixture/topology.dot")
            self.assertEqual(run.call_args.args[0][1], "-Tcanon")
            run.return_value = subprocess.CompletedProcess([], 1, "", "syntax error")
            with self.assertRaisesRegex(backup_import.BackupImportError, "syntax error"):
                backup_import._validate_project_topology_dot(valid, "/fixture/topology.dot")
            # The stronger LLDPq endpoint check still runs before Graphviz.
            with self.assertRaisesRegex(backup_import.BackupImportError, "reused"):
                backup_import._validate_project_topology_dot(
                    valid.replace('}\n', '"leaf":"swp1" -- "server2":"eth0";\n}\n'),
                    "/fixture/topology.dot",
                )


class TopologySetupBackupRoundTripTest(backup_fixture.BMCSetupBackupRoundTripTest):
    """Reuse the isolated real Setup export/restore transaction fixture."""

    def test_large_topology_round_trip_and_oversize_restore_preserve_saved_file(self):
        # Native topology is shared through the application symlink. Docker
        # additionally points the web path at its managed config directory.
        for use_config_link, size in (
            (False, backup_import.MAX_CONFIG_BYTES + 1),
            (True, backup_import.MAX_TOPOLOGY_BYTES),
        ):
            with self.subTest(managed_config_link=use_config_link, size=size):
                logical = self.web / "topology.dot"
                application_link = self.application / "topology.dot"
                if application_link.is_symlink():
                    application_link.unlink()
                if logical.exists():
                    logical.unlink()
                target = logical
                if use_config_link:
                    target = self.application / "config/topology.dot"
                    target.parent.mkdir(exist_ok=True)
                    logical.symlink_to(target)
                application_link.symlink_to(logical)
                original = topology_bytes(size)
                target.write_bytes(original)
                exported = self.call_setup("backup-export", {"include_key": False})
                self.assertTrue(exported["success"], exported)
                self.assertIn("topology.dot", exported["files"])
                target.write_text('graph {\n"a":"p1" -- "b":"p2";\n}\n')
                restored = self.call_setup("backup-import", {"data": exported["data"]})
                self.assertTrue(restored["success"], restored)
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(logical.is_symlink(), use_config_link)
                self.assertTrue(application_link.is_symlink())
                self.assertFalse((self.home / ".lldpq-state/.backup-import-recovery").exists())

                oversized = bundle_bytes({
                    "topology.dot": topology_bytes(backup_import.MAX_TOPOLOGY_BYTES + 1),
                })
                rejected = self.call_setup("backup-import", {
                    "data": base64.b64encode(oversized).decode(),
                })
                self.assertFalse(rejected["success"], rejected)
                self.assertIn("too large", rejected["error"])
                self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
