#!/usr/bin/env python3
"""Focused regression tests for switch-level lifecycle tracking."""

import grp
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import backup_import
from tracking_config import (
    TrackingConfigError,
    TrackingConflictError,
    TrackingValidationError,
    get_tracking_payload,
    save_tracking,
)


DEVICES_YAML = """\
defaults:
  username: cumulus
devices:
  10.0.0.1: LEAF-01 @leaf
  10.0.0.2:
    hostname: LEAF-02
    username: operator
    role: leaf
  10.0.0.3: SPINE-01 @spine
"""


class TrackingConfigTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.devices = self.root / "devices.yaml"
        self.tracking = self.root / "tracking.yaml"
        self.devices.write_text(DEVICES_YAML, encoding="utf-8")

    def payload(self):
        return get_tracking_payload(str(self.devices), str(self.tracking))

    def save(self, revision, switches, **kwargs):
        return save_tracking(
            str(self.devices),
            str(self.tracking),
            expected_revision=revision,
            handed_over_switches=switches,
            changed_by=kwargs.pop("changed_by", "admin"),
            changed_at=kwargs.pop("changed_at", "2026-07-07T10:00:00Z"),
            **kwargs,
        )

    def parse_bundle_files(self, files):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, content in files.items():
                backup_import.add_regular_tar_member(archive, name, content)
        lldpq_dir = str(Path(__file__).resolve().parent)
        entries, preferences = backup_import._parse_bundle(
            buffer.getvalue(),
            {name: lldpq_dir for name in files},
            set(),
            set(),
            lambda _value: True,
            lldpq_dir,
        )
        self.assertEqual(preferences, {})
        return entries

    def test_missing_tracking_defaults_every_device_to_commissioning(self):
        payload = self.payload()

        self.assertEqual(
            payload["counts"],
            {"total": 3, "commissioning": 3, "handed_over": 0},
        )
        self.assertEqual(payload["handed_over_switches"], [])
        self.assertEqual(
            [device["hostname"] for device in payload["devices"]],
            ["LEAF-01", "LEAF-02", "SPINE-01"],
        )
        self.assertTrue(
            all(device["state"] == "commissioning" for device in payload["devices"])
        )

    def test_save_preserves_unchanged_metadata_and_records_both_transitions(self):
        initial = self.payload()
        handed_over = self.save(
            initial["revision"],
            ["LEAF-01"],
            note="customer batch 1",
        )
        first_metadata = handed_over["devices"][0]
        self.assertEqual(handed_over["counts"]["handed_over"], 1)
        self.assertEqual(first_metadata["changed_by"], "admin")
        self.assertEqual(first_metadata["note"], "customer batch 1")

        unchanged = self.save(
            handed_over["revision"],
            ["LEAF-01"],
            changed_by="other-admin",
            changed_at="2026-07-07T11:00:00Z",
            note="must not replace unchanged metadata",
        )
        unchanged_metadata = unchanged["devices"][0]
        self.assertEqual(unchanged_metadata["changed_by"], "admin")
        self.assertEqual(unchanged_metadata["changed_at"], "2026-07-07T10:00:00Z")
        self.assertEqual(unchanged_metadata["note"], "customer batch 1")

        commissioned = self.save(
            unchanged["revision"],
            [],
            changed_by="other-admin",
            changed_at="2026-07-07T12:00:00Z",
            note="returned to deployment",
        )
        commissioned_metadata = commissioned["devices"][0]
        self.assertEqual(commissioned_metadata["state"], "commissioning")
        self.assertEqual(commissioned_metadata["changed_by"], "other-admin")
        self.assertEqual(
            commissioned_metadata["changed_at"], "2026-07-07T12:00:00Z"
        )
        stored = yaml.safe_load(self.tracking.read_text(encoding="utf-8"))
        self.assertEqual(stored["switches"]["LEAF-01"]["state"], "commissioning")

    def test_stale_revision_is_rejected_without_overwriting_current_state(self):
        initial = self.payload()
        current = self.save(initial["revision"], ["LEAF-01"])

        with self.assertRaises(TrackingConflictError) as caught:
            self.save(initial["revision"], ["SPINE-01"])

        self.assertEqual(caught.exception.revision, current["revision"])
        after = self.payload()
        self.assertEqual(after["handed_over_switches"], ["LEAF-01"])

    def test_save_requires_exact_unique_inventory_hostnames(self):
        revision = self.payload()["revision"]
        with self.assertRaisesRegex(TrackingValidationError, "Unknown switch"):
            self.save(revision, ["leaf-01"])
        with self.assertRaisesRegex(TrackingValidationError, "duplicate hostname"):
            self.save(revision, ["LEAF-01", "LEAF-01"])

    def test_normal_save_preserves_orphaned_transition_history(self):
        self.tracking.write_text(
            """\
version: 1
default_state: commissioning
switches:
  OLD-LEAF:
    state: handed_over
    changed_at: '2026-06-01T00:00:00Z'
    changed_by: admin
""",
            encoding="utf-8",
        )
        before = self.payload()
        self.assertEqual(before["orphaned_switches"], ["OLD-LEAF"])

        after = self.save(before["revision"], ["LEAF-02"])

        self.assertEqual(after["orphaned_switches"], ["OLD-LEAF"])
        stored = yaml.safe_load(self.tracking.read_text(encoding="utf-8"))
        self.assertIn("OLD-LEAF", stored["switches"])

    def test_inventory_change_is_part_of_revision(self):
        before = self.payload()
        self.devices.write_text(
            DEVICES_YAML.replace("SPINE-01 @spine", "SPINE-02 @spine"),
            encoding="utf-8",
        )
        after = self.payload()

        self.assertNotEqual(before["revision"], after["revision"])
        with self.assertRaises(TrackingConflictError):
            self.save(before["revision"], [])

    def test_parser_rejects_fields_not_supported_by_backup_schema(self):
        self.tracking.write_text(
            "version: 1\ndefault_state: commissioning\nswitches: {}\nextra: true\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(TrackingValidationError, "unsupported keys"):
            self.payload()

        self.tracking.write_text(
            """\
version: 1
default_state: commissioning
switches:
  LEAF-01:
    state: handed_over
    unsupported: true
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(TrackingValidationError, "unsupported fields"):
            self.payload()

        self.tracking.write_text(
            """\
version: 1
default_state: commissioning
switches:
  LEAF-01:
    state: handed_over
    note: ''
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(TrackingValidationError, "note.*invalid"):
            self.payload()
        with self.assertRaisesRegex(
            backup_import.BackupImportError, "note.*invalid"
        ):
            backup_import.validate_tracking_config(
                {
                    "version": 1,
                    "default_state": "commissioning",
                    "switches": {
                        "LEAF-01": {"state": "handed_over", "note": ""}
                    },
                }
            )

    def test_save_json_cli_writes_as_the_invoking_file_owner(self):
        initial = self.payload()
        module = Path(__file__).resolve().with_name("tracking_config.py")
        group = grp.getgrgid(os.getgid()).gr_name
        completed = subprocess.run(
            [
                sys.executable,
                str(module),
                "save-json",
                "--devices",
                str(self.devices),
                "--tracking",
                str(self.tracking),
                "--changed-by",
                "admin",
                "--file-group",
                group,
            ],
            input=json.dumps(
                {
                    "revision": initial["revision"],
                    "handed_over_switches": ["LEAF-02"],
                }
            ),
            capture_output=True,
            text=True,
            check=True,
        )
        response = json.loads(completed.stdout)

        self.assertTrue(response["success"])
        self.assertEqual(response["handed_over_switches"], ["LEAF-02"])
        self.assertEqual(self.tracking.stat().st_gid, os.getgid())
        self.assertEqual(self.tracking.stat().st_mode & 0o777, 0o664)

    def test_backup_bundle_round_trip_preserves_orphan_history(self):
        tracking = b"""\
version: 1
default_state: commissioning
switches:
  MISSING-LEAF:
    state: handed_over
"""
        lldpq_dir = str(Path(__file__).resolve().parent)
        backup_import.validate_config_for_bundle(
            "devices.yaml", DEVICES_YAML.encode("utf-8"), lldpq_dir=lldpq_dir
        )
        backup_import.validate_config_for_bundle(
            "tracking.yaml", tracking, lldpq_dir=lldpq_dir
        )

        entries = self.parse_bundle_files(
            {"devices.yaml": DEVICES_YAML.encode("utf-8"), "tracking.yaml": tracking}
        )

        restored = {entry["name"]: entry["content"] for entry in entries}
        self.assertEqual(restored["tracking.yaml"], tracking)

    def test_legacy_bundle_without_tracking_remains_accepted(self):
        self.tracking.write_text(
            """\
version: 1
default_state: commissioning
switches:
  OLD-LEAF:
    state: handed_over
""",
            encoding="utf-8",
        )
        entries = self.parse_bundle_files(
            {"devices.yaml": DEVICES_YAML.encode("utf-8")}
        )

        # Restore only stages recognized archive entries, so an installed
        # tracking.yaml remains untouched when the legacy bundle omits it.
        self.assertEqual([entry["name"] for entry in entries], ["devices.yaml"])

    def test_backup_tracking_parser_rejects_unsupported_non_string_key(self):
        with self.assertRaisesRegex(
            backup_import.BackupImportError, "unsupported keys"
        ):
            backup_import.validate_tracking_config(
                {
                    "version": 1,
                    "default_state": "commissioning",
                    "switches": {},
                    7: True,
                }
            )

    def test_save_preserves_managed_docker_config_symlink(self):
        config_dir = self.root / "config"
        config_dir.mkdir()
        persistent = config_dir / "tracking.yaml"
        persistent.write_text(
            "version: 1\ndefault_state: commissioning\nswitches: {}\n",
            encoding="utf-8",
        )
        self.tracking.symlink_to(persistent)
        initial = self.payload()

        saved = self.save(initial["revision"], ["SPINE-01"])

        self.assertTrue(self.tracking.is_symlink())
        self.assertEqual(saved["handed_over_switches"], ["SPINE-01"])
        stored = yaml.safe_load(persistent.read_text(encoding="utf-8"))
        self.assertEqual(stored["switches"]["SPINE-01"]["state"], "handed_over")

    def test_save_rejects_tracking_symlink_outside_managed_directory(self):
        outside_root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: outside_root.rmdir())
        outside = outside_root / "tracking.yaml"
        outside.write_text(
            "version: 1\ndefault_state: commissioning\nswitches: {}\n",
            encoding="utf-8",
        )
        self.addCleanup(outside.unlink)
        self.tracking.symlink_to(outside)
        initial = self.payload()

        with self.assertRaisesRegex(
            TrackingConfigError, "outside the managed LLDPq directory"
        ):
            self.save(initial["revision"], ["LEAF-01"])

    def test_save_rejects_tracking_symlink_to_other_managed_file(self):
        other = self.root / "other.yaml"
        other.write_text(
            "version: 1\ndefault_state: commissioning\nswitches: {}\n",
            encoding="utf-8",
        )
        self.tracking.symlink_to(other)
        initial = self.payload()

        with self.assertRaisesRegex(
            TrackingConfigError, "not the managed Docker config target"
        ):
            self.save(initial["revision"], ["LEAF-01"])


class DockerRecoveryStartupTest(unittest.TestCase):
    def test_fresh_docker_config_has_no_recovery_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "system-config").mkdir()
            with (
                mock.patch.object(
                    backup_import, "_docker_environment", return_value=True
                ),
                mock.patch.object(
                    backup_import, "_secure_list_dir", return_value=[]
                ),
                mock.patch.object(backup_import, "_ensure_recovery_base") as ensure,
            ):
                result = backup_import._load_recovery_authority(
                    lldpq_dir=str(root),
                    web_root=str(root / "web"),
                    user="lldpq",
                    allowed={},
                    key_names=set(),
                    ssh_dir=str(root / ".ssh"),
                )

            self.assertIsNone(result)
            ensure.assert_not_called()

    def test_docker_recovery_base_uses_shared_setgid_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "system-config"
            base.mkdir()
            os.chmod(base, 0o750)
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            group = SimpleNamespace(gr_gid=os.getgid())
            real_stat = os.stat

            def apply_directory_metadata(_user, _script, path, _gid, **_kwargs):
                return SimpleNamespace(stdout=b"", stderr=b"", returncode=0)

            def docker_stat(path, *args, **kwargs):
                metadata = real_stat(path, *args, **kwargs)
                if (
                    os.fspath(path) == os.fspath(base)
                    and kwargs.get("follow_symlinks") is False
                ):
                    return SimpleNamespace(
                        st_uid=account.pw_uid,
                        st_gid=group.gr_gid,
                        st_mode=(metadata.st_mode & ~0o7777) | 0o2770,
                    )
                return metadata

            with (
                mock.patch.object(
                    backup_import, "_docker_environment", return_value=True
                ),
                mock.patch.object(
                    backup_import.pwd, "getpwnam", return_value=account
                ),
                mock.patch.object(
                    backup_import.grp, "getgrnam", return_value=group
                ),
                mock.patch.object(
                    backup_import,
                    "_collector_shell",
                    side_effect=apply_directory_metadata,
                ) as collector_shell,
                mock.patch.object(backup_import.os, "stat", side_effect=docker_stat),
                mock.patch.object(backup_import, "_durable_path"),
            ):
                backup_import._ensure_recovery_base("lldpq", str(base))

            command = collector_shell.call_args.args
            self.assertIn('chmod -- 2770 "$1"', command[1])
            self.assertEqual(command[2:], (str(base), str(os.getgid())))

    def test_docker_recovery_base_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real-config").mkdir()
            (root / "system-config").symlink_to(root / "real-config")
            with mock.patch.object(
                backup_import, "_docker_environment", return_value=True
            ):
                with self.assertRaisesRegex(
                    backup_import.BackupImportError, "may not be a symlink"
                ):
                    backup_import._recovery_base(str(root), "lldpq")

    def test_recovery_authority_clears_inherited_shared_directory_bits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "system-config"
            recovery = base / backup_import.RECOVERY_DIR_NAME
            account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            completed = SimpleNamespace(stdout=b"", stderr=b"", returncode=0)
            with (
                mock.patch.object(
                    backup_import, "_recovery_base", return_value=str(base)
                ),
                mock.patch.object(backup_import, "_ensure_recovery_base"),
                mock.patch.object(backup_import, "_cleanup_recovery_debris"),
                mock.patch.object(
                    backup_import.pwd, "getpwnam", return_value=account
                ),
                mock.patch.object(
                    backup_import, "_recovery_path", return_value=str(recovery)
                ),
                mock.patch.object(
                    backup_import, "_secure_path_state", return_value="missing"
                ),
                mock.patch.object(backup_import, "_as_collector"),
                mock.patch.object(
                    backup_import, "_collector_shell", return_value=completed
                ) as collector_shell,
                mock.patch.object(backup_import, "_secure_require_private_dir"),
                mock.patch.object(backup_import, "_secure_write"),
            ):
                backup_import._create_recovery_authority(
                    [],
                    None,
                    lldpq_dir=str(root),
                    web_root=str(root / "web"),
                    user="lldpq",
                    token="123-0123456789abcdef",
                )

            command = collector_shell.call_args_list[0].args
            self.assertIn('chgrp -- "$2" "$1"', command[1])
            self.assertIn('chmod -- g-s,u-s "$1"', command[1])
            self.assertIn('chmod -- 700 "$1"', command[1])
            self.assertEqual(
                command[2:],
                (f"{recovery}.tmp-123-0123456789abcdef", str(os.getgid())),
            )


if __name__ == "__main__":
    unittest.main()
