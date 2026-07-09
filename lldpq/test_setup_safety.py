#!/usr/bin/env python3
"""Regression tests for Setup's durable configuration editor writes."""

from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "html" / "setup_safety.py"
SPEC = importlib.util.spec_from_file_location("test_lldpq_setup_safety", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
SAFETY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAFETY)


class SetupSafetyWriteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state_parent = self.root / "persistent-state"
        self.state_parent.mkdir()
        self.journal_root = self.state_parent / "config-write-journals"
        self.journal_root.mkdir(mode=0o700)
        self.state_patch = mock.patch.object(
            SAFETY, "DIRECT_MOUNT_JOURNAL_ROOT", str(self.journal_root)
        )
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.persistence_patch = mock.patch.object(
            SAFETY, "_journal_storage_is_persistent", return_value=True
        )
        self.persistence_patch.start()
        self.addCleanup(self.persistence_patch.stop)
        self.target = self.root / "devices.yaml"
        self.original = b"devices:\n  leaf01:\n    ip: 192.0.2.1\n"
        self.candidate = "devices:\n  leaf01:\n    ip: 192.0.2.2\n"
        self.target.write_bytes(self.original)
        self.target.chmod(0o640)
        journal = SAFETY._direct_mount_journal_path(str(self.target))
        assert journal is not None
        self.journal = Path(journal)

    def _ebusy_on_target_replace(self, error=errno.EBUSY, before_error=None):
        real_replace = os.replace
        target = os.path.abspath(self.target)

        def replace(source, destination, **options):
            if os.path.abspath(destination) == target:
                if before_error is not None:
                    before_error()
                raise OSError(error, os.strerror(error), destination)
            return real_replace(source, destination, **options)

        return mock.patch.object(SAFETY.os, "replace", side_effect=replace)

    def _fallback_write(self, **kwargs):
        info = {}
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace():
                revision = SAFETY.atomic_write_text(
                    str(self.target),
                    self.candidate,
                    expected_revision=SAFETY.revision_bytes(self.original),
                    managed_roots=[str(self.root)],
                    allow_direct_mount_inplace=True,
                    result_info=info,
                    **kwargs,
                )
        return revision, info

    def test_normal_path_remains_atomic_and_replaces_inode(self):
        old_inode = self.target.stat().st_ino
        info = {}

        revision = SAFETY.atomic_write_text(
            str(self.target),
            self.candidate,
            expected_revision=SAFETY.revision_bytes(self.original),
            managed_roots=[str(self.root)],
            allow_direct_mount_inplace=True,
            result_info=info,
        )

        self.assertEqual(self.target.read_text(), self.candidate)
        self.assertNotEqual(self.target.stat().st_ino, old_inode)
        self.assertEqual(revision, SAFETY.revision_text(self.candidate))
        self.assertEqual(info, {"atomic": True, "write_mode": "atomic-replace"})
        self.assertEqual(Path(str(self.target) + ".bak").read_bytes(), self.original)
        self.assertFalse(self.journal.exists())

    def test_exact_direct_mount_ebusy_uses_journaled_pinned_inode_write(self):
        old_inode = self.target.stat().st_ino

        revision, info = self._fallback_write()

        self.assertEqual(self.target.read_text(), self.candidate)
        self.assertEqual(self.target.stat().st_ino, old_inode)
        self.assertEqual(revision, SAFETY.revision_text(self.candidate))
        self.assertEqual(
            info,
            {
                "atomic": False,
                "write_mode": "direct-mount-journaled-in-place",
                "recovery_scope": "persistent-state",
            },
        )
        self.assertEqual(Path(str(self.target) + ".bak").read_bytes(), self.original)
        self.assertFalse(self.journal.exists())

    def test_ebusy_without_explicit_opt_in_does_not_rewrite_inode(self):
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace():
                with self.assertRaises(OSError) as caught:
                    SAFETY.atomic_write_text(
                        str(self.target), self.candidate,
                        managed_roots=[str(self.root)],
                    )
        self.assertEqual(caught.exception.errno, errno.EBUSY)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_ebusy_on_non_mount_does_not_rewrite_inode(self):
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=False):
            with self._ebusy_on_target_replace():
                with self.assertRaises(OSError) as caught:
                    SAFETY.atomic_write_text(
                        str(self.target),
                        self.candidate,
                        managed_roots=[str(self.root)],
                        allow_direct_mount_inplace=True,
                    )
        self.assertEqual(caught.exception.errno, errno.EBUSY)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_non_ebusy_replace_error_never_uses_direct_mount_fallback(self):
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace(errno.EPERM):
                with self.assertRaises(OSError) as caught:
                    SAFETY.atomic_write_text(
                        str(self.target),
                        self.candidate,
                        managed_roots=[str(self.root)],
                        allow_direct_mount_inplace=True,
                    )
        self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_pinned_revision_recheck_preserves_external_change(self):
        external = b"devices:\n  external: {}\n"

        def concurrent_write():
            with open(self.target, "r+b", buffering=0) as handle:
                handle.truncate(0)
                handle.write(external)
                os.fsync(handle.fileno())

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace(before_error=concurrent_write):
                with self.assertRaises(SAFETY.RevisionConflict):
                    SAFETY.atomic_write_text(
                        str(self.target),
                        self.candidate,
                        expected_revision=SAFETY.revision_bytes(self.original),
                        managed_roots=[str(self.root)],
                        allow_direct_mount_inplace=True,
                    )
        self.assertEqual(self.target.read_bytes(), external)
        self.assertFalse(self.journal.exists())

    def test_symlink_swap_before_fallback_cannot_touch_other_file(self):
        victim = self.root / "victim"
        victim.write_bytes(b"do not change")

        def swap_target():
            if not self.target.is_symlink():
                self.target.unlink()
                self.target.symlink_to(victim)

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace(before_error=swap_target):
                with self.assertRaises(SAFETY.SetupSafetyError):
                    SAFETY.atomic_write_text(
                        str(self.target),
                        self.candidate,
                        managed_roots=[str(self.root)],
                        allow_direct_mount_inplace=True,
                    )
        self.assertEqual(victim.read_bytes(), b"do not change")
        self.assertTrue(self.target.is_symlink())

    def test_write_failure_rolls_pinned_inode_back_and_retires_journal(self):
        real_write_descriptor = SAFETY._write_descriptor
        calls = 0

        def fail_candidate_then_restore(descriptor, content):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.ftruncate(descriptor, 0)
                os.write(descriptor, b"partial")
                os.fsync(descriptor)
                raise OSError(errno.EIO, "injected write failure")
            return real_write_descriptor(descriptor, content)

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace():
                with mock.patch.object(
                    SAFETY, "_write_descriptor", side_effect=fail_candidate_then_restore
                ):
                    with self.assertRaises(OSError):
                        SAFETY.atomic_write_text(
                            str(self.target),
                            self.candidate,
                            managed_roots=[str(self.root)],
                            allow_direct_mount_inplace=True,
                        )
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertFalse(self.journal.exists())

    def test_failed_rollback_retains_journal_and_next_get_recovers(self):
        def fail_all_writes(descriptor, _content):
            os.ftruncate(descriptor, 0)
            os.write(descriptor, b"partial")
            os.fsync(descriptor)
            raise OSError(errno.EIO, "injected write and rollback failure")

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            with self._ebusy_on_target_replace():
                with mock.patch.object(SAFETY, "_write_descriptor", side_effect=fail_all_writes):
                    with self.assertRaises(SAFETY.SetupSafetyError):
                        SAFETY.atomic_write_text(
                            str(self.target),
                            self.candidate,
                            managed_roots=[str(self.root)],
                            allow_direct_mount_inplace=True,
                        )
            self.assertTrue(self.journal.exists())
            content, revision, exists = SAFETY.read_managed_text(
                str(self.target), managed_roots=[str(self.root)]
            )

        self.assertTrue(exists)
        self.assertEqual(content.encode(), self.original)
        self.assertEqual(revision, SAFETY.revision_bytes(self.original))
        self.assertFalse(self.journal.exists())

    def test_get_recovers_partial_crash_from_durable_journal(self):
        metadata = self.target.stat()
        SAFETY._publish_direct_mount_journal(
            str(self.target), self.original, self.candidate.encode(), metadata
        )
        with open(self.target, "r+b", buffering=0) as handle:
            handle.truncate(0)
            handle.write(b"devices:\n  half")
            os.fsync(handle.fileno())

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            content, revision, exists = SAFETY.read_managed_text(
                str(self.target), managed_roots=[str(self.root)]
            )

        self.assertTrue(exists)
        self.assertEqual(content.encode(), self.original)
        self.assertEqual(revision, SAFETY.revision_bytes(self.original))
        self.assertFalse(self.journal.exists())

    def test_get_commits_fully_written_candidate_after_crash(self):
        candidate = self.candidate.encode()
        SAFETY._publish_direct_mount_journal(
            str(self.target), self.original, candidate, self.target.stat()
        )
        with open(self.target, "r+b", buffering=0) as handle:
            handle.truncate(0)
            handle.write(candidate)
            os.fsync(handle.fileno())

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            content, revision, exists = SAFETY.read_managed_text(
                str(self.target), managed_roots=[str(self.root)]
            )

        self.assertTrue(exists)
        self.assertEqual(content, self.candidate)
        self.assertEqual(revision, SAFETY.revision_bytes(candidate))
        self.assertFalse(self.journal.exists())

    def test_recovery_fsyncs_matching_target_before_retiring_journal(self):
        real_fsync = SAFETY.os.fsync
        real_retire = SAFETY._retire_direct_mount_journal
        target_identity = (self.target.stat().st_dev, self.target.stat().st_ino)

        for current in (self.original, self.candidate.encode()):
            with self.subTest(current=current):
                with open(self.target, "r+b", buffering=0) as handle:
                    handle.truncate(0)
                    handle.write(current)
                    os.fsync(handle.fileno())
                SAFETY._publish_direct_mount_journal(
                    str(self.target),
                    self.original,
                    self.candidate.encode(),
                    self.target.stat(),
                )
                events = []

                def track_fsync(descriptor):
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) == target_identity:
                        events.append("target-fsync")
                    return real_fsync(descriptor)

                def track_retire(path):
                    events.append("journal-retire")
                    return real_retire(path)

                with mock.patch.object(SAFETY.os, "fsync", side_effect=track_fsync):
                    with mock.patch.object(
                        SAFETY,
                        "_retire_direct_mount_journal",
                        side_effect=track_retire,
                    ):
                        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
                            SAFETY.read_managed_text(
                                str(self.target), managed_roots=[str(self.root)]
                            )
                self.assertIn("target-fsync", events)
                self.assertLess(
                    events.index("target-fsync"), events.index("journal-retire")
                )

    def test_recovery_fsync_failure_retains_journal(self):
        candidate = self.candidate.encode()
        SAFETY._publish_direct_mount_journal(
            str(self.target), self.original, candidate, self.target.stat()
        )
        with open(self.target, "r+b", buffering=0) as handle:
            handle.truncate(0)
            handle.write(candidate)
            os.fsync(handle.fileno())
        target_identity = (self.target.stat().st_dev, self.target.stat().st_ino)
        real_fsync = SAFETY.os.fsync

        def fail_target_fsync(descriptor):
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == target_identity:
                raise OSError(errno.EIO, "injected recovery fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(SAFETY.os, "fsync", side_effect=fail_target_fsync):
            with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
                with self.assertRaises(OSError):
                    SAFETY.read_managed_text(
                        str(self.target), managed_roots=[str(self.root)]
                    )
        self.assertTrue(self.journal.exists())

    def test_unsafe_journal_permissions_fail_closed(self):
        self.journal.write_text("{}")
        self.journal.chmod(0o644)
        with self.assertRaises(SAFETY.SetupSafetyError):
            SAFETY.read_managed_text(str(self.target), managed_roots=[str(self.root)])
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_short_writes_are_retried_until_full_candidate_is_verified(self):
        descriptor = os.open(self.target, os.O_RDWR)
        real_write = os.write

        def short_write(fd, content):
            return real_write(fd, bytes(content[:3]))

        try:
            with mock.patch.object(SAFETY.os, "write", side_effect=short_write):
                SAFETY._write_descriptor(descriptor, self.candidate.encode())
        finally:
            os.close(descriptor)
        self.assertEqual(self.target.read_text(), self.candidate)

    def test_direct_mount_fails_closed_without_persistent_recovery_volume(self):
        with mock.patch.object(
            SAFETY, "_journal_storage_is_persistent", return_value=False
        ):
            with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
                content, _revision, exists = SAFETY.read_managed_text(
                    str(self.target), managed_roots=[str(self.root)]
                )
                self.assertTrue(exists)
                self.assertEqual(content.encode(), self.original)
                with self._ebusy_on_target_replace():
                    with self.assertRaisesRegex(
                        SAFETY.SetupSafetyError, "requires persistent recovery storage"
                    ):
                        SAFETY.atomic_write_text(
                            str(self.target),
                            self.candidate,
                            managed_roots=[str(self.root)],
                            allow_direct_mount_inplace=True,
                        )
        self.assertEqual(self.target.read_bytes(), self.original)

    def test_missing_journal_directory_on_persistent_mount_blocks_direct_get(self):
        missing = self.state_parent / "missing-journal-root"
        with mock.patch.object(SAFETY, "DIRECT_MOUNT_JOURNAL_ROOT", str(missing)):
            with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
                with self.assertRaisesRegex(
                    SAFETY.SetupSafetyError, "recovery directory is missing"
                ):
                    SAFETY.read_managed_text(
                        str(self.target), managed_roots=[str(self.root)]
                    )


class SetupSafetyCrossProcessRecoveryTests(unittest.TestCase):
    def test_killed_writer_is_recovered_by_new_helper_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "host-bind" / "devices.yaml"
            target.parent.mkdir()
            original = b"devices:\n  before: {}\n"
            candidate = b"devices:\n  after: {}\n"
            target.write_bytes(original)
            state_parent = root / "persistent-volume"
            state_parent.mkdir()
            journal_root = state_parent / "config-write-journals"
            environment = dict(os.environ)
            environment["LLDPQ_DIRECT_WRITE_STATE_DIR"] = str(journal_root)
            first = f"""
import importlib.util, os
spec = importlib.util.spec_from_file_location('writer_setup_safety', {str(HELPER_PATH)!r})
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module._journal_storage_is_persistent = lambda root: True
path = {str(target)!r}; original = {original!r}; candidate = {candidate!r}
module._publish_direct_mount_journal(path, original, candidate, os.stat(path))
fd = os.open(path, os.O_RDWR)
os.ftruncate(fd, 0); os.write(fd, b'devices:\\n  interrupted'); os.fsync(fd)
os._exit(91)
"""
            killed = subprocess.run([sys.executable, "-c", first], env=environment)
            self.assertEqual(killed.returncode, 91)
            self.assertFalse(Path(str(target) + ".direct-write-journal").exists())
            self.assertTrue(any(journal_root.glob("*.json")))

            second = f"""
import importlib.util, json
spec = importlib.util.spec_from_file_location('reader_setup_safety', {str(HELPER_PATH)!r})
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module._is_direct_mount = lambda path: True
print(json.dumps(module.read_managed_text({str(target)!r}, managed_roots=[{str(root)!r}])))
"""
            recovered = subprocess.run(
                [sys.executable, "-c", second],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            content, revision, exists = json.loads(recovered.stdout)
            self.assertTrue(exists)
            self.assertEqual(content.encode(), original)
            self.assertEqual(revision, SAFETY.revision_bytes(original))
            self.assertFalse(any(journal_root.glob("*.json")))

    def test_startup_recover_all_removes_killed_pre_publish_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lldpq_dir = root / "lldpq"
            web_root = root / "web"
            lldpq_dir.mkdir()
            web_root.mkdir()
            targets = (
                lldpq_dir / "devices.yaml",
                web_root / "topology.dot",
                web_root / "topology_config.yaml",
                lldpq_dir / "notifications.yaml",
                web_root / "display-aliases.json",
            )
            for target in targets:
                target.write_text("initial\n", encoding="utf-8")

            target = targets[0]
            original = target.read_bytes()
            candidate = b"candidate\n"
            state_parent = root / "persistent-volume"
            state_parent.mkdir()
            journal_root = state_parent / "config-write-journals"
            environment = dict(os.environ)
            environment["LLDPQ_DIRECT_WRITE_STATE_DIR"] = str(journal_root)
            first = f"""
import importlib.util, os
spec = importlib.util.spec_from_file_location('writer_setup_safety', {str(HELPER_PATH)!r})
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module._journal_storage_is_persistent = lambda root: True
module.os.replace = lambda *args, **kwargs: os._exit(92)
path = {str(target)!r}; original = {original!r}; candidate = {candidate!r}
module._publish_direct_mount_journal(path, original, candidate, os.stat(path))
"""
            killed = subprocess.run([sys.executable, "-c", first], env=environment)

            self.assertEqual(killed.returncode, 92)
            self.assertEqual(target.read_bytes(), original)
            staged = list(journal_root.iterdir())
            self.assertEqual(len(staged), 1)
            self.assertRegex(
                staged[0].name,
                r"^\.[0-9a-f]{64}\.json\.tmp\.[0-9a-f]{24}$",
            )

            with (
                mock.patch.object(
                    SAFETY, "DIRECT_MOUNT_JOURNAL_ROOT", str(journal_root)
                ),
                mock.patch.object(
                    SAFETY, "_journal_storage_is_persistent", return_value=True
                ),
                mock.patch.object(SAFETY, "_is_direct_mount", return_value=False),
            ):
                recovered = SAFETY.recover_all_managed_writes(
                    str(lldpq_dir), str(web_root)
                )

            self.assertEqual(recovered, [])
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(list(journal_root.iterdir()), [])


class SetupSafetyRecoverAllTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lldpq_dir = self.root / "lldpq"
        self.web_root = self.root / "web"
        self.lldpq_dir.mkdir()
        self.web_root.mkdir()
        self.targets = {
            "devices": self.lldpq_dir / "devices.yaml",
            "topology": self.web_root / "topology.dot",
            "topology_config": self.web_root / "topology_config.yaml",
            "notifications": self.lldpq_dir / "notifications.yaml",
            "aliases": self.web_root / "display-aliases.json",
        }
        for target in self.targets.values():
            target.write_text("initial\n")
        self.state_parent = self.root / "persistent-state"
        self.state_parent.mkdir()
        self.journal_root = self.state_parent / "config-write-journals"
        self.journal_root.mkdir(mode=0o700)
        self.state_patch = mock.patch.object(
            SAFETY, "DIRECT_MOUNT_JOURNAL_ROOT", str(self.journal_root)
        )
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.persistence_patch = mock.patch.object(
            SAFETY, "_journal_storage_is_persistent", return_value=True
        )
        self.persistence_patch.start()
        self.addCleanup(self.persistence_patch.stop)

    def test_recover_all_restores_allowlisted_partial_devices_before_use(self):
        target = self.targets["devices"]
        original = target.read_bytes()
        candidate = b"candidate\n"
        SAFETY._publish_direct_mount_journal(
            str(target), original, candidate, target.stat()
        )
        with open(target, "r+b", buffering=0) as handle:
            handle.truncate(0)
            handle.write(b"part")
            os.fsync(handle.fileno())

        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=True):
            recovered = SAFETY.recover_all_managed_writes(
                str(self.lldpq_dir), str(self.web_root)
            )

        self.assertEqual(recovered, [str(target)])
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(list(self.journal_root.iterdir()), [])

    def test_recover_all_rejects_unknown_hashed_journal(self):
        unknown = self.journal_root / ("f" * 64 + ".json")
        unknown.write_text("{}")
        unknown.chmod(0o600)
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=False):
            with self.assertRaisesRegex(SAFETY.SetupSafetyError, "unknown file"):
                SAFETY.recover_all_managed_writes(
                    str(self.lldpq_dir), str(self.web_root)
                )

    def test_recover_all_rejects_corrupt_allowlisted_journal(self):
        journal = SAFETY._direct_mount_journal_path(str(self.targets["devices"]))
        assert journal is not None
        Path(journal).write_text("not-json")
        Path(journal).chmod(0o600)
        with mock.patch.object(SAFETY, "_is_direct_mount", return_value=False):
            with self.assertRaisesRegex(
                SAFETY.SetupSafetyError, "recovery journal is invalid"
            ):
                SAFETY.recover_all_managed_writes(
                    str(self.lldpq_dir), str(self.web_root)
                )

    def test_recover_all_cli_takes_global_then_inventory_before_file_recovery(self):
        events = []

        def global_lock():
            events.append("global")
            return os.open(os.devnull, os.O_RDONLY)

        def inventory_lock(_path):
            events.append("inventory")
            return os.open(os.devnull, os.O_RDONLY)

        def recover(_lldpq_dir, _web_root):
            events.append("file-recovery")
            return []

        argv = [
            str(HELPER_PATH),
            "recover-all",
            "--lldpq-dir", str(self.lldpq_dir),
            "--web-root", str(self.web_root),
            "--inventory-lock", str(self.web_root / ".inventory.lock"),
            "--direct-write-state-dir", str(self.journal_root),
        ]
        with mock.patch.object(sys, "argv", argv):
            with mock.patch.object(
                SAFETY, "acquire_global_configuration_lock", side_effect=global_lock
            ):
                with mock.patch.object(
                    SAFETY, "acquire_inventory_lock", side_effect=inventory_lock
                ):
                    with mock.patch.object(
                        SAFETY, "recover_all_managed_writes", side_effect=recover
                    ):
                        with mock.patch("sys.stdout", new_callable=io.StringIO):
                            self.assertEqual(SAFETY._main(), 0)
        self.assertEqual(events, ["global", "inventory", "file-recovery"])


class SetupSafetyMountDetectionTests(unittest.TestCase):
    def test_mountinfo_requires_exact_decoded_mountpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            mountinfo = Path(directory) / "mountinfo"
            mountinfo.write_text(
                "35 24 0:31 / /home/lldpq rw - ext4 /dev/root rw\n"
                "36 35 0:32 / /home/lldpq/devices.yaml rw - ext4 /dev/root rw\n"
                "37 35 0:33 / /home/lldpq/name\\040with\\040space rw - ext4 /dev/root rw\n"
            )
            self.assertTrue(
                SAFETY._is_direct_mount(
                    "/home/lldpq/devices.yaml", mountinfo_path=str(mountinfo)
                )
            )
            self.assertFalse(
                SAFETY._is_direct_mount(
                    "/home/lldpq/devices.yaml/child", mountinfo_path=str(mountinfo)
                )
            )
            self.assertTrue(
                SAFETY._is_direct_mount(
                    "/home/lldpq/name with space", mountinfo_path=str(mountinfo)
                )
            )


class SetupSafetyInventoryLockTests(unittest.TestCase):
    def test_shared_inventory_lock_serializes_another_process(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / ".inventory.lock"
            first = SAFETY.acquire_inventory_lock(str(lock_path))
            script = f"""
import importlib.util, os
spec = importlib.util.spec_from_file_location('lock_setup_safety', {str(HELPER_PATH)!r})
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
fd = module.acquire_inventory_lock({str(lock_path)!r})
print('acquired', flush=True)
os.close(fd)
"""
            waiter = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    waiter.communicate(timeout=0.1)
                os.close(first)
                first = None
                stdout, stderr = waiter.communicate(timeout=3)
                self.assertEqual(waiter.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "acquired")
            finally:
                if first is not None:
                    os.close(first)
                if waiter.poll() is None:
                    waiter.kill()
                    waiter.communicate()


class SetupEditorRecoveryContractTests(unittest.TestCase):
    def test_all_config_editor_get_paths_use_safe_read_helper(self):
        self.assertIn("read-devices", (ROOT / "html" / "edit-devices.sh").read_text())
        self.assertIn("read-text", (ROOT / "html" / "edit-topology.sh").read_text())
        self.assertIn("read-text", (ROOT / "html" / "edit-config.sh").read_text())
        setup_api = (ROOT / "html" / "setup-api.sh").read_text()
        self.assertIn("snapshot = service_safe_read(alias_file)", setup_api)
        self.assertIn("snapshot = service_safe_read(notif_yaml)", setup_api)

    def test_devices_editor_joins_shared_inventory_lock(self):
        editor = (ROOT / "html" / "edit-devices.sh").read_text()
        self.assertIn('INVENTORY_LOCK="$WEB_ROOT/.inventory.lock"', editor)
        self.assertGreaterEqual(editor.count('--inventory-lock "$INVENTORY_LOCK"'), 2)

    def test_docker_keeps_private_journals_in_persistent_named_volume(self):
        compose = (ROOT / "docker" / "docker-compose.yml").read_text()
        self.assertIn(
            "lldpq-provision-state:/var/lib/lldpq/provision-state", compose
        )
        entrypoint = (ROOT / "docker" / "docker-entrypoint.sh").read_text()
        self.assertIn(
            'CONFIG_WRITE_JOURNAL_DIR="$PROVISION_STATE_DIR/config-write-journals"',
            entrypoint,
        )
        self.assertIn('chmod 0700 "$CONFIG_WRITE_JOURNAL_DIR"', entrypoint)
        self.assertIn(
            '[ "$runtime_state" = "$PROVISION_STATE_DIR" ] && continue', entrypoint
        )
        normalizer = 'PROVISION_STATE_DIR="${PROVISION_STATE_DIR%/}"'
        self.assertIn(normalizer, entrypoint)
        self.assertLess(entrypoint.index(normalizer), entrypoint.index("for runtime_state in"))
        docker_doc = (ROOT / "DOCKER.md").read_text()
        self.assertIn(
            "fail before modifying a legacy\n"
            "single-file mount and return a migration hint",
            docker_doc,
        )

    def test_provision_state_trailing_slashes_normalize_before_chown_exclusion(self):
        normalizer = r'''
PROVISION_STATE_DIR="$1"
while [ "$PROVISION_STATE_DIR" != "/" ] && \
      [ "${PROVISION_STATE_DIR%/}" != "$PROVISION_STATE_DIR" ]; do
    PROVISION_STATE_DIR="${PROVISION_STATE_DIR%/}"
done
printf '%s' "$PROVISION_STATE_DIR"
'''
        for supplied in (
            "/var/lib/lldpq/provision-state/",
            "/var/lib/lldpq/provision-state///",
        ):
            with self.subTest(supplied=supplied):
                result = subprocess.run(
                    ["bash", "-c", normalizer, "--", supplied],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(result.stdout, "/var/lib/lldpq/provision-state")

    def test_startup_recovery_precedes_config_seeding_and_devices_consumers(self):
        entrypoint = (ROOT / "docker" / "docker-entrypoint.sh").read_text()
        recovery = entrypoint.index('"$SETUP_SAFETY_HELPER" recover-all')
        self.assertLess(recovery, entrypoint.index("# ─── Single config directory"))
        self.assertLess(recovery, entrypoint.index('echo "✓ devices.yaml loaded'))
        self.assertLess(recovery, entrypoint.index("cat > /etc/cron.d/lldpq"))
        self.assertIn(
            "retained config-write journal could not be recovered; startup stopped",
            entrypoint,
        )
        dockerfile = (ROOT / "docker" / "Dockerfile").read_text()
        self.assertIn(
            "html/setup_safety.py /usr/local/libexec/lldpq-setup-safety.py",
            dockerfile,
        )
        self.assertIn(
            "lldpq-setup-safety.py)\" = \"0:0:755\"",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
