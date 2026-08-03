#!/usr/bin/env python3
"""Regression tests for locked /etc/lldpq.conf web updates."""

import contextlib
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "html" / "lldpq_config_write.py"
AI_API = ROOT / "html" / "ai-api.sh"
FABRIC_API = ROOT / "html" / "fabric-api.sh"
SETUP_API = ROOT / "html" / "setup-api.sh"
CONFIG_HELPER = ROOT / "bin" / "lldpq-config"


def load_helper():
    spec = importlib.util.spec_from_file_location("lldpq_config_write_test", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_heredoc(source: str, marker: str) -> str:
    lines = source.splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if f"<< '{marker}'" in line or f'<< "{marker}"' in line or f"<< {marker}" in line
    ) + 1
    end = next(index for index in range(start, len(lines)) if lines[index] == marker)
    return "\n".join(lines[start:end]) + "\n"


class LldpqConfigWriteTests(unittest.TestCase):
    def setUp(self):
        self.module = load_helper()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "lldpq.conf"
        self.lock = self.root / "lldpq.conf.lock"
        self.config.write_text("LLDPQ_DIR=/srv/lldpq\nAI_MODEL=old\n", encoding="utf-8")
        self.lock.write_text("", encoding="utf-8")
        os.chmod(self.config, 0o640)
        os.chmod(self.lock, 0o660)

    def tearDown(self):
        self.temporary.cleanup()

    def update(self, updates, **kwargs):
        return self.module.update_lldpq_config(
            updates,
            config_path=str(self.config),
            lock_path=str(self.lock),
            **kwargs,
        )

    def test_atomic_update_preserves_metadata_and_removes_shadowing_duplicates(self):
        self.config.write_text(
            "LLDPQ_DIR=/srv/lldpq\nAI_MODEL=old\nAI_MODEL=shadow\nKEEP=yes\n",
            encoding="utf-8",
        )
        os.chmod(self.config, 0o640)
        before = self.config.stat()

        result = self.update({"AI_MODEL": "new model", "AI_API_KEY": "secret value"})

        self.assertTrue(result["changed"])
        content = self.config.read_text(encoding="utf-8")
        self.assertEqual(content.count("AI_MODEL="), 1)
        self.assertIn("AI_MODEL='new model'\n", content)
        self.assertIn("AI_API_KEY='secret value'\n", content)
        self.assertIn("KEEP=yes\n", content)
        after = self.config.stat()
        self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))

    def test_symlink_backed_persistent_target_keeps_symlink(self):
        target = self.root / "system-config" / "lldpq.conf"
        target.parent.mkdir()
        target.write_text(self.config.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(target, 0o640)
        self.config.unlink()
        self.config.symlink_to(target)

        self.update({"AI_PROVIDER": "ollama"})

        self.assertTrue(self.config.is_symlink())
        self.assertIn("AI_PROVIDER=ollama\n", target.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_changing_exact_direct_mount_fails_before_mutation(self):
        original = self.config.read_bytes()
        inode = self.config.stat().st_ino
        with mock.patch.object(self.module, "is_direct_file_mount", return_value=True):
            with self.assertRaisesRegex(
                self.module.ConfigWriteError,
                "lldpq-system-config.*directory/named volume",
            ):
                self.update({"AI_MODEL": "new"})
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(self.config.stat().st_ino, inode)

    def test_unchanged_direct_mount_is_a_noop(self):
        original = self.config.read_bytes()
        with mock.patch.object(self.module, "is_direct_file_mount", return_value=True):
            result = self.update({"AI_MODEL": "old"})
        self.assertFalse(result["changed"])
        self.assertEqual(self.config.read_bytes(), original)

    def test_expected_revision_rejects_stale_update(self):
        original = self.config.read_bytes()
        with self.assertRaises(self.module.RevisionConflict):
            self.update({"AI_MODEL": "new"}, expected_revision="0" * 64)
        self.assertEqual(self.config.read_bytes(), original)

    def test_directory_fsync_failure_after_replace_restores_exact_generation(self):
        original = self.config.read_bytes()
        metadata = self.config.stat()
        real_fsync_directory = self.module._fsync_directory
        calls = 0

        def fail_first_directory_sync(path):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated post-replace directory fsync failure")
            return real_fsync_directory(path)

        with mock.patch.object(
            self.module,
            "_fsync_directory",
            side_effect=fail_first_directory_sync,
        ):
            with self.assertRaisesRegex(
                self.module.ConfigWriteError, "previous generation was restored"
            ):
                self.update({"AI_MODEL": "new"})

        restored = self.config.stat()
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(
            (restored.st_uid, restored.st_gid, stat.S_IMODE(restored.st_mode)),
            (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
        )

    def test_post_replace_readback_mismatch_restores_exact_generation(self):
        original = self.config.read_bytes()
        metadata = self.config.stat()
        real_verify = self.module._verify_installed
        calls = 0

        def fail_first_verification(target, expected, expected_metadata):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise self.module.ConfigWriteError("simulated readback mismatch")
            return real_verify(target, expected, expected_metadata)

        with mock.patch.object(
            self.module, "_verify_installed", side_effect=fail_first_verification
        ):
            with self.assertRaisesRegex(
                self.module.ConfigWriteError, "previous generation was restored"
            ):
                self.update({"AI_MODEL": "new"})

        restored = self.config.stat()
        self.assertEqual(calls, 2)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(
            (restored.st_uid, restored.st_gid, stat.S_IMODE(restored.st_mode)),
            (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
        )

    def test_rollback_preserves_noncooperating_post_commit_replacement(self):
        external = b"AI_MODEL=external\n"
        real_fsync_directory = self.module._fsync_directory
        replaced = False

        def replace_before_failed_directory_sync(path):
            nonlocal replaced
            if not replaced:
                external_stage = self.root / ".external-config"
                external_stage.write_bytes(external)
                os.chmod(external_stage, 0o640)
                os.replace(external_stage, self.config)
                replaced = True
                raise OSError("simulated post-replace directory fsync failure")
            return real_fsync_directory(path)

        with mock.patch.object(
            self.module,
            "_fsync_directory",
            side_effect=replace_before_failed_directory_sync,
        ):
            with self.assertRaisesRegex(
                self.module.ConfigWriteError, "rollback skipped.*externally replaced"
            ):
                self.update({"AI_MODEL": "losing-writer"})

        self.assertTrue(replaced)
        self.assertEqual(self.config.read_bytes(), external)
        self.assertEqual(list(self.root.glob(".lldpq.conf.lldpq-*.tmp")), [])

    def test_lock_is_entered_before_the_first_config_read(self):
        events = []
        real_snapshot = self.module._snapshot_target

        @contextlib.contextmanager
        def observed_lock(_path):
            events.append("lock")
            yield

        def observed_snapshot(path):
            events.append("read")
            return real_snapshot(path)

        with mock.patch.object(self.module, "_configuration_lock", observed_lock), \
             mock.patch.object(self.module, "_snapshot_target", observed_snapshot):
            self.update({"AI_MODEL": "new"})
        self.assertEqual(events[0:2], ["lock", "read"])

    def test_native_unwritable_parent_uses_fixed_privileged_stage(self):
        original_default = self.module.DEFAULT_CONFIG_PATH
        real_mkstemp = self.module.tempfile.mkstemp
        commands = []

        def deny_same_directory_stage(*args, **kwargs):
            if kwargs.get("dir") == str(self.root):
                raise PermissionError("simulated root-owned parent")
            return real_mkstemp(*args, **kwargs)

        def emulate_sudo(arguments, *, timeout=15):
            del timeout
            commands.append(tuple(arguments))
            command = arguments[0]
            if command == "/usr/bin/cp":
                shutil.copyfile(arguments[-2], arguments[-1])
            elif command == "/usr/bin/chmod":
                os.chmod(arguments[-1], int(arguments[1], 8))
            elif command == "/usr/bin/chown":
                os.chown(arguments[-1], *map(int, arguments[1].split(":")))
            elif command == "/usr/bin/mv":
                os.replace(arguments[-2], arguments[-1])
            elif command == "/usr/bin/rm":
                try:
                    os.unlink(arguments[-1])
                except FileNotFoundError:
                    pass
            elif command != "/usr/bin/sync":
                raise AssertionError(f"unexpected privileged command: {arguments}")

        try:
            self.module.DEFAULT_CONFIG_PATH = str(self.config)
            with mock.patch.object(
                self.module.tempfile, "mkstemp", side_effect=deny_same_directory_stage
            ), mock.patch.object(self.module, "_run_sudo", side_effect=emulate_sudo):
                self.update({"AI_MODEL": "native-safe"})
        finally:
            self.module.DEFAULT_CONFIG_PATH = original_default

        self.assertIn("AI_MODEL=native-safe\n", self.config.read_text(encoding="utf-8"))
        self.assertTrue(any(command[0] == "/usr/bin/cp" for command in commands))
        self.assertTrue(any(command[0] == "/usr/bin/mv" for command in commands))
        move = next(command for command in commands if command[0] == "/usr/bin/mv")
        self.assertEqual(move[-2], str(self.config) + ".lldpq-root-stage")
        self.assertEqual(move[-1], str(self.config))

    def test_native_post_replace_sync_failure_uses_privileged_rollback(self):
        original = self.config.read_bytes()
        metadata = self.config.stat()
        original_default = self.module.DEFAULT_CONFIG_PATH
        real_mkstemp = self.module.tempfile.mkstemp
        directory_sync_calls = 0

        def deny_same_directory_stage(*args, **kwargs):
            if kwargs.get("dir") == str(self.root):
                raise PermissionError("simulated root-owned parent")
            return real_mkstemp(*args, **kwargs)

        def emulate_sudo(arguments, *, timeout=15):
            nonlocal directory_sync_calls
            del timeout
            command = arguments[0]
            if command == "/usr/bin/cp":
                shutil.copyfile(arguments[-2], arguments[-1])
            elif command == "/usr/bin/chmod":
                os.chmod(arguments[-1], int(arguments[1], 8))
            elif command == "/usr/bin/chown":
                os.chown(arguments[-1], *map(int, arguments[1].split(":")))
            elif command == "/usr/bin/mv":
                os.replace(arguments[-2], arguments[-1])
            elif command == "/usr/bin/rm":
                try:
                    os.unlink(arguments[-1])
                except FileNotFoundError:
                    pass
            elif command == "/usr/bin/sync":
                if arguments[-1] == "/etc":
                    directory_sync_calls += 1
                    if directory_sync_calls == 1:
                        raise self.module.ConfigWriteError(
                            "simulated privileged directory sync failure"
                        )
            else:
                raise AssertionError(f"unexpected privileged command: {arguments}")

        try:
            self.module.DEFAULT_CONFIG_PATH = str(self.config)
            with mock.patch.object(
                self.module.tempfile, "mkstemp", side_effect=deny_same_directory_stage
            ), mock.patch.object(self.module, "_run_sudo", side_effect=emulate_sudo):
                with self.assertRaisesRegex(
                    self.module.ConfigWriteError, "previous generation was restored"
                ):
                    self.update({"AI_MODEL": "native-rollback"})
        finally:
            self.module.DEFAULT_CONFIG_PATH = original_default

        restored = self.config.stat()
        self.assertEqual(directory_sync_calls, 2)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(
            (restored.st_uid, restored.st_gid, stat.S_IMODE(restored.st_mode)),
            (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)),
        )

    def test_mount_detection_requires_exact_file_path(self):
        mountinfo = self.root / "mountinfo"
        escaped_root = os.path.realpath(self.root).replace(" ", "\\040")
        escaped_config = os.path.realpath(self.config).replace(" ", "\\040")
        mountinfo.write_text(
            f"36 25 0:31 / {escaped_root} rw,relatime - ext4 /dev/root rw\n",
            encoding="utf-8",
        )
        self.assertFalse(
            self.module.is_direct_file_mount(str(self.config), str(mountinfo))
        )
        mountinfo.write_text(
            f"36 25 0:31 / {escaped_config} rw,relatime - ext4 /dev/root rw\n",
            encoding="utf-8",
        )
        self.assertTrue(
            self.module.is_direct_file_mount(str(self.config), str(mountinfo))
        )


class ConfigWriterApiContractTests(unittest.TestCase):
    def test_ai_and_fabric_blocks_compile_and_use_shared_writer(self):
        ai = AI_API.read_text(encoding="utf-8")
        fabric = FABRIC_API.read_text(encoding="utf-8")
        compile(extract_heredoc(ai, "PYTHON_SCRIPT"), str(AI_API), "exec")
        compile(
            extract_heredoc(fabric, "PYTHON_SAVE_TELEM"), str(FABRIC_API), "exec"
        )
        compile(
            extract_heredoc(fabric, "PYTHON_REMOVE_STACK"), str(FABRIC_API), "exec"
        )
        self.assertIn("_config_write_update(", ai)
        self.assertNotIn("with open(conf, 'w')", ai)
        save_block = extract_heredoc(fabric, "PYTHON_SAVE_TELEM")
        remove_block = extract_heredoc(fabric, "PYTHON_REMOVE_STACK")
        self.assertIn("update_lldpq_config", save_block)
        self.assertIn("update_lldpq_config", remove_block)
        self.assertNotIn("open('/etc/lldpq.conf', 'w')", save_block + remove_block)


def _setup_api_fmt_val():
    """Exec only write_conf's nested _fmt_val out of the setup-api heredoc."""
    source = extract_heredoc(SETUP_API.read_text(encoding="utf-8"), "PYTHON")
    lines = source.splitlines()
    start = next(
        index for index, line in enumerate(lines)
        if line.lstrip().startswith("def _fmt_val(")
    )
    indent = len(lines[start]) - len(lines[start].lstrip())
    block = [lines[start][indent:]]
    for line in lines[start + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        block.append(line[indent:] if len(line) > indent else "")
    namespace = {}
    exec("\n".join(block) + "\n", namespace)
    return namespace["_fmt_val"]


class SetSchedulesConfRoundTripTests(unittest.TestCase):
    """A set-schedules-shaped write must decode back to the bare cron string.

    Regression: pre-quoted caller values were quoted a second time by
    _fmt_val, producing LLDPQ_CRON="\\"*/10 * * * *\\"" which the next
    install.sh aborted on with 'Invalid LLDPQ_CRON'."""

    def _decode(self, conf_text):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "lldpq.conf"
            config.write_text(conf_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(CONFIG_HELPER), "--config", str(config)],
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        values = {}
        for line in result.stdout.splitlines():
            key, _, raw = line.partition("=")
            values[key] = shlex.split(raw)[0] if raw else ""
        return values

    def test_set_schedules_shaped_write_round_trips_bare_cron(self):
        fmt_val = _setup_api_fmt_val()
        conf = "LLDPQ_CRON=%s\nGETCONF_CRON=%s\n" % (
            fmt_val("*/10 * * * *"), fmt_val("0 */6 * * *"))
        values = self._decode(conf)
        self.assertEqual(values["LLDPQ_CRON"], "*/10 * * * *")
        self.assertEqual(values["GETCONF_CRON"], "0 */6 * * *")

    def test_fmt_val_strips_one_layer_of_literal_pre_quoting(self):
        # The exact shape the buggy callers produced; also heals values read
        # back from a conf corrupted while the bug was live.
        fmt_val = _setup_api_fmt_val()
        values = self._decode("LLDPQ_CRON=%s\n" % fmt_val('"*/10 * * * *"'))
        self.assertEqual(values["LLDPQ_CRON"], "*/10 * * * *")

    def test_round_trip_value_passes_installer_cron_validation(self):
        fmt_val = _setup_api_fmt_val()
        values = self._decode("LLDPQ_CRON=%s\n" % fmt_val("*/10 * * * *"))
        result = subprocess.run(
            [sys.executable, str(CONFIG_HELPER),
             "--validate-cron", values["LLDPQ_CRON"]],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_write_conf_callers_pass_raw_unquoted_values(self):
        source = SETUP_API.read_text(encoding="utf-8")
        for pre_quoted in (
            "'LLDPQ_CRON': '\"' + lldpq_cron",
            "'GETCONF_CRON': '\"' + getconf_cron",
            "'TRANSCEIVER_FW_SKIP_MODELS': '\"' + skip_models",
        ):
            self.assertNotIn(pre_quoted, source)
        self.assertIn("'LLDPQ_CRON': lldpq_cron", source)
        self.assertIn("'GETCONF_CRON': getconf_cron", source)
        self.assertIn("'TRANSCEIVER_FW_SKIP_MODELS': skip_models", source)


if __name__ == "__main__":
    unittest.main()
