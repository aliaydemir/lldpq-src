"""Exercise the real CGI boundary and portable BMC backup validation locally."""
import ast
import base64
import builtins
from contextlib import ExitStack, redirect_stdout
import grp
import fcntl
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_import

REPO = Path(__file__).resolve().parent.parent
ROW = {"switch": "oob-01", "port": "swp1", "expected_mac": "02-AA-BB-CC-DD-01",
       "hostname": "server-01-bmc", "vlan": 100, "enabled": True}


class BMCAPITest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("bmc_config.py", "bmc_results.py", "parse_devices.py", "addressing.py"):
            (self.root / name).symlink_to(REPO / "lldpq" / name)
        (self.root / "devices.yaml").write_text("defaults:\n  username: cumulus\ndevices:\n  192.0.2.1: oob-01 @oob\n")
        helper = self.root / "config-helper"
        helper.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote("LLDPQ_DIR=" + shlex.quote(str(self.root))) + "\n")
        helper.chmod(0o755)
        self.env = {**os.environ, "LLDPQ_CONFIG_HELPER": str(helper), "WEB_ROOT": str(self.root),
                    "LLDPQ_AUTH_ROLE": "admin", "LLDPQ_AUTH_USER": "test-admin",
                    "LLDPQ_BMC_FILE_GROUP": grp.getgrgid(os.getgid()).gr_name,
                    "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")}

    def call(self, action="config", body=None, **env):
        raw = json.dumps(body).encode() if isinstance(body, (dict, list)) else body or b""
        settings = {**self.env, "QUERY_STRING": "action=" + action,
                    "REQUEST_METHOD": "GET" if body is None else "POST",
                    "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(raw)), **env}
        result = subprocess.run(["bash", str(REPO / "html/bmc-api.sh")], input=raw,
                                env=settings, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        headers, payload = result.stdout.decode().split("\n\n", 1)
        status = int(next(line for line in headers.splitlines() if line.startswith("Status:")).split()[1])
        return status, json.loads(payload)

    def test_config_save_results_and_conflict(self):
        status, initial = self.call()
        self.assertEqual(status, 200)
        self.assertEqual(initial["mappings"], [])
        status, saved = self.call("save", {"revision": initial["revision"], "mappings": [ROW]})
        self.assertEqual(status, 200, saved)
        self.assertEqual(saved["mappings"][0]["expected_mac"], "02:aa:bb:cc:dd:01")
        status, results = self.call("results")
        self.assertEqual(status, 200, results)
        self.assertEqual(results["rows"][0]["status"], "UNKNOWN")
        self.assertEqual(results["rows"][0]["active_macs"], [])
        status, conflict = self.call("save", {"revision": initial["revision"], "mappings": []})
        self.assertEqual(status, 409)
        self.assertTrue(conflict["conflict"])
        self.assertEqual(self.call()[1]["mappings"], saved["mappings"])

    def test_roles(self):
        self.assertEqual(self.call(LLDPQ_AUTH_ROLE="")[0], 401)
        self.assertEqual(self.call(LLDPQ_AUTH_ROLE="operator")[0], 200)
        self.assertEqual(self.call("save", {}, LLDPQ_AUTH_ROLE="operator")[0], 403)

    def test_request_validation_does_not_write(self):
        cases = [
            ("invalid", None, {}, 400),
            ("save", None, {}, 405),
            ("results", {}, {}, 405),
            ("save", b"{}", {"CONTENT_TYPE": "text/plain"}, 415),
            ("save", b"{}", {"CONTENT_LENGTH": "2097153"}, 413),
            ("save", b"{}", {"CONTENT_LENGTH": "-2"}, 400),
            ("save", b"{}", {"CONTENT_LENGTH": "10"}, 400),
            ("save", b"{broken", {}, 400),
            ("save", b'{"mappings":NaN}', {}, 400),
            ("save", [], {}, 400),
            ("save", {}, {}, 400),
        ]
        for action, body, env, expected in cases:
            with self.subTest(action=action, body=body, env=env):
                self.assertEqual(self.call(action, body, **env)[0], expected)
        self.assertFalse((self.root / "bmc.yaml").exists())

    def test_invalid_mapping_cannot_replace_saved_configuration(self):
        revision = self.call()[1]["revision"]
        self.assertEqual(self.call("save", {"revision": revision, "mappings": [ROW]})[0], 200)
        previous = (self.root / "bmc.yaml").read_bytes()
        revision = self.call()[1]["revision"]
        status, _ = self.call("save", {"revision": revision, "mappings": [{**ROW, "port": "bond0"}]})
        self.assertEqual(status, 400)
        self.assertEqual((self.root / "bmc.yaml").read_bytes(), previous)

    def test_save_waits_for_inventory_writer_then_rechecks_revision(self):
        revision = self.call()[1]["revision"]
        raw = json.dumps({"revision": revision, "mappings": [ROW]}).encode()
        settings = {**self.env, "QUERY_STRING": "action=save", "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(raw))}
        with open(self.root / ".inventory.lock", "w+") as writer:
            fcntl.flock(writer, fcntl.LOCK_EX)
            pending = subprocess.Popen(["bash", str(REPO / "html/bmc-api.sh")],
                                       env=settings, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    pending.communicate(raw, timeout=0.5)
                self.assertFalse((self.root / "bmc.yaml").exists())
                # Cached reads do not need the writer lock.
                self.assertEqual(self.call("config")[0], 200)
                self.assertEqual(self.call("results")[0], 200)
                with (self.root / "devices.yaml").open("a") as inventory:
                    inventory.write("# Changed by the inventory writer\n")
                fcntl.flock(writer, fcntl.LOCK_UN)
                output, errors = pending.communicate(timeout=10)
                self.assertEqual(pending.returncode, 0, errors.decode())
                self.assertIn(b"Status: 409 Conflict", output)
                self.assertFalse((self.root / "bmc.yaml").exists())
            finally:
                if pending.poll() is None:
                    pending.kill()
                    pending.communicate()

    def test_save_restores_owned_inventory_lock_group_bits(self):
        revision = self.call()[1]["revision"]
        lock = self.root / ".inventory.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        self.assertEqual(self.call("save", {"revision": revision, "mappings": [ROW]})[0], 200)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode) & 0o660, 0o660)


class BMCBackupTest(unittest.TestCase):
    def validate(self, content):
        return backup_import.validate_config_for_bundle("bmc.yaml", content, lldpq_dir=str(REPO / "lldpq"))

    def test_backup_round_trip_including_orphan_switch(self):
        content = json.dumps({"version": 1, "mappings": [ROW]}).encode()
        self.assertTrue(self.validate(content))
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            backup_import.add_regular_tar_member(archive, "bmc.yaml", content)
        entries, prefs = backup_import._parse_bundle(data.getvalue(), {"bmc.yaml": str(REPO / "lldpq")},
                                                     set(), set(), lambda _: True, str(REPO / "lldpq"))
        self.assertEqual(entries[0]["content"], content)
        self.assertEqual(prefs, {})

    def test_rejects_duplicate_keys_invalid_mac_and_conflicting_bindings(self):
        for content in (b"version: 1\nmappings: []\nmappings: []\n",
                        json.dumps({"mappings": [{**ROW, "expected_mac": "bad"}]}).encode(),
                        json.dumps({"mappings": [ROW, {**ROW, "port": "swp2"}]}).encode()):
            with self.subTest(content=content), self.assertRaises(backup_import.BackupImportError):
                self.validate(content)

    def test_legacy_recovery_without_bmc_support_remains_available(self):
        with tempfile.TemporaryDirectory() as root:
            with backup_import.bmc_configuration_lock(root):
                self.assertFalse((Path(root) / "bmc.yaml").exists())

    def test_backup_lock_works_without_application_module_and_shares_editor_lock(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "bmc.yaml"
            target.write_text("version: 1\nmappings: []\n")
            with backup_import.bmc_configuration_lock(root):
                with open(str(target) + ".lock", "r+") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with open(str(target) + ".lock", "r+") as contender:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_backup_lock_resolves_missing_docker_target_and_floors_group_mode(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "config/bmc.yaml"
            target.parent.mkdir()
            (Path(root) / "bmc.yaml").symlink_to(target)
            old_umask = os.umask(0o077)
            try:
                with backup_import.bmc_configuration_lock(root):
                    lock = Path(str(target) + ".lock")
                    self.assertEqual(lock.stat().st_mode & 0o777, 0o660)
                    self.assertEqual(lock.stat().st_gid, target.parent.stat().st_gid)
                    self.assertFalse(target.exists())
            finally:
                os.umask(old_umask)

    def test_backup_lock_rejects_unmanaged_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "other.yaml").write_text("{}")
            (Path(root) / "bmc.yaml").symlink_to(Path(root) / "other.yaml")
            with self.assertRaises(backup_import.BackupImportError):
                with backup_import.bmc_configuration_lock(root):
                    self.fail("unmanaged target was locked")


class BMCSetupBackupRoundTripTest(unittest.TestCase):
    """Run Setup's actual export/import handlers against isolated config files.

    Only OS account/privilege boundaries are adapted to the current test user;
    archive validation, staging, activation, and recovery cleanup are real.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lldpq-bmc-backup-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.application = self.root / "application"
        self.web = self.root / "web"
        self.home = self.root / "home"
        for directory in (self.application, self.web, self.home):
            directory.mkdir()
        (self.application / "bmc_config.py").symlink_to(REPO / "lldpq/bmc_config.py")
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(),
                                       pw_dir=str(self.home), pw_name="lldpq-backup-test")
        self.group = SimpleNamespace(gr_gid=os.getgid())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(backup_import.pwd, "getpwnam", return_value=self.account))
        self.stack.enter_context(mock.patch.object(backup_import.grp, "getgrnam", return_value=self.group))
        self.stack.enter_context(mock.patch.object(backup_import, "_docker_environment", return_value=False))
        self.stack.enter_context(mock.patch.object(
            backup_import, "_as_collector",
            side_effect=lambda _user, arguments, **kwargs: backup_import._run(arguments, **kwargs),
        ))
        # Production runs on Linux. Homebrew provides equivalent GNU commands
        # for running the same filesystem transaction in macOS development.
        if sys.platform == "darwin":
            commands = ("sync", "mv", "chmod", "chgrp", "stat", "cp", "rm")
            binaries = {name: shutil.which("g" + name) for name in commands}
            if not all(binaries.values()):
                self.skipTest("GNU coreutils are needed for the Linux restore transaction")
            toolbin = self.root / "bin"
            toolbin.mkdir()
            for name, executable in binaries.items():
                (toolbin / name).symlink_to(executable)
            self.stack.enter_context(mock.patch.dict(os.environ, {
                "PATH": str(toolbin) + os.pathsep + os.environ.get("PATH", ""),
            }))
            self.stack.enter_context(mock.patch.object(
                backup_import, "_secure_list_dir",
                side_effect=lambda _user, path: os.listdir(path),
            ))
        original_open = builtins.open

        def fixture_open(path, *args, **kwargs):
            if path == "/etc/lldpq.conf":
                raise FileNotFoundError(path)
            return original_open(path, *args, **kwargs)

        self.stack.enter_context(mock.patch("builtins.open", side_effect=fixture_open))
        source = (REPO / "html/setup-api.sh").read_text().split("python3 << 'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
        self.handlers = {}
        for node in ast.parse(source).body:
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
                if isinstance(node.test.left, ast.Name) and node.test.left.id == "action":
                    action = ast.literal_eval(node.test.comparators[0])
                    if action in ("backup-export", "backup-import"):
                        self.handlers[action] = compile(ast.Module(body=[node], type_ignores=[]), "setup-backup-handler", "exec")

    def call_setup(self, action, body):
        with ExitStack() as locks:
            def acquire_lock():
                locks.enter_context(backup_import.bmc_configuration_lock(str(self.application)))

            namespace = {
                "action": action, "post_data": body, "json": json, "sys": sys,
                "lldpq_dir": str(self.application), "web_root": str(self.web),
                "lldpq_user": self.account.pw_name, "LLDPQ_PREF_KEYS": set(),
                "load_backup_import_helper": lambda _name: backup_import,
                "ensure_backup_locks": acquire_lock,
                "ensure_restore_locks": acquire_lock,
                "ensure_configuration_lock": lambda: None,
                "valid_cron_schedule": lambda _schedule: True,
            }
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
                exec(self.handlers[action], namespace)
            self.assertEqual(stopped.exception.code, 0)
            return json.loads(output.getvalue())

    def test_setup_export_then_restore_preserves_bmc_mappings_and_managed_link(self):
        for use_link in (False, True):
            with self.subTest(managed_config_link=use_link):
                logical = self.application / "bmc.yaml"
                if logical.exists():
                    logical.unlink()
                target = logical
                if use_link:
                    target = self.application / "config/bmc.yaml"
                    target.parent.mkdir(exist_ok=True)
                    logical.symlink_to(target)
                original = json.dumps({"version": 1, "mappings": [
                    ROW, {**ROW, "switch": "oob-02", "port": "swp12",
                          "expected_mac": "02:aa:bb:cc:dd:02", "hostname": "server-02-bmc",
                          "vlan": None, "bmc_ip": "192.0.2.22", "enabled": False},
                ]}).encode()
                target.write_bytes(original)
                exported = self.call_setup("backup-export", {"include_key": False})
                self.assertTrue(exported["success"], exported)
                self.assertIn("bmc.yaml", exported["files"])
                with tarfile.open(fileobj=io.BytesIO(base64.b64decode(exported["data"])), mode="r:gz") as archive:
                    self.assertTrue(archive.getmember("bmc.yaml").isfile())
                    self.assertEqual(archive.extractfile("bmc.yaml").read(), original)
                target.write_text("version: 1\nmappings: []\n")
                restored = self.call_setup("backup-import", {"data": exported["data"]})
                self.assertTrue(restored["success"], restored)
                self.assertIn("bmc.yaml", restored["restored"])
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(logical.is_symlink(), use_link)
                self.assertFalse((self.home / ".lldpq-state/.backup-import-recovery").exists())


if __name__ == "__main__":
    unittest.main()
