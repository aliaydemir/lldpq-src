#!/usr/bin/env python3
"""Atomicity and deployment contracts for the authentication users database."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "lldpq" / "auth_users.py"
SPEC = importlib.util.spec_from_file_location("test_lldpq_auth_users", HELPER_PATH)
assert SPEC is not None and SPEC.loader is not None
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)


def password_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class AuthUsersAtomicTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.users = self.root / "lldpq-users.conf"
        self.lock = self.root / "lldpq-users.conf.lock"
        self.admin_hash = password_hash("admin")
        self.operator_hash = password_hash("operator")
        self.original = (
            f"admin:{self.admin_hash}:admin\n"
            f"operator:{self.operator_hash}:operator\n"
        ).encode()
        self.users.write_bytes(self.original)
        self.users.chmod(0o600)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        # Pre-create the stable lock as install/startup does; concurrent tests
        # therefore exercise flock ordering rather than lock bootstrap.
        lock_fd = AUTH._open_lock(str(self.lock), self.uid, self.gid)
        os.close(lock_fd)

    def mutate(self, request, **options):
        return AUTH.mutate_users(
            request,
            users_path=str(self.users),
            lock_path=str(self.lock),
            allowed_config_target=None,
            owner_uid=self.uid,
            owner_gid=self.gid,
            lock_uid=self.uid,
            lock_gid=self.gid,
            direct_mount_detector=lambda _path: False,
            **options,
        )

    def records(self):
        return AUTH._parse_users(self.users.read_bytes())

    def test_change_create_delete_use_one_atomic_commit_and_preserve_metadata(self):
        original_inode = self.users.stat().st_ino
        changed_hash = password_hash("new-password")
        response = self.mutate({
            "action": "change-password",
            "username": "operator",
            "password_hash": changed_hash,
        })
        self.assertTrue(response["changed"])
        self.assertNotEqual(self.users.stat().st_ino, original_inode)
        self.assertEqual(self.records()[1]["password_hash"], changed_hash)

        response = self.mutate({
            "action": "create-user",
            "username": "leafuser",
            "password_hash": password_hash("leaf-password"),
        })
        self.assertTrue(response["changed"])
        self.assertEqual([item["username"] for item in self.records()][-1], "leafuser")

        response = self.mutate({"action": "delete-user", "username": "leafuser"})
        self.assertEqual(response["deleted_user"], "leafuser")
        self.assertNotIn("leafuser", [item["username"] for item in self.records()])
        metadata = self.users.stat()
        self.assertEqual(metadata.st_uid, self.uid)
        self.assertEqual(metadata.st_gid, self.gid)
        self.assertEqual(metadata.st_mode & 0o777, 0o600)

    def test_official_config_symlink_is_preserved_and_target_is_atomically_replaced(self):
        config_dir = self.root / "config"
        config_dir.mkdir()
        target = config_dir / "lldpq-users.conf"
        self.users.replace(target)
        self.users.symlink_to(target)
        target_inode = target.stat().st_ino

        AUTH.mutate_users(
            {
                "action": "change-password",
                "username": "operator",
                "password_hash": password_hash("replacement"),
            },
            users_path=str(self.users),
            lock_path=str(self.lock),
            allowed_config_target=str(target),
            owner_uid=self.uid,
            owner_gid=self.gid,
            lock_uid=self.uid,
            lock_gid=self.gid,
            direct_mount_detector=lambda _path: False,
        )

        self.assertTrue(self.users.is_symlink())
        self.assertNotEqual(target.stat().st_ino, target_inode)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_direct_file_mount_changed_fails_without_touching_target(self):
        before = self.users.read_bytes()
        inode = self.users.stat().st_ino
        with self.assertRaisesRegex(AUTH.AuthUsersError, "legacy direct-file mount") as caught:
            AUTH.mutate_users(
                {
                    "action": "create-user",
                    "username": "blockeduser",
                    "password_hash": password_hash("blocked-password"),
                },
                users_path=str(self.users),
                lock_path=str(self.lock),
                allowed_config_target=None,
                owner_uid=self.uid,
                owner_gid=self.gid,
                lock_uid=self.uid,
                lock_gid=self.gid,
                direct_mount_detector=lambda _path: True,
            )
        self.assertEqual(caught.exception.code, "migration_required")
        self.assertEqual(self.users.read_bytes(), before)
        self.assertEqual(self.users.stat().st_ino, inode)
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_direct_file_mount_unchanged_is_successful_noop(self):
        inode = self.users.stat().st_ino
        response = AUTH.mutate_users(
            {
                "action": "change-password",
                "username": "operator",
                "password_hash": self.operator_hash,
            },
            users_path=str(self.users),
            lock_path=str(self.lock),
            allowed_config_target=None,
            owner_uid=self.uid,
            owner_gid=self.gid,
            lock_uid=self.uid,
            lock_gid=self.gid,
            direct_mount_detector=lambda _path: True,
        )
        self.assertFalse(response["changed"])
        self.assertEqual(self.users.stat().st_ino, inode)
        self.assertEqual(self.users.read_bytes(), self.original)

    def test_failure_after_durable_stage_before_replace_keeps_original(self):
        def injected_crash():
            raise RuntimeError("injected crash before replace")

        inode = self.users.stat().st_ino
        with self.assertRaisesRegex(RuntimeError, "injected crash"):
            self.mutate(
                {
                    "action": "change-password",
                    "username": "operator",
                    "password_hash": password_hash("never-installed"),
                },
                before_replace=injected_crash,
            )
        self.assertEqual(self.users.read_bytes(), self.original)
        self.assertEqual(self.users.stat().st_ino, inode)
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_killed_before_replace_keeps_original_and_next_commit_cleans_stage(self):
        request = {
            "action": "change-password",
            "username": "operator",
            "password_hash": password_hash("after-crash"),
        }
        script = f"""
import importlib.util, os
spec=importlib.util.spec_from_file_location('auth_users_killed', {str(HELPER_PATH)!r})
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.mutate_users(
    {request!r}, users_path={str(self.users)!r}, lock_path={str(self.lock)!r},
    allowed_config_target=None, owner_uid={self.uid}, owner_gid={self.gid},
    lock_uid={self.uid}, lock_gid={self.gid},
    direct_mount_detector=lambda path: False,
    before_replace=lambda: os._exit(91))
"""
        killed = subprocess.run([sys.executable, "-c", script])
        self.assertEqual(killed.returncode, 91)
        self.assertEqual(self.users.read_bytes(), self.original)
        self.assertEqual(len(list(self.root.glob("*.auth.tmp.*"))), 1)

        response = self.mutate(request)
        self.assertTrue(response["changed"])
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_directory_fsync_failure_rolls_back_original_durably(self):
        real_fsync = AUTH.os.fsync
        injected = False

        def fail_first_directory_fsync(descriptor):
            nonlocal injected
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not injected:
                injected = True
                raise OSError(errno.EIO, "injected directory fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(AUTH.os, "fsync", side_effect=fail_first_directory_fsync):
            with self.assertRaisesRegex(OSError, "injected directory fsync failure"):
                self.mutate({
                    "action": "change-password",
                    "username": "operator",
                    "password_hash": password_hash("must-be-rolled-back"),
                })

        self.assertTrue(injected)
        self.assertEqual(self.users.read_bytes(), self.original)
        metadata = self.users.stat()
        self.assertEqual((metadata.st_uid, metadata.st_gid), (self.uid, self.gid))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_commit_readback_failure_rolls_back_original_durably(self):
        real_read = AUTH._read_descriptor
        reads = 0

        def fail_candidate_readback(descriptor, limit=AUTH.MAX_USERS_BYTES):
            nonlocal reads
            reads += 1
            # Initial snapshot, staged write verification, original recheck and
            # staged pre-commit verification all succeed.  Fail only the first
            # read through the newly installed pathname.
            if reads == 5:
                return b"injected-invalid-candidate-readback"
            return real_read(descriptor, limit)

        with mock.patch.object(
            AUTH, "_read_descriptor", side_effect=fail_candidate_readback
        ):
            with self.assertRaises(AUTH.AuthUsersError) as caught:
                self.mutate({
                    "action": "create-user",
                    "username": "rollbackuser",
                    "password_hash": password_hash("must-be-rolled-back"),
                })

        self.assertEqual(caught.exception.code, "commit_verification_failed")
        self.assertGreaterEqual(reads, 7)
        self.assertEqual(self.users.read_bytes(), self.original)
        metadata = self.users.stat()
        self.assertEqual((metadata.st_uid, metadata.st_gid), (self.uid, self.gid))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_rollback_preserves_noncooperating_post_commit_replacement(self):
        external_hash = password_hash("external-after-commit")
        external = (
            f"admin:{self.admin_hash}:admin\n"
            f"operator:{external_hash}:operator\n"
        ).encode()
        real_fsync = AUTH.os.fsync
        replaced = False

        def replace_before_failed_directory_fsync(descriptor):
            nonlocal replaced
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not replaced:
                external_stage = self.root / ".external-users"
                external_stage.write_bytes(external)
                external_stage.chmod(0o600)
                os.replace(external_stage, self.users)
                replaced = True
                raise OSError(errno.EIO, "injected post-replace fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(
            AUTH.os, "fsync", side_effect=replace_before_failed_directory_fsync
        ):
            with self.assertRaises(AUTH.AuthUsersError) as caught:
                self.mutate({
                    "action": "change-password",
                    "username": "operator",
                    "password_hash": password_hash("losing-writer"),
                })

        self.assertTrue(replaced)
        self.assertEqual(caught.exception.code, "rollback_skipped_external_change")
        self.assertEqual(self.users.read_bytes(), external)
        self.assertEqual(list(self.root.glob("*.auth.tmp.*")), [])

    def test_noncooperating_replace_race_is_detected_without_clobber(self):
        external_hash = password_hash("external-writer")
        external = (
            f"admin:{self.admin_hash}:admin\n"
            f"operator:{external_hash}:operator\n"
        ).encode()

        def external_replace():
            stage = self.root / "external"
            stage.write_bytes(external)
            stage.chmod(0o600)
            os.replace(stage, self.users)

        with self.assertRaises(AUTH.AuthUsersError) as caught:
            self.mutate(
                {
                    "action": "change-password",
                    "username": "operator",
                    "password_hash": password_hash("racing-update"),
                },
                before_replace=external_replace,
            )
        self.assertEqual(caught.exception.code, "revision_conflict")
        self.assertEqual(self.users.read_bytes(), external)

    def test_malformed_users_file_fails_closed_without_rewrite(self):
        malformed = (
            f"admin:{self.admin_hash}:admin\n"
            f"operator:not-a-hash:operator\n"
        ).encode()
        self.users.write_bytes(malformed)
        self.users.chmod(0o600)
        inode = self.users.stat().st_ino
        with self.assertRaises(AUTH.AuthUsersError) as caught:
            self.mutate({
                "action": "create-user",
                "username": "newuser",
                "password_hash": password_hash("new-password"),
            })
        self.assertEqual(caught.exception.code, "malformed_users_file")
        self.assertEqual(self.users.read_bytes(), malformed)
        self.assertEqual(self.users.stat().st_ino, inode)

    def test_create_cannot_commit_more_than_the_valid_user_limit(self):
        records = [f"admin:{self.admin_hash}:admin\n"]
        records.extend(
            f"u{number:04d}:{password_hash(str(number))}:operator\n"
            for number in range(999)
        )
        full = "".join(records).encode()
        self.users.write_bytes(full)
        self.users.chmod(0o600)
        inode = self.users.stat().st_ino
        with self.assertRaises(AUTH.AuthUsersError) as caught:
            self.mutate({
                "action": "create-user",
                "username": "overflowuser",
                "password_hash": password_hash("overflow-password"),
            })
        self.assertEqual(caught.exception.code, "user_limit_reached")
        self.assertEqual(self.users.read_bytes(), full)
        self.assertEqual(self.users.stat().st_ino, inode)

    def test_two_concurrent_creates_serialize_and_only_one_commits(self):
        request = {
            "action": "create-user",
            "username": "raceuser",
            "password_hash": password_hash("race-password"),
        }
        script = f"""
import importlib.util, json, os
spec=importlib.util.spec_from_file_location('auth_users_subprocess', {str(HELPER_PATH)!r})
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
try:
    result=module.mutate_users(
        {request!r}, users_path={str(self.users)!r}, lock_path={str(self.lock)!r},
        allowed_config_target=None, owner_uid={self.uid}, owner_gid={self.gid},
        lock_uid={self.uid}, lock_gid={self.gid},
        direct_mount_detector=lambda path: False)
    print(json.dumps({{'success': True, 'result': result}}))
except module.AuthUsersError as exc:
    print(json.dumps({{'success': False, 'code': exc.code}}))
"""
        workers = [
            subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        results = []
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=5)
            self.assertEqual(worker.returncode, 0, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(sum(bool(item["success"]) for item in results), 1)
        self.assertEqual(
            [item.get("code") for item in results if not item["success"]], ["user_exists"]
        )
        self.assertEqual(
            [item["username"] for item in self.records()].count("raceuser"), 1
        )


class AuthUsersDeploymentContractTests(unittest.TestCase):
    def test_auth_cgi_has_no_live_truncate_or_append_mutation(self):
        source = (ROOT / "html" / "auth-api.sh").read_text()
        self.assertIn("auth_users_mutate", source)
        self.assertIn("/usr/local/libexec/lldpq-auth-users.py", source)
        self.assertNotRegex(source, r'cat\s+"\$TMP_FILE"\s*>\s*"\$USERS_FILE"')
        self.assertNotRegex(source, r'>>\s*"\$USERS_FILE"')
        self.assertIn('current_record=$(get_user_record "$session_user")', source)
        login = source[source.index("    login)"):source.index("    logout)")]
        self.assertLess(login.index("acquire_users_read_lock"),
                        login.index("verify_credentials"))
        self.assertLess(login.index("verify_credentials"),
                        login.index("# Create session file (single write)"))
        self.assertLess(login.index("# Create session file (single write)"),
                        login.index("release_users_read_lock"))
        self.assertLess(source.index("RESULT=$(auth_users_mutate delete-user"),
                        source.index("# Remove any active sessions for this user"))

    def test_native_and_docker_install_root_helper_lock_and_exact_sudo_rule(self):
        install = (ROOT / "install.sh").read_text()
        dockerfile = (ROOT / "docker" / "Dockerfile").read_text()
        entrypoint = (ROOT / "docker" / "docker-entrypoint.sh").read_text()
        uninstall = (ROOT / "uninstall.sh").read_text()
        for source in (install, dockerfile):
            self.assertIn("lldpq-auth-users.py", source)
        self.assertIn('$LLDPQ_AUTH_USERS_HELPER \\\"\\\"', install)
        self.assertIn('lldpq-auth-users.py ""', dockerfile)
        self.assertIn("prepare_shared_lock_files /etc/lldpq-users.conf.lock", install)
        self.assertIn('$LLDPQ_INSTALL_DIR/auth_users.py', install)
        self.assertGreaterEqual(install.count("auth-users-helper"), 3)
        self.assertGreaterEqual(install.count("sudoers-www-data-lldpq-auth"), 3)
        self.assertIn("/home/lldpq/lldpq/auth_users.py", dockerfile)
        self.assertIn("/etc/lldpq-users.conf.lock", entrypoint)
        self.assertIn("LLDPQ_AUTH_USERS_HELPER", uninstall)
        self.assertIn("www-data-lldpq-auth", uninstall)
        self.assertIn("/etc/lldpq-users.conf.lock", uninstall)


if __name__ == "__main__":
    unittest.main()
