#!/usr/bin/env python3
"""Root-owned atomic mutation gateway for /etc/lldpq-users.conf."""

from __future__ import annotations

import argparse
import errno
import fcntl
import grp
import json
import os
import pwd
import re
import secrets
import stat
import sys
from typing import Callable, Optional


USERS_PATH = "/etc/lldpq-users.conf"
LOCK_PATH = "/etc/lldpq-users.conf.lock"
CONFIG_TARGET = "/home/lldpq/lldpq/config/lldpq-users.conf"
MAX_USERS_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 16 * 1024
USERNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,19}")
HASH_RE = re.compile(r"[0-9a-f]{64}")


class AuthUsersError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _read_descriptor(descriptor: int, limit: int = MAX_USERS_BYTES) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise AuthUsersError("malformed_users_file", "Users file exceeds the safe size limit")


def _write_descriptor(descriptor: int, content: bytes) -> None:
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "users-file stage write made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)
    if _read_descriptor(descriptor) != content:
        raise OSError(errno.EIO, "users-file stage verification failed")


def _fsync_directory(path: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_direct_mount(path: str, mountinfo_path: str = "/proc/self/mountinfo") -> bool:
    normalized = os.path.normpath(os.path.abspath(path))
    try:
        with open(mountinfo_path, encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) < 5:
                    continue
                mountpoint = fields[4]
                for escaped, plain in (
                    ("\\040", " "),
                    ("\\011", "\t"),
                    ("\\012", "\n"),
                    ("\\134", "\\"),
                ):
                    mountpoint = mountpoint.replace(escaped, plain)
                if os.path.normpath(mountpoint) == normalized:
                    return True
    except OSError:
        pass
    return False


def _open_lock(path: str, owner_uid: int, owner_gid: int) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o660)
        created = True
    except FileExistsError:
        descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if created:
            os.fchown(descriptor, owner_uid, owner_gid)
            os.fchmod(descriptor, 0o660)
            os.fsync(descriptor)
            _fsync_directory(os.path.dirname(path))
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != owner_uid
            or opened.st_gid != owner_gid
            or stat.S_IMODE(opened.st_mode) != 0o660
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise AuthUsersError("unsafe_lock", "Users transaction lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (locked.st_dev, locked.st_ino):
            raise AuthUsersError("unsafe_lock", "Users transaction lock changed while waiting")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _resolve_and_open_users(
    users_path: str,
    allowed_config_target: Optional[str],
    owner_uid: int,
    owner_gid: int,
) -> tuple[int, os.stat_result, str, os.stat_result, bool]:
    logical = os.path.abspath(users_path)
    before = os.lstat(logical)
    is_symlink = stat.S_ISLNK(before.st_mode)
    if is_symlink:
        if not allowed_config_target:
            raise AuthUsersError("unsafe_users_file", "Users-file symlink is not allowed")
        target = os.path.realpath(logical)
        expected = os.path.abspath(allowed_config_target)
        if target != expected:
            raise AuthUsersError(
                "unsafe_users_file",
                "Users file does not point to the supported configuration directory",
            )
        target_metadata = os.lstat(target)
        if not stat.S_ISREG(target_metadata.st_mode):
            raise AuthUsersError("unsafe_users_file", "Users-file target is not regular")
    elif stat.S_ISREG(before.st_mode):
        target = logical
        target_metadata = before
    else:
        raise AuthUsersError("unsafe_users_file", "Users file is not a regular file")

    parent = os.path.dirname(target)
    if os.path.realpath(parent) != parent:
        raise AuthUsersError("unsafe_users_file", "Users-file parent is not a real directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        current_target = os.lstat(target)
        current_logical = os.lstat(logical)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (target_metadata.st_dev, target_metadata.st_ino)
            or (opened.st_dev, opened.st_ino)
            != (current_target.st_dev, current_target.st_ino)
        ):
            raise AuthUsersError("unsafe_users_file", "Users file changed while opening")
        if is_symlink:
            if (
                not stat.S_ISLNK(current_logical.st_mode)
                or (before.st_dev, before.st_ino)
                != (current_logical.st_dev, current_logical.st_ino)
                or os.path.realpath(logical) != target
            ):
                raise AuthUsersError("unsafe_users_file", "Users-file link changed while opening")
        elif (opened.st_dev, opened.st_ino) != (
            current_logical.st_dev,
            current_logical.st_ino,
        ):
            raise AuthUsersError("unsafe_users_file", "Users file changed while opening")
        if (
            opened.st_uid != owner_uid
            or opened.st_gid != owner_gid
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise AuthUsersError(
                "unsafe_users_file", "Users file must be owned by www-data with mode 0600"
            )
        return descriptor, opened, target, before, is_symlink
    except Exception:
        os.close(descriptor)
        raise


def _parse_users(raw: bytes) -> list[dict[str, str]]:
    if not raw or len(raw) > MAX_USERS_BYTES or not raw.endswith(b"\n"):
        raise AuthUsersError(
            "malformed_users_file", "Users file is empty, oversized, or lacks a final newline"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuthUsersError("malformed_users_file", "Users file is not valid UTF-8") from exc
    records = []
    seen = set()
    for line in text.splitlines():
        if not line or line.count(":") != 2:
            raise AuthUsersError("malformed_users_file", "Users file has an invalid record")
        username, password_hash, role = line.split(":")
        if not USERNAME_RE.fullmatch(username) or username in seen:
            raise AuthUsersError(
                "malformed_users_file", "Users file has an invalid or duplicate username"
            )
        if not HASH_RE.fullmatch(password_hash):
            raise AuthUsersError("malformed_users_file", "Users file has an invalid password hash")
        if role not in ("admin", "operator"):
            raise AuthUsersError("malformed_users_file", "Users file has an invalid role")
        seen.add(username)
        records.append({"username": username, "password_hash": password_hash, "role": role})
        if len(records) > 1000:
            raise AuthUsersError("malformed_users_file", "Users file has too many records")
    admins = [record for record in records if record["role"] == "admin"]
    if len(admins) != 1 or admins[0]["username"] != "admin":
        raise AuthUsersError(
            "malformed_users_file", "Users file must contain exactly one admin account"
        )
    return records


def _render_users(records: list[dict[str, str]]) -> bytes:
    return (
        "".join(
            f"{record['username']}:{record['password_hash']}:{record['role']}\n"
            for record in records
        )
    ).encode("utf-8")


def _validate_request(request: object) -> tuple[str, str, Optional[str]]:
    if not isinstance(request, dict):
        raise AuthUsersError("invalid_request", "Mutation request must be an object")
    action = request.get("action")
    expected = {
        "change-password": {"action", "username", "password_hash"},
        "create-user": {"action", "username", "password_hash"},
        "delete-user": {"action", "username"},
    }
    if action not in expected or set(request) != expected[action]:
        raise AuthUsersError("invalid_request", "Mutation request fields are invalid")
    username = request.get("username")
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise AuthUsersError("invalid_username", "Invalid username")
    password_hash = request.get("password_hash")
    if action != "delete-user" and (
        not isinstance(password_hash, str) or not HASH_RE.fullmatch(password_hash)
    ):
        raise AuthUsersError("invalid_password_hash", "Invalid password hash")
    return action, username, password_hash


def _apply_mutation(
    records: list[dict[str, str]], action: str, username: str, password_hash: Optional[str]
) -> tuple[list[dict[str, str]], str]:
    index = next(
        (position for position, record in enumerate(records) if record["username"] == username),
        None,
    )
    if action == "change-password":
        if index is None:
            raise AuthUsersError("user_not_found", "User not found")
        updated = [dict(record) for record in records]
        updated[index]["password_hash"] = password_hash
        return updated, "Password changed successfully"
    if action == "create-user":
        if index is not None:
            raise AuthUsersError("user_exists", "User already exists")
        if username == "admin":
            raise AuthUsersError("protected_admin", "Cannot create admin user")
        if len(records) >= 1000:
            raise AuthUsersError("user_limit_reached", "User limit reached")
        updated = [dict(record) for record in records]
        updated.append(
            {"username": username, "password_hash": password_hash, "role": "operator"}
        )
        return updated, f"User '{username}' created successfully"
    if username == "admin":
        raise AuthUsersError("protected_admin", "Cannot delete admin user")
    if index is None:
        raise AuthUsersError("user_not_found", "User not found")
    updated = [dict(record) for position, record in enumerate(records) if position != index]
    return updated, f"User '{username}' deleted successfully"


def _revalidate_original(
    descriptor: int,
    metadata: os.stat_result,
    raw: bytes,
    logical: str,
    target: str,
    logical_before: os.stat_result,
    is_symlink: bool,
) -> None:
    current_target = os.lstat(target)
    if (current_target.st_dev, current_target.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        raise AuthUsersError("revision_conflict", "Users file changed during the update")
    current_logical = os.lstat(logical)
    if is_symlink:
        if (
            not stat.S_ISLNK(current_logical.st_mode)
            or (current_logical.st_dev, current_logical.st_ino)
            != (logical_before.st_dev, logical_before.st_ino)
            or os.path.realpath(logical) != target
        ):
            raise AuthUsersError("revision_conflict", "Users-file link changed during the update")
    elif (current_logical.st_dev, current_logical.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        raise AuthUsersError("revision_conflict", "Users file changed during the update")
    if _read_descriptor(descriptor) != raw:
        raise AuthUsersError("revision_conflict", "Users file changed during the update")


def _cleanup_stale_stages(
    directory_fd: int, target_name: str, owner_uid: int, owner_gid: int
) -> None:
    pattern = re.compile(r"\." + re.escape(target_name) + r"\.auth\.tmp\.[0-9a-f]{24}")
    removed = False
    for name in os.listdir(directory_fd):
        if not pattern.fullmatch(name):
            continue
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != owner_uid
            or metadata.st_gid != owner_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AuthUsersError("unsafe_stage", "Retained users-file stage is unsafe")
        os.unlink(name, dir_fd=directory_fd)
        removed = True
    if removed:
        os.fsync(directory_fd)


def _rollback_installed_candidate(
    directory_fd: int,
    target_name: str,
    original: bytes,
    installed_metadata: os.stat_result,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Durably restore *original* only while our candidate inode is installed.

    Commit verification happens after rename, so an fsync/readback failure can
    otherwise return an API error while leaving the new users database live.
    The rollback itself is another same-directory atomic replacement.  A
    non-cooperating writer that has already replaced our candidate wins: its
    inode is preserved rather than being overwritten with stale data.
    """
    rollback_name = "." + target_name + ".auth.tmp." + secrets.token_hex(12)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    rollback_fd = os.open(rollback_name, flags, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(rollback_fd, owner_uid, owner_gid)
        os.fchmod(rollback_fd, 0o600)
        _write_descriptor(rollback_fd, original)
        rollback_metadata = os.fstat(rollback_fd)
        if (
            not stat.S_ISREG(rollback_metadata.st_mode)
            or rollback_metadata.st_nlink != 1
            or rollback_metadata.st_uid != owner_uid
            or rollback_metadata.st_gid != owner_gid
            or stat.S_IMODE(rollback_metadata.st_mode) != 0o600
        ):
            raise AuthUsersError("rollback_failed", "Users-file rollback stage is unsafe")

        try:
            current = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise AuthUsersError(
                "rollback_skipped_external_change",
                "Users file changed after commit; external replacement was preserved",
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino)
            != (installed_metadata.st_dev, installed_metadata.st_ino)
        ):
            raise AuthUsersError(
                "rollback_skipped_external_change",
                "Users file changed after commit; external replacement was preserved",
            )

        os.replace(
            rollback_name,
            target_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        rollback_name = None
        os.fsync(directory_fd)

        verify_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        verify_flags |= getattr(os, "O_NOFOLLOW", 0)
        verify_fd = os.open(target_name, verify_flags, dir_fd=directory_fd)
        try:
            restored = os.fstat(verify_fd)
            if (
                not stat.S_ISREG(restored.st_mode)
                or restored.st_nlink != 1
                or restored.st_uid != owner_uid
                or restored.st_gid != owner_gid
                or stat.S_IMODE(restored.st_mode) != 0o600
                or (restored.st_dev, restored.st_ino)
                != (rollback_metadata.st_dev, rollback_metadata.st_ino)
                or _read_descriptor(verify_fd) != original
            ):
                raise AuthUsersError(
                    "rollback_failed", "Users-file rollback verification failed"
                )
        finally:
            os.close(verify_fd)
    finally:
        if rollback_name is not None:
            try:
                os.unlink(rollback_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(rollback_fd)


def mutate_users(
    request: object,
    *,
    users_path: str = USERS_PATH,
    lock_path: str = LOCK_PATH,
    allowed_config_target: Optional[str] = CONFIG_TARGET,
    owner_uid: Optional[int] = None,
    owner_gid: Optional[int] = None,
    lock_uid: int = 0,
    lock_gid: Optional[int] = None,
    direct_mount_detector: Callable[[str], bool] = _is_direct_mount,
    before_replace: Optional[Callable[[], None]] = None,
) -> dict:
    if owner_uid is None:
        owner_uid = pwd.getpwnam("www-data").pw_uid
    if owner_gid is None:
        owner_gid = grp.getgrnam("www-data").gr_gid
    if lock_gid is None:
        lock_gid = owner_gid
    action, username, password_hash = _validate_request(request)
    lock_fd = _open_lock(lock_path, lock_uid, lock_gid)
    users_fd = None
    directory_fd = None
    stage_fd = None
    staged_name = None
    try:
        users_fd, metadata, target, logical_before, is_symlink = _resolve_and_open_users(
            users_path, allowed_config_target, owner_uid, owner_gid
        )
        raw = _read_descriptor(users_fd)
        records = _parse_users(raw)
        updated, message = _apply_mutation(records, action, username, password_hash)
        candidate = _render_users(updated)
        # Re-validate the complete candidate, including global invariants such
        # as the record limit, before deciding whether any filesystem work is
        # allowed.
        _parse_users(candidate)
        if candidate == raw:
            return {"success": True, "changed": False, "message": message}
        logical = os.path.abspath(users_path)
        if direct_mount_detector(logical) or direct_mount_detector(target):
            raise AuthUsersError(
                "migration_required",
                "The users file is a legacy direct-file mount and cannot be updated "
                "atomically. Migrate it to the supported config directory/volume and retry.",
            )

        parent = os.path.dirname(target)
        target_name = os.path.basename(target)
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dir_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(parent, dir_flags)
        _cleanup_stale_stages(directory_fd, target_name, owner_uid, owner_gid)
        staged_name = "." + target_name + ".auth.tmp." + secrets.token_hex(12)
        stage_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        stage_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        stage_fd = os.open(staged_name, stage_flags, 0o600, dir_fd=directory_fd)
        os.fchown(stage_fd, owner_uid, owner_gid)
        os.fchmod(stage_fd, 0o600)
        _write_descriptor(stage_fd, candidate)

        if before_replace is not None:
            before_replace()
        _revalidate_original(
            users_fd,
            metadata,
            raw,
            logical,
            target,
            logical_before,
            is_symlink,
        )
        if direct_mount_detector(logical) or direct_mount_detector(target):
            raise AuthUsersError(
                "migration_required",
                "The users file became a direct-file mount during the update; migrate it "
                "to the supported config directory/volume and retry.",
            )
        staged_path = os.stat(staged_name, dir_fd=directory_fd, follow_symlinks=False)
        staged_open = os.fstat(stage_fd)
        if (
            not stat.S_ISREG(staged_open.st_mode)
            or staged_open.st_nlink != 1
            or (staged_open.st_dev, staged_open.st_ino)
            != (staged_path.st_dev, staged_path.st_ino)
            or staged_open.st_uid != owner_uid
            or staged_open.st_gid != owner_gid
            or stat.S_IMODE(staged_open.st_mode) != 0o600
            or _read_descriptor(stage_fd) != candidate
        ):
            raise AuthUsersError("unsafe_stage", "Users-file stage changed before commit")
        candidate_installed = False
        try:
            os.replace(
                staged_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            staged_name = None
            candidate_installed = True
            os.fsync(directory_fd)

            verify_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            verify_flags |= getattr(os, "O_NOFOLLOW", 0)
            verify_fd = os.open(target_name, verify_flags, dir_fd=directory_fd)
            try:
                installed = os.fstat(verify_fd)
                if (
                    not stat.S_ISREG(installed.st_mode)
                    or installed.st_nlink != 1
                    or installed.st_uid != owner_uid
                    or installed.st_gid != owner_gid
                    or stat.S_IMODE(installed.st_mode) != 0o600
                    or (installed.st_dev, installed.st_ino)
                    != (staged_open.st_dev, staged_open.st_ino)
                    or _read_descriptor(verify_fd) != candidate
                ):
                    raise AuthUsersError(
                        "commit_verification_failed", "Users-file commit failed"
                    )
            finally:
                os.close(verify_fd)
        except Exception as commit_error:
            if not candidate_installed:
                raise
            try:
                _rollback_installed_candidate(
                    directory_fd,
                    target_name,
                    raw,
                    staged_open,
                    owner_uid,
                    owner_gid,
                )
            except AuthUsersError as rollback_error:
                if rollback_error.code == "rollback_skipped_external_change":
                    raise rollback_error from commit_error
                raise AuthUsersError(
                    "rollback_failed",
                    "Users-file commit failed and the original database could not be "
                    "verified as restored",
                ) from rollback_error
            except OSError as rollback_error:
                raise AuthUsersError(
                    "rollback_failed",
                    "Users-file commit failed and the original database could not be "
                    "verified as restored",
                ) from rollback_error
            raise
        response = {"success": True, "changed": True, "message": message}
        if action == "delete-user":
            response["deleted_user"] = username
        return response
    finally:
        if staged_name is not None and directory_fd is not None:
            try:
                os.unlink(staged_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        if stage_fd is not None:
            os.close(stage_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        if users_fd is not None:
            os.close(users_fd)
        os.close(lock_fd)


def _load_request() -> object:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise AuthUsersError("invalid_request", "Mutation request is too large")

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise AuthUsersError("invalid_request", "Mutation request has duplicate keys")
            value[key] = item
        return value

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthUsersError("invalid_request", "Mutation request is not valid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise AuthUsersError("privilege_required", "Auth users helper must run as root")
        response = mutate_users(_load_request())
        print(json.dumps(response, separators=(",", ":")))
        return 0
    except AuthUsersError as exc:
        print(json.dumps({"success": False, "code": exc.code, "error": str(exc)}))
        return 2
    except OSError as exc:
        print(json.dumps({"success": False, "code": "io_error", "error": str(exc)[:300]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
