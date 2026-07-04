#!/usr/bin/env python3
"""Validated, all-or-rollback Setup backup restore transaction."""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import grp
import hashlib
import io
import json
import os
import pathlib
import pwd
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable, Iterable


class BackupImportError(RuntimeError):
    """A bundle could not be validated, committed, or rolled back safely."""


def collect_managed_config_files(wanted, managed_roots, *, max_size=2 * 1024 * 1024):
    """Read config links as stable regular-file bytes, confined to managed roots."""
    roots = tuple(os.path.realpath(root) for root in managed_roots)
    collected = []
    for archive_name, base_dir in wanted:
        logical_path = os.path.join(base_dir, archive_name)
        if not os.path.lexists(logical_path):
            continue
        resolved = os.path.realpath(logical_path)
        try:
            managed = any(
                os.path.commonpath((resolved, root)) == root for root in roots
            )
        except ValueError:
            managed = False
        if not managed:
            raise BackupImportError(
                f"Config link points outside the managed LLDPq directories: {logical_path}"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(resolved, flags)
        except OSError as exc:
            raise BackupImportError(f"Could not open {logical_path}: {exc}") from exc
        try:
            with os.fdopen(descriptor, "rb") as handle:
                before = os.fstat(handle.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise BackupImportError(
                        f"Backup source is not a regular file: {logical_path}"
                    )
                if before.st_size > max_size:
                    raise BackupImportError(
                        f"Backup source is too large: {archive_name}"
                    )
                content = handle.read(max_size + 1)
                after = os.fstat(handle.fileno())
        except Exception:
            # os.fdopen owns and closes descriptor once construction succeeds.
            raise
        if len(content) > max_size:
            raise BackupImportError(f"Backup source is too large: {archive_name}")
        if (
            len(content) != after.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise BackupImportError(
                f"Backup source changed while it was being read: {archive_name}"
            )
        collected.append((archive_name, content))
    return collected


def add_regular_tar_member(archive, name, content, *, mode=0o600):
    """Add deterministic bytes as a regular member; never preserve source link metadata."""
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise BackupImportError(f"Unsafe archive member name: {name}")
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = mode
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = 0
    archive.addfile(member, io.BytesIO(content))


def _run(command, *, input_data=None, timeout=10):
    try:
        result = subprocess.run(
            command, input=input_data, capture_output=True, timeout=timeout,
        )
    except Exception as exc:
        raise BackupImportError(f"Command failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()[:160]
        raise BackupImportError(detail or f"Command returned {result.returncode}")
    return result


def _as_collector(user, arguments, **kwargs):
    return _run(["sudo", "-u", user, *arguments], **kwargs)


def _collector_shell(user, script, *arguments, timeout=10):
    # The script is constant. Paths are positional arguments, never shell text.
    return _as_collector(
        user,
        ["bash", "-c", script, "lldpq-backup-import", *arguments],
        timeout=timeout,
    )


def _secure_path_state(user, path):
    result = _collector_shell(
        user,
        'if [ -L "$1" ]; then printf symlink; '
        'elif [ -d "$1" ]; then printf directory; '
        'elif [ -f "$1" ]; then printf file; '
        'elif [ -e "$1" ]; then printf other; else printf missing; fi',
        path,
        timeout=10,
    )
    state = result.stdout.decode("ascii", "strict")
    if state not in ("symlink", "directory", "file", "other", "missing"):
        raise BackupImportError("Could not determine secure path state")
    return state


def _is_direct_mount(path):
    """Return True when path itself is a Linux mount point (including file binds)."""
    normalized = os.path.normpath(os.path.abspath(path))
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) < 5:
                    continue
                mountpoint = fields[4]
                for escaped, plain in (
                    ("\\040", " "), ("\\011", "\t"),
                    ("\\012", "\n"), ("\\134", "\\"),
                ):
                    mountpoint = mountpoint.replace(escaped, plain)
                if os.path.normpath(mountpoint) == normalized:
                    return True
    except OSError:
        pass
    return False


def _durable_path(path, *, reader=None, include_parent=True):
    """Flush file metadata/content and, for rename durability, its parent directory."""
    if reader:
        script = 'sync -f -- "$1"; if [ "$2" = yes ]; then sync -f -- "$(dirname -- "$1")"; fi'
        _collector_shell(
            reader, script, path, "yes" if include_parent else "no", timeout=15
        )
        return
    targets = [path]
    if include_parent:
        targets.append(os.path.dirname(path) or "/")
    for target in targets:
        descriptor = None
        try:
            descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            os.fsync(descriptor)
        except OSError as exc:
            raise BackupImportError(f"Could not durably flush {target}: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _durable_existing_parent(path, *, reader=None):
    """Flush the nearest existing directory when a missing target has no parent yet."""
    candidate = os.path.dirname(path) or "/"
    while not os.path.isdir(candidate):
        parent = os.path.dirname(candidate) or "/"
        if parent == candidate:
            break
        candidate = parent
    _durable_path(candidate, reader=reader, include_parent=False)


def _read_file(path, reader=None):
    if reader:
        return _as_collector(reader, ["cat", path], timeout=10).stdout
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise BackupImportError(f"Could not read {path}: {exc}") from exc


def _safe_target(path, lldpq_dir, web_root, *, allow_config_symlink):
    """Resolve Docker config-volume links but reject arbitrary SSH-key links."""
    if not allow_config_symlink:
        if os.path.islink(path):
            raise BackupImportError(f"Refusing to replace symbolic-link SSH key: {path}")
        return path
    resolved = os.path.realpath(path)
    roots = (os.path.realpath(lldpq_dir), os.path.realpath(web_root))
    try:
        managed = any(os.path.commonpath((resolved, root)) == root for root in roots)
    except ValueError:
        managed = False
    if not managed:
        raise BackupImportError(
            f"Config link points outside the managed LLDPq directories: {path}"
        )
    return resolved


def _safe_root_config_target(logical_path, lldpq_dir):
    """Resolve Docker's /etc config link only into its persistent system volume."""
    if not os.path.islink(logical_path):
        return logical_path
    managed_root = os.path.realpath(lldpq_dir)
    system_path = os.path.join(managed_root, "system-config")
    if os.path.islink(system_path):
        raise BackupImportError("LLDPq system-config may not be a symbolic link")
    system_root = os.path.realpath(system_path)
    resolved = os.path.realpath(logical_path)
    try:
        managed = (
            os.path.commonpath((system_root, managed_root)) == managed_root
            and os.path.commonpath((resolved, system_root)) == system_root
        )
    except ValueError:
        managed = False
    if not managed or os.path.basename(resolved) != "lldpq.conf":
        raise BackupImportError(
            f"Root config link points outside LLDPq system-config: {logical_path}"
        )
    return resolved


def _expected_recovery_config_target(
    name, logical_path, recorded_target, lldpq_dir, web_root
):
    current_target = _safe_target(
        logical_path, lldpq_dir, web_root, allow_config_symlink=True
    )
    if current_target == recorded_target:
        return current_target
    # At Docker boot, app-config symlinks are recreated only after system config
    # validation. The persistent volume target is still the exact safe authority.
    if _docker_environment():
        managed_root = os.path.realpath(lldpq_dir)
        config_path = os.path.join(managed_root, "config")
        if os.path.islink(config_path):
            raise BackupImportError("LLDPq config volume path may not be a symlink")
        config_root = os.path.realpath(config_path)
        persistent_target = os.path.realpath(os.path.join(config_root, name))
        try:
            managed = (
                os.path.commonpath((config_root, managed_root)) == managed_root
                and os.path.commonpath((persistent_target, config_root)) == config_root
            )
        except ValueError:
            managed = False
        if managed and recorded_target == persistent_target:
            return persistent_target
    raise BackupImportError("Recovery config target no longer matches its logical path")


def _docker_environment():
    return os.path.exists("/.dockerenv")


def _snapshot_file(path, *, reader=None):
    if os.path.islink(path):
        raise BackupImportError(f"Unresolved symbolic-link target: {path}")
    if not os.path.exists(path):
        return {"path": path, "present": False, "reader": reader}
    if not os.path.isfile(path):
        raise BackupImportError(f"Restore target is not a regular file: {path}")
    content = _read_file(path, reader)
    try:
        stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise BackupImportError(f"Could not stat {path}: {exc}") from exc
    return {
        "path": path,
        "present": True,
        "content": content,
        "mode": stat.st_mode & 0o7777,
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "reader": reader,
    }


def _verify_file(path, expected, mode, uid, gid, *, reader=None):
    if _read_file(path, reader) != expected:
        raise BackupImportError(f"Installed file verification failed: {path}")
    try:
        stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise BackupImportError(f"Could not verify {path}: {exc}") from exc
    if (
        stat.st_mode & 0o7777 != mode
        or stat.st_uid != uid
        or stat.st_gid != gid
    ):
        raise BackupImportError(f"Installed file metadata verification failed: {path}")


def _stage_collector_file(entry, user, uid, config_gid, key_gid, token):
    stage = entry.get("stage") or f"{entry['target']}.lldpq-import-stage-{token}"
    entry["stage"] = stage
    _as_collector(user, ["tee", stage], input_data=entry["content"], timeout=15)
    if entry["kind"] == "key-private":
        mode, gid = 0o600, key_gid
    elif entry["kind"] == "key-public":
        mode, gid = 0o644, key_gid
    else:
        mode, gid = 0o664, config_gid
    _run(["sudo", "chown", f"{uid}:{gid}", stage])
    _run(["sudo", "chmod", format(mode, "o"), stage])
    _verify_file(stage, entry["content"], mode, uid, gid, reader=user)
    entry.update({"mode": mode, "uid": uid, "gid": gid})


def _activate_collector_file(entry, user):
    if entry.get("direct_mount"):
        # Docker's documented legacy single-file bind mounts reject rename(2)
        # with EBUSY.  Keep the mount inode and copy verified bytes in-place.
        _install_bytes_as_root(
            entry["content"], entry["target"], entry["mode"],
            entry["uid"], entry["gid"], reader=user,
        )
        _as_collector(user, ["rm", "-f", "--", entry["stage"]])
        _durable_path(os.path.dirname(entry["stage"]), reader=user, include_parent=False)
        entry["stage"] = None
        return
    _collector_shell(user, 'mv -fT -- "$1" "$2"', entry["stage"], entry["target"])
    _verify_file(
        entry["target"], entry["content"], entry["mode"], entry["uid"],
        entry["gid"], reader=user,
    )
    _durable_path(entry["target"], reader=user)
    entry["stage"] = None


def _install_bytes_as_root(content, target, mode, uid, gid, *, reader=None):
    temp_path = None
    sibling_stage = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".lldpq-import-root.", dir="/tmp")
        with os.fdopen(fd, "wb") as staged:
            staged.write(content)
            staged.flush()
            os.fsync(staged.fileno())
        parent = os.path.dirname(target) or "/"
        atomic_system_config = (
            os.path.basename(parent) == "system-config"
            and os.path.basename(target) == "lldpq.conf"
            and not os.path.islink(target)
            and not _is_direct_mount(target)
        )
        install_target = target
        if atomic_system_config:
            try:
                move_user = pwd.getpwuid(os.stat(parent).st_uid).pw_name
            except (KeyError, OSError) as exc:
                raise BackupImportError("Could not resolve system-config owner") from exc
            sibling_stage = f"{target}.lldpq-root-stage-{os.getpid()}-{secrets.token_hex(8)}"
            if os.path.lexists(sibling_stage):
                raise BackupImportError("Root config sibling stage already exists")
            install_target = sibling_stage
        _run(["sudo", "cp", temp_path, install_target])
        _run(["sudo", "chmod", format(mode, "o"), install_target])
        _run(["sudo", "chown", f"{uid}:{gid}", install_target])
        _verify_file(install_target, content, mode, uid, gid, reader=reader)
        _durable_path(install_target, reader=reader)
        if sibling_stage:
            _collector_shell(
                move_user, 'mv -fT -- "$1" "$2"', sibling_stage, target, timeout=15
            )
            sibling_stage = None
        _verify_file(target, content, mode, uid, gid, reader=reader)
        _durable_path(target, reader=reader)
    finally:
        if sibling_stage:
            try:
                _run(["sudo", "rm", "-f", "--", sibling_stage])
            except Exception:
                pass
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def _restore_snapshot(snapshot):
    if snapshot["present"]:
        _install_bytes_as_root(
            snapshot["content"],
            snapshot["path"],
            snapshot["mode"],
            snapshot["uid"],
            snapshot["gid"],
            reader=snapshot["reader"],
        )
        return
    _run(["sudo", "rm", "-f", "--", snapshot["path"]])
    if os.path.lexists(snapshot["path"]):
        raise BackupImportError(
            f"Could not remove newly-created target: {snapshot['path']}"
        )
    _durable_existing_parent(snapshot["path"], reader=snapshot["reader"])


RECOVERY_SCHEMA = 1
RECOVERY_DIR_NAME = ".backup-import-recovery"
_RECOVERY_TARGET_KEYS = {
    "kind", "name", "logical", "target", "stage", "direct_mount",
    "present", "snapshot", "size", "sha256", "mode", "uid", "gid", "reader",
}


def _recovery_base(lldpq_dir, user):
    if _docker_environment():
        base = os.path.realpath(os.path.join(lldpq_dir, "system-config"))
        managed_root = os.path.realpath(lldpq_dir)
        try:
            managed = os.path.commonpath((base, managed_root)) == managed_root
        except ValueError:
            managed = False
        if not managed:
            raise BackupImportError("Docker recovery root escaped LLDPQ_DIR")
        return base
    home = os.path.realpath(os.path.expanduser(f"~{user}"))
    base = os.path.join(home, ".lldpq-state")
    if os.path.lexists(base) and os.path.islink(base):
        raise BackupImportError("Native recovery state directory may not be a symlink")
    return base


def _recovery_path(lldpq_dir, user):
    return os.path.join(_recovery_base(lldpq_dir, user), RECOVERY_DIR_NAME)


def _ensure_recovery_base(user, base):
    try:
        account = pwd.getpwnam(user)
        expected_gid = (
            grp.getgrnam("www-data").gr_gid if _docker_environment() else account.pw_gid
        )
    except KeyError as exc:
        raise BackupImportError(f"Recovery owner/group is unavailable: {exc}") from exc
    expected_mode = 0o750 if _docker_environment() else 0o700
    if os.path.lexists(base):
        if os.path.islink(base) or not os.path.isdir(base):
            raise BackupImportError("Recovery base is not a safe directory")
    else:
        _as_collector(user, ["mkdir", "-p", base])
    _run(["sudo", "chown", f"{account.pw_uid}:{expected_gid}", base])
    _run(["sudo", "chmod", format(expected_mode, "o"), base])
    metadata = os.stat(base, follow_symlinks=False)
    if (
        metadata.st_uid != account.pw_uid
        or metadata.st_gid != expected_gid
        or metadata.st_mode & 0o7777 != expected_mode
    ):
        raise BackupImportError("Recovery base ownership/mode verification failed")
    _durable_path(base, reader=user)


def _secure_write(user, path, content, mode="600"):
    _as_collector(user, ["tee", path], input_data=content, timeout=20)
    _collector_shell(
        user, 'chmod "$1" "$2" && sync -f -- "$2"', mode, path, timeout=20
    )
    if mode == "600":
        _secure_require_private_file(user, path)


def _secure_remove_tree(user, path, parent):
    _as_collector(user, ["rm", "-rf", "--", path], timeout=20)
    _durable_path(parent, reader=user, include_parent=False)


def _retire_recovery_authority(user, recovery_dir, parent, token, disposition):
    """Atomically retire authority, then best-effort erase its private tombstone."""
    if disposition not in ("committed", "rolled-back"):
        raise BackupImportError("Invalid recovery retirement disposition")
    tombstone = f"{recovery_dir}.{disposition}-{token}"
    if _secure_path_state(user, tombstone) != "missing":
        raise BackupImportError("Recovery tombstone already exists")
    # If the parent fsync fails, put authority back before returning failure so
    # the caller can still perform an authoritative rollback.
    _collector_shell(
        user,
        'test -d "$1" && test ! -L "$1" || exit 4; '
        'test ! -e "$2" && test ! -L "$2" || exit 5; '
        'mv -nT -- "$1" "$2" || exit 1; '
        'test ! -e "$1" && test ! -L "$1" && test -d "$2" && test ! -L "$2" || exit 6; '
        'if sync -f -- "$3"; then exit 0; fi; '
        'test ! -e "$1" && test ! -L "$1" || exit 7; '
        'mv -nT -- "$2" "$1" || exit 2; '
        'test -d "$1" && test ! -L "$1" && test ! -e "$2" && test ! -L "$2" || exit 8; '
        'sync -f -- "$3" || exit 3; exit 1',
        recovery_dir,
        tombstone,
        parent,
        timeout=20,
    )
    try:
        _secure_remove_tree(user, tombstone, parent)
    except Exception:
        # The durable rename already removed rollback authority. A private,
        # committed tombstone is safe to clean on a later maintenance pass.
        pass


def _commit_recovery_authority(user, recovery_dir, parent, token):
    _retire_recovery_authority(
        user, recovery_dir, parent, token, "committed"
    )


def _secure_list_dir(user, path):
    result = _collector_shell(
        user,
        'find "$1" -mindepth 1 -maxdepth 1 -printf "%f\\n"',
        path,
        timeout=10,
    )
    return [line for line in result.stdout.decode("utf-8").splitlines() if line]


def _secure_require_regular(user, path):
    _collector_shell(user, 'test -f "$1" && test ! -L "$1"', path)


def _secure_stat(user, path):
    result = _collector_shell(
        user, 'stat -c "%u %g %a" -- "$1"', path, timeout=10
    )
    try:
        uid, gid, mode = result.stdout.decode("ascii").strip().split()
        return int(uid), int(gid), int(mode, 8)
    except (ValueError, UnicodeError) as exc:
        raise BackupImportError("Could not parse recovery metadata") from exc


def _secure_require_private_file(user, path):
    _secure_require_regular(user, path)
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise BackupImportError(f"Recovery owner is unavailable: {exc}") from exc
    uid, gid, mode = _secure_stat(user, path)
    if uid != account.pw_uid or gid != account.pw_gid or mode != 0o600:
        raise BackupImportError("Recovery file owner/mode is not trusted")


def _secure_require_private_dir(user, path):
    _collector_shell(user, 'test -d "$1" && test ! -L "$1"', path)
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise BackupImportError(f"Recovery owner is unavailable: {exc}") from exc
    uid, gid, mode = _secure_stat(user, path)
    if uid != account.pw_uid or gid != account.pw_gid or mode != 0o700:
        raise BackupImportError("Recovery directory owner/mode is not trusted")


def _cleanup_recovery_debris(user, base):
    """Delete unpublished temp dirs and already-retired tombstones only."""
    if not os.path.isdir(base):
        return
    prefixes = (
        RECOVERY_DIR_NAME + ".tmp-",
        RECOVERY_DIR_NAME + ".committed-",
        RECOVERY_DIR_NAME + ".rolled-back-",
    )
    for name in _secure_list_dir(user, base):
        prefix = next((candidate for candidate in prefixes if name.startswith(candidate)), None)
        if prefix is None or not _valid_transaction_id(name[len(prefix):]):
            continue
        path = os.path.join(base, name)
        _collector_shell(user, 'test -d "$1" && test ! -L "$1"', path)
        _secure_remove_tree(user, path, base)


def _snapshot_record(entry, index, user):
    snapshot = entry["snapshot"]
    present = bool(snapshot["present"])
    content = snapshot.get("content", b"") if present else b""
    snapshot_name = f"snapshot-{index:04d}.bin" if present else None
    return {
        "kind": entry["kind"],
        "name": entry["name"],
        "logical": entry["logical_target"],
        "target": entry["target"],
        "stage": entry.get("stage"),
        "direct_mount": bool(entry.get("direct_mount", False)),
        "present": present,
        "snapshot": snapshot_name,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest() if present else None,
        "mode": snapshot.get("mode") if present else None,
        "uid": snapshot.get("uid") if present else None,
        "gid": snapshot.get("gid") if present else None,
        "reader": "collector" if snapshot.get("reader") == user else None,
    }, content


def _create_recovery_authority(
    entries, root_entries, ssh_snapshot, *, lldpq_dir, web_root, user, token
):
    recovery_base = _recovery_base(lldpq_dir, user)
    _ensure_recovery_base(user, recovery_base)
    _cleanup_recovery_debris(user, recovery_base)
    recovery_dir = _recovery_path(lldpq_dir, user)
    temporary_dir = f"{recovery_dir}.tmp-{token}"
    if _secure_path_state(user, recovery_dir) != "missing":
        raise BackupImportError(
            f"Retained backup-import recovery authority already exists: {recovery_dir}"
        )
    if _secure_path_state(user, temporary_dir) != "missing":
        raise BackupImportError("Backup-import temporary authority already exists")
    records = []
    snapshot_contents = []
    all_entries = list(entries) + list(root_entries)
    for index, entry in enumerate(all_entries):
        record, content = _snapshot_record(entry, index, user)
        records.append(record)
        if record["present"]:
            snapshot_contents.append((record["snapshot"], content))
    manifest = {
        "schema": RECOVERY_SCHEMA,
        "transaction_id": token,
        "lldpq_dir": os.path.realpath(lldpq_dir),
        "web_root": os.path.realpath(web_root),
        "recovery_dir": recovery_dir,
        "user": user,
        "targets": records,
        "ssh_dir": ssh_snapshot,
    }
    manifest_bytes = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    try:
        _as_collector(user, ["mkdir", temporary_dir])
        _collector_shell(
            user,
            'chmod 700 "$1" && sync -f -- "$1" && sync -f -- "$(dirname -- "$1")"',
            temporary_dir,
            timeout=20,
        )
        _secure_require_private_dir(user, temporary_dir)
        for name, content in snapshot_contents:
            _secure_write(user, os.path.join(temporary_dir, name), content)
        manifest_path = os.path.join(temporary_dir, "manifest.json")
        _secure_write(user, manifest_path, manifest_bytes)
        _collector_shell(
            user,
            'sync -f -- "$1"; test -d "$1" && test ! -L "$1" || exit 4; '
            'test ! -e "$2" && test ! -L "$2" || exit 5; '
            'mv -nT -- "$1" "$2" || exit 1; '
            'test ! -e "$1" && test ! -L "$1" && test -d "$2" && test ! -L "$2" || exit 6; '
            'if sync -f -- "$3"; then exit 0; fi; '
            'test ! -e "$1" && test ! -L "$1" || exit 7; '
            'mv -nT -- "$2" "$1" || exit 2; '
            'test -d "$1" && test ! -L "$1" && test ! -e "$2" && test ! -L "$2" || exit 8; '
            'sync -f -- "$3" || exit 3; exit 1',
            temporary_dir,
            recovery_dir,
            recovery_base,
            timeout=20,
        )
    except Exception:
        try:
            if _secure_path_state(user, recovery_dir) != "missing":
                _secure_remove_tree(user, recovery_dir, recovery_base)
            if _secure_path_state(user, temporary_dir) != "missing":
                _secure_remove_tree(user, temporary_dir, recovery_base)
        except Exception:
            pass
        raise
    return recovery_dir


def _valid_transaction_id(token):
    pid, separator, random_part = token.partition("-")
    return (
        bool(separator) and pid.isdigit() and len(random_part) == 16
        and all(character in "0123456789abcdef" for character in random_part)
    )


def _load_recovery_authority(
    *, lldpq_dir, web_root, user, allowed, key_names, ssh_dir
):
    recovery_base = _recovery_base(lldpq_dir, user)
    if os.path.isdir(recovery_base):
        _ensure_recovery_base(user, recovery_base)
        _cleanup_recovery_debris(user, recovery_base)
    recovery_dir = _recovery_path(lldpq_dir, user)
    recovery_state = _secure_path_state(user, recovery_dir)
    if recovery_state == "missing":
        return None
    if recovery_state != "directory":
        raise BackupImportError("Recovery authority path is not a private directory")
    _secure_require_private_dir(user, recovery_dir)
    manifest_path = os.path.join(recovery_dir, "manifest.json")
    try:
        _secure_require_private_file(user, manifest_path)
        manifest_bytes = _read_file(manifest_path, reader=user)
        if len(manifest_bytes) > 1024 * 1024:
            raise BackupImportError("Recovery manifest is too large")
        manifest = json.loads(manifest_bytes)
    except Exception as exc:
        if isinstance(exc, BackupImportError):
            raise BackupImportError(
                "Incomplete or unreadable retained backup-import recovery authority"
            ) from exc
        raise BackupImportError("Invalid retained backup-import recovery manifest") from exc
    expected_top_keys = {
        "schema", "transaction_id", "lldpq_dir", "web_root", "recovery_dir", "user",
        "targets", "ssh_dir",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_top_keys:
        raise BackupImportError("Recovery manifest schema is ambiguous")
    if manifest["schema"] != RECOVERY_SCHEMA:
        raise BackupImportError("Unsupported recovery manifest schema")
    token = manifest["transaction_id"]
    if not isinstance(token, str) or not _valid_transaction_id(token):
        raise BackupImportError("Invalid recovery transaction identifier")
    if (
        manifest["lldpq_dir"] != os.path.realpath(lldpq_dir)
        or manifest["web_root"] != os.path.realpath(web_root)
        or manifest["recovery_dir"] != recovery_dir
        or manifest["user"] != user
    ):
        raise BackupImportError("Recovery authority belongs to a different installation")
    records = manifest["targets"]
    if not isinstance(records, list) or not records or len(records) > 16:
        raise BackupImportError("Invalid recovery target list")

    expected_files = {"manifest.json"}
    seen_targets = set()
    total_snapshot_size = 0
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _RECOVERY_TARGET_KEYS:
            raise BackupImportError("Invalid recovery target schema")
        kind, name = record["kind"], record["name"]
        if kind == "config":
            if name not in allowed:
                raise BackupImportError("Unknown recovery config target")
            expected_logical = os.path.join(allowed[name], name)
            expected_target = _expected_recovery_config_target(
                name, expected_logical, record["target"], lldpq_dir, web_root
            )
            expected_reader = "collector"
        elif kind in ("key-private", "key-public"):
            if name not in key_names:
                raise BackupImportError("Unknown recovery SSH target")
            expected_logical = os.path.join(ssh_dir, name)
            expected_target = _safe_target(
                expected_logical, lldpq_dir, web_root, allow_config_symlink=False
            )
            expected_reader = "collector"
        elif kind == "root-conf":
            if name != "lldpq.conf":
                raise BackupImportError("Unknown root config recovery target")
            expected_logical = "/etc/lldpq.conf"
            expected_target = _safe_root_config_target(expected_logical, lldpq_dir)
            expected_reader = None
        elif kind == "root-cron":
            if name != "lldpq-cron" or record["target"] not in (
                "/etc/cron.d/lldpq", "/etc/crontab"
            ):
                raise BackupImportError("Unknown cron recovery target")
            expected_logical = expected_target = record["target"]
            expected_reader = None
        else:
            raise BackupImportError("Unknown recovery target kind")
        if (
            record["logical"] != expected_logical
            or record["target"] != expected_target
            or record["reader"] != expected_reader
            or record["target"] in seen_targets
        ):
            raise BackupImportError("Recovery target path or reader mismatch")
        seen_targets.add(record["target"])
        current_mount = _is_direct_mount(record["target"])
        if not isinstance(record["direct_mount"], bool) or record["direct_mount"] != current_mount:
            raise BackupImportError("Recovery target mount identity changed")
        expected_stage = (
            f"{record['target']}.lldpq-import-stage-{token}"
            if expected_reader == "collector" else None
        )
        if record["stage"] != expected_stage:
            raise BackupImportError("Recovery stage path mismatch")
        if not isinstance(record["present"], bool):
            raise BackupImportError("Recovery presence marker is invalid")
        if record["present"]:
            snapshot_name = f"snapshot-{index:04d}.bin"
            if record["snapshot"] != snapshot_name:
                raise BackupImportError("Recovery snapshot name mismatch")
            if not all(isinstance(record[field], int) for field in ("size", "mode", "uid", "gid")):
                raise BackupImportError("Recovery snapshot metadata is invalid")
            if record["size"] < 0 or record["size"] > 16 * 1024 * 1024:
                raise BackupImportError("Recovery snapshot size is invalid")
            if not isinstance(record["sha256"], str) or len(record["sha256"]) != 64:
                raise BackupImportError("Recovery snapshot hash is invalid")
            snapshot_path = os.path.join(recovery_dir, snapshot_name)
            _secure_require_private_file(user, snapshot_path)
            content = _read_file(snapshot_path, reader=user)
            if len(content) != record["size"] or hashlib.sha256(content).hexdigest() != record["sha256"]:
                raise BackupImportError("Recovery snapshot hash/size mismatch")
            record["_content"] = content
            expected_files.add(snapshot_name)
            total_snapshot_size += len(content)
        elif any(
            record[field] is not None
            for field in ("snapshot", "sha256", "mode", "uid", "gid")
        ) or record["size"] != 0:
            raise BackupImportError("Missing recovery target has snapshot metadata")
    if total_snapshot_size > 48 * 1024 * 1024:
        raise BackupImportError("Recovery snapshots exceed the safe limit")
    if set(_secure_list_dir(user, recovery_dir)) != expected_files:
        raise BackupImportError("Recovery directory contains unexpected or missing files")

    ssh_record = manifest["ssh_dir"]
    has_key_targets = any(record["kind"].startswith("key-") for record in records)
    if ssh_record is None:
        if has_key_targets:
            raise BackupImportError("SSH recovery metadata is missing")
    else:
        if not has_key_targets:
            raise BackupImportError("Unexpected SSH recovery metadata")
        if not isinstance(ssh_record, dict) or set(ssh_record) != {
            "path", "present", "mode", "uid", "gid"
        }:
            raise BackupImportError("Invalid SSH directory recovery schema")
        if ssh_record["path"] != ssh_dir or not isinstance(ssh_record["present"], bool):
            raise BackupImportError("SSH directory recovery path mismatch")
        if ssh_record["present"]:
            if not all(isinstance(ssh_record[field], int) for field in ("mode", "uid", "gid")):
                raise BackupImportError("Invalid SSH directory recovery metadata")
        elif any(ssh_record[field] is not None for field in ("mode", "uid", "gid")):
            raise BackupImportError("Missing SSH directory has metadata")
    return recovery_dir, manifest


def _recover_retained_authority(
    *, lldpq_dir, web_root, user, allowed, key_names, ssh_dir
):
    loaded = _load_recovery_authority(
        lldpq_dir=lldpq_dir, web_root=web_root, user=user,
        allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
    )
    if loaded is None:
        return False
    recovery_dir, manifest = loaded
    errors = []
    for record in reversed(manifest["targets"]):
        snapshot = {
            "path": record["target"],
            "present": record["present"],
            "reader": user if record["reader"] == "collector" else None,
        }
        if record["present"]:
            snapshot.update({
                "content": record["_content"], "mode": record["mode"],
                "uid": record["uid"], "gid": record["gid"],
            })
        try:
            _restore_snapshot(snapshot)
            if record["stage"]:
                _as_collector(user, ["rm", "-f", "--", record["stage"]])
                _durable_existing_parent(record["stage"], reader=user)
        except Exception as exc:
            errors.append(str(exc))
    ssh_record = manifest["ssh_dir"]
    if ssh_record is not None:
        try:
            if ssh_record["present"]:
                _run(["sudo", "chmod", format(ssh_record["mode"], "o"), ssh_dir])
                _run(["sudo", "chown", f"{ssh_record['uid']}:{ssh_record['gid']}", ssh_dir])
                _durable_path(ssh_dir, reader=user)
            elif os.path.isdir(ssh_dir):
                _run(["sudo", "rm", "-d", "--", ssh_dir])
                _durable_path(os.path.dirname(ssh_dir), reader=user, include_parent=False)
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise BackupImportError(
            "Retained backup-import recovery is incomplete; authority was kept: "
            + "; ".join(errors[:2])
        )
    _retire_recovery_authority(
        user,
        recovery_dir,
        _recovery_base(lldpq_dir, user),
        manifest["transaction_id"],
        "rolled-back",
    )
    return True


def _render_conf(original, values):
    keys = set(values)
    output = []
    for line in original.splitlines():
        stripped = line.strip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if stripped and not stripped.startswith("#") and key in keys:
            continue
        output.append(line)
    output.extend(f"{key}={value}" for key, value in values.items())
    return "\n".join(output) + "\n"


def _render_cron(values, original, validate_cron):
    def clean(value):
        return value.strip().strip('"').strip("'") if value else None

    lldpq_cron = clean(values.get("LLDPQ_CRON"))
    getconf_cron = clean(values.get("GETCONF_CRON"))
    if not lldpq_cron and not getconf_cron:
        return None
    if (
        lldpq_cron
        and not validate_cron(lldpq_cron)
        or getconf_cron
        and not validate_cron(getconf_cron)
    ):
        raise BackupImportError("Imported cron schedule failed validation")
    output = []
    found_lldpq = not bool(lldpq_cron)
    found_getconf = not bool(getconf_cron)
    for line in original.splitlines(True):
        parts = line.split()
        if (
            not line.lstrip().startswith("#")
            and len(parts) >= 7
            and parts[6] == "/usr/local/bin/lldpq"
            and lldpq_cron
        ):
            output.append(lldpq_cron + " " + " ".join(parts[5:]) + "\n")
            found_lldpq = True
        elif (
            not line.lstrip().startswith("#")
            and len(parts) >= 7
            and parts[6] == "/usr/local/bin/get-conf"
            and getconf_cron
        ):
            output.append(getconf_cron + " " + " ".join(parts[5:]) + "\n")
            found_getconf = True
        else:
            output.append(line)
    if not found_lldpq or not found_getconf:
        raise BackupImportError(
            "Required LLDPq cron entry is missing; run install.sh first"
        )
    return "".join(output)


def _validate_config(name, content, validation_dir, lldpq_dir):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupImportError(f"{name} is not valid UTF-8") from exc
    if "\x00" in text:
        raise BackupImportError(f"{name} contains NUL bytes")
    staged = os.path.join(validation_dir, name)
    with open(staged, "wb") as handle:
        handle.write(content)
    if name == "devices.yaml":
        parser = os.path.join(lldpq_dir, "parse_devices.py")
        if not os.path.isfile(parser):
            raise BackupImportError("Canonical device parser is missing")
        parsed = subprocess.run(
            [sys.executable, parser, "--format", "json", "--file", staged],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if parsed.returncode != 0:
            detail = (parsed.stderr or "invalid inventory").strip()[:180]
            raise BackupImportError(f"devices.yaml is invalid: {detail}")
    elif name in ("topology_config.yaml", "notifications.yaml"):
        import yaml

        value = yaml.safe_load(text)
        if value is not None and not isinstance(value, dict):
            raise BackupImportError(f"{name} must contain a YAML mapping")
    elif name == "display-aliases.json":
        value = json.loads(text)
        if not isinstance(value, dict):
            raise BackupImportError(f"{name} must contain a JSON object")


def _validate_key(name, content, validation_dir):
    key_path = os.path.join(validation_dir, name)
    with open(key_path, "wb") as handle:
        handle.write(content)
    os.chmod(key_path, 0o600)
    if name.endswith(".pub"):
        command = ["ssh-keygen", "-l", "-f", key_path]
    else:
        if b"PRIVATE KEY" not in content:
            raise BackupImportError(f"{name} is not a private key")
        command = ["ssh-keygen", "-y", "-f", key_path]
    checked = subprocess.run(command, capture_output=True, timeout=10)
    if checked.returncode != 0:
        raise BackupImportError(f"{name} failed SSH key validation")
    return checked.stdout.strip()


def _parse_bundle(raw, allowed, key_names, pref_keys, validate_cron, lldpq_dir):
    entries = []
    pref_values = {}
    recognized_names = set()
    key_validation = {}
    key_content = {}
    with tempfile.TemporaryDirectory(prefix="lldpq-import-validate-") as validation_dir:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            total_size = 0
            for member in archive.getmembers():
                name = member.name.replace("\\", "/")
                parts = pathlib.PurePosixPath(name).parts
                if name.startswith("/") or ".." in parts:
                    raise BackupImportError("Archive contains an unsafe path")
                is_key = (
                    name.startswith("ssh/")
                    and name[4:] in key_names
                    and "/" not in name[4:]
                )
                recognized = name in allowed or name == "prefs/lldpq.conf" or is_key
                if not recognized:
                    continue
                if not member.isfile():
                    raise BackupImportError(
                        f"Recognized backup entry is not a regular file: {name}"
                    )
                if name in recognized_names:
                    raise BackupImportError(f"Duplicate backup entry: {name}")
                recognized_names.add(name)
                if member.size < 0 or member.size > 2 * 1024 * 1024:
                    raise BackupImportError(f"Backup entry is too large: {name}")
                total_size += member.size
                if total_size > 8 * 1024 * 1024:
                    raise BackupImportError("Expanded backup bundle is too large")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BackupImportError(f"Could not read backup entry: {name}")
                content = extracted.read(member.size + 1)
                if len(content) != member.size:
                    raise BackupImportError(f"Backup entry size mismatch: {name}")

                if name == "prefs/lldpq.conf":
                    try:
                        text = content.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise BackupImportError(
                            "Portable preferences are not valid UTF-8"
                        ) from exc
                    seen = set()
                    for line in text.splitlines():
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#") or "=" not in stripped:
                            continue
                        key, value = stripped.split("=", 1)
                        key, candidate = key.strip(), value.strip()
                        if key not in pref_keys:
                            continue
                        if key in seen:
                            raise BackupImportError(
                                f"Duplicate portable preference: {key}"
                            )
                        seen.add(key)
                        if key in ("LLDPQ_CRON", "GETCONF_CRON"):
                            cron = candidate.strip().strip('"').strip("'")
                            if not validate_cron(cron):
                                raise BackupImportError(
                                    f"Invalid imported cron schedule: {key}"
                                )
                        pref_values[key] = candidate
                    continue

                if is_key:
                    base = name[4:]
                    key_validation[base] = _validate_key(
                        base, content, validation_dir
                    )
                    key_content[base] = content
                    entries.append(
                        {
                            "name": base,
                            "content": content,
                            "kind": "key-public"
                            if base.endswith(".pub")
                            else "key-private",
                        }
                    )
                else:
                    _validate_config(name, content, validation_dir, lldpq_dir)
                    entries.append(
                        {"name": name, "content": content, "kind": "config"}
                    )

        for private_name in ("id_ed25519", "id_rsa"):
            public_name = private_name + ".pub"
            if private_name in key_validation and public_name in key_validation:
                derived = key_validation[private_name].split()[:2]
                supplied = key_content[public_name].split()[:2]
                if derived != supplied:
                    raise BackupImportError(
                        f"SSH private/public key pair does not match: {private_name}"
                    )
            elif private_name in key_validation:
                # A private key is authoritative. Always transact its derived
                # public half too, so an omitted bundle member cannot leave a
                # stale .pub file paired with the newly restored identity.
                derived_public = key_validation[private_name].strip() + b"\n"
                key_content[public_name] = derived_public
                entries.append(
                    {
                        "name": public_name,
                        "content": derived_public,
                        "kind": "key-public",
                        "derived": True,
                    }
                )
    if not entries and not pref_values:
        raise BackupImportError("No recognized config files inside the archive")
    return entries, pref_values


def _validate_public_only_keys(entries, user, ssh_dir):
    """Public-only imports may update metadata only when the live private half matches."""
    names = {entry["name"] for entry in entries if entry["kind"].startswith("key-")}
    by_name = {entry["name"]: entry for entry in entries}
    for private_name in ("id_ed25519", "id_rsa"):
        public_name = private_name + ".pub"
        if public_name not in names or private_name in names:
            continue
        private_path = os.path.join(ssh_dir, private_name)
        if os.path.islink(private_path):
            raise BackupImportError(
                f"Refusing public-only restore through symbolic-link private key: {private_name}"
            )
        try:
            derived = _as_collector(
                user, ["ssh-keygen", "-y", "-f", private_path], timeout=10
            ).stdout.split()[:2]
        except BackupImportError as exc:
            raise BackupImportError(
                f"Public-only bundle has no readable matching private key: {private_name}"
            ) from exc
        supplied = by_name[public_name]["content"].split()[:2]
        if derived != supplied:
            raise BackupImportError(
                f"Public-only key does not match the installed private key: {public_name}"
            )


def _cleanup_stages(entries, user):
    for entry in entries:
        stage = entry.get("stage")
        if not stage:
            continue
        try:
            _as_collector(user, ["rm", "-f", "--", stage])
        except BackupImportError:
            pass


def restore_bundle(
    encoded_data,
    *,
    lldpq_user,
    lldpq_dir,
    web_root,
    pref_keys: Iterable[str],
    validate_cron: Callable[[str], bool],
    acquire_lock: Callable[[], None],
):
    """Validate and restore a Setup bundle as one all-or-rollback transaction."""
    allowed = {
        "devices.yaml": lldpq_dir,
        "topology.dot": web_root,
        "topology_config.yaml": web_root,
        "notifications.yaml": lldpq_dir,
        "display-aliases.json": web_root,
    }
    key_names = {"id_ed25519", "id_ed25519.pub", "id_rsa", "id_rsa.pub"}
    ssh_dir = os.path.expanduser(f"~{lldpq_user}/.ssh")

    # Recovery always precedes parsing or staging a new request. The same lock
    # serializes normal setup writes and retained transaction recovery.
    acquire_lock()
    _recover_retained_authority(
        lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user,
        allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
    )

    try:
        raw = base64.b64decode(encoded_data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BackupImportError("Invalid file (not base64)") from exc
    if len(raw) > 16 * 1024 * 1024:
        raise BackupImportError("Backup bundle is too large")

    try:
        entries, pref_values = _parse_bundle(
            raw,
            allowed,
            key_names,
            set(pref_keys),
            validate_cron,
            lldpq_dir,
        )
    except (BackupImportError, tarfile.TarError, OSError, ValueError) as exc:
        if isinstance(exc, BackupImportError):
            raise
        raise BackupImportError(str(exc)) from exc

    try:
        account = pwd.getpwnam(lldpq_user)
        config_group = grp.getgrnam("www-data")
    except KeyError as exc:
        raise BackupImportError(f"Required LLDPq account/group is missing: {exc}") from exc
    _validate_public_only_keys(entries, lldpq_user, ssh_dir)

    logical_targets = {
        name: os.path.join(directory, name) for name, directory in allowed.items()
    }
    resolved_targets = set()
    for entry in entries:
        logical = (
            os.path.join(ssh_dir, entry["name"])
            if entry["kind"].startswith("key-")
            else logical_targets[entry["name"]]
        )
        entry["logical_target"] = logical
        entry["target"] = _safe_target(
            logical,
            lldpq_dir,
            web_root,
            allow_config_symlink=entry["kind"] == "config",
        )
        if entry["target"] in resolved_targets:
            raise BackupImportError("Multiple backup entries resolve to one target")
        resolved_targets.add(entry["target"])
        entry["direct_mount"] = _is_direct_mount(entry["target"])
        entry["snapshot"] = _snapshot_file(entry["target"], reader=lldpq_user)

    root_entries = []
    if pref_values:
        conf_logical = "/etc/lldpq.conf"
        conf_target = _safe_root_config_target(conf_logical, lldpq_dir)
        conf_snapshot = _snapshot_file(conf_target)
        if not conf_snapshot["present"]:
            raise BackupImportError("/etc/lldpq.conf is missing; run install.sh first")
        try:
            original_conf = conf_snapshot["content"].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BackupImportError("/etc/lldpq.conf is not valid UTF-8") from exc
        root_entries.append(
            {
                "kind": "root-conf",
                "name": "lldpq.conf",
                "logical_target": conf_logical,
                "target": conf_target,
                "content": _render_conf(original_conf, pref_values).encode(),
                "mode": 0o664,
                "uid": 0,
                "gid": config_group.gr_gid,
                "snapshot": conf_snapshot,
                "stage": None,
                "direct_mount": _is_direct_mount(conf_target),
            }
        )
        if "LLDPQ_CRON" in pref_values or "GETCONF_CRON" in pref_values:
            cron_path = (
                "/etc/cron.d/lldpq"
                if os.path.exists("/etc/cron.d/lldpq")
                else "/etc/crontab"
            )
            cron_snapshot = _snapshot_file(cron_path)
            if not cron_snapshot["present"]:
                raise BackupImportError("LLDPq cron file is missing; run install.sh first")
            try:
                original_cron = cron_snapshot["content"].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BackupImportError("LLDPq cron file is not valid UTF-8") from exc
            rendered_cron = _render_cron(pref_values, original_cron, validate_cron)
            root_entries.append(
                {
                    "kind": "root-cron",
                    "name": "lldpq-cron",
                    "logical_target": cron_path,
                    "target": cron_path,
                    "content": rendered_cron.encode(),
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "snapshot": cron_snapshot,
                    "stage": None,
                    "direct_mount": _is_direct_mount(cron_path),
                }
            )

    has_keys = any(entry["kind"].startswith("key-") for entry in entries)
    if os.path.lexists(ssh_dir) and not os.path.isdir(ssh_dir):
        raise BackupImportError("Collector .ssh path is not a directory")
    if os.path.islink(ssh_dir):
        raise BackupImportError("Collector .ssh directory may not be a symbolic link")
    ssh_dir_existed = os.path.isdir(ssh_dir)
    ssh_dir_stat = os.stat(ssh_dir) if ssh_dir_existed else None
    token = f"{os.getpid()}-{secrets.token_hex(8)}"
    for entry in entries:
        entry["stage"] = f"{entry['target']}.lldpq-import-stage-{token}"
    ssh_snapshot = None
    if has_keys:
        ssh_snapshot = {
            "path": ssh_dir,
            "present": ssh_dir_existed,
            "mode": (ssh_dir_stat.st_mode & 0o7777) if ssh_dir_existed else None,
            "uid": ssh_dir_stat.st_uid if ssh_dir_existed else None,
            "gid": ssh_dir_stat.st_gid if ssh_dir_existed else None,
        }

    # Publish fsynced rollback authority before creating .ssh, staging beside
    # targets, or performing the first live activation.
    recovery_dir = _create_recovery_authority(
        entries, root_entries, ssh_snapshot,
        lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user, token=token,
    )

    # Stage and verify every service-owned file before the first activation.
    try:
        if has_keys:
            _as_collector(lldpq_user, ["mkdir", "-p", ssh_dir])
        for entry in entries:
            _stage_collector_file(
                entry,
                lldpq_user,
                account.pw_uid,
                config_group.gr_gid,
                account.pw_gid,
                token,
            )
    except Exception as stage_error:
        _cleanup_stages(entries, lldpq_user)
        try:
            recovered = _recover_retained_authority(
                lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user,
                allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
            )
            if not recovered:
                raise BackupImportError("Durable recovery authority disappeared")
        except Exception as recovery_error:
            raise BackupImportError(
                f"Import staging failed and recovery is incomplete: {stage_error}; "
                f"recovery: {recovery_error}"
            ) from stage_error
        raise BackupImportError(
            f"Import staging failed; all targets were restored: {stage_error}"
        ) from stage_error

    try:
        if has_keys:
            _run(["sudo", "chown", f"{account.pw_uid}:{account.pw_gid}", ssh_dir])
            _run(["sudo", "chmod", "700", ssh_dir])
            stat = os.stat(ssh_dir)
            if (
                stat.st_mode & 0o7777 != 0o700
                or stat.st_uid != account.pw_uid
                or stat.st_gid != account.pw_gid
            ):
                raise BackupImportError("SSH directory metadata verification failed")
            _durable_path(ssh_dir, reader=lldpq_user)
        for entry in entries:
            _activate_collector_file(entry, lldpq_user)
        for entry in root_entries:
            _install_bytes_as_root(
                entry["content"],
                entry["target"],
                entry["mode"],
                entry["uid"],
                entry["gid"],
            )
        # Removing the authority is itself part of commit. If it fails, the
        # exception path below consumes the retained authority and rolls back.
        _commit_recovery_authority(
            lldpq_user, recovery_dir, _recovery_base(lldpq_dir, lldpq_user), token
        )
    except Exception as commit_error:
        _cleanup_stages(entries, lldpq_user)
        try:
            recovered = _recover_retained_authority(
                lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user,
                allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
            )
            if not recovered:
                raise BackupImportError("Durable recovery authority disappeared")
        except Exception as recovery_error:
            raise BackupImportError(
                f"Import failed and durable recovery is incomplete: {commit_error}; "
                f"recovery: {recovery_error}"
            ) from commit_error
        raise BackupImportError(
            f"Import failed; all targets were rolled back: {commit_error}"
        ) from commit_error
    finally:
        _cleanup_stages(entries, lldpq_user)

    return {
        "success": True,
        "restored": sorted(
            entry["name"] for entry in entries if entry["kind"] == "config"
        ),
        "keys": sorted(
            entry["name"]
            for entry in entries
            if entry["kind"].startswith("key-")
        ),
        "prefs": sorted(pref_values),
    }


def recover_retained_import(*, lldpq_dir, user, web_root):
    """Recover a retained transaction without reading the potentially partial config."""
    allowed = {
        "devices.yaml": lldpq_dir,
        "topology.dot": web_root,
        "topology_config.yaml": web_root,
        "notifications.yaml": lldpq_dir,
        "display-aliases.json": web_root,
    }
    key_names = {"id_ed25519", "id_ed25519.pub", "id_rsa", "id_rsa.pub"}
    ssh_dir = os.path.expanduser(f"~{user}/.ssh")
    return _recover_retained_authority(
        lldpq_dir=lldpq_dir, web_root=web_root, user=user,
        allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
    )


def _is_native_recovery_artifact_name(name):
    if name == RECOVERY_DIR_NAME:
        return True
    for disposition in ("tmp", "committed", "rolled-back"):
        prefix = f"{RECOVERY_DIR_NAME}.{disposition}-"
        if name.startswith(prefix):
            return _valid_transaction_id(name[len(prefix):])
    return False


def _is_recovery_payload_name(name):
    if name == "manifest.json":
        return True
    return (
        name.startswith("snapshot-") and name.endswith(".bin")
        and len(name) == len("snapshot-0000.bin")
        and name[len("snapshot-"):-len(".bin")].isdigit()
    )


def _open_directory_no_follow(path, *, dir_fd=None):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, dir_fd=dir_fd)


def _purge_recovery_artifact_at(state_fd, state_metadata, name, account):
    """Remove one validated, flat recovery directory through trusted dir fds."""
    try:
        artifact_fd = _open_directory_no_follow(name, dir_fd=state_fd)
    except OSError as exc:
        raise BackupImportError(
            f"Native recovery artifact is not a safe directory: {name}"
        ) from exc
    try:
        artifact_metadata = os.fstat(artifact_fd)
        mode = stat.S_IMODE(artifact_metadata.st_mode)
        if (
            not stat.S_ISDIR(artifact_metadata.st_mode)
            or artifact_metadata.st_uid != account.pw_uid
            or artifact_metadata.st_gid != account.pw_gid
            or mode & 0o022
            or artifact_metadata.st_dev != state_metadata.st_dev
        ):
            raise BackupImportError(
                f"Native recovery artifact ownership/mode is not trusted: {name}"
            )

        payloads = []
        for payload_name in os.listdir(artifact_fd):
            if not _is_recovery_payload_name(payload_name):
                raise BackupImportError(
                    f"Native recovery artifact contains an unexpected entry: {name}"
                )
            payload_metadata = os.stat(
                payload_name, dir_fd=artifact_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(payload_metadata.st_mode)
                or payload_metadata.st_uid != account.pw_uid
                or payload_metadata.st_gid != account.pw_gid
                or stat.S_IMODE(payload_metadata.st_mode) & 0o022
                or payload_metadata.st_dev != artifact_metadata.st_dev
            ):
                raise BackupImportError(
                    f"Native recovery payload ownership/type is not trusted: {name}"
                )
            payloads.append((payload_name, payload_metadata.st_dev, payload_metadata.st_ino))

        # Re-check every inode through the opened directory immediately before
        # unlinking it. Symlinks and path substitution are never followed.
        for payload_name, expected_device, expected_inode in payloads:
            current = os.stat(
                payload_name, dir_fd=artifact_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_dev != expected_device
                or current.st_ino != expected_inode
            ):
                raise BackupImportError(
                    f"Native recovery payload changed during cleanup: {name}"
                )
            os.unlink(payload_name, dir_fd=artifact_fd)
        os.fsync(artifact_fd)

        current_artifact = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current_artifact.st_mode)
            or current_artifact.st_dev != artifact_metadata.st_dev
            or current_artifact.st_ino != artifact_metadata.st_ino
        ):
            raise BackupImportError(
                f"Native recovery artifact changed during cleanup: {name}"
            )
        os.rmdir(name, dir_fd=state_fd)
        os.fsync(state_fd)
    finally:
        os.close(artifact_fd)


def purge_native_recovery_state(*, user):
    """Remove only LLDPq's validated native recovery namespace for uninstall."""
    if _docker_environment():
        raise BackupImportError("Native recovery cleanup is not valid in Docker")
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise BackupImportError(f"Recovery owner is unavailable: {exc}") from exc
    declared_home = account.pw_dir
    if not declared_home or not os.path.isabs(declared_home) or "\x00" in declared_home:
        raise BackupImportError("Native recovery home directory is invalid")
    home = os.path.realpath(declared_home)
    if home == "/" or not os.path.isabs(home):
        raise BackupImportError("Native recovery home directory is unsafe")
    state_path = os.path.join(home, ".lldpq-state")
    try:
        if os.path.commonpath((state_path, home)) != home or os.path.dirname(state_path) != home:
            raise BackupImportError("Native recovery state escaped the service home")
    except ValueError as exc:
        raise BackupImportError("Native recovery state path is invalid") from exc

    try:
        home_fd = _open_directory_no_follow(home)
    except OSError as exc:
        raise BackupImportError("Could not safely open the service home") from exc
    try:
        try:
            state_fd = _open_directory_no_follow(".lldpq-state", dir_fd=home_fd)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise BackupImportError(
                "Native recovery state is not a safe, non-symlink directory"
            ) from exc
        try:
            names = sorted(
                name for name in os.listdir(state_fd)
                if _is_native_recovery_artifact_name(name)
            )
            if not names:
                return []
            state_metadata = os.fstat(state_fd)
            state_mode = stat.S_IMODE(state_metadata.st_mode)
            if (
                not stat.S_ISDIR(state_metadata.st_mode)
                or state_metadata.st_uid != account.pw_uid
                or state_metadata.st_gid != account.pw_gid
                or state_mode & 0o022
            ):
                raise BackupImportError(
                    "Native recovery state ownership/mode is not trusted"
                )
            for name in names:
                _purge_recovery_artifact_at(state_fd, state_metadata, name, account)
            return names
        finally:
            os.close(state_fd)
    finally:
        os.close(home_fd)


def _acquire_configuration_lock(path="/etc/lldpq.conf.lock"):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    handle = None
    try:
        descriptor = os.open(path, flags, 0o660)
        handle = os.fdopen(descriptor, "a+")
        descriptor = None
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle
    except Exception as exc:
        try:
            if handle is not None:
                handle.close()
            elif descriptor is not None:
                os.close(descriptor)
        except OSError:
            pass
        raise BackupImportError(f"Could not acquire configuration lock: {exc}") from exc


def _main(argv=None):
    parser = argparse.ArgumentParser(description="LLDPq backup-import recovery helper")
    subparsers = parser.add_subparsers(dest="command", required=True)
    recover = subparsers.add_parser("recover")
    recover.add_argument("--lldpq-dir", required=True)
    recover.add_argument("--user", required=True)
    recover.add_argument("--web-root", required=True)
    purge = subparsers.add_parser("purge-native-state")
    purge.add_argument("--user", required=True)
    args = parser.parse_args(argv)
    if not args.user or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for character in args.user
    ):
        parser.error("invalid service user")
    if args.command == "recover":
        for value in (args.lldpq_dir, args.web_root):
            if not os.path.isabs(value) or "\x00" in value:
                parser.error("recovery paths must be absolute")
    lock_handle = None
    try:
        # This is the same lock used by Setup imports. A path-triggered service
        # waits for a normal transaction; after release it either recovers the
        # retained authority or observes that the completed import removed it.
        lock_handle = _acquire_configuration_lock()
        if args.command == "recover":
            result = recover_retained_import(
                lldpq_dir=os.path.normpath(args.lldpq_dir), user=args.user,
                web_root=os.path.normpath(args.web_root),
            )
        else:
            result = purge_native_recovery_state(user=args.user)
    except Exception as exc:
        print(f"backup-import recovery failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if lock_handle is not None:
            try:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                lock_handle.close()
    if args.command == "recover":
        print("backup-import recovery: restored" if result else "backup-import recovery: clean")
    else:
        print(f"backup-import recovery state purged: {len(result)} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
