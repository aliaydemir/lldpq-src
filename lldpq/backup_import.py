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
import math
import os
import pathlib
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
from typing import Callable, Iterable


class BackupImportError(RuntimeError):
    """A bundle could not be validated, committed, or rolled back safely."""


DISPLAY_ALIAS_LIMITS = {
    "interfaces": (2000, 64, 32),
    "devices": (2000, 128, 64),
}

TRACKING_STATES = frozenset(("commissioning", "handed_over"))
TRACKING_METADATA_LIMITS = {
    "changed_at": 253,
    "changed_by": 253,
    "note": 1000,
}


def validate_tracking_config(value):
    """Validate the portable switch lifecycle configuration."""
    if not isinstance(value, dict):
        raise BackupImportError("tracking.yaml must contain a YAML mapping")
    supported_fields = {"version", "default_state", "switches"}
    unexpected = [key for key in value if key not in supported_fields]
    if unexpected:
        raise BackupImportError(
            "tracking.yaml contains unsupported keys: "
            + ", ".join(sorted(repr(key) for key in unexpected))
        )
    if value.get("version", 1) != 1:
        raise BackupImportError("tracking.yaml version must be 1")
    if value.get("default_state", "commissioning") != "commissioning":
        raise BackupImportError(
            "tracking.yaml default_state must be 'commissioning'"
        )
    switches = value.get("switches", {})
    if switches is None:
        switches = {}
    if not isinstance(switches, dict):
        raise BackupImportError("tracking.yaml 'switches' must be a mapping")
    if len(switches) > 10000:
        raise BackupImportError("tracking.yaml contains too many switches")

    folded = set()
    for hostname, entry in switches.items():
        if (
            not isinstance(hostname, str)
            or hostname != hostname.strip()
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}", hostname)
            or ".." in hostname
        ):
            raise BackupImportError("tracking.yaml contains an invalid hostname")
        identity = hostname.casefold()
        if identity in folded:
            raise BackupImportError(
                f"tracking.yaml contains a duplicate hostname: {hostname}"
            )
        folded.add(identity)
        if not isinstance(entry, dict):
            raise BackupImportError(
                f"tracking.yaml entry for {hostname!r} must be a mapping"
            )
        supported_entry_fields = {"state"} | set(TRACKING_METADATA_LIMITS)
        unknown_fields = [
            key for key in entry if key not in supported_entry_fields
        ]
        if unknown_fields:
            raise BackupImportError(
                f"tracking.yaml entry for {hostname!r} contains unsupported fields"
            )
        if entry.get("state") not in TRACKING_STATES:
            raise BackupImportError(
                f"tracking.yaml state for {hostname!r} is invalid"
            )
        for field, maximum in TRACKING_METADATA_LIMITS.items():
            candidate = entry.get(field)
            if candidate is None:
                continue
            if (
                not isinstance(candidate, str)
                or not candidate.strip()
                or len(candidate.strip()) > maximum
                or any(char in candidate for char in ("\x00", "\r", "\n"))
            ):
                raise BackupImportError(
                    f"tracking.yaml {field} for {hostname!r} is invalid"
                )
    return value


def validate_display_aliases(value):
    """Validate and normalize the public display-alias configuration.

    Aliases are presentation-only, but the file is read by several pages and is
    portable through Setup backups.  Keep its schema deliberately small so a
    malformed restore cannot turn every alias lookup into a runtime error.
    """
    if not isinstance(value, dict):
        raise BackupImportError("display-aliases.json must contain a JSON object")
    unexpected = sorted(set(value) - set(DISPLAY_ALIAS_LIMITS))
    if unexpected:
        raise BackupImportError(
            "display-aliases.json contains unsupported keys: "
            + ", ".join(unexpected)
        )

    normalized = {}
    for namespace, (max_entries, max_key, max_label) in DISPLAY_ALIAS_LIMITS.items():
        source = value.get(namespace, {})
        if not isinstance(source, dict):
            raise BackupImportError(
                f"display-aliases.json {namespace} must be a JSON object"
            )
        if len(source) > max_entries:
            raise BackupImportError(
                f"display-aliases.json {namespace} exceeds {max_entries} entries"
            )

        clean = {}
        folded = {}
        for canonical, label in source.items():
            if not isinstance(canonical, str) or not isinstance(label, str):
                raise BackupImportError(
                    f"display-aliases.json {namespace} entries must map strings to strings"
                )
            canonical = canonical.strip()
            label = label.strip()
            if not canonical or not label:
                raise BackupImportError(
                    f"display-aliases.json {namespace} contains an empty name or label"
                )
            if len(canonical) > max_key or len(label) > max_label:
                raise BackupImportError(
                    f"display-aliases.json {namespace} contains an overlong name or label"
                )
            if any(ord(char) < 32 or ord(char) == 127 for char in canonical + label):
                raise BackupImportError(
                    f"display-aliases.json {namespace} contains control characters"
                )
            folded_key = canonical.casefold()
            previous = folded.get(folded_key)
            if previous is not None and previous != canonical:
                raise BackupImportError(
                    f"display-aliases.json {namespace} contains a case-insensitive "
                    f"duplicate: {previous!r} and {canonical!r}"
                )
            folded[folded_key] = canonical
            clean[canonical] = label
        normalized[namespace] = clean
    return normalized


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


def _canonical_service_metadata(kind, name, user):
    try:
        account = pwd.getpwnam(user)
        config_gid = grp.getgrnam("www-data").gr_gid
    except KeyError as exc:
        raise BackupImportError(f"Required service account/group is missing: {exc}") from exc
    if kind == "config":
        return 0o664, account.pw_uid, config_gid
    if kind == "key-private" or kind == "key-remove" and not name.endswith(".pub"):
        return 0o600, account.pw_uid, account.pw_gid
    if kind == "key-public" or kind == "key-remove" and name.endswith(".pub"):
        return 0o644, account.pw_uid, account.pw_gid
    raise BackupImportError("Unknown service-owned recovery metadata kind")


def _collector_set_metadata(user, path, mode, uid, gid):
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise BackupImportError(f"Collector account is unavailable: {exc}") from exc
    if uid != account.pw_uid or mode & 0o7000:
        raise BackupImportError("Unsafe collector-owned file metadata")
    # No privileged pathname operation is used below. If the collector races
    # its own path into a symlink, it gains no authority it did not already
    # possess; the post-operation no-follow stat still rejects the ambiguity.
    _collector_shell(
        user,
        'chgrp -- "$1" "$2" && chmod -- "$3" "$2"',
        str(gid), path, format(mode, "o"), timeout=10,
    )


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
    _collector_set_metadata(user, stage, mode, uid, gid)
    _verify_file(stage, entry["content"], mode, uid, gid, reader=user)
    entry.update({"mode": mode, "uid": uid, "gid": gid})


def _install_direct_mount_no_follow(content, target, mode, uid, gid):
    """Rewrite a pinned bind-mount inode without following a replaceable link."""
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(target, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BackupImportError("Direct-mount restore target is not a regular file")
        if os.geteuid() != 0 and (
            before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) != mode
        ):
            raise BackupImportError("Direct-mount metadata cannot be safely normalized")
        os.ftruncate(descriptor, 0)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BackupImportError("Direct-mount write made no progress")
            view = view[written:]
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            after.st_uid != uid
            or after.st_gid != gid
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise BackupImportError("Direct-mount metadata verification failed")
    except OSError as exc:
        raise BackupImportError(f"Safe direct-mount write failed: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _install_bytes_as_collector(content, target, mode, uid, gid, *, user):
    """Install service-owned bytes without any privileged pathname mutation."""
    if _is_direct_mount(target):
        _install_direct_mount_no_follow(content, target, mode, uid, gid)
        _verify_file(target, content, mode, uid, gid, reader=user)
        _durable_path(target, reader=user)
        return
    stage = f"{target}.lldpq-collector-stage-{os.getpid()}-{secrets.token_hex(8)}"
    try:
        _as_collector(user, ["tee", stage], input_data=content, timeout=15)
        _collector_set_metadata(user, stage, mode, uid, gid)
        _verify_file(stage, content, mode, uid, gid, reader=user)
        _durable_path(stage, reader=user)
        _collector_shell(user, 'mv -fT -- "$1" "$2"', stage, target, timeout=15)
        stage = None
        _verify_file(target, content, mode, uid, gid, reader=user)
        _durable_path(target, reader=user)
    finally:
        if stage is not None:
            try:
                _as_collector(user, ["rm", "-f", "--", stage])
            except Exception:
                pass


def _activate_collector_file(entry, user):
    if entry.get("direct_mount"):
        # Docker's documented legacy single-file bind mounts reject rename(2)
        # with EBUSY.  Keep the mount inode and copy verified bytes in-place.
        _install_bytes_as_collector(
            entry["content"], entry["target"], entry["mode"],
            entry["uid"], entry["gid"], user=user,
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


def _activate_collector_removal(entry, user):
    """Remove a retired SSH identity member and durably verify its absence."""
    if entry.get("stage") is not None or entry.get("kind") != "key-remove":
        raise BackupImportError("Invalid collector key-retirement entry")
    _as_collector(user, ["rm", "-f", "--", entry["target"]])
    if os.path.lexists(entry["target"]):
        raise BackupImportError(
            f"Could not retire opposite collector key: {entry['name']}"
        )
    _durable_existing_parent(entry["target"], reader=user)


def _install_bytes_as_root(content, target, mode, uid, gid, *, reader=None):
    if reader is not None:
        return _install_bytes_as_collector(
            content, target, mode, uid, gid, user=reader
        )
    resolved = os.path.realpath(target)
    resolved_parent = os.path.dirname(resolved) or "/"
    service_system_config = (
        os.path.basename(resolved_parent) == "system-config"
        and os.path.basename(resolved) == "lldpq.conf"
        and not os.path.islink(resolved_parent)
    )
    if service_system_config:
        try:
            metadata = os.stat(resolved_parent, follow_symlinks=False)
            service_user = pwd.getpwuid(metadata.st_uid).pw_name
        except (KeyError, OSError) as exc:
            raise BackupImportError("Could not resolve system-config owner") from exc
        return _install_bytes_as_collector(
            content, resolved, mode, metadata.st_uid, gid, user=service_user
        )
    privileged_atomic_targets = {
        "/etc/lldpq.conf",
        "/etc/crontab",
        "/etc/cron.d/lldpq",
    }
    if target not in privileged_atomic_targets or os.path.islink(target):
        raise BackupImportError("Refusing privileged write outside exact root targets")
    temp_path = None
    sibling_stage = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".lldpq-import-root.", dir="/tmp")
        with os.fdopen(fd, "wb") as staged:
            staged.write(content)
            staged.flush()
            os.fsync(staged.fileno())
        parent = os.path.dirname(target) or "/"
        atomic_privileged = (
            target in privileged_atomic_targets and not _is_direct_mount(target)
        )
        if not atomic_privileged:
            raise BackupImportError("Privileged direct mounts are not safely replaceable")
        install_target = target
        if atomic_privileged:
            sibling_stage = f"{target}.lldpq-root-stage"
            if os.path.lexists(sibling_stage):
                # A killed prior transaction cannot have changed the live
                # target before rename. Retire only the fixed root-owned
                # staging name, then construct and verify it again.
                _run(["sudo", "rm", "-f", "--", sibling_stage])
            if os.path.lexists(sibling_stage):
                raise BackupImportError("Root config sibling stage could not be retired")
            install_target = sibling_stage
        _run(["sudo", "cp", temp_path, install_target])
        _run(["sudo", "chmod", format(mode, "o"), install_target])
        _run(["sudo", "chown", f"{uid}:{gid}", install_target])
        _verify_file(install_target, content, mode, uid, gid)
        _durable_path(install_target)
        if sibling_stage:
            _run(["sudo", "mv", "-fT", "--", sibling_stage, target])
            sibling_stage = None
        _verify_file(target, content, mode, uid, gid)
        _durable_path(target)
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
    if snapshot["reader"]:
        _as_collector(
            snapshot["reader"], ["rm", "-f", "--", snapshot["path"]]
        )
    else:
        if snapshot["path"] not in {
            "/etc/lldpq.conf", "/etc/crontab", "/etc/cron.d/lldpq"
        }:
            raise BackupImportError("Refusing privileged removal outside root targets")
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
    _collector_set_metadata(
        user, base, expected_mode, account.pw_uid, expected_gid
    )
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
    mode = snapshot.get("mode") if present else None
    uid = snapshot.get("uid") if present else None
    gid = snapshot.get("gid") if present else None
    if present and snapshot.get("reader") == user:
        mode, uid, gid = _canonical_service_metadata(
            entry["kind"], entry["name"], user
        )
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
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "reader": "collector" if snapshot.get("reader") == user else None,
    }, content


def _create_recovery_authority(
    entries, ssh_snapshot, *, lldpq_dir, web_root, user, token
):
    """Publish rollback state for service-owned targets only.

    The authority lives below the collector account's home (or its Docker
    config volume) and is therefore deliberately writable by that account.
    It must never contain enough authority for the root recovery service to
    replace privileged system files such as /etc/lldpq.conf or cron files.
    Those targets are rolled back synchronously from in-process snapshots.
    """
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
    for index, entry in enumerate(entries):
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
        elif kind in ("key-private", "key-public", "key-remove"):
            if name not in key_names:
                raise BackupImportError("Unknown recovery SSH target")
            expected_logical = os.path.join(ssh_dir, name)
            expected_target = _safe_target(
                expected_logical, lldpq_dir, web_root, allow_config_symlink=False
            )
            expected_reader = "collector"
        elif kind in ("root-conf", "root-cron"):
            raise BackupImportError(
                "Collector-owned recovery authority may not contain privileged targets"
            )
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
            if expected_reader == "collector" and kind != "key-remove"
            else None
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
            expected_mode, expected_uid, expected_gid = _canonical_service_metadata(
                kind, name, user
            )
            if (
                record["mode"] != expected_mode
                or record["uid"] != expected_uid
                or record["gid"] != expected_gid
            ):
                raise BackupImportError(
                    "Recovery snapshot metadata exceeds service-user authority"
                )
            if record["size"] < 0 or record["size"] > 16 * 1024 * 1024:
                raise BackupImportError("Recovery snapshot size is invalid")
            if (
                not isinstance(record["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
            ):
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
            try:
                account = pwd.getpwnam(user)
            except KeyError as exc:
                raise BackupImportError("Collector account is unavailable") from exc
            if (
                ssh_record["mode"] != 0o700
                or ssh_record["uid"] != account.pw_uid
                or ssh_record["gid"] != account.pw_gid
            ):
                raise BackupImportError(
                    "SSH directory recovery metadata exceeds collector authority"
                )
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
                _collector_set_metadata(
                    user, ssh_dir, ssh_record["mode"],
                    ssh_record["uid"], ssh_record["gid"],
                )
                metadata = os.stat(ssh_dir, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != ssh_record["uid"]
                    or metadata.st_gid != ssh_record["gid"]
                    or stat.S_IMODE(metadata.st_mode) != ssh_record["mode"]
                ):
                    raise BackupImportError("SSH directory recovery verification failed")
                _durable_path(ssh_dir, reader=user)
            elif os.path.isdir(ssh_dir):
                _as_collector(user, ["rm", "-d", "--", ssh_dir])
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


def _topology_tokenize(content):
    """Tokenize the LLDPq DOT subset without trusting the service tree."""
    tokens = []
    index = 0
    line = 1
    column = 1

    def advance(character):
        nonlocal line, column
        if character == "\n":
            line += 1
            column = 1
        else:
            column += 1

    while index < len(content):
        character = content[index]
        if character.isspace():
            advance(character)
            index += 1
            continue
        if character == "#" or content.startswith("//", index):
            while index < len(content) and content[index] != "\n":
                advance(content[index])
                index += 1
            continue
        if content.startswith("/*", index):
            start_line, start_column = line, column
            advance(content[index])
            advance(content[index + 1])
            index += 2
            while index + 1 < len(content) and content[index:index + 2] != "*/":
                advance(content[index])
                index += 1
            if index + 1 >= len(content):
                raise BackupImportError(
                    f"topology.dot:{start_line}:{start_column}: unterminated block comment"
                )
            advance(content[index])
            advance(content[index + 1])
            index += 2
            continue

        start_line, start_column = line, column
        if character == '"':
            advance(character)
            index += 1
            value = []
            while index < len(content):
                current = content[index]
                if current == '"':
                    advance(current)
                    index += 1
                    break
                if current == "\\":
                    if index + 1 >= len(content):
                        raise BackupImportError(
                            f"topology.dot:{start_line}:{start_column}: unterminated quoted identifier"
                        )
                    escaped = content[index + 1]
                    advance(current)
                    advance(escaped)
                    index += 2
                    if escaped != "\n":
                        value.append(escaped)
                    continue
                if current in "\r\n":
                    raise BackupImportError(
                        f"topology.dot:{start_line}:{start_column}: newline in quoted identifier"
                    )
                value.append(current)
                advance(current)
                index += 1
            else:
                raise BackupImportError(
                    f"topology.dot:{start_line}:{start_column}: unterminated quoted identifier"
                )
            tokens.append(("ID", "".join(value), start_line, start_column, True))
            continue

        if character == "[":
            depth = 1
            quoted = False
            escaped = False
            advance(character)
            index += 1
            while index < len(content) and depth:
                current = content[index]
                if quoted:
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == '"':
                        quoted = False
                elif current == '"':
                    quoted = True
                elif current == "[":
                    depth += 1
                elif current == "]":
                    depth -= 1
                advance(current)
                index += 1
            if depth:
                raise BackupImportError(
                    f"topology.dot:{start_line}:{start_column}: unterminated attribute list"
                )
            continue

        if content.startswith("--", index):
            tokens.append(("EDGE", "--", start_line, start_column, False))
            advance("-")
            advance("-")
            index += 2
            continue
        if content.startswith("->", index):
            raise BackupImportError(
                f"topology.dot:{start_line}:{start_column}: directed edges are unsupported; use '--'"
            )
        punctuation = {
            ":": "COLON", ";": "SEMI", "{": "LBRACE", "}": "RBRACE",
            ",": "COMMA", "=": "EQUAL",
        }
        if character in punctuation:
            tokens.append((
                punctuation[character], character, start_line, start_column, False
            ))
            advance(character)
            index += 1
            continue

        value = []
        while index < len(content):
            current = content[index]
            if current.isspace() or current in '\"#:;{}[],=':
                break
            if (
                content.startswith("--", index)
                or content.startswith("//", index)
                or content.startswith("/*", index)
            ):
                break
            value.append(current)
            advance(current)
            index += 1
        if not value:
            raise BackupImportError(
                f"topology.dot:{start_line}:{start_column}: unsupported character {character!r}"
            )
        tokens.append(("ID", "".join(value), start_line, start_column, False))
    return tokens


def _topology_endpoint(tokens, index):
    if index >= len(tokens) or tokens[index][0] != "ID":
        return None
    if (
        index + 2 >= len(tokens)
        or tokens[index + 1][0] != "COLON"
        or tokens[index + 2][0] != "ID"
    ):
        return None
    device = tokens[index][1]
    port_parts = [tokens[index + 2][1]]
    cursor = index + 3
    while (
        cursor + 1 < len(tokens)
        and tokens[cursor][0] == "COLON"
        and tokens[cursor + 1][0] == "ID"
    ):
        port_parts.append(tokens[cursor + 1][1])
        cursor += 2
    port = ":".join(port_parts)
    if not device or not port:
        return None
    return device, port, cursor, tokens[index][2]


def _topology_normalize_hostname(name):
    value = name.strip().rstrip(".")
    while value:
        folded = value.casefold()
        suffix = next((item for item in (
            ".cm.cluster", ".localdomain", ".local"
        ) if folded.endswith(item)), None)
        if suffix is None:
            break
        value = value[:-len(suffix)].rstrip(".")
    return value


def _topology_device_key_resolver(known_names):
    names = []
    seen = set()
    for raw_name in known_names:
        name = raw_name.strip().rstrip(".")
        if name and name.casefold() not in seen:
            names.append(name)
            seen.add(name.casefold())
    short_identities = {name.casefold() for name in names if "." not in name}
    exact_to_key = {}
    aliases = {}
    for name in names:
        exact = name.casefold()
        short = name.split(".", 1)[0].casefold()
        normalized = _topology_normalize_hostname(name).casefold() or exact
        canonical = short if "." in name and short in short_identities else normalized
        exact_to_key[exact] = canonical
        for candidate in (exact, canonical, short):
            if candidate:
                aliases.setdefault(candidate, set()).add(canonical)
    unique_aliases = {
        alias: next(iter(keys)) for alias, keys in aliases.items() if len(keys) == 1
    }

    def resolve(raw_name):
        name = raw_name.strip().rstrip(".")
        folded = name.casefold()
        if folded in exact_to_key:
            return exact_to_key[folded]
        for candidate in (
            _topology_normalize_hostname(name).casefold(),
            name.split(".", 1)[0].casefold(),
        ):
            if candidate in unique_aliases:
                return unique_aliases[candidate]
        return _topology_normalize_hostname(name).casefold()

    return resolve


def _validate_project_topology_dot(text, staged_path):
    """Validate the same syntax and P2P semantics as the Setup editor."""
    if not text.strip():
        raise BackupImportError("topology.dot cannot be empty")
    tokens = _topology_tokenize(text)
    cursor = 0
    if (
        cursor < len(tokens)
        and tokens[cursor][0] == "ID"
        and not tokens[cursor][4]
        and tokens[cursor][1].casefold() == "strict"
    ):
        cursor += 1
    if (
        cursor >= len(tokens)
        or tokens[cursor][0] != "ID"
        or tokens[cursor][4]
        or tokens[cursor][1].casefold() != "graph"
    ):
        raise BackupImportError(
            "topology.dot must start with an undirected 'graph' declaration"
        )
    cursor += 1
    if cursor < len(tokens) and tokens[cursor][0] == "ID":
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor][0] != "LBRACE":
        raise BackupImportError("topology.dot graph declaration must be followed by '{'")

    header_brace = cursor
    depth = 0
    closing = None
    for token_index in range(header_brace, len(tokens)):
        kind = tokens[token_index][0]
        token_line = tokens[token_index][2]
        token_column = tokens[token_index][3]
        if kind == "LBRACE":
            depth += 1
        elif kind == "RBRACE":
            depth -= 1
            if depth < 0:
                raise BackupImportError(
                    f"topology.dot:{token_line}:{token_column}: unmatched closing brace"
                )
            if depth == 0:
                closing = token_index
                break
    if depth:
        raise BackupImportError("topology.dot graph has unbalanced braces")
    if closing is None:
        raise BackupImportError("topology.dot graph is missing a closing brace")
    for token in tokens[closing + 1:]:
        if token[0] != "SEMI":
            raise BackupImportError(
                f"topology.dot:{token[2]}:{token[3]}: content appears after the top-level graph"
            )

    edges = []
    consumed_edges = set()
    consumed_endpoints = set()
    index = 0
    while index < len(tokens):
        endpoint = _topology_endpoint(tokens, index)
        if endpoint is None:
            index += 1
            continue
        left_device, left_port, edge_cursor, edge_line = endpoint
        if edge_cursor >= len(tokens) or tokens[edge_cursor][0] != "EDGE":
            index += 1
            continue
        consumed_endpoints.update(range(index, edge_cursor))
        while edge_cursor < len(tokens) and tokens[edge_cursor][0] == "EDGE":
            consumed_edges.add(edge_cursor)
            right = _topology_endpoint(tokens, edge_cursor + 1)
            if right is None:
                token = tokens[edge_cursor]
                raise BackupImportError(
                    f"topology.dot:{token[2]}:{token[3]}: edge endpoint must be device:port"
                )
            right_device, right_port, next_cursor, _right_line = right
            consumed_endpoints.update(range(edge_cursor + 1, next_cursor))
            edges.append((left_device, left_port, right_device, right_port, edge_line))
            left_device, left_port = right_device, right_port
            edge_cursor = next_cursor
        index = edge_cursor

    for token_index, token in enumerate(tokens):
        if token[0] == "EDGE" and token_index not in consumed_edges:
            raise BackupImportError(
                f"topology.dot:{token[2]}:{token[3]}: unsupported topology edge syntax"
            )
        if token[0] == "COLON" and token_index not in consumed_endpoints:
            raise BackupImportError(
                f"topology.dot:{token[2]}:{token[3]}: device:port endpoint is not part of an edge"
            )

    known_names = [name for edge in edges for name in (edge[0], edge[2])]
    device_key = _topology_device_key_resolver(known_names)
    seen_edges = {}
    seen_endpoints = {}
    for left_device, left_port, right_device, right_port, edge_line in edges:
        for label, value in (
            ("device", left_device), ("interface", left_port),
            ("device", right_device), ("interface", right_port),
        ):
            if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
                raise BackupImportError(
                    f"topology.dot:{edge_line}: topology {label} {value!r} contains "
                    "whitespace or control characters unsupported by LLDP reports"
                )
        left = (device_key(left_device), left_port.strip().strip(","))
        right = (device_key(right_device), right_port.strip().strip(","))
        if left == right:
            raise BackupImportError(
                f"topology.dot:{edge_line}: topology edge connects endpoint "
                f"{left_device}:{left_port} to itself"
            )
        edge_key = tuple(sorted((left, right)))
        if edge_key in seen_edges:
            raise BackupImportError(
                f"topology.dot:{edge_line}: duplicate topology edge; first defined "
                f"on line {seen_edges[edge_key]}"
            )
        for endpoint_key, display in (
            (left, f"{left_device}:{left_port}"),
            (right, f"{right_device}:{right_port}"),
        ):
            if endpoint_key in seen_endpoints:
                raise BackupImportError(
                    f"topology.dot:{edge_line}: endpoint {display} is reused; first "
                    f"used on line {seen_endpoints[endpoint_key]}"
                )
            seen_endpoints[endpoint_key] = edge_line
        seen_edges[edge_key] = edge_line

    # Graphviz is a useful second parser, but never replaces LLDPq's stricter
    # edge grammar above: Graphviz also accepts directed and non-edge graphs.
    dot = shutil.which("dot")
    if dot:
        try:
            checked = subprocess.run(
                [dot, "-Tdot", staged_path, "-o", os.devnull],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise BackupImportError("topology.dot validation timed out") from exc
        except OSError as exc:
            raise BackupImportError(f"Could not validate topology.dot: {exc}") from exc
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout or "invalid DOT").strip()
            raise BackupImportError("Invalid topology.dot: " + detail[:300])


def _load_yaml_mapping(text, name, *, allow_empty=False):
    try:
        import yaml
    except ImportError as exc:
        raise BackupImportError("PyYAML is required to restore configuration") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise BackupImportError(f"Invalid unhashable YAML key in {name}") from exc
            if duplicate:
                raise BackupImportError(f"Duplicate YAML key in {name}: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        value = yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise BackupImportError(f"Invalid {name} YAML: {str(exc)[:300]}") from exc
    if value is None and allow_empty:
        return {}
    if not isinstance(value, dict):
        raise BackupImportError(f"{name} must contain a YAML mapping")
    return value


def _load_json_no_duplicate_keys(text, name):
    def object_hook(pairs):
        result = {}
        seen = {}
        for key, value in pairs:
            folded = key.casefold()
            if folded in seen:
                raise BackupImportError(
                    f"Duplicate JSON key in {name}: {seen[folded]!r} and {key!r}"
                )
            seen[folded] = key
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=object_hook)
    except json.JSONDecodeError as exc:
        raise BackupImportError(f"{name} is not valid JSON") from exc


def _topology_string(value, field, *, maximum=512):
    if not isinstance(value, str):
        raise BackupImportError(f"{field} must be a string")
    value = value.strip()
    if not value:
        raise BackupImportError(f"{field} cannot be empty")
    if len(value) > maximum or any(char in value for char in ("\x00", "\r", "\n")):
        raise BackupImportError(
            f"{field} is too long or contains unsupported control characters"
        )
    return value


def _topology_layer(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000:
        raise BackupImportError(f"{field} must be an integer between 0 and 1000")
    return value


def _topology_pattern(value, field):
    value = _topology_string(value, field)
    try:
        return re.compile(value)
    except re.error as exc:
        raise BackupImportError(f"{field} is not a valid regular expression: {exc}") from exc


def _validate_topology_config(value):
    topology = value.get("topology", "minimal")
    if topology not in ("minimal", "full"):
        raise BackupImportError(
            "topology_config.yaml 'topology' must be 'minimal' or 'full'"
        )

    categories = value.get("device_categories", [])
    if not isinstance(categories, list):
        raise BackupImportError("'device_categories' must be a list")
    for index, category in enumerate(categories):
        prefix = f"device_categories[{index}]"
        if not isinstance(category, dict):
            raise BackupImportError(prefix + " must be a mapping")
        _topology_pattern(category.get("pattern"), prefix + ".pattern")
        _topology_layer(category.get("layer"), prefix + ".layer")
        _topology_string(category.get("icon"), prefix + ".icon", maximum=64)

    default = value.get("default", {"layer": 9, "icon": "server"})
    if not isinstance(default, dict):
        raise BackupImportError("'default' must be a mapping")
    _topology_layer(default.get("layer"), "default.layer")
    _topology_string(default.get("icon"), "default.icon", maximum=64)

    rules = value.get("special_rules", [])
    if not isinstance(rules, list):
        raise BackupImportError("'special_rules' must be a list")
    for index, rule in enumerate(rules):
        prefix = f"special_rules[{index}]"
        if not isinstance(rule, dict):
            raise BackupImportError(prefix + " must be a mapping")
        _topology_pattern(rule.get("pattern"), prefix + ".pattern")
        rule_type = _topology_string(rule.get("type"), prefix + ".type", maximum=64)
        if rule_type not in ("stagger", "even_odd_suffix"):
            raise BackupImportError(
                prefix + ".type must be 'stagger' or 'even_odd_suffix'"
            )
        if "number_regex" in rule:
            number_pattern = _topology_pattern(
                rule["number_regex"], prefix + ".number_regex"
            )
            if number_pattern.groups < 1:
                raise BackupImportError(
                    prefix + ".number_regex must include a capture group"
                )
        _topology_string(rule.get("icon"), prefix + ".icon", maximum=64)
        if rule_type == "even_odd_suffix":
            _topology_layer(rule.get("even_layer"), prefix + ".even_layer")
            _topology_layer(rule.get("odd_layer"), prefix + ".odd_layer")
        elif "layer" in rule:
            _topology_layer(rule["layer"], prefix + ".layer")


def _optional_mapping(parent, key, path):
    if key not in parent:
        return {}
    value = parent[key]
    if not isinstance(value, dict):
        raise BackupImportError(path + " must be a mapping")
    return value


def _known_bool(parent, key, path):
    if key in parent and not isinstance(parent[key], bool):
        raise BackupImportError(path + " must be true or false")


def _known_text(parent, key, path, *, maximum):
    if key not in parent:
        return None
    value = parent[key]
    if not isinstance(value, str):
        raise BackupImportError(path + " must be a string")
    value = value.strip()
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise BackupImportError(path + " is too long or contains control characters")
    return value


def _known_number(parent, key, path, low, high, *, integer=False):
    if key not in parent:
        return None
    value = parent[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BackupImportError(path + " must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise BackupImportError(path + " must be a finite number")
    if integer and int(value) != value:
        raise BackupImportError(path + " must be a whole number")
    if value < low or value > high:
        raise BackupImportError(f"{path} must be between {low} and {high}")
    return value


def _validate_notifications(value):
    notifications = _optional_mapping(value, "notifications", "notifications")
    thresholds = _optional_mapping(value, "thresholds", "thresholds")
    alert_types = _optional_mapping(value, "alert_types", "alert_types")
    strategy = _optional_mapping(value, "alert_strategy", "alert_strategy")
    frequency = _optional_mapping(value, "frequency", "frequency")

    _known_bool(notifications, "enabled", "notifications.enabled")
    server_url = _known_text(
        notifications, "server_url", "notifications.server_url", maximum=2048
    )
    if server_url and not re.fullmatch(r"https?://[^\s]+", server_url):
        raise BackupImportError("notifications.server_url must be an http(s) URL")

    slack = _optional_mapping(notifications, "slack", "notifications.slack")
    _known_bool(slack, "enabled", "notifications.slack.enabled")
    webhook = _known_text(
        slack, "webhook", "notifications.slack.webhook", maximum=2048
    )
    if webhook and not webhook.startswith("https://hooks.slack.com/"):
        raise BackupImportError(
            "notifications.slack.webhook must be an https://hooks.slack.com/ URL"
        )
    _known_text(slack, "channel", "notifications.slack.channel", maximum=128)

    for key in (
        "hardware_alerts",
        "network_alerts",
        "system_alerts",
        "topology_alerts",
        "log_alerts",
    ):
        _known_bool(alert_types, key, "alert_types." + key)

    mode = _known_text(strategy, "mode", "alert_strategy.mode", maximum=32)
    if mode is not None and mode not in ("summary", "immediate", "change_only"):
        raise BackupImportError("Unsupported alert_strategy.mode")
    _known_number(
        frequency,
        "min_interval_minutes",
        "frequency.min_interval_minutes",
        1,
        10080,
        integer=True,
    )

    network = _optional_mapping(thresholds, "network", "thresholds.network")
    hardware = _optional_mapping(thresholds, "hardware", "thresholds.hardware")
    system = _optional_mapping(thresholds, "system", "thresholds.system")
    _known_number(
        network, "bgp_down_minutes", "thresholds.network.bgp_down_minutes", 0, 10080
    )
    flap_warning = _known_number(
        network,
        "link_flaps_per_hour",
        "thresholds.network.link_flaps_per_hour",
        0,
        100000,
    )
    flap_critical = _known_number(
        network,
        "link_flaps_critical",
        "thresholds.network.link_flaps_critical",
        0,
        100000,
    )
    if (
        flap_warning is not None
        and flap_critical is not None
        and flap_critical < flap_warning
    ):
        raise BackupImportError(
            "thresholds.network.link_flaps_critical must be greater than or equal "
            "to link_flaps_per_hour"
        )
    _known_number(
        network,
        "optical_power_margin",
        "thresholds.network.optical_power_margin",
        -100,
        100,
    )
    _known_number(
        hardware,
        "cpu_temp_critical",
        "thresholds.hardware.cpu_temp_critical",
        0,
        250,
    )
    _known_number(
        hardware,
        "asic_temp_critical",
        "thresholds.hardware.asic_temp_critical",
        0,
        250,
    )
    _known_number(
        system,
        "disk_usage_critical",
        "thresholds.system.disk_usage_critical",
        0,
        100,
    )


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
        value = _load_yaml_mapping(text, name)
        if (
            "devices" not in value
            or not isinstance(value.get("devices"), dict)
            or not value["devices"]
        ):
            raise BackupImportError(
                "devices.yaml must contain a non-empty 'devices' mapping"
            )
        defaults = value.get("defaults", {})
        if defaults is not None and not isinstance(defaults, dict):
            raise BackupImportError("devices.yaml 'defaults' must be a mapping")
        endpoint_hosts = value.get("endpoint_hosts", [])
        if endpoint_hosts is not None and (
            not isinstance(endpoint_hosts, list)
            or any(not isinstance(item, str) for item in endpoint_hosts)
        ):
            raise BackupImportError(
                "devices.yaml 'endpoint_hosts' must be a list of strings"
            )
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
    elif name == "topology.dot":
        _validate_project_topology_dot(text, staged)
    elif name == "topology_config.yaml":
        _validate_topology_config(_load_yaml_mapping(text, name))
    elif name == "notifications.yaml":
        _validate_notifications(_load_yaml_mapping(text, name, allow_empty=True))
    elif name == "tracking.yaml":
        validate_tracking_config(_load_yaml_mapping(text, name, allow_empty=True))
    elif name == "display-aliases.json":
        value = _load_json_no_duplicate_keys(text, name)
        normalized = validate_display_aliases(value)
        if normalized != value:
            raise BackupImportError(
                f"{name} must use trimmed names and include interfaces/devices objects"
            )


def validate_config_for_bundle(name, content, *, lldpq_dir):
    """Apply restore-time validation before advertising a backup as usable."""
    supported = {
        "devices.yaml", "topology.dot", "topology_config.yaml",
        "notifications.yaml", "tracking.yaml", "display-aliases.json",
    }
    if name not in supported:
        raise BackupImportError(f"Unsupported managed backup config: {name}")
    if not isinstance(content, bytes):
        raise BackupImportError(f"Backup config must be bytes: {name}")
    if len(content) > 2 * 1024 * 1024:
        raise BackupImportError(f"Backup config is too large: {name}")
    with tempfile.TemporaryDirectory(prefix="lldpq-export-validate-") as validation_dir:
        _validate_config(name, content, validation_dir, lldpq_dir)
    return True


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


_PORTABLE_BOOLEAN_KEYS = {
    "SKIP_OPTICAL", "SKIP_L1", "AUTO_BASE_CONFIG", "AUTO_ZTP_DISABLE",
    "AUTO_SET_HOSTNAME", "TELEMETRY_ENABLED", "MONITOR_TIMING",
}
_PORTABLE_INTEGER_RANGES = {
    "AI_CONTEXT_WINDOW_TOKENS": (8_000, 2_000_000),
    "AI_FALLBACK_CONTEXT_WINDOW_TOKENS": (8_000, 2_000_000),
    "SCAN_INTERVAL": (0, 86400),
    "MONITOR_MAX_PARALLEL": (1, 1000),
    "PFC_ECN_MAX_PARALLEL": (1, 8),
    "PFC_ECN_COLLECTION_BUDGET_SECONDS": (1, 86400),
    "PFC_ECN_PORT_TIMEOUT_SECONDS": (1, 86400),
    "OPTICAL_COLLECTION_BUDGET_SECONDS": (1, 86400),
    "OPTICAL_PORT_TIMEOUT_SECONDS": (1, 86400),
    "LLDP_MAX_PARALLEL": (1, 1000),
    "ASSETS_MAX_PARALLEL": (1, 1000),
    "GET_CONFIGS_MAX_PARALLEL": (1, 1000),
    "SEND_CMD_MAX_PARALLEL": (1, 1000),
    "TELEMETRY_MAX_PARALLEL": (1, 1000),
    "TRANSCEIVER_FW_MAX_PARALLEL": (1, 1000),
    "GET_CONFIGS_SSH_TIMEOUT": (1, 86400),
    "TRANSCEIVER_FW_SSH_TIMEOUT": (1, 86400),
    "TRANSCEIVER_FW_MIN_INTERVAL": (0, 604800),
}
_PORTABLE_OPTIONAL_INTEGER_KEYS = {
    "AI_CONTEXT_WINDOW_TOKENS", "AI_FALLBACK_CONTEXT_WINDOW_TOKENS",
}
_PORTABLE_URL_KEYS = {
    "PROMETHEUS_URL", "AI_API_URL", "OLLAMA_URL", "AI_PROXY_URL", "AI_SEARCH_URL",
}
_PORTABLE_OPTIONAL_URL_KEYS = {"AI_PROXY_URL", "AI_SEARCH_URL"}
_PORTABLE_MODEL_KEYS = {"AI_MODEL", "AI_FALLBACK_MODEL", "AI_SEARCH_MODEL"}
_PORTABLE_OPTIONAL_MODEL_KEYS = {"AI_FALLBACK_MODEL", "AI_SEARCH_MODEL"}


def _portable_scalar(candidate, key):
    if not isinstance(candidate, str) or len(candidate) > 2048:
        raise BackupImportError(f"Portable preference {key} is too long")
    value = candidate.strip()
    if value[:1] in ("'", '"') or value[-1:] in ("'", '"'):
        if len(value) < 2 or value[0] != value[-1] or value[0] not in ("'", '"'):
            raise BackupImportError(f"Portable preference {key} has mismatched quotes")
        value = value[1:-1]
    if len(value) > 1024 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BackupImportError(
            f"Portable preference {key} contains invalid control text"
        )
    return value


def _validate_portable_preference(key, candidate, validate_cron):
    """Validate a portable value and return one shell-safe assignment token."""
    value = _portable_scalar(candidate, key)
    if key in ("LLDPQ_CRON", "GETCONF_CRON"):
        if not value or len(value) > 128 or not validate_cron(value):
            raise BackupImportError(f"Invalid imported cron schedule: {key}")
        return shlex.quote(value)
    if key in _PORTABLE_BOOLEAN_KEYS:
        normalized = value.casefold()
        if normalized not in ("true", "false"):
            raise BackupImportError(
                f"Portable preference {key} must be true or false"
            )
        return normalized
    if key in _PORTABLE_INTEGER_RANGES:
        if not value and key in _PORTABLE_OPTIONAL_INTEGER_KEYS:
            return shlex.quote(value)
        if not re.fullmatch(r"[0-9]+", value):
            raise BackupImportError(
                f"Portable preference {key} must be a whole number"
            )
        number = int(value)
        minimum, maximum = _PORTABLE_INTEGER_RANGES[key]
        if not minimum <= number <= maximum:
            raise BackupImportError(
                f"Portable preference {key} must be between {minimum} and {maximum}"
            )
        return str(number)
    if key == "TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY":
        normalized = value.casefold()
        if normalized not in ("run", "skip"):
            raise BackupImportError(
                "Portable preference TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY "
                "must be run or skip"
            )
        return normalized
    if key == "TRANSCEIVER_FW_SKIP_MODELS":
        if len(value) > 512 or (
            value and not re.fullmatch(r"[A-Za-z0-9_.-]+(?:[\s,]+[A-Za-z0-9_.-]+)*", value)
        ):
            raise BackupImportError(
                "Portable preference TRANSCEIVER_FW_SKIP_MODELS has invalid model names"
            )
        return shlex.quote(value)
    if key == "AI_PROVIDER":
        normalized = value.casefold()
        if normalized not in (
            "ollama", "openai", "claude", "gemini", "custom", "nvidia"
        ):
            raise BackupImportError("Portable preference AI_PROVIDER is unsupported")
        return normalized
    if key in _PORTABLE_MODEL_KEYS:
        if not value and key in _PORTABLE_OPTIONAL_MODEL_KEYS:
            return shlex.quote(value)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+~-]{0,255}", value):
            raise BackupImportError(f"Portable preference {key} has an invalid model name")
        return shlex.quote(value)
    if key in _PORTABLE_URL_KEYS:
        if not value and key in _PORTABLE_OPTIONAL_URL_KEYS:
            return shlex.quote(value)
        if len(value) > 2048:
            raise BackupImportError(f"Portable preference {key} URL is too long")
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise BackupImportError(
                f"Portable preference {key} must be an http(s) URL without credentials"
            )
        try:
            _ = parsed.port
        except ValueError as exc:
            raise BackupImportError(
                f"Portable preference {key} has an invalid URL port"
            ) from exc
        return shlex.quote(value)
    # Future caller-allowlisted keys remain bounded and shell-quoted until a
    # more specific semantic validator is added here.
    if len(value) > 512:
        raise BackupImportError(f"Portable preference {key} is too long")
    return shlex.quote(value)


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
                # Six managed configs, portable preferences and four possible
                # SSH key members can each legally reach the 2 MiB entry cap.
                # Keep import at least as permissive as bundles export can make.
                if total_size > 20 * 1024 * 1024:
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
                        pref_values[key] = _validate_portable_preference(
                            key, candidate, validate_cron
                        )
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

        private_names = [
            name for name in ("id_ed25519", "id_rsa")
            if name in key_validation
        ]
        if len(private_names) > 1:
            raise BackupImportError(
                "Backup bundle contains multiple SSH private identities"
            )
        if private_names:
            selected = private_names[0]
            opposite = "id_rsa" if selected == "id_ed25519" else "id_ed25519"
            if opposite in key_validation or opposite + ".pub" in key_validation:
                raise BackupImportError(
                    "A private-key backup may not include opposite-algorithm key material"
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


def _restore_root_entries(root_entries):
    """Synchronously roll privileged targets back from process-owned memory."""
    errors = []
    for entry in reversed(root_entries):
        try:
            _restore_snapshot(entry["snapshot"])
        except Exception as exc:
            errors.append(f"{entry['name']}: {exc}")
    if errors:
        raise BackupImportError(
            "Privileged target rollback is incomplete: " + "; ".join(errors[:2])
        )


def _append_opposite_key_retirements(
    entries, *, ssh_dir, lldpq_dir, web_root, user, resolved_targets
):
    """Add deletion entries for the inactive SSH algorithm to the transaction."""
    private_entries = [entry for entry in entries if entry["kind"] == "key-private"]
    if not private_entries:
        return
    if len(private_entries) != 1:
        # Parsing already rejects this; retain the invariant at the mutation
        # boundary in case restore_bundle is called with a different parser.
        raise BackupImportError("Backup bundle contains multiple SSH private identities")
    selected = private_entries[0]["name"]
    if selected not in ("id_ed25519", "id_rsa"):
        raise BackupImportError("Unsupported collector SSH private identity")
    opposite = "id_rsa" if selected == "id_ed25519" else "id_ed25519"
    for name in (opposite, opposite + ".pub"):
        logical = os.path.join(ssh_dir, name)
        target = _safe_target(
            logical, lldpq_dir, web_root, allow_config_symlink=False
        )
        if target in resolved_targets:
            raise BackupImportError(
                "Private-key restore conflicts with opposite-algorithm key material"
            )
        resolved_targets.add(target)
        entries.append(
            {
                "name": name,
                "content": b"",
                "kind": "key-remove",
                "logical_target": logical,
                "target": target,
                "stage": None,
                "direct_mount": _is_direct_mount(target),
                "snapshot": _snapshot_file(target, reader=user),
            }
        )


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
        "tracking.yaml": lldpq_dir,
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
                "mode": 0o660,
                # CLI access must not depend on a just-added supplementary
                # group becoming visible in the caller's existing shell.
                # Docker's persistent system-config writer already uses the
                # same service-account ownership for atomic replacements.
                "uid": account.pw_uid,
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
    _append_opposite_key_retirements(
        entries,
        ssh_dir=ssh_dir,
        lldpq_dir=lldpq_dir,
        web_root=web_root,
        user=lldpq_user,
        resolved_targets=resolved_targets,
    )
    token = f"{os.getpid()}-{secrets.token_hex(8)}"
    for entry in entries:
        entry["stage"] = (
            None
            if entry["kind"] == "key-remove"
            else f"{entry['target']}.lldpq-import-stage-{token}"
        )
    ssh_snapshot = None
    if has_keys:
        ssh_snapshot = {
            "path": ssh_dir,
            "present": ssh_dir_existed,
            "mode": 0o700 if ssh_dir_existed else None,
            "uid": account.pw_uid if ssh_dir_existed else None,
            "gid": account.pw_gid if ssh_dir_existed else None,
        }

    # Publish fsynced rollback authority before creating .ssh, staging beside
    # targets, or performing the first live activation.
    recovery_dir = None
    if entries:
        recovery_dir = _create_recovery_authority(
            entries, ssh_snapshot,
            lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user, token=token,
        )

    # Stage and verify every service-owned file before the first activation.
    try:
        if has_keys:
            _as_collector(lldpq_user, ["mkdir", "-p", ssh_dir])
        for entry in entries:
            if entry["kind"] == "key-remove":
                continue
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
            recovered = recovery_dir is not None and _recover_retained_authority(
                lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user,
                allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
            )
            if recovery_dir is not None and not recovered:
                raise BackupImportError("Durable recovery authority disappeared")
        except Exception as recovery_error:
            raise BackupImportError(
                f"Import staging failed and recovery is incomplete: {stage_error}; "
                f"recovery: {recovery_error}"
            ) from stage_error
        raise BackupImportError(
            f"Import staging failed; all targets were restored: {stage_error}"
        ) from stage_error

    root_activation_started = False
    try:
        if has_keys:
            _collector_set_metadata(
                lldpq_user, ssh_dir, 0o700, account.pw_uid, account.pw_gid
            )
            ssh_metadata = os.stat(ssh_dir, follow_symlinks=False)
            if (
                not stat.S_ISDIR(ssh_metadata.st_mode)
                or ssh_metadata.st_mode & 0o7777 != 0o700
                or ssh_metadata.st_uid != account.pw_uid
                or ssh_metadata.st_gid != account.pw_gid
            ):
                raise BackupImportError("SSH directory metadata verification failed")
            _durable_path(ssh_dir, reader=lldpq_user)
        for entry in entries:
            if entry["kind"] == "key-remove":
                _activate_collector_removal(entry, lldpq_user)
            else:
                _activate_collector_file(entry, lldpq_user)
        root_activation_started = bool(root_entries)
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
        if recovery_dir is not None:
            _commit_recovery_authority(
                lldpq_user, recovery_dir,
                _recovery_base(lldpq_dir, lldpq_user), token,
            )
    except Exception as commit_error:
        _cleanup_stages(entries, lldpq_user)
        rollback_errors = []
        if root_activation_started:
            try:
                _restore_root_entries(root_entries)
            except Exception as root_recovery_error:
                rollback_errors.append(f"privileged recovery: {root_recovery_error}")
        try:
            recovered = recovery_dir is not None and _recover_retained_authority(
                lldpq_dir=lldpq_dir, web_root=web_root, user=lldpq_user,
                allowed=allowed, key_names=key_names, ssh_dir=ssh_dir,
            )
            if recovery_dir is not None and not recovered:
                raise BackupImportError("Durable recovery authority disappeared")
        except Exception as recovery_error:
            rollback_errors.append(f"service recovery: {recovery_error}")
        if rollback_errors:
            raise BackupImportError(
                f"Import failed and recovery is incomplete: {commit_error}; "
                + "; ".join(rollback_errors)
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
            if entry["kind"] in ("key-private", "key-public")
        ),
        "prefs": sorted(pref_values),
    }


def recover_retained_import(*, lldpq_dir, user, web_root):
    """Recover a retained transaction without reading the potentially partial config."""
    allowed = {
        "devices.yaml": lldpq_dir,
        "tracking.yaml": lldpq_dir,
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


def _acquire_inventory_lock(web_root):
    """Join Provision's inventory transaction during retained recovery."""
    path = os.path.join(web_root, ".inventory.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    handle = None
    try:
        descriptor = os.open(path, flags, 0o664)
        if os.geteuid() == 0:
            try:
                inventory_gid = grp.getgrnam("www-data").gr_gid
            except KeyError as exc:
                raise BackupImportError(
                    "Required inventory lock group is unavailable"
                ) from exc
            os.fchown(descriptor, 0, inventory_gid)
            os.fchmod(descriptor, 0o660)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IWOTH:
            raise BackupImportError("Inventory lock has unsafe type or permissions")
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
        if isinstance(exc, BackupImportError):
            raise
        raise BackupImportError(f"Could not acquire inventory lock: {exc}") from exc


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
    inventory_lock_handle = None
    try:
        # This is the same lock used by Setup imports. A path-triggered service
        # waits for a normal transaction; after release it either recovers the
        # retained authority or observes that the completed import removed it.
        lock_handle = _acquire_configuration_lock()
        if args.command == "recover":
            inventory_lock_handle = _acquire_inventory_lock(
                os.path.normpath(args.web_root)
            )
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
        if inventory_lock_handle is not None:
            try:
                fcntl.flock(inventory_lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                inventory_lock_handle.close()
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
