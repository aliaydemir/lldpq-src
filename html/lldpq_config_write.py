#!/usr/bin/env python3
"""Locked, durable updates for the shared LLDPq runtime configuration.

The web APIs must not truncate ``/etc/lldpq.conf`` in place.  Docker normally
exposes that path as a symlink into the persistent ``system-config`` volume,
while native installs keep a regular file in the root-owned ``/etc``
directory.  This module preserves both layouts and deliberately rejects a
changing legacy single-file bind mount, which cannot be replaced atomically.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from typing import Mapping, Optional


DEFAULT_CONFIG_PATH = "/etc/lldpq.conf"
DEFAULT_LOCK_PATH = "/etc/lldpq.conf.lock"
MAX_CONFIG_BYTES = 4 * 1024 * 1024
ORPHAN_STAGE_GRACE_SECONDS = 3600
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ConfigWriteError(RuntimeError):
    """A safe configuration read/update could not be completed."""


class RevisionConflict(ConfigWriteError):
    """The target changed after the caller's expected revision."""


class RollbackSkipped(ConfigWriteError):
    """A later non-cooperating replacement must not be overwritten."""


def _revision(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _mountinfo_path(value: str) -> str:
    for escaped, plain in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(escaped, plain)
    return os.path.normpath(value)


def is_direct_file_mount(path: str, mountinfo_path: str = "/proc/self/mountinfo") -> bool:
    """Return true only when the resolved regular file is an exact mountpoint."""
    resolved = os.path.normpath(os.path.abspath(os.path.realpath(path)))
    try:
        metadata = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise ConfigWriteError(f"Cannot inspect LLDPq configuration target: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ConfigWriteError("LLDPq configuration target is not a regular file")
    try:
        with open(mountinfo_path, "r", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) >= 5 and _mountinfo_path(fields[4]) == resolved:
                    return True
    except FileNotFoundError:
        # Unit tests and native development may run outside Linux.  A deployed
        # Linux service must be able to prove that the target is replaceable.
        if sys.platform.startswith("linux"):
            raise ConfigWriteError(
                "Cannot verify whether /etc/lldpq.conf is a direct file mount"
            )
    except OSError as exc:
        raise ConfigWriteError(
            f"Cannot verify whether /etc/lldpq.conf is a direct file mount: {exc}"
        ) from exc
    return False


def _open_regular_no_follow(path: str, flags: int) -> tuple[int, os.stat_result]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ConfigWriteError(f"Configuration target is not a regular file: {path}")
    descriptor = os.open(
        path,
        flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        after = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ConfigWriteError("Configuration target changed while opening")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, MAX_CONFIG_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_CONFIG_BYTES:
            raise ConfigWriteError("LLDPq configuration exceeds the safe size limit")
    return b"".join(chunks)


def _snapshot_target(path: str) -> tuple[bytes, os.stat_result]:
    descriptor, metadata = _open_regular_no_follow(path, os.O_RDONLY)
    try:
        content = _read_descriptor(descriptor)
        stable = os.fstat(descriptor)
        if (stable.st_dev, stable.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ConfigWriteError("Configuration target changed while reading")
        return content, stable
    finally:
        os.close(descriptor)


def _same_snapshot(
    path: str, expected_content: bytes, expected_metadata: os.stat_result
) -> bool:
    try:
        current, metadata = _snapshot_target(path)
    except (OSError, ConfigWriteError):
        return False
    return (
        current == expected_content
        and (metadata.st_dev, metadata.st_ino)
        == (expected_metadata.st_dev, expected_metadata.st_ino)
        and metadata.st_uid == expected_metadata.st_uid
        and metadata.st_gid == expected_metadata.st_gid
        and stat.S_IMODE(metadata.st_mode) == stat.S_IMODE(expected_metadata.st_mode)
    )


@contextlib.contextmanager
def _configuration_lock(lock_path: str):
    lock_path = os.path.abspath(lock_path)
    try:
        before = os.lstat(lock_path)
    except OSError as exc:
        raise ConfigWriteError(
            "Shared LLDPq configuration lock is missing; repair the installation"
        ) from exc
    expected_owner = 0 if lock_path == DEFAULT_LOCK_PATH else os.geteuid()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_owner
        or before.st_mode & stat.S_IWOTH
    ):
        raise ConfigWriteError(
            "Shared LLDPq configuration lock has unsafe ownership, type, or mode"
        )
    descriptor = os.open(
        lock_path,
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ConfigWriteError("Shared LLDPq configuration lock changed while opening")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        after = os.lstat(lock_path)
        if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
            raise ConfigWriteError("Shared LLDPq configuration lock changed while waiting")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _resolve_target(logical_path: str) -> str:
    logical_path = os.path.abspath(logical_path)
    target = os.path.realpath(logical_path) if os.path.islink(logical_path) else logical_path
    if not os.path.isabs(target):
        raise ConfigWriteError("LLDPq configuration target must be absolute")
    return os.path.normpath(target)


def _render_updates(
    original: str, updates: Mapping[str, object], *, quote_values: bool
) -> str:
    normalized = {}
    for key, raw_value in updates.items():
        key = str(key)
        value = str(raw_value)
        if not _KEY_RE.fullmatch(key):
            raise ConfigWriteError(f"Invalid LLDPq configuration key: {key}")
        if any(character in value for character in ("\x00", "\r", "\n")):
            raise ConfigWriteError(f"Invalid control character in {key}")
        normalized[key] = shlex.quote(value) if quote_values else value

    output = []
    replaced = set()
    for line in original.splitlines(keepends=True):
        matched_key = None
        for key in normalized:
            if line.startswith(f"{key}="):
                matched_key = key
                break
        if matched_key is None:
            output.append(line)
        elif matched_key not in replaced:
            output.append(f"{matched_key}={normalized[matched_key]}\n")
            replaced.add(matched_key)
        # Drop later duplicates so the newly saved value cannot be shadowed.
    if output and not output[-1].endswith(("\n", "\r")):
        output[-1] += "\n"
    for key, value in normalized.items():
        if key not in replaced:
            output.append(f"{key}={value}\n")
    return "".join(output)


def _fsync_directory(path: str) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_sudo(arguments: list[str], *, timeout: int = 15) -> None:
    result = subprocess.run(
        ["sudo", "-n", *arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise ConfigWriteError(
            result.stderr.strip() or f"Privileged config operation failed: {arguments[0]}"
        )


def _verify_installed(
    target: str, expected: bytes, expected_metadata: os.stat_result
) -> None:
    content, metadata = _snapshot_target(target)
    if content != expected:
        raise ConfigWriteError("LLDPq configuration readback mismatch")
    if (
        metadata.st_uid != expected_metadata.st_uid
        or metadata.st_gid != expected_metadata.st_gid
        or stat.S_IMODE(metadata.st_mode) != stat.S_IMODE(expected_metadata.st_mode)
    ):
        raise ConfigWriteError("LLDPq configuration metadata changed during activation")


def _set_stage_owner(
    stage: str, metadata: os.stat_result, *, allow_privileged: bool
) -> None:
    current = os.lstat(stage)
    if (current.st_uid, current.st_gid) == (metadata.st_uid, metadata.st_gid):
        return
    try:
        os.chown(stage, metadata.st_uid, metadata.st_gid)
    except PermissionError:
        if not allow_privileged:
            raise ConfigWriteError("Cannot preserve LLDPq configuration ownership")
        _run_sudo(
            ["/usr/bin/chown", f"{metadata.st_uid}:{metadata.st_gid}", "--", stage],
            timeout=5,
        )


def _stage_prefix(target: str) -> str:
    return f".{os.path.basename(target)}.lldpq-"


_STAGE_SUFFIX = ".tmp"


def _sweep_orphaned_stages(
    target: str, *, grace_seconds: int = ORPHAN_STAGE_GRACE_SECONDS
) -> None:
    """Best-effort removal of stale stage files left by killed writers.

    Must only be called while holding the shared configuration lock, which
    guarantees that no live writer owns a stage older than the grace period.
    """
    directory = os.path.dirname(target) or "."
    prefix = _stage_prefix(target)
    cutoff = time.time() - grace_seconds
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for name in entries:
        if not (name.startswith(prefix) and name.endswith(_STAGE_SUFFIX)):
            continue
        stale = os.path.join(directory, name)
        try:
            info = os.lstat(stale)
            if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                os.unlink(stale)
        except OSError:
            continue


def _durable_same_directory_stage(
    logical_path: str,
    target: str,
    content: bytes,
    metadata: os.stat_result,
) -> str:
    """Stage exact bytes and metadata durably beside *target*."""
    directory = os.path.dirname(target) or "."
    descriptor = -1
    stage: Optional[str] = None
    try:
        descriptor, stage = tempfile.mkstemp(
            prefix=_stage_prefix(target), suffix=_STAGE_SUFFIX, dir=directory
        )
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _set_stage_owner(
            stage, metadata, allow_privileged=logical_path == DEFAULT_CONFIG_PATH
        )
        # chown/chmod are inode mutations too.  Flush them through the still-open
        # writable descriptor before this stage can become rollback authority.
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        staged_path = os.lstat(stage)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_nlink != 1
            or (staged.st_dev, staged.st_ino)
            != (staged_path.st_dev, staged_path.st_ino)
            or staged.st_uid != metadata.st_uid
            or staged.st_gid != metadata.st_gid
            or stat.S_IMODE(staged.st_mode) != stat.S_IMODE(metadata.st_mode)
            or _read_descriptor(descriptor) != content
        ):
            raise ConfigWriteError("LLDPq configuration stage verification failed")
        result = stage
        stage = None
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if stage is not None:
            try:
                os.unlink(stage)
            except FileNotFoundError:
                pass


def _same_directory_atomic_replace(
    logical_path: str,
    target: str,
    original: bytes,
    candidate: bytes,
    metadata: os.stat_result,
    activation_state: Optional[dict] = None,
) -> None:
    directory = os.path.dirname(target) or "."
    stage: Optional[str] = None
    try:
        stage = _durable_same_directory_stage(
            logical_path, target, candidate, metadata
        )
        if not _same_snapshot(target, original, metadata):
            raise RevisionConflict("LLDPq configuration changed while the update was staged")
        staged_metadata = os.lstat(stage)
        os.replace(stage, target)
        stage = None
        if activation_state is not None:
            activation_state.update({
                "replaced": True,
                "installed_identity": (
                    staged_metadata.st_dev,
                    staged_metadata.st_ino,
                ),
                "candidate": candidate,
            })
        _fsync_directory(directory)
    finally:
        if stage is not None:
            try:
                os.unlink(stage)
            except FileNotFoundError:
                pass


def _restore_same_directory(
    logical_path: str,
    target: str,
    original: bytes,
    metadata: os.stat_result,
) -> None:
    """Restore and durably verify the exact pre-update generation."""
    directory = os.path.dirname(target) or "."
    stage: Optional[str] = None
    try:
        stage = _durable_same_directory_stage(
            logical_path, target, original, metadata
        )
        os.replace(stage, target)
        stage = None
        _fsync_directory(directory)
        _verify_installed(target, original, metadata)
    finally:
        if stage is not None:
            try:
                os.unlink(stage)
            except FileNotFoundError:
                pass


def _require_activated_candidate(
    target: str,
    metadata: os.stat_result,
    activation_state: Mapping[str, object],
) -> None:
    """Refuse rollback after a non-cooperating writer replaced our candidate."""
    expected_identity = activation_state.get("installed_identity")
    expected_content = activation_state.get("candidate")
    if (
        not isinstance(expected_identity, tuple)
        or len(expected_identity) != 2
        or not isinstance(expected_content, bytes)
    ):
        raise RollbackSkipped("Activated LLDPq configuration identity is unavailable")
    try:
        descriptor, installed = _open_regular_no_follow(target, os.O_RDONLY)
    except (OSError, ConfigWriteError) as exc:
        raise RollbackSkipped(
            "Automatic rollback skipped because the activated configuration "
            "was externally replaced"
        ) from exc
    try:
        current = _read_descriptor(descriptor)
    finally:
        os.close(descriptor)
    if (
        (installed.st_dev, installed.st_ino) != expected_identity
        or installed.st_uid != metadata.st_uid
        or installed.st_gid != metadata.st_gid
        or stat.S_IMODE(installed.st_mode) != stat.S_IMODE(metadata.st_mode)
        or current != expected_content
    ):
        raise RollbackSkipped(
            "Automatic rollback skipped because the activated configuration "
            "was externally replaced"
        )


def _privileged_atomic_replace(
    logical_path: str,
    target: str,
    original: bytes,
    candidate: bytes,
    metadata: os.stat_result,
    activation_state: Optional[dict] = None,
) -> None:
    """Activate a native regular /etc file through the fixed sudoers stage."""
    if logical_path != DEFAULT_CONFIG_PATH or target != DEFAULT_CONFIG_PATH:
        raise ConfigWriteError(
            "Cannot atomically stage the LLDPq configuration in its parent directory"
        )
    root_stage = DEFAULT_CONFIG_PATH + ".lldpq-root-stage"
    descriptor, local_stage = tempfile.mkstemp(prefix="lldpq-config-", suffix=".tmp")
    try:
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        if not _same_snapshot(target, original, metadata):
            raise RevisionConflict("LLDPq configuration changed before privileged staging")
        _run_sudo(
            ["/usr/bin/cp", "--remove-destination", "--", local_stage, root_stage]
        )
        try:
            _run_sudo(
                [
                    "/usr/bin/chmod",
                    format(stat.S_IMODE(metadata.st_mode), "o"),
                    "--",
                    root_stage,
                ],
                timeout=5,
            )
            _run_sudo(
                [
                    "/usr/bin/chown",
                    f"{metadata.st_uid}:{metadata.st_gid}",
                    "--",
                    root_stage,
                ],
                timeout=5,
            )
            _run_sudo(["/usr/bin/sync", "-f", root_stage])
            staged_content, staged_metadata = _snapshot_target(root_stage)
            if (
                staged_content != candidate
                or staged_metadata.st_uid != metadata.st_uid
                or staged_metadata.st_gid != metadata.st_gid
                or stat.S_IMODE(staged_metadata.st_mode)
                != stat.S_IMODE(metadata.st_mode)
            ):
                raise ConfigWriteError("Privileged configuration stage verification failed")
            if not _same_snapshot(target, original, metadata):
                raise RevisionConflict(
                    "LLDPq configuration changed during privileged staging"
                )
            _run_sudo(
                [
                    "/usr/bin/mv",
                    "-fT",
                    "--",
                    root_stage,
                    DEFAULT_CONFIG_PATH,
                ]
            )
            if activation_state is not None:
                activation_state.update({
                    "replaced": True,
                    "installed_identity": (
                        staged_metadata.st_dev,
                        staged_metadata.st_ino,
                    ),
                    "candidate": candidate,
                })
            _run_sudo(["/usr/bin/sync", "-f", "/etc"])
        except Exception:
            try:
                _run_sudo(["/usr/bin/rm", "-f", "--", root_stage], timeout=5)
            except Exception:
                pass
            raise
    finally:
        try:
            os.unlink(local_stage)
        except FileNotFoundError:
            pass


def _restore_privileged(
    target: str,
    original: bytes,
    metadata: os.stat_result,
) -> None:
    """Restore native /etc configuration through the fixed root-owned stage."""
    if target != DEFAULT_CONFIG_PATH:
        raise ConfigWriteError("Cannot restore LLDPq configuration outside /etc")
    root_stage = DEFAULT_CONFIG_PATH + ".lldpq-root-stage"
    descriptor, local_stage = tempfile.mkstemp(
        prefix="lldpq-config-rollback-", suffix=".tmp"
    )
    try:
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        _run_sudo(
            ["/usr/bin/cp", "--remove-destination", "--", local_stage, root_stage]
        )
        try:
            _run_sudo(
                [
                    "/usr/bin/chmod",
                    format(stat.S_IMODE(metadata.st_mode), "o"),
                    "--",
                    root_stage,
                ],
                timeout=5,
            )
            _run_sudo(
                [
                    "/usr/bin/chown",
                    f"{metadata.st_uid}:{metadata.st_gid}",
                    "--",
                    root_stage,
                ],
                timeout=5,
            )
            _run_sudo(["/usr/bin/sync", "-f", root_stage])
            _run_sudo(
                [
                    "/usr/bin/mv",
                    "-fT",
                    "--",
                    root_stage,
                    DEFAULT_CONFIG_PATH,
                ]
            )
            _run_sudo(["/usr/bin/sync", "-f", "/etc"])
            _verify_installed(target, original, metadata)
        except Exception:
            try:
                _run_sudo(["/usr/bin/rm", "-f", "--", root_stage], timeout=5)
            except Exception:
                pass
            raise
    finally:
        try:
            os.unlink(local_stage)
        except FileNotFoundError:
            pass


def read_lldpq_config(
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    lock_path: str = DEFAULT_LOCK_PATH,
) -> dict:
    """Read one stable config generation under the shared lock."""
    logical_path = os.path.abspath(config_path)
    with _configuration_lock(lock_path):
        target = _resolve_target(logical_path)
        content, metadata = _snapshot_target(target)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigWriteError("LLDPq configuration is not valid UTF-8") from exc
        return {
            "content": text,
            "revision": _revision(content),
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }


def update_lldpq_config(
    updates: Mapping[str, object],
    *,
    config_path: str = DEFAULT_CONFIG_PATH,
    lock_path: str = DEFAULT_LOCK_PATH,
    quote_values: bool = True,
    expected_revision: Optional[str] = None,
) -> dict:
    """Merge KEY=value updates into the latest locked config generation."""
    if not isinstance(updates, Mapping) or not updates:
        raise ConfigWriteError("At least one LLDPq configuration update is required")
    logical_path = os.path.abspath(config_path)
    with _configuration_lock(lock_path):
        target = _resolve_target(logical_path)
        _sweep_orphaned_stages(target)
        original, metadata = _snapshot_target(target)
        old_revision = _revision(original)
        if expected_revision is not None and expected_revision != old_revision:
            raise RevisionConflict("LLDPq configuration changed; reload and retry")
        try:
            original_text = original.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigWriteError("LLDPq configuration is not valid UTF-8") from exc
        candidate = _render_updates(
            original_text, updates, quote_values=quote_values
        ).encode("utf-8")
        if len(candidate) > MAX_CONFIG_BYTES:
            raise ConfigWriteError("Updated LLDPq configuration exceeds the safe size limit")
        new_revision = _revision(candidate)
        if candidate == original:
            return {
                "changed": False,
                "old_revision": old_revision,
                "new_revision": new_revision,
            }

        if is_direct_file_mount(target):
            raise ConfigWriteError(
                "Cannot safely update the legacy direct-file mount at /etc/lldpq.conf. "
                "The current file was not changed. Remove that individual bind mount "
                "and use the documented lldpq-system-config directory/named volume at "
                "/home/lldpq/lldpq/system-config."
            )

        activation = {"mode": "same-directory", "replaced": False}
        try:
            try:
                _same_directory_atomic_replace(
                    logical_path,
                    target,
                    original,
                    candidate,
                    metadata,
                    activation,
                )
            except PermissionError:
                if activation["replaced"]:
                    raise
                # Native installs cannot create a stage in root-owned /etc.  The
                # fixed root stage is allowlisted in sudoers.  Never take this path
                # for Docker's symlink-backed persistent target.
                activation = {"mode": "privileged", "replaced": False}
                _privileged_atomic_replace(
                    logical_path,
                    target,
                    original,
                    candidate,
                    metadata,
                    activation,
                )
            _verify_installed(target, candidate, metadata)
        except Exception as commit_error:
            if not activation["replaced"]:
                raise
            try:
                _require_activated_candidate(target, metadata, activation)
                if activation["mode"] == "same-directory":
                    _restore_same_directory(
                        logical_path, target, original, metadata
                    )
                else:
                    _restore_privileged(target, original, metadata)
            except RollbackSkipped as rollback_error:
                raise ConfigWriteError(str(rollback_error)) from commit_error
            except Exception as rollback_error:
                raise ConfigWriteError(
                    "LLDPq configuration update failed after activation and "
                    "automatic rollback also failed: " + str(rollback_error)
                ) from commit_error
            raise ConfigWriteError(
                "LLDPq configuration update failed after activation; the exact "
                "previous generation was restored: " + str(commit_error)
            ) from commit_error
        return {
            "changed": True,
            "old_revision": old_revision,
            "new_revision": new_revision,
        }
