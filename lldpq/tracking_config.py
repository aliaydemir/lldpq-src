#!/usr/bin/env python3
"""Read and update switch lifecycle tracking without changing devices.yaml.

``devices.yaml`` remains the managed-device inventory.  ``tracking.yaml`` only
stores lifecycle overrides and transition metadata.  A device that has no
tracking entry is therefore always considered to be in ``commissioning``.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import yaml


SCHEMA_VERSION = 1
DEFAULT_STATE = "commissioning"
VALID_STATES = frozenset((DEFAULT_STATE, "handed_over"))
MAX_SWITCHES = 10000
MAX_NOTE_LENGTH = 1000
MAX_IDENTITY_LENGTH = 253


class TrackingConfigError(Exception):
    """Base class for errors safe to show to an authenticated user."""


class TrackingValidationError(TrackingConfigError):
    """The inventory, tracking file, or requested update is invalid."""


class TrackingConflictError(TrackingConfigError):
    """The caller attempted to save a stale tracking generation."""

    def __init__(self, revision: str):
        super().__init__(
            "Handover assignments changed on the server. Reload and review "
            "before saving."
        )
        self.revision = revision


def _read_bytes(path: Path, *, missing_ok: bool = False) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        if missing_ok:
            return b""
        raise TrackingValidationError(f"{path.name} was not found") from None
    except OSError as exc:
        raise TrackingConfigError(f"Could not read {path.name}: {exc}") from exc


def _load_yaml_mapping(raw: bytes, filename: str) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        value = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TrackingValidationError(f"{filename} is not valid YAML: {exc}") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TrackingValidationError(f"{filename} must contain a YAML mapping")
    return value


def _parse_inline_device(value: str) -> Tuple[str, Optional[str]]:
    match = re.fullmatch(r"(.+?)\s+@([A-Za-z0-9_.-]+)", value.strip())
    if match:
        return match.group(1).strip(), match.group(2).lower()
    return value.strip(), None


def _validate_hostname(hostname: Any, address: str) -> str:
    hostname = str(hostname or "").strip()
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}", hostname)
        or ".." in hostname
    ):
        raise TrackingValidationError(
            f"devices.yaml has an invalid hostname for {address!r}"
        )
    return hostname


def _parse_devices(raw: bytes) -> List[Dict[str, Any]]:
    config = _load_yaml_mapping(raw, "devices.yaml")
    defaults = config.get("defaults", {})
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        raise TrackingValidationError("devices.yaml 'defaults' must be a mapping")
    default_username = str(defaults.get("username", "cumulus")).strip()

    if "devices" in config:
        devices = config.get("devices")
    else:
        # Accept the old flat mapping for compatibility with older installs.
        devices = {
            key: value
            for key, value in config.items()
            if key not in ("defaults", "endpoint_hosts")
        }
    if devices is None:
        devices = {}
    if not isinstance(devices, dict):
        raise TrackingValidationError("devices.yaml 'devices' must be a mapping")
    if len(devices) > MAX_SWITCHES:
        raise TrackingValidationError(
            f"devices.yaml contains too many switches (max {MAX_SWITCHES})"
        )

    result: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    for raw_address, value in devices.items():
        address = str(raw_address).strip()
        if isinstance(value, str):
            hostname, role = _parse_inline_device(value)
            username = default_username
        elif isinstance(value, dict):
            hostname = value.get("hostname", "")
            username = str(value.get("username", default_username)).strip()
            role_value = value.get("role")
            role = str(role_value).strip().lower() if role_value else None
        else:
            raise TrackingValidationError(
                f"devices.yaml has an invalid entry for {address!r}"
            )

        hostname = _validate_hostname(hostname, address)
        identity = hostname.casefold()
        if identity in seen:
            raise TrackingValidationError(
                f"devices.yaml contains duplicate hostname {hostname!r}"
            )
        seen[identity] = hostname
        result.append(
            {
                "hostname": hostname,
                "ip": address,
                "address": address,
                "username": username,
                "role": role,
            }
        )
    return result


def _optional_metadata_text(
    value: Any, field: str, *, maximum: int
) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TrackingValidationError(f"tracking.yaml {field} must be a string")
    value = value.strip()
    if not value:
        raise TrackingValidationError(f"tracking.yaml {field} is invalid")
    if len(value) > maximum or any(char in value for char in ("\x00", "\r", "\n")):
        raise TrackingValidationError(f"tracking.yaml {field} is invalid")
    return value


def _parse_tracking(raw: bytes) -> Dict[str, Any]:
    config = _load_yaml_mapping(raw, "tracking.yaml")
    supported_root_fields = {"version", "default_state", "switches"}
    unexpected_root_fields = [
        key for key in config if key not in supported_root_fields
    ]
    if unexpected_root_fields:
        display = ", ".join(
            sorted(repr(key) for key in unexpected_root_fields)
        )
        raise TrackingValidationError(
            f"tracking.yaml contains unsupported keys: {display}"
        )
    version = config.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise TrackingValidationError(
            f"tracking.yaml version must be {SCHEMA_VERSION}"
        )
    default_state = config.get("default_state", DEFAULT_STATE)
    if default_state != DEFAULT_STATE:
        raise TrackingValidationError(
            f"tracking.yaml default_state must be {DEFAULT_STATE!r}"
        )
    switches = config.get("switches", {})
    if switches is None:
        switches = {}
    if not isinstance(switches, dict):
        raise TrackingValidationError("tracking.yaml 'switches' must be a mapping")
    if len(switches) > MAX_SWITCHES:
        raise TrackingValidationError(
            f"tracking.yaml contains too many switches (max {MAX_SWITCHES})"
        )

    normalized: Dict[str, Dict[str, str]] = {}
    casefold_names: Dict[str, str] = {}
    for raw_hostname, raw_entry in switches.items():
        if not isinstance(raw_hostname, str) or not raw_hostname.strip():
            raise TrackingValidationError(
                "tracking.yaml switch names must be non-empty strings"
            )
        hostname = raw_hostname.strip()
        if (
            hostname != raw_hostname
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}", hostname
            )
            or ".." in hostname
        ):
            raise TrackingValidationError(
                f"tracking.yaml contains invalid hostname {raw_hostname!r}"
            )
        identity = hostname.casefold()
        if identity in casefold_names:
            raise TrackingValidationError(
                f"tracking.yaml contains duplicate hostname {hostname!r}"
            )
        casefold_names[identity] = hostname
        if not isinstance(raw_entry, dict):
            raise TrackingValidationError(
                f"tracking.yaml entry for {hostname!r} must be a mapping"
            )
        supported_entry_fields = {"state", "changed_at", "changed_by", "note"}
        unexpected_entry_fields = [
            key for key in raw_entry if key not in supported_entry_fields
        ]
        if unexpected_entry_fields:
            raise TrackingValidationError(
                f"tracking.yaml entry for {hostname!r} contains unsupported fields"
            )
        state = raw_entry.get("state")
        if state not in VALID_STATES:
            raise TrackingValidationError(
                f"tracking.yaml state for {hostname!r} must be commissioning "
                "or handed_over"
            )
        entry: Dict[str, str] = {"state": state}
        for field, maximum in (
            ("changed_at", MAX_IDENTITY_LENGTH),
            ("changed_by", MAX_IDENTITY_LENGTH),
            ("note", MAX_NOTE_LENGTH),
        ):
            value = _optional_metadata_text(
                raw_entry.get(field), f"{field} for {hostname!r}", maximum=maximum
            )
            if value is not None:
                entry[field] = value
        normalized[hostname] = entry
    return {
        "version": SCHEMA_VERSION,
        "default_state": DEFAULT_STATE,
        "switches": normalized,
    }


def _revision(devices_raw: bytes, tracking_raw: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(b"devices.yaml\0")
    digest.update(devices_raw)
    digest.update(b"\0tracking.yaml\0")
    digest.update(tracking_raw if tracking_raw else b"<missing-or-empty>")
    return "sha256:" + digest.hexdigest()


def _build_payload(
    devices_raw: bytes, tracking_raw: bytes, *, success: bool = True
) -> Dict[str, Any]:
    devices = _parse_devices(devices_raw)
    tracking = _parse_tracking(tracking_raw)
    entries: Mapping[str, Mapping[str, str]] = tracking["switches"]
    inventory_names = {device["hostname"] for device in devices}

    counts = {"total": len(devices), DEFAULT_STATE: 0, "handed_over": 0}
    handed_over: List[str] = []
    rendered_devices: List[Dict[str, Any]] = []
    for device in devices:
        hostname = device["hostname"]
        metadata = entries.get(hostname, {})
        state = metadata.get("state", DEFAULT_STATE)
        counts[state] += 1
        if state == "handed_over":
            handed_over.append(hostname)
        rendered = dict(device)
        rendered.update(
            {
                "state": state,
                "changed_at": metadata.get("changed_at"),
                "changed_by": metadata.get("changed_by"),
                "note": metadata.get("note"),
            }
        )
        rendered_devices.append(rendered)

    return {
        "success": success,
        "revision": _revision(devices_raw, tracking_raw),
        "default_state": DEFAULT_STATE,
        "counts": counts,
        "handed_over_switches": handed_over,
        "devices": rendered_devices,
        "orphaned_switches": sorted(
            hostname for hostname in entries if hostname not in inventory_names
        ),
    }


def get_tracking_payload(devices_path: str, tracking_path: str) -> Dict[str, Any]:
    """Return an API-ready effective tracking view for every managed switch."""
    devices_raw = _read_bytes(Path(devices_path))
    tracking_raw = _read_bytes(Path(tracking_path), missing_ok=True)
    return _build_payload(devices_raw, tracking_raw)


def _normalize_requested_switches(
    requested: Any, inventory_names: Iterable[str]
) -> List[str]:
    if not isinstance(requested, list):
        raise TrackingValidationError("handed_over_switches must be a list")
    if len(requested) > MAX_SWITCHES:
        raise TrackingValidationError(
            f"handed_over_switches is too large (max {MAX_SWITCHES})"
        )

    known = set(inventory_names)
    normalized: List[str] = []
    seen = set()
    for value in requested:
        if not isinstance(value, str) or not value:
            raise TrackingValidationError(
                "handed_over_switches must contain non-empty hostname strings"
            )
        if value in seen:
            raise TrackingValidationError(
                f"handed_over_switches contains duplicate hostname {value!r}"
            )
        seen.add(value)
        normalized.append(value)
    unknown = sorted(set(normalized) - known)
    if unknown:
        display = ", ".join(repr(value) for value in unknown[:10])
        if len(unknown) > 10:
            display += f", and {len(unknown) - 10} more"
        raise TrackingValidationError(f"Unknown switch hostname(s): {display}")
    return normalized


def _transition_identity(value: Any) -> str:
    if not isinstance(value, str):
        raise TrackingValidationError("changed_by must be a string")
    value = value.strip()
    if (
        not value
        or len(value) > MAX_IDENTITY_LENGTH
        or any(char in value for char in ("\x00", "\r", "\n"))
    ):
        raise TrackingValidationError("changed_by is invalid")
    return value


def _request_note(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TrackingValidationError("note must be a string")
    value = value.strip()
    if len(value) > MAX_NOTE_LENGTH:
        raise TrackingValidationError(
            f"note is too long (max {MAX_NOTE_LENGTH} characters)"
        )
    if any(char in value for char in ("\x00", "\r", "\n")):
        raise TrackingValidationError("note contains unsupported control characters")
    return value or None


@contextmanager
def _exclusive_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(lock_path), flags, 0o660)
    except OSError as exc:
        raise TrackingConfigError(f"Could not open tracking lock: {exc}") from exc
    handle = os.fdopen(descriptor, "r+")
    try:
        os.fchmod(handle.fileno(), 0o660)
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IWOTH:
            raise TrackingConfigError("Tracking lock has unsafe permissions")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _serialize_tracking(switches: Mapping[str, Mapping[str, str]]) -> str:
    document = {
        "version": SCHEMA_VERSION,
        "default_state": DEFAULT_STATE,
        "switches": dict(switches),
    }
    content = yaml.safe_dump(
        document,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )
    # Verify the exact bytes before they can replace the live configuration.
    _parse_tracking(content.encode("utf-8"))
    return content


def _resolve_tracking_write_target(path: Path) -> Path:
    """Resolve Docker's managed config symlink without leaving LLDPQ_DIR."""
    logical = Path(os.path.abspath(path))
    managed_root = os.path.realpath(str(logical.parent))
    resolved = Path(os.path.realpath(str(logical)))
    try:
        confined = os.path.commonpath((str(resolved), managed_root)) == managed_root
    except ValueError:
        confined = False
    if not confined:
        raise TrackingConfigError(
            "tracking.yaml link points outside the managed LLDPq directory"
        )
    if logical.is_symlink():
        docker_target = Path(os.path.realpath(
            str(logical.parent / "config" / logical.name)
        ))
        if resolved != docker_target:
            raise TrackingConfigError(
                "tracking.yaml link is not the managed Docker config target"
            )
        if not resolved.is_file():
            raise TrackingConfigError(
                "tracking.yaml link target must be an existing regular file"
            )
    if resolved.exists() and not resolved.is_file():
        raise TrackingConfigError("tracking.yaml must be a regular file")
    return resolved


def _atomic_write(
    path: Path, content: str, *, file_group: Optional[str] = None
) -> None:
    if path.is_symlink():
        raise TrackingConfigError("tracking.yaml must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = content.encode("utf-8")
    temporary: Optional[str] = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o664)
        expected_gid = None
        if file_group:
            try:
                expected_gid = grp.getgrnam(file_group).gr_gid
            except KeyError as exc:
                raise TrackingConfigError(
                    f"Required tracking file group is unavailable: {file_group}"
                ) from exc
            try:
                os.chown(temporary, -1, expected_gid)
            except OSError as exc:
                raise TrackingConfigError(
                    f"Could not set tracking.yaml group to {file_group}: {exc}"
                ) from exc
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(
            str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if path.read_bytes() != encoded:
            raise TrackingConfigError("tracking.yaml readback verification failed")
        installed = os.stat(path, follow_symlinks=False)
        if installed.st_uid != os.geteuid():
            raise TrackingConfigError("tracking.yaml owner verification failed")
        if stat.S_IMODE(installed.st_mode) != 0o664:
            raise TrackingConfigError("tracking.yaml permissions verification failed")
        if expected_gid is not None and installed.st_gid != expected_gid:
            raise TrackingConfigError("tracking.yaml group verification failed")
    except TrackingConfigError:
        raise
    except OSError as exc:
        raise TrackingConfigError(f"Could not write tracking.yaml: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def save_tracking(
    devices_path: str,
    tracking_path: str,
    *,
    expected_revision: Any,
    handed_over_switches: Any,
    changed_by: Any,
    note: Any = None,
    changed_at: Optional[str] = None,
    file_group: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply one complete handed-over set with optimistic concurrency.

    Explicit ``commissioning`` entries are retained for switches that move
    back from handed-over so both transition directions have audit metadata.
    Switches that never changed remain implicit and do not bloat the file.
    """
    if not isinstance(expected_revision, str) or not expected_revision:
        raise TrackingValidationError("revision is required")
    actor = _transition_identity(changed_by)
    transition_note = _request_note(note)
    if changed_at is None:
        changed_at = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    else:
        changed_at = _optional_metadata_text(
            changed_at, "changed_at", maximum=MAX_IDENTITY_LENGTH
        )
        if changed_at is None:
            raise TrackingValidationError("changed_at is invalid")

    devices = Path(devices_path)
    tracking_logical = Path(tracking_path)
    tracking = _resolve_tracking_write_target(tracking_logical)
    with _exclusive_lock(Path(str(tracking) + ".lock")):
        devices_raw = _read_bytes(devices)
        tracking_raw = _read_bytes(tracking, missing_ok=True)
        current_revision = _revision(devices_raw, tracking_raw)
        if expected_revision != current_revision:
            raise TrackingConflictError(current_revision)

        inventory = _parse_devices(devices_raw)
        existing = _parse_tracking(tracking_raw)["switches"]
        requested = _normalize_requested_switches(
            handed_over_switches,
            (device["hostname"] for device in inventory),
        )
        desired_handed_over = set(requested)

        updated: Dict[str, Dict[str, str]] = {}
        inventory_names = {device["hostname"] for device in inventory}
        # Keep orphaned metadata until an inventory/restore workflow explicitly
        # resolves it; a normal handover edit must not silently destroy history.
        for hostname, entry in existing.items():
            if hostname not in inventory_names:
                updated[hostname] = dict(entry)

        for device in inventory:
            hostname = device["hostname"]
            previous = existing.get(hostname)
            previous_state = (
                previous.get("state", DEFAULT_STATE) if previous else DEFAULT_STATE
            )
            desired_state = (
                "handed_over" if hostname in desired_handed_over else DEFAULT_STATE
            )
            if previous_state == desired_state:
                if previous is not None:
                    updated[hostname] = dict(previous)
                continue

            transition = {
                "state": desired_state,
                "changed_at": changed_at,
                "changed_by": actor,
            }
            if transition_note is not None:
                transition["note"] = transition_note
            updated[hostname] = transition

        content = _serialize_tracking(updated)
        # Detect an inventory replacement that raced validation/rendering.  The
        # tracking lock serializes handover writers; inventory writers use their
        # own transaction and publish devices.yaml atomically.
        if _read_bytes(devices) != devices_raw:
            latest_revision = _revision(
                _read_bytes(devices), _read_bytes(tracking, missing_ok=True)
            )
            raise TrackingConflictError(latest_revision)
        if _resolve_tracking_write_target(tracking_logical) != tracking:
            raise TrackingConfigError(
                "tracking.yaml link changed while the update was prepared"
            )
        _atomic_write(tracking, content, file_group=file_group)
        return _build_payload(devices_raw, content.encode("utf-8"))


def _save_cli_payload(args: argparse.Namespace) -> Dict[str, Any]:
    try:
        request = json.load(sys.stdin)
    except (UnicodeError, json.JSONDecodeError):
        return {
            "success": False,
            "error_code": "tracking_validation",
            "error": "Invalid JSON",
        }
    if not isinstance(request, dict):
        return {
            "success": False,
            "error_code": "tracking_validation",
            "error": "JSON body must be an object",
        }
    try:
        payload = save_tracking(
            args.devices,
            args.tracking,
            expected_revision=request.get("revision"),
            handed_over_switches=request.get("handed_over_switches"),
            changed_by=args.changed_by,
            note=request.get("note"),
            file_group=args.file_group,
        )
        payload["message"] = "Handover assignments saved"
        return payload
    except TrackingConflictError as exc:
        return {
            "success": False,
            "error_code": "tracking_conflict",
            "error": str(exc),
            "revision": exc.revision,
        }
    except TrackingValidationError as exc:
        return {
            "success": False,
            "error_code": "tracking_validation",
            "error": str(exc),
        }
    except TrackingConfigError as exc:
        return {
            "success": False,
            "error_code": "tracking_write_failed",
            "error": str(exc),
        }
    except Exception:
        return {
            "success": False,
            "error_code": "tracking_write_failed",
            "error": "Handover assignments could not be saved",
        }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read or atomically update LLDPq switch lifecycle tracking"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    save_parser = subparsers.add_parser(
        "save-json", help="read a complete save request as JSON from stdin"
    )
    save_parser.add_argument("--devices", required=True)
    save_parser.add_argument("--tracking", required=True)
    save_parser.add_argument("--changed-by", required=True)
    save_parser.add_argument("--file-group")
    args = parser.parse_args(argv)

    if args.command == "save-json":
        print(json.dumps(_save_cli_payload(args), separators=(",", ":")))
        return 0
    parser.error("unknown command")
    return 2


__all__ = [
    "DEFAULT_STATE",
    "TrackingConfigError",
    "TrackingConflictError",
    "TrackingValidationError",
    "get_tracking_payload",
    "save_tracking",
]


if __name__ == "__main__":
    raise SystemExit(main())
