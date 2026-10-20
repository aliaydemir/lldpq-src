#!/usr/bin/env python3
"""BMC cabling expectations, independent of collected switch observations."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import grp
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile

import yaml

try:
    from .parse_devices import UniqueKeyLoader, get_all_devices
except ImportError:
    from parse_devices import UniqueKeyLoader, get_all_devices


MAX_MAPPINGS = 20000
PORT_PATTERN = re.compile(r"swp[1-9][0-9]*(?:s[0-9]+)?")
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}")
MAPPING_FIELDS = {"switch", "port", "expected_mac", "hostname", "vlan", "bmc_ip", "enabled"}


class BMCConfigError(Exception):
    """A configuration error safe to display in the BMC editor."""


class BMCValidationError(BMCConfigError):
    """Invalid configuration or submitted mappings."""


class BMCConflictError(BMCConfigError):
    def __init__(self, revision):
        super().__init__("BMC mappings or device inventory changed. Reload before saving.")
        self.revision = revision


def normalize_mac(value):
    """Accept common Ethernet address notations; reject non-unicast addresses."""
    if not isinstance(value, str):
        raise BMCValidationError("MAC address must be a string")
    value = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{12}", value):
        compact = value
    elif re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        compact = value.replace(":", "")
    elif re.fullmatch(r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}", value):
        compact = value.replace("-", "")
    elif re.fullmatch(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", value):
        compact = value.replace(".", "")
    else:
        raise BMCValidationError(f"Invalid MAC address: {value!r}")
    if compact == "0" * 12 or int(compact[:2], 16) & 1:
        raise BMCValidationError("Expected MAC must be a nonzero unicast Ethernet address")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def _name(value, field):
    if not isinstance(value, str):
        raise BMCValidationError(f"{field} must be a name")
    value = value.strip()
    if not NAME_PATTERN.fullmatch(value) or ".." in value:
        raise BMCValidationError(f"Invalid {field}: {value!r}")
    return value


def validate_document(value):
    """Validate a document without requiring its switches in the live inventory.

    Backup restore can validate this before replacing devices.yaml. Unknown
    metadata is retained so ordinary edits do not discard operator annotations.
    """
    if not isinstance(value, dict):
        raise BMCValidationError("bmc.yaml must contain a YAML mapping")
    if type(value.get("version", 1)) is not int or value.get("version", 1) != 1:
        raise BMCValidationError("bmc.yaml version must be 1")
    mappings = value.get("mappings", [])
    if not isinstance(mappings, list) or len(mappings) > MAX_MAPPINGS:
        raise BMCValidationError(f"mappings must be a list with at most {MAX_MAPPINGS} rows")
    result = []
    ports = set()
    mac_bindings = {}
    for index, raw in enumerate(mappings, 1):
        if not isinstance(raw, dict):
            raise BMCValidationError(f"Mapping {index} must be an object")
        row = dict(raw)
        row["switch"] = _name(raw.get("switch"), "switch")
        row["hostname"] = _name(raw.get("hostname"), "BMC hostname")
        port = raw.get("port")
        if not isinstance(port, str) or not PORT_PATTERN.fullmatch(port.strip()):
            raise BMCValidationError(f"Mapping {index}: port must be a physical switch port (for example swp1 or swp1s0)")
        row["port"] = port.strip()
        row["expected_mac"] = normalize_mac(raw.get("expected_mac"))
        vlan = raw.get("vlan")
        if vlan == "":
            vlan = None
        if isinstance(vlan, str) and re.fullmatch(r"[0-9]{1,4}", vlan):
            vlan = int(vlan)
        if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094):
            raise BMCValidationError(f"Mapping {index}: VLAN must be 1 through 4094 or empty")
        row["vlan"] = vlan
        bmc_ip = raw.get("bmc_ip", "")
        if bmc_ip is None:
            bmc_ip = ""
        if not isinstance(bmc_ip, str):
            raise BMCValidationError(f"Mapping {index}: BMC IP must be a string")
        bmc_ip = bmc_ip.strip()
        if bmc_ip:
            try:
                bmc_ip = str(ipaddress.ip_address(bmc_ip))
            except ValueError as exc:
                raise BMCValidationError(f"Mapping {index}: invalid BMC IP") from exc
        row["bmc_ip"] = bmc_ip
        row["enabled"] = raw.get("enabled", True)
        if type(row["enabled"]) is not bool:
            raise BMCValidationError(f"Mapping {index}: enabled must be true or false")
        key = (row["switch"].casefold(), row["port"])
        if key in ports:
            raise BMCValidationError(f"Duplicate switch/port mapping: {row['switch']} {row['port']}")
        ports.add(key)
        if row["enabled"]:
            bindings = mac_bindings.setdefault(row["expected_mac"], [])
            if any(vlan is None or other_vlan is None or vlan == other_vlan for other_vlan in bindings):
                raise BMCValidationError(f"Conflicting bindings for MAC {row['expected_mac']}")
            bindings.append(vlan)
        result.append(row)
    return {**value, "version": 1, "mappings": result}


def _read(path, *, missing_ok=False):
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        if missing_ok:
            return b""
        raise BMCConfigError(f"{Path(path).name} was not found") from None
    except OSError as exc:
        raise BMCConfigError(f"Could not read {Path(path).name}: {exc}") from exc


def _load(raw, filename):
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=UniqueKeyLoader) if raw else {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise BMCValidationError(f"Invalid {filename}: {exc}") from exc
    if not isinstance(value, dict):
        raise BMCValidationError(f"{filename} must contain a YAML mapping")
    return value


def _switches(raw):
    config = _load(raw, "devices.yaml")
    try:
        devices = get_all_devices(config)
    except SystemExit as exc:
        raise BMCValidationError("devices.yaml contains invalid device entries") from exc
    return [{"hostname": hostname, "ip": address, "address": address, "role": role}
            for address, _username, hostname, role in devices]


def _revision(devices_raw, bmc_raw):
    return "sha256:" + hashlib.sha256(b"devices\0" + devices_raw + b"\0bmc\0" + bmc_raw).hexdigest()


def _payload(devices_raw, bmc_raw):
    switches = _switches(devices_raw)
    document = validate_document(_load(bmc_raw, "bmc.yaml"))
    known = {switch["hostname"].casefold() for switch in switches}
    return {"success": True, "revision": _revision(devices_raw, bmc_raw),
            "switches": switches, "mappings": [{key: row[key] for key in MAPPING_FIELDS}
                                                for row in document["mappings"]],
            "orphaned_switches": sorted({row["switch"] for row in document["mappings"]
                                         if row["switch"].casefold() not in known})}


def get_config(devices_path, bmc_path):
    return _payload(_read(devices_path), _read(bmc_path, missing_ok=True))


def _write_target(path):
    logical = Path(os.path.abspath(path))
    resolved = logical.resolve()
    if logical.is_symlink():
        expected = logical.parent / "config" / logical.name
        if resolved != expected.resolve() or not resolved.is_file():
            raise BMCConfigError("bmc.yaml link must point to the managed Docker config file")
        if not resolved.is_relative_to(logical.parent.resolve()):
            raise BMCConfigError("bmc.yaml link points outside the managed LLDPq directory")
    if resolved.exists() and not resolved.is_file():
        raise BMCConfigError("bmc.yaml must be a regular file")
    return resolved


@contextmanager
def config_lock(bmc_path):
    target = _write_target(bmc_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(str(target) + ".lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o660)
        with os.fdopen(descriptor, "r+") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise BMCConfigError("BMC configuration lock must be a regular file")
            if metadata.st_uid == os.geteuid() or os.geteuid() == 0:
                # Setup runs with a restrictive umask; the web editor must
                # still share the same lock after a backup restore.
                os.fchmod(handle.fileno(), 0o660)
                group_source = target if target.exists() else target.parent
                os.fchown(handle.fileno(), -1, group_source.stat().st_gid)
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield target
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError as exc:
        raise BMCConfigError(f"Could not lock BMC configuration: {exc}") from exc


def _atomic_write(path, content, file_group):
    temporary = None
    try:
        existing = path.stat() if path.exists() else None
        descriptor, temporary = tempfile.mkstemp(prefix=".bmc-", suffix=".tmp", dir=path.parent)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(existing.st_mode) if existing else 0o664)
        gid = grp.getgrnam(file_group).gr_gid if file_group else (existing.st_gid if existing else None)
        if gid is not None:
            os.chown(temporary, existing.st_uid if existing and os.geteuid() == 0 else -1, gid)
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, KeyError) as exc:
        raise BMCConfigError(f"Could not save bmc.yaml: {exc}") from exc
    finally:
        if temporary is not None:
            os.unlink(temporary)


def save_config(devices_path, bmc_path, mappings, expected_revision, *, file_group=None):
    if not isinstance(expected_revision, str) or not expected_revision:
        raise BMCValidationError("revision is required")
    with config_lock(bmc_path) as target:
        devices_raw = _read(devices_path)
        bmc_raw = _read(target, missing_ok=True)
        revision = _revision(devices_raw, bmc_raw)
        if revision != expected_revision:
            raise BMCConflictError(revision)
        existing = validate_document(_load(bmc_raw, "bmc.yaml"))
        document = validate_document({**existing, "mappings": mappings})
        known = {switch["hostname"].casefold(): switch["hostname"] for switch in _switches(devices_raw)}
        previous = {(row["switch"].casefold(), row["port"]): row for row in existing["mappings"]}
        for index, row in enumerate(document["mappings"]):
            canonical = known.get(row["switch"].casefold())
            if canonical is None:
                raise BMCValidationError(f"Unknown switch hostname: {row['switch']}")
            old = previous.get((row["switch"].casefold(), row["port"]), {})
            document["mappings"][index] = {**old, **row, "switch": canonical}
        content = yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode("utf-8")
        validate_document(_load(content, "bmc.yaml"))
        latest_devices = _read(devices_path)
        if latest_devices != devices_raw:
            raise BMCConflictError(_revision(latest_devices, bmc_raw))
        if _write_target(bmc_path) != target:
            raise BMCConfigError("BMC configuration link changed during save")
        _atomic_write(target, content, file_group)
        return _payload(devices_raw, content)
