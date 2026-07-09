#!/usr/bin/env python3
"""Validation and durable-write helpers for the Setup CGI endpoints.

The CGI scripts deliberately invoke the write commands as ``LLDPQ_USER``.  That
user owns the managed configuration directories, which lets us stage and rename
in the destination directory instead of truncating a live file through ``tee``.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import math
import io
from pathlib import Path
from typing import Optional


MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_DIRECT_MOUNT_JOURNAL_BYTES = 4 * 1024 * 1024
DIRECT_MOUNT_JOURNAL_VERSION = 1
DIRECT_MOUNT_JOURNAL_ROOT = os.environ.get(
    "LLDPQ_DIRECT_WRITE_STATE_DIR",
    "/var/lib/lldpq/provision-state/config-write-journals",
)
DIRECT_MOUNT_JOURNAL_STAGE_RE = re.compile(
    r"^\.(?P<journal>[0-9a-f]{64}\.json)\.tmp\.[0-9a-f]{24}$"
)
ALIAS_LIMITS = {
    "interfaces": (2000, 64, 32),
    "devices": (2000, 128, 64),
}


class SetupSafetyError(ValueError):
    """A validation or durable-write failure suitable for an API response."""


class RevisionConflict(SetupSafetyError):
    def __init__(self, current_revision: str):
        super().__init__("Configuration changed since it was loaded. Reload and try again.")
        self.current_revision = current_revision


def classify_background_job(*, done, process_alive, active_exists, age_seconds):
    """Pure status decision used by run/update log polling."""
    if done or process_alive:
        return {"running": bool(process_alive and not done), "stale_reservation": False}
    if active_exists and age_seconds <= 120:
        return {"running": True, "stale_reservation": False}
    if active_exists:
        return {"running": False, "stale_reservation": True}
    return {"running": False, "stale_reservation": False}


def completion_belongs_to_job(*, raw_done, log_job_id, known_job_id, active_exists):
    """Prevent an old DONE marker from completing a newly reserved job."""
    if not raw_done:
        return False
    if log_job_id:
        if active_exists:
            return bool(known_job_id and log_job_id == known_job_id)
        return not known_job_id or log_job_id == known_job_id
    # Marker-less logs are legacy. Accept them only when no new reservation can
    # be mistaken for the old completed run.
    return not active_exists


def revision_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def revision_text(content: str) -> str:
    return revision_bytes(content.encode("utf-8"))


def parse_json_no_duplicate_keys(content: str, label="JSON"):
    def object_hook(pairs):
        output = {}
        seen = {}
        for key, value in pairs:
            folded = key.casefold()
            if folded in seen:
                raise SetupSafetyError(
                    f"{label} contains a duplicate key: {seen[folded]!r} and {key!r}"
                )
            seen[folded] = key
            output[key] = value
        return output

    try:
        return json.loads(content, object_pairs_hook=object_hook)
    except json.JSONDecodeError as exc:
        raise SetupSafetyError(f"Invalid {label}: {exc}") from exc


def parse_editor_request(content: str):
    request = parse_json_no_duplicate_keys(content, "editor request JSON")
    if not isinstance(request, dict) or not isinstance(request.get("content"), str):
        raise SetupSafetyError("Editor request must contain a string 'content' field")
    expected_revision = request.get("expected_revision", request.get("revision"))
    if expected_revision is not None and not isinstance(expected_revision, str):
        raise SetupSafetyError("Editor request revision must be a string")
    return request["content"], expected_revision


def acquire_global_configuration_lock(path="/etc/lldpq.conf.lock") -> int:
    """Serialize Setup saves with backup restore's global transaction lock."""
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SetupSafetyError(
            "Global configuration lock is missing; repair the LLDPq installation"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & stat.S_IWOTH
    ):
        raise SetupSafetyError(
            "Global configuration lock has unsafe ownership, type, or permissions"
        )
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(descriptor)
        raise SetupSafetyError("Global configuration lock changed while opening")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def acquire_inventory_lock(path: str) -> int:
    """Join Provision/backup inventory transactions after the global lock."""
    if not os.path.isabs(path):
        raise SetupSafetyError("Inventory lock path must be absolute")
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o660)
    except OSError as exc:
        raise SetupSafetyError("Cannot open the shared inventory lock") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_mode & stat.S_IWOTH
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise SetupSafetyError(
                "Inventory lock has unsafe type, permissions, or identity"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (locked.st_dev, locked.st_ino):
            raise SetupSafetyError("Inventory lock changed while waiting to acquire it")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _yaml_load_mapping(content: str, label: str):
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - installation dependency
        raise SetupSafetyError("PyYAML is required to validate configuration") from exc
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
                raise SetupSafetyError(f"Invalid unhashable YAML key in {label}") from exc
            if duplicate:
                raise SetupSafetyError(f"Duplicate YAML key in {label}: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        value = yaml.load(content, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise SetupSafetyError(f"Invalid {label} YAML: {str(exc)[:300]}") from exc
    if not isinstance(value, dict):
        raise SetupSafetyError(f"{label} must contain a YAML mapping at the top level")
    return value


def validate_devices(content: str, parser_path: str) -> None:
    """Validate syntax and then use the collector's canonical inventory parser."""
    data = _yaml_load_mapping(content, "devices.yaml")
    if "devices" not in data or not isinstance(data.get("devices"), dict) or not data["devices"]:
        raise SetupSafetyError("devices.yaml must contain a non-empty 'devices' mapping")
    defaults = data.get("defaults", {})
    if defaults is not None and not isinstance(defaults, dict):
        raise SetupSafetyError("devices.yaml 'defaults' must be a mapping")
    endpoint_hosts = data.get("endpoint_hosts", [])
    if endpoint_hosts is not None:
        if not isinstance(endpoint_hosts, list) or any(not isinstance(v, str) for v in endpoint_hosts):
            raise SetupSafetyError("devices.yaml 'endpoint_hosts' must be a list of strings")
    if not os.path.isfile(parser_path):
        raise SetupSafetyError("Canonical device parser is missing; repair the LLDPq installation")
    fd, candidate = tempfile.mkstemp(prefix=".devices.validate.", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        result = subprocess.run(
            [sys.executable, parser_path, "--format", "json", "--file", candidate],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "invalid inventory").strip()
            raise SetupSafetyError("Canonical devices.yaml validation failed: " + detail[:300])
        try:
            records = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SetupSafetyError("Canonical device parser returned invalid data") from exc
        if not isinstance(records, list) or not records:
            raise SetupSafetyError("devices.yaml must define at least one usable device")
    except subprocess.TimeoutExpired as exc:
        raise SetupSafetyError("Canonical devices.yaml validation timed out") from exc
    finally:
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass


def validate_topology_dot(content: str, topology_parser_path: str = None) -> None:
    if not content.strip():
        raise SetupSafetyError("topology.dot cannot be empty")
    if topology_parser_path:
        if not os.path.isfile(topology_parser_path):
            raise SetupSafetyError(
                "Shared topology parser is missing; repair the LLDPq installation"
            )
        try:
            semantic = subprocess.run(
                [sys.executable, topology_parser_path, "--validate-stdin"],
                input=content,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise SetupSafetyError("Topology semantic validation timed out") from exc
        if semantic.returncode != 0:
            detail = (semantic.stderr or semantic.stdout or "invalid topology").strip()
            raise SetupSafetyError("Invalid topology semantics: " + detail[:300])
    else:
        # Older installs do not have the shared parser. Enforce the subset that
        # lldp-validate.py consumes, rather than trusting Graphviz alone.
        stripped = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        meaningful = []
        for raw in stripped.splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            meaningful.append(line)
        if not meaningful or not re.match(r'^graph(?:\s+"(?:[^"\\]|\\.)*"|\s+[A-Za-z0-9_.-]+)?\s*\{$', meaningful[0]):
            raise SetupSafetyError("topology.dot must start with a Graphviz 'graph ... {' declaration")
        if meaningful[-1] != '}':
            raise SetupSafetyError("topology.dot must end with a closing '}'")
        if sum(line.count('{') for line in meaningful) != sum(line.count('}') for line in meaningful):
            raise SetupSafetyError("topology.dot contains unbalanced braces")
        quoted = re.compile(
            r'^"(?:[^"\\]|\\.)+"\s*:\s*"(?:[^"\\]|\\.)+"\s*--\s*'
            r'"(?:[^"\\]|\\.)+"\s*:\s*"(?:[^"\\]|\\.)+"'
            r'(?:\s*\[[^\]\r\n]*\])?\s*;?$'
        )
        unquoted = re.compile(
            r'^[A-Za-z0-9_.()-]+:[A-Za-z0-9_.:/()-]+\s*--\s*'
            r'[A-Za-z0-9_.()-]+:[A-Za-z0-9_.:/()-]+'
            r'(?:\s*\[[^\]\r\n]*\])?\s*;?$'
        )
        for line in meaningful[1:-1]:
            if '--' in line and not (quoted.fullmatch(line) or unquoted.fullmatch(line)):
                raise SetupSafetyError("Unsupported topology edge syntax: " + line[:160])
            if '--' not in line:
                raise SetupSafetyError("Unsupported topology.dot statement: " + line[:160])

    dot = shutil.which("dot")
    if not dot:
        return
    fd, candidate = tempfile.mkstemp(prefix=".topology.validate.", suffix=".dot")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            target.write(content)
        result = subprocess.run(
            [dot, "-Tdot", candidate, "-o", os.devnull],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "invalid DOT").strip()
            raise SetupSafetyError("Invalid topology.dot: " + detail[:300])
    except subprocess.TimeoutExpired as exc:
        raise SetupSafetyError("topology.dot validation timed out") from exc
    finally:
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass


def _string(value, field: str, *, required: bool = True, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise SetupSafetyError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise SetupSafetyError(f"{field} cannot be empty")
    if len(value) > maximum or any(c in value for c in ("\x00", "\r", "\n")):
        raise SetupSafetyError(f"{field} is too long or contains unsupported control characters")
    return value


def _layer(value, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000:
        raise SetupSafetyError(f"{field} must be an integer between 0 and 1000")
    return value


def _pattern(value, field: str) -> str:
    value = _string(value, field)
    try:
        re.compile(value)
    except re.error as exc:
        raise SetupSafetyError(f"{field} is not a valid regular expression: {exc}") from exc
    return value


def validate_topology_config(content: str) -> None:
    data = _yaml_load_mapping(content, "topology_config.yaml")
    topology = data.get("topology", "minimal")
    if topology not in ("minimal", "full"):
        raise SetupSafetyError("topology_config.yaml 'topology' must be 'minimal' or 'full'")

    categories = data.get("device_categories", [])
    if not isinstance(categories, list):
        raise SetupSafetyError("'device_categories' must be a list")
    for index, category in enumerate(categories):
        prefix = f"device_categories[{index}]"
        if not isinstance(category, dict):
            raise SetupSafetyError(prefix + " must be a mapping")
        _pattern(category.get("pattern"), prefix + ".pattern")
        _layer(category.get("layer"), prefix + ".layer")
        _string(category.get("icon"), prefix + ".icon", maximum=64)

    default = data.get("default", {"layer": 9, "icon": "server"})
    if not isinstance(default, dict):
        raise SetupSafetyError("'default' must be a mapping")
    _layer(default.get("layer"), "default.layer")
    _string(default.get("icon"), "default.icon", maximum=64)

    rules = data.get("special_rules", [])
    if not isinstance(rules, list):
        raise SetupSafetyError("'special_rules' must be a list")
    for index, rule in enumerate(rules):
        prefix = f"special_rules[{index}]"
        if not isinstance(rule, dict):
            raise SetupSafetyError(prefix + " must be a mapping")
        _pattern(rule.get("pattern"), prefix + ".pattern")
        rule_type = _string(rule.get("type"), prefix + ".type", maximum=64)
        if rule_type not in ("stagger", "even_odd_suffix"):
            raise SetupSafetyError(prefix + ".type must be 'stagger' or 'even_odd_suffix'")
        if "number_regex" in rule:
            pattern = _pattern(rule["number_regex"], prefix + ".number_regex")
            if re.compile(pattern).groups < 1:
                raise SetupSafetyError(prefix + ".number_regex must include a capture group")
        _string(rule.get("icon"), prefix + ".icon", maximum=64)
        if rule_type == "even_odd_suffix":
            _layer(rule.get("even_layer"), prefix + ".even_layer")
            _layer(rule.get("odd_layer"), prefix + ".odd_layer")
        elif "layer" in rule:
            _layer(rule["layer"], prefix + ".layer")


def normalize_aliases(value) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        raise SetupSafetyError("Aliases payload must be an object")
    unknown = set(value) - set(ALIAS_LIMITS)
    if unknown:
        raise SetupSafetyError("Unknown aliases section: " + ", ".join(sorted(map(str, unknown))))
    normalized: dict[str, dict[str, str]] = {}
    for section, (entry_limit, key_limit, value_limit) in ALIAS_LIMITS.items():
        mapping = value.get(section, {})
        if not isinstance(mapping, dict):
            raise SetupSafetyError(f"aliases.{section} must be an object")
        if len(mapping) > entry_limit:
            raise SetupSafetyError(f"aliases.{section} exceeds the {entry_limit}-entry limit")
        output: dict[str, str] = {}
        seen: dict[str, str] = {}
        for raw_key, raw_value in mapping.items():
            if not isinstance(raw_key, str) or not isinstance(raw_value, str):
                raise SetupSafetyError(f"aliases.{section} keys and values must be strings")
            key = raw_key.strip()
            alias = raw_value.strip()
            if not key or not alias:
                raise SetupSafetyError(f"aliases.{section} contains an empty key or alias")
            if len(key) > key_limit or len(alias) > value_limit:
                raise SetupSafetyError(
                    f"aliases.{section} limits are {key_limit} characters for names and "
                    f"{value_limit} for aliases"
                )
            if any(ord(c) < 32 or ord(c) == 127 for c in key + alias):
                raise SetupSafetyError(f"aliases.{section} contains unsupported control characters")
            folded = key.casefold()
            if folded in seen:
                raise SetupSafetyError(
                    f"aliases.{section} contains a case-insensitive collision: "
                    f"{seen[folded]!r} and {key!r}"
                )
            seen[folded] = key
            output[key] = alias
        normalized[section] = dict(sorted(
            output.items(), key=lambda item: (item[0].casefold(), item[0])
        ))
    return normalized


def aliases_text(value) -> tuple[dict[str, dict[str, str]], str]:
    normalized = normalize_aliases(value)
    return normalized, json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"


def _notification_bool(payload, name: str) -> bool:
    value = payload.get(name)
    if not isinstance(value, bool):
        raise SetupSafetyError(name + " must be true or false")
    return value


def _notification_text(payload, name: str, default="", maximum=2048) -> str:
    value = payload.get(name, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise SetupSafetyError(name + " must be a string")
    value = value.strip()
    if len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise SetupSafetyError(name + " is too long or contains control characters")
    return value


def _notification_number(value, name: str, low, high, *, integer=False):
    if isinstance(value, str) and re.fullmatch(
        r"-?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)", value.strip()
    ):
        value = float(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SetupSafetyError(name + " must be a number")
    if value < low or value > high:
        raise SetupSafetyError(f"{name} must be between {low} and {high}")
    if integer and int(value) != value:
        raise SetupSafetyError(name + " must be a whole number")
    return int(value) if integer or int(value) == value else value


def render_notifications(existing_text: Optional[str], payload: dict) -> str:
    """Round-trip-update UI-owned fields while retaining comments and extra keys."""
    if not isinstance(payload, dict):
        raise SetupSafetyError("Notifications request must be an object")
    try:
        from ruamel.yaml import YAML
    except ImportError as exc:  # installed for LLDPQ_USER by install.sh
        raise SetupSafetyError(
            "ruamel.yaml is required to preserve notifications.yaml comments"
        ) from exc
    yaml_rt = YAML()
    yaml_rt.preserve_quotes = True
    yaml_rt.width = 4096
    try:
        cfg = yaml_rt.load(existing_text) if existing_text is not None else {}
    except Exception as exc:
        raise SetupSafetyError("Cannot parse existing notifications.yaml: " + str(exc)[:300]) from exc
    if cfg is None:
        cfg = {}
    if not isinstance(cfg, dict):
        raise SetupSafetyError("notifications.yaml must contain a mapping")

    def sub(parent, key):
        value = parent.get(key)
        if value is not None and not isinstance(value, dict):
            raise SetupSafetyError(key + " must be a mapping")
        if value is None:
            value = {}
            parent[key] = value
        return value

    notifications = sub(cfg, "notifications")
    slack = sub(notifications, "slack")
    notifications["enabled"] = _notification_bool(payload, "enabled")
    server_url = _notification_text(payload, "server_url")
    if server_url and not re.fullmatch(r"https?://[^\s]+", server_url):
        raise SetupSafetyError("server_url must be an http(s) URL")
    notifications["server_url"] = server_url
    slack["enabled"] = _notification_bool(payload, "slack_enabled")
    webhook = _notification_text(payload, "webhook")
    if webhook and not webhook.startswith("https://hooks.slack.com/"):
        raise SetupSafetyError("webhook must be an https://hooks.slack.com/ URL")
    slack["webhook"] = webhook
    slack["channel"] = _notification_text(payload, "channel", "#lldpq", 128) or "#lldpq"
    slack.setdefault("username", "LLDPq Bot")
    slack.setdefault("icon_emoji", ":warning:")

    alert_types = sub(cfg, "alert_types")
    for request_name, config_name in (
        ("t_hardware", "hardware_alerts"), ("t_network", "network_alerts"),
        ("t_system", "system_alerts"), ("t_topology", "topology_alerts"),
        ("t_log", "log_alerts"),
    ):
        alert_types[config_name] = _notification_bool(payload, request_name)

    mode = _notification_text(payload, "mode", "summary", 32)
    if mode not in ("summary", "immediate", "change_only"):
        raise SetupSafetyError("Unsupported alert mode")
    sub(cfg, "alert_strategy")["mode"] = mode
    sub(cfg, "frequency")["min_interval_minutes"] = _notification_number(
        payload.get("min_interval"), "min_interval", 1, 10080, integer=True
    )

    supplied = payload.get("thresholds")
    if not isinstance(supplied, dict):
        raise SetupSafetyError("thresholds must be an object")
    thresholds = sub(cfg, "thresholds")
    network = sub(thresholds, "network")
    hardware = sub(thresholds, "hardware")
    system = sub(thresholds, "system")
    network["bgp_down_minutes"] = _notification_number(
        supplied.get("bgp"), "thresholds.bgp", 0, 10080
    )
    network["link_flaps_per_hour"] = _notification_number(
        supplied.get("flap_warn"), "thresholds.flap_warn", 0, 100000
    )
    network["link_flaps_critical"] = _notification_number(
        supplied.get("flap_crit"), "thresholds.flap_crit", 0, 100000
    )
    if network["link_flaps_critical"] < network["link_flaps_per_hour"]:
        raise SetupSafetyError("thresholds.flap_crit must be greater than or equal to flap_warn")
    network["optical_power_margin"] = _notification_number(
        supplied.get("optical"), "thresholds.optical", -100, 100
    )
    hardware["cpu_temp_critical"] = _notification_number(
        supplied.get("cpu"), "thresholds.cpu", 0, 250
    )
    hardware["asic_temp_critical"] = _notification_number(
        supplied.get("asic"), "thresholds.asic", 0, 250
    )
    system["disk_usage_critical"] = _notification_number(
        supplied.get("disk"), "thresholds.disk", 0, 100
    )

    output = io.StringIO()
    try:
        yaml_rt.dump(cfg, output)
    except Exception as exc:
        raise SetupSafetyError("YAML serialize failed: " + str(exc)[:300]) from exc
    body = output.getvalue()
    if existing_text is None:
        return (
            "# LLDPq Notification Configuration — managed via the Setup page (Notifications).\n"
            "# Slack incoming-webhook guide: https://api.slack.com/messaging/webhooks\n"
            + body
        )
    return body


def update_notifications(
    path: str,
    payload: dict,
    *,
    expected_revision: Optional[str] = None,
    managed_roots=None,
    allow_direct_mount_inplace: bool = False,
    result_info: Optional[dict] = None,
) -> str:
    # Recover before parsing the preservation base, including on a POST with
    # no prior editor GET after a container/process crash.
    existing_text, base_revision, exists = read_managed_text(
        path, managed_roots=managed_roots
    )
    existing = existing_text if exists else None
    if expected_revision is not None and expected_revision != base_revision:
        raise RevisionConflict(base_revision)
    rendered = render_notifications(existing, payload)
    # Always use the revision we just parsed, even for legacy callers that did
    # not send one.  This closes the read/round-trip/write race.
    return atomic_write_text(
        path,
        rendered,
        expected_revision=base_revision,
        managed_roots=managed_roots,
        allow_direct_mount_inplace=allow_direct_mount_inplace,
        result_info=result_info,
    )


def load_aliases(path: str) -> tuple[dict[str, dict[str, str]], str]:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        normalized = {"interfaces": {}, "devices": {}}
        return normalized, revision_bytes(b"")
    if len(raw) > MAX_CONFIG_BYTES:
        raise SetupSafetyError("display-aliases.json is too large")
    try:
        value = parse_json_no_duplicate_keys(raw.decode("utf-8"), "display-aliases.json")
    except (UnicodeDecodeError, SetupSafetyError) as exc:
        raise SetupSafetyError("display-aliases.json is invalid: " + str(exc)) from exc
    return normalize_aliases(value), revision_bytes(raw)


def _resolved_regular_target(logical_path: str, managed_roots=None) -> str:
    logical_path = os.path.abspath(logical_path)
    try:
        metadata = os.lstat(logical_path)
    except FileNotFoundError:
        parent = os.path.realpath(os.path.dirname(logical_path))
        if not os.path.isdir(parent):
            raise SetupSafetyError("Configuration directory does not exist")
        resolved = os.path.join(parent, os.path.basename(logical_path))
        _require_managed_target(resolved, managed_roots)
        return resolved
    if stat.S_ISLNK(metadata.st_mode):
        resolved = os.path.realpath(logical_path)
        if resolved == logical_path:
            raise SetupSafetyError("Configuration symlink does not resolve safely")
        try:
            resolved_metadata = os.stat(resolved)
        except FileNotFoundError as exc:
            raise SetupSafetyError("Configuration symlink target is missing") from exc
        if not stat.S_ISREG(resolved_metadata.st_mode):
            raise SetupSafetyError("Configuration symlink must resolve to a regular file")
        _require_managed_target(resolved, managed_roots)
        return resolved
    if not stat.S_ISREG(metadata.st_mode):
        raise SetupSafetyError("Configuration target must be a regular file")
    _require_managed_target(logical_path, managed_roots)
    return logical_path


def _require_managed_target(path: str, managed_roots) -> None:
    if not managed_roots:
        return
    resolved = os.path.realpath(path)
    roots = [os.path.realpath(root) for root in managed_roots]
    try:
        managed = any(os.path.commonpath((resolved, root)) == root for root in roots)
    except ValueError:
        managed = False
    if not managed:
        raise SetupSafetyError("Configuration link points outside managed LLDPq directories")


def _write_staged(path: str, content: bytes, metadata: Optional[os.stat_result]) -> str:
    directory = os.path.dirname(path)
    fd, staged = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".tmp.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        if metadata is not None:
            os.chmod(staged, stat.S_IMODE(metadata.st_mode))
            try:
                os.chown(staged, metadata.st_uid, metadata.st_gid)
            except PermissionError:
                # Running as the existing owner cannot change group on every platform;
                # the temp file normally inherits the correct primary group already.
                staged_meta = os.stat(staged)
                if staged_meta.st_uid != metadata.st_uid or staged_meta.st_gid != metadata.st_gid:
                    raise
        else:
            os.chmod(staged, 0o664)
            try:
                os.chown(staged, os.geteuid(), os.stat(directory).st_gid)
            except PermissionError:
                # The service user may not belong to a custom parent group;
                # mode 0664 still leaves the managed file readable.
                pass
        return staged
    except Exception:
        try:
            os.unlink(staged)
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_configuration_lock(path: str) -> int:
    """Open a stable per-file lock without accepting symlink replacement."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o660)
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_mode & stat.S_IWOTH
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise SetupSafetyError("Configuration lock is unsafe or changed while opening")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.lstat(path)
        if (opened.st_dev, opened.st_ino) != (locked.st_dev, locked.st_ino):
            raise SetupSafetyError("Configuration lock changed while waiting to acquire it")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _is_direct_mount(path: str, mountinfo_path: str = "/proc/self/mountinfo") -> bool:
    """Return True only when *path itself* is a Linux mount point."""
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


def _open_regular_no_follow(path: str, flags: int) -> tuple[int, os.stat_result]:
    """Open a stable regular-file pathname without following its final component."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise SetupSafetyError("Configuration target must remain a regular file")
    descriptor = os.open(
        path,
        flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        after = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or identity != (before.st_dev, before.st_ino)
            or identity != (after.st_dev, after.st_ino)
        ):
            raise SetupSafetyError("Configuration target changed while opening")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, limit: int = MAX_CONFIG_BYTES) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise SetupSafetyError("Configuration exceeds the safe size limit")


def _write_descriptor(descriptor: int, content: bytes) -> None:
    """Rewrite an already pinned inode, handling short writes and verifying bytes."""
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise SetupSafetyError("Direct-mount write made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)
    if _read_descriptor(descriptor) != content:
        raise SetupSafetyError("Direct-mount write verification failed")


def _open_direct_mount_journal_root(
    *, create: bool
) -> Optional[tuple[int, str]]:
    """Open the private persistent journal directory without following links."""
    root = DIRECT_MOUNT_JOURNAL_ROOT
    if not os.path.isabs(root):
        if create:
            raise SetupSafetyError("Direct-write recovery directory must be absolute")
        return None
    root = os.path.normpath(root)
    parent = os.path.dirname(root)
    try:
        parent_metadata = os.lstat(parent)
    except FileNotFoundError:
        parent_metadata = None
    if parent_metadata is not None and not stat.S_ISDIR(parent_metadata.st_mode):
        raise SetupSafetyError("Direct-write recovery parent is not a real directory")
    try:
        metadata = os.lstat(root)
    except FileNotFoundError:
        if not create:
            return None
        if parent_metadata is None:
            raise SetupSafetyError(
                "Persistent direct-write recovery storage is unavailable; ensure "
                "/var/lib/lldpq/provision-state is mounted and retry"
            )
        try:
            os.mkdir(root, 0o700)
        except FileExistsError:
            pass
        metadata = os.lstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SetupSafetyError(
            "Persistent direct-write recovery directory has unsafe ownership, type, or mode"
        )
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, flags)
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(root)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise SetupSafetyError("Direct-write recovery directory changed while opening")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, root


def _direct_mount_journal_root(*, create: bool) -> Optional[str]:
    opened = _open_direct_mount_journal_root(create=create)
    if opened is None:
        return None
    descriptor, root = opened
    os.close(descriptor)
    return root


def _direct_mount_journal_name(path: str) -> str:
    target_key = hashlib.sha256(os.fsencode(os.path.abspath(path))).hexdigest()
    return target_key + ".json"


def _journal_storage_is_persistent(root: str) -> bool:
    """The journal is recreation-safe only when its state parent is a mount."""
    return _is_direct_mount(os.path.dirname(os.path.normpath(root)))


def _direct_mount_journal_path(path: str, *, create_root: bool = False) -> Optional[str]:
    root = _direct_mount_journal_root(create=create_root)
    if root is None:
        return None
    return os.path.join(root, _direct_mount_journal_name(path))


def _journal_payload(
    path: str,
    original: bytes,
    candidate: bytes,
    metadata: os.stat_result,
) -> dict:
    return {
        "version": DIRECT_MOUNT_JOURNAL_VERSION,
        "target": os.path.abspath(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "original_size": len(original),
        "original_sha256": revision_bytes(original),
        "candidate_size": len(candidate),
        "candidate_sha256": revision_bytes(candidate),
        "original_base64": base64.b64encode(original).decode("ascii"),
    }


def _publish_direct_mount_journal(
    path: str,
    original: bytes,
    candidate: bytes,
    metadata: os.stat_result,
) -> str:
    if not _journal_storage_is_persistent(DIRECT_MOUNT_JOURNAL_ROOT):
        raise SetupSafetyError(
            "Legacy direct-file editing requires persistent recovery storage; mount "
            "lldpq-provision-state at /var/lib/lldpq/provision-state and retry"
        )
    opened_root = _open_direct_mount_journal_root(create=True)
    if opened_root is None:  # Defensive; create=True either returns or raises.
        raise SetupSafetyError("Persistent direct-write recovery storage is unavailable")
    root_fd, root = opened_root
    journal_name = _direct_mount_journal_name(path)
    journal = os.path.join(root, journal_name)
    descriptor = -1
    staged = "." + journal_name + ".tmp." + secrets.token_hex(12)
    try:
        try:
            os.stat(journal_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SetupSafetyError(
                "A retained direct-mount recovery journal must be resolved first"
            )
        payload = _journal_payload(path, original, candidate, metadata)
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        if len(encoded) > MAX_DIRECT_MOUNT_JOURNAL_BYTES:
            raise SetupSafetyError("Direct-mount recovery journal exceeds the safe limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(staged, flags, 0o600, dir_fd=root_fd)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, journal_name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        staged = None
        os.fsync(root_fd)
        return journal
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if staged is not None:
            try:
                os.unlink(staged, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.close(root_fd)


def _load_direct_mount_journal(path: str) -> Optional[dict]:
    direct_mount = _is_direct_mount(path)
    persistent_storage = _journal_storage_is_persistent(DIRECT_MOUNT_JOURNAL_ROOT)
    opened_root = _open_direct_mount_journal_root(create=False)
    if opened_root is None:
        if direct_mount and persistent_storage:
            raise SetupSafetyError(
                "Persistent direct-write recovery directory is missing for this legacy "
                "file mount; restart the container to repair it before saving"
            )
        return None
    root_fd, _root = opened_root
    journal_name = _direct_mount_journal_name(path)
    descriptor = None
    try:
        try:
            before = os.stat(journal_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(journal_name, flags, dir_fd=root_fd)
        opened = os.fstat(descriptor)
        after = os.stat(journal_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > MAX_DIRECT_MOUNT_JOURNAL_BYTES
        ):
            raise SetupSafetyError("Direct-mount recovery journal is unsafe")
        raw = _read_descriptor(descriptor, MAX_DIRECT_MOUNT_JOURNAL_BYTES)
    except (OSError, SetupSafetyError):
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root_fd)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupSafetyError("Direct-mount recovery journal is invalid") from exc
    expected = {
        "version", "target", "device", "inode", "mode", "uid", "gid",
        "original_size", "original_sha256", "candidate_size", "candidate_sha256",
        "original_base64",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise SetupSafetyError("Direct-mount recovery journal schema is invalid")
    if payload["version"] != DIRECT_MOUNT_JOURNAL_VERSION:
        raise SetupSafetyError("Direct-mount recovery journal version is unsupported")
    if payload["target"] != os.path.abspath(path):
        raise SetupSafetyError("Direct-mount recovery journal targets another file")
    for name in (
        "device", "inode", "mode", "uid", "gid", "original_size", "candidate_size",
    ):
        if isinstance(payload[name], bool) or not isinstance(payload[name], int):
            raise SetupSafetyError("Direct-mount recovery journal metadata is invalid")
    if not 0 < payload["candidate_size"] <= MAX_CONFIG_BYTES:
        raise SetupSafetyError("Direct-mount recovery candidate size is invalid")
    for name in ("original_sha256", "candidate_sha256"):
        if not isinstance(payload[name], str) or not re.fullmatch(r"[0-9a-f]{64}", payload[name]):
            raise SetupSafetyError("Direct-mount recovery journal digest is invalid")
    try:
        original = base64.b64decode(payload["original_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise SetupSafetyError("Direct-mount recovery snapshot is invalid") from exc
    if (
        len(original) != payload["original_size"]
        or len(original) > MAX_CONFIG_BYTES
        or revision_bytes(original) != payload["original_sha256"]
    ):
        raise SetupSafetyError("Direct-mount recovery snapshot does not match its digest")
    payload["original"] = original
    return payload


def _retire_direct_mount_journal(path: str) -> None:
    opened_root = _open_direct_mount_journal_root(create=False)
    if opened_root is None:
        raise SetupSafetyError("Persistent direct-write recovery journal disappeared")
    root_fd, _root = opened_root
    journal_name = _direct_mount_journal_name(path)
    try:
        metadata = os.stat(journal_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise SetupSafetyError("Direct-mount recovery journal changed before retirement")
        os.unlink(journal_name, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _validate_direct_mount_descriptor(
    path: str,
    metadata: os.stat_result,
    *,
    expected_identity: Optional[tuple[int, int]] = None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SetupSafetyError("Direct-mount target is not a regular file")
    if not _is_direct_mount(path):
        raise SetupSafetyError("Direct-mount target no longer has the expected mount identity")
    if metadata.st_nlink != 1:
        raise SetupSafetyError("Direct-mount target has an unsafe link count")
    if expected_identity is not None and (
        metadata.st_dev, metadata.st_ino
    ) != expected_identity:
        raise SetupSafetyError("Direct-mount target inode changed")


def _recover_direct_mount_journal_locked(path: str) -> bool:
    payload = _load_direct_mount_journal(path)
    if payload is None:
        return False
    descriptor = None
    try:
        descriptor, metadata = _open_regular_no_follow(path, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_direct_mount_descriptor(
            path,
            metadata,
            expected_identity=(payload["device"], payload["inode"]),
        )
        if (
            stat.S_IMODE(metadata.st_mode) != payload["mode"]
            or metadata.st_uid != payload["uid"]
            or metadata.st_gid != payload["gid"]
        ):
            raise SetupSafetyError("Direct-mount target metadata changed during recovery")
        current = _read_descriptor(descriptor)
        current_revision = revision_bytes(current)
        if (
            len(current) == payload["candidate_size"]
            and current_revision == payload["candidate_sha256"]
        ):
            pass
        elif current_revision == payload["original_sha256"]:
            if current != payload["original"]:
                raise SetupSafetyError("Direct-mount recovery digest collision detected")
        else:
            _write_descriptor(descriptor, payload["original"])
            restored = os.fstat(descriptor)
            if (
                (restored.st_dev, restored.st_ino) != (payload["device"], payload["inode"])
                or stat.S_IMODE(restored.st_mode) != payload["mode"]
                or restored.st_uid != payload["uid"]
                or restored.st_gid != payload["gid"]
            ):
                raise SetupSafetyError("Direct-mount rollback metadata verification failed")
        # Even when bytes already equal the completed candidate/original, do
        # not retire persistent recovery authority until that inode is durable.
        os.fsync(descriptor)
        durable = os.fstat(descriptor)
        if (
            (durable.st_dev, durable.st_ino) != (payload["device"], payload["inode"])
            or stat.S_IMODE(durable.st_mode) != payload["mode"]
            or durable.st_uid != payload["uid"]
            or durable.st_gid != payload["gid"]
        ):
            raise SetupSafetyError("Direct-mount recovery durability metadata changed")
        _retire_direct_mount_journal(path)
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)


def recover_direct_mount_write(logical_path: str, managed_roots=None) -> bool:
    """Recover one interrupted config-file direct-mount write under its file lock."""
    path = _resolved_regular_target(logical_path, managed_roots)
    lock_path = path + ".lock"
    lock_fd = _open_configuration_lock(lock_path)
    try:
        return _recover_direct_mount_journal_locked(path)
    finally:
        os.close(lock_fd)


def _retire_orphan_direct_mount_journal_stage(
    root_fd: int, name: str, allowed_journals: set[str]
) -> bool:
    """Remove one killed pre-publication stage after strict inode validation."""
    match = DIRECT_MOUNT_JOURNAL_STAGE_RE.fullmatch(name)
    if match is None:
        return False
    if match.group("journal") not in allowed_journals:
        raise SetupSafetyError(
            "Persistent config-write recovery stage targets an unknown file"
        )

    before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise SetupSafetyError("Persistent config-write recovery stage is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=root_fd)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or identity != (before.st_dev, before.st_ino)
            or identity != (current.st_dev, current.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or not 0 <= opened.st_size <= MAX_DIRECT_MOUNT_JOURNAL_BYTES
        ):
            raise SetupSafetyError("Persistent config-write recovery stage is unsafe")
        os.unlink(name, dir_fd=root_fd)
        if os.fstat(descriptor).st_nlink != 0:
            raise SetupSafetyError(
                "Persistent config-write recovery stage changed during retirement"
            )
    finally:
        os.close(descriptor)
    return True


def recover_all_managed_writes(lldpq_dir: str, web_root: str) -> list[str]:
    """Recover only the fixed set of Setup-managed configuration targets."""
    lldpq_dir = os.path.abspath(lldpq_dir)
    web_root = os.path.abspath(web_root)
    for label, root in (("LLDPq", lldpq_dir), ("web", web_root)):
        if not os.path.isabs(root) or not os.path.isdir(root):
            raise SetupSafetyError(f"Managed {label} root is unavailable")

    targets = (
        (os.path.join(lldpq_dir, "devices.yaml"), (lldpq_dir,)),
        (os.path.join(web_root, "topology.dot"), (web_root, lldpq_dir)),
        (os.path.join(web_root, "topology_config.yaml"), (web_root, lldpq_dir)),
        (os.path.join(lldpq_dir, "notifications.yaml"), (lldpq_dir,)),
        (os.path.join(web_root, "display-aliases.json"), (web_root, lldpq_dir)),
    )
    allowed_journals = set()
    recovered = []
    for logical_path, managed_roots in targets:
        resolved = _resolved_regular_target(logical_path, managed_roots)
        allowed_journals.add(_direct_mount_journal_name(resolved))
        if recover_direct_mount_write(logical_path, managed_roots=managed_roots):
            recovered.append(resolved)

    opened_root = _open_direct_mount_journal_root(create=False)
    if opened_root is None:
        return recovered
    root_fd, _root = opened_root
    try:
        remaining = os.listdir(root_fd)
        unresolved = []
        retired_stage = False
        for name in remaining:
            if _retire_orphan_direct_mount_journal_stage(
                root_fd, name, allowed_journals
            ):
                retired_stage = True
                continue
            if not re.fullmatch(r"[0-9a-f]{64}\.json", name):
                raise SetupSafetyError(
                    "Persistent config-write recovery directory contains an unsafe entry"
                )
            if name not in allowed_journals:
                raise SetupSafetyError(
                    "Persistent config-write recovery journal targets an unknown file"
                )
            unresolved.append(name)
        if retired_stage:
            os.fsync(root_fd)
        if unresolved:
            raise SetupSafetyError(
                "A managed config-write recovery journal remains unresolved"
            )
    finally:
        os.close(root_fd)
    return recovered


def _install_direct_mount_candidate(
    path: str,
    content: bytes,
    original: bytes,
    metadata: os.stat_result,
) -> None:
    descriptor = None
    try:
        descriptor, opened = _open_regular_no_follow(path, os.O_RDWR)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        _validate_direct_mount_descriptor(
            path,
            opened,
            expected_identity=(metadata.st_dev, metadata.st_ino),
        )
        if (
            stat.S_IMODE(opened.st_mode) != stat.S_IMODE(metadata.st_mode)
            or opened.st_uid != metadata.st_uid
            or opened.st_gid != metadata.st_gid
        ):
            raise SetupSafetyError("Direct-mount target metadata changed before writing")
        pinned_current = _read_descriptor(descriptor)
        if pinned_current != original:
            raise RevisionConflict(revision_bytes(pinned_current))
        _publish_direct_mount_journal(path, original, content, opened)
        try:
            _write_descriptor(descriptor, content)
            installed = os.fstat(descriptor)
            if (
                (installed.st_dev, installed.st_ino) != (opened.st_dev, opened.st_ino)
                or stat.S_IMODE(installed.st_mode) != stat.S_IMODE(opened.st_mode)
                or installed.st_uid != opened.st_uid
                or installed.st_gid != opened.st_gid
            ):
                raise SetupSafetyError("Direct-mount installed metadata verification failed")
            _retire_direct_mount_journal(path)
        except Exception as write_error:
            try:
                _write_descriptor(descriptor, original)
                restored = os.fstat(descriptor)
                if (
                    (restored.st_dev, restored.st_ino) != (opened.st_dev, opened.st_ino)
                    or stat.S_IMODE(restored.st_mode) != stat.S_IMODE(opened.st_mode)
                    or restored.st_uid != opened.st_uid
                    or restored.st_gid != opened.st_gid
                ):
                    raise SetupSafetyError("Direct-mount rollback metadata verification failed")
                _retire_direct_mount_journal(path)
            except Exception as rollback_error:
                raise SetupSafetyError(
                    "Direct-mount write failed and rollback is retained for recovery: "
                    + str(rollback_error)
                ) from write_error
            raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # A retained journal was fsynced before target mutation and remains the
        # recovery authority for the next GET/save invocation.


def atomic_write_text(
    logical_path: str,
    content: str,
    expected_revision: Optional[str] = None,
    managed_roots=None,
    *,
    allow_direct_mount_inplace: bool = False,
    result_info: Optional[dict] = None,
) -> str:
    encoded = content.encode("utf-8")
    if not encoded or len(encoded) > MAX_CONFIG_BYTES:
        raise SetupSafetyError("Configuration must be between 1 byte and 2 MiB")
    path = _resolved_regular_target(logical_path, managed_roots)
    directory = os.path.dirname(path)
    lock_path = path + ".lock"
    lock_fd = _open_configuration_lock(lock_path)
    try:
        _recover_direct_mount_journal_locked(path)
        try:
            current = Path(path).read_bytes()
            metadata = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            current = b""
            metadata = None
        current_revision = revision_bytes(current)
        if expected_revision is not None and expected_revision != current_revision:
            raise RevisionConflict(current_revision)

        backup_stage = None
        target_stage = None
        direct_mount_attempted = False
        try:
            if metadata is not None:
                backup_path = path + ".bak"
                try:
                    backup_metadata = os.stat(backup_path, follow_symlinks=False)
                    if not stat.S_ISREG(backup_metadata.st_mode):
                        raise SetupSafetyError("Configuration backup target is not a regular file")
                except FileNotFoundError:
                    backup_metadata = metadata
                backup_stage = _write_staged(backup_path, current, backup_metadata)
                os.replace(backup_stage, backup_path)
                backup_stage = None
                _fsync_directory(directory)
            target_stage = _write_staged(path, encoded, metadata)
            try:
                os.replace(target_stage, path)
                target_stage = None
                if result_info is not None:
                    result_info.update({"atomic": True, "write_mode": "atomic-replace"})
            except OSError as exc:
                if not (
                    exc.errno == errno.EBUSY
                    and allow_direct_mount_inplace
                    and metadata is not None
                    and _is_direct_mount(path)
                ):
                    raise
                # The durable journal supersedes the now-useless replacement
                # stage.  Remove it before touching the mounted inode so a
                # cleanup failure cannot turn a committed write into an error.
                os.unlink(target_stage)
                target_stage = None
                direct_mount_attempted = True
                _install_direct_mount_candidate(path, encoded, current, metadata)
                if result_info is not None:
                    result_info.update({
                        "atomic": False,
                        "write_mode": "direct-mount-journaled-in-place",
                        "recovery_scope": "persistent-state",
                    })
            if not direct_mount_attempted:
                _fsync_directory(directory)
        except Exception:
            if direct_mount_attempted:
                # The direct-mount installer either restored the pinned inode
                # or retained a durable journal for GET/save recovery.  A
                # rename-based rollback cannot replace a bind-mounted target.
                raise
            # If replacement happened and a later durability step failed, restore
            # the exact previous bytes before reporting failure.
            try:
                try:
                    installed = Path(path).read_bytes()
                except FileNotFoundError:
                    installed = b""
                if installed != current:
                    if metadata is None:
                        os.unlink(path)
                    else:
                        rollback = _write_staged(path, current, metadata)
                        os.replace(rollback, path)
                    _fsync_directory(directory)
            except Exception as rollback_error:
                raise SetupSafetyError(
                    "Write failed and automatic rollback also failed: " + str(rollback_error)
                )
            raise
        finally:
            for staged in (backup_stage, target_stage):
                if staged:
                    try:
                        os.unlink(staged)
                    except FileNotFoundError:
                        pass
        return revision_bytes(encoded)
    finally:
        os.close(lock_fd)


def read_managed_text(logical_path: str, managed_roots=None) -> tuple[str, str, bool]:
    """Recover any retained direct-mount transaction, then read one stable file."""
    path = _resolved_regular_target(logical_path, managed_roots)
    lock_path = path + ".lock"
    lock_fd = _open_configuration_lock(lock_path)
    try:
        _recover_direct_mount_journal_locked(path)
        try:
            descriptor, _metadata = _open_regular_no_follow(path, os.O_RDONLY)
        except FileNotFoundError:
            return "", revision_bytes(b""), False
        try:
            raw = _read_descriptor(descriptor)
        finally:
            os.close(descriptor)
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SetupSafetyError("Configuration must be valid UTF-8") from exc
        return content, revision_bytes(raw), True
    finally:
        os.close(lock_fd)


def _read_stdin_text(limit=MAX_CONFIG_BYTES) -> str:
    raw = sys.stdin.buffer.read(limit + 1)
    if len(raw) > limit:
        raise SetupSafetyError("Request exceeds the safe size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SetupSafetyError("Configuration must be valid UTF-8") from exc


def _main() -> int:
    global DIRECT_MOUNT_JOURNAL_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=(
        "recover-all", "read-text", "read-devices", "save-devices", "save-topology", "save-topology-config", "save-aliases",
        "save-notifications", "save-text",
    ))
    parser.add_argument("--target")
    parser.add_argument("--lldpq-dir")
    parser.add_argument("--web-root")
    parser.add_argument("--parser")
    parser.add_argument("--topology-parser")
    parser.add_argument("--expected-revision")
    parser.add_argument("--managed-root", action="append", default=[])
    parser.add_argument("--inventory-lock")
    parser.add_argument("--direct-write-state-dir")
    parser.add_argument("--request-json", action="store_true")
    args = parser.parse_args()
    if args.direct_write_state_dir:
        DIRECT_MOUNT_JOURNAL_ROOT = args.direct_write_state_dir
    global_lock_fd = None
    inventory_lock_fd = None
    try:
        if args.command != "recover-all" and not args.target:
            raise SetupSafetyError("Configuration target is required")
        incoming = "" if args.command in ("recover-all", "read-text", "read-devices") else _read_stdin_text(
            MAX_CONFIG_BYTES * 4 if args.request_json else MAX_CONFIG_BYTES
        )
        content = incoming
        expected_revision = args.expected_revision
        if args.request_json:
            content, expected_revision = parse_editor_request(incoming)
        global_lock_fd = acquire_global_configuration_lock()
        if args.command in ("recover-all", "read-devices", "save-devices"):
            if not args.inventory_lock:
                raise SetupSafetyError(
                    "Shared inventory lock is required for devices.yaml access"
                )
            inventory_lock_fd = acquire_inventory_lock(args.inventory_lock)
        if args.command == "recover-all":
            if not args.lldpq_dir or not args.web_root:
                raise SetupSafetyError("Managed LLDPq and web roots are required")
            recovered = recover_all_managed_writes(args.lldpq_dir, args.web_root)
            print(json.dumps({
                "success": True,
                "recovered": recovered,
                "recovered_count": len(recovered),
            }))
            return 0
        if args.command in ("read-text", "read-devices"):
            content, revision, exists = read_managed_text(
                args.target, managed_roots=args.managed_root
            )
            print(json.dumps({
                "success": True,
                "content": content,
                "revision": revision,
                "exists": exists,
            }))
            return 0
        normalized = None
        if args.command == "save-notifications":
            payload = parse_json_no_duplicate_keys(content, "notifications request JSON")
            write_info = {}
            revision = update_notifications(
                args.target,
                payload,
                expected_revision=expected_revision,
                managed_roots=args.managed_root,
                allow_direct_mount_inplace=True,
                result_info=write_info,
            )
            print(json.dumps({"success": True, "revision": revision, **write_info}))
            return 0
        if args.command == "save-devices":
            if not args.parser:
                raise SetupSafetyError("Canonical parser path is required")
            validate_devices(content, args.parser)
        elif args.command == "save-topology":
            validate_topology_dot(content, args.topology_parser)
        elif args.command == "save-topology-config":
            validate_topology_config(content)
        elif args.command == "save-aliases":
            value = parse_json_no_duplicate_keys(content, "aliases JSON")
            normalized, content = aliases_text(value)
        write_info = {}
        revision = atomic_write_text(
            args.target, content, expected_revision, managed_roots=args.managed_root,
            allow_direct_mount_inplace=True,
            result_info=write_info,
        )
        response = {"success": True, "revision": revision, **write_info}
        if normalized is not None:
            response["aliases"] = normalized
        print(json.dumps(response, ensure_ascii=False))
        return 0
    except RevisionConflict as exc:
        print(json.dumps({
            "success": False,
            "conflict": True,
            "current_revision": exc.current_revision,
            "error": str(exc),
        }))
        return 3
    except (SetupSafetyError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"success": False, "error": str(exc)[:500]}))
        return 2
    finally:
        if inventory_lock_fd is not None:
            os.close(inventory_lock_fd)
        if global_lock_fd is not None:
            os.close(global_lock_fd)


if __name__ == "__main__":
    raise SystemExit(_main())
