#!/usr/bin/env python3
"""
LLDPq Alert System - Network monitoring alerts for Slack
Copyright (c) 2024 LLDPq Project - Licensed under MIT License

This script analyzes monitoring data and sends alerts based on configured thresholds.
Called every 10 minutes by the lldpq cron job.
"""

import hashlib
import json
import yaml
import requests
import os
import sys
import glob
import math
import time
import datetime
import fcntl
import re
from pathlib import Path

try:
    from .lldp_report import LLDPReportError, parse_lldp_report
except ImportError:  # Direct script execution has no package context.
    from lldp_report import LLDPReportError, parse_lldp_report


DEFAULT_LOAD_PER_CORE_WARNING = 1.0
DEFAULT_LOAD_PER_CORE_CRITICAL = 1.5
PIPELINE_FILE_MTIME_TOLERANCE_SECONDS = 2.0


def resolve_load_per_core_thresholds(hardware_thresholds):
    """Resolve validated warning/critical thresholds in load-per-core units.

    Legacy ``system.load_average_*`` values are intentionally not accepted as
    aliases: those values are absolute loads and interpreting them as per-core
    thresholds would silently mix units.  Missing or invalid explicit keys use
    the same defaults as the hardware report.
    """
    configured = (
        hardware_thresholds if isinstance(hardware_thresholds, dict) else {}
    )
    def finite_or_default(key, default):
        try:
            value = float(configured.get(key, default))
        except (TypeError, ValueError):
            return default
        return value if math.isfinite(value) else default

    warning = finite_or_default(
        "load_per_core_warning", DEFAULT_LOAD_PER_CORE_WARNING
    )
    critical = finite_or_default(
        "load_per_core_critical", DEFAULT_LOAD_PER_CORE_CRITICAL
    )
    if (not math.isfinite(warning) or not math.isfinite(critical) or
            not 0 < warning < critical):
        return DEFAULT_LOAD_PER_CORE_WARNING, DEFAULT_LOAD_PER_CORE_CRITICAL
    return warning, critical


def parse_load_per_core(hardware_data):
    """Return (normalized load, raw 5-minute load, cores) from a collection."""
    if not isinstance(hardware_data, str):
        return None
    load_match = re.search(
        r'^CPU_INFO:\n'
        r'(?:__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:OK\s*\n)?'
        r'[0-9.]+\s+([0-9.]+)\s+[0-9.]+\s+',
        hardware_data,
        re.MULTILINE,
    )
    cores_match = re.search(r'^CPU_CORES:\s*(\d+)', hardware_data, re.MULTILINE)
    if not load_match or not cores_match:
        return None
    raw_load = float(load_match.group(1))
    cores = int(cores_match.group(1))
    if not math.isfinite(raw_load) or raw_load < 0 or cores <= 0:
        return None
    return raw_load / cores, raw_load, cores


def read_stable_pipeline_file(path, run_manifest=None):
    """Read a stable file and, when available, bind it to the pipeline window.

    ``run_manifest=None`` intentionally keeps this helper usable by focused
    unit/debug callers that do not run the complete monitoring pipeline.
    Production alert paths provide the validated current-run manifest.
    """
    if not path.is_file():
        raise FileNotFoundError(path)
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    before_identity = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    )
    after_identity = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    )
    if before_identity != after_identity:
        raise RuntimeError("file changed while it was read")

    if isinstance(run_manifest, dict):
        if not run_manifest.get("pipeline_complete"):
            raise ValueError("current manifest is not from a complete pipeline")
        started_at = run_manifest.get("pipeline_started_at")
        if (isinstance(started_at, bool) or
                not isinstance(started_at, (int, float)) or
                not math.isfinite(started_at) or started_at <= 0):
            raise ValueError("pipeline start time is invalid")

        completed_value = run_manifest.get("completed_at")
        if not isinstance(completed_value, str) or not completed_value.strip():
            raise ValueError("pipeline completion time is invalid")
        normalized = completed_value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            completed = datetime.datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError("pipeline completion time is invalid") from exc
        if completed.tzinfo is None:
            completed = completed.astimezone()

        file_mtime = before.st_mtime_ns / 1_000_000_000
        completed_limit = (
            completed.timestamp() + PIPELINE_FILE_MTIME_TOLERANCE_SECONDS
        )
        if file_mtime < started_at:
            raise ValueError("file predates the current pipeline")
        if file_mtime > completed_limit:
            raise ValueError("file was modified after pipeline completion")

    return content.decode("utf-8", errors="replace")


class LLDPqAlerts:
    def __init__(self, script_dir):
        self.script_dir = Path(script_dir)
        self.config_file = self.script_dir / "notifications.yaml"
        self.state_dir = self.script_dir / "alert-states"
        self.monitor_results = self.script_dir / "monitor-results"
        self.config_error = False
        self.notifications_disabled = False
        self.had_error = False
        self.run_manifest = None
        
        # Create state directory if it doesn't exist (like `mkdir -p`)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self.load_config()
        
    def load_config(self):
        """Load notification configuration from YAML file"""
        try:
            if not self.config_file.exists():
                print(f"❌ Configuration file not found: {self.config_file}")
                self.config_error = True
                return None
                
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            if not isinstance(config, dict):
                raise ValueError("configuration root must be a mapping")

            if not config.get('notifications', {}).get('enabled', False):
                print("Notifications disabled in config")
                self.notifications_disabled = True
                return None
                
            return config
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            self.config_error = True
            return None

    def monitor_is_stale(self):
        """Return True when the most recent monitor run was not publishable."""
        marker = self.monitor_results / ".lldpq-stale"
        if not marker.exists():
            return False
        try:
            reason = marker.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            reason = f"could not read stale marker: {exc}"
        print(f"❌ Monitoring results are stale; alerts were not evaluated ({reason})")
        self.had_error = True
        return True

    def load_run_manifest(self):
        """Load and validate the manifest for the completed analysis bundle."""
        manifest_file = self.monitor_results / ".lldpq-current.json"
        if not manifest_file.exists():
            print(f"❌ Current-run manifest is missing: {manifest_file}")
            self.had_error = True
            return False

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or manifest.get("status") != "current":
                raise ValueError("manifest status is not current")
            pipeline_id = manifest.get("pipeline_id")
            if (manifest.get("pipeline_complete") is not True or
                    not isinstance(pipeline_id, str) or
                    not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", pipeline_id)):
                raise ValueError("manifest is not from one complete pipeline")

            analyses = manifest.get("analyses")
            skipped = manifest.get("skipped", [])
            device_count = manifest.get("device_count")
            if (not isinstance(analyses, list) or
                    any(not isinstance(item, str) or not item for item in analyses)):
                raise ValueError("manifest analyses must be a list of names")
            if (not isinstance(skipped, list) or
                    any(not isinstance(item, str) or not item for item in skipped)):
                raise ValueError("manifest skipped must be a list of names")
            if (isinstance(device_count, bool) or
                    not isinstance(device_count, int) or device_count < 0):
                raise ValueError("manifest device_count must be a non-negative integer")

            skipped_set = set(skipped)
            required_analyses = {"bgp", "flap", "ber", "hardware", "log", "duplicate"}
            if "optical" not in skipped_set:
                required_analyses.add("optical")
            missing_analyses = sorted(required_analyses.difference(analyses))
            if missing_analyses:
                raise ValueError(
                    "manifest is missing completed analyses: "
                    + ", ".join(missing_analyses)
                )

            sources = manifest.get("sources")
            expected_source_paths = {
                "assets": ".pipeline-inputs/assets.ini",
                "lldp": ".pipeline-inputs/lldp_results.ini",
            }
            if not isinstance(sources, dict):
                raise ValueError("manifest source identities are missing")
            for name, expected_path in expected_source_paths.items():
                identity = sources.get(name)
                if (not isinstance(identity, dict) or
                        identity.get("path") != expected_path or
                        not isinstance(identity.get("sha256"), str) or
                        re.fullmatch(r"[a-f0-9]{64}", identity["sha256"], re.I) is None or
                        isinstance(identity.get("size"), bool) or
                        not isinstance(identity.get("size"), int) or
                        identity["size"] < 0 or
                        isinstance(identity.get("mtime_ns"), bool) or
                        not isinstance(identity.get("mtime_ns"), int) or
                        identity["mtime_ns"] < 0):
                    raise ValueError(f"manifest {name} source identity is invalid")

            completed_at = manifest.get("completed_at")
            if not isinstance(completed_at, str) or not completed_at.strip():
                raise ValueError("manifest completed_at is missing")
            normalized_time = completed_at.strip()
            if normalized_time.endswith("Z"):
                normalized_time = normalized_time[:-1] + "+00:00"
            completed = datetime.datetime.fromisoformat(normalized_time)
            if completed.tzinfo is None:
                completed = completed.astimezone()

            age_seconds = time.time() - completed.timestamp()
            if age_seconds < -300:
                raise ValueError("manifest completion time is in the future")
            max_age_seconds = manifest.get("max_age_seconds")
            if max_age_seconds is None:
                # Compatibility for one pre-upgrade generation. New manifests
                # carry the same policy consumed by the web/API surfaces.
                max_age_seconds = self.get_frequency_seconds(
                    "data_stale_minutes", 30
                )
            if (isinstance(max_age_seconds, bool) or
                    not isinstance(max_age_seconds, (int, float)) or
                    not math.isfinite(float(max_age_seconds)) or
                    max_age_seconds < 0):
                raise ValueError("manifest maximum age is invalid")
            if age_seconds > max_age_seconds:
                raise ValueError(
                    f"manifest is stale ({age_seconds / 60:.1f} minutes old)"
                )
            return manifest
        except (OSError, OverflowError, ValueError, TypeError,
                json.JSONDecodeError) as exc:
            print(f"❌ Could not read current-run manifest: {exc}")
            self.had_error = True
            return False

    def source_matches_run_manifest(self, source_name, path):
        """Verify that a summary source is exactly the file monitor consumed."""
        if not isinstance(self.run_manifest, dict):
            return True
        if not self.run_manifest.get("pipeline_complete"):
            print("❌ Monitoring manifest is not from a complete assets/LLDP pipeline")
            self.had_error = True
            return False
        identity = self.run_manifest.get("sources", {}).get(source_name)
        if not isinstance(identity, dict):
            print(f"❌ Monitoring manifest lacks {source_name} source identity")
            self.had_error = True
            return False
        try:
            before = path.stat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            after = path.stat()
            stable_identity = (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
            ) == (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            )
            matches = (
                path.is_file()
                and stable_identity
                and identity.get("sha256") == digest
                and identity.get("size") == before.st_size
                and identity.get("mtime_ns") == before.st_mtime_ns
            )
        except (OSError, TypeError, ValueError):
            matches = False
        if not matches:
            print(
                f"❌ {source_name} changed or does not belong to the current "
                "monitoring pipeline"
            )
            self.had_error = True
            return False
        return True
    
    def get_alert_state(self, device, alert_type):
        """Get the last alert state for a device/alert combination"""
        state_file = self.state_dir / f"{device}_{alert_type}.state"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    return f.read().strip()
            except OSError as exc:
                print(f"❌ Error reading alert state: {exc}")
                self.had_error = True
        return "UNKNOWN"

    def _atomic_write_state(self, destination, value):
        """Atomically write alert state so a failed write cannot truncate it."""
        temporary = destination.with_name(
            f".{destination.name}.tmp.{os.getpid()}.{time.time_ns()}"
        )
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(str(value))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            return True
        except OSError as exc:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
            print(f"❌ Error saving alert state: {exc}")
            self.had_error = True
            return False
    
    def set_alert_state(self, device, alert_type, state):
        """Save the current alert state"""
        state_file = self.state_dir / f"{device}_{alert_type}.state"
        return self._atomic_write_state(state_file, state)

    def _alert_marker_file(self, device, alert_type, marker):
        """Return a state marker path for an alert."""
        return self.state_dir / f"{device}_{alert_type}.{marker}"

    def _read_marker_time(self, device, alert_type, marker):
        marker_file = self._alert_marker_file(device, alert_type, marker)
        try:
            return float(marker_file.read_text().strip())
        except FileNotFoundError:
            return None
        except (OSError, TypeError, ValueError) as exc:
            print(f"❌ Error reading alert {marker}: {exc}")
            self.had_error = True
            return None

    def _write_marker_time(self, device, alert_type, marker):
        marker_file = self._alert_marker_file(device, alert_type, marker)
        return self._atomic_write_state(marker_file, time.time())

    def record_alert_attempt(self, device, alert_type):
        """Record a delivery attempt without claiming the alert was delivered."""
        return self._write_marker_time(device, alert_type, "attempt")

    def record_alert_delivery(self, device, alert_type, current_state):
        """Persist state and rate-limit timestamp only after successful delivery."""
        state_saved = self.set_alert_state(device, alert_type, current_state)
        if not state_saved:
            # Keep the attempt marker so retry backoff still applies, but never
            # claim a delivery timestamp when the delivered state was not saved.
            return False
        timestamp_saved = self._write_marker_time(device, alert_type, "timestamp")
        attempt_cleared = self._clear_alert_attempt(device, alert_type)
        return timestamp_saved and attempt_cleared

    def _clear_alert_attempt(self, device, alert_type):
        try:
            self._alert_marker_file(device, alert_type, "attempt").unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            print(f"❌ Error clearing alert attempt marker: {exc}")
            self.had_error = True
            return False

    def record_state_without_delivery(self, device, alert_type, current_state):
        """Advance an intentionally silent state transition (for disabled recovery)."""
        state_saved = self.set_alert_state(device, alert_type, current_state)
        attempt_cleared = self._clear_alert_attempt(device, alert_type)
        return state_saved and attempt_cleared

    def get_frequency_seconds(self, key, default_minutes):
        """Read a non-negative frequency setting while accepting YAML numbers/strings."""
        try:
            minutes = float(
                self.config.get('frequency', {}).get(key, default_minutes)
            )
        except (AttributeError, TypeError, ValueError):
            minutes = default_minutes
        return max(minutes, 0) * 60

    def get_data_max_age_seconds(self):
        """Return the current manifest's cross-surface freshness policy."""
        run_manifest = getattr(self, "run_manifest", None)
        if isinstance(run_manifest, dict):
            value = run_manifest.get("max_age_seconds")
            if (not isinstance(value, bool) and isinstance(value, (int, float))
                    and math.isfinite(float(value)) and value >= 0):
                return float(value)
        return self.get_frequency_seconds("data_stale_minutes", 30)
    
    def should_send_alert(self, device, alert_type, current_state):
        """Check if we should send an alert based on state changes and frequency limits"""
        if not self.config:
            return False
            
        last_state = self.get_alert_state(device, alert_type)
        
        # Only alert on state changes
        if current_state == last_state:
            return False
            
        # Check minimum interval (prevent spam)
        min_interval = self.get_frequency_seconds('min_interval_minutes', 30)
        last_delivery = self._read_marker_time(device, alert_type, "timestamp")
        if last_delivery is not None and time.time() - last_delivery < min_interval:
            return False

        # A failed webhook remains pending, but rapid/manual invocations should not
        # hammer Slack. This marker is deliberately separate from last delivery.
        retry_interval = self.get_frequency_seconds('retry_interval_minutes', 5)
        last_attempt = self._read_marker_time(device, alert_type, "attempt")
        if last_attempt is not None and time.time() - last_attempt < retry_interval:
            return False
            
        return True
    
    def send_notification(self, title, message, severity, device, alert_type=""):
        """Send notification to configured channels and report delivery success."""
        if not self.config:
            return False
            
        # Color mapping
        colors = {
            "CRITICAL": "#FF0000",  # Red
            "WARNING": "#FFA500",   # Orange  
            "INFO": "#0066CC",      # Blue
            "RECOVERED": "#00AA00"  # Green
        }
        
        color = colors.get(severity, "#808080")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Send to Slack
        slack_config = self.config.get('notifications', {}).get('slack', {})
        if not slack_config.get('enabled'):
            # Preserve the existing disabled-channel behavior: there is no
            # requested delivery to retry.
            return True
        if not slack_config.get('webhook'):
            print("❌ Slack notification enabled but webhook is empty")
            self.had_error = True
            return False
        delivered = self.send_slack_message(
            title, message, color, device, timestamp, slack_config
        )
        if not delivered:
            self.had_error = True
        return delivered

    def send_stateful_notification(self, title, message, severity, device,
                                   alert_type, current_state):
        """Attempt an alert and advance its state only after delivery succeeds."""
        self.record_alert_attempt(device, alert_type)
        delivered = self.send_notification(
            title, message, severity, device, alert_type
        )
        if delivered:
            persisted = self.record_alert_delivery(
                device, alert_type, current_state
            )
            return delivered and persisted
        return False
    

    def send_slack_message(self, title, message, color, device, timestamp, slack_config):
        """Send message to Slack"""
        try:
            server_url = self.config.get('notifications', {}).get('server_url', 'http://localhost')
            payload = {
                "channel": slack_config.get('channel', '#network-alerts'),
                "username": slack_config.get('username', 'LLDPq Bot'),
                "icon_emoji": slack_config.get('icon_emoji', ':warning:'),
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": message,
                    "fields": [
                        {"title": "Device", "value": device, "short": True},
                        {"title": "Time", "value": timestamp, "short": True}
                    ],
                    "actions": [{
                        "type": "button",
                        "text": "View Details",
                        "url": f"{server_url}/device.html?device={device}"
                    }]
                }]
            }
            
            response = requests.post(slack_config['webhook'], json=payload, timeout=10)
            if 200 <= response.status_code < 300:
                print(f"Slack alert sent: {title}")
                return True
            else:
                print(f"❌ Slack alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Slack notification error: {e}")
            return False
    
    def check_hardware_alerts(self, device):
        """Check hardware-related alerts (CPU temp, fans, memory, etc.)"""
        if not self.config.get('alert_types', {}).get('hardware_alerts', True):
            return
            
        hardware_file = self.monitor_results / "hardware-data" / f"{device}_hardware.txt"
        if not hardware_file.exists():
            return
            
        try:
            with open(hardware_file, 'r') as f:
                hardware_data = f.read()
        except OSError as exc:
            print(f"    ❌ Could not read hardware data for {device}: {exc}")
            self.had_error = True
            return
        
        thresholds = self.config.get('thresholds', {}).get('hardware', {})
        
        # Check CPU temperature. Cumulus hardware-management fallbacks are
        # emitted without a degree suffix, while lm-sensors uses °C.
        cpu_temperatures = []
        for pattern in (
            r'CPU ACPI temp:\s*\+?([0-9.]+)°C',
            r'Core \d+:\s*\+?([0-9.]+)°C',
            r'Package id \d+:\s*\+?([0-9.]+)°C',
            r'HW_MGMT_CPU:\s*([0-9.]+)',
        ):
            cpu_temperatures.extend(
                float(value) for value in re.findall(pattern, hardware_data)
            )

        if cpu_temperatures:
            cpu_temp = max(cpu_temperatures)
            cpu_critical = thresholds.get('cpu_temp_critical', 85)
            cpu_warning = thresholds.get('cpu_temp_warning', 75)
            
            if cpu_temp >= cpu_critical:
                current_state = "CRITICAL"
            elif cpu_temp >= cpu_warning:
                current_state = "WARNING"
            else:
                current_state = "OK"
            
            send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
            if current_state == "OK" and not send_recovery:
                self.record_state_without_delivery(device, "cpu_temp", current_state)
            elif self.should_send_alert(device, "cpu_temp", current_state):
                if current_state == "CRITICAL":
                    self.send_stateful_notification(
                        f"🔥 Critical CPU Temperature",
                        f"CPU temperature: {cpu_temp}°C (threshold: {cpu_critical}°C)",
                        "CRITICAL", device, "cpu_temp", current_state
                    )
                elif current_state == "WARNING":
                    self.send_stateful_notification(
                        f"⚠️ High CPU Temperature",
                        f"CPU temperature: {cpu_temp}°C (threshold: {cpu_warning}°C)",
                        "WARNING", device, "cpu_temp", current_state
                    )
                elif current_state == "OK":
                    self.send_stateful_notification(
                        f"CPU Temperature Recovered",
                        f"CPU temperature: {cpu_temp}°C (back to normal)",
                        "RECOVERED", device, "cpu_temp", current_state
                    )
        
        # Check ASIC temperature across sensors and Cumulus fallback labels.
        asic_temperatures = []
        for pattern in (
            r'ASIC.*temp.*:\s*\+?([0-9.]+)°C',
            r'(?:HW_MGMT_ASIC|THERMAL_ZONE_ASIC|HWMON_ASIC):\s*([0-9.]+)',
        ):
            asic_temperatures.extend(
                float(value) for value in re.findall(
                    pattern, hardware_data, re.IGNORECASE
                )
            )
        if asic_temperatures:
            asic_temp = max(asic_temperatures)
            asic_critical = thresholds.get('asic_temp_critical', 90)
            asic_warning = thresholds.get('asic_temp_warning', 80)
            
            if asic_temp >= asic_critical:
                current_state = "CRITICAL"
            elif asic_temp >= asic_warning:
                current_state = "WARNING"
            else:
                current_state = "OK"
                
            send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
            if current_state == "OK" and not send_recovery:
                self.record_state_without_delivery(device, "asic_temp", current_state)
            elif self.should_send_alert(device, "asic_temp", current_state):
                if current_state == "CRITICAL":
                    self.send_stateful_notification(
                        f"🔥 Critical ASIC Temperature",
                        f"ASIC temperature: {asic_temp}°C (threshold: {asic_critical}°C)",
                        "CRITICAL", device, "asic_temp", current_state
                    )
                elif current_state == "WARNING":
                    self.send_stateful_notification(
                        f"⚠️ High ASIC Temperature",
                        f"ASIC temperature: {asic_temp}°C (threshold: {asic_warning}°C)",
                        "WARNING", device, "asic_temp", current_state
                    )
                elif current_state == "OK":
                    self.send_stateful_notification(
                        f"ASIC Temperature Recovered",
                        f"ASIC temperature: {asic_temp}°C (back to normal)",
                        "RECOVERED", device, "asic_temp", current_state
                    )

        # Check fan speeds
        fan_matches = re.findall(r'fan\d+:\s*(\d+)\s*RPM', hardware_data, re.IGNORECASE)
        if fan_matches:
            fan_critical = thresholds.get('fan_rpm_critical', 3000)
            fan_warning = thresholds.get('fan_rpm_warning', 4000)
            
            failed_fans = []
            warning_fans = []
            
            for i, rpm_str in enumerate(fan_matches, 1):
                rpm = int(rpm_str)
                if rpm < fan_critical:
                    failed_fans.append(f"Fan{i}: {rpm} RPM")
                elif rpm < fan_warning:
                    warning_fans.append(f"Fan{i}: {rpm} RPM")
            
            if failed_fans:
                current_state = "CRITICAL"
            elif warning_fans:
                current_state = "WARNING"
            else:
                current_state = "OK"
            
            send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
            if current_state == "OK" and not send_recovery:
                self.record_state_without_delivery(device, "fan_speed", current_state)
            elif self.should_send_alert(device, "fan_speed", current_state):
                if current_state == "CRITICAL":
                    self.send_stateful_notification(
                        f"🌀 Critical Fan Failure",
                        f"Fan(s) below critical threshold: {', '.join(failed_fans)}",
                        "CRITICAL", device, "fan_speed", current_state
                    )
                elif current_state == "WARNING":
                    self.send_stateful_notification(
                        f"⚠️ Fan Speed Warning",
                        f"Fan(s) below warning threshold: {', '.join(warning_fans)}",
                        "WARNING", device, "fan_speed", current_state
                    )
                elif current_state == "OK":
                    self.send_stateful_notification(
                        f"Fan Speeds Recovered",
                        f"All fans operating normally",
                        "RECOVERED", device, "fan_speed", current_state
                    )

    def check_system_alerts(self, device):
        """Check system metrics that are collected with hardware telemetry."""
        if not self.config.get('alert_types', {}).get('system_alerts', True):
            return

        hardware_file = (
            self.monitor_results / "hardware-data" / f"{device}_hardware.txt"
        )
        run_manifest = getattr(self, "run_manifest", None)
        # UNREACHABLE devices deliberately have their old raw artifacts
        # removed by monitor.sh. Availability/assets alerts own that state; a
        # file that is absent from the outset is therefore not a system-load
        # collection error. If a file disappears after this check, the stable
        # reader below still treats that read race as a fail-closed error.
        if not hardware_file.exists():
            return
        try:
            hardware_data = read_stable_pipeline_file(
                hardware_file, run_manifest
            )
        except (OSError, OverflowError, RuntimeError, TypeError, ValueError) as exc:
            print(
                f"    ❌ System data for {device} is not from the current "
                f"stable pipeline: {exc}"
            )
            self.had_error = True
            return

        # Grade and notify on the same normalized 5-minute load used by the
        # hardware report. Absolute load is retained only as message context.
        parsed_load = parse_load_per_core(hardware_data)
        if parsed_load is None:
            return
        load_per_core, raw_load, cpu_cores = parsed_load
        thresholds = self.config.get('thresholds', {}).get('hardware', {})
        load_warning, load_critical = resolve_load_per_core_thresholds(
            thresholds
        )
        if load_per_core >= load_critical:
            current_state = "CRITICAL"
        elif load_per_core >= load_warning:
            current_state = "WARNING"
        else:
            current_state = "OK"

        alert_type = "cpu_load_per_core"
        last_state = self.get_alert_state(device, alert_type)
        if current_state == "OK" and last_state == "UNKNOWN":
            # This alert type is new. Establish a healthy baseline silently so
            # an upgrade cannot emit one false recovery per inventory device.
            self.record_state_without_delivery(device, alert_type, current_state)
            return

        send_recovery = self.config.get('frequency', {}).get(
            'send_recovery', True
        )
        if current_state == "OK" and not send_recovery:
            self.record_state_without_delivery(device, alert_type, current_state)
            return
        if not self.should_send_alert(device, alert_type, current_state):
            return

        load_context = (
            f"5-minute load per core: {load_per_core:.2f} "
            f"(raw load {raw_load:.2f} / {cpu_cores} cores)"
        )
        if current_state == "CRITICAL":
            self.send_stateful_notification(
                "🔥 Critical CPU Load",
                f"{load_context}; critical threshold: {load_critical:g}/core",
                "CRITICAL", device, alert_type, current_state
            )
        elif current_state == "WARNING":
            self.send_stateful_notification(
                "⚠️ High CPU Load",
                f"{load_context}; warning threshold: {load_warning:g}/core",
                "WARNING", device, alert_type, current_state
            )
        else:
            self.send_stateful_notification(
                "CPU Load Recovered",
                f"{load_context}; back below {load_warning:g}/core",
                "RECOVERED", device, alert_type, current_state
            )

    def check_network_alerts(self, device):
        """Check network-related alerts (BGP, flaps, BER and optical)."""
        if not self.config.get('alert_types', {}).get('network_alerts', True):
            return
            
        # Check BGP status
        processed_bgp_status = self.get_device_bgp_status(device)
        if processed_bgp_status in {"stale", "unknown"}:
            print(
                f"    ⚠️ Skipping BGP neighbor state for {device}: "
                f"collection is {processed_bgp_status}"
            )
        elif processed_bgp_status in {"warning", "critical"}:
            current_state = processed_bgp_status.upper()
            if self.should_send_alert(device, "bgp_neighbors", current_state):
                state_detail = (
                    "exceeded the configured down-duration threshold"
                    if current_state == "CRITICAL"
                    else "is in a warning state (grace-period or queue/policy issue)"
                )
                self.send_stateful_notification(
                    ("BGP Neighbors Down" if current_state == "CRITICAL"
                     else "BGP Neighbor Warning"),
                    f"Processed BGP analysis reports that a neighbor {state_detail}",
                    current_state, device, "bgp_neighbors", current_state
                )
        elif processed_bgp_status == "established":
            current_state = "OK"
            send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
            if not send_recovery:
                self.record_state_without_delivery(device, "bgp_neighbors", current_state)
            elif self.should_send_alert(device, "bgp_neighbors", current_state):
                self.send_stateful_notification(
                    "BGP Neighbors Recovered",
                    "All BGP neighbors established",
                    "RECOVERED", device, "bgp_neighbors", current_state
                )
        
        # carrier_changes is cumulative. Use the analyzer's timestamped deltas
        # rather than counting lines in the raw snapshot.
        flap_counts = self.get_device_flap_counts(device, window_seconds=3600)
        if flap_counts is not None:
            high_flap_interfaces = []
            critical_flap_interfaces = []
            
            thresholds = self.config.get('thresholds', {}).get('network', {})
            try:
                flap_warning = float(thresholds.get('link_flaps_per_hour', 10))
                flap_critical = float(thresholds.get('link_flaps_critical', 20))
            except (TypeError, ValueError):
                print("    ❌ Invalid link-flap thresholds; using 10/20")
                self.had_error = True
                flap_warning, flap_critical = 10, 20
            
            for interface, flap_count in sorted(flap_counts.items()):
                if flap_count >= flap_critical:
                    critical_flap_interfaces.append(f"{interface}: {flap_count}")
                elif flap_count >= flap_warning:
                    high_flap_interfaces.append(f"{interface}: {flap_count}")
            
            if critical_flap_interfaces:
                current_state = "CRITICAL"
            elif high_flap_interfaces:
                current_state = "WARNING"
            else:
                current_state = "OK"
            
            send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
            if current_state == "OK" and not send_recovery:
                self.record_state_without_delivery(device, "link_flaps", current_state)
            elif self.should_send_alert(device, "link_flaps", current_state):
                if current_state == "CRITICAL":
                    self.send_stateful_notification(
                        f"⚡ Critical Link Flapping",
                        f"Interfaces with excessive flaps: {', '.join(critical_flap_interfaces)}",
                        "CRITICAL", device, "link_flaps", current_state
                    )
                elif current_state == "WARNING":
                    self.send_stateful_notification(
                        f"⚠️ High Link Flapping",
                        f"Interfaces with high flaps: {', '.join(high_flap_interfaces)}",
                        "WARNING", device, "link_flaps", current_state
                    )
                elif current_state == "OK":
                    self.send_stateful_notification(
                        f"Link Flaps Stabilized",
                        f"All interfaces stable",
                        "RECOVERED", device, "link_flaps", current_state
                    )

        self.check_processed_network_alerts(device)

    def _notify_processed_health(self, device, alert_type, label, status):
        """Deliver one stateful alert from an analyzer's per-device grade."""
        normalized = str(status or "unknown").lower()
        if normalized == "not_applicable":
            return True
        if normalized == "critical":
            state, severity = "CRITICAL", "CRITICAL"
            title = f"{label} Critical"
            message = f"Processed {label} analysis reports a critical condition"
        elif normalized in {"warning", "warnings", "down", "unplugged", "unknown"}:
            state = "WARNING_UNKNOWN" if normalized == "unknown" else normalized.upper()
            severity = "WARNING"
            title = f"{label} Warning"
            descriptions = {
                "down": "a monitored optical link is down",
                "unplugged": "an expected optical module is unplugged",
                "unknown": "current diagnostics are incomplete or unknown",
            }
            message = (
                f"Processed {label} analysis reports "
                f"{descriptions.get(normalized, 'a warning condition')}"
            )
        elif normalized in {"excellent", "good", "ok"}:
            state, severity = "OK", "RECOVERED"
            title = f"{label} Recovered"
            message = f"Processed {label} analysis is healthy"
        else:
            state, severity = "WARNING_UNSUPPORTED", "WARNING"
            title = f"{label} Status Unknown"
            message = f"Processed {label} analysis returned an unsupported state"

        previous_state = self.get_alert_state(device, alert_type)
        if state == "OK" and previous_state == "UNKNOWN":
            return self.record_state_without_delivery(device, alert_type, state)
        if state == "OK" and not self.config.get('frequency', {}).get(
                'send_recovery', True):
            return self.record_state_without_delivery(device, alert_type, state)
        if not self.should_send_alert(device, alert_type, state):
            return True
        return self.send_stateful_notification(
            title, message, severity, device, alert_type, state
        )

    def check_processed_network_alerts(self, device):
        """Evaluate BER and Optical domains in individual-alert mode."""
        if not self.config.get('alert_types', {}).get('network_alerts', True):
            return True
        results = [
            self._notify_processed_health(
                device, "ber_health", "BER", self.get_device_ber_status(device)
            )
        ]
        run_manifest = getattr(self, "run_manifest", None)
        skipped = (
            set(run_manifest.get("skipped", []))
            if isinstance(run_manifest, dict) else set()
        )
        if "optical" not in skipped:
            results.append(self._notify_processed_health(
                device, "optical_health", "Optical",
                self.get_device_optical_status(device),
            ))
        return all(result is not False for result in results)

    def get_device_flap_counts(self, device, window_seconds=3600):
        """Return per-interface flap deltas recorded inside the time window."""
        asset_stats = self.get_asset_stats([device])
        if not asset_stats:
            return None
        asset_status = asset_stats["statuses"].get(device, "unknown")
        if asset_status == "unreachable":
            print(f"    ⚠️ Skipping link flaps for unreachable device {device}")
            return None
        if asset_status != "successful":
            print(
                f"    ❌ Link-flap data is not current for {device}: "
                f"asset status is {asset_status}"
            )
            self.had_error = True
            return None

        history_file = self.monitor_results / "flap_history.json"
        if not history_file.exists():
            print(f"    ❌ Link-flap history is missing for {device}")
            self.had_error = True
            return None

        try:
            payload = json.loads(history_file.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("link-flap history root must be an object")
            histories = payload.get("flapping_hist")
            if not isinstance(histories, dict):
                raise ValueError("flapping_hist is missing")

            last_update = payload.get("last_update")
            if isinstance(last_update, bool) or not isinstance(
                    last_update, (int, float)):
                raise ValueError("last_update is missing or invalid")
            if not math.isfinite(float(last_update)):
                raise ValueError("last_update is not finite")
            history_age = time.time() - float(last_update)
            if history_age < -300:
                raise ValueError("link-flap history timestamp is in the future")
            max_age_seconds = self.get_data_max_age_seconds()
            if history_age > max_age_seconds:
                raise ValueError(
                    f"link-flap history is stale ({history_age / 60:.1f} minutes old)"
                )

            now = time.time()
            window = max(float(window_seconds), 0)
            cutoff = now - window
            prefix = f"{device}:"
            counts = {}
            for port, entries in histories.items():
                if not isinstance(port, str) or not port.startswith(prefix):
                    continue
                interface = port[len(prefix):]
                total = 0
                if not isinstance(entries, list):
                    raise ValueError(f"invalid flap history for {port}")
                for entry in entries:
                    if not isinstance(entry, (list, tuple)) or len(entry) < 3:
                        raise ValueError(f"invalid flap sample for {port}")
                    timestamp = float(entry[0])
                    flap_count = int(entry[2])
                    if not math.isfinite(timestamp) or timestamp > now + 300:
                        raise ValueError(f"invalid flap timestamp for {port}")
                    if len(entry) >= 5:
                        interval_seconds = max(float(entry[4]), 0.0)
                        if not math.isfinite(interval_seconds):
                            raise ValueError(f"invalid flap interval for {port}")
                        fits_window = now - timestamp + interval_seconds <= window
                    else:
                        # Legacy samples do not say which poll interval produced
                        # the delta. Never assign those deltas to a short window.
                        fits_window = window >= 3600 and timestamp >= cutoff
                    if fits_window and flap_count > 0:
                        total += flap_count
                counts[interface] = total
            return counts
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(f"    ❌ Could not evaluate link flaps for {device}: {exc}")
            self.had_error = True
            return None

    def check_log_alerts(self, device):
        """Check for critical system logs"""
        if not self.config.get('alert_types', {}).get('log_alerts', True):
            return

        counts = self.get_device_log_counts(device)
        if counts is None:
            print(
                f"    ⚠️ Skipping log state for {device}: "
                "processed log summary is unavailable"
            )
            return

        if counts["critical"] > 0:
            current_state = "CRITICAL"
        elif counts["errors"] > 0 or counts["warnings"] > 0:
            current_state = "WARNING"
        else:
            current_state = "OK"

        send_recovery = self.config.get('frequency', {}).get(
            'send_recovery', True
        )
        if current_state == "OK" and not send_recovery:
            self.record_state_without_delivery(
                device, "system_logs", current_state
            )
        elif self.should_send_alert(device, "system_logs", current_state):
            if current_state == "CRITICAL":
                self.send_stateful_notification(
                    "Critical System Logs",
                    f"Found {counts['critical']} critical log entries",
                    "CRITICAL", device, "system_logs", current_state,
                )
            elif current_state == "WARNING":
                self.send_stateful_notification(
                    "System Log Warning",
                    (f"Found {counts['errors']} error and "
                     f"{counts['warnings']} warning log entries"),
                    "WARNING", device, "system_logs", current_state,
                )
            else:
                self.send_stateful_notification(
                    "System Logs Clear",
                    "No critical, error, or warning log entries detected",
                    "RECOVERED", device, "system_logs", current_state,
                )

    def get_inventory_devices(self):
        """Return every configured hostname from devices.yaml in inventory order."""
        devices_file = self.script_dir / "devices.yaml"
        try:
            with open(devices_file, 'r') as f:
                config = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            print(f"❌ Error reading device inventory: {e}")
            return []

        configured = config.get('devices', {})
        if not isinstance(configured, dict):
            print("❌ Invalid devices.yaml: 'devices' must be a mapping")
            return []

        hostnames = []
        for ip, device_config in configured.items():
            if isinstance(device_config, str):
                hostname = re.sub(
                    r'\s+@[A-Za-z0-9_.-]+\s*$', '', device_config
                ).strip()
            elif isinstance(device_config, dict):
                hostname = str(device_config.get('hostname', '')).strip()
            else:
                hostname = ''

            if not hostname:
                print(f"⚠️ Device {ip} has no hostname; excluding it from alert labels")
                continue
            if hostname not in hostnames:
                hostnames.append(hostname)

        return hostnames

    def get_asset_stats(self, devices):
        """Classify every inventory device using the latest assets collection.

        Existing ``successful``/``failed`` fields are retained for message
        compatibility. ``unknown`` and ``stale`` make missing/old evidence
        explicit instead of silently treating it as a success.
        """
        stats = {
            "successful": 0,
            "failed": 0,
            "unreachable": 0,
            "unknown": 0,
            "stale": 0,
            "total": len(devices),
            "statuses": {},
        }
        if (isinstance(self.run_manifest, dict) and
                self.run_manifest.get("pipeline_complete")):
            assets_file = (
                self.monitor_results / ".pipeline-inputs" / "assets.ini"
            )
        else:
            assets_file = self.script_dir / "assets.ini"
        if not assets_file.exists():
            print("❌ assets.ini is missing")
            self.had_error = True
            return {}
        if not self.source_matches_run_manifest("assets", assets_file):
            return {}

        max_age_seconds = self.get_data_max_age_seconds()

        try:
            file_mtime = assets_file.stat().st_mtime
            lines = assets_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            nonempty = [line.strip() for line in lines if line.strip()]
            expected_header = (
                "DEVICE-NAME IP ETH0-MAC SERIAL MODEL RELEASE UPTIME "
                "STATUS LAST-SEEN"
            )
            if len(nonempty) < 3 or nonempty[1] != expected_header:
                raise ValueError("missing or invalid assets header")
            created = datetime.datetime.strptime(
                nonempty[0].removeprefix("Created on "),
                "%Y-%m-%d %H-%M-%S",
            )
            snapshot_time = created.timestamp()
            if abs(file_mtime - snapshot_time) > 120:
                raise ValueError("assets Created time does not match file mtime")
            age = time.time() - snapshot_time
            if age < -300 or age > max_age_seconds:
                raise ValueError("assets snapshot is stale or from the future")

            rows = {}
            allowed = {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}
            for line in nonempty[2:]:
                parts = line.split()
                if len(parts) < 9 or parts[7].upper() not in allowed:
                    raise ValueError(f"invalid assets row: {line}")
                if parts[0] in rows:
                    raise ValueError(f"duplicate assets row: {parts[0]}")
                rows[parts[0]] = parts[7].upper()
            inventory_devices = self.get_inventory_devices()
            expected_devices = set(inventory_devices or devices)
            if set(rows) != expected_devices:
                raise ValueError("assets device set does not match inventory")
        except (OSError, UnicodeError, ValueError) as e:
            print(f"❌ Error reading assets status: {e}")
            self.had_error = True
            return {}

        for device in devices:
            raw_status = rows.get(device)
            if raw_status is None:
                status = "unknown"
            elif raw_status == "OK":
                status = "successful"
            elif raw_status in {"UNREACHABLE", "SSH-FAILED"}:
                status = "unreachable"
            else:
                status = "unknown"

            stats["statuses"][device] = status
            if status == "successful":
                stats["successful"] += 1
            elif status == "unreachable":
                # ``failed`` is the legacy field consumed by the summary.
                stats["failed"] += 1
                stats["unreachable"] += 1
            elif status == "stale":
                stats["stale"] += 1
            else:
                stats["unknown"] += 1

        return stats

    def check_fabric_availability(self):
        """Alert on total fabric loss using assets, independent of monitor reports."""
        devices = self.get_inventory_devices()
        if not devices:
            print("❌ No devices found for availability evaluation")
            self.had_error = True
            return False
        stats = self.get_asset_stats(devices)
        if not stats:
            return False

        available = stats["successful"]
        current_state = "OUTAGE" if available == 0 else "OK"
        last_state = self.get_alert_state("_fabric", "availability")
        if current_state == "OK" and last_state == "UNKNOWN":
            # Establish a baseline without sending a misleading first-run
            # recovery notification.
            return self.record_state_without_delivery(
                "_fabric", "availability", current_state
            )
        if not self.should_send_alert(
                "_fabric", "availability", current_state):
            return True

        if current_state == "OUTAGE":
            unavailable = [
                device for device, status in stats["statuses"].items()
                if status != "successful"
            ]
            message = (
                f"No inventory device is reachable ({len(unavailable)}/"
                f"{len(devices)} unavailable). Devices: "
                + ", ".join(unavailable[:25])
            )
            if len(unavailable) > 25:
                message += f" … and {len(unavailable) - 25} more"
            return self.send_stateful_notification(
                "Fabric Availability Outage", message, "CRITICAL",
                "_fabric", "availability", current_state,
            )

        send_recovery = self.config.get('frequency', {}).get(
            'send_recovery', True
        )
        if not send_recovery:
            return self.record_state_without_delivery(
                "_fabric", "availability", current_state
            )
        return self.send_stateful_notification(
            "Fabric Availability Recovered",
            f"{available}/{len(devices)} inventory devices are reachable again.",
            "RECOVERED", "_fabric", "availability", current_state,
        )

    def check_all_devices(self):
        """Check alerts for all monitored devices"""
        if not self.config:
            if self.notifications_disabled:
                return True
            print("❌ Notifications configuration could not be loaded")
            return False

        if self.monitor_is_stale():
            return False
        self.run_manifest = self.load_run_manifest()
        if self.run_manifest is False:
            return False
            
        # Get alert strategy
        alert_strategy = self.config.get('alert_strategy', {})
        mode = alert_strategy.get('mode', 'summary')
        
        print(f"Checking alerts for all devices (mode: {mode})...")
        
        # devices.yaml is the source of truth. Fall back to collected files only
        # for older/misconfigured installations where inventory cannot be read.
        devices = self.get_inventory_devices()
        if not devices:
            hardware_dir = self.monitor_results / "hardware-data"
            device_files = glob.glob(str(hardware_dir / "*_hardware.txt"))
            devices = [os.path.basename(f).replace('_hardware.txt', '') for f in device_files]
            if devices:
                print("⚠️ Using collected hardware files because devices.yaml is empty")
        
        if not devices:
            print("❌ No devices found in inventory or collected hardware data")
            self.had_error = True
            return False

        manifest_device_count = self.run_manifest.get("device_count")
        if manifest_device_count != len(devices):
            print(
                "❌ Current-run manifest device count does not match inventory "
                f"({manifest_device_count} != {len(devices)})"
            )
            self.had_error = True
            return False
            
        print(f"Found {len(devices)} devices to check")
        
        if mode == "summary":
            if not self.send_summary_alert(devices):
                self.had_error = True
        elif mode == "change_only":
            self.check_changes_only(devices)
        elif mode == "immediate":
            self.check_immediate_alerts(devices)
        else:
            print(f"❌ Unsupported alert strategy mode: {mode!r}")
            self.had_error = True
        
        print("Alert check completed")
        return not self.had_error

    def check_immediate_alerts(self, devices):
        """Run every enabled alert domain using individual stateful alerts."""
        for device in devices:
            print(f"  📍 Checking {device}...")
            try:
                self.check_hardware_alerts(device)
                self.check_system_alerts(device)
                self.check_network_alerts(device)
                self.check_log_alerts(device)
            except Exception as exc:
                print(f"    ❌ Error checking {device}: {exc}")
                self.had_error = True
                continue
        if not self.check_lldp_alerts():
            self.had_error = True
        if not self.check_duplicate_alerts():
            self.had_error = True

    def send_summary_alert(self, devices, *, include_schedule=True):
        """Send dashboard-style summary alert"""
        print("Generating network health summary...")
        if (not isinstance(self.run_manifest, dict) or
                not self.run_manifest.get("pipeline_complete")):
            print(
                "❌ Summary was not sent because assets, LLDP and monitor "
                "outputs were not produced by one complete pipeline"
            )
            return False
        
        # A missing or malformed report is unknown evidence, not a healthy zero.
        total_devices = len(devices)
        hardware_stats = self.get_stats_from_html("hardware-analysis.html")
        log_stats = self.get_log_stats_from_json()
        bgp_stats = self.get_stats_from_html("bgp-analysis.html")
        asset_stats = self.get_asset_stats(devices)
        ber_stats = self.get_stats_from_html("ber-analysis.html")
        flap_stats = self.get_stats_from_html("link-flap-analysis.html")
        lldp_stats = self.get_lldp_stats_from_ini()
        duplicate_stats = self.get_duplicate_stats()

        skipped = set()
        if isinstance(self.run_manifest, dict):
            skipped = set(self.run_manifest.get("skipped", []))
        optical_skipped = "optical" in skipped
        optical_stats = (
            None if optical_skipped
            else self.get_stats_from_html("optical-analysis.html")
        )

        required_sources = {
            "assets.ini": asset_stats,
            "hardware-analysis.html": hardware_stats,
            "log_summary.json": log_stats,
            "bgp-analysis.html": bgp_stats,
            "ber-analysis.html": ber_stats,
            "link-flap-analysis.html": flap_stats,
            "lldp_results.ini": lldp_stats,
            "duplicate-analysis.html": duplicate_stats,
        }
        if not optical_skipped:
            required_sources["optical-analysis.html"] = optical_stats
        missing_sources = [
            name for name, stats in required_sources.items() if not stats
        ]
        if missing_sources:
            print(
                "❌ Summary was not sent because required report data is "
                f"missing or invalid: {', '.join(missing_sources)}"
            )
            return False
        
        critical_issues = []
        warning_issues = []
        
        # Generate an aggregate open-issues summary. Warning-only reports must
        # not be sent as green/healthy.
        if hardware_stats.get('critical', 0) > 0:
            critical_issues.append(f"🔥 Hardware: {hardware_stats['critical']} devices with critical issues")
        if hardware_stats.get('warnings', 0) > 0:
            warning_issues.append(
                f"Hardware: {hardware_stats['warnings']} devices with warnings"
            )
        if hardware_stats.get('unknown', 0) > 0:
            warning_issues.append(
                f"Hardware: {hardware_stats['unknown']} devices with unknown telemetry"
            )
        
        if log_stats.get('critical', 0) > 0:
            critical_issues.append(f"Logs: {log_stats['critical']} critical log entries")
        if log_stats.get('warnings', 0) > 0:
            warning_issues.append(f"Logs: {log_stats['warnings']} warning entries")
        if log_stats.get('errors', 0) > 0:
            warning_issues.append(f"Logs: {log_stats['errors']} error entries")
        
        if bgp_stats.get('critical', 0) > 0:
            critical_issues.append(
                f"BGP: {bgp_stats['critical']} critical neighbors"
            )
        if bgp_stats.get('warnings', 0) > 0:
            warning_issues.append(
                f"BGP: {bgp_stats['warnings']} warning-state neighbors"
            )
        if bgp_stats.get('stale', 0) > 0:
            warning_issues.append(f"BGP: {bgp_stats['stale']} device collections stale")
        if bgp_stats.get('unknown', 0) > 0:
            warning_issues.append(f"BGP: {bgp_stats['unknown']} device collections unknown")
        
        if optical_stats and optical_stats.get('critical', 0) > 0:
            critical_issues.append(f"Optical: {optical_stats['critical']} ports with critical issues")
        if optical_stats and optical_stats.get('warnings', 0) > 0:
            warning_issues.append(
                f"Optical: {optical_stats['warnings']} ports with warnings"
            )
        if optical_stats and optical_stats.get('down', 0) > 0:
            warning_issues.append(
                f"Optical: {optical_stats['down']} ports with no receive light/down state"
            )
        if optical_stats and optical_stats.get('unplugged', 0) > 0:
            warning_issues.append(
                f"Optical: {optical_stats['unplugged']} expected modules unplugged"
            )
        if optical_stats and optical_stats.get('unknown', 0) > 0:
            warning_issues.append(
                f"Optical: {optical_stats['unknown']} ports with unknown diagnostics"
            )
        
        if ber_stats.get('critical', 0) > 0:
            critical_issues.append(f"BER: {ber_stats['critical']} ports with critical errors")
        if ber_stats.get('warnings', 0) > 0:
            warning_issues.append(
                f"BER: {ber_stats['warnings']} ports with warnings"
            )
        if ber_stats.get('unknown', 0) > 0:
            warning_issues.append(
                f"BER: {ber_stats['unknown']} ports awaiting a complete traffic sample"
            )
        
        if flap_stats.get('critical', 0) > 0:
            critical_issues.append(f"Link Flap: {flap_stats['critical']} problematic ports")
        if flap_stats.get('warnings', 0) > 0:
            warning_issues.append(
                f"Link Flap: {flap_stats['warnings']} warning ports"
            )

        if asset_stats.get('unreachable', 0) > 0:
            critical_issues.append(
                f"Assets: {asset_stats['unreachable']} devices unreachable"
            )
        if asset_stats.get('unknown', 0) > 0:
            warning_issues.append(
                f"Assets: {asset_stats['unknown']} devices have unknown status"
            )
        if asset_stats.get('stale', 0) > 0:
            warning_issues.append(
                f"Assets: {asset_stats['stale']} devices have stale status data"
            )
        
        if lldp_stats['failed'] > 0:
            critical_issues.append(f"🔗 LLDP Topology: {lldp_stats['failed']} failed connections")
        if lldp_stats['warnings'] > 0:
            warning_issues.append(
                f"LLDP Topology: {lldp_stats['warnings']} warning connections"
            )
        if lldp_stats['no_info'] > 0:
            warning_issues.append(
                f"LLDP Topology: {lldp_stats['no_info']} connections without current information"
            )

        if duplicate_stats['active'] > 0:
            critical_issues.append(
                f"Duplicate IP: {duplicate_stats['active']} active conflicts"
            )
        if duplicate_stats['quiesced'] > 0:
            warning_issues.append(
                f"Duplicate IP: {duplicate_stats['quiesced']} quiesced conflicts"
            )

        report_stats = {
            "Hardware": hardware_stats,
            "Logs": log_stats,
            "BGP": bgp_stats,
            "BER": ber_stats,
            "Link Flap": flap_stats,
            "Duplicate IP": duplicate_stats,
        }
        if optical_stats:
            report_stats["Optical"] = optical_stats
        for label, report in report_stats.items():
            if report.get("coverage_partial"):
                expected = report.get("coverage_expected")
                current = report.get("coverage_current")
                suffix = (
                    f" ({current}/{expected} devices current)"
                    if expected is not None and current is not None else ""
                )
                warning_issues.append(f"{label}: partial collection coverage{suffix}")
        
        # Create summary signature for state tracking (include optical and LLDP)
        optical_signature = (
            "skipped" if optical_skipped else
            f"{optical_stats['excellent']}:{optical_stats['good']}:"
            f"{optical_stats['warnings']}:{optical_stats['critical']}:"
            f"{optical_stats.get('down', 0)}:"
            f"{optical_stats.get('unplugged', 0)}:"
            f"{optical_stats.get('unknown', 0)}:"
            f"{int(bool(optical_stats.get('coverage_partial')))}"
        )
        summary_signature = "_".join(map(str, (
            total_devices,
            hardware_stats['excellent'], hardware_stats['good'],
            hardware_stats['warnings'], hardware_stats['critical'],
            hardware_stats.get('unknown', 0),
            int(bool(hardware_stats.get('coverage_partial'))),
            log_stats['critical'], log_stats['warnings'], log_stats['errors'],
            int(bool(log_stats.get('coverage_partial'))),
            bgp_stats['established'], bgp_stats['down'],
            bgp_stats.get('warnings', 0), bgp_stats.get('critical', 0),
            bgp_stats.get('stale', 0), bgp_stats.get('unknown', 0),
            int(bool(bgp_stats.get('coverage_partial'))),
            asset_stats['successful'], asset_stats['failed'],
            asset_stats['unknown'], asset_stats['stale'],
            ber_stats['excellent'], ber_stats['good'], ber_stats['warnings'],
            ber_stats['critical'], ber_stats.get('unknown', 0),
            int(bool(ber_stats.get('coverage_partial'))),
            flap_stats['stable'], flap_stats['warnings'],
            flap_stats['critical'],
            int(bool(flap_stats.get('coverage_partial'))), optical_signature,
            lldp_stats['successful'], lldp_stats['failed'],
            lldp_stats['warnings'], lldp_stats['no_info'],
            duplicate_stats['active'], duplicate_stats['quiesced'],
            duplicate_stats.get('coverage_expected'),
            duplicate_stats.get('coverage_current'),
            duplicate_stats.get('coverage_failures', 0),
            int(bool(duplicate_stats.get('coverage_partial'))),
        )))
        
        # Check if summary changed or it's scheduled time (critical issues don't force immediate send in summary mode)
        if self.should_send_summary_alert(
                summary_signature, include_schedule=include_schedule):
            server_url = self.config.get('notifications', {}).get('server_url', 'http://localhost')
            if optical_skipped:
                optical_section = "Optical Diagnostics Analysis:\n\nSkipped by configuration"
            else:
                optical_section = (
                    "Optical Diagnostics Analysis:\n\n"
                    f"Excellent: {optical_stats['excellent']}     "
                    f"Good: {optical_stats['good']}     "
                    f"Warning: {optical_stats['warnings']}     "
                    f"Down: {optical_stats.get('down', 0)}     "
                    f"Unplugged: {optical_stats.get('unplugged', 0)}     "
                    f"Unknown: {optical_stats.get('unknown', 0)}     "
                    f"Critical: {optical_stats['critical']}"
                )
            
            # Create clean dashboard-style message with spacing
            title = "Network Health Summary"
            message = f"""

Total Devices: {total_devices}

─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Hardware Health Analysis:


Excellent: {hardware_stats['excellent']}     🔵 Good: {hardware_stats['good']}     Warnings: {hardware_stats['warnings']}     Critical: {hardware_stats['critical']}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Log Analysis Results:


Critical: {log_stats['critical']}     Warnings: {log_stats['warnings']}     🔵 Errors: {log_stats['errors']}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Asset Analysis Results:


Successful: {asset_stats['successful']}     Failed: {asset_stats['failed']}     Unknown: {asset_stats['unknown']}     Stale: {asset_stats['stale']}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

LLDP Topology Analysis Results:


Successful: {lldp_stats['successful']}     Failed: {lldp_stats['failed']}     Warnings: {lldp_stats['warnings']}     🔵 No Info: {lldp_stats['no_info']}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

BGP Analysis Results:


Established: {bgp_stats['established']}     Down: {bgp_stats['down']}     Warning: {bgp_stats.get('warnings', 0)}     Critical: {bgp_stats.get('critical', 0)}     Stale: {bgp_stats.get('stale', 0)}     Unknown: {bgp_stats.get('unknown', 0)}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Link Flap Analysis Results:


Stable: {flap_stats['stable']}     Warnings: {flap_stats['warnings']}     Critical: {flap_stats['critical']}

─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

{optical_section}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

BER Analysis Results:


Excellent: {ber_stats['excellent']}     Good: {ber_stats['good']}     Warnings: {ber_stats['warnings']}     Critical: {ber_stats['critical']}     Awaiting Sample: {ber_stats.get('unknown', 0)}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Duplicate IP Analysis Results:


Active: {duplicate_stats['active']}     Quiesced: {duplicate_stats['quiesced']}     Coverage: {duplicate_stats.get('coverage_current')}/{duplicate_stats.get('coverage_expected')}

"""
            open_issues = (
                [f"[CRITICAL] {issue}" for issue in critical_issues]
                + [f"[WARNING] {issue}" for issue in warning_issues]
            )
            if open_issues:
                message += (
                    "\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──"
                    "\n\nOpen Issues:\n" + "\n".join(open_issues[:5])
                )
                if len(open_issues) > 5:
                    message += f"\n... and {len(open_issues) - 5} more issues"
                    
            message += f"\n\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──\n\n[View Full Dashboard]({server_url})"
            
            # Send notification
            if critical_issues:
                severity = "CRITICAL"
            elif warning_issues:
                severity = "WARNING"
            else:
                severity = "INFO"
            self.record_alert_attempt("network_summary", "last_summary")
            delivered = self.send_notification(
                title, message, severity, "Network Summary"
            )

            # A failed summary remains pending and will be retried. Neither its
            # signature nor its schedule marker may claim a delivery occurred.
            if delivered:
                persisted = self.record_alert_delivery(
                    "network_summary", "last_summary", summary_signature
                )
                due_slot = self.due_summary_slot() if include_schedule else None
                if due_slot is not None:
                    persisted = self.set_alert_state(
                        "network_summary", "last_summary_time", due_slot
                    ) and persisted
                return delivered and persisted
            return False

        return True

    def check_lldp_alerts(self):
        """Send one fabric-wide stateful alert for the current LLDP report."""
        if not self.config.get('alert_types', {}).get('topology_alerts', True):
            return True
        stats = self.get_lldp_stats_from_ini()
        if not stats:
            return False

        failed = stats["failed"]
        warnings = stats["warnings"]
        no_info = stats["no_info"]
        if failed:
            severity, notification_severity = "CRITICAL", "CRITICAL"
            title = "LLDP Topology Failures"
        elif warnings or no_info:
            severity, notification_severity = "WARNING", "WARNING"
            title = "LLDP Topology Warning"
        else:
            severity, notification_severity = "OK", "RECOVERED"
            title = "LLDP Topology Recovered"
        state = f"{severity}:{failed}:{warnings}:{no_info}"
        previous_state = self.get_alert_state("_fabric", "lldp_topology")
        if severity == "OK" and previous_state == "UNKNOWN":
            return self.record_state_without_delivery(
                "_fabric", "lldp_topology", state
            )
        if severity == "OK" and not self.config.get('frequency', {}).get(
                'send_recovery', True):
            return self.record_state_without_delivery(
                "_fabric", "lldp_topology", state
            )
        if not self.should_send_alert("_fabric", "lldp_topology", state):
            return True
        message = (
            f"Failed connections: {failed}; warning connections: {warnings}; "
            f"connections without current information: {no_info}."
        )
        return self.send_stateful_notification(
            title, message, notification_severity, "_fabric",
            "lldp_topology", state,
        )

    def check_duplicate_alerts(self):
        """Send one fabric-wide stateful alert for authoritative IP conflicts."""
        stats = self.get_duplicate_stats()
        if not stats:
            self.had_error = True
            return False

        active = stats["active"]
        quiesced = stats["quiesced"]
        partial = bool(stats.get("coverage_partial"))
        if active:
            severity = "CRITICAL"
            title = "Active Duplicate IP Conflicts"
        elif quiesced or partial:
            severity = "WARNING"
            title = (
                "Quiesced Duplicate IP Conflicts"
                if quiesced else "Duplicate IP Coverage Partial"
            )
        else:
            severity = "OK"
            title = "Duplicate IP Conflicts Cleared"

        state = ":".join(map(str, (
            severity, active, quiesced,
            stats.get("coverage_current"), stats.get("coverage_expected"),
            int(partial),
        )))
        previous_state = self.get_alert_state("_fabric", "duplicate_ip")

        # Establish a clean first-run baseline without sending a fake recovery.
        if severity == "OK" and previous_state == "UNKNOWN":
            return self.record_state_without_delivery(
                "_fabric", "duplicate_ip", state
            )
        if not self.should_send_alert("_fabric", "duplicate_ip", state):
            return True

        coverage = (
            f"{stats.get('coverage_current')}/{stats.get('coverage_expected')}"
        )
        message = (
            f"Active duplicate IP conflicts: {active}; "
            f"quiesced conflicts: {quiesced}; collection coverage: {coverage}."
        )
        if severity == "OK":
            send_recovery = self.config.get('frequency', {}).get(
                'send_recovery', True
            )
            if not send_recovery:
                return self.record_state_without_delivery(
                    "_fabric", "duplicate_ip", state
                )
            notification_severity = "RECOVERED"
        else:
            notification_severity = severity

        return self.send_stateful_notification(
            title, message, notification_severity, "_fabric",
            "duplicate_ip", state,
        )

    def should_send_summary_alert(self, current_signature, *, include_schedule=True):
        """Check if summary should be sent based on changes or schedule"""
        retry_interval = self.get_frequency_seconds('retry_interval_minutes', 5)
        last_attempt = self._read_marker_time(
            "network_summary", "last_summary", "attempt"
        )
        if last_attempt is not None and time.time() - last_attempt < retry_interval:
            return False

        last_signature = self.get_alert_state("network_summary", "last_summary")
        
        # Send if data changed
        if current_signature != last_signature:
            return True
            
        # Send if a scheduled slot was reached and not yet sent for today
        if include_schedule:
            due_slot = self.due_summary_slot()
            if due_slot is not None:
                last_summary_time = self.get_alert_state("network_summary", "last_summary_time")

                if due_slot != last_summary_time:
                    return True

        return False

    def get_device_hardware_status(self, device):
        """Get hardware health status for a device from JSON history"""
        try:
            # Read from processed hardware_history.json
            hardware_history_file = self.monitor_results / "hardware_history.json"
            if not hardware_history_file.exists():
                return "unknown"
                
            with open(hardware_history_file, 'r') as f:
                hardware_data = json.load(f)
            
            # Get latest hardware entry for this device
            device_history = hardware_data.get("hardware_history", {}).get(device, [])
            if device_history and len(device_history) > 0:
                latest_entry = device_history[-1]  # Get most recent entry
                overall_grade = latest_entry.get("overall_grade", "UNKNOWN")
                return overall_grade.lower()
            
            return "unknown"
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
            print(f"    ❌ Error reading hardware status for {device}: {e}")
            self.had_error = True
            return "unknown"

    def get_device_log_counts(self, device):
        """Get log severity counts for a device from processed summary"""
        try:
            # Read from processed log_summary.json instead of raw files
            summary_file = self.monitor_results / "log_summary.json"
            if not summary_file.exists():
                return None
                
            with open(summary_file, 'r') as f:
                summary_data = json.load(f)
            
            device_counts = summary_data.get("device_counts", {}).get(device)
            if device_counts:
                # Map to expected format
                return {
                    "critical": device_counts.get("critical", 0),
                    "warnings": device_counts.get("warning", 0), 
                    "errors": device_counts.get("error", 0),
                    "info": device_counts.get("info", 0)
                }
            return None
        except:
            return None

    def get_device_bgp_status(self, device):
        """Get BGP status for a device from processed summary"""
        try:
            # Read from processed bgp_history.json
            bgp_history_file = self.monitor_results / "bgp_history.json"
            if not bgp_history_file.exists():
                return "unknown"
                
            with open(bgp_history_file, 'r') as f:
                bgp_data = json.load(f)
            if not isinstance(bgp_data, dict):
                raise ValueError("BGP history root must be an object")
            
            # Get latest BGP stats for this device. Older files may not contain
            # data_status; those remain compatible and are treated as current.
            current_stats = bgp_data.get("current_bgp_stats", {})
            if not isinstance(current_stats, dict):
                raise ValueError("current_bgp_stats must be an object")
            device_bgp = current_stats.get(device, {})
            if device_bgp and not isinstance(device_bgp, dict):
                raise ValueError(f"invalid BGP status record for {device}")
            if device_bgp:
                data_status = device_bgp.get("data_status", "current")
                if data_status in {"stale", "unknown"}:
                    return data_status
                critical_neighbors = int(
                    device_bgp.get("critical_neighbors", 0) or 0
                )
                warning_neighbors = int(
                    device_bgp.get("warning_neighbors", 0) or 0
                )
                if critical_neighbors > 0:
                    return "critical"
                if warning_neighbors > 0:
                    return "warning"

                # Legacy history did not persist severity buckets.  Keep its
                # prior fail-closed behavior until one new analysis is saved.
                if "critical_neighbors" not in device_bgp:
                    down_neighbors = int(
                        device_bgp.get("down_neighbors", 0) or 0
                    )
                    if down_neighbors > 0:
                        return "critical"
                return "established"
            
            return "unknown"
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(f"    ❌ Error reading BGP status for {device}: {exc}")
            self.had_error = True
            return "unknown"

    def get_device_asset_status(self, device):
        """Get asset status for a device"""
        try:
            # Check if device exists in monitoring results (simple check)
            device_file = self.monitor_results / f"{device}.html"
            if device_file.exists():
                return "successful"
            else:
                return "failed"
        except:
            return "failed"

    def get_device_ber_status(self, device):
        """Get BER status for a device"""
        try:
            history_file = self.monitor_results / "ber_history.json"
            if not history_file.exists():
                return "unknown"
            payload = json.loads(history_file.read_text(encoding="utf-8"))
            current = payload.get("current_ber_stats", {})
            if not isinstance(current, dict):
                raise ValueError("current_ber_stats must be an object")
            grades = []
            for port_name, port_stats in current.items():
                if (not isinstance(port_name, str) or
                        port_name.split(":", 1)[0] != device or
                        not isinstance(port_stats, dict)):
                    continue
                grade = str(
                    port_stats.get("status")
                    or port_stats.get("effective_grade")
                    or port_stats.get("grade")
                    or "unknown"
                ).lower()
                grades.append(grade)
            if not grades:
                return "not_applicable"
            priority = {
                "critical": 4, "warning": 3, "warnings": 3,
                "unknown": 2, "good": 1, "excellent": 0,
            }
            result = max(grades, key=lambda value: priority.get(value, 2))
            return "warnings" if result == "warning" else result
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(f"    ❌ Error reading BER status for {device}: {exc}")
            self.had_error = True
            return "unknown"

    def get_device_flap_status(self, device):
        """Get link flap status for a device from processed summary"""
        counts = self.get_device_flap_counts(device, window_seconds=3600)
        if counts is None:
            return "unknown"
        thresholds = self.config.get('thresholds', {}).get('network', {})
        try:
            warning = float(thresholds.get('link_flaps_per_hour', 10))
            critical = float(thresholds.get('link_flaps_critical', 20))
        except (TypeError, ValueError):
            warning, critical = 10, 20
        if any(count >= critical for count in counts.values()):
            return "critical"
        if any(count >= warning for count in counts.values()):
            return "warnings"
        return "stable"
    
    def get_device_optical_status(self, device):
        """Get optical diagnostics status for a device from processed summary"""
        try:
            # Read from processed optical_history.json
            optical_history_file = self.monitor_results / "optical_history.json"
            if not optical_history_file.exists():
                return "unknown"
                
            with open(optical_history_file, 'r') as f:
                optical_data = json.load(f)

            current_stats = optical_data.get("current_optical_stats", {})
            if not isinstance(current_stats, dict):
                raise ValueError("current_optical_stats must be an object")
            health_values = []
            for port_name, stats in current_stats.items():
                if (not isinstance(port_name, str) or
                        port_name.split(":", 1)[0] != device or
                        not isinstance(stats, dict)):
                    continue
                health_values.append(
                    str(stats.get("health_status", "unknown")).lower()
                )
            if not health_values:
                return "not_applicable"
            priority = {
                "critical": 7, "down": 6, "warning": 5,
                "unknown": 4, "unplugged": 3, "good": 2,
                "excellent": 1,
            }
            result = max(
                health_values, key=lambda value: priority.get(value, 3)
            )
            if result == "warning":
                return "warnings"
            return result
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(f"    ❌ Error reading optical status for {device}: {exc}")
            self.had_error = True
            return "unknown"

    def analyze_lldp_topology(self):
        """Analyze LLDP topology data like the web frontend does"""
        try:
            # Check for lldp_results.ini in different locations
            lldp_file = None
            possible_paths = [
                self.cable_check_dir.parent / "html" / "lldp_results.ini",  # main html dir
                self.monitor_results.parent / "html" / "lldp_results.ini", # relative to monitor-results
                self.cable_check_dir / "lldp-results" / "lldp_results.ini", # lldp-results dir
                self.monitor_results / "lldp_results.ini"  # monitor-results dir
            ]
            
            for path in possible_paths:
                if path.exists():
                    lldp_file = path
                    break
                    
            if not lldp_file:
                print(f"    ❌ No lldp_results.ini found in any expected location")
                return {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
            
            with open(lldp_file, 'r') as f:
                data = f.read()
            
            # Parse LLDP data similar to the frontend JavaScript
            lines = data.split('\n')
            connections = []
            current_device = ''
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                parts = line.split('\t')
                if len(parts) == 1:
                    # Device name line
                    current_device = parts[0]
                elif len(parts) >= 6 and current_device:
                    # Connection line
                    connection = {
                        'localDevice': current_device,
                        'localPort': parts[0],
                        'expectedDevice': parts[1] if parts[1] != 'N/A' else None,
                        'expectedPort': parts[2] if parts[2] != 'N/A' else None,
                        'actualDevice': parts[3] if parts[3] != 'N/A' else None,
                        'actualPort': parts[4] if parts[4] != 'N/A' else None,
                        'lldpStatus': parts[5]
                    }
                    connections.append(connection)
            
            # Count by status (replicate frontend logic)
            stats = {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
            
            for connection in connections:
                status = self.determine_lldp_status(connection)
                if status == 'SUCCESS':
                    stats["successful"] += 1
                elif status == 'FAILED':
                    stats["failed"] += 1
                elif status == 'WARNING':
                    stats["warnings"] += 1
                elif status == 'NO INFO':
                    stats["no_info"] += 1
            
            return stats
            
        except Exception as e:
            print(f"    ❌ Error analyzing LLDP topology: {e}")
            return {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
    
    def determine_lldp_status(self, connection):
        """Determine LLDP connection status (replicate frontend logic)"""
        lldp_status = connection.get('lldpStatus', '').upper()
        
        if lldp_status == 'SUCCESS':
            return 'SUCCESS'
        elif lldp_status == 'NO LLDP INFO':
            return 'NO INFO'
        elif lldp_status in ['MISSING FROM EXPECTED', 'EXTRA CONNECTION']:
            return 'WARNING'
        else:
            # Check if it's a connection mismatch
            expected_device = connection.get('expectedDevice')
            expected_port = connection.get('expectedPort') 
            actual_device = connection.get('actualDevice')
            actual_port = connection.get('actualPort')
            
            if (expected_device and actual_device and 
                (expected_device != actual_device or expected_port != actual_port)):
                return 'FAILED'
            else:
                return 'WARNING'

    def get_stats_from_html(self, html_filename):
        """Extract statistics from HTML analysis files using specific element IDs"""
        try:
            html_file = self.monitor_results / html_filename
            if not html_file.exists():
                return {}
                
            with open(html_file, 'r', encoding='utf-8') as f:
                content = f.read()

            collection_status = (
                self.extract_attribute_value(
                    content, "data-collection-status"
                ) or self.extract_attribute_value(
                    content, "data-coverage-status"
                ) or "current"
            ).lower()
            if collection_status == "unavailable":
                print(
                    f"    ❌ {html_filename} has no current device telemetry"
                )
                self.had_error = True
                return {}

            expected = self.extract_attribute_int(
                content, "data-coverage-expected"
            )
            if expected is None:
                expected = self.extract_attribute_int(
                    content, "data-expected-devices"
                )
            current = self.extract_attribute_int(
                content, "data-coverage-current"
            )
            if current is None:
                current = self.extract_attribute_int(
                    content, "data-current-devices"
                )
            coverage_partial = (
                self.extract_attribute_value(
                    content, "data-coverage-partial"
                ) or ""
            ).lower() == "true"
            if collection_status == "partial":
                coverage_partial = True
            if expected is not None and current is not None and current < expected:
                coverage_partial = True

            # Extract numbers from stable element IDs and hidden metadata.  The
            # metadata does not change the report layout; it prevents an
            # unreachable or partially collected domain being read as healthy.
            stats = {}
            required_metrics = []
            
            if "hardware" in html_filename:
                excellent = self.extract_element_value(content, 'excellent-devices')
                good = self.extract_element_value(content, 'good-devices')
                warnings = self.extract_element_value(content, 'warning-devices')
                critical = self.extract_element_value(content, 'critical-devices')
                unknown = self.extract_attribute_int(
                    content, 'data-unknown-devices'
                )
                if unknown is None:
                    unknown = 0
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical,
                    "unknown": unknown,
                }
                required_metrics = ["excellent", "good", "warnings", "critical"]
                
            elif "optical" in html_filename:
                excellent = self.extract_element_value(content, 'excellent-ports')
                good = self.extract_element_value(content, 'good-ports')
                warnings = self.extract_element_value(content, 'warning-ports')
                critical = self.extract_element_value(content, 'critical-ports')
                down = self.extract_element_value(content, 'down-ports')
                if down is None:
                    # Backward compatibility with reports generated before
                    # DOWN received its own summary card.
                    down = 0
                total = self.extract_element_value(content, 'total-ports')
                unplugged = self.extract_attribute_int(
                    content, 'data-optical-unplugged'
                )
                unknown = self.extract_attribute_int(
                    content, 'data-optical-unknown'
                )
                # One pre-upgrade report may lack the machine metadata. Its
                # table rows still carry the exact category and avoid folding
                # unplugged cages into UNKNOWN diagnostics.
                if unplugged is None:
                    unplugged = len(re.findall(
                        r'<tr\b[^>]*\bdata-health=["\']unplugged["\']',
                        content, re.IGNORECASE,
                    ))
                if unknown is None:
                    unknown = len(re.findall(
                        r'<tr\b[^>]*\bdata-health=["\']unknown["\']',
                        content, re.IGNORECASE,
                    ))
                known = [excellent, good, warnings, critical, down,
                         unplugged, unknown]
                if (total is not None and all(value is not None for value in known)
                        and sum(known) != total):
                    unknown = None
                if unknown and unknown > 0:
                    coverage_partial = True
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical,
                    "down": down,
                    "unplugged": unplugged,
                    "unknown": unknown,
                }
                required_metrics = [
                    "excellent", "good", "warnings", "critical",
                    "unplugged", "unknown"
                ]
                
            elif "ber" in html_filename:
                excellent = self.extract_element_value(content, 'excellent-ports')
                good = self.extract_element_value(content, 'good-ports')
                warnings = self.extract_element_value(content, 'warning-ports')
                critical = self.extract_element_value(content, 'critical-ports')
                unknown = self.extract_element_value(content, 'unknown-ports')
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical,
                    "unknown": unknown,
                }
                required_metrics = [
                    "excellent", "good", "warnings", "critical", "unknown"
                ]
                
            elif "link-flap" in html_filename:
                stable = self.extract_element_value(content, 'stable-ports')
                problematic = self.extract_element_value(content, 'problematic-ports')
                warnings = self.extract_attribute_int(
                    content, 'data-warning-ports'
                )
                critical = self.extract_attribute_int(
                    content, 'data-critical-ports'
                )
                if warnings is None and critical is None:
                    # Legacy reports had a single problematic bucket.
                    warnings, critical = 0, problematic
                
                stats = {
                    "stable": stable,
                    "warnings": warnings,
                    "critical": critical,
                }
                required_metrics = ["stable", "warnings", "critical"]
                
            elif "bgp" in html_filename:
                established = self.extract_element_value(content, 'established-neighbors')
                down = self.extract_element_value(content, 'down-neighbors')
                stale = self.extract_element_value(content, 'stale-devices')
                unknown = self.extract_element_value(content, 'unknown-devices')
                warnings = self.extract_attribute_int(
                    content, 'data-warning-neighbors'
                )
                critical = self.extract_attribute_int(
                    content, 'data-critical-neighbors'
                )
                if warnings is None and critical is None:
                    warnings, critical = 0, down
                bgp_current = self.extract_attribute_int(
                    content, 'data-current-bgp-devices'
                )
                evpn_current = self.extract_attribute_int(
                    content, 'data-current-evpn-devices'
                )
                if expected is not None:
                    available_counts = [
                        value for value in (bgp_current, evpn_current)
                        if value is not None
                    ]
                    if available_counts:
                        current = min(available_counts)
                        coverage_partial = coverage_partial or current < expected
                
                stats = {
                    "established": established,
                    "down": down,
                    "warnings": warnings,
                    "critical": critical,
                    "stale": stale,
                    "unknown": unknown,
                }
                required_metrics = [
                    "established", "down", "warnings", "critical",
                    "stale", "unknown",
                ]

            missing_metrics = [
                name for name in required_metrics if stats.get(name) is None
            ]
            if not stats or missing_metrics:
                if missing_metrics:
                    print(
                        f"    ❌ Missing metrics in {html_filename}: "
                        f"{', '.join(missing_metrics)}"
                    )
                self.had_error = True
                return {}
            stats.update({
                "collection_status": collection_status,
                "coverage_partial": coverage_partial,
                "coverage_expected": expected,
                "coverage_current": current,
            })
            return stats
            
        except Exception as e:
            print(f"    ❌ Error reading stats from {html_filename}: {e}")
            self.had_error = True
            return {}

    def get_duplicate_stats(self):
        """Read the duplicate report's authoritative machine summary."""
        report = self.monitor_results / "duplicate-analysis.html"
        if not report.is_file():
            print(f"    ❌ Duplicate report is missing: {report}")
            self.had_error = True
            return {}
        try:
            content = report.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"    ❌ Could not read duplicate report: {exc}")
            self.had_error = True
            return {}

        collection_status = (
            self.extract_attribute_value(content, "data-collection-status")
            or ""
        ).lower()
        active = self.extract_attribute_int(
            content, "data-confirmed-ip-active"
        )
        quiesced = self.extract_attribute_int(content, "data-ip-quiesced")
        expected = self.extract_attribute_int(content, "data-coverage-expected")
        current = self.extract_attribute_int(content, "data-coverage-current")
        failures = self.extract_attribute_int(content, "data-coverage-failures")
        partial_text = (
            self.extract_attribute_value(content, "data-coverage-partial")
            or ""
        ).lower()

        required = (active, quiesced, expected, current, failures)
        if collection_status not in {"current", "partial"} or any(
                value is None for value in required):
            print("    ❌ Duplicate report has no valid current machine summary")
            self.had_error = True
            return {}
        if partial_text not in {"true", "false"}:
            print("    ❌ Duplicate report has invalid coverage metadata")
            self.had_error = True
            return {}

        coverage_partial = (
            collection_status == "partial"
            or partial_text == "true"
            or failures > 0
            or current < expected
        )
        return {
            "active": active,
            "quiesced": quiesced,
            "coverage_expected": expected,
            "coverage_current": current,
            "coverage_failures": failures,
            "coverage_partial": coverage_partial,
            "collection_status": collection_status,
        }

    def extract_attribute_value(self, html_content, attribute):
        """Return one quoted machine-readable HTML attribute value."""
        try:
            pattern = rf'\b{re.escape(attribute)}="([^"]*)"'
            match = re.search(pattern, html_content, re.IGNORECASE)
            return match.group(1) if match else None
        except (TypeError, re.error):
            return None

    def extract_attribute_int(self, html_content, attribute):
        """Return a non-negative integer HTML attribute, or None."""
        value = self.extract_attribute_value(html_content, attribute)
        if value is None or not re.fullmatch(r'\d+', value.strip()):
            return None
        return int(value)

    def extract_element_value(self, html_content, element_id):
        """Extract numeric value from HTML element by ID"""
        try:
            # Look for id="element_id">number
            pattern = rf'id="{re.escape(element_id)}"[^>]*>\s*(\d+)'
            match = re.search(pattern, html_content)
            if match:
                return int(match.group(1))
            return None
        except (TypeError, ValueError, re.error):
            return None

    def get_log_stats_from_json(self):
        """Get log statistics from log_summary.json (JavaScript logic)"""
        try:
            log_summary_file = self.monitor_results / "log_summary.json"
            if not log_summary_file.exists():
                return {}
                
            with open(log_summary_file, 'r') as f:
                log_data = json.load(f)

            if log_data.get("collection_status") != "current":
                print("    ❌ log_summary.json has no current device telemetry")
                self.had_error = True
                return {}
            
            totals = log_data.get("totals")
            required = ("critical", "warning", "error", "info")
            if not isinstance(totals, dict) or any(
                    key not in totals
                    or isinstance(totals[key], bool)
                    or not isinstance(totals[key], (int, float))
                    or totals[key] < 0
                    for key in required):
                print("    ❌ log_summary.json has incomplete totals")
                self.had_error = True
                return {}
            coverage = log_data.get("coverage", {})
            if coverage is None:
                coverage = {}
            if not isinstance(coverage, dict):
                print("    ❌ log_summary.json has invalid coverage metadata")
                self.had_error = True
                return {}
            expected_devices = coverage.get("expected_devices", [])
            current_devices = coverage.get("current_devices", [])
            if (not isinstance(expected_devices, list) or
                    not isinstance(current_devices, list)):
                print("    ❌ log_summary.json has invalid coverage device lists")
                self.had_error = True
                return {}
            return {
                "critical": totals["critical"],
                "warnings": totals["warning"],
                "errors": totals["error"],
                "info": totals["info"],
                "collection_status": "current",
                "coverage_partial": bool(coverage.get("partial", False)),
                "coverage_expected": len(expected_devices),
                "coverage_current": len(current_devices),
            }
            
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
            print(f"    ❌ Error reading log stats from JSON: {e}")
            self.had_error = True
            return {}

    def get_lldp_stats_from_ini(self):
        """Get strict Wiring-compatible statistics from lldp_results.ini."""
        try:
            # Check for lldp_results.ini in different locations
            canonical_lldp = self.script_dir / "lldp-results" / "lldp_results.ini"
            if (isinstance(self.run_manifest, dict) and
                    self.run_manifest.get("pipeline_complete")):
                # Parse the immutable copy bundled with this monitor run.
                possible_paths = [
                    self.monitor_results / ".pipeline-inputs" / "lldp_results.ini"
                ]
            else:
                possible_paths = [
                    canonical_lldp,
                    self.script_dir.parent / "html" / "lldp_results.ini",
                    self.monitor_results / "lldp_results.ini",
                ]
            
            existing_paths = [path for path in possible_paths if path.is_file()]
            lldp_file = max(
                existing_paths, key=lambda path: path.stat().st_mtime,
                default=None,
            )
                    
            if not lldp_file:
                print(f"    ❌ No lldp_results.ini found in any expected location")
                return {}
            if not self.source_matches_run_manifest("lldp", lldp_file):
                return {}
                
            report = parse_lldp_report(
                lldp_file.read_text(encoding="utf-8")
            )
            # Naive legacy timestamps deliberately retain the historical local
            # timezone interpretation.  ISO headers carry their explicit offset.
            created_time = report.created_at.timestamp()
            file_mtime = lldp_file.stat().st_mtime
            if abs(file_mtime - created_time) > 120:
                print("    ❌ lldp_results.ini Created time does not match file mtime")
                return {}
            lldp_age = time.time() - created_time
            max_age = self.get_data_max_age_seconds()
            if lldp_age < -300 or lldp_age > max_age:
                print("    ❌ lldp_results.ini is stale or from the future")
                return {}
            
            return report.counts.as_dict()
            
        except LLDPReportError as e:
            print(f"    ❌ Invalid lldp_results.ini schema: {e}")
            return {}
        except Exception as e:
            print(f"    ❌ Error reading LLDP stats from INI: {e}")
            return {}

    def is_summary_time(self):
        """Check if it's time for scheduled summary"""
        return self.due_summary_slot() is not None

    def due_summary_slot(self):
        """Return the newest summary slot already reached today, or None.

        check_alerts runs at the end of the monitoring pipeline, minutes
        after the cron minute, so an exact HH:MM match would never fire.
        Comparing the reached slot against the last-sent slot marker lets a
        scheduled summary fire exactly once per configured time per day.
        """
        strategy = self.config.get('alert_strategy', {})
        summary_times = strategy.get('summary_times', ['09:00', '17:00'])

        now = datetime.datetime.now()
        current_time = now.strftime("%H:%M")
        due_times = [
            slot for slot in summary_times
            if isinstance(slot, str) and re.fullmatch(r'\d{2}:\d{2}', slot)
            and slot <= current_time
        ]
        if not due_times:
            return None
        return f"{now.strftime('%Y-%m-%d')} {max(due_times)}"

    def check_changes_only(self, devices):
        """Send the complete health summary only when its state changes."""
        print("🔄 Evaluating complete network state for changes")
        if not self.send_summary_alert(devices, include_schedule=False):
            self.had_error = True

def main():
    """Main function"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    alerts = LLDPqAlerts(script_dir)

    lock_path = alerts.state_dir / ".check-alerts.lock"
    try:
        alert_lock = lock_path.open("a+")
        fcntl.flock(alert_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError) as exc:
        print(f"Alert evaluation is already running or could not be locked: {exc}")
        return 75

    if len(sys.argv) > 1 and sys.argv[1] == "--assets-only":
        if not alerts.config:
            return 0 if alerts.notifications_disabled else 1
        return 0 if alerts.check_fabric_availability() else 1

    if len(sys.argv) > 1:
        # Specific device check (for debugging)
        device = sys.argv[1]
        if not alerts.config:
            return 0 if alerts.notifications_disabled else 1
        if alerts.monitor_is_stale():
            return 1
        alerts.run_manifest = alerts.load_run_manifest()
        if alerts.run_manifest is False:
            return 1
        print(f"Checking alerts for device: {device}")
        try:
            alerts.check_hardware_alerts(device)
            alerts.check_system_alerts(device)
            alerts.check_network_alerts(device)
            alerts.check_log_alerts(device)
        except Exception as exc:
            print(f"❌ Alert evaluation failed for {device}: {exc}")
            alerts.had_error = True
        return 1 if alerts.had_error else 0

    return 0 if alerts.check_all_devices() else 1

if __name__ == "__main__":
    sys.exit(main())
