#!/usr/bin/env python3
"""
LLDPq Alert System - Network monitoring alerts for Slack
Copyright (c) 2024 LLDPq Project - Licensed under MIT License

This script analyzes monitoring data and sends alerts based on configured thresholds.
Called every 10 minutes by the lldpq cron job.
"""

import json
import yaml
import requests
import os
import sys
import glob
import time
import datetime
import re
from pathlib import Path

class LLDPqAlerts:
    def __init__(self, script_dir):
        self.script_dir = Path(script_dir)
        self.config_file = self.script_dir / "notifications.yaml"
        self.state_dir = self.script_dir / "alert-states"
        self.monitor_results = self.script_dir / "monitor-results"
        
        # Create state directory if it doesn't exist (like `mkdir -p`)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self.load_config()
        
    def load_config(self):
        """Load notification configuration from YAML file"""
        try:
            if not self.config_file.exists():
                print(f"❌ Configuration file not found: {self.config_file}")
                return None
                
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            if not config.get('notifications', {}).get('enabled', False):
                print("Notifications disabled in config")
                return None
                
            return config
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return None
    
    def get_alert_state(self, device, alert_type):
        """Get the last alert state for a device/alert combination"""
        state_file = self.state_dir / f"{device}_{alert_type}.state"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    return f.read().strip()
            except:
                pass
        return "UNKNOWN"
    
    def set_alert_state(self, device, alert_type, state):
        """Save the current alert state"""
        state_file = self.state_dir / f"{device}_{alert_type}.state"
        try:
            with open(state_file, 'w') as f:
                f.write(state)
        except Exception as e:
            print(f"❌ Error saving state: {e}")

    def _alert_marker_file(self, device, alert_type, marker):
        """Return a state marker path for an alert."""
        return self.state_dir / f"{device}_{alert_type}.{marker}"

    def _read_marker_time(self, device, alert_type, marker):
        marker_file = self._alert_marker_file(device, alert_type, marker)
        try:
            return float(marker_file.read_text().strip())
        except (OSError, TypeError, ValueError):
            return None

    def _write_marker_time(self, device, alert_type, marker):
        marker_file = self._alert_marker_file(device, alert_type, marker)
        try:
            marker_file.write_text(str(time.time()))
        except OSError as e:
            print(f"❌ Error saving alert {marker}: {e}")

    def record_alert_attempt(self, device, alert_type):
        """Record a delivery attempt without claiming the alert was delivered."""
        self._write_marker_time(device, alert_type, "attempt")

    def record_alert_delivery(self, device, alert_type, current_state):
        """Persist state and rate-limit timestamp only after successful delivery."""
        self.set_alert_state(device, alert_type, current_state)
        self._write_marker_time(device, alert_type, "timestamp")
        self._clear_alert_attempt(device, alert_type)

    def _clear_alert_attempt(self, device, alert_type):
        try:
            self._alert_marker_file(device, alert_type, "attempt").unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"❌ Error clearing alert attempt marker: {e}")

    def record_state_without_delivery(self, device, alert_type, current_state):
        """Advance an intentionally silent state transition (for disabled recovery)."""
        self.set_alert_state(device, alert_type, current_state)
        self._clear_alert_attempt(device, alert_type)

    def get_frequency_seconds(self, key, default_minutes):
        """Read a non-negative frequency setting while accepting YAML numbers/strings."""
        try:
            minutes = float(
                self.config.get('frequency', {}).get(key, default_minutes)
            )
        except (TypeError, ValueError):
            minutes = default_minutes
        return max(minutes, 0) * 60
    
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
            return False
        return self.send_slack_message(title, message, color, device, timestamp, slack_config)

    def send_stateful_notification(self, title, message, severity, device,
                                   alert_type, current_state):
        """Attempt an alert and advance its state only after delivery succeeds."""
        self.record_alert_attempt(device, alert_type)
        delivered = self.send_notification(
            title, message, severity, device, alert_type
        )
        if delivered:
            self.record_alert_delivery(device, alert_type, current_state)
        return delivered
    

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
        except:
            return
        
        thresholds = self.config.get('thresholds', {}).get('hardware', {})
        
        # Check CPU temperature
        cpu_temp_match = re.search(r'CPU ACPI temp:\s*\+?([0-9.]+)°C', hardware_data)
        if not cpu_temp_match:
            cpu_temp_match = re.search(r'Core \d+:\s*\+?([0-9.]+)°C', hardware_data)
        
        if cpu_temp_match:
            cpu_temp = float(cpu_temp_match.group(1))
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
        
        # Check ASIC temperature
        asic_temp_match = re.search(r'ASIC.*temp.*:\s*\+?([0-9.]+)°C', hardware_data)
        if asic_temp_match:
            asic_temp = float(asic_temp_match.group(1))
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

    def check_network_alerts(self, device):
        """Check network-related alerts (BGP, link flaps, optical)"""
        if not self.config.get('alert_types', {}).get('network_alerts', True):
            return
            
        # Check BGP status
        bgp_file = self.monitor_results / "bgp-data" / f"{device}_bgp.txt"
        processed_bgp_status = self.get_device_bgp_status(device)
        if processed_bgp_status in {"stale", "unknown"}:
            print(
                f"    ⚠️ Skipping BGP neighbor state for {device}: "
                f"collection is {processed_bgp_status}"
            )
        elif bgp_file.exists():
            try:
                with open(bgp_file, 'r') as f:
                    bgp_data = f.read()
                
                # Count BGP neighbors that are down
                down_neighbors = re.findall(r'(\d+\.\d+\.\d+\.\d+).*?(Active|Idle|Connect)', bgp_data)
                
                if down_neighbors:
                    current_state = "CRITICAL"
                    neighbor_list = [f"{ip} ({state})" for ip, state in down_neighbors]
                    
                    if self.should_send_alert(device, "bgp_neighbors", current_state):
                        self.send_stateful_notification(
                            f"BGP Neighbors Down",
                            f"BGP neighbors down: {', '.join(neighbor_list)}",
                            "CRITICAL", device, "bgp_neighbors", current_state
                        )
                else:
                    current_state = "OK"
                    send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
                    if not send_recovery:
                        self.record_state_without_delivery(device, "bgp_neighbors", current_state)
                    elif self.should_send_alert(device, "bgp_neighbors", current_state):
                        self.send_stateful_notification(
                            f"BGP Neighbors Recovered",
                            f"All BGP neighbors established",
                            "RECOVERED", device, "bgp_neighbors", current_state
                        )
            except:
                pass
        
        # Check link flaps
        flap_files = glob.glob(str(self.monitor_results / "flap-data" / f"{device}_*_transitions.txt"))
        if flap_files:
            high_flap_interfaces = []
            critical_flap_interfaces = []
            
            thresholds = self.config.get('thresholds', {}).get('network', {})
            flap_warning = thresholds.get('link_flaps_per_hour', 10)
            flap_critical = thresholds.get('link_flaps_critical', 20)
            
            for flap_file in flap_files:
                try:
                    interface = os.path.basename(flap_file).replace(f"{device}_", "").replace("_transitions.txt", "")
                    with open(flap_file, 'r') as f:
                        flap_count = len(f.readlines())
                    
                    if flap_count >= flap_critical:
                        critical_flap_interfaces.append(f"{interface}: {flap_count}")
                    elif flap_count >= flap_warning:
                        high_flap_interfaces.append(f"{interface}: {flap_count}")
                except:
                    continue
            
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

    def check_log_alerts(self, device):
        """Check for critical system logs"""
        if not self.config.get('alert_types', {}).get('log_alerts', True):
            return
            
        log_file = self.monitor_results / "log-data" / f"{device}_logs.txt"
        if not log_file.exists():
            return
            
        try:
            with open(log_file, 'r') as f:
                log_data = f.read()
            
            # Count critical log entries
            critical_patterns = [
                r'CRITICAL|CRIT',
                r'ALERT|EMERG', 
                r'kernel.*panic',
                r'out of memory|oom',
                r'segfault|segmentation fault'
            ]
            
            critical_logs = []
            for pattern in critical_patterns:
                matches = re.findall(pattern, log_data, re.IGNORECASE)
                critical_logs.extend(matches)
            
            if len(critical_logs) > 0:
                current_state = "CRITICAL"
                if self.should_send_alert(device, "system_logs", current_state):
                    self.send_stateful_notification(
                        f"Critical System Logs",
                        f"Found {len(critical_logs)} critical log entries",
                        "CRITICAL", device, "system_logs", current_state
                    )
            else:
                current_state = "OK"
                send_recovery = self.config.get('frequency', {}).get('send_recovery', True)
                if not send_recovery:
                    self.record_state_without_delivery(device, "system_logs", current_state)
                elif self.should_send_alert(device, "system_logs", current_state):
                    self.send_stateful_notification(
                        f"System Logs Clear",
                        f"No critical system issues detected",
                        "RECOVERED", device, "system_logs", current_state
                    )
        except:
            pass

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
        assets_file = self.script_dir / "assets.ini"
        if not assets_file.exists():
            stats["unknown"] = len(devices)
            stats["statuses"] = {device: "unknown" for device in devices}
            return stats

        try:
            stale_minutes = float(
                self.config.get('frequency', {}).get('data_stale_minutes', 30)
            )
        except (TypeError, ValueError):
            stale_minutes = 30

        try:
            snapshot_time = assets_file.stat().st_mtime
            rows = {}
            with open(assets_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('Created on '):
                        try:
                            created = datetime.datetime.strptime(
                                line.removeprefix('Created on ').strip(),
                                "%Y-%m-%d %H-%M-%S"
                            )
                            snapshot_time = created.timestamp()
                        except ValueError:
                            pass
                        continue
                    if line.startswith('DEVICE-NAME'):
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    status = next(
                        (part.upper() for part in parts[1:]
                         if part.upper() in {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}),
                        None
                    )
                    if status:
                        rows[parts[0]] = status
        except OSError as e:
            print(f"❌ Error reading assets status: {e}")
            stats["unknown"] = len(devices)
            stats["statuses"] = {device: "unknown" for device in devices}
            return stats

        snapshot_stale = time.time() - snapshot_time > max(stale_minutes, 0) * 60
        for device in devices:
            raw_status = rows.get(device)
            if raw_status is None:
                status = "unknown"
            elif snapshot_stale:
                status = "stale"
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

    def check_all_devices(self):
        """Check alerts for all monitored devices"""
        if not self.config:
            print("Notifications disabled or config error")
            return
            
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
            return
            
        print(f"Found {len(devices)} devices to check")
        
        if mode == "summary":
            self.send_summary_alert(devices)
        elif mode == "change_only":
            self.check_changes_only(devices)  
        else:
            # Immediate mode (original behavior)
            for device in devices:
                print(f"  📍 Checking {device}...")
                try:
                    self.check_hardware_alerts(device)
                    self.check_network_alerts(device)
                    self.check_log_alerts(device)
                except Exception as e:
                    print(f"    ❌ Error checking {device}: {e}")
                    continue
        
        print("Alert check completed")

    def send_summary_alert(self, devices):
        """Send dashboard-style summary alert"""
        print("Generating network health summary...")
        
        # Get stats directly from HTML analysis files with defaults
        total_devices = len(devices)
        
        hardware_stats = self.get_stats_from_html("hardware-analysis.html")
        if not hardware_stats:
            hardware_stats = {"excellent": 0, "good": 0, "warnings": 0, "critical": 0}
        
        log_stats = self.get_log_stats_from_json()
        if not log_stats:
            log_stats = {"critical": 0, "warnings": 0, "errors": 0, "info": 0}
        
        bgp_stats = self.get_stats_from_html("bgp-analysis.html")
        if not bgp_stats:
            bgp_stats = {"established": 0, "down": 0, "stale": 0, "unknown": 0}
        
        asset_stats = self.get_asset_stats(devices)
        
        ber_stats = self.get_stats_from_html("ber-analysis.html")
        if not ber_stats:
            ber_stats = {"excellent": 0, "good": 0, "warnings": 0, "critical": 0}
        
        flap_stats = self.get_stats_from_html("link-flap-analysis.html")  # Correct filename
        if not flap_stats:
            flap_stats = {"stable": 0, "warnings": 0, "critical": 0}
        
        optical_stats = self.get_stats_from_html("optical-analysis.html")
        if not optical_stats:
            optical_stats = {"excellent": 0, "good": 0, "warnings": 0, "critical": 0}
        
        critical_issues = []
        
        # Generate critical issues summary from aggregate stats (faster than per-device checks)
        if hardware_stats.get('critical', 0) > 0:
            critical_issues.append(f"🔥 Hardware: {hardware_stats['critical']} devices with critical issues")
        
        if log_stats.get('critical', 0) > 0:
            critical_issues.append(f"Logs: {log_stats['critical']} critical log entries")
        
        if bgp_stats.get('down', 0) > 0:
            critical_issues.append(f"BGP: {bgp_stats['down']} neighbors down")
        if bgp_stats.get('stale', 0) > 0:
            critical_issues.append(f"BGP: {bgp_stats['stale']} device collections stale")
        if bgp_stats.get('unknown', 0) > 0:
            critical_issues.append(f"BGP: {bgp_stats['unknown']} device collections unknown")
        
        if optical_stats.get('critical', 0) > 0:
            critical_issues.append(f"Optical: {optical_stats['critical']} ports with critical issues")
        
        if ber_stats.get('critical', 0) > 0:
            critical_issues.append(f"BER: {ber_stats['critical']} ports with critical errors")
        
        if flap_stats.get('critical', 0) > 0:
            critical_issues.append(f"Link Flap: {flap_stats['critical']} problematic ports")

        if asset_stats.get('unreachable', 0) > 0:
            critical_issues.append(
                f"Assets: {asset_stats['unreachable']} devices unreachable"
            )
        if asset_stats.get('unknown', 0) > 0:
            critical_issues.append(
                f"Assets: {asset_stats['unknown']} devices have unknown status"
            )
        if asset_stats.get('stale', 0) > 0:
            critical_issues.append(
                f"Assets: {asset_stats['stale']} devices have stale status data"
            )
        
        # Analyze LLDP topology (global analysis, not per device)
        lldp_stats = self.get_lldp_stats_from_ini()
        if not lldp_stats:
            lldp_stats = {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
        
        # Check for LLDP critical issues
        if lldp_stats['failed'] > 0:
            critical_issues.append(f"🔗 LLDP Topology: {lldp_stats['failed']} failed connections")
        
        # Create summary signature for state tracking (include optical and LLDP)
        summary_signature = f"{total_devices}_{hardware_stats['excellent']}_{hardware_stats['good']}_{hardware_stats['warnings']}_{hardware_stats['critical']}_{log_stats['critical']}_{log_stats['warnings']}_{bgp_stats['down']}_{bgp_stats.get('stale', 0)}_{bgp_stats.get('unknown', 0)}_{asset_stats['failed']}_{asset_stats['unknown']}_{asset_stats['stale']}_{ber_stats['excellent']}_{ber_stats['critical']}_{flap_stats['critical']}_{optical_stats['critical']}_{lldp_stats['failed']}"
        
        # Check if summary changed or it's scheduled time (critical issues don't force immediate send in summary mode)
        if self.should_send_summary_alert(summary_signature):
            server_url = self.config.get('notifications', {}).get('server_url', 'http://localhost')
            
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


Established: {bgp_stats['established']}     Down: {bgp_stats['down']}     Stale: {bgp_stats.get('stale', 0)}     Unknown: {bgp_stats.get('unknown', 0)}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Link Flap Analysis Results:


Stable: {flap_stats['stable']}     Warnings: {flap_stats['warnings']}     Critical: {flap_stats['critical']}

─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

Optical Diagnostics Analysis:


Excellent: {optical_stats['excellent']}     Good: {optical_stats['good']}     Warning: {optical_stats['warnings']}     Critical: {optical_stats['critical']}


─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──

BER Analysis Results:


Excellent: {ber_stats['excellent']}     Good: {ber_stats['good']}     Warnings: {ber_stats['warnings']}     Critical: {ber_stats['critical']}

"""
            if critical_issues:
                message += f"\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──\n\nCritical Issues:\n" + "\n".join(critical_issues[:5])
                if len(critical_issues) > 5:
                    message += f"\n... and {len(critical_issues) - 5} more issues"
                    
            message += f"\n\n─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ──\n\n[View Full Dashboard]({server_url})"
            
            # Send notification
            color = "#FF0000" if critical_issues else "#00AA00"
            severity = "CRITICAL" if critical_issues else "INFO"
            self.record_alert_attempt("network_summary", "last_summary")
            delivered = self.send_notification(
                title, message, severity, "Network Summary"
            )

            # A failed summary remains pending and will be retried. Neither its
            # signature nor its schedule marker may claim a delivery occurred.
            if delivered:
                self.record_alert_delivery(
                    "network_summary", "last_summary", summary_signature
                )
                if self.is_summary_time():
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                    self.set_alert_state(
                        "network_summary", "last_summary_time", current_time
                    )
            
        

    def should_send_summary_alert(self, current_signature):
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
            
        # Send if it's scheduled time and hasn't been sent recently
        if self.is_summary_time():
            last_summary_time = self.get_alert_state("network_summary", "last_summary_time")
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            
            if current_time != last_summary_time:
                return True
                
        return False

    def get_device_hardware_status(self, device):
        """Get hardware health status for a device from JSON history"""
        try:
            # Read from processed hardware_history.json
            hardware_history_file = self.monitor_results / "hardware_history.json"
            if not hardware_history_file.exists():
                return "good"  # Default to healthy if no data
                
            with open(hardware_history_file, 'r') as f:
                hardware_data = json.load(f)
            
            # Get latest hardware entry for this device
            device_history = hardware_data.get("hardware_history", {}).get(device, [])
            if device_history and len(device_history) > 0:
                latest_entry = device_history[-1]  # Get most recent entry
                overall_grade = latest_entry.get("overall_grade", "GOOD")
                return overall_grade.lower()
            
            return "good"
        except Exception as e:
            print(f"    ❌ Error reading hardware status for {device}: {e}")
            return "good"

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
            
            # Get latest BGP stats for this device. Older files may not contain
            # data_status; those remain compatible and are treated as current.
            device_bgp = bgp_data.get("current_bgp_stats", {}).get(device, {})
            if device_bgp:
                data_status = device_bgp.get("data_status", "current")
                if data_status in {"stale", "unknown"}:
                    return data_status
                down_neighbors = device_bgp.get("down_neighbors", 0)
                return "down" if down_neighbors > 0 else "established"
            
            return "unknown"
        except:
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
            ber_file = self.monitor_results / "ber-data" / f"{device}_ber.txt"
            if not ber_file.exists():
                return "good"
                
            with open(ber_file, 'r') as f:
                ber_data = f.read()
            
            # Simple BER check - look for high error rates
            if re.search(r'ERROR|CRITICAL|HIGH.*ERROR', ber_data, re.IGNORECASE):
                return "critical"
            elif re.search(r'WARNING|WARN', ber_data, re.IGNORECASE):
                return "warnings"
            
            return "good"
        except:
            return "good"

    def get_device_flap_status(self, device):
        """Get link flap status for a device from processed summary"""
        try:
            # Read from processed flap_history.json
            flap_history_file = self.monitor_results / "flap_history.json"
            if not flap_history_file.exists():
                return "stable"
                
            with open(flap_history_file, 'r') as f:
                flap_data = json.load(f)
            
            # Get flap stats for this device
            device_flap = flap_data.get(device, {})
            if device_flap:
                current_stats = device_flap.get("current_stats", {})
                # Look for flapping or flapped ports
                flapping_count = len(current_stats.get("flapping_ports", []))
                flapped_count = len(current_stats.get("flapped_ports", []))
                
                if flapping_count > 0:
                    return "critical"
                elif flapped_count > 0:
                    return "warnings"
            
            return "stable"
        except:
            return "stable"
    
    def get_device_optical_status(self, device):
        """Get optical diagnostics status for a device from processed summary"""
        try:
            # Read from processed optical_history.json
            optical_history_file = self.monitor_results / "optical_history.json"
            if not optical_history_file.exists():
                return "excellent"  # Default to healthy if no data
                
            with open(optical_history_file, 'r') as f:
                optical_data = json.load(f)
            
            # Get optical stats for this device
            device_optical = optical_data.get(device, {})
            if device_optical:
                current_stats = device_optical.get("current_stats", {})
                
                # Check for critical optical issues
                critical_ports = len(current_stats.get("critical_ports", []))
                warning_ports = len(current_stats.get("warning_ports", []))
                good_ports = len(current_stats.get("good_ports", []))
                excellent_ports = len(current_stats.get("excellent_ports", []))
                
                if critical_ports > 0:
                    return "critical"
                elif warning_ports > 0:
                    return "warnings"
                elif good_ports > 0:
                    return "good"
            
            return "excellent"
        except:
            return "excellent"

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
            
            # Extract numbers from specific HTML element IDs (JavaScript logic)
            stats = {}
            
            if "hardware" in html_filename:
                # Hardware stats from element IDs
                excellent = self.extract_element_value(content, 'excellent-devices')
                good = self.extract_element_value(content, 'good-devices')
                warnings = self.extract_element_value(content, 'warning-devices')
                critical = self.extract_element_value(content, 'critical-devices')
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical
                }
                
            elif "optical" in html_filename:
                # Optical stats from element IDs
                excellent = self.extract_element_value(content, 'excellent-ports')
                good = self.extract_element_value(content, 'good-ports')
                warnings = self.extract_element_value(content, 'warning-ports')
                critical = self.extract_element_value(content, 'critical-ports')
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical
                }
                
            elif "ber" in html_filename:
                # BER stats from element IDs
                excellent = self.extract_element_value(content, 'excellent-ports')
                good = self.extract_element_value(content, 'good-ports')
                warnings = self.extract_element_value(content, 'warning-ports')
                critical = self.extract_element_value(content, 'critical-ports')
                
                stats = {
                    "excellent": excellent,
                    "good": good,
                    "warnings": warnings,
                    "critical": critical
                }
                
            elif "link-flap" in html_filename:
                # Flap stats from element IDs
                stable = self.extract_element_value(content, 'stable-ports')
                problematic = self.extract_element_value(content, 'problematic-ports')
                
                stats = {
                    "stable": stable,
                    "warnings": 0,  # Flap doesn't have warnings
                    "critical": problematic
                }
                
            elif "bgp" in html_filename:
                # BGP stats from element IDs
                established = self.extract_element_value(content, 'established-neighbors')
                down = self.extract_element_value(content, 'down-neighbors')
                stale = self.extract_element_value(content, 'stale-devices')
                unknown = self.extract_element_value(content, 'unknown-devices')
                
                stats = {
                    "established": established,
                    "down": down,
                    "stale": stale,
                    "unknown": unknown
                }
            
            return stats
            
        except Exception as e:
            print(f"    ❌ Error reading stats from {html_filename}: {e}")
            return {}

    def extract_element_value(self, html_content, element_id):
        """Extract numeric value from HTML element by ID"""
        try:
            # Look for id="element_id">number
            pattern = rf'id="{element_id}"[^>]*>(\d+)'
            match = re.search(pattern, html_content)
            if match:
                return int(match.group(1))
            return 0
        except:
            return 0

    def get_log_stats_from_json(self):
        """Get log statistics from log_summary.json (JavaScript logic)"""
        try:
            log_summary_file = self.monitor_results / "log_summary.json"
            if not log_summary_file.exists():
                return {}
                
            with open(log_summary_file, 'r') as f:
                log_data = json.load(f)
            
            totals = log_data.get("totals", {})
            
            return {
                "critical": totals.get("critical", 0),
                "warnings": totals.get("warning", 0),  # Note: "warning" not "warnings" in JSON
                "errors": totals.get("error", 0),
                "info": totals.get("info", 0)
            }
            
        except Exception as e:
            print(f"    ❌ Error reading log stats from JSON: {e}")
            return {}

    def get_lldp_stats_from_ini(self):
        """Get LLDP topology statistics from lldp_results.ini (JavaScript logic)"""
        try:
            # Check for lldp_results.ini in different locations
            possible_paths = [
                self.script_dir / "lldp-results" / "lldp_results.ini",  # monitor/lldp-results/
                self.script_dir.parent / "html" / "lldp_results.ini",  # html/ directory  
                self.monitor_results / "lldp_results.ini"  # monitor-results/
            ]
            
            lldp_file = None
            for path in possible_paths:
                if path.exists():
                    lldp_file = path
                    break
                    
            if not lldp_file:
                print(f"    ❌ No lldp_results.ini found in any expected location")
                return {}
                
            with open(lldp_file, 'r') as f:
                content = f.read()
            
            lines = content.split('\n')
            stats = {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
            
            # Parse each line like JavaScript does
            for line in lines:
                line = line.strip()
                # Look for port status lines (swp + Pass/Fail/No-Info pattern)
                if 'swp' in line and ('Pass' in line or 'Fail' in line or 'No-Info' in line):
                    parts = line.split()
                    if len(parts) >= 2:
                        status = parts[1]  # Status is second column
                        if status == 'Pass':
                            stats["successful"] += 1
                        elif status == 'Fail':
                            stats["failed"] += 1  
                        elif status == 'No-Info':
                            stats["no_info"] += 1
            

            return stats
            
        except Exception as e:
            print(f"    ❌ Error reading LLDP stats from INI: {e}")
            return {}

    def is_summary_time(self):
        """Check if it's time for scheduled summary"""
        strategy = self.config.get('alert_strategy', {})
        summary_times = strategy.get('summary_times', ['09:00', '17:00'])
        
        current_time = datetime.datetime.now().strftime("%H:%M")
        return current_time in summary_times

    def check_changes_only(self, devices):
        """Check and alert only on significant changes"""
        # This would compare with previous state and only alert on changes
        # For now, fall back to immediate mode
        print("🔄 Change-only mode not fully implemented, using immediate mode")
        for device in devices:
            print(f"  📍 Checking {device}...")
            try:
                self.check_hardware_alerts(device)
                self.check_network_alerts(device)
                self.check_log_alerts(device)
            except Exception as e:
                print(f"    ❌ Error checking {device}: {e}")
                continue

def main():
    """Main function"""
    if len(sys.argv) > 1:
        # Specific device check (for debugging)
        device = sys.argv[1]
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alerts = LLDPqAlerts(script_dir)
        
        print(f"Checking alerts for device: {device}")
        alerts.check_hardware_alerts(device)
        alerts.check_network_alerts(device)
        alerts.check_log_alerts(device)
    else:
        # Check all devices
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alerts = LLDPqAlerts(script_dir)
        alerts.check_all_devices()

if __name__ == "__main__":
    main()
