#!/usr/bin/env python3
"""
Link Error Analysis Module for LLDPq

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import time
import re
import os
import math
import stat
import tempfile
import html
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

try:
    import yaml
except ImportError:
    yaml = None

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

class BERGrade(Enum):
    """BER quality grades"""
    EXCELLENT = "excellent"
    GOOD = "good"  
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class BERAnalyzer:
    """Professional BER Analysis System"""

    # Trend evaluation consumes the last ten analyzed samples.  Keep those
    # plus two newest context samples so an intervening baseline/low-traffic
    # record cannot hide a valid trend.  Also retain the newest sample carrying
    # an L1 symbol counter: L1 collection may be unavailable for many runs and
    # the first recovered sample still needs its previous counter baseline.
    # Version 2 migrates the former time-only history to this bounded
    # representation when it is loaded/saved.
    TREND_ANALYSIS_POINTS = 10
    HISTORY_CONTEXT_POINTS = 2
    HISTORY_SYMBOL_CONTEXT_POINTS = 1
    MAX_HISTORY_ENTRIES_PER_PORT = (
        TREND_ANALYSIS_POINTS
        + HISTORY_CONTEXT_POINTS
        + HISTORY_SYMBOL_CONTEXT_POINTS
    )
    HISTORY_SCHEMA_VERSION = 2
    
    # Interface error-event density, raw (pre-FEC) BER, and effective
    # (post-FEC) BER are different metrics and intentionally have separate
    # contracts. NVIDIA's cable-validation guidance accepts raw BER through
    # 1e-6; applying the post-FEC service threshold to raw BER makes healthy
    # high-speed FEC links appear critical. The configured network BER limit
    # therefore applies only to effective BER.
    DEFAULT_CONFIG = {
        "frame_density_warning_threshold": 1.0E-6,
        "frame_density_critical_threshold": 1.0E-5,
        "raw_phy_ber_warning_threshold": 1.0E-6,
        "raw_phy_ber_critical_threshold": 1.0E-5,
        "effective_phy_ber_warning_threshold": 1.0E-12,
        "effective_phy_ber_critical_threshold": 1.0E-11,
        # A physically operational link cannot sustain a pre/post-FEC BER at or
        # above this floor (that is 100% or more corrupted symbols). l1-show on
        # an admin-down / link-down port reports the degenerate coef=1,
        # magnitude=0 => 1.0e+00 "no measurement" sentinel; readings at or above
        # this floor are discarded instead of being graded as a real fault.
        "phy_ber_invalid_floor": 1.0,
        # Compatibility aliases used by the processing summary and older
        # callers; these always mirror the effective/post-FEC limits.
        "phy_ber_warning_threshold": 1.0E-12,
        "phy_ber_critical_threshold": 1.0E-11,
        "symbol_error_warning_delta": 1,
        "symbol_error_critical_delta": 1000,
        "min_packets_for_analysis": 1000,  # Minimum packets for reliable BER
        # Time is an upper bound; persisted trend state is additionally
        # sample-bounded by MAX_HISTORY_ENTRIES_PER_PORT.
        "history_retention_hours": 24,
        "trend_analysis_points": TREND_ANALYSIS_POINTS  # Minimum trend points
    }
    
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.ber_history = {}  # port -> list of ber readings over time
        self.current_ber_stats = {}  # port -> current ber status
        self.config = self.DEFAULT_CONFIG.copy()
        self._raw_phy_ber_cache = {}  # hostname -> { interface: raw_ber_float }
        self._l1_extras_cache = {}  # hostname -> { interface: {effective_ber, symbol_errors} }
        self._last_delta_details = {}  # port -> directional deltas/sample window
        self.baseline_data = {}  # hostname -> { interface: {counters, timestamp} }
        self._load_network_thresholds()
        
        # Ensure ber-data directory exists
        os.makedirs(f"{self.data_dir}/ber-data", exist_ok=True)
        
        # Load historical data and baseline
        self.load_ber_history()
        self.load_baseline_data()

    def _load_network_thresholds(self) -> None:
        """Load the configured PHY BER boundary without affecting frame density."""
        if yaml is None:
            return
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'notifications.yaml'),
            os.path.join(os.path.dirname(os.path.abspath(self.data_dir)),
                         'notifications.yaml'),
        ]
        for path in dict.fromkeys(candidates):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, 'r') as stream:
                    config = yaml.safe_load(stream) or {}
                value = config.get('thresholds', {}).get('network', {}).get(
                    'ber_error_rate'
                )
                if value is None:
                    return
                threshold = float(value)
                if math.isfinite(threshold) and threshold > 0:
                    self.config['effective_phy_ber_warning_threshold'] = threshold
                    self.config['effective_phy_ber_critical_threshold'] = threshold * 10.0
                    self.config['phy_ber_warning_threshold'] = threshold
                    self.config['phy_ber_critical_threshold'] = threshold * 10.0
                return
            except (OSError, TypeError, ValueError, yaml.YAMLError):
                return
    
    def load_ber_history(self):
        """Load historical BER data from file"""
        try:
            with open(f"{self.data_dir}/ber_history.json", "r") as f:
                data = json.load(f)
                self.ber_history = data.get("ber_history", {})
                self.current_ber_stats = data.get("current_ber_stats", {})
                
                # Clean old data (older than retention period)
                self.cleanup_old_history()
        except (FileNotFoundError, json.JSONDecodeError):
            print("No previous BER history found, starting fresh")
    
    def load_baseline_data(self):
        """Load baseline counter data for delta calculations"""
        try:
            with open(f"{self.data_dir}/ber_baseline.json", "r") as f:
                self.baseline_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            print("No baseline data found, will establish on first run")
            self.baseline_data = {}
    
    def save_baseline_data(self):
        """Save baseline counter data"""
        try:
            self._atomic_json_write(
                f"{self.data_dir}/ber_baseline.json", self.baseline_data
            )
            return True
        except Exception as e:
            print(f"Error saving baseline data: {e}")
            return False

    @staticmethod
    def _atomic_json_write(path: str, value: Any) -> None:
        """Write compact JSON atomically and durably without a partial file."""
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except FileNotFoundError:
            mode = 0o644

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{os.path.basename(path)}.", dir=directory
        )
        try:
            # Web-served output: nginx must always retain read access.
            os.fchmod(descriptor, mode | 0o644)
            with os.fdopen(descriptor, "w") as stream:
                descriptor = -1
                json.dump(value, stream, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)

            # Persist the directory entry on filesystems which support it.
            directory_fd = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _atomic_text_write(path: str, text: str) -> None:
        """Write a text report atomically so a reader never sees a partial file."""
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except FileNotFoundError:
            mode = 0o644

        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{os.path.basename(path)}.", dir=directory
        )
        try:
            # Web-served output: nginx must always retain read access.
            os.fchmod(descriptor, mode | 0o644)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)

            directory_fd = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def _parse_raw_phy_ber_for_device(self, hostname: str) -> Dict[str, float]:
        """Parse RAW PHY BER per interface for given device.

        Sources (in order):
          1) monitor-results/ber-data/<hostname>_l1_show.txt (direct l1-show output)
             - Use raw_ber_coef × 10^(raw_ber_magnitude)
             - Fallback to corrected_bits/received_bits
          2) monitor-results/ber-data/<hostname>_detailed_counters.txt (legacy combined extract)
        """
        if hostname in self._raw_phy_ber_cache:
            return self._raw_phy_ber_cache[hostname]

        result: Dict[str, float] = {}

        def parse_content(content: str):
            nonlocal result
            current_if: Optional[str] = None
            current_received_bits: Optional[int] = None
            current_corrected_bits: Optional[int] = None
            current_raw_coef: Optional[int] = None
            current_raw_mag: Optional[int] = None

            def flush():
                nonlocal current_if, current_received_bits, current_corrected_bits, current_raw_coef, current_raw_mag
                if not current_if:
                    return
                if current_raw_coef is not None and current_raw_mag is not None:
                    try:
                        raw_ber = float(current_raw_coef) * (10.0 ** float(current_raw_mag))
                        if raw_ber >= 0:
                            result[current_if] = raw_ber
                    except Exception:
                        pass
                elif (current_received_bits is not None and
                      current_corrected_bits is not None and
                      current_received_bits > 0 and current_corrected_bits >= 0):
                    try:
                        raw_ber = float(current_corrected_bits) / float(current_received_bits)
                        result[current_if] = raw_ber
                    except Exception:
                        pass
                current_if = None
                current_received_bits = None
                current_corrected_bits = None
                current_raw_coef = None
                current_raw_mag = None

            for line in content.splitlines():
                s = line.strip()
                if not s:
                    continue
                if s.startswith("Port:") or s.startswith("Interface:"):
                    flush()
                    try:
                        name = s.split(":", 1)[1].strip()
                        current_if = name
                    except Exception:
                        current_if = None
                    continue
                if ":" in s and current_if:
                    key, val = s.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    try:
                        if key == "phy_received_bits":
                            current_received_bits = int(val)
                        elif key == "phy_corrected_bits":
                            current_corrected_bits = int(val)
                        elif key == "raw_ber_coef":
                            current_raw_coef = int(val)
                        elif key == "raw_ber_magnitude":
                            current_raw_mag = int(val)
                    except Exception:
                        pass
            flush()

        # 1) Prefer direct l1-show output if present
        l1_path = f"{self.data_dir}/ber-data/{hostname}_l1_show.txt"
        try:
            if os.path.exists(l1_path):
                with open(l1_path, "r") as f:
                    parse_content(f.read())
        except Exception:
            pass

        # 2) Fallback to legacy detailed counters
        if not result:
            legacy_path = f"{self.data_dir}/ber-data/{hostname}_detailed_counters.txt"
            try:
                if os.path.exists(legacy_path):
                    with open(legacy_path, "r") as f:
                        parse_content(f.read())
            except Exception:
                pass

        self._raw_phy_ber_cache[hostname] = result
        return result

    def _parse_l1_extras_for_device(self, hostname: str) -> Dict[str, Dict[str, Any]]:
        """Parse Effective (post-FEC) PHY BER and PHY symbol errors per interface from l1-show.

        Effective BER = effective_ber_coef * 10^effective_ber_magnitude (same encoding as raw BER).
        Symbol errors = phy_symbol_errors (direct counter). Both come from the same
        `l1-show all -p` output already collected per cycle -- no extra collection needed.
        Returns { interface: {'effective_ber': float|None, 'symbol_errors': int|None} }.
        """
        if hostname in self._l1_extras_cache:
            return self._l1_extras_cache[hostname]

        result: Dict[str, Dict[str, Any]] = {}

        def parse_content(content: str):
            cur = None
            eff_coef = eff_mag = sym = None

            def flush():
                nonlocal cur, eff_coef, eff_mag, sym
                if cur:
                    d: Dict[str, Any] = {}
                    if eff_coef is not None and eff_mag is not None:
                        try:
                            d['effective_ber'] = float(eff_coef) * (10.0 ** float(eff_mag))
                        except Exception:
                            pass
                    if sym is not None:
                        d['symbol_errors'] = sym
                    if d:
                        result[cur] = d
                cur = None
                eff_coef = eff_mag = sym = None

            for line in content.splitlines():
                s = line.strip()
                if not s:
                    continue
                if s.startswith("Port:") or s.startswith("Interface:"):
                    flush()
                    try:
                        cur = s.split(":", 1)[1].strip()
                    except Exception:
                        cur = None
                    continue
                if ":" in s and cur:
                    key, val = s.split(":", 1)
                    key = key.strip().lower().replace(" ", "_")
                    val = val.strip()
                    try:
                        if key == "effective_ber_coef":
                            eff_coef = int(val)
                        elif key == "effective_ber_magnitude":
                            eff_mag = int(val)
                        elif key == "phy_symbol_errors":
                            sym = int(val)
                    except Exception:
                        pass
            flush()

        l1_path = f"{self.data_dir}/ber-data/{hostname}_l1_show.txt"
        try:
            if os.path.exists(l1_path):
                with open(l1_path, "r") as f:
                    parse_content(f.read())
        except Exception:
            pass

        self._l1_extras_cache[hostname] = result
        return result

    @staticmethod
    def _physical_port_name(interface: str) -> str:
        """Return the cage-level name for a Cumulus breakout interface."""
        match = re.fullmatch(r'(swp\d+)s\d+', interface or '')
        return match.group(1) if match else interface

    def _lookup_l1_metric(self, mapping: Dict[str, Any], interface: str):
        """Resolve exact L1 data first, then its cage-level breakout record."""
        if interface in mapping:
            return mapping[interface]
        physical = self._physical_port_name(interface)
        if physical in mapping:
            return mapping[physical]
        return None
    
    def save_ber_history(self):
        """Save BER history to file"""
        try:
            # Bound both newly collected data and legacy time-only history
            # before serialization.  current_ber_stats and baselines remain
            # independent, complete snapshots.
            self.cleanup_old_history()
            data = {
                "ber_history": self.ber_history,
                "current_ber_stats": self.current_ber_stats,
                "last_update": time.time(),
                "config": self.config,
                "history_schema_version": self.HISTORY_SCHEMA_VERSION,
                "history_max_entries_per_port": self.MAX_HISTORY_ENTRIES_PER_PORT,
            }
            self._atomic_json_write(
                f"{self.data_dir}/ber_history.json", data
            )
            return True
        except Exception as e:
            print(f"Error saving BER history: {e}")
            return False

    def _bound_port_history(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Retain trend inputs, recent context, and the latest L1 baseline."""
        if len(entries) <= self.MAX_HISTORY_ENTRIES_PER_PORT:
            return entries

        analyzed_indices = [
            index for index, entry in enumerate(entries)
            if entry.get("sample_status", "analyzed") == "analyzed"
        ]
        keep = set(analyzed_indices[-self.TREND_ANALYSIS_POINTS:])
        context_start = max(0, len(entries) - self.HISTORY_CONTEXT_POINTS)
        keep.update(range(context_start, len(entries)))

        # A long L1 outage can place the last valid symbol counter outside the
        # trend/context window.  Keep that one record so recovery computes the
        # accumulated delta instead of silently treating it as a first sample.
        for index in range(len(entries) - 1, -1, -1):
            if isinstance(entries[index].get("symbol_errors"), int):
                keep.add(index)
                break

        # The union is at most 13 entries. Preserve chronological order so
        # trend and previous-symbol lookup semantics remain unchanged.
        return [entries[index] for index in sorted(keep)]
    
    def cleanup_old_history(self):
        """Remove history entries older than retention period"""
        current_time = time.time()
        retention_seconds = self.config["history_retention_hours"] * 3600
        
        for port_name in list(self.ber_history.keys()):
            if port_name in self.ber_history:
                retained = [
                    entry for entry in self.ber_history[port_name]
                    if current_time - entry['timestamp'] <= retention_seconds
                ]
                self.ber_history[port_name] = self._bound_port_history(retained)
                
                # Remove port if no history left
                if not self.ber_history[port_name]:
                    del self.ber_history[port_name]
    
    def is_physical_port(self, interface_name: str) -> bool:
        """Check if interface is a physical port (excludes management interfaces)"""
        # Exclude management interfaces
        if interface_name in ['eth0', 'mgmt', 'lo']:
            return False
        
        physical_patterns = [
            r'^swp\d+',      # Cumulus swp interfaces
            r'^eth\d+',      # Ethernet interfaces (eth1, eth2, etc. but not eth0)
            r'^eno\d+',      # Predictable network interface names
            r'^ens\d+',      # Systemd predictable names
            r'^enp\d+s\d+',  # PCI slot names
        ]
        
        for pattern in physical_patterns:
            if re.match(pattern, interface_name):
                return True
        return False
    
    def calculate_delta_ber(self, hostname: str, interface: str, current_stats: Dict[str, int]) -> tuple:
        """Calculate delta-based interface error-event density.

        `/proc/net/dev` exposes errored packet/frame events, not erroneous bit
        counts.  The returned value is therefore the worse of RX and TX error
        events divided by the corresponding observed bit volume; it must not
        be interpreted as a physical BER.
        
        Returns: (ber_value, is_baseline_run, delta_errors, delta_bytes,
        delta_packets). Samples below min_packets_for_analysis remain
        accumulated against the prior baseline instead of being discarded.
        """
        port_key = f"{hostname}:{interface}"
        current_time = time.time()

        if not hasattr(self, '_last_delta_details'):
            self._last_delta_details = {}

        def remember(delta_rx_errors=0, delta_tx_errors=0,
                     delta_rx_bytes=0, delta_tx_bytes=0,
                     delta_rx_packets=0, delta_tx_packets=0,
                     sample_seconds=0.0, reset=False):
            self._last_delta_details[port_key] = {
                'delta_rx_errors': delta_rx_errors,
                'delta_tx_errors': delta_tx_errors,
                'delta_rx_bytes': delta_rx_bytes,
                'delta_tx_bytes': delta_tx_bytes,
                'delta_rx_packets': delta_rx_packets,
                'delta_tx_packets': delta_tx_packets,
                'sample_duration_seconds': max(0.0, sample_seconds),
                'counter_reset': reset,
            }
        
        # Extract current values
        current_rx_errors = current_stats.get('rx_errors', 0)
        current_tx_errors = current_stats.get('tx_errors', 0)
        current_rx_bytes = current_stats.get('rx_bytes', 0)
        current_tx_bytes = current_stats.get('tx_bytes', 0)
        current_rx_packets = current_stats.get('rx_packets', 0)
        current_tx_packets = current_stats.get('tx_packets', 0)
        
        # Check if we have baseline data for this interface
        if hostname not in self.baseline_data:
            self.baseline_data[hostname] = {}
        
        if interface not in self.baseline_data[hostname]:
            # First run - establish baseline
            self.baseline_data[hostname][interface] = {
                'rx_errors': current_rx_errors,
                'tx_errors': current_tx_errors,
                'rx_bytes': current_rx_bytes,
                'tx_bytes': current_tx_bytes,
                'rx_packets': current_rx_packets,
                'tx_packets': current_tx_packets,
                'timestamp': current_time
            }
            remember()
            # Note: save_baseline_data() called once after all interfaces processed
            return 0.0, True, 0, 0, 0  # Baseline run, no BER calculation
        
        # Calculate deltas
        baseline = self.baseline_data[hostname][interface]
        try:
            sample_seconds = current_time - float(baseline.get('timestamp', current_time))
        except (TypeError, ValueError):
            sample_seconds = 0.0
        current_counters = (
            current_rx_errors, current_tx_errors, current_rx_bytes,
            current_tx_bytes, current_rx_packets, current_tx_packets,
        )
        baseline_counters = (
            baseline['rx_errors'], baseline['tx_errors'], baseline['rx_bytes'],
            baseline['tx_bytes'], baseline['rx_packets'], baseline['tx_packets'],
        )
        if any(current < previous for current, previous in
               zip(current_counters, baseline_counters)):
            # Interface/counter reset: establish a fresh baseline and avoid a
            # misleading zero/excellent sample for this run.
            self.baseline_data[hostname][interface] = {
                'rx_errors': current_rx_errors,
                'tx_errors': current_tx_errors,
                'rx_bytes': current_rx_bytes,
                'tx_bytes': current_tx_bytes,
                'rx_packets': current_rx_packets,
                'tx_packets': current_tx_packets,
                'timestamp': current_time,
            }
            remember(sample_seconds=sample_seconds, reset=True)
            return 0.0, True, 0, 0, 0

        delta_rx_errors = current_rx_errors - baseline['rx_errors']
        delta_tx_errors = current_tx_errors - baseline['tx_errors']
        delta_rx_bytes = current_rx_bytes - baseline['rx_bytes']
        delta_tx_bytes = current_tx_bytes - baseline['tx_bytes']
        delta_rx_packets = current_rx_packets - baseline['rx_packets']
        delta_tx_packets = current_tx_packets - baseline['tx_packets']
        
        total_delta_errors = delta_rx_errors + delta_tx_errors
        total_delta_bytes = delta_rx_bytes + delta_tx_bytes
        total_delta_packets = delta_rx_packets + delta_tx_packets

        remember(
            delta_rx_errors, delta_tx_errors,
            delta_rx_bytes, delta_tx_bytes,
            delta_rx_packets, delta_tx_packets,
            sample_seconds,
        )
        
        # Calculate the observed directional event density before applying the
        # confidence gate.  Low-traffic ports still have a real observation to
        # display, and an early error must not be hidden by returning a forced
        # zero merely because the packet target has not been reached yet.
        def directional_density(errors, byte_count, packet_count):
            if errors <= 0:
                return 0.0
            if byte_count > 0:
                return errors / (byte_count * 8)
            avg_bits_per_packet = 12000  # 1500 bytes conservative estimate
            return (errors / (packet_count * avg_bits_per_packet)
                    if packet_count > 0 else 0.0)

        error_density = (
            max(
                directional_density(
                    delta_rx_errors, delta_rx_bytes, delta_rx_packets
                ),
                directional_density(
                    delta_tx_errors, delta_tx_bytes, delta_tx_packets
                ),
            )
            if total_delta_errors > 0 else 0.0
        )

        if total_delta_packets < self.config["min_packets_for_analysis"]:
            # Retain the prior baseline so several low-traffic intervals can
            # accumulate into one statistically useful grading sample.  The
            # observed value is returned for transparent UI display only.
            return (error_density, False, total_delta_errors,
                    total_delta_bytes, total_delta_packets)

        # Update baseline only after a complete sample (or counter reset).
        self.baseline_data[hostname][interface] = {
            'rx_errors': current_rx_errors,
            'tx_errors': current_tx_errors,
            'rx_bytes': current_rx_bytes,
            'tx_bytes': current_tx_bytes,
            'rx_packets': current_rx_packets,
            'tx_packets': current_tx_packets,
            'timestamp': current_time
        }
        # Note: save_baseline_data() called once after all interfaces processed

        return error_density, False, total_delta_errors, total_delta_bytes, total_delta_packets

    def calculate_ber(self, rx_packets: int, tx_packets: int, rx_errors: int, tx_errors: int, rx_bytes: int, tx_bytes: int) -> float:
        """Legacy whole-counter interface error density calculation.

        Note: Use calculate_delta_ber() for current interval measurements.
        """
        total_packets = rx_packets + tx_packets
        if total_packets < self.config["min_packets_for_analysis"]:
            return 0.0  # Not enough data for reliable BER calculation

        if rx_errors + tx_errors == 0:
            return 0.0  # Perfect transmission

        def directional_density(errors, byte_count, packet_count):
            if errors <= 0:
                return 0.0
            if byte_count > 0:
                return errors / (byte_count * 8)
            avg_bits_per_packet = 12000  # 1500 bytes as conservative estimate
            return (errors / (packet_count * avg_bits_per_packet)
                    if packet_count > 0 else 0.0)

        return max(
            directional_density(rx_errors, rx_bytes, rx_packets),
            directional_density(tx_errors, tx_bytes, tx_packets),
        )
    
    def get_ber_grade(self, ber_value: float) -> BERGrade:
        """Determine interface error-density grade (compatibility name)."""
        if ber_value == 0.0:
            return BERGrade.EXCELLENT
        elif ber_value < self.config["frame_density_warning_threshold"]:
            return BERGrade.GOOD
        elif ber_value < self.config["frame_density_critical_threshold"]:
            return BERGrade.WARNING
        else:
            return BERGrade.CRITICAL

    @staticmethod
    def _get_phy_ber_grade(ber_value: float, warning_threshold: float,
                           critical_threshold: float) -> BERGrade:
        """Grade one PHY BER metric against its own engineering limits."""
        if ber_value == 0.0:
            return BERGrade.EXCELLENT
        if ber_value < warning_threshold:
            return BERGrade.GOOD
        if ber_value < critical_threshold:
            return BERGrade.WARNING
        return BERGrade.CRITICAL

    def get_raw_phy_ber_grade(self, ber_value: float) -> BERGrade:
        """Grade pre-FEC BER without treating normal FEC corrections as loss."""
        return self._get_phy_ber_grade(
            ber_value,
            self.config['raw_phy_ber_warning_threshold'],
            self.config['raw_phy_ber_critical_threshold'],
        )

    def get_effective_phy_ber_grade(self, ber_value: float) -> BERGrade:
        """Grade post-FEC BER seen by the MAC/application layer."""
        return self._get_phy_ber_grade(
            ber_value,
            self.config['effective_phy_ber_warning_threshold'],
            self.config['effective_phy_ber_critical_threshold'],
        )

    def get_phy_ber_grade(self, ber_value: float) -> BERGrade:
        """Compatibility alias for the service-impacting effective BER grade."""
        return self.get_effective_phy_ber_grade(ber_value)
    
    def update_interface_ber(self, port_name: str, interface_stats: Dict[str, int]):
        """Update BER statistics for an interface"""
        current_time = time.time()
        
        # Calculate BER
        ber_value = self.calculate_ber(
            interface_stats.get('rx_packets', 0),
            interface_stats.get('tx_packets', 0), 
            interface_stats.get('rx_errors', 0),
            interface_stats.get('tx_errors', 0),
            interface_stats.get('rx_bytes', 0),
            interface_stats.get('tx_bytes', 0)
        )
        
        # Get quality grade
        grade = self.get_ber_grade(ber_value)
        
        # Create BER record
        ber_record = {
            'timestamp': current_time,
            'ber_value': ber_value,
            'grade': grade.value,
            'rx_packets': interface_stats.get('rx_packets', 0),
            'tx_packets': interface_stats.get('tx_packets', 0),
            'rx_errors': interface_stats.get('rx_errors', 0),
            'tx_errors': interface_stats.get('tx_errors', 0),
            'total_packets': interface_stats.get('rx_packets', 0) + interface_stats.get('tx_packets', 0)
        }
        
        # Update history
        if port_name not in self.ber_history:
            self.ber_history[port_name] = []
        
        self.ber_history[port_name].append(ber_record)
        
        # Update current stats
        self.current_ber_stats[port_name] = ber_record
        
        return ber_record
    
    def get_ber_trend(self, port_name: str) -> Dict[str, Any]:
        """Analyze BER trend for a port"""
        if port_name not in self.ber_history or len(self.ber_history[port_name]) < self.config["trend_analysis_points"]:
            return {"trend": "insufficient_data", "confidence": "low"}
        
        history = self.ber_history[port_name]
        analyzed_history = [
            entry for entry in history
            if entry.get('sample_status', 'analyzed') == 'analyzed'
        ]
        recent_values = [
            entry['ber_value']
            for entry in analyzed_history[-self.config["trend_analysis_points"]:]
        ]
        
        # Simple trend analysis
        if len(recent_values) < 2:
            return {"trend": "stable", "confidence": "low"}
        
        # Calculate trend direction
        first_half = recent_values[:len(recent_values)//2]
        second_half = recent_values[len(recent_values)//2:]
        
        avg_first = sum(first_half) / len(first_half) if first_half else 0
        avg_second = sum(second_half) / len(second_half) if second_half else 0
        
        change_ratio = (avg_second - avg_first) / (avg_first + 1e-15)  # Avoid division by zero
        
        if abs(change_ratio) < 0.1:
            trend = "stable"
        elif change_ratio > 0.1:
            trend = "worsening" 
        else:
            trend = "improving"
        
        confidence = "high" if len(recent_values) >= self.config["trend_analysis_points"] else "medium"
        
        return {
            "trend": trend,
            "confidence": confidence,
            "change_ratio": change_ratio,
            "recent_avg": avg_second,
            "previous_avg": avg_first
        }
    
    @staticmethod
    def _grade_priority(grade: str) -> int:
        return {
            BERGrade.EXCELLENT.value: 0,
            BERGrade.GOOD.value: 1,
            BERGrade.WARNING.value: 2,
            BERGrade.CRITICAL.value: 3,
        }.get(grade, -1)

    @staticmethod
    def _format_duration(seconds: Any) -> str:
        try:
            seconds = max(0, int(float(seconds)))
        except (TypeError, ValueError):
            return 'N/A'
        if seconds < 60:
            return f'{seconds}s'
        if seconds < 3600:
            return f'{seconds // 60}m{seconds % 60:02d}s'
        return f'{seconds // 3600}h{(seconds % 3600) // 60:02d}m'

    def _previous_symbol_errors(self, port_name: str,
                                current_stats: Dict[str, Any]) -> Optional[int]:
        current_timestamp = current_stats.get('timestamp', 0)
        for entry in reversed(self.ber_history.get(port_name, [])):
            if entry is current_stats:
                continue
            try:
                if entry.get('timestamp', 0) >= current_timestamp:
                    continue
            except TypeError:
                continue
            value = entry.get('symbol_errors')
            if isinstance(value, int):
                return value
        return None

    def _analyze_port(self, port_name: str,
                      stats: Dict[str, Any]) -> Dict[str, Any]:
        """Combine frame-density, PHY BER and symbol-delta evidence once."""
        device, _, interface = port_name.partition(':')
        if not interface:
            interface = device
            device = 'unknown'

        raw_ber = self._lookup_l1_metric(
            self._parse_raw_phy_ber_for_device(device), interface
        )
        l1_extras = self._lookup_l1_metric(
            self._parse_l1_extras_for_device(device), interface
        ) or {}
        effective_ber = l1_extras.get('effective_ber')
        symbol_errors = l1_extras.get('symbol_errors')

        frame_density = stats.get('ber_value', 0)
        sample_status = stats.get('sample_status', 'analyzed')
        grades = []
        reasons = []

        low_sample_with_errors = (
            sample_status == 'insufficient_traffic'
            and (
                stats.get('delta_rx_errors', 0)
                + stats.get('delta_tx_errors', 0)
            ) > 0
        )
        if ((sample_status == 'analyzed' or low_sample_with_errors)
                and isinstance(frame_density, (int, float))):
            observed_frame_grade = self.get_ber_grade(frame_density).value
            is_actionable = (
                self._grade_priority(observed_frame_grade)
                >= self._grade_priority(BERGrade.WARNING.value)
            )
            # A complete sample may establish any grade.  Before the sample
            # target, only an observed warning/critical condition is allowed
            # to affect health; a small provisional sample cannot prove GOOD.
            if sample_status == 'analyzed' or is_actionable:
                frame_grade = observed_frame_grade
                grades.append(frame_grade)
            else:
                frame_grade = BERGrade.UNKNOWN.value
            if is_actionable:
                qualifier = (
                    'provisional low-sample ' if low_sample_with_errors else ''
                )
                reasons.append(
                    f"{qualifier}interface error density {frame_density:.2e}"
                )
        else:
            frame_grade = BERGrade.UNKNOWN.value

        # The PHY BER ratios (raw/effective) and the symbol counter describe the
        # physical link, not the traffic on it. A live PHY keeps advancing its
        # FEC symbol counter even with no L2 traffic (idle/control symbols still
        # cross the wire); an admin-down or link-down port does not, and its
        # l1-show snapshot freezes at the last reading -- frequently the
        # degenerate coef=1 / magnitude=0 => 1.0e+00 "no measurement" sentinel.
        # That stale snapshot must never be graded as a real bit-error fault.
        # Guard 1: discard physically impossible readings (a real link cannot
        # run at a pre/post-FEC BER at or above the invalid floor).
        if (isinstance(raw_ber, (int, float))
                and raw_ber >= self.config['phy_ber_invalid_floor']):
            raw_ber = None
        if (isinstance(effective_ber, (int, float))
                and effective_ber >= self.config['phy_ber_invalid_floor']):
            effective_ber = None

        previous_symbols = self._previous_symbol_errors(port_name, stats)
        symbol_delta = None
        if isinstance(symbol_errors, int) and isinstance(previous_symbols, int):
            # A reset/wrap establishes a new baseline instead of inventing a
            # negative or enormous delta.
            if symbol_errors >= previous_symbols:
                symbol_delta = symbol_errors - previous_symbols

        # Guard 2: only let the L1 metrics drive health when this sample proves
        # the link was actually receiving -- traffic flowed, new interface
        # errors appeared, or the FEC symbol counter advanced. An idle/down port
        # (no traffic, no errors, no symbol advance) keeps its stale snapshot
        # for display but stays ungraded.
        error_delta = (stats.get('delta_rx_errors', 0)
                       + stats.get('delta_tx_errors', 0))
        link_active = (
            sample_status == 'analyzed'
            or stats.get('delta_packets', 0) > 0
            or error_delta > 0
            or (isinstance(symbol_delta, int) and symbol_delta > 0)
        )
        # Guard 2 fallback: some platforms' l1-show reports no
        # phy_symbol_errors counter at all, so an idle-but-live degraded link
        # can never prove activity through a symbol advance and would stay
        # UNKNOWN indefinitely. Without a counter a stale snapshot cannot be
        # distinguished from a live reading anyway, so grade any plausible
        # (below the invalid floor) PHY BER on counter-less ports; Guard 1
        # above still discards the admin-down 1.0e+00 sentinel.
        if not link_active and not isinstance(symbol_errors, int):
            link_active = (isinstance(raw_ber, (int, float))
                           or isinstance(effective_ber, (int, float)))

        raw_grade = BERGrade.UNKNOWN.value
        if link_active and isinstance(raw_ber, (int, float)):
            raw_grade = self.get_raw_phy_ber_grade(raw_ber).value
            grades.append(raw_grade)
            if self._grade_priority(raw_grade) >= self._grade_priority(BERGrade.WARNING.value):
                reasons.append(f"raw PHY BER {raw_ber:.2e}")

        effective_grade = BERGrade.UNKNOWN.value
        if link_active and isinstance(effective_ber, (int, float)):
            effective_grade = self.get_effective_phy_ber_grade(effective_ber).value
            grades.append(effective_grade)
            if self._grade_priority(effective_grade) >= self._grade_priority(BERGrade.WARNING.value):
                reasons.append(f"effective PHY BER {effective_ber:.2e}")

        symbol_grade = BERGrade.UNKNOWN.value
        if link_active and isinstance(symbol_delta, int):
            if symbol_delta >= self.config['symbol_error_critical_delta']:
                symbol_grade = BERGrade.CRITICAL.value
            elif symbol_delta >= self.config['symbol_error_warning_delta']:
                symbol_grade = BERGrade.WARNING.value
            else:
                symbol_grade = BERGrade.EXCELLENT.value
            grades.append(symbol_grade)
            if self._grade_priority(symbol_grade) >= self._grade_priority(BERGrade.WARNING.value):
                reasons.append(f"PHY symbol errors +{symbol_delta}")

        status = (max(grades, key=self._grade_priority)
                  if grades else BERGrade.UNKNOWN.value)

        # Persist the L1 snapshot on the current history record so the next run
        # can calculate a real symbol counter delta.
        stats.update({
            'raw_ber': raw_ber,
            'effective_ber': effective_ber,
            'symbol_errors': symbol_errors,
            'symbol_error_delta': symbol_delta,
            'effective_grade': status,
            'severity_reasons': reasons,
        })

        return {
            "port": port_name,
            "ber_value": frame_density,
            "frame_error_density": frame_density,
            "frame_grade": frame_grade,
            "raw_ber": raw_ber if isinstance(raw_ber, (int, float)) else None,
            "raw_grade": raw_grade,
            "effective_ber": effective_ber if isinstance(effective_ber, (int, float)) else None,
            "effective_grade": effective_grade,
            "symbol_errors": symbol_errors if isinstance(symbol_errors, int) else None,
            "symbol_error_delta": symbol_delta,
            "symbol_grade": symbol_grade,
            "status": status,
            "severity_reasons": reasons,
            "sample_status": sample_status,
            "sample_duration_seconds": stats.get('sample_duration_seconds', 0),
            "delta_packets": stats.get('delta_packets', 0),
            "delta_rx_errors": stats.get('delta_rx_errors', 0),
            "delta_tx_errors": stats.get('delta_tx_errors', 0),
            "total_packets": stats.get('total_packets', 0),
            "rx_errors": stats.get('rx_errors', 0),
            "tx_errors": stats.get('tx_errors', 0),
            "timestamp": stats.get('timestamp', time.time()),
        }

    def get_ber_summary(self) -> Dict[str, Any]:
        """Get overall link-error analysis summary."""
        summary = {
            "total_ports": 0,
            "excellent_ports": [],
            "good_ports": [], 
            "warning_ports": [],
            "critical_ports": [],
            "unknown_ports": []
        }
        
        for port_name, stats in self.current_ber_stats.items():
            summary["total_ports"] += 1
            port_info = self._analyze_port(port_name, stats)
            eff_grade = port_info['status']
            
            if eff_grade == BERGrade.EXCELLENT.value:
                summary["excellent_ports"].append(port_info)
            elif eff_grade == BERGrade.GOOD.value:
                summary["good_ports"].append(port_info)
            elif eff_grade == BERGrade.WARNING.value:
                summary["warning_ports"].append(port_info)
            elif eff_grade == BERGrade.CRITICAL.value:
                summary["critical_ports"].append(port_info)
            else:
                summary["unknown_ports"].append(port_info)
        
        return summary
    
    def detect_ber_anomalies(
        self, summary: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Detect anomalies from the same combined evidence as the report."""
        anomalies = []

        if summary is None:
            summary = self.get_ber_summary()
        port_infos = (summary['critical_ports'] + summary['warning_ports'] +
                      summary['good_ports'] + summary['excellent_ports'] +
                      summary['unknown_ports'])

        for port_info in port_infos:
            port_name = port_info['port']
            grade = port_info['status']
            frame_density = port_info['frame_error_density']
            reasons = port_info.get('severity_reasons') or []
            reason_text = ', '.join(reasons) if reasons else 'combined link error evidence'

            if grade == BERGrade.CRITICAL.value:
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "HIGH_LINK_ERROR_RATE",
                    "severity": "critical",
                    "message": f"Critical link error condition: {reason_text}",
                    "details": {
                        "frame_error_density": frame_density,
                        "raw_ber": port_info.get('raw_ber'),
                        "effective_ber": port_info.get('effective_ber'),
                        "symbol_error_delta": port_info.get('symbol_error_delta'),
                        "frame_density_threshold": self.config[
                            "frame_density_critical_threshold"
                        ],
                        "raw_phy_ber_threshold": self.config[
                            "raw_phy_ber_critical_threshold"
                        ],
                        "effective_phy_ber_threshold": self.config[
                            "effective_phy_ber_critical_threshold"
                        ],
                        "phy_ber_threshold": self.config[
                            "effective_phy_ber_critical_threshold"
                        ],
                        "delta_rx_errors": port_info.get('delta_rx_errors', 0),
                        "delta_tx_errors": port_info.get('delta_tx_errors', 0),
                    },
                    "action": f"Immediate attention required - check cable and transceivers for {port_name}"
                })

            elif grade == BERGrade.WARNING.value:
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "ELEVATED_LINK_ERROR_RATE",
                    "severity": "warning",
                    "message": f"Elevated link error condition: {reason_text}",
                    "details": {
                        "frame_error_density": frame_density,
                        "raw_ber": port_info.get('raw_ber'),
                        "effective_ber": port_info.get('effective_ber'),
                        "symbol_error_delta": port_info.get('symbol_error_delta'),
                        "frame_density_threshold": self.config[
                            "frame_density_warning_threshold"
                        ],
                        "raw_phy_ber_threshold": self.config[
                            "raw_phy_ber_warning_threshold"
                        ],
                        "effective_phy_ber_threshold": self.config[
                            "effective_phy_ber_warning_threshold"
                        ],
                        "phy_ber_threshold": self.config[
                            "effective_phy_ber_warning_threshold"
                        ],
                        "delta_rx_errors": port_info.get('delta_rx_errors', 0),
                        "delta_tx_errors": port_info.get('delta_tx_errors', 0),
                    },
                    "action": f"Monitor {port_name} closely and consider preventive maintenance"
                })
            
            # Trend-based anomalies
            trend_info = self.get_ber_trend(port_name)
            if trend_info["trend"] == "worsening" and trend_info["confidence"] == "high":
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "LINK_ERROR_TREND_WORSENING",
                    "severity": "warning",
                    "message": f"Interface error-density trend worsening on {port_name}",
                    "details": {
                        "trend": trend_info["trend"],
                        "change_ratio": trend_info.get("change_ratio", 0),
                        "current_error_density": frame_density
                    },
                    "action": f"Investigate potential cable degradation on {port_name}"
                })
        
        return anomalies
    
    def export_ber_data_for_web(
        self,
        output_file: str,
        summary: Optional[Dict[str, Any]] = None,
        anomalies: Optional[List[Dict[str, Any]]] = None,
    ):
        """Export BER data for web display - same format as BGP/Link Flap/Optical"""
        if summary is None:
            summary = self.get_ber_summary()
        if anomalies is None:
            anomalies = self.detect_ber_anomalies(summary)
        expected_hosts = getattr(self, 'coverage_expected_hosts', None)
        current_hosts = getattr(self, 'coverage_current_hosts', None)
        coverage_attrs = ''
        coverage_banner = ''
        coverage_partial = False
        if isinstance(expected_hosts, int) and isinstance(current_hosts, int):
            coverage_partial = current_hosts < expected_hosts
            coverage_status = 'partial' if coverage_partial else 'complete'
            coverage_attrs = (
                f' data-coverage-status="{coverage_status}"'
                f' data-coverage-expected="{expected_hosts}"'
                f' data-coverage-current="{current_hosts}"'
            )
            if coverage_partial:
                missing = max(0, expected_hosts - current_hosts)
                coverage_banner = (
                    '<div class="coverage-banner">Partial collection: '
                    f'interface counters returned for {current_hosts} of '
                    f'{expected_hosts} expected devices ({missing} missing or '
                    'stale). Ports for uncollected devices are not shown; the '
                    'status below may be incomplete.</div>'
                )

        # Determine overall health status
        total_problematic = len(summary['warning_ports']) + len(summary['critical_ports'])
        
        if total_problematic == 0:
            overall_status = "healthy"
            status_color = "#4caf50"
        elif len(summary['critical_ports']) > 0:
            overall_status = "critical"
            status_color = "#f44336"
        else:
            overall_status = "warning"
            status_color = "#ff9800"
        
        # Calculate health percentages
        total_ports = summary['total_ports']
        if total_ports > 0:
            excellent_pct = len(summary['excellent_ports']) / total_ports * 100
            good_pct = len(summary['good_ports']) / total_ports * 100
            warning_pct = len(summary['warning_ports']) / total_ports * 100
            critical_pct = len(summary['critical_ports']) / total_ports * 100
        else:
            excellent_pct = good_pct = warning_pct = critical_pct = 0
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Link Error / BER Analysis</title>
    <link rel="shortcut icon" href="/png/favicon.ico">
    <link rel="stylesheet" type="text/css" href="/css/select2.min.css">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; min-height: 100vh; }}
        .page-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #404040; }}
        .page-title {{ font-size: 24px; font-weight: 600; color: #76b900; }}
        .last-updated {{ font-size: 13px; color: #888; }}
        .dashboard-section {{ background: #2d2d2d; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 12px 16px; background: #333; font-weight: 600; font-size: 14px; color: #76b900; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #404040; }}
        .section-content {{ padding: 16px; }}
        .section-content-table {{ padding: 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
        .summary-card {{ background: #252526; padding: 15px; border-radius: 6px; border-left: 3px solid #76b900; cursor: pointer; transition: all 0.2s ease; }}
        .summary-card:hover {{ background: #2d2d2d; transform: translateY(-1px); }}
        .summary-card.active {{ background: #333; border-left-width: 5px; }}
        .card-excellent {{ border-left-color: #76b900; }}
        .card-good {{ border-left-color: #8bc34a; }}
        .card-warning {{ border-left-color: #ff9800; }}
        .card-critical {{ border-left-color: #f44336; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .card-excellent .metric {{ color: #76b900; }}
        .card-good .metric {{ color: #8bc34a; }}
        .card-warning .metric {{ color: #ff9800; }}
        .card-critical .metric {{ color: #f44336; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .badge-gray {{ background: rgba(158, 158, 158, 0.2); color: #999; }}
        .ber-excellent {{ color: #76b900; font-weight: bold; }}
        .ber-good {{ color: #8bc34a; font-weight: bold; }}
        .ber-warning {{ color: #ff9800; font-weight: bold; }}
        .ber-critical {{ color: #f44336; font-weight: bold; }}
        .ber-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .ber-table th, .ber-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; word-wrap: break-word; }}
        .ber-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .ber-table tbody tr {{ background: #252526; }}
        .ber-table tbody tr:hover {{ background: #2d2d2d; }}
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sort-arrow::before {{ content: '▲▼'; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
        .coverage-banner {{ margin: 0 0 20px 0; padding: 9px 12px; background: #35270f; color: #ffb74d; border: 1px solid #6d511d; border-radius: 6px; font-size: 13px; }}
        .empty-row td {{ text-align: center; color: #888; padding: 30px; font-style: italic; }}
        .anomaly-more {{ padding: 8px 4px 2px; color: #888; font-size: 12px; }}
        .ber-table tbody tr.ber-row {{ cursor: pointer; }}
        .ber-table tbody tr.detail-row {{ background: #202020; }}
        .ber-table tbody tr.detail-row:hover {{ background: #202020; }}
        .detail-row td {{ padding: 0; }}
        .detail-panel {{ padding: 14px 20px 18px; background: #202020; border-left: 3px solid #76b900; }}
        .detail-title {{ color: #76b900; font-weight: 700; margin-bottom: 12px; font-size: 14px; }}
        .detail-kv {{ display: grid; grid-template-columns: 180px 1fr; gap: 6px 14px; margin-bottom: 12px; }}
        .detail-kv span:nth-child(odd) {{ color: #999; }}
        .detail-reasons {{ margin: 6px 0 0 18px; line-height: 1.7; }}
        .detail-reasons li {{ color: #ffb74d; }}
        .detail-none {{ color: #76b900; }}
        .anomaly-card {{ margin: 10px 0; padding: 12px 15px; background: #252526; border-radius: 6px; border-left: 3px solid #f44336; }}
        .anomaly-card.warning {{ border-left-color: #ff9800; }}
        .anomaly-card h4 {{ color: #d4d4d4; margin-bottom: 8px; font-size: 14px; }}
        .anomaly-card p {{ font-size: 13px; color: #888; margin: 4px 0; }}
        .btn {{ padding: 8px 14px; border: none; border-radius: 4px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 6px; }}
        .btn-primary {{ background: linear-gradient(0deg, #76b900 0%, #5a8c00 100%); color: white; }}
        .btn-primary:hover {{ background: linear-gradient(0deg, #8bd400 0%, #6ba000 100%); }}
        .btn-secondary {{ background: linear-gradient(0deg, #4fc3f7 0%, #0288d1 100%); color: white; }}
        .btn-secondary:hover {{ background: linear-gradient(0deg, #81d4fa 0%, #039be5 100%); }}
        .action-buttons {{ display: flex; gap: 10px; align-items: center; }}
        .device-search-container {{ display: flex; align-items: center; gap: 8px; }}
        .device-search-container .select2-container {{ min-width: 200px; }}
        .device-search-container .select2-container--default .select2-selection--single {{ height: 34px; border: 1px solid #555; border-radius: 4px; background: #3c3c3c; display: flex; align-items: center; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered {{ line-height: 34px; color: #d4d4d4; padding-left: 10px; font-size: 13px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow {{ height: 34px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__placeholder {{ color: #888; }}
        .select2-dropdown {{ background: #2d2d2d; border: 1px solid #555; }}
        .select2-container--default .select2-search--dropdown .select2-search__field {{ background: #3c3c3c; border: 1px solid #555; color: #d4d4d4; }}
        .select2-container--default .select2-results__option {{ color: #d4d4d4; padding: 8px 12px; }}
        .select2-container--default .select2-results__option--highlighted[aria-selected] {{ background: #76b900; color: #000; }}
        .select2-container--default .select2-results__option[aria-selected=true] {{ background: #3c3c3c; }}
        .clear-search-btn {{ background: #f44336; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; display: none; }}
        .clear-search-btn:hover {{ background: #d32f2f; }}
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: #1e1e1e; }}
        ::-webkit-scrollbar-thumb {{ background: #404040; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #555; }}
        @keyframes spin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body{coverage_attrs}>
    <div class="page-header">
        <div>
            <div class="page-title">Link Error / BER Analysis</div>
            <div class="last-updated">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="action-buttons">
            <div class="device-search-container">
                <select id="deviceSearch" style="width: 200px;"><option value="">Search Device...</option></select>
                <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">✕</button>
            </div>
            <button id="thresholds-btn" onclick="openThresholdsModal()" class="btn btn-secondary" title="Thresholds &amp; grading reference">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
                Thresholds
            </button>
            <button id="run-analysis" onclick="runAnalysis()" class="btn btn-secondary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>
                Run Analysis
            </button>
            <button id="download-csv" onclick="downloadCSV()" class="btn btn-primary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>
                Download CSV
            </button>
        </div>
    </div>
    {coverage_banner}
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            BER Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-ports-card">
                    <div class="metric" id="total-ports">{total_ports}</div>
                    <div class="metric-label">Total Ports</div>
                </div>
                <div class="summary-card card-excellent" id="excellent-card">
                    <div class="metric" id="excellent-ports">{len(summary['excellent_ports'])}</div>
                    <div class="metric-label">Excellent</div>
                </div>
                <div class="summary-card card-good" id="good-card">
                    <div class="metric" id="good-ports">{len(summary['good_ports'])}</div>
                    <div class="metric-label">Good</div>
                </div>
                <div class="summary-card card-warning" id="warning-card">
                    <div class="metric" id="warning-ports">{len(summary['warning_ports'])}</div>
                    <div class="metric-label">Warning</div>
                </div>
                <div class="summary-card card-critical" id="critical-card">
                    <div class="metric" id="critical-ports">{len(summary['critical_ports'])}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="summary-card card-info" id="unknown-card">
                    <div class="metric" id="unknown-ports">{len(summary['unknown_ports'])}</div>
                    <div class="metric-label">Awaiting Sample</div>
                </div>
            </div>
        </div>
    </div>
"""
        
        # Add anomalies section if any
        if anomalies:
            html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
            BER Anomalies Detected ({len(anomalies)})
        </div>
        <div class="section-content">
"""
            for anomaly in anomalies[:10]:  # Show top 10 anomalies
                severity_class = "warning" if anomaly['severity'] == 'warning' else ""
                anomaly_device_key = html.escape(str(anomaly['device']), quote=True)
                html_content += f"""
            <div class="anomaly-card {severity_class}" data-device-key="{anomaly_device_key}">
                <h4>{anomaly['device']}:{anomaly['interface']}</h4>
                <p>{anomaly['message']}</p>
                <p><strong>Action:</strong> {anomaly['action']}</p>
            </div>
"""
            if len(anomalies) > 10:
                html_content += f"""
            <div class="anomaly-more">Showing the 10 highest-severity of {len(anomalies)} anomalies. All affected ports are listed in the Interface Error Status table below.</div>
"""
            html_content += """
        </div>
    </div>
"""
        
        # Add detailed table  
        html_content += """
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Interface Error Status
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="ber-table" id="ber-table">
                <thead>
                    <tr>
                        <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="1" data-type="port">Interface <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="2" data-type="ber-status">Status <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="3" data-type="ber-value">Frame Error Density <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="4" data-type="ber-value">Physical BER <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="5" data-type="ber-value">Effective BER <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="6" data-type="number">PHY Symbol Δ / Total <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="7" data-type="number">Δ Pkt <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="8" data-type="number">Δ RX Err <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="9" data-type="number">Δ TX Err <span class="sort-arrow"></span></th>
                        <th class="sortable" data-column="10" data-type="time">Updated / Window <span class="sort-arrow"></span></th>
                    </tr>
                </thead>
                <tbody id="ber-data">
"""
        
        # Add all ports to table (sorted by health - problems first, then good ones)
        all_ports = (summary['excellent_ports'] + summary['good_ports'] +
                    summary['warning_ports'] + summary['critical_ports'] +
                    summary['unknown_ports'])
        
        # Sort ports by BER status priority (critical/warning first)
        def get_ber_priority(port_info):
            # Sort by the effective (raw-BER-escalated) status — worst first.
            return {
                BERGrade.CRITICAL.value: 0,
                BERGrade.WARNING.value: 1,
                BERGrade.GOOD.value: 2,
                BERGrade.EXCELLENT.value: 3,
            }.get(port_info.get('status'), 4)
        
        sorted_ports = sorted(all_ports, key=get_ber_priority)

        # Per-port evidence surfaced in the expandable detail panel.  These are
        # values the analyzer already computed; nothing new is collected.
        port_details: Dict[str, Any] = {}

        for port_info in sorted_ports:
            port_name = port_info['port']
            device = port_name.split(':')[0] if ':' in port_name else "unknown"
            interface = port_name.split(':')[1] if ':' in port_name else port_name
            
            # Status = effective grade (frame BER escalated by raw/physical BER), computed once
            # in get_ber_summary so the summary cards and this table always agree.
            ber_value = port_info['ber_value']
            status = str(port_info.get('status') or 'unknown').upper()
            badge_class = {
                "EXCELLENT": "badge badge-green",
                "GOOD": "badge badge-green",
                "WARNING": "badge badge-orange",
                "CRITICAL": "badge badge-red",
            }.get(status, "badge badge-gray")
            
            sample_status = port_info.get('sample_status')
            delta_packets = port_info.get('delta_packets', 0)
            sample_target = self.config['min_packets_for_analysis']
            if (sample_status == 'insufficient_traffic'
                    and isinstance(ber_value, (int, float))
                    and delta_packets > 0):
                observed = f"{ber_value:.2e}" if ber_value > 0 else "0"
                ber_display = (
                    f'<span title="Observed low-traffic value; grading waits '
                    f'for {sample_target:,} packets while the baseline keeps '
                    f'accumulating">{observed} '
                    f'({delta_packets:,}/{sample_target:,})</span>'
                )
            elif sample_status == 'insufficient_traffic':
                ber_display = "No traffic"
            elif sample_status == 'counter_reset':
                ber_display = "Counter reset"
            elif sample_status == 'baseline':
                ber_display = "Baseline"
            elif port_info.get('frame_grade') == BERGrade.UNKNOWN.value:
                ber_display = "N/A"
            else:
                ber_display = f"{ber_value:.2e}" if ber_value > 0 else "0"
            
            # RAW PHY BER (pre-FEC) — already parsed during classification.
            raw_phy_val = port_info.get('raw_ber')
            raw_phy_display = f"{raw_phy_val:.2e}" if isinstance(raw_phy_val, (int, float)) else "N/A"

            # Effective (post-FEC) PHY BER + PHY symbol errors (from l1-show) — what HPC engineering
            # tracks day-to-day.
            eff_val = port_info.get('effective_ber')
            eff_display = f"{eff_val:.2e}" if isinstance(eff_val, (int, float)) else "N/A"
            sym_val = port_info.get('symbol_errors')
            sym_delta = port_info.get('symbol_error_delta')
            if isinstance(sym_val, int) and isinstance(sym_delta, int):
                sym_display = f"+{sym_delta:,} / {sym_val:,}"
            elif isinstance(sym_val, int):
                sym_display = f"baseline / {sym_val:,}"
            else:
                sym_display = "N/A"

            timestamp = datetime.fromtimestamp(port_info['timestamp']).strftime('%H:%M:%S')
            sample_window = self._format_duration(
                port_info.get('sample_duration_seconds', 0)
            )
            device_key = html.escape(str(device), quote=True)
            port_key = html.escape(str(port_name), quote=True)

            # Numeric sort keys so composite/text cells sort correctly.
            sym_sort = str(sym_delta) if isinstance(sym_delta, int) else ''
            try:
                ts_sort = float(port_info['timestamp'])
            except (TypeError, ValueError):
                ts_sort = 0.0

            port_details[port_name] = {
                'status': status,
                'severity_reasons': port_info.get('severity_reasons') or [],
                'sample_status': port_info.get('sample_status'),
                'frame_error_density': port_info.get('frame_error_density'),
                'raw_ber': port_info.get('raw_ber'),
                'effective_ber': port_info.get('effective_ber'),
                'symbol_errors': port_info.get('symbol_errors'),
                'symbol_error_delta': port_info.get('symbol_error_delta'),
                'delta_packets': port_info.get('delta_packets', 0),
                'delta_rx_errors': port_info.get('delta_rx_errors', 0),
                'delta_tx_errors': port_info.get('delta_tx_errors', 0),
                'sample_window': sample_window,
            }

            html_content += f"""
                <tr class="ber-row" data-device-key="{device_key}" data-status="{status.lower()}" data-port="{port_key}" onclick="toggleBerDetails(this)">
                    <td>{canonical(device)}</td>
                    <td>{interface}</td>
                    <td><span class="{badge_class}">{status}</span></td>
                    <td>{ber_display}</td>
                    <td>{raw_phy_display}</td>
                    <td>{eff_display}</td>
                    <td data-sort="{sym_sort}">{sym_display}</td>
                    <td>{port_info['delta_packets']:,}</td>
                    <td>{port_info['delta_rx_errors']:,}</td>
                    <td>{port_info['delta_tx_errors']:,}</td>
                    <td data-sort="{ts_sort}">{timestamp} / {sample_window}</td>
                </tr>
"""
        
        if not sorted_ports:
            if coverage_partial:
                empty_message = (
                    "No interface counters were collected in this run. See the "
                    "partial collection notice above."
                )
            else:
                empty_message = (
                    "No physical interfaces reported link errors in the current "
                    "collection."
                )
            html_content += f"""
                <tr class="empty-row"><td colspan="11">{empty_message}</td></tr>
"""

        html_content += f"""
                </tbody>
            </table>
        </div>
    </div>

    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            Link Error / BER Thresholds
        </div>
        <div class="section-content-table">
            <table class="ber-table">
                <thead>
                    <tr><th>Parameter</th><th>Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>Excellent</td><td>Zero new errors</td><td>No new error events in the sample</td></tr>
                    <tr><td>Frame Density</td><td>Warning &ge; {self.config['frame_density_warning_threshold']:.0e}; Critical &ge; {self.config['frame_density_critical_threshold']:.0e}</td><td>Interface error events per observed bit volume</td></tr>
                    <tr><td>Raw PHY BER (pre-FEC)</td><td>Warning &ge; {self.config['raw_phy_ber_warning_threshold']:.0e}; Critical &ge; {self.config['raw_phy_ber_critical_threshold']:.0e}</td><td>Physical-link quality before FEC correction</td></tr>
                    <tr><td>Effective PHY BER (post-FEC)</td><td>Warning &ge; {self.config['effective_phy_ber_warning_threshold']:.0e}; Critical &ge; {self.config['effective_phy_ber_critical_threshold']:.0e}</td><td>Configured by notifications.yaml network.ber_error_rate (critical is 10×)</td></tr>
                    <tr><td>PHY Symbol Δ</td><td>Warning &ge; {self.config['symbol_error_warning_delta']:,}; Critical &ge; {self.config['symbol_error_critical_delta']:,}</td><td>New symbol errors since the previous L1 sample</td></tr>
                    <tr><td>Analysis Method</td><td>Worst RX/TX direction</td><td>Interface error events per observed bit volume; this is not a physical BER</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/></svg>
            Understanding BER Metrics
        </div>
        <div class="section-content" style="font-size: 13px; color: #888;">
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li><strong style="color: #d4d4d4;">Frame Error Density</strong>: The worse RX/TX <code>/proc/net/dev</code> error-event count divided by that direction's observed bit volume. It is an operational density indicator, not a physical bit-error rate.</li>
                <li><strong style="color: #d4d4d4;">Physical BER</strong>: Physical layer bit error rate from l1-show/PCS layer. Shows actual fiber and optics health including FEC-corrected errors.</li>
                <li><strong style="color: #d4d4d4;">Effective BER</strong>: Post-FEC bit error rate from l1-show (<code>effective_ber_coef × 10^effective_ber_magnitude</code>). This is the error rate the traffic actually sees after FEC correction — the primary day-to-day health metric.</li>
                <li><strong style="color: #d4d4d4;">PHY Symbol Errors</strong>: The table shows new symbol errors and the lifetime total from <code>l1-show</code>. Severity uses only the new delta; a reset establishes a fresh baseline.</li>
                <li><strong style="color: #d4d4d4;">Sample window</strong>: The Δ packet/error columns and the window beside Updated describe the exact interval used for Frame Error Density. A value followed by progress such as <code>0 (509/1,000)</code> is the observed low-traffic value; the baseline keeps accumulating and a zero-error sample is not graded until the target is reached. Errors observed before the target are evaluated immediately. Raw and Effective BER are current L1 snapshots.</li>
            </ul>
        </div>
    </div>

"""
        
        details_json = json.dumps(
            port_details, separators=(",", ":"), ensure_ascii=True
        ).replace("</", "<\\/")
        html_content += f"""
    <script>window.__berPortDetails = {details_json};</script>
"""

        html_content += """
    <!-- jQuery and Select2 for device search -->
    <script src="/css/jquery-3.5.1.min.js"></script>
    <script src="/css/select2.min.js"></script>
    
    <script>
        // Filter functionality
        let currentFilter = 'ALL';
        let allRows = [];
        let deviceSearchActive = false;
        let selectedDevice = '';
        
        document.addEventListener('DOMContentLoaded', function() {
            // Store all real data rows for filtering (excludes empty-state / detail rows)
            allRows = Array.from(document.querySelectorAll('#ber-data tr.ber-row'));
            
            // Add click events to summary cards
            setupCardEvents();
            
            // Initialize table sorting
            initTableSorting();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });
        
        function setupCardEvents() {
            console.log('BER: Setting up card events...');
            
            // Check if elements exist
            const totalPortsCard = document.getElementById('total-ports-card');
            console.log('BER: total-ports-card found?', totalPortsCard);
            
            if (totalPortsCard) {
                totalPortsCard.addEventListener('click', function() {
                    console.log('BER: Total ports clicked');
                    if (parseInt(document.getElementById('total-ports').textContent) > 0) {
                        filterPorts('TOTAL');
                    }
                });
            } else {
                console.error('BER: total-ports-card not found!');
            }
            
            document.getElementById('excellent-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('excellent-ports').textContent) > 0) {
                    filterPorts('EXCELLENT');
                }
            });
            
            document.getElementById('good-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('good-ports').textContent) > 0) {
                    filterPorts('GOOD');
                }
            });
            
            document.getElementById('warning-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('warning-ports').textContent) > 0) {
                    filterPorts('WARNING');
                }
            });
            
            document.getElementById('critical-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('critical-ports').textContent) > 0) {
                    filterPorts('CRITICAL');
                }
            });

            document.getElementById('unknown-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('unknown-ports').textContent) > 0) {
                    filterPorts('UNKNOWN');
                }
            });
        }
        
        function removeBerDetailRows() {
            document.querySelectorAll('#ber-data tr.detail-row').forEach(r => r.remove());
        }

        function filterPorts(filterType) {
            currentFilter = filterType;
            removeBerDetailRows();

            // Clear device search when using card filters
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Clear active state from all cards
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });
            
            let filteredRows = allRows;
            let filterText = '';
            
            if (filterType === 'EXCELLENT') {
                filteredRows = allRows.filter(row => row.dataset.status === 'excellent');
                filterText = 'Showing ' + filteredRows.length + ' Excellent Ports';
                document.getElementById('excellent-card').classList.add('active');
            } else if (filterType === 'GOOD') {
                filteredRows = allRows.filter(row => row.dataset.status === 'good');
                filterText = 'Showing ' + filteredRows.length + ' Good Ports';
                document.getElementById('good-card').classList.add('active');
            } else if (filterType === 'WARNING') {
                filteredRows = allRows.filter(row => row.dataset.status === 'warning');
                filterText = 'Showing ' + filteredRows.length + ' Warning Ports';
                document.getElementById('warning-card').classList.add('active');
            } else if (filterType === 'CRITICAL') {
                filteredRows = allRows.filter(row => row.dataset.status === 'critical');
                filterText = 'Showing ' + filteredRows.length + ' Critical Ports';
                document.getElementById('critical-card').classList.add('active');
            } else if (filterType === 'UNKNOWN') {
                filteredRows = allRows.filter(row => row.dataset.status === 'unknown');
                filterText = 'Showing ' + filteredRows.length + ' Ports Awaiting Sample';
                document.getElementById('unknown-card').classList.add('active');
            } else if (filterType === 'TOTAL') {
                filteredRows = allRows;
                document.getElementById('total-ports-card').classList.add('active');
            }
            
            // Show filter info for all filters except TOTAL
            if (filterType !== 'ALL' && filterType !== 'TOTAL') {
                document.getElementById('filter-info').style.display = 'block';
                document.getElementById('filter-text').textContent = filterText;
            } else {
                document.getElementById('filter-info').style.display = 'none';
            }
            
            // Hide all rows first
            allRows.forEach(row => row.style.display = 'none');
            
            // Show filtered rows
            filteredRows.forEach(row => row.style.display = '');
        }
        
        function clearFilter() {
            currentFilter = 'ALL';
            removeBerDetailRows();
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });
            document.getElementById('filter-info').style.display = 'none';
            
            // Also clear device search
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Show all rows
            allRows.forEach(row => row.style.display = '');
        }
        
        // ===== Device Search Functions =====
        function initDeviceSearch() {
            $('#deviceSearch').select2({
                placeholder: 'Search Device...',
                allowClear: true,
                width: '250px',
                dropdownAutoWidth: true,
                matcher: function(params, data) {
                    if ($.trim(params.term) === '') return data;
                    if (typeof data.text === 'undefined') return null;
                    if (data.text.toLowerCase().indexOf(params.term.toLowerCase()) > -1) return data;
                    return null;
                }
            });
            
            $('#deviceSearch').on('select2:select', function(e) {
                const device = e.params.data.id;
                if (device) filterByDevice(device);
            });
            
            $('#deviceSearch').on('select2:clear', function(e) {
                clearDeviceSearch();
            });
        }
        
        function populateDeviceList() {
            const deviceSet = new Set();
            allRows.forEach(row => {
                // First column is the device name
                const deviceName = row.cells[0]?.textContent?.trim();
                if (deviceName) deviceSet.add(deviceName);
            });
            
            const sortedDevices = Array.from(deviceSet).sort((a, b) => 
                a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
            );
            
            const select = document.getElementById('deviceSearch');
            select.innerHTML = '<option value="">Search Device...</option>';
            sortedDevices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.textContent = device;
                select.appendChild(option);
            });
        }
        
        function filterByDevice(deviceName) {
            if (!deviceName) return;
            
            selectedDevice = deviceName;
            deviceSearchActive = true;
            removeBerDetailRows();

            // Clear card-based filter
            currentFilter = 'ALL';
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            // Filter table rows
            let matchCount = 0;
            allRows.forEach(row => {
                const rowDeviceName = row.cells[0]?.textContent?.trim();
                if (rowDeviceName === deviceName) {
                    row.style.display = '';
                    matchCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show filter info
            document.getElementById('filter-info').style.display = 'block';
            document.getElementById('filter-text').textContent = 'Showing interfaces for device: ' + deviceName + ' (' + matchCount + ' interfaces)';
            document.getElementById('clearSearchBtn').style.display = 'inline-block';
        }
        
        function clearDeviceSearch() {
            selectedDevice = '';
            deviceSearchActive = false;
            removeBerDetailRows();
            $('#deviceSearch').val('').trigger('change');
            document.getElementById('clearSearchBtn').style.display = 'none';
            document.getElementById('filter-info').style.display = 'none';
            allRows.forEach(row => row.style.display = '');
        }
        
        // Generic table sorting functionality
        let tableSortState = { column: -1, direction: 'asc' };
        
        function initTableSorting() {
            const headers = document.querySelectorAll('.sortable');
            headers.forEach(header => {
                header.addEventListener('click', function() {
                    const column = parseInt(this.dataset.column);
                    const type = this.dataset.type;
                    
                    // Toggle sort direction
                    if (tableSortState.column === column) {
                        tableSortState.direction = tableSortState.direction === 'asc' ? 'desc' : 'asc';
                    } else {
                        tableSortState.direction = 'asc';
                    }
                    tableSortState.column = column;
                    
                    // Update header styling
                    headers.forEach(h => h.classList.remove('asc', 'desc'));
                    this.classList.add(tableSortState.direction);
                    
                    // Sort table
                    sortBERTable(column, tableSortState.direction, type);
                });
            });
        }
        
        function sortBERTable(columnIndex, direction, type) {
            const table = document.getElementById('ber-table');
            const tbody = table.querySelector('tbody');
            removeBerDetailRows();
            // Only reorder real data rows; any empty-state placeholder stays put.
            const rows = Array.from(tbody.querySelectorAll('tr.ber-row'));
            if (!rows.length) return;

            // Prefer an explicit numeric/time data-sort key over the formatted
            // cell text so composite cells (e.g. "+1,234 / 5,000") sort correctly.
            const sortRaw = (row) => {
                const cell = row.cells[columnIndex];
                if (!cell) return '';
                return cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent.trim();
            };

            rows.sort((a, b) => {
                let aVal = (a.cells[columnIndex]?.textContent || '').trim();
                let bVal = (b.cells[columnIndex]?.textContent || '').trim();

                // Extract actual text for status columns (remove HTML)
                if (type === 'ber-status') {
                    aVal = a.cells[columnIndex]?.querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex]?.querySelector('span')?.textContent || bVal;
                }

                let result = 0;

                switch(type) {
                    case 'port':
                        result = comparePort(aVal, bVal);
                        break;
                    case 'ber-status':
                        result = compareBERStatus(aVal, bVal);
                        break;
                    case 'ber-value':
                        result = compareBERValue(aVal, bVal);
                        break;
                    case 'number': {
                        const numA = parseFloat(String(sortRaw(a)).replace(/,/g, ''));
                        const numB = parseFloat(String(sortRaw(b)).replace(/,/g, ''));
                        if (isNaN(numA) && isNaN(numB)) result = 0;
                        else if (isNaN(numA)) result = 1;
                        else if (isNaN(numB)) result = -1;
                        else result = numA - numB;
                        break;
                    }
                    case 'time': {
                        const rawA = a.cells[columnIndex]?.dataset.sort;
                        const rawB = b.cells[columnIndex]?.dataset.sort;
                        if (rawA !== undefined && rawB !== undefined) {
                            result = parseFloat(rawA) - parseFloat(rawB);
                        } else {
                            result = aVal.localeCompare(bVal);
                        }
                        break;
                    }
                    case 'string':
                    default:
                        result = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });
                        break;
                }

                return direction === 'desc' ? -result : result;
            });

            // Re-append in sorted order (appendChild moves the existing nodes).
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function comparePort(a, b) {
            if (a === 'N/A') return 1;
            if (b === 'N/A') return -1;

            // Handle port sorting (swp1, swp10, swp1s0, etc.)
            const extractPortNumber = (port) => {
                const match = port.match(/swp(\\d+)(?:s(\\d+))?/);
                if (match) {
                    const mainPort = parseInt(match[1]);
                    const subPort = match[2] ? parseInt(match[2]) : 0;
                    return mainPort * 1000 + subPort;
                }
                return null;
            };

            const na = extractPortNumber(a);
            const nb = extractPortNumber(b);
            // Both are swp interfaces: compare on the derived numeric key.
            if (na !== null && nb !== null) return na - nb;
            // Keep swp interfaces grouped before non-swp names (eth1, eno1, ...).
            if (na !== null) return -1;
            if (nb !== null) return 1;
            // Neither matches swp: stable numeric-aware string compare of a vs b.
            return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
        }
        
        function compareBERStatus(a, b) {
            const priority = {
                'CRITICAL': 0,
                'WARNING': 1,
                'GOOD': 2,
                'EXCELLENT': 3,
                'UNKNOWN': 4
            };
            
            return (priority[a] ?? 5) - (priority[b] ?? 5);
        }
        
        function compareBERValue(a, b) {
            // Handle scientific notation (1.23e-5) and plain numbers
            const numA = parseFloat(a);
            const numB = parseFloat(b);
            
            if (isNaN(numA) && isNaN(numB)) return 0;
            if (isNaN(numA)) return 1;
            if (isNaN(numB)) return -1;

            return numA - numB;
        }

        // ===== Expandable per-row detail panels =====
        function berEsc(v) {
            return String(v === null || v === undefined ? '' : v).replace(/[&<>"]/g, function(c) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
            });
        }

        function berFmtBer(v) {
            if (v === null || v === undefined || v === '') return 'N/A';
            const n = Number(v);
            if (isNaN(n)) return berEsc(String(v));
            if (n === 0) return '0';
            return n.toExponential(2);
        }

        function berFmtInt(v) {
            if (v === null || v === undefined || v === '') return 'N/A';
            const n = Number(v);
            return isNaN(n) ? berEsc(String(v)) : n.toLocaleString();
        }

        function toggleBerDetails(row) {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('detail-row')) { next.remove(); return; }
            removeBerDetailRows();
            const details = (window.__berPortDetails || {})[row.dataset.port];
            if (!details) return;
            const device = row.cells[0] ? row.cells[0].textContent.trim() : '';
            const iface = row.cells[1] ? row.cells[1].textContent.trim() : '';
            const reasons = Array.isArray(details.severity_reasons) ? details.severity_reasons : [];
            const reasonsHtml = reasons.length
                ? '<ul class="detail-reasons">' + reasons.map(function(r) { return '<li>' + berEsc(r) + '</li>'; }).join('') + '</ul>'
                : '<div class="detail-none">No warning/critical evidence — link is within thresholds.</div>';
            const symText = (details.symbol_error_delta !== null && details.symbol_error_delta !== undefined)
                ? ('+' + berFmtInt(details.symbol_error_delta) + ' since last sample (total ' + berFmtInt(details.symbol_errors) + ')')
                : berFmtInt(details.symbol_errors);
            const detail = document.createElement('tr');
            detail.className = 'detail-row';
            detail.innerHTML = '<td colspan="11"><div class="detail-panel">'
                + '<div class="detail-title">' + berEsc(device) + ' : ' + berEsc(iface) + '</div>'
                + '<div class="detail-kv">'
                + '<span>Status</span><span>' + berEsc(String(details.status || '').toUpperCase()) + '</span>'
                + '<span>Sample State</span><span>' + berEsc(String(details.sample_status || 'analyzed')) + '</span>'
                + '<span>Frame Error Density</span><span>' + berFmtBer(details.frame_error_density) + '</span>'
                + '<span>Physical BER (pre-FEC)</span><span>' + berFmtBer(details.raw_ber) + '</span>'
                + '<span>Effective BER (post-FEC)</span><span>' + berFmtBer(details.effective_ber) + '</span>'
                + '<span>PHY Symbol Errors</span><span>' + berEsc(symText) + '</span>'
                + '<span>&Delta; Packets / RX Err / TX Err</span><span>' + berFmtInt(details.delta_packets) + ' / ' + berFmtInt(details.delta_rx_errors) + ' / ' + berFmtInt(details.delta_tx_errors) + '</span>'
                + '<span>Sample Window</span><span>' + berEsc(String(details.sample_window || 'N/A')) + '</span>'
                + '</div>'
                + '<div><strong style="color:#d4d4d4;">Severity evidence:</strong></div>'
                + reasonsHtml
                + '</div></td>';
            row.after(detail);
        }

        // Run Analysis Function
        async function runAnalysis() {
            const button = document.getElementById('run-analysis');
            const originalText = button.innerHTML;
            let notification = null;
            
            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/>
                </svg>
                Running...
            `;
            
            try {
                let baseline = null;
                if (typeof window.lldpqCaptureAnalysisState === 'function') {
                    baseline = await window.lldpqCaptureAnalysisState('ber');
                }

                const response = await fetch('/trigger-monitor?scope=ber', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await response.json();
                if (!response.ok || data.status !== 'success' || !data.trigger_id || data.scope !== 'ber') {
                    throw new Error(data.message || 'Failed to trigger monitor analysis');
                }

                console.log('✅ Monitor analysis triggered successfully');
                notification = document.createElement('div');
                    notification.style.cssText = `
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        background: #c87f0a;
                        color: white;
                        padding: 15px 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                        z-index: 1000;
                        font-size: 14px;
                        max-width: 350px;
                        font-family: monospace;
                    `;
                    notification.innerHTML = `
                        <strong>✅ Monitor Analysis Started</strong><br>
                        The BER analysis is running in the background.<br>
                        <small>Page will refresh after the new BER results are completely published.</small>
                    `;
                document.body.appendChild(notification);

                if (typeof window.waitForLldpqAnalysisCompletion === 'function') {
                    await window.waitForLldpqAnalysisCompletion(
                        baseline, { scope: 'ber', pipelineId: data.trigger_id });
                } else {
                    await new Promise(resolve => setTimeout(resolve, 35000));
                }

                window.location.reload();
            } catch (error) {
                console.error('❌ Error triggering analysis:', error);
                if (notification) notification.remove();
                alert('Analysis did not complete: ' + (error.message || error));
                button.disabled = false;
                button.innerHTML = originalText;
            }
        }

        // CSV Download Function
        function downloadCSV() {
            try {
                // Get current date for filename
                const now = new Date();
                const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
                const timeStr = now.toTimeString().slice(0, 5).replace(':', '-'); // HH-MM
                const filename = `BER_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Header + rows are read straight from the table so any columns (Effective BER,
                // PHY Symbol Errors, ...) are picked up automatically and stay in sync with the view.
                const table = document.getElementById('ber-table');
                const headers = Array.from(table.querySelectorAll('thead th')).map(function(th){
                    return th.textContent.replace('▲▼', '').trim();
                });
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr.ber-row');

                // Detect an active filter so the exported subset is clearly labelled.
                const filterActive = deviceSearchActive || (currentFilter !== 'ALL' && currentFilter !== 'TOTAL');

                // Comment/summary block goes BEFORE the header row so standard CSV
                // parsers (which only skip leading comment lines) read it correctly.
                let csvContent = `# Link Error / BER Analysis Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Ports: ${document.getElementById('total-ports').textContent}\\n`;
                csvContent += `# Excellent: ${document.getElementById('excellent-ports').textContent}\\n`;
                csvContent += `# Good: ${document.getElementById('good-ports').textContent}\\n`;
                csvContent += `# Warning: ${document.getElementById('warning-ports').textContent}\\n`;
                csvContent += `# Critical: ${document.getElementById('critical-ports').textContent}\\n`;
                csvContent += `# Awaiting Sample: ${document.getElementById('unknown-ports').textContent}\\n`;
                if (filterActive) {
                    csvContent += `# NOTE: a filter is active - only the currently visible rows are exported; the counts above reflect the full fabric.\\n`;
                }
                csvContent += `#\\n`;
                csvContent += headers.join(',') + '\\n';

                // Process each visible data row (all columns, dynamically)
                rows.forEach(row => {
                    if (row.style.display === 'none') return;
                    const cells = row.querySelectorAll('td');
                    if (!cells.length) return;
                    const rowData = Array.from(cells).map(function(td){
                        const span = td.querySelector('span');
                        return (span ? span.textContent : td.textContent).trim();
                    });
                    const escapedData = rowData.map(field => {
                        if (field.includes(',') || field.includes('"') || field.includes('\\n')) {
                            return '"' + field.replace(/"/g, '""') + '"';
                        }
                        return field;
                    });
                    csvContent += escapedData.join(',') + '\\n';
                });
                
                // Create and trigger download
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = filename;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                console.log(`✅ CSV downloaded: ${filename}`);
                
            } catch (error) {
                console.error('❌ Error generating CSV:', error);
                alert('Error generating CSV file. Please try again.');
            }
        }
    </script>
    <!-- Thresholds reference modal: the in-page threshold/explanation sections are
         relocated in here at load time and shown via the "Thresholds" toolbar button. -->
    <div id="thresholdModal" class="threshold-modal" onclick="if(event.target===this)closeThresholdsModal()">
        <div class="threshold-modal-box">
            <div class="threshold-modal-head">
                <h2>Thresholds</h2>
                <button type="button" class="threshold-modal-close" onclick="closeThresholdsModal()" title="Close">&times;</button>
            </div>
            <div id="thresholdModalBody" class="threshold-modal-body"></div>
        </div>
    </div>
    <style>
        .threshold-modal { display:none; position:fixed; inset:0; z-index:1000; background:rgba(0,0,0,0.65); }
        .threshold-modal.open { display:flex; align-items:flex-start; justify-content:center; }
        .threshold-modal-box { background:#1e1e1e; border:1px solid #3c3c3c; border-radius:8px; width:92%; max-width:920px; margin:40px 16px; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 12px 48px rgba(0,0,0,0.55); }
        .threshold-modal-head { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-bottom:1px solid #3c3c3c; }
        .threshold-modal-head h2 { margin:0; font-size:16px; color:#e0e0e0; }
        .threshold-modal-close { background:none; border:none; color:#aaa; font-size:24px; line-height:1; cursor:pointer; padding:0 6px; }
        .threshold-modal-close:hover { color:#fff; }
        .threshold-modal-body { padding:4px 18px 18px; overflow:auto; }
        .threshold-modal-body .dashboard-section { margin:14px 0 0; }
        .threshold-modal-body .dashboard-section:first-child { margin-top:6px; }
    </style>
    <script>
        (function () {
            function buildThresholdModal() {
                var body = document.getElementById('thresholdModalBody');
                if (!body) return;
                var sections = Array.prototype.slice.call(document.querySelectorAll('.dashboard-section'));
                var start = -1;
                for (var i = 0; i < sections.length; i++) {
                    var h = sections[i].querySelector('.section-header');
                    if (h && /threshold/i.test(h.textContent)) { start = i; break; }
                }
                if (start < 0) return;
                // Move the threshold section + any trailing explanation sections into the modal.
                for (var j = start; j < sections.length; j++) { body.appendChild(sections[j]); }
            }
            window.openThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.add('open'); };
            window.closeThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.remove('open'); };
            document.addEventListener('keydown', function (e) { if (e.key === 'Escape') window.closeThresholdsModal(); });
            buildThresholdModal();
        })();
    </script>
    <script src="/p2p-alias.js"></script>
    <script src="/css/analysis-guard.js?v=20260707-scoped-runner-2"></script>
</body>
</html>"""
        
        try:
            self._atomic_text_write(output_file, html_content)
            print(f"BER analysis report generated: {output_file}")
        except Exception as e:
            print(f"Error writing BER analysis report: {e}")
