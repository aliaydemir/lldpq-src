#!/usr/bin/env python3
"""
Optical Diagnostics Analysis Module for LLDPq
Advanced SFP/QSFP monitoring and cable health assessment

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import time
import re
import os
import math
from datetime import datetime
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

class OpticalHealth(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    DOWN = "down"
    UNPLUGGED = "unplugged"
    UNKNOWN = "unknown"


def coerce_optical_health(value: Any) -> OpticalHealth:
    """Return a known health enum for current and historical status values."""
    if isinstance(value, OpticalHealth):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith("opticalhealth."):
            normalized = normalized.split(".", 1)[1]
        try:
            return OpticalHealth(normalized)
        except ValueError:
            pass
    return OpticalHealth.UNKNOWN

class OpticalAnalyzer:
    # Industry standard optical power thresholds (dBm)
    DEFAULT_THRESHOLDS = {
        "rx_power_min_dbm": -14.0,      # Minimum receive power
        "rx_power_max_dbm": 7.0,        # Maximum receive power (critical high)
        # High RX thresholds: treat >5 dBm as warning, >7 dBm as critical (typical DR optics)
        "rx_power_warning_high_dbm": 5.0,
        "rx_power_critical_high_dbm": 7.0,
        "tx_power_min_dbm": -11.0,      # Minimum transmit power
        "tx_power_max_dbm": 4.0,        # Maximum transmit power
        "temperature_max_c": 70.0,      # Maximum operating temperature
        "temperature_min_c": 0.0,       # Minimum operating temperature
        "voltage_min_v": 3.0,           # Minimum supply voltage
        "voltage_max_v": 3.6,           # Maximum supply voltage
        "bias_current_max_ma": 100.0,   # Maximum laser bias current
        "link_margin_min_db": 3.0       # Minimum acceptable link margin
    }
    # Several drivers report a dark optical lane as -40 dBm (or -inf).  Keep
    # those readings as evidence; dropping them can turn a failed lane into a
    # healthy-looking average.
    DARK_POWER_DBM = -35.0
    NEGATIVE_INFINITY_FLOOR_DBM = -40.0
    # Match the optical media standard reported by common ethtool/NVUE
    # variants, for example ``100G Base-DR`` and ``100GBASE-DR``.  The lane
    # suffix describes optical lanes (DR4/SR4/etc.), not the host electrical
    # width of the pluggable module.
    OPTICAL_MEDIA_STANDARD_RE = re.compile(
        r'\b\d+\s*G(?:\s*[-_ ]?\s*BASE)?\s*[-_ ]*'
        r'(?P<family>DR|FR|SR|LR|ER|ZR|PSM|CWDM)'
        r'(?P<lanes>\d+)?\b',
        re.IGNORECASE,
    )
    # DR and FR without a numeric suffix are defined as a single optical
    # lane.  Other families are only treated as single-lane when the media
    # string explicitly says so (LR1/ER1/ZR1, for example).
    UNNUMBERED_SINGLE_LANE_MEDIA = frozenset({'DR', 'FR'})

    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.optical_history = {}  # port -> historical readings
        self.current_optical_stats = {}  # port -> current optical status
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        self._load_network_thresholds()

        # Load historical data
        self.load_optical_history()

    def _load_network_thresholds(self) -> None:
        """Load the configurable margin while retaining safe defaults.

        Module-specific alarm tables are not collected yet, so all other
        optical limits remain the documented conservative defaults above.
        """
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
                    'optical_power_margin'
                )
                if value is None:
                    return
                margin = float(value)
                if math.isfinite(margin) and margin >= 0:
                    self.thresholds['link_margin_min_db'] = margin
                return
            except (OSError, TypeError, ValueError, yaml.YAMLError):
                # Invalid or unreadable configuration deliberately keeps the
                # documented 3 dB default.
                return

    def load_optical_history(self):
        """Load historical optical data"""
        try:
            with open(f"{self.data_dir}/optical_history.json", "r") as f:
                data = json.load(f)
                self.optical_history = data.get("optical_history", {})
                self.current_optical_stats = data.get("current_optical_stats", {})
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def save_optical_history(self):
        """Save optical history to file"""
        try:
            data = {
                "optical_history": self.optical_history,
                "current_optical_stats": self.current_optical_stats,
                "last_update": time.time()
            }
            with open(f"{self.data_dir}/optical_history.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving optical history: {e}")

    def parse_optical_data(self, optical_data: str) -> Optional[Dict[str, Any]]:
        """Parse optical output (NVUE transceiver commands) for optical parameters
        
        Returns None if this is a DAC/Copper cable (not optical)
        """
        # Check for DAC/Copper cable - these don't have optical diagnostics
        cable_type_indicators = [
            'Passive copper',
            'Active copper',
            'Copper cable',
            'Base-CR',  # Copper (e.g., 100G Base-CR4)
            'DAC',
            'Twinax',
            'No separable connector'  # DAC cables
        ]
        
        for indicator in cable_type_indicators:
            if indicator in optical_data:
                # This is a copper/DAC cable, not optical - skip optical analysis
                return None
        
        optical_params = {
            'rx_power_dbm': None,
            'tx_power_dbm': None,
            'temperature_c': None,
            'voltage_v': None,
            'bias_current_ma': None
        }

        # Preserve lane identity.  The scalar values exposed to the report are
        # selected from the worst lane below rather than averaged, so the
        # displayed value explains the resulting severity.
        rx_readings = []
        tx_readings = []
        bias_readings = []

        number = r'[-+]?(?:\d+(?:\.\d*)?|\.\d+)'
        power_value = rf'(?P<value>-?inf|{number})'
        rx_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-rx-power|'
            rf'(?:Rcvr|Receiver)\s+signal\s+(?:avg|average)\s+optical\s+power'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*(?:-?inf|{number})\s*mW\s*/\s*{power_value}\s*dBm',
            re.IGNORECASE,
        )
        tx_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-tx-power|'
            rf'(?:Transmit\s+avg\s+optical\s+power|Laser\s+output\s+power)'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*(?:-?inf|{number})\s*mW\s*/\s*{power_value}\s*dBm',
            re.IGNORECASE,
        )
        bias_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-tx-bias-current|'
            rf'Laser\s+tx\s+bias\s+current'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*(?P<value>{number})\s*mA',
            re.IGNORECASE,
        )

        def lane_number(match, readings):
            value = match.groupdict().get('nvue_lane') or match.groupdict().get('ethtool_lane')
            return int(value) if value is not None else len(readings) + 1

        def power_from_match(match):
            value = match.group('value').lower()
            if value == '-inf':
                return self.NEGATIVE_INFINITY_FLOOR_DBM
            if value == 'inf':
                return abs(self.NEGATIVE_INFINITY_FLOOR_DBM)
            return float(value)

        lines = optical_data.strip().split('\n')
        for line in lines:
            line = line.strip()

            # Parse temperature (NVUE format: "temperature : 48.71 degrees C" or ethtool: "Module temperature : 48.85 degrees C")
            temp_match = re.search(r'(?:Module\s+)?temperature\s*:\s*([\d.-]+)\s*degrees?\s*C', line)
            if temp_match:
                optical_params['temperature_c'] = float(temp_match.group(1))
            
            # Parse voltage (NVUE format: "voltage : 3.2688 V" or ethtool: "Module voltage : 3.2096 V")
            voltage_match = re.search(r'(?:Module\s+)?voltage\s*:\s*([\d.-]+)\s*V', line)
            if voltage_match:
                optical_params['voltage_v'] = float(voltage_match.group(1))

            rx_power_match = rx_pattern.search(line)
            if rx_power_match:
                try:
                    rx_readings.append((
                        lane_number(rx_power_match, rx_readings),
                        power_from_match(rx_power_match),
                    ))
                except ValueError:
                    pass

            tx_power_match = tx_pattern.search(line)
            if tx_power_match:
                try:
                    tx_readings.append((
                        lane_number(tx_power_match, tx_readings),
                        power_from_match(tx_power_match),
                    ))
                except ValueError:
                    pass

            bias_match = bias_pattern.search(line)
            if bias_match:
                try:
                    bias_readings.append((
                        lane_number(bias_match, bias_readings),
                        float(bias_match.group('value')),
                    ))
                except ValueError:
                    pass

        self._set_lane_readings(optical_params, 'rx_power', rx_readings)
        self._set_lane_readings(optical_params, 'tx_power', tx_readings)
        self._set_lane_readings(optical_params, 'bias_current', bias_readings)
        self._select_declared_optical_lanes(optical_data, optical_params)

        return optical_params

    def _declared_optical_lane_count(self, optical_data: str) -> Optional[int]:
        """Return an unambiguous optical lane count from module media text.

        A QSFP host can expose four diagnostic channels even when its optical
        media is single-lane PAM4.  In that case unused channels are commonly
        rendered as ``-40 dBm``/``0 mA`` placeholders.  Conversely, standards
        such as DR4, SR4 and LR4 have genuinely independent optical lanes and
        must retain worst-lane analysis.

        If the raw block advertises conflicting media standards, return
        ``None`` rather than guessing and potentially hiding a failed lane.
        """
        lane_counts = set()
        for match in self.OPTICAL_MEDIA_STANDARD_RE.finditer(optical_data):
            family = match.group('family').upper()
            suffix = match.group('lanes')
            if suffix is not None:
                count = int(suffix)
                if count > 0:
                    lane_counts.add(count)
            elif family in self.UNNUMBERED_SINGLE_LANE_MEDIA:
                lane_counts.add(1)

        if len(lane_counts) == 1:
            return next(iter(lane_counts))
        return None

    def _select_declared_optical_lanes(
            self, optical_data: str,
            optical_params: Dict[str, Any]) -> None:
        """Drop driver placeholder channels for declared single-lane media.

        Filtering is intentionally metadata-driven.  A dark reading or zero
        bias alone is never considered proof that a channel is unused.  Lane
        1 must also be present; otherwise all readings are preserved so an
        unfamiliar channel numbering scheme cannot mask a fault.
        """
        optical_lane_count = self._declared_optical_lane_count(optical_data)
        optical_params['_declared_optical_lane_count'] = optical_lane_count
        if optical_lane_count != 1:
            return

        for metric in ('rx_power', 'tx_power', 'bias_current'):
            lanes_key = (f'_{metric}_lanes_dbm' if metric != 'bias_current'
                         else '_bias_current_lanes_ma')
            ids_key = f'_{metric}_lane_ids'
            values = optical_params.get(lanes_key) or []
            lane_ids = optical_params.get(ids_key) or []
            if len(values) <= 1:
                continue
            readings = list(zip(lane_ids, values))
            lane_one = [item for item in readings if item[0] == 1]
            if lane_one:
                self._set_lane_readings(optical_params, metric, lane_one)

    def _lane_risk(self, metric: str, value: float) -> tuple:
        """Return a sortable risk tuple used to select the displayed lane."""
        if metric == 'rx_power':
            low = self.thresholds['rx_power_min_dbm']
            high = self.thresholds['rx_power_critical_high_dbm']
            if value <= self.DARK_POWER_DBM:
                return (4, low - value)
            if value < low or value > high:
                return (3, max(low - value, value - high))
            if (self.calculate_link_margin(value) < self.thresholds['link_margin_min_db'] or
                    value > self.thresholds['rx_power_warning_high_dbm']):
                return (2, max(low + self.thresholds['link_margin_min_db'] - value,
                               value - self.thresholds['rx_power_warning_high_dbm']))
            return (1, -min(value - low, high - value))
        if metric == 'tx_power':
            low = self.thresholds['tx_power_min_dbm']
            high = self.thresholds['tx_power_max_dbm']
            if value < low or value > high:
                return (3, max(low - value, value - high))
            if value < low + 1.0 or value > high - 1.0:
                return (2, max(low + 1.0 - value, value - (high - 1.0)))
            return (1, -min(value - low, high - value))
        # High bias is the only currently defined bias risk.
        return (1, value)

    def _set_lane_readings(self, optical_params: Dict[str, Any], metric: str,
                           readings: List[tuple]) -> None:
        value_key = f'{metric}_dbm' if metric != 'bias_current' else 'bias_current_ma'
        lanes_key = f'_{metric}_lanes_dbm' if metric != 'bias_current' else '_bias_current_lanes_ma'
        ids_key = f'_{metric}_lane_ids'
        lane_key = f'{metric}_lane'

        optical_params[lanes_key] = [value for _lane, value in readings]
        optical_params[ids_key] = [lane for lane, _value in readings]
        optical_params[lane_key] = None
        if not readings:
            optical_params[value_key] = None
            return

        lane, value = max(readings, key=lambda item: self._lane_risk(metric, item[1]))
        optical_params[value_key] = value
        optical_params[lane_key] = lane

    def _select_breakout_lane(self, port_name: str,
                              optical_params: Dict[str, Any]) -> None:
        """Limit a breakout interface to its matching physical channel.

        Drivers often return all cage lanes for every `swpNsM` interface.  In
        that case channel M+1 is the only lane owned by the logical interface.
        A single returned lane is already interface-scoped and is left intact.
        """
        interface = port_name.split(':', 1)[-1]
        match = re.fullmatch(r'swp\d+s(\d+)', interface)
        if not match:
            return
        wanted_lane = int(match.group(1)) + 1

        for metric in ('rx_power', 'tx_power', 'bias_current'):
            lanes_key = f'_{metric}_lanes_dbm' if metric != 'bias_current' else '_bias_current_lanes_ma'
            ids_key = f'_{metric}_lane_ids'
            values = optical_params.get(lanes_key) or []
            lane_ids = optical_params.get(ids_key) or []
            if len(values) <= 1:
                continue
            readings = list(zip(lane_ids, values))
            selected = [item for item in readings if item[0] == wanted_lane]
            if selected:
                self._set_lane_readings(optical_params, metric, selected)

    def calculate_link_margin(self, rx_power_dbm: float) -> float:
        """Calculate optical link margin"""
        if rx_power_dbm is None:
            return 0.0

        # Link margin = RX Power - Minimum sensitivity threshold
        # Using -14 dBm as a conservative minimum sensitivity for most optics
        min_sensitivity = self.thresholds['rx_power_min_dbm']
        return rx_power_dbm - min_sensitivity

    def assess_optical_health(self, optical_params: Dict[str, Any]) -> OpticalHealth:
        """Assess optical health based on parameters"""
        rx_power = optical_params.get('rx_power_dbm')
        tx_power = optical_params.get('tx_power_dbm')
        temperature = optical_params.get('temperature_c')
        voltage = optical_params.get('voltage_v')
        bias_current = optical_params.get('bias_current_ma')
        rx_lanes = optical_params.get('_rx_power_lanes_dbm') or (
            [rx_power] if rx_power is not None else []
        )
        tx_lanes = optical_params.get('_tx_power_lanes_dbm') or (
            [tx_power] if tx_power is not None else []
        )
        bias_lanes = optical_params.get('_bias_current_lanes_ma') or (
            [bias_current] if bias_current is not None else []
        )

        # No optical data available.  Voltage alone is useful inventory
        # evidence, but it is not enough to claim a healthy optical path.
        if all(v is None for v in [rx_power, tx_power, temperature, voltage,
                                   bias_current]):
            return OpticalHealth.UNKNOWN

        # Preserve an explicit link-down state when every relevant receive lane
        # is dark.  A single dark lane on a non-breakout multi-lane link remains
        # CRITICAL below, while breakout interfaces are lane-filtered first.
        if rx_lanes and all(value <= self.DARK_POWER_DBM for value in rx_lanes):
            return OpticalHealth.DOWN

        # Critical conditions (any one triggers critical status)
        if any(value < self.thresholds['rx_power_min_dbm'] for value in rx_lanes):
            return OpticalHealth.CRITICAL
        if any(value > self.thresholds.get('rx_power_critical_high_dbm', 7.0)
               for value in rx_lanes):
            return OpticalHealth.CRITICAL
        if any(value < self.thresholds['tx_power_min_dbm'] or
               value > self.thresholds['tx_power_max_dbm']
               for value in tx_lanes):
            return OpticalHealth.CRITICAL
        if temperature is not None and temperature > self.thresholds['temperature_max_c']:
            return OpticalHealth.CRITICAL
        if temperature is not None and temperature < self.thresholds['temperature_min_c']:
            return OpticalHealth.CRITICAL
        if voltage is not None and (voltage < self.thresholds['voltage_min_v'] or voltage > self.thresholds['voltage_max_v']):
            return OpticalHealth.CRITICAL
        if any(value > self.thresholds['bias_current_max_ma'] for value in bias_lanes):
            return OpticalHealth.CRITICAL

        if not rx_lanes and not tx_lanes:
            return OpticalHealth.UNKNOWN

        # Warning conditions
        warning_count = 0

        # Low link margin warning
        if rx_lanes and any(
            self.calculate_link_margin(value) < self.thresholds['link_margin_min_db']
            for value in rx_lanes
        ):
            warning_count += 1

        # High RX power warning (above warning high but below critical high)
        if any(value > self.thresholds.get('rx_power_warning_high_dbm', 5.0)
               for value in rx_lanes):
            warning_count += 1

        # TX power near limits
        if tx_lanes:
            if any(value < self.thresholds['tx_power_min_dbm'] + 1.0 or
                   value > self.thresholds['tx_power_max_dbm'] - 1.0
                   for value in tx_lanes):
                warning_count += 1

        # Temperature approaching limits
        if temperature is not None:
            if temperature > self.thresholds['temperature_max_c'] - 10.0:
                warning_count += 1

        # Any independently meaningful threshold violation is a warning.  The
        # previous two-warning rule hid a real low-margin/high-power condition
        # behind a GOOD badge.
        if warning_count:
            return OpticalHealth.WARNING
        return OpticalHealth.EXCELLENT

    def update_optical_stats(self, port_name: str, optical_data: str):
        """Update optical statistics for a port
        
        Returns False if port is DAC/Copper (skipped), True if processed
        """
        optical_params = self.parse_optical_data(optical_data)
        
        # Skip DAC/Copper cables - parse_optical_data returns None for these
        if optical_params is None:
            return False

        self._select_breakout_lane(port_name, optical_params)
        
        health = self.assess_optical_health(optical_params)

        # Calculate additional metrics
        link_margin_db = None
        rx_lanes = optical_params.get('_rx_power_lanes_dbm') or []
        if rx_lanes:
            link_margin_db = min(self.calculate_link_margin(value)
                                 for value in rx_lanes)
        elif optical_params['rx_power_dbm'] is not None:
            link_margin_db = self.calculate_link_margin(optical_params['rx_power_dbm'])

        # Store current stats
        self.current_optical_stats[port_name] = {
            'health_status': health.value,
            'rx_power_dbm': optical_params['rx_power_dbm'],
            'tx_power_dbm': optical_params['tx_power_dbm'],
            'temperature_c': optical_params['temperature_c'],
            'voltage_v': optical_params['voltage_v'],
            'bias_current_ma': optical_params['bias_current_ma'],
            'rx_power_lane': optical_params.get('rx_power_lane'),
            'tx_power_lane': optical_params.get('tx_power_lane'),
            'bias_current_lane': optical_params.get('bias_current_lane'),
            'rx_power_lanes_dbm': optical_params.get('_rx_power_lanes_dbm', []),
            'tx_power_lanes_dbm': optical_params.get('_tx_power_lanes_dbm', []),
            'bias_current_lanes_ma': optical_params.get('_bias_current_lanes_ma', []),
            'link_margin_db': link_margin_db,
            'last_updated': time.time(),
            'raw_data': optical_data[:500]  # Store first 500 chars for debugging
        }

        # Store in history
        if port_name not in self.optical_history:
            self.optical_history[port_name] = []

        # Add to history (keep last 100 entries)
        history_entry = {
            'timestamp': time.time(),
            'health': health.value,
            'rx_power_dbm': optical_params['rx_power_dbm'],
            'tx_power_dbm': optical_params['tx_power_dbm'],
            'temperature_c': optical_params['temperature_c'],
            'link_margin_db': link_margin_db,
            'rx_power_lane': optical_params.get('rx_power_lane'),
            'tx_power_lane': optical_params.get('tx_power_lane'),
            'bias_current_lane': optical_params.get('bias_current_lane')
        }

        self.optical_history[port_name].append(history_entry)
        if len(self.optical_history[port_name]) > 100:
            self.optical_history[port_name] = self.optical_history[port_name][-100:]
        
        return True

    def get_optical_summary(self) -> Dict[str, Any]:
        """Get optical analysis summary"""
        summary = {
            "total_ports": 0,
            "excellent_ports": [],
            "good_ports": [],
            "warning_ports": [],
            "critical_ports": [],
            "down_ports": [],
            "unplugged_ports": [],
            "unknown_ports": []
        }

        for port_name, stats in self.current_optical_stats.items():
            health = stats.get('health_status', 'unknown')
            health_enum = coerce_optical_health(health)

            port_info = {
                "port": port_name,
                "health": health,
                "rx_power_dbm": stats.get('rx_power_dbm'),
                "tx_power_dbm": stats.get('tx_power_dbm'),
                "temperature_c": stats.get('temperature_c'),
                "link_margin_db": stats.get('link_margin_db'),
                "voltage_v": stats.get('voltage_v'),
                "bias_current_ma": stats.get('bias_current_ma'),
                "rx_power_lane": stats.get('rx_power_lane'),
                "tx_power_lane": stats.get('tx_power_lane'),
                "bias_current_lane": stats.get('bias_current_lane')
            }

            if health_enum == OpticalHealth.EXCELLENT:
                summary["excellent_ports"].append(port_info)
            elif health_enum == OpticalHealth.GOOD:
                summary["good_ports"].append(port_info)
            elif health_enum == OpticalHealth.WARNING:
                summary["warning_ports"].append(port_info)
            elif health_enum == OpticalHealth.CRITICAL:
                summary["critical_ports"].append(port_info)
            elif health_enum == OpticalHealth.DOWN:
                summary["down_ports"].append(port_info)
            elif health_enum == OpticalHealth.UNPLUGGED:
                # An absent module is an availability/inventory state, not a
                # failed optical measurement.  Keep it visible in the table
                # without inflating either Critical or Down.
                summary["unplugged_ports"].append(port_info)
            else:
                summary["unknown_ports"].append(port_info)

        # UNKNOWN is a monitored port with incomplete diagnostics, not an
        # absent port.  Include it in coverage and in the detailed table.
        summary["total_ports"] = (len(summary["excellent_ports"]) +
                                 len(summary["good_ports"]) +
                                 len(summary["warning_ports"]) +
                                 len(summary["critical_ports"]) +
                                 len(summary["down_ports"]) +
                                 len(summary["unplugged_ports"]) +
                                 len(summary["unknown_ports"]))

        return summary

    def detect_optical_anomalies(self) -> List[Dict[str, Any]]:
        """Detect optical-related anomalies"""
        anomalies = []

        for port_name, stats in self.current_optical_stats.items():
            health = coerce_optical_health(stats.get('health_status', 'unknown'))

            if health == OpticalHealth.DOWN:
                anomalies.append({
                    "port": port_name,
                    "type": "OPTICAL_LINK_DOWN",
                    "severity": "warning",
                    "message": "No receive light on the selected active optical lane",
                    "action": "Check fiber connection, peer state, and transceiver",
                    "rx_power_dbm": stats.get('rx_power_dbm')
                })
                continue

            if health == OpticalHealth.UNPLUGGED:
                anomalies.append({
                    "port": port_name,
                    "type": "OPTICAL_MODULE_UNPLUGGED",
                    "severity": "warning",
                    "message": "Optical module is unplugged",
                    "action": "Install or reseat the expected optical module"
                })
                continue

            if health == OpticalHealth.CRITICAL:
                # Critical optical issues
                anomaly_count = len(anomalies)
                rx_power = stats.get('rx_power_dbm')
                tx_power = stats.get('tx_power_dbm')
                temperature = stats.get('temperature_c')

                if rx_power is not None and rx_power < self.thresholds['rx_power_min_dbm']:
                    anomalies.append({
                        "port": port_name,
                        "type": "LOW_OPTICAL_POWER",
                        "severity": "critical",
                        "message": f"RX power too low: {rx_power:.2f} dBm (threshold: {self.thresholds['rx_power_min_dbm']} dBm)",
                        "action": "Check fiber connection, clean connectors, or replace cable",
                        "rx_power_dbm": rx_power
                    })

                if tx_power is not None and (
                        tx_power < self.thresholds['tx_power_min_dbm'] or
                        tx_power > self.thresholds['tx_power_max_dbm']):
                    anomalies.append({
                        "port": port_name,
                        "type": "TX_POWER_OUT_OF_RANGE",
                        "severity": "critical",
                        "message": f"TX power out of range: {tx_power:.2f} dBm",
                        "action": "Inspect or replace the transceiver and verify module compatibility",
                        "tx_power_dbm": tx_power
                    })

                if temperature is not None and temperature > self.thresholds['temperature_max_c']:
                    anomalies.append({
                        "port": port_name,
                        "type": "HIGH_TEMPERATURE",
                        "severity": "critical",
                        "message": f"SFP temperature too high: {temperature:.1f}°C (threshold: {self.thresholds['temperature_max_c']}°C)",
                        "action": "Check cooling, reduce load, or replace SFP module",
                        "temperature_c": temperature
                    })

                if len(anomalies) == anomaly_count:
                    anomalies.append({
                        "port": port_name,
                        "type": "CRITICAL_OPTICAL_PARAMETER",
                        "severity": "critical",
                        "message": "A voltage, bias, high-RX, or lane threshold is critical",
                        "action": "Inspect the displayed worst-lane values and transceiver diagnostics"
                    })

            elif health == OpticalHealth.WARNING:
                # Warning level issues
                link_margin = stats.get('link_margin_db')
                if (isinstance(link_margin, (int, float)) and
                        link_margin < self.thresholds['link_margin_min_db']):
                    anomalies.append({
                        "port": port_name,
                        "type": "LOW_LINK_MARGIN",
                        "severity": "warning",
                        "message": f"Low link margin: {link_margin:.2f} dB (threshold: {self.thresholds['link_margin_min_db']} dB)",
                        "action": "Monitor closely, schedule proactive maintenance",
                        "link_margin_db": link_margin
                    })
                else:
                    anomalies.append({
                        "port": port_name,
                        "type": "OPTICAL_PARAMETER_WARNING",
                        "severity": "warning",
                        "message": "An optical power or temperature value is near its limit",
                        "action": "Review the displayed worst-lane value and monitor the port"
                    })

        return anomalies

    def get_recommended_action(self, port_info: Dict[str, Any]) -> str:
        """Get recommended action for a port based on its health status and parameters"""
        health = port_info.get('health', 'unknown')

        if health == OpticalHealth.DOWN.value:
            return "Check fiber connection, peer state, and transceiver"

        if health == OpticalHealth.UNPLUGGED.value:
            return "Install or reseat the expected optical module"

        if health == OpticalHealth.EXCELLENT.value:
            return ""  # No action needed for excellent health

        if health == OpticalHealth.CRITICAL.value:
            rx_power = port_info.get('rx_power_dbm')
            temperature = port_info.get('temperature_c')

            if rx_power is not None and rx_power < self.thresholds['rx_power_min_dbm']:
                return "Check fiber connection, clean connectors, or replace cable"
            elif temperature is not None and temperature > self.thresholds['temperature_max_c']:
                return "Check cooling, reduce load, or replace SFP module"
            else:
                return "Investigate critical optical parameters immediately"

        if health == OpticalHealth.WARNING.value:
            link_margin = port_info.get('link_margin_db')
            if (isinstance(link_margin, (int, float)) and
                    link_margin < self.thresholds['link_margin_min_db']):
                return "Monitor closely, schedule proactive maintenance"
            else:
                return "Monitor optical parameters regularly"

        if health == OpticalHealth.GOOD.value:
            return "Continue regular monitoring"

        return "Check optical diagnostics availability"

    def export_optical_data_for_web(self, output_file: str):
        """Export optical data for web display - EXACT same styling as BGP/Link Flap"""
        summary = self.get_optical_summary()
        anomalies = self.detect_optical_anomalies()
        expected_hosts = getattr(self, 'coverage_expected_hosts', None)
        current_hosts = getattr(self, 'coverage_current_hosts', None)
        coverage_attrs = ''
        if isinstance(expected_hosts, int) and isinstance(current_hosts, int):
            coverage_status = (
                'complete' if current_hosts >= expected_hosts else 'partial'
            )
            coverage_attrs = (
                f' data-coverage-status="{coverage_status}"'
                f' data-coverage-expected="{expected_hosts}"'
                f' data-coverage-current="{current_hosts}"'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Optical Diagnostics Analysis</title>
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
        .card-down {{ border-left-color: #ff9800; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .badge-gray {{ background: rgba(158, 158, 158, 0.2); color: #999; }}
        .optical-excellent {{ color: #76b900; font-weight: bold; }}
        .optical-good {{ color: #8bc34a; font-weight: bold; }}
        .optical-warning {{ color: #ff9800; font-weight: bold; }}
        .optical-critical {{ color: #f44336; font-weight: bold; }}
        .optical-down {{ color: #ff9800; font-weight: bold; }}
        .optical-unknown {{ color: #888; }}
        .optical-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .optical-table th, .optical-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; }}
        .optical-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .optical-table tbody tr {{ background: #252526; }}
        .optical-table tbody tr:hover {{ background: #2d2d2d; }}
        .optical-table td {{ word-wrap: break-word; overflow-wrap: break-word; }}
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
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
            <div class="page-title">Optical Diagnostics Analysis</div>
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
    
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            Optical Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-ports-card">
                    <div class="metric" id="total-ports">{summary['total_ports']}</div>
                    <div class="metric-label">Total Ports</div>
                </div>
                <div class="summary-card card-excellent" id="excellent-card">
                    <div class="metric optical-excellent" id="excellent-ports">{len(summary['excellent_ports'])}</div>
                    <div class="metric-label">Excellent</div>
                </div>
                <div class="summary-card card-good" id="good-card">
                    <div class="metric optical-good" id="good-ports">{len(summary['good_ports'])}</div>
                    <div class="metric-label">Good</div>
                </div>
                <div class="summary-card card-warning" id="warning-card">
                    <div class="metric optical-warning" id="warning-ports">{len(summary['warning_ports'])}</div>
                    <div class="metric-label">Warning</div>
                </div>
                <div class="summary-card card-critical" id="critical-card">
                    <div class="metric optical-critical" id="critical-ports">{len(summary['critical_ports'])}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="summary-card card-down" id="down-card">
                    <div class="metric optical-down" id="down-ports">{len(summary['down_ports'])}</div>
                    <div class="metric-label">Down</div>
                </div>
            </div>
        </div>
    </div>
    
"""

        # Create one unified table for all monitored ports.  UNKNOWN rows are
        # retained so missing diagnostics cannot improve the visible coverage.
        all_ports = (summary['critical_ports'] + summary['down_ports'] +
                     summary['warning_ports'] + summary['unplugged_ports'] +
                     summary['unknown_ports'] + summary['good_ports'] +
                     summary['excellent_ports'])

        html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Optical Port Status ({len(all_ports)} total)
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="optical-table" id="optical-table">
                <thead>
                <tr>
                    <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="1" data-type="port">Port <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="2" data-type="optical-health">Health <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="3" data-type="optical-power">Rx Pwr <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="4" data-type="optical-power">Tx Pwr <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="5" data-type="temperature">Temp <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="6" data-type="optical-power">Margin <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="7" data-type="voltage">Voltage <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="8" data-type="current">Bias <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="9" data-type="string">Action <span class="sort-arrow">▲▼</span></th>
                </tr>
                </thead>
                <tbody id="optical-data">"""

        for port in all_ports:
            # Split port name into device and interface
            port_name = port['port']
            if ':' in port_name:
                device_name = port_name.split(':')[0]
                interface_name = port_name.split(':')[1]
            else:
                device_name = "unknown"
                interface_name = port_name
            
            rx_lane = port.get('rx_power_lane')
            tx_lane = port.get('tx_power_lane')
            bias_lane = port.get('bias_current_lane')
            rx_power = f"{port['rx_power_dbm']:.2f}" if port['rx_power_dbm'] is not None else "N/A"
            tx_power = f"{port['tx_power_dbm']:.2f}" if port['tx_power_dbm'] is not None else "N/A"
            if rx_lane is not None:
                rx_power += f" (L{rx_lane})"
            if tx_lane is not None:
                tx_power += f" (L{tx_lane})"
            temperature = f"{port['temperature_c']:.1f}" if port['temperature_c'] is not None else "N/A"
            link_margin = f"{port['link_margin_db']:.2f}" if port['link_margin_db'] is not None else "N/A"
            voltage = f"{port['voltage_v']:.2f}" if port['voltage_v'] is not None else "N/A"
            bias_current = f"{port['bias_current_ma']:.2f}" if port['bias_current_ma'] is not None else "N/A"
            if bias_lane is not None:
                bias_current += f" (L{bias_lane})"
            recommended_action = self.get_recommended_action(port)
            # Badge class based on health
            health = port['health']
            if health == 'excellent':
                badge_class = 'badge badge-green'
            elif health == 'good':
                badge_class = 'badge badge-green'
            elif health == 'warning':
                badge_class = 'badge badge-orange'
            elif health == 'critical':
                badge_class = 'badge badge-red'
            elif health == 'down':
                badge_class = 'badge badge-orange'
            elif health == 'unplugged':
                badge_class = 'badge badge-gray'
            else:
                badge_class = 'badge badge-gray'

            html_content += f"""
                <tr data-health="{port['health']}">
                    <td>{canonical(device_name)}</td>
                    <td>{interface_name}</td>
                    <td><span class="{badge_class}">{port['health'].upper()}</span></td>
                    <td>{rx_power}</td>
                    <td>{tx_power}</td>
                    <td>{temperature}</td>
                    <td>{link_margin}</td>
                    <td>{voltage}</td>
                    <td>{bias_current}</td>
                    <td>{recommended_action}</td>
                </tr>"""

        html_content += """
        </tbody>
            </table>
        </div>
    </div>"""

        html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            Optical Health Thresholds
        </div>
        <div class="section-content-table">
            <table class="optical-table">
                <thead>
                    <tr><th>Parameter</th><th>Min Threshold</th><th>Max Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>RX Power</td><td>{self.thresholds['rx_power_min_dbm']} dBm</td><td>{self.thresholds['rx_power_critical_high_dbm']} dBm</td><td>Received power on active optical lanes only (warning above {self.thresholds['rx_power_warning_high_dbm']} dBm); media-declared inactive placeholder channels are excluded</td></tr>
                    <tr><td>TX Power</td><td>{self.thresholds['tx_power_min_dbm']} dBm</td><td>{self.thresholds['tx_power_max_dbm']} dBm</td><td>Transmitted optical power range</td></tr>
                    <tr><td>Temperature</td><td>{self.thresholds['temperature_min_c']}°C</td><td>{self.thresholds['temperature_max_c']}°C</td><td>SFP/QSFP operating temperature</td></tr>
                    <tr><td>Voltage</td><td>{self.thresholds['voltage_min_v']}V</td><td>{self.thresholds['voltage_max_v']}V</td><td>Supply voltage range</td></tr>
                    <tr><td>Link Margin</td><td>{self.thresholds['link_margin_min_db']} dB</td><td>-</td><td>Minimum margin from notifications.yaml; based on the current generic RX sensitivity until module-specific limits are collected</td></tr>
                    <tr><td>Bias Current</td><td>-</td><td>{self.thresholds['bias_current_max_ma']} mA</td><td>Maximum laser bias current</td></tr>
                    <tr><td>Down</td><td>-</td><td>{self.DARK_POWER_DBM} dBm RX</td><td>No receive light on every selected active optical lane; reported separately from Critical threshold violations</td></tr>
                </tbody>
            </table>
        </div>
    </div>
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
            // Store all table rows for filtering
            allRows = Array.from(document.querySelectorAll('#optical-data tr'));

            // Add click events to summary cards
            setupCardEvents();

            // Initialize table sorting
            initTableSorting();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });

        function setupCardEvents() {
            document.getElementById('total-ports-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('total-ports').textContent) > 0) {
                    filterPorts('TOTAL');
                }
            });

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

            document.getElementById('down-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('down-ports').textContent) > 0) {
                    filterPorts('DOWN');
                }
            });
        }

        function filterPorts(filterType) {
            currentFilter = filterType;

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
                filteredRows = allRows.filter(row => row.dataset.health === 'excellent');
                filterText = `Showing ${filteredRows.length} Excellent Ports`;
                document.getElementById('excellent-card').classList.add('active');
            } else if (filterType === 'GOOD') {
                filteredRows = allRows.filter(row => row.dataset.health === 'good');
                filterText = `Showing ${filteredRows.length} Good Ports`;
                document.getElementById('good-card').classList.add('active');
            } else if (filterType === 'WARNING') {
                filteredRows = allRows.filter(row => row.dataset.health === 'warning');
                filterText = `Showing ${filteredRows.length} Warning Ports`;
                document.getElementById('warning-card').classList.add('active');
            } else if (filterType === 'CRITICAL') {
                filteredRows = allRows.filter(row => row.dataset.health === 'critical');
                filterText = `Showing ${filteredRows.length} Critical Ports`;
                document.getElementById('critical-card').classList.add('active');
            } else if (filterType === 'DOWN') {
                filteredRows = allRows.filter(row => row.dataset.health === 'down');
                filterText = `Showing ${filteredRows.length} Down Ports`;
                document.getElementById('down-card').classList.add('active');
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
                // Device column (cells[0]) contains just the hostname
                const deviceName = row.cells[0]?.textContent?.trim();
                if (deviceName) {
                    deviceSet.add(deviceName);
                }
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
            
            // Clear card-based filter
            currentFilter = 'ALL';
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            // Filter table rows - match hostname part of port name
            let matchCount = 0;
            allRows.forEach(row => {
                const portName = row.cells[0]?.textContent?.trim() || '';
                const hostname = portName.split(':')[0];
                if (hostname === deviceName) {
                    row.style.display = '';
                    matchCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show filter info
            document.getElementById('filter-info').style.display = 'block';
            document.getElementById('filter-text').textContent = 'Showing ports for device: ' + deviceName + ' (' + matchCount + ' ports)';
            document.getElementById('clearSearchBtn').style.display = 'inline-block';
        }
        
        function clearDeviceSearch() {
            selectedDevice = '';
            deviceSearchActive = false;
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
                    sortOpticalTable(column, tableSortState.direction, type);
                });
            });
        }

        function sortOpticalTable(columnIndex, direction, type) {
            const table = document.getElementById('optical-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows);

            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();

                // Extract actual text for health columns (remove HTML)
                if (type === 'optical-health') {
                    aVal = a.cells[columnIndex].querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex].querySelector('span')?.textContent || bVal;
                }

                let result = 0;

                switch(type) {
                    case 'optical-power':
                    case 'temperature':
                    case 'voltage':
                    case 'current':
                        result = compareOpticalValue(aVal, bVal);
                        break;
                    case 'port':
                        result = comparePort(aVal, bVal);
                        break;
                    case 'optical-health':
                        result = compareOpticalHealth(aVal, bVal);
                        break;
                    case 'string':
                    default:
                        result = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });
                        break;
                }

                return direction === 'desc' ? -result : result;
            });

            // Clear tbody and add sorted rows back
            tbody.innerHTML = '';
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
                return port.localeCompare(b, undefined, { numeric: true });
            };

            return extractPortNumber(a) - extractPortNumber(b);
        }

        function compareOpticalHealth(a, b) {
            const priority = {
                'CRITICAL': 0,
                'DOWN': 1,
                'UNPLUGGED': 2,
                'WARNING': 3,
                'GOOD': 4,
                'EXCELLENT': 5,
                'UNKNOWN': 6
            };

            return (priority[a] ?? 5) - (priority[b] ?? 5);
        }

        function compareOpticalValue(a, b) {
            // Handle 'N/A' values
            if (a === 'N/A' && b === 'N/A') return 0;
            if (a === 'N/A') return 1;
            if (b === 'N/A') return -1;

            // Parse numerical values (handle negative numbers)
            const numA = parseFloat(a);
            const numB = parseFloat(b);

            if (isNaN(numA) && isNaN(numB)) return 0;
            if (isNaN(numA)) return 1;
            if (isNaN(numB)) return -1;

            return numA - numB;
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
                // Capture the current pipeline generation before triggering a
                // new one.  The shared analysis guard resolves only after a
                // newer complete generation has been published.
                let baseline = null;
                if (typeof window.lldpqCapturePipelineState === 'function') {
                    baseline = await window.lldpqCapturePipelineState();
                }

                const response = await fetch('/trigger-monitor', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await response.json();
                if (data.status !== 'success') {
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
                        The full system analysis is running in the background.<br>
                        <small>Page will refresh after the new analysis is completely published.</small>
                    `;
                document.body.appendChild(notification);

                if (typeof window.waitForLldpqAnalysisCompletion === 'function') {
                    await window.waitForLldpqAnalysisCompletion(baseline);
                } else {
                    // Compatibility fallback for older installations that do
                    // not yet provide analysis-guard.js completion polling.
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
                const filename = `Optical_Analysis_Report_${dateStr}_${timeStr}.csv`;

                // Read headers and cells from the same table so Device/Action
                // and future columns cannot become shifted or truncated.
                const table = document.getElementById('optical-table');
                const headers = Array.from(table.querySelectorAll('thead th')).map(th =>
                    th.textContent.replace('▲▼', '').trim()
                );
                let csvContent = headers.join(',') + '\\n';

                // Get table data (only visible rows)
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');

                // Add summary stats as comments
                csvContent += `# Optical Diagnostics Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Ports: ${document.getElementById('total-ports').textContent}\\n`;
                csvContent += `# Excellent: ${document.getElementById('excellent-ports').textContent}\\n`;
                csvContent += `# Good: ${document.getElementById('good-ports').textContent}\\n`;
                csvContent += `# Warning: ${document.getElementById('warning-ports').textContent}\\n`;
                csvContent += `# Critical: ${document.getElementById('critical-ports').textContent}\\n`;
                csvContent += `# Down: ${document.getElementById('down-ports').textContent}\\n`;
                csvContent += `#\\n`;

                // Process each visible row
                rows.forEach(row => {
                    if (row.style.display !== 'none') {
                        const cells = row.querySelectorAll('td');
                        if (cells.length) {
                            const rowData = Array.from(cells).map(cell =>
                                cell.textContent.trim()
                            );

                            // Escape commas and quotes in data
                            const escapedData = rowData.map(field => {
                                if (field.includes(',') || field.includes('"') || field.includes('\\n')) {
                                    return '"' + field.replace(/"/g, '""') + '"';
                                }
                                return field;
                            });

                            csvContent += escapedData.join(',') + '\\n';
                        }
                    }
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
    <script src="/css/analysis-guard.js"></script>
</body>
</html>"""

        with open(output_file, "w") as f:
            f.write(html_content)

if __name__ == "__main__":
    analyzer = OpticalAnalyzer()
    print("Optical analyzer initialized")
    print(f"Monitoring {len(analyzer.current_optical_stats)} ports")
