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
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

class OpticalHealth(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

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

    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.optical_history = {}  # port -> historical readings
        self.current_optical_stats = {}  # port -> current optical status
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()

        # Load historical data
        self.load_optical_history()

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

    def parse_optical_data(self, optical_data: str) -> Dict[str, float]:
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

        # Track channel data for averaging
        rx_powers = []
        tx_powers = []
        bias_currents = []

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

            # Parse RX power (NVUE: "ch-1-rx-power : 1.7055 mW / 2.32 dBm" or ethtool: "Rcvr signal avg optical power(Channel 1) : 1.5601 mW / 1.93 dBm")
            # Enhanced regex to handle parentheses around Channel
            rx_power_match = re.search(r'(?:ch-\d+-rx-power|Rcvr\s+signal\s+avg\s+optical\s+power\s*\(?\s*Channel\s+\d+\s*\)?)\s*:\s*[\d.-]+\s*mW\s*/\s*([-\d.]+)\s*dBm', line)
            if rx_power_match:
                try:
                    rx_dbm = float(rx_power_match.group(1))
                    # Ignore placeholder lanes commonly reported as -40 dBm on unused channels
                    if rx_dbm > -35.0:
                        rx_powers.append(rx_dbm)
                except ValueError:
                    pass

            # Parse TX power (NVUE: "ch-1-tx-power : 1.1706 mW / 0.68 dBm" or ethtool: "Transmit avg optical power (Channel 1) : 1.0466 mW / 0.20 dBm")
            # Enhanced regex to handle parentheses around Channel
            tx_power_match = re.search(r'(?:ch-\d+-tx-power|Transmit\s+avg\s+optical\s+power\s*\(?\s*Channel\s+\d+\s*\)?)\s*:\s*[\d.-]+\s*mW\s*/\s*([-\d.]+)\s*dBm', line)
            if tx_power_match:
                try:
                    tx_dbm = float(tx_power_match.group(1))
                    # Ignore unused lanes at ~-40 dBm
                    if tx_dbm > -35.0:
                        tx_powers.append(tx_dbm)
                except ValueError:
                    pass

            # Parse bias current (NVUE: "ch-1-tx-bias-current : 7.056 mA" or ethtool: "Laser tx bias current (Channel 1) : 72.500 mA")
            # Enhanced regex to handle parentheses around Channel
            bias_match = re.search(r'(?:ch-\d+-tx-bias-current|Laser\s+tx\s+bias\s+current\s*\(?\s*Channel\s+\d+\s*\)?)\s*:\s*([\d.-]+)\s*mA', line)
            if bias_match:
                try:
                    bias_ma = float(bias_match.group(1))
                    # Ignore zero bias reported on unused lanes
                    if bias_ma > 0.1:
                        bias_currents.append(bias_ma)
                except ValueError:
                    pass

        # Average multi-channel values
        if rx_powers:
            optical_params['rx_power_dbm'] = sum(rx_powers) / len(rx_powers)
        if tx_powers:
            optical_params['tx_power_dbm'] = sum(tx_powers) / len(tx_powers)
        if bias_currents:
            optical_params['bias_current_ma'] = sum(bias_currents) / len(bias_currents)

        # Fallback: parse on full blob if line-by-line missed values (ethtool formatting variations)
        # Enhanced to handle both "Channel 1" and "(Channel 1)" formats
        if optical_params['rx_power_dbm'] is None:
            rx_all = re.findall(r'(?:Rcvr\s+signal\s+avg\s+optical\s+power\s*\(?\s*Channel\s*\d+\s*\)?|ch-\d+-rx-power)\s*:\s*[\d.-]+\s*mW\s*/\s*([-\d.]+)\s*dBm', optical_data, flags=re.IGNORECASE)
            if rx_all:
                rx_vals = [float(v) for v in rx_all if float(v) > -35.0]
                if rx_vals:
                    optical_params['rx_power_dbm'] = sum(rx_vals) / len(rx_vals)
        if optical_params['tx_power_dbm'] is None:
            tx_all = re.findall(r'(?:Transmit\s+avg\s+optical\s+power\s*\(?\s*Channel\s*\d+\s*\)?|ch-\d+-tx-power)\s*:\s*[\d.-]+\s*mW\s*/\s*([-\d.]+)\s*dBm', optical_data, flags=re.IGNORECASE)
            if tx_all:
                tx_vals = [float(v) for v in tx_all if float(v) > -35.0]
                if tx_vals:
                    optical_params['tx_power_dbm'] = sum(tx_vals) / len(tx_vals)
        if optical_params['bias_current_ma'] is None:
            bias_all = re.findall(r'(?:Laser\s+tx\s+bias\s+current\s*\(?\s*Channel\s*\d+\s*\)?|ch-\d+-tx-bias-current)\s*:\s*([\d.-]+)\s*mA', optical_data, flags=re.IGNORECASE)
            if bias_all:
                bias_vals = [float(v) for v in bias_all if float(v) > 0.1]
                if bias_vals:
                    optical_params['bias_current_ma'] = sum(bias_vals) / len(bias_vals)

        return optical_params

    def calculate_link_margin(self, rx_power_dbm: float) -> float:
        """Calculate optical link margin"""
        if rx_power_dbm is None:
            return 0.0

        # Link margin = RX Power - Minimum sensitivity threshold
        # Using -14 dBm as a conservative minimum sensitivity for most optics
        min_sensitivity = self.thresholds['rx_power_min_dbm']
        return rx_power_dbm - min_sensitivity

    def assess_optical_health(self, optical_params: Dict[str, float]) -> OpticalHealth:
        """Assess optical health based on parameters"""
        rx_power = optical_params.get('rx_power_dbm')
        tx_power = optical_params.get('tx_power_dbm')
        temperature = optical_params.get('temperature_c')
        voltage = optical_params.get('voltage_v')
        bias_current = optical_params.get('bias_current_ma')

        # No optical data available
        if all(v is None for v in [rx_power, tx_power, temperature]):
            return OpticalHealth.UNKNOWN

        # Critical conditions (any one triggers critical status)
        if rx_power is not None and rx_power < self.thresholds['rx_power_min_dbm']:
            return OpticalHealth.CRITICAL
        if rx_power is not None and \
           rx_power > self.thresholds.get('rx_power_critical_high_dbm', 7.0):
            return OpticalHealth.CRITICAL
        if temperature is not None and temperature > self.thresholds['temperature_max_c']:
            return OpticalHealth.CRITICAL
        if temperature is not None and temperature < self.thresholds['temperature_min_c']:
            return OpticalHealth.CRITICAL
        if voltage is not None and (voltage < self.thresholds['voltage_min_v'] or voltage > self.thresholds['voltage_max_v']):
            return OpticalHealth.CRITICAL
        if bias_current is not None and bias_current > self.thresholds['bias_current_max_ma']:
            return OpticalHealth.CRITICAL

        # Warning conditions
        warning_count = 0

        # Low link margin warning
        if rx_power is not None:
            link_margin = self.calculate_link_margin(rx_power)
            if link_margin < self.thresholds['link_margin_min_db']:
                warning_count += 1

        # High RX power warning (above warning high but below critical high)
        if rx_power is not None and \
           rx_power > self.thresholds.get('rx_power_warning_high_dbm', 5.0):
            warning_count += 1

        # TX power near limits
        if tx_power is not None:
            if tx_power < self.thresholds['tx_power_min_dbm'] + 1.0 or tx_power > self.thresholds['tx_power_max_dbm'] - 1.0:
                warning_count += 1

        # Temperature approaching limits
        if temperature is not None:
            if temperature > self.thresholds['temperature_max_c'] - 10.0:
                warning_count += 1

        # Return health status
        if warning_count >= 2:
            return OpticalHealth.WARNING
        elif warning_count == 1:
            return OpticalHealth.GOOD
        else:
            return OpticalHealth.EXCELLENT

    def update_optical_stats(self, port_name: str, optical_data: str):
        """Update optical statistics for a port
        
        Returns False if port is DAC/Copper (skipped), True if processed
        """
        optical_params = self.parse_optical_data(optical_data)
        
        # Skip DAC/Copper cables - parse_optical_data returns None for these
        if optical_params is None:
            return False
        
        health = self.assess_optical_health(optical_params)

        # Calculate additional metrics
        link_margin_db = None
        if optical_params['rx_power_dbm'] is not None:
            link_margin_db = self.calculate_link_margin(optical_params['rx_power_dbm'])

        # Store current stats
        self.current_optical_stats[port_name] = {
            'health_status': health.value,
            'rx_power_dbm': optical_params['rx_power_dbm'],
            'tx_power_dbm': optical_params['tx_power_dbm'],
            'temperature_c': optical_params['temperature_c'],
            'voltage_v': optical_params['voltage_v'],
            'bias_current_ma': optical_params['bias_current_ma'],
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
            'link_margin_db': link_margin_db
        }

        self.optical_history[port_name].append(history_entry)
        if len(self.optical_history[port_name]) > 100:
            self.optical_history[port_name] = self.optical_history[port_name][-100:]
        
        return True

    def get_optical_summary(self) -> Dict[str, Any]:
        """Get optical analysis summary"""
        summary = {
            "total_ports": 0,  # Will calculate as sum of classified ports
            "excellent_ports": [],
            "good_ports": [],
            "warning_ports": [],
            "critical_ports": [],
            "unknown_ports": []
        }

        for port_name, stats in self.current_optical_stats.items():
            health = stats.get('health_status', 'unknown')

            port_info = {
                "port": port_name,
                "health": health,
                "rx_power_dbm": stats.get('rx_power_dbm'),
                "tx_power_dbm": stats.get('tx_power_dbm'),
                "temperature_c": stats.get('temperature_c'),
                "link_margin_db": stats.get('link_margin_db'),
                "voltage_v": stats.get('voltage_v'),
                "bias_current_ma": stats.get('bias_current_ma')
            }

            if health == OpticalHealth.EXCELLENT.value:
                summary["excellent_ports"].append(port_info)
            elif health == OpticalHealth.GOOD.value:
                summary["good_ports"].append(port_info)
            elif health == OpticalHealth.WARNING.value:
                summary["warning_ports"].append(port_info)
            elif health == OpticalHealth.CRITICAL.value:
                summary["critical_ports"].append(port_info)
            else:
                summary["unknown_ports"].append(port_info)

        # Calculate total as sum of classified ports (exclude unknown)
        summary["total_ports"] = (len(summary["excellent_ports"]) +
                                 len(summary["good_ports"]) +
                                 len(summary["warning_ports"]) +
                                 len(summary["critical_ports"]))

        return summary

    def detect_optical_anomalies(self) -> List[Dict[str, Any]]:
        """Detect optical-related anomalies"""
        anomalies = []

        for port_name, stats in self.current_optical_stats.items():
            health = OpticalHealth(stats.get('health_status', 'unknown'))

            if health == OpticalHealth.CRITICAL:
                # Critical optical issues
                rx_power = stats.get('rx_power_dbm')
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

                if temperature is not None and temperature > self.thresholds['temperature_max_c']:
                    anomalies.append({
                        "port": port_name,
                        "type": "HIGH_TEMPERATURE",
                        "severity": "critical",
                        "message": f"SFP temperature too high: {temperature:.1f}°C (threshold: {self.thresholds['temperature_max_c']}°C)",
                        "action": "Check cooling, reduce load, or replace SFP module",
                        "temperature_c": temperature
                    })

            elif health == OpticalHealth.WARNING:
                # Warning level issues
                link_margin = stats.get('link_margin_db', 0)
                if link_margin < self.thresholds['link_margin_min_db']:
                    anomalies.append({
                        "port": port_name,
                        "type": "LOW_LINK_MARGIN",
                        "severity": "warning",
                        "message": f"Low link margin: {link_margin:.2f} dB (threshold: {self.thresholds['link_margin_min_db']} dB)",
                        "action": "Monitor closely, schedule proactive maintenance",
                        "link_margin_db": link_margin
                    })

        return anomalies

    def get_recommended_action(self, port_info: Dict[str, Any]) -> str:
        """Get recommended action for a port based on its health status and parameters"""
        health = port_info.get('health', 'unknown')

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
            link_margin = port_info.get('link_margin_db', 0)
            if link_margin < self.thresholds['link_margin_min_db']:
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
<body>
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
            </div>
        </div>
    </div>
    
"""

        # Create one unified table for all ports (sorted by health - problems first)
        all_ports = summary['critical_ports'] + summary['warning_ports'] + summary['good_ports'] + summary['excellent_ports']

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
            
            rx_power = f"{port['rx_power_dbm']:.2f}" if port['rx_power_dbm'] is not None else "N/A"
            tx_power = f"{port['tx_power_dbm']:.2f}" if port['tx_power_dbm'] is not None else "N/A"
            temperature = f"{port['temperature_c']:.1f}" if port['temperature_c'] is not None else "N/A"
            link_margin = f"{port['link_margin_db']:.2f}" if port['link_margin_db'] is not None else "N/A"
            voltage = f"{port['voltage_v']:.2f}" if port['voltage_v'] is not None else "N/A"
            bias_current = f"{port['bias_current_ma']:.2f}" if port['bias_current_ma'] is not None else "N/A"
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
            else:
                badge_class = 'badge badge-gray'

            html_content += f"""
                <tr data-health="{port['health']}">
                    <td>{device_name}</td>
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
                    <tr><td>RX Power</td><td>{self.thresholds['rx_power_min_dbm']} dBm</td><td>{self.thresholds['rx_power_critical_high_dbm']} dBm</td><td>Received optical power range (warning above {self.thresholds['rx_power_warning_high_dbm']} dBm)</td></tr>
                    <tr><td>TX Power</td><td>{self.thresholds['tx_power_min_dbm']} dBm</td><td>{self.thresholds['tx_power_max_dbm']} dBm</td><td>Transmitted optical power range</td></tr>
                    <tr><td>Temperature</td><td>{self.thresholds['temperature_min_c']}°C</td><td>{self.thresholds['temperature_max_c']}°C</td><td>SFP/QSFP operating temperature</td></tr>
                    <tr><td>Voltage</td><td>{self.thresholds['voltage_min_v']}V</td><td>{self.thresholds['voltage_max_v']}V</td><td>Supply voltage range</td></tr>
                    <tr><td>Link Margin</td><td>{self.thresholds['link_margin_min_db']} dB</td><td>-</td><td>Minimum acceptable link budget margin</td></tr>
                    <tr><td>Bias Current</td><td>-</td><td>{self.thresholds['bias_current_max_ma']} mA</td><td>Maximum laser bias current</td></tr>
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
                'WARNING': 1,
                'GOOD': 2,
                'EXCELLENT': 3,
                'UNKNOWN': 4
            };

            return (priority[a] || 5) - (priority[b] || 5);
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
        function runAnalysis() {
            const button = document.getElementById('run-analysis');
            const originalText = button.innerHTML;

            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/>
                </svg>
                Running...
            `;

            // Send POST request to trigger monitor
            fetch('/trigger-monitor', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    console.log('✅ Monitor analysis triggered successfully');
                    // Show notification
                    const notification = document.createElement('div');
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
                        <small>Page will automatically refresh in 35 seconds to show the latest results.</small>
                    `;
                    document.body.appendChild(notification);
                    // Auto-refresh page after 35 seconds
                    setTimeout(() => {
                        window.location.reload();
                    }, 35000);
                } else {
                    console.error('❌ Failed to trigger monitor analysis:', data.message);
                    alert('Failed to trigger analysis. Please try again.');
                    // Restore button
                    button.disabled = false;
                    button.innerHTML = originalText;
                }
            })
            .catch(error => {
                console.error('❌ Error triggering analysis:', error);
                alert('Error triggering analysis. Please try again.');
                // Restore button
                button.disabled = false;
                button.innerHTML = originalText;
            });
        }

        // CSV Download Function
        function downloadCSV() {
            try {
                // Get current date for filename
                const now = new Date();
                const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
                const timeStr = now.toTimeString().slice(0, 5).replace(':', '-'); // HH-MM
                const filename = `Optical_Analysis_Report_${dateStr}_${timeStr}.csv`;

                // Create CSV header
                const headers = [
                    'Port',
                    'Health',
                    'Rx Power (dBm)',
                    'Tx Power (dBm)',
                    'Temperature (°C)',
                    'Link Margin (dB)',
                    'Voltage (V)',
                    'Bias Current (mA)',
                    'Recommended Action'
                ];

                let csvContent = headers.join(',') + '\\n';

                // Get table data (only visible rows)
                const table = document.getElementById('optical-table');
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
                csvContent += `#\\n`;

                // Process each visible row
                rows.forEach(row => {
                    if (row.style.display !== 'none') {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 9) {
                            const rowData = [
                                cells[0].textContent.trim(), // Port
                                cells[1].querySelector('span') ? cells[1].querySelector('span').textContent.trim() : cells[1].textContent.trim(), // Health
                                cells[2].textContent.trim(), // Rx Power
                                cells[3].textContent.trim(), // Tx Power
                                cells[4].textContent.trim(), // Temperature
                                cells[5].textContent.trim(), // Link Margin
                                cells[6].textContent.trim(), // Voltage
                                cells[7].textContent.trim(), // Bias Current
                                cells[8].textContent.trim()  // Recommended Action
                            ];

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
    <script src="/p2p-alias.js"></script>
</body>
</html>"""

        with open(output_file, "w") as f:
            f.write(html_content)

if __name__ == "__main__":
    analyzer = OpticalAnalyzer()
    print("Optical analyzer initialized")
    print(f"Monitoring {len(analyzer.current_optical_stats)} ports")