#!/usr/bin/env python3
"""
BER (Bit Error Rate) Analysis Module for LLDPq

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import time
import re
import os
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

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
    
    # Industry-standard BER thresholds
    DEFAULT_CONFIG = {
        "raw_ber_threshold": 1.0E-6,      # 1 error per million bits
        "warning_ber_threshold": 1.0E-5,   # 1 error per 100k bits  
        "critical_ber_threshold": 1.0E-4,  # 1 error per 10k bits
        "min_packets_for_analysis": 1000,  # Minimum packets for reliable BER
        "history_retention_hours": 24,     # Keep 24 hours of history
        "trend_analysis_points": 10        # Minimum points for trend analysis
    }
    
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.ber_history = {}  # port -> list of ber readings over time
        self.current_ber_stats = {}  # port -> current ber status
        self.config = self.DEFAULT_CONFIG.copy()
        self._raw_phy_ber_cache = {}  # hostname -> { interface: raw_ber_float }
        self.baseline_data = {}  # hostname -> { interface: {counters, timestamp} }
        
        # Ensure ber-data directory exists
        os.makedirs(f"{self.data_dir}/ber-data", exist_ok=True)
        
        # Load historical data and baseline
        self.load_ber_history()
        self.load_baseline_data()
    
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
            with open(f"{self.data_dir}/ber_baseline.json", "w") as f:
                json.dump(self.baseline_data, f, indent=2)
        except Exception as e:
            print(f"Error saving baseline data: {e}")

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
                elif current_received_bits and current_corrected_bits and current_received_bits > 0 and current_corrected_bits >= 0:
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
    
    def save_ber_history(self):
        """Save BER history to file"""
        try:
            data = {
                "ber_history": self.ber_history,
                "current_ber_stats": self.current_ber_stats,
                "last_update": time.time(),
                "config": self.config
            }
            with open(f"{self.data_dir}/ber_history.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving BER history: {e}")
    
    def cleanup_old_history(self):
        """Remove history entries older than retention period"""
        current_time = time.time()
        retention_seconds = self.config["history_retention_hours"] * 3600
        
        for port_name in list(self.ber_history.keys()):
            if port_name in self.ber_history:
                self.ber_history[port_name] = [
                    entry for entry in self.ber_history[port_name]
                    if current_time - entry['timestamp'] <= retention_seconds
                ]
                
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
        """Calculate delta-based BER using only new errors since last measurement.
        
        Returns: (ber_value, is_baseline_run, delta_errors, delta_bytes)
        """
        port_key = f"{hostname}:{interface}"
        current_time = time.time()
        
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
            # Note: save_baseline_data() called once after all interfaces processed
            return 0.0, True, 0, 0  # Baseline run, no BER calculation
        
        # Calculate deltas
        baseline = self.baseline_data[hostname][interface]
        delta_rx_errors = max(0, current_rx_errors - baseline['rx_errors'])
        delta_tx_errors = max(0, current_tx_errors - baseline['tx_errors'])
        delta_rx_bytes = max(0, current_rx_bytes - baseline['rx_bytes'])
        delta_tx_bytes = max(0, current_tx_bytes - baseline['tx_bytes'])
        delta_rx_packets = max(0, current_rx_packets - baseline['rx_packets'])
        delta_tx_packets = max(0, current_tx_packets - baseline['tx_packets'])
        
        total_delta_errors = delta_rx_errors + delta_tx_errors
        total_delta_bytes = delta_rx_bytes + delta_tx_bytes
        total_delta_packets = delta_rx_packets + delta_tx_packets
        
        # Update baseline for next run
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
        
        # Calculate BER from deltas
        if total_delta_errors == 0:
            return 0.0, False, 0, total_delta_bytes
        
        if total_delta_packets < self.config["min_packets_for_analysis"]:
            return 0.0, False, total_delta_errors, total_delta_bytes
        
        # Prefer byte-based calculation
        if total_delta_bytes > 0:
            total_delta_bits = total_delta_bytes * 8
            ber = total_delta_errors / total_delta_bits
        else:
            # Fallback to packet estimation
            avg_bits_per_packet = 12000  # 1500 bytes conservative estimate
            total_delta_bits = total_delta_packets * avg_bits_per_packet
            ber = total_delta_errors / total_delta_bits if total_delta_bits > 0 else 0.0
        
        return ber, False, total_delta_errors, total_delta_bytes

    def calculate_ber(self, rx_packets: int, tx_packets: int, rx_errors: int, tx_errors: int, rx_bytes: int, tx_bytes: int) -> float:
        """Legacy BER calculation - kept for compatibility.
        
        Note: Use calculate_delta_ber() for accurate delta-based measurements.
        """
        total_packets = rx_packets + tx_packets
        total_errors = rx_errors + tx_errors
        total_bytes = rx_bytes + tx_bytes

        if total_packets < self.config["min_packets_for_analysis"]:
            return 0.0  # Not enough data for reliable BER calculation

        if total_errors == 0:
            return 0.0  # Perfect transmission

        # Prefer exact bit volume from byte counters (MTU-independent)
        total_bits = total_bytes * 8

        # Fallback to estimated bits if byte counters are missing/zero
        if total_bits <= 0:
            avg_bits_per_packet = 12000  # 1500 bytes as conservative estimate
            total_bits = total_packets * avg_bits_per_packet

        ber = total_errors / total_bits if total_bits > 0 else 0.0
        return ber
    
    def get_ber_grade(self, ber_value: float) -> BERGrade:
        """Determine BER quality grade"""
        if ber_value == 0.0:
            return BERGrade.EXCELLENT
        elif ber_value < self.config["raw_ber_threshold"]:
            return BERGrade.GOOD
        elif ber_value < self.config["warning_ber_threshold"]:
            return BERGrade.WARNING
        else:
            return BERGrade.CRITICAL
    
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
        recent_values = [entry['ber_value'] for entry in history[-self.config["trend_analysis_points"]:]]
        
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
    
    def get_ber_summary(self) -> Dict[str, Any]:
        """Get overall BER analysis summary"""
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
            grade = stats.get('grade', 'unknown')
            
            port_info = {
                "port": port_name,
                "ber_value": stats.get('ber_value', 0),
                "total_packets": stats.get('total_packets', 0),
                "rx_errors": stats.get('rx_errors', 0),
                "tx_errors": stats.get('tx_errors', 0),
                "timestamp": stats.get('timestamp', time.time())
            }
            
            if grade == BERGrade.EXCELLENT.value:
                summary["excellent_ports"].append(port_info)
            elif grade == BERGrade.GOOD.value:
                summary["good_ports"].append(port_info)
            elif grade == BERGrade.WARNING.value:
                summary["warning_ports"].append(port_info)
            elif grade == BERGrade.CRITICAL.value:
                summary["critical_ports"].append(port_info)
            else:
                summary["unknown_ports"].append(port_info)
        
        return summary
    
    def detect_ber_anomalies(self) -> List[Dict[str, Any]]:
        """Detect BER-related anomalies"""
        anomalies = []
        
        for port_name, stats in self.current_ber_stats.items():
            grade = stats.get('grade', 'unknown')
            ber_value = stats.get('ber_value', 0)
            
            # Critical BER anomaly
            if grade == BERGrade.CRITICAL.value:
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "HIGH_BER_RATE",
                    "severity": "critical",
                    "message": f"Critical BER detected: {ber_value:.2e}",
                    "details": {
                        "ber_value": ber_value,
                        "threshold": self.config["critical_ber_threshold"],
                        "rx_errors": stats.get('rx_errors', 0),
                        "tx_errors": stats.get('tx_errors', 0)
                    },
                    "action": f"Immediate attention required - check cable and transceivers for {port_name}"
                })
            
            # Warning BER anomaly  
            elif grade == BERGrade.WARNING.value:
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "ELEVATED_BER_RATE",
                    "severity": "warning",
                    "message": f"Elevated BER detected: {ber_value:.2e}",
                    "details": {
                        "ber_value": ber_value,
                        "threshold": self.config["warning_ber_threshold"],
                        "rx_errors": stats.get('rx_errors', 0),
                        "tx_errors": stats.get('tx_errors', 0)
                    },
                    "action": f"Monitor {port_name} closely and consider preventive maintenance"
                })
            
            # Trend-based anomalies
            trend_info = self.get_ber_trend(port_name)
            if trend_info["trend"] == "worsening" and trend_info["confidence"] == "high":
                anomalies.append({
                    "device": port_name.split(':')[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':')[1] if ':' in port_name else port_name,
                    "type": "BER_TREND_WORSENING",
                    "severity": "warning",
                    "message": f"BER trend worsening on {port_name}",
                    "details": {
                        "trend": trend_info["trend"],
                        "change_ratio": trend_info.get("change_ratio", 0),
                        "current_ber": ber_value
                    },
                    "action": f"Investigate potential cable degradation on {port_name}"
                })
        
        return anomalies
    
    def export_ber_data_for_web(self, output_file: str):
        """Export BER data for web display - same format as BGP/Link Flap/Optical"""
        summary = self.get_ber_summary()
        anomalies = self.detect_ber_anomalies()
        
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
    <title>BER Analysis Results</title>
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
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
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
<body>
    <div class="page-header">
        <div>
            <div class="page-title">BER Analysis Results</div>
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
                html_content += f"""
            <div class="anomaly-card {severity_class}">
                <h4>{anomaly['device']}:{anomaly['interface']}</h4>
                <p>{anomaly['message']}</p>
                <p><strong>Action:</strong> {anomaly['action']}</p>
            </div>
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
            Interface BER Status
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="ber-table" id="ber-table">
                <thead>
                    <tr>
                        <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="1" data-type="port">Interface <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="2" data-type="ber-status">Status <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="3" data-type="ber-value">Frame BER <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="4" data-type="ber-value">Physical BER <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="5" data-type="number">Total Pkt <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="6" data-type="number">RX Err <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="7" data-type="number">TX Err <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="8" data-type="time">Updated <span class="sort-arrow">▲▼</span></th>
                    </tr>
                </thead>
                <tbody id="ber-data">
"""
        
        # Add all ports to table (sorted by health - problems first, then good ones)
        all_ports = (summary['excellent_ports'] + summary['good_ports'] + 
                    summary['warning_ports'] + summary['critical_ports'])
        
        # Sort ports by BER status priority (critical/warning first)
        def get_ber_priority(port_info):
            ber_value = port_info['ber_value']
            if ber_value >= self.config["critical_ber_threshold"]:
                return 0  # Critical first
            elif ber_value >= self.config["warning_ber_threshold"]:
                return 1  # Warning second  
            elif ber_value == 0:
                return 3  # Excellent third (perfect quality)
            elif ber_value < self.config["raw_ber_threshold"]:
                return 2  # Good second (low error rate)
            else:
                return 4  # Marginal last
        
        sorted_ports = sorted(all_ports, key=get_ber_priority)
        
        for port_info in sorted_ports:
            port_name = port_info['port']
            device = port_name.split(':')[0] if ':' in port_name else "unknown"
            interface = port_name.split(':')[1] if ':' in port_name else port_name
            
            # Determine status and badge class
            ber_value = port_info['ber_value']
            if ber_value == 0:
                status = "EXCELLENT"
                badge_class = "badge badge-green"
            elif ber_value < self.config["raw_ber_threshold"]:
                status = "GOOD"
                badge_class = "badge badge-green"
            elif ber_value < self.config["warning_ber_threshold"]:
                status = "WARNING"
                badge_class = "badge badge-orange"
            else:
                status = "CRITICAL"
                badge_class = "badge badge-red"
            
            ber_display = f"{ber_value:.2e}" if ber_value > 0 else "0"
            
            # Lookup RAW PHY BER for this device/interface (if available)
            raw_map = self._parse_raw_phy_ber_for_device(device)
            raw_phy_val = raw_map.get(interface)
            raw_phy_display = f"{raw_phy_val:.2e}" if isinstance(raw_phy_val, (int, float)) and raw_phy_val is not None else "N/A"

            timestamp = datetime.fromtimestamp(port_info['timestamp']).strftime('%H:%M:%S')
            
            html_content += f"""
                <tr data-status="{status.lower()}">
                    <td>{canonical(device)}</td>
                    <td>{interface}</td>
                    <td><span class="{badge_class}">{status}</span></td>
                    <td>{ber_display}</td>
                    <td>{raw_phy_display}</td>
                    <td>{port_info['total_packets']:,}</td>
                    <td>{port_info['rx_errors']:,}</td>
                    <td>{port_info['tx_errors']:,}</td>
                    <td>{timestamp}</td>
                </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
        
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            BER Analysis Thresholds
        </div>
        <div class="section-content-table">
            <table class="ber-table">
                <thead>
                    <tr><th>Parameter</th><th>Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>Excellent</td><td>Zero errors</td><td>Zero bit errors detected</td></tr>
                    <tr><td>Good</td><td>&lt; 1×10⁻⁶</td><td>Industry standard acceptable BER level</td></tr>
                    <tr><td>Warning</td><td>1×10⁻⁶ to 1×10⁻⁵</td><td>Elevated error rate requiring monitoring</td></tr>
                    <tr><td>Critical</td><td>&gt; 1×10⁻⁵</td><td>Unacceptable error rate, immediate attention required</td></tr>
                    <tr><td>Analysis Method</td><td>Interface statistics</td><td>Based on error counters and packet statistics</td></tr>
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
                <li><strong style="color: #d4d4d4;">Frame BER</strong>: Computed from interface error counters to show overall link quality. Uses delta measurement (new errors since last check) for accurate current status.</li>
                <li><strong style="color: #d4d4d4;">Physical BER</strong>: Physical layer bit error rate from l1-show/PCS layer. Shows actual fiber and optics health including FEC-corrected errors.</li>
                <li><strong style="color: #d4d4d4;">Delta-based measurement</strong>: Both metrics use only new errors since the last measurement to avoid showing accumulated historical errors. First measurement establishes baseline.</li>
            </ul>
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
            allRows = Array.from(document.querySelectorAll('#ber-data tr'));
            
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
            const rows = Array.from(tbody.rows);
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                // Extract actual text for status columns (remove HTML)
                if (type === 'ber-status') {
                    aVal = a.cells[columnIndex].querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex].querySelector('span')?.textContent || bVal;
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
                    case 'number':
                        const numA = parseInt(aVal.replace(/,/g, ''));
                        const numB = parseInt(bVal.replace(/,/g, ''));
                        result = numA - numB;
                        break;
                    case 'time':
                        result = aVal.localeCompare(bVal);
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
        
        function compareBERStatus(a, b) {
            const priority = {
                'CRITICAL': 0,
                'WARNING': 1,
                'GOOD': 2,
                'EXCELLENT': 3,
                'UNKNOWN': 4
            };
            
            return (priority[a] || 5) - (priority[b] || 5);
        }
        
        function compareBERValue(a, b) {
            // Handle scientific notation (1.23e-5) and plain numbers
            if (a === '0' && b === '0') return 0;
            if (a === '0') return 1; // 0 is best (excellent)
            if (b === '0') return -1;
            
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
                const filename = `BER_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Create CSV header
                const headers = [
                    'Port',
                    'Health Status',
                    'BER Value',
                    'RX Errors',
                    'TX Errors',
                    'Total Frames',
                    'Error Rate',
                    'Last Scan'
                ];
                
                let csvContent = headers.join(',') + '\\n';
                
                // Get table data (only visible rows)
                const table = document.getElementById('ber-table');
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');
                
                // Add summary stats as comments
                csvContent += `# BER Analysis Summary Report\\n`;
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
                        if (cells.length >= 8) {
                            const rowData = [
                                cells[0].textContent.trim(), // Port
                                cells[1].querySelector('span') ? cells[1].querySelector('span').textContent.trim() : cells[1].textContent.trim(), // Health Status
                                cells[2].textContent.trim(), // BER Value
                                cells[3].textContent.trim(), // RX Errors
                                cells[4].textContent.trim(), // TX Errors
                                cells[5].textContent.trim(), // Total Frames
                                cells[6].textContent.trim(), // Error Rate
                                cells[7].textContent.trim()  // Last Scan
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
</body>
</html>"""
        
        try:
            with open(output_file, 'w') as f:
                f.write(html_content)
            print(f"BER analysis report generated: {output_file}")
        except Exception as e:
            print(f"Error writing BER analysis report: {e}")
        
        # Save history after analysis
        self.save_ber_history()