#!/usr/bin/env python3
"""
Link Flap Detection Module for LLDPq
Professional Carrier Transition Based

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import json
import html
import time
import collections
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, NamedTuple
from dataclasses import dataclass, asdict

try:
    import yaml
except Exception:
    yaml = None

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

class FlapStatus(Enum):
    """flap status"""
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"

class FlapPeriod(Enum):
    """flap detection periods"""
    FLAP_30_SEC = 30
    FLAP_1_MIN = 60
    FLAP_5_MIN = 5 * 60
    FLAP_1_HR = 60 * 60
    FLAP_12_HRS = 12 * 60 * 60
    FLAP_24_HRS = 24 * 60 * 60

@dataclass
class CarrierTransitionData:
    """Carrier transition data for a port"""
    port_name: str
    transitions: int
    timestamp: float
    device: str = ""
    interface: str = ""
    
class LinkFlapAnalyzer:
    """Professional Link Flap Detection System"""
    
    # constants  
    FLAPPING_INTERVAL = 125  # seconds - detection window
    MIN_CARRIER_TRANSITION_DELTA = 2  # minimum transitions to consider flap
    INTERVAL_TO_PERSIST_FLAP = 60  # seconds - how long flap status persists
    INTERVAL_24_HOURS = 24 * 60 * 60  # 24 hour cleanup
    DEFAULT_THRESHOLDS = {
        "warning_flaps_per_hour": 10,
        "critical_flaps_per_hour": 20,
    }
    
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.carrier_transitions_lookback = {}  # port -> deque of (time, transitions)
        # port -> deque of legacy 3-tuples or interval-aware 5-tuples
        self.flapping_hist = {}
        self.carrier_transitions_stats = {}  # port -> current transition count
        self.prev_cumulative = {}  # port -> last cycle's cumulative carrier_changes (persisted baseline)
        self.prev_sample_time = {}  # port -> timestamp of persisted baseline
        self.flapping_counters = {}  # port -> {period: count}
        self._port_cache = {}  # Cache for calculated port status/counters
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        self.collection_coverage = {
            "expected_devices": 0,
            "current_devices": 0,
            "unavailable_devices": [],
        }
        self._load_configured_thresholds()
        
        # Ensure flap-data directory exists
        os.makedirs(f"{self.data_dir}/flap-data", exist_ok=True)
        
        # Load historical data if exists
        self.load_flap_history()

    def _load_configured_thresholds(self):
        """Load the same flap thresholds used by the notification pipeline."""
        candidates = [
            os.environ.get("LLDPQ_NOTIFICATIONS_FILE"),
            os.path.join(os.path.dirname(os.path.abspath(self.data_dir)), "notifications.yaml"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "notifications.yaml"),
        ]
        if yaml is not None:
            for path in candidates:
                if not path or not os.path.isfile(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        config = yaml.safe_load(handle) or {}
                    network = config.get("thresholds", {}).get("network", {})
                    warning = int(network.get(
                        "link_flaps_per_hour",
                        self.thresholds["warning_flaps_per_hour"],
                    ))
                    critical = int(network.get(
                        "link_flaps_critical",
                        self.thresholds["critical_flaps_per_hour"],
                    ))
                    if warning >= 0:
                        self.thresholds["warning_flaps_per_hour"] = warning
                    if critical >= 0:
                        self.thresholds["critical_flaps_per_hour"] = critical
                    break
                except (OSError, TypeError, ValueError, AttributeError):
                    continue

        for env_name, key in (
            ("LINK_FLAPS_PER_HOUR", "warning_flaps_per_hour"),
            ("LINK_FLAPS_CRITICAL", "critical_flaps_per_hour"),
        ):
            raw = os.environ.get(env_name)
            if raw is None:
                continue
            try:
                value = int(raw)
                if value >= 0:
                    self.thresholds[key] = value
            except ValueError:
                continue

        # A critical boundary below warning would make the grading ambiguous.
        self.thresholds["critical_flaps_per_hour"] = max(
            self.thresholds["critical_flaps_per_hour"],
            self.thresholds["warning_flaps_per_hour"],
        )
    
    def load_flap_history(self):
        """Load historical flap data from file"""
        try:
            with open(f"{self.data_dir}/flap_history.json", "r") as f:
                data = json.load(f)
                # Convert lists back to deques
                for port, hist in data.get("flapping_hist", {}).items():
                    self.flapping_hist[port] = collections.deque(hist, maxlen=1000)
                for port, lookback in data.get("carrier_transitions_lookback", {}).items():
                    self.carrier_transitions_lookback[port] = collections.deque(lookback, maxlen=100)
                self.prev_cumulative = dict(data.get("prev_cumulative", {}))
                self.prev_sample_time = dict(data.get("prev_sample_time", {}))
                saved_coverage = data.get("collection_coverage")
                if isinstance(saved_coverage, dict):
                    self.collection_coverage.update(saved_coverage)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    
    def save_flap_history(self):
        """Save flap history to file"""
        try:
            data = {
                "flapping_hist": {port: list(deq) for port, deq in self.flapping_hist.items()},
                "carrier_transitions_lookback": {port: list(deq) for port, deq in self.carrier_transitions_lookback.items()},
                "prev_cumulative": self.prev_cumulative,
                "prev_sample_time": self.prev_sample_time,
                "collection_coverage": self.collection_coverage,
                "last_update": time.time()
            }
            with open(f"{self.data_dir}/flap_history.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving flap history: {e}")
    
    def update_carrier_transitions(self, port_name: str, current_transitions: int):
        """Update carrier transition count for a port, and record any NEW flaps since the previous
        cycle.

        carrier_changes is a cumulative kernel counter and the monitor runs every few minutes -- far
        longer than any short lookback window -- so flaps are detected by the delta against the
        PREVIOUS cycle's cumulative value (a persisted baseline), not by trying to keep two samples
        inside a 125s window. Each detected delta is timestamped so the 1h/12h/24h buckets populate.
        (The old code compared two samples that never coexisted at a 10-min cadence -> windows were
        always 0 while the raw Total counter still showed a value.)"""
        curr_time = time.time()
        self._port_cache = {}

        # Initialize if new port
        if port_name not in self.carrier_transitions_lookback:
            self.carrier_transitions_lookback[port_name] = collections.deque(maxlen=100)
        if port_name not in self.flapping_hist:
            self.flapping_hist[port_name] = collections.deque(maxlen=1000)

        # Cycle-over-cycle delta vs the persisted previous cumulative reading.
        prev = self.prev_cumulative.get(port_name)
        prev_time = self.prev_sample_time.get(port_name)
        if prev is not None and current_transitions >= prev:
            delta = current_transitions - prev
            if delta >= self.MIN_CARRIER_TRANSITION_DELTA:
                # The exact event time is unknown.  Persist the complete poll
                # interval so short-window counters can refuse to overclaim it.
                if prev_time is None:
                    # Baselines persisted by older versions have no sampling
                    # timestamp, so the delta may span minutes or days. Rebase
                    # once instead of assigning an unknowable interval.
                    pass
                else:
                    interval_start = float(prev_time)
                    interval_seconds = max(0.0, curr_time - interval_start)
                    self.flapping_hist[port_name].append((
                        curr_time,
                        current_transitions,
                        delta // 2,
                        interval_start,
                        interval_seconds,
                    ))
        # current < prev => counter reset (e.g. reboot); skip this cycle and just re-baseline below.
        self.prev_cumulative[port_name] = current_transitions
        self.prev_sample_time[port_name] = curr_time

        # Keep lookback/stats for the rest of the report (Total column = current cumulative counter).
        self.carrier_transitions_lookback[port_name].append((curr_time, current_transitions))
        self.carrier_transitions_stats[port_name] = current_transitions

        # Clean old entries
        self._cleanup_old_entries(curr_time)
    
    def _cleanup_old_entries(self, curr_time: float):
        """Remove entries older than thresholds"""
        # Remove entries older than flapping interval
        for port, lookback_queue in self.carrier_transitions_lookback.items():
            while lookback_queue and (curr_time - lookback_queue[0][0] > self.FLAPPING_INTERVAL):
                lookback_queue.popleft()
        
        # Remove entries older than 24 hrs
        for port, flap_hist_queue in self.flapping_hist.items():
            while flap_hist_queue and (curr_time - flap_hist_queue[0][0] > self.INTERVAL_24_HOURS):
                flap_hist_queue.popleft()
    
    def check_flapping(self) -> bool:
        """Return True when any port crosses the configured hourly warning rate."""
        warning = self.thresholds["warning_flaps_per_hour"]
        for port_name in self.carrier_transitions_stats:
            count = self.calculate_flapping_rate(port_name)["flap_1_hr"]
            if warning > 0 and count >= warning:
                print(f"Flap threshold exceeded on {port_name}: {count} flaps in last hour")
                return True
        return False
    
    def calculate_flapping_rate(self, port_name: str) -> Dict[str, int]:
        """Calculate flapping rates for different time periods"""
        flap_counters = {period.name.lower(): 0 for period in FlapPeriod}
        
        curr_time = time.time()
        flaps = self.flapping_hist.get(port_name, [])
        
        if flaps:
            for event in flaps:
                if len(event) < 3:
                    continue
                flap_time, _, flap_count = event[:3]
                sample_age = max(0.0, curr_time - float(flap_time))
                is_interval_aware = len(event) >= 5
                interval_seconds = max(0.0, float(event[4])) if is_interval_aware else None

                for period in FlapPeriod:
                    if is_interval_aware:
                        # Count only when the entire observation interval fits
                        # inside the requested lookback. A ten-minute poll can
                        # therefore populate 1h/12h/24h, never 30s/1m/5m.
                        fits = sample_age + interval_seconds <= period.value
                    else:
                        # Legacy entries lack observation-window metadata. Keep
                        # them out of short buckets where they could be false.
                        fits = period.value >= FlapPeriod.FLAP_1_HR.value and sample_age <= period.value
                    if fits:
                        flap_counters[period.name.lower()] += int(flap_count)
        
        return flap_counters
    
    def _build_port_cache(self):
        """Build cache of all port statuses and counters - call once before bulk operations"""
        self._port_cache = {}
        for port_name in self.carrier_transitions_stats.keys():
            counters = self.calculate_flapping_rate(port_name)
            status = self._status_for_counters(counters)
            self._port_cache[port_name] = {'status': status, 'counters': counters}

    def _status_for_counters(self, counters: Dict[str, int]) -> FlapStatus:
        """Grade a port from configured one-hour flap thresholds."""
        hourly = counters.get("flap_1_hr", 0)
        critical = self.thresholds["critical_flaps_per_hour"]
        warning = self.thresholds["warning_flaps_per_hour"]
        if critical > 0 and hourly >= critical:
            return FlapStatus.CRITICAL
        if warning > 0 and hourly >= warning:
            return FlapStatus.WARNING
        return FlapStatus.OK
    
    def get_port_flap_status(self, port_name: str) -> FlapStatus:
        """Get current flap status for a port"""
        counters = self.calculate_flapping_rate(port_name)
        
        return self._status_for_counters(counters)
    
    def get_flap_summary(self) -> Dict[str, Any]:
        """Get summary of all flapping ports - uses cache for performance"""
        summary = {
            "total_ports": len(self.carrier_transitions_stats),
            "critical_ports": [],
            "warning_ports": [],
            "ok_ports": [],
            "collection_coverage": dict(self.collection_coverage),
            "timestamp": datetime.now().isoformat()
        }
        
        # Build cache if empty
        if not self._port_cache:
            self._build_port_cache()
        
        for port_name, cached in self._port_cache.items():
            status = cached['status']
            counters = cached['counters']
            
            port_info = {
                "port": port_name,
                "status": status.value,
                "counters": counters,
                "last_transitions": self.carrier_transitions_stats.get(port_name, 0)
            }
            
            if status == FlapStatus.CRITICAL:
                summary["critical_ports"].append(port_info)
            elif status == FlapStatus.WARNING:
                summary["warning_ports"].append(port_info)
            else:
                summary["ok_ports"].append(port_info)

        # Compatibility aliases for consumers upgraded independently.
        summary["flapping_ports"] = summary["critical_ports"]
        summary["flapped_ports"] = summary["warning_ports"]
        
        return summary
    
    def detect_flap_anomalies(self) -> List[Dict[str, Any]]:
        """Detect interface flapping anomalies - uses cache for performance"""
        anomalies = []
        
        # Build cache if empty
        if not self._port_cache:
            self._build_port_cache()
        
        for port_name, cached in self._port_cache.items():
            status = cached['status']
            counters = cached['counters']
            
            if status == FlapStatus.CRITICAL:
                anomalies.append({
                    "device": port_name.split(':', 1)[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':', 1)[1] if ':' in port_name else port_name,
                    "type": "CRITICAL_FLAPPING",
                    "severity": "critical",
                    "message": f"Port {port_name} crossed the critical threshold ({counters['flap_1_hr']} flaps in last hour)",
                    "details": {
                        "flap_count_1hr": counters['flap_1_hr'],
                        "critical_threshold": self.thresholds["critical_flaps_per_hour"],
                        "current_transitions": self.carrier_transitions_stats.get(port_name, 0)
                    },
                    "action": f"Check physical cabling and hardware health for {port_name}"
                })
            
            elif status == FlapStatus.WARNING:
                anomalies.append({
                    "device": port_name.split(':', 1)[0] if ':' in port_name else "unknown",
                    "interface": port_name.split(':', 1)[1] if ':' in port_name else port_name,
                    "type": "WARNING_FLAPPING",
                    "severity": "warning",
                    "message": f"Port {port_name} crossed the warning threshold ({counters['flap_1_hr']} flaps in last hour)",
                    "details": {
                        "flap_count_1hr": counters['flap_1_hr'],
                        "warning_threshold": self.thresholds["warning_flaps_per_hour"],
                        "current_transitions": self.carrier_transitions_stats.get(port_name, 0)
                    },
                    "action": f"Monitor {port_name} closely and investigate if pattern continues"
                })
        
        return anomalies

    def set_collection_coverage(self, expected_devices, current_devices):
        expected = set(expected_devices)
        current = set(current_devices)
        self.collection_coverage = {
            "expected_devices": len(expected),
            "current_devices": len(current),
            "unavailable_devices": sorted(expected - current),
        }
    
    def export_flap_data_for_web(self, output_file: str):
        """Export flap data for web display - optimized with caching"""
        # Build cache once at the start
        self._build_port_cache()
        
        summary = self.get_flap_summary()
        anomalies = self.detect_flap_anomalies()
        
        # Determine overall health status
        total_problematic = len(summary['critical_ports']) + len(summary['warning_ports'])
        stability_ratio = ((summary['total_ports'] - total_problematic) / summary['total_ports'] * 100) if summary['total_ports'] > 0 else 0
        if summary['critical_ports']:
            problem_card_class = "card-critical"
            problem_metric_class = "flap-critical"
        elif summary['warning_ports']:
            problem_card_class = "card-warning"
            problem_metric_class = "flap-warning"
        else:
            problem_card_class = "card-excellent"
            problem_metric_class = "flap-excellent"
        coverage = summary.get("collection_coverage", {})
        expected_devices = int(coverage.get("expected_devices", 0) or 0)
        current_devices = int(coverage.get("current_devices", 0) or 0)
        if expected_devices and current_devices == 0:
            coverage_status = "unavailable"
        elif expected_devices and current_devices < expected_devices:
            coverage_status = "partial"
        else:
            coverage_status = "current"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Link Flap Detection Results</title>
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
        .card-warning {{ border-left-color: #ff9800; }}
        .card-critical {{ border-left-color: #f44336; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .flap-excellent {{ color: #76b900; font-weight: bold; }}
        .flap-good {{ color: #8bc34a; font-weight: bold; }}
        .flap-warning {{ color: #ff9800; font-weight: bold; }}
        .flap-critical {{ color: #f44336; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .status-ok {{ color: #76b900; font-weight: bold; }}
        .status-flapping {{ color: #f44336; font-weight: bold; }}
        .status-flapped {{ color: #ff9800; font-weight: bold; }}
        .flap-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .flap-table th, .flap-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; }}
        .flap-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .flap-table tbody tr {{ background: #252526; }}
        .flap-table tbody tr:hover {{ background: #2d2d2d; }}
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
        
        /* Custom fast tooltip */
        .info-tooltip {{
            position: relative;
            cursor: help;
        }}
        .info-tooltip::after {{
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: #fff;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: normal;
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.1s, visibility 0.1s;
            z-index: 1000;
            pointer-events: none;
        }}
        .info-tooltip:hover::after {{
            opacity: 1;
            visibility: visible;
        }}
    </style>
</head>
<body>
    <div data-analysis-summary="flap" data-collection-status="{coverage_status}"
         data-expected-devices="{expected_devices}"
         data-current-devices="{current_devices}"
         data-critical-ports="{len(summary['critical_ports'])}"
         data-warning-ports="{len(summary['warning_ports'])}" style="display:none"></div>
    <div class="page-header">
        <div>
            <div class="page-title">Link Flap Detection Results</div>
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
            Link Flap Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-devices-card" data-metric-key="flap_current_devices" data-metric-value="{len(set(port.split(':', 1)[0] for port in self.carrier_transitions_stats.keys()))}">
                    <div class="metric" id="total-devices">{len(set(port.split(':', 1)[0] for port in self.carrier_transitions_stats.keys()))}</div>
                    <div class="metric-label">Total Devices</div>
                </div>
                <div class="summary-card card-info" id="total-ports-card" data-metric-key="flap_total_ports" data-metric-value="{summary['total_ports']}">
                    <div class="metric" id="total-ports">{summary['total_ports']}</div>
                    <div class="metric-label">Total Ports</div>
                </div>
                <div class="summary-card card-excellent" id="stable-card" data-metric-key="flap_stable_ports" data-metric-value="{len(summary['ok_ports'])}">
                    <div class="metric flap-excellent" id="stable-ports">{len(summary['ok_ports'])}</div>
                    <div class="metric-label">Stable</div>
                </div>
                <div class="summary-card {problem_card_class}" id="problematic-card" data-metric-key="flap_problematic_ports" data-metric-value="{total_problematic}">
                    <div class="metric {problem_metric_class}" id="problematic-ports">{total_problematic}</div>
                    <div class="metric-label">Problematic</div>
                </div>
                <div class="summary-card" id="stability-card" data-metric-key="flap_stability_ratio" data-metric-value="{stability_ratio:.1f}">
                    <div class="metric" id="stability-ratio">{stability_ratio:.1f}%</div>
                    <div class="metric-label">Stability Ratio</div>
                </div>
            </div>
        </div>
    </div>
"""
        
        # Add anomalies section if any exist
        if anomalies:
            html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
            Detailed Issue Analysis ({len(anomalies)})
        </div>
        <div class="section-content">
"""
            for anomaly in anomalies:
                severity_class = "warning" if anomaly['severity'] == 'warning' else ""
                anomaly_device_key = html.escape(str(anomaly['device']), quote=True)
                html_content += f"""
            <div class="anomaly-card {severity_class}" data-device-key="{anomaly_device_key}">
                <h4>{anomaly['device']} - {anomaly['interface']}</h4>
                <p><strong>Issue:</strong> {anomaly['message']}</p>
                <p><strong>Recommended Action:</strong> {anomaly['action']}</p>
            </div>
"""
            html_content += """
        </div>
    </div>
"""
        
        # Collect all ports for display - using cache
        all_ports = []
        for port_name, cached in self._port_cache.items():
            device = port_name.split(':', 1)[0] if ':' in port_name else "unknown"
            interface = port_name.split(':', 1)[1] if ':' in port_name else port_name
            
            port_info = {
                'device': device,
                'interface': interface,
                'status': cached['status'],
                'counters': cached['counters'],
                'total_transitions': self.carrier_transitions_stats.get(port_name, 0)
            }
            all_ports.append(port_info)
        
        # Interface flapping table (sorted by problems first, like BGP)
        html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Interface Flapping Status ({len(all_ports)} total)
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="flap-table" id="flap-table">
                <thead>
                <tr>
                    <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="1" data-type="port">Interface <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="2" data-type="flap-status">Status <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="3" data-type="number">30s <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="4" data-type="number">1m <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="5" data-type="number">5m <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="6" data-type="number">1h <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="7" data-type="number">12h <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="8" data-type="number">24h <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="9" data-type="number">Total <span class="info-tooltip" data-tooltip="Cumulative count since last device reboot">ⓘ</span> <span class="sort-arrow">▲▼</span></th>
                </tr>
                </thead>
                <tbody id="flap-data">
"""
        
        # Sort by severity (problems first, like BGP)
        sorted_ports = sorted(all_ports, key=lambda x: (
            0 if x['status'] == FlapStatus.CRITICAL else
            1 if x['status'] == FlapStatus.WARNING else 2
        ))
        
        # Build table rows using list for O(n) performance instead of O(n²) string concat
        table_rows = []
        for port in sorted_ports:
            counters = port['counters']
            # Badge class based on status
            status_val = port['status'].value
            if status_val == 'ok':
                badge_class = 'badge badge-green'
            elif status_val == 'critical':
                badge_class = 'badge badge-red'
            else:  # warning
                badge_class = 'badge badge-orange'
            
            # The cumulative counter can be large on a healthy old device; its
            # colour follows the current threshold grade, not lifetime total.
            if status_val == "critical":
                transition_class = "transition-critical"
            elif status_val == "warning":
                transition_class = "transition-warning"
            else:
                transition_class = "transition-good"

            dashboard_status = "ok" if status_val == "ok" else "problematic"
            device_key = html.escape(str(port['device']), quote=True)
            table_rows.append(f"""
        <tr data-device-key="{device_key}" data-status="{dashboard_status}" data-flap-status="{status_val}">
            <td>{canonical(port['device'])}</td>
            <td>{port['interface']}</td>
            <td><span class="{badge_class}">{status_val.upper()}</span></td>
            <td>{counters['flap_30_sec']}</td>
            <td>{counters['flap_1_min']}</td>
            <td>{counters['flap_5_min']}</td>
            <td>{counters['flap_1_hr']}</td>
            <td>{counters['flap_12_hrs']}</td>
            <td>{counters['flap_24_hrs']}</td>
            <td><span class="{transition_class}">{port['total_transitions']}</span></td>
        </tr>""")
        
        html_content += ''.join(table_rows)
        
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
    
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            Link Flap Detection Thresholds
        </div>
        <div class="section-content-table">
            <table class="flap-table">
                <thead>
                    <tr><th>Parameter</th><th>Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>Warning Rate</td><td>__FLAP_WARNING_THRESHOLD__</td><td>Flaps observed during complete sampling intervals within the last hour</td></tr>
                    <tr><td>Critical Rate</td><td>__FLAP_CRITICAL_THRESHOLD__</td><td>Critical one-hour flap boundary</td></tr>
                    <tr><td>Min Transition Delta</td><td>2+ transitions</td><td>Minimum transitions to trigger flap detection</td></tr>
                    <tr><td>Short Windows</td><td>Complete interval only</td><td>A poll interval is never attributed to a shorter 30s, 1m, or 5m bucket</td></tr>
                    <tr><td>Data Retention</td><td>24 hours</td><td>Historical carrier transition data retention</td></tr>
                </tbody>
            </table>
        </div>
    </div>

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
            allRows = Array.from(document.querySelectorAll('#flap-data tr'));
            
            // Add click events to summary cards
            setupCardEvents();
            
            // Initialize table sorting
            initTableSorting();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });
        
        function setupCardEvents() {
            // Check if elements exist
            const totalDevicesCard = document.getElementById('total-devices-card');
            const totalPortsCard = document.getElementById('total-ports-card');
            
            if (totalDevicesCard) {
                totalDevicesCard.addEventListener('click', function() {
                    filterPorts('TOTAL');
                });
            }
            
            if (totalPortsCard) {
                totalPortsCard.addEventListener('click', function() {
                    if (parseInt(document.getElementById('total-ports').textContent) > 0) {
                        filterPorts('TOTAL');
                    }
                });
            }
            
            document.getElementById('stable-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('stable-ports').textContent) > 0) {
                    filterPorts('STABLE');
                }
            });
            
            document.getElementById('problematic-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('problematic-ports').textContent) > 0) {
                    filterPorts('PROBLEMATIC');
                }
            });
            
            document.getElementById('stability-card').addEventListener('click', function() {
                console.log('LINK FLAP: Stability clicked');
                filterPorts('TOTAL'); // Stability ratio shows all ports
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
            
            if (filterType === 'STABLE') {
                filteredRows = allRows.filter(row => row.dataset.status === 'ok');
                filterText = 'Showing ' + filteredRows.length + ' Stable Ports';
                document.getElementById('stable-card').classList.add('active');
            } else if (filterType === 'PROBLEMATIC') {
                filteredRows = allRows.filter(row => row.dataset.status === 'problematic');
                filterText = 'Showing ' + filteredRows.length + ' Problematic Ports';
                document.getElementById('problematic-card').classList.add('active');
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
                minimumInputLength: 0,
                matcher: function(params, data) {
                    // If no search term, show all
                    if ($.trim(params.term) === '') return data;
                    // Skip items without text
                    if (typeof data.text === 'undefined' || data.text === null) return null;
                    // Case-insensitive partial match
                    const term = params.term.toLowerCase();
                    const text = data.text.toLowerCase();
                    if (text.indexOf(term) > -1) {
                        return data;
                    }
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
                    sortFlapTable(column, tableSortState.direction, type);
                });
            });
        }
        
        function sortFlapTable(columnIndex, direction, type) {
            const table = document.getElementById('flap-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows);
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                // Extract actual text for status columns (remove HTML)
                if (type === 'flap-status') {
                    aVal = a.cells[columnIndex].querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex].querySelector('span')?.textContent || bVal;
                }
                
                let result = 0;
                
                switch(type) {
                    case 'number':
                        result = parseInt(aVal) - parseInt(bVal);
                        break;
                    case 'port':
                        result = comparePort(aVal, bVal);
                        break;
                    case 'flap-status':
                        result = compareFlapStatus(aVal, bVal);
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
        
        function compareFlapStatus(a, b) {
            const priority = {
                'CRITICAL': 0,
                'WARNING': 1,
                'OK': 2
            };
            
            const aPriority = Object.prototype.hasOwnProperty.call(priority, a) ? priority[a] : 99;
            const bPriority = Object.prototype.hasOwnProperty.call(priority, b) ? priority[b] : 99;
            return aPriority - bPriority;
        }

        // Run Analysis Function
        async function runAnalysis() {
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
            let baseline = null;
            if (typeof window.lldpqCaptureAnalysisState === 'function') {
                try { baseline = await window.lldpqCaptureAnalysisState('flap'); } catch (error) { baseline = null; }
            }
            
            // Send POST request to trigger monitor
            fetch('/trigger-monitor?scope=flap', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success' && data.trigger_id && data.scope === 'flap') {
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
                        The link flap analysis is running in the background.<br>
                        <small>Waiting for the link flap results to be published before refreshing.</small>
                    `;
                    document.body.appendChild(notification);
                    const completion = typeof window.waitForLldpqAnalysisCompletion === 'function'
                        ? window.waitForLldpqAnalysisCompletion(
                            baseline, { scope: 'flap', pipelineId: data.trigger_id })
                        : new Promise(resolve => setTimeout(resolve, 35000));
                    Promise.resolve(completion)
                        .then(() => window.location.reload())
                        .catch(error => {
                            console.error('Analysis did not complete successfully:', error);
                            notification.remove();
                            alert('Analysis did not complete successfully. The previous report was kept.');
                            button.disabled = false;
                            button.innerHTML = originalText;
                        });
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
                const filename = `Link_Flap_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Create CSV header
                const headers = [
                    'Device',
                    'Port',
                    'Status',
                    '30s',
                    '1m',
                    '5m',
                    '1h',
                    '12h',
                    '24h',
                    'Total'
                ];
                
                let csvContent = headers.join(',') + '\\n';
                
                // Get table data (only visible rows)
                const table = document.getElementById('flap-table');
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');
                
                // Add summary stats as comments
                csvContent += `# Link Flap Analysis Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Devices: ${document.getElementById('total-devices').textContent}\\n`;
                csvContent += `# Total Ports: ${document.getElementById('total-ports').textContent}\\n`;
                csvContent += `# Stable Ports: ${document.getElementById('stable-ports').textContent}\\n`;
                csvContent += `# Problematic Ports: ${document.getElementById('problematic-ports').textContent}\\n`;
                csvContent += `# Stability Ratio: ${document.getElementById('stability-ratio').textContent}\\n`;
                csvContent += `#\\n`;
                
                // Process each visible row
                rows.forEach(row => {
                    if (row.style.display !== 'none') {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 10) {
                            const rowData = [
                                cells[0].textContent.trim(), // Device
                                cells[1].textContent.trim(), // Port
                                cells[2].querySelector('span') ? cells[2].querySelector('span').textContent.trim() : cells[2].textContent.trim(), // Status
                                cells[3].textContent.trim(), // 30 sec
                                cells[4].textContent.trim(), // 1 min
                                cells[5].textContent.trim(), // 5 min
                                cells[6].textContent.trim(), // 1 hour
                                cells[7].textContent.trim(), // 12 hours
                                cells[8].textContent.trim(), // 24 hours
                                cells[9].textContent.trim()  // Total
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
    <script src="/css/analysis-guard.js?v=20260707-scoped-runner-2"></script>
</body>
</html>"""

        html_content = html_content.replace(
            "__FLAP_WARNING_THRESHOLD__",
            f'{self.thresholds["warning_flaps_per_hour"]}+ flaps/hour',
        ).replace(
            "__FLAP_CRITICAL_THRESHOLD__",
            f'{self.thresholds["critical_flaps_per_hour"]}+ flaps/hour',
        )
        
        with open(output_file, "w") as f:
            f.write(html_content)

if __name__ == "__main__":
    analyzer = LinkFlapAnalyzer()
    print("Link Flap analyzer initialized")
    print(f"Monitoring {len(analyzer.carrier_transitions_stats)} ports")
