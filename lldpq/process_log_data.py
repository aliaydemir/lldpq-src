#!/usr/bin/env python3
"""
Log Analysis Script
Processes collected log data and generates severity-based analysis

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

class LogAnalyzer:
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.log_data_dir = os.path.join(data_dir, "log-data")
        self.log_analysis = defaultdict(lambda: {"critical": [], "warning": [], "error": [], "info": []})
        self.log_counts = defaultdict(lambda: {"critical": 0, "warning": 0, "error": 0, "info": 0})
        
        # Patterns that should NOT be critical (demoted to warning)
        # These are transient issues, not real critical problems
        self.excluded_from_critical = [
            r'sx_sdk.*bulk_counter',           # ASIC counter read errors
            r'bulk-cntr.*ioctl.*failed',       # Driver busy errors
            r'bulk-read.*transaction',         # Transaction errors
            r'device or resource busy',        # Resource busy
            r'port-counter-transaction',       # Port counter transaction errors
        ]
        
        # Patterns to completely ignore (not even counted as info)
        # These are our own monitoring commands or noise
        self.skip_patterns = [
            r'ethtool -m swp',               # Our optical monitoring commands
            r'cumulus.*sudo.*ethtool',       # sudo logs from our monitoring
            r'cumulus.*COMMAND=.*ethtool',   # sudo command logs
            r'cumulus.*COMMAND=.*l1-show',   # sudo l1-show commands
            r'cumulus.*COMMAND=.*sensors',   # sudo sensors commands
            r'pam_unix.*session opened',     # PAM session logs
            r'pam_unix.*session closed',     # PAM session logs
            r'connection collision resolution',  # Normal BGP behavior
        ]
        
        # Enhanced severity patterns for network infrastructure
        self.severity_patterns = {
            'critical': [
                r'\b(critical|emergency|panic|fatal|disaster|catastrophic)\b',
                r'\b(failed|failure|error|exception|crash|abort)\b.*\b(critical|severe)\b',
                r'\b(down|offline|unreachable|disconnected)\b.*\b(interface|link|connection|peer|neighbor)\b',
                r'\b(kernel panic|segmentation fault|out of memory|disk full)\b',
                r'priority:\s*[0-2]',  # Emergency, Alert, Critical
                # Network-specific critical patterns
                r'\b(bgp.*down|ospf.*down|routing.*failed|switching.*failed)\b',
                r'\b(mlag.*failed|clag.*conflict|spanning.*tree.*blocked)\b',
                r'\b(switchd.*died|nvued.*crashed|frr.*stopped)\b',
                r'\b(hardware.*fault|transceiver.*failed|port.*failed)\b',
            ],
            'warning': [
                r'\b(warning|warn|caution|alert)\b',
                r'\b(high|elevated|unusual|abnormal)\b.*\b(usage|load|temperature|traffic)\b',
                r'\b(timeout|retry|retransmit|flap|unstable)\b',
                r'\b(deprecat|obsolet|unsupport)\b',
                r'priority:\s*[3-4]',  # Error, Warning
                # Network-specific warning patterns
                r'\b(bgp.*flap|neighbor.*timeout|routing.*convergence)\b',
                r'\b(stp.*topology.*change|vlan.*inconsistent)\b',
                r'\b(mlag.*mismatch|bond.*degraded|link.*unstable)\b',
                r'\b(high.*utilization|buffer.*full|queue.*overflow)\b',
                r'\b(authentication.*failed|permission.*denied)\b',
            ],
            'error': [
                r'\b(error|err|exception|fault|fail)\b',
                r'\b(invalid|illegal|unauthorized|forbidden|denied)\b',
                r'\b(corrupt|damaged|broken|malformed)\b',
                r'\b(cannot|unable|refused|rejected)\b',
                r'priority:\s*[5-6]',  # Notice, Info (errors in context)
                # Network-specific error patterns
                r'\b(config.*error|nv.*set.*failed|commit.*failed)\b',
                r'\b(route.*unreachable|arp.*failed|mac.*learning.*failed)\b',
                r'\b(vxlan.*error|tunnel.*failed|encap.*error)\b',
            ],
            'info': [
                r'\b(info|information|notice|debug|trace)\b',
                r'\b(start|started|stop|stopped|restart|reload)\b',
                r'\b(up|online|connected|established|ready)\b',
                r'\b(configured|enabled|disabled|updated)\b',
                r'priority:\s*[7]',  # Debug
                # Network-specific info patterns
                r'\b(bgp.*established|neighbor.*up|route.*learned)\b',
                r'\b(interface.*up|link.*up|carrier.*detected)\b',
                r'\b(mlag.*sync|clag.*active|stp.*forwarding)\b',
                r'\b(config.*applied|nv.*set.*success|commit.*complete)\b',
            ]
        }
    
    def categorize_log_line(self, line):
        """Categorize a log line by severity"""
        line_lower = line.lower()
        
        # First check if this should be completely skipped (our own monitoring noise)
        for pattern in self.skip_patterns:
            if re.search(pattern, line_lower):
                return None  # Skip completely, don't count at all
        
        # Then check if this should be excluded from critical
        # These are transient issues that look critical but aren't
        for pattern in self.excluded_from_critical:
            if re.search(pattern, line_lower):
                return 'info'     # These are just noise, not real warnings
        
        # Check critical patterns first (highest priority)
        for pattern in self.severity_patterns['critical']:
            if re.search(pattern, line_lower):
                return 'critical'
        
        # Then warning patterns
        for pattern in self.severity_patterns['warning']:
            if re.search(pattern, line_lower):
                return 'warning'
        
        # Then error patterns
        for pattern in self.severity_patterns['error']:
            if re.search(pattern, line_lower):
                return 'error'
        
        # Default to info if no specific pattern matches
        return 'info'
    
    def parse_timestamp(self, line):
        """Extract timestamp from log line if available"""
        # Common timestamp patterns
        timestamp_patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Nov 15 14:30:22
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',  # 2024-11-15T14:30:22
            r'(\d{2}:\d{2}:\d{2})',                     # 14:30:22
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def parse_timestamp_to_datetime(self, line):
        """Extract timestamp from log line and convert to datetime object"""
        now = datetime.now()
        
        # Pattern 1: "Jan 13 18:37:49" format
        match = re.search(r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', line)
        if match:
            try:
                month_str, day, hour, minute, second = match.groups()
                month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                month = month_map.get(month_str, 1)
                year = now.year
                log_dt = datetime(year, month, int(day), int(hour), int(minute), int(second))
                # Handle year rollover (if log is from December and now is January)
                if log_dt > now + timedelta(days=1):
                    log_dt = datetime(year - 1, month, int(day), int(hour), int(minute), int(second))
                return log_dt
            except:
                pass
        
        # Pattern 2: "2024-01-13T18:37:49" format
        match = re.search(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', line)
        if match:
            try:
                year, month, day, hour, minute, second = match.groups()
                return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
            except:
                pass
        
        # Pattern 3: Just time "18:37:49" - assume today
        match = re.search(r'(\d{2}):(\d{2}):(\d{2})', line)
        if match:
            try:
                hour, minute, second = match.groups()
                return datetime(now.year, now.month, now.day, int(hour), int(minute), int(second))
            except:
                pass
        
        return None
    
    def adjust_severity_by_age(self, severity, log_datetime):
        """Adjust severity based on log age - older logs are less critical"""
        if log_datetime is None:
            return severity  # Can't determine age, keep original
        
        now = datetime.now()
        age = now - log_datetime
        age_minutes = age.total_seconds() / 60
        
        # Time-based severity adjustment:
        # - Last 30 minutes: Keep original severity
        # - 30 min to 2 hours: Demote critical → warning
        # - Over 2 hours: Demote critical/warning → info
        
        if age_minutes < 30:
            return severity  # Fresh log, keep original
        elif age_minutes < 120:  # 30 min - 2 hours
            if severity == 'critical':
                return 'warning'  # Demote critical to warning
            return severity
        else:  # Over 2 hours
            if severity in ('critical', 'warning'):
                return 'info'  # Demote to info (historical)
            return severity
    
    def process_device_logs(self, device_name, log_file_path):
        """Process logs for a single device"""
        if not os.path.exists(log_file_path):
            print(f"⚠️  Log file not found: {log_file_path}")
            return
        
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Split into sections based on log type markers
            sections = {
                'FRR_ROUTING_LOGS': [],
                'SWITCHD_LOGS': [],
                'NVUE_CONFIG_LOGS': [],
                'MSTPD_STP_LOGS': [],
                'CLAGD_MLAG_LOGS': [],
                'AUTH_SECURITY_LOGS': [],
                'SYSTEM_CRITICAL_LOGS': [],
                'JOURNALCTL_PRIORITY_LOGS': [],
                'DMESG_HARDWARE_LOGS': [],
                'NETWORK_INTERFACE_LOGS': []
            }
            
            current_section = None
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Check for section markers
                if line.startswith('===') or line.endswith(':'):
                    if 'FRR_ROUTING_LOGS' in line:
                        current_section = 'FRR_ROUTING_LOGS'
                    elif 'SWITCHD_LOGS' in line:
                        current_section = 'SWITCHD_LOGS'
                    elif 'NVUE_CONFIG_LOGS' in line:
                        current_section = 'NVUE_CONFIG_LOGS'
                    elif 'MSTPD_STP_LOGS' in line:
                        current_section = 'MSTPD_STP_LOGS'
                    elif 'CLAGD_MLAG_LOGS' in line:
                        current_section = 'CLAGD_MLAG_LOGS'
                    elif 'AUTH_SECURITY_LOGS' in line:
                        current_section = 'AUTH_SECURITY_LOGS'
                    elif 'SYSTEM_CRITICAL_LOGS' in line:
                        current_section = 'SYSTEM_CRITICAL_LOGS'
                    elif 'JOURNALCTL_PRIORITY_LOGS' in line:
                        current_section = 'JOURNALCTL_PRIORITY_LOGS'
                    elif 'DMESG_HARDWARE_LOGS' in line:
                        current_section = 'DMESG_HARDWARE_LOGS'
                    elif 'NETWORK_INTERFACE_LOGS' in line:
                        current_section = 'NETWORK_INTERFACE_LOGS'
                    continue
                
                # Skip non-informative lines
                if (line.startswith('No ') or line == '' or len(line) < 10 or 
                    'No entries' in line or line.strip() == '-- No entries --' or
                    'not found' in line.lower() or 'log not found' in line):
                    continue
                
                if current_section:
                    sections[current_section].append(line)
            
            # Process each section
            for section_name, lines in sections.items():
                for line in lines:
                    if len(line.strip()) < 5:  # Skip very short lines
                        continue
                    
                    severity = self.categorize_log_line(line)
                    
                    # Skip if severity is None (monitoring noise)
                    if severity is None:
                        continue
                    
                    timestamp = self.parse_timestamp(line)
                    
                    # Adjust severity based on log age (older logs are less critical)
                    log_datetime = self.parse_timestamp_to_datetime(line)
                    original_severity = severity
                    severity = self.adjust_severity_by_age(severity, log_datetime)
                    
                    log_entry = {
                        'timestamp': timestamp,
                        'section': section_name,
                        'message': line.strip(),
                        'severity': severity,
                        'original_severity': original_severity if original_severity != severity else None
                    }
                    
                    self.log_analysis[device_name][severity].append(log_entry)
                    self.log_counts[device_name][severity] += 1
        
        except Exception as e:
            print(f"❌ Error processing logs for {device_name}: {e}")
    
    def generate_html_report(self):
        """Generate HTML report for log analysis"""
        print("Generating log analysis HTML report...")
        
        # Calculate totals
        total_devices = len(self.log_counts)
        totals = {"critical": 0, "warning": 0, "error": 0, "info": 0}
        
        for device_counts in self.log_counts.values():
            for severity in totals:
                totals[severity] += device_counts[severity]
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Results</title>
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
        .log-excellent {{ color: #76b900; font-weight: bold; }}
        .log-good {{ color: #8bc34a; font-weight: bold; }}
        .log-warning {{ color: #ff9800; font-weight: bold; }}
        .log-critical {{ color: #f44336; font-weight: bold; }}
        .total-excellent {{ color: #76b900; font-weight: bold; }}
        .total-good {{ color: #8bc34a; font-weight: bold; }}
        .total-warning {{ color: #ff9800; font-weight: bold; }}
        .total-critical {{ color: #f44336; font-weight: bold; }}
        .log-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .log-table th, .log-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; word-wrap: break-word; }}
        .log-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .log-table tbody tr {{ background: #252526; }}
        .log-table tbody tr:hover {{ background: #2d2d2d; }}
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
        .severity-count {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; cursor: pointer; transition: all 0.2s ease; min-width: 30px; text-align: center; font-size: 12px; }}
        .severity-count:hover {{ transform: scale(1.05); }}
        .severity-count.critical {{ background: rgba(244, 67, 54, 0.2); color: #f44336; border: 1px solid #f44336; }}
        .severity-count.warning {{ background: rgba(255, 152, 0, 0.2); color: #ff9800; border: 1px solid #ff9800; }}
        .severity-count.error {{ background: rgba(255, 152, 0, 0.2); color: #ff9800; border: 1px solid #ff9800; }}
        .severity-count.info {{ background: rgba(79, 195, 247, 0.2); color: #4fc3f7; border: 1px solid #4fc3f7; }}
        .severity-count.zero {{ background: #333; color: #666; border: 1px solid #555; cursor: default; }}
        .log-details {{ display: none; background: #252526; border: 1px solid #404040; border-radius: 6px; margin: 10px 0; max-height: 400px; overflow-y: auto; }}
        .log-entry {{ padding: 10px 15px; border-bottom: 1px solid #404040; font-family: 'Courier New', monospace; font-size: 12px; color: #d4d4d4; }}
        .log-entry:last-child {{ border-bottom: none; }}
        .log-timestamp {{ color: #888; margin-right: 10px; }}
        .log-section {{ background: #3c3c3c; color: #d4d4d4; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 10px; }}
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
            <div class="page-title">Log Analysis Results</div>
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
            Log Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-devices-card">
                    <div class="metric" id="total-devices">{total_devices}</div>
                    <div class="metric-label">Total Devices</div>
                </div>
                <div class="summary-card card-critical" id="critical-card">
                    <div class="metric log-critical" id="critical-logs">{totals['critical']}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="summary-card card-warning" id="warning-card">
                    <div class="metric log-warning" id="warning-logs">{totals['warning']}</div>
                    <div class="metric-label">Warning</div>
                </div>
                <div class="summary-card card-warning" id="error-card">
                    <div class="metric log-warning" id="error-logs">{totals['error']}</div>
                    <div class="metric-label">Error</div>
                </div>
                <div class="summary-card card-excellent" id="info-card">
                    <div class="metric log-good" id="info-logs">{totals['info']}</div>
                    <div class="metric-label">Info</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Device Log Details
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="log-table" id="log-table">
                <thead>
                    <tr>
                        <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="1" data-type="number">Critical <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="2" data-type="number">Warning <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="3" data-type="number">Error <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="4" data-type="number">Info <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="5" data-type="number">Total <span class="sort-arrow">▲▼</span></th>
                    </tr>
                </thead>
                <tbody>"""
        
        # Sort devices by total log count (descending)
        sorted_devices = sorted(self.log_counts.items(), 
                              key=lambda x: sum(x[1].values()), reverse=True)
        
        for device_name, counts in sorted_devices:
            total_count = sum(counts.values())
            
            # Color code total count like other analysis pages
            if total_count == 0:
                total_class = "total-excellent"
            elif total_count <= 50:
                total_class = "total-good" 
            elif total_count <= 100:
                total_class = "total-warning"
            else:
                total_class = "total-critical"
            
            html_content += f"""
                    <tr>
                        <td>{canonical(device_name)}</td>
                        <td>
                            <span class="severity-count critical {'zero' if counts['critical'] == 0 else ''}" 
                                  data-device="{device_name}" data-severity="critical"
                                  id="critical-{device_name}">
                                {counts['critical']}
                            </span>
                        </td>
                        <td>
                            <span class="severity-count warning {'zero' if counts['warning'] == 0 else ''}" 
                                  data-device="{device_name}" data-severity="warning"
                                  id="warning-{device_name}">
                                {counts['warning']}
                            </span>
                        </td>
                        <td>
                            <span class="severity-count error {'zero' if counts['error'] == 0 else ''}" 
                                  data-device="{device_name}" data-severity="error"
                                  id="error-{device_name}">
                                {counts['error']}
                            </span>
                        </td>
                        <td>
                            <span class="severity-count info {'zero' if counts['info'] == 0 else ''}" 
                                  data-device="{device_name}" data-severity="info"
                                  id="info-{device_name}">
                                {counts['info']}
                            </span>
                        </td>
                        <td><span class="{total_class}">{total_count}</span></td>
                    </tr>
                    <tr id="details-{device_name}-critical" class="log-details">
                        <td colspan="6">
                            <div id="content-{device_name}-critical"></div>
                        </td>
                    </tr>
                    <tr id="details-{device_name}-warning" class="log-details">
                        <td colspan="6">
                            <div id="content-{device_name}-warning"></div>
                        </td>
                    </tr>
                    <tr id="details-{device_name}-error" class="log-details">
                        <td colspan="6">
                            <div id="content-{device_name}-error"></div>
                        </td>
                    </tr>
                    <tr id="details-{device_name}-info" class="log-details">
                        <td colspan="6">
                            <div id="content-{device_name}-info"></div>
                        </td>
                    </tr>"""
        
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- jQuery and Select2 for device search -->
    <script src="/css/jquery-3.5.1.min.js"></script>
    <script src="/css/select2.min.js"></script>
    
    <script>
        // Log data embedded in the page
        const logData = """ + json.dumps(dict(self.log_analysis), indent=2) + """;
        
        // Initialize page functionality
        let deviceSearchActive = false;
        let selectedDevice = '';
        
        document.addEventListener('DOMContentLoaded', function() {
            initSummaryCardFilters();
            initTableSorting();
            initLogDetailsClickHandlers();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });
        
        function initLogDetailsClickHandlers() {
            // Event delegation for severity count clicks (survives table sorting)
            const table = document.getElementById('log-table');
            table.addEventListener('click', function(event) {
                if (event.target.classList.contains('severity-count') && !event.target.classList.contains('zero')) {
                    const deviceName = event.target.getAttribute('data-device');
                    const severity = event.target.getAttribute('data-severity');
                    if (deviceName && severity) {
                        toggleLogDetails(deviceName, severity);
                    }
                }
            });
        }
        
        function initSummaryCardFilters() {
            // Add click handlers to summary cards
            document.getElementById('total-devices-card').addEventListener('click', () => clearFilter());
            document.getElementById('critical-card').addEventListener('click', () => filterTable('critical'));
            document.getElementById('warning-card').addEventListener('click', () => filterTable('warning'));  
            document.getElementById('error-card').addEventListener('click', () => filterTable('error'));
            document.getElementById('info-card').addEventListener('click', () => filterTable('info'));
        }
        
        function filterTable(severity) {
            const table = document.querySelector('.log-table');
            const rows = table.querySelectorAll('tbody tr');
            const filterInfo = document.getElementById('filter-info');
            const filterText = document.getElementById('filter-text');
            
            // Clear device search when using card filters
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Remove active class from all cards
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            // Add active class to clicked card
            document.getElementById(severity + '-card').classList.add('active');
            
            let visibleCount = 0;
            
            // Filter table rows
            rows.forEach(row => {
                if (row.classList.contains('log-details')) {
                    row.style.display = 'none';
                    return;
                }
                
                const severityCell = getSeverityCellValue(row, severity);
                
                if (severityCell > 0) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show filter info
            const severityLabels = {
                'critical': 'Critical Issues',
                'warning': 'Warning Messages', 
                'error': 'Error Messages',
                'info': 'Info Messages'
            };
            
            filterText.textContent = `Showing ${visibleCount} devices with ${severityLabels[severity]}`;
            filterInfo.style.display = 'block';
        }
        
        function getSeverityCellValue(row, severity) {
            const severityMap = {
                'critical': 1, // Column index for Critical
                'warning': 2,  // Column index for Warning  
                'error': 3,    // Column index for Error
                'info': 4      // Column index for Info
            };
            
            const cellIndex = severityMap[severity];
            if (!cellIndex) return 0;
            
            const cell = row.cells[cellIndex];
            if (!cell) return 0;
            
            const countElement = cell.querySelector('.severity-count');
            if (!countElement) return 0;
            
            return parseInt(countElement.textContent) || 0;
        }
        
        function clearFilter() {
            const table = document.querySelector('.log-table');
            const allRows = table.querySelectorAll('tbody tr');
            const filterInfo = document.getElementById('filter-info');
            
            // Also clear device search
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Remove active class from all cards
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            // Add active class to total card
            document.getElementById('total-devices-card').classList.add('active');
            
            // Hide filter info
            filterInfo.style.display = 'none';
            
            // Show all rows (except detail rows)
            allRows.forEach(row => {
                if (row.classList.contains('log-details')) {
                    row.style.display = 'none';
                } else {
                    row.style.display = '';
                }
            });
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
            const table = document.querySelector('.log-table');
            const rows = table.querySelectorAll('tbody tr');
            const deviceSet = new Set();
            
            rows.forEach(row => {
                if (!row.classList.contains('log-details')) {
                    const deviceName = row.cells[0]?.textContent?.trim();
                    if (deviceName) deviceSet.add(deviceName);
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
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            const table = document.querySelector('.log-table');
            const rows = table.querySelectorAll('tbody tr');
            const filterInfo = document.getElementById('filter-info');
            const filterText = document.getElementById('filter-text');
            
            // Filter table rows
            let matchCount = 0;
            rows.forEach(row => {
                if (row.classList.contains('log-details')) {
                    row.style.display = 'none';
                    return;
                }
                
                const rowDeviceName = row.cells[0]?.textContent?.trim();
                if (rowDeviceName === deviceName) {
                    row.style.display = '';
                    matchCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show filter info
            filterText.textContent = 'Showing logs for device: ' + deviceName;
            filterInfo.style.display = 'block';
            document.getElementById('clearSearchBtn').style.display = 'inline-block';
        }
        
        function clearDeviceSearch() {
            selectedDevice = '';
            deviceSearchActive = false;
            $('#deviceSearch').val('').trigger('change');
            document.getElementById('clearSearchBtn').style.display = 'none';
            
            const table = document.querySelector('.log-table');
            const allRows = table.querySelectorAll('tbody tr');
            const filterInfo = document.getElementById('filter-info');
            
            filterInfo.style.display = 'none';
            allRows.forEach(row => {
                if (row.classList.contains('log-details')) {
                    row.style.display = 'none';
                } else {
                    row.style.display = '';
                }
            });
        }
        
        function toggleLogDetails(deviceName, severity) {
            const detailsRow = document.getElementById(`details-${deviceName}-${severity}`);
            const contentDiv = document.getElementById(`content-${deviceName}-${severity}`);
            
            // Check if elements exist (should always exist now)
            if (!detailsRow || !contentDiv) {
                return;
            }
            
            // Hide all other details first
            document.querySelectorAll('.log-details').forEach(row => {
                if (row.id !== `details-${deviceName}-${severity}`) {
                    row.style.display = 'none';
                }
            });
            
            if (detailsRow.style.display === 'table-row') {
                detailsRow.style.display = 'none';
                return;
            }
            
            // Check if logs exist for this severity
            const logs = logData[deviceName] && logData[deviceName][severity];
            if (!logs || logs.length === 0) {
                return; // Don't show anything for zero counts
            }
            
            // Populate content if not already done
            if (contentDiv.innerHTML === '') {
                contentDiv.innerHTML = logs.map(log => `
                    <div class="log-entry">
                        ${log.timestamp ? `<span class="log-timestamp">${log.timestamp}</span>` : ''}
                        <span class="log-section">${log.section}</span>
                        <span class="log-message">${log.message}</span>
                    </div>
                `).join('');
            }
            
            detailsRow.style.display = 'table-row';
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
                    sortLogTable(column, tableSortState.direction, type);
                });
            });
        }
        
        function sortLogTable(columnIndex, direction, type) {
            const table = document.getElementById('log-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows).filter(row => !row.classList.contains('log-details'));
            
            rows.sort((a, b) => {
                let aVal, bVal;
                
                if (type === 'number' && columnIndex > 0) {
                    // For severity count columns, try to get number from span first, then fallback to direct text
                    const aSpan = a.cells[columnIndex].querySelector('.severity-count');
                    const bSpan = b.cells[columnIndex].querySelector('.severity-count');
                    
                    if (aSpan && bSpan) {
                        // Severity columns with spans
                        aVal = parseInt(aSpan.textContent) || 0;
                        bVal = parseInt(bSpan.textContent) || 0;
                    } else {
                        // Total column (direct text content)
                        aVal = parseInt(a.cells[columnIndex].textContent.trim()) || 0;
                        bVal = parseInt(b.cells[columnIndex].textContent.trim()) || 0;
                    }
                } else {
                    // For device names and other text
                    aVal = a.cells[columnIndex].textContent.trim();
                    bVal = b.cells[columnIndex].textContent.trim();
                }
                
                let result = 0;
                
                switch(type) {
                    case 'number':
                        result = aVal - bVal;
                        break;
                    case 'string':
                    default:
                        result = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });
                        break;
                }
                
                return direction === 'desc' ? -result : result;
            });
            
            // DIFFERENT APPROACH: Move existing DOM nodes instead of destroying them
            rows.forEach((row, index) => {
                const deviceName = row.cells[0].textContent.trim();
                
                // Move the device row to its new position
                tbody.appendChild(row);
                
                // Move the associated log-details rows right after the device row
                const logDetailsRows = Array.from(tbody.querySelectorAll('.log-details')).filter(
                    detailRow => detailRow.id.includes(deviceName)
                );
                logDetailsRows.forEach(detailRow => tbody.appendChild(detailRow));
            });
        }
        
        // reattachClickHandlers function removed - no longer needed since we don't destroy DOM nodes
        
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
                    console.log('Monitor analysis triggered successfully');
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
                        <strong>Monitor Analysis Started</strong><br>
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
                const filename = `Log_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Create CSV header
                const headers = [
                    'Device',
                    'Critical',
                    'Warning',
                    'Error',
                    'Info',
                    'Total'
                ];
                
                let csvContent = headers.join(',') + '\\n';
                
                // Get table data (only visible rows)
                const table = document.getElementById('log-table');
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');
                
                // Add summary stats as comments
                csvContent += `# Log Analysis Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Devices: ${document.getElementById('total-devices').textContent}\\n`;
                csvContent += `# Critical Issues: ${document.getElementById('critical-logs').textContent}\\n`;
                csvContent += `# Warning Messages: ${document.getElementById('warning-logs').textContent}\\n`;
                csvContent += `# Error Messages: ${document.getElementById('error-logs').textContent}\\n`;
                csvContent += `# Info Messages: ${document.getElementById('info-logs').textContent}\\n`;
                csvContent += `#\\n`;
                
                // Process each visible row (skip log-details rows)
                rows.forEach(row => {
                    if (row.style.display !== 'none' && !row.classList.contains('log-details')) {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 6) {
                            const rowData = [
                                cells[0].textContent.trim(), // Device
                                cells[1].querySelector('.severity-count') ? cells[1].querySelector('.severity-count').textContent.trim() : '0', // Critical
                                cells[2].querySelector('.severity-count') ? cells[2].querySelector('.severity-count').textContent.trim() : '0', // Warning
                                cells[3].querySelector('.severity-count') ? cells[3].querySelector('.severity-count').textContent.trim() : '0', // Error
                                cells[4].querySelector('.severity-count') ? cells[4].querySelector('.severity-count').textContent.trim() : '0', // Info
                                cells[5].textContent.trim()  // Total
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
                
                console.log(`CSV downloaded: ${filename}`);
                
            } catch (error) {
                console.error('❌ Error generating CSV:', error);
                alert('Error generating CSV file. Please try again.');
            }
        }
    </script>
    <script src="/p2p-alias.js"></script>
    <script src="/css/analysis-guard.js"></script>
</body>
</html>"""
        
        # Write HTML file
        output_file = os.path.join(self.data_dir, "log-analysis.html")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Log analysis HTML generated: {output_file}")
    
    def save_summary_data(self):
        """Save summary data for dashboard and AI integration"""
        recent_messages = {}
        for device, categories in self.log_analysis.items():
            msgs = []
            for entry in categories.get("critical", [])[-20:]:
                text = entry.get('message', str(entry)) if isinstance(entry, dict) else str(entry)
                msgs.append(f"[CRITICAL] {text[:200]}")
            for entry in categories.get("error", [])[-10:]:
                text = entry.get('message', str(entry)) if isinstance(entry, dict) else str(entry)
                msgs.append(f"[ERROR] {text[:200]}")
            if msgs:
                recent_messages[device] = msgs
        
        summary_data = {
            "timestamp": datetime.now().isoformat(),
            "total_devices": len(self.log_counts),
            "totals": {
                "critical": sum(device["critical"] for device in self.log_counts.values()),
                "warning": sum(device["warning"] for device in self.log_counts.values()),
                "error": sum(device["error"] for device in self.log_counts.values()),
                "info": sum(device["info"] for device in self.log_counts.values())
            },
            "device_counts": dict(self.log_counts),
            "recent_messages": recent_messages
        }
        
        summary_file = os.path.join(self.data_dir, "log_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        print(f"Log summary data saved: {summary_file}")
    
    def run_analysis(self):
        """Main analysis function"""
        print("Starting log analysis...")
        
        if not os.path.exists(self.log_data_dir):
            print(f"❌ Log data directory not found: {self.log_data_dir}")
            return False
        
        # Process all log files
        log_files = [f for f in os.listdir(self.log_data_dir) if f.endswith('_logs.txt')]
        
        if not log_files:
            print("⚠️  No log files found")
            return False
        
        for log_file in log_files:
            device_name = log_file.replace('_logs.txt', '')
            log_file_path = os.path.join(self.log_data_dir, log_file)
            
            # Ensure device is initialized in counts (even if no logs)
            if device_name not in self.log_counts:
                self.log_counts[device_name] = {"critical": 0, "warning": 0, "error": 0, "info": 0}
                self.log_analysis[device_name] = {"critical": [], "warning": [], "error": [], "info": []}
            
            self.process_device_logs(device_name, log_file_path)
        
        print(f"Processed {len(log_files)} devices")
        
        # Generate outputs
        self.generate_html_report()
        self.save_summary_data()
        
        # Print summary
        total_logs = sum(sum(device.values()) for device in self.log_counts.values())
        total_critical = sum(device["critical"] for device in self.log_counts.values())
        total_warning = sum(device["warning"] for device in self.log_counts.values())
        
        print(f"Analysis complete:")
        print(f"   • Total devices: {len(self.log_counts)}")
        print(f"   • Total log entries: {total_logs}")
        print(f"   • Critical issues: {total_critical}")
        print(f"   • Warnings: {total_warning}")
        
        return True

def main():
    """Main entry point"""
    try:
        analyzer = LogAnalyzer()
        success = analyzer.run_analysis()
        return 0 if success else 1
    except Exception as e:
        print(f"❌ Log analysis failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())