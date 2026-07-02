#!/usr/bin/env python3
"""
BGP Neighbor Health Analyzer for LLDPq Enhanced Monitoring

Analyzes BGP neighbor status, detects problems, and provides insights

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, NamedTuple
from dataclasses import dataclass

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

class BGPState(Enum):
    """BGP neighbor states"""
    ESTABLISHED = "established"
    IDLE = "idle"
    ACTIVE = "active"
    CONNECT = "connect"
    OPENSENT = "opensent"
    OPENCONFIRM = "openconfirm"
    UNKNOWN = "unknown"

class BGPHealth(Enum):
    """BGP neighbor health levels"""
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


def coerce_bgp_state(value: Any) -> BGPState:
    """Normalize serialized/current BGP states without guessing established."""
    if isinstance(value, BGPState):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower().replace("_", "")
        if normalized.startswith("bgpstate."):
            normalized = normalized.split(".", 1)[1]
        try:
            return BGPState(normalized)
        except ValueError:
            pass
    return BGPState.UNKNOWN

def get_enum_value(obj):
    """Safely get value from enum or return string as-is"""
    if hasattr(obj, 'value'):
        return obj.value
    return str(obj)

@dataclass
class BGPNeighbor:
    """BGP neighbor information"""
    hostname: str
    neighbor_name: str
    neighbor_ip: str
    version: int
    asn: int
    messages_received: int
    messages_sent: int
    table_version: int
    in_queue: int
    out_queue: int
    uptime: str
    state: BGPState
    prefixes_received: int
    prefixes_sent: int
    description: str
    interface: Optional[str] = None

@dataclass
class EVPNStats:
    """EVPN statistics for a device"""
    hostname: str
    total_vnis: int = 0
    l2_vnis: int = 0
    l3_vnis: int = 0
    type2_routes: int = 0  # MAC/IP routes
    type5_routes: int = 0  # IP prefix routes
    vni_details: List[Dict] = None
    
    def __post_init__(self):
        if self.vni_details is None:
            self.vni_details = []


class BGPAnalyzer:
    """BGP neighbor health and status analyzer"""
    
    # BGP health thresholds
    DEFAULT_THRESHOLDS = {
        "critical_down_hours": 1.0,        # Critical if down > 1 hour
        "warning_down_minutes": 30,        # Warning if down > 30 minutes
        "high_queue_threshold": 10,        # Warning if queue > 10
        "low_prefix_threshold": 1,         # Warning if prefixes < 1
        "uptime_stability_days": 1,        # Expect > 1 day uptime for good health
        "message_ratio_threshold": 0.8,    # Warning if sent/received ratio < 0.8
        "history_retention_hours": 24       # Keep 24 hours of historical data
    }
    
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.bgp_history = {}  # hostname -> BGP historical data
        self.current_bgp_stats = {}  # hostname -> current BGP neighbors
        self.current_evpn_stats = {}  # hostname -> EVPN statistics
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        
        # Ensure bgp-data and evpn-data directories exist
        os.makedirs(f"{self.data_dir}/bgp-data", exist_ok=True)
        os.makedirs(f"{self.data_dir}/evpn-data", exist_ok=True)
        
        # Load historical data
        self.load_bgp_history()
    
    def load_bgp_history(self):
        """Load historical BGP data"""
        try:
            with open(f"{self.data_dir}/bgp_history.json", "r") as f:
                data = json.load(f)
                self.bgp_history = data.get("bgp_history", {})
                self.current_bgp_stats = data.get("current_bgp_stats", {})
                
                # Clean old data (older than retention period)
                self.cleanup_old_history()
        except (FileNotFoundError, json.JSONDecodeError):
            print("No previous BGP history found, starting fresh")
    
    def save_bgp_history(self):
        """Save BGP history to file"""
        try:
            data = {
                "bgp_history": self.bgp_history,
                "current_bgp_stats": self.current_bgp_stats,
                "last_update": time.time()
            }
            with open(f"{self.data_dir}/bgp_history.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving BGP history: {e}")
    
    def cleanup_old_history(self):
        """Remove history entries older than retention period"""
        current_time = time.time()
        retention_seconds = self.thresholds["history_retention_hours"] * 3600
        
        for hostname in list(self.bgp_history.keys()):
            if hostname in self.bgp_history:
                filtered_entries = []
                for entry in self.bgp_history[hostname]:
                    timestamp = entry.get('timestamp', 0)
                    
                    # Handle different timestamp formats
                    try:
                        if isinstance(timestamp, str):
                            # Parse ISO format: '2025-08-01T03:26:51.970342'
                            if 'T' in timestamp:
                                entry_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                            else:
                                entry_time = float(timestamp)
                        else:
                            entry_time = float(timestamp)
                        
                        if current_time - entry_time <= retention_seconds:
                            filtered_entries.append(entry)
                    except (ValueError, TypeError):
                        # Skip entries with invalid timestamps
                        continue
                
                self.bgp_history[hostname] = filtered_entries
                
                # Remove hostname if no history left
                if not self.bgp_history[hostname]:
                    del self.bgp_history[hostname]
    
    def parse_bgp_output(self, bgp_data: str) -> List[BGPNeighbor]:
        """Parse BGP neighbor output from vtysh command"""
        neighbors = []
        neighbor_dict = {}  # Track unique neighbors by IP, keep last seen
        
        lines = bgp_data.strip().split('\n')
        current_vrf = "default"
        local_asn = None
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Extract VRF information
            vrf_match = re.search(r'Summary \(VRF\s+([^\)]+)\)', line)
            if vrf_match:
                current_vrf = vrf_match.group(1)
                continue
            
            # Extract local AS number
            asn_match = re.search(r'local AS number (\d+)', line)
            if asn_match:
                local_asn = int(asn_match.group(1))
                continue
            
            # Parse neighbor entries (skip header lines)
            if re.match(r'^[A-Za-z0-9._-]+.*\s+\d+\s+\d+\s+\d+\s+\d+', line):
                parts = line.split()
                if len(parts) >= 10:

                    try:
                        neighbor_name = parts[0]
                        version = int(parts[1])
                        neighbor_asn = int(parts[2])
                        msg_rcvd = int(parts[3])
                        msg_sent = int(parts[4])
                        tbl_ver = int(parts[5])
                        in_q = int(parts[6])
                        out_q = int(parts[7])
                        uptime = parts[8]
                        
                        # Parse state and prefix count
                        state_pfx = parts[9] if len(parts) > 9 else "Unknown"
                        pfx_sent = int(parts[10]) if len(parts) > 10 else 0
                        description = parts[11] if len(parts) > 11 else "N/A"
                        
                        # Determine state and prefix count
                        try:
                            pfx_rcvd = int(state_pfx)
                            state = BGPState.ESTABLISHED
                        except ValueError:
                            state = coerce_bgp_state(state_pfx)
                            pfx_rcvd = 0
                        
                        # Extract interface from neighbor name if present
                        interface = None
                        interface_match = re.search(r'\(([^)]+)\)', neighbor_name)
                        if interface_match:
                            interface = interface_match.group(1)
                            neighbor_ip = neighbor_name.split('(')[0]
                        else:
                            neighbor_ip = neighbor_name
                        
                        # Store neighbor (overwrite if duplicate IP found - keep last seen)
                        neighbor = BGPNeighbor(
                            hostname="",  # Will be set by caller
                            neighbor_name=neighbor_name,
                            neighbor_ip=neighbor_ip,
                            version=version,
                            asn=neighbor_asn,
                            messages_received=msg_rcvd,
                            messages_sent=msg_sent,
                            table_version=tbl_ver,
                            in_queue=in_q,
                            out_queue=out_q,
                            uptime=uptime,
                            state=state,
                            prefixes_received=pfx_rcvd,
                            prefixes_sent=pfx_sent,
                            description=description,
                            interface=interface
                        )
                        
                        # Use neighbor IP as unique key, overwrite duplicates
                        neighbor_dict[neighbor_name] = neighbor
                        
                    except (ValueError, IndexError) as e:
                        print(f"Error parsing BGP neighbor line: {line}, Error: {e}")
                        continue
        
        # Return unique neighbors (duplicates by IP are filtered out)
        return list(neighbor_dict.values())
    
    def assess_neighbor_health(self, neighbor: BGPNeighbor) -> BGPHealth:
        """Assess health of a BGP neighbor"""
        
        # Critical: Neighbor in Idle, Active, or Connect state
        if neighbor.state in [BGPState.IDLE, BGPState.ACTIVE, BGPState.CONNECT]:
            return BGPHealth.CRITICAL
        
        # Unknown state
        if neighbor.state == BGPState.UNKNOWN:
            return BGPHealth.UNKNOWN
        
        # For established neighbors, check other metrics
        if neighbor.state == BGPState.ESTABLISHED:
            issues = 0
            
            # Check queue depths
            if neighbor.in_queue > self.thresholds["high_queue_threshold"] or \
               neighbor.out_queue > self.thresholds["high_queue_threshold"]:
                issues += 1
            
            # Check prefix counts
            if neighbor.prefixes_received < self.thresholds["low_prefix_threshold"]:
                issues += 1
            
            # Check message ratio (basic health indicator)
            if neighbor.messages_sent > 0 and neighbor.messages_received > 0:
                ratio = min(neighbor.messages_sent, neighbor.messages_received) / \
                       max(neighbor.messages_sent, neighbor.messages_received)
                if ratio < self.thresholds["message_ratio_threshold"]:
                    issues += 1
            
            # Determine health based on issues
            if issues == 0:
                return BGPHealth.EXCELLENT
            elif issues == 1:
                return BGPHealth.GOOD
            else:
                return BGPHealth.WARNING
        
        # Other connecting states
        return BGPHealth.WARNING
    
    def parse_uptime(self, uptime_str: str) -> Optional[timedelta]:
        """Parse BGP uptime string to timedelta"""
        try:
            # Handle different uptime formats: "1d23h", "23:45:12", "never"
            if uptime_str.lower() == "never":
                return timedelta(0)
            
            # Format: "01w2d22h" 
            if 'w' in uptime_str or 'd' in uptime_str or 'h' in uptime_str:
                total_seconds = 0
                
                # Extract weeks
                week_match = re.search(r'(\d+)w', uptime_str)
                if week_match:
                    total_seconds += int(week_match.group(1)) * 7 * 24 * 3600
                
                # Extract days
                day_match = re.search(r'(\d+)d', uptime_str)
                if day_match:
                    total_seconds += int(day_match.group(1)) * 24 * 3600
                
                # Extract hours
                hour_match = re.search(r'(\d+)h', uptime_str)
                if hour_match:
                    total_seconds += int(hour_match.group(1)) * 3600
                
                # Extract minutes
                min_match = re.search(r'(\d+)m', uptime_str)
                if min_match:
                    total_seconds += int(min_match.group(1)) * 60
                
                return timedelta(seconds=total_seconds)
            
            # Format: "23:45:12"
            if ':' in uptime_str:
                time_parts = uptime_str.split(':')
                if len(time_parts) == 3:
                    hours = int(time_parts[0])
                    minutes = int(time_parts[1])
                    seconds = int(time_parts[2])
                    return timedelta(hours=hours, minutes=minutes, seconds=seconds)
            
            return None
            
        except Exception:
            return None
    
    def update_bgp_stats(self, hostname: str, bgp_data: str):
        """Update BGP statistics for a device"""
        neighbors = self.parse_bgp_output(bgp_data)
        
        # Set hostname for all neighbors
        for neighbor in neighbors:
            neighbor.hostname = hostname
        
        # Update current stats (convert enums to strings for JSON serialization)
        neighbor_dicts = []
        for neighbor in neighbors:
            neighbor_dict = neighbor.__dict__.copy()
            neighbor_dict['state'] = get_enum_value(neighbor.state)
            neighbor_dicts.append(neighbor_dict)
        
        self.current_bgp_stats[hostname] = {
            "neighbors": neighbor_dicts,
            "total_neighbors": len(neighbors),
            "established_neighbors": len([n for n in neighbors if n.state == BGPState.ESTABLISHED]),
            "down_neighbors": len([n for n in neighbors if n.state != BGPState.ESTABLISHED]),
            "last_update": datetime.now().isoformat()
        }
        
        # Add to history (keep last 50 entries per device)
        if hostname not in self.bgp_history:
            self.bgp_history[hostname] = []
        
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "total_neighbors": len(neighbors),
            "established_count": len([n for n in neighbors if n.state == BGPState.ESTABLISHED]),
            "down_count": len([n for n in neighbors if n.state != BGPState.ESTABLISHED]),
            "neighbors": neighbor_dicts  # Use the same serialized data
        }
        
        self.bgp_history[hostname].append(history_entry)
        
        # Keep only last 50 entries
        if len(self.bgp_history[hostname]) > 50:
            self.bgp_history[hostname] = self.bgp_history[hostname][-50:]
    
    def parse_evpn_output(self, evpn_data: str) -> EVPNStats:
        """Parse EVPN data output from vtysh commands"""
        stats = EVPNStats(hostname="")
        
        lines = evpn_data.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Detect section markers
            if "=== EVPN VNI SUMMARY ===" in line:
                current_section = "vni_summary"
                continue
            elif "=== EVPN ROUTE COUNTS ===" in line:
                current_section = "route_counts"
                continue
            elif "=== EVPN TYPE COUNTS ===" in line:
                current_section = "type_counts"
                continue
            
            # Parse VNI summary section
            # Format: VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF      VLAN       BRIDGE
            #         300242     L2   vxlan48               0        0        1               default         0          br_default
            #         2303002    L3   vxlan99               7        7        n/a             compute         3702       br_l3vni
            if current_section == "vni_summary":
                # Match VNI lines (starts with number) - Remote VTEPs can be number or n/a
                vni_match = re.match(r'^(\d+)\s+(L2|L3)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)', line)
                if vni_match:
                    vni_type = vni_match.group(2)
                    if vni_type == "L2":
                        stats.l2_vnis += 1
                    else:
                        stats.l3_vnis += 1
                    stats.total_vnis += 1
                    
                    # Parse remote_vteps - handle n/a
                    remote_vteps_str = vni_match.group(6)
                    remote_vteps = int(remote_vteps_str) if remote_vteps_str.isdigit() else 0
                    
                    stats.vni_details.append({
                        'vni': int(vni_match.group(1)),
                        'type': vni_type,
                        'interface': vni_match.group(3),
                        'macs': int(vni_match.group(4)),
                        'arps': int(vni_match.group(5)),
                        'remote_vteps': remote_vteps,
                        'vrf': vni_match.group(7) or 'default'
                    })
            
            # Parse type counts section
            # Routes format: " *> [2]:[0]:[48]:[...]" or " *  [5]:[0]:[...]"
            # Lines start with whitespace, then * or >, then route type [N]:
            if current_section == "type_counts":
                # Count Type-2 (MAC/IP) routes - lines with [2]:
                if '[2]:' in line:
                    stats.type2_routes += 1
                # Count Type-5 (IP prefix) routes - lines with [5]:
                elif '[5]:' in line:
                    stats.type5_routes += 1
        
        return stats
    
    def update_evpn_stats(self, hostname: str, evpn_data: str):
        """Update EVPN statistics for a device"""
        stats = self.parse_evpn_output(evpn_data)
        stats.hostname = hostname
        
        self.current_evpn_stats[hostname] = {
            "total_vnis": stats.total_vnis,
            "l2_vnis": stats.l2_vnis,
            "l3_vnis": stats.l3_vnis,
            "type2_routes": stats.type2_routes,
            "type5_routes": stats.type5_routes,
            "vni_details": stats.vni_details,
            "last_update": datetime.now().isoformat()
        }
    
    def get_evpn_summary(self) -> Dict[str, Any]:
        """Get network-wide EVPN summary"""
        total_devices = len(self.current_evpn_stats)
        total_vnis = sum(s.get("total_vnis", 0) for s in self.current_evpn_stats.values())
        total_l2_vnis = sum(s.get("l2_vnis", 0) for s in self.current_evpn_stats.values())
        total_l3_vnis = sum(s.get("l3_vnis", 0) for s in self.current_evpn_stats.values())
        total_type2 = sum(s.get("type2_routes", 0) for s in self.current_evpn_stats.values())
        total_type5 = sum(s.get("type5_routes", 0) for s in self.current_evpn_stats.values())
        
        return {
            "total_devices": total_devices,
            "total_vnis": total_vnis,
            "l2_vnis": total_l2_vnis,
            "l3_vnis": total_l3_vnis,
            "type2_routes": total_type2,
            "type5_routes": total_type5,
            "per_device": self.current_evpn_stats,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_bgp_summary(self) -> Dict[str, Any]:
        """Get network-wide BGP summary"""
        total_devices = len(self.current_bgp_stats)
        total_neighbors = sum(stats["total_neighbors"] for stats in self.current_bgp_stats.values())
        total_established = sum(stats["established_neighbors"] for stats in self.current_bgp_stats.values())
        total_down = sum(stats["down_neighbors"] for stats in self.current_bgp_stats.values())
        stale_devices = sum(
            1 for stats in self.current_bgp_stats.values()
            if stats.get("data_status") == "stale"
        )
        unknown_devices = sum(
            1 for stats in self.current_bgp_stats.values()
            if stats.get("data_status") == "unknown"
        )
        
        # Get problem neighbors
        problem_neighbors = []
        for hostname, stats in self.current_bgp_stats.items():
            for neighbor_data in stats["neighbors"]:
                # Handle both enum and string state values
                neighbor_dict = neighbor_data.copy()
                neighbor_dict['state'] = coerce_bgp_state(neighbor_dict.get('state'))
                
                neighbor = BGPNeighbor(**neighbor_dict)
                health = self.assess_neighbor_health(neighbor)
                if health in [BGPHealth.CRITICAL, BGPHealth.WARNING]:
                    problem_neighbors.append({
                        "hostname": hostname,
                        "neighbor": neighbor.neighbor_name,
                        "state": get_enum_value(neighbor.state),
                        "health": get_enum_value(health),
                        "uptime": neighbor.uptime
                    })
        
        return {
            "total_devices": total_devices,
            "total_neighbors": total_neighbors,
            "established_neighbors": total_established,
            "down_neighbors": total_down,
            "stale_devices": stale_devices,
            "unknown_devices": unknown_devices,
            "problem_neighbors": problem_neighbors,
            "health_ratio": (total_established / total_neighbors * 100) if total_neighbors > 0 else 0,
            "timestamp": datetime.now().isoformat()
        }
    
    def detect_bgp_anomalies(self) -> List[Dict[str, Any]]:
        """Detect BGP anomalies and problems"""
        anomalies = []
        
        for hostname, stats in self.current_bgp_stats.items():
            data_status = stats.get("data_status")
            if data_status in {"stale", "unknown"}:
                last_update = stats.get("last_update") or "never"
                anomalies.append({
                    "device": hostname,
                    "neighbor": "collection",
                    "type": "BGP_DATA_UNAVAILABLE",
                    "severity": "warning",
                    "message": (
                        f"BGP collection is {data_status}; "
                        f"last successful update: {last_update}"
                    ),
                    "details": {
                        "data_status": data_status,
                        "last_update": stats.get("last_update"),
                        "collection_error": stats.get("collection_error"),
                    },
                    "action": "Check device reachability and rerun BGP collection",
                })

            for neighbor_data in stats["neighbors"]:
                neighbor_dict = neighbor_data.copy()
                neighbor_dict['state'] = coerce_bgp_state(neighbor_dict.get('state'))
                neighbor = BGPNeighbor(**neighbor_dict)
                health = self.assess_neighbor_health(neighbor)
                
                # Critical: Down neighbors
                if neighbor.state in [BGPState.IDLE, BGPState.ACTIVE, BGPState.CONNECT]:
                    anomalies.append({
                        "device": hostname,
                        "neighbor": neighbor.neighbor_name,
                        "type": "BGP_NEIGHBOR_DOWN",
                        "severity": "critical",
                        "message": f"BGP neighbor {neighbor.neighbor_name} is in {get_enum_value(neighbor.state).upper()} state",
                        "details": {
                            "state": get_enum_value(neighbor.state),
                            "uptime": neighbor.uptime,
                            "asn": neighbor.asn,
                            "interface": neighbor.interface
                        },
                        "action": f"Check physical connectivity and BGP configuration for {neighbor.neighbor_name}"
                    })

                elif neighbor.state in [BGPState.OPENSENT, BGPState.OPENCONFIRM]:
                    anomalies.append({
                        "device": hostname,
                        "neighbor": neighbor.neighbor_name,
                        "type": "BGP_NEIGHBOR_NOT_ESTABLISHED",
                        "severity": "warning",
                        "message": f"BGP neighbor {neighbor.neighbor_name} is in {get_enum_value(neighbor.state).upper()} state",
                        "details": {
                            "state": get_enum_value(neighbor.state),
                            "uptime": neighbor.uptime,
                            "asn": neighbor.asn,
                            "interface": neighbor.interface
                        },
                        "action": f"Check BGP negotiation and authentication for {neighbor.neighbor_name}"
                    })
                
                # Warning: High queue depths
                elif neighbor.in_queue > self.thresholds["high_queue_threshold"] or \
                     neighbor.out_queue > self.thresholds["high_queue_threshold"]:
                    anomalies.append({
                        "device": hostname,
                        "neighbor": neighbor.neighbor_name,
                        "type": "BGP_HIGH_QUEUE",
                        "severity": "warning",
                        "message": f"High queue depth detected: InQ={neighbor.in_queue}, OutQ={neighbor.out_queue}",
                        "details": {
                            "in_queue": neighbor.in_queue,
                            "out_queue": neighbor.out_queue,
                            "state": get_enum_value(neighbor.state)
                        },
                        "action": "Monitor for potential congestion or processing delays"
                    })
                
                # Warning: Low prefix count
                elif neighbor.prefixes_received < self.thresholds["low_prefix_threshold"] and \
                     neighbor.state == BGPState.ESTABLISHED:
                    anomalies.append({
                        "device": hostname,
                        "neighbor": neighbor.neighbor_name,
                        "type": "BGP_LOW_PREFIXES",
                        "severity": "warning",
                        "message": f"Low prefix count: receiving only {neighbor.prefixes_received} prefixes",
                        "details": {
                            "prefixes_received": neighbor.prefixes_received,
                            "prefixes_sent": neighbor.prefixes_sent,
                            "state": get_enum_value(neighbor.state)
                        },
                        "action": "Verify route advertisements and filtering policies"
                    })
        
        return anomalies
    
    def export_bgp_data_for_web(self, output_file: str):
        """Export BGP data for web display"""
        summary = self.get_bgp_summary()
        evpn_summary = self.get_evpn_summary()
        anomalies = self.detect_bgp_anomalies()
        
        # Serialize EVPN per-device data for JavaScript
        evpn_per_device_json = json.dumps(evpn_summary.get('per_device', {}))
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BGP Neighbor Analysis</title>
    <link rel="shortcut icon" href="/png/favicon.ico">
    <link rel="stylesheet" type="text/css" href="/css/select2.min.css">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            min-height: 100vh;
        }}
        
        /* Page Header */
        .page-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #404040;
        }}
        .page-title {{ font-size: 24px; font-weight: 600; color: #76b900; }}
        .last-updated {{ font-size: 13px; color: #888; }}
        
        /* Dashboard Section */
        .dashboard-section {{
            background: #2d2d2d;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .section-header {{
            padding: 12px 16px;
            background: #333;
            font-weight: 600;
            font-size: 14px;
            color: #76b900;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 1px solid #404040;
        }}
        .section-content {{ padding: 16px; }}
        .section-content-table {{ padding: 0; }}
        
        /* Summary Grid */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
        }}
        .summary-card {{
            background: #252526;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #76b900;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .summary-card:hover {{ background: #2d2d2d; transform: translateY(-1px); }}
        .summary-card.active {{ background: #333; border-left-width: 5px; }}
        .evpn-clickable {{ cursor: pointer; }}
        .evpn-clickable:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.3); }}
        .card-excellent {{ border-left-color: #76b900; }}
        
        /* EVPN Modal */
        .evpn-modal {{
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(2px);
        }}
        .evpn-modal.show {{ display: flex; justify-content: center; align-items: center; }}
        .evpn-modal-content {{
            background: #2d2d2d;
            border-radius: 8px;
            width: 90%;
            max-width: 900px;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        .evpn-modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: #333;
            border-bottom: 1px solid #444;
        }}
        .evpn-modal-header h3 {{ margin: 0; color: #76b900; font-size: 16px; }}
        .evpn-modal-close {{
            background: none;
            border: none;
            color: #888;
            font-size: 24px;
            cursor: pointer;
            padding: 0 5px;
        }}
        .evpn-modal-close:hover {{ color: #fff; }}
        .evpn-modal-body {{
            padding: 0;
            overflow-y: auto;
            max-height: calc(80vh - 60px);
        }}
        .evpn-modal-body table {{
            margin: 0;
        }}
        .evpn-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .evpn-table th, .evpn-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #404040;
        }}
        .evpn-table th {{
            background: #333;
            color: #76b900;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        .evpn-table tr:hover {{ background: #353535; }}
        .evpn-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
        .evpn-badge-l2 {{ background: #9c27b0; color: #fff; }}
        .evpn-badge-l3 {{ background: #ff9800; color: #000; }}
        .card-critical {{ border-left-color: #f44336; }}
        .card-warning {{ border-left-color: #ff9800; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        
        /* BGP Status Colors */
        .bgp-excellent {{ color: #76b900; font-weight: bold; }}
        .bgp-good {{ color: #8bc34a; font-weight: bold; }}
        .bgp-warning {{ color: #ff9800; font-weight: bold; }}
        .bgp-critical {{ color: #f44336; font-weight: bold; }}
        .bgp-unknown {{ color: #888; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .badge-gray {{ background: rgba(158, 158, 158, 0.2); color: #999; }}
        .state-established {{ color: #76b900; font-weight: bold; }}
        .state-idle {{ color: #f44336; font-weight: bold; }}
        .state-active {{ color: #f44336; font-weight: bold; }}
        .state-connect {{ color: #f44336; font-weight: bold; }}
        
        /* Table Styling */
        .bgp-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .bgp-table th, .bgp-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; }}
        .bgp-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .bgp-table tbody tr {{ background: #252526; }}
        .bgp-table tbody tr:hover {{ background: #2d2d2d; }}
        
        /* Sortable */
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        
        /* Filter Info */
        .filter-info {{
            text-align: center;
            padding: 10px 15px;
            margin: 15px 16px;
            background: rgba(118, 185, 0, 0.1);
            border: 1px solid rgba(118, 185, 0, 0.3);
            border-radius: 6px;
            color: #76b900;
            display: none;
            font-size: 13px;
        }}
        .filter-info button {{
            margin-left: 10px;
            padding: 4px 10px;
            background: #76b900;
            color: #000;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}
        
        /* Anomaly Cards */
        .anomaly-card {{
            margin: 10px 0;
            padding: 12px 15px;
            background: #252526;
            border-radius: 6px;
            border-left: 3px solid #f44336;
        }}
        .anomaly-card.warning {{ border-left-color: #ff9800; }}
        .anomaly-card h4 {{ color: #d4d4d4; margin-bottom: 8px; font-size: 14px; }}
        .anomaly-card p {{ font-size: 13px; color: #888; margin: 4px 0; }}
        
        /* Buttons */
        .btn {{
            padding: 8px 14px;
            border: none;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .btn-primary {{ background: linear-gradient(0deg, #76b900 0%, #5a8c00 100%); color: white; }}
        .btn-primary:hover {{ background: linear-gradient(0deg, #8bd400 0%, #6ba000 100%); }}
        .btn-secondary {{ background: linear-gradient(0deg, #4fc3f7 0%, #0288d1 100%); color: white; }}
        .btn-secondary:hover {{ background: linear-gradient(0deg, #81d4fa 0%, #039be5 100%); }}
        .action-buttons {{ display: flex; gap: 10px; align-items: center; }}
        
        /* Device Search - Dark Theme */
        .device-search-container {{ display: flex; align-items: center; gap: 8px; }}
        .device-search-container .select2-container {{ min-width: 200px; }}
        .device-search-container .select2-container--default .select2-selection--single {{
            height: 34px; border: 1px solid #555; border-radius: 4px; background: #3c3c3c; display: flex; align-items: center;
        }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered {{
            line-height: 34px; color: #d4d4d4; padding-left: 10px; font-size: 13px;
        }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow {{ height: 34px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__placeholder {{ color: #888; }}
        .select2-dropdown {{ background: #2d2d2d; border: 1px solid #555; }}
        .select2-container--default .select2-search--dropdown .select2-search__field {{ background: #3c3c3c; border: 1px solid #555; color: #d4d4d4; }}
        .select2-container--default .select2-results__option {{ color: #d4d4d4; padding: 8px 12px; }}
        .select2-container--default .select2-results__option--highlighted[aria-selected] {{ background: #76b900; color: #000; }}
        .select2-container--default .select2-results__option[aria-selected=true] {{ background: #3c3c3c; }}
        .clear-search-btn {{ background: #f44336; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; display: none; }}
        .clear-search-btn:hover {{ background: #d32f2f; }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: #1e1e1e; }}
        ::-webkit-scrollbar-thumb {{ background: #404040; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #555; }}
        
        @keyframes spin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <!-- Page Header -->
    <div class="page-header">
        <div>
            <div class="page-title">BGP Neighbor Analysis</div>
            <div class="last-updated">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="action-buttons">
            <div class="device-search-container">
                <select id="deviceSearch" style="width: 200px;">
                    <option value="">Search Device...</option>
                </select>
                <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">✕</button>
            </div>
            <button id="thresholds-btn" onclick="openThresholdsModal()" class="btn btn-secondary" title="Thresholds &amp; grading reference">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
                Thresholds
            </button>
            <button id="run-analysis" onclick="runAnalysis()" class="btn btn-secondary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/>
                </svg>
                Run Analysis
            </button>
            <button id="download-csv" onclick="downloadCSV()" class="btn btn-primary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/>
                </svg>
                Download CSV
            </button>
        </div>
    </div>
    
    <!-- BGP Summary Section -->
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
            </svg>
            BGP Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-devices-card">
                    <div class="metric" id="total-devices">{summary['total_devices']}</div>
                    <div class="metric-label">BGP Devices</div>
                </div>
                <div class="summary-card card-info" id="total-neighbors-card">
                    <div class="metric" id="total-neighbors">{summary['total_neighbors']}</div>
                    <div class="metric-label">Total Neighbors</div>
                </div>
                <div class="summary-card card-excellent" id="established-card">
                    <div class="metric bgp-excellent" id="established-neighbors">{summary['established_neighbors']}</div>
                    <div class="metric-label">Established</div>
                </div>
                <div class="summary-card card-critical" id="down-card">
                    <div class="metric bgp-critical" id="down-neighbors">{summary['down_neighbors']}</div>
                    <div class="metric-label">Down/Problem</div>
                </div>
                <div class="summary-card card-warning" id="stale-devices-card">
                    <div class="metric bgp-warning" id="stale-devices">{summary['stale_devices']}</div>
                    <div class="metric-label">Stale Collections</div>
                </div>
                <div class="summary-card card-info" id="unknown-devices-card">
                    <div class="metric bgp-unknown" id="unknown-devices">{summary['unknown_devices']}</div>
                    <div class="metric-label">Unknown Collections</div>
                </div>
                <div class="summary-card" id="health-card">
                    <div class="metric" id="health-ratio">{summary['health_ratio']:.1f}%</div>
                    <div class="metric-label">Health Ratio</div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- EVPN Summary Section -->
    <div class="dashboard-section" id="evpn">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
            </svg>
            EVPN Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info evpn-clickable" onclick="showEvpnModal('all')" title="Click to see VNI details">
                    <div class="metric" id="evpn-total-vnis" style="color: #4fc3f7;">{evpn_summary['total_vnis']}</div>
                    <div class="metric-label">Total VNIs</div>
                </div>
                <div class="summary-card evpn-clickable" style="border-left-color: #9c27b0;" onclick="showEvpnModal('L2')" title="Click to see L2 VNIs">
                    <div class="metric" id="evpn-l2-vnis" style="color: #ce93d8;">{evpn_summary['l2_vnis']}</div>
                    <div class="metric-label">L2 VNIs</div>
                </div>
                <div class="summary-card evpn-clickable" style="border-left-color: #ff9800;" onclick="showEvpnModal('L3')" title="Click to see L3 VNIs">
                    <div class="metric" id="evpn-l3-vnis" style="color: #ffb74d;">{evpn_summary['l3_vnis']}</div>
                    <div class="metric-label">L3 VNIs</div>
                </div>
                <div class="summary-card evpn-clickable" style="border-left-color: #00bcd4;" onclick="showEvpnModal('type2')" title="Click to see Type-2 route breakdown">
                    <div class="metric" id="evpn-type2-routes" style="color: #4dd0e1;">{evpn_summary['type2_routes']}</div>
                    <div class="metric-label">Type-2 Routes (MAC/IP)</div>
                </div>
                <div class="summary-card evpn-clickable" style="border-left-color: #8bc34a;" onclick="showEvpnModal('type5')" title="Click to see Type-5 route breakdown">
                    <div class="metric" id="evpn-type5-routes" style="color: #aed581;">{evpn_summary['type5_routes']}</div>
                    <div class="metric-label">Type-5 Routes (IP Prefix)</div>
                </div>
            </div>
        </div>
    </div>
"""
        
        # Collect all neighbors for display
        all_neighbors = []
        
        for hostname, stats in self.current_bgp_stats.items():
            for neighbor_data in stats["neighbors"]:
                # Handle both enum and string state values
                neighbor_dict = neighbor_data.copy()
                if isinstance(neighbor_dict['state'], str):
                    neighbor_dict['state'] = BGPState(neighbor_dict['state'])
                
                neighbor = BGPNeighbor(**neighbor_dict)
                health = self.assess_neighbor_health(neighbor)
                
                neighbor_info = {
                    'hostname': hostname,
                    'neighbor': neighbor,
                    'health': health
                }
                
                all_neighbors.append(neighbor_info)
        
        # Add anomalies section if any exist
        if anomalies:
            html_content += f"""
    <!-- Issues Section -->
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
            </svg>
            Detailed Issue Analysis ({len(anomalies)})
        </div>
        <div class="section-content">
"""
            for anomaly in anomalies:
                severity_class = "warning" if anomaly['severity'] == 'warning' else ""
                html_content += f"""
            <div class="anomaly-card {severity_class}">
                <h4>{anomaly['device']} - {anomaly['neighbor']}</h4>
                <p><strong>Issue:</strong> {anomaly['message']}</p>
                <p><strong>Recommended Action:</strong> {anomaly['action']}</p>
            </div>
"""
            html_content += """
        </div>
    </div>
"""
        
        # BGP neighbors table (sorted by health - problems first)
        html_content += f"""
    <!-- Neighbors Status Section -->
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/>
            </svg>
            BGP Neighbors Status ({len(all_neighbors)} total)
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="bgp-table" id="bgp-table">
                <thead>
                <tr>
                    <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="1" data-type="string">Neighbor <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="2" data-type="port">Interface <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="3" data-type="bgp-state">State <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="4" data-type="number">ASN <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="5" data-type="uptime">Uptime <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="6" data-type="ratio">Prefixes RX/TX <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="7" data-type="ratio">Messages RX/TX <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="8" data-type="ratio">Queue In/Out <span class="sort-arrow">▲▼</span></th>
                    <th class="sortable" data-column="9" data-type="bgp-health">Health <span class="sort-arrow">▲▼</span></th>
                </tr>
                </thead>
                <tbody id="bgp-data">
"""
        
        # Add all neighbor data (sorted by health - problems first, then good ones)
        sorted_neighbors = sorted(all_neighbors, key=lambda x: (
            0 if x['health'] == BGPHealth.CRITICAL else
            1 if x['health'] == BGPHealth.WARNING else
            2 if x['health'] == BGPHealth.GOOD else
            3 if x['health'] == BGPHealth.EXCELLENT else 4
        ))
        
        for neighbor_info in sorted_neighbors:
            neighbor = neighbor_info['neighbor']
            health = neighbor_info['health']
            hostname = neighbor_info['hostname']
            
            state_val = get_enum_value(neighbor.state)
            health_val = get_enum_value(health)
            
            # Badge class based on state
            if state_val == 'established':
                state_badge_class = 'badge badge-green'
            elif state_val in ['idle', 'active', 'connect']:
                state_badge_class = 'badge badge-red'
            else:
                state_badge_class = 'badge badge-orange'
            
            # Badge class based on health
            if health_val == 'excellent':
                health_badge_class = 'badge badge-green'
            elif health_val == 'good':
                health_badge_class = 'badge badge-green'
            elif health_val == 'warning':
                health_badge_class = 'badge badge-orange'
            elif health_val == 'critical':
                health_badge_class = 'badge badge-red'
            else:
                health_badge_class = 'badge badge-gray'
            
            html_content += f"""
        <tr data-health="{health_val}" data-state="{state_val}">
            <td>{canonical(hostname)}</td>
            <td>{neighbor.neighbor_name}</td>
            <td>{neighbor.interface or 'N/A'}</td>
            <td><span class="{state_badge_class}">{state_val.upper()}</span></td>
            <td>{neighbor.asn}</td>
            <td>{neighbor.uptime}</td>
            <td>{neighbor.prefixes_received}/{neighbor.prefixes_sent}</td>
            <td>{neighbor.messages_received}/{neighbor.messages_sent}</td>
            <td>{neighbor.in_queue}/{neighbor.out_queue}</td>
            <td><span class="{health_badge_class}">{health_val.upper()}</span></td>
        </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
    
    <!-- Thresholds Section -->
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/>
            </svg>
            BGP Health Thresholds
        </div>
        <div class="section-content-table">
            <table class="bgp-table">
                <thead>
                    <tr><th>Parameter</th><th>Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>Critical Down Time</td><td>1+ hours</td><td>Neighbor down for extended period</td></tr>
                    <tr><td>High Queue Depth</td><td>10+ messages</td><td>Processing delays or congestion</td></tr>
                    <tr><td>Low Prefix Count</td><td>&lt; 1 prefix</td><td>Potential route advertisement issues</td></tr>
                    <tr><td>Message Ratio</td><td>&lt; 80%</td><td>Imbalanced message exchange</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- EVPN Detail Modal -->
    <div class="evpn-modal" id="evpnModal">
        <div class="evpn-modal-content">
            <div class="evpn-modal-header">
                <h3 id="evpnModalTitle">EVPN Details</h3>
                <button class="evpn-modal-close" onclick="closeEvpnModal()">&times;</button>
            </div>
            <div class="evpn-modal-body" id="evpnModalBody">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <!-- jQuery and Select2 for device search -->
    <script src="/css/jquery-3.5.1.min.js"></script>
    <script src="/css/select2.min.js"></script>
    
    <script>
        // EVPN per-device data
        const evpnPerDevice = __EVPN_DATA_PLACEHOLDER__;
        
        // EVPN Modal functions
        function showEvpnModal(filterType) {
            const modal = document.getElementById('evpnModal');
            const title = document.getElementById('evpnModalTitle');
            const body = document.getElementById('evpnModalBody');
            
            let html = '';
            
            if (filterType === 'type2' || filterType === 'type5') {
                // Show per-device route count breakdown
                const routeType = filterType === 'type2' ? 'Type-2 Routes (MAC/IP)' : 'Type-5 Routes (IP Prefix)';
                const routeKey = filterType === 'type2' ? 'type2_routes' : 'type5_routes';
                title.textContent = routeType + ' - Per Device';
                
                html = '<table class="evpn-table"><thead><tr><th>Device</th><th>Route Count</th></tr></thead><tbody>';
                
                // Sort by route count descending
                const sorted = Object.entries(evpnPerDevice)
                    .map(([device, data]) => ({ device, count: data[routeKey] || 0 }))
                    .filter(d => d.count > 0)
                    .sort((a, b) => b.count - a.count);
                
                sorted.forEach(item => {
                    html += '<tr><td>' + item.device + '</td><td>' + item.count.toLocaleString() + '</td></tr>';
                });
                
                html += '</tbody></table>';
                if (sorted.length === 0) html = '<p style="color:#888;text-align:center;">No routes found</p>';
                
            } else {
                // Show VNI details table
                let vniFilter = filterType; // 'all', 'L2', or 'L3'
                title.textContent = vniFilter === 'all' ? 'All VNIs' : vniFilter + ' VNIs';
                
                // Collect all VNIs from all devices
                let allVnis = [];
                Object.entries(evpnPerDevice).forEach(([device, data]) => {
                    if (data.vni_details) {
                        data.vni_details.forEach(vni => {
                            if (vniFilter === 'all' || vni.type === vniFilter) {
                                allVnis.push(Object.assign({}, vni, {device: device}));
                            }
                        });
                    }
                });
                
                // Remove duplicates (same VNI from multiple devices) - keep first occurrence
                const uniqueVnis = [];
                const seenVnis = new Set();
                allVnis.forEach(vni => {
                    if (!seenVnis.has(vni.vni)) {
                        seenVnis.add(vni.vni);
                        uniqueVnis.push(vni);
                    }
                });
                
                // Sort by Type (L3 first), then VNI number
                uniqueVnis.sort((a, b) => {
                    if (a.type !== b.type) return a.type === 'L3' ? -1 : 1;
                    return a.vni - b.vni;
                });
                
                html = '<table class="evpn-table"><thead><tr><th>VNI</th><th>Type</th><th>VRF</th><th>MACs</th><th>ARPs</th><th>Remote VTEPs</th></tr></thead><tbody>';
                
                uniqueVnis.forEach(vni => {
                    const badge = vni.type === 'L2' ? 'evpn-badge-l2' : 'evpn-badge-l3';
                    html += '<tr><td>' + vni.vni + '</td><td><span class="evpn-badge ' + badge + '">' + vni.type + '</span></td><td>' + (vni.vrf || 'default') + '</td><td>' + (vni.macs || 0) + '</td><td>' + (vni.arps || 0) + '</td><td>' + (vni.remote_vteps || 0) + '</td></tr>';
                });
                
                html += '</tbody></table>';
                if (uniqueVnis.length === 0) html = '<p style="color:#888;text-align:center;">No VNIs found</p>';
            }
            
            body.innerHTML = html;
            modal.classList.add('show');
        }
        
        function closeEvpnModal() {
            document.getElementById('evpnModal').classList.remove('show');
        }
        
        // Close modal on outside click
        document.getElementById('evpnModal').addEventListener('click', function(e) {
            if (e.target === this) closeEvpnModal();
        });
        
        // Close modal on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeEvpnModal();
        });
        
        // Filter functionality
        let currentFilter = 'ALL';
        let allRows = [];
        let deviceSearchActive = false;
        let selectedDevice = '';
        
        document.addEventListener('DOMContentLoaded', function() {
            // Store all table rows for filtering
            allRows = Array.from(document.querySelectorAll('#bgp-data tr'));
            
            // Add click events to summary cards
            setupCardEvents();
            
            // Initialize table sorting
            initTableSorting();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });
        
        function setupCardEvents() {
            document.getElementById('total-devices-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('total-devices').textContent) > 0) {
                    filterNeighbors('TOTAL');
                }
            });
            
            document.getElementById('total-neighbors-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('total-neighbors').textContent) > 0) {
                    filterNeighbors('TOTAL');
                }
            });
            
            document.getElementById('established-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('established-neighbors').textContent) > 0) {
                    filterNeighbors('ESTABLISHED');
                }
            });
            
            document.getElementById('down-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('down-neighbors').textContent) > 0) {
                    filterNeighbors('DOWN');
                }
            });
        }
        
        function filterNeighbors(filterType) {
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
            
            if (filterType === 'ESTABLISHED') {
                filteredRows = allRows.filter(row => row.dataset.state === 'established');
                filterText = `Showing ${filteredRows.length} Established Neighbors`;
                document.getElementById('established-card').classList.add('active');
            } else if (filterType === 'DOWN') {
                filteredRows = allRows.filter(row => 
                    row.dataset.state !== 'established' || 
                    row.dataset.health === 'critical' || 
                    row.dataset.health === 'warning'
                );
                filterText = `Showing ${filteredRows.length} Down/Problem Neighbors`;
                document.getElementById('down-card').classList.add('active');
            } else if (filterType === 'TOTAL') {
                filteredRows = allRows;
                document.getElementById('total-neighbors-card').classList.add('active');
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
            document.getElementById('filter-text').textContent = 'Showing neighbors for device: ' + deviceName + ' (' + matchCount + ' neighbors)';
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
                    sortBGPTable(column, tableSortState.direction, type);
                });
            });
        }
        
        function sortBGPTable(columnIndex, direction, type) {
            const table = document.getElementById('bgp-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows);
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                // Extract actual text for status/health columns (remove HTML)
                if (type === 'bgp-state' || type === 'bgp-health') {
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
                    case 'uptime':
                        result = compareBGPUptime(aVal, bVal);
                        break;
                    case 'bgp-state':
                        result = compareBGPState(aVal, bVal);
                        break;
                    case 'bgp-health':
                        result = compareBGPHealth(aVal, bVal);
                        break;
                    case 'ratio':
                        result = compareRatio(aVal, bVal);
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
        
        function compareBGPUptime(a, b) {
            if (a === 'never') return 1;
            if (b === 'never') return -1;
            
            // Parse BGP uptime format (e.g., "1d23h", "00:30:45", etc.)
            const parseUptime = (uptime) => {
                let minutes = 0;
                
                // Handle format like "1d23h", "2w3d", etc.
                const weekMatch = uptime.match(/(\\d+)w/);
                const dayMatch = uptime.match(/(\\d+)d/);
                const hourMatch = uptime.match(/(\\d+)h/);
                
                if (weekMatch) minutes += parseInt(weekMatch[1]) * 7 * 24 * 60;
                if (dayMatch) minutes += parseInt(dayMatch[1]) * 24 * 60;
                if (hourMatch) minutes += parseInt(hourMatch[1]) * 60;
                
                // Handle HH:MM:SS format
                const timeMatch = uptime.match(/(\\d+):(\\d+):(\\d+)/);
                if (timeMatch) {
                    minutes += parseInt(timeMatch[1]) * 60; // hours
                    minutes += parseInt(timeMatch[2]); // minutes
                }
                
                return minutes;
            };
            
            return parseUptime(a) - parseUptime(b);
        }
        
        function compareBGPState(a, b) {
            const priority = {
                'IDLE': 0,
                'ACTIVE': 1,
                'CONNECT': 2,
                'ESTABLISHED': 3
            };
            
            return (priority[a] || 4) - (priority[b] || 4);
        }
        
        function compareBGPHealth(a, b) {
            const priority = {
                'CRITICAL': 0,
                'WARNING': 1,
                'GOOD': 2,
                'EXCELLENT': 3
            };
            
            return (priority[a] || 4) - (priority[b] || 4);
        }
        
        function compareRatio(a, b) {
            // Parse ratio like "100/200" and compare by first number
            const getRatioValue = (ratio) => {
                const parts = ratio.split('/');
                return parseInt(parts[0]) || 0;
            };
            
            return getRatioValue(a) - getRatioValue(b);
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
                        background: #2d2d2d;
                        color: #d4d4d4;
                        padding: 15px 20px;
                        border-radius: 8px;
                        border-left: 4px solid #76b900;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.4);
                        z-index: 1000;
                        font-size: 13px;
                        max-width: 350px;
                    `;
                    notification.innerHTML = `
                        <strong style="color: #76b900;">✅ Monitor Analysis Started</strong><br>
                        The full system analysis is running in the background.<br>
                        <small style="color: #888;">Page will automatically refresh in 35 seconds to show the latest results.</small>
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
                const filename = `BGP_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Create CSV header
                const headers = [
                    'Device',
                    'Neighbor', 
                    'Interface',
                    'State',
                    'ASN',
                    'Uptime',
                    'Prefixes RX/TX',
                    'Messages RX/TX',
                    'Queue In/Out',
                    'Health'
                ];
                
                let csvContent = headers.join(',') + '\\n';
                
                // Get table data (only visible rows)
                const table = document.getElementById('bgp-table');
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');
                
                // Add summary stats as comments
                csvContent += `# BGP Analysis Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Devices: ${document.getElementById('total-devices').textContent}\\n`;
                csvContent += `# Total Neighbors: ${document.getElementById('total-neighbors').textContent}\\n`;
                csvContent += `# Established: ${document.getElementById('established-neighbors').textContent}\\n`;
                csvContent += `# Down/Problem: ${document.getElementById('down-neighbors').textContent}\\n`;
                csvContent += `# Health Ratio: ${document.getElementById('health-ratio').textContent}\\n`;
                csvContent += `#\\n`;
                
                // Process each visible row
                rows.forEach(row => {
                    if (row.style.display !== 'none') {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 10) {
                            const rowData = [
                                cells[0].textContent.trim(), // Device
                                cells[1].textContent.trim(), // Neighbor
                                cells[2].textContent.trim(), // Interface
                                cells[3].textContent.trim(), // State
                                cells[4].textContent.trim(), // ASN
                                cells[5].textContent.trim(), // Uptime
                                cells[6].textContent.trim(), // Prefixes RX/TX
                                cells[7].textContent.trim(), // Messages RX/TX
                                cells[8].textContent.trim(), // Queue In/Out
                                cells[9].textContent.trim()  // Health
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
    <script src="/css/analysis-guard.js"></script>
</body>
</html>
"""
        
        # Replace EVPN data placeholder with actual JSON
        html_content = html_content.replace('__EVPN_DATA_PLACEHOLDER__', evpn_per_device_json)
        
        with open(output_file, "w") as f:
            f.write(html_content)

if __name__ == "__main__":
    analyzer = BGPAnalyzer()
    print("BGP analyzer initialized")
    print(f"Monitoring {len(analyzer.current_bgp_stats)} devices")
