#!/usr/bin/env python3
"""
BGP vs Topology.dot Comparison Report

Usage:
    python3 compare_bgp_topology.py <bgp_report.csv>

This script compares BGP with topology.dot and generates a full report:
- Devices in BGP but NOT in topology.dot
- Links in BGP but NOT in topology.dot
- BGP DOWN links (IDLE/ACTIVE states)
- Summary statistics
"""

import csv
import re
import sys
import os
from datetime import datetime
from collections import defaultdict

def parse_bgp_report(csv_path):
    """Parse BGP report and return devices, links, and down states."""
    devices = set()
    established_links = set()
    down_idle = []
    down_active = []
    device_neighbors = defaultdict(set)
    
    # Resolve columns by header name.  The exported BGP CSV injects VRF and
    # Address Family columns (Device,VRF,Address Family,Neighbor,Interface,
    # State,...), so a fixed positional read of State (old row[3]) silently
    # picked up the Neighbor column and never matched IDLE/ACTIVE/ESTABLISHED.
    # Fall back to the legacy positional layout when no header row is present.
    col = {'device': 0, 'neighbor': 1, 'state': 3}

    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        header_seen = False
        for row in reader:
            if not row or row[0].startswith('#'):
                continue

            # Detect and consume the header row, mapping columns by name.
            if not header_seen:
                header_seen = True
                first = row[0].strip().lower()
                if first in ('device', 'hostname'):
                    lookup = {
                        name.strip().lower(): idx for idx, name in enumerate(row)
                    }
                    col['device'] = lookup.get(
                        'device', lookup.get('hostname', col['device'])
                    )
                    col['neighbor'] = lookup.get('neighbor', col['neighbor'])
                    col['state'] = lookup.get('state', col['state'])
                    continue
                # No header: fall through and parse this first row positionally.

            if len(row) <= max(col.values()):
                continue

            device = row[col['device']]
            neighbor_raw = row[col['neighbor']]
            state = row[col['state']].strip().upper()
            devices.add(device)
            
            # Skip firewall links
            if 'cfw' in neighbor_raw.lower():
                continue
            
            if state == 'ESTABLISHED':
                match = re.match(r'([a-z]{3}-\d[a-z]{2}-\d+-\d+)', neighbor_raw)
                if match:
                    neighbor = match.group(1)
                    devices.add(neighbor)
                    link = tuple(sorted([device, neighbor]))
                    established_links.add(link)
                    device_neighbors[device].add(neighbor)
                    device_neighbors[neighbor].add(device)
            elif state == 'IDLE':
                down_idle.append((device, neighbor_raw))
            elif state == 'ACTIVE':
                down_active.append((device, neighbor_raw))
    
    return devices, established_links, down_idle, down_active, device_neighbors

def parse_topology_dot(dot_path):
    """Parse topology.dot and return devices, links, and device:port pairs."""
    devices = set()
    links = set()
    device_ports = set()  # Set of "device:port" strings
    
    with open(dot_path, 'r') as f:
        for line in f:
            line = line.strip()
            if '--' not in line or line.startswith('#'):
                continue
            
            match = re.findall(r'"([^"]+)"', line)
            if len(match) >= 4:
                d1, p1, d2, p2 = match[0], match[1], match[2], match[3]
                # Skip non-switch links (DGX, servers, etc.)
                if any(x in d1.lower() or x in d2.lower() for x in ['dgx-', 'enp', 'prod-']):
                    continue
                devices.add(d1)
                devices.add(d2)
                link = tuple(sorted([d1, d2]))
                links.add(link)
                # Add device:port pairs
                device_ports.add(f"{d1}:{p1}")
                device_ports.add(f"{d2}:{p2}")
    
    return devices, links, device_ports

def categorize_device(name):
    """Categorize device by prefix."""
    prefix = name[:3] if len(name) >= 3 else name
    categories = {
        'csw': 'Core Switch',
        'ssw': 'Spine Switch', 
        'lsw': 'Leaf Switch',
        'osw': 'OOB Switch',
    }
    return categories.get(prefix, 'Unknown')

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 compare_bgp_topology.py <bgp_report.csv>")
        sys.exit(1)
    
    bgp_path = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Look for topology.dot in order of priority
    topo_paths = [
        os.path.join(script_dir, 'topology.dot'),  # Same directory as script
        '/var/www/html/topology.dot',               # Web root
    ]
    
    topo_path = None
    for path in topo_paths:
        if os.path.exists(path):
            topo_path = path
            break
    
    if not topo_path:
        print("Error: topology.dot not found in:")
        for path in topo_paths:
            print(f"  - {path}")
        sys.exit(1)
    
    # Parse files
    bgp_devices, bgp_links, bgp_idle, bgp_active, device_neighbors = parse_bgp_report(bgp_path)
    topo_devices, topo_links, topo_device_ports = parse_topology_dot(topo_path)
    
    # Calculate differences
    missing_devices = bgp_devices - topo_devices
    extra_topo_devices = topo_devices - bgp_devices
    missing_links = bgp_links - topo_links
    
    # Group missing devices by category
    missing_by_category = defaultdict(list)
    for dev in missing_devices:
        cat = categorize_device(dev)
        missing_by_category[cat].append(dev)
    
    # Print Report
    print("=" * 70)
    print("        BGP vs TOPOLOGY.DOT COMPARISON REPORT")
    print("=" * 70)
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  BGP Report: {os.path.basename(bgp_path)}")
    print("=" * 70)
    
    # Summary
    print("\n  SUMMARY")
    print("  " + "-" * 66)
    print(f"  BGP Devices:          {len(bgp_devices):>5}")
    print(f"  Topology Devices:     {len(topo_devices):>5}")
    print(f"  BGP Links:            {len(bgp_links):>5}")
    print(f"  Topology Links:       {len(topo_links):>5}")
    print("  " + "-" * 66)
    status_dev = "ACTION REQUIRED" if missing_devices else "OK"
    status_link = "ACTION REQUIRED" if missing_links else "OK"
    # Pre-calculate IDLE in/not in topology
    idle_in_topo_count = sum(1 for d, p in bgp_idle if f"{d}:{p}" in topo_device_ports)
    idle_not_in_topo_count = len(bgp_idle) - idle_in_topo_count
    
    status_idle_topo = "ACTION REQUIRED" if idle_in_topo_count else "OK"
    status_idle_other = "INFO" if idle_not_in_topo_count else "OK"
    status_active = "FIREWALL/L3" if bgp_active else "OK"
    print(f"  Missing Devices:      {len(missing_devices):>5}  [{status_dev}]")
    print(f"  Missing Links:        {len(missing_links):>5}  [{status_link}]")
    print(f"  IDLE (in topology):   {idle_in_topo_count:>5}  [{status_idle_topo}]")
    print(f"  IDLE (not in topo):   {idle_not_in_topo_count:>5}  [{status_idle_other}]")
    print(f"  BGP Down (ACTIVE):    {len(bgp_active):>5}  [{status_active}]")
    
    # Missing Devices
    print("\n" + "=" * 70)
    print("  MISSING DEVICES (in BGP but NOT in topology.dot)")
    print("=" * 70)
    if missing_devices:
        for category in ['Core Switch', 'Spine Switch', 'Leaf Switch', 'OOB Switch', 'Unknown']:
            if category in missing_by_category:
                print(f"\n  {category}:")
                for dev in sorted(missing_by_category[category]):
                    neighbors = device_neighbors.get(dev, set())
                    neighbor_str = ', '.join(sorted(neighbors)[:3])
                    if len(neighbors) > 3:
                        neighbor_str += f" (+{len(neighbors)-3} more)"
                    print(f"    - {dev}")
                    if neighbors:
                        print(f"      Neighbors: {neighbor_str}")
    else:
        print("\n  [OK] All BGP devices are documented in topology.dot")
    
    # Missing Links
    print("\n" + "=" * 70)
    print("  MISSING LINKS (in BGP but NOT in topology.dot)")
    print("=" * 70)
    if missing_links:
        print("\n  Add these to topology.dot:\n")
        for link in sorted(missing_links):
            print(f'    "{link[0]}" -- "{link[1]}"')
        print(f"\n  Total: {len(missing_links)} links")
    else:
        print("\n  [OK] All BGP links are documented in topology.dot")
    
    # Extra devices in topology
    extra_switches = {d for d in extra_topo_devices if d[:3] in ['csw', 'ssw', 'lsw', 'osw']}
    if extra_switches:
        print("\n" + "=" * 70)
        print("  TOPOLOGY DEVICES NOT IN BGP (down or not installed)")
        print("=" * 70)
        for dev in sorted(extra_switches):
            print(f"    - {dev}")
    
    # BGP Down Links - separate by topology.dot presence
    idle_in_topo = []
    idle_not_in_topo = []
    for device, port in bgp_idle:
        device_port = f"{device}:{port}"
        if device_port in topo_device_ports:
            idle_in_topo.append((device, port))
        else:
            idle_not_in_topo.append((device, port))
    
    print("\n" + "=" * 70)
    print("  BGP DOWN LINKS")
    print("=" * 70)
    
    if idle_in_topo:
        print(f"\n  IDLE - IN TOPOLOGY.DOT ({len(idle_in_topo)} ports) [ACTION REQUIRED]:")
        for device, port in idle_in_topo:
            print(f"    [!] {device}:{port}")
    
    if idle_not_in_topo:
        print(f"\n  IDLE - NOT IN TOPOLOGY.DOT ({len(idle_not_in_topo)} ports) [INFO]:")
        for device, port in idle_not_in_topo:
            print(f"    [ ] {device}:{port}")
    
    if bgp_active:
        print("\n  ACTIVE (Waiting for Peer - Firewall/L3):")
        for device, neighbor in bgp_active:
            print(f"    [i] {device} -> {neighbor}")
    
    if not bgp_idle and not bgp_active:
        print("\n  [OK] All BGP sessions are ESTABLISHED")
    
    # Final Status
    print("\n" + "=" * 70)
    issues = len(missing_devices) + len(missing_links) + len(idle_in_topo)
    if issues == 0:
        print("  STATUS: [OK] ALL GOOD - No action required")
    else:
        print(f"  STATUS: [!] {issues} issue(s) found - Review above sections")
    print("=" * 70 + "\n")
    
    sys.exit(1 if (missing_devices or missing_links or idle_in_topo) else 0)

if __name__ == '__main__':
    main()
