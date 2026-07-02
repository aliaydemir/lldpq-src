#!/bin/bash
# Search API - MAC/ARP Table Backend
# Backend for search.html

source "$(dirname "$0")/auth-guard.sh"
require_auth

# Load allowlisted config data through the fixed, root-owned parser.
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

# Set defaults (use $HOME for portable fallback)
LLDPQ_DIR="${LLDPQ_DIR:-$HOME/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Export for Python scripts
export LLDPQ_DIR LLDPQ_USER

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    ACTION=$(echo "$query" | grep -oP 'action=\K[^&]*' | head -1)
    DEVICE=$(echo "$query" | grep -oP 'device=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null)
    SEARCH=$(echo "$query" | grep -oP 'search=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null)
}

# Resolve SSH target (username@ip) from devices.yaml
# Usage: ssh_target=$(get_ssh_target "$DEVICE")
get_ssh_target() {
    local ip="$1"
    local username
    if ! username=$(python3 - "$ip" <<'PYTHON'
import os
import re
import sys

import yaml

ip = sys.argv[1]
try:
    # The request may select only a syntactically safe, configured inventory key.
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:%-]{0,252}', ip):
        raise ValueError('invalid device')
    with open(os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq')) + '/devices.yaml') as f:
        d = yaml.safe_load(f)
    if not isinstance(d, dict):
        raise ValueError('invalid inventory')
    default_user = d.get('defaults', {}).get('username', '')
    devs = d.get('devices', d)
    if not isinstance(devs, dict) or ip not in devs:
        raise ValueError('unknown device')
    info = devs.get(ip, {})
    if isinstance(info, dict):
        username = info.get('username', default_user)
    else:
        username = default_user
    if username and (
        not isinstance(username, str)
        or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}', username)
    ):
        raise ValueError('invalid username')
    print(username or '')
except Exception:
    sys.exit(1)
PYTHON
    ); then
        return 1
    fi
    if [[ -n "$username" ]]; then
        echo "${username}@${ip}"
    else
        echo "$ip"
    fi
}

# List available devices from devices.yaml
list_devices() {
    python3 << 'PYTHON'
import json
import yaml
import os

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
devices_file = f"{lldpq_dir}/devices.yaml"

# Fallback paths
if not os.path.exists(devices_file):
    devices_file = os.path.expanduser("~/lldpq/devices.yaml")

try:
    with open(devices_file, 'r') as f:
        devices_data = yaml.safe_load(f)
    
    devices = []
    
    # Get devices from 'devices' section
    devices_section = devices_data.get('devices', {})
    if not devices_section:
        # Fallback: treat entire file as devices (old format)
        devices_section = devices_data
    
    for ip, info in devices_section.items():
        # Skip non-device entries
        if ip in ['defaults', 'endpoint_hosts']:
            continue
        
        if isinstance(info, dict):
            hostname = info.get('hostname', ip)
        else:
            # Format: hostname as string
            hostname = str(info) if info else ip
        
        devices.append({"ip": ip, "hostname": hostname})
    
    # Sort by hostname
    devices.sort(key=lambda x: x['hostname'])
    
    print(json.dumps({"success": True, "devices": devices}))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
PYTHON
}

# Get MAC table from a device
get_mac_table() {
    local device="$1"
    local search="$2"
    
    if [[ -z "$device" ]]; then
        echo '{"success": false, "error": "Device not specified"}'
        return
    fi
    
    # SSH to device using LLDPQ user's SSH keys
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 30 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" '
        # Get bridge FDB (MAC table)
        /usr/sbin/bridge fdb show 2>/dev/null | grep -v "permanent\|self" | head -500
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

entries = []
for line in output.strip().split('\n'):
    if not line.strip():
        continue
    
    parts = line.split()
    if len(parts) >= 3:
        mac = parts[0]
        # Find interface (usually after 'dev')
        iface = ""
        vlan = ""
        for i, p in enumerate(parts):
            if p == "dev" and i + 1 < len(parts):
                iface = parts[i + 1]
            if p == "vlan" and i + 1 < len(parts):
                vlan = parts[i + 1]
        
        entry = {
            "mac": mac,
            "interface": iface,
            "vlan": vlan,
            "type": "dynamic"
        }
        
        # Apply search filter
        if search:
            if search in mac.lower() or search in iface.lower() or search in vlan.lower():
                entries.append(entry)
        else:
            entries.append(entry)

print(json.dumps({"success": True, "entries": entries[:200], "total": len(entries)}))
PYTHON
}

# Get ARP table from a device
get_arp_table() {
    local device="$1"
    local search="$2"
    
    if [[ -z "$device" ]]; then
        echo '{"success": false, "error": "Device not specified"}'
        return
    fi
    
    # SSH to device - get ARP entries and interface VRF mappings
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 30 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" '
        # Get ARP table (single query, no duplicates)
        /usr/sbin/ip neigh show 2>/dev/null | head -300
        echo "---VRF_MAP---"
        # Get VRF list
        /usr/sbin/ip vrf list 2>/dev/null
        echo "---IFACE_VRF---"
        # Get interface to VRF mappings
        for i in /sys/class/net/*/master; do
            n=$(echo $i | cut -d/ -f5)
            m=$(readlink $i 2>/dev/null | xargs basename 2>/dev/null)
            [ -n "$m" ] && echo "$n $m"
        done
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import re
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

# Parse sections
sections = output.split("---VRF_MAP---")
arp_lines = sections[0].strip().split('\n') if len(sections) > 0 else []

vrf_list = set()
iface_to_vrf = {}

if len(sections) > 1:
    rest = sections[1].split("---IFACE_VRF---")
    # Parse VRF list
    for line in rest[0].strip().split('\n'):
        if line and not line.startswith("Name") and not line.startswith("-"):
            parts = line.split()
            if parts:
                vrf_list.add(parts[0])
    # Parse interface to VRF mappings
    if len(rest) > 1:
        for line in rest[1].strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                iface, master = parts[0], parts[1]
                if master in vrf_list:
                    iface_to_vrf[iface] = master

entries = []
for line in arp_lines:
    if not line.strip():
        continue
    
    parts = line.split()
    if len(parts) >= 4:
        ip_addr = parts[0]
        mac = ""
        iface = ""
        state = ""
        
        for i, p in enumerate(parts):
            if p == "dev" and i + 1 < len(parts):
                iface = parts[i + 1]
            if p == "lladdr" and i + 1 < len(parts):
                mac = parts[i + 1]
        
        if parts[-1] in ["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"]:
            state = parts[-1]
        
        if mac:
            # Skip VRR interfaces
            if iface and re.search(r'-v\d+$', iface):
                continue
            vrf = iface_to_vrf.get(iface, "default")
            entry = {
                "ip": ip_addr,
                "mac": mac,
                "interface": iface,
                "vrf": vrf,
                "state": state
            }
            
            if search:
                if (search in ip_addr.lower() or search in mac.lower() or 
                    search in iface.lower() or search in vrf.lower()):
                    entries.append(entry)
            else:
                entries.append(entry)

print(json.dumps({"success": True, "entries": entries[:500], "total": len(entries)}))
PYTHON
}

# Get all MAC/ARP from all devices (parallel)
get_all_tables() {
    local table_type="$1"  # mac or arp
    local search="$2"
    
    python3 - "$table_type" "$search" <<'PYTHON'
import json
import yaml
import subprocess
import concurrent.futures
import os
import re
import sys

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
devices_file = f"{lldpq_dir}/devices.yaml"

if not os.path.exists(devices_file):
    devices_file = os.path.expanduser("~/lldpq/devices.yaml")

table_type = sys.argv[1]
search = sys.argv[2].lower()
default_ssh_user = ""

def ssh_target(ip, info):
    username = default_ssh_user
    if isinstance(info, dict):
        username = info.get('username') or default_ssh_user
    return f"{username}@{ip}" if username else ip

def get_device_table(device_info):
    ip, info = device_info
    if isinstance(info, dict):
        hostname = info.get('hostname', ip)
    else:
        hostname = str(info) if info else ip
    
    try:
        lldpq_user = os.environ.get('LLDPQ_USER', os.environ.get('USER', 'root'))
        target = ssh_target(ip, info)
        if table_type == "mac":
            remote_script = "/usr/sbin/bridge fdb show 2>/dev/null | grep -v permanent | head -200"
            cmd_parts = [
                "sudo", "-u", lldpq_user, "timeout", "15", "ssh",
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", target,
                remote_script
            ]
            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=20)
        else:  # arp - get ARP with interface VRF mappings
            remote_script = '/usr/sbin/ip neigh show 2>/dev/null | head -200; echo ---VRF_MAP---; /usr/sbin/ip vrf list 2>/dev/null; echo ---IFACE_VRF---; for i in /sys/class/net/vlan*/master /sys/class/net/eth*/master; do n=$(basename $(dirname $i)); m=$(readlink $i | xargs basename); [ -n "$m" ] && echo $n $m; done 2>/dev/null'
            cmd_parts = [
                "sudo", "-u", lldpq_user, "timeout", "15", "ssh",
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", target,
                remote_script
            ]
            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=20)
        
        entries = []
        
        if table_type == "mac":
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    mac = parts[0]
                    iface = ""
                    vlan = ""
                    for i, p in enumerate(parts):
                        if p == "dev" and i + 1 < len(parts):
                            iface = parts[i + 1]
                        if p == "vlan" and i + 1 < len(parts):
                            vlan = parts[i + 1]
                    
                    entry = {"device": hostname, "mac": mac, "interface": iface, "vlan": vlan}
                    if not search or search in mac.lower() or search in iface.lower() or search in hostname.lower():
                        entries.append(entry)
        
        elif table_type == "arp":
            # Parse ARP with VRF info from interface masters
            output = result.stdout.strip()
            sections = output.split("---VRF_MAP---")
            arp_lines = sections[0].strip().split('\n') if sections else []
            
            vrf_list = set()
            iface_to_vrf = {}
            
            if len(sections) > 1:
                rest = sections[1].split("---IFACE_VRF---")
                for line in rest[0].strip().split('\n'):
                    if line and not line.startswith("Name") and not line.startswith("-"):
                        parts = line.split()
                        if parts:
                            vrf_list.add(parts[0])
                if len(rest) > 1:
                    for line in rest[1].strip().split('\n'):
                        parts = line.split()
                        # Check if second part is a VRF (skip bridge masters like br_default)
                        if len(parts) >= 2 and parts[1] in vrf_list:
                            iface_to_vrf[parts[0]] = parts[1]
            
            for line in arp_lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue
                    
                ip_addr = parts[0]
                mac = ""
                iface = ""
                for i, p in enumerate(parts):
                    if p == "dev" and i + 1 < len(parts):
                        iface = parts[i + 1]
                    if p == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1]
                
                if mac:
                    if iface and re.search(r'-v\d+$', iface):
                        continue
                    vrf = iface_to_vrf.get(iface, "default")
                    entry = {"device": hostname, "ip": ip_addr, "mac": mac, "interface": iface, "vrf": vrf}
                    if not search or search in ip_addr.lower() or search in mac.lower() or search in hostname.lower():
                        entries.append(entry)
        
        return entries
    except Exception as e:
        return []

try:
    with open(devices_file, 'r') as f:
        devices_data = yaml.safe_load(f)
    default_ssh_user = devices_data.get('defaults', {}).get('username', '')
    
    # Get devices from 'devices' section
    devices_section = devices_data.get('devices', {})
    if not devices_section:
        devices_section = devices_data
    
    # Filter out non-device entries
    device_list = [(ip, info) for ip, info in devices_section.items() 
                   if ip not in ['defaults', 'endpoint_hosts']]
    
    all_entries = []
    
    # Parallel execution - increase workers for faster search
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(get_device_table, device_list)
        for entries in results:
            all_entries.extend(entries)
    
    print(json.dumps({"success": True, "entries": all_entries[:500], "total": len(all_entries)}))

except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
PYTHON
}

# Get VXLAN VTEPs from a device
get_vtep_table() {
    local device="$1"
    local search="$2"
    
    if [[ -z "$device" ]]; then
        echo '{"success": false, "error": "Device not specified"}'
        return
    fi
    
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 30 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" '
        /usr/sbin/bridge fdb show 2>/dev/null | grep "dst " | head -1000
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

entries = []
vtep_summary = {}  # VTEP IP -> {vni_count, mac_count}

for line in output.strip().split('\n'):
    if not line.strip():
        continue
    
    parts = line.split()
    mac = parts[0] if parts else ""
    vtep_ip = ""
    vni = ""
    iface = ""
    state = ""
    
    for i, p in enumerate(parts):
        if p == "dst" and i + 1 < len(parts):
            vtep_ip = parts[i + 1]
        # Handle both "vni" and "src_vni" formats
        if p in ("vni", "src_vni") and i + 1 < len(parts):
            vni = parts[i + 1]
        if p == "dev" and i + 1 < len(parts):
            iface = parts[i + 1]
    
    # Determine state from flags in the line
    if "permanent" in line:
        state = "permanent"
    elif "offload" in line:
        state = "offload"
    elif "extern_learn" in line:
        state = "learned"
    else:
        state = "dynamic"
    
    # Determine if it's a BUM entry (00:00:00:00:00:00)
    entry_type = "BUM" if mac == "00:00:00:00:00:00" else "MAC"
    
    if vtep_ip:
        # Track summary
        if vtep_ip not in vtep_summary:
            vtep_summary[vtep_ip] = {"vnis": set(), "macs": 0}
        vtep_summary[vtep_ip]["vnis"].add(vni)
        vtep_summary[vtep_ip]["macs"] += 1
        
        entry = {
            "vtep": vtep_ip, 
            "vni": vni, 
            "mac": mac, 
            "interface": iface,
            "state": state,
            "type": entry_type
        }
        if not search or search in vtep_ip.lower() or search in vni.lower() or search in mac.lower():
            entries.append(entry)

# Sort by VTEP IP, then VNI, then MAC
def ip_sort_key(ip):
    try:
        return tuple(int(x) for x in ip.split('.'))
    except:
        return (255, 255, 255, 255)

entries.sort(key=lambda x: (ip_sort_key(x['vtep']), x['vni'], x['mac']))

# Build summary for header
summary = {
    "unique_vteps": len(vtep_summary),
    "total_entries": len(entries)
}

print(json.dumps({"success": True, "entries": entries[:500], "total": len(entries), "summary": summary}))
PYTHON
}

# Get Route table from a device
get_route_table() {
    local device="$1"
    local search="$2"
    
    if [[ -z "$device" ]]; then
        echo '{"success": false, "error": "Device not specified"}'
        return
    fi
    
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 45 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" '
        sudo vtysh -c "show ip route vrf all" 2>/dev/null | head -5000
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import re
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

# Parse vtysh output
# Format: VRF xxx:
# B>* 10.10.10.1/32 [20/0] via fe80::..., swp33s0, weight 1, 01w6d20h
# Route codes: B=BGP, C=connected, S=static, K=kernel, O=OSPF, etc.

vrf_data = {}  # {vrf_name: [routes]}
current_vrf = "default"
current_prefix = None
current_entry = None

route_codes = {
    'B': 'BGP', 'C': 'connected', 'S': 'static', 'K': 'kernel',
    'O': 'OSPF', 'R': 'RIP', 'I': 'IS-IS', 'E': 'EIGRP',
    'L': 'local', 'A': 'Babel', 'D': 'SHARP'
}

last_entry = None

for line in output.strip().split('\n'):
    line = line.rstrip()
    if not line:
        continue
    
    # Skip header lines (Codes:, etc.)
    if line.startswith('Codes:') or line.startswith('       '):
        if 'VRF' not in line:
            continue
    
    # VRF header: "VRF xxx:" or "VRF default:"
    vrf_match = re.match(r'^VRF\s+(\S+):', line)
    if vrf_match:
        current_vrf = vrf_match.group(1)
        if current_vrf not in vrf_data:
            vrf_data[current_vrf] = []
        last_entry = None
        continue
    
    # ECMP continuation line: starts with spaces and * (must check before route match)
    if line.startswith('  ') and '*' in line[:10] and last_entry:
        last_entry['ecmp'] += 1
        continue
    
    # New route line: starts with route code (B, C, S, K, L, etc.)
    # Format with metric: B>* 10.10.10.1/32 [20/0] via fe80::..., swp33s0, weight 1, 01w6d20h
    # Format without metric: C>* 192.168.100.0/24 is directly connected, eth0, 01w6d20h
    
    # First try: route with [AD/metric]
    route_match = re.match(r'^([BCSKORIEALT])([>*\s]+)\s*(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+\[(\d+)/(\d+)\]', line)
    
    # Second try: route without [AD/metric] (connected, local)
    if not route_match:
        route_match_simple = re.match(r'^([BCSKORIEALT])([>*\s]+)\s*(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+', line)
        if route_match_simple:
            code = route_match_simple.group(1)
            prefix = route_match_simple.group(3)
            ad = "0"
            metric = "0"
        else:
            continue
    else:
        code = route_match.group(1)
        prefix = route_match.group(3)
        ad = route_match.group(4)  # Administrative distance
        metric = route_match.group(5)
    
    # Add /32 if no mask
    if '/' not in prefix:
        prefix = prefix + '/32'
    
    # Extract next hop and interface
    nexthop = ""
    iface = ""
    age = ""
    
    # Parse "via X, interface, ..." or "is directly connected, interface"
    via_match = re.search(r'via\s+(\S+),\s*(\S+)', line)
    if via_match:
        nh = via_match.group(1)
        # Skip IPv6 link-local as nexthop, use interface instead
        if nh.startswith('fe80::'):
            nexthop = "link-local"
        else:
            nexthop = nh.rstrip(',')
        iface = via_match.group(2).rstrip(',')
    
    connected_match = re.search(r'directly connected,\s*(\S+)', line)
    if connected_match:
        nexthop = "connected"
        iface = connected_match.group(1).rstrip(',')
    
    # Handle unreachable routes
    if 'unreachable' in line:
        nexthop = "unreachable"
    
    # Extract age if present (e.g., 01w6d20h)
    age_match = re.search(r',\s*(\d+[wdhms]\d*[wdhms]*\d*[wdhms]*)$', line)
    if age_match:
        age = age_match.group(1)
    
    protocol = route_codes.get(code, code)
    
    # Skip kernel routes (unreachable, blackhole, etc.) - they are confusing
    if protocol == 'kernel':
        continue
    
    last_entry = {
        "prefix": prefix,
        "nexthop": nexthop or "-",
        "interface": iface or "-",
        "protocol": protocol,
        "ad": ad,
        "metric": metric,
        "age": age or "-",
        "ecmp": 1  # ECMP path count
    }
    
    if current_vrf not in vrf_data:
        vrf_data[current_vrf] = []
    vrf_data[current_vrf].append(last_entry)

# Build flat entries list for filtering and sorting
entries = []
for vrf, routes in vrf_data.items():
    for r in routes:
        r['vrf'] = vrf
        entries.append(r)

# Apply search filter
if search:
    filtered = []
    for e in entries:
        # Search in prefix, nexthop, interface, protocol
        if (search in e['prefix'].lower() or 
            search in e['nexthop'].lower() or 
            search in e['interface'].lower() or
            search in e['protocol'].lower()):
            filtered.append(e)
        # VRF exact match or starts with
        elif e['vrf'].lower() == search or e['vrf'].lower().startswith(search):
            filtered.append(e)
    entries = filtered

# Sort: default VRF first, then alphabetical, mgmt last
def prefix_to_sortable(prefix):
    if prefix == "0.0.0.0/0":
        return (0, 0, 0, 0, 0)
    try:
        if '/' in prefix:
            ip_part, mask = prefix.rsplit('/', 1)
            mask = int(mask)
        else:
            ip_part = prefix
            mask = 32
        octets = tuple(int(o) for o in ip_part.split('.'))
        return (1,) + octets + (mask,)
    except:
        return (2, 255, 255, 255, 255, 32)

def vrf_sort_key(e):
    vrf = e['vrf']
    prefix_key = prefix_to_sortable(e['prefix'])
    if vrf == 'default':
        return (0, vrf, prefix_key)
    elif vrf == 'mgmt':
        return (2, vrf, prefix_key)
    else:
        return (1, vrf, prefix_key)

entries.sort(key=vrf_sort_key)

# Group by VRF for UI display
vrf_tables = {}
for e in entries:
    vrf = e['vrf']
    if vrf not in vrf_tables:
        vrf_tables[vrf] = []
    vrf_tables[vrf].append(e)

# Order VRF list: default first, mgmt last
vrf_order = []
if 'default' in vrf_tables:
    vrf_order.append('default')
for v in sorted(vrf_tables.keys()):
    if v not in ('default', 'mgmt'):
        vrf_order.append(v)
if 'mgmt' in vrf_tables:
    vrf_order.append('mgmt')

print(json.dumps({
    "success": True, 
    "vrf_tables": {v: vrf_tables[v][:100] for v in vrf_order},
    "vrf_order": vrf_order,
    "total": len(entries)
}))
PYTHON
}

# Get bond members for an interface
get_bond_members() {
    local device="$1"
    local bond="$2"
    
    if [[ -z "$device" ]] || [[ -z "$bond" ]]; then
        echo '{"success": false, "error": "Device and bond not specified"}'
        return
    fi

    if [[ ! "$bond" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
        echo '{"success": false, "error": "Invalid bond interface"}'
        return
    fi
    
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 10 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes "$ssh_target" "
        cat /sys/class/net/$bond/bonding/slaves 2>/dev/null || echo ''
    " 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to get bond members"}'
        return
    fi
    
    # Convert space-separated list to JSON array
    local members=$(echo "$ssh_output" | tr ' ' '\n' | grep -v '^$' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//')
    echo "{\"success\": true, \"members\": [$members]}"
}

# Get LLDP neighbors from a device
get_lldp_neighbors() {
    local device="$1"
    local search="$2"
    
    if [[ -z "$device" ]]; then
        echo '{"success": false, "error": "Device not specified"}'
        return
    fi
    
    local ssh_target
    if ! ssh_target=$(get_ssh_target "$device"); then
        echo '{"success": false, "error": "Invalid or unknown device"}'
        return
    fi
    local ssh_output
    ssh_output=$(sudo -u "$LLDPQ_USER" timeout 30 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes "$ssh_target" '
        sudo lldpctl -f json 2>/dev/null || echo "{}"
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

entries = []

try:
    data = json.loads(output)
    lldp_data = data.get('lldp', [])
    
    # Handle array format from lldpctl
    if isinstance(lldp_data, list):
        for item in lldp_data:
            interfaces = item.get('interface', [])
            if isinstance(interfaces, list):
                for iface in interfaces:
                    iface_name = iface.get('name', '')
                    chassis_list = iface.get('chassis', [])
                    port_list = iface.get('port', [])
                    
                    neighbor = ""
                    mgmt_ip = ""
                    remote_port = ""
                    
                    # Parse chassis info
                    if chassis_list and isinstance(chassis_list, list):
                        chassis = chassis_list[0]
                        name_list = chassis.get('name', [])
                        if name_list and isinstance(name_list, list):
                            neighbor = name_list[0].get('value', '')
                        
                        mgmt_list = chassis.get('mgmt-ip', [])
                        if mgmt_list and isinstance(mgmt_list, list):
                            mgmt_ip = mgmt_list[0].get('value', '')
                    
                    # Parse port info
                    if port_list and isinstance(port_list, list):
                        port = port_list[0]
                        id_list = port.get('id', [])
                        if id_list and isinstance(id_list, list):
                            remote_port = id_list[0].get('value', '')
                        if not remote_port:
                            descr_list = port.get('descr', [])
                            if descr_list and isinstance(descr_list, list):
                                remote_port = descr_list[0].get('value', '')
                    
                    if neighbor:
                        entry = {
                            "local_port": iface_name,
                            "neighbor": neighbor,
                            "remote_port": remote_port,
                            "mgmt_ip": mgmt_ip
                        }
                        
                        if not search or search in neighbor.lower() or search in iface_name.lower() or search in str(mgmt_ip).lower():
                            entries.append(entry)
    
    # Sort by local port
    entries.sort(key=lambda x: x['local_port'])
    
except Exception as e:
    pass

print(json.dumps({"success": True, "entries": entries, "total": len(entries)}))
PYTHON
}

# Get fabric scan status
get_scan_status() {
    python3 << 'PYTHON'
import json
import os
from datetime import datetime

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
summary_file = f"{lldpq_dir}/monitor-results/fabric-tables/summary.json"

try:
    if os.path.exists(summary_file):
        with open(summary_file) as f:
            data = json.load(f)
        
        timestamp = data.get('timestamp', '')
        device_count = len(data.get('devices', []))
        
        # Calculate age
        if timestamp:
            scan_time = datetime.fromisoformat(timestamp)
            age_seconds = (datetime.now() - scan_time).total_seconds()
            age_minutes = int(age_seconds / 60)
        else:
            age_minutes = -1
        
        print(json.dumps({
            "success": True,
            "timestamp": timestamp,
            "device_count": device_count,
            "age_minutes": age_minutes
        }))
    else:
        print(json.dumps({
            "success": True,
            "timestamp": None,
            "device_count": 0,
            "age_minutes": -1,
            "message": "No scan data available"
        }))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
PYTHON
}

# Trigger fabric scan
run_fabric_scan() {
    local lldpq_dir="${LLDPQ_DIR:-$HOME/lldpq}"
    local scan_script="$lldpq_dir/fabric-scan.sh"
    
    if [[ ! -f "$scan_script" ]]; then
        echo '{"success": false, "error": "fabric-scan.sh not found"}'
        return
    fi
    
    # Check if already running
    if pgrep -f "fabric-scan.sh" > /dev/null; then
        echo '{"success": false, "error": "Scan already in progress"}'
        return
    fi
    
    # Run scan in background
    cd "$lldpq_dir"
    sudo -u "$LLDPQ_USER" nohup bash "$scan_script" > /tmp/fabric-scan.log 2>&1 &
    
    echo '{"success": true, "message": "Fabric scan started"}'
}

# Search cached routes (VRF-grouped structure)
search_cached_routes() {
    local search_ip="$1"
    
    python3 - "$search_ip" <<'PYTHON'
import json
import os
import struct
import socket
import sys

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
search_ip = sys.argv[1]

def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def is_ip_in_prefix(ip, prefix):
    try:
        if '/' not in prefix:
            return ip == prefix
        network, mask = prefix.split('/')
        mask = int(mask)
        ip_int = ip_to_int(ip)
        net_int = ip_to_int(network)
        mask_bits = (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF if mask > 0 else 0
        return (ip_int & mask_bits) == (net_int & mask_bits)
    except:
        return False

def get_prefix_len(prefix):
    try:
        if '/' in prefix:
            return int(prefix.split('/')[1])
        return 32
    except:
        return 0

results = {}  # vrf -> [routes with best match]
all_vrfs = set()  # Collect all unique VRFs
device_vrfs = {}  # Track which VRFs each device has

try:
    if not os.path.exists(tables_dir):
        print(json.dumps({"success": False, "error": "No cached data. Run Fabric Scan first."}))
        exit()
    
    # First pass: collect all VRFs and find best matches
    for filename in os.listdir(tables_dir):
        if not filename.endswith('.json') or filename == 'summary.json':
            continue
        
        hostname = filename.replace('.json', '')
        filepath = os.path.join(tables_dir, filename)
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            routes = data.get('routes', {})
            device_vrfs[hostname] = set()
            
            for vrf, vrf_routes in routes.items():
                # Skip invalid VRF names
                if vrf.startswith('-') or not vrf.strip():
                    continue
                    
                all_vrfs.add(vrf)
                device_vrfs[hostname].add(vrf)
                
                best_match = None
                best_prefix_len = -1
                
                for route in vrf_routes:
                    prefix = route.get('prefix', '')
                    if is_ip_in_prefix(search_ip, prefix):
                        prefix_len = get_prefix_len(prefix)
                        if prefix_len > best_prefix_len:
                            best_prefix_len = prefix_len
                            best_match = route.copy()
                            best_match['device'] = hostname
                            best_match['vrf'] = vrf
                
                if best_match:
                    if vrf not in results:
                        results[vrf] = []
                    results[vrf].append(best_match)
        except Exception as e:
            continue
    
    # Second pass: add "No Route" for VRFs without any match
    for vrf in all_vrfs:
        if vrf not in results:
            # Count devices that have this VRF
            devices_with_vrf = [d for d, vrfs in device_vrfs.items() if vrf in vrfs]
            results[vrf] = [{
                'device': 'all',
                'vrf': vrf,
                'prefix': 'No Route',
                'nexthop': '-',
                'interface': '-',
                'protocol': '-',
                'no_route': True,
                'device_count': len(devices_with_vrf)
            }]
    
    print(json.dumps({
        "success": True,
        "vrf_routes": results,
        "cached": True
    }))

except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
PYTHON
}

# Get list of VRFs from cached route data
get_vrfs() {
    python3 << 'PYTHON'
import json
import os

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"

vrfs = set(['default'])

try:
    if os.path.exists(tables_dir):
        for filename in os.listdir(tables_dir):
            if not filename.endswith('.json') or filename == 'summary.json':
                continue
            
            filepath = os.path.join(tables_dir, filename)
            try:
                with open(filepath) as f:
                    data = json.load(f)
                
                routes = data.get('routes', {})
                for vrf in routes.keys():
                    vrfs.add(vrf)
            except:
                pass
    
    print(json.dumps({"vrfs": sorted(list(vrfs))}))
except Exception as e:
    print(json.dumps({"vrfs": ["default"], "error": str(e)}))
PYTHON
}

# Find which VRF an IP belongs to (search across all devices)
find_ip_vrf() {
    local ip="$1"
    
    python3 - "$ip" <<'PYTHON'
import json
import os
import ipaddress
import sys

search_ip = sys.argv[1]

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"

def prefix_match(ip, prefix):
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        ip_addr = ipaddress.ip_address(ip)
        if ip_addr in network:
            return network.prefixlen
        return -1
    except:
        return -1

try:
    vrfs_found = set()
    
    if os.path.exists(tables_dir):
        for filename in os.listdir(tables_dir):
            if not filename.endswith('.json') or filename == 'summary.json':
                continue
            
            filepath = os.path.join(tables_dir, filename)
            try:
                with open(filepath) as f:
                    data = json.load(f)
                
                # Check ARP entries
                for arp in data.get('arp', []):
                    if arp.get('ip') == search_ip:
                        vrf = arp.get('vrf', 'default')
                        vrfs_found.add(vrf if vrf else 'default')
                
                # Check routes for connected networks
                routes = data.get('routes', {})
                for vrf, vrf_routes in routes.items():
                    for route in vrf_routes:
                        prefix = route.get('prefix', '')
                        protocol = route.get('protocol', '')
                        if protocol in ['kernel', 'connected', 'local']:
                            if prefix and prefix_match(search_ip, prefix) >= 0:
                                vrfs_found.add(vrf)
            except:
                pass
    
    result_vrfs = sorted(list(vrfs_found)) if vrfs_found else []
    # Sort: mgmt at the end so tenant/production VRFs get selected first
    def vrf_sort_key(v):
        if v == 'mgmt': return (2, v)
        if v == 'default': return (1, v)
        return (0, v)  # tenant VRFs first
    result_vrfs.sort(key=vrf_sort_key)
    print(json.dumps({"vrfs": result_vrfs}))

except Exception as e:
    print(json.dumps({"vrfs": [], "error": str(e)}))
PYTHON
}

# Trace path from source IP to destination IP
trace_path_ip() {
    local source_ip="$1"
    local dest_ip="$2"
    local vrf="$3"
    local dst_vrf_param="$4"
    
    python3 - "$source_ip" "$dest_ip" "$vrf" "$dst_vrf_param" <<'PYTHON'
import json
import os
import re
import ipaddress
import sys

source_ip = sys.argv[1]
dest_ip = sys.argv[2]
vrf_hint = sys.argv[3]
dst_vrf_hint = sys.argv[4]

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
lldp_file = '/var/www/html/lldp_results.ini'

# ─── Utility functions ───

def prefix_match(ip, prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        if ipaddress.ip_address(ip) in net:
            return net.prefixlen
        return -1
    except:
        return -1

def find_best_route(ip, routes, vrf):
    best, best_len = None, -1
    for r in routes.get(vrf, []):
        p = r.get('prefix', '')
        if p:
            ml = prefix_match(ip, p)
            if ml > best_len:
                best_len = ml
                best = r
    return best, best_len

def base(name):
    """Extract base hostname: 'csw-3na-17-39 @core' -> 'csw-3na-17-39'"""
    return name.split(' ')[0] if ' ' in name else name

def load_all_data():
    all_data = {}
    if not os.path.exists(tables_dir):
        return all_data
    for fn in os.listdir(tables_dir):
        if not fn.endswith('.json') or fn == 'summary.json':
            continue
        try:
            with open(os.path.join(tables_dir, fn)) as f:
                all_data[fn.replace('.json', '')] = json.load(f)
        except:
            pass
    return all_data

# ─── LLDP parsing ───

def load_lldp_data():
    """Parse lldp_results.ini -> neighbors, port_neighbors, link_status.
    neighbors: {device: set(neighbor_devices)}
    port_neighbors: {device: {port: neighbor_device}}
    link_status: {(device, neighbor): {'up': N, 'down': N, 'fail': N}}
    """
    neighbors = {}
    port_neighbors = {}  # {device: {port: neighbor}}
    link_status = {}
    
    if not os.path.exists(lldp_file):
        return neighbors, port_neighbors, link_status
    
    try:
        with open(lldp_file) as f:
            content = f.read()
        
        current_device = None
        for line in content.split('\n'):
            m = re.match(r'^=+\s+(\S+)\s+=+$', line)
            if m:
                current_device = m.group(1)
                neighbors.setdefault(current_device, set())
                port_neighbors.setdefault(current_device, {})
                continue
            
            if not current_device or line.startswith('-') or line.startswith('Port'):
                continue
            
            parts = line.split()
            if len(parts) >= 6:
                local_port = parts[0]   # swp1s0
                status = parts[1]       # Pass/Fail
                act_nbr = parts[4]      # Actual neighbor
                port_status = parts[5] if len(parts) > 5 else ''
                
                if act_nbr and act_nbr not in ('-', 'Act-Nbr'):
                    neighbors[current_device].add(act_nbr)
                    neighbors.setdefault(act_nbr, set())
                    neighbors[act_nbr].add(current_device)
                    
                    # Track port->neighbor mapping
                    port_neighbors[current_device][local_port] = act_nbr
                    
                    # Track link status
                    key = (current_device, act_nbr)
                    if key not in link_status:
                        link_status[key] = {'up': 0, 'down': 0, 'fail': 0}
                    
                    if status == 'Fail' or port_status == 'DOWN':
                        link_status[key]['down'] += 1
                    else:
                        link_status[key]['up'] += 1
    except:
        pass
    
    return neighbors, port_neighbors, link_status

def build_host_set(all_data, port_neighbors):
    """Identify hosts by cross-referencing bond ports with LLDP neighbors.
    A neighbor on a bond port = host. A neighbor on a non-bond port = fabric switch.
    """
    hosts = set()
    
    for device_key, data in all_data.items():
        device_base = device_key.split(' ')[0] if ' ' in device_key else device_key
        bonds = data.get('bonds', {})
        if not bonds:
            continue
        
        # Collect all bond member ports
        bond_ports = set()
        for bond_name, members in bonds.items():
            if isinstance(members, str):
                for m in members.split():
                    bond_ports.add(m)
            elif isinstance(members, list):
                for m in members:
                    bond_ports.add(m)
        
        if not bond_ports:
            continue
        
        # Find this device in port_neighbors (try base name match)
        device_ports = None
        if device_base in port_neighbors:
            device_ports = port_neighbors[device_base]
        else:
            for pn_key in port_neighbors:
                if pn_key == device_base or pn_key.startswith(device_base):
                    device_ports = port_neighbors[pn_key]
                    break
        
        if not device_ports:
            continue
        
        # Any LLDP neighbor on a bond port = host
        for port, neighbor in device_ports.items():
            if port in bond_ports:
                hosts.add(neighbor)
    
    return hosts

def determine_tiers(neighbors, hosts):
    """Determine Clos tiers using degree-based leaf identification + BFS.
    
    tier -1: host (identified via bond-port detection)
    tier  0: leaf  (lowest tier in fabric)
    tier  1: spine (1 hop from leaf)
    tier  2: core  (2 hops from leaf)
    
    Key problem: hosts may bond to spines (multi-homing), not just leaves.
    Naive BFS from host-connected devices would wrongly mark spines as tier 0.
    
    Solution: use fabric degree analysis to distinguish real leaves from
    host-connected spines. In Clos, a leaf's fabric degree (after removing
    hosts) is LOWER than its neighbors' average degree, because leaves only
    connect upward to spines. A spine connects to both leaves AND cores,
    giving it a higher degree than its individual neighbors' average.
    """
    if not neighbors:
        return {}
    
    tiers = {h: -1 for h in hosts}
    
    # Build fabric-only neighbor graph (exclude hosts)
    fabric_nbrs = {}
    for device, nbrs in neighbors.items():
        if device in hosts:
            continue
        clean = {n for n in nbrs if n not in hosts}
        if clean:
            fabric_nbrs[device] = clean
    
    if not fabric_nbrs:
        return tiers
    
    # ── Step 1: Find host-connected fabric devices ──
    host_connected = set()
    for device, nbrs in neighbors.items():
        if device in hosts or device not in fabric_nbrs:
            continue
        if any(n in hosts for n in nbrs):
            host_connected.add(device)
    
    if not host_connected:
        # No hosts detected at all — mark everything tier 0
        for d in fabric_nbrs:
            tiers[d] = 0
        return tiers
    
    # ── Step 2: Degree-based real leaf identification ──
    # Calculate fabric degree for every device (host connections excluded)
    degrees = {d: len(nbrs) for d, nbrs in fabric_nbrs.items()}
    
    # A real leaf has degree <= average of its neighbors' degrees.
    # A spine with host bonds has degree > average (it connects to
    # both leaves below AND cores above, inflating its degree).
    real_leaves = set()
    for device in host_connected:
        d_self = degrees.get(device, 0)
        nbrs = fabric_nbrs.get(device, set())
        if not nbrs:
            real_leaves.add(device)
            continue
        d_nbrs_avg = sum(degrees.get(n, 0) for n in nbrs) / len(nbrs)
        if d_self <= d_nbrs_avg:
            real_leaves.add(device)
    
    # Fallback: if ALL host-connected devices have high degree (all are spines),
    # take their lowest-degree fabric neighbors as real leaves instead.
    if not real_leaves:
        candidates = set()
        for device in host_connected:
            for nbr in fabric_nbrs.get(device, set()):
                if nbr not in host_connected:
                    candidates.add(nbr)
        if candidates:
            min_deg = min(degrees.get(d, 0) for d in candidates)
            real_leaves = {d for d in candidates
                          if degrees.get(d, 0) <= min_deg * 1.5}
    
    # Last resort: use host-connected as-is (original BFS behavior)
    if not real_leaves:
        real_leaves = host_connected
    
    # ── Step 3: BFS from real leaves ──
    for d in real_leaves:
        tiers[d] = 0
    
    visited = set(real_leaves) | hosts
    current_set = set(real_leaves)
    current_tier = 0
    
    while current_set:
        next_set = set()
        for device in current_set:
            for nbr in fabric_nbrs.get(device, set()):
                if nbr not in visited:
                    next_set.add(nbr)
                    visited.add(nbr)
        if next_set:
            current_tier += 1
            for d in next_set:
                tiers[d] = current_tier
        current_set = next_set
    
    # Any unreachable fabric device defaults to leaf
    for d in fabric_nbrs:
        if d not in tiers:
            tiers[d] = 0
    
    return tiers

def find_border_leaf_devices(src_vrf, all_data, tier_func):
    """Find ALL border leaves for inter-VRF / external traffic.
    
    Uses majority analysis: most leaves share the same default route
    nexthop pattern (pointing to spines). Border leaves have a DIFFERENT
    nexthop pattern (pointing to firewalls/routers).
    
    The "nexthop signature" is the set of /24 subnets of the ECMP nexthops.
    The most common signature = regular leaves. Outliers = border leaves.
    This is fully generic — no hardcoded IPs or hostname patterns.
    """
    # Collect each leaf's default route nexthop signature
    leaf_signatures = {}  # hostname -> frozenset of /24 subnets
    
    for hostname, data in all_data.items():
        # Don't filter by tier — border leaves may get wrong tier from BFS
        # (they're not host-connected so BFS discovers them late).
        # The majority analysis itself separates border from non-border.
        if tier_func(hostname) < 0:  # only skip hosts (tier -1)
            continue
        
        routes = data.get('routes', {}).get(src_vrf, [])
        for r in routes:
            if r.get('prefix') != '0.0.0.0/0':
                continue
            
            nh = r.get('nexthop', '')
            nh_subnets = set()
            
            if nh and nh not in ('', '-', 'ECMP', 'link-local', 'unreachable', 'connected'):
                # Single nexthop: extract /24 subnet
                parts = nh.split('.')
                if len(parts) == 4:
                    nh_subnets.add('.'.join(parts[:3]))
            
            if nh == 'ECMP':
                ecmp_nhs = r.get('ecmp_nexthops', [])
                for enh in ecmp_nhs:
                    enh_ip = enh.get('ip', '')
                    parts = enh_ip.split('.')
                    if len(parts) == 4:
                        nh_subnets.add('.'.join(parts[:3]))
            
            if nh_subnets:
                leaf_signatures[hostname] = frozenset(nh_subnets)
            break
    
    if not leaf_signatures:
        return []
    
    # Find the most common signature (= regular leaves pointing to spines)
    from collections import Counter
    sig_counts = Counter(leaf_signatures.values())
    most_common_sig = sig_counts.most_common(1)[0][0] if sig_counts else None
    
    if not most_common_sig:
        return []
    
    # Border leaves = leaves with a DIFFERENT signature than the majority
    border_leaves = [h for h, sig in leaf_signatures.items()
                     if sig != most_common_sig]
    
    return sorted(border_leaves)

# ─── Main logic ───

try:
    all_data = load_all_data()
    if not all_data:
        print(json.dumps({"error": "No cached data. Run Fabric Scan first."}))
        exit()
    
    lldp_neighbors, lldp_port_neighbors, lldp_link_status = load_lldp_data()
    known_hosts = build_host_set(all_data, lldp_port_neighbors)
    device_tiers = determine_tiers(lldp_neighbors, known_hosts)
    
    # ─── Find device by IP (prefer leaf tier) ───
    
    def get_tier(hostname):
        b = base(hostname)
        if hostname in device_tiers: return device_tiers[hostname]
        if b in device_tiers: return device_tiers[b]
        for d, t in device_tiers.items():
            if base(d) == b: return t
        return 999
    
    def find_device_prefer_leaf(ip, prefer_vrf=None):
        candidates = []
        for hostname, data in all_data.items():
            for arp in data.get('arp', []):
                if arp.get('ip') == ip:
                    v = arp.get('vrf', 'default')
                    # Check if this device has a CONNECTED route for the IP's subnet.
                    # Connected route = IP is locally attached = real local leaf.
                    # Remote EVPN-learned ARP entries exist on all leaves but
                    # only the local leaf has the connected route.
                    is_local = 0  # 0 = local (best), 1 = remote
                    has_connected = False
                    for route in data.get('routes', {}).get(v, []):
                        if route.get('protocol') in ('connected', 'kernel', 'local'):
                            if route.get('prefix') and prefix_match(ip, route['prefix']) >= 0:
                                has_connected = True
                                break
                    is_local = 0 if has_connected else 1
                    # Fabric degree: leaf has fewer fabric neighbors than spine.
                    # Use this to prefer leaf over spine when both have connected routes.
                    b = base(hostname)
                    fab_degree = len([n for n in lldp_neighbors.get(b, set())
                                     if n not in known_hosts])
                    candidates.append((hostname, v if v else 'default', is_local, fab_degree))
        if not candidates:
            for hostname, data in all_data.items():
                for v, vr in data.get('routes', {}).items():
                    for r in vr:
                        if r.get('protocol') in ['kernel', 'connected', 'local']:
                            if r.get('prefix') and prefix_match(ip, r['prefix']) >= 0:
                                b = base(hostname)
                                fab_degree = len([n for n in lldp_neighbors.get(b, set())
                                                 if n not in known_hosts])
                                candidates.append((hostname, v, 0, fab_degree))
        if not candidates:
            return None, None
        # Sort: prefer matching VRF, then local (connected route), then lowest degree (leaf < spine)
        def sort_key(x):
            vrf_match = 0 if (prefer_vrf and x[1] == prefer_vrf) else 1
            return (vrf_match, x[2], x[3])  # vrf_match, is_local, fab_degree
        candidates.sort(key=sort_key)
        return candidates[0][0], candidates[0][1]
    
    # ─── Find on-path devices using LLDP neighbors ───
    
    def get_lldp_neighbors(device_name):
        """Get LLDP neighbors for a device (try base name match)."""
        b = base(device_name)
        if b in lldp_neighbors:
            return lldp_neighbors[b]
        for d, nbrs in lldp_neighbors.items():
            if base(d) == b:
                return nbrs
        return set()
    
    def get_link_health(src_device, dst_devices):
        """Count up/down links between src and a set of dst devices."""
        up, down = 0, 0
        b_src = base(src_device)
        for dst in dst_devices:
            b_dst = base(dst)
            for (a, b_key), status in lldp_link_status.items():
                if (a == b_src and b_key == b_dst) or (a == b_dst and b_key == b_src):
                    up += status.get('up', 0)
                    down += status.get('down', 0) + status.get('fail', 0)
        return up, down
    
    def find_on_path_layers(src_device, dst_device):
        """Find spine and core layers between source and dest using LLDP.
        Returns list of layers, each layer is a list of device names.
        
        Tier-independent approach: instead of relying on BFS tier numbers
        (which can be wrong when not all leaves have hosts), we identify
        spines as "LLDP neighbors of a leaf that are NOT hosts and NOT
        other leaves". Cores are "spine neighbors that bridge to the
        other pod's spines".
        """
        src_nbrs = get_lldp_neighbors(src_device)
        dst_nbrs = get_lldp_neighbors(dst_device)
        
        # Spine = LLDP neighbor of leaf that is:
        #   - NOT a host (tier -1)
        #   - NOT the other leaf
        #   - EXISTS in fabric data (all_data) → excludes firewalls, routers, etc.
        def is_fabric_device(d):
            """Check if device exists in fabric-scan data (managed switch)."""
            b = base(d)
            return any(base(k) == b for k in all_data)
        
        src_spines = sorted([d for d in src_nbrs
                            if d not in known_hosts and get_tier(d) != -1
                            and d != dst_device and is_fabric_device(d)])
        dst_spines = sorted([d for d in dst_nbrs
                            if d not in known_hosts and get_tier(d) != -1
                            and d != src_device and is_fabric_device(d)])
        
        # Shared spines (same pod)
        shared = sorted(set(src_spines) & set(dst_spines))
        
        if shared:
            # Same pod: leaf → shared_spines → leaf (3-stage)
            # In Clos, same-pod traffic NEVER goes through cores.
            # Single spine layer — ascending and descending are the SAME devices.
            return [
                {"tier": 1, "devices": shared, "label": "Spine"}
            ]
        else:
            # Cross-pod: leaf → src_spines → cores → dst_spines → leaf
            # Core = neighbor of src_spine that also connects to any dst_spine.
            # Must NOT be a src_spine or dst_spine itself (avoid spine-to-spine).
            all_spines = set(src_spines) | set(dst_spines)
            dst_spines_set = set(dst_spines)
            cores = set()
            for spine in src_spines:
                for nbr in get_lldp_neighbors(spine):
                    if nbr in all_spines or nbr in known_hosts:
                        continue  # skip other spines and hosts
                    # Check if this device bridges to dst pod
                    nbr_neighbors = get_lldp_neighbors(nbr)
                    if dst_spines_set & nbr_neighbors:
                        cores.add(nbr)
            
            layers = []
            if src_spines:
                layers.append({"tier": 1, "devices": src_spines, "label": "Spine"})
            if cores:
                layers.append({"tier": 2, "devices": sorted(cores), "label": "Core"})
            if dst_spines and dst_spines != src_spines:
                layers.append({"tier": 1, "devices": dst_spines, "label": "Spine"})
            
            return layers
    
    # ─── Resolve source and dest ───
    
    source_leaf, detected_vrf = find_device_prefer_leaf(source_ip, vrf_hint)
    dest_leaf, dest_vrf = find_device_prefer_leaf(dest_ip, vrf_hint)
    
    if not source_leaf:
        print(json.dumps({"error": f"Source IP {source_ip} not found in any device."}))
        exit()
    
    # Check if dest IP is local to the fabric (in ANY device's ARP, any VRF).
    # Must check BEFORE error handling — external IPs (8.8.8.8) won't be in
    # any device and that's OK.
    dest_is_local = False
    for hn, dd in all_data.items():
        for arp in dd.get('arp', []):
            if arp.get('ip') == dest_ip:
                dest_is_local = True
                break
        if dest_is_local:
            break
    
    # External IPs: find_device_prefer_leaf may return a wrong device via
    # route fallback (e.g. 8.8.8.8 matching a wide connected prefix).
    # Clear it — external destinations have no fabric device.
    if not dest_is_local:
        dest_leaf = None
    
    # Only error if dest is local but device not found (shouldn't happen)
    if not dest_leaf and dest_is_local:
        print(json.dumps({"error": f"Destination IP {dest_ip} not found in any device."}))
        exit()
    
    # VRF resolution: use explicit hints from user, fall back to auto-detect.
    src_vrf = vrf_hint if vrf_hint else (detected_vrf or 'default')
    dst_vrf = dst_vrf_hint if dst_vrf_hint else src_vrf
    vrf = src_vrf
    
    # ─── Dest VRF validation ───
    # If user manually selected a dest VRF, verify the dest IP actually
    # exists in that VRF. If it doesn't, auto-correct to the VRF where
    # the IP was actually found (from ARP). This prevents false inter-VRF
    # paths when user selects wrong VRF.
    if dest_is_local and dst_vrf_hint and dest_vrf:
        # dest_vrf = VRF where find_device_prefer_leaf found the dest IP
        # dst_vrf_hint = what user selected
        if dst_vrf_hint != dest_vrf:
            # Check if dest IP truly exists in the user-selected VRF
            dest_in_selected_vrf = False
            for hn, dd in all_data.items():
                for arp in dd.get('arp', []):
                    if arp.get('ip') == dest_ip:
                        v = arp.get('vrf', 'default')
                        if (v or 'default') == dst_vrf_hint:
                            dest_in_selected_vrf = True
                            break
                if dest_in_selected_vrf:
                    break
            
            if not dest_in_selected_vrf:
                # Dest IP not in selected VRF → auto-correct
                dst_vrf = dest_vrf
    
    # ─── Route leak detection ───
    # If src_vrf != dst_vrf, check if source device has a SPECIFIC route
    # (not just default 0.0.0.0/0) to dest IP in src_vrf. If yes, the
    # dest subnet is leaked into src_vrf → traffic stays in src_vrf,
    # no firewall traversal needed. Treat as intra-VRF.
    route_leak_info = None  # Track leak for UI display
    if src_vrf != dst_vrf and source_leaf and dest_is_local:
        src_data = all_data.get(source_leaf, {})
        leaked_route, leaked_len = find_best_route(dest_ip, src_data.get('routes', {}), src_vrf)
        if leaked_route and leaked_len > 0:
            # Source has a specific route (not default) → leaked route exists
            route_leak_info = {
                "from_vrf": dst_vrf,
                "to_vrf": src_vrf,
                "prefix": leaked_route.get('prefix', ''),
                "protocol": leaked_route.get('protocol', '')
            }
            # Traffic stays in src_vrf, override dst_vrf
            dst_vrf = src_vrf
    
    has_inter_vrf = (src_vrf != dst_vrf)
    
    # External = dest not in fabric ARP (same VRF, traffic exits via border leaf)
    dest_is_external = not dest_is_local and not has_inter_vrf
    has_external = has_inter_vrf  # keep for backward compat in build_path
    
    # ─── Build path ───
    
    def map_to_fabric_name(lldp_name):
        """Map LLDP hostname to fabric-table key."""
        b = base(lldp_name)
        for key in all_data:
            if base(key) == b:
                return key
        return lldp_name
    
    def build_path():
        path = []
        
        # Source endpoint
        path.append({"device": source_ip, "role": "endpoint_src", "indent": 0})
        
        # Source leaf
        src_data = all_data.get(source_leaf, {})
        route, _ = find_best_route(dest_ip, src_data.get('routes', {}), src_vrf)
        path.append({
            "device": source_leaf, "vrf": src_vrf,
            "prefix": route.get('prefix', '') if route else '',
            "nexthop": route.get('nexthop', '') if route else '',
            "protocol": route.get('protocol', '') if route else '',
            "role": "source", "indent": 1
        })
        
        # Same device, same VRF — traffic stays local, no network traversal
        if source_leaf == dest_leaf and not has_external:
            path[1]["role"] = "source+destination"
            path[1]["prefix"] = "local"
            path[1]["nexthop"] = "local switching"
            path[1]["protocol"] = "connected"
            path.append({"device": dest_ip, "role": "endpoint_dst", "indent": 0})
            return path
        
        # ─── Helper functions ───
        def make_layer_hop(devices, vrf, indent, label, tier=1):
            """Create a hop dict for a layer of devices."""
            if len(devices) == 1:
                return {"device": devices[0], "vrf": vrf, "role": "transit",
                        "indent": indent, "label": label, "tier": tier}
            return {"device": f'{label} ({len(devices)} devices)',
                    "devices": devices, "vrf": vrf, "role": "ecmp", "indent": indent, "tier": tier}
        
        def add_ascending(path, layers, vrf, base_indent=2):
            """Add ascending layers (indent increases: 2, 3, 4, ...)."""
            for idx, layer in enumerate(layers):
                devices = sorted(set(map_to_fabric_name(d) for d in layer["devices"]))
                path.append(make_layer_hop(devices, vrf, base_indent + idx, layer["label"], layer.get("tier", 1)))
        
        def add_descending(path, layers, vrf):
            """Add descending layers (indent decreases from peak)."""
            if not layers:
                return
            peak = max(h.get('indent', 0) for h in path)
            for idx, layer in enumerate(layers):
                devices = sorted(set(map_to_fabric_name(d) for d in layer["devices"]))
                indent = max(2, peak - idx - 1)
                path.append(make_layer_hop(devices, vrf, indent, layer["label"], layer.get("tier", 1)))
        
        # ─── Helper: make border hop (single or ECMP group) ───
        def make_border_hop(borders, vrf, indent):
            """Create a border leaf hop — single device or ECMP group."""
            if len(borders) == 1:
                return {"device": borders[0], "vrf": vrf,
                        "role": "border", "indent": indent, "label": "Border Leaf"}
            return {"device": f'Border Leaf ({len(borders)} devices)',
                    "devices": borders, "vrf": vrf,
                    "role": "border", "indent": indent}
        
        # ─── Build intermediate path ───
        if has_external:
            # ── Inter-VRF: Source → Border → External GW → Border → Dest ──
            # Try src VRF first, then dst VRF (border leaf may only have route in one)
            borders = find_border_leaf_devices(src_vrf, all_data, get_tier)
            if not borders:
                borders = find_border_leaf_devices(dst_vrf, all_data, get_tier)
            border = borders[0] if borders else None
            
            if borders:
                # Source → fabric layers → Border
                if border != source_leaf:
                    s2b = find_on_path_layers(source_leaf, border)
                    s2b_asc = s2b[: (len(s2b) + 1) // 2]
                    s2b_desc = s2b[(len(s2b) + 1) // 2:]
                    add_ascending(path, s2b_asc, src_vrf)
                    add_descending(path, s2b_desc, src_vrf)
                    peak = max(h.get('indent', 0) for h in path)
                    path.append(make_border_hop(borders, src_vrf, peak + 1))
                else:
                    path[-1]["label"] = "Source & Border Leaf"
                
                ext_indent = max(h.get('indent', 0) for h in path) + 1
                path.append({"device": "External Gateway", "role": "external",
                             "indent": ext_indent, "src_vrf": src_vrf, "dst_vrf": dst_vrf})
                
                # Border → fabric layers → Dest (symmetric descent)
                border_indent = ext_indent - 1
                path.append(make_border_hop(borders, dst_vrf, border_indent))
                
                if border != dest_leaf:
                    b2d = find_on_path_layers(border, dest_leaf)
                    for idx, layer in enumerate(b2d):
                        devices = sorted(set(map_to_fabric_name(d) for d in layer["devices"]))
                        layer_indent = max(2, border_indent - idx - 1)
                        path.append(make_layer_hop(devices, dst_vrf, layer_indent, layer["label"], layer.get("tier", 1)))
            else:
                layers = find_on_path_layers(source_leaf, dest_leaf)
                asc = layers[: (len(layers) + 1) // 2]
                desc = layers[(len(layers) + 1) // 2:]
                add_ascending(path, asc, src_vrf)
                peak = max(h.get('indent', 0) for h in path) + 1
                path.append({"device": "External Gateway", "role": "external",
                             "indent": peak, "src_vrf": src_vrf, "dst_vrf": dst_vrf})
                add_descending(path, desc, dst_vrf)
            
            # Dest leaf + endpoint
            dest_hop = {"device": dest_leaf, "vrf": dst_vrf,
                        "prefix": "local", "protocol": "connected",
                        "role": "destination", "indent": 1}
            # Mark if dest leaf is also a border leaf
            if borders and dest_leaf in [map_to_fabric_name(b) for b in borders]:
                dest_hop["label"] = "Destination & Border Leaf"
            path.append(dest_hop)
            path.append({"device": dest_ip, "role": "endpoint_dst", "indent": 0})
        
        elif dest_is_external:
            # ── External dest (same VRF): Source → Spines → Border → External → dest ──
            # One-way flow: indent keeps increasing (drilling deeper toward exit)
            borders = find_border_leaf_devices(src_vrf, all_data, get_tier)
            border = borders[0] if borders else None
            
            if borders:
                if border != source_leaf:
                    s2b = find_on_path_layers(source_leaf, border)
                    # Add ALL layers as ascending (one-way, no descent)
                    add_ascending(path, s2b, src_vrf)
                
                peak = max(h.get('indent', 0) for h in path) + 1
                path.append(make_border_hop(borders, src_vrf, peak))
                path.append({"device": "External Network", "role": "external",
                             "indent": peak + 1, "src_vrf": src_vrf, "dst_vrf": "external"})
            else:
                layers = find_on_path_layers(source_leaf, dest_leaf)
                add_ascending(path, layers, src_vrf)
                peak = max(h.get('indent', 0) for h in path) + 1
                path.append({"device": "External Network", "role": "external",
                             "indent": peak, "src_vrf": src_vrf, "dst_vrf": "external"})
            
            # Dest endpoint (traffic exits fabric)
            path.append({"device": dest_ip, "role": "endpoint_dst", "indent": 0})
        
        else:
            # ── Same-VRF local: Source → layers → Dest ──
            layers = find_on_path_layers(source_leaf, dest_leaf)
            asc = layers[: (len(layers) + 1) // 2]
            desc = layers[(len(layers) + 1) // 2:]
            add_ascending(path, asc, src_vrf)
            add_descending(path, desc, src_vrf)
            
            # Dest leaf + endpoint
            path.append({"device": dest_leaf, "vrf": src_vrf,
                         "prefix": "local", "protocol": "connected",
                         "role": "destination", "indent": 1})
            path.append({"device": dest_ip, "role": "endpoint_dst", "indent": 0})
        
        return path
    
    path = build_path()
    
    # ─── Post-process: enrich ECMP/transit hops with link health ───
    
    def enrich_link_health(path):
        """Add links_up / links_down to ECMP and transit hops.
        
        For each ECMP/transit hop, check LLDP link status between it and
        its adjacent hops (previous and next). This gives:
          - ascending spines: link health from source leaf → spines
          - descending spines: link health from spines → dest leaf
          - cores: link health from spines → cores (both sides)
        """
        for i, hop in enumerate(path):
            if hop.get('role') not in ('ecmp', 'transit'):
                continue
            
            # Get this hop's actual device list
            ecmp_devs = hop.get('devices', [])
            if not ecmp_devs:
                d = hop.get('device', '')
                if d:
                    ecmp_devs = [d]
            ecmp_devs = [base(d) for d in ecmp_devs if d]
            if not ecmp_devs:
                continue
            
            total_up, total_down = 0, 0
            
            # Check links FROM previous hop → this layer
            if i > 0:
                prev = path[i - 1]
                if prev.get('role') not in ('endpoint_src', 'endpoint_dst', 'external'):
                    pdevs = prev.get('devices', [])
                    if not pdevs:
                        pd = prev.get('device', '')
                        if pd:
                            pdevs = [pd]
                    for pd in pdevs:
                        u, d = get_link_health(base(pd), ecmp_devs)
                        total_up += u
                        total_down += d
            
            # Check links FROM this layer → next hop
            if i < len(path) - 1:
                nxt = path[i + 1]
                if nxt.get('role') not in ('endpoint_src', 'endpoint_dst', 'external'):
                    ndevs = nxt.get('devices', [])
                    if not ndevs:
                        nd = nxt.get('device', '')
                        if nd:
                            ndevs = [nd]
                    for nd in ndevs:
                        u, d = get_link_health(base(nd), ecmp_devs)
                        total_up += u
                        total_down += d
            
            if total_up > 0 or total_down > 0:
                hop['links_up'] = total_up
                hop['links_down'] = total_down
    
    enrich_link_health(path)
    
    vrf_display = f"{src_vrf} -> {dst_vrf}" if has_external else vrf
    if dest_is_external:
        vrf_display = f"{src_vrf} -> external"
    
    result = {
        "path": path,
        "source_device": source_leaf,
        "source_ip": source_ip,
        "destination": dest_ip,
        "vrf": vrf_display,
        "inter_vrf": has_external,
        "tiers_found": len(set(device_tiers.values())) if device_tiers else 0
    }
    # Only include dest_device for fabric-local destinations
    if dest_is_local and dest_leaf:
        result["dest_device"] = dest_leaf
    
    # Include route leak info if detected
    if route_leak_info:
        result["route_leak"] = route_leak_info
    
    print(json.dumps(result))

except Exception as e:
    import traceback
    print(json.dumps({"error": str(e), "detail": traceback.format_exc()}))
PYTHON
}

# Detect VRFs that have a route to given IP on a specific device
detect_vrfs() {
    local device="$1"
    local dest_ip="$2"
    
    python3 - "$device" "$dest_ip" <<'PYTHON'
import json
import os
import ipaddress
import sys

device = sys.argv[1]
dest_ip = sys.argv[2]

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"

def prefix_match(ip, prefix):
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        ip_addr = ipaddress.ip_address(ip)
        if ip_addr in network:
            return network.prefixlen
        return -1
    except:
        return -1

try:
    filepath = os.path.join(tables_dir, f"{device}.json")
    
    if not os.path.exists(filepath):
        print(json.dumps({"vrfs": ["default"]}))
        exit()
    
    with open(filepath) as f:
        data = json.load(f)
    
    routes = data.get('routes', {})
    matching_vrfs = []
    
    for vrf, vrf_routes in routes.items():
        for route in vrf_routes:
            prefix = route.get('prefix', '')
            if prefix and prefix_match(dest_ip, prefix) >= 0:
                if vrf not in matching_vrfs:
                    matching_vrfs.append(vrf)
                break
    
    if not matching_vrfs:
        matching_vrfs = ['default']
    
    print(json.dumps({"vrfs": sorted(matching_vrfs)}))

except Exception as e:
    print(json.dumps({"vrfs": ["default"], "error": str(e)}))
PYTHON
}

# Trace path from source device to destination IP
trace_path() {
    local dest_ip="$1"
    local vrf="$2"
    local source="$3"
    
    python3 - "$dest_ip" "$vrf" "$source" <<'PYTHON'
import json
import os
import ipaddress
import sys

dest_ip = sys.argv[1]
vrf = sys.argv[2] or "default"
source_device = sys.argv[3]

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"

def prefix_match(ip, prefix):
    """Check if IP matches prefix and return prefix length."""
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        ip_addr = ipaddress.ip_address(ip)
        if ip_addr in network:
            return network.prefixlen
        return -1
    except:
        return -1

def find_best_route(ip, routes, vrf):
    """Find the best matching route for an IP in a VRF."""
    vrf_routes = routes.get(vrf, [])
    best_match = None
    best_prefix_len = -1
    
    for route in vrf_routes:
        prefix = route.get('prefix', '')
        if not prefix:
            continue
        
        match_len = prefix_match(ip, prefix)
        if match_len > best_prefix_len:
            best_prefix_len = match_len
            best_match = route
    
    return best_match, best_prefix_len

def load_all_data():
    """Load all fabric table data."""
    all_data = {}
    
    if not os.path.exists(tables_dir):
        return all_data
    
    for filename in os.listdir(tables_dir):
        if not filename.endswith('.json') or filename == 'summary.json':
            continue
        
        hostname = filename.replace('.json', '')
        filepath = os.path.join(tables_dir, filename)
        
        try:
            with open(filepath) as f:
                all_data[hostname] = json.load(f)
        except:
            pass
    
    return all_data

def find_device_by_nexthop(nexthop_ip, all_data, exclude_devices, vrf):
    """Find which device has the nexthop IP as its interface."""
    for hostname, data in all_data.items():
        if hostname in exclude_devices:
            continue
        
        # Check ARP entries - nexthop might be in ARP
        for arp in data.get('arp', []):
            if arp.get('ip') == nexthop_ip:
                # This device knows about the nexthop
                pass
        
        # Check routes - connected routes show interface IPs
        routes = data.get('routes', {})
        for vrf_name, vrf_routes in routes.items():
            for route in vrf_routes:
                prefix = route.get('prefix', '')
                protocol = route.get('protocol', '')
                
                # Connected/kernel routes indicate local IPs
                if protocol in ['kernel', 'connected', 'local']:
                    if prefix and '/' in prefix:
                        # Check if nexthop is in this connected network
                        if prefix_match(nexthop_ip, prefix) >= 0:
                            return hostname
    
    return None

def is_destination_local(dest_ip, device_data, vrf):
    """Check if destination IP is local to this device."""
    routes = device_data.get('routes', {})
    vrf_routes = routes.get(vrf, [])
    
    for route in vrf_routes:
        prefix = route.get('prefix', '')
        protocol = route.get('protocol', '')
        
        if protocol in ['kernel', 'connected', 'local']:
            if prefix and prefix_match(dest_ip, prefix) >= 0:
                return True
    
    # Also check ARP
    for arp in device_data.get('arp', []):
        if arp.get('ip') == dest_ip:
            return True
    
    return False

try:
    all_data = load_all_data()
    
    if not all_data:
        print(json.dumps({"error": "No cached data. Run Fabric Scan first."}))
        exit()
    
    if source_device not in all_data:
        print(json.dumps({"error": f"Source device '{source_device}' not found in cached data."}))
        exit()
    
    path = []
    visited = set()
    current_device = source_device
    max_hops = 10
    matched_prefix = None
    
    for hop_num in range(max_hops):
        if current_device in visited:
            # Loop detected
            break
        
        visited.add(current_device)
        device_data = all_data.get(current_device, {})
        
        if not device_data:
            break
        
        # Check if destination is local to this device
        if is_destination_local(dest_ip, device_data, vrf):
            hop = {
                "device": current_device,
                "vrf": vrf,
                "prefix": "local",
                "nexthop": dest_ip,
                "interface": "",
                "protocol": "connected",
                "is_destination": True
            }
            path.append(hop)
            break
        
        # Find best route
        routes = device_data.get('routes', {})
        best_route, prefix_len = find_best_route(dest_ip, routes, vrf)
        
        if not best_route:
            # No route found
            hop = {
                "device": current_device,
                "vrf": vrf,
                "prefix": "no route",
                "nexthop": "",
                "interface": "",
                "protocol": "",
                "is_dead_end": True
            }
            path.append(hop)
            break
        
        if not matched_prefix or prefix_len > prefix_match(dest_ip, matched_prefix):
            matched_prefix = best_route.get('prefix', '')
        
        hop = {
            "device": current_device,
            "vrf": vrf,
            "prefix": best_route.get('prefix', ''),
            "nexthop": best_route.get('nexthop', ''),
            "interface": best_route.get('interface', ''),
            "protocol": best_route.get('protocol', '')
        }
        path.append(hop)
        
        # Find next hop device
        nexthop = best_route.get('nexthop', '')
        
        if not nexthop or nexthop in ['', 'ECMP']:
            # Connected route or ECMP - destination should be reachable
            break
        
        next_device = find_device_by_nexthop(nexthop, all_data, visited, vrf)
        
        if not next_device:
            # Can't find next device - might be external
            break
        
        current_device = next_device
    
    if path:
        result = {
            "path": path,
            "matched_prefix": matched_prefix,
            "source": source_device,
            "destination": dest_ip,
            "vrf": vrf
        }
    else:
        result = {
            "path": [],
            "error": f"No route from {source_device} to {dest_ip} in VRF {vrf}"
        }
    
    print(json.dumps(result))

except Exception as e:
    import traceback
    print(json.dumps({"error": str(e), "trace": traceback.format_exc()}))
PYTHON
}

# Search cached fabric tables (fast)
search_cached_tables() {
    local table_type="$1"
    local search="$2"
    
    python3 - "$table_type" "$search" <<'PYTHON'
import json
import os
import re
import sys

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
table_type = sys.argv[1]
search = sys.argv[2].lower()

# Detect if search is a full IP (4 octets) → use exact match on IP/ip fields
is_full_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', search))

entries = []

try:
    if not os.path.exists(tables_dir):
        print(json.dumps({"success": False, "error": "No cached data. Run Fabric Scan first."}))
        exit()
    
    for filename in os.listdir(tables_dir):
        if not filename.endswith('.json') or filename == 'summary.json':
            continue
        
        hostname = filename.replace('.json', '')
        filepath = os.path.join(tables_dir, filename)
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            
            table_data = data.get(table_type, [])
            
            for entry in table_data:
                entry['device'] = hostname
                
                # Filter by search term
                if search:
                    if is_full_ip and table_type == 'arp':
                        # Full IP: exact match on IP field only (avoid 192.168.64.11 matching .111)
                        if entry.get('ip', '') != search:
                            continue
                    else:
                        # Substring match for partial IP, MAC, hostname searches
                        match = False
                        for val in entry.values():
                            if search in str(val).lower():
                                match = True
                                break
                        if not match:
                            continue
                
                # Skip VRR interfaces for ARP
                if table_type == 'arp':
                    iface = entry.get('interface', '')
                    if re.search(r'-v\d+$', iface):
                        continue
                
                entries.append(entry)
        except:
            continue
    
    print(json.dumps({
        "success": True,
        "entries": entries[:500],
        "total": len(entries),
        "cached": True
    }))

except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
PYTHON
}

# Main routing
parse_query

case "$ACTION" in
    "list-devices")
        list_devices
        ;;
    "get-mac")
        get_mac_table "$DEVICE" "$SEARCH"
        ;;
    "get-arp")
        get_arp_table "$DEVICE" "$SEARCH"
        ;;
    "get-all-mac")
        get_all_tables "mac" "$SEARCH"
        ;;
    "get-all-arp")
        get_all_tables "arp" "$SEARCH"
        ;;
    "get-vtep")
        get_vtep_table "$DEVICE" "$SEARCH"
        ;;
    "get-route")
        get_route_table "$DEVICE" "$SEARCH"
        ;;
    "get-lldp")
        get_lldp_neighbors "$DEVICE" "$SEARCH"
        ;;
    "get-bond-members")
        BOND=$(echo "$QUERY_STRING" | grep -oE 'bond=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        get_bond_members "$DEVICE" "$BOND"
        ;;
    "scan-status")
        get_scan_status
        ;;
    "run-scan")
        run_fabric_scan
        ;;
    "search-cached-mac")
        search_cached_tables "mac" "$SEARCH"
        ;;
    "search-cached-arp")
        search_cached_tables "arp" "$SEARCH"
        ;;
    "search-cached-vtep")
        search_cached_tables "vtep" "$SEARCH"
        ;;
    "search-cached-lldp")
        search_cached_tables "lldp" "$SEARCH"
        ;;
    "search-cached-routes")
        search_cached_routes "$SEARCH"
        ;;
    "trace-path")
        IP=$(echo "$QUERY_STRING" | grep -oE 'ip=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        VRF=$(echo "$QUERY_STRING" | grep -oE 'vrf=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        SOURCE=$(echo "$QUERY_STRING" | grep -oE 'source=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        trace_path "$IP" "$VRF" "$SOURCE"
        ;;
    "detect-vrfs")
        IP=$(echo "$QUERY_STRING" | grep -oE 'ip=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        detect_vrfs "$DEVICE" "$IP"
        ;;
    "find-ip-vrf")
        IP=$(echo "$QUERY_STRING" | grep -oE 'ip=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        find_ip_vrf "$IP"
        ;;
    "trace-path-ip")
        SOURCE_IP=$(echo "$QUERY_STRING" | grep -oE 'source_ip=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        DEST_IP=$(echo "$QUERY_STRING" | grep -oE 'dest_ip=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        VRF=$(echo "$QUERY_STRING" | grep -oE 'vrf=[^&]+' | head -1 | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        DST_VRF=$(echo "$QUERY_STRING" | grep -oE 'dst_vrf=[^&]+' | cut -d= -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        trace_path_ip "$SOURCE_IP" "$DEST_IP" "$VRF" "$DST_VRF"
        ;;
    "get-vrfs")
        get_vrfs
        ;;
    *)
        echo '{"success": false, "error": "Invalid action"}'
        ;;
esac
