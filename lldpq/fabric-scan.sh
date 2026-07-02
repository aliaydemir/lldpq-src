#!/usr/bin/env bash
# Fabric Table Scanner - Collects MAC/ARP/Route tables from all devices
# Results stored in monitor-results/fabric-tables/ for fast search

# Load allowlisted config data through the fixed, root-owned parser.
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
LLDPQ_DIR="${LLDPQ_DIR:-$HOME/lldpq}"
cd "$LLDPQ_DIR"

# Configuration
MAX_PARALLEL=100
SSH_TIMEOUT=10
OUTPUT_DIR="monitor-results/fabric-tables"
DEVICES_FILE="devices.yaml"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Get device list from devices.yaml
get_devices() {
    python3 << 'PYEOF'
import yaml
import sys

try:
    with open('devices.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    defaults = data.get('defaults', {})
    default_username = defaults.get('username', 'cumulus')
    
    devices = data.get('devices', data)
    for ip, info in devices.items():
        if ip in ['defaults', 'endpoint_hosts']:
            continue
        if isinstance(info, dict):
            hostname = info.get('hostname', ip)
            username = info.get('username', default_username)
        elif isinstance(info, str):
            # Keep hostname with @role suffix for grouped file naming
            hostname = info.strip()
            username = default_username
        else:
            hostname = ip
            username = default_username
        print(f"{ip}|{hostname}|{username}")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# Check if host is reachable
# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds 'ip rule' for mgmt VRF so plain ping works. No ip vrf exec needed.
PING="ping"

is_reachable() {
    local ip="$1"
    $PING -c 1 -W 1 "$ip" >/dev/null 2>&1
}

# Collect data from a single device
collect_device_data() {
    local ip="$1"
    local hostname="$2"
    local username="${3:-cumulus}"
    local output_file="$OUTPUT_DIR/${hostname}.json"
    
    # Skip unreachable hosts
    if ! is_reachable "$ip"; then
        echo "SKIP"
        return
    fi
    
    # Collect raw data via SSH
    local raw_data
    raw_data=$(timeout $SSH_TIMEOUT ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes "${username}@${ip}" '
        echo "===ARP==="
        /usr/sbin/ip neigh show 2>/dev/null | head -300
        echo "===VRFMAP==="
        /usr/sbin/ip vrf list 2>/dev/null
        echo "===IFACEVRF==="
        for i in /sys/class/net/vlan*/master /sys/class/net/eth*/master; do
            n=$(basename $(dirname $i) 2>/dev/null)
            m=$(readlink $i 2>/dev/null | xargs basename 2>/dev/null)
            [ -n "$m" ] && echo "$n $m"
        done 2>/dev/null
        echo "===MAC==="
        /usr/sbin/bridge fdb show 2>/dev/null | head -500
        echo "===VTEP==="
        /usr/sbin/bridge fdb show 2>/dev/null | grep "dst " | head -100
        echo "===BOND==="
        for b in /sys/class/net/*/bonding/slaves; do
            [ -f "$b" ] && echo "$(basename $(dirname $(dirname $b))):$(cat $b)"
        done 2>/dev/null
        echo "===LOOPBACKS==="
        /usr/sbin/ip -4 addr show lo 2>/dev/null | grep 'inet ' | awk '{print $2}'
        echo "===NEXTHOPS==="
        /usr/sbin/ip nexthop show 2>/dev/null | head -500
        echo "===ROUTES==="
        echo "VRF:default"
        /usr/sbin/ip route show 2>/dev/null | head -300
        for vrf in $(/usr/sbin/ip vrf list 2>/dev/null | awk "NR>1 {print \$1}"); do
            echo "VRF:$vrf"
            /usr/sbin/ip route show vrf "$vrf" 2>/dev/null | head -300
        done
        echo "===END==="
    ' 2>/dev/null)
    
    if [ -z "$raw_data" ]; then
        echo "FAIL"
        return
    fi
    
    # Parse with Python
    python3 << PYEOF
import json
import re

raw = '''$raw_data'''

# Parse sections
sections = {}
current = None
for line in raw.split('\n'):
    if line.startswith('===') and line.endswith('==='):
        current = line.strip('=')
        sections[current] = []
    elif current:
        sections[current].append(line)

# Build VRF mapping
vrf_list = set()
iface_vrf = {}
for line in sections.get('VRFMAP', []):
    if line and not line.startswith('Name') and not line.startswith('-'):
        parts = line.split()
        if parts:
            vrf_list.add(parts[0])

for line in sections.get('IFACEVRF', []):
    parts = line.split()
    if len(parts) >= 2 and parts[1] in vrf_list:
        iface_vrf[parts[0]] = parts[1]

# Parse ARP
arp_entries = []
for line in sections.get('ARP', []):
    if not line.strip():
        continue
    parts = line.split()
    if len(parts) < 4:
        continue
    ip_addr = parts[0]
    iface = mac = state = ''
    for i, p in enumerate(parts):
        if p == 'dev' and i+1 < len(parts): iface = parts[i+1]
        if p == 'lladdr' and i+1 < len(parts): mac = parts[i+1]
    if parts[-1] in ['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'FAILED', 'PERMANENT']:
        state = parts[-1]
    if mac and not re.search(r'-v\d+$', iface):
        vrf = iface_vrf.get(iface, 'default')
        arp_entries.append({'ip': ip_addr, 'mac': mac, 'interface': iface, 'vrf': vrf, 'state': state})

# Parse MAC
mac_entries = []
for line in sections.get('MAC', []):
    if not line.strip():
        continue
    # Skip permanent entries that are switch's own MACs (usually on bridge interface)
    # But keep physical port entries even if marked permanent
    if 'permanent' in line and 'dev br' in line:
        continue
    parts = line.split()
    if len(parts) < 3:
        continue
    mac = parts[0]
    iface = vlan = ''
    is_permanent = 'permanent' in line
    for i, p in enumerate(parts):
        if p == 'dev' and i+1 < len(parts): iface = parts[i+1]
        if p == 'vlan' and i+1 < len(parts): vlan = parts[i+1]
    # Skip bridge interface entries (switch's own MACs)
    if iface and iface.startswith('br'):
        continue
    if mac and iface:
        entry = {'mac': mac, 'interface': iface, 'vlan': vlan}
        if is_permanent:
            entry['type'] = 'static'
        mac_entries.append(entry)

# Parse VTEP
vtep_entries = []
for line in sections.get('VTEP', []):
    if not line.strip():
        continue
    parts = line.split()
    mac = dst = vni = ''
    if parts:
        mac = parts[0]
    for i, p in enumerate(parts):
        if p == 'dst' and i+1 < len(parts): dst = parts[i+1]
        if p in ['vni', 'src_vni'] and i+1 < len(parts): vni = parts[i+1]
    if dst:
        vtep_entries.append({'mac': mac, 'remote_vtep': dst, 'vni': vni})

# Parse BOND members (format: bondname:swp1 swp2)
bond_members = {}
for line in sections.get('BOND', []):
    if not line.strip() or ':' not in line:
        continue
    bond_name, members = line.split(':', 1)
    if members.strip():
        bond_members[bond_name] = members.strip().split()

# Add bond_ports to MAC entries
for entry in mac_entries:
    iface = entry.get('interface', '')
    if iface in bond_members:
        entry['bond_ports'] = bond_members[iface]

# Parse NEXTHOPS table (ip nexthop show)
# Format: "id 18578 via 10.10.10.4 dev vlan4063_l3 scope link proto zebra onlink"
# Format: "id 40050 group 18578/18635/18652 proto zebra"
nexthop_table = {}  # nhid -> {'via': ip, 'dev': iface} or {'group': [nhid1, nhid2, ...]}
for line in sections.get('NEXTHOPS', []):
    line = line.strip()
    if not line or not line.startswith('id '):
        continue
    parts = line.split()
    nhid = ''
    via = ''
    dev = ''
    group_ids = []
    for i, p in enumerate(parts):
        if p == 'id' and i+1 < len(parts): nhid = parts[i+1]
        if p == 'via' and i+1 < len(parts): via = parts[i+1]
        if p == 'dev' and i+1 < len(parts): dev = parts[i+1]
        if p == 'group' and i+1 < len(parts): group_ids = parts[i+1].split('/')
    if nhid:
        if group_ids:
            nexthop_table[nhid] = {'group': group_ids}
        elif via:
            nexthop_table[nhid] = {'via': via, 'dev': dev}

def resolve_nhid(nhid):
    """Resolve a nexthop ID to a list of (ip, dev) tuples."""
    entry = nexthop_table.get(nhid, {})
    if 'via' in entry:
        return [{'ip': entry['via'], 'interface': entry.get('dev', '')}]
    if 'group' in entry:
        result = []
        for gid in entry['group']:
            sub = nexthop_table.get(gid, {})
            if 'via' in sub:
                result.append({'ip': sub['via'], 'interface': sub.get('dev', '')})
        return result
    return []

# Parse ROUTES (per VRF)
route_entries = {}  # vrf -> list of routes
current_vrf = 'default'
last_ecmp_entry = None  # Track last ECMP route for continuation lines

for line in sections.get('ROUTES', []):
    raw_line = line
    line = line.strip()
    if not line:
        continue
    if line.startswith('VRF:'):
        current_vrf = line[4:]
        if current_vrf not in route_entries:
            route_entries[current_vrf] = []
        last_ecmp_entry = None
        continue
    
    # ECMP continuation line: starts with whitespace + "nexthop"
    # e.g. "        nexthop via 10.0.0.1 dev swp1 weight 1"
    if raw_line.startswith(' ') and 'nexthop' in line and 'via' in line:
        if last_ecmp_entry is not None:
            # Parse individual ECMP nexthop
            nh_parts = line.split()
            nh_ip = ''
            nh_iface = ''
            for i, p in enumerate(nh_parts):
                if p == 'via' and i+1 < len(nh_parts): nh_ip = nh_parts[i+1]
                if p == 'dev' and i+1 < len(nh_parts): nh_iface = nh_parts[i+1]
            if nh_ip:
                if 'ecmp_nexthops' not in last_ecmp_entry:
                    last_ecmp_entry['ecmp_nexthops'] = []
                last_ecmp_entry['ecmp_nexthops'].append({'ip': nh_ip, 'interface': nh_iface})
        continue
    
    # Parse route line: prefix [via nexthop] [nhid X] [dev interface] [proto protocol] [metric X]
    parts = line.split()
    if not parts:
        continue
    
    prefix = parts[0]
    
    # Convert 'default' to '0.0.0.0/0'
    if prefix == 'default':
        prefix = '0.0.0.0/0'
    
    nexthop = ''
    nhid = ''
    interface = ''
    protocol = ''
    metric = ''
    
    for i, p in enumerate(parts):
        if p == 'via' and i+1 < len(parts): nexthop = parts[i+1]
        if p == 'nhid' and i+1 < len(parts): nhid = parts[i+1]
        if p == 'dev' and i+1 < len(parts): interface = parts[i+1]
        if p == 'proto' and i+1 < len(parts): protocol = parts[i+1]
        if p == 'metric' and i+1 < len(parts): metric = parts[i+1]
    
    # If no via but has nhid, it's ECMP (mark as such)
    if not nexthop and nhid:
        nexthop = 'ECMP'
    
    # Skip unusable routes (linkdown, unreachable, redirect)
    # But KEEP kernel routes with dev (connected subnets - needed for nexthop resolution)
    if 'linkdown' in line or 'unreachable' in line or protocol == 'redirect':
        last_ecmp_entry = None
        continue
    # Skip kernel routes without interface (loopback, etc.) but keep ones with dev
    if protocol == 'kernel' and not interface:
        last_ecmp_entry = None
        continue
    
    if current_vrf not in route_entries:
        route_entries[current_vrf] = []
    
    entry = {
        'prefix': prefix,
        'nexthop': nexthop,
        'interface': interface,
        'protocol': protocol,
        'metric': metric
    }
    
    # Resolve ECMP nexthops from nexthop table
    if nexthop == 'ECMP' and nhid:
        resolved = resolve_nhid(nhid)
        if resolved:
            entry['ecmp_nexthops'] = resolved
    
    route_entries[current_vrf].append(entry)
    
    # Track ECMP entries for continuation lines
    if nexthop == 'ECMP':
        last_ecmp_entry = entry
    else:
        last_ecmp_entry = None

# Parse LOOPBACK IPs
loopback_ips = []
for line in sections.get('LOOPBACKS', []):
    line = line.strip()
    if line and '/' in line:
        ip_part = line.split('/')[0]
        if ip_part != '127.0.0.1':
            loopback_ips.append(ip_part)

result = {
    'arp': arp_entries,
    'mac': mac_entries,
    'vtep': vtep_entries,
    'bonds': bond_members,
    'routes': route_entries,
    'loopbacks': loopback_ips,
    'lldp': []  # Skip LLDP for now to keep it simple
}

with open('$output_file', 'w') as f:
    json.dump(result, f)

print('OK')
PYEOF
}

# Main execution
echo "Fabric Scan - Collecting network tables"
echo "========================================"

# Get devices into array
devices_list=$(get_devices)
device_count=$(echo "$devices_list" | wc -l)

# Clean stale files — remove .json files for devices no longer in devices.yaml
# This handles role changes (old filename stays, new one created)
if [ -d "$OUTPUT_DIR" ]; then
    # Build list of expected hostnames from devices_list
    expected_hosts=$(echo "$devices_list" | awk -F'|' '{print $2}')
    stale_count=0
    for f in "$OUTPUT_DIR"/*.json; do
        [ ! -f "$f" ] && continue
        basename=$(basename "$f" .json)
        [ "$basename" = "summary" ] && continue
        if ! echo "$expected_hosts" | grep -qxF "$basename"; then
            rm -f "$f"
            stale_count=$((stale_count + 1))
        fi
    done
    [ "$stale_count" -gt 0 ] && echo "Cleaned $stale_count stale files"
fi

echo "Devices: $device_count"
echo "Collecting..."

# Parallel collection using temp file for device list
tmp_devices=$(mktemp)
echo "$devices_list" > "$tmp_devices"

job_count=0
while IFS='|' read -r ip hostname username; do
    [ -z "$ip" ] && continue
    username="${username:-cumulus}"
    
    (
        result=$(collect_device_data "$ip" "$hostname" "$username" 2>/dev/null)
        case "$result" in
            OK) echo -n "." ;;
            SKIP) echo -n "-" ;;
            *) echo -n "x" ;;
        esac
    ) &
    
    job_count=$((job_count + 1))
    
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n 2>/dev/null || wait
        job_count=$((job_count - 1))
    fi
done < "$tmp_devices"

# Wait for ALL remaining jobs
wait

rm -f "$tmp_devices"
echo ""

# Create summary file with timestamp
python3 << PYEOF
import os
import json
from datetime import datetime

output_dir = "$OUTPUT_DIR"
summary = {
    "timestamp": datetime.now().isoformat(),
    "devices": []
}

for f in os.listdir(output_dir):
    if f.endswith('.json') and f != 'summary.json':
        hostname = f.replace('.json', '')
        filepath = os.path.join(output_dir, f)
        try:
            with open(filepath) as fp:
                data = json.load(fp)
            summary["devices"].append({
                "hostname": hostname,
                "arp_count": len(data.get("arp", [])),
                "mac_count": len(data.get("mac", [])),
                "vtep_count": len(data.get("vtep", [])),
                "lldp_count": len(data.get("lldp", []))
            })
        except:
            pass

with open(os.path.join(output_dir, "summary.json"), "w") as f:
    json.dump(summary, f, indent=2)

print(f"Scan complete: {len(summary['devices'])} devices")
print(f"Results: {output_dir}/")
PYEOF

exit 0
