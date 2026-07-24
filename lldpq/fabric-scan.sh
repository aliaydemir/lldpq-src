#!/usr/bin/env bash
# Fabric Table Scanner - Collects MAC/ARP/Route tables from all devices
# Results stored in monitor-results/fabric-tables/ for fast search

set -o pipefail

# A scheduled scan must never publish into a fallback tree after a partial
# upgrade. Explicit LLDPQ_DIR remains available to the isolated test harness.
LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
if [[ -x "$LLDPQ_CONFIG_HELPER" ]]; then
    LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
        --require-key LLDPQ_DIR 2>/dev/null) || {
        echo "fabric-scan: required runtime configuration is missing or unreadable" >&2
        exit 1
    }
    eval "$LLDPQ_CONFIG_ASSIGNMENTS"
    unset LLDPQ_CONFIG_ASSIGNMENTS
elif [[ -z "${LLDPQ_DIR:-}" ]]; then
    echo "fabric-scan: required config helper is missing: $LLDPQ_CONFIG_HELPER" >&2
    exit 1
fi
[[ -n "${LLDPQ_DIR:-}" ]] || exit 1

# fabric-scan also runs on its own one-minute cron, so the conf toggle must
# gate the script itself, not only the bin/lldpq pipeline. The explicit web
# "scan now" trigger bypasses the toggle via LLDPQ_FABRIC_SCAN_FORCE=1.
case "$(printf '%s' "${SKIP_FABRIC_SCAN:-false}" | tr '[:upper:]' '[:lower:]')" in
    true|1|yes|y|on)
        if [[ "${LLDPQ_FABRIC_SCAN_FORCE:-0}" != "1" ]]; then
            echo "fabric scan disabled by configuration (SKIP_FABRIC_SCAN)" >&2
            exit 0
        fi
        ;;
esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$LLDPQ_DIR" || exit 1

# Configuration
MAX_PARALLEL="${FABRIC_SCAN_MAX_PARALLEL:-100}"
SSH_TIMEOUT="${FABRIC_SCAN_SSH_TIMEOUT:-60}"
OUTPUT_DIR="${FABRIC_SCAN_OUTPUT_DIR:-monitor-results/fabric-tables}"
DEVICES_FILE="${FABRIC_SCAN_DEVICES_FILE:-devices.yaml}"
PING_BIN="${FABRIC_SCAN_PING_BIN:-ping}"
LOCK_FILE="${FABRIC_SCAN_LOCK_FILE:-/tmp/lldpq-fabric-scan.lock}"

case "$MAX_PARALLEL" in
    ''|*[!0-9]*|0) MAX_PARALLEL=100 ;;
esac
case "$SSH_TIMEOUT" in
    ''|*[!0-9]*|0) SSH_TIMEOUT=60 ;;
esac

if ! command -v flock >/dev/null 2>&1; then
    echo "fabric-scan requires flock (util-linux)" >&2
    exit 1
fi

# The main LLDPq pipeline invokes this scanner after report publication while
# still holding descriptor 9.  Scheduled standalone scans must acquire that
# same global lock first so their SSH fan-out cannot overlap asset, LLDP or
# monitor collection.  Keep the dedicated fabric lock as the second lock in a
# consistent global->fabric order.
global_lock_is_inherited=false
if [[ "${LLDPQ_MONITOR_LOCK_HELD:-0}" == "1" ]] && { : >&9; } 2>/dev/null; then
    global_lock_is_inherited=true
fi
if [[ "$global_lock_is_inherited" != "true" ]]; then
    GLOBAL_LOCK_FILE="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    exec 9>"$GLOBAL_LOCK_FILE" || {
        echo "Could not open LLDPq pipeline lock: $GLOBAL_LOCK_FILE" >&2
        exit 1
    }
    if ! flock -n 9; then
        echo "LLDPq collection is running; scheduled fabric scan skipped" >&2
        exit 75
    fi
    export LLDPQ_MONITOR_LOCK_HELD=1
fi

exec 8>"$LOCK_FILE" || {
    echo "Could not open fabric scan lock: $LOCK_FILE" >&2
    exit 1
}
if ! flock -n 8; then
    echo "Another fabric scan is already running" >&2
    exit 75
fi

STAGING_DIR=""
PUBLISH_DIR=""
cleanup_fabric_scan() {
    [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]] && rm -rf -- "$STAGING_DIR"
    [[ -n "$PUBLISH_DIR" && -e "$PUBLISH_DIR" ]] && rm -rf -- "$PUBLISH_DIR"
}
trap cleanup_fabric_scan EXIT

# Check if host is reachable.
is_reachable() {
    local ip="$1"
    "$PING_BIN" -c 1 -W 1 "$ip" >/dev/null 2>&1
}

write_collection_status() {
    local hostname="$1" status="$2" reason="${3:-}"
    printf '%s\t%s\n' "$status" "$reason" > "$STAGING_DIR/status/${hostname}.status"
}

validate_raw_snapshot() {
    python3 - "$1" <<'PYEOF'
import sys

expected = [
    "ARP", "VRFMAP", "IFACEVRF", "MAC", "VTEP", "BOND",
    "LOOPBACKS", "NEXTHOPS", "ROUTES", "END",
]
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
        lines = [line.strip() for line in fh]
    markers = [
        line[3:-3]
        for line in lines
        if line.startswith("===") and line.endswith("===")
    ]
except OSError:
    sys.exit(1)

if any(line.startswith("__LLDPQ_COLLECTION_ERROR__:") for line in lines):
    sys.exit(1)

if markers != expected:
    sys.exit(1)
PYEOF
}

# Collect data from a single device
collect_device_data() {
    local ip="$1"
    local hostname="$2"
    local username="${3:-cumulus}"
    local raw_file="$STAGING_DIR/raw/${hostname}.txt"
    local output_file="$STAGING_DIR/data/${hostname}.json"
    local ssh_status
    
    # A failed host keeps its last-known-good JSON. The parent process will
    # mark that snapshot stale and record the failure in summary.json.
    if ! is_reachable "$ip"; then
        write_collection_status "$hostname" "unreachable" "ping_failed"
        return 10
    fi
    
    # Collect into a private raw file. Do not parse or publish partial stdout.
    timeout "$SSH_TIMEOUT" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o BatchMode=yes "${username}@${ip}" '
        echo "===ARP==="
        _arp_output=$(/usr/sbin/ip neigh show 2>/dev/null)
        _arp_status=$?
        if [ "$_arp_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:ARP"
        else
            printf "%s\n" "$_arp_output"
        fi
        echo "===VRFMAP==="
        _vrf_output=$(/usr/sbin/ip vrf list 2>/dev/null)
        _vrf_status=$?
        if [ "$_vrf_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:VRFMAP"
        else
            printf "%s\n" "$_vrf_output"
        fi
        echo "===IFACEVRF==="
        for i in /sys/class/net/vlan*/master /sys/class/net/eth*/master; do
            n=$(basename $(dirname $i) 2>/dev/null)
            m=$(readlink $i 2>/dev/null | xargs basename 2>/dev/null)
            [ -n "$m" ] && echo "$n $m"
        done 2>/dev/null
        echo "===MAC==="
        _fdb_output=$(/usr/sbin/bridge fdb show 2>/dev/null)
        _fdb_status=$?
        if [ "$_fdb_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:FDB"
        else
            printf "%s\n" "$_fdb_output"
        fi
        echo "===VTEP==="
        if [ "$_fdb_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:VTEP"
        else
            printf "%s\n" "$_fdb_output" | grep "dst " || true
        fi
        echo "===BOND==="
        for b in /sys/class/net/*/bonding/slaves; do
            [ -f "$b" ] && echo "$(basename $(dirname $(dirname $b))):$(cat $b)"
        done 2>/dev/null
        echo "===LOOPBACKS==="
        _loopback_output=$(/usr/sbin/ip -4 addr show lo 2>/dev/null)
        _loopback_status=$?
        if [ "$_loopback_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:LOOPBACKS"
        else
            printf "%s\n" "$_loopback_output" | awk '/inet / {print $2}'
        fi
        echo "===NEXTHOPS==="
        _nexthop_output=$(/usr/sbin/ip nexthop show 2>/dev/null)
        _nexthop_status=$?
        if [ "$_nexthop_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:NEXTHOPS"
        else
            printf "%s\n" "$_nexthop_output"
        fi
        echo "===ROUTES==="
        echo "VRF:default"
        _default_routes=$(/usr/sbin/ip route show 2>/dev/null)
        _route_status=$?
        if [ "$_route_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:ROUTES_DEFAULT"
        else
            printf "%s\n" "$_default_routes"
        fi
        for vrf in $(printf "%s\n" "$_vrf_output" | awk \
            "NR>1 && \$1 !~ /^-+\$/ && \$1 != \"Name\" && \$1 != \"default\" {print \$1}"); do
            echo "VRF:$vrf"
            _vrf_routes=$(/usr/sbin/ip route show vrf "$vrf" 2>/dev/null)
            _route_status=$?
            if [ "$_route_status" -ne 0 ]; then
                echo "__LLDPQ_COLLECTION_ERROR__:ROUTES_VRF:$vrf"
            else
                printf "%s\n" "$_vrf_routes"
            fi
        done
        echo "===END==="
    ' > "$raw_file" 2>/dev/null
    ssh_status=$?

    if [[ $ssh_status -ne 0 ]]; then
        rm -f "$raw_file"
        write_collection_status "$hostname" "ssh-failed" "ssh_status_${ssh_status}"
        return 11
    fi
    if [[ ! -s "$raw_file" ]] || ! validate_raw_snapshot "$raw_file"; then
        rm -f "$raw_file"
        write_collection_status "$hostname" "invalid" "partial_or_invalid_output"
        return 12
    fi
    
    # Parse the completed snapshot. Source data is read as data from a file,
    # never interpolated into Python source.
    if ! python3 - "$raw_file" "$output_file" "$hostname" "$ip" <<'PYEOF'
import json
import re
import sys
from datetime import datetime

raw_file, output_file, hostname, address = sys.argv[1:5]
with open(raw_file, 'r', encoding='utf-8', errors='replace') as fh:
    raw = fh.read()

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
    'lldp': [],  # Skip LLDP for now to keep it simple
    '_collection': {
        'status': 'current',
        'checked_at': datetime.now().isoformat(),
        'last_success': datetime.now().isoformat(),
        'error': None,
        'address': address,
    },
}

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(result, f)
PYEOF

    then
        rm -f "$raw_file" "$output_file"
        write_collection_status "$hostname" "invalid" "parse_failed"
        return 13
    fi

    rm -f "$raw_file"
    write_collection_status "$hostname" "current" ""
    return 0
}

prepare_publish_tree() {
    local staged_file output_parent output_name

    output_parent=$(dirname -- "$OUTPUT_DIR") || return 1
    output_name=$(basename -- "$OUTPUT_DIR") || return 1
    PUBLISH_DIR=$(mktemp -d "$output_parent/.${output_name}.publish.XXXXXXXXXX") || return 1

    # Preserve non-managed files, but rebuild the complete managed JSON set.
    # Publication never mutates the active tree while files are being copied.
    if [[ -d "$OUTPUT_DIR" ]] && ! cp -a "$OUTPUT_DIR/." "$PUBLISH_DIR/"; then
        return 1
    fi
    rm -f -- "$PUBLISH_DIR"/*.json || return 1

    for staged_file in "$STAGING_DIR/data"/*.json; do
        [[ -f "$staged_file" ]] || continue
        if ! cp "$staged_file" "$PUBLISH_DIR/$(basename -- "$staged_file")"; then
            return 1
        fi
    done
    if ! cp "$STAGING_DIR/summary.json" "$PUBLISH_DIR/summary.json" ||
       ! chmod 775 "$PUBLISH_DIR" ||
       ! chmod 664 "$PUBLISH_DIR"/*.json; then
        return 1
    fi
}

exchange_publish_tree() {
    # Linux renameat2(RENAME_EXCHANGE) and macOS renamex_np(RENAME_SWAP) swap
    # two same-filesystem directory names atomically. Return 2 when the host
    # lacks either primitive so the guarded rollback fallback can be used.
    python3 - "$OUTPUT_DIR" "$PUBLISH_DIR" <<'PYEOF'
import ctypes
import errno
import os
import sys

active, candidate = map(os.fsencode, sys.argv[1:3])
libc = ctypes.CDLL(None, use_errno=True)

if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
    rename_swap = 0x00000002
    fn = libc.renamex_np
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    result = fn(active, candidate, rename_swap)
elif hasattr(libc, "renameat2"):
    at_fdcwd = -100
    rename_exchange = 0x2
    fn = libc.renameat2
    fn.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    ]
    fn.restype = ctypes.c_int
    result = fn(at_fdcwd, active, at_fdcwd, candidate, rename_exchange)
else:
    sys.exit(2)

if result == 0:
    sys.exit(0)
error = ctypes.get_errno()
if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
    sys.exit(2)
raise OSError(error, os.strerror(error))
PYEOF
}

publish_complete_tree() {
    local exchange_status rollback_dir old_hup old_int old_term

    restore_signal_traps() {
        if [[ -n "$old_hup" ]]; then eval "$old_hup"; else trap - HUP; fi
        if [[ -n "$old_int" ]]; then eval "$old_int"; else trap - INT; fi
        if [[ -n "$old_term" ]]; then eval "$old_term"; else trap - TERM; fi
    }

    if [[ ! -d "$OUTPUT_DIR" ]]; then
        if mv "$PUBLISH_DIR" "$OUTPUT_DIR"; then
            PUBLISH_DIR=""
            return 0
        fi
        return 1
    fi

    if exchange_publish_tree; then
        # After the exchange this path contains the previous complete tree.
        if ! rm -rf -- "$PUBLISH_DIR"; then
            echo "Warning: old fabric cache cleanup failed at $PUBLISH_DIR" >&2
        fi
        PUBLISH_DIR=""
        return 0
    else
        exchange_status=$?
    fi
    [[ $exchange_status -eq 2 ]] || return 1

    # Portable fallback. Mask termination during the short two-rename commit,
    # and restore the previous tree if the second rename cannot complete.
    rollback_dir=$(mktemp -d "$(dirname -- "$OUTPUT_DIR")/.fabric-rollback.XXXXXXXXXX") || return 1
    rmdir "$rollback_dir" || return 1
    old_hup=$(trap -p HUP)
    old_int=$(trap -p INT)
    old_term=$(trap -p TERM)
    trap '' HUP INT TERM
    if ! mv "$OUTPUT_DIR" "$rollback_dir"; then
        restore_signal_traps
        return 1
    fi
    if mv "$PUBLISH_DIR" "$OUTPUT_DIR"; then
        PUBLISH_DIR=""
        if ! rm -rf -- "$rollback_dir"; then
            echo "Warning: old fabric cache cleanup failed at $rollback_dir" >&2
        fi
        exchange_status=0
    else
        exchange_status=1
        if ! mv "$rollback_dir" "$OUTPUT_DIR"; then
            echo "CRITICAL: fabric cache rollback is retained at $rollback_dir" >&2
        fi
    fi
    restore_signal_traps
    return "$exchange_status"
}

prepare_last_known_snapshot() {
    local hostname="$1" reason="$2"
    local existing_file="$OUTPUT_DIR/${hostname}.json"
    local staged_file="$STAGING_DIR/data/${hostname}.json"

    if [[ ! -f "$existing_file" ]]; then
        write_collection_status "$hostname" "unavailable" "$reason"
        return 0
    fi

    if python3 - "$existing_file" "$staged_file" "$reason" <<'PYEOF'
import json
import os
import sys
from datetime import datetime

source, destination, reason = sys.argv[1:4]
with open(source, 'r', encoding='utf-8') as fh:
    data = json.load(fh)
if not isinstance(data, dict):
    raise ValueError('cached device snapshot is not an object')

collection = data.get('_collection')
if not isinstance(collection, dict):
    collection = {}
last_success = collection.get('last_success') or collection.get('checked_at')
if not last_success:
    last_success = datetime.fromtimestamp(os.path.getmtime(source)).isoformat()
collection.update({
    'status': 'stale',
    'checked_at': datetime.now().isoformat(),
    'last_success': last_success,
    'error': reason,
})
data['_collection'] = collection
with open(destination, 'w', encoding='utf-8') as fh:
    json.dump(data, fh)
PYEOF
    then
        write_collection_status "$hostname" "stale" "$reason"
    else
        rm -f "$staged_file"
        write_collection_status "$hostname" "unavailable" "${reason};invalid_lkg"
    fi
}

build_summary() {
    python3 - "$STAGING_DIR/inventory.tsv" "$STAGING_DIR/status" \
        "$STAGING_DIR/data" "$OUTPUT_DIR" "$STAGING_DIR/summary.json" <<'PYEOF'
import json
import os
import sys
from datetime import datetime

inventory_file, status_dir, staged_dir, output_dir, summary_file = sys.argv[1:6]
summary = {
    'timestamp': datetime.now().isoformat(),
    'complete': True,
    'status_counts': {'current': 0, 'stale': 0, 'unavailable': 0},
    'devices': [],
}

with open(inventory_file, 'r', encoding='utf-8') as inventory:
    for line in inventory:
        address, username, hostname = line.rstrip('\n').split('\t', 2)
        status_path = os.path.join(status_dir, hostname + '.status')
        try:
            with open(status_path, 'r', encoding='utf-8') as status_file:
                status, reason = (status_file.readline().rstrip('\n').split('\t', 1) + [''])[:2]
        except OSError:
            status, reason = 'unavailable', 'missing_child_status'

        if status not in {'current', 'stale', 'unavailable'}:
            status = 'unavailable'
        summary['status_counts'][status] += 1
        if status != 'current':
            summary['complete'] = False

        candidate = os.path.join(staged_dir, hostname + '.json')
        if not os.path.isfile(candidate):
            candidate = os.path.join(output_dir, hostname + '.json')
        data = {}
        try:
            with open(candidate, 'r', encoding='utf-8') as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            pass
        collection = data.get('_collection', {}) if isinstance(data, dict) else {}
        summary['devices'].append({
            'hostname': hostname,
            'address': address,
            'status': status,
            'collection_error': reason or collection.get('error'),
            'last_success': collection.get('last_success'),
            'arp_count': len(data.get('arp', [])),
            'mac_count': len(data.get('mac', [])),
            'vtep_count': len(data.get('vtep', [])),
            'lldp_count': len(data.get('lldp', [])),
        })

with open(summary_file, 'w', encoding='utf-8') as fh:
    json.dump(summary, fh, indent=2)
PYEOF
}

# Main execution. Inventory must parse completely before the existing cache is
# inspected, pruned, or published.
echo "Fabric Scan - Collecting network tables"
echo "========================================"

source "$SCRIPT_DIR/load_devices.sh"
if ! load_devices "$SCRIPT_DIR/parse_devices.py" -f "$DEVICES_FILE"; then
    echo "Invalid device inventory; existing fabric cache was preserved." >&2
    exit 1
fi

declare -A expected_hosts=()
for ip in "${!devices[@]}"; do
    IFS=' ' read -r username hostname <<< "${devices[$ip]}"
    if [[ "$hostname" == "summary" ]]; then
        echo "Reserved hostname in device inventory: $hostname" >&2
        exit 1
    fi
    if [[ -n "${expected_hosts[$hostname]+present}" ]]; then
        echo "Duplicate hostname in device inventory: $hostname" >&2
        exit 1
    fi
    expected_hosts["$hostname"]="$ip"
done

STAGING_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-fabric-scan.XXXXXX") || exit 1
mkdir -p "$STAGING_DIR/raw" "$STAGING_DIR/data" "$STAGING_DIR/status" || exit 1
for ip in "${!devices[@]}"; do
    IFS=' ' read -r username hostname <<< "${devices[$ip]}"
    printf '%s\t%s\t%s\n' "$ip" "$username" "$hostname" >> "$STAGING_DIR/inventory.tsv"
done
mkdir -p "$OUTPUT_DIR" || exit 1

device_count=${#devices[@]}
echo "Devices: $device_count"
echo "Collecting..."

declare -a scan_pids=()
declare -a scan_hosts=()
declare -a scan_failures=()
next_wait=0
active_jobs=0

wait_for_scan_job() {
    local index="$1" status
    if wait "${scan_pids[$index]}"; then
        status=0
        printf '.'
    else
        status=$?
        scan_failures+=("${scan_hosts[$index]}:${status}")
        printf 'x'
    fi
}

for ip in "${!devices[@]}"; do
    IFS=' ' read -r username hostname <<< "${devices[$ip]}"
    collect_device_data "$ip" "$hostname" "$username" 8>&- &
    scan_pids+=("$!")
    scan_hosts+=("$hostname")
    ((active_jobs++))
    if (( active_jobs >= MAX_PARALLEL )); then
        wait_for_scan_job "$next_wait"
        ((next_wait++))
        ((active_jobs--))
    fi
done
while (( next_wait < ${#scan_pids[@]} )); do
    wait_for_scan_job "$next_wait"
    ((next_wait++))
done
echo ""

# Convert failed device snapshots into explicitly stale LKG copies. A host
# without a valid prior snapshot is listed as unavailable in summary.json.
for ip in "${!devices[@]}"; do
    IFS=' ' read -r username hostname <<< "${devices[$ip]}"
    status_file="$STAGING_DIR/status/${hostname}.status"
    if [[ ! -f "$status_file" ]]; then
        write_collection_status "$hostname" "unavailable" "missing_child_status"
        scan_failures+=("${hostname}:missing-status")
    fi
    IFS=$'\t' read -r collection_status collection_reason < "$status_file"
    if [[ "$collection_status" != "current" ]]; then
        prepare_last_known_snapshot "$hostname" "${collection_reason:-collection_failed}"
    fi
done

if ! build_summary; then
    echo "Could not build fabric scan summary; existing cache was preserved." >&2
    exit 1
fi

# A valid inventory is authoritative. Count retired artifacts for the status
# message; the complete candidate tree omits them and is activated as one unit.
retired_count=0
for cached_file in "$OUTPUT_DIR"/*.json; do
    [[ -f "$cached_file" ]] || continue
    cached_host=$(basename "$cached_file" .json)
    [[ "$cached_host" == "summary" ]] && continue
    if [[ -z "${expected_hosts[$cached_host]+present}" ]]; then
        ((retired_count++))
    fi
done

if ! prepare_publish_tree || ! publish_complete_tree; then
    echo "Fabric cache publication failed; the previous complete tree was preserved." >&2
    exit 1
fi

[[ $retired_count -gt 0 ]] && echo "Removed $retired_count retired fabric cache files"
python3 - "$STAGING_DIR/summary.json" "$OUTPUT_DIR" <<'PYEOF'
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    summary = json.load(fh)
counts = summary['status_counts']
print(
    f"Scan complete: {len(summary['devices'])} devices "
    f"({counts['current']} current, {counts['stale']} stale, "
    f"{counts['unavailable']} unavailable)"
)
print(f"Results: {sys.argv[2]}/")
PYEOF

if [[ ${#scan_failures[@]} -gt 0 ]]; then
    printf 'Fabric scan completed with partial coverage: %d device collections unavailable or stale\n' \
        "${#scan_failures[@]}" >&2
fi
exit 0
