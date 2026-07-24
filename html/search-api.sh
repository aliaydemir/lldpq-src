#!/bin/bash
# Search API - MAC/ARP Table Backend
# Backend for search.html

source "$(dirname "$0")/auth-guard.sh"
require_auth

# Load allowlisted config data through the fixed, root-owned parser.  A partial
# upgrade must fail explicitly: silently falling back to the CGI user's HOME
# makes every device lookup use the wrong inventory while still returning 200.
LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
config_bootstrap_error() {
    echo "Status: 500 Internal Server Error"
    echo "Content-Type: application/json"
    echo ""
    printf '%s\n' '{"success": false, "error": "LLDPq runtime configuration is unavailable; complete or repair the installation"}'
    exit 0
}
if [[ ! -x "$LLDPQ_CONFIG_HELPER" ]]; then
    config_bootstrap_error
fi
if ! LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
    --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
    2>/dev/null); then
    config_bootstrap_error
fi
if ! eval "$LLDPQ_CONFIG_ASSIGNMENTS"; then
    config_bootstrap_error
fi
unset LLDPQ_CONFIG_ASSIGNMENTS

# Set defaults (use $HOME for portable fallback)
LLDPQ_DIR="${LLDPQ_DIR:-$HOME/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Export for Python scripts
export LLDPQ_DIR LLDPQ_USER WEB_ROOT

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    ACTION=$(echo "$query" | grep -oP 'action=\K[^&]*' | head -1)
    DEVICE=$(echo "$query" | grep -oP 'device=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null)
    SEARCH=$(echo "$query" | grep -oP 'search=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null)
    # Normalize dash (aa-bb-cc-dd-ee-ff) and dot (aabb.ccdd.eeff) MAC notations
    # to the colon format used by bridge fdb / ip neigh output
    if [[ -n "$SEARCH" ]]; then
        SEARCH=$(echo "$SEARCH" | python3 -c '
import re, sys
term = sys.stdin.read().strip()
if re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", term):
    term = term.replace("-", ":")
elif re.fullmatch(r"(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}", term):
    digits = term.replace(".", "")
    term = ":".join(digits[i:i+2] for i in range(0, 12, 2))
print(term)
' 2>/dev/null)
    fi
}

# Exact-key query parameter lookup.  grep substring extraction lets keys
# overlap (vrf= also matches inside dst_vrf=), so parse the query string with
# a real parser and keep blank values ("vrf=") distinct from missing keys.
get_query_param() {
    printf '%s' "$QUERY_STRING" | python3 -c '
import sys
import urllib.parse

params = urllib.parse.parse_qs(sys.stdin.read(), keep_blank_values=True)
print(params.get(sys.argv[1], [""])[0])
' "$1" 2>/dev/null
}

# Search and the collectors must consume one inventory contract.  Calling the
# canonical parser here keeps type normalization, legacy usernames (for
# example DOMAIN\user and user+tag), validation and error handling identical.
inventory_json() {
    local parser="$LLDPQ_DIR/parse_devices.py"
    local inventory="$LLDPQ_DIR/devices.yaml"
    [[ -f "$parser" && -f "$inventory" ]] || return 1
    python3 "$parser" --format json --file "$inventory"
}

# Resolve SSH target (username@address) from the validated inventory JSON.
# Usage: ssh_target=$(get_ssh_target "$DEVICE")
get_ssh_target() {
    local address="$1"
    local target
    if ! target=$(inventory_json | python3 -c '
import json
import sys

requested = sys.argv[1]
try:
    records = json.load(sys.stdin)
    matches = [record for record in records if record.get("address") == requested]
    if len(matches) != 1:
        raise ValueError("unknown device")
    record = matches[0]
    username = record.get("username", "")
    address = record["address"]
    print(f"{username}@{address}" if username else address)
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
' "$address"); then
        return 1
    fi
    printf '%s\n' "$target"
}

# List devices from the same normalized parser output used by every collector.
list_devices() {
    local records
    if ! records=$(inventory_json 2>/dev/null); then
        printf '%s\n' '{"success": false, "error": "Device inventory is invalid or unavailable"}'
        return
    fi
    printf '%s' "$records" | python3 -c '
import json
import sys

try:
    records = json.load(sys.stdin)
    devices = [
        {"ip": record["address"], "hostname": record["hostname"]}
        for record in records
    ]
    devices.sort(key=lambda item: (item["hostname"].casefold(), item["ip"]))
    print(json.dumps({"success": True, "devices": devices}))
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
    print(json.dumps({"success": False, "error": f"Invalid device inventory: {exc}"}))
'
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
        if ! /usr/sbin/bridge fdb show 2>/dev/null; then
            exit 41
        fi
        echo "---BOND_MAP---"
        # Bond member ports (same "bond:swp1 swp2" format the fabric scan uses)
        # so live results carry the same Physical Ports data as cached results.
        for b in /sys/class/net/*/bonding/slaves; do
            [ -f "$b" ] && echo "$(basename $(dirname $(dirname $b))):$(cat $b)"
        done 2>/dev/null
        exit 0
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

raw = sys.stdin.read()
search = sys.argv[1].lower()

# Split FDB output from the bond membership map appended by the remote script.
sections = raw.split('---BOND_MAP---', 1)
output = sections[0]
bond_members = {}
if len(sections) > 1:
    for bond_line in sections[1].strip().split('\n'):
        if ':' not in bond_line:
            continue
        bond_name, members = bond_line.split(':', 1)
        bond_name = bond_name.strip()
        if bond_name and members.strip():
            bond_members[bond_name] = members.strip().split()

entries = []
parse_candidates = 0
parsed_count = 0
malformed_count = 0
for line in output.strip().split('\n'):
    if not line.strip():
        continue
    if "permanent" in line or "self" in line:
        continue
    parse_candidates += 1
    
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

        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac) or not iface:
            malformed_count += 1
            continue
        parsed_count += 1
        
        entry = {
            "mac": mac,
            "interface": iface,
            "vlan": vlan,
            "type": "dynamic"
        }
        if iface in bond_members:
            entry["bond_ports"] = bond_members[iface]

        # Apply search filter
        if search:
            if search in mac.lower() or search in iface.lower() or search in vlan.lower():
                entries.append(entry)
        else:
            entries.append(entry)
    else:
        malformed_count += 1

if parse_candidates and parsed_count == 0:
    print(json.dumps({"success": False, "error": "Unable to parse MAC table response"}))
else:
    limit = 200
    returned = entries[:limit]
    print(json.dumps({
        "success": True,
        "entries": returned,
        "total": len(entries),
        "returned_total": len(returned),
        "limit": limit,
        "truncated": len(returned) < len(entries),
        "complete": malformed_count == 0,
        "partial": malformed_count > 0,
        "warnings": ([f"Skipped {malformed_count} malformed MAC entr{'y' if malformed_count == 1 else 'ies'}"]
                     if malformed_count else []),
    }))
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
        if ! /usr/sbin/ip neigh show 2>/dev/null; then
            exit 41
        fi
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
        # The loop above legitimately ends with a failed test when the last
        # interface has no master; that must not look like an SSH failure.
        exit 0
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import ipaddress
import json
import re
import sys

output = sys.stdin.read()
search = sys.argv[1].lower()

# Parse sections. Both delimiters are emitted by the remote command; missing
# delimiters mean the response was incomplete and must not look like an empty
# but successful neighbor table.
if "---VRF_MAP---" not in output or "---IFACE_VRF---" not in output:
    print(json.dumps({"success": False, "error": "Incomplete ARP table response"}))
    raise SystemExit(0)

sections = output.split("---VRF_MAP---", 1)
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
malformed_count = 0
for line in arp_lines:
    if not line.strip():
        continue
    
    parts = line.split()
    if len(parts) < 2:
        malformed_count += 1
        continue

    ip_addr = parts[0]
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        malformed_count += 1
        continue

    mac = ""
    iface = ""
    state = ""
    for i, p in enumerate(parts):
        if p == "dev" and i + 1 < len(parts):
            iface = parts[i + 1]
        if p == "lladdr" and i + 1 < len(parts):
            mac = parts[i + 1]

    if not iface:
        malformed_count += 1
        continue
    if parts[-1] in ["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"]:
        state = parts[-1]

    # FAILED/INCOMPLETE neighbor rows legitimately have no MAC and are not
    # useful search results, but they are not parser failures.
    if mac:
        if re.search(r'-v\d+$', iface):
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

limit = 500
returned = entries[:limit]
print(json.dumps({
    "success": True,
    "entries": returned,
    "total": len(entries),
    "returned_total": len(returned),
    "limit": limit,
    "truncated": len(returned) < len(entries),
    "complete": malformed_count == 0,
    "partial": malformed_count > 0,
    "warnings": ([f"Skipped {malformed_count} malformed ARP entr{'y' if malformed_count == 1 else 'ies'}"]
                 if malformed_count else []),
}))
PYTHON
}

# Get all MAC/ARP from all devices (parallel)
get_all_tables() {
    local table_type="$1"  # mac or arp
    local search="$2"
    local records

    if ! records=$(inventory_json 2>/dev/null); then
        printf '%s\n' '{"success": false, "error": "Device inventory is invalid or unavailable"}'
        return
    fi

    # Feed canonical normalized records on stdin; keep Python source on fd 3.
    printf '%s' "$records" | python3 /dev/fd/3 \
        "$table_type" "$search" "$LLDPQ_USER" 3<<'PYTHON'
import json
import subprocess
import concurrent.futures
import re
import sys

table_type = sys.argv[1]
search = sys.argv[2].lower()
lldpq_user = sys.argv[3]

try:
    device_list = json.load(sys.stdin)
    if not isinstance(device_list, list) or not device_list:
        raise ValueError("empty device inventory")
except (TypeError, ValueError, json.JSONDecodeError) as exc:
    print(json.dumps({"success": False, "error": f"Invalid device inventory: {exc}"}))
    raise SystemExit(0)

def get_device_table(record):
    try:
        ip = record['address']
        hostname = record['hostname']
        username = record.get('username', '')
        target = f"{username}@{ip}" if username else ip
        if table_type == "mac":
            remote_script = "/usr/sbin/bridge fdb show 2>/dev/null"
            cmd_parts = [
                "sudo", "-u", lldpq_user, "timeout", "15", "ssh",
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", target,
                remote_script
            ]
            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=20)
        else:  # arp - get ARP with interface VRF mappings
            remote_script = 'if ! /usr/sbin/ip neigh show 2>/dev/null; then exit 41; fi; echo ---VRF_MAP---; /usr/sbin/ip vrf list 2>/dev/null; echo ---IFACE_VRF---; for i in /sys/class/net/*/master; do n=$(basename $(dirname $i)); m=$(readlink $i 2>/dev/null | xargs basename 2>/dev/null); [ -n "$m" ] && echo $n $m; done 2>/dev/null'
            cmd_parts = [
                "sudo", "-u", lldpq_user, "timeout", "15", "ssh",
                "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", target,
                remote_script
            ]
            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return [], hostname

        entries = []
        if table_type == "mac":
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                if "permanent" in line:
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
                    
                    entry = {
                        "device": hostname,
                        "mac": mac,
                        "interface": iface,
                        "vlan": vlan,
                    }
                    if not search or search in mac.lower() or search in iface.lower() or search in vlan.lower() or search in hostname.lower():
                        entries.append(entry)
        elif table_type == "arp":
            # Parse ARP with VRF info from interface masters
            output = result.stdout.strip()
            if "---VRF_MAP---" not in output or "---IFACE_VRF---" not in output:
                return [], hostname
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
                state = parts[-1] if parts[-1] in {
                    "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT"
                } else ""
                for i, p in enumerate(parts):
                    if p == "dev" and i + 1 < len(parts):
                        iface = parts[i + 1]
                    if p == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1]
                
                if mac:
                    if iface and re.search(r'-v\d+$', iface):
                        continue
                    vrf = iface_to_vrf.get(iface, "default")
                    entry = {
                        "device": hostname,
                        "ip": ip_addr,
                        "mac": mac,
                        "interface": iface,
                        "vrf": vrf,
                        "state": state,
                    }
                    if (not search or search in ip_addr.lower() or
                            search in mac.lower() or search in hostname.lower() or
                            search in iface.lower() or search in vrf.lower()):
                        entries.append(entry)
        return entries, None
    except Exception:
        return [], str(record.get('hostname', record.get('address', 'unknown')))

try:
    all_entries = []
    failed_devices = []
    # Full tables are collected before filtering so exact searches cannot miss
    # rows beyond an arbitrary head limit. Bound concurrency to cap memory.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(device_list))) as executor:
        results = executor.map(get_device_table, device_list)
        for entries, failed_device in results:
            all_entries.extend(entries)
            if failed_device:
                failed_devices.append(failed_device)

    successful_devices = len(device_list) - len(failed_devices)
    if successful_devices == 0:
        print(json.dumps({
            "success": False,
            "error": "Failed to query every configured device",
            "failed_devices": failed_devices,
        }))
    else:
        print(json.dumps({
            "success": True,
            "entries": all_entries[:500],
            "total": len(all_entries),
            "returned_total": min(len(all_entries), 500),
            "limit": 500,
            "truncated": len(all_entries) > 500,
            "complete": not failed_devices,
            "partial": bool(failed_devices),
            "successful_device_count": successful_devices,
            "failed_devices": failed_devices,
            "warnings": [f"Failed to query device: {device}" for device in failed_devices],
        }))

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
        /usr/sbin/bridge fdb show 2>/dev/null
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to query VTEP table on device"}'
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
candidate_count = 0
parse_error_count = 0

for line in output.strip().split('\n'):
    if not line.strip():
        continue
    
    parts = line.split()
    if "dst" not in parts:
        continue
    candidate_count += 1
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
    else:
        parse_error_count += 1

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
    "total_entries": len(entries),
    "collected_entries": sum(item["macs"] for item in vtep_summary.values()),
}

if candidate_count and candidate_count == parse_error_count:
    print(json.dumps({"success": False, "error": "Unable to parse VTEP table response"}))
else:
    limit = 500
    returned = entries[:limit]
    print(json.dumps({
        "success": True,
        "entries": returned,
        "total": len(entries),
        "returned_total": len(returned),
        "limit": limit,
        "truncated": len(returned) < len(entries),
        "complete": parse_error_count == 0,
        "partial": parse_error_count > 0,
        "warnings": ([f"Skipped {parse_error_count} malformed VTEP entr{'y' if parse_error_count == 1 else 'ies'}"]
                     if parse_error_count else []),
        "summary": summary,
    }))
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
        sudo vtysh -c "show ip route vrf all" 2>/dev/null
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to connect to device"}'
        return
    fi
    
    # Keep SSH output on stdin so device-controlled text is never Python source.
    printf '%s' "$ssh_output" | python3 /dev/fd/3 "$search" 3<<'PYTHON'
import json
import ipaddress
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
    
    # Skip kernel routes (unreachable, blackhole, etc.) - they are confusing.
    # Reset last_entry so the skipped route's ECMP continuation lines cannot
    # inflate the ECMP count of the previous route.
    if protocol == 'kernel':
        last_entry = None
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

# Compute longest-prefix matches from the complete collected table before the
# display filter/limit is applied.  The response stays bounded (one result per
# VRF), while searches remain correct when the matching route is beyond the
# first 100 display rows.
best_matches = {}
best_match_order = []
try:
    search_ip = ipaddress.IPv4Address(search) if search else None
except ipaddress.AddressValueError:
    search_ip = None

if search_ip is not None:
    for vrf, routes in vrf_data.items():
        best_route = None
        best_prefixlen = -1
        for route in routes:
            try:
                network = ipaddress.IPv4Network(route['prefix'], strict=False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, KeyError, ValueError):
                continue
            if search_ip in network and network.prefixlen > best_prefixlen:
                best_route = dict(route)
                best_route['vrf'] = vrf
                best_prefixlen = network.prefixlen
        if best_route is None:
            best_route = {
                'prefix': 'No Route',
                'nexthop': '-',
                'interface': '-',
                'protocol': '-',
                'vrf': vrf,
                'no_route': True,
            }
        best_matches[vrf] = best_route

    best_match_order = list(vrf_data)
    best_match_order.sort(key=lambda vrf: (
        0 if vrf == 'default' else 2 if vrf == 'mgmt' else 1,
        vrf,
    ))

# Apply search filter for the bounded display table.
if search:
    filtered = []
    for e in entries:
        # A complete IP uses exact field matching so 10.0.0.1 does not match
        # 10.0.0.10 and accidentally suppress the LPM response. Partial/text
        # searches retain the existing substring behavior.
        if search_ip is not None:
            field_match = (
                e['prefix'].split('/', 1)[0].lower() == search or
                e['nexthop'].lower() == search
            )
        else:
            field_match = (
                search in e['prefix'].lower() or
                search in e['nexthop'].lower() or
                search in e['interface'].lower() or
                search in e['protocol'].lower()
            )
        if field_match:
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

per_vrf_limit = 100
limited_tables = {v: vrf_tables[v][:per_vrf_limit] for v in vrf_order}
vrf_counts = {v: len(vrf_tables[v]) for v in vrf_order}
returned_total = sum(len(routes) for routes in limited_tables.values())

print(json.dumps({
    "success": True,
    "vrf_tables": limited_tables,
    "vrf_order": vrf_order,
    "vrf_counts": vrf_counts,
    "total": len(entries),
    "returned_total": returned_total,
    "truncated": returned_total < len(entries),
    "per_vrf_limit": per_vrf_limit,
    "best_matches": best_matches,
    "best_match_order": best_match_order,
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
        sudo lldpctl -f json 2>/dev/null
    ' 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
        echo '{"success": false, "error": "Failed to query LLDP on device"}'
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
    if not isinstance(data, dict):
        raise ValueError("LLDP response is not a JSON object")
    if 'lldp' not in data:
        raise ValueError("LLDP response is missing the lldp payload")
    lldp_data = data['lldp']
    if not isinstance(lldp_data, list):
        raise ValueError("LLDP payload is not a list")
    
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
                        
                        if (not search or search in neighbor.lower() or
                                search in iface_name.lower() or
                                search in remote_port.lower() or
                                search in str(mgmt_ip).lower()):
                            entries.append(entry)
    
    # Sort by local port
    entries.sort(key=lambda x: x['local_port'])
    
except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
    print(json.dumps({"success": False, "error": f"Invalid LLDP response: {exc}"}))
    raise SystemExit(0)

print(json.dumps({
    "success": True,
    "entries": entries,
    "total": len(entries),
    "returned_total": len(entries),
    "truncated": False,
    "complete": True,
}))
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

def parse_timestamp(value):
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None

def most_recent_timestamp(values):
    parsed = [(parse_timestamp(value), value) for value in values]
    parsed = [(stamp, value) for stamp, value in parsed if stamp is not None]
    if not parsed:
        return None
    # Normalize to a numeric instant so aware and naive values can coexist.
    return max(parsed, key=lambda item: item[0].timestamp())[1]

try:
    if os.path.exists(summary_file):
        with open(summary_file) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Fabric scan summary is not a JSON object")

        timestamp = data.get('timestamp', '')
        devices = data.get('devices', [])
        if not isinstance(devices, list):
            raise ValueError("Fabric scan summary devices is not a list")
        device_count = len(devices)

        known_statuses = [
            device.get('status') for device in devices
            if isinstance(device, dict) and device.get('status') in {'current', 'stale', 'unavailable'}
        ]
        raw_counts = data.get('status_counts', {})
        if not isinstance(raw_counts, dict):
            raw_counts = {}
        status_counts = {}
        for status in ('current', 'stale', 'unavailable'):
            fallback = known_statuses.count(status)
            try:
                count = int(raw_counts.get(status, fallback))
            except (TypeError, ValueError):
                count = fallback
            status_counts[status] = max(0, count)
        # The per-device records are authoritative when every device has a
        # recognized status. This also repairs inconsistent legacy summaries.
        if device_count and len(known_statuses) == device_count:
            status_counts = {
                status: known_statuses.count(status)
                for status in ('current', 'stale', 'unavailable')
            }

        complete = bool(data.get(
            'complete',
            device_count > 0 and status_counts['current'] == device_count,
        ))
        if status_counts['stale'] or status_counts['unavailable']:
            complete = False

        last_success = data.get('last_success')
        if not last_success:
            last_success = most_recent_timestamp([
                device.get('last_success') for device in devices
                if isinstance(device, dict)
            ])
        if not last_success and complete:
            last_success = timestamp or None
        
        # Calculate age
        scan_time = parse_timestamp(timestamp)
        if scan_time is not None:
            now = datetime.now(scan_time.tzinfo) if scan_time.tzinfo else datetime.now()
            age_seconds = (now - scan_time).total_seconds()
            age_minutes = int(age_seconds / 60)
        else:
            age_minutes = -1
        
        print(json.dumps({
            "success": True,
            "timestamp": timestamp,
            "device_count": device_count,
            "age_minutes": age_minutes,
            "complete": complete,
            "status_counts": status_counts,
            "current_count": status_counts['current'],
            "stale_count": status_counts['stale'],
            "unavailable_count": status_counts['unavailable'],
            "devices": devices,
            "last_success": last_success,
        }))
    else:
        print(json.dumps({
            "success": True,
            "timestamp": None,
            "device_count": 0,
            "age_minutes": -1,
            "message": "No scan data available",
            "complete": False,
            "status_counts": {"current": 0, "stale": 0, "unavailable": 0},
            "current_count": 0,
            "stale_count": 0,
            "unavailable_count": 0,
            "devices": [],
            "last_success": None,
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
    
    # Run scan in background. The explicit operator action overrides a
    # configured SKIP_FABRIC_SCAN (the script self-gates on the toggle).
    cd "$lldpq_dir"
    sudo -u "$LLDPQ_USER" nohup env LLDPQ_FABRIC_SCAN_FORCE=1 bash "$scan_script" > /tmp/fabric-scan.log 2>&1 &
    
    echo '{"success": true, "message": "Fabric scan started"}'
}

# Search cached routes (VRF-grouped structure)
search_cached_routes() {
    local search_ip="$1"
    
    python3 - "$search_ip" <<'PYTHON'
import ipaddress
import json
import os
import sys

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
summary_file = os.path.join(tables_dir, "summary.json")
search_text = sys.argv[1].strip()

# socket.inet_aton accepts legacy abbreviated forms such as "192.168.64" and
# maps invalid input to zero in the old implementation. Route LPM must only run
# for a complete, valid IPv4 address.
try:
    search_ip = ipaddress.IPv4Address(search_text)
except ipaddress.AddressValueError:
    print(json.dumps({
        "success": False,
        "error": "A complete valid IPv4 address is required for route search",
        "code": "invalid_ipv4",
    }))
    raise SystemExit(0)

results = {}  # vrf -> [routes with best match]
all_vrfs = set()  # Collect all unique VRFs
device_vrfs = {}  # Track which VRFs each device has
warnings = []
candidate_file_count = 0
processed_device_count = 0
failed_devices = []
summary_devices = {}
snapshot_hostnames = set()

try:
    if not os.path.exists(tables_dir):
        print(json.dumps({"success": False, "error": "No cached data. Run Fabric Scan first."}))
        exit()

    if os.path.exists(summary_file):
        try:
            with open(summary_file) as summary_handle:
                summary = json.load(summary_handle)
            for device in summary.get('devices', []):
                if not isinstance(device, dict) or not device.get('hostname'):
                    continue
                summary_devices[str(device['hostname'])] = str(device.get('status', 'unknown'))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            warnings.append(f"summary.json: {exc}")
    
    # First pass: collect all VRFs and find best matches
    for filename in os.listdir(tables_dir):
        if not filename.endswith('.json') or filename == 'summary.json':
            continue
        candidate_file_count += 1
        
        hostname = filename.replace('.json', '')
        snapshot_hostnames.add(hostname)
        filepath = os.path.join(tables_dir, filename)
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("snapshot is not a JSON object")
            if 'routes' not in data:
                raise ValueError("snapshot is missing routes")
            routes = data['routes']
            if not isinstance(routes, dict):
                raise ValueError("routes is not an object")

            collection = data.get('_collection', {})
            if isinstance(collection, dict) and collection.get('status') in {'stale', 'unavailable'}:
                warnings.append(f"{filename}: snapshot status is {collection['status']}")

            processed_device_count += 1
            device_vrfs[hostname] = set()
            skipped_routes = 0
            
            for vrf, vrf_routes in routes.items():
                # Skip invalid VRF names
                if not isinstance(vrf, str) or vrf.startswith('-') or not vrf.strip():
                    skipped_routes += len(vrf_routes) if isinstance(vrf_routes, list) else 1
                    continue
                if not isinstance(vrf_routes, list):
                    warnings.append(f"{filename}: routes for VRF {vrf} is not a list")
                    continue
                    
                all_vrfs.add(vrf)
                device_vrfs[hostname].add(vrf)
                
                best_match = None
                best_prefix_len = -1
                
                for route in vrf_routes:
                    if not isinstance(route, dict):
                        skipped_routes += 1
                        continue
                    prefix = route.get('prefix', '')
                    try:
                        network = ipaddress.IPv4Network(prefix, strict=False)
                    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError, ValueError):
                        skipped_routes += 1
                        continue
                    if search_ip in network and network.prefixlen > best_prefix_len:
                        best_prefix_len = network.prefixlen
                        best_match = route.copy()
                        best_match['device'] = hostname
                        best_match['vrf'] = vrf
                
                if best_match:
                    if vrf not in results:
                        results[vrf] = []
                    results[vrf].append(best_match)
            if skipped_routes:
                warnings.append(
                    f"{filename}: skipped {skipped_routes} malformed route "
                    f"entr{'y' if skipped_routes == 1 else 'ies'}"
                )
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            warnings.append(f"{filename}: {exc}")
            failed_devices.append(hostname)

    for hostname, status in summary_devices.items():
        if hostname not in snapshot_hostnames:
            warnings.append(f"{hostname}: {status} device has no cached snapshot")
            failed_devices.append(hostname)
        elif status in {'stale', 'unavailable'}:
            warnings.append(f"{hostname}: snapshot status is {status}")
            if status == 'unavailable':
                failed_devices.append(hostname)

    if candidate_file_count == 0:
        print(json.dumps({
            "success": False,
            "error": "No cached device data. Run Fabric Scan first.",
            "warnings": warnings,
            "partial": False,
            "complete": False,
        }))
        raise SystemExit(0)
    if processed_device_count == 0:
        print(json.dumps({
            "success": False,
            "error": "Cached route data is unreadable or invalid",
            "warnings": warnings,
            "partial": True,
            "complete": False,
            "processed_device_count": 0,
            "failed_device_count": candidate_file_count,
        }))
        raise SystemExit(0)
    
    # Second pass: preserve the existing synthetic "No Route" row and also
    # expose per-VRF coverage. Without coverage, one matching device can make a
    # partially missing route look fabric-wide and consistent.
    route_coverage = {}
    devices_without_route = {}
    for vrf in all_vrfs:
        devices_with_vrf = sorted(d for d, vrfs in device_vrfs.items() if vrf in vrfs)
        matched_devices = {
            route.get('device') for route in results.get(vrf, [])
            if isinstance(route, dict) and route.get('device')
        }
        without_route = [device for device in devices_with_vrf if device not in matched_devices]
        devices_without_route[vrf] = without_route
        route_coverage[vrf] = {
            'expected_device_count': len(devices_with_vrf),
            'matched_device_count': len(matched_devices),
            'devices_without_route': without_route,
        }
        if vrf not in results:
            results[vrf] = [{
                'device': 'all',
                'vrf': vrf,
                'prefix': 'No Route',
                'nexthop': '-',
                'interface': '-',
                'protocol': '-',
                'no_route': True,
                'device_count': len(devices_with_vrf),
                'expected_device_count': len(devices_with_vrf),
                'devices_without_route': without_route,
            }]
    
    warnings = sorted(set(warnings))
    failed_devices = sorted(set(failed_devices))
    expected_device_count = len(summary_devices) if summary_devices else candidate_file_count
    print(json.dumps({
        "success": True,
        "vrf_routes": results,
        "cached": True,
        "warnings": warnings,
        "partial": bool(warnings),
        "complete": not warnings,
        "processed_device_count": processed_device_count,
        "failed_device_count": len(failed_devices),
        "expected_device_count": expected_device_count,
        "missing_devices": failed_devices,
        "devices_without_route": devices_without_route,
        "route_coverage": route_coverage,
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
from datetime import datetime, timezone

source_ip = sys.argv[1]
dest_ip = sys.argv[2]
vrf_hint = sys.argv[3]
dst_vrf_hint = sys.argv[4]

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
web_root = os.environ.get('WEB_ROOT', '/var/www/html')
lldp_file = os.path.join(web_root, 'lldp_results.ini')
local_timezone = datetime.now().astimezone().tzinfo

# ─── Utility functions ───

def require_ipv4(value, label):
    """Reject malformed, IPv6 and non-canonical address input at the API edge."""
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        print(json.dumps({"error": f"Invalid {label} IPv4 address."}))
        raise SystemExit(0)
    if not isinstance(parsed, ipaddress.IPv4Address):
        print(json.dumps({"error": f"Invalid {label} IPv4 address."}))
        raise SystemExit(0)
    return str(parsed)

source_ip = require_ipv4(source_ip, "source")
dest_ip = require_ipv4(dest_ip, "destination")

warnings = []
warning_codes = set()

def add_warning(code, message, **details):
    """Add a stable, machine-readable warning without changing legacy fields."""
    if code in warning_codes:
        return
    warning = {"code": code, "message": message}
    warning.update(details)
    warnings.append(warning)
    warning_codes.add(code)

def parse_iso_timestamp(value):
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=local_timezone)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None

def cache_max_age_seconds():
    try:
        return max(60, int(os.environ.get('TRACEPATH_CACHE_MAX_AGE_SECONDS', '300')))
    except (TypeError, ValueError):
        return 300

def prefix_match(ip, prefix):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        if ipaddress.ip_address(ip) in net:
            return net.prefixlen
        return -1
    except:
        return -1

def find_best_route(ip, routes, vrf):
    candidates = []
    for r in routes.get(vrf, []):
        p = r.get('prefix', '')
        if p:
            ml = prefix_match(ip, p)
            if ml < 0:
                continue
            try:
                metric = int(r.get('metric') or 0)
            except (TypeError, ValueError):
                metric = 0
            candidates.append((
                -ml,
                -int(route_is_usable(r)),
                metric,
                json.dumps(r, sort_keys=True, separators=(',', ':')),
                r,
            ))
    if not candidates:
        return None, -1
    candidates.sort(key=lambda candidate: candidate[:-1])
    selected = candidates[0]
    return selected[-1], -selected[0]

def route_is_usable(route):
    """Fabric scan normally filters rejects; keep the API safe for old caches too."""
    if not isinstance(route, dict):
        return False
    protocol = str(route.get('protocol', '')).strip().lower()
    nexthop = str(route.get('nexthop', '')).strip().lower()
    route_type = str(route.get('type', '')).strip().lower()
    rejected = {'unreachable', 'blackhole', 'prohibit', 'throw', 'reject'}
    return protocol not in rejected and nexthop not in rejected and route_type not in rejected

def base(name):
    """Extract base hostname: 'csw-3na-17-39 @core' -> 'csw-3na-17-39'"""
    if not isinstance(name, str) or not name:
        return ''
    return name.split(' ')[0] if ' ' in name else name

def load_all_data():
    all_data = {}
    invalid_files = []
    if not os.path.exists(tables_dir):
        return all_data
    for fn in sorted(os.listdir(tables_dir)):
        if not fn.endswith('.json') or fn == 'summary.json':
            continue
        try:
            with open(os.path.join(tables_dir, fn)) as f:
                data = json.load(f)
            if isinstance(data, dict):
                all_data[fn.replace('.json', '')] = data
            else:
                invalid_files.append(fn)
        except (OSError, json.JSONDecodeError):
            invalid_files.append(fn)
    if invalid_files:
        add_warning(
            'cache_file_invalid',
            'One or more device cache files could not be read; path coverage may be incomplete.',
            invalid_files=sorted(invalid_files),
        )
    return all_data

def load_data_quality(all_data):
    """Describe cache coverage and surface stale/partial evidence to callers."""
    summary_path = os.path.join(tables_dir, 'summary.json')
    summary = None
    try:
        with open(summary_path, encoding='utf-8') as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            summary = loaded
    except (OSError, json.JSONDecodeError):
        pass

    if summary is None:
        counts = {'current': 0, 'stale': 0, 'unavailable': 0}
        for data in all_data.values():
            collection = data.get('_collection', {})
            status = collection.get('status', 'current') if isinstance(collection, dict) else 'current'
            if status not in counts:
                status = 'unavailable'
            counts[status] += 1
        complete = counts['stale'] == 0 and counts['unavailable'] == 0
        quality = {
            'complete': complete,
            'timestamp': None,
            'status_counts': counts,
        }
        add_warning(
            'collection_summary_missing',
            'Fabric collection summary is unavailable; path coverage may be incomplete.'
        )
    else:
        raw_counts = summary.get('status_counts', {})
        counts = {}
        for status in ('current', 'stale', 'unavailable'):
            try:
                counts[status] = max(0, int(raw_counts.get(status, 0)))
            except (TypeError, ValueError, AttributeError):
                counts[status] = 0
        complete = bool(summary.get('complete', False))
        quality = {
            'complete': complete,
            'timestamp': summary.get('timestamp'),
            'status_counts': counts,
        }

    counts = quality['status_counts']
    if not quality['complete'] or counts.get('stale', 0) or counts.get('unavailable', 0):
        add_warning(
            'partial_snapshot',
            'Trace uses partial fabric data; one or more device snapshots are stale or unavailable.',
            stale_devices=counts.get('stale', 0),
            unavailable_devices=counts.get('unavailable', 0),
        )

    timestamp = parse_iso_timestamp(quality.get('timestamp'))
    if timestamp is not None:
        age = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))
        quality['age_seconds'] = age
        if age > cache_max_age_seconds():
            add_warning(
                'stale_snapshot',
                'Fabric data is older than the Tracepath freshness threshold.',
                age_seconds=age,
            )
    return quality

# ─── LLDP parsing ───

def load_lldp_data():
    """Parse lldp_results.ini -> neighbors, port_neighbors, link_status.
    neighbors: {device: set(neighbor_devices)}
    port_neighbors: {device: {port: neighbor_device}}
    link_status: {(device_a, device_b): {'up': N, 'down': N, 'fail': N}}

    Physical links are keyed by both endpoint ports, so reciprocal LLDP rows
    count once. Explicitly DOWN links remain in health data but are excluded
    from the routing graph.
    """
    neighbors = {}
    port_neighbors = {}  # {device: {port: neighbor}}
    link_status = {}
    quality = {
        'available': False,
        'timestamp': None,
        'age_seconds': None,
        'rows': 0,
        'invalid_rows': 0,
        'down_links': 0,
    }
    
    if not os.path.exists(lldp_file):
        return neighbors, port_neighbors, link_status, quality
    
    try:
        with open(lldp_file, encoding='utf-8') as f:
            content = f.read()

        if not content.strip():
            return neighbors, port_neighbors, link_status, quality
        quality['available'] = True
        first_nonempty = next((line.strip() for line in content.splitlines() if line.strip()), '')
        timestamp_match = re.match(
            r'^Created on (\d{4}-\d{2}-\d{2} \d{2}-\d{2}(?:-\d{2})?)$',
            first_nonempty,
        )
        if timestamp_match:
            raw_timestamp = timestamp_match.group(1)
            timestamp_format = '%Y-%m-%d %H-%M-%S' if raw_timestamp.count('-') == 4 else '%Y-%m-%d %H-%M'
            try:
                parsed_timestamp = datetime.strptime(raw_timestamp, timestamp_format).replace(tzinfo=local_timezone)
                quality['timestamp'] = parsed_timestamp.isoformat()
                quality['age_seconds'] = max(
                    0, int((datetime.now(timezone.utc) - parsed_timestamp).total_seconds())
                )
            except ValueError:
                quality['timestamp'] = None
        
        current_device = None
        physical_links = {}
        invalid_neighbor_values = {
            '', '-', 'none', 'n/a', 'no-info', 'no_info', 'unknown', 'act-nbr'
        }

        def physical_link_key(device, local_port, neighbor, neighbor_port):
            left = (base(device), local_port)
            right = (base(neighbor), neighbor_port)
            if neighbor_port.lower() not in invalid_neighbor_values:
                return tuple(sorted((left, right)))
            # A legacy row without the remote port cannot be safely paired
            # with its reciprocal row. Keep the local endpoint in the key to
            # avoid collapsing genuine parallel links.
            return (tuple(sorted((base(device), base(neighbor)))), left)

        state_rank = {'up': 0, 'fail': 1, 'down': 2}
        for line in content.split('\n'):
            m = re.match(r'^=+\s+(\S+)\s+=+$', line)
            if m:
                current_device = base(m.group(1))
                neighbors.setdefault(current_device, set())
                port_neighbors.setdefault(current_device, {})
                continue
            
            stripped = line.strip()
            if (not current_device or not stripped or stripped.startswith('-') or
                    stripped.startswith('Port') or stripped.startswith('Created')):
                continue
            
            parts = stripped.split()
            if len(parts) >= 7:
                local_port = parts[0]   # swp1s0
                validation_status = parts[1].upper()  # Pass/Fail/No-Info
                act_nbr_raw = parts[4]                # Actual neighbor
                act_nbr_port = parts[5]               # Actual neighbor port
                port_status = parts[6].upper()         # UP/DOWN/UNKNOWN

                if act_nbr_raw.lower() in invalid_neighbor_values:
                    quality['invalid_rows'] += 1
                    continue

                act_nbr = base(act_nbr_raw)
                quality['rows'] += 1
                if port_status == 'DOWN':
                    state = 'down'
                elif validation_status == 'FAIL':
                    state = 'fail'
                else:
                    state = 'up'

                key = physical_link_key(current_device, local_port, act_nbr, act_nbr_port)
                observation = physical_links.get(key)
                mapping = (current_device, local_port, act_nbr)
                if observation is None:
                    physical_links[key] = {
                        'devices': tuple(sorted((current_device, act_nbr))),
                        'state': state,
                        'mappings': {mapping},
                    }
                else:
                    observation['mappings'].add(mapping)
                    if state_rank[state] > state_rank[observation['state']]:
                        observation['state'] = state
            elif parts and not stripped.startswith('='):
                quality['invalid_rows'] += 1

        for observation in physical_links.values():
            device_pair = observation['devices']
            status = link_status.setdefault(
                device_pair, {'up': 0, 'down': 0, 'fail': 0}
            )
            state = observation['state']
            status[state] += 1
            if state == 'down':
                quality['down_links'] += 1
                continue

            device_a, device_b = device_pair
            neighbors.setdefault(device_a, set()).add(device_b)
            neighbors.setdefault(device_b, set()).add(device_a)
            for device, local_port, neighbor in observation['mappings']:
                port_neighbors.setdefault(device, {})[local_port] = neighbor
    except (OSError, UnicodeError, ValueError):
        quality['available'] = False

    return neighbors, port_neighbors, link_status, quality

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
    
    The "nexthop signature" is the set of exact ECMP nexthop addresses.
    The most common signature = regular leaves. Outliers = border leaves.
    A tied majority is intentionally treated as ambiguous: returning no
    border is safer than presenting a topology-order-dependent egress.
    """
    # Collect each leaf's default route nexthop signature.
    leaf_signatures = {}  # hostname -> tuple of exact nexthop addresses
    signature_tiers = {}
    
    for hostname in sorted(all_data):
        data = all_data[hostname]
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
            nexthops = set()
            
            if nh and nh not in ('', '-', 'ECMP', 'link-local', 'unreachable', 'connected'):
                try:
                    parsed_nh = ipaddress.ip_address(nh)
                    if isinstance(parsed_nh, ipaddress.IPv4Address):
                        nexthops.add(str(parsed_nh))
                except ValueError:
                    pass
            
            if nh == 'ECMP':
                ecmp_nhs = r.get('ecmp_nexthops', [])
                for enh in ecmp_nhs:
                    enh_ip = enh.get('ip', '')
                    try:
                        parsed_nh = ipaddress.ip_address(enh_ip)
                        if isinstance(parsed_nh, ipaddress.IPv4Address):
                            nexthops.add(str(parsed_nh))
                    except ValueError:
                        pass
            
            if nexthops:
                leaf_signatures[hostname] = tuple(sorted(nexthops))
                signature_tiers[hostname] = tier_func(hostname)
            break
    
    if not leaf_signatures:
        return []
    
    # All signatures contribute to the majority because incomplete LLDP often
    # leaves regular leaves un-tiered. Once outliers are known, however, a
    # confirmed tier-0 outlier is always preferred; known spine/core outliers
    # are never returned while any tier-0 signature evidence exists.
    if len(leaf_signatures) < 2:
        return []

    # Find the most common signature (= regular leaves pointing to spines)
    from collections import Counter
    sig_counts = Counter(leaf_signatures.values())
    ranked_signatures = sorted(
        sig_counts.items(), key=lambda item: (-item[1], item[0])
    )
    if not ranked_signatures:
        return []
    if len(ranked_signatures) > 1 and ranked_signatures[0][1] == ranked_signatures[1][1]:
        return []
    most_common_sig = ranked_signatures[0][0]
    most_common_count = ranked_signatures[0][1]
    if most_common_count < 2 or most_common_count * 2 <= len(leaf_signatures):
        return []
    
    # Border leaves = leaves with a DIFFERENT signature than the majority
    outliers = [h for h, sig in leaf_signatures.items() if sig != most_common_sig]
    tier_zero_outliers = [h for h in outliers if signature_tiers.get(h) == 0]
    if tier_zero_outliers:
        return sorted(tier_zero_outliers)
    if any(tier == 0 for tier in signature_tiers.values()):
        return []
    if outliers:
        add_warning(
            'border_inference_low_confidence',
            'Border inference used devices without a confirmed leaf tier.'
        )
    return sorted(outliers)

# ─── Main logic ───

try:
    all_data = load_all_data()
    if not all_data:
        print(json.dumps({"error": "No cached data. Run Fabric Scan first."}))
        exit()

    data_quality = load_data_quality(all_data)
    lldp_neighbors, lldp_port_neighbors, lldp_link_status, lldp_quality = load_lldp_data()
    data_quality['lldp'] = lldp_quality
    if not lldp_quality.get('available'):
        add_warning(
            'lldp_snapshot_missing',
            'LLDP topology data is unavailable; transit-hop coverage may be incomplete.'
        )
    elif lldp_quality.get('age_seconds') is not None and lldp_quality['age_seconds'] > cache_max_age_seconds():
        add_warning(
            'stale_lldp_snapshot',
            'LLDP topology data is older than the Tracepath freshness threshold.',
            age_seconds=lldp_quality['age_seconds'],
        )
    if lldp_quality.get('invalid_rows', 0):
        add_warning(
            'partial_lldp_snapshot',
            'Some LLDP rows were incomplete or had no usable actual neighbor.',
            invalid_rows=lldp_quality['invalid_rows'],
        )
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
    
    def find_device_prefer_leaf(ip, prefer_vrf=None, require_vrf=False,
                                allow_route_fallback=True):
        candidates = []
        for hostname in sorted(all_data):
            data = all_data[hostname]
            for arp in data.get('arp', []):
                if arp.get('ip') == ip:
                    v = arp.get('vrf', 'default') or 'default'
                    if require_vrf and prefer_vrf and v != prefer_vrf:
                        continue
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
        if not candidates and allow_route_fallback:
            for hostname in sorted(all_data):
                data = all_data[hostname]
                for v in sorted(data.get('routes', {})):
                    if require_vrf and prefer_vrf and v != prefer_vrf:
                        continue
                    vr = data.get('routes', {}).get(v, [])
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
            return (vrf_match, x[2], x[3], base(x[0]), x[0], x[1])
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
        """Count canonical links; validation mismatches are still physically up."""
        up, down, mismatch = 0, 0, 0
        b_src = base(src_device)
        seen_pairs = set()
        for dst in sorted(set(dst_devices)):
            b_dst = base(dst)
            if not b_src or not b_dst or b_src == b_dst:
                continue
            pair = tuple(sorted((b_src, b_dst)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            status = lldp_link_status.get(pair, {})
            mismatched_links = status.get('fail', 0)
            up += status.get('up', 0) + mismatched_links
            down += status.get('down', 0)
            mismatch += mismatched_links
        return up, down, mismatch
    
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

        # A layer is only on-path when both leaf sides have an active LLDP
        # attachment. Do not fill a missing side with the other side's spine;
        # that would reintroduce an explicitly DOWN edge into the rendering.
        if not src_spines or not dst_spines:
            return []
        
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
            if not cores:
                return []
            layers.append({"tier": 2, "devices": sorted(cores), "label": "Core"})
            if dst_spines and dst_spines != src_spines:
                layers.append({"tier": 1, "devices": dst_spines, "label": "Spine"})
            
            return layers
    
    # ─── Resolve source and dest ───

    def emit_trace_error(message):
        response = {"error": message}
        if warnings:
            response['warnings'] = warnings
        response['data_quality'] = data_quality
        print(json.dumps(response))
        raise SystemExit(0)

    source_leaf, detected_vrf = find_device_prefer_leaf(source_ip, vrf_hint)
    if not source_leaf:
        emit_trace_error(f"Source IP {source_ip} not found in any device.")

    # VRF resolution starts with the source. Destination lookup must use the
    # destination hint, not the source hint, to handle overlapping address
    # space correctly.
    src_vrf = vrf_hint if vrf_hint else (detected_vrf or 'default')
    selected_dst_vrf = dst_vrf_hint if dst_vrf_hint else src_vrf

    # Check if dest IP is local to the fabric (in ANY device's ARP, any VRF).
    # Must check BEFORE error handling — external IPs (8.8.8.8) won't be in
    # any device and that's OK.
    destination_vrfs = set()
    connected_destination_vrfs = set()
    for hn in sorted(all_data):
        dd = all_data[hn]
        for arp in dd.get('arp', []):
            if arp.get('ip') == dest_ip:
                destination_vrfs.add(arp.get('vrf', 'default') or 'default')
        for route_vrf, routes in dd.get('routes', {}).items():
            for route in routes:
                if str(route.get('protocol', '')).lower() not in {'connected', 'kernel', 'local'}:
                    continue
                route_prefix = route.get('prefix', '')
                if route_prefix and prefix_match(dest_ip, route_prefix) > 0:
                    connected_destination_vrfs.add(route_vrf or 'default')
    dest_is_local = bool(destination_vrfs)

    if not dest_is_local and connected_destination_vrfs:
        add_warning(
            'fabric_endpoint_unresolved',
            'Destination belongs to a connected fabric subnet but has no current endpoint/ARP record.',
            candidate_vrfs=sorted(connected_destination_vrfs),
        )
        emit_trace_error(
            f"Destination IP {dest_ip} is in a connected fabric subnet, but its endpoint could not be resolved."
        )

    if dest_is_local:
        # First require the selected destination VRF. If the IP does not exist
        # there, preserve the old auto-correction behavior, but re-resolve the
        # leaf in the detected VRF so device and VRF cannot disagree.
        dest_leaf, detected_dest_vrf = find_device_prefer_leaf(
            dest_ip, selected_dst_vrf, require_vrf=True,
            allow_route_fallback=False,
        )
        if dest_leaf:
            dst_vrf = selected_dst_vrf
        else:
            dest_leaf, detected_dest_vrf = find_device_prefer_leaf(
                dest_ip, selected_dst_vrf, allow_route_fallback=False
            )
            if not dest_leaf:
                emit_trace_error(f"Destination IP {dest_ip} not found in any device.")
            dst_vrf = detected_dest_vrf or sorted(destination_vrfs)[0]
            if selected_dst_vrf != dst_vrf:
                add_warning(
                    'destination_vrf_corrected',
                    'Destination IP was not present in the selected VRF; the detected VRF was used.',
                    requested_vrf=selected_dst_vrf,
                    detected_vrf=dst_vrf,
                )

        resolved_leaf, resolved_vrf = find_device_prefer_leaf(
            dest_ip, dst_vrf, require_vrf=True,
            allow_route_fallback=False,
        )
        if not resolved_leaf:
            emit_trace_error(
                f"Destination IP {dest_ip} could not be resolved in VRF {dst_vrf}."
            )
        dest_leaf, dst_vrf = resolved_leaf, resolved_vrf or dst_vrf
    else:
        # An external address has no destination-side fabric VRF. Treat it as
        # an exit from the source VRF and never pass None as a topology node.
        dest_leaf = None
        dst_vrf = src_vrf
        if dst_vrf_hint and dst_vrf_hint != src_vrf:
            add_warning(
                'destination_vrf_ignored_external',
                'Destination VRF was ignored because the destination is external to the fabric.',
                requested_vrf=dst_vrf_hint,
                effective_vrf=src_vrf,
            )

    vrf = src_vrf

    # ─── Route leak detection ───
    # A specific route alone is not proof of a VRF leak: a firewall route is
    # also commonly specific/BGP. Only explicit collector metadata or a
    # dedicated protocol value may suppress the inter-VRF gateway.
    def route_has_explicit_leak_evidence(route, from_vrf):
        if not isinstance(route, dict):
            return False
        metadata = route.get('route_leak')
        if metadata is True:
            return True
        if isinstance(metadata, dict):
            metadata_from = metadata.get('from_vrf') or metadata.get('source_vrf')
            if not metadata_from or metadata_from == from_vrf:
                return True
        leaked_from = route.get('leaked_from_vrf') or route.get('imported_from_vrf')
        if leaked_from and leaked_from == from_vrf:
            return True
        protocol = str(route.get('protocol', '')).strip().lower()
        return protocol in {'vrf-leak', 'route-leak', 'leaked'}

    route_leak_info = None  # Track leak for UI display
    src_data = all_data.get(source_leaf, {})
    source_route, source_route_len = find_best_route(
        dest_ip, src_data.get('routes', {}), src_vrf
    )
    if not source_route or source_route_len < 0 or not route_is_usable(source_route):
        emit_trace_error(
            f"No usable route from {source_ip} to {dest_ip} in VRF {src_vrf}."
        )
    if (dest_is_local and src_vrf == dst_vrf and source_leaf != dest_leaf and
            source_route_len == 0):
        emit_trace_error(
            f"No specific intra-VRF route from {source_ip} to {dest_ip} in VRF {src_vrf}."
        )

    if src_vrf != dst_vrf and source_leaf and dest_is_local:
        if source_route_len > 0 and route_has_explicit_leak_evidence(source_route, dst_vrf):
            route_leak_info = {
                "from_vrf": dst_vrf,
                "to_vrf": src_vrf,
                "prefix": source_route.get('prefix', ''),
                "protocol": source_route.get('protocol', '')
            }
            dst_vrf = src_vrf

    has_inter_vrf = (src_vrf != dst_vrf)

    # External = dest not in fabric ARP (same VRF, traffic exits via border leaf)
    dest_is_external = not dest_is_local
    has_external = has_inter_vrf  # keep for backward compat in build_path
    
    # ─── Build path ───
    
    def map_to_fabric_name(lldp_name):
        """Map LLDP hostname to fabric-table key."""
        b = base(lldp_name)
        for key in sorted(all_data):
            if base(key) == b:
                return key
        return lldp_name

    trace_state = {'egress_resolved': True}

    def build_path():
        path = []
        
        # Source endpoint
        path.append({"device": source_ip, "role": "endpoint_src", "indent": 0})
        
        # Source leaf
        route = source_route
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
            borders = sorted(set(borders))
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
                mapped_borders = sorted(set(map_to_fabric_name(b) for b in borders))
                source_is_border = source_leaf in mapped_borders
                destination_is_border = dest_leaf in mapped_borders
                # Source → fabric layers → Border
                if not source_is_border:
                    s2b = find_on_path_layers(source_leaf, border)
                    if not s2b:
                        add_warning(
                            'topology_path_incomplete',
                            'No active LLDP transit path was found for one or more routed segments.'
                        )
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
                if not destination_is_border:
                    path.append(make_border_hop(borders, dst_vrf, border_indent))
                    b2d = find_on_path_layers(border, dest_leaf)
                    if not b2d:
                        add_warning(
                            'topology_path_incomplete',
                            'No active LLDP transit path was found for one or more routed segments.'
                        )
                    for idx, layer in enumerate(b2d):
                        devices = sorted(set(map_to_fabric_name(d) for d in layer["devices"]))
                        layer_indent = max(2, border_indent - idx - 1)
                        path.append(make_layer_hop(devices, dst_vrf, layer_indent, layer["label"], layer.get("tier", 1)))
            else:
                trace_state['egress_resolved'] = False
                add_warning(
                    'unknown_egress',
                    'The routed egress could not be mapped to a unique border leaf.'
                )
                layers = find_on_path_layers(source_leaf, dest_leaf)
                if not layers and source_leaf != dest_leaf:
                    add_warning(
                        'topology_path_incomplete',
                        'No active LLDP transit path was found for one or more routed segments.'
                    )
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
                mapped_borders = sorted(set(map_to_fabric_name(b) for b in borders))
                source_is_border = source_leaf in mapped_borders
                if not source_is_border:
                    s2b = find_on_path_layers(source_leaf, border)
                    if not s2b:
                        add_warning(
                            'topology_path_incomplete',
                            'No active LLDP transit path was found for one or more routed segments.'
                        )
                    # Add ALL layers as ascending (one-way, no descent)
                    add_ascending(path, s2b, src_vrf)
                    border_indent = max(h.get('indent', 0) for h in path) + 1
                    path.append(make_border_hop(borders, src_vrf, border_indent))
                else:
                    path[-1]["label"] = "Source & Border Leaf"

                peak = max(h.get('indent', 0) for h in path) + 1
                path.append({"device": "External Network", "role": "external",
                             "indent": peak, "src_vrf": src_vrf, "dst_vrf": "external"})
            else:
                trace_state['egress_resolved'] = False
                add_warning(
                    'unknown_egress',
                    'The routed egress could not be mapped to a unique border leaf.'
                )
                peak = max(h.get('indent', 0) for h in path) + 1
                path.append({"device": "External Network", "role": "external",
                             "indent": peak, "src_vrf": src_vrf,
                             "dst_vrf": "external", "resolved": False})
            
            # Dest endpoint (traffic exits fabric)
            path.append({"device": dest_ip, "role": "endpoint_dst", "indent": 0})
        
        else:
            # ── Same-VRF local: Source → layers → Dest ──
            layers = find_on_path_layers(source_leaf, dest_leaf)
            if not layers and source_leaf != dest_leaf:
                add_warning(
                    'topology_path_incomplete',
                    'No active LLDP transit path was found for one or more routed segments.'
                )
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
            
            total_up, total_down, total_mismatch = 0, 0, 0
            
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
                        u, d, m = get_link_health(base(pd), ecmp_devs)
                        total_up += u
                        total_down += d
                        total_mismatch += m
            
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
                        u, d, m = get_link_health(base(nd), ecmp_devs)
                        total_up += u
                        total_down += d
                        total_mismatch += m
            
            if total_up > 0 or total_down > 0:
                hop['links_up'] = total_up
                hop['links_down'] = total_down
                if total_mismatch:
                    hop['links_mismatch'] = total_mismatch
    
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
        "tiers_found": len(set(device_tiers.values())) if device_tiers else 0,
        "path_basis": "cached-fib-active-lldp-inference",
        "warnings": warnings,
        "data_quality": data_quality,
    }
    if has_external or dest_is_external:
        result['egress_resolved'] = trace_state['egress_resolved']
    # Only include dest_device for fabric-local destinations
    if dest_is_local and dest_leaf:
        result["dest_device"] = dest_leaf
    
    # Include route leak info if detected
    if route_leak_info:
        result["route_leak"] = route_leak_info
    
    print(json.dumps(result))

except Exception as e:
    print(f"trace-path-ip failed: {type(e).__name__}: {e}", file=sys.stderr)
    print(json.dumps({"error": "Trace path computation failed."}))
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
    print(f"trace-path failed: {type(e).__name__}: {e}", file=sys.stderr)
    print(json.dumps({"error": "Trace path computation failed."}))
PYTHON
}

# Search cached fabric tables (fast)
search_cached_tables() {
    local table_type="$1"
    local search="$2"
    
    python3 - "$table_type" "$search" <<'PYTHON'
import ipaddress
import json
import os
import re
import sys

lldpq_dir = os.environ.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
tables_dir = f"{lldpq_dir}/monitor-results/fabric-tables"
summary_file = os.path.join(tables_dir, "summary.json")
table_type = sys.argv[1]
search = sys.argv[2].lower()

# Detect if search is a full IP (4 octets) → use exact match on IP/ip fields
try:
    ipaddress.IPv4Address(search)
    is_full_ip = True
except ipaddress.AddressValueError:
    is_full_ip = False

entries = []
warnings = []
candidate_file_count = 0
processed_device_count = 0
summary_devices = {}
snapshot_hostnames = set()
failed_devices = set()

try:
    if not os.path.exists(tables_dir):
        print(json.dumps({"success": False, "error": "No cached data. Run Fabric Scan first."}))
        exit()

    if os.path.exists(summary_file):
        try:
            with open(summary_file) as summary_handle:
                summary = json.load(summary_handle)
            for device in summary.get('devices', []):
                if not isinstance(device, dict) or not device.get('hostname'):
                    continue
                summary_devices[str(device['hostname'])] = str(device.get('status', 'unknown'))
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            warnings.append(f"summary.json: {exc}")
    
    for filename in os.listdir(tables_dir):
        if not filename.endswith('.json') or filename == 'summary.json':
            continue
        candidate_file_count += 1
        
        hostname = filename.replace('.json', '')
        snapshot_hostnames.add(hostname)
        filepath = os.path.join(tables_dir, filename)
        
        try:
            with open(filepath) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("snapshot is not a JSON object")
            processed_device_count += 1

            collection = data.get('_collection', {})
            if isinstance(collection, dict):
                collection_status = collection.get('status')
                if collection_status in {'stale', 'unavailable'}:
                    warnings.append(f"{filename}: snapshot status is {collection_status}")

            if table_type not in data:
                warnings.append(f"{filename}: snapshot is missing {table_type}")
                continue
            table_data = data[table_type]
            if not isinstance(table_data, list):
                warnings.append(f"{filename}: {table_type} is not a list")
                continue

            skipped_entries = 0
            
            for cached_entry in table_data:
                if not isinstance(cached_entry, dict):
                    skipped_entries += 1
                    continue
                entry = dict(cached_entry)
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
            if skipped_entries:
                warnings.append(
                    f"{filename}: skipped {skipped_entries} malformed {table_type} "
                    f"entr{'y' if skipped_entries == 1 else 'ies'}"
                )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            warnings.append(f"{filename}: {exc}")
            failed_devices.add(hostname)

    for hostname, status in summary_devices.items():
        if hostname not in snapshot_hostnames:
            warnings.append(f"{hostname}: {status} device has no cached snapshot")
            failed_devices.add(hostname)
        elif status in {'stale', 'unavailable'}:
            warnings.append(f"{hostname}: snapshot status is {status}")
            if status == 'unavailable':
                failed_devices.add(hostname)

    if candidate_file_count == 0:
        print(json.dumps({
            "success": False,
            "error": "No cached device data. Run Fabric Scan first.",
            "warnings": warnings,
            "partial": False,
            "complete": False,
        }))
        raise SystemExit(0)
    if processed_device_count == 0:
        print(json.dumps({
            "success": False,
            "error": "Cached table data is unreadable or invalid",
            "warnings": warnings,
            "partial": True,
            "complete": False,
            "processed_device_count": 0,
            "failed_device_count": candidate_file_count,
        }))
        raise SystemExit(0)
    
    warnings = sorted(set(warnings))
    expected_device_count = len(summary_devices) if summary_devices else candidate_file_count
    limit = 500
    returned = entries[:limit]
    print(json.dumps({
        "success": True,
        "entries": returned,
        "total": len(entries),
        "returned_total": len(returned),
        "limit": limit,
        "truncated": len(returned) < len(entries),
        "cached": True,
        "warnings": warnings,
        "partial": bool(warnings),
        "complete": not warnings,
        "processed_device_count": processed_device_count,
        "failed_device_count": len(failed_devices),
        "expected_device_count": expected_device_count,
        "missing_devices": sorted(failed_devices),
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
        SOURCE_IP=$(get_query_param source_ip)
        DEST_IP=$(get_query_param dest_ip)
        VRF=$(get_query_param vrf)
        DST_VRF=$(get_query_param dst_vrf)
        trace_path_ip "$SOURCE_IP" "$DEST_IP" "$VRF" "$DST_VRF"
        ;;
    "get-vrfs")
        get_vrfs
        ;;
    *)
        echo '{"success": false, "error": "Invalid action"}'
        ;;
esac
