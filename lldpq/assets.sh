#!/usr/bin/env bash
# LLDPq Topology Check Script  
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License
set -euo pipefail

#### CONFIGURATION
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
eval "$(python3 "$SCRIPT_DIR/parse_devices.py")"

# Load config with fallback
source /etc/lldpq.conf 2>/dev/null || true
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
ASSETS_MAX_PARALLEL="${ASSETS_MAX_PARALLEL:-50}"
case "$ASSETS_MAX_PARALLEL" in
  ''|*[!0-9]*|0) ASSETS_MAX_PARALLEL=50 ;;
esac

TMPFILE="$SCRIPT_DIR/assets.tmp"
UNREACH="$SCRIPT_DIR/unreachable.tmp"
FINAL="$SCRIPT_DIR/assets.ini"
CACHE_FILE="$WEB_ROOT/device-cache.json"
export WEB_ROOT FINAL

rm -f "$TMPFILE" "$UNREACH"

#### CACHE FUNCTIONS
# Initialize cache file if not exists
init_cache() {
  if [[ ! -f "$CACHE_FILE" ]]; then
    echo '{}' | sudo tee "$CACHE_FILE" > /dev/null
    sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$CACHE_FILE"
    sudo chmod 664 "$CACHE_FILE"
  fi
}

# Update cache with device info (called after successful data collection)
update_cache() {
  local hostname="$1" ip="$2" mac="$3" serial="$4" model="$5" release="$6" uptime="$7"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  python3 << PYTHON_END
import json
import os

cache_file = "$CACHE_FILE"
try:
    with open(cache_file, 'r') as f:
        cache = json.load(f)
except:
    cache = {}

cache["$hostname"] = {
    "hostname": "$hostname",
    "ip": "$ip",
    "mac": "$mac",
    "serial": "$serial",
    "model": "$model",
    "release": "$release",
    "uptime": "$uptime",
    "last_seen": "$timestamp",
    "status": "ok"
}

with open(cache_file, 'w') as f:
    json.dump(cache, f, indent=2)
PYTHON_END
}

# Get cached data for unreachable device
get_cached_device() {
  local hostname="$1"
  
  python3 << PYTHON_END
import json
import sys

cache_file = "$CACHE_FILE"
try:
    with open(cache_file, 'r') as f:
        cache = json.load(f)
    
    if "$hostname" in cache:
        d = cache["$hostname"]
        # Output: ip mac serial model release uptime last_seen
        print(f"{d.get('ip', 'No-Info')}|{d.get('mac', 'No-Info')}|{d.get('serial', 'No-Info')}|{d.get('model', 'No-Info')}|{d.get('release', 'No-Info')}|{d.get('uptime', 'No-Info')}|{d.get('last_seen', 'Never')}")
    else:
        print("NOCACHE")
except Exception as e:
    print("NOCACHE")
PYTHON_END
}

init_cache

#### REMOTE INFO FUNCTION
remote_info() {
  # 1) HOSTNAME
  h="$HOSTNAME"
  # 2) IPv4
  ip4=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
  # 3) MAC
  mac=$(cat /sys/class/net/eth0/address 2>/dev/null)
  # 4) SERIAL (fast alternative) — strip whitespace, replace spaces with dashes
  serial=$(sudo dmidecode -s system-serial-number 2>/dev/null | head -1 | xargs)
  [[ -z "$serial" ]] && serial="NA"
  serial="${serial// /-}"
  # 5) MODEL (fast alternative) — strip whitespace, replace spaces with dashes
  model=$(sudo dmidecode -s system-product-name 2>/dev/null | head -1 | xargs)
  [[ -z "$model" ]] && model="NA"
  model="${model// /-}"
  # 6) RELEASE
  rel=$(grep RELEASE /etc/lsb-release 2>/dev/null | cut -d "=" -f2)
  [[ -z "$rel" ]] && rel="NA"
  # 7) UPTIME
  up=$(uptime -p 2>/dev/null | sed 's/,//g; s/ /-/g')
  [[ -z "$up" ]] && up="NA"

  # Print 7 columns (STATUS and LAST-SEEN will be added by collect function)
  printf '%s %s %s %s %s %s %s\n' \
    "$h" "$ip4" "$mac" "$serial" "$model" "$rel" "$up"
}

#### HEADER (9 columns - added STATUS and LAST-SEEN)
printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
  "DEVICE-NAME" "IP" "ETH0-MAC" "SERIAL" "MODEL" "RELEASE" "UPTIME" "STATUS" "LAST-SEEN" > "$TMPFILE"

#### WORKFLOW
# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds 'ip rule' for mgmt VRF so plain ping works. No ip vrf exec needed.
PING="ping"

ping_test() {
  local ip=$1 host=$2
  if ! $PING -c1 -W1 "$ip" &>/dev/null; then
    echo "$host" >> "$UNREACH"
    return 1
  fi
}

collect() {
  local ip=$1 user=$2 host=$3
  local now=$(date '+%Y-%m-%d_%H:%M')
  
  # Try SSH connection and capture result
  local ssh_output
  if ssh_output=$(ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no \
      "$user@$ip" "$(declare -f remote_info); remote_info" 2>/dev/null); then
    # SSH successful - parse and write with STATUS=OK and LAST-SEEN=now
    local r_host r_ip r_mac r_serial r_model r_release r_uptime
    read -r r_host r_ip r_mac r_serial r_model r_release r_uptime <<< "$ssh_output"
    
    # Ensure all fields have values (some platforms return empty fields)
    [[ -z "$r_ip" ]] && r_ip="$ip"
    [[ -z "$r_mac" ]] && r_mac="NA"
    [[ -z "$r_serial" ]] && r_serial="NA"
    [[ -z "$r_model" ]] && r_model="NA"
    [[ -z "$r_release" ]] && r_release="NA"
    [[ -z "$r_uptime" ]] && r_uptime="NA"
    
    # Use devices.yaml hostname ($host) for consistency, not remote hostname
    printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
      "$host" "$r_ip" "$r_mac" "$r_serial" "$r_model" "$r_release" "$r_uptime" "OK" "$now" \
      >> "$TMPFILE"
    
    return 0
  else
    # SSH failed - add device with SSH-FAILED status
    printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
      "$host" "$ip" "N/A" "N/A" "N/A" "N/A" "N/A" "SSH-FAILED" "$now" \
      >> "$TMPFILE"
    return 1
  fi
}

process_one() {
  local ip=$1 entry=$2 user host
  read -r user host <<< "$entry"
  if ping_test "$ip" "$host"; then
    collect "$ip" "$user" "$host"
  fi
}

wait_for_slot() {
  while (( $(jobs -rp | wc -l) >= ASSETS_MAX_PARALLEL )); do
    wait -n 2>/dev/null || true
  done
}

# Parallel execution
for ip in "${!devices[@]}"; do
  wait_for_slot
  process_one "$ip" "${devices[$ip]}" &
done
wait

#### FORMAT & SORT
# Use column -t if available, otherwise cat (printf already does fixed-width formatting)
if command -v column &>/dev/null; then
  COLUMNS=200 column -t "$TMPFILE" > "$SCRIPT_DIR/assets.sorted"
else
  cat "$TMPFILE" > "$SCRIPT_DIR/assets.sorted"
fi
rm -f "$TMPFILE"

sort -t'.' -k1,1n -k2,2n -k3,3n -k4,4n "$SCRIPT_DIR/assets.sorted" > "$SCRIPT_DIR/assets.sorted2"
rm -f "$SCRIPT_DIR/assets.sorted"

# Append unreachable devices - use cache if available
if [[ -s "$UNREACH" ]]; then
  while read -r host; do
    # Try to get cached data for this device
    cached_data=$(get_cached_device "$host")
    
    if [[ "$cached_data" != "NOCACHE" ]]; then
      # Parse cached data (format: ip|mac|serial|model|release|uptime|last_seen)
      IFS='|' read -r c_ip c_mac c_serial c_model c_release c_uptime c_last_seen <<< "$cached_data"
      
      # Write with UNREACHABLE status and cached data
      printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
        "$host" "$c_ip" "$c_mac" "$c_serial" "$c_model" "$c_release" "$c_uptime" "UNREACHABLE" "$c_last_seen" \
        >> "$SCRIPT_DIR/assets.sorted2"
    else
      # No cache available - show NO-INFO
      printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
        "$host" "No-Info" "No-Info" "No-Info" "No-Info" "No-Info" "No-Info" "NO-INFO" "Never" \
        >> "$SCRIPT_DIR/assets.sorted2"
    fi
  done < "$UNREACH"
fi

# Add timestamp and header
DATE_STR=$(date '+%Y-%m-%d %H-%M-%S')
echo "Created on $DATE_STR" > "$FINAL.tmp"
echo "" >> "$FINAL.tmp"
printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
  "DEVICE-NAME" "IP" "ETH0-MAC" "SERIAL" "MODEL" "RELEASE" "UPTIME" "STATUS" "LAST-SEEN" >> "$FINAL.tmp"
tail -n +2 "$SCRIPT_DIR/assets.sorted2" >> "$FINAL.tmp"
mv "$FINAL.tmp" "$FINAL"
sudo cp "$FINAL" "$WEB_ROOT/"
sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$WEB_ROOT/$(basename $FINAL)"
sudo chmod 664 "$WEB_ROOT/$(basename $FINAL)"
rm -f "$TMPFILE" "$UNREACH"
rm -rf "$SCRIPT_DIR/assets.sorted2"

#### REBUILD CACHE FROM ASSETS FILE (race-condition-free)
# All parallel processes have finished; build cache once from the final assets file
python3 << 'REBUILD_CACHE'
import json
import os
import sys

cache_file = os.environ.get('WEB_ROOT', '/var/www/html') + '/device-cache.json'
assets_file = os.environ.get('FINAL', '')

if not assets_file or not os.path.exists(assets_file):
    sys.exit(0)

# Start from the EXISTING cache and MERGE — so a device that is merely DOWN this run keeps its
# last-known data instead of being dropped to "Never". (Previously the cache was rebuilt from
# scratch each run: a single run where a down device's cached row was missed — e.g. a transient
# read, or an overlapping assets run during a mass reboot — permanently lost that device until it
# next came back up. Merging makes the cache resilient to those hiccups.)
cache = {}
try:
    with open(cache_file) as f:
        _prev = json.load(f)
    if isinstance(_prev, dict):
        cache = _prev
except Exception:
    cache = {}

seen = set()
try:
    with open(assets_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('Created on') or line.startswith('DEVICE-NAME'):
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            hostname = parts[0]
            ip = parts[1]
            mac = parts[2]
            serial = parts[3]
            model = parts[4]
            release = parts[5]
            uptime = parts[6]
            status = parts[7]
            last_seen = parts[8] if len(parts) > 8 else ''
            seen.add(hostname)

            if status == 'OK':
                cache[hostname] = {
                    "hostname": hostname,
                    "ip": ip,
                    "mac": mac,
                    "serial": serial,
                    "model": model,
                    "release": release,
                    "uptime": uptime,
                    "last_seen": last_seen.replace('_', ' '),
                    "status": "ok"
                }
            elif status == 'UNREACHABLE' and ip != 'No-Info':
                # Keep cached data for unreachable devices
                cache[hostname] = {
                    "hostname": hostname,
                    "ip": ip,
                    "mac": mac,
                    "serial": serial,
                    "model": model,
                    "release": release,
                    "uptime": uptime,
                    "last_seen": last_seen.replace('_', ' '),
                    "status": "unreachable"
                }
            # status == 'NO-INFO' (never yet collected while up): do NOT drop — keep any existing
            # cache entry so a currently-down device retains its last-known data.

    # Prune only devices that no longer appear in the run at all (e.g. removed from devices.yaml).
    # Every inventory device produces a row (OK / UNREACHABLE / NO-INFO), so a merely-down device
    # is in `seen` and is retained; only truly-removed devices are dropped.
    cache = {h: v for h, v in cache.items() if h in seen}

    with open(cache_file, 'w') as f:
        json.dump(cache, f, indent=2)
except Exception as e:
    print(f"Cache rebuild error: {e}", file=sys.stderr)
REBUILD_CACHE

sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$CACHE_FILE" 2>/dev/null
sudo chmod 664 "$CACHE_FILE" 2>/dev/null

exit 0