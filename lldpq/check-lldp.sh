#!/usr/bin/env bash
# LLDPq Topology Check Script - OPTIMIZED VERSION
# Single SSH session per device + Parallel limits
#
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License

set -o pipefail

# Start timing
START_TIME=$(date +%s)
echo "Starting LLDP check at $(date)"

DATE=$(date '+%Y-%m-%d--%H-%M')

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"
load_devices "$SCRIPT_DIR/parse_devices.py" || exit 1

# Load allowlisted config data through the fixed, root-owned parser.
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# === TUNING PARAMETERS ===
MAX_PARALLEL="${LLDP_MAX_PARALLEL:-100}"  # Maximum parallel SSH connections
case "$MAX_PARALLEL" in
    ''|*[!0-9]*|0) MAX_PARALLEL=100 ;;
esac
SSH_TIMEOUT=30    # SSH connection timeout in seconds

mkdir -p "$SCRIPT_DIR/lldp-results"

unreachable_hosts_file=$(mktemp)
active_jobs_file=$(mktemp)
completed_count_file=$(mktemp)
echo "0" > "$completed_count_file"
postprocess_dir=""

cleanup_check_lldp() {
    rm -f "$unreachable_hosts_file" "$active_jobs_file" \
        "$completed_count_file" "$completed_count_file.lock"
    [[ -n "$postprocess_dir" ]] && rm -rf "$postprocess_dir"
}
trap cleanup_check_lldp EXIT

publish_web_file() {
    local source_file="$1" destination_file="$2" temp_file
    temp_file=$(sudo mktemp "$(dirname "$destination_file")/.lldpq-publish.XXXXXXXXXX") || return 1
    if ! sudo cp "$source_file" "$temp_file" ||
       ! sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$temp_file" ||
       ! sudo chmod 664 "$temp_file" ||
       ! sudo mv -fT "$temp_file" "$destination_file"; then
        sudo rm -f "$temp_file" 2>/dev/null || true
        return 1
    fi
}

# Total device count for progress
TOTAL_DEVICES=${#devices[@]}

# SSH options with multiplexing
SSH_OPTS="-o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPath=~/.ssh/cm-%r@%h:%p -o ControlPersist=60 -o BatchMode=yes -o ConnectTimeout=$SSH_TIMEOUT"

# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds 'ip rule' for mgmt VRF so plain ping works. No ip vrf exec needed.
PING="ping"

ping_test() {
    local device=$1
    local hostname=$2
    $PING -c 1 -W 0.5 "$device" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "$device $hostname" >> "$unreachable_hosts_file"
        return 1
    fi
    return 0
}

# ============================================================================
# OPTIMIZED: Single SSH session collects ALL LLDP data
# ============================================================================
execute_commands_optimized() {
    local device=$1
    local user=$2
    local hostname=$3
    
    # Single SSH connection collects everything
    ssh $SSH_OPTS -T -q "$user@$device" "
        echo '=========================================${hostname}========================================='
        echo ''
        
        # LLDP data
        sudo lldpctl 2>/dev/null
        
        # Port status
        echo ''
        echo '===PORT_STATUS_START==='
        for port in /sys/class/net/swp*; do
            [ -d \"\$port\" ] || continue
            port_name=\$(basename \"\$port\")
            oper_state=\$(cat \"\$port/operstate\" 2>/dev/null || echo 'unknown')
            carrier=\$(cat \"\$port/carrier\" 2>/dev/null || echo '0')
            
            if [ \"\$oper_state\" = 'up' ] && [ \"\$carrier\" = '1' ]; then
                echo \"\$port_name UP\"
            elif [ \"\$oper_state\" = 'down' ] || [ \"\$carrier\" = '0' ]; then
                echo \"\$port_name DOWN\"
            else
                echo \"\$port_name UNKNOWN\"
            fi
        done | sort -V
        echo '===PORT_STATUS_END==='
        
        # Port speed
        echo ''
        echo '===PORT_SPEED_START==='
        for port in /sys/class/net/swp*; do
            [ -d \"\$port\" ] || continue
            port_name=\$(basename \"\$port\")
            speed=\$(cat \"\$port/speed\" 2>/dev/null || echo '0')
            if [ \"\$speed\" -gt 0 ] 2>/dev/null; then
                echo \"\$port_name \$speed\"
            fi
        done | sort -V
        echo '===PORT_SPEED_END==='
        echo ''
    " > "lldp-results/${hostname}_lldp_result.ini" 2>/dev/null
}

process_device() {
    local device=$1
    local user=$2
    local hostname=$3
    
    ping_test "$device" "$hostname"
    if [ $? -eq 0 ]; then
        execute_commands_optimized "$device" "$user" "$hostname"
    fi
    
    # Update progress counter (thread-safe with flock)
    (
        flock -x 200
        count=$(cat "$completed_count_file")
        count=$((count + 1))
        echo "$count" > "$completed_count_file"
        printf "\rCollecting [%d/%d]" "$count" "$TOTAL_DEVICES"
    ) 200>"$completed_count_file.lock"
}

# ============================================================================
# PARALLEL EXECUTION WITH LIMITS
# ============================================================================
echo "Devices: $TOTAL_DEVICES"

job_count=0
for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    
    # Start job in background
    process_device "$device" "$user" "$hostname" &
    
    job_count=$((job_count + 1))
    
    # Limit parallel jobs
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n 2>/dev/null || wait
        job_count=$((job_count - 1))
    fi
done

# Wait for all remaining jobs
wait

echo ""
echo ""

# Show unreachable hosts
if [ -s "$unreachable_hosts_file" ]; then
    echo -e "\e[0;36mUnreachable hosts:\e[0m"
    echo ""
    while IFS= read -r host; do
        IFS=' ' read -r ip hostname <<< "$host"
        printf "\e[31m[%-14s]\t\e[0;31m[%-1s]\e[0m\n" "$ip" "$hostname"
    done < "$unreachable_hosts_file"
    echo ""
fi

# Run validation
echo "Validating..."
if ! /usr/bin/python3 ./lldp-validate.py; then
    echo "LLDP validation/topology generation failed; existing reports and raw inputs were preserved." >&2
    exit 1
fi

# Process results in private staging; leave previous derived reports intact on
# any grep/awk/disk failure.
postprocess_dir=$(mktemp -d "$SCRIPT_DIR/lldp-results/.post.XXXXXX") || exit 1
raw_problems="$postprocess_dir/raw-problems-lldp_results.ini"
problems="$postprocess_dir/problems-lldp_results.ini"
down="$postprocess_dir/down-lldp_results.ini"

if ! awk '!/Pass/' lldp-results/lldp_results.ini > "$raw_problems"; then
    echo "Failed to derive LLDP problem input" >&2
    exit 1
fi
if ! awk 'NF' RS='\n\n' "$raw_problems" | \
     awk '/No-Info/ || /Fail/' RS= | \
     sed '/^================================/i\\' > "$problems"; then
    echo "Failed to build LLDP problem report" >&2
    exit 1
fi
if [ ! -s "$problems" ]; then
    head -n 1 "$raw_problems" >> "$problems" || exit 1
    echo -e "\nGood news, there are no problematic ports..." >> "$problems" || exit 1
fi
if ! grep -q "Created on" "$problems"; then
    header=$(head -n 1 "$raw_problems") || exit 1
    { printf '%s\n' "$header"; cat "$problems"; } > "$problems.with-header" || exit 1
    mv "$problems.with-header" "$problems" || exit 1
fi

if ! awk 'BEGIN{RS="\n\n"; ORS="\n\n"} /No-Info/ && !/Fail/' "$problems" > "$down"; then
    echo "Failed to build LLDP down-port report" >&2
    exit 1
fi
if [ ! -s "$down" ]; then
    head -n 1 "$raw_problems" >> "$down" || exit 1
    echo -e "\nGood news, there are no DOWN ports..." >> "$down" || exit 1
fi
if ! grep -q "Created on" "$down"; then
    header=$(head -n 1 "$raw_problems") || exit 1
    { printf '%s\n' "$header"; cat "$down"; } > "$down.with-header" || exit 1
    mv "$down.with-header" "$down" || exit 1
fi

mv "$raw_problems" lldp-results/raw-problems-lldp_results.ini || exit 1
mv "$problems" lldp-results/problems-lldp_results.ini || exit 1
mv "$down" lldp-results/down-lldp_results.ini || exit 1

# Copy results to web server
echo "Copying to web..."
sudo mkdir -p "$WEB_ROOT/hstr" || exit 1
if [[ -f "$WEB_ROOT/problems-lldp_results.ini" ]]; then
    publish_web_file \
        "$WEB_ROOT/problems-lldp_results.ini" \
        "$WEB_ROOT/hstr/Problems-${DATE}.ini" || exit 1
fi
publish_web_file lldp-results/lldp_results.ini "$WEB_ROOT/lldp_results.ini" || exit 1
publish_web_file \
    lldp-results/problems-lldp_results.ini \
    "$WEB_ROOT/problems-lldp_results.ini" || exit 1

# Cleanup old history files (keep 1 per day for last 30 days)
folder_path="$WEB_ROOT/hstr"
cd "$folder_path" || exit 1
declare -a keep_files
for i in {1..30}; do
    start_date=$(date -d "$i days ago" '+%Y-%m-%d 00:00:00')
    end_date=$(date -d "$((i - 1)) days ago" '+%Y-%m-%d 00:00:00')
    file=$(find . -type f -name "*.ini" -newermt "$start_date" ! -newermt "$end_date" | sort | head -n 1)
    if [ -n "$file" ]; then
        keep_files+=("$file")
    fi
done
recent_files=$(find . -type f -name "*.ini" -mtime -1)
for file in $recent_files; do
    keep_files+=("$file")
done
find . -type f -name "*.ini" | while read file; do
    if [[ ! " ${keep_files[@]} " =~ " ${file} " ]]; then
        sudo rm "$file"
    fi
done

# Show timing
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo ""
echo "Done: ${DURATION}s"
exit 0
