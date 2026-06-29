#!/usr/bin/env bash
# Monitor Script - OPTIMIZED VERSION
# Single SSH session per device + Parallel limits + Parallel analysis
#
# Copyright (c) 2024 LLDPq Project
# Licensed under MIT License - see LICENSE file for details

# Start timing
START_TIME=$(date +%s)
echo "Starting monitoring at $(date)"

DATE=$(date '+%Y-%m-%d %H-%M-%S')
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
eval "$(python3 "$SCRIPT_DIR/parse_devices.py")"

# Load config with fallback
source /etc/lldpq.conf 2>/dev/null || true
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

normalize_bool() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        true|1|yes|y|on) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

# Parse flags
SKIP_OPTICAL="${SKIP_OPTICAL:-false}"
SKIP_L1="${SKIP_L1:-true}"
while getopts "s" opt; do
    case $opt in
        s) SKIP_OPTICAL=true ;;
    esac
done
SKIP_OPTICAL="$(normalize_bool "$SKIP_OPTICAL")"
SKIP_L1="$(normalize_bool "$SKIP_L1")"

# === TUNING PARAMETERS ===
MAX_PARALLEL="${MONITOR_MAX_PARALLEL:-${MAX_PARALLEL:-100}}"  # Maximum parallel SSH connections
case "$MAX_PARALLEL" in
    ''|*[!0-9]*|0) MAX_PARALLEL=100 ;;
esac
SSH_TIMEOUT=60   # SSH connection timeout in seconds

mkdir -p "$SCRIPT_DIR/monitor-results"
mkdir -p "$SCRIPT_DIR/monitor-results/flap-data"
mkdir -p "$SCRIPT_DIR/monitor-results/bgp-data"
mkdir -p "$SCRIPT_DIR/monitor-results/evpn-data"
mkdir -p "$SCRIPT_DIR/monitor-results/dup-data"
mkdir -p "$SCRIPT_DIR/monitor-results/optical-data"
mkdir -p "$SCRIPT_DIR/monitor-results/ber-data"
mkdir -p "$SCRIPT_DIR/monitor-results/hardware-data"
mkdir -p "$SCRIPT_DIR/monitor-results/log-data"

unreachable_hosts_file=$(mktemp)
active_jobs_file=$(mktemp)

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
# OPTIMIZED: Single SSH session collects ALL data
# ============================================================================
execute_commands_optimized() {
    local device=$1
    local user=$2
    local hostname=$3
    local device_start=$(date +%s)
    
    # Arrays to store timing data for summary
    declare -a section_names
    declare -a section_times
    
    # Progress output removed for performance
    
    # Create HTML header
    cat > monitor-results/${hostname}.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Monitor Results - ${hostname}</title>
    <link rel="stylesheet" type="text/css" href="/css/styles2.css">
    <style>
        .config-content {
            background: #1a1a1a;
            border: 1px solid #43453B;
            border-radius: 12px;
            margin: 30px 0;
            padding: 25px;
            min-height: 400px;
            font-family: 'Fira Code', 'Courier New', Courier, monospace;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            overflow-x: auto;
        }
        .comment { color: #6a9955; font-style: italic; }
        .keyword { color: #569cd6; font-weight: bold; }
        .string { color: #ce9178; }
        .number { color: #d7ba7d; }
        .ip-number { color: #ffffff; }
        .variable { color: #9cdcfe; }
        .operator { color: #d4d4d4; }
        .section { color: #dcdcaa; font-weight: bold; }
        .interface { color: #4ec9b0; }
        .ip-address { color: #ffffff; }
        .default { color: #569cd6; }
    </style>
</head>
<body>
    <h1><font color="#b57614">Monitor Results - ${hostname}</font></h1>
    <h3 class='interface-info'>
    <pre>
    <span style="color:tomato;">Created on $DATE</span>

EOF

    # =========================================================================
    # SINGLE SSH SESSION - Collect ALL data at once
    # =========================================================================
    # Verbose output removed for performance
    local ssh_start=$(date +%s)
    
    timeout 300 ssh $SSH_OPTS -q "$user@$device" '
        HOSTNAME_VAR="'"$hostname"'"
        SKIP_OPTICAL="'"$SKIP_OPTICAL"'"
        
        # =====================================================================
        # SECTION 1: Interface Overview (for HTML)
        # =====================================================================
        echo "===HTML_OUTPUT_START==="
        
        echo "<h1></h1><h1><font color=\"#b57614\">Port Status '"$hostname"'</font></h1><h3></h3>"
        printf "<span style=\"color:green;\">%-14s %-12s %-12s %s</span>\n" "Interface" "State" "Link" "Description"
        
        for interface in $(ip link show | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}" | sort -V); do
            if [ -e "/sys/class/net/$interface" ]; then
                state=$(cat /sys/class/net/$interface/operstate 2>/dev/null || echo "unknown")
                link_status=$([ "$state" = "up" ] && echo "up" || echo "down")
                color=$([ "$link_status" = "up" ] && echo "lime" || echo "red")
                description=$(ip link show "$interface" | grep -o "alias.*" | sed "s/alias //")
                [ -z "$description" ] && description="No description"
                printf "<span style=\"color:steelblue;\">%-14s</span> <span style=\"color:%s;\">%-12s</span> <span style=\"color:%s;\">%-12s</span> %s\n" "$interface" "$color" "$state" "$color" "$link_status" "$description"
            fi
        done

        echo "<h1></h1><h1><font color=\"#b57614\">Interface IP Addresses '"$hostname"'</font></h1><h3></h3>"
        printf "<span style=\"color:green;\">%-20s %-18s %s</span>\n" "Interface" "IPv4" "IPv6 Global"
        
        for interface in $(ip addr show | grep "^[0-9]*:" | cut -d: -f2 | cut -d@ -f1); do
            interface=$(echo "$interface" | xargs)
            ipv4=$(ip addr show "$interface" 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+" | head -1)
            ipv6=$(ip addr show "$interface" 2>/dev/null | grep "inet6.*scope global" | grep -o "[0-9a-f:]\+/[0-9]\+" | head -1)
            if [ -n "$ipv4" ] || [ -n "$ipv6" ]; then
                [ -z "$ipv4" ] && ipv4="-"
                [ -z "$ipv6" ] && ipv6="-"
                printf "<span style=\"color:steelblue;\">%-20s</span> <span style=\"color:orange;\">%-18s</span> <span style=\"color:cyan;\">%s</span>\n" "$interface" "$ipv4" "$ipv6"
            fi
        done

        echo "<h1></h1><h1><font color=\"#b57614\">VLAN Configuration Table '"$hostname"'</font></h1><h3></h3>"
        echo "<pre style=\"font-family:monospace;\">"
        printf "<span style=\"color:green;\">%-20s %-12s %s</span>\n" "PORT" "PVID" "VLANs"
        sudo /usr/sbin/bridge vlan 2>/dev/null | \
          awk '\''BEGIN{cp=""}
               NR==1||NF==0{next}
               NF>=2{
                 if(cp!="") print cp "|" p "|" v
                 cp=$1; p=""; v=$2
                 if($3=="PVID") p=$2
                 next
               }
               NF==1{ v=v"," $1 }
               NF>2&&$3=="PVID"{ p=$2; v=v"," $2 }
               END{ if(cp!="") print cp "|" p "|" v }'\'' | \
          awk -F"|" '\''{
                if($1~/^vxlan/) { n="9999" } else { n="5000" }
                printf "%s|%s|%s|%s\n", n, $1, $2, $3
           }'\'' | sort -t"|" -k1,1n -k2,2V | \
          awk -F"|" '\''{
               port_colored = "<span style=\"color:steelblue;\">" $2 "</span>"
               if($3 != "") { pvid_colored = "PVID=<span style=\"color:lime;\">" $3 "</span>" }
               else { pvid_colored = "PVID=<span style=\"color:gray;\">N/A</span>" }
               vlan_colored = $4
               gsub(/([0-9]+)/, "<span style=\"color:tomato;\">&</span>", vlan_colored)
               port_pad = 20 - length($2)
               if($3 != "") { pvid_text_len = length("PVID=" $3) } else { pvid_text_len = length("PVID=N/A") }
               pvid_pad = 12 - pvid_text_len
               printf "%s%*s %s%*s VLANs=%s\n", port_colored, port_pad, "", pvid_colored, pvid_pad, "", vlan_colored
          }'\''
        echo "</pre>"

        echo "<h1></h1><h1><font color=\"#b57614\">ARP Table '"$hostname"'</font></h1><h3></h3>"
        ip neighbour | grep -E -v "fe80" | sort -t "." -k1,1n -k2,2n -k3,3n -k4,4n | sed -E "s/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/<span style=\"color:tomato;\">\1<\/span>/; s/dev ([^ ]+)/dev <span style=\"color:steelblue;\">\1<\/span>/; s/lladdr ([0-9a-f:]+)/lladdr <span style=\"color:tomato;\">\1<\/span>/"
        
        echo "<h1></h1><h1><font color=\"#b57614\">MAC Table '"$hostname"'</font></h1><h3></h3>"
        sudo /usr/sbin/bridge fdb 2>/dev/null | grep -E -v "00:00:00:00:00:00" | sort | sed -E "s/^([0-9a-f:]+)/<span style=\"color:tomato;\">\1<\/span>/; s/dev ([^ ]+)/dev <span style=\"color:steelblue;\">\1<\/span>/; s/vlan ([0-9]+)/vlan <span style=\"color:red;\">\1<\/span>/; s/dst ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/dst <span style=\"color:lime;\">\1<\/span>/"
        
        echo "<h1></h1><h1><font color=\"#b57614\">BGP Status '"$hostname"'</font></h1><h3></h3>"
        sudo vtysh -c "show bgp vrf all sum" 2>/dev/null | sed -E "s/(VRF\s+)([a-zA-Z0-9_-]+)/\1<span style=\"color:tomato;\">\2<\/span>/g; s/Total number of neighbors ([0-9]+)/Total number of neighbors <span style=\"color:steelblue;\">\1<\/span>/g; s/(\S+)\s+(\S+)\s+Summary/<span style=\"color:lime;\">\1 \2<\/span> Summary/g; s/\b(Active|Idle)\b/<span style=\"color:red;\">\1<\/span>/g"
        
        echo "===HTML_OUTPUT_END==="
        
        # =====================================================================
        # SECTION 2: BGP Data (for analysis)
        # =====================================================================
        echo "===BGP_DATA_START==="
        sudo vtysh -c "show bgp vrf all sum" 2>/dev/null
        echo "===BGP_DATA_END==="
        
        # =====================================================================
        # SECTION 2b: EVPN Data (for EVPN route counts)
        # =====================================================================
        echo "===EVPN_DATA_START==="
        # VNI summary - full output
        echo "=== EVPN VNI SUMMARY ==="
        sudo vtysh -c "show evpn vni" 2>/dev/null | cat || echo "EVPN not configured"
        # Type-2 and Type-5 route counts (grep lines with route types [N]:)
        echo "=== EVPN TYPE COUNTS ==="
        sudo vtysh -c "show bgp l2vpn evpn" 2>/dev/null | grep -E '\[[1-5]\]:' | head -1000 || echo "No EVPN routes"
        echo "===EVPN_DATA_END==="
        
        # =====================================================================
        # SECTION 2c: Duplicate IP/MAC Data (EVPN dup-detection + FDB + neighbours)
        # =====================================================================
        echo "===DUP_DATA_START==="
        echo "=== DUP VNI MAP ==="
        sudo vtysh -c "show evpn vni" 2>/dev/null
        echo "=== DUP CONFIG ==="
        sudo vtysh -c "show evpn" 2>/dev/null | grep -i -A1 "duplicate"
        echo "=== DUP ARP ==="
        sudo vtysh -c "show evpn arp-cache vni all duplicate" 2>/dev/null
        echo "=== DUP MAC ==="
        sudo vtysh -c "show evpn mac vni all duplicate" 2>/dev/null
        echo "=== DUP LOG ==="
        sudo grep -i "detected as duplicate" /var/log/frr/frr.log 2>/dev/null | tail -300
        # MAC / IP mobility: entries whose EVPN sequence number is >= 10 (a 2+ digit local or
        # remote seq). Works even where dup-address-detection is OFF (EVPN-MH), because the
        # mobility sequence is ALWAYS tracked. Stable MACs (0/0) and normal failovers (<10)
        # are filtered out on-device to keep this small.
        echo "=== DUP MACMOB ==="
        sudo vtysh -c "show evpn mac vni all" 2>/dev/null | grep -E "^VNI |[0-9][0-9]+/[0-9]+$|/[0-9][0-9]+$" | head -800
        echo "=== DUP ARPMOB ==="
        sudo vtysh -c "show evpn arp-cache vni all" 2>/dev/null | grep -E "^VNI |[0-9][0-9]+/[0-9]+$|/[0-9][0-9]+$" | head -800
        echo "===DUP_DATA_END==="
        
        echo "===FDB_DATA_START==="
        sudo /usr/sbin/bridge fdb show 2>/dev/null | grep -E -v "00:00:00:00:00:00"
        echo "===FDB_DATA_END==="
        
        echo "===NEIGH_DATA_START==="
        ip -4 neighbour show 2>/dev/null
        echo "===NEIGH_DATA_END==="
        
        # =====================================================================
        # SECTION 3: Carrier Transitions (for flap analysis)
        # =====================================================================
        echo "===CARRIER_DATA_START==="
        all_interfaces=$(ip link show | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}")
        for interface in $all_interfaces; do
            if [ -e "/sys/class/net/$interface" ]; then
                carrier_count=$(cat /sys/class/net/$interface/carrier_changes 2>/dev/null || echo "0")
                echo "$interface:$carrier_count"
            fi
        done
        echo "===CARRIER_DATA_END==="
        
        # =====================================================================
        # SECTION 4: Optical Transceiver Data (skippable with -s flag)
        # =====================================================================
        echo "===OPTICAL_DATA_START==="
        if [ "$SKIP_OPTICAL" != "true" ]; then
            all_interfaces=$(ip link show | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}")
            for interface in $all_interfaces; do
                if [ -e "/sys/class/net/$interface" ]; then
                    state=$(cat /sys/class/net/$interface/operstate 2>/dev/null)
                    if [ "$state" = "up" ]; then
                        echo "--- Interface: $interface"
                        ethtool_output=$(sudo ethtool -m "$interface" 2>/dev/null)
                        if [ -n "$ethtool_output" ]; then
                            echo "$ethtool_output"
                        else
                            echo "No transceiver data"
                        fi
                    fi
                fi
            done
        fi
        echo "===OPTICAL_DATA_END==="
        
        # =====================================================================
        # SECTION 5: BER/Interface Statistics
        # =====================================================================
        echo "===BER_DATA_START==="
        cat /proc/net/dev 2>/dev/null
        echo "===BER_DATA_END==="
        
        # =====================================================================
        # SECTION 6: L1-Show (if available)
        # =====================================================================
        echo "===L1_DATA_START==="
        if [ "$SKIP_L1" = "true" ]; then
            echo "l1-show skipped"
        elif command -v l1-show >/dev/null 2>&1; then
            sudo l1-show all -p 2>/dev/null || echo "l1-show failed"
        else
            echo "l1-show not available"
        fi
        echo "===L1_DATA_END==="
        
        # =====================================================================
        # SECTION 7: Hardware Health (with fallback)
        # =====================================================================
        echo "===HARDWARE_DATA_START==="
        echo "HARDWARE_HEALTH:"
        sensors 2>/dev/null || echo "No sensors available"
        echo "HW_MGMT_THERMAL:"
        asic_raw=""
        for asic_file in /var/run/hw-management/thermal/asic /run/hw-management/thermal/asic /var/run/hw-management/thermal/asic1 /run/hw-management/thermal/asic1; do
            if [ -e "$asic_file" ]; then
                asic_raw=$(sudo -n cat "$asic_file" 2>/dev/null || cat "$asic_file" 2>/dev/null || echo "")
                if [ -n "$asic_raw" ]; then
                    break
                fi
            fi
        done
        if [ -n "$asic_raw" ]; then
            awk "BEGIN{printf \"HW_MGMT_ASIC: %.1f\n\", $asic_raw/1000}"
        else
            # Fallback: Try alternative ASIC temperature sources
            echo "ASIC_FALLBACK_DEBUG:"
            # Check thermal zones
            for zone in /sys/class/thermal/thermal_zone*/type; do
                if [ -r "$zone" ]; then
                    zone_type=$(cat "$zone" 2>/dev/null)
                    if echo "$zone_type" | grep -qi "asic\|switch\|mlxsw"; then
                        zone_dir=$(dirname "$zone")
                        temp_file="$zone_dir/temp"
                        if [ -r "$temp_file" ]; then
                            temp_raw=$(cat "$temp_file" 2>/dev/null)
                            if [ -n "$temp_raw" ] && [ "$temp_raw" -gt 0 ]; then
                                awk "BEGIN{printf \"THERMAL_ZONE_ASIC: %.1f\n\", $temp_raw/1000}"
                                break
                            fi
                        fi
                    fi
                fi
            done
            # Check hwmon for ASIC
            for hwmon in /sys/class/hwmon/hwmon*/temp*_label; do
                if [ -r "$hwmon" ]; then
                    label=$(cat "$hwmon" 2>/dev/null)
                    if echo "$label" | grep -qi "asic\|switch"; then
                        temp_file=$(echo "$hwmon" | sed "s/_label$/_input/")
                        if [ -r "$temp_file" ]; then
                            temp_raw=$(cat "$temp_file" 2>/dev/null)
                            if [ -n "$temp_raw" ] && [ "$temp_raw" -gt 0 ]; then
                                awk "BEGIN{printf \"HWMON_ASIC: %.1f\n\", $temp_raw/1000}"
                                break
                            fi
                        fi
                    fi
                fi
            done
        fi
        cpu_raw=""
        for cpu_file in /var/run/hw-management/thermal/cpu_pack /run/hw-management/thermal/cpu_pack; do
            if [ -e "$cpu_file" ]; then
                cpu_raw=$(sudo -n cat "$cpu_file" 2>/dev/null || cat "$cpu_file" 2>/dev/null || echo "")
                if [ -n "$cpu_raw" ]; then
                    break
                fi
            fi
        done
        if [ -n "$cpu_raw" ]; then
            awk "BEGIN{printf \"HW_MGMT_CPU: %.1f\n\", $cpu_raw/1000}"
        fi
        echo "MEMORY_INFO:"
        free -h 2>/dev/null || echo "No memory info"
        echo "CPU_INFO:"
        cat /proc/loadavg 2>/dev/null || echo "No CPU info"
        echo "CPU_CORES: $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 0)"
        echo "===HARDWARE_DATA_END==="
        
        # =====================================================================
        # SECTION 8: System Logs (comprehensive)
        # =====================================================================
        echo "===LOG_DATA_START==="
        echo "=== COMPREHENSIVE SYSTEM LOGS ==="
        
        # FRR Routing Logs
        echo "FRR_ROUTING_LOGS:"
        if systemctl is-active --quiet frr 2>/dev/null; then
            sudo journalctl -u frr --since="2 hours ago" --no-pager --lines=200 2>/dev/null | grep -E "(ERROR|WARN|CRIT|FAIL|DOWN|BGP|neighbor|peer)" || echo "No recent FRR routing issues"
        elif [ -f "/var/log/frr/frr.log" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/frr/frr.log 2>/dev/null | tail -30 | grep -E "(error|warn|crit|fail|down|bgp)" || echo "No recent FRR routing issues"
        else
            echo "FRR service/log not available"
        fi
        
        # Switch daemon logs
        echo "SWITCHD_LOGS:"
        if systemctl is-active --quiet switchd 2>/dev/null; then
            sudo journalctl -u switchd --since="2 hours ago" --no-pager --lines=50 2>/dev/null | grep -E "(ERROR|WARN|CRIT|FAIL|EXCEPT|port|link|vlan)" || echo "No recent switchd issues"
        elif [ -f "/var/log/switchd.log" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/switchd.log 2>/dev/null | tail -30 | grep -E "(error|warn|crit|fail|except)" || echo "No recent switchd issues"
        else
            echo "Switchd service/log not available"
        fi
        
        # NVUE configuration logs
        echo "NVUE_CONFIG_LOGS:"
        if systemctl is-active --quiet nvued 2>/dev/null; then
            sudo journalctl -u nvued --since="2 hours ago" --no-pager --lines=50 2>/dev/null | grep -E "(ERROR|WARN|FAIL|EXCEPT|config|commit|rollback)" || echo "No recent NVUE config issues"
        elif [ -f "/var/log/nvued.log" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/nvued.log 2>/dev/null | tail -30 | grep -E "(ERROR|WARN|FAIL|EXCEPT|config|commit|rollback)" || echo "No recent NVUE config issues"
        else
            echo "NVUE log not found"
        fi
        
        # Spanning Tree Protocol logs
        echo "MSTPD_STP_LOGS:"
        if systemctl is-active --quiet mstpd 2>/dev/null; then
            sudo journalctl -u mstpd --since="2 hours ago" --no-pager --lines=50 2>/dev/null | grep -E "(ERROR|WARN|TOPOLOGY|CHANGE|port|state|bridge)" || echo "No recent STP issues"
        elif [ -f "/var/log/mstpd" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/mstpd 2>/dev/null | tail -30 | grep -E "(ERROR|WARN|TOPOLOGY|CHANGE|port|state|bridge)" || echo "No recent STP issues"
        else
            echo "MSTPD log not found"
        fi
        
        # MLAG coordination logs
        echo "CLAGD_MLAG_LOGS:"
        if systemctl is-active --quiet clagd 2>/dev/null; then
            sudo journalctl -u clagd --since="2 hours ago" --no-pager --lines=50 2>/dev/null | grep -E "(ERROR|WARN|FAIL|CONFLICT|PEER|bond|backup|primary)" || echo "No recent MLAG issues"
        elif [ -f "/var/log/clagd.log" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/clagd.log 2>/dev/null | tail -30 | grep -E "(ERROR|WARN|FAIL|CONFLICT|PEER|bond|backup|primary)" || echo "No recent MLAG issues"
        else
            echo "CLAG log not found"
        fi
        
        # Authentication and security logs
        echo "AUTH_SECURITY_LOGS:"
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            sudo journalctl --since="2 hours ago" --grep="FAIL|ERROR|INVALID|DENIED|ATTACK|authentication|unauthorized" --no-pager --lines=50 2>/dev/null | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|--since|--grep|swp\|bond\|vlan\|carrier\|link|vtysh|sudo.*authentication.*grantor=pam_permit|USER_AUTH.*res=success)" || echo "No recent auth issues"
        elif [ -f "/var/log/auth.log" ]; then
            sudo grep "$(date '\''+%b %d'\'')" /var/log/auth.log 2>/dev/null | tail -30 | grep -E "(FAIL|ERROR|INVALID|DENIED|ATTACK|authentication|unauthorized)" | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|--since|swp\|bond\|vlan\|carrier\|link|vtysh|sudo.*authentication.*grantor=pam_permit|USER_AUTH.*res=success)" || echo "No recent auth issues"
        else
            echo "Auth log not found"
        fi
        
        # System critical logs
        CRITICAL_LOGS=""
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            CRITICAL_LOGS=$(sudo journalctl --since="2 hours ago" --priority=0..3 --grep="ERROR|CRIT|ALERT|EMERG|FAIL|kernel|oom|segfault" --no-pager --lines=50 2>/dev/null)
        elif [ -f "/var/log/syslog" ]; then
            CRITICAL_LOGS=$(sudo grep "$(date '\''+%b %d'\'')" /var/log/syslog 2>/dev/null | tail -50 | grep -E "(ERROR|CRIT|ALERT|EMERG|FAIL|kernel|oom|segfault)")
        fi
        
        if [ -n "$CRITICAL_LOGS" ]; then
            echo "SYSTEM_CRITICAL_LOGS:"
            echo "$CRITICAL_LOGS"
        fi
        
        # High priority journalctl logs
        echo "JOURNALCTL_PRIORITY_LOGS:"
        sudo journalctl --since="3 hours ago" --priority=0..3 --no-pager --lines=75 2>/dev/null | grep -E "(CRIT|ALERT|EMERG|ERROR|fail|crash|panic)" || echo "No high priority journal logs"
        
        # Hardware and kernel critical messages
        echo "DMESG_HARDWARE_LOGS:"
        sudo dmesg --since="3 hours ago" --level=crit,alert,emerg 2>/dev/null | tail -40 || echo "No critical hardware logs"
        
        # Network interface state changes
        echo "NETWORK_INTERFACE_LOGS:"
        sudo journalctl --since="3 hours ago" --grep="swp|bond|vlan|carrier|link.*up|link.*down|port.*up|port.*down" --no-pager --lines=40 2>/dev/null | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|sudo.*journalctl)" || echo "No interface state changes"
        
        echo "===LOG_DATA_END==="
        
        
    ' > "monitor-results/${hostname}_raw_data.txt" 2>/dev/null
    
    local ssh_end=$(date +%s)
    local ssh_duration=$((ssh_end - ssh_start))
    section_names+=("SSH Data Collection")
    section_times+=("$ssh_duration")
    
    # =========================================================================
    # Parse raw data into separate files
    # =========================================================================
    local parse_start=$(date +%s)
    
    if [ -f "monitor-results/${hostname}_raw_data.txt" ]; then
        # Extract HTML output
        sed -n '/===HTML_OUTPUT_START===/,/===HTML_OUTPUT_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===HTML_OUTPUT" >> "monitor-results/${hostname}.html"
        
        # Extract BGP data
        sed -n '/===BGP_DATA_START===/,/===BGP_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===BGP_DATA" > "monitor-results/bgp-data/${hostname}_bgp.txt"
        
        # Extract EVPN data
        sed -n '/===EVPN_DATA_START===/,/===EVPN_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===EVPN_DATA" > "monitor-results/evpn-data/${hostname}_evpn.txt"
        
        # Extract Duplicate IP/MAC data (EVPN dup-detection + FDB + neighbours)
        sed -n '/===DUP_DATA_START===/,/===DUP_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===DUP_DATA" > "monitor-results/dup-data/${hostname}_dup.txt"
        sed -n '/===FDB_DATA_START===/,/===FDB_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===FDB_DATA" > "monitor-results/dup-data/${hostname}_fdb.txt"
        sed -n '/===NEIGH_DATA_START===/,/===NEIGH_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===NEIGH_DATA" > "monitor-results/dup-data/${hostname}_neigh.txt"
        
        # Extract Carrier data
        echo "=== CARRIER TRANSITIONS ===" > "monitor-results/flap-data/${hostname}_carrier_transitions.txt"
        sed -n '/===CARRIER_DATA_START===/,/===CARRIER_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===CARRIER_DATA" >> "monitor-results/flap-data/${hostname}_carrier_transitions.txt"
        
        # Extract Optical data
        echo "=== OPTICAL DIAGNOSTICS ===" > "monitor-results/optical-data/${hostname}_optical.txt"
        sed -n '/===OPTICAL_DATA_START===/,/===OPTICAL_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===OPTICAL_DATA" >> "monitor-results/optical-data/${hostname}_optical.txt"
        
        # Extract BER data
        sed -n '/===BER_DATA_START===/,/===BER_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===BER_DATA" > "monitor-results/ber-data/${hostname}_interface_errors.txt"
        
        # Extract L1 data
        sed -n '/===L1_DATA_START===/,/===L1_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===L1_DATA" > "monitor-results/ber-data/${hostname}_l1_show.txt"
        
        # Extract Hardware data
        sed -n '/===HARDWARE_DATA_START===/,/===HARDWARE_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===HARDWARE_DATA" > "monitor-results/hardware-data/${hostname}_hardware.txt"
        
        # Extract Log data
        sed -n '/===LOG_DATA_START===/,/===LOG_DATA_END===/p' "monitor-results/${hostname}_raw_data.txt" | \
            grep -v "===LOG_DATA" > "monitor-results/log-data/${hostname}_logs.txt"
        
        # Cleanup raw file
        rm -f "monitor-results/${hostname}_raw_data.txt"
    fi
    
    local parse_end=$(date +%s)
    local parse_duration=$((parse_end - parse_start))
    section_names+=("Data Processing")
    section_times+=("$parse_duration")
    
    # Add config section to HTML
    local config_start=$(date +%s)
    
    cat >> monitor-results/${hostname}.html << EOF

<h1></h1><h1><font color="#b57614">Device Configuration - ${hostname}</font></h1><h3></h3>
EOF

    if [ -f "$WEB_ROOT/configs/${hostname}.txt" ]; then
        echo "<h2><font color='steelblue'>NV Set Commands</font></h2>" >> monitor-results/${hostname}.html
        echo "<div class='config-content' id='config-content'>" >> monitor-results/${hostname}.html
        cat "$WEB_ROOT/configs/${hostname}.txt" | sed '
            s/</\&lt;/g; s/>/\&gt;/g;
            s/^#.*/<span class="comment">&<\/span>/;
            /description/ {
                s/\(.*\)\(description\s\+\)\(.*\)$/\1\2<span class="comment">\3<\/span>/;
            }
        ' >> monitor-results/${hostname}.html
        echo "</div>" >> monitor-results/${hostname}.html
    else
        echo "<p><span style='color: orange;'>⚠️  Configuration not available for ${hostname}</span></p>" >> monitor-results/${hostname}.html
    fi
    
    # Close HTML
    cat >> monitor-results/${hostname}.html << EOF
    </pre>
    </h3>
    <span style="color:tomato;">Created on $DATE</span>
</body>
</html>
EOF

    local config_end=$(date +%s)
    local config_duration=$((config_end - config_start))
    section_names+=("Configuration Section")
    section_times+=("$config_duration")

    # Silent completion - no per-device output for performance
}

process_device() {
    local device=$1
    local user=$2
    local hostname=$3
    ping_test "$device" "$hostname"
    if [ $? -eq 0 ]; then
        execute_commands_optimized "$device" "$user" "$hostname"
    fi
}

# ============================================================================
# PARALLEL EXECUTION WITH LIMIT
# ============================================================================
# Parallel monitoring started
total_devices=${#devices[@]}
completed_file="/tmp/monitor_completed_$$"
echo "0" > "$completed_file"

# Simple parallel execution without animation (animation causes hangs)
job_count=0
device_count=0
for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    
    process_device "$device" "$user" "$hostname" &
    ((job_count++))
    ((device_count++))
    
    # Wait if we hit the parallel limit
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n 2>/dev/null || wait
        ((job_count--))
    fi
done

# Wait for all remaining jobs
wait
echo "Collected $device_count devices"
data_collection_end=$(date +%s)
data_collection_duration=$((data_collection_end - START_TIME))

# ============================================================================
# PARALLEL ANALYSIS PHASE
# ============================================================================
echo "Analyzing..."
analysis_start=$(date +%s)

# Run all analyses in parallel (suppress all output)
python3 process_bgp_data.py >/dev/null 2>&1 &
python3 process_flap_data.py >/dev/null 2>&1 &
if [[ "$SKIP_OPTICAL" != "true" ]]; then
    python3 process_optical_data.py >/dev/null 2>&1 &
fi
python3 process_ber_data.py >/dev/null 2>&1 &
python3 process_hardware_data.py >/dev/null 2>&1 &
python3 process_log_data.py >/dev/null 2>&1 &
python3 process_duplicate_data.py >/dev/null 2>&1 &

# Wait for all
wait

analysis_end=$(date +%s)
analysis_duration=$((analysis_end - analysis_start))

# ============================================================================
# COPY RESULTS
# ============================================================================
sudo cp -r monitor-results "$WEB_ROOT/"
sudo chown -R "${LLDPQ_USER:-$(whoami)}:www-data" "$WEB_ROOT/monitor-results/"
sudo find "$WEB_ROOT/monitor-results/" -type d -exec chmod 775 {} \;
sudo find "$WEB_ROOT/monitor-results/" -type f -exec chmod 664 {} \;

rm -f "$unreachable_hosts_file"
rm -f "$active_jobs_file"

# Calculate execution time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo "Done: ${#devices[@]} devices, ${MINUTES}m${SECONDS}s (collect:${data_collection_duration}s, analyze:${analysis_duration}s)"
exit 0
