#!/usr/bin/env bash
# LLDPq asset inventory collector
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Share the full-pipeline lock with bin/lldpq-trigger, check-lldp.sh and
# monitor.sh.  An environment marker alone is not sufficient: descriptor 9
# must still be open in this process before the inherited lock is trusted.
lock_is_inherited=false
if [[ "${LLDPQ_MONITOR_LOCK_HELD:-0}" == "1" ]] && { : >&9; } 2>/dev/null; then
    lock_is_inherited=true
fi
if [[ "$lock_is_inherited" != "true" ]]; then
    LOCK_FILE="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    if ! command -v flock >/dev/null 2>&1; then
        echo "assets: flock is required for safe asset collection" >&2
        exit 1
    fi
    exec 9>"$LOCK_FILE" || exit 1
    if ! flock -n 9; then
        echo "Asset collection is already running; this invocation was skipped." >&2
        exit 75
    fi
    export LLDPQ_MONITOR_LOCK_HELD=1
fi

# Installed runs require the root-owned parser. Explicit WEB_ROOT is accepted
# only for isolated tests/source-tree execution.
LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
if [[ -x "$LLDPQ_CONFIG_HELPER" ]]; then
    LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
        --require-key WEB_ROOT --require-key LLDPQ_USER 2>/dev/null) || {
        echo "assets: required runtime configuration is missing or unreadable" >&2
        exit 1
    }
    eval "$LLDPQ_CONFIG_ASSIGNMENTS"
    unset LLDPQ_CONFIG_ASSIGNMENTS
elif [[ -z "${WEB_ROOT:-}" ]]; then
    echo "assets: required config helper is missing: $LLDPQ_CONFIG_HELPER" >&2
    exit 1
fi

LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
ASSETS_WEB_OWNER="${ASSETS_WEB_OWNER:-$LLDPQ_USER}"
ASSETS_WEB_GROUP="${ASSETS_WEB_GROUP:-www-data}"
ASSETS_MAX_PARALLEL="${ASSETS_MAX_PARALLEL:-50}"
ASSETS_SSH_DEADLINE="${ASSETS_SSH_DEADLINE:-${ASSETS_SSH_TIMEOUT:-60}}"
ASSETS_SSH_CONNECT_TIMEOUT="${ASSETS_SSH_CONNECT_TIMEOUT:-5}"
ASSETS_SERVER_ALIVE_INTERVAL="${ASSETS_SERVER_ALIVE_INTERVAL:-10}"
ASSETS_SERVER_ALIVE_COUNT_MAX="${ASSETS_SERVER_ALIVE_COUNT_MAX:-2}"
ASSETS_TIMEOUT_BIN="${ASSETS_TIMEOUT_BIN:-timeout}"
ASSETS_SSH_BIN="${ASSETS_SSH_BIN:-ssh}"
ASSETS_PING_BIN="${ASSETS_PING_BIN:-ping}"
ASSETS_SUDO_BIN="${ASSETS_SUDO_BIN:-sudo}"

for numeric_setting in \
    ASSETS_MAX_PARALLEL \
    ASSETS_SSH_DEADLINE \
    ASSETS_SSH_CONNECT_TIMEOUT \
    ASSETS_SERVER_ALIVE_INTERVAL \
    ASSETS_SERVER_ALIVE_COUNT_MAX; do
    value=${!numeric_setting}
    case "$value" in
        ''|*[!0-9]*|0)
            echo "assets: $numeric_setting must be a positive integer" >&2
            exit 1
            ;;
    esac
done

if ! command -v "$ASSETS_TIMEOUT_BIN" >/dev/null 2>&1; then
    echo "assets: timeout is required for bounded SSH collection" >&2
    exit 1
fi
if ! command -v "$ASSETS_SSH_BIN" >/dev/null 2>&1; then
    echo "assets: ssh is required for asset collection" >&2
    exit 1
fi
if ! command -v "$ASSETS_PING_BIN" >/dev/null 2>&1; then
    echo "assets: ping is required for reachability classification" >&2
    exit 1
fi

source "$SCRIPT_DIR/load_devices.sh"
device_args=()
if [[ -n "${LLDPQ_DEVICES_FILE:-}" ]]; then
    device_args=(-f "$LLDPQ_DEVICES_FILE")
fi
load_devices "$SCRIPT_DIR/parse_devices.py" "${device_args[@]}" || exit 1

FINAL="${LLDPQ_ASSETS_FILE:-$SCRIPT_DIR/assets.ini}"
FINAL_DIR=$(dirname "$FINAL")
WEB_FINAL="$WEB_ROOT/assets.ini"
CACHE_FILE="$WEB_ROOT/device-cache.json"

if [[ ! -d "$FINAL_DIR" ]]; then
    echo "assets: local output directory does not exist: $FINAL_DIR" >&2
    exit 1
fi
if [[ ! -d "$WEB_ROOT" ]]; then
    echo "assets: web root does not exist: $WEB_ROOT" >&2
    exit 1
fi

# Keep all intermediate files private, run-specific and on the same filesystem
# as the local assets.ini so its final rename is atomic.
STAGING_DIR=$(mktemp -d "$FINAL_DIR/.assets-run.XXXXXX") || exit 1
ROWS_DIR="$STAGING_DIR/rows"
INVENTORY_FILE="$STAGING_DIR/inventory.tsv"
PREVIOUS_CACHE="$STAGING_DIR/device-cache.previous.json"
STAGED_FINAL="$STAGING_DIR/assets.ini"
STAGED_CACHE="$STAGING_DIR/device-cache.json"
mkdir -p "$ROWS_DIR"
: > "$INVENTORY_FILE"

WEB_ASSETS_TMP=""
WEB_CACHE_TMP=""
LOCAL_FINAL_TMP=""
ROLLBACK_TMP=""

remove_managed_file() {
    local path=$1
    [[ -n "$path" ]] || return 0
    if rm -f -- "$path" 2>/dev/null; then
        return 0
    fi
    "$ASSETS_SUDO_BIN" -n rm -f -- "$path" >/dev/null 2>&1 || true
}

cleanup() {
    remove_managed_file "${WEB_ASSETS_TMP:-}"
    remove_managed_file "${WEB_CACHE_TMP:-}"
    remove_managed_file "${ROLLBACK_TMP:-}"
    [[ -z "${LOCAL_FINAL_TMP:-}" ]] || rm -f -- "$LOCAL_FINAL_TMP" 2>/dev/null || true
    [[ -z "${STAGING_DIR:-}" ]] || rm -rf -- "$STAGING_DIR" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Take one validated cache snapshot for the entire run.  Collection failures
# must not race a concurrently changed cache or silently replace malformed JSON.
python3 - "$CACHE_FILE" "$PREVIOUS_CACHE" <<'PY'
import json
import os
import sys

source, destination = sys.argv[1:]
if os.path.exists(source):
    try:
        with open(source, "r", encoding="utf-8") as handle:
            cache = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"assets: cannot read device cache: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(cache, dict):
        print("assets: device cache root must be a JSON object", file=sys.stderr)
        raise SystemExit(1)
else:
    cache = {}

with open(destination, "w", encoding="utf-8") as handle:
    json.dump(cache, handle, ensure_ascii=False)
    handle.write("\n")
PY

#### REMOTE INFO FUNCTION
remote_info() {
    # Every field is a single token because assets.ini is whitespace-delimited.
    local h ip4 mac serial model rel up
    h="$HOSTNAME"
    ip4=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [[ -z "$ip4" ]] && ip4="NA"
    mac=$(cat /sys/class/net/eth0/address 2>/dev/null || true)
    [[ -z "$mac" ]] && mac="NA"
    serial=$(sudo -n dmidecode -s system-serial-number 2>/dev/null | head -1 | xargs || true)
    [[ -z "$serial" ]] && serial="NA"
    serial="${serial// /-}"
    model=$(sudo -n dmidecode -s system-product-name 2>/dev/null | head -1 | xargs || true)
    [[ -z "$model" ]] && model="NA"
    model="${model// /-}"
    rel=$(grep RELEASE /etc/lsb-release 2>/dev/null | cut -d '=' -f2 | head -1 || true)
    [[ -z "$rel" ]] && rel="NA"
    rel="${rel// /-}"
    up=$(uptime -p 2>/dev/null | sed 's/,//g; s/ /-/g' || true)
    [[ -z "$up" ]] && up="NA"

    printf '%s %s %s %s %s %s %s\n' \
        "$h" "$ip4" "$mac" "$serial" "$model" "$rel" "$up"
}

get_cached_device() {
    local hostname=$1
    python3 - "$PREVIOUS_CACHE" "$hostname" <<'PY'
import json
import re
import sys

cache_path, hostname = sys.argv[1:]
with open(cache_path, "r", encoding="utf-8") as handle:
    cache = json.load(handle)
entry = cache.get(hostname)
if not isinstance(entry, dict):
    print("NOCACHE")
    raise SystemExit(0)

last_seen = str(entry.get("last_seen", "")).strip()
if not last_seen or last_seen.lower() in {"never", "none", "no-info", "n/a"}:
    print("NOCACHE")
    raise SystemExit(0)

def token(value, fallback):
    text = str(value if value not in (None, "") else fallback).strip()
    text = re.sub(r"\s+", "-", text).replace("|", "-")
    return text or fallback

# LAST-SEEN must stay one token in assets.ini.  Cache JSON retains the
# human-readable space used by existing consumers.
last_seen_token = re.sub(r"\s+", "_", last_seen).replace("|", "-")
values = (
    token(entry.get("ip"), "No-Info"),
    token(entry.get("mac"), "No-Info"),
    token(entry.get("serial"), "No-Info"),
    token(entry.get("model"), "No-Info"),
    token(entry.get("release"), "No-Info"),
    token(entry.get("uptime"), "No-Info"),
    last_seen_token,
)
print("|".join(values))
PY
}

write_row() {
    local row_file=$1 host=$2 ip=$3 mac=$4 serial=$5 model=$6
    local release=$7 uptime=$8 status=$9 last_seen=${10}
    printf '%-20s %-15s %-17s %-12s %-20s %-10s %-15s %-12s %s\n' \
        "$host" "$ip" "$mac" "$serial" "$model" "$release" "$uptime" \
        "$status" "$last_seen" > "$row_file"
}

collect_over_ssh() {
    local ip=$1 user=$2 host=$3 row_file=$4 now=$5
    local ssh_output r_host r_ip r_mac r_serial r_model r_release r_uptime extra

    if ! ssh_output=$(
        "$ASSETS_TIMEOUT_BIN" --signal=TERM --kill-after=5 "$ASSETS_SSH_DEADLINE" \
            "$ASSETS_SSH_BIN" \
            -o BatchMode=yes \
            -o "ConnectTimeout=$ASSETS_SSH_CONNECT_TIMEOUT" \
            -o "ServerAliveInterval=$ASSETS_SERVER_ALIVE_INTERVAL" \
            -o "ServerAliveCountMax=$ASSETS_SERVER_ALIVE_COUNT_MAX" \
            -o StrictHostKeyChecking=no \
            "$user@$ip" "$(declare -f remote_info); remote_info" 2>/dev/null
    ); then
        return 1
    fi

    # Reject extra/malformed output instead of shifting fields and publishing a
    # syntactically valid but semantically corrupt row.
    if [[ "$ssh_output" == *$'\n'* ]]; then
        return 1
    fi
    read -r r_host r_ip r_mac r_serial r_model r_release r_uptime extra <<< "$ssh_output"
    if [[ -z "${r_host:-}" || -n "${extra:-}" ]]; then
        return 1
    fi
    [[ -z "${r_ip:-}" || "$r_ip" == "NA" ]] && r_ip="$ip"
    [[ -z "${r_mac:-}" ]] && r_mac="NA"
    [[ -z "${r_serial:-}" ]] && r_serial="NA"
    [[ -z "${r_model:-}" ]] && r_model="NA"
    [[ -z "${r_release:-}" ]] && r_release="NA"
    [[ -z "${r_uptime:-}" ]] && r_uptime="NA"

    write_row "$row_file" "$host" "$r_ip" "$r_mac" "$r_serial" \
        "$r_model" "$r_release" "$r_uptime" "OK" "$now"
}

process_one() {
    local ip=$1 user=$2 host=$3 row_file=$4
    local ping_reachable=true now cached_data
    local c_ip c_mac c_serial c_model c_release c_uptime c_last_seen

    now=$(date '+%Y-%m-%d_%H:%M:%S')
    if ! "$ASSETS_PING_BIN" -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        ping_reachable=false
    fi

    # ICMP is only a classification hint.  Devices that filter ping are still
    # queried over SSH and are reported OK when the authoritative command works.
    if collect_over_ssh "$ip" "$user" "$host" "$row_file" "$now"; then
        return 0
    fi

    cached_data=$(get_cached_device "$host")
    if [[ "$cached_data" != "NOCACHE" ]]; then
        IFS='|' read -r c_ip c_mac c_serial c_model c_release c_uptime c_last_seen \
            <<< "$cached_data"
    else
        c_last_seen="Never"
    fi

    if [[ "$ping_reachable" == "false" ]]; then
        if [[ "$cached_data" != "NOCACHE" ]]; then
            write_row "$row_file" "$host" "$c_ip" "$c_mac" "$c_serial" \
                "$c_model" "$c_release" "$c_uptime" "UNREACHABLE" "$c_last_seen"
        else
            write_row "$row_file" "$host" "No-Info" "No-Info" "No-Info" \
                "No-Info" "No-Info" "No-Info" "NO-INFO" "Never"
        fi
    else
        # Ping succeeded but the bounded SSH command did not.  Keep the prior
        # successful timestamp distinct from this failed attempt.
        write_row "$row_file" "$host" "$ip" "N/A" "N/A" "N/A" "N/A" \
            "N/A" "SSH-FAILED" "$c_last_seen"
    fi
}

# One file per worker avoids concurrent appends.  The later exact-coverage
# validation turns any worker/write failure into a failed run without replacing
# the previous published snapshots.
pids=()
worker_failed=false
index=0
for ip in "${device_ips[@]}"; do
    read -r user host <<< "${devices[$ip]}"
    printf '%s\t%s\n' "$host" "$ip" >> "$INVENTORY_FILE"
    row_file=$(printf '%s/%06d.row' "$ROWS_DIR" "$index")
    process_one "$ip" "$user" "$host" "$row_file" &
    pids+=("$!")
    index=$((index + 1))

    if (( ${#pids[@]} >= ASSETS_MAX_PARALLEL )); then
        for pid in "${pids[@]}"; do
            wait "$pid" || worker_failed=true
        done
        pids=()
    fi
done
for pid in "${pids[@]}"; do
    wait "$pid" || worker_failed=true
done
if [[ "$worker_failed" == "true" ]]; then
    echo "assets: one or more collection workers failed" >&2
    exit 1
fi

CREATED_AT=$(date '+%Y-%m-%d %H-%M-%S')

# Validate exactly one well-formed row for every unique inventory hostname,
# then sort data rows by their inventory IP without ever sorting the header.
python3 - "$INVENTORY_FILE" "$ROWS_DIR" "$STAGED_FINAL" "$CREATED_AT" <<'PY'
import ipaddress
import os
import re
import sys
from pathlib import Path

inventory_path, rows_path, output_path, created_at = sys.argv[1:]
allowed_statuses = {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}
timestamp_re = re.compile(r"^(?:Never|\d{4}-\d{2}-\d{2}_\d{2}:\d{2}(?::\d{2})?)$")

inventory = []
inventory_by_host = {}
with open(inventory_path, "r", encoding="utf-8") as handle:
    for line_number, raw in enumerate(handle, 1):
        parts = raw.rstrip("\n").split("\t")
        if len(parts) != 2 or not all(parts):
            raise SystemExit(f"assets: malformed inventory record at line {line_number}")
        hostname, address = parts
        folded = hostname.casefold()
        if folded in inventory_by_host:
            raise SystemExit(f"assets: duplicate inventory hostname: {hostname}")
        inventory_by_host[folded] = (hostname, address)
        inventory.append((hostname, address))

rows = {}
row_files = sorted(Path(rows_path).glob("*.row"))
for row_file in row_files:
    lines = row_file.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise SystemExit(f"assets: malformed row file: {row_file.name}")
    fields = lines[0].split()
    if len(fields) != 9:
        raise SystemExit(f"assets: expected 9 columns in {row_file.name}")
    hostname, status, last_seen = fields[0], fields[7], fields[8]
    if status not in allowed_statuses:
        raise SystemExit(f"assets: unsupported status for {hostname}: {status}")
    if not timestamp_re.fullmatch(last_seen):
        raise SystemExit(f"assets: invalid LAST-SEEN token for {hostname}: {last_seen}")
    folded = hostname.casefold()
    if folded in rows:
        raise SystemExit(f"assets: duplicate collected hostname: {hostname}")
    rows[folded] = fields

expected = set(inventory_by_host)
actual = set(rows)
if actual != expected or len(row_files) != len(inventory):
    missing = sorted(inventory_by_host[key][0] for key in expected - actual)
    extra = sorted(rows[key][0] for key in actual - expected)
    raise SystemExit(
        "assets: incomplete collection; "
        f"expected={len(inventory)} actual={len(row_files)} "
        f"missing={missing} extra={extra}"
    )

def address_key(hostname):
    address = inventory_by_host[hostname.casefold()][1]
    try:
        parsed = ipaddress.ip_address(address)
        return (0, parsed.version, int(parsed))
    except ValueError:
        return (1, address.casefold(), address)

ordered = sorted((rows[key] for key in actual), key=lambda fields: address_key(fields[0]))

def formatted(fields):
    widths = (20, 15, 17, 12, 20, 10, 15, 12)
    return " ".join(f"{value:<{width}}" for value, width in zip(fields[:8], widths)) + " " + fields[8]

header = (
    "DEVICE-NAME", "IP", "ETH0-MAC", "SERIAL", "MODEL", "RELEASE",
    "UPTIME", "STATUS", "LAST-SEEN",
)
with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
    handle.write(f"Created on {created_at}\n\n")
    handle.write(formatted(header) + "\n")
    for fields in ordered:
        handle.write(formatted(fields) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
PY

# Build a complete cache snapshot from the validated report.  last_seen remains
# the last successful collection; last_attempt and last_attempt_status record
# this run even when SSH failed or no prior successful data exists.
ATTEMPT_AT=$(date '+%Y-%m-%d %H:%M:%S')
python3 - "$PREVIOUS_CACHE" "$STAGED_FINAL" "$INVENTORY_FILE" \
    "$STAGED_CACHE" "$ATTEMPT_AT" <<'PY'
import json
import os
import sys

previous_path, assets_path, inventory_path, output_path, attempt_at = sys.argv[1:]
with open(previous_path, "r", encoding="utf-8") as handle:
    previous = json.load(handle)

inventory_ip = {}
with open(inventory_path, "r", encoding="utf-8") as handle:
    for raw in handle:
        hostname, address = raw.rstrip("\n").split("\t", 1)
        inventory_ip[hostname] = address

rows = []
with open(assets_path, "r", encoding="utf-8") as handle:
    for raw in handle:
        fields = raw.split()
        if not fields or fields[0] in {"Created", "DEVICE-NAME"}:
            continue
        if len(fields) != 9:
            raise SystemExit("assets: validated report changed before cache build")
        rows.append(fields)

status_names = {
    "OK": "ok",
    "UNREACHABLE": "unreachable",
    "SSH-FAILED": "ssh-failed",
    "NO-INFO": "no-info",
}
cache = {}
for fields in rows:
    hostname, ip, mac, serial, model, release, uptime, status, last_seen = fields
    old = previous.get(hostname)
    entry = dict(old) if isinstance(old, dict) else {}

    if status == "OK":
        entry = {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "serial": serial,
            "model": model,
            "release": release,
            "uptime": uptime,
            "last_seen": last_seen.replace("_", " ", 1),
        }
    else:
        entry["hostname"] = hostname
        entry.setdefault("ip", inventory_ip.get(hostname, ip))
        entry.setdefault("mac", mac)
        entry.setdefault("serial", serial)
        entry.setdefault("model", model)
        entry.setdefault("release", release)
        entry.setdefault("uptime", uptime)
        entry.setdefault("last_seen", "Never")

    entry["status"] = status_names[status]
    entry["last_attempt"] = attempt_at
    entry["last_attempt_status"] = status
    cache[hostname] = entry

if set(cache) != set(inventory_ip):
    raise SystemExit("assets: cache coverage does not match inventory")

with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(cache, handle, indent=2, ensure_ascii=False, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY

install_managed() {
    local source=$1 destination=$2
    if install -m 664 -o "$ASSETS_WEB_OWNER" -g "$ASSETS_WEB_GROUP" \
        "$source" "$destination" 2>/dev/null; then
        return 0
    fi
    "$ASSETS_SUDO_BIN" -n install -m 664 -o "$ASSETS_WEB_OWNER" \
        -g "$ASSETS_WEB_GROUP" "$source" "$destination"
}

move_managed() {
    local source=$1 destination=$2
    if mv -f -- "$source" "$destination" 2>/dev/null; then
        return 0
    fi
    "$ASSETS_SUDO_BIN" -n mv -f -- "$source" "$destination"
}

restore_web_target() {
    local backup=$1 destination=$2 existed=$3
    if [[ "$existed" != "true" ]]; then
        remove_managed_file "$destination"
        return 0
    fi
    ROLLBACK_TMP="$WEB_ROOT/.$(basename "$destination").rollback.$$.$RANDOM"
    install_managed "$backup" "$ROLLBACK_TMP" || return 1
    move_managed "$ROLLBACK_TMP" "$destination" || return 1
    ROLLBACK_TMP=""
}

restore_local_target() {
    local backup=$1 existed=$2
    if [[ "$existed" != "true" ]]; then
        rm -f -- "$FINAL"
        return 0
    fi
    ROLLBACK_TMP=$(mktemp "$FINAL_DIR/.assets.ini.rollback.XXXXXX") || return 1
    install -m 664 "$backup" "$ROLLBACK_TMP" || return 1
    mv -f -- "$ROLLBACK_TMP" "$FINAL" || return 1
    ROLLBACK_TMP=""
}

# Prepare every destination first.  Each final path is then replaced with a
# same-directory rename, so readers never observe a truncated JSON/report.
LOCAL_BACKUP="$STAGING_DIR/previous-local-assets.ini"
WEB_ASSETS_BACKUP="$STAGING_DIR/previous-web-assets.ini"
WEB_CACHE_BACKUP="$STAGING_DIR/previous-device-cache.json"
LOCAL_FINAL_EXISTED=false
WEB_ASSETS_EXISTED=false
WEB_CACHE_EXISTED=false
if [[ -e "$FINAL" ]]; then
    cp -- "$FINAL" "$LOCAL_BACKUP"
    LOCAL_FINAL_EXISTED=true
fi
if [[ -e "$WEB_FINAL" ]]; then
    cp -- "$WEB_FINAL" "$WEB_ASSETS_BACKUP"
    WEB_ASSETS_EXISTED=true
fi
if [[ -e "$CACHE_FILE" ]]; then
    cp -- "$CACHE_FILE" "$WEB_CACHE_BACKUP"
    WEB_CACHE_EXISTED=true
fi

publish_token="$$.$RANDOM"
WEB_ASSETS_TMP="$WEB_ROOT/.assets.ini.tmp.$publish_token"
WEB_CACHE_TMP="$WEB_ROOT/.device-cache.json.tmp.$publish_token"
LOCAL_FINAL_TMP=$(mktemp "$FINAL_DIR/.assets.ini.publish.XXXXXX")

install -m 664 "$STAGED_FINAL" "$LOCAL_FINAL_TMP"
install_managed "$STAGED_CACHE" "$WEB_CACHE_TMP"
install_managed "$STAGED_FINAL" "$WEB_ASSETS_TMP"

# Publish cache first: when the new web report becomes visible, its matching
# cache is already present. Every move is atomic for its individual target.
# If a later rename fails, restore every target already replaced so a reported
# failure cannot leave a durable mixed generation behind.
cache_published=false
web_assets_published=false
local_assets_published=false
publication_failed=""

if move_managed "$WEB_CACHE_TMP" "$CACHE_FILE"; then
    WEB_CACHE_TMP=""
    cache_published=true
else
    publication_failed="device cache"
fi
if [[ -z "$publication_failed" ]]; then
    if move_managed "$WEB_ASSETS_TMP" "$WEB_FINAL"; then
        WEB_ASSETS_TMP=""
        web_assets_published=true
    else
        publication_failed="web Assets report"
    fi
fi
if [[ -z "$publication_failed" ]]; then
    if mv -f -- "$LOCAL_FINAL_TMP" "$FINAL"; then
        LOCAL_FINAL_TMP=""
        local_assets_published=true
    else
        publication_failed="local Assets report"
    fi
fi

if [[ -n "$publication_failed" ]]; then
    rollback_failed=false
    if [[ "$local_assets_published" == "true" ]] && \
       ! restore_local_target "$LOCAL_BACKUP" "$LOCAL_FINAL_EXISTED"; then
        rollback_failed=true
    fi
    if [[ "$web_assets_published" == "true" ]] && \
       ! restore_web_target "$WEB_ASSETS_BACKUP" "$WEB_FINAL" "$WEB_ASSETS_EXISTED"; then
        rollback_failed=true
    fi
    if [[ "$cache_published" == "true" ]] && \
       ! restore_web_target "$WEB_CACHE_BACKUP" "$CACHE_FILE" "$WEB_CACHE_EXISTED"; then
        rollback_failed=true
    fi
    if [[ "$rollback_failed" == "true" ]]; then
        echo "assets: publication failed at $publication_failed; rollback was incomplete" >&2
    else
        echo "assets: publication failed at $publication_failed; previous outputs restored" >&2
    fi
    exit 1
fi

exit 0
