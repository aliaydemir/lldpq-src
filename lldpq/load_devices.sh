#!/usr/bin/env bash
# Safely load devices.yaml records without evaluating generated shell code.

load_devices() {
    if [[ $# -lt 1 ]]; then
        echo "ERROR: load_devices requires the parse_devices.py path" >&2
        return 1
    fi

    local parser=$1
    shift
    local data_file
    data_file=$(mktemp "${TMPDIR:-/tmp}/lldpq-devices.XXXXXX") || return 1

    if ! python3 "$parser" --format nul "$@" > "$data_file"; then
        rm -f "$data_file"
        return 1
    fi

    device_ips=()
    device_info=()
    device_roles=()
    unset devices 2>/dev/null || true
    declare -gA devices=()

    local ip username hostname role
    while IFS= read -r -d '' ip; do
        if ! IFS= read -r -d '' username ||
           ! IFS= read -r -d '' hostname ||
           ! IFS= read -r -d '' role; then
            echo "ERROR: Incomplete device record from $parser" >&2
            rm -f "$data_file"
            return 1
        fi

        device_ips+=("$ip")
        device_info+=("$username $hostname")
        device_roles+=("$role")
        devices["$ip"]="$username $hostname"
    done < "$data_file"

    rm -f "$data_file"

    if [[ ${#device_ips[@]} -eq 0 ]]; then
        echo "ERROR: No devices found" >&2
        return 1
    fi
}
