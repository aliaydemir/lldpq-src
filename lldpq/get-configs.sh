#!/usr/bin/env bash
# LLDPq switch configuration collector
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License

set -u
set -o pipefail

# Parse only the settings this script needs.  /etc/lldpq.conf is shared with
# the web UI and therefore must be treated as data, never sourced as shell.
load_lldpq_runtime_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value

    [[ -f "$config_file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        case "$key" in
            WEB_ROOT|PROJECT_DIR|LLDPQ_USER|GET_CONFIGS_MAX_PARALLEL) ;;
            *) continue ;;
        esac
        raw="${BASH_REMATCH[2]}"
        value="$raw"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ ${#value} -ge 2 ]]; then
            if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || \
               [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi
        printf -v "$key" '%s' "$value"
    done < "$config_file"
}

canonical_path() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$path"
    else
        python3 -c 'import os,sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$path"
    fi
}

guard_managed_root() {
    local label="$1" path="$2"
    local canonical relative depth

    if [[ -z "$path" || "$path" != /* || "$path" == *$'\n'* || "$path" == *$'\r'* ]]; then
        echo "Refusing unsafe $label path: '$path'" >&2
        return 1
    fi
    canonical=$(canonical_path "$path") || return 1
    case "$canonical" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/www|"$HOME")
            echo "Refusing unsafe $label path: '$canonical'" >&2
            return 1
            ;;
    esac
    relative="${canonical#/}"
    depth=$(awk -F/ '{print NF}' <<< "$relative")
    if (( depth < 2 )); then
        echo "Refusing shallow $label path: '$canonical'" >&2
        return 1
    fi
    printf '%s\n' "$canonical"
}

guard_web_root() {
    local canonical="$1"
    local canonical_home
    canonical_home=$(canonical_path "$HOME") || return 1
    case "$canonical" in
        /home/*|/root/*)
            if [[ "$canonical" != "$canonical_home"/* ]]; then
                echo "Refusing web root under another user's home: '$canonical'" >&2
                return 1
            fi
            ;;
    esac
    if [[ "$canonical" == /var/www/* ]]; then
        printf '%s\n' "$canonical"
        return 0
    fi
    case "$canonical" in
        /bin/*|/boot/*|/dev/*|/etc/*|/lib/*|/lib64/*|/proc/*|/run/*|/sbin/*|/sys/*|/usr/*|/var/*)
            echo "Refusing web root inside protected system tree: '$canonical'" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$canonical"
}

guard_child_path() {
    local parent="$1" child="$2" label="$3"
    local canonical_parent canonical_child
    canonical_parent=$(canonical_path "$parent") || return 1
    canonical_child=$(canonical_path "$child") || return 1
    case "$canonical_child" in
        "$canonical_parent"/*) printf '%s\n' "$canonical_child" ;;
        *)
            echo "Refusing $label outside managed root: '$canonical_child'" >&2
            return 1
            ;;
    esac
}

root_run() {
    if [[ "${LLDPQ_TEST_NO_SUDO:-false}" == "true" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

safe_config_filename() {
    local hostname="$1"
    [[ -n "$hostname" && "$hostname" != "." && "$hostname" != ".." && \
       "$hostname" =~ ^[A-Za-z0-9._-]+$ ]]
}

# Publish one completed file using a sibling temporary and rename.  Existing
# content remains untouched if any copy/permission step fails.
atomic_publish_file() {
    local source_file="$1" destination_file="$2" use_root="${3:-false}"
    local owner="${4:-}" group="${5:-}" temp_destination

    [[ -s "$source_file" ]] || return 1
    if [[ "$use_root" == "true" ]]; then
        # Root mktemp uses O_EXCL, so a group-writable destination directory
        # cannot pre-create a symlink at the random staging path. Keeping the
        # inode beside its destination also guarantees the final mv is a
        # same-filesystem rename (including Docker named volumes).
        temp_destination=$(root_run mktemp "$(dirname "$destination_file")/.lldpq-config-publish.XXXXXXXXXX") || return 1
        root_run cp "$source_file" "$temp_destination" || {
            root_run rm -f "$temp_destination"; return 1;
        }
        root_run chmod 664 "$temp_destination" || {
            root_run rm -f "$temp_destination"; return 1;
        }
        if [[ -n "$owner" && -n "$group" ]]; then
            root_run chown "$owner:$group" "$temp_destination" || {
                root_run rm -f "$temp_destination"; return 1;
            }
        fi
        root_run mv -fT "$temp_destination" "$destination_file"
    else
        temp_destination="${destination_file}.lldpq-new.$$.$RANDOM"
        cp "$source_file" "$temp_destination" || return 1
        chmod 664 "$temp_destination" || { rm -f "$temp_destination"; return 1; }
        mv -f "$temp_destination" "$destination_file"
    fi
}

publish_flat_staging() {
    local staging_root="$1" destination_root="$2" use_root="${3:-false}"
    local owner="${4:-}" group="${5:-}" category source_file
    local published=0

    if [[ "$use_root" == "true" ]]; then
        root_run mkdir -p "$destination_root"
    else
        mkdir -p "$destination_root"
    fi
    for category in nv-yaml nv-set; do
        while IFS= read -r -d '' source_file; do
            atomic_publish_file \
                "$source_file" \
                "$destination_root/$(basename "$source_file")" \
                "$use_root" "$owner" "$group" || return 1
            published=$((published + 1))
        done < <(find "$staging_root/$category" -maxdepth 1 -type f -size +0c -print0 2>/dev/null)
    done
    printf '%s\n' "$published"
}

publish_nested_staging() {
    local staging_root="$1" destination_root="$2"
    local category source_file

    for category in nv-yaml nv-set; do
        mkdir -p "$destination_root/$category"
        while IFS= read -r -d '' source_file; do
            atomic_publish_file \
                "$source_file" \
                "$destination_root/$category/$(basename "$source_file")" \
                false || return 1
        done < <(find "$staging_root/$category" -maxdepth 1 -type f -size +0c -print0 2>/dev/null)
    done
}

if [[ "${LLDPQ_GET_CONFIGS_LIB_ONLY:-false}" == "true" ]]; then
    return 0 2>/dev/null || exit 0
fi

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"
load_devices "$SCRIPT_DIR/parse_devices.py" || exit 1

LLDPQ_CONFIG_FILE="${LLDPQ_CONFIG_FILE:-/etc/lldpq.conf}"
load_lldpq_runtime_config "$LLDPQ_CONFIG_FILE"

WEB_ROOT="${WEB_ROOT:-/var/www/html}"
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
PROJECT_DIR="${PROJECT_DIR:-}"
GET_CONFIGS_MAX_PARALLEL="${GET_CONFIGS_MAX_PARALLEL:-50}"
case "$GET_CONFIGS_MAX_PARALLEL" in
    ''|*[!0-9]*|0) GET_CONFIGS_MAX_PARALLEL=50 ;;
esac
if [[ ! "$LLDPQ_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
    echo "Invalid LLDPQ_USER: '$LLDPQ_USER'" >&2
    exit 1
fi

WEB_ROOT=$(guard_managed_root "web root" "$WEB_ROOT") || exit 1
WEB_ROOT=$(guard_web_root "$WEB_ROOT") || exit 1
WEB_CONFIG_DIR=$(guard_child_path "$WEB_ROOT" "$WEB_ROOT/configs" "web config directory") || exit 1

STAGING_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-configs.XXXXXX")
UNREACHABLE_FILE="$STAGING_DIR/unreachable"
mkdir -p "$STAGING_DIR/nv-yaml" "$STAGING_DIR/nv-set" "$STAGING_DIR/status"
: > "$UNREACHABLE_FILE"
cleanup() {
    if [[ -n "${STAGING_DIR:-}" && -d "$STAGING_DIR" ]]; then
        rm -rf -- "$STAGING_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds an mgmt-VRF rule so plain ping works.
PING="ping"

ping_test() {
    local device="$1" hostname="$2"
    if ! "$PING" -c 1 -W 0.5 "$device" >/dev/null 2>&1; then
        printf '%s\t%s\n' "$device" "$hostname" >> "$UNREACHABLE_FILE"
        return 1
    fi
}

execute_commands() {
    local device="$1" user="$2" hostname="$3"
    local yaml_temp set_temp

    if ! safe_config_filename "$hostname"; then
        echo "Invalid hostname for config filename: '$hostname'" >&2
        return 1
    fi

    yaml_temp="$STAGING_DIR/nv-yaml/.${hostname}.yaml.tmp.$$"
    set_temp="$STAGING_DIR/nv-set/.${hostname}.txt.tmp.$$"

    if ssh -q -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
        "${user}@${device}" "sudo cat /etc/nvue.d/startup.yaml" \
        > "$yaml_temp" 2>/dev/null && [[ -s "$yaml_temp" ]]; then
        mv "$yaml_temp" "$STAGING_DIR/nv-yaml/${hostname}.yaml"
        : > "$STAGING_DIR/status/${hostname}.yaml.ok"

        if ssh -q -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
            "${user}@${device}" "nv config show -o commands" \
            > "$set_temp" 2>/dev/null && [[ -s "$set_temp" ]]; then
            mv "$set_temp" "$STAGING_DIR/nv-set/${hostname}.txt"
            : > "$STAGING_DIR/status/${hostname}.set.ok"
        else
            rm -f "$set_temp"
            echo "NV set command export failed for $hostname; last-known-good copy kept" >&2
        fi
        echo -e "\e[0;32mConfig of \e[1;32m${hostname}\e[0;32m device has been pulled...\e[0m"
    else
        rm -f "$yaml_temp" "$set_temp"
        echo -e "\e[0;31mFailed to execute commands on ${hostname} (${device}); last-known-good copy kept\e[0m"
        return 1
    fi
}

process_device() {
    local device="$1" user="$2" hostname="$3"
    ping_test "$device" "$hostname" || return 1
    execute_commands "$device" "$user" "$hostname"
}

wait_for_slot() {
    while (( $(jobs -rp | wc -l) >= GET_CONFIGS_MAX_PARALLEL )); do
        wait -n 2>/dev/null || true
    done
}

# Validate every output name before starting any network work.  Duplicate
# hostnames would otherwise race on the same staging/final file.
declare -A CONFIG_HOSTNAMES_SEEN=()
for device in "${!devices[@]}"; do
    IFS=' ' read -r _user _hostname <<< "${devices[$device]}"
    if ! safe_config_filename "$_hostname"; then
        echo "Invalid hostname for config filename: '$_hostname'" >&2
        exit 1
    fi
    if [[ -n "${CONFIG_HOSTNAMES_SEEN[$_hostname]+present}" ]]; then
        echo "Duplicate hostname in devices.yaml: '$_hostname'" >&2
        exit 1
    fi
    CONFIG_HOSTNAMES_SEEN["$_hostname"]="$device"
done

for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    wait_for_slot
    process_device "$device" "$user" "$hostname" &
done
wait || true

echo ""
if [[ -s "$UNREACHABLE_FILE" ]]; then
    echo -e "\e[0;36mUnreachable hosts:\e[0m"
    while IFS=$'\t' read -r ip hostname; do
        printf "\e[31m[%-14s]\t\e[0;31m[%-1s]\e[0m\n" "$ip" "$hostname"
    done < "$UNREACHABLE_FILE"
    echo ""
else
    echo -e "\e[0;32mAll hosts are reachable.\e[0m"
    echo ""
fi

YAML_SUCCESS_COUNT=$(find "$STAGING_DIR/nv-yaml" -maxdepth 1 -type f -size +0c | wc -l | tr -d ' ')
SET_SUCCESS_COUNT=$(find "$STAGING_DIR/nv-set" -maxdepth 1 -type f -size +0c | wc -l | tr -d ' ')
if (( YAML_SUCCESS_COUNT == 0 )); then
    echo "No switch configurations were collected; all existing published configs were preserved" >&2
    exit 1
fi

root_run mkdir -p "$WEB_CONFIG_DIR"
WEB_CONFIG_DIR=$(guard_child_path "$WEB_ROOT" "$WEB_CONFIG_DIR" "web config directory") || exit 1
PUBLISHED_COUNT=$(publish_flat_staging \
    "$STAGING_DIR" "$WEB_CONFIG_DIR" true "$LLDPQ_USER" www-data) || exit 1
root_run chmod 775 "$WEB_CONFIG_DIR"

# Use PROJECT_DIR from configuration or discover a compatible project.  Unlike
# the previous implementation, the project configs directory is never removed;
# only successfully collected files are atomically updated.
if [[ -z "$PROJECT_DIR" ]]; then
    for dir in "$HOME"/*; do
        if [[ -d "$dir" && -d "$dir/inventory" && -d "$dir/playbooks" && \
              -d "$dir/roles" && -d "$dir/assets" ]]; then
            PROJECT_DIR="$dir"
            break
        fi
    done
fi

if [[ -n "$PROJECT_DIR" && "$PROJECT_DIR" != "NoNe" ]]; then
    PROJECT_DIR=$(guard_managed_root "project root" "$PROJECT_DIR") || exit 1
    if [[ -d "$PROJECT_DIR/inventory" && -d "$PROJECT_DIR/playbooks" ]]; then
        PROJECT_CONFIG_DIR=$(guard_child_path \
            "$PROJECT_DIR" "$PROJECT_DIR/configs" "project config directory") || exit 1
        mkdir -p "$PROJECT_CONFIG_DIR"
        PROJECT_CONFIG_DIR=$(guard_child_path \
            "$PROJECT_DIR" "$PROJECT_CONFIG_DIR" "project config directory") || exit 1
        publish_nested_staging "$STAGING_DIR" "$PROJECT_CONFIG_DIR" || exit 1
        echo "Project configs updated safely: $PROJECT_CONFIG_DIR"
    else
        echo "Configured project folder is missing inventory/playbooks; project publish skipped" >&2
    fi
else
    echo "Project folder not configured; web configs were still updated" >&2
fi

echo "Published $PUBLISHED_COUNT successful files ($YAML_SUCCESS_COUNT YAML, $SET_SUCCESS_COUNT NV set)."
echo "Failed/unreachable devices retained their last-known-good published files."
exit 0
