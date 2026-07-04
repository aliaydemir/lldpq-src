#!/usr/bin/env bash
# LLDPq switch configuration collector
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License

set -u
set -o pipefail

# Parse only the settings this script needs.  /etc/lldpq.conf is shared with
# the web UI and therefore must be treated as data, never sourced as shell.
load_lldpq_runtime_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value config_lock_fd="" read_status=0
    local saw_web_root=false saw_lldpq_user=false

    if [[ ! -f "$config_file" ]]; then
        echo "Required runtime configuration is missing: $config_file" >&2
        return 1
    fi
    if [[ -e "${config_file}.lock" ]] && command -v flock >/dev/null 2>&1; then
        exec {config_lock_fd}<>"${config_file}.lock" || return 1
        flock -s "$config_lock_fd" || {
            exec {config_lock_fd}>&-
            return 1
        }
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        case "$key" in
            WEB_ROOT) saw_web_root=true ;;
            LLDPQ_USER) saw_lldpq_user=true ;;
            PROJECT_DIR|GET_CONFIGS_MAX_PARALLEL|GET_CONFIGS_SSH_TIMEOUT) ;;
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
    done < "$config_file" || read_status=$?
    if [[ -n "$config_lock_fd" ]]; then
        flock -u "$config_lock_fd" || true
        exec {config_lock_fd}>&-
    fi
    if (( read_status != 0 )); then
        echo "Required runtime configuration is unreadable: $config_file" >&2
        return 1
    fi
    if [[ "$saw_web_root" != "true" || "$saw_lldpq_user" != "true" ||
          -z "${WEB_ROOT:-}" || -z "${LLDPQ_USER:-}" ]]; then
        echo "Required WEB_ROOT or LLDPQ_USER setting is missing or empty in $config_file" >&2
        return 1
    fi
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

acquire_config_collection_lock() {
    local lock_file="${1:-${LLDPQ_GET_CONFIGS_LOCK_FILE:-/tmp/lldpq-get-configs.lock}}"
    if ! command -v flock >/dev/null 2>&1; then
        echo "flock is required for safe configuration collection" >&2
        return 1
    fi
    exec 8>"$lock_file" || return 1
    if ! flock -n 8; then
        echo "Configuration collection is already running; this invocation was skipped." >&2
        return 75
    fi
}

safe_config_filename() {
    local hostname="$1"
    # Match parse_devices.py's hostname contract. Parentheses occur in legacy
    # customer inventories and are safe because every path use is quoted.
    [[ "$hostname" =~ ^[A-Za-z0-9][A-Za-z0-9._()-]{0,252}$ && \
       "$hostname" != *..* ]]
}

default_config_state_root() {
    local script_root="$1" home_root="$2"
    local persistent_system_config="$script_root/system-config"

    # docker-compose mounts system-config as a named volume. Keeping lifecycle
    # state and archives below that path prevents a container replacement from
    # discarding the only copy of configs removed from the configs volume.
    if [[ -d "$persistent_system_config" ]]; then
        printf '%s\n' "$persistent_system_config/config-collection"
    else
        printf '%s\n' "$home_root/.lldpq-state/config-collection"
    fi
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

regular_config_exists() {
    local candidate
    for candidate in "$@"; do
        [[ -n "$candidate" && -s "$candidate" && -f "$candidate" && ! -L "$candidate" ]] && return 0
    done
    return 1
}

write_collection_manifest() {
    local output_file="$1" collected_at="$2" web_config_dir="${3:-}"
    local project_config_dir="${4:-}"
    local hostname device status yaml_status set_status

    {
        printf '# lldpq-config-manifest-v1\n'
        printf '# generated_at=%s\n' "$collected_at"
        printf '# project_config_dir=%s\n' "$project_config_dir"
        printf '# hostname\tdevice\tcollection_status\tyaml_status\tnv_set_status\n'
        while IFS= read -r hostname; do
            device="${CONFIG_HOSTNAMES_SEEN[$hostname]}"
            if regular_config_exists \
                "${web_config_dir:+$web_config_dir/${hostname}.yaml}" \
                "${project_config_dir:+$project_config_dir/nv-yaml/${hostname}.yaml}"; then
                yaml_status="preserved"
            else
                yaml_status="missing"
            fi
            if regular_config_exists \
                "${web_config_dir:+$web_config_dir/${hostname}.txt}" \
                "${project_config_dir:+$project_config_dir/nv-set/${hostname}.txt}"; then
                set_status="preserved"
            else
                set_status="missing"
            fi

            if [[ -f "$STAGING_DIR/status/${hostname}.yaml.ok" ]]; then
                yaml_status="fresh"
                if [[ -f "$STAGING_DIR/status/${hostname}.set.ok" ]]; then
                    set_status="fresh"
                fi
            fi

            if [[ "$yaml_status" == "fresh" && "$set_status" == "fresh" ]]; then
                status="collected"
            elif [[ "$yaml_status" == "fresh" ]]; then
                status="partially-collected"
            elif [[ "$yaml_status" == "preserved" || "$set_status" == "preserved" ]]; then
                status="last-known-good-preserved"
            else
                status="unavailable"
            fi
            printf '%s\t%s\t%s\t%s\t%s\n' \
                "$hostname" "$device" "$status" "$yaml_status" "$set_status"
        done < <(printf '%s\n' "${!CONFIG_HOSTNAMES_SEEN[@]}" | LC_ALL=C sort)
    } > "$output_file"
}

manifest_project_config_dir() {
    local manifest="$1" line value canonical

    [[ -f "$manifest" && ! -L "$manifest" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            '# project_config_dir='*)
                value="${line#\# project_config_dir=}"
                [[ -n "$value" ]] || return 0
                if [[ "$(basename -- "$value")" != "configs" ]]; then
                    echo "Invalid project config sink in manifest: '$value'" >&2
                    return 1
                fi
                canonical=$(guard_managed_root "manifest project config sink" "$value") || return 1
                printf '%s\n' "$canonical"
                return 0
                ;;
        esac
    done < "$manifest"
}

find_removed_manifest_hosts() {
    local previous_manifest="$1" output_file="$2" web_config_dir="${3:-}"
    local project_config_dir="${4:-}" hostname device remainder source_file
    local -A removed_seen=()

    : > "$output_file"
    if [[ -f "$previous_manifest" && ! -L "$previous_manifest" ]]; then
        while IFS=$'\t' read -r hostname device remainder; do
            [[ -z "$hostname" || "$hostname" == \#* ]] && continue
            if ! safe_config_filename "$hostname"; then
                echo "Invalid hostname in config manifest: '$hostname'" >&2
                return 1
            fi
            if [[ -z "${CONFIG_HOSTNAMES_SEEN[$hostname]+present}" ]]; then
                printf '%s\t%s\n' "$hostname" "$device" >> "$output_file"
            fi
        done < "$previous_manifest"
        return 0
    fi

    # Migration bootstrap: before the first manifest exists, recognize only
    # regular .yaml/.txt files in the two LLDPq-managed config layouts.  Unknown
    # inventory names are archived (never deleted), establishing a clean first
    # manifest without losing legacy output.
    while IFS= read -r -d '' source_file; do
        hostname=$(basename "$source_file")
        hostname="${hostname%.yaml}"
        hostname="${hostname%.txt}"
        safe_config_filename "$hostname" || continue
        if [[ -z "${CONFIG_HOSTNAMES_SEEN[$hostname]+present}" &&
              -z "${removed_seen[$hostname]+present}" ]]; then
            printf '%s\t%s\n' "$hostname" "legacy-untracked" >> "$output_file"
            removed_seen["$hostname"]=1
        fi
    done < <(
        if [[ -n "$web_config_dir" && -d "$web_config_dir" ]]; then
            find "$web_config_dir" -maxdepth 1 -type f \
                \( -name '*.yaml' -o -name '*.txt' \) -print0
        fi
        if [[ -n "$project_config_dir" && -d "$project_config_dir" ]]; then
            find "$project_config_dir/nv-yaml" "$project_config_dir/nv-set" \
                -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.txt' \) \
                -print0 2>/dev/null
        fi
    )
}

archive_regular_config() {
    local source_file="$1" destination_file="$2"
    local destination_dir temp_file

    [[ -e "$source_file" || -L "$source_file" ]] || return 0
    if [[ ! -f "$source_file" || -L "$source_file" ]]; then
        echo "Refusing to archive non-regular config: '$source_file'" >&2
        return 1
    fi

    destination_dir=$(dirname "$destination_file")
    mkdir -p "$destination_dir" || return 1
    temp_file=$(mktemp "$destination_dir/.lldpq-archive.XXXXXXXXXX") || return 1
    if ! cp -- "$source_file" "$temp_file" ||
       ! chmod 600 "$temp_file" ||
       ! mv -f -- "$temp_file" "$destination_file"; then
        rm -f -- "$temp_file"
        return 1
    fi
}

remove_archived_config() {
    local source_file="$1" destination_file="$2" remove_with_root="${3:-false}"
    local quarantine_dir quarantine_file conflict_file

    [[ -e "$source_file" || -L "$source_file" ]] || return 0
    if [[ ! -f "$source_file" || -L "$source_file" ||
          ! -f "$destination_file" || -L "$destination_file" ]]; then
        echo "Refusing to remove config without a regular archived copy: '$source_file'" >&2
        return 1
    fi
    # Move the exact source inode out of the live name first. A publisher that
    # creates a new file before/after this rename is therefore never removed by
    # the retirement cleanup. The root-owned private directory also prevents a
    # writable web directory from pre-creating the quarantine destination.
    if [[ "$remove_with_root" == "true" ]]; then
        quarantine_dir=$(root_run mktemp -d \
            "$(dirname "$source_file")/.lldpq-retire.XXXXXXXXXX") || return 1
        quarantine_file="$quarantine_dir/$(basename "$source_file")"
        if ! root_run mv -T -- "$source_file" "$quarantine_file"; then
            root_run rmdir "$quarantine_dir" 2>/dev/null || true
            return 1
        fi
    else
        quarantine_dir=$(mktemp -d \
            "$(dirname "$source_file")/.lldpq-retire.XXXXXXXXXX") || return 1
        quarantine_file="$quarantine_dir/$(basename "$source_file")"
        if ! mv -T -- "$source_file" "$quarantine_file"; then
            rmdir "$quarantine_dir" 2>/dev/null || true
            return 1
        fi
    fi

    if { [[ "$remove_with_root" == "true" ]] && \
         root_run cmp -s -- "$quarantine_file" "$destination_file"; } || \
       { [[ "$remove_with_root" != "true" ]] && \
         cmp -s -- "$quarantine_file" "$destination_file"; }; then
        if [[ "$remove_with_root" == "true" ]]; then
            root_run rm -f -- "$quarantine_file" || return 1
            root_run rmdir "$quarantine_dir" || return 1
        else
            rm -f -- "$quarantine_file" || return 1
            rmdir "$quarantine_dir" || return 1
        fi
        return 0
    fi

    echo "Config changed while it was being archived; changed source preserved: '$source_file'" >&2
    if [[ ! -e "$source_file" && ! -L "$source_file" ]]; then
        # No replacement appeared. Restore without clobbering a file that may
        # race in while mv is running; GNU mv -n leaves the quarantine in place
        # if a destination appeared.
        if [[ "$remove_with_root" == "true" ]]; then
            root_run mv -nT -- "$quarantine_file" "$source_file" || true
        else
            mv -nT -- "$quarantine_file" "$source_file" || true
        fi
    fi

    if [[ -e "$quarantine_file" || -L "$quarantine_file" ]]; then
        # A new live source exists (or restore failed). Preserve the captured
        # version alongside the archive for manual recovery instead of either
        # overwriting the new source or discarding data.
        conflict_file="${destination_file}.source-conflict.$$.$RANDOM"
        if [[ "$remove_with_root" == "true" ]]; then
            root_run mv -T -- "$quarantine_file" "$conflict_file" || {
                echo "Recovery copy retained at $quarantine_file" >&2
                return 1
            }
            root_run chmod 600 "$conflict_file" || return 1
        else
            mv -T -- "$quarantine_file" "$conflict_file" || {
                echo "Recovery copy retained at $quarantine_file" >&2
                return 1
            }
            chmod 600 "$conflict_file" || return 1
        fi
    fi

    if [[ "$remove_with_root" == "true" ]]; then
        root_run rmdir "$quarantine_dir" 2>/dev/null || true
    else
        rmdir "$quarantine_dir" 2>/dev/null || true
    fi
    return 1
}

archive_removed_configs() {
    local removed_file="$1" archive_root="$2" web_config_dir="$3"
    local project_config_dir="${4:-}" hostname device

    [[ -s "$removed_file" ]] || return 0
    mkdir -p "$archive_root/web/nv-yaml" "$archive_root/web/nv-set" || return 1
    if [[ -n "$project_config_dir" ]]; then
        mkdir -p "$archive_root/project/nv-yaml" "$archive_root/project/nv-set" || return 1
    fi

    # Phase one copies every candidate before any published source is removed.
    # A full/archive-volume failure therefore leaves the live set
    # intact instead of producing a half-moved batch.
    while IFS=$'\t' read -r hostname device; do
        safe_config_filename "$hostname" || return 1
        archive_regular_config \
            "$web_config_dir/${hostname}.yaml" \
            "$archive_root/web/nv-yaml/${hostname}.yaml" || return 1
        archive_regular_config \
            "$web_config_dir/${hostname}.txt" \
            "$archive_root/web/nv-set/${hostname}.txt" || return 1

        if [[ -n "$project_config_dir" ]]; then
            archive_regular_config \
                "$project_config_dir/nv-yaml/${hostname}.yaml" \
                "$archive_root/project/nv-yaml/${hostname}.yaml" || return 1
            archive_regular_config \
                "$project_config_dir/nv-set/${hostname}.txt" \
                "$archive_root/project/nv-set/${hostname}.txt" || return 1
        fi
    done < "$removed_file"

    # Phase two removes only byte-identical sources. If a concurrent/manual
    # change occurred after the copy, preserve it and leave the manifest
    # pending so a later collection can retry safely.
    while IFS=$'\t' read -r hostname device; do
        remove_archived_config \
            "$web_config_dir/${hostname}.yaml" \
            "$archive_root/web/nv-yaml/${hostname}.yaml" true || return 1
        remove_archived_config \
            "$web_config_dir/${hostname}.txt" \
            "$archive_root/web/nv-set/${hostname}.txt" true || return 1

        if [[ -n "$project_config_dir" ]]; then
            remove_archived_config \
                "$project_config_dir/nv-yaml/${hostname}.yaml" \
                "$archive_root/project/nv-yaml/${hostname}.yaml" false || return 1
            remove_archived_config \
                "$project_config_dir/nv-set/${hostname}.txt" \
                "$archive_root/project/nv-set/${hostname}.txt" false || return 1
        fi
    done < "$removed_file"
}

archive_retired_project_sink() {
    local project_config_dir="$1" archive_root="$2"
    local category extension source_file hostname

    [[ -d "$project_config_dir" ]] || {
        echo "Previous project config sink is unavailable: '$project_config_dir'" >&2
        return 1
    }
    mkdir -p "$archive_root/nv-yaml" "$archive_root/nv-set" || return 1

    # Copy every generated config out of a sink before it is retired. Keeping
    # only removed inventory hosts is insufficient: an active host can be
    # removed later, after the old sink identity has otherwise been forgotten.
    for category in nv-yaml nv-set; do
        if [[ "$category" == "nv-yaml" ]]; then
            extension="yaml"
        else
            extension="txt"
        fi
        [[ -d "$project_config_dir/$category" ]] || continue
        while IFS= read -r -d '' source_file; do
            hostname=$(basename -- "$source_file")
            hostname="${hostname%.$extension}"
            safe_config_filename "$hostname" || {
                echo "Invalid config filename in retired project sink: '$source_file'" >&2
                return 1
            }
            archive_regular_config \
                "$source_file" "$archive_root/$category/$(basename -- "$source_file")" || return 1
        done < <(find "$project_config_dir/$category" -maxdepth 1 \
            \( -type f -o -type l \) -name "*.$extension" -print0)
    done

    # Remove only the exact bytes copied above. Concurrently replaced sources
    # survive and cause the lifecycle transaction to remain pending.
    for category in nv-yaml nv-set; do
        if [[ "$category" == "nv-yaml" ]]; then
            extension="yaml"
        else
            extension="txt"
        fi
        while IFS= read -r -d '' source_file; do
            remove_archived_config \
                "$source_file" "$archive_root/$category/$(basename -- "$source_file")" false || return 1
        done < <(find "$project_config_dir/$category" -maxdepth 1 \
            \( -type f -o -type l \) -name "*.$extension" -print0 2>/dev/null)
    done
}

config_collection_incomplete_count() {
    local staging_root="$1" hostname incomplete=0
    for hostname in "${!CONFIG_HOSTNAMES_SEEN[@]}"; do
        if [[ ! -f "$staging_root/status/${hostname}.yaml.ok" ||
              ! -f "$staging_root/status/${hostname}.set.ok" ]]; then
            incomplete=$((incomplete + 1))
        fi
    done
    printf '%s\n' "$incomplete"
}

if [[ "${LLDPQ_GET_CONFIGS_LIB_ONLY:-false}" == "true" ]]; then
    return 0 2>/dev/null || exit 0
fi

acquire_config_collection_lock || exit $?

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"
load_devices "$SCRIPT_DIR/parse_devices.py" || exit 1

LLDPQ_CONFIG_FILE="${LLDPQ_CONFIG_FILE:-/etc/lldpq.conf}"
load_lldpq_runtime_config "$LLDPQ_CONFIG_FILE" || exit 1

WEB_ROOT="${WEB_ROOT:-/var/www/html}"
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
PROJECT_DIR="${PROJECT_DIR:-}"
GET_CONFIGS_MAX_PARALLEL="${GET_CONFIGS_MAX_PARALLEL:-50}"
GET_CONFIGS_SSH_TIMEOUT="${GET_CONFIGS_SSH_TIMEOUT:-60}"
if [[ -z "$WEB_ROOT" || -z "$LLDPQ_USER" ]]; then
    echo "Required WEB_ROOT or LLDPQ_USER setting is empty in $LLDPQ_CONFIG_FILE" >&2
    exit 1
fi
case "$GET_CONFIGS_MAX_PARALLEL" in
    ''|*[!0-9]*|0) GET_CONFIGS_MAX_PARALLEL=50 ;;
esac
case "$GET_CONFIGS_SSH_TIMEOUT" in
    ''|*[!0-9]*|0) GET_CONFIGS_SSH_TIMEOUT=60 ;;
esac
if ! command -v timeout >/dev/null 2>&1; then
    echo "timeout is required for bounded configuration collection" >&2
    exit 1
fi
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

    if timeout --signal=TERM --kill-after=5 "$GET_CONFIGS_SSH_TIMEOUT" \
        ssh -q -o BatchMode=yes -o ConnectTimeout=10 \
        -o ServerAliveInterval=10 -o ServerAliveCountMax=2 \
        -o StrictHostKeyChecking=no \
        "${user}@${device}" "sudo cat /etc/nvue.d/startup.yaml" \
        > "$yaml_temp" 2>/dev/null && [[ -s "$yaml_temp" ]]; then
        mv "$yaml_temp" "$STAGING_DIR/nv-yaml/${hostname}.yaml"
        : > "$STAGING_DIR/status/${hostname}.yaml.ok"

        if timeout --signal=TERM --kill-after=5 "$GET_CONFIGS_SSH_TIMEOUT" \
            ssh -q -o BatchMode=yes -o ConnectTimeout=10 \
            -o ServerAliveInterval=10 -o ServerAliveCountMax=2 \
            -o StrictHostKeyChecking=no \
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
    # A killed parent must release the process-wide lock immediately; remote
    # workers do not need or inherit its descriptor.
    process_device "$device" "$user" "$hostname" 8>&- &
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
PROJECT_CONFIG_DIR=""
PROJECT_LIFECYCLE_READY=true
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
        # Keep the previous host manifest authoritative.  A retired device may
        # still have configs in this temporarily unavailable target; advancing
        # the manifest would forget that tombstone and leave those files stale
        # forever when the mount/project returns.
        PROJECT_LIFECYCLE_READY=false
    fi
else
    echo "Project folder not configured; web configs were still updated" >&2
fi

# The manifest is the authority for lifecycle cleanup.  Only a hostname that
# was in the previous manifest and is absent from the current inventory is
# archived.  Current but unreachable devices remain in the new manifest, so
# their last-known-good files are never mistaken for removed inventory.
DEFAULT_CONFIG_STATE_ROOT=$(default_config_state_root "$SCRIPT_DIR" "$HOME") || exit 1
CONFIG_STATE_ROOT="${LLDPQ_CONFIG_STATE_DIR:-$DEFAULT_CONFIG_STATE_ROOT}"
CONFIG_STATE_ROOT=$(guard_managed_root \
    "config lifecycle state" "$CONFIG_STATE_ROOT") || exit 1
mkdir -p "$CONFIG_STATE_ROOT" || exit 1
chmod 700 "$CONFIG_STATE_ROOT" || exit 1

CONFIG_MANIFEST="$CONFIG_STATE_ROOT/active-hosts.tsv"
NEW_MANIFEST="$STAGING_DIR/active-hosts.tsv"
REMOVED_HOSTS="$STAGING_DIR/removed-hosts.tsv"
PREVIOUS_PROJECT_CONFIG_DIR=""
if ! PREVIOUS_PROJECT_CONFIG_DIR=$(manifest_project_config_dir "$CONFIG_MANIFEST"); then
    exit 1
fi
PROJECT_SINK_CHANGED=false
if [[ -n "$PREVIOUS_PROJECT_CONFIG_DIR" && \
      "$PREVIOUS_PROJECT_CONFIG_DIR" != "$PROJECT_CONFIG_DIR" ]]; then
    PROJECT_SINK_CHANGED=true
    if [[ ! -d "$PREVIOUS_PROJECT_CONFIG_DIR" ]]; then
        echo "Previous project config sink is unavailable; lifecycle manifest retained" >&2
        PROJECT_LIFECYCLE_READY=false
    fi
fi
COLLECTION_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
write_collection_manifest \
    "$NEW_MANIFEST" "$COLLECTION_TIME" "$WEB_CONFIG_DIR" \
    "$PROJECT_CONFIG_DIR" || exit 1
find_removed_manifest_hosts \
    "$CONFIG_MANIFEST" "$REMOVED_HOSTS" "$WEB_CONFIG_DIR" \
    "$PROJECT_CONFIG_DIR" || exit 1

if [[ "$PROJECT_LIFECYCLE_READY" == "true" && \
      ( -s "$REMOVED_HOSTS" || "$PROJECT_SINK_CHANGED" == "true" ) ]]; then
    ARCHIVE_ID=$(date -u '+%Y%m%dT%H%M%SZ')
    ARCHIVE_ROOT="$CONFIG_STATE_ROOT/archive/$ARCHIVE_ID"
    if [[ -e "$ARCHIVE_ROOT" ]]; then
        ARCHIVE_ROOT="${ARCHIVE_ROOT}.$$"
    fi
    ARCHIVE_ROOT=$(guard_child_path \
        "$CONFIG_STATE_ROOT" "$ARCHIVE_ROOT" "config archive") || exit 1
    mkdir -p "$ARCHIVE_ROOT" || exit 1
    chmod 700 "$ARCHIVE_ROOT" || exit 1

    if [[ -f "$CONFIG_MANIFEST" && ! -L "$CONFIG_MANIFEST" ]]; then
        atomic_publish_file \
            "$CONFIG_MANIFEST" "$ARCHIVE_ROOT/previous-manifest.tsv" false || exit 1
        chmod 600 "$ARCHIVE_ROOT/previous-manifest.tsv" || exit 1
    fi
    if [[ -s "$REMOVED_HOSTS" ]]; then
        atomic_publish_file \
            "$REMOVED_HOSTS" "$ARCHIVE_ROOT/removed-hosts.tsv" false || exit 1
        chmod 600 "$ARCHIVE_ROOT/removed-hosts.tsv" || exit 1
    fi

    if [[ "$PROJECT_SINK_CHANGED" == "true" ]]; then
        archive_retired_project_sink \
            "$PREVIOUS_PROJECT_CONFIG_DIR" "$ARCHIVE_ROOT/retired-project" || exit 1
        printf '%s\n' "$PREVIOUS_PROJECT_CONFIG_DIR" \
            > "$ARCHIVE_ROOT/retired-project-root.txt" || exit 1
        chmod 600 "$ARCHIVE_ROOT/retired-project-root.txt" || exit 1
        echo "Archived retired project config sink: $PREVIOUS_PROJECT_CONFIG_DIR"
    fi

    if [[ -s "$REMOVED_HOSTS" ]]; then
        archive_removed_configs \
            "$REMOVED_HOSTS" "$ARCHIVE_ROOT" "$WEB_CONFIG_DIR" \
            "$PROJECT_CONFIG_DIR" || exit 1
        REMOVED_COUNT=$(wc -l < "$REMOVED_HOSTS" | tr -d ' ')
        echo "Archived configs for $REMOVED_COUNT inventory-removed device(s): $ARCHIVE_ROOT"
    fi
fi

if [[ "$PROJECT_LIFECYCLE_READY" == "true" ]]; then
    atomic_publish_file "$NEW_MANIFEST" "$CONFIG_MANIFEST" false || exit 1
    chmod 600 "$CONFIG_MANIFEST" || exit 1
else
    echo "Config lifecycle manifest retained until the configured project target is available" >&2
fi

echo "Published $PUBLISHED_COUNT successful files ($YAML_SUCCESS_COUNT YAML, $SET_SUCCESS_COUNT NV set)."
echo "Failed/unreachable devices retained their last-known-good published files."

# A partial run is useful (fresh files have already been published and every
# failed host kept its LKG), but it is not a completed trigger. Return non-zero
# so lldpq-trigger keeps the same request pending with bounded backoff.
INCOMPLETE_COUNT=$(config_collection_incomplete_count "$STAGING_DIR") || exit 1
if [[ "$PROJECT_LIFECYCLE_READY" != "true" ]]; then
    echo "Config collection lifecycle is incomplete; project target retry remains pending" >&2
    exit 1
fi
if (( INCOMPLETE_COUNT > 0 )); then
    echo "Config collection incomplete for $INCOMPLETE_COUNT device(s); retry remains pending" >&2
    exit 1
fi
exit 0
