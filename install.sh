#!/usr/bin/env bash
# LLDPq Installation & Update Script
#
# Copyright (c) 2024-2026 LLDPq Project
# Licensed under MIT License - see LICENSE file for details
#
# Automatically detects existing installation:
#   No existing install → Fresh install (packages, configs, everything)
#   Existing install    → Update mode (backup, preserve configs, update files)
#
# Usage: ./install.sh [-y] [--enable-telemetry] [--disable-telemetry]
#                     [--replace-dhcp-config]
#   -y                  Auto-yes to all prompts (non-interactive mode, uses defaults)
#   --enable-telemetry  Enable streaming telemetry support (installs Docker)
#   --disable-telemetry Disable streaming telemetry support
#   --replace-dhcp-config
#                       Replace a pre-existing non-LLDPq dhcpd.conf after
#                       validating the replacement and taking a backup
#
# ALGORITHM:
# ┌─────────────────────────────────────────────────────────┐
# │ 1. Parse arguments (-y, --help, --enable/disable-tele.) │
# │ 2. Telemetry-only mode? → handle Docker and exit        │
# │ 3. Initial checks (no sudo wrapper, in lldpq-src dir)   │
# │ 4. Detect LLDPQ_INSTALL_DIR from /etc/lldpq.conf        │
# │    or default (~/lldpq for user, /opt/lldpq for root)   │
# ├──────────────────────────────────────────────────────────┤
# │ MODE DETECTION:                                          │
# │ /etc/lldpq.conf exists? ───┬── YES → UPDATE MODE        │
# │                            └── NO  → FRESH MODE         │
# │ (User can force clean install → switches to FRESH)       │
# ├──────────────────────────────────────────────────────────┤
# │ FRESH MODE ONLY:                                         │
# │   • Check/stop Apache2 (port 80 conflict)                │
# │   • apt install (nginx, fcgiwrap, python3, sshpass, etc) │
# │   • Download Monaco Editor (offline code editor)         │
# │   • apt install Python requests + ruamel.yaml            │
# ├──────────────────────────────────────────────────────────┤
# │ UPDATE MODE ONLY:                                        │
# │   • Safely parse /etc/lldpq.conf → save existing settings│
# │   • Optional full snapshot with --backup                 │
# │   • Always preserve runtime/config data through update   │
# │   • Stop running LLDPq processes                         │
# │   • Preserve user configs + .git to temp dir             │
# │   • Remove old lldpq directory                           │
# ├──────────────────────────────────────────────────────────┤
# │ COMMON (both modes):                                     │
# │   • Copy etc/* → /etc/        (nginx config)             │
# │   • Copy html/* → /var/www/html/  (web UI)               │
# │   • Monaco + js-yaml check (download if missing)         │
# │   • Copy bin/* → /usr/local/bin/  (CLI tools)            │
# │   • Copy lldpq/* → $LLDPQ_INSTALL_DIR (core scripts)    │
# │   • Restore preserved configs + .git (update only)       │
# │   • Copy telemetry stack                                 │
# │   • Set permissions:                                     │
# │     - Web: $LLDPQ_USER:www-data, 775/664, .sh +x        │
# │     - LLDPq dir: 750, devices.yaml 664                  │
# │     - ACL for group read inheritance                     │
# │   • Topology symlinks (lldpq/ → /var/www/html/)          │
# │   • Ansible directory detection + permissions            │
# │   • Write /etc/lldpq.conf (all vars + telemetry)         │
# │   • Sudoers: www-data → SSH/SCP + DHCP/Provision         │
# │   • DHCP directories + ZTP script placeholder            │
# │   • Authentication (sessions dir, users file)            │
# │   • Python packages verify (update only)                 │
# │   • nginx config + restart + fcgiwrap restart            │
# │   • Cron jobs (lldpq, get-conf, triggers, git commit)    │
# ├──────────────────────────────────────────────────────────┤
# │ UPDATE MODE POST:                                        │
# │   • Restore monitoring data from backup                  │
# │   • Print preserved files summary                        │
# ├──────────────────────────────────────────────────────────┤
# │ FRESH MODE POST:                                         │
# │   • Print config file edit instructions                  │
# │   • Telemetry prompt → Docker install if yes             │
# │   • SSH key setup instructions                           │
# │   • Initialize git repository + hooks                    │
# └──────────────────────────────────────────────────────────┘

set -e

# Root/system services and the web backup/uninstall workflows must never
# execute copies under LLDPQ_DIR: that tree is intentionally writable by the
# service account.
LLDPQ_BACKUP_IMPORT_HELPER="/usr/local/libexec/lldpq-backup-import.py"
LLDPQ_AUTH_USERS_HELPER="/usr/local/libexec/lldpq-auth-users.py"
LLDPQ_AUTH_USERS_SUDOERS="/etc/sudoers.d/www-data-lldpq-auth"
LLDPQ_UNINSTALL_SCRIPT="/usr/local/libexec/lldpq-uninstall.sh"
LLDPQ_UNINSTALL_WEB_GATEWAY="/usr/local/libexec/lldpq-uninstall-web.py"
LLDPQ_UNINSTALL_SUDOERS="/etc/sudoers.d/www-data-lldpq-uninstall"
LLDPQ_SOURCE_MANIFEST="/etc/lldpq-source.json"
LLDPQ_LIFECYCLE_LOCK="/etc/lldpq.lifecycle.lock"
LLDPQ_UNINSTALL_ACTIVE_MARKER="/run/lldpq-uninstall.active"
INSTALL_LIFECYCLE_LOCK_FD=""

# Create shared transaction locks without ever following a pre-existing
# symlink. Existing lock inodes are retained so an in-flight flock cannot be
# split from a newly installed process during an update.
prepare_shared_lock_files() {
    sudo python3 - "$@" <<'PYTHON'
import grp
import os
import stat
import sys

group_id = grp.getgrnam("www-data").gr_gid
base_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
base_flags |= getattr(os, "O_NOFOLLOW", 0)

for path in sys.argv[1:]:
    if not os.path.isabs(path):
        raise SystemExit(f"transaction lock path must be absolute: {path}")
    try:
        descriptor = os.open(path, base_flags | os.O_CREAT | os.O_EXCL, 0o660)
    except FileExistsError:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise SystemExit(f"transaction lock is not a regular file: {path}")
        descriptor = os.open(path, base_flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            os.close(descriptor)
            raise SystemExit(f"transaction lock changed while opening: {path}")
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SystemExit(f"transaction lock is not a regular file: {path}")
        os.fchown(descriptor, 0, group_id)
        os.fchmod(descriptor, 0o660)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PYTHON
}

acquire_install_lifecycle_lock() {
    local current_uid temp_acl=false wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"
    local lock_gid opened_identity path_identity lock_metadata gateway_metadata gateway_parent_metadata
    [[ -z "$INSTALL_LIFECYCLE_LOCK_FD" ]] || return 0
    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    command -v flock >/dev/null 2>&1 || return 1
    # This path already exists on every installation that has the uninstall
    # gateway.  Do not recreate it here: an uninstall may have removed the
    # gateway, marker and lock while this installer was entering the wait.
    # Recreating the lock would split the lifecycle transaction.
    if [[ -L "$LLDPQ_LIFECYCLE_LOCK" || ! -f "$LLDPQ_LIFECYCLE_LOCK" ]]; then
        echo "[!] LLDPq lifecycle lock disappeared; restart install/update after checking the host" >&2
        return 1
    fi
    lock_gid=$(getent group www-data 2>/dev/null | awk -F: 'NR == 1 { print $3 }')
    [[ "$lock_gid" =~ ^[0-9]+$ ]] || return 1
    current_uid=$(id -u) || return 1
    if (( current_uid != 0 )); then
        sudo setfacl -m "u:${current_uid}:rw" "$LLDPQ_LIFECYCLE_LOCK" || return 1
        temp_acl=true
    fi
    if ! exec {INSTALL_LIFECYCLE_LOCK_FD}<>"$LLDPQ_LIFECYCLE_LOCK"; then
        $temp_acl && sudo setfacl -x "u:${current_uid}" "$LLDPQ_LIFECYCLE_LOCK" 2>/dev/null || true
        INSTALL_LIFECYCLE_LOCK_FD=""
        return 1
    fi
    $temp_acl && sudo setfacl -x "u:${current_uid}" "$LLDPQ_LIFECYCLE_LOCK" 2>/dev/null || true
    if ! flock -w "$wait_seconds" "$INSTALL_LIFECYCLE_LOCK_FD"; then
        echo "[!] Timed out waiting for the LLDPq lifecycle lock" >&2
        exec {INSTALL_LIFECYCLE_LOCK_FD}>&-
        INSTALL_LIFECYCLE_LOCK_FD=""
        return 1
    fi

    # flock protects the opened inode, not the pathname.  The uninstaller
    # intentionally unlinks this lock at the end of its transaction, so a
    # waiter can wake while holding an obsolete inode.  Re-resolve the path
    # after locking and require it to still name the exact opened inode.
    opened_identity=$(stat -Lc '%d:%i' "/proc/$$/fd/$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true)
    path_identity=$(stat -c '%d:%i' -- "$LLDPQ_LIFECYCLE_LOCK" 2>/dev/null || true)
    lock_metadata=$(stat -Lc '%u:%g:%a:%h' "/proc/$$/fd/$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true)
    if [[ -z "$opened_identity" || "$opened_identity" != "$path_identity" || \
          -L "$LLDPQ_LIFECYCLE_LOCK" || \
          "$lock_metadata" != "0:${lock_gid}:660:1" ]]; then
        echo "[!] LLDPq lifecycle lock was removed or replaced while waiting; install/update was not started" >&2
        flock -u "$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true
        exec {INSTALL_LIFECYCLE_LOCK_FD}>&-
        INSTALL_LIFECYCLE_LOCK_FD=""
        return 1
    fi
    if [[ -e "$LLDPQ_UNINSTALL_ACTIVE_MARKER" || -L "$LLDPQ_UNINSTALL_ACTIVE_MARKER" ]]; then
        echo "[!] LLDPq uninstall is scheduled or running; install/update was not started" >&2
        flock -u "$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true
        exec {INSTALL_LIFECYCLE_LOCK_FD}>&-
        INSTALL_LIFECYCLE_LOCK_FD=""
        return 1
    fi

    # The fixed gateway and its protected parent are the other half of this
    # lifecycle authority.  A waiter on an old lock must not continue after a
    # completed uninstall has removed them, even though the public marker is
    # already gone at that point.
    gateway_metadata=$(stat -c '%u:%g:%a:%h' -- "$LLDPQ_UNINSTALL_WEB_GATEWAY" 2>/dev/null || true)
    gateway_parent_metadata=$(stat -c '%u:%a' -- "${LLDPQ_UNINSTALL_WEB_GATEWAY%/*}" 2>/dev/null || true)
    if [[ -L "$LLDPQ_UNINSTALL_WEB_GATEWAY" || \
          ! -f "$LLDPQ_UNINSTALL_WEB_GATEWAY" || \
          "$gateway_metadata" != "0:0:755:1" || \
          -L "${LLDPQ_UNINSTALL_WEB_GATEWAY%/*}" || \
          ! -d "${LLDPQ_UNINSTALL_WEB_GATEWAY%/*}" || \
          ! "$gateway_parent_metadata" =~ ^0:[0-7]?[0-7][0145][0145]$ ]]; then
        echo "[!] LLDPq uninstall authority disappeared or became unsafe while waiting; install/update was not started" >&2
        flock -u "$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true
        exec {INSTALL_LIFECYCLE_LOCK_FD}>&-
        INSTALL_LIFECYCLE_LOCK_FD=""
        return 1
    fi
}

release_install_lifecycle_lock() {
    [[ -n "$INSTALL_LIFECYCLE_LOCK_FD" ]] || return 0
    flock -u "$INSTALL_LIFECYCLE_LOCK_FD" 2>/dev/null || true
    exec {INSTALL_LIFECYCLE_LOCK_FD}>&-
    INSTALL_LIFECYCLE_LOCK_FD=""
}

# Copy the fixed system configuration into a private, unprivileged snapshot.
# This is used when either the config or its stable lock inode cannot be opened
# by the invoking shell (for example after an interrupted root-owned recovery,
# or before a newly-added supplementary group is visible to that shell).  Never
# extend this privileged read to a caller-supplied path.
snapshot_system_lldpq_config() {
    local config_file="$1" snapshot lock_file="${1}.lock"

    [[ "$config_file" == "/etc/lldpq.conf" ]] || return 1
    snapshot=$(mktemp "${TMPDIR:-/tmp}/lldpq-config-read.XXXXXX") || return 1
    chmod 600 "$snapshot" || { rm -f "$snapshot"; return 1; }
    if [[ -e "$lock_file" ]] && command -v flock >/dev/null 2>&1; then
        if ! sudo flock -s "$lock_file" cat -- "$config_file" > "$snapshot"; then
            rm -f "$snapshot"
            return 1
        fi
    elif ! sudo cat -- "$config_file" > "$snapshot"; then
        rm -f "$snapshot"
        return 1
    fi
    printf '%s\n' "$snapshot"
}

normalize_installed_lldpq_config_access() {
    local config_file="/etc/lldpq.conf" lock_file="/etc/lldpq.conf.lock" reader
    local current_uid runtime_uid

    [[ -f "$config_file" ]] || {
        echo "[!] Installed LLDPq configuration is missing: $config_file" >&2
        return 1
    }
    if [[ ! "${LLDPQ_USER:-}" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]] || \
       ! runtime_uid=$(id -u "$LLDPQ_USER" 2>/dev/null); then
        echo "[!] Invalid or unavailable LLDPq runtime user: '${LLDPQ_USER:-}'" >&2
        return 1
    fi
    current_uid=$(id -u) || return 1
    # The runtime account owns the data file so a first-install shell can use
    # the CLI immediately; www-data retains the intended web write access.
    # The stable lock inode stays root-owned and grants only this runtime UID a
    # named ACL. Atomic config replacements therefore need no ACL propagation.
    sudo chown "$LLDPQ_USER:www-data" "$config_file" || return 1
    sudo chmod 660 "$config_file" || return 1
    prepare_shared_lock_files "$lock_file" || return 1
    command -v setfacl >/dev/null 2>&1 || {
        echo "[!] setfacl is required to grant narrow runtime lock access" >&2
        return 1
    }
    if [[ "$LLDPQ_USER" != "root" ]]; then
        sudo setfacl -m "u:${LLDPQ_USER}:rw" "$lock_file" || return 1
        sudo usermod -a -G www-data "$LLDPQ_USER" || return 1
    fi
    if ! sudo -u "$LLDPQ_USER" /usr/local/bin/lldpq-config --require-config \
       --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
       --config "$config_file" >/dev/null; then
        echo "[!] Runtime user '$LLDPQ_USER' cannot read the installed LLDPq configuration" >&2
        return 1
    fi
    if (( current_uid == runtime_uid )) && \
       ! /usr/local/bin/lldpq-config --require-config \
           --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
           --config "$config_file" >/dev/null; then
        echo "[!] The current runtime shell still cannot read the installed LLDPq configuration" >&2
        return 1
    fi
    if ! sudo -u www-data /usr/local/bin/lldpq-config --require-config \
       --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
       --config "$config_file" >/dev/null; then
        echo "[!] Web worker cannot read the installed LLDPq configuration" >&2
        return 1
    fi
    for reader in "$LLDPQ_USER" www-data; do
        if ! sudo -u "$reader" python3 -c '
import os, stat, sys
flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(sys.argv[1], flags)
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(1)
finally:
    os.close(descriptor)
' "$lock_file"; then
            echo "[!] '$reader' cannot open the LLDPq configuration lock read-write" >&2
            return 1
        fi
    done
    if (( current_uid == runtime_uid )) && ! python3 -c '
import os, stat, sys
flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(sys.argv[1], flags)
try:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise SystemExit(1)
finally:
    os.close(descriptor)
' "$lock_file"; then
        echo "[!] The current runtime shell still cannot open the LLDPq configuration lock" >&2
        return 1
    fi
}

# Read legacy KEY=value configuration without executing it as shell code.  The
# file is intentionally writable by the shared web/CLI group, so `source` would
# turn a configuration write into arbitrary code execution during install.
load_lldpq_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value config_lock_fd="" config_snapshot=""

    [[ -f "$config_file" ]] || return 0
    if [[ ! -r "$config_file" ]] || \
       { [[ -e "${config_file}.lock" ]] && \
         { [[ ! -r "${config_file}.lock" ]] || [[ ! -w "${config_file}.lock" ]]; }; }; then
        config_snapshot=$(snapshot_system_lldpq_config "$config_file") || return 1
        config_file="$config_snapshot"
    elif [[ -e "${config_file}.lock" ]] && command -v flock >/dev/null 2>&1; then
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
        raw="${BASH_REMATCH[2]}"

        # Only variables that LLDPq itself writes/consumes are accepted.  This
        # also prevents assignment to shell internals such as PATH or BASH_ENV.
        case "$key" in
            LLDPQ_DIR|LLDPQ_USER|LLDPQ_SRC|LLDPQ_HOSTNAME|LLDPQ_CRON|GETCONF_CRON|WEB_ROOT|\
            ANSIBLE_DIR|EDITOR_ROOT|PROJECT_DIR|DHCP_HOSTS_FILE|DHCP_CONF_FILE|\
            DHCP_LEASES_FILE|ZTP_SCRIPT_FILE|BASE_CONFIG_DIR|AUTO_BASE_CONFIG|\
            AUTO_ZTP_DISABLE|AUTO_SET_HOSTNAME|SKIP_OPTICAL|SKIP_L1|MONITOR_TIMING|\
            MONITOR_MAX_PARALLEL|MONITOR_COMMAND_TIMEOUT_SECONDS|PFC_ECN_MAX_PARALLEL|\
            PFC_ECN_COLLECTION_BUDGET_SECONDS|PFC_ECN_PORT_TIMEOUT_SECONDS|\
            OPTICAL_COLLECTION_BUDGET_SECONDS|OPTICAL_PORT_TIMEOUT_SECONDS|\
            LLDP_MAX_PARALLEL|ASSETS_MAX_PARALLEL|\
            GET_CONFIGS_MAX_PARALLEL|GET_CONFIGS_SSH_TIMEOUT|SEND_CMD_MAX_PARALLEL|TELEMETRY_MAX_PARALLEL|\
            TRANSCEIVER_FW_SKIP_MODELS|TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY|\
            TRANSCEIVER_FW_MAX_PARALLEL|TRANSCEIVER_FW_MIN_INTERVAL|\
            TRANSCEIVER_FW_SSH_TIMEOUT|TELEMETRY_ENABLED|PROMETHEUS_URL|\
            TELEMETRY_COLLECTOR_IP|TELEMETRY_COLLECTOR_PORT|\
            TELEMETRY_COLLECTOR_VRF|DISCOVERY_RANGE|SCAN_INTERVAL|AI_PROVIDER|AI_MODEL|\
            AI_FALLBACK_MODEL|AI_CONTEXT_WINDOW_TOKENS|AI_FALLBACK_CONTEXT_WINDOW_TOKENS|\
            AI_API_KEY|AI_API_URL|OLLAMA_URL|AI_PROXY_URL|AI_SEARCH_MODEL|\
            AI_SEARCH_URL|AI_SEARCH_KEY)
                ;;
            *) continue ;;
        esac

        # Trim outer whitespace and the simple single/double quotes emitted by
        # older installers.  No command, parameter or backslash expansion is
        # performed: values such as $(command) remain literal data.
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
    if [[ -n "$config_lock_fd" ]]; then
        flock -u "$config_lock_fd" || true
        exec {config_lock_fd}>&-
    fi
    [[ -z "$config_snapshot" ]] || rm -f "$config_snapshot"
}

canonical_path() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$path"
    else
        python3 -c 'import os,sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$path"
    fi
}

# Guard paths that later feed recursive ownership/removal operations.  The
# canonical path must be absolute, below a meaningful directory, and must not
# be a system root or the invoking user's home directory itself.
guard_managed_path() {
    local label="$1" path="$2" min_depth="${3:-2}"
    local canonical relative depth

    if [[ -z "$path" || "$path" != /* || "$path" == *$'\n'* || "$path" == *$'\r'* ]]; then
        echo "[!] Refusing unsafe $label path: '$path'" >&2
        return 1
    fi
    canonical=$(canonical_path "$path") || return 1
    case "$canonical" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/www|"$HOME")
            echo "[!] Refusing unsafe $label path: '$canonical'" >&2
            return 1
            ;;
    esac
    relative="${canonical#/}"
    depth=$(awk -F/ '{print NF}' <<< "$relative")
    if (( depth < min_depth )); then
        echo "[!] Refusing shallow $label path: '$canonical'" >&2
        return 1
    fi
    printf '%s\n' "$canonical"
}

# Recursive install/chown targets must not live inside operating-system trees.
# WEB_ROOT is the sole exception for descendants of /var/www.
guard_recursive_target() {
    local label="$1" canonical="$2" allow_var_www="${3:-false}"
    local canonical_home
    canonical_home=$(canonical_path "$HOME") || return 1
    case "$canonical" in
        /home/*|/root/*)
            if [[ "$canonical" != "$canonical_home"/* ]]; then
                echo "[!] Refusing $label under another user's home: '$canonical'" >&2
                return 1
            fi
            ;;
    esac
    if [[ "$allow_var_www" == "true" && "$canonical" == /var/www/* ]]; then
        printf '%s\n' "$canonical"
        return 0
    fi
    case "$canonical" in
        /bin/*|/boot/*|/dev/*|/etc/*|/lib/*|/lib64/*|/proc/*|/run/*|/sbin/*|/sys/*|/usr/*|/var/*)
            echo "[!] Refusing $label inside protected system tree: '$canonical'" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$canonical"
}

paths_overlap() {
    local first="${1%/}" second="${2%/}"
    [[ "$first" == "$second" || "$first" == "$second"/* || "$second" == "$first"/* ]]
}

# Validate the exact source checkout used by this installer and, after the
# update rollback authority is ready, publish a root-owned identity record for
# the uninstaller.  /etc/lldpq.conf is deliberately writable by the runtime and
# web accounts, so it must never be the sole authority for recursively deleting
# LLDPQ_SRC.  The sidecar binds the canonical root directory (and .git when this
# is a directly-owned Git checkout) to stable filesystem identities. Offline
# tarballs and linked worktrees remain valid install sources but receive
# zero-valued Git identities, so recursive source removal stays unavailable.
manage_lldpq_source_manifest() {
    local mode="$1" source_path="$2"
    local -a python_runner=(python3)

    case "$mode" in
        validate) ;;
        install) python_runner=(sudo python3) ;;
        *)
            echo "[!] Invalid LLDPq source-manifest operation: $mode" >&2
            return 1
            ;;
    esac

    "${python_runner[@]}" - "$mode" "$source_path" "$LLDPQ_SOURCE_MANIFEST" <<'PYTHON'
import json
import os
import stat
import sys
import tempfile


mode, source_value, target = sys.argv[1:]


def fail(message):
    raise SystemExit("LLDPq source provenance: " + message)


def required_node(source, relative, expected):
    candidate = os.path.join(source, *relative.split("/"))
    try:
        metadata = os.lstat(candidate)
    except OSError as error:
        fail(f"required source sentinel is unavailable: {relative}: {error}")
    if expected == "directory":
        valid = stat.S_ISDIR(metadata.st_mode)
    else:
        valid = stat.S_ISREG(metadata.st_mode)
    if not valid:
        fail(f"required source sentinel is not a real {expected}: {relative}")


def source_payload(source):
    if not os.path.isabs(source) or "\x00" in source or "\n" in source or "\r" in source:
        fail("source path must be one absolute line")
    canonical = os.path.realpath(os.path.abspath(source))
    if source != canonical:
        fail(f"source path is not canonical: {source!r} -> {canonical!r}")
    try:
        source_metadata = os.lstat(source)
    except OSError as error:
        fail(f"source directory is unavailable: {error}")
    if not stat.S_ISDIR(source_metadata.st_mode):
        fail("source path is not a real directory")
    if source_metadata.st_dev <= 0 or source_metadata.st_ino <= 0:
        fail("source directory has an unusable filesystem identity")

    for relative in ("lldpq", "html", "bin", "etc"):
        required_node(source, relative, "directory")
    for relative in (
        "install.sh",
        "uninstall.sh",
        "README.md",
        "VERSION",
        "lldpq/monitor.sh",
        "html/setup.html",
        "bin/lldpq-config",
    ):
        required_node(source, relative, "file")

    git_path = os.path.join(source, ".git")
    try:
        git_metadata = os.lstat(git_path)
    except FileNotFoundError:
        git_device = 0
        git_inode = 0
    except OSError as error:
        fail(f"cannot inspect .git: {error}")
    else:
        if stat.S_ISDIR(git_metadata.st_mode):
            if git_metadata.st_dev <= 0 or git_metadata.st_ino <= 0:
                fail(".git has an unusable filesystem identity")
            git_device = git_metadata.st_dev
            git_inode = git_metadata.st_ino
        else:
            # Linked worktrees legitimately use a regular .git indirection
            # file. Installation/update must remain compatible with them, but
            # zero Git identity deliberately withholds recursive-delete
            # authority: uninstall consumers reject 0/0 while .git exists and
            # direct the operator to remove that checkout manually.
            git_device = 0
            git_inode = 0

    # Re-read the root after walking the sentinels so a replaced checkout is not
    # accidentally recorded under the identity inspected at function entry.
    current = os.lstat(source)
    if (current.st_dev, current.st_ino, current.st_uid) != (
        source_metadata.st_dev,
        source_metadata.st_ino,
        source_metadata.st_uid,
    ):
        fail("source directory changed during validation")
    if git_device:
        current_git = os.lstat(git_path)
        if (not stat.S_ISDIR(current_git.st_mode)
                or (current_git.st_dev, current_git.st_ino) != (git_device, git_inode)):
            fail(".git changed during validation")

    return {
        "version": 1,
        "path": canonical,
        "device": source_metadata.st_dev,
        "inode": source_metadata.st_ino,
        "uid": source_metadata.st_uid,
        "git_device": git_device,
        "git_inode": git_inode,
    }


payload = source_payload(source_value)
if mode == "validate":
    raise SystemExit(0)
if mode != "install" or target != "/etc/lldpq-source.json":
    fail("refusing an unsupported manifest destination")

parent = os.path.dirname(target)
parent_metadata = os.lstat(parent)
if (not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or parent_metadata.st_gid != 0
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022):
    fail("manifest parent directory failed its ownership/type/mode check")
encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
if len(encoded) > 4096:
    fail("manifest content exceeds the 4096-byte limit")
descriptor = -1
temporary = None
try:
    descriptor, temporary = tempfile.mkstemp(prefix=".lldpq-source.", dir=parent)
    os.fchmod(descriptor, 0o600)
    os.fchown(descriptor, 0, 0)
    with os.fdopen(descriptor, "wb", closefd=True) as output:
        descriptor = -1
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())

    # Do not publish a record for a checkout replaced while the staged JSON was
    # being written. os.replace keeps readers on either the old or new record.
    if source_payload(source_value) != payload:
        fail("source identity changed before manifest publication")
    os.replace(temporary, target)
    temporary = None
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    if temporary is not None:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
manifest_fd = os.open(target, flags)
try:
    metadata = os.fstat(manifest_fd)
    if (not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 4096):
        fail("installed manifest failed its ownership/type/mode check")
    raw = os.read(manifest_fd, 4097)
finally:
    os.close(manifest_fd)
try:
    installed = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"installed manifest is not valid JSON: {error}")
if installed != payload:
    fail("installed manifest content does not match the validated source")
PYTHON
}

assert_lldpq_install_tree() {
    local path="$1"
    [[ -d "$path" ]] || return 0
    if [[ ! -f "$path/devices.yaml" || ! -f "$path/monitor.sh" ]]; then
        echo "[!] Refusing recursive replacement of unrecognized directory: '$path'" >&2
        return 1
    fi
}

validate_cron_schedule() {
    local schedule="$1"
    local validator="${LLDPQ_CRON_VALIDATOR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bin/lldpq-config}"
    [[ -x "$validator" ]] || {
        echo "[!] Cron validator is missing or not executable: $validator" >&2
        return 1
    }
    "$validator" --validate-cron "$schedule"
}

shell_single_quote() {
    local value="$1"
    printf "'%s'" "${value//\'/\'\\\'\'}"
}

# Remove only commands installed by historical LLDPq releases.  Generic words
# such as "monitor" are deliberately not matched.
filter_legacy_lldpq_crontab() {
    local input_file="$1" output_file="$2" install_dir="$3"
    awk -v install_dir="$install_dir" '
        function owned(line) {
            return line ~ /\/usr\/local\/bin\/lldpq([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-trigger([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-provision-scheduler([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-ai-analyze([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/get-conf([[:space:]]|$)/ ||
                   index(line, install_dir "/fabric-scan.sh") > 0 ||
                   (index(line, "cd " install_dir) > 0 && index(line, "./fabric-scan.sh") > 0) ||
                   index(line, install_dir "/fabric-scan-cron.sh") > 0 ||
                   (index(line, install_dir) > 0 && index(line, "topology.dot.bkp") > 0)
        }
        !owned($0) { print }
    ' "$input_file" > "$output_file"
}

render_lldpq_cron_file() {
    local output_file="$1" user="$2" install_dir="$3" web_root="$4"
    local lldpq_schedule="$5" getconf_schedule="$6" include_fabric_cron="$7"
    local q_install q_web

    [[ "$user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]] || {
        echo "[!] Invalid LLDPq cron user: '$user'" >&2
        return 1
    }
    validate_cron_schedule "$lldpq_schedule" || {
        echo "[!] Invalid LLDPQ_CRON schedule: '$lldpq_schedule'" >&2
        return 1
    }
    validate_cron_schedule "$getconf_schedule" || {
        echo "[!] Invalid GETCONF_CRON schedule: '$getconf_schedule'" >&2
        return 1
    }
    q_install=$(shell_single_quote "$install_dir")
    q_web=$(shell_single_quote "$web_root")

    {
        echo "# Managed by LLDPq. Local changes may be replaced by install.sh."
        echo "SHELL=/bin/sh"
        echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        echo "$lldpq_schedule $user /usr/local/bin/lldpq"
        echo "$getconf_schedule $user /usr/local/bin/get-conf"
        echo "* * * * * $user /usr/local/bin/lldpq-trigger"
        echo "* * * * * www-data /usr/local/bin/lldpq-provision-scheduler"
        # Give a full collector scheduled on the same minute enough time to
        # acquire the shared pipeline lock before this best-effort cache scan.
        echo "* * * * * $user /bin/sleep 30 && cd $q_install && ./fabric-scan.sh >/dev/null 2>&1"
        echo "0 0 * * * $user cd $q_install && cp $q_web/topology.dot topology.dot.bkp 2>/dev/null; cp $q_web/topology_config.yaml topology_config.yaml.bkp 2>/dev/null; git add -A; git diff --cached --quiet || git commit -m \"auto: \$(date +\\%Y-\\%m-\\%d)\""
        if [[ "$include_fabric_cron" == "true" ]]; then
            echo "33 3 * * * $user $q_install/fabric-scan-cron.sh"
        fi
    } > "$output_file"
}

validate_lldpq_cron_file() {
    local cron_file="$1" line minute hour dom month dow user command job_count=0
    [[ -s "$cron_file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* || "$line" == SHELL=* || "$line" == PATH=* ]] && continue
        read -r minute hour dom month dow user command <<< "$line"
        [[ -n "$command" ]] || return 1
        validate_cron_schedule "$minute $hour $dom $month $dow" || return 1
        [[ "$user" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]] || return 1
        job_count=$((job_count + 1))
    done < "$cron_file"
    (( job_count >= 6 ))
}

rollback_cron_target() {
    local target="$1" had_previous="$2" backup="$3"
    if [[ "$had_previous" == "true" ]]; then
        root_run cp "$backup" "$target"
        root_run chmod 644 "$target"
    else
        root_run rm -f "$target"
    fi
}

# Install the already-rendered/validated cron.d file first.  Only after that
# succeeds are legacy /etc/crontab entries migrated.  Any migration failure
# restores the previous cron.d state, preventing a half-applied schedule.
install_lldpq_cron_transaction() {
    local rendered="$1" system_crontab="$2" cron_target="$3" install_dir="$4"
    local target_stage crontab_stage filtered backup had_previous=false

    validate_lldpq_cron_file "$rendered" || {
        echo "[!] Refusing invalid LLDPq cron file" >&2
        return 1
    }
    backup=$(mktemp "${TMPDIR:-/tmp}/lldpq-cron-backup.XXXXXX")
    if [[ -e "$cron_target" ]]; then
        root_run cp "$cron_target" "$backup" || { rm -f "$backup"; return 1; }
        had_previous=true
    fi
    target_stage=$(root_run mktemp "$(dirname "$cron_target")/.lldpq-cron.XXXXXXXXXX") || {
        rm -f "$backup"; return 1;
    }
    if ! root_run cp "$rendered" "$target_stage" || \
       ! root_run chmod 644 "$target_stage" || \
       ! root_run mv -fT "$target_stage" "$cron_target"; then
        root_run rm -f "$target_stage" 2>/dev/null || true
        rm -f "$backup"
        return 1
    fi

    if [[ -f "$system_crontab" ]]; then
        filtered=$(mktemp "${TMPDIR:-/tmp}/lldpq-crontab-filtered.XXXXXX")
        if ! filter_legacy_lldpq_crontab "$system_crontab" "$filtered" "$install_dir"; then
            rollback_cron_target "$cron_target" "$had_previous" "$backup" || true
            rm -f "$filtered" "$backup"
            return 1
        fi
        if ! cmp -s "$system_crontab" "$filtered"; then
            crontab_stage=$(root_run mktemp "$(dirname "$system_crontab")/.lldpq-crontab.XXXXXXXXXX") || {
                rollback_cron_target "$cron_target" "$had_previous" "$backup" || true
                rm -f "$filtered" "$backup"
                return 1
            }
            if ! root_run cp "$filtered" "$crontab_stage" || \
               ! root_run chmod 644 "$crontab_stage" || \
               ! root_run mv -fT "$crontab_stage" "$system_crontab"; then
                root_run rm -f "$crontab_stage" 2>/dev/null || true
                rollback_cron_target "$cron_target" "$had_previous" "$backup" || true
                rm -f "$filtered" "$backup"
                return 1
            fi
        fi
        rm -f "$filtered"
    fi
    rm -f "$backup"
}

root_run() {
    if [[ "${LLDPQ_TEST_NO_SUDO:-false}" == "true" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

render_ai_config() {
    local provider="$1" model="$2" api_key="$3" api_url="$4" ollama_url="$5"
    local proxy_url="$6" search_model="$7" search_url="$8" search_key="$9"
    local fallback_model="${10}"
    local context_window="${11}" fallback_context_window="${12}"
    printf 'AI_PROVIDER=%s\n' "$provider"
    printf 'AI_MODEL=%s\n' "$model"
    printf 'AI_FALLBACK_MODEL=%s\n' "$fallback_model"
    printf 'AI_CONTEXT_WINDOW_TOKENS=%s\n' "$context_window"
    printf 'AI_FALLBACK_CONTEXT_WINDOW_TOKENS=%s\n' "$fallback_context_window"
    printf 'AI_API_KEY=%s\n' "$api_key"
    printf 'AI_API_URL=%s\n' "$api_url"
    printf 'OLLAMA_URL=%s\n' "$ollama_url"
    printf 'AI_PROXY_URL=%s\n' "$proxy_url"
    printf 'AI_SEARCH_MODEL=%s\n' "$search_model"
    printf 'AI_SEARCH_URL=%s\n' "$search_url"
    printf 'AI_SEARCH_KEY=%s\n' "$search_key"
}

render_runtime_tuning_config() {
    local lldpq_cron="$1" getconf_cron="$2" skip_optical="$3" skip_l1="$4"
    local monitor_parallel="$5" lldp_parallel="$6" assets_parallel="$7"
    local getconfigs_parallel="$8" send_parallel="$9" telemetry_parallel="${10}"
    local scan_interval="${11:-300}" getconfigs_ssh_timeout="${12:-60}"
    local pfc_parallel="${13:-4}" pfc_budget="${14:-60}"
    local pfc_port_timeout="${15:-5}" optical_budget="${16:-120}"
    local optical_port_timeout="${17:-10}" monitor_timing="${18:-false}"
    local monitor_command_timeout="${19:-20}"
    case "$scan_interval" in
        ''|*[!0-9]*) scan_interval=300 ;;
    esac
    case "$getconfigs_ssh_timeout" in
        ''|*[!0-9]*|0) getconfigs_ssh_timeout=60 ;;
    esac
    case "$monitor_command_timeout" in
        ''|*[!0-9]*|????*) monitor_command_timeout=20 ;;
        *)
            monitor_command_timeout=$((10#$monitor_command_timeout))
            if (( monitor_command_timeout == 0 )); then
                monitor_command_timeout=20
            elif (( monitor_command_timeout > 120 )); then
                monitor_command_timeout=120
            fi
            ;;
    esac
    printf 'LLDPQ_CRON="%s"\n' "$lldpq_cron"
    printf 'GETCONF_CRON="%s"\n' "$getconf_cron"
    printf 'SKIP_OPTICAL=%s\n' "$skip_optical"
    printf 'SKIP_L1=%s\n' "$skip_l1"
    printf 'MONITOR_MAX_PARALLEL=%s\n' "$monitor_parallel"
    printf 'MONITOR_COMMAND_TIMEOUT_SECONDS=%s\n' "$monitor_command_timeout"
    printf 'PFC_ECN_MAX_PARALLEL=%s\n' "$pfc_parallel"
    printf 'PFC_ECN_COLLECTION_BUDGET_SECONDS=%s\n' "$pfc_budget"
    printf 'PFC_ECN_PORT_TIMEOUT_SECONDS=%s\n' "$pfc_port_timeout"
    printf 'OPTICAL_COLLECTION_BUDGET_SECONDS=%s\n' "$optical_budget"
    printf 'OPTICAL_PORT_TIMEOUT_SECONDS=%s\n' "$optical_port_timeout"
    printf 'MONITOR_TIMING=%s\n' "$monitor_timing"
    printf 'LLDP_MAX_PARALLEL=%s\n' "$lldp_parallel"
    printf 'ASSETS_MAX_PARALLEL=%s\n' "$assets_parallel"
    printf 'GET_CONFIGS_MAX_PARALLEL=%s\n' "$getconfigs_parallel"
    printf 'GET_CONFIGS_SSH_TIMEOUT=%s\n' "$getconfigs_ssh_timeout"
    printf 'SEND_CMD_MAX_PARALLEL=%s\n' "$send_parallel"
    printf 'TELEMETRY_MAX_PARALLEL=%s\n' "$telemetry_parallel"
    printf 'SCAN_INTERVAL=%s\n' "$scan_interval"
}

render_preserved_provisioning_config() {
    local auto_base="$1" auto_ztp="$2" auto_hostname="$3"
    local skip_models="$4" unknown_policy="$5" max_parallel="$6"
    local min_interval="$7" ssh_timeout="$8"
    printf 'AUTO_BASE_CONFIG=%s\n' "$auto_base"
    printf 'AUTO_ZTP_DISABLE=%s\n' "$auto_ztp"
    printf 'AUTO_SET_HOSTNAME=%s\n' "$auto_hostname"
    printf 'TRANSCEIVER_FW_SKIP_MODELS=%s\n' "$skip_models"
    printf 'TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=%s\n' "$unknown_policy"
    printf 'TRANSCEIVER_FW_MAX_PARALLEL=%s\n' "$max_parallel"
    printf 'TRANSCEIVER_FW_MIN_INTERVAL=%s\n' "$min_interval"
    printf 'TRANSCEIVER_FW_SSH_TIMEOUT=%s\n' "$ssh_timeout"
}

render_default_dhcp_config() {
    local output_file="$1" server_ip="$2" hosts_file="$3"
    local subnet gateway
    subnet=$(sed 's/\.[0-9]*$/.0/' <<< "$server_ip")
    gateway=$(sed 's/\.[0-9]*$/.1/' <<< "$server_ip")

    cat > "$output_file" <<DHCPEOF
# /etc/dhcp/dhcpd.conf - Generated by LLDPq

ddns-update-style none;
authoritative;
log-facility local7;

option www-server code 72 = ip-address;
option default-url code 114 = text;
option cumulus-provision-url code 239 = text;
option space onie code width 1 length width 1;
option onie.installer_url code 1 = text;
option onie.updater_url   code 2 = text;
option onie.machine       code 3 = text;
option onie.arch          code 4 = text;
option onie.machine_rev   code 5 = text;

option space vivso code width 4 length width 1;
option vivso.onie code 42623 = encapsulate onie;
option vivso.iana code 0 = string;
option op125 code 125 = encapsulate vivso;

class "onie-vendor-classes" {
  match if substring(option vendor-class-identifier, 0, 11) = "onie_vendor";
  option vivso.iana 01:01:01;
}

# OOB Management subnet
shared-network OOB {
  subnet ${subnet} netmask 255.255.255.0 {
    range ${subnet%.*}.210 ${subnet%.*}.249;
    option routers ${gateway};
    option domain-name "example.com";
    option domain-name-servers ${gateway};
    option www-server ${server_ip};
    option default-url "http://${server_ip}/";
    option cumulus-provision-url "http://${server_ip}/cumulus-ztp.sh";
    default-lease-time 172800;
    max-lease-time     345600;
  }
}

include "${hosts_file}";
DHCPEOF
}

# Return codes: 0 = created/replaced, 10 = existing LLDPq config kept,
# 11 = existing foreign config preserved because no explicit opt-in was given.
is_lldpq_managed_dhcp_config() {
    local conf_file="$1"
    [[ -f "$conf_file" ]] && \
        grep -Eq '^# /etc/dhcp/dhcpd\.conf - Generated by LLDPq( Provision)?$' "$conf_file"
}

is_packaged_dhcp_sample() {
    local conf_file="$1"
    [[ ! -s "$conf_file" ]] && return 0
    # Debian/Ubuntu's packaged sample has example.org defaults but no active
    # network declaration. It is safe to replace; an operator configuration is
    # not inferred merely from an LLDPq-related option name.
    grep -Eq '^[[:space:]]*option[[:space:]]+domain-name[[:space:]]+"example\.org";' "$conf_file" || return 1
    ! grep -Eq '^[[:space:]]*(subnet|shared-network|host|include)[[:space:]]' "$conf_file"
}

prepare_default_dhcp_config() {
    local conf_file="$1" hosts_file="$2" replace_foreign="$3"
    local owner="${4:-}" group="${5:-}" server_ip="$6"
    local temp_file validation_hosts="" backup_file staged_file validator

    validator="${DHCPD_VALIDATOR:-dhcpd}"

    if is_lldpq_managed_dhcp_config "$conf_file"; then
        if [[ ! -e "$hosts_file" ]]; then
            root_run mkdir -p "$(dirname "$hosts_file")" || return 12
            root_run touch "$hosts_file" || return 12
            root_run chmod 664 "$hosts_file" || return 12
            if [[ -n "$owner" && -n "$group" ]]; then
                root_run chown "$owner:$group" "$hosts_file" || return 12
            fi
        fi
        if ! command -v "$validator" >/dev/null 2>&1; then
            echo "  [!] dhcpd validator not found; existing LLDPq config was not accepted" >&2
            return 12
        fi
        if ! "$validator" -t -cf "$conf_file" >/dev/null 2>&1; then
            echo "  [!] Existing LLDPq DHCP config is invalid; leaving it unchanged" >&2
            return 12
        fi
        echo "  DHCP config already managed by LLDPq, keeping"
        return 10
    fi
    if [[ -e "$conf_file" ]] && ! is_packaged_dhcp_sample "$conf_file" && \
       [[ "$replace_foreign" != "true" ]]; then
        echo "  [!] Existing non-LLDPq DHCP config preserved: $conf_file"
        echo "      Re-run with --replace-dhcp-config to validate, back up and replace it."
        return 11
    fi

    temp_file=$(mktemp "${TMPDIR:-/tmp}/lldpq-dhcp.XXXXXX")
    validation_hosts="$hosts_file"
    if [[ ! -e "$hosts_file" ]]; then
        validation_hosts=$(mktemp "${TMPDIR:-/tmp}/lldpq-dhcp-hosts.XXXXXX")
    fi
    render_default_dhcp_config "$temp_file" "$server_ip" "$validation_hosts"

    if command -v "$validator" >/dev/null 2>&1; then
        if ! "$validator" -t -cf "$temp_file" >/dev/null 2>&1; then
            echo "  [!] Generated DHCP config failed validation; existing config was not changed" >&2
            rm -f "$temp_file"
            [[ "$validation_hosts" != "$hosts_file" ]] && rm -f "$validation_hosts"
            return 1
        fi
    else
        echo "  [!] dhcpd validator not found; refusing to activate an unvalidated config" >&2
        rm -f "$temp_file"
        [[ "$validation_hosts" != "$hosts_file" ]] && rm -f "$validation_hosts"
        return 1
    fi

    # The validation-only include may live in /tmp.  Render the exact final
    # include path only after syntax validation succeeds.
    render_default_dhcp_config "$temp_file" "$server_ip" "$hosts_file"
    [[ "$validation_hosts" != "$hosts_file" ]] && rm -f "$validation_hosts"

    if ! root_run mkdir -p "$(dirname "$conf_file")" "$(dirname "$hosts_file")"; then
        rm -f "$temp_file"
        return 1
    fi
    if [[ ! -e "$hosts_file" ]]; then
        if ! root_run touch "$hosts_file"; then
            rm -f "$temp_file"
            return 1
        fi
    fi
    if ! root_run chmod 664 "$hosts_file"; then
        rm -f "$temp_file"
        return 1
    fi
    if [[ -n "$owner" && -n "$group" ]]; then
        root_run chown "$owner:$group" "$hosts_file" || {
            rm -f "$temp_file"
            return 1
        }
    fi

    if [[ -e "$conf_file" ]]; then
        backup_file="${conf_file}.pre-lldpq-$(date +%Y%m%d-%H%M%S)-$$.bak"
        if ! root_run cp -p "$conf_file" "$backup_file"; then
            echo "  [!] Could not back up existing DHCP config; replacement aborted" >&2
            rm -f "$temp_file"
            return 1
        fi
        echo "  Existing DHCP config backed up to: $backup_file"
    fi

    # Stage beside the target and rename only after permissions are ready, so a
    # failed copy/chown cannot leave a truncated active configuration.
    staged_file="${conf_file}.lldpq-new.$$"
    if ! root_run cp "$temp_file" "$staged_file" || \
       ! root_run chmod 664 "$staged_file"; then
        root_run rm -f "$staged_file" 2>/dev/null || true
        rm -f "$temp_file"
        return 1
    fi
    if [[ -n "$owner" && -n "$group" ]]; then
        if ! root_run chown "$owner:$group" "$staged_file"; then
            root_run rm -f "$staged_file" 2>/dev/null || true
            rm -f "$temp_file"
            return 1
        fi
    fi
    if ! root_run mv -f "$staged_file" "$conf_file"; then
        root_run rm -f "$staged_file" 2>/dev/null || true
        rm -f "$temp_file"
        return 1
    fi
    rm -f "$temp_file"
    return 0
}

# Update rollback is intentionally automatic and lightweight. Runtime result
# trees are already preserved separately; this snapshot protects the previous
# executable tree and the system files most likely to make an update unusable
# if a later DHCP, service or cron step fails.
UPDATE_ROLLBACK_DIR=""
UPDATE_ROLLBACK_ACTIVE=false
UPDATE_ROLLBACK_HAD_INSTALL=false
UPDATE_ROLLBACK_CORE_RESTORED=false
UPDATE_ROLLBACK_RESTORED_VERSION=""
UPDATE_CONFIG_LOCK_FD=""
UPDATE_PROCESS_LOCK_FD=""
UPDATE_PROVISION_LOCK_FDS=()
_UPDATE_WEB_QUIESCED=false
_UPDATE_FINALIZE_IN_PROGRESS=false
UPDATE_RECOVERY_STATE_DIR="/var/lib/lldpq/update-rollback"
UPDATE_RECOVERY_MARKER="$UPDATE_RECOVERY_STATE_DIR/active.json"
UPDATE_RECOVERY_HELPER="/usr/local/libexec/lldpq-update-recovery.py"
UPDATE_RECOVERY_SERVICE="/etc/systemd/system/lldpq-update-recovery.service"

write_update_recovery_marker() {
    local phase="$1" rollback_dir="${2:-}"
    [[ -n "${_DATA_PRESERVE:-}" ]] || return 1
    sudo python3 - "$UPDATE_RECOVERY_STATE_DIR" "$UPDATE_RECOVERY_MARKER" \
        "$phase" "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" "$_DATA_PRESERVE" \
        "$rollback_dir" <<'PYTHON'
import json
import os
import sys
import tempfile

state_dir, marker, phase, install_dir, web_root, preserve_dir, rollback_dir = sys.argv[1:]
if phase not in {"preserving", "rollback_ready"}:
    raise SystemExit("invalid update recovery phase")
for label, value in (
    ("install_dir", install_dir),
    ("web_root", web_root),
    ("preserve_dir", preserve_dir),
):
    if not os.path.isabs(value) or "\n" in value or "\r" in value:
        raise SystemExit(f"unsafe {label}")
if rollback_dir and (not os.path.isabs(rollback_dir) or "\n" in rollback_dir or "\r" in rollback_dir):
    raise SystemExit("unsafe rollback_dir")

os.makedirs(state_dir, mode=0o700, exist_ok=True)
os.chown(state_dir, 0, 0)
os.chmod(state_dir, 0o700)
payload = {
    "version": 1,
    "phase": phase,
    "install_dir": install_dir,
    "web_root": web_root,
    "preserve_dir": preserve_dir,
    "rollback_dir": rollback_dir or None,
}
descriptor, temporary = tempfile.mkstemp(prefix=".active.", dir=state_dir)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, marker)
    directory_fd = os.open(state_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    try:
        os.close(descriptor)
    except OSError:
        pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYTHON
}

clear_update_recovery_marker() {
    root_run rm -f "$UPDATE_RECOVERY_MARKER" || return 1
    return 0
}

acquire_update_config_lock() {
    local lock_file="/etc/lldpq.conf.lock"
    local wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"
    local invoker_uid runtime_uid
    [[ -z "$UPDATE_CONFIG_LOCK_FD" ]] || return 0
    command -v flock >/dev/null 2>&1 || return 1
    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    invoker_uid=$(id -u) || return 1
    runtime_uid=$(id -u "$LLDPQ_USER") || return 1
    # On a first upgrade the invoking shell may not yet see its newly-added
    # www-data supplementary group. Keep the canonical root:www-data metadata
    # intact and grant only this invoking UID temporary access to the stable
    # inode. This avoids a crash window with an unrelated group owner.
    if ! prepare_shared_lock_files "$lock_file"; then
        return 1
    fi
    if (( invoker_uid != 0 )) && \
       ! sudo setfacl -m "u:${invoker_uid}:rw" "$lock_file"; then
        return 1
    fi
    if ! exec {UPDATE_CONFIG_LOCK_FD}<>"$lock_file"; then
        (( invoker_uid == 0 )) || sudo setfacl -x "u:${invoker_uid}" "$lock_file" 2>/dev/null || true
        UPDATE_CONFIG_LOCK_FD=""
        return 1
    fi
    # Apply the durable runtime ACL before retiring a different admin's
    # temporary entry, so every ordinary failure/rollback path remains usable.
    if (( runtime_uid != 0 )) && \
       ! sudo setfacl -m "u:${runtime_uid}:rw" "$lock_file"; then
        exec {UPDATE_CONFIG_LOCK_FD}>&-
        UPDATE_CONFIG_LOCK_FD=""
        (( invoker_uid == 0 )) || sudo setfacl -x "u:${invoker_uid}" "$lock_file" 2>/dev/null || true
        return 1
    fi
    if (( invoker_uid != 0 && invoker_uid != runtime_uid )) && \
       ! sudo setfacl -x "u:${invoker_uid}" "$lock_file"; then
        exec {UPDATE_CONFIG_LOCK_FD}>&-
        UPDATE_CONFIG_LOCK_FD=""
        return 1
    fi
    if ! flock -w "$wait_seconds" "$UPDATE_CONFIG_LOCK_FD"; then
        echo "[!] Timed out waiting for an active Setup save/restore; update was not started" >&2
        exec {UPDATE_CONFIG_LOCK_FD}>&-
        UPDATE_CONFIG_LOCK_FD=""
        return 1
    fi
    echo "  Setup configuration lock acquired"
}

release_update_config_lock() {
    [[ -n "$UPDATE_CONFIG_LOCK_FD" ]] || return 0
    flock -u "$UPDATE_CONFIG_LOCK_FD" 2>/dev/null || true
    exec {UPDATE_CONFIG_LOCK_FD}>&-
    UPDATE_CONFIG_LOCK_FD=""
}

acquire_update_process_lock() {
    local lock_file="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    local wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"

    [[ -z "$UPDATE_PROCESS_LOCK_FD" ]] || return 0
    command -v flock >/dev/null 2>&1 || {
        echo "[!] flock is required to quiesce LLDPq during an update" >&2
        return 1
    }
    case "$wait_seconds" in
        ''|*[!0-9]*|0)
            echo "[!] Invalid LLDPQ_UPDATE_LOCK_TIMEOUT: '$wait_seconds'" >&2
            return 1
            ;;
    esac

    exec {UPDATE_PROCESS_LOCK_FD}>"$lock_file" || return 1
    if ! flock -w "$wait_seconds" "$UPDATE_PROCESS_LOCK_FD"; then
        echo "[!] Timed out waiting for the active LLDPq collection to finish; update was not started" >&2
        exec {UPDATE_PROCESS_LOCK_FD}>&-
        UPDATE_PROCESS_LOCK_FD=""
        return 1
    fi
    echo "  LLDPq collection lock acquired; cron/web refreshes will stay out of the update"
}

release_update_process_lock() {
    [[ -n "$UPDATE_PROCESS_LOCK_FD" ]] || return 0
    flock -u "$UPDATE_PROCESS_LOCK_FD" 2>/dev/null || true
    exec {UPDATE_PROCESS_LOCK_FD}>&-
    UPDATE_PROCESS_LOCK_FD=""
}

release_update_provision_locks() {
    local index fd
    for ((index=${#UPDATE_PROVISION_LOCK_FDS[@]}-1; index>=0; index--)); do
        fd="${UPDATE_PROVISION_LOCK_FDS[index]}"
        flock -u "$fd" 2>/dev/null || true
        exec {fd}>&-
    done
    UPDATE_PROVISION_LOCK_FDS=()
}

reconcile_stale_legacy_upgrade_jobs() {
    local upgrade_dir="$1"
    local stale_seconds="${LLDPQ_LEGACY_UPGRADE_STALE_SECONDS:-86400}"
    local devices_file="${LLDPQ_RECONCILE_DEVICES_FILE:-${LLDPQ_INSTALL_DIR:-${LLDPQ_DIR:-}}/devices.yaml}"
    local inventory_file="${LLDPQ_RECONCILE_INVENTORY_FILE:-${WEB_ROOT:-/var/www/html}/inventory.json}"
    local service_user="${LLDPQ_USER:-$(id -un)}"
    local allow_current_incomplete="${LLDPQ_RECONCILE_ALLOW_CURRENT_INCOMPLETE:-false}"
    case "$stale_seconds" in
        ''|*[!0-9]*)
            echo "[!] Invalid LLDPQ_LEGACY_UPGRADE_STALE_SECONDS: '$stale_seconds'" >&2
            return 1
            ;;
    esac
    if ((stale_seconds < 3600 || stale_seconds > 2592000)); then
        echo "[!] LLDPQ_LEGACY_UPGRADE_STALE_SECONDS must be between 3600 and 2592000" >&2
        return 1
    fi
    case "$allow_current_incomplete" in
        true|false) ;;
        *)
            echo "[!] Invalid LLDPQ_RECONCILE_ALLOW_CURRENT_INCOMPLETE: '$allow_current_incomplete'" >&2
            return 1
            ;;
    esac

    root_run python3 - "$upgrade_dir" "$stale_seconds" "$service_user" \
        "$devices_file" "$inventory_file" "$allow_current_incomplete" <<'PYTHON'
import concurrent.futures
import datetime
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

directory = os.path.abspath(sys.argv[1])
stale_seconds = int(sys.argv[2])
service_user = sys.argv[3]
devices_file = os.path.abspath(sys.argv[4])
inventory_file = os.path.abspath(sys.argv[5])
allow_current_incomplete = sys.argv[6] == 'true'
now = int(time.time())
supported_schema_version = 2
uuid_json = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.json$')

# This is the exact pre-v4 persisted job contract. New/current jobs carry one
# or more immutable-launch/initialization fields below and are never rewritten
# by the installer, regardless of age.
legacy_required = {
    'id', 'created_at', 'target_version', 'image_name', 'server_ip',
    'batch_size', 'stop_on_failure', 'base_config_after', 'timeout_seconds',
    'complete', 'cancelled', 'devices',
}
# The first persisted pre-v4 writer did not emit worker_started_at. The later
# pre-v4 worker added it without changing the rest of the contract; both exact
# historical variants are intentionally recognized.
legacy_optional = {
    'worker_started_at', 'worker_heartbeat', 'worker_error', 'completed_at',
}
current_schema_fields = {
    'schema_version', 'image_size', 'image_sha256', 'ready', 'aliases_published',
    'onie_alias_snapshot', 'ztp_artifact', 'ztp_size', 'ztp_sha256',
}
current_device_fields = {
    'operation_id', 'claimed_at', 'remote_prepared_at',
    'launch_attempted_at', 'launch_uncertain',
}
legacy_device_statuses = {
    'queued', 'upgrading', 'waiting_reboot',
    'done', 'failed', 'cancelled', 'blocked',
}
terminal_statuses = {'done', 'failed', 'cancelled', 'blocked'}
current_required = legacy_required | {
    'image_size', 'image_sha256', 'ready', 'aliases_published',
    'onie_alias_snapshot', 'worker_started_at', 'worker_heartbeat',
    'ztp_artifact', 'ztp_size', 'ztp_sha256',
}
current_statuses = legacy_device_statuses | {'starting'}


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def numeric_timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('timestamp is not numeric')
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > now + 300:
        raise ValueError('timestamp is invalid')
    return result


def positive_integer(value, label, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or \
            (maximum is not None and value > maximum):
        raise ValueError(f'invalid {label}')


def validate_resumable_current(filename, job, metadata):
    """Recognize only the exact resumable contract from the previous release."""
    missing = sorted(current_required.difference(job))
    if missing:
        raise ValueError('current upgrade state is missing: ' + ', '.join(missing))
    if job.get('id') != filename[:-5] or job.get('complete') is not False:
        raise ValueError('invalid current upgrade identity/completion state')
    positive_integer(job['created_at'], 'created_at')
    positive_integer(job['worker_started_at'], 'worker_started_at')
    positive_integer(job['worker_heartbeat'], 'worker_heartbeat')
    positive_integer(job['image_size'], 'image_size')
    positive_integer(job['ztp_size'], 'ztp_size')
    positive_integer(job['batch_size'], 'batch_size', 100)
    positive_integer(job['timeout_seconds'], 'timeout_seconds', 7 * 86400)
    for value in (
            job['created_at'], job['worker_started_at'], job['worker_heartbeat'],
            metadata.st_mtime):
        numeric_timestamp(value)
    for key in (
            'stop_on_failure', 'base_config_after', 'cancelled', 'ready',
            'aliases_published'):
        if not isinstance(job.get(key), bool):
            raise ValueError(f'invalid {key}')
    if job['ready'] != job['aliases_published']:
        raise ValueError('inconsistent current readiness/alias state')
    if not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,99}', str(job['target_version'])) or \
            not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:bin|img|iso)', str(job['image_name'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['image_sha256'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['ztp_sha256'])) or \
            not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]{1,5})?', str(job['server_ip'])):
        raise ValueError('invalid current image/server metadata')
    expected_ztp = (
        f"provision-uploads/ztp-artifacts/{job['id']}.ztp"
    )
    if job['ztp_artifact'] != expected_ztp:
        raise ValueError('invalid current ZTP artifact reference')
    snapshot = job['onie_alias_snapshot']
    expected_snapshot = {
        f'{scope}:{name}'
        for scope in ('uploads', 'web')
        for name in ('onie-installer-x86_64',
                     'onie-installer-x86_64-mlnx', 'onie-installer')
    }
    if not isinstance(snapshot, dict) or set(snapshot) != expected_snapshot or any(
            value is not None and (
                not isinstance(value, str) or
                not re.fullmatch(r'(?:provision-uploads/)?[A-Za-z0-9_.-]+', value)
            ) for value in snapshot.values()):
        raise ValueError('invalid current ONIE alias snapshot')
    if not isinstance(job['devices'], list) or not job['devices']:
        raise ValueError('current upgrade has no devices')
    seen_ips = set()
    for device in job['devices']:
        if not isinstance(device, dict) or device.get('status') not in current_statuses:
            raise ValueError('invalid current device state')
        try:
            ip = str(ipaddress.IPv4Address(str(device.get('ip', ''))))
        except ipaddress.AddressValueError as exc:
            raise ValueError('invalid current device IP') from exc
        if ip in seen_ips:
            raise ValueError('duplicate current device IP')
        seen_ips.add(ip)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',
                            str(device.get('hostname', ''))) or \
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',
                                 str(device.get('username', ''))) or \
                device.get('target_version') != job['target_version']:
            raise ValueError('invalid current device identity')
        raw_mac = str(device.get('expected_mac', '')).strip().lower()
        mac = raw_mac if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', raw_mac) else ''
        serial = str(device.get('expected_serial', '')).strip()
        if serial.lower() in ('na', 'n/a', 'not specified', 'none'):
            serial = ''
        if (raw_mac and not mac) or (not mac and not serial):
            raise ValueError('current device identity evidence is invalid')
        for key in ('claimed_at', 'remote_prepared_at',
                    'launch_attempted_at', 'started_at', 'last_check'):
            if device.get(key) is not None:
                positive_integer(device[key], key)
                numeric_timestamp(device[key])
        if device['status'] in ('starting', 'upgrading', 'waiting_reboot') and (
                not re.fullmatch(
                    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
                                 str(device.get('operation_id', ''))) or
                device.get('claimed_at') is None):
            raise ValueError('invalid current active-device claim')
        if device['status'] in ('upgrading', 'waiting_reboot') and (
                device.get('remote_prepared_at') is None or
                device.get('launch_attempted_at') is None or
                device.get('started_at') is None):
            raise ValueError('invalid current launched-device evidence')


def read_stable_regular(path):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('job is not a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('job changed while opening')
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_fd = os.fstat(descriptor)
        after_path = os.lstat(path)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != (
                after_fd.st_dev, after_fd.st_ino,
                after_fd.st_size, after_fd.st_mtime_ns,
        ) or identity != (
                after_path.st_dev, after_path.st_ino,
                after_path.st_size, after_path.st_mtime_ns,
        ):
            raise ValueError('job changed while reading')
        return b''.join(chunks), opened
    finally:
        os.close(descriptor)


def fsync_directory():
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path, content, metadata):
    descriptor, temporary = tempfile.mkstemp(prefix='.legacy-upgrade.', dir=directory)
    try:
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        try:
            os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        except PermissionError:
            # A non-root installer normally owns these files.  If it is not a
            # member of the historical group, the 0664-compatible mode still
            # keeps completed records readable by the web UI.
            pass
        with os.fdopen(descriptor, 'wb') as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def unique_backup_path(filename, label='legacy-stale'):
    stamp = datetime.datetime.fromtimestamp(
        now, datetime.timezone.utc
    ).strftime('%Y%m%dT%H%M%SZ')
    base = os.path.join(directory, f'{filename}.{label}-{stamp}.bak')
    candidate = base
    suffix = 0
    while os.path.lexists(candidate):
        suffix += 1
        candidate = f'{base}.{suffix}'
    return candidate


def exclusive_backup(path, content, metadata):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, stat.S_IMODE(metadata.st_mode))
    created = True
    try:
        try:
            os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        except PermissionError:
            pass
        with os.fdopen(descriptor, 'wb') as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        fsync_directory()
        verified, _ = read_stable_regular(path)
        if verified != content:
            raise OSError('backup verification failed')
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            try:
                os.unlink(path)
                fsync_directory()
            except OSError:
                pass
        raise


def acquire_lock(lock_path, owner_metadata):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(lock_path, flags, 0o664)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError('lock is not a regular file')
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    try:
        current = os.lstat(lock_path)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError('lock path changed while opening')
        os.fchown(descriptor, owner_metadata.st_uid, owner_metadata.st_gid)
        os.fchmod(descriptor, 0o664)
        os.fsync(descriptor)
    except Exception:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        raise
    return descriptor


def classify_legacy(filename, job, metadata, expected_complete):
    if current_schema_fields.intersection(job):
        return None, 'current-schema upgrade job'
    if any(
            isinstance(device, dict) and current_device_fields.intersection(device)
            for device in job.get('devices', [])
    ):
        return None, 'current-schema device state'
    keys = set(job)
    if not legacy_required.issubset(keys) or not keys.issubset(
            legacy_required | legacy_optional):
        return None, 'unknown upgrade job schema'
    if job.get('id') != filename[:-5] or not uuid_json.fullmatch(filename):
        return None, 'job filename/id mismatch'
    if job.get('complete') is not expected_complete or \
            not isinstance(job.get('cancelled'), bool):
        return None, 'invalid legacy completion state'
    if not isinstance(job.get('stop_on_failure'), bool) or \
            not isinstance(job.get('base_config_after'), bool):
        return None, 'invalid legacy job flags'
    if isinstance(job.get('batch_size'), bool) or \
            not isinstance(job.get('batch_size'), int) or job['batch_size'] <= 0:
        return None, 'invalid legacy batch size'
    if not isinstance(job.get('target_version'), str) or \
            not job['target_version'].strip():
        return None, 'invalid legacy target version'
    devices = job.get('devices')
    if not isinstance(devices, list) or not devices:
        return None, 'legacy job has no devices'
    for device in devices:
        if not isinstance(device, dict) or device.get('status') not in legacy_device_statuses:
            return None, 'invalid legacy device state'
    if expected_complete and any(
            device['status'] not in terminal_statuses for device in devices):
        return None, 'completed legacy job has nonterminal devices'
    try:
        # Cancellation/status writes can race a launch-before-save window. A
        # recently touched terminal-looking record therefore remains inside
        # the safety window as well. The installer already holds scheduler,
        # coordinator and per-job worker locks, so an actually running legacy
        # writer is rejected rather than allowed to extend this forever.
        activity = [numeric_timestamp(job['created_at'])]
        if job.get('worker_started_at') is not None:
            numeric_timestamp(job['worker_started_at'])
        for key in ('worker_heartbeat', 'completed_at'):
            if job.get(key) is not None:
                value = numeric_timestamp(job[key])
                if expected_complete:
                    activity.append(value)
        for device in devices:
            if device.get('started_at') is not None:
                activity.append(numeric_timestamp(device['started_at']))
            if device.get('last_check') is not None:
                value = numeric_timestamp(device['last_check'])
                if expected_complete:
                    activity.append(value)
        if metadata.st_mtime > now + 300:
            return None, 'legacy job file timestamp is unexpectedly in the future'
        if expected_complete:
            activity.append(numeric_timestamp(metadata.st_mtime))
        timeout_seconds = int(job.get('timeout_seconds', 3600))
        if timeout_seconds <= 0 or timeout_seconds > 7 * 86400:
            return None, 'invalid legacy timeout'
    except (TypeError, ValueError):
        return None, 'invalid legacy timestamps'
    effective_stale_seconds = max(stale_seconds, timeout_seconds + 3600)
    last_activity = max(activity)
    return (
        last_activity,
        effective_stale_seconds,
        now - last_activity < effective_stale_seconds,
    ), None


def load_authorized_targets():
    devices_raw, _ = read_stable_regular(devices_file)
    parser = (
        'import json,sys; from ruamel.yaml import YAML; '
        'json.dump(YAML(typ="safe").load(sys.stdin.read()) or {}, sys.stdout)'
    )
    yaml_command = [sys.executable, '-c', parser]
    try:
        service_uid = pwd.getpwnam(service_user).pw_uid
    except KeyError as exc:
        raise ValueError('configured LLDPq service user does not exist') from exc
    if os.geteuid() != service_uid:
        sudo_binary = shutil.which('sudo')
        if not sudo_binary:
            raise ValueError('sudo is unavailable for devices.yaml validation')
        yaml_command = [
            sudo_binary, '-n', '-H', '-u', service_user, '--',
        ] + yaml_command
    parsed = subprocess.run(
        yaml_command, input=devices_raw.decode('utf-8'),
        capture_output=True, text=True, timeout=15,
    )
    if parsed.returncode != 0:
        detail = (parsed.stderr or 'ruamel.yaml parser failed').strip()[:200]
        raise ValueError('devices.yaml could not be safely parsed: ' + detail)
    payload = json.loads(parsed.stdout, object_pairs_hook=strict_object)
    if not isinstance(payload, dict):
        raise ValueError('devices.yaml is not an object')
    defaults = payload.get('defaults', {})
    if not isinstance(defaults, dict):
        raise ValueError('devices.yaml defaults are invalid')
    default_username = str(defaults.get('username', 'cumulus')).strip()
    configured = payload.get('devices', payload)
    if not isinstance(configured, dict):
        raise ValueError('devices.yaml devices are invalid')
    by_ip = {}
    for raw_ip, info in configured.items():
        if raw_ip in ('defaults', 'endpoint_hosts'):
            continue
        try:
            ip = str(ipaddress.IPv4Address(str(raw_ip)))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f'invalid devices.yaml IP: {raw_ip}') from exc
        if isinstance(info, dict):
            hostname = str(info.get('hostname', ip)).strip()
            username = str(info.get('username', default_username)).strip()
        elif isinstance(info, str):
            hostname = info.split('@', 1)[0].strip()
            username = default_username
        else:
            raise ValueError(f'invalid devices.yaml entry for {ip}')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
            raise ValueError(f'invalid devices.yaml hostname for {ip}')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
            raise ValueError(f'invalid devices.yaml username for {ip}')
        if ip in by_ip:
            raise ValueError(f'duplicate devices.yaml IP: {ip}')
        by_ip[ip] = {'hostname': hostname, 'username': username}

    inventory_raw, _ = read_stable_regular(inventory_file)
    inventory = json.loads(
        inventory_raw.decode('utf-8'), object_pairs_hook=strict_object
    )
    if not isinstance(inventory, dict) or not isinstance(inventory.get('bindings'), list):
        raise ValueError('inventory.json bindings are invalid')
    bindings = {}
    for binding in inventory['bindings']:
        if not isinstance(binding, dict) or binding.get('commented'):
            continue
        raw_ip = str(binding.get('ip', '')).strip()
        if not raw_ip:
            continue
        try:
            ip = str(ipaddress.IPv4Address(raw_ip))
        except ipaddress.AddressValueError as exc:
            raise ValueError('inventory.json contains an invalid IP') from exc
        hostname = str(binding.get('hostname', '')).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
            raise ValueError(f'invalid inventory hostname for {ip}')
        mac = re.sub(r'[^0-9a-f]', '', str(binding.get('mac', '')).lower())
        if mac and len(mac) != 12:
            raise ValueError(f'invalid inventory MAC for {ip}')
        serial = str(binding.get('serial', '')).strip()
        if serial.lower() in ('na', 'n/a', 'not specified', 'none'):
            serial = ''
        if not mac and not serial:
            raise ValueError(f'inventory identity is missing for {ip}')
        if ip in bindings:
            raise ValueError(f'duplicate inventory IP: {ip}')
        bindings[ip] = {'hostname': hostname, 'mac': mac, 'serial': serial}
    return by_ip, bindings


def authorize_probe_target(device, configured, bindings):
    hostname = str(device.get('hostname', '')).strip()
    username = str(device.get('username', 'cumulus')).strip()
    try:
        ip = str(ipaddress.IPv4Address(str(device.get('ip', '')).strip()))
    except ipaddress.AddressValueError as exc:
        raise ValueError('legacy device IP is invalid') from exc
    current = configured.get(ip)
    binding = bindings.get(ip)
    if current is None or binding is None:
        raise ValueError(f'{hostname or ip} is absent from current devices/inventory')
    if current['hostname'].lower() != hostname.lower() or \
            binding['hostname'].lower() != hostname.lower():
        raise ValueError(f'{hostname or ip} no longer matches current inventory hostname')
    if current['username'] != username:
        raise ValueError(f'{hostname or ip} no longer matches current SSH username')
    return {
        'ip': ip, 'hostname': current['hostname'], 'username': username,
        'expected_mac': binding['mac'], 'expected_serial': binding['serial'],
    }


remote_probe = r'''set +e
printf 'LLDPQ_LEGACY_PROBE_V1_BEGIN\n'
version="$(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"' || true)"
printf 'VERSION=%s\n' "$(printf '%s' "$version" | tr -cd 'A-Za-z0-9._+~:-' | head -c 100)"
test -s /etc/nvue.d/startup.yaml && echo STARTUP=1 || echo STARTUP=0
test -f /etc/lldpq-base-deployed && echo BASE=1 || echo BASE=0
if command -v pgrep >/dev/null 2>&1; then
  pgrep -f '[o]nie-install' >/dev/null 2>&1 && echo ONIE=active || echo ONIE=inactive
else
  echo ONIE=unknown
fi
operation="$(cat /tmp/lldpq-upgrade.operation 2>/dev/null | tr -cd 'A-Za-z0-9._+~:-' | head -c 100 || true)"
printf 'OPERATION=%s\n' "$operation"
if test -s /tmp/lldpq-upgrade.exit; then
  upgrade_exit="$(cat /tmp/lldpq-upgrade.exit 2>/dev/null | tr -cd '0-9-' | head -c 12)"
  test -n "$upgrade_exit" && printf 'EXIT=%s\n' "$upgrade_exit" || echo EXIT=invalid
else
  echo EXIT=missing
fi
mac="$(cat /sys/class/net/eth0/address 2>/dev/null | tr -cd '0-9A-Fa-f' | tr 'A-F' 'a-f' | head -c 12 || true)"
printf 'MAC=%s\n' "$mac"
serial="$(sudo -n dmidecode -s system-serial-number 2>/dev/null | head -1 | tr -cd 'A-Za-z0-9._+~:-' | head -c 100 || true)"
printf 'SERIAL=%s\n' "$serial"
printf 'LLDPQ_LEGACY_PROBE_V1_END\n'
'''


def probe_device(target):
    ssh_binary = shutil.which('ssh')
    if not ssh_binary:
        return None, 'ssh client is unavailable'
    command = [
        ssh_binary, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
        '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR', f"{target['username']}@{target['ip']}",
        remote_probe,
    ]
    try:
        service_uid = pwd.getpwnam(service_user).pw_uid
    except KeyError:
        return None, 'configured LLDPq service user does not exist'
    if os.geteuid() != service_uid:
        sudo_binary = shutil.which('sudo')
        if not sudo_binary:
            return None, 'sudo is unavailable for the LLDPq service account probe'
        command = [sudo_binary, '-n', '-u', service_user, '--'] + command
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f'SSH probe failed: {exc}'
    lines = [line.strip() for line in result.stdout.splitlines()]
    try:
        begin = lines.index('LLDPQ_LEGACY_PROBE_V1_BEGIN')
        end = lines.index('LLDPQ_LEGACY_PROBE_V1_END', begin + 1)
    except ValueError:
        detail = (result.stderr or 'no authenticated probe response').strip()[:160]
        return None, f'SSH probe unavailable: {detail}'
    if result.returncode != 0:
        return None, f'SSH probe exited with status {result.returncode}'
    values = {}
    for line in lines[begin + 1:end]:
        if '=' not in line:
            return None, 'SSH probe returned malformed evidence'
        key, value = line.split('=', 1)
        if key in values or key not in {
                'VERSION', 'STARTUP', 'BASE', 'ONIE', 'OPERATION',
                'EXIT', 'MAC', 'SERIAL',
        }:
            return None, 'SSH probe returned ambiguous evidence'
        values[key] = value
    if set(values) != {
            'VERSION', 'STARTUP', 'BASE', 'ONIE', 'OPERATION',
            'EXIT', 'MAC', 'SERIAL',
    }:
        return None, 'SSH probe evidence is incomplete'
    observed_mac = re.sub(r'[^0-9a-f]', '', values['MAC'].lower())
    observed_serial = values['SERIAL'].strip()
    matches = 0
    if target['expected_mac'] and observed_mac:
        if target['expected_mac'] != observed_mac:
            return None, 'live MAC does not match current inventory'
        matches += 1
    if target['expected_serial'] and observed_serial:
        if target['expected_serial'].lower() != observed_serial.lower():
            return None, 'live serial does not match current inventory'
        matches += 1
    if matches == 0:
        return None, 'live device identity could not be verified'
    return values, None


def version_relation(current, target):
    if current == target:
        return 0
    current_match = re.match(r'^(\d+(?:\.\d+)+)', current)
    target_match = re.match(r'^(\d+(?:\.\d+)+)', target)
    if not current_match or not target_match:
        return None
    current_parts = [int(part) for part in current_match.group(1).split('.')]
    target_parts = [int(part) for part in target_match.group(1).split('.')]
    width = max(len(current_parts), len(target_parts))
    current_parts.extend([0] * (width - len(current_parts)))
    target_parts.extend([0] * (width - len(target_parts)))
    return (current_parts > target_parts) - (current_parts < target_parts)


def resolve_probe(job, device, evidence, superseding_operations=None):
    superseding_operations = superseding_operations or set()
    operation = evidence['OPERATION']
    if operation and operation in superseding_operations:
        return 'failed', (
            'Expired legacy state was superseded by a validated resumable '
            'current upgrade operation for this device.'
        )
    relation = version_relation(evidence['VERSION'], job['target_version'])
    if evidence['ONIE'] != 'inactive':
        return None, 'ONIE installer activity is active or could not be determined'
    if relation is None:
        return None, 'device version cannot be safely compared with the legacy target'
    if relation >= 0:
        if relation == 0 and evidence['OPERATION']:
            return None, 'exact target has an unrelated upgrade operation marker'
        missing = []
        if evidence['STARTUP'] != '1':
            missing.append('startup configuration')
        if job.get('base_config_after') and evidence['BASE'] != '1':
            missing.append('base deployment')
        if missing:
            return 'failed', (
                'OS upgrade version was verified, but required ' +
                ' and '.join(missing) + ' marker evidence is missing.'
            )
        return 'done', (
            'Legacy upgrade completion verified from the live target/newer '
            'version and required configuration markers.'
        )
    if evidence['OPERATION']:
        return None, 'older version has an unrelated upgrade operation marker'
    if evidence['EXIT'] == 'invalid':
        return None, 'older version has an invalid upgrade exit marker'
    return 'failed', (
        'Expired legacy upgrade verified as stopped: the device is reachable '
        'on an older version with no ONIE process or operation marker.'
    )


# Phase 1: classify the complete directory before acquiring or mutating any
# candidate. One current/recent/corrupt/ambiguous incomplete job means zero
# legacy migrations. Recent completed legacy jobs are candidates for the same
# live proof instead of being blocked solely by their completion timestamp.
candidates = []
resumable_current_jobs = []
blockers = []
job_entries = sorted(
    (entry for entry in os.scandir(directory) if entry.name.endswith('.json')),
    key=lambda item: item.name,
)
initial_job_names = [entry.name for entry in job_entries]
for entry in job_entries:
    try:
        original, metadata = read_stable_regular(entry.path)
        job = json.loads(original.decode('utf-8'), object_pairs_hook=strict_object)
        if not isinstance(job, dict):
            raise ValueError('job is not an object')
        if not uuid_json.fullmatch(entry.name) or job.get('id') != entry.name[:-5]:
            raise ValueError('job filename/id mismatch')
        if not isinstance(job.get('devices'), list):
            raise ValueError('job devices are invalid')
        if not isinstance(job.get('complete'), bool):
            raise ValueError('job complete flag is invalid')
    except Exception as exc:
        blockers.append(f'{entry.name}: corrupt/unsafe state ({exc})')
        continue
    schema_version = job.get('schema_version')
    if schema_version is not None and (
            isinstance(schema_version, bool) or
            not isinstance(schema_version, int) or
            schema_version != supported_schema_version):
        blockers.append(f'{entry.name}: unsupported upgrade job schema version')
        continue
    if job['complete']:
        if schema_version == supported_schema_version or \
                current_schema_fields.intersection(job):
            continue
        classification, reason = classify_legacy(
            entry.name, job, metadata, True
        )
        if classification is None:
            blockers.append(f'{entry.name}: {reason}')
            continue
        # Old completed jobs outside the conservative safety window need no
        # rewrite. Recent pre-schema completions are live-probed instead of
        # blindly delaying the installer for a fixed day.
        if not classification[2]:
            continue
        candidates.append({
            'kind': 'legacy-reconciliation',
            'name': entry.name, 'path': entry.path, 'original': original,
            'metadata': metadata, 'job': job,
            'last_activity': classification[0],
            'stale_after': classification[1],
        })
        continue
    if schema_version == supported_schema_version and allow_current_incomplete:
        # Docker image recreation has already switched code before entrypoint
        # runs. Supported current jobs must remain intact so the new scheduler
        # can resume them; only unversioned legacy state needs reconciliation.
        try:
            validate_resumable_current(entry.name, job, metadata)
        except Exception as exc:
            blockers.append(
                f'{entry.name}: incompatible schema-v2 upgrade state ({exc})'
            )
            continue
        resumable_current_jobs.append(job)
        continue
    if schema_version is None and current_schema_fields.intersection(job):
        if not allow_current_incomplete:
            blockers.append(f'{entry.name}: current-schema upgrade job')
            continue
        try:
            validate_resumable_current(entry.name, job, metadata)
        except Exception as exc:
            blockers.append(
                f'{entry.name}: incompatible current upgrade state ({exc})'
            )
            continue
        candidates.append({
            'kind': 'current-schema-promotion',
            'name': entry.name, 'path': entry.path, 'original': original,
            'metadata': metadata, 'job': job,
        })
        resumable_current_jobs.append(job)
        continue
    classification, reason = classify_legacy(
        entry.name, job, metadata, False
    )
    if classification is None:
        blockers.append(f'{entry.name}: {reason}')
        continue
    if classification[2]:
        blockers.append(
            f'{entry.name}: legacy job is still inside its expiry window'
        )
        continue
    candidates.append({
        'kind': 'legacy-reconciliation',
        'name': entry.name, 'path': entry.path, 'original': original,
        'metadata': metadata, 'job': job,
        'last_activity': classification[0],
        'stale_after': classification[1],
    })

if blockers:
    print('[!] Legacy upgrade reconciliation was skipped: ' + '; '.join(blockers), file=sys.stderr)
    raise SystemExit(0)
if not candidates:
    raise SystemExit(0)

superseding_operations = {}
for current_job in resumable_current_jobs:
    for device in current_job['devices']:
        operation = str(device.get('operation_id', '')).strip()
        if operation and device.get('status') in (
                'starting', 'upgrading', 'waiting_reboot'):
            superseding_operations.setdefault(str(device['ip']), set()).add(
                operation
            )

# Phase 2: use the historical worker->job lock order for every candidate. Keep
# all locks until every backup and commit is durable so mixed generations are
# never created by a concurrent legacy worker/API reader.
locks = []
lock_failure = None
try:
    for candidate in candidates:
        for suffix in ('.worker.lock', '.lock'):
            descriptor = acquire_lock(
                candidate['path'] + suffix, candidate['metadata']
            )
            if descriptor is None:
                lock_failure = f"{candidate['name']}{suffix} is active"
                break
            locks.append(descriptor)
        if lock_failure:
            break
    if lock_failure:
        print(f'[!] Legacy upgrade reconciliation was skipped: {lock_failure}', file=sys.stderr)
        raise SystemExit(0)

    # Phase 3: all candidates must still be byte-for-byte and inode-identical.
    for candidate in candidates:
        current, metadata = read_stable_regular(candidate['path'])
        original_metadata = candidate['metadata']
        if current != candidate['original'] or (
            metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns
        ) != (
            original_metadata.st_dev, original_metadata.st_ino,
            original_metadata.st_size, original_metadata.st_mtime_ns,
        ):
            print(
                f"[!] Legacy upgrade reconciliation was skipped: {candidate['name']} changed",
                file=sys.stderr,
            )
            raise SystemExit(0)

    active = []
    for candidate in candidates:
        if candidate['kind'] != 'legacy-reconciliation':
            continue
        for index, device in enumerate(candidate['job']['devices']):
            # Both legacy implementations could persist queued before a later
            # status/worker pass launched the next batch remotely. A crash
            # between launch and the following save can therefore leave a
            # genuinely launched device looking queued. Only queued entries in
            # a durably cancelled job are known never to be launched afterward.
            # Every state except a positively completed `done` can hide a
            # launch-before-save crash (including failed/blocked/cancelled
            # terminal-looking rows). Read-only live proof closes that gap.
            if device['status'] != 'done':
                active.append((candidate, index, device))

    # Phase 4: authorize every SSH destination against two current canonical
    # sources before making any network connection, then collect read-only live
    # proof in parallel. Ambiguity leaves every original byte untouched.
    resolutions = {}
    if active:
        try:
            configured, bindings = load_authorized_targets()
            authorized = []
            unique_targets = {}
            for candidate, index, device in active:
                target = authorize_probe_target(device, configured, bindings)
                target_key = (
                    target['ip'], target['username'], target['hostname'].lower(),
                    target['expected_mac'], target['expected_serial'].lower(),
                )
                unique_targets.setdefault(target_key, target)
                authorized.append((candidate, index, target_key, target))
        except Exception as exc:
            print(f'[!] Legacy upgrade reconciliation was skipped: {exc}', file=sys.stderr)
            raise SystemExit(0)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(8, len(unique_targets))) as executor:
            futures = {
                executor.submit(probe_device, target): target_key
                for target_key, target in unique_targets.items()
            }
            probe_results = {}
            for future in concurrent.futures.as_completed(futures):
                probe_results[futures[future]] = future.result()
            probe_blockers = []
            for candidate, index, target_key, target in authorized:
                evidence, error = probe_results[target_key]
                if error:
                    probe_blockers.append(
                        f"{candidate['name']}:{target['hostname']}: {error}"
                    )
                    continue
                status, detail = resolve_probe(
                    candidate['job'], candidate['job']['devices'][index],
                    evidence, superseding_operations.get(target['ip'], set()),
                )
                if status is None:
                    probe_blockers.append(
                        f"{candidate['name']}:{target['hostname']}: {detail}"
                    )
                    continue
                resolutions[(candidate['name'], index)] = (status, detail, evidence)
            if probe_blockers:
                print(
                    '[!] Legacy upgrade reconciliation was skipped: ' +
                    '; '.join(sorted(probe_blockers)), file=sys.stderr,
                )
                raise SystemExit(0)

    # Probes can take several minutes on a large fabric. Revalidate both the
    # complete directory membership and every candidate immediately before
    # rendering/backing up state, even though compliant writers are already
    # excluded by the coordinator and per-job locks.
    current_job_names = sorted(
        entry.name for entry in os.scandir(directory)
        if entry.name.endswith('.json')
    )
    if current_job_names != initial_job_names:
        print(
            '[!] Legacy upgrade reconciliation was skipped: upgrade job set changed',
            file=sys.stderr,
        )
        raise SystemExit(0)
    for candidate in candidates:
        current, metadata = read_stable_regular(candidate['path'])
        original_metadata = candidate['metadata']
        if current != candidate['original'] or (
            metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns
        ) != (
            original_metadata.st_dev, original_metadata.st_ino,
            original_metadata.st_size, original_metadata.st_mtime_ns,
        ):
            print(
                f"[!] Legacy upgrade reconciliation was skipped: {candidate['name']} changed during probes",
                file=sys.stderr,
            )
            raise SystemExit(0)

    # Phase 5: render everything in memory, then durably verify every original
    # backup before the first job file is replaced.
    reason = (
        'Expired pre-v4 upgrade state was reconciled by the LLDPq update '
        'bootstrap using live read-only device evidence.'
    )
    for candidate in candidates:
        job = candidate['job']
        if candidate['kind'] == 'current-schema-promotion':
            backup_path = unique_backup_path(candidate['name'], 'schema-v2')
            candidate['backup_path'] = backup_path
            job['schema_version'] = supported_schema_version
            job['schema_migration'] = {
                'action': 'previous-current-job-promoted-for-runtime',
                'migrated_at': now,
                'original_sha256': hashlib.sha256(
                    candidate['original']
                ).hexdigest(),
                'backup_file': os.path.basename(backup_path),
            }
            candidate['rendered'] = (
                json.dumps(job, indent=2, sort_keys=True) + '\n'
            ).encode('utf-8')
            continue
        evidence_summary = []
        for index, device in enumerate(job['devices']):
            previous = device['status']
            if previous in terminal_statuses and \
                    (candidate['name'], index) not in resolutions:
                continue
            device['legacy_status'] = previous
            status, detail, evidence = resolutions[(candidate['name'], index)]
            if status == 'failed' and previous in ('queued', 'cancelled'):
                if candidate['job'].get('cancelled') or previous == 'cancelled':
                    status = 'cancelled'
                    detail = (
                        'Expired legacy cancellation was verified: the device '
                        'remained below the target version with no active ONIE '
                        'process or upgrade operation marker.'
                    )
                else:
                    status = 'blocked'
                    detail = (
                        'Expired legacy queued launch is no longer active; the '
                        'device remained below the requested target version.'
                    )
            elif status == 'failed' and previous in ('failed', 'blocked'):
                status = previous
                detail = (
                    'Expired legacy terminal state was verified: the device '
                    'remained below the target version with no active ONIE '
                    'process or upgrade operation marker.'
                )
            device['status'] = status
            if status == 'done':
                device['message'] = detail
                device.pop('error', None)
            else:
                device['error'] = detail
            probe_record = {
                'probed_at': now,
                'version': evidence['VERSION'],
                'startup_config': evidence['STARTUP'] == '1',
                'base_deployed': evidence['BASE'] == '1',
                'onie_process': evidence['ONIE'],
                'operation_marker': evidence['OPERATION'],
                'exit_marker': evidence['EXIT'],
                'observed_mac': evidence['MAC'],
                'observed_serial': evidence['SERIAL'],
                'result': status,
            }
            device['legacy_reconciliation_probe'] = probe_record
            evidence_summary.append({
                'hostname': device.get('hostname', device.get('ip', '')),
                **probe_record,
            })
        if not all(item['status'] in terminal_statuses for item in job['devices']):
            raise RuntimeError(f"{candidate['name']} did not resolve to terminal state")
        backup_path = unique_backup_path(candidate['name'])
        candidate['backup_path'] = backup_path
        # The live record has now been deterministically converted to the
        # current terminal contract. The byte-exact pre-v4 source remains in
        # the verified backup referenced below.
        job['schema_version'] = supported_schema_version
        job['complete'] = True
        job['completed_at'] = now
        # A completed reconciled job has no retrying worker. Preserve the
        # original worker_error in the verified backup/audit hash, but do not
        # make the existing UI display the contradictory “worker retrying”.
        job.pop('worker_error', None)
        job['legacy_reconciliation'] = {
            'schema': 'pre-v4-upgrade-job',
            'action': 'expired-job-reconciled-for-update',
            'reconciled_at': now,
            'last_launch_activity_at': int(candidate['last_activity']),
            'stale_after_seconds': candidate['stale_after'],
            'original_sha256': hashlib.sha256(candidate['original']).hexdigest(),
            'backup_file': os.path.basename(backup_path),
            'device_evidence': evidence_summary,
        }
        candidate['rendered'] = (
            json.dumps(job, indent=2, sort_keys=True) + '\n'
        ).encode('utf-8')

    created_backups = []
    try:
        for candidate in candidates:
            exclusive_backup(
                candidate['backup_path'], candidate['original'], candidate['metadata']
            )
            created_backups.append(candidate['backup_path'])
    except Exception as exc:
        for backup in created_backups:
            try:
                os.unlink(backup)
            except OSError:
                pass
        fsync_directory()
        raise RuntimeError(f'could not create verified legacy backup: {exc}') from exc

    attempted = []
    try:
        for candidate in candidates:
            # Include an in-progress candidate in rollback even if replace()
            # succeeds but a following fsync/readback raises.
            attempted.append(candidate)
            atomic_write(candidate['path'], candidate['rendered'], candidate['metadata'])
            verified, _ = read_stable_regular(candidate['path'])
            if verified != candidate['rendered']:
                raise OSError('terminal state verification failed')
    except Exception as exc:
        rollback_errors = []
        for candidate in reversed(attempted):
            try:
                atomic_write(candidate['path'], candidate['original'], candidate['metadata'])
            except Exception as rollback_exc:
                rollback_errors.append(f"{candidate['name']}: {rollback_exc}")
        detail = f'could not commit reconciled legacy state: {exc}'
        if rollback_errors:
            detail += '; rollback failed: ' + '; '.join(rollback_errors)
        raise RuntimeError(detail) from exc

    for candidate in candidates:
        if candidate['kind'] == 'current-schema-promotion':
            print(
                f"  Promoted resumable upgrade {candidate['job']['id']} to "
                f"schema v{supported_schema_version}; original saved as "
                f"{os.path.basename(candidate['backup_path'])}"
            )
        else:
            print(
                f"  Reconciled historical legacy upgrade {candidate['job']['id']}; "
                f"original saved as {os.path.basename(candidate['backup_path'])}"
            )
finally:
    for descriptor in reversed(locks):
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
PYTHON
}

verify_no_active_upgrade_jobs() {
    local upgrade_dir="$1"
    local legacy_stale_seconds="${LLDPQ_LEGACY_UPGRADE_STALE_SECONDS:-86400}"
    python3 - "$upgrade_dir" "$legacy_stale_seconds" <<'PYTHON'
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import sys
import time

uuid_json = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.json$')
supported_schema_version = 2
artifact_grace_seconds = 86400
legacy_stale_seconds = int(sys.argv[2])
now = time.time()
current_schema_fields = {
    'schema_version', 'image_size', 'image_sha256', 'ready',
    'aliases_published', 'onie_alias_snapshot', 'ztp_artifact',
    'ztp_size', 'ztp_sha256',
}

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result

def read_regular(path):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('job is not a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('job changed while opening')
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.lstat(path)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('job changed while reading')
        return b''.join(chunks), opened.st_mtime
    finally:
        os.close(descriptor)

def finite_timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('invalid upgrade timestamp')
    value = float(value)
    if not math.isfinite(value) or value <= 0 or value > now + 300:
        raise ValueError('invalid upgrade timestamp')
    return value

def promoted_resume_is_quiesced(job, job_path):
    migration = job.get('schema_migration')
    if not isinstance(migration, dict) or \
            migration.get('action') != 'previous-current-job-promoted-for-runtime' or \
            not re.fullmatch(r'[0-9a-f]{64}', str(migration.get('original_sha256', ''))):
        return False
    try:
        finite_timestamp(migration.get('migrated_at'))
        backup_name = migration.get('backup_file')
        if not isinstance(backup_name, str) or os.path.basename(backup_name) != backup_name or \
                '.schema-v2-' not in backup_name:
            return False
        backup_path = os.path.join(os.path.dirname(job_path), backup_name)
        backup_raw, _ = read_regular(backup_path)
        if hashlib.sha256(backup_raw).hexdigest() != migration['original_sha256']:
            return False
        original = json.loads(
            backup_raw.decode('utf-8'), object_pairs_hook=strict_object
        )
        if not isinstance(original, dict) or original.get('id') != job.get('id') or \
                original.get('complete') is not False or \
                original.get('schema_version') is not None:
            return False
    except Exception:
        return False

    descriptors = []
    try:
        for suffix in ('.worker.lock', '.lock'):
            lock_path = job_path + suffix
            before = os.lstat(lock_path)
            if not stat.S_ISREG(before.st_mode):
                return False
            flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0)
            flags |= getattr(os, 'O_NOFOLLOW', 0)
            descriptor = os.open(lock_path, flags)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return False
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
        return True
    except OSError:
        return False
    finally:
        for descriptor in reversed(descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

def holds_provision_resources(job, file_mtime, job_path):
    if job.get('alias_rollback_failed'):
        return True
    if not job['complete']:
        if promoted_resume_is_quiesced(job, job_path):
            return False
        return True
    uncertain = any(
        item.get('launch_attempted_at') and (
            item.get('launch_uncertain') or
            'timeout' in str(item.get('error', '')).lower()
        )
        for item in job['devices'] if isinstance(item, dict)
    )
    if uncertain:
        completed_at = job.get('completed_at')
        if completed_at is None:
            return True
        return now - finite_timestamp(completed_at) < artifact_grace_seconds

    # Completed pre-v4 jobs had a launch-before-save crash window. Do not
    # replace runtime code while such an unversioned completion is still inside
    # the same conservative timeout+grace window used for stale reconciliation.
    if job.get('schema_version') is None and not current_schema_fields.intersection(job):
        activity = [
            finite_timestamp(job.get('created_at')),
            finite_timestamp(file_mtime),
        ]
        for key in ('worker_started_at', 'worker_heartbeat', 'completed_at'):
            if job.get(key) is not None:
                activity.append(finite_timestamp(job[key]))
        for item in job['devices']:
            if not isinstance(item, dict):
                raise ValueError('invalid legacy device state')
            for key in ('started_at', 'last_check'):
                if item.get(key) is not None:
                    activity.append(finite_timestamp(item[key]))
        timeout_seconds = int(job.get('timeout_seconds', 3600))
        if timeout_seconds <= 0 or timeout_seconds > 7 * 86400:
            raise ValueError('invalid legacy timeout')
        return now - max(activity) < max(
            legacy_stale_seconds, timeout_seconds + 3600
        )
    return False

active_job = None
for entry in sorted(os.scandir(sys.argv[1]), key=lambda item: item.name):
    if not entry.name.endswith('.json'):
        continue
    name = entry.name
    try:
        raw, file_mtime = read_regular(entry.path)
        job = json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object)
        if not isinstance(job, dict):
            raise ValueError('job is not an object')
        if not uuid_json.fullmatch(name):
            raise ValueError('unexpected upgrade job filename')
        if job.get('id') != name[:-5] or not isinstance(job.get('devices'), list):
            raise ValueError('job schema/id mismatch')
        if not isinstance(job.get('complete'), bool):
            raise ValueError('complete must be boolean')
        schema_version = job.get('schema_version')
        if schema_version is not None and (
                isinstance(schema_version, bool) or
                not isinstance(schema_version, int) or
                schema_version != supported_schema_version):
            raise ValueError('unsupported upgrade job schema version')
    except Exception as exc:
        print(f'corrupt upgrade job {name}: {exc}')
        raise SystemExit(11)
    try:
        holds_resources = holds_provision_resources(job, file_mtime, entry.path)
    except Exception as exc:
        print(f'corrupt upgrade job {name}: {exc}')
        raise SystemExit(11)
    if holds_resources and active_job is None:
        active_job = job.get('id') or name
if active_job is not None:
    print(active_job)
    raise SystemExit(10)
PYTHON
}

verify_upgrade_jobs_runtime_compatible() {
    local upgrade_dir="$1"
    local legacy_stale_seconds="${LLDPQ_LEGACY_UPGRADE_STALE_SECONDS:-86400}"
    python3 - "$upgrade_dir" "$legacy_stale_seconds" <<'PYTHON'
import ipaddress
import json
import math
import os
import re
import stat
import sys
import time

directory = sys.argv[1]
legacy_stale_seconds = int(sys.argv[2])
supported_schema_version = 2
now = time.time()
uuid_json = re.compile(
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.json$'
)
current_schema_fields = {
    'image_size', 'image_sha256', 'ready', 'aliases_published',
    'onie_alias_snapshot', 'ztp_artifact', 'ztp_size', 'ztp_sha256',
}
terminal_statuses = {'done', 'failed', 'cancelled', 'blocked'}
current_statuses = terminal_statuses | {
    'queued', 'starting', 'upgrading', 'waiting_reboot',
}

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result

def read_regular(path):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('job is not a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('job changed while opening')
        content = b''
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content += chunk
        after = os.lstat(path)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('job changed while reading')
        return content, opened.st_mtime
    finally:
        os.close(descriptor)

def timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('invalid legacy timestamp')
    value = float(value)
    if not math.isfinite(value) or value <= 0 or value > now + 300:
        raise ValueError('invalid legacy timestamp')
    return value

def positive_integer(value, label, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or \
            (maximum is not None and value > maximum):
        raise ValueError(f'invalid {label}')

def validate_schema_v2(job, name):
    reconciliation = job.get('legacy_reconciliation')
    if reconciliation is not None:
        if not job['complete'] or not job['devices'] or \
                not isinstance(reconciliation, dict) or \
                reconciliation.get('action') != 'expired-job-reconciled-for-update' or \
                not re.fullmatch(r'[0-9a-f]{64}', str(reconciliation.get('original_sha256', ''))) or \
                not isinstance(reconciliation.get('backup_file'), str) or \
                '/' in reconciliation['backup_file'] or '\\' in reconciliation['backup_file'] or \
                any(not isinstance(item, dict) or
                    item.get('status') not in terminal_statuses
                    for item in job['devices']):
            raise ValueError('invalid reconciled legacy upgrade state')
        return

    required = {
        'created_at', 'target_version', 'image_name', 'image_size',
        'image_sha256', 'server_ip', 'batch_size', 'stop_on_failure',
        'base_config_after', 'timeout_seconds', 'cancelled', 'ready',
        'aliases_published', 'onie_alias_snapshot', 'worker_started_at',
        'worker_heartbeat', 'ztp_artifact', 'ztp_size', 'ztp_sha256',
    }
    missing = sorted(required.difference(job))
    if missing:
        raise ValueError('upgrade job is missing: ' + ', '.join(missing))
    positive_integer(job['created_at'], 'created_at')
    positive_integer(job['worker_started_at'], 'worker_started_at')
    positive_integer(job['worker_heartbeat'], 'worker_heartbeat')
    positive_integer(job['image_size'], 'image_size')
    positive_integer(job['ztp_size'], 'ztp_size')
    positive_integer(job['batch_size'], 'batch_size', 100)
    positive_integer(job['timeout_seconds'], 'timeout_seconds', 7 * 86400)
    for key in ('created_at', 'worker_started_at', 'worker_heartbeat'):
        timestamp(job[key])
    if job['complete']:
        positive_integer(job.get('completed_at'), 'completed_at')
        timestamp(job['completed_at'])
    for key in ('stop_on_failure', 'base_config_after', 'cancelled',
                'ready', 'aliases_published'):
        if not isinstance(job[key], bool):
            raise ValueError(f'invalid {key}')
    if job['ready'] != job['aliases_published']:
        raise ValueError('inconsistent readiness/alias state')
    if not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,99}', str(job['target_version'])) or \
            not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:bin|img|iso)', str(job['image_name'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['image_sha256'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['ztp_sha256'])) or \
            not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]{1,5})?', str(job['server_ip'])):
        raise ValueError('invalid upgrade image/server metadata')
    expected_ztp = f'provision-uploads/ztp-artifacts/{name[:-5]}.ztp'
    if job['ztp_artifact'] != expected_ztp:
        raise ValueError('invalid upgrade ZTP artifact reference')
    snapshot = job['onie_alias_snapshot']
    expected_snapshot = {
        f'{scope}:{alias}' for scope in ('uploads', 'web') for alias in (
            'onie-installer-x86_64', 'onie-installer-x86_64-mlnx',
            'onie-installer',
        )
    }
    if not isinstance(snapshot, dict) or set(snapshot) != expected_snapshot or any(
            value is not None and (
                not isinstance(value, str) or
                not re.fullmatch(r'(?:provision-uploads/)?[A-Za-z0-9_.-]+', value)
            ) for value in snapshot.values()):
        raise ValueError('invalid ONIE alias rollback snapshot')
    if not job['devices']:
        raise ValueError('upgrade job has no devices')
    seen_ips = set()
    for item in job['devices']:
        if not isinstance(item, dict) or item.get('status') not in current_statuses:
            raise ValueError('invalid upgrade device state')
        try:
            ip = str(ipaddress.IPv4Address(str(item.get('ip', ''))))
        except ipaddress.AddressValueError as exc:
            raise ValueError('invalid upgrade device IP') from exc
        if ip in seen_ips:
            raise ValueError('duplicate upgrade device IP')
        seen_ips.add(ip)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',
                            str(item.get('hostname', ''))) or \
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',
                                 str(item.get('username', ''))) or \
                item.get('target_version') != job['target_version']:
            raise ValueError('invalid upgrade device identity')
        raw_mac = str(item.get('expected_mac', '')).strip().lower()
        mac = raw_mac if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', raw_mac) else ''
        serial = str(item.get('expected_serial', '')).strip()
        if serial.lower() in ('na', 'n/a', 'not specified', 'none'):
            serial = ''
        if (raw_mac and not mac) or (not mac and not serial):
            raise ValueError('upgrade device identity evidence is invalid')
        for key in ('claimed_at', 'remote_prepared_at', 'launch_attempted_at',
                    'started_at', 'last_check'):
            if item.get(key) is not None:
                positive_integer(item[key], key)
                timestamp(item[key])
        if item['status'] in ('starting', 'upgrading', 'waiting_reboot') and (
                not re.fullmatch(
                    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
                                 str(item.get('operation_id', ''))) or
                item.get('claimed_at') is None):
            raise ValueError('invalid active upgrade device claim')
        if item['status'] in ('upgrading', 'waiting_reboot') and (
                item.get('remote_prepared_at') is None or
                item.get('launch_attempted_at') is None or
                item.get('started_at') is None):
            raise ValueError('invalid launched upgrade device evidence')
    all_terminal = all(
        item['status'] in terminal_statuses for item in job['devices']
    )
    if job['complete'] and not all_terminal:
        raise ValueError('upgrade completion/device states disagree')

for entry in sorted(os.scandir(directory), key=lambda item: item.name):
    if not entry.name.endswith('.json'):
        continue
    try:
        if not uuid_json.fullmatch(entry.name):
            raise ValueError('unexpected upgrade job filename')
        raw, file_mtime = read_regular(entry.path)
        job = json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object)
        if not isinstance(job, dict) or job.get('id') != entry.name[:-5] or \
                not isinstance(job.get('devices'), list) or \
                not isinstance(job.get('complete'), bool):
            raise ValueError('job schema/id mismatch')
        schema_version = job.get('schema_version')
        if schema_version is not None:
            if isinstance(schema_version, bool) or \
                    not isinstance(schema_version, int) or \
                    schema_version != supported_schema_version:
                raise ValueError('unsupported upgrade job schema version')
            validate_schema_v2(job, entry.name)
            continue
        if not job['complete']:
            raise ValueError(
                'unfinished pre-schema job could not be safely reconciled'
            )
        if current_schema_fields.intersection(job):
            # Completed jobs written immediately before schema_version was
            # introduced use the current state machine and remain readable.
            validate_schema_v2(job, entry.name)
            continue
        activity = [timestamp(job.get('created_at')), timestamp(file_mtime)]
        for key in ('worker_started_at', 'worker_heartbeat', 'completed_at'):
            if job.get(key) is not None:
                activity.append(timestamp(job[key]))
        for device in job['devices']:
            if not isinstance(device, dict):
                raise ValueError('legacy device state is invalid')
            for key in ('started_at', 'last_check'):
                if device.get(key) is not None:
                    activity.append(timestamp(device[key]))
        timeout_seconds = int(job.get('timeout_seconds', 3600))
        if timeout_seconds <= 0 or timeout_seconds > 7 * 86400:
            raise ValueError('invalid legacy timeout')
        if now - max(activity) < max(
                legacy_stale_seconds, timeout_seconds + 3600):
            raise ValueError(
                'recent pre-schema completion remains inside its safety window'
            )
    except Exception as exc:
        print(
            f'[!] Upgrade job is incompatible with this runtime: '
            f'{entry.name}: {exc}',
            file=sys.stderr,
        )
        raise SystemExit(1)
PYTHON
}

acquire_update_provision_locks() {
    local jobs_dir="${LLDPQ_PROVISION_JOBS_DIR:-/var/lib/lldpq/provision-jobs}"
    local upgrade_dir="${LLDPQ_UPGRADE_JOBS_DIR:-/var/lib/lldpq/upgrade-jobs}"
    local wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"
    local path label fd active_job active_status
    local -a lock_paths=()

    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    if [[ -d "$jobs_dir" ]]; then
        lock_paths+=(
            "$jobs_dir/.scheduler.lock"
            "$jobs_dir/.coordinator.lock"
            "$jobs_dir/.scan.lock"
        )
    fi
    if [[ -d "$upgrade_dir" ]]; then
        lock_paths+=("$upgrade_dir/.coordinator.lock")
    fi
    ((${#lock_paths[@]} > 0)) || return 0

    # Normalize existing 0644 scheduler locks in place and create missing
    # locks as root:www-data 0660 without replacing an in-flight inode.
    prepare_shared_lock_files "${lock_paths[@]}" || {
        echo "[!] Could not prepare Provision update locks" >&2
        return 1
    }

    for path in "${lock_paths[@]}"; do
        label=$(basename "$path")
        if ! exec {fd}<>"$path"; then
            echo "[!] Could not open Provision update lock: $path" >&2
            release_update_provision_locks
            return 1
        fi
        if ! flock -w "$wait_seconds" "$fd"; then
            echo "[!] Timed out waiting for Provision worker lock: $label" >&2
            exec {fd}>&-
            release_update_provision_locks
            return 1
        fi
        UPDATE_PROVISION_LOCK_FDS+=("$fd")
    done

    # Never replace the running code underneath a persisted device upgrade.
    # Holding the upgrade coordinator prevents a new web job from appearing
    # between this check and the end of the update transaction.
    if [[ -d "$upgrade_dir" ]]; then
        # A previous-release current-contract job has no compatible scheduler
        # until this update is installed. Promote that exact, lock-quiesced
        # format to v2; verify_no_active_upgrade_jobs independently rechecks
        # its byte-exact backup and worker/job locks before allowing takeover.
        if ! LLDPQ_RECONCILE_ALLOW_CURRENT_INCOMPLETE=true \
                reconcile_stale_legacy_upgrade_jobs "$upgrade_dir"; then
            release_update_provision_locks
            return 1
        fi
        if ! verify_upgrade_jobs_runtime_compatible "$upgrade_dir"; then
            echo "[!] Persisted Provision upgrade state is incompatible with this update" >&2
            release_update_provision_locks
            return 1
        fi
        if active_job=$(verify_no_active_upgrade_jobs "$upgrade_dir"); then
            :
        else
            active_status=$?
            case "$active_status" in
                10) echo "[!] Active device upgrade $active_job; LLDPq update was not started" >&2 ;;
                *)  echo "[!] Could not verify upgrade job state: $active_job" >&2 ;;
            esac
            release_update_provision_locks
            return 1
        fi
    fi
    echo "  Provision scheduler/workers quiesced for update"
}

restore_update_web() {
    [[ "${_UPDATE_WEB_QUIESCED:-false}" == "true" ]] || return 0
    if ! root_run nginx -t >/dev/null 2>&1; then
        echo "[!] nginx configuration is invalid; web service was not started" >&2
        return 1
    fi
    if ! root_run systemctl start nginx >/dev/null 2>&1 && \
       ! root_run service nginx start >/dev/null 2>&1; then
        echo "[!] nginx could not be started after the update transaction" >&2
        return 1
    fi
    _UPDATE_WEB_QUIESCED=false
    return 0
}

quiesce_update_web() {
    local wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"
    local deadline pid args web_cgi_running ancestor ancestor_pids=" " writer
    local -a state_writers=(
        setup-api.sh edit-devices.sh edit-topology.sh edit-config.sh
        fabric-api.sh provision-api.sh ai-api.sh assets-api.sh
    )
    [[ "$INSTALL_MODE" == "update" ]] || return 0
    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    if systemctl is-active --quiet nginx 2>/dev/null; then
        if ! root_run systemctl stop nginx; then
            echo "[!] Could not stop nginx for a safe update" >&2
            return 1
        fi
        _UPDATE_WEB_QUIESCED=true
        echo "  Web requests paused for update"
    fi

    # Drain state-changing CGI processes after nginx is stopped. Starting this
    # drain before taking /etc/lldpq.conf.lock avoids deadlocking a request that
    # was already waiting for that lock. Exclude this installer's ancestor
    # launcher (Setup's detached update wrapper), which must remain alive while
    # the update runs. Internal Provision workers are handled by persisted job
    # locks/checks below.
    ancestor=$PPID
    while [[ "$ancestor" =~ ^[0-9]+$ ]] && ((ancestor > 1)); do
        ancestor_pids+="$ancestor "
        ancestor=$(ps -p "$ancestor" -o ppid= 2>/dev/null | tr -d ' ') || break
    done
    deadline=$((SECONDS + wait_seconds))
    while true; do
        web_cgi_running=false
        for writer in "${state_writers[@]}"; do
            while IFS= read -r pid; do
                [[ -n "$pid" && "$pid" != "$$" ]] || continue
                [[ "$ancestor_pids" == *" $pid "* ]] && continue
                args=$(ps -p "$pid" -o args= 2>/dev/null || true)
                [[ -n "$args" ]] || continue
                case "$args" in
                    *"provision-api.sh --upgrade-worker "*|\
                    *"provision-api.sh --discovery-worker "*|\
                    *"provision-api.sh --discovery-schedule"*|\
                    *"provision-api.sh --upgrade-resume"*) continue ;;
                esac
                web_cgi_running=true
                break 2
            done < <(pgrep -f -- "$WEB_ROOT/$writer" 2>/dev/null || true)
        done
        [[ "$web_cgi_running" == "false" ]] && return 0
        if ((SECONDS >= deadline)); then
            echo "[!] Timed out draining active state-changing web requests; update was not started" >&2
            restore_update_web
            return 1
        fi
        sleep 1
    done
}

snapshot_update_file() {
    local path="$1" label="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        root_run cp -a "$path" "$UPDATE_ROLLBACK_DIR/system/$label" || return 1
        root_run touch "$UPDATE_ROLLBACK_DIR/system/$label.present" || return 1
    else
        root_run touch "$UPDATE_ROLLBACK_DIR/system/$label.missing" || return 1
    fi
}

restore_update_file() {
    local path="$1" label="$2"
    if root_run test -f "$UPDATE_ROLLBACK_DIR/system/$label.present"; then
        root_run mkdir -p "$(dirname "$path")" || return 1
        root_run rm -rf "$path" || return 1
        root_run cp -a "$UPDATE_ROLLBACK_DIR/system/$label" "$path" || return 1
    elif root_run test -f "$UPDATE_ROLLBACK_DIR/system/$label.missing"; then
        root_run rm -rf "$path" || return 1
    fi
    return 0
}

snapshot_managed_tree() {
    local source_root="$1" target_root="$2" label="$3" exclude_runtime="${4:-false}"
    local manifest_tmp source_path relative target_path backup_path status
    manifest_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-rollback-manifest.XXXXXX") || return 1
    root_run mkdir -p "$UPDATE_ROLLBACK_DIR/trees/$label/files" || {
        rm -f "$manifest_tmp"; return 1;
    }

    while IFS= read -r -d '' source_path; do
        relative="${source_path#"$source_root"/}"
        # `cp source/*` does not install top-level dotfiles (for example the
        # repository's .DS_Store), so rollback must not touch matching system
        # paths that the update never owns.
        [[ "$relative" == .* ]] && continue
        target_path="$target_root/$relative"
        backup_path="$UPDATE_ROLLBACK_DIR/trees/$label/files/$relative"
        status=missing
        if root_run test -e "$target_path" || root_run test -L "$target_path"; then
            root_run mkdir -p "$(dirname "$backup_path")" || { rm -f "$manifest_tmp"; return 1; }
            root_run cp -a "$target_path" "$backup_path" || { rm -f "$manifest_tmp"; return 1; }
            status=present
        fi
        printf '%s\t%s\n' "$status" "$relative" >> "$manifest_tmp"
    done < <(
        if [[ "$exclude_runtime" == "true" ]]; then
            find "$source_root" \
                \( -path "$source_root/configs" -o -path "$source_root/hstr" -o \
                   -path "$source_root/monitor-results" \) -prune -o \
                \( -type f -o -type l \) -print0
        else
            find "$source_root" \( -type f -o -type l \) -print0
        fi
    )
    # The manifest is the authority used by restore_managed_tree.  Never report
    # a usable rollback snapshot when publishing that authority failed: the
    # cleanup command below used to mask cp's non-zero status.
    if ! root_run cp "$manifest_tmp" "$UPDATE_ROLLBACK_DIR/trees/$label/manifest"; then
        rm -f "$manifest_tmp"
        return 1
    fi
    rm -f "$manifest_tmp"
    return 0
}

restore_managed_tree() {
    local target_root="$1" label="$2" status relative target_path backup_path
    local manifest_tmp restore_failed=false
    root_run test -f "$UPDATE_ROLLBACK_DIR/trees/$label/manifest" || return 0
    manifest_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-restore-manifest.XXXXXX") || return 1
    if ! root_run cat "$UPDATE_ROLLBACK_DIR/trees/$label/manifest" > "$manifest_tmp"; then
        rm -f "$manifest_tmp"
        return 1
    fi
    while IFS=$'\t' read -r status relative; do
        [[ -n "$relative" ]] || continue
        target_path="$target_root/$relative"
        backup_path="$UPDATE_ROLLBACK_DIR/trees/$label/files/$relative"
        if ! root_run rm -rf "$target_path"; then
            restore_failed=true
            continue
        fi
        if [[ "$status" == "present" ]]; then
            if ! root_run mkdir -p "$(dirname "$target_path")" || \
               ! root_run cp -a "$backup_path" "$target_path"; then
                restore_failed=true
            fi
        fi
    done < "$manifest_tmp"
    rm -f "$manifest_tmp"
    [[ "$restore_failed" == "false" ]]
}

systemd_quote_value() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

render_lldpq_recovery_service() {
    local output="$1" user="$2" install_dir="$3" web_root="$4"
    local script_q install_q user_q web_q
    script_q=$(systemd_quote_value "$LLDPQ_BACKUP_IMPORT_HELPER")
    install_q=$(systemd_quote_value "$install_dir")
    user_q=$(systemd_quote_value "$user")
    web_q=$(systemd_quote_value "$web_root")
    cat > "$output" <<EOF
[Unit]
Description=LLDPq retained backup-import recovery
After=local-fs.target
Before=nginx.service fcgiwrap.service lldpq-console.service

[Service]
Type=oneshot
TimeoutStartSec=0
UMask=0077
ExecStart=/usr/bin/python3 $script_q recover --lldpq-dir $install_q --user $user_q --web-root $web_q

[Install]
WantedBy=multi-user.target
EOF
}

render_lldpq_recovery_path() {
    local output="$1" manifest_path="$2" manifest_unit
    # systemd path directives are not ExecStart argument lists.  Quoting the
    # whole value makes the quote character part of the path on systemd 255,
    # so the value no longer begins with '/' and the unit is rejected.  Keep
    # this renderer separate from systemd_quote_value(), validate fail-closed,
    # and only escape literal '%' against systemd specifier expansion.
    if [[ -z "$manifest_path" || "$manifest_path" != /* || \
          "$manifest_path" == *$'\n'* || "$manifest_path" == *$'\r'* ]]; then
        echo "[!] Refusing unsafe recovery manifest path: '$manifest_path'" >&2
        return 1
    fi
    manifest_unit="${manifest_path//\%/%%}"
    cat > "$output" <<EOF
[Unit]
Description=Watch for retained LLDPq backup-import recovery authority
After=local-fs.target

[Path]
PathExists=$manifest_unit
Unit=lldpq-recovery.service

[Install]
WantedBy=multi-user.target
EOF
}

resolve_lldpq_user_home() {
    local user="$1" user_home
    user_home=$(getent passwd "$user" | cut -d: -f6)
    if [[ -z "$user_home" || "$user_home" != /* || \
          "$user_home" == *$'\n'* || "$user_home" == *$'\r'* ]]; then
        echo "[!] Could not resolve a safe home directory for $user" >&2
        return 1
    fi
    printf '%s\n' "$user_home"
}

ensure_update_runtime_dependencies() {
    [[ "$INSTALL_MODE" == "update" ]] || return 0
    local command_name package_name
    local missing_commands="" packages=""

    while read -r command_name package_name; do
        [[ -n "$command_name" ]] || continue
        if ! command -v "$command_name" >/dev/null 2>&1; then
            missing_commands+=" $command_name"
            case " $packages " in
                *" $package_name "*) ;;
                *) packages+=" $package_name" ;;
            esac
        fi
    done <<'DEPENDENCIES'
nginx nginx
fcgiwrap fcgiwrap
python3 python3
flock util-linux
mountpoint util-linux
column bsdextrautils
ssh openssh-client
sshpass sshpass
ip iproute2
ping iputils-ping
pgrep procps
curl curl
unzip unzip
git git
setfacl acl
dhcpd isc-dhcp-server
systemd-analyze systemd
DEPENDENCIES

    if command -v python3 >/dev/null 2>&1; then
        if ! sudo -H -u "$LLDPQ_USER" python3 -m pip --version >/dev/null 2>&1; then
            missing_commands+=" python3-pip"
            packages+=" python3-pip"
        fi
        if ! sudo -H -u "$LLDPQ_USER" python3 -c 'import yaml' >/dev/null 2>&1; then
            missing_commands+=" python3-yaml"
            packages+=" python3-yaml"
        fi
        if ! sudo -H -u "$LLDPQ_USER" python3 -c 'import ruamel.yaml' >/dev/null 2>&1; then
            missing_commands+=" python3-ruamel.yaml"
            packages+=" python3-ruamel.yaml"
        fi
        if ! sudo -H -u "$LLDPQ_USER" python3 -c 'import requests' >/dev/null 2>&1; then
            missing_commands+=" python3-requests"
            packages+=" python3-requests"
        fi
    fi

    [[ -n "$missing_commands" ]] || {
        echo "  Required operating-system runtime dependencies verified"
        return 0
    }

    if [[ "${LLDPQ_OFFLINE_UPDATE:-0}" == "1" ]]; then
        echo "[!] Offline update preflight: required runtime components are missing:${missing_commands}" >&2
        echo "    Install these packages before retrying:${packages}" >&2
        echo "    No package download was attempted and the existing runtime was not changed." >&2
        return 1
    fi

    echo "  Installing missing update dependencies:${packages}"
    sudo apt-get update || {
        echo "[!] Could not refresh package metadata; the existing runtime was not changed" >&2
        return 1
    }
    # Word splitting is intentional: packages contains only fixed literals
    # selected from the table above, never configuration or user input.
    sudo apt-get install -y $packages || {
        echo "[!] Could not install required runtime dependencies; the existing runtime was not changed" >&2
        return 1
    }

    while read -r command_name package_name; do
        [[ -z "$command_name" ]] || command -v "$command_name" >/dev/null 2>&1 || {
            echo "[!] Runtime dependency remains unavailable after install: $command_name" >&2
            return 1
        }
    done <<'DEPENDENCIES'
nginx nginx
fcgiwrap fcgiwrap
python3 python3
flock util-linux
mountpoint util-linux
column bsdextrautils
ssh openssh-client
sshpass sshpass
ip iproute2
ping iputils-ping
pgrep procps
curl curl
unzip unzip
git git
setfacl acl
dhcpd isc-dhcp-server
systemd-analyze systemd
DEPENDENCIES
    sudo -H -u "$LLDPQ_USER" python3 -m pip --version >/dev/null 2>&1 || return 1
    sudo -H -u "$LLDPQ_USER" python3 -c 'import yaml' >/dev/null 2>&1 || return 1
    sudo -H -u "$LLDPQ_USER" python3 -c 'import ruamel.yaml' >/dev/null 2>&1 || return 1
    sudo -H -u "$LLDPQ_USER" python3 -c 'import requests' >/dev/null 2>&1 || return 1
    echo "  Required operating-system runtime dependencies installed and verified"
}

install_update_recovery_guard() {
    [[ "$INSTALL_MODE" == "update" ]] || return 0
    local temporary_dir helper_tmp service_tmp verify_output
    local recovery_was_required=false
    temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-update-recovery.XXXXXX") || return 1
    helper_tmp="$temporary_dir/lldpq-update-recovery.py"
    service_tmp="$temporary_dir/lldpq-update-recovery.service"

    cat > "$helper_tmp" <<'PYTHON'
#!/usr/bin/env python3
"""Restore an LLDPq update interrupted by SIGKILL, reboot or power loss."""

import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

STATE_DIR = Path("/var/lib/lldpq/update-rollback")
MARKER = STATE_DIR / "active.json"
LOCK = STATE_DIR / "recovery.lock"
RUNTIME_ITEMS = ("monitor-results", "lldp-results", "alert-states", "assets.ini")


def fail(message):
    print(f"lldpq-update-recovery: {message}", file=sys.stderr)
    raise RuntimeError(message)


def remove_path(path):
    path = Path(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def copy_node(source, target):
    source, target = Path(source), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        target.symlink_to(os.readlink(source))
    elif source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        shutil.copy2(source, target, follow_symlinks=False)


def read_marker():
    metadata = MARKER.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o077):
        fail("recovery marker has unsafe ownership, type or permissions")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(MARKER, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            fail("recovery marker changed while opening")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if payload.get("version") != 1:
        fail("unsupported recovery marker version")
    return payload


def safe_absolute(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.startswith("/") or "\n" in value or "\r" in value:
        fail(f"unsafe {name} in recovery marker")
    path = Path(value)
    if path in (Path("/"), Path("/etc"), Path("/usr"), Path("/var"), Path("/home")):
        fail(f"unsafe {name} root")
    return path


def validate_paths(payload):
    install_dir = safe_absolute(payload, "install_dir")
    web_root = safe_absolute(payload, "web_root")
    preserve_dir = safe_absolute(payload, "preserve_dir")
    if not preserve_dir.name.startswith(".lldpq-data-preserve."):
        fail("unexpected runtime preservation directory")
    rollback_value = payload.get("rollback_dir")
    rollback_dir = None
    if rollback_value is not None:
        if not isinstance(rollback_value, str) or not rollback_value.startswith("/"):
            fail("unsafe rollback directory")
        rollback_dir = Path(rollback_value)
        if (rollback_dir.parent != install_dir.parent
                or not rollback_dir.name.startswith(".lldpq-update-rollback.")):
            fail("rollback directory is outside the managed install parent")
        metadata = rollback_dir.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            fail("rollback directory has unsafe ownership or type")
    return install_dir, web_root, preserve_dir, rollback_dir


def restore_runtime(preserve_dir, install_dir):
    if not preserve_dir.exists():
        return
    install_dir.mkdir(parents=True, exist_ok=True)
    for name in RUNTIME_ITEMS:
        source = preserve_dir / name
        if not source.exists() and not source.is_symlink():
            continue
        target = install_dir / name
        if target.exists() or target.is_symlink():
            fail(f"refusing to overwrite restored runtime item: {target}")
        os.replace(source, target)
    try:
        preserve_dir.rmdir()
    except OSError:
        if any(preserve_dir.iterdir()):
            fail(f"runtime preservation directory is not empty: {preserve_dir}")


def restore_one(snapshot, target, label):
    present = snapshot / "system" / f"{label}.present"
    missing = snapshot / "system" / f"{label}.missing"
    if present.is_file():
        source = snapshot / "system" / label
        if not source.exists() and not source.is_symlink():
            fail(f"missing snapshot payload for {label}")
        remove_path(target)
        copy_node(source, target)
    elif missing.is_file():
        remove_path(target)
    else:
        fail(f"missing snapshot authority for {label}")


def restore_tree(snapshot, target_root, label):
    manifest = snapshot / "trees" / label / "manifest"
    if not manifest.is_file():
        fail(f"missing managed-tree manifest: {label}")
    files_root = snapshot / "trees" / label / "files"
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        status_value, separator, relative = raw.partition("\t")
        relative_path = Path(relative)
        if (not separator or status_value not in {"present", "missing"}
                or not relative or relative_path.is_absolute() or ".." in relative_path.parts):
            fail(f"unsafe managed-tree entry in {label}")
        target = target_root / relative_path
        remove_path(target)
        if status_value == "present":
            source = files_root / relative_path
            if not source.exists() and not source.is_symlink():
                fail(f"missing managed-tree payload: {label}/{relative}")
            copy_node(source, target)


def restore_snapshot(snapshot, web_root):
    mappings = (
        (Path("/etc/lldpq.conf"), "lldpq.conf"),
        (Path("/etc/cron.d/lldpq"), "cron.d-lldpq"),
        (Path("/etc/crontab"), "crontab"),
        (Path("/etc/dhcp/dhcpd.conf"), "dhcpd.conf"),
        (Path("/etc/dhcp/dhcpd.hosts"), "dhcpd.hosts"),
        (Path("/etc/default/isc-dhcp-server"), "isc-dhcp-default"),
        (Path("/usr/local/libexec/lldpq-backup-import.py"), "backup-import-helper"),
        (Path("/usr/local/libexec/lldpq-auth-users.py"), "auth-users-helper"),
        (Path("/usr/local/libexec/lldpq-uninstall.sh"), "uninstall-script"),
        (Path("/usr/local/libexec/lldpq-uninstall-web.py"), "uninstall-web-gateway"),
        (Path("/etc/sudoers.d/www-data-lldpq"), "sudoers-www-data-lldpq"),
        (Path("/etc/sudoers.d/www-data-provision"), "sudoers-www-data-provision"),
        (Path("/etc/sudoers.d/www-data-lldpq-auth"), "sudoers-www-data-lldpq-auth"),
        (Path("/etc/sudoers.d/www-data-lldpq-uninstall"), "sudoers-www-data-lldpq-uninstall"),
        (Path("/etc/nginx/sites-enabled/lldpq"), "nginx-enabled-lldpq"),
        (Path("/etc/nginx/sites-enabled/default"), "nginx-enabled-default"),
        (web_root / "VERSION", "web-version"),
        (Path("/etc/systemd/system/lldpq-console.service"), "console-service"),
        (Path("/etc/systemd/system/lldpq-recovery.service"), "recovery-service"),
        (Path("/etc/systemd/system/lldpq-recovery.path"), "recovery-path"),
        (Path("/etc/systemd/system/multi-user.target.wants/lldpq-recovery.service"), "recovery-service-wants"),
        (Path("/etc/systemd/system/multi-user.target.wants/lldpq-recovery.path"), "recovery-path-wants"),
        (Path("/etc/rsyslog.d/10-lldpq-dhcp.conf"), "rsyslog-dhcp"),
    )
    for target, label in mappings:
        restore_one(snapshot, target, label)
    # Snapshots created before source provenance was introduced do not have
    # this authority. New snapshots always carry either .present or .missing,
    # allowing a failed first upgrade to remove a newly-created sidecar.
    source_present = snapshot / "system" / "source-manifest.present"
    source_missing = snapshot / "system" / "source-manifest.missing"
    if source_present.is_file() or source_missing.is_file():
        restore_one(snapshot, Path("/etc/lldpq-source.json"), "source-manifest")
    restore_tree(snapshot, Path("/etc"), "etc")
    restore_tree(snapshot, Path("/usr/local/bin"), "bin")
    restore_tree(snapshot, web_root, "web")


def run(command, required=True):
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if required and result.returncode != 0:
        fail("command failed: " + " ".join(command))
    return result.returncode == 0


def recover():
    if not MARKER.exists():
        return
    payload = read_marker()
    install_dir, web_root, preserve_dir, rollback_dir = validate_paths(payload)
    run(["systemctl", "stop", "nginx"], required=False)
    run(["systemctl", "stop", "lldpq-recovery.path"], required=False)

    if rollback_dir is not None:
        previous_install = rollback_dir / "install"
        if previous_install.is_dir():
            if install_dir.exists() or install_dir.is_symlink():
                # A power loss may occur after the success path has already
                # moved some/all preserved runtime into the new tree but
                # before the rollback snapshot commits. Carry those live
                # items back into the previous tree before parking the partial
                # installation, matching the normal EXIT rollback path.
                for name in RUNTIME_ITEMS:
                    preserved = preserve_dir / name
                    current = install_dir / name
                    previous = previous_install / name
                    if (preserved.exists() or preserved.is_symlink()
                            or not (current.exists() or current.is_symlink())
                            or previous.exists() or previous.is_symlink()):
                        continue
                    os.replace(current, previous)
                interrupted = rollback_dir / ("interrupted-install-" + str(int(time.time())))
                os.replace(install_dir, interrupted)
            os.replace(previous_install, install_dir)
        elif not install_dir.is_dir():
            fail("previous installation is unavailable")
        restore_runtime(preserve_dir, install_dir)
        restore_snapshot(rollback_dir, web_root)
    else:
        if not install_dir.is_dir():
            fail("installation disappeared before rollback snapshot was ready")
        restore_runtime(preserve_dir, install_dir)

    run(["systemctl", "daemon-reload"])
    run(["nginx", "-t"])

    # Do not start/restart units from this recovery service.  The unit is
    # ordered Before=nginx/fcgiwrap/console/cron; waiting for one of those jobs
    # here creates a systemd dependency deadlock.  At boot, their queued start
    # jobs continue automatically after this oneshot exits.  An interactive
    # installer performs any required restarts after `systemctl start` returns.

    MARKER.unlink()
    directory_fd = os.open(STATE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if rollback_dir is not None and rollback_dir.exists():
        shutil.rmtree(rollback_dir)


def main():
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(STATE_DIR, 0, 0)
    os.chmod(STATE_DIR, 0o700)
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        recover()
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"lldpq-update-recovery: recovery failed: {error}", file=sys.stderr)
        raise SystemExit(1)
PYTHON

    cat > "$service_tmp" <<EOF
[Unit]
Description=LLDPq interrupted update recovery
After=local-fs.target
Before=nginx.service fcgiwrap.service lldpq-console.service cron.service
ConditionPathExists=$UPDATE_RECOVERY_MARKER

[Service]
Type=oneshot
TimeoutStartSec=0
UMask=0077
ExecStart=/usr/bin/python3 $UPDATE_RECOVERY_HELPER

[Install]
WantedBy=multi-user.target
EOF

    if ! sudo install -d -o root -g root -m 0755 /usr/local/libexec || \
       ! sudo install -d -o root -g root -m 0700 "$UPDATE_RECOVERY_STATE_DIR" || \
       ! sudo install -o root -g root -m 0755 "$helper_tmp" "$UPDATE_RECOVERY_HELPER"; then
        rm -rf "$temporary_dir"
        echo "[!] Could not install interrupted-update recovery helper" >&2
        return 1
    fi
    if command -v systemd-analyze >/dev/null 2>&1; then
        if ! verify_output=$(systemd-analyze verify "$service_tmp" 2>&1); then
            echo "[!] Interrupted-update recovery unit verification failed" >&2
            [[ -z "$verify_output" ]] || printf '%s\n' "$verify_output" >&2
            rm -rf "$temporary_dir"
            return 1
        fi
    fi
    if ! sudo install -o root -g root -m 0644 "$service_tmp" "$UPDATE_RECOVERY_SERVICE"; then
        rm -rf "$temporary_dir"
        echo "[!] Could not install interrupted-update recovery guard" >&2
        return 1
    fi
    rm -rf "$temporary_dir"
    sudo systemctl daemon-reload || return 1
    sudo systemctl enable lldpq-update-recovery.service >/dev/null 2>&1 || return 1
    # Consume an authority retained by a previously killed update before this
    # invocation creates a new transaction.
    if sudo test -f "$UPDATE_RECOVERY_MARKER"; then
        recovery_was_required=true
    fi
    sudo systemctl start lldpq-update-recovery.service || {
        echo "[!] A previous interrupted update could not be recovered" >&2
        return 1
    }
    if [[ "$recovery_was_required" == "true" ]]; then
        # These calls run outside the Before= recovery unit, so they cannot
        # wait on the very oneshot that is issuing them.
        sudo systemctl try-restart fcgiwrap 2>/dev/null || true
        sudo systemctl try-restart lldpq-console.service 2>/dev/null || true
        sudo systemctl try-restart rsyslog 2>/dev/null || true
        if ! sudo systemctl start nginx; then
            echo "[!] Interrupted update was restored, but nginx could not be started" >&2
            return 1
        fi
    fi
    echo "  Interrupted-update boot recovery guard verified"
}

ensure_ruamel_for_lldpq_user() {
    # setup_safety.py is executed as LLDPQ_USER, so checking the interactive
    # installer's Python environment can report a false success.
    if sudo -H -u "$LLDPQ_USER" python3 -c 'import ruamel.yaml' 2>/dev/null; then
        return 0
    fi
    if [[ "$INSTALL_MODE" == "update" && "${LLDPQ_OFFLINE_UPDATE:-0}" == "1" ]]; then
        echo "[!] Offline update preflight: ruamel.yaml is unavailable to $LLDPQ_USER" >&2
        echo "    Install the OS package before retrying: sudo apt-get install python3-ruamel.yaml" >&2
        echo "    No package download was attempted and the existing runtime was not changed." >&2
        return 1
    fi
    echo "  Installing OS package python3-ruamel.yaml..."
    sudo apt-get update || {
        echo "[!] Could not refresh package metadata for ruamel.yaml" >&2
        return 1
    }
    sudo apt-get install -y python3-ruamel.yaml || {
        echo "[!] Could not install python3-ruamel.yaml" >&2
        return 1
    }
    if ! sudo -H -u "$LLDPQ_USER" python3 -c 'import ruamel.yaml' 2>/dev/null; then
        echo "[!] ruamel.yaml is unavailable to $LLDPQ_USER; Notifications cannot preserve comments safely" >&2
        echo "    The selected python3 does not expose the installed OS package" >&2
        return 1
    fi
}

preflight_lldpq_recovery_units() {
    local user_home="$1" user="$2" install_dir="$3" web_root="$4"
    local verify_dir path_file service_file verify_output
    verify_dir=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-recovery-preflight.XXXXXX") || return 1
    path_file="$verify_dir/lldpq-recovery.path"
    service_file="$verify_dir/lldpq-recovery.service"

    if ! render_lldpq_recovery_service \
        "$service_file" "$user" "$install_dir" "$web_root" || \
       ! render_lldpq_recovery_path \
        "$path_file" \
        "$user_home/.lldpq-state/.backup-import-recovery/manifest.json"; then
        rm -rf "$verify_dir"
        return 1
    fi

    if ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "[!] systemd-analyze is required to validate recovery units" >&2
        rm -rf "$verify_dir"
        return 1
    fi
    if ! verify_output=$(systemd-analyze verify "$service_file" "$path_file" 2>&1); then
        echo "[!] Retained-import recovery unit compatibility check failed" >&2
        [[ -n "$verify_output" ]] && printf '%s\n' "$verify_output" >&2
        rm -rf "$verify_dir"
        return 1
    fi
    rm -rf "$verify_dir"
}

show_lldpq_recovery_diagnostics() {
    echo "  Recovery unit diagnostics:" >&2
    sudo systemctl cat lldpq-recovery.service lldpq-recovery.path >&2 || true
    sudo systemd-analyze verify \
        /etc/systemd/system/lldpq-recovery.service \
        /etc/systemd/system/lldpq-recovery.path >&2 || true
    sudo systemctl status lldpq-recovery.service lldpq-recovery.path \
        --no-pager -l >&2 || true
    sudo journalctl -b --no-pager \
        -u lldpq-recovery.service -u lldpq-recovery.path -n 40 >&2 || true
}

prepare_update_rollback() {
    local parent
    parent=$(dirname "$LLDPQ_INSTALL_DIR")
    UPDATE_ROLLBACK_DIR=$(root_run mktemp -d "$parent/.lldpq-update-rollback.XXXXXXXX") || return 1
    # /etc/lldpq.conf.lock deliberately carries no data and is not snapshotted:
    # restore_update_file uses rm+cp, which would split concurrent flock users
    # across two inodes. prepare_shared_lock_files normalizes the stable inode.
    if ! root_run mkdir -p "$UPDATE_ROLLBACK_DIR/system" || \
       ! snapshot_update_file /etc/lldpq.conf lldpq.conf || \
       ! snapshot_update_file "$LLDPQ_SOURCE_MANIFEST" source-manifest || \
       ! snapshot_update_file /etc/cron.d/lldpq cron.d-lldpq || \
       ! snapshot_update_file /etc/crontab crontab || \
       ! snapshot_update_file /etc/dhcp/dhcpd.conf dhcpd.conf || \
       ! snapshot_update_file /etc/dhcp/dhcpd.hosts dhcpd.hosts || \
       ! snapshot_update_file /etc/default/isc-dhcp-server isc-dhcp-default || \
       ! snapshot_update_file "$LLDPQ_BACKUP_IMPORT_HELPER" backup-import-helper || \
       ! snapshot_update_file "$LLDPQ_AUTH_USERS_HELPER" auth-users-helper || \
       ! snapshot_update_file "$LLDPQ_UNINSTALL_SCRIPT" uninstall-script || \
       ! snapshot_update_file "$LLDPQ_UNINSTALL_WEB_GATEWAY" uninstall-web-gateway || \
       ! snapshot_update_file /etc/sudoers.d/www-data-lldpq sudoers-www-data-lldpq || \
       ! snapshot_update_file /etc/sudoers.d/www-data-provision sudoers-www-data-provision || \
       ! snapshot_update_file "$LLDPQ_AUTH_USERS_SUDOERS" sudoers-www-data-lldpq-auth || \
       ! snapshot_update_file "$LLDPQ_UNINSTALL_SUDOERS" sudoers-www-data-lldpq-uninstall || \
       ! snapshot_update_file /etc/nginx/sites-enabled/lldpq nginx-enabled-lldpq || \
       ! snapshot_update_file /etc/nginx/sites-enabled/default nginx-enabled-default || \
       ! snapshot_update_file "$WEB_ROOT/VERSION" web-version || \
       ! snapshot_update_file /etc/systemd/system/lldpq-console.service console-service || \
       ! snapshot_update_file /etc/systemd/system/lldpq-recovery.service recovery-service || \
       ! snapshot_update_file /etc/systemd/system/lldpq-recovery.path recovery-path || \
       ! snapshot_update_file /etc/systemd/system/multi-user.target.wants/lldpq-recovery.service recovery-service-wants || \
       ! snapshot_update_file /etc/systemd/system/multi-user.target.wants/lldpq-recovery.path recovery-path-wants || \
       ! snapshot_update_file /etc/rsyslog.d/10-lldpq-dhcp.conf rsyslog-dhcp || \
       ! snapshot_managed_tree "$LLDPQ_SRC_DIR/etc" /etc etc false || \
       ! snapshot_managed_tree "$LLDPQ_SRC_DIR/bin" /usr/local/bin bin false || \
       ! snapshot_managed_tree "$LLDPQ_SRC_DIR/html" "$WEB_ROOT" web true; then
        root_run rm -rf "$UPDATE_ROLLBACK_DIR" 2>/dev/null || true
        UPDATE_ROLLBACK_DIR=""
        return 1
    fi

    # Publish the snapshot location before the old install tree moves. The
    # boot-time recovery helper can therefore handle a power loss on either
    # side of the rename without guessing which tree is authoritative.
    if ! write_update_recovery_marker rollback_ready "$UPDATE_ROLLBACK_DIR"; then
        root_run rm -rf "$UPDATE_ROLLBACK_DIR" 2>/dev/null || true
        UPDATE_ROLLBACK_DIR=""
        return 1
    fi

    if [[ -d "$LLDPQ_INSTALL_DIR" ]]; then
        # Publish the rollback intent before the destructive rename. If the
        # installer receives TERM/HUP/INT while waiting for mv, the EXIT
        # handler must already know that the previous tree belongs here.
        UPDATE_ROLLBACK_HAD_INSTALL=true
        UPDATE_ROLLBACK_ACTIVE=true
        if ! root_run mv "$LLDPQ_INSTALL_DIR" "$UPDATE_ROLLBACK_DIR/install"; then
            UPDATE_ROLLBACK_ACTIVE=false
            UPDATE_ROLLBACK_HAD_INSTALL=false
            write_update_recovery_marker preserving "" || true
            root_run rm -rf "$UPDATE_ROLLBACK_DIR" 2>/dev/null || true
            UPDATE_ROLLBACK_DIR=""
            return 1
        fi
    else
        UPDATE_ROLLBACK_ACTIVE=true
    fi
}

rollback_failed_update() {
    [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" && -n "$UPDATE_ROLLBACK_DIR" ]] || return 0
    echo "[!] Update failed; restoring the previous LLDPq runtime and system configuration" >&2
    UPDATE_ROLLBACK_CORE_RESTORED=false
    UPDATE_ROLLBACK_RESTORED_VERSION=""
    local rollback_restore_failed=false
    local rollback_install_available=false
    local rollback_install_still_live=false
    if [[ "$UPDATE_ROLLBACK_HAD_INSTALL" == "true" ]]; then
        if root_run test -d "$UPDATE_ROLLBACK_DIR/install"; then
            rollback_install_available=true
        elif root_run test -d "$LLDPQ_INSTALL_DIR"; then
            # A signal may arrive after rollback intent is published but
            # before rename(2) executes. In that state the original tree is
            # already exactly where it belongs and must not be removed.
            rollback_install_still_live=true
        else
            rollback_restore_failed=true
        fi
    fi
    if [[ "$rollback_install_available" == "true" ]]; then
        local runtime_dir
        for runtime_dir in monitor-results lldp-results alert-states assets.ini; do
            # During most of the update the original runtime data lives in
            # _DATA_PRESERVE.  Do not replace it with a newly copied empty
            # runtime directory: the EXIT handler moves the preserved data
            # back after this code tree has been restored.  After the normal
            # restore phase _DATA_PRESERVE is empty/removed, so a later
            # failure still carries the live runtime tree into the rollback.
            if [[ -n "${_DATA_PRESERVE:-}" ]] && \
               root_run test -e "$_DATA_PRESERVE/$runtime_dir"; then
                continue
            fi
            if root_run test -e "$LLDPQ_INSTALL_DIR/$runtime_dir" && \
               ! root_run test -e "$UPDATE_ROLLBACK_DIR/install/$runtime_dir"; then
                if ! root_run mv "$LLDPQ_INSTALL_DIR/$runtime_dir" \
                    "$UPDATE_ROLLBACK_DIR/install/" 2>/dev/null; then
                    rollback_restore_failed=true
                fi
            fi
        done
    fi
    if [[ "$rollback_install_still_live" == "true" ]] || \
       { [[ "$UPDATE_ROLLBACK_HAD_INSTALL" == "true" ]] && \
         [[ "$rollback_install_available" != "true" ]]; }; then
        # Keep the partial current tree in place when the previous install
        # copy itself is unexpectedly unavailable.
        :
    elif ! root_run rm -rf "$LLDPQ_INSTALL_DIR" 2>/dev/null; then
        rollback_restore_failed=true
    elif [[ "$rollback_install_available" == "true" ]] && \
         ! root_run mv "$UPDATE_ROLLBACK_DIR/install" "$LLDPQ_INSTALL_DIR" 2>/dev/null; then
        rollback_restore_failed=true
    fi
    root_run systemctl stop lldpq-recovery.path lldpq-recovery.service \
        >/dev/null 2>&1 || true
    restore_update_file /etc/lldpq.conf lldpq.conf || rollback_restore_failed=true
    restore_update_file "$LLDPQ_SOURCE_MANIFEST" source-manifest || rollback_restore_failed=true
    restore_update_file /etc/cron.d/lldpq cron.d-lldpq || rollback_restore_failed=true
    restore_update_file /etc/crontab crontab || rollback_restore_failed=true
    restore_update_file /etc/dhcp/dhcpd.conf dhcpd.conf || rollback_restore_failed=true
    restore_update_file /etc/dhcp/dhcpd.hosts dhcpd.hosts || rollback_restore_failed=true
    restore_update_file /etc/default/isc-dhcp-server isc-dhcp-default || rollback_restore_failed=true
    restore_update_file "$LLDPQ_BACKUP_IMPORT_HELPER" backup-import-helper || rollback_restore_failed=true
    restore_update_file "$LLDPQ_AUTH_USERS_HELPER" auth-users-helper || rollback_restore_failed=true
    restore_update_file "$LLDPQ_UNINSTALL_SCRIPT" uninstall-script || rollback_restore_failed=true
    restore_update_file "$LLDPQ_UNINSTALL_WEB_GATEWAY" uninstall-web-gateway || rollback_restore_failed=true
    restore_update_file /etc/sudoers.d/www-data-lldpq sudoers-www-data-lldpq || rollback_restore_failed=true
    restore_update_file /etc/sudoers.d/www-data-provision sudoers-www-data-provision || rollback_restore_failed=true
    restore_update_file "$LLDPQ_AUTH_USERS_SUDOERS" sudoers-www-data-lldpq-auth || rollback_restore_failed=true
    restore_update_file "$LLDPQ_UNINSTALL_SUDOERS" sudoers-www-data-lldpq-uninstall || rollback_restore_failed=true
    restore_update_file /etc/nginx/sites-enabled/lldpq nginx-enabled-lldpq || rollback_restore_failed=true
    restore_update_file /etc/nginx/sites-enabled/default nginx-enabled-default || rollback_restore_failed=true
    restore_update_file "$WEB_ROOT/VERSION" web-version || rollback_restore_failed=true
    restore_update_file /etc/systemd/system/lldpq-console.service console-service || rollback_restore_failed=true
    restore_update_file /etc/systemd/system/lldpq-recovery.service recovery-service || rollback_restore_failed=true
    restore_update_file /etc/systemd/system/lldpq-recovery.path recovery-path || rollback_restore_failed=true
    restore_update_file /etc/systemd/system/multi-user.target.wants/lldpq-recovery.service recovery-service-wants || rollback_restore_failed=true
    restore_update_file /etc/systemd/system/multi-user.target.wants/lldpq-recovery.path recovery-path-wants || rollback_restore_failed=true
    restore_update_file /etc/rsyslog.d/10-lldpq-dhcp.conf rsyslog-dhcp || rollback_restore_failed=true
    restore_managed_tree /etc etc || rollback_restore_failed=true
    restore_managed_tree /usr/local/bin bin || rollback_restore_failed=true
    restore_managed_tree "$WEB_ROOT" web || rollback_restore_failed=true
    root_run systemctl daemon-reload 2>/dev/null || rollback_restore_failed=true
    if root_run test -L /etc/systemd/system/multi-user.target.wants/lldpq-recovery.service; then
        root_run systemctl start lldpq-recovery.service 2>/dev/null || rollback_restore_failed=true
    fi
    if root_run test -L /etc/systemd/system/multi-user.target.wants/lldpq-recovery.path; then
        root_run systemctl start lldpq-recovery.path 2>/dev/null || rollback_restore_failed=true
    fi
    # nginx stays stopped until runtime data is back and the rollback outcome
    # is final. Starting it here would expose a half-restored dashboard and
    # allow new state-changing requests to race the remaining transaction.
    if ! root_run nginx -t >/dev/null 2>&1; then
        rollback_restore_failed=true
    fi
    root_run systemctl try-restart fcgiwrap 2>/dev/null || rollback_restore_failed=true
    root_run systemctl try-restart lldpq-console.service 2>/dev/null || rollback_restore_failed=true
    root_run systemctl try-restart rsyslog 2>/dev/null || rollback_restore_failed=true

    if [[ "$rollback_restore_failed" == "true" ]]; then
        echo "[!] Automatic rollback was incomplete; recovery snapshot retained at: $UPDATE_ROLLBACK_DIR" >&2
        return 1
    fi
    UPDATE_ROLLBACK_RESTORED_VERSION=$(
        root_run sed -n '1p' "$WEB_ROOT/VERSION" 2>/dev/null || true
    )
    if ! clear_update_recovery_marker; then
        echo "[!] Rollback completed, but its durable recovery marker could not be cleared" >&2
        return 1
    fi
    root_run rm -rf "$UPDATE_ROLLBACK_DIR" 2>/dev/null || \
        echo "[!] Rollback succeeded, but its completed snapshot remains at: $UPDATE_ROLLBACK_DIR" >&2
    UPDATE_ROLLBACK_ACTIVE=false
    UPDATE_ROLLBACK_CORE_RESTORED=true
    return 0
}

commit_update_rollback() {
    [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" ]] || return 0
    local completed_rollback_dir="$UPDATE_ROLLBACK_DIR"
    if ! clear_update_recovery_marker; then
        echo "[!] Update is complete, but its durable recovery marker could not be cleared; rollback snapshot retained" >&2
        return 1
    fi
    UPDATE_ROLLBACK_ACTIVE=false
    UPDATE_ROLLBACK_DIR=""
    root_run rm -rf "$completed_rollback_dir" 2>/dev/null || \
        echo "  [!] Completed update rollback snapshot could not be removed: $completed_rollback_dir" >&2
}

restore_preserved_runtime_data() {
    local preserve_dir="${_DATA_PRESERVE:-}"
    local runtime_dir restore_failed=false
    [[ -n "$preserve_dir" && -d "$preserve_dir" ]] || return 0

    for runtime_dir in monitor-results lldp-results alert-states assets.ini; do
        if [[ -e "$preserve_dir/$runtime_dir" || \
              -L "$preserve_dir/$runtime_dir" ]]; then
            # The pre-update preservation copy is authoritative while the
            # transaction locks are still held. A partial new install or a
            # restored old tree may already contain an empty/default runtime
            # path; leaving that collision in place strands the real data and
            # keeps nginx fail-closed. Match the normal success-path restore:
            # remove only this known runtime target, then move its preserved
            # counterpart back atomically on the same filesystem.
            if ! root_run rm -rf -- "$LLDPQ_INSTALL_DIR/$runtime_dir" 2>/dev/null || \
               ! root_run mv -- "$preserve_dir/$runtime_dir" \
                    "$LLDPQ_INSTALL_DIR/" 2>/dev/null; then
                restore_failed=true
                echo "[!] Preserved runtime data could not be restored: $preserve_dir/$runtime_dir" >&2
            fi
        fi
    done
    if [[ "$restore_failed" == "true" ]]; then
        echo "[!] Preserved runtime data remains at $preserve_dir; it was not deleted" >&2
        return 1
    fi
    if find "$preserve_dir" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
        echo "[!] Preserved runtime data remains at $preserve_dir; it was not deleted" >&2
        return 1
    fi
    if ! rmdir "$preserve_dir" 2>/dev/null; then
        echo "[!] Empty runtime preserve directory could not be removed: $preserve_dir" >&2
        return 1
    fi
    return 0
}

lldpq_install_exit_handler() {
    local status="$1"
    local disposition="${2:-exit}"
    local rollback_attempted=false
    local rollback_core_ok=true
    local runtime_restore_ok=true
    local web_restore_ok=true
    local final_tree_safe=true

    if [[ -n "${_config_validation_snapshot:-}" ]]; then
        rm -f -- "$_config_validation_snapshot" 2>/dev/null || true
        _config_validation_snapshot=""
    fi

    if [[ "$disposition" == "return" ]]; then
        # Keep the installed EXIT trap armed throughout explicit success-path
        # finalization. A TERM/HUP/INT must still enter the recovery path while
        # runtime data, nginx startup or rollback commit is in progress.
        _UPDATE_FINALIZE_IN_PROGRESS=true
    else
        trap - EXIT
        if [[ "${_UPDATE_FINALIZE_IN_PROGRESS:-false}" == "true" && \
              "$UPDATE_ROLLBACK_ACTIVE" == "true" ]]; then
            # A signal may arrive after nginx starts but before the rollback
            # snapshot commits. Stop it again before restoring the old tree.
            if root_run systemctl stop nginx >/dev/null 2>&1; then
                _UPDATE_WEB_QUIESCED=true
            else
                web_restore_ok=false
                echo "[!] Could not re-quiesce nginx during interrupted update finalization" >&2
            fi
        fi
    fi

    # A failed update restores the previous executable/config tree first; its
    # preserved runtime data is then moved back into that restored tree.
    if (( status != 0 )) && \
       [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" && -n "$UPDATE_ROLLBACK_DIR" ]]; then
        rollback_attempted=true
        rollback_failed_update || rollback_core_ok=false
    fi

    if ! restore_preserved_runtime_data; then
        runtime_restore_ok=false
        if (( status == 0 )); then
            # Runtime data is part of the update transaction. Never report a
            # successful update with missing/currently-preserved reports.
            status=1
            if [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" && -n "$UPDATE_ROLLBACK_DIR" ]]; then
                rollback_attempted=true
                rollback_failed_update || rollback_core_ok=false
                # rollback_failed_update carries already-restored runtime
                # directories into the old tree. Retry any items that were
                # still left in the preservation directory.
                runtime_restore_ok=true
                restore_preserved_runtime_data || runtime_restore_ok=false
            fi
        fi
    fi

    if [[ "$runtime_restore_ok" != "true" ]] || \
       { [[ "$rollback_attempted" == "true" ]] && \
         { [[ "$rollback_core_ok" != "true" ]] || \
           [[ "$UPDATE_ROLLBACK_CORE_RESTORED" != "true" ]]; }; }; then
        final_tree_safe=false
    fi

    # Only expose the web UI after its runtime data and final code/config tree
    # are in place. The process/provision locks are intentionally retained
    # through this start, so any immediately-arriving mutation must wait until
    # the transaction commits. An incomplete rollback remains fail-closed.
    if [[ "$final_tree_safe" == "true" ]]; then
        if ! restore_update_web; then
            web_restore_ok=false
            if (( status == 0 )); then
                # A failed systemd start can very rarely leave worker
                # processes behind. Re-quiesce before replacing its files.
                root_run systemctl stop nginx >/dev/null 2>&1 || \
                    root_run service nginx stop >/dev/null 2>&1 || true
                _UPDATE_WEB_QUIESCED=true
                status=1
                if [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" && -n "$UPDATE_ROLLBACK_DIR" ]]; then
                    rollback_attempted=true
                    rollback_failed_update || rollback_core_ok=false
                    # The failed start leaves the quiesced flag set. Retry once
                    # only when the previous tree and runtime are fully back.
                    if [[ "$rollback_core_ok" == "true" && \
                          "$UPDATE_ROLLBACK_CORE_RESTORED" == "true" && \
                          "$runtime_restore_ok" == "true" ]]; then
                        web_restore_ok=true
                        restore_update_web || web_restore_ok=false
                    fi
                fi
            fi
        fi
    else
        web_restore_ok=false
        echo "[!] Web service remains stopped because update recovery is incomplete" >&2
    fi

    # Discard the previous runtime snapshot only after data restoration and a
    # verified nginx start. Until this point every success-path failure can
    # still roll back to the prior installation.
    if (( status == 0 )); then
        if ! commit_update_rollback; then
            status=1
            final_tree_safe=false
        fi
    elif [[ "$UPDATE_ROLLBACK_ACTIVE" != "true" && \
            "$runtime_restore_ok" == "true" && \
            "$web_restore_ok" == "true" && \
            "$final_tree_safe" == "true" ]]; then
        # Failures before prepare_update_rollback leave the original tree in
        # place. Once its temporarily moved runtime has been restored, the
        # preserving-phase marker is no longer needed.
        clear_update_recovery_marker || \
            echo "[!] Recovered the original runtime, but could not clear its durable update marker" >&2
    fi

    # Never let the recovery trigger inherit process-wide update locks.
    # Keeping these descriptors open in a long-running child would block every
    # subsequent collection or Provision job indefinitely.
    release_update_provision_locks
    release_update_config_lock
    release_update_process_lock
    release_install_lifecycle_lock
    if (( status != 0 )) && [[ "${_UPDATE_PROCESSES_STOPPED:-false}" == "true" ]] && \
       [[ -x /usr/local/bin/lldpq-trigger ]]; then
        # The monitor run that was interrupted will be picked up by cron. Bring
        # the lightweight web-trigger daemon back immediately after rollback.
        sudo -u "${LLDPQ_USER:-$(id -un)}" nohup /usr/local/bin/lldpq-trigger \
            >/dev/null 2>&1 &
    fi
    if [[ "$rollback_attempted" == "true" ]]; then
        if [[ "$rollback_core_ok" == "true" && \
              "$UPDATE_ROLLBACK_CORE_RESTORED" == "true" && \
              "$runtime_restore_ok" == "true" && \
              "$web_restore_ok" == "true" ]]; then
            if [[ -n "$UPDATE_ROLLBACK_RESTORED_VERSION" ]]; then
                echo "[!] Update failed, but automatic rollback completed; active runtime remains $UPDATE_ROLLBACK_RESTORED_VERSION. The requested update was not installed." >&2
            else
                echo "[!] Update failed, but automatic rollback completed; the previous runtime remains active. The requested update was not installed." >&2
            fi
        else
            echo "[!] Automatic rollback was incomplete; review the retained paths and errors above before retrying." >&2
        fi
    fi
    if [[ "$disposition" == "return" ]]; then
        _UPDATE_FINALIZE_IN_PROGRESS=false
        trap - EXIT
        return "$status"
    fi
    exit "$status"
}

# Test harnesses source the helpers without executing installer side effects.
if [[ "${LLDPQ_INSTALL_LIB_ONLY:-false}" == "true" ]]; then
    return 0 2>/dev/null || exit 0
fi

# Step counter for progress display
STEP=0
step() { STEP=$((STEP + 1)); printf "\n[%02d] %s\n" "$STEP" "$1"; }

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
AUTO_YES=false
ENABLE_TELEMETRY=false
DISABLE_TELEMETRY=false
FORCE_BACKUP=false
REPLACE_DHCP_CONFIG=false
# Remember where we were installed FROM (the source repo) so the web "Update"
# button can later git pull + reinstall from here (stored as LLDPQ_SRC in lldpq.conf).
LLDPQ_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Keep caller intent separate from values loaded from an existing config. A
# clean install must not carry an old SKIP_L1 preference into the new config,
# but an explicit environment override remains supported.
_CALLER_SKIP_L1_WAS_SET=false
_CALLER_SKIP_L1_VALUE=""
if [[ -n "${SKIP_L1+x}" ]]; then
    _CALLER_SKIP_L1_WAS_SET=true
    _CALLER_SKIP_L1_VALUE="$SKIP_L1"
fi

for arg in "$@"; do
    case $arg in
        -y) AUTO_YES=true ;;
        --backup) FORCE_BACKUP=true ;;
        --replace-dhcp-config) REPLACE_DHCP_CONFIG=true ;;
        --enable-telemetry) ENABLE_TELEMETRY=true ;;
        --disable-telemetry) DISABLE_TELEMETRY=true ;;
        -h|--help)
            echo "Usage: ./install.sh [-y] [--backup] [--replace-dhcp-config] [--enable-telemetry] [--disable-telemetry]"
            echo ""
            echo "Automatically detects existing installation:"
            echo "  No existing install → Fresh install (packages, configs, everything)"
            echo "  Existing install    → Update mode (backup, preserve configs, update files)"
            echo ""
            echo "Options:"
            echo "  -y                  Auto-yes to all prompts"
            echo "  --backup            (update mode) take a full backup before updating"
            echo "  --replace-dhcp-config"
            echo "                      Replace a non-LLDPq dhcpd.conf after validation + backup"
            echo "  --enable-telemetry  Enable streaming telemetry (requires Docker)"
            echo "  --disable-telemetry Disable streaming telemetry"
            exit 0
            ;;
    esac
done

LLDPQ_CONFIG_FILE="${LLDPQ_CONFIG_FILE:-/etc/lldpq.conf}"
if ! load_lldpq_config "$LLDPQ_CONFIG_FILE"; then
    echo "[!] Existing runtime configuration could not be read safely: $LLDPQ_CONFIG_FILE" >&2
    exit 1
fi

# ============================================================================
# TELEMETRY-ONLY MODE (early exit — no other changes needed)
# ============================================================================
if [[ "$ENABLE_TELEMETRY" == "true" ]] || [[ "$DISABLE_TELEMETRY" == "true" ]]; then
    if [[ ! -f "$LLDPQ_CONFIG_FILE" ]] || \
       [[ ! "${LLDPQ_USER:-}" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]] || \
       ! id "$LLDPQ_USER" >/dev/null 2>&1; then
        echo "[!] Telemetry-only mode requires a valid existing LLDPq installation" >&2
        exit 1
    fi
    # LLDPQ_DIR was loaded as data above; do not source the group-writable file.
    LLDPQ_INSTALL_DIR="${LLDPQ_DIR:-}"
    if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
        if [[ $EUID -eq 0 ]]; then
            LLDPQ_INSTALL_DIR="/opt/lldpq"
        else
            LLDPQ_INSTALL_DIR="$HOME/lldpq"
        fi
    fi
    LLDPQ_INSTALL_DIR=$(guard_managed_path "LLDPq install" "$LLDPQ_INSTALL_DIR" 2) || exit 1
    LLDPQ_INSTALL_DIR=$(guard_recursive_target "LLDPq install" "$LLDPQ_INSTALL_DIR" false) || exit 1
    if [[ -e "$LLDPQ_UNINSTALL_WEB_GATEWAY" || -L "$LLDPQ_UNINSTALL_WEB_GATEWAY" ||
          -e "$LLDPQ_UNINSTALL_ACTIVE_MARKER" || -L "$LLDPQ_UNINSTALL_ACTIVE_MARKER" ]]; then
        acquire_install_lifecycle_lock || exit 1
    fi

    if [[ "$ENABLE_TELEMETRY" == "true" ]]; then
        echo "Enabling Streaming Telemetry..."
        echo ""

        if ! command -v docker &> /dev/null; then
            echo "Docker not found. Installing Docker..."
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sudo sh /tmp/get-docker.sh
            sudo usermod -aG docker "$(whoami)"
            rm /tmp/get-docker.sh
            echo "Docker installed successfully"
            echo "[!] NOTE: You may need to logout/login for Docker group to take effect"
        else
            echo "Docker found: $(docker --version)"
        fi

        # The web UI runs as www-data and lldpq scripts as the current user; both need
        # Docker socket access to (re)start the telemetry stack from the UI later.
        sudo usermod -aG docker www-data 2>/dev/null || true
        sudo usermod -aG docker "$(whoami)" 2>/dev/null || true
        sudo systemctl restart fcgiwrap 2>/dev/null || sudo service fcgiwrap restart 2>/dev/null || true

        if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
            echo "Installing docker-compose..."
            sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            sudo chmod +x /usr/local/bin/docker-compose
            echo "docker-compose installed"
        fi

        if [[ -n "${TELEMETRY_ENABLED+x}" ]]; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=true/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=true" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        if [[ -z "${PROMETHEUS_URL+x}" ]]; then
            echo "PROMETHEUS_URL=http://localhost:9090" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        echo ""
        echo "Telemetry support enabled!"
        echo ""

        if [[ ! -f /etc/docker/daemon.json ]]; then
            echo "Configuring Docker storage driver..."
            sudo mkdir -p /etc/docker
            echo '{"storage-driver": "vfs"}' | sudo tee /etc/docker/daemon.json > /dev/null
            sudo systemctl restart docker
        fi

        if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]; then
            echo ""
            echo "Starting telemetry stack..."
            cd "$LLDPQ_INSTALL_DIR/telemetry"
            if docker compose up -d 2>&1; then
                :
            elif docker-compose up -d 2>&1; then
                :
            elif sudo docker compose up -d 2>&1; then
                :
            elif sudo docker-compose up -d 2>&1; then
                :
            else
                echo "[!] Could not start stack. Try manually:"
                echo "    cd $LLDPQ_INSTALL_DIR/telemetry && sudo docker compose up -d"
            fi
            cd - > /dev/null

            sleep 3
            if docker ps --filter "name=lldpq-prometheus" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                echo ""
                echo "Telemetry stack is running:"
                echo "  - OTEL Collector: http://localhost:4317"
                echo "  - Prometheus:     http://localhost:9090"
                echo "  - Alertmanager:   http://localhost:9093"
            fi
        else
            echo "[!] Telemetry files not found. Run ./install.sh first."
        fi

        echo ""
        echo "Next step: Enable telemetry on switches from web UI:"
        echo "  Telemetry → Configuration → Enable Telemetry"

    elif [[ "$DISABLE_TELEMETRY" == "true" ]]; then
        echo "Disabling Streaming Telemetry..."
        echo ""
        echo "This will completely remove the telemetry stack and all stored metrics."

        if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]; then
            cd "$LLDPQ_INSTALL_DIR/telemetry"
            echo "Stopping and removing containers..."
            docker-compose down -v 2>/dev/null || docker compose down -v 2>/dev/null || true
            cd - > /dev/null
            echo "Telemetry stack removed (containers + volumes)"
        fi

        sudo sed -i '/^TELEMETRY_COLLECTOR_IP=/d' /etc/lldpq.conf 2>/dev/null || true
        sudo sed -i '/^TELEMETRY_COLLECTOR_PORT=/d' /etc/lldpq.conf 2>/dev/null || true
        sudo sed -i '/^TELEMETRY_COLLECTOR_VRF=/d' /etc/lldpq.conf 2>/dev/null || true

        if [[ -n "${TELEMETRY_ENABLED+x}" ]]; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=false/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=false" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        echo "Telemetry support disabled"
    fi

    normalize_installed_lldpq_config_access || exit 1
    exit 0
fi

# Reject malformed schedules before update mode stops processes or replaces
# any files. The same semantic validator is used by Docker startup.
validate_cron_schedule "${LLDPQ_CRON:-*/10 * * * *}" || {
    echo "[!] Invalid LLDPQ_CRON schedule: ${LLDPQ_CRON:-}" >&2
    exit 1
}
validate_cron_schedule "${GETCONF_CRON:-0 */12 * * *}" || {
    echo "[!] Invalid GETCONF_CRON schedule: ${GETCONF_CRON:-}" >&2
    exit 1
}

# ============================================================================
# INITIAL CHECKS
# ============================================================================

# Check if running via sudo from non-root user (causes $HOME issues)
if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]] && [[ "$SUDO_USER" != "root" ]]; then
    echo "[!] Please run without sudo: ./install.sh"
    echo "    The script will ask for sudo when needed"
    exit 1
fi

# Check if we're in the same canonical lldpq-src directory as this script. The
# installer copies relative paths throughout, so recording BASH_SOURCE while
# installing a different current directory would create false provenance.
if [[ "$(pwd -P)" != "$LLDPQ_SRC_DIR" ]] || \
   [[ ! -f "README.md" ]] || [[ ! -d "lldpq" ]]; then
    echo "[!] Please run this script from the lldpq-src directory"
    echo "    Make sure you're in the directory containing README.md and lldpq/"
    exit 1
fi
if ! manage_lldpq_source_manifest validate "$LLDPQ_SRC_DIR"; then
    echo "[!] Refusing an unrecognized or unsafe LLDPq source checkout" >&2
    exit 1
fi

# ============================================================================
# DIRECTORY SETUP
# ============================================================================

# Read LLDPQ_INSTALL_DIR from the safely parsed existing config (if available).
LLDPQ_INSTALL_DIR="${LLDPQ_DIR:-}"

# Default based on user
if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
    if [[ $EUID -eq 0 ]]; then
        LLDPQ_INSTALL_DIR="/opt/lldpq"
    else
        LLDPQ_INSTALL_DIR="$HOME/lldpq"
    fi
fi

LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

LLDPQ_INSTALL_DIR=$(guard_managed_path "LLDPq install" "$LLDPQ_INSTALL_DIR" 2) || exit 1
WEB_ROOT=$(guard_managed_path "web root" "$WEB_ROOT" 2) || exit 1
LLDPQ_INSTALL_DIR=$(guard_recursive_target "LLDPq install" "$LLDPQ_INSTALL_DIR" false) || exit 1
WEB_ROOT=$(guard_recursive_target "web root" "$WEB_ROOT" true) || exit 1
if paths_overlap "$LLDPQ_INSTALL_DIR" "$WEB_ROOT"; then
    echo "[!] LLDPQ_DIR and WEB_ROOT must not overlap" >&2
    exit 1
fi
if [[ ! "$LLDPQ_USER" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]]; then
    echo "[!] Invalid LLDPQ_USER in configuration: '$LLDPQ_USER'" >&2
    exit 1
fi
_SOURCE_PROTECT_HOME=$(resolve_lldpq_user_home "$LLDPQ_USER") || exit 1
for _source_protected_path in \
    "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" \
    "$_SOURCE_PROTECT_HOME/.lldpq-state" "$_SOURCE_PROTECT_HOME/.ssh"; do
    if paths_overlap "$LLDPQ_SRC_DIR" "$_source_protected_path"; then
        echo "[!] LLDPQ_SRC must not overlap a managed or preserved LLDPq path:" >&2
        echo "    source:    $LLDPQ_SRC_DIR" >&2
        echo "    protected: $_source_protected_path" >&2
        echo "    Move the source checkout and run install.sh again." >&2
        exit 1
    fi
done
case "$LLDPQ_SRC_DIR" in
    "$_SOURCE_PROTECT_HOME"/lldpq-backup-*)
        echo "[!] LLDPQ_SRC must not be inside a preserved ~/lldpq-backup-* snapshot" >&2
        echo "    Move the source checkout and run install.sh again." >&2
        exit 1
        ;;
esac
unset _SOURCE_PROTECT_HOME _source_protected_path
if [[ -e "$LLDPQ_UNINSTALL_WEB_GATEWAY" || -L "$LLDPQ_UNINSTALL_WEB_GATEWAY" ||
      -e "$LLDPQ_UNINSTALL_ACTIVE_MARKER" || -L "$LLDPQ_UNINSTALL_ACTIVE_MARKER" ]]; then
    acquire_install_lifecycle_lock || exit 1
fi

# Running as root advisory
if [[ $EUID -eq 0 ]]; then
    echo ""
    echo "[!] Running as root"
    echo "    Files will be installed in $LLDPQ_INSTALL_DIR"
    echo "    Recommended: Install as a regular user (e.g., 'cumulus' or 'lldpq')"
    echo "    This allows better SSH key management and security."
    echo ""
    sleep 2
fi

quiesce_recovery_units_for_fresh_install() {
    local unit clean_user_home
    # A clean/fresh install deliberately discards retained transactions. Stop
    # their oneshots before deleting /var/lib/lldpq; otherwise an already
    # running recovery process can keep nginx/fcgiwrap start jobs waiting even
    # after its marker directory has been removed.
    for unit in lldpq-recovery.path lldpq-recovery.service \
                lldpq-update-recovery.service; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            if ! sudo timeout 30s systemctl stop "$unit"; then
                echo "[!] Could not stop stale recovery unit: $unit" >&2
                return 1
            fi
        fi
        sudo systemctl disable "$unit" >/dev/null 2>&1 || true
    done
    # Prevent the old cron/trigger generation from starting collectors while
    # the fresh tree and its locks are being rebuilt.
    sudo rm -f /etc/cron.d/lldpq
    pkill -f "$LLDPQ_INSTALL_DIR/monitor.sh" 2>/dev/null || true
    pkill -f "/usr/local/bin/lldpq-trigger" 2>/dev/null || true
    sudo systemctl stop lldpq-console.service 2>/dev/null || true
    sudo rm -f \
        /etc/systemd/system/lldpq-recovery.path \
        /etc/systemd/system/lldpq-recovery.service \
        /etc/systemd/system/lldpq-update-recovery.service \
        /etc/systemd/system/multi-user.target.wants/lldpq-recovery.path \
        /etc/systemd/system/multi-user.target.wants/lldpq-recovery.service \
        /etc/systemd/system/multi-user.target.wants/lldpq-update-recovery.service \
        /usr/local/libexec/lldpq-update-recovery.py
    # A clean install must not leave a previous checkout identity authoritative
    # if this install stops before publishing its own validated manifest.
    sudo rm -f -- "$LLDPQ_SOURCE_MANIFEST" || return 1
    clean_user_home=$(resolve_lldpq_user_home "$LLDPQ_USER") || return 1
    # Clean install means no retained transaction may replay old config/state
    # after the new files are written.  This also removes stale Setup upgrade
    # markers and config-collection state from the prior installation.
    sudo rm -rf -- "$clean_user_home/.lldpq-state"
    sudo systemctl daemon-reload
}

# ============================================================================
# MODE DETECTION
# ============================================================================
INSTALL_MODE="fresh"
BACKUP_DIR=""

if [[ -f /etc/lldpq.conf ]] || [[ -f /etc/lldpq-users.conf ]] || [[ -d /var/lib/lldpq ]]; then
    echo ""
    echo "Existing LLDPq installation detected:"
    [[ -f /etc/lldpq.conf ]] && echo "  • /etc/lldpq.conf"
    [[ -f /etc/lldpq-users.conf ]] && echo "  • /etc/lldpq-users.conf (user credentials)"
    [[ -d /var/lib/lldpq ]] && echo "  • /var/lib/lldpq/ (sessions)"
    [[ -d "$LLDPQ_INSTALL_DIR" ]] && echo "  • $LLDPQ_INSTALL_DIR/ (scripts and configs)"
    echo ""
    echo "  Options:"
    echo "  1. Update — preserve configs, backup existing data (default)"
    echo "  2. Clean install — remove everything and start fresh"
    echo ""
    if [[ "$AUTO_YES" == "true" ]]; then
        echo "  Using update mode (auto-yes)"
        INSTALL_MODE="update"
    else
        read -p "  Clean install? [y/N]: " clean_response
        if [[ "$clean_response" =~ ^[Yy]$ ]]; then
            echo "  Cleaning existing installation..."
            quiesce_recovery_units_for_fresh_install || exit 1
            sudo rm -f /etc/lldpq.conf
            sudo rm -f /etc/lldpq-users.conf
            sudo rm -rf /var/lib/lldpq
            # Remove the old telemetry tree: `cp -r telemetry` later would
            # otherwise nest into the pre-existing directory and leave the
            # stale docker-compose/config files authoritative.
            sudo rm -rf "$LLDPQ_INSTALL_DIR/telemetry"
            echo "  Old installation files removed"
            INSTALL_MODE="fresh"
            if [[ "$_CALLER_SKIP_L1_WAS_SET" == "true" ]]; then
                SKIP_L1="$_CALLER_SKIP_L1_VALUE"
            else
                unset SKIP_L1
            fi
        else
            INSTALL_MODE="update"
        fi
    fi
fi

# Banner
echo ""
if [[ "$INSTALL_MODE" == "update" ]]; then
    echo "LLDPq Update"
    echo "============"
else
    echo "LLDPq Fresh Installation"
    echo "========================"
fi
if [[ "$AUTO_YES" == "true" ]]; then
    echo "  Running in non-interactive mode (-y)"
fi

# ============================================================================
# FRESH-ONLY: Package installation
# ============================================================================
if [[ "$INSTALL_MODE" == "fresh" ]]; then

    # Also cover machines where config/state was removed manually but an old
    # recovery unit is still enabled or activating.
    quiesce_recovery_units_for_fresh_install || exit 1

    step "Checking for conflicting services..."
    if systemctl is-active --quiet apache2 2>/dev/null; then
        echo "  [!] Apache2 is running on port 80!"
        echo "  LLDPq uses nginx as web server."
        echo ""
        echo "  Options:"
        echo "  1. Stop Apache2 (recommended for LLDPq)"
        echo "  2. Exit and resolve manually"
        echo ""
        if [[ "$AUTO_YES" == "true" ]]; then
            response="y"
            echo "  Stopping Apache2 (auto-yes mode)"
        else
            read -p "  Stop and disable Apache2? [Y/n]: " response
        fi
        if [[ ! "$response" =~ ^[Nn]$ ]]; then
            sudo systemctl stop apache2
            sudo systemctl disable apache2
            echo "  Apache2 stopped and disabled"
        else
            echo "  [!] Please stop Apache2 or configure nginx to use a different port"
            echo "  Edit /etc/nginx/sites-available/lldpq to change the port"
            exit 1
        fi
    fi

    step "Installing required packages..."
    sudo apt update || { echo "[!] apt update failed"; exit 1; }
    sudo apt install -y nginx fcgiwrap python3 python3-pip python3-yaml python3-ruamel.yaml python3-requests util-linux bsdextrautils \
        openssh-client sshpass iproute2 iputils-ping procps curl unzip acl isc-dhcp-server git || {
        echo "[!] Package installation failed"
        echo "    Try running: sudo apt --fix-broken install"
        exit 1
    }
    if ! sudo systemctl enable --now nginx; then
        echo "[!] nginx could not be enabled/started" >&2
        systemctl list-jobs --no-pager 2>/dev/null || true
        exit 1
    fi
    if ! sudo systemctl enable --now fcgiwrap; then
        echo "[!] fcgiwrap could not be enabled/started" >&2
        systemctl list-jobs --no-pager 2>/dev/null || true
        exit 1
    fi

    step "Downloading Monaco Editor for offline use..."
    MONACO_VERSION="0.45.0"
    MONACO_DIR="$WEB_ROOT/monaco"
    if [[ ! -d "$MONACO_DIR" ]]; then
        echo "  Downloading Monaco Editor v${MONACO_VERSION}..."
        TMP_DIR=$(mktemp -d)
        if curl -sfL "https://registry.npmjs.org/monaco-editor/-/monaco-editor-${MONACO_VERSION}.tgz" -o "$TMP_DIR/monaco.tgz" && \
           mkdir -p "$TMP_DIR/monaco" && \
           tar -xzf "$TMP_DIR/monaco.tgz" -C "$TMP_DIR/monaco" --strip-components=1; then
            sudo mkdir -p "$MONACO_DIR"
            sudo cp -r "$TMP_DIR/monaco/min/vs" "$MONACO_DIR/"
            echo "  Monaco Editor installed to $MONACO_DIR"
        else
            echo "  [!] Monaco Editor download failed (editor will use CDN fallback)"
        fi
        rm -rf "$TMP_DIR"
    else
        echo "  Monaco Editor already exists, skipping download"
    fi

    echo "  Required Python packages installed from OS packages"
fi

# Update mode skips the fresh-install apt block. Verify the complete runtime
# before stopping collectors or replacing any live file, and only download
# packages when the caller did not explicitly request an offline update.
ensure_update_runtime_dependencies || exit 1

# Notifications is a comment-preserving editor, so a lossy PyYAML fallback is
# not acceptable. Verify the exact account used by the CGI before update mode
# stops processes or replaces any runtime files.
ensure_ruamel_for_lldpq_user || exit 1
echo "  Required Python package verified for $LLDPQ_USER (ruamel.yaml)"
if [[ "$INSTALL_MODE" == "update" ]] && \
   ! sudo -H -u "$LLDPQ_USER" python3 -c 'import requests' 2>/dev/null; then
    if [[ "${LLDPQ_OFFLINE_UPDATE:-0}" == "1" ]]; then
        echo "[!] Offline update preflight: Python requests is unavailable to $LLDPQ_USER" >&2
        echo "    Install it for that account before retrying; no download was attempted and the existing runtime was not changed." >&2
        exit 1
    fi
    echo "  Installing OS package python3-requests..."
    sudo apt-get update >/dev/null || {
        echo "[!] Could not refresh package metadata for requests" >&2
        exit 1
    }
    sudo apt-get install -y python3-requests >/dev/null || {
        echo "[!] Could not install python3-requests" >&2
        exit 1
    }
    sudo -H -u "$LLDPQ_USER" python3 -c 'import requests' 2>/dev/null || {
        echo "[!] Python requests remains unavailable to $LLDPQ_USER" >&2
        exit 1
    }
fi

# Validate the recovery path grammar before update mode stops processes or
# mutates permissions/configuration.  Fresh installs reach this point only
# after the systemd package set has been installed.
echo "  Preflighting retained-import recovery units..."
LLDPQ_USER_HOME=$(resolve_lldpq_user_home "$LLDPQ_USER") || exit 1
if ! preflight_lldpq_recovery_units \
    "$LLDPQ_USER_HOME" "$LLDPQ_USER" "$LLDPQ_INSTALL_DIR" "$WEB_ROOT"; then
    if [[ "$INSTALL_MODE" == "update" ]]; then
        echo "[!] Recovery unit preflight failed; update was not started and the existing runtime remains active" >&2
    else
        echo "[!] Recovery unit preflight failed; LLDPq runtime files were not installed" >&2
    fi
    exit 1
fi
echo "  Recovery unit preflight passed"
install_update_recovery_guard || exit 1

# ============================================================================
# UPDATE-ONLY: Backup & prepare
# ============================================================================
_preserved_dir=""

if [[ "$INSTALL_MODE" == "update" ]]; then
    # Allow-listed values were loaded once before mode detection.  Do not
    # re-read a group-writable file after validating its managed paths.
    WEB_ROOT="${WEB_ROOT:-/var/www/html}"
    LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"

    # -- Optional full backup (ask; default No) -------------------------------
    # NOTE: runtime monitoring data is ALWAYS preserved across the update (see the
    # "Preparing update" step below) — this optional backup is just an extra rollback
    # copy of configs, keys and a data snapshot.
    BACKUP_DIR=""
    _do_backup=false
    if [[ "$FORCE_BACKUP" == "true" ]]; then
        _do_backup=true
    elif [[ "$AUTO_YES" != "true" ]]; then
        read -p "  Take a full backup (configs/keys/data) before updating? [y/N]: " _bk_response
        [[ "$_bk_response" =~ ^[Yy]$ ]] && _do_backup=true
    fi

    if [[ "$_do_backup" == "true" ]]; then
        step "Creating backup..."
        BACKUP_DIR="$HOME/lldpq-backup-$(date +%Y-%m-%d_%H-%M-%S)"
        mkdir "$BACKUP_DIR"
        echo "  Backup directory: $BACKUP_DIR"

        _backup_copy() {
            local source="$1" destination="$2" description="$3"
            [[ -e "$source" || -L "$source" ]] || return 0
            if ! root_run cp -a "$source" "$destination"; then
                echo "[!] Requested backup is incomplete; could not copy: $source" >&2
                echo "    Partial backup retained for inspection: $BACKUP_DIR" >&2
                return 1
            fi
            echo "  • $description"
        }

        _backup_inventory_tracking_pair() {
            local wait_seconds="${LLDPQ_UPDATE_LOCK_TIMEOUT:-600}"
            local inventory_lock="$WEB_ROOT/.inventory.lock"
            local -a sources=()
            case "$wait_seconds" in
                ''|*[!0-9]*|0) return 1 ;;
            esac
            [[ ! -e "$LLDPQ_INSTALL_DIR/devices.yaml" ]] || \
                sources+=("$LLDPQ_INSTALL_DIR/devices.yaml")
            [[ ! -e "$LLDPQ_INSTALL_DIR/tracking.yaml" ]] || \
                sources+=("$LLDPQ_INSTALL_DIR/tracking.yaml")
            ((${#sources[@]} > 0)) || return 0
            prepare_shared_lock_files /etc/lldpq.conf.lock "$inventory_lock" || \
                return 1
            # Match Setup/Provision's global -> inventory order so this
            # optional rollback snapshot cannot capture a mixed generation.
            root_run flock -w "$wait_seconds" /etc/lldpq.conf.lock \
                flock -w "$wait_seconds" "$inventory_lock" \
                cp -a -- "${sources[@]}" "$BACKUP_DIR/" || return 1
            [[ ! -e "$LLDPQ_INSTALL_DIR/devices.yaml" ]] || echo "  • devices.yaml"
            [[ ! -e "$LLDPQ_INSTALL_DIR/tracking.yaml" ]] || echo "  • tracking.yaml"
        }

        # Configuration files
        _backup_inventory_tracking_pair || {
            echo "[!] Requested backup is incomplete; could not snapshot inventory/tracking" >&2
            echo "    Partial backup retained for inspection: $BACKUP_DIR" >&2
            exit 1
        }
        _backup_copy "$LLDPQ_INSTALL_DIR/notifications.yaml" "$BACKUP_DIR/" notifications.yaml || exit 1
        _backup_copy "$WEB_ROOT/topology.dot" "$BACKUP_DIR/" topology.dot || exit 1
        _backup_copy "$WEB_ROOT/topology_config.yaml" "$BACKUP_DIR/" topology_config.yaml || exit 1
        _backup_copy /etc/lldpq.conf "$BACKUP_DIR/" /etc/lldpq.conf || exit 1
        _backup_copy /etc/lldpq-users.conf "$BACKUP_DIR/" /etc/lldpq-users.conf || exit 1
        _backup_copy /etc/dhcp/dhcpd.conf "$BACKUP_DIR/" /etc/dhcp/dhcpd.conf || exit 1
        _backup_copy /etc/dhcp/dhcpd.hosts "$BACKUP_DIR/" /etc/dhcp/dhcpd.hosts || exit 1
        _backup_copy /var/lib/dhcp/dhcpd.leases "$BACKUP_DIR/" /var/lib/dhcp/dhcpd.leases || exit 1
        _backup_copy "$WEB_ROOT/cumulus-ztp.sh" "$BACKUP_DIR/" cumulus-ztp.sh || exit 1
        _backup_copy "$WEB_ROOT/serial-mapping.txt" "$BACKUP_DIR/" serial-mapping.txt || exit 1
        _backup_copy "$WEB_ROOT/inventory.json" "$BACKUP_DIR/" inventory.json || exit 1
        _backup_copy "$WEB_ROOT/discovery-cache.json" "$BACKUP_DIR/" discovery-cache.json || exit 1
        _backup_copy "$WEB_ROOT/display-aliases.json" "$BACKUP_DIR/" display-aliases.json || exit 1
        _backup_copy "$WEB_ROOT/generated_config_folder" "$BACKUP_DIR/" generated_config_folder/ || exit 1
        _backup_copy "$WEB_ROOT/provision-uploads" "$BACKUP_DIR/" provision-uploads/ || exit 1

        # Older native/Docker layouts kept OS images and generic ONIE aliases
        # directly in WEB_ROOT. Include those in an explicitly requested full
        # data snapshot as well.
        _provision_files=("$WEB_ROOT"/*.bin "$WEB_ROOT"/*.img "$WEB_ROOT"/*.iso \
            "$WEB_ROOT"/onie-installer "$WEB_ROOT"/onie-installer-x86_64 \
            "$WEB_ROOT"/onie-installer-x86_64-mlnx)
        for _provision_file in "${_provision_files[@]}"; do
            if [[ -e "$_provision_file" || -L "$_provision_file" ]]; then
                mkdir -p "$BACKUP_DIR/provision-root-files"
                _backup_copy "$_provision_file" "$BACKUP_DIR/provision-root-files/" \
                    "provision file: $(basename "$_provision_file")" || exit 1
            fi
        done

        # SSH keys
        _ssh_keys=("$HOME"/.ssh/id_*)
        if [[ -e "${_ssh_keys[0]}" || -L "${_ssh_keys[0]}" ]]; then
            mkdir -p "$BACKUP_DIR/ssh-keys"
            for _ssh_key in "${_ssh_keys[@]}"; do
                _backup_copy "$_ssh_key" "$BACKUP_DIR/ssh-keys/" "SSH key: $(basename "$_ssh_key")" || exit 1
            done
            echo "  • SSH keys (~/.ssh/id_*)"
        fi

        # Monitoring data snapshot (may hold root-owned files from cron).
        for _d in monitor-results lldp-results alert-states assets.ini; do
            _backup_copy "$LLDPQ_INSTALL_DIR/$_d" "$BACKUP_DIR/" "$_d/" || exit 1
        done

        # The README promises that configuration history is included when a
        # full backup is explicitly requested.
        _backup_copy "$LLDPQ_INSTALL_DIR/.git" "$BACKUP_DIR/lldpq-git-history" ".git history" || exit 1

        printf 'LLDPq requested backup completed at %s\n' "$(date -Is)" > "$BACKUP_DIR/COMPLETE"
        test -s "$BACKUP_DIR/COMPLETE" || exit 1

        echo "  Backup complete"
    else
        echo "  Skipping full backup (monitoring data is still preserved across the update)"
    fi

    # -- Preserve user configs for restore after copy -------------------------
    step "Preparing update..."
    _preserved_dir=$(mktemp -d)
    # Preserve the customized ZTP script (image server IP, target OS, password, SSH key
    # are all baked into this file by the Provision UI — must survive 'cp -r html/*')
    if [[ -f "$WEB_ROOT/cumulus-ztp.sh" ]]; then
        sudo cp -a "$WEB_ROOT/cumulus-ztp.sh" "$_preserved_dir/" || {
            echo "[!] Could not preserve the customized ZTP script; update was not started" >&2
            sudo rm -rf "$_preserved_dir" 2>/dev/null || true
            _preserved_dir=""
            exit 1
        }
    fi

    # Preserve telemetry user config
    if [[ -d "$LLDPQ_INSTALL_DIR/telemetry/config" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/telemetry/config" \
            "$_preserved_dir/telemetry-config" || {
            echo "[!] Could not preserve telemetry configuration; update was not started" >&2
            sudo rm -rf "$_preserved_dir" 2>/dev/null || true
            _preserved_dir=""
            exit 1
        }
    fi

    # Preserve git history (tracks config changes over time)
    if [[ -d "$LLDPQ_INSTALL_DIR/.git" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/.git" "$_preserved_dir/dot-git" || {
            echo "[!] Could not preserve Git history; update was not started" >&2
            sudo rm -rf "$_preserved_dir" 2>/dev/null || true
            _preserved_dir=""
            exit 1
        }
        echo "  Git history preserved"
    fi

    # Preserve runtime data across the rm+recopy (ALWAYS — independent of the optional
    # backup above). Uses sudo because monitor-results may contain root-owned files
    # written by cron; a rename keeps it on the same filesystem (fast, no big copy).
    if ! _DATA_PRESERVE=$(mktemp -d "$HOME/.lldpq-data-preserve.XXXXXX"); then
        echo "[!] Could not create runtime preservation directory; update was not started" >&2
        sudo rm -rf "$_preserved_dir" 2>/dev/null || true
        _preserved_dir=""
        exit 1
    fi

    # Install the EXIT safety net before the first rename. An interrupt during
    # the preserve loop must not strand only part of the runtime tree outside
    # the installation directory.
    trap 'lldpq_install_exit_handler $?' EXIT
    if ! write_update_recovery_marker preserving ""; then
        echo "[!] Could not publish durable update recovery state; update was not started" >&2
        exit 1
    fi

    # Stop mutable jobs only after every ordinary config copy and the runtime
    # recovery trap are ready. An early mktemp/copy failure therefore leaves
    # the currently installed service running unchanged.
    _UPDATE_PROCESSES_STOPPED=false
    if pgrep -f "$LLDPQ_INSTALL_DIR/monitor.sh" >/dev/null 2>&1 || \
       pgrep -f "/usr/local/bin/lldpq-trigger" >/dev/null 2>&1; then
        echo "  Stopping LLDPq processes..."
        pkill -f "$LLDPQ_INSTALL_DIR/monitor.sh" 2>/dev/null || true
        pkill -f "/usr/local/bin/lldpq-trigger" 2>/dev/null || true
        sleep 2
        _UPDATE_PROCESSES_STOPPED=true
        echo "  Processes stopped"
    fi

    # The full CLI wrapper and every asset/LLDP/monitor web refresh use this
    # same lock. Waiting here safely covers runs that are still in assets.sh or
    # check-lldp.sh (where a monitor.sh-only pgrep cannot see them), then keeps
    # cron and web refreshes outside the entire replace/rollback transaction.
    # Stop new requests and drain existing state-changing CGI processes before
    # taking the lock; otherwise a writer could block behind the installer and
    # commit after the preservation snapshot.
    quiesce_update_web || exit 1
    acquire_update_process_lock || exit 1
    # Collectors take the process lock before reading the shared configuration.
    # Preserve that global order here so an active collector cannot hold the
    # process lock while waiting behind this installer's config lock.
    acquire_update_config_lock || exit 1
    acquire_update_provision_locks || exit 1

    if [[ -f "$LLDPQ_INSTALL_DIR/devices.yaml" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/devices.yaml" "$_preserved_dir/" || {
            echo "[!] Could not preserve devices.yaml; update was not started" >&2
            exit 1
        }
    fi
    if [[ -f "$LLDPQ_INSTALL_DIR/tracking.yaml" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/tracking.yaml" "$_preserved_dir/" || {
            echo "[!] Could not preserve tracking.yaml; update was not started" >&2
            exit 1
        }
    fi
    if [[ -f "$LLDPQ_INSTALL_DIR/notifications.yaml" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/notifications.yaml" "$_preserved_dir/" || {
            echo "[!] Could not preserve notifications.yaml; update was not started" >&2
            exit 1
        }
    fi
    # Web mutations are now quiesced and the Setup-managed files are safely
    # copied. Release before the long update/recovery transaction to avoid a
    # self-deadlock when the root recovery service takes the same lock.
    release_update_config_lock

    _data_preserve_failed=false
    for _d in monitor-results lldp-results alert-states assets.ini; do
        if [[ -e "$LLDPQ_INSTALL_DIR/$_d" ]] && \
           ! root_run mv "$LLDPQ_INSTALL_DIR/$_d" "$_DATA_PRESERVE/" 2>/dev/null; then
            echo "[!] Could not preserve runtime data before update: $LLDPQ_INSTALL_DIR/$_d" >&2
            _data_preserve_failed=true
            break
        fi
    done
    if [[ "$_data_preserve_failed" == "true" ]]; then
        _data_restore_failed=false
        for _d in monitor-results lldp-results alert-states assets.ini; do
            if [[ -e "$_DATA_PRESERVE/$_d" ]] && \
               ! root_run mv "$_DATA_PRESERVE/$_d" "$LLDPQ_INSTALL_DIR/" 2>/dev/null; then
                _data_restore_failed=true
            fi
        done
        if [[ "$_data_restore_failed" == "true" ]] || \
           find "$_DATA_PRESERVE" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
            echo "[!] Update was not started; preserved runtime data remains at $_DATA_PRESERVE" >&2
        else
            rmdir "$_DATA_PRESERVE" 2>/dev/null || true
        fi
        exit 1
    fi

    # Move the previous runtime into an automatic rollback snapshot. This is a
    # same-filesystem rename and is much cheaper than copying the runtime tree.
    echo "  Preparing automatic update rollback..."
    assert_lldpq_install_tree "$LLDPQ_INSTALL_DIR" || exit 1
    prepare_update_rollback || {
        echo "[!] Could not prepare automatic rollback; update was not started" >&2
        exit 1
    }
    echo "  Ready for update"

    # Save safely parsed config values before /etc/lldpq.conf is overwritten.
    _SAVE_TELEMETRY_ENABLED="${TELEMETRY_ENABLED:-}"
    _SAVE_PROMETHEUS_URL="${PROMETHEUS_URL:-}"
    _SAVE_TELEMETRY_COLLECTOR_IP="${TELEMETRY_COLLECTOR_IP:-}"
    _SAVE_DISCOVERY_RANGE="${DISCOVERY_RANGE:-}"
    _SAVE_SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
    _SAVE_GET_CONFIGS_SSH_TIMEOUT="${GET_CONFIGS_SSH_TIMEOUT:-60}"
    _SAVE_PROJECT_DIR="${PROJECT_DIR:-}"
    _SAVE_AUTO_BASE_CONFIG="${AUTO_BASE_CONFIG:-true}"
    _SAVE_AUTO_ZTP_DISABLE="${AUTO_ZTP_DISABLE:-true}"
    _SAVE_AUTO_SET_HOSTNAME="${AUTO_SET_HOSTNAME:-true}"
    _SAVE_TRANSCEIVER_FW_SKIP_MODELS="${TRANSCEIVER_FW_SKIP_MODELS:-}"
    _SAVE_TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY="${TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY:-skip}"
    _SAVE_TRANSCEIVER_FW_MAX_PARALLEL="${TRANSCEIVER_FW_MAX_PARALLEL:-10}"
    _SAVE_TRANSCEIVER_FW_MIN_INTERVAL="${TRANSCEIVER_FW_MIN_INTERVAL:-1800}"
    _SAVE_TRANSCEIVER_FW_SSH_TIMEOUT="${TRANSCEIVER_FW_SSH_TIMEOUT:-300}"
    _SAVE_TELEMETRY_COLLECTOR_PORT="${TELEMETRY_COLLECTOR_PORT:-}"
    _SAVE_TELEMETRY_COLLECTOR_VRF="${TELEMETRY_COLLECTOR_VRF:-}"
    _SAVE_AI_PROVIDER="${AI_PROVIDER:-ollama}"
    _SAVE_AI_MODEL="${AI_MODEL:-llama3.2}"
    _SAVE_AI_FALLBACK_MODEL="${AI_FALLBACK_MODEL:-}"
    _SAVE_AI_CONTEXT_WINDOW_TOKENS="${AI_CONTEXT_WINDOW_TOKENS:-}"
    _SAVE_AI_FALLBACK_CONTEXT_WINDOW_TOKENS="${AI_FALLBACK_CONTEXT_WINDOW_TOKENS:-}"
    _SAVE_AI_API_KEY="${AI_API_KEY:-}"
    _SAVE_AI_API_URL="${AI_API_URL:-https://api.openai.com/v1}"
    _SAVE_OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
    _SAVE_AI_PROXY_URL="${AI_PROXY_URL:-}"
    _SAVE_AI_SEARCH_MODEL="${AI_SEARCH_MODEL:-}"
    _SAVE_AI_SEARCH_URL="${AI_SEARCH_URL:-}"
    _SAVE_AI_SEARCH_KEY="${AI_SEARCH_KEY:-}"
    # Save Ansible dir and Editor root from sourced config
    _SAVE_ANSIBLE_DIR="${ANSIBLE_DIR:-}"
    _SAVE_EDITOR_ROOT="${EDITOR_ROOT:-}"
fi

# ============================================================================
# COMMON: Copy files to system directories
# ============================================================================
step "Copying files to system directories..."

echo "  - Copying etc/* to /etc/"
# Preserve an operator-customized system tmux configuration before the copy
# below overwrites it (uninstall restores this backup).
if [[ -f /etc/tmux.conf ]] && [[ ! -f /etc/tmux.conf.pre-lldpq ]] && \
   ! cmp -s etc/tmux.conf /etc/tmux.conf; then
    sudo cp -p /etc/tmux.conf /etc/tmux.conf.pre-lldpq
fi
sudo cp -r etc/* /etc/

# The packaged nginx site hardcodes the default web root; align it with the
# configured WEB_ROOT (no-op for the default /var/www/html).
if [[ "$WEB_ROOT" != "/var/www/html" ]]; then
    sudo sed -i "s|/var/www/html|${WEB_ROOT}|g" /etc/nginx/sites-available/lldpq
fi

echo "  - Copying html/* to $WEB_ROOT/"
sudo cp -r html/* "$WEB_ROOT/"

# The former Commissioning/Handed Over overview was replaced by the per-tab
# Analysis Scope filter. In-place updates do not otherwise remove files that
# disappeared from html/, so explicitly retire the obsolete deployed page.
sudo rm -f -- "$WEB_ROOT/handover.html"

# Ensure Monaco Editor exists (may have been deleted or never downloaded)
MONACO_DIR="$WEB_ROOT/monaco"
if [[ ! -d "$MONACO_DIR" ]]; then
    echo "  - Downloading Monaco Editor..."
    MONACO_VERSION="0.45.0"
    TMP_DIR=$(mktemp -d)
    if curl -sfL "https://registry.npmjs.org/monaco-editor/-/monaco-editor-${MONACO_VERSION}.tgz" -o "$TMP_DIR/monaco.tgz" && \
       mkdir -p "$TMP_DIR/monaco" && \
       tar -xzf "$TMP_DIR/monaco.tgz" -C "$TMP_DIR/monaco" --strip-components=1; then
        sudo mkdir -p "$MONACO_DIR"
        sudo cp -r "$TMP_DIR/monaco/min/vs" "$MONACO_DIR/"
        echo "    Monaco Editor installed"
    else
        echo "    [!] Monaco Editor download failed (editor will use CDN fallback)"
    fi
    rm -rf "$TMP_DIR"
fi

echo "  - Verifying js-yaml..."
JSYAML_VERSION="4.1.0"
if [[ ! -f "$WEB_ROOT/css/js-yaml.min.js" ]]; then
    sudo curl -sL "https://cdn.jsdelivr.net/npm/js-yaml@${JSYAML_VERSION}/dist/js-yaml.min.js" \
        -o "$WEB_ROOT/css/js-yaml.min.js" || \
        echo "    [!] js-yaml download failed (will work without offline validation)"
    echo "    js-yaml installed"
fi

echo "  - Copying VERSION to $WEB_ROOT/"
sudo cp VERSION "$WEB_ROOT/"
sudo chmod 664 "$WEB_ROOT/VERSION"

echo "  - Setting permissions on web directories"
sudo chmod o+rx /var/www 2>/dev/null || true
sudo chown -R "$LLDPQ_USER:www-data" "$WEB_ROOT/"
sudo find "$WEB_ROOT" -type d -exec chmod 775 {} \;
sudo find "$WEB_ROOT" -type f -exec chmod 664 {} \;
sudo find "$WEB_ROOT" -name '*.sh' -exec chmod 775 {} \;
sudo mkdir -p "$WEB_ROOT/hstr" "$WEB_ROOT/configs" "$WEB_ROOT/monitor-results" \
    "$WEB_ROOT/topology" "$WEB_ROOT/generated_config_folder" "$WEB_ROOT/provision-uploads"
sudo chown -R "$LLDPQ_USER:www-data" "$WEB_ROOT/hstr" "$WEB_ROOT/configs" \
    "$WEB_ROOT/monitor-results" "$WEB_ROOT/topology" \
    "$WEB_ROOT/generated_config_folder" "$WEB_ROOT/provision-uploads"
sudo chmod 775 "$WEB_ROOT/hstr" "$WEB_ROOT/configs" "$WEB_ROOT/monitor-results" \
    "$WEB_ROOT/topology" "$WEB_ROOT/generated_config_folder" "$WEB_ROOT/provision-uploads"

# Keep native installs at parity with Docker: display aliases are persistent
# operator configuration and must exist before either Setup or LLDP first uses it.
if [[ ! -f "$WEB_ROOT/display-aliases.json" ]]; then
    printf '{"interfaces":{},"devices":{}}\n' | \
        sudo tee "$WEB_ROOT/display-aliases.json" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/display-aliases.json"
sudo chmod 664 "$WEB_ROOT/display-aliases.json"

# Create serial-mapping.txt if it doesn't exist
if [ ! -f "$WEB_ROOT/serial-mapping.txt" ]; then
    echo -e "# Serial → Hostname mapping for ZTP config resolution\n# Format: SERIAL_NUMBER  HOSTNAME\n" | sudo tee "$WEB_ROOT/serial-mapping.txt" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/serial-mapping.txt"
sudo chmod 664 "$WEB_ROOT/serial-mapping.txt"

echo "  - Copying bin/* to /usr/local/bin/"
# Copy only regular files (a stray bin/__pycache__ directory must not abort
# the install) and chmod only what this installer ships, never the whole dir.
for _bin_file in bin/*; do
    [[ -f "$_bin_file" ]] || continue
    sudo cp "$_bin_file" /usr/local/bin/
    sudo chmod 755 "/usr/local/bin/${_bin_file##*/}"
done
unset _bin_file
if [[ ! -x /usr/local/bin/lldpq-config ]]; then
    echo "[!] Required runtime config helper was not installed: /usr/local/bin/lldpq-config" >&2
    exit 1
fi
if [[ "$INSTALL_MODE" == "update" ]]; then
    _config_validation_file="$LLDPQ_CONFIG_FILE"
    _config_validation_snapshot=""
    # Validate content with the freshly installed parser, but never execute
    # that newly copied program as root.  A private snapshot also avoids
    # rejecting a valid update merely because the invoking admin is not the
    # configured runtime account or has not refreshed group membership yet.
    if [[ "$LLDPQ_CONFIG_FILE" == "/etc/lldpq.conf" ]]; then
        _config_validation_snapshot=$(
            snapshot_system_lldpq_config "$LLDPQ_CONFIG_FILE"
        ) || {
            echo "[!] Existing runtime configuration could not be snapshotted safely: $LLDPQ_CONFIG_FILE" >&2
            exit 1
        }
        _config_validation_file="$_config_validation_snapshot"
    fi
    if ! /usr/local/bin/lldpq-config --require-config \
       --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
       --config "$_config_validation_file" >/dev/null; then
        [[ -z "$_config_validation_snapshot" ]] || rm -f "$_config_validation_snapshot"
        echo "[!] Existing runtime configuration is invalid: $LLDPQ_CONFIG_FILE" >&2
        exit 1
    fi
    [[ -z "$_config_validation_snapshot" ]] || rm -f "$_config_validation_snapshot"
    unset _config_validation_file _config_validation_snapshot
fi

echo "  - Installing root-owned backup/import helper"
_backup_helper_dir=$(dirname "$LLDPQ_BACKUP_IMPORT_HELPER")
if [[ -L "$_backup_helper_dir" ]] || \
   { [[ -e "$_backup_helper_dir" ]] && [[ ! -d "$_backup_helper_dir" ]]; }; then
    echo "[!] Refusing unsafe backup helper directory: $_backup_helper_dir" >&2
    exit 1
fi
if [[ ! -f lldpq/backup_import.py || -L lldpq/backup_import.py ]]; then
    echo "[!] Packaged backup/import helper is missing or is a symlink" >&2
    exit 1
fi
sudo install -d -o root -g root -m 0755 "$_backup_helper_dir"
sudo install -o root -g root -m 0755 -- \
    lldpq/backup_import.py "$LLDPQ_BACKUP_IMPORT_HELPER"
_backup_helper_dir_metadata=$(sudo stat -c '%u:%g:%a' -- "$_backup_helper_dir" 2>/dev/null || true)
_backup_helper_metadata=$(sudo stat -c '%u:%g:%a' -- "$LLDPQ_BACKUP_IMPORT_HELPER" 2>/dev/null || true)
if [[ -L "$_backup_helper_dir" ]] || \
   [[ "$_backup_helper_dir_metadata" != "0:0:755" ]] || \
   [[ -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]] || \
   [[ ! -f "$LLDPQ_BACKUP_IMPORT_HELPER" ]] || \
   [[ "$_backup_helper_metadata" != "0:0:755" ]]; then
    echo "[!] Root-owned backup/import helper verification failed" >&2
    exit 1
fi

echo "  - Installing root-owned authentication users helper"
if [[ ! -f lldpq/auth_users.py || -L lldpq/auth_users.py ]] || \
   ! python3 -c 'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], "exec")' \
        lldpq/auth_users.py; then
    echo "[!] Packaged authentication users helper is missing, linked, or invalid" >&2
    exit 1
fi
_auth_users_stage="${LLDPQ_AUTH_USERS_HELPER}.lldpq-new"
sudo rm -f -- "$_auth_users_stage"
if ! sudo install -o root -g root -m 0755 -- \
        lldpq/auth_users.py "$_auth_users_stage" || \
   ! sudo mv -fT -- "$_auth_users_stage" "$LLDPQ_AUTH_USERS_HELPER"; then
    sudo rm -f -- "$_auth_users_stage" 2>/dev/null || true
    echo "[!] Could not install the root-owned authentication users helper" >&2
    exit 1
fi
_auth_users_metadata=$(sudo stat -c '%u:%g:%a:%h' -- \
    "$LLDPQ_AUTH_USERS_HELPER" 2>/dev/null || true)
if [[ -L "$LLDPQ_AUTH_USERS_HELPER" ]] || \
   [[ ! -f "$LLDPQ_AUTH_USERS_HELPER" ]] || \
   [[ "$_auth_users_metadata" != "0:0:755:1" ]] || \
   ! sudo cmp -s -- lldpq/auth_users.py "$LLDPQ_AUTH_USERS_HELPER"; then
    echo "[!] Root-owned authentication users helper verification failed" >&2
    exit 1
fi

echo "  - Installing root-owned web uninstall gateway"
if [[ ! -f uninstall.sh || -L uninstall.sh ]]; then
    echo "[!] Packaged uninstaller is missing or is a symlink" >&2
    exit 1
fi
if [[ ! -f lldpq/uninstall_web.py || -L lldpq/uninstall_web.py ]]; then
    echo "[!] Packaged web uninstall gateway is missing or is a symlink" >&2
    exit 1
fi
if ! bash -n uninstall.sh || \
   ! python3 -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], "exec")' \
        lldpq/uninstall_web.py; then
    echo "[!] Packaged web uninstall helper syntax validation failed" >&2
    exit 1
fi
_uninstall_script_stage="${LLDPQ_UNINSTALL_SCRIPT}.lldpq-new"
_uninstall_gateway_stage="${LLDPQ_UNINSTALL_WEB_GATEWAY}.lldpq-new"
sudo rm -f -- "$_uninstall_script_stage" "$_uninstall_gateway_stage"
if ! sudo install -o root -g root -m 0755 -- \
        uninstall.sh "$_uninstall_script_stage" || \
   ! sudo install -o root -g root -m 0755 -- \
        lldpq/uninstall_web.py "$_uninstall_gateway_stage" || \
   ! sudo mv -fT -- "$_uninstall_script_stage" "$LLDPQ_UNINSTALL_SCRIPT" || \
   ! sudo mv -fT -- "$_uninstall_gateway_stage" "$LLDPQ_UNINSTALL_WEB_GATEWAY"; then
    sudo rm -f -- "$_uninstall_script_stage" "$_uninstall_gateway_stage" 2>/dev/null || true
    echo "[!] Could not install the root-owned web uninstall helpers" >&2
    exit 1
fi
_uninstall_script_metadata=$(sudo stat -c '%u:%g:%a:%h' -- \
    "$LLDPQ_UNINSTALL_SCRIPT" 2>/dev/null || true)
_uninstall_gateway_metadata=$(sudo stat -c '%u:%g:%a:%h' -- \
    "$LLDPQ_UNINSTALL_WEB_GATEWAY" 2>/dev/null || true)
if [[ -L "$LLDPQ_UNINSTALL_SCRIPT" ]] || \
   [[ ! -f "$LLDPQ_UNINSTALL_SCRIPT" ]] || \
   [[ "$_uninstall_script_metadata" != "0:0:755:1" ]] || \
   ! sudo cmp -s -- uninstall.sh "$LLDPQ_UNINSTALL_SCRIPT" || \
   [[ -L "$LLDPQ_UNINSTALL_WEB_GATEWAY" ]] || \
   [[ ! -f "$LLDPQ_UNINSTALL_WEB_GATEWAY" ]] || \
   [[ "$_uninstall_gateway_metadata" != "0:0:755:1" ]] || \
   ! sudo cmp -s -- lldpq/uninstall_web.py "$LLDPQ_UNINSTALL_WEB_GATEWAY"; then
    echo "[!] Root-owned web uninstall helper verification failed" >&2
    exit 1
fi
if ! prepare_shared_lock_files "$LLDPQ_LIFECYCLE_LOCK"; then
    echo "[!] Could not prepare the shared LLDPq lifecycle lock" >&2
    exit 1
fi

# The CGI may invoke only these three fixed root-owned gateway entry points.
# Options are passed as bounded JSON on stdin; never broaden this policy with
# an argv wildcard or permission to execute uninstall.sh directly.
_uninstall_sudoers_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-uninstall-sudoers.XXXXXX") || exit 1
if ! printf '%s\n' \
    "www-data ALL=(root) NOPASSWD: $LLDPQ_UNINSTALL_WEB_GATEWAY preview, $LLDPQ_UNINSTALL_WEB_GATEWAY start, $LLDPQ_UNINSTALL_WEB_GATEWAY status" \
    > "$_uninstall_sudoers_tmp" || \
   ! chmod 0440 "$_uninstall_sudoers_tmp"; then
    rm -f "$_uninstall_sudoers_tmp"
    echo "[!] Could not stage the web uninstall sudoers policy" >&2
    exit 1
fi
_visudo_bin=$(command -v visudo 2>/dev/null || true)
if [[ -z "$_visudo_bin" && -x /usr/sbin/visudo ]]; then
    _visudo_bin=/usr/sbin/visudo
fi
if [[ -z "$_visudo_bin" ]] || \
   ! sudo "$_visudo_bin" -cf "$_uninstall_sudoers_tmp" >/dev/null; then
    rm -f "$_uninstall_sudoers_tmp"
    echo "[!] Web uninstall sudoers policy failed visudo validation" >&2
    exit 1
fi
if sudo test -L "$LLDPQ_UNINSTALL_SUDOERS"; then
    rm -f "$_uninstall_sudoers_tmp"
    echo "[!] Refusing symlinked web uninstall sudoers policy" >&2
    exit 1
fi
_uninstall_sudoers_stage="${LLDPQ_UNINSTALL_SUDOERS}.lldpq-new"
sudo rm -f -- "$_uninstall_sudoers_stage"
if ! sudo install -o root -g root -m 0440 -- \
        "$_uninstall_sudoers_tmp" "$_uninstall_sudoers_stage" || \
   ! sudo "$_visudo_bin" -cf "$_uninstall_sudoers_stage" >/dev/null || \
   ! sudo mv -fT -- "$_uninstall_sudoers_stage" "$LLDPQ_UNINSTALL_SUDOERS"; then
    sudo rm -f -- "$_uninstall_sudoers_stage" 2>/dev/null || true
    rm -f "$_uninstall_sudoers_tmp"
    echo "[!] Could not install the validated web uninstall sudoers policy" >&2
    exit 1
fi
rm -f "$_uninstall_sudoers_tmp"
_uninstall_sudoers_metadata=$(sudo stat -c '%u:%g:%a:%h' -- \
    "$LLDPQ_UNINSTALL_SUDOERS" 2>/dev/null || true)
if sudo test -L "$LLDPQ_UNINSTALL_SUDOERS" || \
   ! sudo test -f "$LLDPQ_UNINSTALL_SUDOERS" || \
   [[ "$_uninstall_sudoers_metadata" != "0:0:440:1" ]] || \
   ! sudo "$_visudo_bin" -cf "$LLDPQ_UNINSTALL_SUDOERS" >/dev/null; then
    echo "[!] Installed web uninstall sudoers policy verification failed" >&2
    exit 1
fi

echo "  - Copying lldpq to $LLDPQ_INSTALL_DIR"
sudo mkdir -p "$LLDPQ_INSTALL_DIR"
sudo cp -r lldpq/* "$LLDPQ_INSTALL_DIR/"
# The source file is packaged with the application, but no installed workflow
# may import or execute either service-user-writable privileged helper copy.
sudo rm -f \
    "$LLDPQ_INSTALL_DIR/backup_import.py" \
    "$LLDPQ_INSTALL_DIR/auth_users.py" \
    "$LLDPQ_INSTALL_DIR/uninstall_web.py"
sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR"

# Restore preserved configs (update mode)
if [[ -n "$_preserved_dir" ]] && [[ -d "$_preserved_dir" ]]; then
    echo "  - Restoring preserved configuration files..."
    if [[ -f "$_preserved_dir/devices.yaml" ]]; then
        sudo cp "$_preserved_dir/devices.yaml" "$LLDPQ_INSTALL_DIR/" || {
            echo "[!] Could not restore preserved devices.yaml" >&2
            exit 1
        }
        echo "    • devices.yaml"
    fi
    if [[ -f "$_preserved_dir/tracking.yaml" ]]; then
        sudo cp "$_preserved_dir/tracking.yaml" "$LLDPQ_INSTALL_DIR/" || {
            echo "[!] Could not restore preserved tracking.yaml" >&2
            exit 1
        }
        echo "    • tracking.yaml"
    fi
    if [[ -f "$_preserved_dir/notifications.yaml" ]]; then
        sudo cp "$_preserved_dir/notifications.yaml" "$LLDPQ_INSTALL_DIR/" || {
            echo "[!] Could not restore preserved notifications.yaml" >&2
            exit 1
        }
        echo "    • notifications.yaml"
    fi
    # Restore the customized ZTP script over the freshly-copied template (update only)
    if [[ -f "$_preserved_dir/cumulus-ztp.sh" ]]; then
        sudo cp "$_preserved_dir/cumulus-ztp.sh" "$WEB_ROOT/" || {
            echo "[!] Could not restore the customized ZTP script" >&2
            exit 1
        }
        echo "    • cumulus-ztp.sh (ZTP script preserved)"
    fi
fi

echo "  - Copying telemetry stack to $LLDPQ_INSTALL_DIR/telemetry"
sudo cp -r telemetry "$LLDPQ_INSTALL_DIR/telemetry"
sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/telemetry"
sudo chmod 755 "$LLDPQ_INSTALL_DIR/telemetry/start.sh"
sudo chmod 644 "$LLDPQ_INSTALL_DIR/telemetry/config/"*.yaml 2>/dev/null || true

# Restore telemetry user config (update mode)
if [[ -n "$_preserved_dir" ]] && [[ -d "$_preserved_dir/telemetry-config" ]]; then
    sudo cp -a "$_preserved_dir/telemetry-config/." \
        "$LLDPQ_INSTALL_DIR/telemetry/config/"
    echo "    • telemetry config preserved"
fi
sudo chmod 644 "$LLDPQ_INSTALL_DIR/telemetry/config/"*.yaml 2>/dev/null || true

# Restore git history (update mode)
if [[ -n "$_preserved_dir" ]] && [[ -d "$_preserved_dir/dot-git" ]]; then
    sudo cp -r "$_preserved_dir/dot-git" "$LLDPQ_INSTALL_DIR/.git"
    echo "    • .git history restored"
fi

# Clean up preserved temp dir
[[ -n "$_preserved_dir" ]] && sudo rm -rf "$_preserved_dir"

echo "  - Setting permissions on $LLDPQ_INSTALL_DIR"
sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR"
sudo chmod 750 "$LLDPQ_INSTALL_DIR"
sudo chmod 664 "$LLDPQ_INSTALL_DIR/devices.yaml" 2>/dev/null || true
sudo chmod 664 "$LLDPQ_INSTALL_DIR/tracking.yaml" 2>/dev/null || true
sudo chmod 664 "$LLDPQ_INSTALL_DIR/notifications.yaml" 2>/dev/null || true
sudo find "$LLDPQ_INSTALL_DIR" -name '*.sh' -exec chmod 755 {} \;
sudo find "$LLDPQ_INSTALL_DIR" -name '*.py' -exec chmod 755 {} \;
sudo mkdir -p "$LLDPQ_INSTALL_DIR/monitor-results/fabric-tables"
sudo chmod 750 "$LLDPQ_INSTALL_DIR/monitor-results"
sudo chmod 750 "$LLDPQ_INSTALL_DIR/monitor-results/fabric-tables"

# Set default ACL so new files/directories also get group read permission
if command -v setfacl &> /dev/null; then
    setfacl -R -d -m g::rX "$LLDPQ_INSTALL_DIR" 2>/dev/null || true
    echo "    Default ACL set (new files will inherit group read permission)"
fi

# Update git hooks if .git exists (update mode preserves .git from backup restore later)
if [[ -d "$LLDPQ_INSTALL_DIR/.git" ]]; then
    echo "  - Updating git hooks..."
    sudo tee "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge" > /dev/null << 'HOOKEOF'
#!/bin/bash
# Fix permissions after git pull/merge (preserve group read access for www-data)
chmod 750 "$(git rev-parse --show-toplevel)" 2>/dev/null || true
chmod 664 "$(git rev-parse --show-toplevel)/devices.yaml" 2>/dev/null || true
chmod 664 "$(git rev-parse --show-toplevel)/tracking.yaml" 2>/dev/null || true
if [ -d "$(git rev-parse --show-toplevel)/monitor-results" ]; then
    chmod -R 750 "$(git rev-parse --show-toplevel)/monitor-results" 2>/dev/null || true
fi
HOOKEOF
    sudo chmod +x "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge"
    sudo cp "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge" "$LLDPQ_INSTALL_DIR/.git/hooks/post-checkout"
    sudo chown "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge" \
        "$LLDPQ_INSTALL_DIR/.git/hooks/post-checkout"
    sudo -u "$LLDPQ_USER" git -C "$LLDPQ_INSTALL_DIR" config core.sharedRepository group 2>/dev/null || true
    echo "    Git hooks updated"
fi

echo "  Files copied successfully"

# ============================================================================
# COMMON: Topology symlinks
# ============================================================================
step "Setting up topology symlinks..."

echo "  - topology.dot"
if [[ -f "$WEB_ROOT/topology.dot" ]]; then
    echo "    Existing topology.dot preserved in web root"
    sudo rm -f "$LLDPQ_INSTALL_DIR/topology.dot" 2>/dev/null
elif [[ -f "$LLDPQ_INSTALL_DIR/topology.dot" ]]; then
    sudo mv "$LLDPQ_INSTALL_DIR/topology.dot" "$WEB_ROOT/topology.dot"
else
    echo "    Creating empty valid topology.dot"
    printf 'graph "FABRIC" {\n}\n' | sudo tee "$WEB_ROOT/topology.dot" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/topology.dot"
sudo chmod 664 "$WEB_ROOT/topology.dot"
sudo ln -sf "$WEB_ROOT/topology.dot" "$LLDPQ_INSTALL_DIR/topology.dot"

echo "  - topology_config.yaml"
if [[ -f "$WEB_ROOT/topology_config.yaml" ]]; then
    echo "    Existing topology_config.yaml preserved in web root"
    sudo rm -f "$LLDPQ_INSTALL_DIR/topology_config.yaml" 2>/dev/null
elif [[ -f "$LLDPQ_INSTALL_DIR/topology_config.yaml" ]]; then
    sudo mv "$LLDPQ_INSTALL_DIR/topology_config.yaml" "$WEB_ROOT/topology_config.yaml"
else
    echo "    Creating empty topology_config.yaml"
    echo "{}" | sudo tee "$WEB_ROOT/topology_config.yaml" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/topology_config.yaml"
sudo chmod 664 "$WEB_ROOT/topology_config.yaml"
sudo ln -sf "$WEB_ROOT/topology_config.yaml" "$LLDPQ_INSTALL_DIR/topology_config.yaml"

# ============================================================================
# COMMON: Ansible directory
# ============================================================================
step "Configuring Ansible directory..."

if [[ "$INSTALL_MODE" == "update" ]]; then
    # Update mode: use ANSIBLE_DIR from sourced config (saved before overwrite)
    ANSIBLE_DIR="${_SAVE_ANSIBLE_DIR:-}"
    EDITOR_ROOT="${_SAVE_EDITOR_ROOT:-$ANSIBLE_DIR}"

    if [[ "$ANSIBLE_DIR" == "NoNe" ]]; then
        echo "  Ansible not configured. Skipping."
    elif [[ -n "$ANSIBLE_DIR" ]] && [[ -d "$ANSIBLE_DIR" ]]; then
        echo "  Using existing: $ANSIBLE_DIR"
    else
        if [[ -n "$ANSIBLE_DIR" ]] && [[ "$ANSIBLE_DIR" != "NoNe" ]]; then
            echo "  [!] Previous ANSIBLE_DIR no longer exists: $ANSIBLE_DIR"
        fi
        # Try auto-detect
        echo "  Searching for Ansible directory..."
        ANSIBLE_DIR=""
        for dir in "$HOME"/*; do
            if [[ -d "$dir" ]] && [[ -d "$dir/inventory" ]] && [[ -d "$dir/playbooks" ]]; then
                ANSIBLE_DIR="$dir"
                echo "  Auto-detected: $ANSIBLE_DIR"
                break
            fi
        done
        [[ -z "$ANSIBLE_DIR" ]] && ANSIBLE_DIR="NoNe" && echo "  No Ansible directory detected"
    fi
else
    # Fresh mode: interactive prompt
    echo "  Detecting Ansible directory..."
    ANSIBLE_DIR=""

    for dir in "$HOME"/*; do
        if [[ -d "$dir" ]] && [[ -d "$dir/inventory" ]] && [[ -d "$dir/playbooks" ]]; then
            ANSIBLE_DIR="$dir"
            echo "  Found Ansible directory: $ANSIBLE_DIR"
            break
        fi
    done

    if [[ -z "$ANSIBLE_DIR" ]]; then
        echo "  Ansible directory not detected automatically"
        echo "  Looking for a directory containing inventory/ and playbooks/"
    fi

    echo ""
    if [[ "$AUTO_YES" == "true" ]]; then
        if [[ -n "$ANSIBLE_DIR" ]]; then
            echo "  Using detected Ansible directory: $ANSIBLE_DIR (auto-yes mode)"
        else
            ANSIBLE_DIR="NoNe"
            echo "  No Ansible directory found, skipping (auto-yes mode)"
        fi
    else
        if [[ -n "$ANSIBLE_DIR" ]]; then
            echo "  Found: $ANSIBLE_DIR"
            read -p "  Use this Ansible directory? [Y/n/skip]: " response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                read -p "  Enter Ansible directory path (or press Enter to skip): " custom_path
                if [[ -z "$custom_path" ]]; then
                    ANSIBLE_DIR="NoNe"
                    echo "  Skipping Ansible (LLDPq will use devices.yaml)"
                else
                    ANSIBLE_DIR="$custom_path"
                fi
            elif [[ "$response" == "skip" ]]; then
                ANSIBLE_DIR="NoNe"
                echo "  Skipping Ansible (LLDPq will use devices.yaml)"
            fi
        else
            read -p "  Enter Ansible directory path (or press Enter to skip): " response
            if [[ -z "$response" ]] || [[ "$response" == "skip" ]]; then
                ANSIBLE_DIR="NoNe"
                echo "  Skipping Ansible configuration (LLDPq will use devices.yaml)"
            else
                ANSIBLE_DIR="$response"
            fi
        fi
    fi
fi

# ANSIBLE_DIR is later used by recursive chmod/chown and git operations.  Treat
# a configured or interactively supplied value with the same root-deny policy
# as the install and web roots.
if [[ "$ANSIBLE_DIR" != "NoNe" ]] && [[ -n "$ANSIBLE_DIR" ]]; then
    ANSIBLE_DIR=$(guard_managed_path "Ansible project" "$ANSIBLE_DIR" 2) || exit 1
    ANSIBLE_DIR=$(guard_recursive_target "Ansible project" "$ANSIBLE_DIR" false) || exit 1
fi
if [[ "${EDITOR_ROOT:-}" != "NoNe" ]] && [[ -n "${EDITOR_ROOT:-}" ]]; then
    EDITOR_ROOT=$(guard_managed_path "editor root" "$EDITOR_ROOT" 2) || exit 1
    EDITOR_ROOT=$(guard_recursive_target "editor root" "$EDITOR_ROOT" false) || exit 1
fi

# Configure Ansible directory permissions (if not NoNe and exists)
if [[ "$ANSIBLE_DIR" != "NoNe" ]] && [[ -n "$ANSIBLE_DIR" ]] && [[ -d "$ANSIBLE_DIR" ]]; then
    echo "  Configuring web access permissions..."
    sudo usermod -a -G "$LLDPQ_USER" www-data 2>/dev/null || true
    echo "  www-data user added to $LLDPQ_USER group"

    chmod -R g+rw "$ANSIBLE_DIR" 2>/dev/null || true
    echo "  Group write permission set on ansible directory"

    if command -v setfacl &> /dev/null; then
        setfacl -R -d -m g::rwX "$ANSIBLE_DIR" 2>/dev/null || true
        echo "  Default ACL set (new files will inherit group write permission)"
    fi

    if [[ -d "$ANSIBLE_DIR/.git" ]]; then
        echo "  Setting up git hooks for permission management..."
        # Try to make .git writable for current user; may already be owned by another user
        sudo chown -R "$LLDPQ_USER:www-data" "$ANSIBLE_DIR/.git" 2>/dev/null || true
        sudo chmod -R g+rwX "$ANSIBLE_DIR/.git" 2>/dev/null || true

        if sudo tee "$ANSIBLE_DIR/.git/hooks/post-merge" >/dev/null 2>&1 << 'HOOKEOF'
#!/bin/bash
# Fix permissions after git pull/merge
chmod -R g+rw "$(git rev-parse --show-toplevel)" 2>/dev/null || true
HOOKEOF
        then
            sudo chmod +x "$ANSIBLE_DIR/.git/hooks/post-merge" 2>/dev/null || true
            sudo cp "$ANSIBLE_DIR/.git/hooks/post-merge" "$ANSIBLE_DIR/.git/hooks/post-checkout" 2>/dev/null || true
            echo "  Git hooks created (post-merge, post-checkout)"
        else
            echo "  [!] Could not write Ansible git hooks (skipped, non-fatal)"
        fi
    fi

    # Add git safe.directory for www-data user
    sudo chmod 775 /var/www 2>/dev/null || true
    sudo chown root:www-data /var/www 2>/dev/null || true
    sudo touch /var/www/.gitconfig 2>/dev/null || true
    sudo chown www-data:www-data /var/www/.gitconfig 2>/dev/null || true
    sudo -u www-data git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true

    git -C "$ANSIBLE_DIR" config core.sharedRepository group 2>/dev/null || true
    sudo chown -R "$LLDPQ_USER:www-data" "$ANSIBLE_DIR/.git" 2>/dev/null || true
    sudo chmod -R g+rwX "$ANSIBLE_DIR/.git" 2>/dev/null || true

    echo "  Ansible directory configured"
elif [[ "$ANSIBLE_DIR" != "NoNe" ]] && [[ -n "$ANSIBLE_DIR" ]]; then
    echo "  [!] Warning: Ansible directory '$ANSIBLE_DIR' does not exist"
    echo "  It will be created when needed or you can create it manually"
fi

[[ -z "$ANSIBLE_DIR" ]] && ANSIBLE_DIR="NoNe"

# ============================================================================
# COMMON: Write /etc/lldpq.conf
# ============================================================================
step "Writing /etc/lldpq.conf..."

echo "# LLDPq Configuration" | sudo tee /etc/lldpq.conf > /dev/null
echo "LLDPQ_DIR=$LLDPQ_INSTALL_DIR" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "LLDPQ_USER=$LLDPQ_USER" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "LLDPQ_SRC=$LLDPQ_SRC_DIR" | sudo tee -a /etc/lldpq.conf > /dev/null
_LLDPQ_HOSTNAME_TO_WRITE="${LLDPQ_HOSTNAME:-lldpq}"
if [[ ! "$_LLDPQ_HOSTNAME_TO_WRITE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    echo "  [!] Invalid LLDPQ_HOSTNAME; using default 'lldpq'" >&2
    _LLDPQ_HOSTNAME_TO_WRITE=lldpq
fi
printf 'LLDPQ_HOSTNAME=%s\n' "$_LLDPQ_HOSTNAME_TO_WRITE" | \
    sudo tee -a /etc/lldpq.conf > /dev/null
echo "WEB_ROOT=$WEB_ROOT" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "ANSIBLE_DIR=$ANSIBLE_DIR" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "EDITOR_ROOT=${EDITOR_ROOT:-$ANSIBLE_DIR}" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_HOSTS_FILE=/etc/dhcp/dhcpd.hosts" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_CONF_FILE=/etc/dhcp/dhcpd.conf" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_LEASES_FILE=/var/lib/dhcp/dhcpd.leases" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "ZTP_SCRIPT_FILE=$WEB_ROOT/cumulus-ztp.sh" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "BASE_CONFIG_DIR=$LLDPQ_INSTALL_DIR/sw-base" | sudo tee -a /etc/lldpq.conf > /dev/null
_PROJECT_DIR_TO_WRITE="${PROJECT_DIR:-}"
if [[ "$INSTALL_MODE" == "update" ]]; then
    _PROJECT_DIR_TO_WRITE="${_SAVE_PROJECT_DIR:-}"
fi
[[ -n "$_PROJECT_DIR_TO_WRITE" ]] && \
    echo "PROJECT_DIR=$_PROJECT_DIR_TO_WRITE" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_BASE_CONFIG=true" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_ZTP_DISABLE=true" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_SET_HOSTNAME=true" | sudo tee -a /etc/lldpq.conf > /dev/null
render_runtime_tuning_config \
    "${LLDPQ_CRON:-*/10 * * * *}" \
    "${GETCONF_CRON:-0 */12 * * *}" \
    "${SKIP_OPTICAL:-false}" \
    "${SKIP_L1:-false}" \
    "${MONITOR_MAX_PARALLEL:-100}" \
    "${LLDP_MAX_PARALLEL:-100}" \
    "${ASSETS_MAX_PARALLEL:-100}" \
    "${GET_CONFIGS_MAX_PARALLEL:-100}" \
    "${SEND_CMD_MAX_PARALLEL:-25}" \
    "${TELEMETRY_MAX_PARALLEL:-25}" \
    "${_SAVE_SCAN_INTERVAL:-${SCAN_INTERVAL:-300}}" \
    "${_SAVE_GET_CONFIGS_SSH_TIMEOUT:-${GET_CONFIGS_SSH_TIMEOUT:-60}}" \
    "${PFC_ECN_MAX_PARALLEL:-4}" \
    "${PFC_ECN_COLLECTION_BUDGET_SECONDS:-60}" \
    "${PFC_ECN_PORT_TIMEOUT_SECONDS:-5}" \
    "${OPTICAL_COLLECTION_BUDGET_SECONDS:-120}" \
    "${OPTICAL_PORT_TIMEOUT_SECONDS:-10}" \
    "${MONITOR_TIMING:-false}" \
    "${MONITOR_COMMAND_TIMEOUT_SECONDS:-20}" | \
    sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SKIP_MODELS=\"\"" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=skip" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MAX_PARALLEL=10" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MIN_INTERVAL=1800" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SSH_TIMEOUT=300" | sudo tee -a /etc/lldpq.conf > /dev/null
render_ai_config \
    ollama llama3.2 "" https://api.openai.com/v1 http://localhost:11434 \
    "" "" "" "" "" "" "" | sudo tee -a /etc/lldpq.conf > /dev/null

# Preserve telemetry settings (update mode)
if [[ "$INSTALL_MODE" == "update" ]]; then
    [[ -n "$_SAVE_TELEMETRY_ENABLED" ]] && \
        echo "TELEMETRY_ENABLED=$_SAVE_TELEMETRY_ENABLED" | sudo tee -a /etc/lldpq.conf > /dev/null
    [[ -n "$_SAVE_PROMETHEUS_URL" ]] && \
        echo "PROMETHEUS_URL=$_SAVE_PROMETHEUS_URL" | sudo tee -a /etc/lldpq.conf > /dev/null
    [[ -n "$_SAVE_TELEMETRY_COLLECTOR_IP" ]] && \
        echo "TELEMETRY_COLLECTOR_IP=$_SAVE_TELEMETRY_COLLECTOR_IP" | sudo tee -a /etc/lldpq.conf > /dev/null
    [[ -n "$_SAVE_TELEMETRY_COLLECTOR_PORT" ]] && \
        echo "TELEMETRY_COLLECTOR_PORT=$_SAVE_TELEMETRY_COLLECTOR_PORT" | sudo tee -a /etc/lldpq.conf > /dev/null
    [[ -n "$_SAVE_TELEMETRY_COLLECTOR_VRF" ]] && \
        echo "TELEMETRY_COLLECTOR_VRF=$_SAVE_TELEMETRY_COLLECTOR_VRF" | sudo tee -a /etc/lldpq.conf > /dev/null
    # Preserve discovery settings
    [[ -n "$_SAVE_DISCOVERY_RANGE" ]] && \
        echo "DISCOVERY_RANGE=$_SAVE_DISCOVERY_RANGE" | sudo tee -a /etc/lldpq.conf > /dev/null
    # Replace preserved values as data. Never interpolate group-writable config
    # into a sed program: GNU sed's `e` flag could otherwise turn a crafted
    # value into command execution during a privileged update.
    sudo sed -i '/^AUTO_BASE_CONFIG=/d;/^AUTO_ZTP_DISABLE=/d;/^AUTO_SET_HOSTNAME=/d;/^TRANSCEIVER_FW_SKIP_MODELS=/d;/^TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=/d;/^TRANSCEIVER_FW_MAX_PARALLEL=/d;/^TRANSCEIVER_FW_MIN_INTERVAL=/d;/^TRANSCEIVER_FW_SSH_TIMEOUT=/d' /etc/lldpq.conf
    render_preserved_provisioning_config \
        "$_SAVE_AUTO_BASE_CONFIG" \
        "$_SAVE_AUTO_ZTP_DISABLE" \
        "$_SAVE_AUTO_SET_HOSTNAME" \
        "$_SAVE_TRANSCEIVER_FW_SKIP_MODELS" \
        "$_SAVE_TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY" \
        "$_SAVE_TRANSCEIVER_FW_MAX_PARALLEL" \
        "$_SAVE_TRANSCEIVER_FW_MIN_INTERVAL" \
        "$_SAVE_TRANSCEIVER_FW_SSH_TIMEOUT" | sudo tee -a /etc/lldpq.conf > /dev/null
    # Preserve AI settings. Values (API key, model like "openai/gpt-5.5", URLs) often
    # contain '/', '|', '&' which break `sed s///` ("unknown option to s"), so delete
    # the freshly-written default lines and re-append the preserved values with echo
    # (safe for ANY value).
    sudo sed -i '/^AI_PROVIDER=/d;/^AI_MODEL=/d;/^AI_FALLBACK_MODEL=/d;/^AI_CONTEXT_WINDOW_TOKENS=/d;/^AI_FALLBACK_CONTEXT_WINDOW_TOKENS=/d;/^AI_API_KEY=/d;/^AI_API_URL=/d;/^OLLAMA_URL=/d;/^AI_PROXY_URL=/d;/^AI_SEARCH_MODEL=/d;/^AI_SEARCH_URL=/d;/^AI_SEARCH_KEY=/d' /etc/lldpq.conf
    render_ai_config \
        "$_SAVE_AI_PROVIDER" \
        "$_SAVE_AI_MODEL" \
        "$_SAVE_AI_API_KEY" \
        "$_SAVE_AI_API_URL" \
        "$_SAVE_OLLAMA_URL" \
        "$_SAVE_AI_PROXY_URL" \
        "$_SAVE_AI_SEARCH_MODEL" \
        "$_SAVE_AI_SEARCH_URL" \
        "$_SAVE_AI_SEARCH_KEY" \
        "$_SAVE_AI_FALLBACK_MODEL" \
        "$_SAVE_AI_CONTEXT_WINDOW_TOKENS" \
        "$_SAVE_AI_FALLBACK_CONTEXT_WINDOW_TOKENS" | sudo tee -a /etc/lldpq.conf > /dev/null
fi

# Create cache and data files with correct permissions
for f in device-cache.json fabric-scan-cache.json discovery-cache.json inventory.json; do
    if [ ! -f "$WEB_ROOT/$f" ]; then
        echo '{}' | sudo tee "$WEB_ROOT/$f" > /dev/null
    fi
    sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/$f"
    sudo chmod 664 "$WEB_ROOT/$f"
done

normalize_installed_lldpq_config_access || exit 1
echo "  Configuration saved to /etc/lldpq.conf"

# ============================================================================
# COMMON: Sudoers
# ============================================================================
step "Configuring sudoers..."

echo "www-data ALL=($LLDPQ_USER) NOPASSWD: /usr/bin/timeout, /usr/bin/ssh, /usr/bin/scp, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/tee, /usr/bin/cat, /usr/bin/ssh-keygen, /usr/bin/bash, /bin/bash" | \
    sudo tee /etc/sudoers.d/www-data-lldpq > /dev/null
sudo chmod 440 /etc/sudoers.d/www-data-lldpq

echo "www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start isc-dhcp-server, /usr/bin/systemctl stop isc-dhcp-server, /usr/bin/systemctl restart isc-dhcp-server, /usr/bin/systemctl disable isc-dhcp-server, /usr/bin/systemctl enable isc-dhcp-server, /usr/bin/tee /etc/dhcp/dhcpd.conf, /usr/bin/tee /etc/dhcp/dhcpd.hosts, /usr/bin/tee /etc/default/isc-dhcp-server, /usr/bin/tee /etc/lldpq.conf, /usr/bin/cp, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/mv -fT -- /etc/lldpq.conf.lldpq-root-stage /etc/lldpq.conf, /usr/bin/mv -fT -- /etc/dhcp/dhcpd.conf.lldpq-root-stage /etc/dhcp/dhcpd.conf, /usr/bin/mv -fT -- /etc/dhcp/dhcpd.hosts.lldpq-root-stage /etc/dhcp/dhcpd.hosts, /usr/bin/mv -fT -- /etc/dhcp/dhcpd.host.lldpq-root-stage /etc/dhcp/dhcpd.host, /usr/bin/mv -fT -- /etc/default/isc-dhcp-server.lldpq-root-stage /etc/default/isc-dhcp-server, /usr/bin/sync -f /etc/lldpq.conf.lldpq-root-stage, /usr/bin/sync -f /etc/dhcp/dhcpd.conf.lldpq-root-stage, /usr/bin/sync -f /etc/dhcp/dhcpd.hosts.lldpq-root-stage, /usr/bin/sync -f /etc/dhcp/dhcpd.host.lldpq-root-stage, /usr/bin/sync -f /etc/default/isc-dhcp-server.lldpq-root-stage, /usr/bin/sync -f /etc, /usr/bin/sync -f /etc/dhcp, /usr/bin/sync -f /etc/default, /usr/bin/mv -fT -- /etc/crontab.lldpq-root-stage /etc/crontab, /usr/bin/mv -fT -- /etc/cron.d/lldpq.lldpq-root-stage /etc/cron.d/lldpq, /usr/bin/pkill -x dhcpd, /usr/sbin/dhcpd, /usr/bin/cat /etc/dhcp/dhcpd.conf, /usr/bin/chmod, /usr/bin/chown" | \
    sudo tee /etc/sudoers.d/www-data-provision > /dev/null
sudo chmod 440 /etc/sudoers.d/www-data-provision

_auth_sudoers_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-auth-sudoers.XXXXXX") || exit 1
if ! printf '%s\n' \
    "www-data ALL=(root) NOPASSWD: $LLDPQ_AUTH_USERS_HELPER \"\"" \
    > "$_auth_sudoers_tmp" || \
   ! chmod 0440 "$_auth_sudoers_tmp" || \
   ! sudo /usr/sbin/visudo -cf "$_auth_sudoers_tmp" >/dev/null || \
   ! sudo install -o root -g root -m 0440 -- \
        "$_auth_sudoers_tmp" "$LLDPQ_AUTH_USERS_SUDOERS"; then
    rm -f "$_auth_sudoers_tmp"
    echo "[!] Could not install the authentication users sudoers policy" >&2
    exit 1
fi
rm -f "$_auth_sudoers_tmp"
if [[ -L "$LLDPQ_AUTH_USERS_SUDOERS" ]] || \
   [[ "$(sudo stat -c '%u:%g:%a' -- "$LLDPQ_AUTH_USERS_SUDOERS" 2>/dev/null || true)" != \
      "0:0:440" ]]; then
    echo "[!] Authentication users sudoers policy verification failed" >&2
    exit 1
fi
echo "  Sudoers configured (SSH/SCP + DHCP/Provision + SSH key mgmt)"

# ============================================================================
# COMMON: DHCP & ZTP directories
# ============================================================================
step "Preparing DHCP/Provision directories..."

sudo mkdir -p /etc/dhcp /var/lib/dhcp
sudo touch /var/lib/dhcp/dhcpd.leases

# A foreign DHCP configuration belongs to the operator.  Auto-yes deliberately
# does not authorize replacing it; only --replace-dhcp-config does.  New or
# explicitly replaced templates are syntax-checked before activation and an
# existing file is always copied to a timestamped backup first.
OUR_IP=$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print; exit}')
OUR_IP="${OUR_IP:-127.0.0.1}"
_dhcp_status=0
prepare_default_dhcp_config \
    /etc/dhcp/dhcpd.conf \
    /etc/dhcp/dhcpd.hosts \
    "$REPLACE_DHCP_CONFIG" \
    "$LLDPQ_USER" \
    www-data \
    "$OUR_IP" || _dhcp_status=$?
case "$_dhcp_status" in
    0)
        echo "  Default DHCP config validated and installed (server: ${OUR_IP})"
        ;;
    10)
        # LLDPq already owns this config, so ensure its include exists and has
        # the expected shared web/CLI permissions.
        [ ! -f /etc/dhcp/dhcpd.hosts ] && sudo touch /etc/dhcp/dhcpd.hosts
        sudo chown "$LLDPQ_USER:www-data" /etc/dhcp/dhcpd.hosts
        sudo chmod 664 /etc/dhcp/dhcpd.hosts
        ;;
    11)
        echo "  DHCP provisioning integration skipped; existing config was not changed"
        ;;
    *)
        echo "  [!] Unable to prepare a validated DHCP configuration" >&2
        exit "$_dhcp_status"
        ;;
esac

# ZTP script with serial-based config resolution (if not exists)
if [ ! -f "$WEB_ROOT/cumulus-ztp.sh" ]; then
    sudo tee "$WEB_ROOT/cumulus-ztp.sh" > /dev/null << 'ZTPEOF'
#!/bin/bash

#
# CUMULUS-AUTOPROVISIONING
# Generated by LLDPq Provision
# LLDPQ_ZTP_TEMPLATE_VERSION=2
#

function ping_until_reachable(){
    local target="${1-}"
    local max_tries=30
    local tries=0

    if [ -z "$target" ]; then
        echo "$(date) ERROR: Image server target is empty." >&2
        return 1
    fi
    while [ "$tries" -lt "$max_tries" ]; do
        tries=$((tries+1))
        echo "$(date) INFO: ( Attempt $tries of $max_tries ) Pinging $target Target Until Reachable."
        if ping "$target" -c2 --no-vrf-switch >/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "$(date) ERROR: Reached maximum number of attempts to ping the target $target ." >&2
    return 1
}

function set_password(){
    passwd -x 99999 cumulus &&
        echo 'cumulus:Nvidia@123' | chpasswd
}

function get_current_release(){
    local release_file="${1:-/etc/lsb-release}"
    local release=""

    release=$(LC_ALL=C awk -F= '
        $1 == "DISTRIB_RELEASE" {
            print substr($0, index($0, "=") + 1)
            found = 1
            exit
        }
        $1 == "RELEASE" { fallback = substr($0, index($0, "=") + 1) }
        END { if (!found && fallback != "") print fallback }
    ' "$release_file") || return 1
    release=${release%$'\r'}
    case "$release" in
        \"*\") release=${release#\"}; release=${release%\"} ;;
        \'*\') release=${release#\'}; release=${release%\'} ;;
    esac
    [[ "$release" =~ ^[0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
    printf '%s\n' "$release"
}

function is_valid_serial(){
    local serial="${1-}"
    [[ -n "$serial" && ${#serial} -le 128 && "$serial" =~ ^[[:alnum:]_.:-]+$ ]]
}

function select_hostname_from_mapping(){
    local serial="${1-}"
    local mapping="${2-}"

    if ! is_valid_serial "$serial" || [ -z "$mapping" ]; then
        return 2
    fi

    printf '%s\n' "$mapping" | LC_ALL=C awk -v wanted="$serial" '
        function serial_ok(value) {
            return length(value) > 0 && length(value) <= 128 && \
                value ~ /^[[:alnum:]_.:-]+$/
        }
        function hostname_ok(value) {
            return length(value) > 0 && length(value) <= 253 && \
                value ~ /^[[:alnum:]][[:alnum:]_.-]*$/
        }
        BEGIN { wanted = tolower(wanted) }
        { sub(/\r$/, "") }
        /^[[:space:]]*(#|$)/ { next }
        {
            if (NF != 2 || !serial_ok($1) || !hostname_ok($2)) {
                invalid = 1
                next
            }
            serial_key = tolower($1)
            hostname_key = tolower($2)
            if (++seen_serial[serial_key] > 1 || ++seen_hostname[hostname_key] > 1) {
                invalid = 1
            }
            if (serial_key == wanted) {
                matches++
                hostname = $2
            }
        }
        END {
            if (invalid || matches > 1) exit 2
            if (matches == 1) {
                print hostname
                exit 0
            }
            exit 1
        }
    '
}

function resolve_hostname(){
    local serial="${1-}"
    local mapping_url="http://$IMAGE_SERVER_HOSTNAME/serial-mapping.txt"
    local mapping=""

    if ! is_valid_serial "$serial"; then
        return 2
    fi
    if ! mapping=$(curl --fail --silent --show-error --connect-timeout 5 \
        --max-time 15 --retry 2 -- "$mapping_url"); then
        echo "Unable to download serial mapping from $mapping_url" >&2
        return 2
    fi
    if [ "${#mapping}" -gt 8388608 ]; then
        echo "Serial mapping is too large" >&2
        return 2
    fi
    select_hostname_from_mapping "$serial" "$mapping"
}

function find_config_url(){
    local hostname="${1-}"
    local destination="${2-}"
    local extension=""
    local url=""
    local candidate=""
    local http_code=""
    local byte_count=0

    [[ -n "$hostname" && ${#hostname} -le 253 && \
        "$hostname" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]] || return 2
    [ -n "$destination" ] || return 2
    candidate="${destination}.download"
    rm -f -- "$candidate"

    for extension in yaml yml; do
        url="http://$IMAGE_SERVER_HOSTNAME/generated_config_folder/${hostname}.${extension}"
        if ! http_code=$(curl --silent --show-error --connect-timeout 5 \
            --max-time 60 --retry 2 --output "$candidate" \
            --write-out '%{http_code}' -- "$url"); then
            rm -f -- "$candidate"
            echo "Unable to download generated config from $url" >&2
            return 2
        fi
        case "$http_code" in
            200)
                if [ ! -s "$candidate" ]; then
                    rm -f -- "$candidate"
                    echo "Generated config from $url is empty" >&2
                    return 2
                fi
                byte_count=$(wc -c < "$candidate") || {
                    rm -f -- "$candidate"
                    return 2
                }
                if [ "$byte_count" -gt 16777216 ]; then
                    rm -f -- "$candidate"
                    echo "Generated config from $url is too large" >&2
                    return 2
                fi
                mv -f -- "$candidate" "$destination" || return 2
                printf '%s\n' "$url"
                return 0
                ;;
            404)
                rm -f -- "$candidate"
                ;;
            *)
                rm -f -- "$candidate"
                echo "Generated config request failed with HTTP $http_code: $url" >&2
                return 2
                ;;
        esac
    done
    return 1
}

function install_authorized_key(){
    local directory="${1-}"
    local owner="${2-}"
    local group="${3-}"
    local authorized_keys="$directory/authorized_keys"

    [ -n "$KEY" ] || return 0
    mkdir -p "$directory" || return 1
    chmod 700 "$directory" || return 1
    touch "$authorized_keys" || return 1
    if ! grep -Fqx -- "$KEY" "$authorized_keys"; then
        if [ -s "$authorized_keys" ] &&
            [ "$(tail -c 1 "$authorized_keys" | wc -l)" -eq 0 ]; then
            printf '\n' >> "$authorized_keys" || return 1
        fi
        printf '%s\n' "$KEY" >> "$authorized_keys" || return 1
    fi
    chmod 600 "$authorized_keys" || return 1
    chown "$owner:$group" "$directory" "$authorized_keys" || return 1
}

function install_cumulus_sudoers(){
    local target=/etc/sudoers.d/10_cumulus
    local staged=""

    staged=$(mktemp /etc/sudoers.d/.10_cumulus.XXXXXX) || return 1
    if ! printf '%s\n' 'cumulus ALL=(ALL) NOPASSWD:ALL' > "$staged" || \
        ! chmod 440 "$staged"; then
        rm -f "$staged"
        return 1
    fi
    if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$staged" >/dev/null; then
        rm -f "$staged"
        return 1
    fi
    mv -f "$staged" "$target"
}

function apply_generated_config(){
    local staged="${1-}"

    if [ ! -s "$staged" ]; then
        echo "Generated config is missing or empty" >&2
        return 1
    fi
    command -v nv >/dev/null 2>&1 || return 1
    if ! nv config replace "$staged" || ! nv config apply -y || ! nv config save; then
        echo "Failed to apply generated config for ${MY_HOSTNAME-unknown}" >&2
        return 1
    fi
    echo "Config applied and saved for ${MY_HOSTNAME-unknown}"
}

function init_ztp(){
    echo "Running ZTP..."

    if ! set_password; then
        echo "Failed to set the cumulus password" >&2
        return 1
    fi
    if ! install_cumulus_sudoers; then
        echo "Failed to install the cumulus sudoers policy" >&2
        return 1
    fi

    KEY=""
    if [ -n "$KEY" ]; then
        if ! install_authorized_key /root/.ssh root root || \
            ! install_authorized_key /home/cumulus/.ssh cumulus cumulus; then
            echo "Failed to install the SSH key" >&2
            return 1
        fi
        echo "SSH key installed"
    fi

    if [ -n "${CONFIG_FILE-}" ]; then
        echo "Applying generated config for $MY_HOSTNAME..."
        apply_generated_config "$CONFIG_FILE" || return 1
    fi
    return 0
}

function main(){
    umask 077

    IMAGE_SERVER_HOSTNAME=__IMAGE_SERVER_IP__
    CUMULUS_TARGET_RELEASE=__TARGET_OS_VERSION__
    if ! CUMULUS_CURRENT_RELEASE=$(get_current_release); then
        echo "Unable to determine the current Cumulus release; refusing OS install" >&2
        return 1
    fi
    if ! [[ "$CUMULUS_TARGET_RELEASE" =~ ^[0-9][A-Za-z0-9._-]{0,63}$ ]]; then
        echo "Invalid target Cumulus release" >&2
        return 1
    fi
    IMAGE_SERVER=http://$IMAGE_SERVER_HOSTNAME/cumulus-linux-$CUMULUS_TARGET_RELEASE-mlx-amd64.bin
    ZTP_URL=http://$IMAGE_SERVER_HOSTNAME/cumulus-ztp.sh
    IMAGE_SERVER_PING_TARGET=${IMAGE_SERVER_HOSTNAME%%:*}
    WORK_DIR=$(mktemp -d /tmp/lldpq-ztp.XXXXXX) || return 1
    trap 'rm -rf -- "${WORK_DIR-}"' EXIT

    MY_SERIAL=$(decode-syseeprom 2>/dev/null | awk '/Serial Number/ {print $NF; exit}')
    [ -z "$MY_SERIAL" ] && MY_SERIAL=$(onie-syseeprom -g 0x23 2>/dev/null | tr -d '[:space:]')
    echo "Serial: $MY_SERIAL"

    MY_HOSTNAME=$(resolve_hostname "$MY_SERIAL")
    mapping_status=$?
    case "$mapping_status" in
        0) ;;
        1) MY_HOSTNAME="" ;;
        *)
            echo "Serial mapping validation or download failed; refusing provisioning" >&2
            return 1
            ;;
    esac
    echo "Resolved hostname: $MY_HOSTNAME"

    CONFIG_URL=""
    CONFIG_FILE=""
    if [ -n "$MY_HOSTNAME" ]; then
        CONFIG_FILE="$WORK_DIR/startup.yaml"
        CONFIG_URL=$(find_config_url "$MY_HOSTNAME" "$CONFIG_FILE")
        config_status=$?
        case "$config_status" in
            0) echo "Config downloaded and verified: $CONFIG_URL" ;;
            1)
                CONFIG_URL=""
                CONFIG_FILE=""
                echo "No generated config found for $MY_HOSTNAME"
                ;;
            *)
                echo "Generated config lookup failed; refusing provisioning" >&2
                return 1
                ;;
        esac
    else
        echo "Serial $MY_SERIAL was not resolved; no config will be applied"
    fi

    echo "Checking if the device is running the correct version..."
    if [ "$CUMULUS_TARGET_RELEASE" != "$CUMULUS_CURRENT_RELEASE" ]; then
        echo "Version mismatch: $CUMULUS_CURRENT_RELEASE -> $CUMULUS_TARGET_RELEASE"
        ping_until_reachable "$IMAGE_SERVER_PING_TARGET" || return 1
        if [ -n "$CONFIG_FILE" ]; then
            echo "Installing OS + config for $MY_HOSTNAME..."
            /usr/cumulus/bin/onie-install -fa -i "$IMAGE_SERVER" -z "$ZTP_URL" \
                -t "$CONFIG_FILE" || return 1
        else
            echo "Installing OS only (no config)..."
            /usr/cumulus/bin/onie-install -fa -i "$IMAGE_SERVER" -z "$ZTP_URL" || return 1
        fi
        rm -rf -- "$WORK_DIR"
        trap - EXIT
        reboot || return 1
    else
        echo "Version is correct: $CUMULUS_TARGET_RELEASE"
        init_ztp || return 1
        rm -rf -- "$WORK_DIR"
        trap - EXIT
    fi
    return 0
}

# ---- Main ----

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
ZTPEOF
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/cumulus-ztp.sh"
sudo chmod 775 "$WEB_ROOT/cumulus-ztp.sh"
echo "  DHCP/Provision directories ready"

# ============================================================================
# COMMON: Authentication
# ============================================================================
step "Setting up authentication..."

sudo mkdir -p /var/lib/lldpq/sessions /var/lib/lldpq/upgrade-jobs /var/lib/lldpq/ai
sudo chown www-data:www-data /var/lib/lldpq
sudo chown www-data:www-data /var/lib/lldpq/sessions
sudo chown "$LLDPQ_USER:www-data" /var/lib/lldpq/upgrade-jobs
sudo chown "$LLDPQ_USER:www-data" /var/lib/lldpq/ai
sudo chmod 755 /var/lib/lldpq
sudo chmod 700 /var/lib/lldpq/sessions
sudo chmod 775 /var/lib/lldpq/upgrade-jobs
sudo chmod 2770 /var/lib/lldpq/ai
prepare_shared_lock_files /var/lib/lldpq/ssh-key.lock
# Opaque LLDP/Assets refresh lifecycle state must survive daemon restarts and
# source-tree replacement.  setgid keeps atomic CGI/daemon replacements in the
# shared group regardless of which side creates the temporary file.
sudo install -d -o "$LLDPQ_USER" -g www-data -m 2770 /var/lib/lldpq/lldp-jobs
sudo install -d -o "$LLDPQ_USER" -g www-data -m 2770 /var/lib/lldpq/assets-jobs
sudo install -d -o "$LLDPQ_USER" -g www-data -m 2770 /var/lib/lldpq/provision-jobs
# Migrate legacy Ask-AI state out of the nginx document root without replacing
# a newer private copy. Existing updates therefore retain memory and analysis.
for ai_state_mapping in \
    "ai-analysis.json:analysis.json" \
    "ai-learnings.json:learnings.json" \
    "ai-analysis-snapshot.json:analysis-snapshot.json"; do
    legacy_ai_state="$WEB_ROOT/${ai_state_mapping%%:*}"
    private_ai_state="/var/lib/lldpq/ai/${ai_state_mapping#*:}"
    if [[ -f "$legacy_ai_state" ]] && {
        [[ ! -s "$private_ai_state" ]] ||
        sudo grep -Eq '^[[:space:]]*(\{\}|\[\])[[:space:]]*$' "$private_ai_state" 2>/dev/null
    }; then
        sudo mv -f "$legacy_ai_state" "$private_ai_state"
    elif [[ -f "$legacy_ai_state" ]]; then
        sudo rm -f "$legacy_ai_state"
    fi
done
[[ -f /var/lib/lldpq/ai/analysis.json ]] || printf '{}\n' | sudo tee /var/lib/lldpq/ai/analysis.json > /dev/null
[[ -f /var/lib/lldpq/ai/learnings.json ]] || printf '[]\n' | sudo tee /var/lib/lldpq/ai/learnings.json > /dev/null
[[ -f /var/lib/lldpq/ai/analysis-snapshot.json ]] || printf '{}\n' | sudo tee /var/lib/lldpq/ai/analysis-snapshot.json > /dev/null
sudo chown "$LLDPQ_USER:www-data" /var/lib/lldpq/ai/*.json
sudo chmod 660 /var/lib/lldpq/ai/*.json
echo "  Sessions directory configured"

if [[ "$INSTALL_MODE" == "fresh" ]] || [[ ! -f /etc/lldpq-users.conf ]]; then
    ADMIN_HASH=$(echo -n "admin" | openssl dgst -sha256 | awk '{print $2}')
    OPERATOR_HASH=$(echo -n "operator" | openssl dgst -sha256 | awk '{print $2}')
    echo "admin:$ADMIN_HASH:admin" | sudo tee /etc/lldpq-users.conf > /dev/null
    echo "operator:$OPERATOR_HASH:operator" | sudo tee -a /etc/lldpq-users.conf > /dev/null
    echo "  Users file created with default credentials:"
    echo "    admin / admin"
    echo "    operator / operator"
    echo "  [!] IMPORTANT: Change default passwords after first login!"
else
    echo "  Users file already exists, keeping existing credentials"
fi
sudo chmod 600 /etc/lldpq-users.conf
sudo chown www-data:www-data /etc/lldpq-users.conf
if ! prepare_shared_lock_files /etc/lldpq-users.conf.lock; then
    echo "[!] Could not prepare the authentication users transaction lock" >&2
    exit 1
fi

# ============================================================================
# COMMON: Verify Python packages (update mode — fresh already installed them)
# ============================================================================
if [[ "$INSTALL_MODE" == "update" ]]; then
    step "Verifying Python packages..."
    sudo -H -u "$LLDPQ_USER" python3 -c 'import requests, ruamel.yaml' 2>/dev/null || {
        echo "[!] Required Python packages disappeared after update preflight" >&2
        exit 1
    }
    echo "  Python packages verified"
fi

# ============================================================================
# COMMON: Retained import recovery (boot + SIGKILL path trigger)
# ============================================================================
step "Configuring retained-import recovery..."

_recovery_unit_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-recovery-units.XXXXXX")
_recovery_service_tmp="$_recovery_unit_tmp_dir/lldpq-recovery.service"
_recovery_path_tmp="$_recovery_unit_tmp_dir/lldpq-recovery.path"
if ! render_lldpq_recovery_service \
        "$_recovery_service_tmp" "$LLDPQ_USER" "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" || \
   ! render_lldpq_recovery_path \
        "$_recovery_path_tmp" \
        "$LLDPQ_USER_HOME/.lldpq-state/.backup-import-recovery/manifest.json"; then
    rm -rf "$_recovery_unit_tmp_dir"
    echo "  [!] Could not render retained-import recovery units" >&2
    exit 1
fi
if ! _recovery_verify_output=$(systemd-analyze verify \
        "$_recovery_service_tmp" "$_recovery_path_tmp" 2>&1); then
    echo "  [!] Retained-import recovery unit verification failed" >&2
    [[ -n "$_recovery_verify_output" ]] && \
        printf '%s\n' "$_recovery_verify_output" >&2
    rm -rf "$_recovery_unit_tmp_dir"
    exit 1
fi
if ! sudo cp "$_recovery_service_tmp" /etc/systemd/system/lldpq-recovery.service || \
   ! sudo cp "$_recovery_path_tmp" /etc/systemd/system/lldpq-recovery.path || \
   ! sudo chmod 644 /etc/systemd/system/lldpq-recovery.service \
       /etc/systemd/system/lldpq-recovery.path; then
    rm -rf "$_recovery_unit_tmp_dir"
    echo "  [!] Could not install retained-import recovery units" >&2
    exit 1
fi
if ! rm -rf "$_recovery_unit_tmp_dir"; then
    echo "  [!] Installed recovery units verified, but the local temporary directory remains: $_recovery_unit_tmp_dir" >&2
fi
if ! sudo systemctl daemon-reload; then
    echo "  [!] Could not reload systemd after installing recovery units" >&2
    show_lldpq_recovery_diagnostics
    exit 1
fi
if ! sudo systemctl enable lldpq-recovery.service lldpq-recovery.path >/dev/null 2>&1; then
    echo "  [!] Could not enable retained-import recovery units" >&2
    show_lldpq_recovery_diagnostics
    exit 1
fi
# This blocking start consumes any authority before nginx/fcgiwrap are restarted.
# Later path-triggered starts wait on /etc/lldpq.conf.lock until an in-flight
# Setup import either commits (then recovery is a no-op) or dies (then rollback).
if ! sudo systemctl start lldpq-recovery.service; then
    echo "  [!] Retained backup-import recovery failed; web services were not restarted" >&2
    show_lldpq_recovery_diagnostics
    exit 1
fi
if ! sudo systemctl start lldpq-recovery.path; then
    echo "  [!] Could not start retained-import recovery watcher" >&2
    show_lldpq_recovery_diagnostics
    exit 1
fi
echo "  retained-import recovery service + path watcher enabled"

# ============================================================================
# COMMON: Nginx configuration
# ============================================================================
step "Configuring nginx..."

sudo ln -sf /etc/nginx/sites-available/lldpq /etc/nginx/sites-enabled/lldpq
[ -L /etc/nginx/sites-enabled/default ] && sudo unlink /etc/nginx/sites-enabled/default || true

# Fix IPv6 listen directive if IPv6 is not supported on this system
if ! cat /proc/net/if_inet6 >/dev/null 2>&1; then
    echo "  IPv6 not available — removing [::] listen directives from nginx config"
    sudo sed -i '/listen \[::]/d' /etc/nginx/sites-available/lldpq
fi

if sudo nginx -t 2>&1; then
    echo "  nginx config OK"
else
    echo "  [!] nginx configuration validation failed" >&2
    exit 1
fi
sudo systemctl restart fcgiwrap
if [[ "$INSTALL_MODE" == "update" ]]; then
    # Keep nginx stopped until preserved reports are restored and rollback can
    # no longer be needed. The EXIT transaction handler performs the start.
    _UPDATE_WEB_QUIESCED=true
    echo "  nginx configured; restart deferred until update commit"
else
    sudo systemctl restart nginx
    _UPDATE_WEB_QUIESCED=false
    echo "  nginx and fcgiwrap configured and restarted"
fi

# ============================================================================
# COMMON: Console service (web SSH terminal — WebSocket/PTY bridge)
# ============================================================================
step "Configuring console service..."

# Runs as www-data (to validate admin sessions); opens PTYs as $LLDPQ_USER via sudo.
sudo tee /etc/systemd/system/lldpq-console.service > /dev/null <<UNIT
[Unit]
Description=LLDPq Console (web SSH terminal WebSocket/PTY bridge)
After=network.target nginx.service

[Service]
Type=simple
User=www-data
Group=www-data
Environment=LLDPQ_CONF=/etc/lldpq.conf
ExecStart=/usr/bin/python3 $LLDPQ_INSTALL_DIR/console-pty.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
sudo mkdir -p /var/log/lldpq 2>/dev/null || true
sudo chown www-data:www-data /var/log/lldpq 2>/dev/null || true

# Route ISC DHCP server logs to a dedicated file so the Provision "DHCP Logs" panel can
# read them without journal access. (In Docker, dhcpd -d writes this file directly; on a
# systemd/rsyslog host, dhcpd logs via syslog and rsyslog forwards them here.)
if [ -d /etc/rsyslog.d ]; then
    sudo touch /var/log/lldpq/dhcpd.log 2>/dev/null || true
    sudo chown syslog:www-data /var/log/lldpq/dhcpd.log 2>/dev/null || sudo chown root:www-data /var/log/lldpq/dhcpd.log 2>/dev/null || true
    sudo chmod 640 /var/log/lldpq/dhcpd.log 2>/dev/null || true
    sudo tee /etc/rsyslog.d/10-lldpq-dhcp.conf > /dev/null <<'RSYSLOG_DHCP'
# LLDPq: send ISC dhcpd messages to a file the web UI (www-data) can tail.
if $programname == 'dhcpd' then {
    action(type="omfile" file="/var/log/lldpq/dhcpd.log" fileGroup="www-data" fileCreateMode="0640")
}
RSYSLOG_DHCP
    sudo systemctl restart rsyslog 2>/dev/null || sudo service rsyslog restart 2>/dev/null || true
    echo "  DHCP logs → /var/log/lldpq/dhcpd.log (rsyslog)"
fi

sudo systemctl daemon-reload
if ! sudo systemctl enable lldpq-console.service >/dev/null 2>&1; then
    echo "  [!] Could not enable lldpq-console.service" >&2
    exit 1
fi
if ! sudo systemctl restart lldpq-console.service; then
    echo "  [!] Could not start lldpq-console.service" >&2
    exit 1
fi
if ! sudo systemctl is-active --quiet lldpq-console.service; then
    echo "  [!] lldpq-console.service did not remain active after restart" >&2
    exit 1
fi
echo "  console-pty service enabled (127.0.0.1:8765)"

# ============================================================================
# COMMON: Cron jobs
# ============================================================================
step "Configuring cron jobs..."

_include_fabric_cron=false
if [[ "$ANSIBLE_DIR" != "NoNe" ]] && [[ -d "$ANSIBLE_DIR" ]] && [[ -d "$ANSIBLE_DIR/playbooks" ]]; then
    _include_fabric_cron=true
    chmod +x "$LLDPQ_INSTALL_DIR/fabric-scan-cron.sh" 2>/dev/null || true
    echo "  - fabric-scan: daily at 03:33 (Ansible diff check)"
fi

_cron_file_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-cron.d.XXXXXX")
render_lldpq_cron_file \
    "$_cron_file_tmp" \
    "$LLDPQ_USER" \
    "$LLDPQ_INSTALL_DIR" \
    "$WEB_ROOT" \
    "${LLDPQ_CRON:-*/10 * * * *}" \
    "${GETCONF_CRON:-0 */12 * * *}" \
    "$_include_fabric_cron"
install_lldpq_cron_transaction \
    "$_cron_file_tmp" /etc/crontab /etc/cron.d/lldpq "$LLDPQ_INSTALL_DIR"
rm -f "$_cron_file_tmp"
echo "  - installed /etc/cron.d/lldpq, then migrated exact legacy entries"

echo "  Cron jobs configured:"
echo "    - lldpq:           every 10 minutes"
echo "    - get-conf:        every 12 hours"
echo "    - web triggers:    every minute (enables Run LLDP Check button)"
echo "    - git auto-commit: daily at midnight"
echo "    - ownership:       /etc/cron.d/lldpq"

# ============================================================================
# UPDATE-ONLY: Restore monitoring data & summary
# ============================================================================
if [[ "$INSTALL_MODE" == "update" ]]; then

    if [[ -n "$_DATA_PRESERVE" ]] && [[ -d "$_DATA_PRESERVE" ]]; then
        step "Restoring monitoring data..."
        for _d in monitor-results lldp-results alert-states assets.ini; do
            if [[ -e "$_DATA_PRESERVE/$_d" ]]; then
                if ! root_run rm -rf "$LLDPQ_INSTALL_DIR/$_d" 2>/dev/null || \
                   ! root_run mv "$_DATA_PRESERVE/$_d" "$LLDPQ_INSTALL_DIR/" 2>/dev/null; then
                    echo "[!] Could not restore preserved runtime data: $_DATA_PRESERVE/$_d" >&2
                    exit 1
                fi
                echo "  • $_d/"
            fi
        done
        # Fix ownership and permissions on restored data
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/monitor-results" 2>/dev/null || true
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/lldp-results" 2>/dev/null || true
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/alert-states" 2>/dev/null || true
        sudo chown "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/assets.ini" 2>/dev/null || true
        sudo chmod 664 "$LLDPQ_INSTALL_DIR/assets.ini" 2>/dev/null || true
        sudo find "$LLDPQ_INSTALL_DIR/monitor-results" -type d -exec chmod 775 {} \; 2>/dev/null || true
        sudo find "$LLDPQ_INSTALL_DIR/monitor-results" -type f -exec chmod 664 {} \; 2>/dev/null || true
        if find "$_DATA_PRESERVE" -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
            echo "[!] Preserved runtime directory is not empty; refusing to delete it: $_DATA_PRESERVE" >&2
            exit 1
        fi
        rmdir "$_DATA_PRESERVE" || {
            echo "[!] Could not remove the empty runtime preserve directory: $_DATA_PRESERVE" >&2
            exit 1
        }
        echo "  Monitoring data restored"
    fi

    step "Update summary"
    echo "  Preserved:"
    echo "    • $LLDPQ_INSTALL_DIR/devices.yaml"
    echo "    • $LLDPQ_INSTALL_DIR/tracking.yaml"
    echo "    • $WEB_ROOT/topology.dot"
    echo "    • $WEB_ROOT/topology_config.yaml"
    [[ -f "$LLDPQ_INSTALL_DIR/notifications.yaml" ]] && echo "    • $LLDPQ_INSTALL_DIR/notifications.yaml"
    [[ -d "$LLDPQ_INSTALL_DIR/monitor-results" ]] && echo "    • monitor-results/"
    [[ -d "$LLDPQ_INSTALL_DIR/lldp-results" ]] && echo "    • lldp-results/"
    [[ -d "$LLDPQ_INSTALL_DIR/alert-states" ]] && echo "    • alert-states/"
    echo ""
    echo "  Full backup: $BACKUP_DIR"
fi

# ============================================================================
# FRESH-ONLY: Post-install setup
# ============================================================================
if [[ "$INSTALL_MODE" == "fresh" ]]; then

    step "Configuration files to edit"
    echo "  You need to manually edit these files with your network details:"
    echo ""
    echo "  1. nano $LLDPQ_INSTALL_DIR/devices.yaml           # Define your network devices (required)"
    echo "  2. nano $LLDPQ_INSTALL_DIR/topology.dot           # Define your network topology"
    echo "  Note: zzh (SSH manager) automatically loads devices from devices.yaml"
    echo ""
    echo "  See README.md for examples of each file format"

    step "Streaming Telemetry (Optional)"
    echo "  Telemetry provides real-time metrics dashboard with:"
    echo "  - Interface throughput, errors, drops charts"
    echo "  - Platform temperature monitoring"
    echo "  - Active alerts from Prometheus"
    echo "  - Requires Docker to run OTEL Collector + Prometheus"
    echo ""

    TELEMETRY_ENABLED=false
    if [[ "$AUTO_YES" == "true" ]]; then
        echo "  Skipping telemetry (auto-yes mode, run './install.sh --enable-telemetry' later)"
    else
        read -p "  Enable streaming telemetry support? [y/N]: " telemetry_response
        if [[ "$telemetry_response" =~ ^[Yy]$ ]]; then
            TELEMETRY_ENABLED=true
        fi
    fi

    if [[ "$TELEMETRY_ENABLED" == "true" ]]; then
        echo ""
        echo "  Checking Docker installation..."

        if ! command -v docker &> /dev/null; then
            echo "  Docker not found. Installing Docker..."
            curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
            sudo sh /tmp/get-docker.sh
            sudo usermod -aG docker "$LLDPQ_USER"
            rm /tmp/get-docker.sh
            echo "  Docker installed successfully"
            echo "  [!] NOTE: You may need to logout/login for Docker group to take effect"
        else
            echo "  Docker found: $(docker --version)"
        fi

        if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
            echo "  Installing docker-compose..."
            sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            sudo chmod +x /usr/local/bin/docker-compose
            echo "  docker-compose installed"
        fi

        if grep -q "^TELEMETRY_ENABLED=" /etc/lldpq.conf 2>/dev/null; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=true/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=true" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        if ! grep -q "^PROMETHEUS_URL=" /etc/lldpq.conf 2>/dev/null; then
            echo "PROMETHEUS_URL=http://localhost:9090" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        echo ""
        echo "  Telemetry support enabled!"
        echo ""

        # Configure Docker storage driver if needed (for VMs without overlay support)
        if [[ ! -f /etc/docker/daemon.json ]]; then
            echo "  Configuring Docker storage driver..."
            sudo mkdir -p /etc/docker
            echo '{"storage-driver": "vfs"}' | sudo tee /etc/docker/daemon.json > /dev/null
            sudo systemctl restart docker
        fi

        # Start the telemetry stack automatically
        if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]; then
            echo ""
            echo "  Starting telemetry stack..."
            cd "$LLDPQ_INSTALL_DIR/telemetry"
            if docker compose up -d 2>&1; then
                :
            elif docker-compose up -d 2>&1; then
                :
            elif sudo docker compose up -d 2>&1; then
                :
            elif sudo docker-compose up -d 2>&1; then
                :
            else
                echo "  [!] Could not start stack. Try manually:"
                echo "      cd $LLDPQ_INSTALL_DIR/telemetry && sudo docker compose up -d"
            fi
            cd - > /dev/null

            sleep 3
            if docker ps --filter "name=lldpq-prometheus" --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
                echo ""
                echo "  Telemetry stack is running:"
                echo "    - OTEL Collector: http://localhost:4317"
                echo "    - Prometheus:     http://localhost:9090"
                echo "    - Alertmanager:   http://localhost:9093"
            fi
        fi

        echo ""
        echo "  Next step: Enable telemetry on switches from web UI:"
        echo "    Telemetry → Configuration → Enable Telemetry"
    else
        echo "  Telemetry skipped. Enable later with: ./install.sh --enable-telemetry"

        if grep -q "^TELEMETRY_ENABLED=" /etc/lldpq.conf 2>/dev/null; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=false/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=false" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi
    fi

    step "SSH Key Setup Required"
    echo "  Before using LLDPq, you must setup SSH key authentication:"
    echo ""
    echo "  For each device in your network:"
    echo "    ssh-copy-id username@device_ip"
    echo ""
    echo "  And ensure sudo works without password on each device:"
    echo "    sudo visudo  # Add: username ALL=(ALL) NOPASSWD:ALL"

    step "Initializing git repository in $LLDPQ_INSTALL_DIR..."
    # git normally arrives with the apt packages above, but a git-less host
    # (e.g. offline tarball install) must degrade gracefully instead of
    # aborting the whole install under set -e.
    if ! command -v git >/dev/null 2>&1; then
        echo "  [!] git not found — skipping git repository setup (config history disabled)"
    else
    cd "$LLDPQ_INSTALL_DIR"

    # Create .gitignore
    cat > .gitignore << 'EOF'
# Output directories (dynamic, changes frequently)
lldp-results/
monitor-results/

# Temporary and backup files
*.log
*.tmp
*.pid
*.bak

# Python cache
__pycache__/
*.pyc
EOF

    # Configure git user if not set (required for commits)
    if ! git config --global user.name >/dev/null 2>&1; then
        git config --global user.name "$LLDPQ_USER"
    fi
    if ! git config --global user.email >/dev/null 2>&1; then
        git config --global user.email "$LLDPQ_USER@$(hostname)"
    fi

    # Initialize git repo with main branch (modern Git convention)
    git init -q -b main
    git add -A
    git commit -q -m "Initial LLDPq configuration"

    # Configure git for group permissions
    git config core.sharedRepository group

    # Add git hooks to preserve permissions after git operations
    echo "  Setting up git hooks for permission preservation..."
    cat > .git/hooks/post-merge << 'HOOKEOF'
#!/bin/bash
# Fix permissions after git pull/merge (preserve group read access for www-data)
chmod 750 "$(git rev-parse --show-toplevel)" 2>/dev/null || true
chmod 664 "$(git rev-parse --show-toplevel)/devices.yaml" 2>/dev/null || true
chmod 664 "$(git rev-parse --show-toplevel)/tracking.yaml" 2>/dev/null || true
if [ -d "$(git rev-parse --show-toplevel)/monitor-results" ]; then
    chmod -R 750 "$(git rev-parse --show-toplevel)/monitor-results" 2>/dev/null || true
fi
HOOKEOF
    chmod +x .git/hooks/post-merge
    cp .git/hooks/post-merge .git/hooks/post-checkout

    echo "  Git repository initialized with initial commit"
    echo "  Git hooks created (permissions preserved after git operations)"
    fi
fi

# Fresh telemetry choices use privileged in-place editors after the initial
# config write. Reassert and verify canonical metadata here as the final
# authority for both fresh installs and updates.
normalize_installed_lldpq_config_access || exit 1

# ============================================================================
# TELEMETRY DOCKER ACCESS (self-healing on every install/update)
# ============================================================================
# The web UI (www-data) and lldpq scripts must reach the Docker socket to start/
# manage the telemetry stack. Without this the UI hits "permission denied ...
# /var/run/docker.sock". Granted idempotently whenever telemetry is enabled and
# Docker is present, so existing deployments self-heal on their next update.
if command -v docker >/dev/null 2>&1 && \
   [[ "${TELEMETRY_ENABLED:-false}" == "true" ]]; then
    _docker_granted=false
    for _u in www-data "$LLDPQ_USER"; do
        [[ -z "$_u" ]] && continue
        if id -nG "$_u" 2>/dev/null | grep -qw docker; then
            continue
        fi
        if sudo usermod -aG docker "$_u" 2>/dev/null; then
            _docker_granted=true
            echo "  Granted Docker access to '$_u' (telemetry stack management)"
        fi
    done
    # fcgiwrap must restart to pick up the new group membership
    if [[ "$_docker_granted" == "true" ]]; then
        sudo systemctl restart fcgiwrap 2>/dev/null || sudo service fcgiwrap restart 2>/dev/null || true
    fi
fi

# Publish source deletion authority only after the final configuration rewrite
# and every ordinary install step has succeeded, but before a successful update
# discards its rollback snapshot. A crash/failure on either side is therefore
# recovered with the matching previous manifest (or removes it on first update).
if ! manage_lldpq_source_manifest install "$LLDPQ_SRC_DIR"; then
    echo "[!] Could not publish the root-owned LLDPq source manifest" >&2
    exit 1
fi
echo "  Source provenance saved to $LLDPQ_SOURCE_MANIFEST"

# Finalize the update transaction before printing a success banner. Calling
# the same EXIT handler explicitly keeps asynchronous failures (runtime data
# restore or nginx start) from ever being presented as a completed update.
if [[ "$INSTALL_MODE" == "update" ]]; then
    if ! lldpq_install_exit_handler 0 return; then
        exit 1
    fi
fi

# ============================================================================
# COMPLETE
# ============================================================================
echo ""
echo "=================================="
if [[ "$INSTALL_MODE" == "update" ]]; then
    echo "LLDPq Update Complete!"
else
    echo "LLDPq Installation Complete!"
fi
echo "=================================="
echo ""
echo "  Web interface: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost')"
echo ""

if [[ "$INSTALL_MODE" == "fresh" ]]; then
    echo "  Default login credentials:"
    echo "    admin / admin       (full access)"
    echo "    operator / operator (no Ansible access)"
    echo "  [!] Change these passwords after first login!"
    echo ""
    echo "  Next steps:"
    echo "    1. Edit devices.yaml with your network devices"
    echo "    2. Setup SSH keys for all devices"
    echo "    3. Test: lldpq, get-conf, zzh, pping"
    echo ""
    echo "  For detailed configuration examples, see README.md"
fi

if [[ -n "$BACKUP_DIR" ]] && [[ -d "$BACKUP_DIR" ]]; then
    echo "  Backup location: $BACKUP_DIR"
    echo "  (Delete when no longer needed: rm -rf $BACKUP_DIR)"
fi

echo ""
echo "LLDPq $(if [[ "$INSTALL_MODE" == "update" ]]; then echo "update"; else echo "installation"; fi) completed successfully!"
echo ""
