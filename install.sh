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
# │   • pip install (requests, ruamel.yaml)                  │
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

# Root/system services and the web backup workflow must never execute the copy
# under LLDPQ_DIR: that tree is intentionally writable by the service account.
LLDPQ_BACKUP_IMPORT_HELPER="/usr/local/libexec/lldpq-backup-import.py"

# Read legacy KEY=value configuration without executing it as shell code.  The
# file is intentionally writable by the shared web/CLI group, so `source` would
# turn a configuration write into arbitrary code execution during install.
load_lldpq_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value config_lock_fd=""

    [[ -f "$config_file" ]] || return 0
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
        raw="${BASH_REMATCH[2]}"

        # Only variables that LLDPq itself writes/consumes are accepted.  This
        # also prevents assignment to shell internals such as PATH or BASH_ENV.
        case "$key" in
            LLDPQ_DIR|LLDPQ_USER|LLDPQ_SRC|LLDPQ_CRON|GETCONF_CRON|WEB_ROOT|\
            ANSIBLE_DIR|EDITOR_ROOT|PROJECT_DIR|DHCP_HOSTS_FILE|DHCP_CONF_FILE|\
            DHCP_LEASES_FILE|ZTP_SCRIPT_FILE|BASE_CONFIG_DIR|AUTO_BASE_CONFIG|\
            AUTO_ZTP_DISABLE|AUTO_SET_HOSTNAME|SKIP_OPTICAL|SKIP_L1|\
            MONITOR_MAX_PARALLEL|LLDP_MAX_PARALLEL|ASSETS_MAX_PARALLEL|\
            GET_CONFIGS_MAX_PARALLEL|GET_CONFIGS_SSH_TIMEOUT|SEND_CMD_MAX_PARALLEL|TELEMETRY_MAX_PARALLEL|\
            TRANSCEIVER_FW_SKIP_MODELS|TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY|\
            TRANSCEIVER_FW_MAX_PARALLEL|TRANSCEIVER_FW_MIN_INTERVAL|\
            TRANSCEIVER_FW_SSH_TIMEOUT|TELEMETRY_ENABLED|PROMETHEUS_URL|\
            TELEMETRY_COLLECTOR_IP|TELEMETRY_COLLECTOR_PORT|\
            TELEMETRY_COLLECTOR_VRF|DISCOVERY_RANGE|SCAN_INTERVAL|AI_PROVIDER|AI_MODEL|\
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

    [[ "$user" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || {
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
        echo "* * * * * $user cd $q_install && ./fabric-scan.sh >/dev/null 2>&1"
        echo "0 0 * * * $user cd $q_install && cp $q_web/topology.dot topology.dot.bkp 2>/dev/null; cp $q_web/topology_config.yaml topology_config.yaml.bkp 2>/dev/null; git add -A; git diff --cached --quiet || git commit -m 'auto: \$(date +\\%Y-\\%m-\\%d)'"
        echo "0 * * * * $user /usr/local/bin/lldpq-ai-analyze"
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
        [[ "$user" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || return 1
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
    printf 'AI_PROVIDER=%s\n' "$provider"
    printf 'AI_MODEL=%s\n' "$model"
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
    case "$scan_interval" in
        ''|*[!0-9]*|0) scan_interval=300 ;;
    esac
    case "$getconfigs_ssh_timeout" in
        ''|*[!0-9]*|0) getconfigs_ssh_timeout=60 ;;
    esac
    printf 'LLDPQ_CRON="%s"\n' "$lldpq_cron"
    printf 'GETCONF_CRON="%s"\n' "$getconf_cron"
    printf 'SKIP_OPTICAL=%s\n' "$skip_optical"
    printf 'SKIP_L1=%s\n' "$skip_l1"
    printf 'MONITOR_MAX_PARALLEL=%s\n' "$monitor_parallel"
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
        grep -Fqx '# /etc/dhcp/dhcpd.conf - Generated by LLDPq' "$conf_file"
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
UPDATE_PROCESS_LOCK_FD=""

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
    if ! root_run mkdir -p "$UPDATE_ROLLBACK_DIR/system" || \
       ! snapshot_update_file /etc/lldpq.conf lldpq.conf || \
       ! snapshot_update_file /etc/cron.d/lldpq cron.d-lldpq || \
       ! snapshot_update_file /etc/crontab crontab || \
       ! snapshot_update_file /etc/dhcp/dhcpd.conf dhcpd.conf || \
       ! snapshot_update_file /etc/dhcp/dhcpd.hosts dhcpd.hosts || \
       ! snapshot_update_file /etc/default/isc-dhcp-server isc-dhcp-default || \
       ! snapshot_update_file /etc/lldpq.conf.lock lldpq.conf.lock || \
       ! snapshot_update_file "$LLDPQ_BACKUP_IMPORT_HELPER" backup-import-helper || \
       ! snapshot_update_file /etc/sudoers.d/www-data-lldpq sudoers-www-data-lldpq || \
       ! snapshot_update_file /etc/sudoers.d/www-data-provision sudoers-www-data-provision || \
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

    if [[ -d "$LLDPQ_INSTALL_DIR" ]]; then
        # Publish the rollback intent before the destructive rename. If the
        # installer receives TERM/HUP/INT while waiting for mv, the EXIT
        # handler must already know that the previous tree belongs here.
        UPDATE_ROLLBACK_HAD_INSTALL=true
        UPDATE_ROLLBACK_ACTIVE=true
        if ! root_run mv "$LLDPQ_INSTALL_DIR" "$UPDATE_ROLLBACK_DIR/install"; then
            UPDATE_ROLLBACK_ACTIVE=false
            UPDATE_ROLLBACK_HAD_INSTALL=false
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
        for runtime_dir in monitor-results lldp-results alert-states; do
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
    restore_update_file /etc/cron.d/lldpq cron.d-lldpq || rollback_restore_failed=true
    restore_update_file /etc/crontab crontab || rollback_restore_failed=true
    restore_update_file /etc/dhcp/dhcpd.conf dhcpd.conf || rollback_restore_failed=true
    restore_update_file /etc/dhcp/dhcpd.hosts dhcpd.hosts || rollback_restore_failed=true
    restore_update_file /etc/default/isc-dhcp-server isc-dhcp-default || rollback_restore_failed=true
    restore_update_file /etc/lldpq.conf.lock lldpq.conf.lock || rollback_restore_failed=true
    restore_update_file "$LLDPQ_BACKUP_IMPORT_HELPER" backup-import-helper || rollback_restore_failed=true
    restore_update_file /etc/sudoers.d/www-data-lldpq sudoers-www-data-lldpq || rollback_restore_failed=true
    restore_update_file /etc/sudoers.d/www-data-provision sudoers-www-data-provision || rollback_restore_failed=true
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
    if root_run nginx -t >/dev/null 2>&1; then
        root_run systemctl try-reload-or-restart nginx 2>/dev/null || rollback_restore_failed=true
    else
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
    root_run rm -rf "$UPDATE_ROLLBACK_DIR" 2>/dev/null || \
        echo "[!] Rollback succeeded, but its completed snapshot remains at: $UPDATE_ROLLBACK_DIR" >&2
    UPDATE_ROLLBACK_ACTIVE=false
    UPDATE_ROLLBACK_CORE_RESTORED=true
    return 0
}

commit_update_rollback() {
    [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" ]] || return 0
    local completed_rollback_dir="$UPDATE_ROLLBACK_DIR"
    UPDATE_ROLLBACK_ACTIVE=false
    UPDATE_ROLLBACK_DIR=""
    root_run rm -rf "$completed_rollback_dir" 2>/dev/null || \
        echo "  [!] Completed update rollback snapshot could not be removed: $completed_rollback_dir" >&2
}

restore_preserved_runtime_data() {
    local preserve_dir="${_DATA_PRESERVE:-}"
    local runtime_dir restore_failed=false
    [[ -n "$preserve_dir" && -d "$preserve_dir" ]] || return 0

    for runtime_dir in monitor-results lldp-results alert-states; do
        if [[ -e "$preserve_dir/$runtime_dir" && \
              ! -e "$LLDPQ_INSTALL_DIR/$runtime_dir" ]]; then
            if ! root_run mv "$preserve_dir/$runtime_dir" \
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
    local rollback_attempted=false
    local rollback_core_ok=true
    local runtime_restore_ok=true
    trap - EXIT
    if (( status != 0 )) && \
       [[ "$UPDATE_ROLLBACK_ACTIVE" == "true" && -n "$UPDATE_ROLLBACK_DIR" ]]; then
        rollback_attempted=true
        rollback_failed_update || rollback_core_ok=false
    fi
    restore_preserved_runtime_data || runtime_restore_ok=false
    # Never let the recovery trigger inherit the process-wide monitor lock.
    # Keeping this descriptor open in a long-running child would block every
    # subsequent cron/web collection indefinitely.
    release_update_process_lock
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
              "$runtime_restore_ok" == "true" ]]; then
            if [[ -n "$UPDATE_ROLLBACK_RESTORED_VERSION" ]]; then
                echo "[!] Update failed, but automatic rollback completed; active runtime remains $UPDATE_ROLLBACK_RESTORED_VERSION. The requested update was not installed." >&2
            else
                echo "[!] Update failed, but automatic rollback completed; the previous runtime remains active. The requested update was not installed." >&2
            fi
        else
            echo "[!] Automatic rollback was incomplete; review the retained paths and errors above before retrying." >&2
        fi
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
LLDPQ_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
load_lldpq_config "$LLDPQ_CONFIG_FILE"

# ============================================================================
# TELEMETRY-ONLY MODE (early exit — no other changes needed)
# ============================================================================
if [[ "$ENABLE_TELEMETRY" == "true" ]] || [[ "$DISABLE_TELEMETRY" == "true" ]]; then
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

        if grep -q "^TELEMETRY_ENABLED=" /etc/lldpq.conf 2>/dev/null; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=true/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=true" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        if ! grep -q "^PROMETHEUS_URL=" /etc/lldpq.conf 2>/dev/null; then
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

        if grep -q "^TELEMETRY_ENABLED=" /etc/lldpq.conf 2>/dev/null; then
            sudo sed -i 's/^TELEMETRY_ENABLED=.*/TELEMETRY_ENABLED=false/' /etc/lldpq.conf
        else
            echo "TELEMETRY_ENABLED=false" | sudo tee -a /etc/lldpq.conf > /dev/null
        fi

        echo "Telemetry support disabled"
    fi

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

# Check if we're in the lldpq-src directory
if [[ ! -f "README.md" ]] || [[ ! -d "lldpq" ]]; then
    echo "[!] Please run this script from the lldpq-src directory"
    echo "    Make sure you're in the directory containing README.md and lldpq/"
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
if [[ ! "$LLDPQ_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
    echo "[!] Invalid LLDPQ_USER in configuration: '$LLDPQ_USER'" >&2
    exit 1
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
            sudo rm -f /etc/lldpq.conf
            sudo rm -f /etc/lldpq-users.conf
            sudo rm -rf /var/lib/lldpq
            echo "  Old installation files removed"
            INSTALL_MODE="fresh"
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
    sudo apt install -y nginx fcgiwrap python3 python3-pip python3-yaml util-linux bsdextrautils sshpass unzip acl isc-dhcp-server || {
        echo "[!] Package installation failed"
        echo "    Try running: sudo apt --fix-broken install"
        exit 1
    }
    sudo systemctl enable --now nginx
    sudo systemctl enable --now fcgiwrap

    step "Downloading Monaco Editor for offline use..."
    MONACO_VERSION="0.45.0"
    MONACO_DIR="$WEB_ROOT/monaco"
    if [[ ! -d "$MONACO_DIR" ]]; then
        echo "  Downloading Monaco Editor v${MONACO_VERSION}..."
        TMP_DIR=$(mktemp -d)
        if curl -sL "https://registry.npmjs.org/monaco-editor/-/monaco-editor-${MONACO_VERSION}.tgz" -o "$TMP_DIR/monaco.tgz"; then
            mkdir -p "$TMP_DIR/monaco"
            tar -xzf "$TMP_DIR/monaco.tgz" -C "$TMP_DIR/monaco" --strip-components=1
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

    echo "  Installing Python packages..."
    pip3 install --user requests ruamel.yaml >/dev/null 2>&1 || \
        pip3 install requests ruamel.yaml >/dev/null 2>&1 || \
        echo "  [!] Some Python packages may need manual installation"
    echo "  Python packages installed (requests, ruamel.yaml)"
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

        # Configuration files
        _backup_copy "$LLDPQ_INSTALL_DIR/devices.yaml" "$BACKUP_DIR/" devices.yaml || exit 1
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
        for _d in monitor-results lldp-results alert-states; do
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
    if [[ -f "$LLDPQ_INSTALL_DIR/devices.yaml" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/devices.yaml" "$_preserved_dir/" || {
            echo "[!] Could not preserve devices.yaml; update was not started" >&2
            sudo rm -rf "$_preserved_dir" 2>/dev/null || true
            _preserved_dir=""
            exit 1
        }
    fi
    if [[ -f "$LLDPQ_INSTALL_DIR/notifications.yaml" ]]; then
        sudo cp -a "$LLDPQ_INSTALL_DIR/notifications.yaml" "$_preserved_dir/" || {
            echo "[!] Could not preserve notifications.yaml; update was not started" >&2
            sudo rm -rf "$_preserved_dir" 2>/dev/null || true
            _preserved_dir=""
            exit 1
        }
    fi
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
    acquire_update_process_lock || exit 1

    _data_preserve_failed=false
    for _d in monitor-results lldp-results alert-states; do
        if [[ -e "$LLDPQ_INSTALL_DIR/$_d" ]] && \
           ! root_run mv "$LLDPQ_INSTALL_DIR/$_d" "$_DATA_PRESERVE/" 2>/dev/null; then
            echo "[!] Could not preserve runtime data before update: $LLDPQ_INSTALL_DIR/$_d" >&2
            _data_preserve_failed=true
            break
        fi
    done
    if [[ "$_data_preserve_failed" == "true" ]]; then
        _data_restore_failed=false
        for _d in monitor-results lldp-results alert-states; do
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
sudo cp -r etc/* /etc/

echo "  - Copying html/* to $WEB_ROOT/"
sudo cp -r html/* "$WEB_ROOT/"

# Ensure Monaco Editor exists (may have been deleted or never downloaded)
MONACO_DIR="$WEB_ROOT/monaco"
if [[ ! -d "$MONACO_DIR" ]]; then
    echo "  - Downloading Monaco Editor..."
    MONACO_VERSION="0.45.0"
    TMP_DIR=$(mktemp -d)
    if curl -sL "https://registry.npmjs.org/monaco-editor/-/monaco-editor-${MONACO_VERSION}.tgz" -o "$TMP_DIR/monaco.tgz"; then
        mkdir -p "$TMP_DIR/monaco"
        tar -xzf "$TMP_DIR/monaco.tgz" -C "$TMP_DIR/monaco" --strip-components=1
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

# Create serial-mapping.txt if it doesn't exist
if [ ! -f "$WEB_ROOT/serial-mapping.txt" ]; then
    echo -e "# Serial → Hostname mapping for ZTP config resolution\n# Format: SERIAL_NUMBER  HOSTNAME\n" | sudo tee "$WEB_ROOT/serial-mapping.txt" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/serial-mapping.txt"
sudo chmod 664 "$WEB_ROOT/serial-mapping.txt"

echo "  - Copying bin/* to /usr/local/bin/"
sudo cp bin/* /usr/local/bin/
sudo chmod 755 /usr/local/bin/lldpq /usr/local/bin/lldpq-trigger 2>/dev/null || true
sudo chmod 755 /usr/local/bin/*
if [[ ! -x /usr/local/bin/lldpq-config ]]; then
    echo "[!] Required runtime config helper was not installed: /usr/local/bin/lldpq-config" >&2
    exit 1
fi
if ! /usr/local/bin/lldpq-config --require-config \
   --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
   --config "$LLDPQ_CONFIG_FILE" >/dev/null 2>&1 && \
   [[ "$INSTALL_MODE" == "update" ]]; then
    echo "[!] Existing runtime configuration cannot be read safely: $LLDPQ_CONFIG_FILE" >&2
    exit 1
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

echo "  - Copying lldpq to $LLDPQ_INSTALL_DIR"
sudo mkdir -p "$LLDPQ_INSTALL_DIR"
sudo cp -r lldpq/* "$LLDPQ_INSTALL_DIR/"
# The source file is packaged with the application, but no installed workflow
# may import or execute the service-user-writable copy.
sudo rm -f "$LLDPQ_INSTALL_DIR/backup_import.py"
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
    cat > "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge" << 'HOOKEOF'
#!/bin/bash
# Fix permissions after git pull/merge (preserve group read access for www-data)
chmod 750 "$(git rev-parse --show-toplevel)" 2>/dev/null || true
chmod 664 "$(git rev-parse --show-toplevel)/devices.yaml" 2>/dev/null || true
if [ -d "$(git rev-parse --show-toplevel)/monitor-results" ]; then
    chmod -R 750 "$(git rev-parse --show-toplevel)/monitor-results" 2>/dev/null || true
fi
HOOKEOF
    chmod +x "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge"
    cp "$LLDPQ_INSTALL_DIR/.git/hooks/post-merge" "$LLDPQ_INSTALL_DIR/.git/hooks/post-checkout"
    git -C "$LLDPQ_INSTALL_DIR" config core.sharedRepository group 2>/dev/null || true
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
    rm -f "$LLDPQ_INSTALL_DIR/topology.dot" 2>/dev/null
elif [[ -f "$LLDPQ_INSTALL_DIR/topology.dot" ]]; then
    sudo mv "$LLDPQ_INSTALL_DIR/topology.dot" "$WEB_ROOT/topology.dot"
else
    echo "    Creating empty topology.dot"
    echo "# LLDPq Topology Definition" | sudo tee "$WEB_ROOT/topology.dot" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/topology.dot"
sudo chmod 664 "$WEB_ROOT/topology.dot"
ln -sf "$WEB_ROOT/topology.dot" "$LLDPQ_INSTALL_DIR/topology.dot"

echo "  - topology_config.yaml"
if [[ -f "$WEB_ROOT/topology_config.yaml" ]]; then
    echo "    Existing topology_config.yaml preserved in web root"
    rm -f "$LLDPQ_INSTALL_DIR/topology_config.yaml" 2>/dev/null
elif [[ -f "$LLDPQ_INSTALL_DIR/topology_config.yaml" ]]; then
    sudo mv "$LLDPQ_INSTALL_DIR/topology_config.yaml" "$WEB_ROOT/topology_config.yaml"
else
    echo "    Creating empty topology_config.yaml"
    echo "{}" | sudo tee "$WEB_ROOT/topology_config.yaml" > /dev/null
fi
sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/topology_config.yaml"
sudo chmod 664 "$WEB_ROOT/topology_config.yaml"
ln -sf "$WEB_ROOT/topology_config.yaml" "$LLDPQ_INSTALL_DIR/topology_config.yaml"

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
    "${SKIP_L1:-true}" \
    "${MONITOR_MAX_PARALLEL:-100}" \
    "${LLDP_MAX_PARALLEL:-100}" \
    "${ASSETS_MAX_PARALLEL:-100}" \
    "${GET_CONFIGS_MAX_PARALLEL:-100}" \
    "${SEND_CMD_MAX_PARALLEL:-25}" \
    "${TELEMETRY_MAX_PARALLEL:-25}" \
    "${_SAVE_SCAN_INTERVAL:-${SCAN_INTERVAL:-300}}" \
    "${_SAVE_GET_CONFIGS_SSH_TIMEOUT:-${GET_CONFIGS_SSH_TIMEOUT:-60}}" | \
    sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SKIP_MODELS=\"\"" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=skip" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MAX_PARALLEL=10" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MIN_INTERVAL=1800" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SSH_TIMEOUT=300" | sudo tee -a /etc/lldpq.conf > /dev/null
render_ai_config \
    ollama llama3.2 "" https://api.openai.com/v1 http://localhost:11434 \
    "" "" "" "" | sudo tee -a /etc/lldpq.conf > /dev/null

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
    sudo sed -i '/^AI_PROVIDER=/d;/^AI_MODEL=/d;/^AI_API_KEY=/d;/^AI_API_URL=/d;/^OLLAMA_URL=/d;/^AI_PROXY_URL=/d;/^AI_SEARCH_MODEL=/d;/^AI_SEARCH_URL=/d;/^AI_SEARCH_KEY=/d' /etc/lldpq.conf
    render_ai_config \
        "$_SAVE_AI_PROVIDER" \
        "$_SAVE_AI_MODEL" \
        "$_SAVE_AI_API_KEY" \
        "$_SAVE_AI_API_URL" \
        "$_SAVE_OLLAMA_URL" \
        "$_SAVE_AI_PROXY_URL" \
        "$_SAVE_AI_SEARCH_MODEL" \
        "$_SAVE_AI_SEARCH_URL" \
        "$_SAVE_AI_SEARCH_KEY" | sudo tee -a /etc/lldpq.conf > /dev/null
fi

# Create cache and data files with correct permissions
for f in device-cache.json fabric-scan-cache.json discovery-cache.json inventory.json ai-analysis.json; do
    if [ ! -f "$WEB_ROOT/$f" ]; then
        echo '{}' | sudo tee "$WEB_ROOT/$f" > /dev/null
    fi
    sudo chown "$LLDPQ_USER:www-data" "$WEB_ROOT/$f"
    sudo chmod 664 "$WEB_ROOT/$f"
done

# Set permissions so web server can update telemetry config
USER_GROUP=$(id -gn)
sudo chown root:$USER_GROUP /etc/lldpq.conf
sudo chmod 664 /etc/lldpq.conf
sudo touch /etc/lldpq.conf.lock
sudo chown root:$USER_GROUP /etc/lldpq.conf.lock
sudo chmod 664 /etc/lldpq.conf.lock
sudo usermod -a -G $USER_GROUP www-data 2>/dev/null || true
sudo usermod -a -G www-data "$LLDPQ_USER" 2>/dev/null || true
echo "  Configuration saved to /etc/lldpq.conf"

# ============================================================================
# COMMON: Sudoers
# ============================================================================
step "Configuring sudoers..."

echo "www-data ALL=($LLDPQ_USER) NOPASSWD: /usr/bin/timeout, /usr/bin/ssh, /usr/bin/scp, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/tee, /usr/bin/cat, /usr/bin/ssh-keygen, /usr/bin/bash, /bin/bash" | \
    sudo tee /etc/sudoers.d/www-data-lldpq > /dev/null
sudo chmod 440 /etc/sudoers.d/www-data-lldpq

echo "www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start isc-dhcp-server, /usr/bin/systemctl stop isc-dhcp-server, /usr/bin/systemctl restart isc-dhcp-server, /usr/bin/systemctl disable isc-dhcp-server, /usr/bin/systemctl enable isc-dhcp-server, /usr/bin/tee /etc/dhcp/dhcpd.conf, /usr/bin/tee /etc/dhcp/dhcpd.hosts, /usr/bin/tee /etc/default/isc-dhcp-server, /usr/bin/tee /etc/lldpq.conf, /usr/bin/cp, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/pkill -x dhcpd, /usr/sbin/dhcpd, /usr/bin/cat /etc/dhcp/dhcpd.conf, /usr/bin/chmod, /usr/bin/chown" | \
    sudo tee /etc/sudoers.d/www-data-provision > /dev/null
sudo chmod 440 /etc/sudoers.d/www-data-provision
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
#

function ping_until_reachable(){
    last_code=1
    max_tries=30
    tries=0
    while [ "0" != "$last_code" ] && [ "$tries" -lt "$max_tries" ]; do
        tries=$((tries+1))
        echo "$(date) INFO: ( Attempt $tries of $max_tries ) Pinging $1 Target Until Reachable."
        ping $1 -c2 --no-vrf-switch &> /dev/null
        last_code=$?
        sleep 1
    done
    if [ "$tries" -eq "$max_tries" ] && [ "$last_code" -ne "0" ]; then
        echo "$(date) ERROR: Reached maximum number of attempts to ping the target $1 ."
        exit 1
    fi
}

function set_password(){
    passwd -x 99999 cumulus
    echo 'cumulus:Nvidia@123' | chpasswd
}

# Resolve hostname from serial number via mapping file on HTTP server
function resolve_hostname(){
    local serial="$1"
    local mapping_url="http://$IMAGE_SERVER_HOSTNAME/serial-mapping.txt"
    local hostname=""
    local mapping=$(curl -sf "$mapping_url" 2>/dev/null)
    if [ -n "$mapping" ]; then
        hostname=$(echo "$mapping" | grep -v '^#' | awk -v s="$serial" 'tolower($1) == tolower(s) {print $2; exit}')
    fi
    echo "$hostname"
}

function init_ztp(){
    echo "Running ZTP..."

    # Change default password
    set_password

    # Make user cumulus passwordless sudo
    echo "cumulus ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/10_cumulus

    # Copy SSH keys
    KEY=""
    if [ -n "$KEY" ]; then
        mkdir -p /root/.ssh /home/cumulus/.ssh
        echo "$KEY" >> /root/.ssh/authorized_keys
        echo "$KEY" >> /home/cumulus/.ssh/authorized_keys
        chown -R cumulus:cumulus /home/cumulus/.ssh
        echo "SSH key installed"
    fi

    # Apply generated config if version was already correct
    if [ -n "$CONFIG_URL" ]; then
        echo "Applying generated config for $MY_HOSTNAME..."
        curl -sf "$CONFIG_URL" -o /tmp/startup.yaml
        if [ -s /tmp/startup.yaml ]; then
            nv config replace /tmp/startup.yaml
            nv config apply -y
            nv config save
            echo "Config applied and saved for $MY_HOSTNAME"
        fi
    fi

    exit 0
}

# ---- Main ----

IMAGE_SERVER_HOSTNAME=__IMAGE_SERVER_IP__
CUMULUS_TARGET_RELEASE=__TARGET_OS_VERSION__
CUMULUS_CURRENT_RELEASE=$(cat /etc/lsb-release | grep RELEASE | cut -d "=" -f2)
IMAGE_SERVER=http://$IMAGE_SERVER_HOSTNAME/cumulus-linux-$CUMULUS_TARGET_RELEASE-mlx-amd64.bin
ZTP_URL=http://$IMAGE_SERVER_HOSTNAME/cumulus-ztp.sh

# Get this switch's serial number and resolve hostname
MY_SERIAL=$(decode-syseeprom 2>/dev/null | grep "Serial Number" | awk '{print $NF}')
[ -z "$MY_SERIAL" ] && MY_SERIAL=$(onie-syseeprom -g 0x23 2>/dev/null | tr -d ' ')
echo "Serial: $MY_SERIAL"

MY_HOSTNAME=$(resolve_hostname "$MY_SERIAL")
echo "Resolved hostname: $MY_HOSTNAME"

# Check if a generated config exists for this switch
CONFIG_URL=""
if [ -n "$MY_HOSTNAME" ]; then
    URL="http://$IMAGE_SERVER_HOSTNAME/generated_config_folder/${MY_HOSTNAME}.yaml"
    if curl -sf --head "$URL" 2>/dev/null | head -1 | grep -q "200"; then
        CONFIG_URL="$URL"
        echo "Config available: $CONFIG_URL"
    else
        echo "No generated config found for $MY_HOSTNAME"
    fi
else
    echo "Serial $MY_SERIAL not found in mapping — no config will be applied"
fi

echo "Checking if the device is running the correct version..."
if [ "$CUMULUS_TARGET_RELEASE" != "$CUMULUS_CURRENT_RELEASE" ]; then
    echo "Version mismatch: $CUMULUS_CURRENT_RELEASE -> $CUMULUS_TARGET_RELEASE"
    ping_until_reachable $IMAGE_SERVER_HOSTNAME
    if [ -n "$CONFIG_URL" ]; then
        echo "Installing OS + config for $MY_HOSTNAME..."
        /usr/cumulus/bin/onie-install -fa -i $IMAGE_SERVER -z $ZTP_URL -t $CONFIG_URL && reboot
    else
        echo "Installing OS only (no config)..."
        /usr/cumulus/bin/onie-install -fa -i $IMAGE_SERVER -z $ZTP_URL && reboot
    fi
else
    echo "Version is correct: $CUMULUS_TARGET_RELEASE"
    init_ztp
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

sudo mkdir -p /var/lib/lldpq/sessions /var/lib/lldpq/upgrade-jobs
sudo chown www-data:www-data /var/lib/lldpq
sudo chown www-data:www-data /var/lib/lldpq/sessions
sudo chown "$LLDPQ_USER:www-data" /var/lib/lldpq/upgrade-jobs
sudo chmod 755 /var/lib/lldpq
sudo chmod 700 /var/lib/lldpq/sessions
sudo chmod 775 /var/lib/lldpq/upgrade-jobs
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

# ============================================================================
# COMMON: Verify Python packages (update mode — fresh already installed them)
# ============================================================================
if [[ "$INSTALL_MODE" == "update" ]]; then
    step "Verifying Python packages..."
    if ! python3 -c "import ruamel.yaml" 2>/dev/null; then
        echo "  Installing ruamel.yaml..."
        pip3 install --user ruamel.yaml >/dev/null 2>&1 || \
            pip3 install ruamel.yaml >/dev/null 2>&1 || \
            echo "  [!] ruamel.yaml installation failed — YAML comment preservation may not work"
    fi
    if ! python3 -c "import requests" 2>/dev/null; then
        echo "  Installing requests..."
        pip3 install --user requests >/dev/null 2>&1 || \
            pip3 install requests >/dev/null 2>&1 || true
    fi
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
    echo "  [!] nginx -t reported warnings — check /etc/nginx/sites-available/lldpq"
fi
sudo systemctl restart nginx
sudo systemctl restart fcgiwrap
echo "  nginx and fcgiwrap configured and restarted"

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
        for _d in monitor-results lldp-results alert-states; do
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
if [ -d "$(git rev-parse --show-toplevel)/monitor-results" ]; then
    chmod -R 750 "$(git rev-parse --show-toplevel)/monitor-results" 2>/dev/null || true
fi
HOOKEOF
    chmod +x .git/hooks/post-merge
    cp .git/hooks/post-merge .git/hooks/post-checkout

    echo "  Git repository initialized with initial commit"
    echo "  Git hooks created (permissions preserved after git operations)"
fi

# ============================================================================
# TELEMETRY DOCKER ACCESS (self-healing on every install/update)
# ============================================================================
# The web UI (www-data) and lldpq scripts must reach the Docker socket to start/
# manage the telemetry stack. Without this the UI hits "permission denied ...
# /var/run/docker.sock". Granted idempotently whenever telemetry is enabled and
# Docker is present, so existing deployments self-heal on their next update.
if command -v docker >/dev/null 2>&1 && grep -q "^TELEMETRY_ENABLED=true" /etc/lldpq.conf 2>/dev/null; then
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

if [[ "$INSTALL_MODE" == "update" ]]; then
    commit_update_rollback
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
