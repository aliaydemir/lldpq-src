#!/usr/bin/env bash
# LLDPq Uninstaller — removes everything install.sh sets up
#
# Usage:
#   ./uninstall.sh            # interactive (asks for confirmation)
#   ./uninstall.sh -y         # auto-yes
#   ./uninstall.sh --dry-run  # show what would be removed, do nothing
#   ./uninstall.sh --keep-data  # keep monitor-results/lldp-results/devices.yaml
#   ./uninstall.sh --force-partial # also remove an unrecognized partial install tree
#   ./uninstall.sh --remove-docker # also remove Docker packages and data
#   ./uninstall.sh --remove-dhcp   # also remove isc-dhcp-server package/config
#
# What it removes:
#   - LLDPq cron entries (/etc/crontab + /etc/cron.d/lldpq)
#   - lldpq-trigger daemon process
#   - retained-import recovery systemd service + path watcher
#   - root-owned backup/import helper and validated native recovery remnants
#   - /usr/local/bin/{lldpq, lldpq-config, lldpq-trigger, lldpq-ai-analyze, zzh, pping, send-cmd, get-conf}
#   - /var/www/html web content (nginx + fcgiwrap site removed)
#   - $LLDPQ_INSTALL_DIR (default ~/lldpq)
#   - /etc/lldpq.conf, /etc/lldpq.conf.lock, /etc/lldpq-users.conf
#   - /var/lib/lldpq (sessions)
#   - /etc/sudoers.d/{www-data-lldpq, www-data-provision}
#   - /etc/nginx/sites-{available,enabled}/lldpq + reload nginx
#   - LLDPq DHCP config markers (does NOT touch dhcp service itself unless --remove-dhcp)
#   - Telemetry docker stack + volumes (always)
#   - User www-data from $LLDPQ_USER group (best effort)

set -u
set -o pipefail

LLDPQ_BACKUP_IMPORT_HELPER="/usr/local/libexec/lldpq-backup-import.py"

load_lldpq_uninstall_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value

    [[ -f "$config_file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        case "$key" in
            LLDPQ_DIR|LLDPQ_USER|WEB_ROOT) ;;
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

guard_destructive_path() {
    local label="$1" path="$2" min_depth="${3:-2}"
    local canonical relative depth

    # uninstall.sh still has a legacy command runner for fixed administrative
    # commands, so managed path values use a deliberately narrow character set.
    if [[ -z "$path" || ! "$path" =~ ^/[A-Za-z0-9._/+:-]+$ ]]; then
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
    if (( depth < min_depth )); then
        echo "Refusing shallow $label path: '$canonical'" >&2
        return 1
    fi
    printf '%s\n' "$canonical"
}

guard_recursive_target() {
    local label="$1" canonical="$2" allow_var_www="${3:-false}"
    local canonical_home
    canonical_home=$(canonical_path "$HOME") || return 1
    case "$canonical" in
        /home/*|/root/*)
            if [[ "$canonical" != "$canonical_home"/* ]]; then
                echo "Refusing $label under another user's home: '$canonical'" >&2
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
            echo "Refusing $label inside protected system tree: '$canonical'" >&2
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
    [[ -f "$path/devices.yaml" && -f "$path/monitor.sh" ]] || {
        echo "Unrecognized or partial LLDPq directory: '$path'" >&2
        return 1
    }
}

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

native_recovery_namespace_present() {
    local user="$1" home state
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [[ -n "$home" && "$home" == /* && "$home" != "/" ]] || return 0
    state="$home/.lldpq-state"
    [[ ! -L "$state" ]] || return 0
    [[ -d "$state" ]] || return 1
    sudo find -P "$state" -mindepth 1 -maxdepth 1 \
        \( -name '.backup-import-recovery' -o \
           -name '.backup-import-recovery.tmp-*' -o \
           -name '.backup-import-recovery.committed-*' -o \
           -name '.backup-import-recovery.rolled-back-*' \) \
        -print -quit 2>/dev/null | grep -q .
}

if [[ "${LLDPQ_UNINSTALL_LIB_ONLY:-false}" == "true" ]]; then
    return 0 2>/dev/null || exit 0
fi

# ─── Args ──────────────────────────────────────────────────────────────
AUTO_YES=false
DRY_RUN=false
KEEP_DATA=false
REMOVE_DHCP=false
REMOVE_NGINX_PKG=false
REMOVE_DOCKER_PKG=false
FORCE_PARTIAL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes) AUTO_YES=true ;;
        --dry-run) DRY_RUN=true ;;
        --keep-data) KEEP_DATA=true ;;
        --remove-dhcp) REMOVE_DHCP=true ;;
        --remove-nginx) REMOVE_NGINX_PKG=true ;;
        --remove-docker) REMOVE_DOCKER_PKG=true ;;
        --force-partial) FORCE_PARTIAL=true ;;
        -h|--help)
            sed -n '1,30p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ─── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

run() {
    if $DRY_RUN; then
        echo "DRY-RUN  $*"
    else
        eval "$@"
    fi
}

step() {
    echo ""
    echo -e "${CYAN}→ $1${NC}"
}

# ─── Detect install paths ─────────────────────────────────────────────
LLDPQ_INSTALL_DIR=""
LLDPQ_USER=""
WEB_ROOT="/var/www/html"

LLDPQ_CONFIG_FILE="${LLDPQ_CONFIG_FILE:-/etc/lldpq.conf}"
load_lldpq_uninstall_config "$LLDPQ_CONFIG_FILE"
LLDPQ_INSTALL_DIR="${LLDPQ_DIR:-}"
LLDPQ_USER="${LLDPQ_USER:-}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
    if [[ $EUID -eq 0 ]]; then
        LLDPQ_INSTALL_DIR="/opt/lldpq"
    else
        LLDPQ_INSTALL_DIR="$HOME/lldpq"
    fi
fi

[[ -z "$LLDPQ_USER" ]] && LLDPQ_USER="$(whoami)"

LLDPQ_INSTALL_DIR=$(guard_destructive_path "LLDPq install" "$LLDPQ_INSTALL_DIR" 2) || exit 1
WEB_ROOT=$(guard_destructive_path "web root" "$WEB_ROOT" 2) || exit 1
LLDPQ_INSTALL_DIR=$(guard_recursive_target "LLDPq install" "$LLDPQ_INSTALL_DIR" false) || exit 1
WEB_ROOT=$(guard_recursive_target "web root" "$WEB_ROOT" true) || exit 1
if paths_overlap "$LLDPQ_INSTALL_DIR" "$WEB_ROOT"; then
    echo "Refusing uninstall: LLDPQ_DIR and WEB_ROOT overlap" >&2
    exit 1
fi
PARTIAL_INSTALL_TREE=false
if ! assert_lldpq_install_tree "$LLDPQ_INSTALL_DIR"; then
    PARTIAL_INSTALL_TREE=true
    if $FORCE_PARTIAL; then
        echo "  [!] --force-partial: the guarded partial install tree will be removed" >&2
    else
        echo "  [!] Known LLDPq system components will be cleaned, but this directory will be left in place." >&2
        echo "      Re-run with --force-partial only after verifying the path." >&2
    fi
fi
if [[ ! "$LLDPQ_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
    echo "Refusing invalid LLDPQ_USER: '$LLDPQ_USER'" >&2
    exit 1
fi

# ─── Banner ───────────────────────────────────────────────────────────
echo -e "${YELLOW}LLDPq Uninstall${NC}"
echo "================================================"
echo "Install dir:    $LLDPQ_INSTALL_DIR"
echo "Install user:   $LLDPQ_USER"
echo "Web root:       $WEB_ROOT"
echo "Dry run:        $DRY_RUN"
echo "Keep data:      $KEEP_DATA"
echo "Remove DHCP:    $REMOVE_DHCP"
echo "Remove nginx:   $REMOVE_NGINX_PKG"
echo "Remove docker:  $REMOVE_DOCKER_PKG"
echo "================================================"

if ! $AUTO_YES && ! $DRY_RUN; then
    echo -e "${RED}This will permanently remove LLDPq from this system.${NC}"
    read -p "Type 'YES' to continue: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# ─── 1. Stop running processes ────────────────────────────────────────
step "Stopping LLDPq processes..."
for proc in lldpq-trigger lldpq-ai-analyze fabric-scan.sh monitor.sh check-lldp.sh assets.sh; do
    if pgrep -f "/usr/local/bin/$proc" >/dev/null 2>&1 || \
       pgrep -f "$LLDPQ_INSTALL_DIR/$proc" >/dev/null 2>&1; then
        run "sudo pkill -f '$proc' 2>/dev/null || true"
        echo "  killed $proc"
    fi
done

# Stop the watcher before removing either the lock or the executable tree. An
# authority published by an interrupted import must not start a now-orphaned
# recovery process while uninstall is in progress.
step "Removing retained-import recovery units..."
run "sudo systemctl disable --now lldpq-recovery.path lldpq-recovery.service 2>/dev/null || true"
if ! $DRY_RUN && \
   { sudo systemctl is-active --quiet lldpq-recovery.path 2>/dev/null || \
     sudo systemctl is-active --quiet lldpq-recovery.service 2>/dev/null; }; then
    echo "[!] Retained-import recovery units are still active; cleanup stopped" >&2
    exit 1
fi
for unit in lldpq-recovery.path lldpq-recovery.service; do
    if ! run "sudo rm -f '/etc/systemd/system/$unit' '/etc/systemd/system/multi-user.target.wants/$unit'"; then
        echo "[!] Could not remove retained-import recovery unit: $unit" >&2
        exit 1
    fi
done
run "sudo systemctl daemon-reload 2>/dev/null || true"
echo "  retained-import recovery service + path watcher removed"

# Quiesce every LLDPq CGI before purging its rollback authority. Stopping only
# the recovery path leaves a race where a running or socket-queued Setup import
# can publish a new authority after purge and before the helper is removed.
FCGIWRAP_SERVICE_WAS_ACTIVE=false
FCGIWRAP_SOCKET_WAS_ACTIVE=false
systemctl is-active --quiet fcgiwrap.service 2>/dev/null && \
    FCGIWRAP_SERVICE_WAS_ACTIVE=true
systemctl is-active --quiet fcgiwrap.socket 2>/dev/null && \
    FCGIWRAP_SOCKET_WAS_ACTIVE=true
echo "  [i] fcgiwrap is shared: LLDPq CGI execution will be paused during cleanup."
echo "      Previously active units will be restored after the LLDPq route and CGI files are removed."
run "sudo systemctl stop fcgiwrap.socket fcgiwrap.service 2>/dev/null || true"
if ! $DRY_RUN && \
   { systemctl is-active --quiet fcgiwrap.socket 2>/dev/null || \
     systemctl is-active --quiet fcgiwrap.service 2>/dev/null; }; then
    echo "[!] fcgiwrap could not be quiesced; recovery authority was not purged" >&2
    exit 1
fi

# Purge only the helper's reserved, validated recovery directories. The helper
# resolves the passwd home, opens it and .lldpq-state with O_NOFOLLOW, validates
# ownership/modes/names, and deletes through directory file descriptors.
if $DRY_RUN; then
    echo "DRY-RUN  sudo '$LLDPQ_BACKUP_IMPORT_HELPER' purge-native-state --user '$LLDPQ_USER'"
else
    _backup_helper_metadata=$(sudo stat -c '%u:%g:%a' -- \
        "$LLDPQ_BACKUP_IMPORT_HELPER" 2>/dev/null || true)
    if [[ -f "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
       [[ ! -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
       [[ "$_backup_helper_metadata" == "0:0:755" ]]; then
        if ! sudo "$LLDPQ_BACKUP_IMPORT_HELPER" purge-native-state \
            --user "$LLDPQ_USER"; then
            echo "[!] Native backup-import recovery state was not safely removed; uninstall stopped" >&2
            exit 1
        fi
    elif native_recovery_namespace_present "$LLDPQ_USER"; then
        echo "[!] Recovery remnants exist but the root-owned cleanup helper is missing or unsafe" >&2
        echo "    Repair the installation before uninstalling so old snapshots cannot survive." >&2
        exit 1
    fi
fi
if [[ -d "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
   [[ ! -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]]; then
    echo "[!] Refusing to recursively remove unexpected helper directory: $LLDPQ_BACKUP_IMPORT_HELPER" >&2
    exit 1
fi
run "sudo rm -f '$LLDPQ_BACKUP_IMPORT_HELPER'"
if ! $DRY_RUN && \
   { [[ -e "$LLDPQ_BACKUP_IMPORT_HELPER" ]] || [[ -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]]; }; then
    echo "[!] Root-owned backup/import helper could not be removed" >&2
    exit 1
fi
echo "  root-owned backup/import helper removed"

# ─── 2. Telemetry stack ───────────────────────────────────────────────
step "Removing telemetry stack..."
if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]; then
    if command -v docker >/dev/null 2>&1; then
        run "(cd '$LLDPQ_INSTALL_DIR/telemetry' && (docker compose down -v 2>/dev/null || docker-compose down -v 2>/dev/null || sudo docker compose down -v 2>/dev/null || sudo docker-compose down -v 2>/dev/null || true))"
    fi
    echo "  telemetry containers + volumes removed"
fi

# ─── 3. Cron jobs ─────────────────────────────────────────────────────
step "Removing LLDPq cron jobs..."
if [[ -f /etc/crontab ]]; then
    if $DRY_RUN; then
        echo "DRY-RUN  remove only legacy LLDPq command paths from /etc/crontab"
    else
        _legacy_cron_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-uninstall-cron.XXXXXX")
        filter_legacy_lldpq_crontab /etc/crontab "$_legacy_cron_tmp" "$LLDPQ_INSTALL_DIR"
        if ! cmp -s /etc/crontab "$_legacy_cron_tmp"; then
            sudo install -o root -g root -m 644 "$_legacy_cron_tmp" /etc/crontab
        fi
        rm -f "$_legacy_cron_tmp"
    fi
    echo "  legacy LLDPq entries removed from /etc/crontab"
fi
if [[ -f /etc/cron.d/lldpq ]]; then
    run "sudo rm -f /etc/cron.d/lldpq"
    echo "  /etc/cron.d/lldpq removed"
fi

# ─── 4. Bin scripts ───────────────────────────────────────────────────
step "Removing CLI tools..."
for bin in lldpq lldpq-config lldpq-trigger lldpq-ai-analyze zzh pping send-cmd get-conf netprobe-ai; do
    if [[ -e "/usr/local/bin/$bin" ]]; then
        run "sudo rm -f /usr/local/bin/$bin"
        echo "  removed /usr/local/bin/$bin"
    fi
done

# ─── 5. Sudoers ───────────────────────────────────────────────────────
step "Removing sudoers files..."
for f in www-data-lldpq www-data-provision; do
    if [[ -f "/etc/sudoers.d/$f" ]]; then
        run "sudo rm -f /etc/sudoers.d/$f"
        echo "  removed /etc/sudoers.d/$f"
    fi
done

# ─── 6. Auth + sessions + config ──────────────────────────────────────
step "Removing config + auth files..."
for f in /etc/lldpq.conf /etc/lldpq.conf.lock /etc/lldpq-users.conf; do
    if [[ "$f" == "/etc/lldpq.conf" && "$PARTIAL_INSTALL_TREE" == "true" && \
          "$FORCE_PARTIAL" != "true" ]]; then
        echo "  kept $f so a verified --force-partial rerun retains the custom install path"
        continue
    fi
    if [[ -e "$f" ]]; then
        run "sudo rm -f '$f'"
        echo "  removed $f"
    fi
done
if [[ -d /var/lib/lldpq ]]; then
    run "sudo rm -rf /var/lib/lldpq"
    echo "  removed /var/lib/lldpq"
fi

# ─── 7. nginx site ────────────────────────────────────────────────────
step "Removing nginx site..."
if [[ -L /etc/nginx/sites-enabled/lldpq ]] || [[ -f /etc/nginx/sites-enabled/lldpq ]]; then
    run "sudo rm -f /etc/nginx/sites-enabled/lldpq"
    echo "  removed sites-enabled/lldpq"
fi
if [[ -f /etc/nginx/sites-available/lldpq ]]; then
    run "sudo rm -f /etc/nginx/sites-available/lldpq"
    echo "  removed sites-available/lldpq"
fi
if command -v nginx >/dev/null 2>&1; then
    run "sudo nginx -t >/dev/null 2>&1 && sudo systemctl reload nginx 2>/dev/null || true"
fi

# ─── 8. Web content ───────────────────────────────────────────────────
step "Removing web content under $WEB_ROOT..."
WEB_TARGETS=(
    "$WEB_ROOT/index.html" "$WEB_ROOT/login.html" "$WEB_ROOT/start.html"
    "$WEB_ROOT/assets.html" "$WEB_ROOT/device.html" "$WEB_ROOT/configs.html"
    "$WEB_ROOT/lldp.html" "$WEB_ROOT/lldp-problem.html" "$WEB_ROOT/archive.html"
    "$WEB_ROOT/dev-conf.html" "$WEB_ROOT/edit-config.sh" "$WEB_ROOT/edit-devices.sh"
    "$WEB_ROOT/edit-topology.sh" "$WEB_ROOT/editor-test.html"
    "$WEB_ROOT/fabric-api.sh" "$WEB_ROOT/fabric-config.html" "$WEB_ROOT/fabric-deploy.html"
    "$WEB_ROOT/fabric-editor.html" "$WEB_ROOT/fabric-exit.html"
    "$WEB_ROOT/auth-api.sh" "$WEB_ROOT/ansible-api.sh"
    "$WEB_ROOT/ai-api.sh" "$WEB_ROOT/ai.html"
    "$WEB_ROOT/provision.html" "$WEB_ROOT/provision-api.sh"
    "$WEB_ROOT/search.html" "$WEB_ROOT/search-api.sh"
    "$WEB_ROOT/setup-api.sh" "$WEB_ROOT/telemetry.html"
    "$WEB_ROOT/tracepath.html" "$WEB_ROOT/transceiver.html"
    "$WEB_ROOT/vlan-report.html" "$WEB_ROOT/vrf-report.html"
    "$WEB_ROOT/lldpq-ztp-new-device-flow.html"
    "$WEB_ROOT/trigger-assets.sh" "$WEB_ROOT/trigger-configs.sh"
    "$WEB_ROOT/trigger-lldp.sh" "$WEB_ROOT/trigger-monitor.sh"
    "$WEB_ROOT/cumulus-ztp.sh" "$WEB_ROOT/serial-mapping.txt"
    "$WEB_ROOT/topology.dot" "$WEB_ROOT/topology_config.yaml"
    "$WEB_ROOT/VERSION"
    "$WEB_ROOT/device-cache.json" "$WEB_ROOT/fabric-scan-cache.json"
    "$WEB_ROOT/discovery-cache.json" "$WEB_ROOT/inventory.json"
    "$WEB_ROOT/ai-analysis.json"
)
WEB_DIRS=(
    "$WEB_ROOT/css" "$WEB_ROOT/png" "$WEB_ROOT/topology"
    "$WEB_ROOT/configs" "$WEB_ROOT/hstr" "$WEB_ROOT/monitor-results"
    "$WEB_ROOT/generated_config_folder" "$WEB_ROOT/monaco"
)

for f in "${WEB_TARGETS[@]}"; do
    [[ -e "$f" ]] && run "sudo rm -f '$f'" && echo "  removed $f"
done
for d in "${WEB_DIRS[@]}"; do
    if $KEEP_DATA && [[ "$d" == *"monitor-results"* || "$d" == *"configs"* || "$d" == *"hstr"* ]]; then
        echo "  kept $d (--keep-data)"
        continue
    fi
    [[ -d "$d" ]] && run "sudo rm -rf '$d'" && echo "  removed $d"
done

# The LLDPq nginx route and CGI files are now gone, so reactivating a shared
# fcgiwrap unit cannot enqueue another backup import. Restore only what was
# active before uninstall; --remove-nginx intentionally leaves it stopped for
# the package-removal phase below.
if $REMOVE_NGINX_PKG; then
    echo "  fcgiwrap remains stopped because --remove-nginx was requested"
elif $FCGIWRAP_SOCKET_WAS_ACTIVE || $FCGIWRAP_SERVICE_WAS_ACTIVE; then
    step "Restoring shared fcgiwrap service..."
    if $FCGIWRAP_SOCKET_WAS_ACTIVE; then
        run "sudo systemctl start fcgiwrap.socket"
    fi
    if $FCGIWRAP_SERVICE_WAS_ACTIVE; then
        run "sudo systemctl start fcgiwrap.service"
    fi
    FCGIWRAP_RESTORE_FAILED=false
    if ! $DRY_RUN; then
        if $FCGIWRAP_SOCKET_WAS_ACTIVE && \
           ! systemctl is-active --quiet fcgiwrap.socket 2>/dev/null; then
            FCGIWRAP_RESTORE_FAILED=true
        fi
        if $FCGIWRAP_SERVICE_WAS_ACTIVE && \
           ! systemctl is-active --quiet fcgiwrap.service 2>/dev/null; then
            FCGIWRAP_RESTORE_FAILED=true
        fi
    fi
    if $FCGIWRAP_RESTORE_FAILED; then
        echo "[!] LLDPq was removed, but the previously active shared fcgiwrap unit could not be restored" >&2
        echo "    Restore it manually with: sudo systemctl start fcgiwrap.socket fcgiwrap.service" >&2
        exit 1
    fi
    echo "  shared fcgiwrap state restored"
fi

# ─── 9. Install directory ─────────────────────────────────────────────
step "Removing install directory..."
if [[ -d "$LLDPQ_INSTALL_DIR" ]]; then
    if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
        echo "  left unrecognized partial directory in place: $LLDPQ_INSTALL_DIR"
    elif $KEEP_DATA; then
        # Keep monitor-results / lldp-results / alert-states / devices.yaml
        run "find '$LLDPQ_INSTALL_DIR' -mindepth 1 -maxdepth 1 ! -name 'monitor-results' ! -name 'lldp-results' ! -name 'alert-states' ! -name 'devices.yaml' ! -name 'notifications.yaml' -exec sudo rm -rf {} +"
        echo "  cleaned $LLDPQ_INSTALL_DIR (kept data)"
    else
        run "sudo rm -rf '$LLDPQ_INSTALL_DIR'"
        echo "  removed $LLDPQ_INSTALL_DIR"
    fi
fi

# ─── 10. DHCP config (LLDPq markers only) ────────────────────────────
step "Cleaning DHCP markers..."
if $REMOVE_DHCP; then
    run "sudo systemctl stop isc-dhcp-server 2>/dev/null || true"
    run "sudo systemctl disable isc-dhcp-server 2>/dev/null || true"
    for f in /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.hosts /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases; do
        [[ -e "$f" ]] && run "sudo rm -f '$f'" && echo "  removed $f"
    done
    run "sudo apt-get remove -y --purge isc-dhcp-server >/dev/null 2>&1 || true"
else
    echo "  --remove-dhcp not set, leaving DHCP service config alone"
fi

# ─── 11. Group membership cleanup ─────────────────────────────────────
step "Cleaning group memberships..."
if id www-data >/dev/null 2>&1; then
    run "sudo gpasswd -d www-data '$LLDPQ_USER' 2>/dev/null || true"
    run "sudo gpasswd -d '$LLDPQ_USER' www-data 2>/dev/null || true"
    echo "  removed group cross-membership"
fi

# ─── 12. Optional package removal ─────────────────────────────────────
if $REMOVE_NGINX_PKG; then
    step "Removing nginx + fcgiwrap packages..."
    run "sudo systemctl stop nginx fcgiwrap 2>/dev/null || true"
    run "sudo apt-get remove -y --purge nginx fcgiwrap >/dev/null 2>&1 || true"
fi

if $REMOVE_DOCKER_PKG; then
    step "Removing Docker packages..."
    run "sudo systemctl stop docker 2>/dev/null || true"
    run "sudo apt-get remove -y --purge docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin >/dev/null 2>&1 || true"
    run "sudo rm -rf /var/lib/docker /var/lib/containerd 2>/dev/null || true"
fi

# ─── Done ─────────────────────────────────────────────────────────────
echo ""
if $DRY_RUN; then
    echo -e "${YELLOW}Dry run complete. No changes were made.${NC}"
else
    echo -e "${GREEN}LLDPq has been uninstalled.${NC}"
fi
echo ""
echo "Verify with:"
if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
    echo "  ls /etc/lldpq* 2>/dev/null   # lldpq.conf is intentionally retained"
    echo "  inspect $LLDPQ_INSTALL_DIR manually (partial tree intentionally retained)"
else
    echo "  ls /etc/lldpq* 2>/dev/null   # should be empty"
    echo "  ls $LLDPQ_INSTALL_DIR 2>/dev/null  # should not exist"
fi
echo "  systemctl status nginx       # nginx state (if you kept it)"
echo "  crontab -l; cat /etc/crontab # no LLDPq lines"
