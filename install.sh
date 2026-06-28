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
#   -y                  Auto-yes to all prompts (non-interactive mode, uses defaults)
#   --enable-telemetry  Enable streaming telemetry support (installs Docker)
#   --disable-telemetry Disable streaming telemetry support
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
# │   • source /etc/lldpq.conf → save existing settings      │
# │   • Full backup → ~/lldpq-backup-YYYY-MM-DD_HH-MM/      │
# │     (devices.yaml, topology, configs, DHCP, SSH keys,    │
# │      monitoring data, .git history)                      │
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

# Step counter for progress display
STEP=0
step() { STEP=$((STEP + 1)); printf "\n[%02d] %s\n" "$STEP" "$1"; }

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
AUTO_YES=false
ENABLE_TELEMETRY=false
DISABLE_TELEMETRY=false

for arg in "$@"; do
    case $arg in
        -y) AUTO_YES=true ;;
        --enable-telemetry) ENABLE_TELEMETRY=true ;;
        --disable-telemetry) DISABLE_TELEMETRY=true ;;
        -h|--help)
            echo "Usage: ./install.sh [-y] [--enable-telemetry] [--disable-telemetry]"
            echo ""
            echo "Automatically detects existing installation:"
            echo "  No existing install → Fresh install (packages, configs, everything)"
            echo "  Existing install    → Update mode (backup, preserve configs, update files)"
            echo ""
            echo "Options:"
            echo "  -y                  Auto-yes to all prompts"
            echo "  --enable-telemetry  Enable streaming telemetry (requires Docker)"
            echo "  --disable-telemetry Disable streaming telemetry"
            exit 0
            ;;
    esac
done

# ============================================================================
# TELEMETRY-ONLY MODE (early exit — no other changes needed)
# ============================================================================
if [[ "$ENABLE_TELEMETRY" == "true" ]] || [[ "$DISABLE_TELEMETRY" == "true" ]]; then
    # Read LLDPQ_INSTALL_DIR from config
    if [[ -f /etc/lldpq.conf ]]; then
        LLDPQ_INSTALL_DIR=$(grep "^LLDPQ_DIR=" /etc/lldpq.conf 2>/dev/null | cut -d'=' -f2 || echo "")
    fi
    if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
        if [[ $EUID -eq 0 ]]; then
            LLDPQ_INSTALL_DIR="/opt/lldpq"
        else
            LLDPQ_INSTALL_DIR="$HOME/lldpq"
        fi
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

# Read LLDPQ_INSTALL_DIR from existing config (if available)
LLDPQ_INSTALL_DIR=""
if [[ -f /etc/lldpq.conf ]]; then
    LLDPQ_INSTALL_DIR=$(grep "^LLDPQ_DIR=" /etc/lldpq.conf 2>/dev/null | cut -d'=' -f2 || echo "")
fi

# Default based on user
if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
    if [[ $EUID -eq 0 ]]; then
        LLDPQ_INSTALL_DIR="/opt/lldpq"
    else
        LLDPQ_INSTALL_DIR="$HOME/lldpq"
    fi
fi

LLDPQ_USER="$(whoami)"
WEB_ROOT="/var/www/html"

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

# ============================================================================
# UPDATE-ONLY: Backup & prepare
# ============================================================================
_preserved_dir=""

if [[ "$INSTALL_MODE" == "update" ]]; then
    # Load existing config (sets ANSIBLE_DIR, TELEMETRY_ENABLED, PROMETHEUS_URL, etc.)
    source /etc/lldpq.conf 2>/dev/null || true
    WEB_ROOT="${WEB_ROOT:-/var/www/html}"
    LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"

    # -- Optional full backup (ask; default No) -------------------------------
    # NOTE: runtime monitoring data is ALWAYS preserved across the update (see the
    # "Preparing update" step below) — this optional backup is just an extra rollback
    # copy of configs, keys and a data snapshot.
    BACKUP_DIR=""
    _do_backup=false
    if [[ "$AUTO_YES" != "true" ]]; then
        read -p "  Take a full backup (configs/keys/data) before updating? [y/N]: " _bk_response
        [[ "$_bk_response" =~ ^[Yy]$ ]] && _do_backup=true
    fi

    if [[ "$_do_backup" == "true" ]]; then
        step "Creating backup..."
        BACKUP_DIR="$HOME/lldpq-backup-$(date +%Y-%m-%d_%H-%M)"
        mkdir -p "$BACKUP_DIR"
        echo "  Backup directory: $BACKUP_DIR"

        # Configuration files
        [[ -f "$LLDPQ_INSTALL_DIR/devices.yaml" ]] && \
            cp "$LLDPQ_INSTALL_DIR/devices.yaml" "$BACKUP_DIR/" && echo "  • devices.yaml"
        [[ -f "$LLDPQ_INSTALL_DIR/notifications.yaml" ]] && \
            cp "$LLDPQ_INSTALL_DIR/notifications.yaml" "$BACKUP_DIR/" && echo "  • notifications.yaml"
        [[ -f "$WEB_ROOT/topology.dot" ]] && \
            sudo cp "$WEB_ROOT/topology.dot" "$BACKUP_DIR/" && echo "  • topology.dot"
        [[ -f "$WEB_ROOT/topology_config.yaml" ]] && \
            sudo cp "$WEB_ROOT/topology_config.yaml" "$BACKUP_DIR/" && echo "  • topology_config.yaml"
        [[ -f /etc/lldpq.conf ]] && \
            sudo cp /etc/lldpq.conf "$BACKUP_DIR/" && echo "  • /etc/lldpq.conf"
        [[ -f /etc/lldpq-users.conf ]] && \
            sudo cp /etc/lldpq-users.conf "$BACKUP_DIR/" && echo "  • /etc/lldpq-users.conf"
        [[ -f /etc/dhcp/dhcpd.conf ]] && \
            sudo cp /etc/dhcp/dhcpd.conf "$BACKUP_DIR/" && echo "  • /etc/dhcp/dhcpd.conf"
        [[ -f /etc/dhcp/dhcpd.hosts ]] && \
            sudo cp /etc/dhcp/dhcpd.hosts "$BACKUP_DIR/" && echo "  • /etc/dhcp/dhcpd.hosts"

        # SSH keys
        if ls ~/.ssh/id_* >/dev/null 2>&1; then
            mkdir -p "$BACKUP_DIR/ssh-keys"
            cp ~/.ssh/id_* "$BACKUP_DIR/ssh-keys/" 2>/dev/null || true
            echo "  • SSH keys (~/.ssh/id_*)"
        fi

        # Monitoring data snapshot (sudo: may hold root-owned files from cron)
        for _d in monitor-results lldp-results alert-states; do
            [[ -d "$LLDPQ_INSTALL_DIR/$_d" ]] && \
                sudo cp -r "$LLDPQ_INSTALL_DIR/$_d" "$BACKUP_DIR/" 2>/dev/null && echo "  • $_d/"
        done

        echo "  Backup complete"
    else
        echo "  Skipping full backup (monitoring data is still preserved across the update)"
    fi

    # -- Stop processes -------------------------------------------------------
    step "Preparing update..."
    if pgrep -f "$LLDPQ_INSTALL_DIR/monitor.sh" >/dev/null 2>&1 || \
       pgrep -f "/usr/local/bin/lldpq-trigger" >/dev/null 2>&1; then
        echo "  Stopping LLDPq processes..."
        pkill -f "$LLDPQ_INSTALL_DIR/monitor.sh" 2>/dev/null || true
        pkill -f "/usr/local/bin/lldpq-trigger" 2>/dev/null || true
        sleep 2
        echo "  Processes stopped"
    fi

    # -- Preserve user configs for restore after copy -------------------------
    _preserved_dir=$(mktemp -d)
    [[ -f "$LLDPQ_INSTALL_DIR/devices.yaml" ]] && cp "$LLDPQ_INSTALL_DIR/devices.yaml" "$_preserved_dir/"
    [[ -f "$LLDPQ_INSTALL_DIR/notifications.yaml" ]] && cp "$LLDPQ_INSTALL_DIR/notifications.yaml" "$_preserved_dir/"
    # Preserve the customized ZTP script (image server IP, target OS, password, SSH key
    # are all baked into this file by the Provision UI — must survive 'cp -r html/*')
    [[ -f "$WEB_ROOT/cumulus-ztp.sh" ]] && cp "$WEB_ROOT/cumulus-ztp.sh" "$_preserved_dir/" 2>/dev/null || true

    # Preserve telemetry user config
    if [[ -d "$LLDPQ_INSTALL_DIR/telemetry/config" ]]; then
        cp -r "$LLDPQ_INSTALL_DIR/telemetry/config" "$_preserved_dir/telemetry-config" 2>/dev/null || true
    fi

    # Preserve git history (tracks config changes over time)
    if [[ -d "$LLDPQ_INSTALL_DIR/.git" ]]; then
        cp -r "$LLDPQ_INSTALL_DIR/.git" "$_preserved_dir/dot-git" 2>/dev/null || true
        echo "  Git history preserved"
    fi

    # Preserve runtime data across the rm+recopy (ALWAYS — independent of the optional
    # backup above). Uses sudo because monitor-results may contain root-owned files
    # written by cron; a rename keeps it on the same filesystem (fast, no big copy).
    _DATA_PRESERVE="$HOME/.lldpq-data-preserve-$$"
    sudo rm -rf "$_DATA_PRESERVE" 2>/dev/null || true
    mkdir -p "$_DATA_PRESERVE"
    for _d in monitor-results lldp-results alert-states; do
        [[ -e "$LLDPQ_INSTALL_DIR/$_d" ]] && sudo mv "$LLDPQ_INSTALL_DIR/$_d" "$_DATA_PRESERVE/" 2>/dev/null || true
    done

    # Remove old lldpq directory (sudo fallback: may contain root-owned files)
    echo "  Removing old lldpq directory..."
    rm -rf "$LLDPQ_INSTALL_DIR" 2>/dev/null || sudo rm -rf "$LLDPQ_INSTALL_DIR"
    echo "  Ready for update"

    # Save config vars from sourced config (before /etc/lldpq.conf is overwritten)
    _SAVE_TELEMETRY_ENABLED="${TELEMETRY_ENABLED:-}"
    _SAVE_PROMETHEUS_URL="${PROMETHEUS_URL:-}"
    _SAVE_TELEMETRY_COLLECTOR_IP="${TELEMETRY_COLLECTOR_IP:-}"
    _SAVE_DISCOVERY_RANGE="${DISCOVERY_RANGE:-}"
    _SAVE_AUTO_BASE_CONFIG="${AUTO_BASE_CONFIG:-true}"
    _SAVE_AUTO_ZTP_DISABLE="${AUTO_ZTP_DISABLE:-true}"
    _SAVE_AUTO_SET_HOSTNAME="${AUTO_SET_HOSTNAME:-true}"
    _SAVE_SKIP_OPTICAL="${SKIP_OPTICAL:-false}"
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
sudo mkdir -p "$WEB_ROOT/hstr" "$WEB_ROOT/configs" "$WEB_ROOT/monitor-results" "$WEB_ROOT/topology" "$WEB_ROOT/generated_config_folder"
sudo chown -R "$LLDPQ_USER:www-data" "$WEB_ROOT/hstr" "$WEB_ROOT/configs" "$WEB_ROOT/monitor-results" "$WEB_ROOT/topology" "$WEB_ROOT/generated_config_folder"
sudo chmod 775 "$WEB_ROOT/hstr" "$WEB_ROOT/configs" "$WEB_ROOT/monitor-results" "$WEB_ROOT/topology" "$WEB_ROOT/generated_config_folder"

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

echo "  - Copying lldpq to $LLDPQ_INSTALL_DIR"
sudo mkdir -p "$LLDPQ_INSTALL_DIR"
sudo cp -r lldpq/* "$LLDPQ_INSTALL_DIR/"
sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR"

# Restore preserved configs (update mode)
if [[ -n "$_preserved_dir" ]] && [[ -d "$_preserved_dir" ]]; then
    echo "  - Restoring preserved configuration files..."
    [[ -f "$_preserved_dir/devices.yaml" ]] && \
        sudo cp "$_preserved_dir/devices.yaml" "$LLDPQ_INSTALL_DIR/" && echo "    • devices.yaml"
    [[ -f "$_preserved_dir/notifications.yaml" ]] && \
        sudo cp "$_preserved_dir/notifications.yaml" "$LLDPQ_INSTALL_DIR/" && echo "    • notifications.yaml"
    # Restore the customized ZTP script over the freshly-copied template (update only)
    [[ -f "$_preserved_dir/cumulus-ztp.sh" ]] && \
        sudo cp "$_preserved_dir/cumulus-ztp.sh" "$WEB_ROOT/" && echo "    • cumulus-ztp.sh (ZTP script preserved)"
fi

echo "  - Copying telemetry stack to $LLDPQ_INSTALL_DIR/telemetry"
sudo cp -r telemetry "$LLDPQ_INSTALL_DIR/telemetry"
sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/telemetry"
sudo chmod 755 "$LLDPQ_INSTALL_DIR/telemetry/start.sh"
sudo chmod 644 "$LLDPQ_INSTALL_DIR/telemetry/config/"*.yaml 2>/dev/null || true

# Restore telemetry user config (update mode)
if [[ -n "$_preserved_dir" ]] && [[ -d "$_preserved_dir/telemetry-config" ]]; then
    sudo cp -r "$_preserved_dir/telemetry-config"/* "$LLDPQ_INSTALL_DIR/telemetry/config/" 2>/dev/null || true
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
echo "WEB_ROOT=$WEB_ROOT" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "ANSIBLE_DIR=$ANSIBLE_DIR" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "EDITOR_ROOT=${EDITOR_ROOT:-$ANSIBLE_DIR}" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_HOSTS_FILE=/etc/dhcp/dhcpd.hosts" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_CONF_FILE=/etc/dhcp/dhcpd.conf" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "DHCP_LEASES_FILE=/var/lib/dhcp/dhcpd.leases" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "ZTP_SCRIPT_FILE=$WEB_ROOT/cumulus-ztp.sh" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "BASE_CONFIG_DIR=$LLDPQ_INSTALL_DIR/sw-base" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_BASE_CONFIG=true" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_ZTP_DISABLE=true" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AUTO_SET_HOSTNAME=true" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "SKIP_OPTICAL=false" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "SKIP_L1=false" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "MONITOR_MAX_PARALLEL=100" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "LLDP_MAX_PARALLEL=100" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "ASSETS_MAX_PARALLEL=50" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "GET_CONFIGS_MAX_PARALLEL=50" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "SEND_CMD_MAX_PARALLEL=25" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TELEMETRY_MAX_PARALLEL=25" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SKIP_MODELS=\"\"" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=skip" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MAX_PARALLEL=10" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_MIN_INTERVAL=1800" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "TRANSCEIVER_FW_SSH_TIMEOUT=300" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AI_PROVIDER=ollama" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AI_MODEL=llama3.2" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AI_API_KEY=" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "AI_API_URL=https://api.openai.com/v1" | sudo tee -a /etc/lldpq.conf > /dev/null
echo "OLLAMA_URL=http://localhost:11434" | sudo tee -a /etc/lldpq.conf > /dev/null

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
    # Overwrite auto-provision toggles with preserved values
    sudo sed -i "s/^AUTO_BASE_CONFIG=.*/AUTO_BASE_CONFIG=$_SAVE_AUTO_BASE_CONFIG/" /etc/lldpq.conf
    sudo sed -i "s/^AUTO_ZTP_DISABLE=.*/AUTO_ZTP_DISABLE=$_SAVE_AUTO_ZTP_DISABLE/" /etc/lldpq.conf
    sudo sed -i "s/^AUTO_SET_HOSTNAME=.*/AUTO_SET_HOSTNAME=$_SAVE_AUTO_SET_HOSTNAME/" /etc/lldpq.conf
    sudo sed -i "s/^SKIP_OPTICAL=.*/SKIP_OPTICAL=$_SAVE_SKIP_OPTICAL/" /etc/lldpq.conf
    sudo sed -i "s|^TRANSCEIVER_FW_SKIP_MODELS=.*|TRANSCEIVER_FW_SKIP_MODELS=\"$_SAVE_TRANSCEIVER_FW_SKIP_MODELS\"|" /etc/lldpq.conf
    sudo sed -i "s/^TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=.*/TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY=$_SAVE_TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY/" /etc/lldpq.conf
    sudo sed -i "s/^TRANSCEIVER_FW_MAX_PARALLEL=.*/TRANSCEIVER_FW_MAX_PARALLEL=$_SAVE_TRANSCEIVER_FW_MAX_PARALLEL/" /etc/lldpq.conf
    sudo sed -i "s/^TRANSCEIVER_FW_MIN_INTERVAL=.*/TRANSCEIVER_FW_MIN_INTERVAL=$_SAVE_TRANSCEIVER_FW_MIN_INTERVAL/" /etc/lldpq.conf
    sudo sed -i "s/^TRANSCEIVER_FW_SSH_TIMEOUT=.*/TRANSCEIVER_FW_SSH_TIMEOUT=$_SAVE_TRANSCEIVER_FW_SSH_TIMEOUT/" /etc/lldpq.conf
    # Preserve AI settings. Values (API key, model like "openai/gpt-5.5", URLs) often
    # contain '/', '|', '&' which break `sed s///` ("unknown option to s"), so delete
    # the freshly-written default lines and re-append the preserved values with echo
    # (safe for ANY value).
    sudo sed -i '/^AI_PROVIDER=/d;/^AI_MODEL=/d;/^AI_API_KEY=/d;/^AI_API_URL=/d;/^OLLAMA_URL=/d' /etc/lldpq.conf
    {
        echo "AI_PROVIDER=$_SAVE_AI_PROVIDER"
        echo "AI_MODEL=$_SAVE_AI_MODEL"
        echo "AI_API_KEY=$_SAVE_AI_API_KEY"
        echo "AI_API_URL=$_SAVE_AI_API_URL"
        echo "OLLAMA_URL=$_SAVE_OLLAMA_URL"
    } | sudo tee -a /etc/lldpq.conf > /dev/null
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
[ ! -f /etc/dhcp/dhcpd.hosts ] && sudo touch /etc/dhcp/dhcpd.hosts
sudo chown "$LLDPQ_USER:www-data" /etc/dhcp/dhcpd.hosts
sudo chmod 664 /etc/dhcp/dhcpd.hosts

# Default dhcpd.conf if not configured yet (same template as Docker entrypoint)
if ! grep -q 'cumulus-provision-url\|LLDPq' /etc/dhcp/dhcpd.conf 2>/dev/null; then
    OUR_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    OUR_IP="${OUR_IP:-127.0.0.1}"
    OUR_SUBNET=$(echo "$OUR_IP" | sed 's/\.[0-9]*$/.0/')
    OUR_GW=$(echo "$OUR_IP" | sed 's/\.[0-9]*$/.1/')

    sudo tee /etc/dhcp/dhcpd.conf > /dev/null << DHCPEOF
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
  subnet ${OUR_SUBNET} netmask 255.255.255.0 {
    range ${OUR_SUBNET%.*}.210 ${OUR_SUBNET%.*}.249;
    option routers ${OUR_GW};
    option domain-name "example.com";
    option domain-name-servers ${OUR_GW};
    option www-server ${OUR_IP};
    option default-url "http://${OUR_IP}/";
    option cumulus-provision-url "http://${OUR_IP}/cumulus-ztp.sh";
    default-lease-time 172800;
    max-lease-time     345600;
  }
}

include "/etc/dhcp/dhcpd.hosts";
DHCPEOF
    sudo chown "$LLDPQ_USER:www-data" /etc/dhcp/dhcpd.conf
    sudo chmod 664 /etc/dhcp/dhcpd.conf
    echo "  Default DHCP config created (subnet: ${OUR_SUBNET}/24, server: ${OUR_IP})"
else
    echo "  DHCP config already exists, keeping"
fi

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
sudo systemctl enable lldpq-console.service >/dev/null 2>&1 || true
sudo systemctl restart lldpq-console.service 2>/dev/null || true
echo "  console-pty service enabled (127.0.0.1:8765)"

# ============================================================================
# COMMON: Cron jobs
# ============================================================================
step "Configuring cron jobs..."

# Remove existing LLDPq cron jobs and re-add (ensures latest)
sudo sed -i '/lldpq\|monitor\|get-conf\|fabric-scan\|ai-analyze/d' /etc/crontab

echo "*/10 * * * * $LLDPQ_USER /usr/local/bin/lldpq" | sudo tee -a /etc/crontab > /dev/null
echo "0 */12 * * * $LLDPQ_USER /usr/local/bin/get-conf" | sudo tee -a /etc/crontab > /dev/null
echo "* * * * * $LLDPQ_USER /usr/local/bin/lldpq-trigger" | sudo tee -a /etc/crontab > /dev/null
echo "* * * * * $LLDPQ_USER cd $LLDPQ_INSTALL_DIR && ./fabric-scan.sh >/dev/null 2>&1" | sudo tee -a /etc/crontab > /dev/null
echo "0 0 * * * $LLDPQ_USER cd $LLDPQ_INSTALL_DIR && cp /var/www/html/topology.dot topology.dot.bkp 2>/dev/null; cp /var/www/html/topology_config.yaml topology_config.yaml.bkp 2>/dev/null; git add -A; git diff --cached --quiet || git commit -m 'auto: \$(date +\\%Y-\\%m-\\%d)'" | sudo tee -a /etc/crontab > /dev/null
echo "0 * * * * $LLDPQ_USER /usr/local/bin/lldpq-ai-analyze" | sudo tee -a /etc/crontab > /dev/null

if [[ "$ANSIBLE_DIR" != "NoNe" ]] && [[ -d "$ANSIBLE_DIR" ]] && [[ -d "$ANSIBLE_DIR/playbooks" ]]; then
    echo "33 3 * * * $LLDPQ_USER $LLDPQ_INSTALL_DIR/fabric-scan-cron.sh" | sudo tee -a /etc/crontab > /dev/null
    chmod +x "$LLDPQ_INSTALL_DIR/fabric-scan-cron.sh" 2>/dev/null || true
    echo "  - fabric-scan: daily at 03:33 (Ansible diff check)"
fi

echo "  Cron jobs configured:"
echo "    - lldpq:           every 10 minutes"
echo "    - get-conf:        every 12 hours"
echo "    - web triggers:    every minute (enables Run LLDP Check button)"
echo "    - git auto-commit: daily at midnight"

# ============================================================================
# UPDATE-ONLY: Restore monitoring data & summary
# ============================================================================
if [[ "$INSTALL_MODE" == "update" ]]; then

    if [[ -n "$_DATA_PRESERVE" ]] && [[ -d "$_DATA_PRESERVE" ]]; then
        step "Restoring monitoring data..."
        for _d in monitor-results lldp-results alert-states; do
            if [[ -e "$_DATA_PRESERVE/$_d" ]]; then
                sudo rm -rf "$LLDPQ_INSTALL_DIR/$_d" 2>/dev/null || true
                sudo mv "$_DATA_PRESERVE/$_d" "$LLDPQ_INSTALL_DIR/" 2>/dev/null && echo "  • $_d/"
            fi
        done
        # Fix ownership and permissions on restored data
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/monitor-results" 2>/dev/null || true
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/lldp-results" 2>/dev/null || true
        sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR/alert-states" 2>/dev/null || true
        sudo find "$LLDPQ_INSTALL_DIR/monitor-results" -type d -exec chmod 775 {} \; 2>/dev/null || true
        sudo find "$LLDPQ_INSTALL_DIR/monitor-results" -type f -exec chmod 664 {} \; 2>/dev/null || true
        rmdir "$_DATA_PRESERVE" 2>/dev/null || sudo rm -rf "$_DATA_PRESERVE" 2>/dev/null || true
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
