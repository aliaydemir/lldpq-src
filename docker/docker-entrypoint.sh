#!/bin/bash
# LLDPq Docker Entrypoint
# Self-healing startup: ensures all required files/dirs exist with correct permissions
# Starts: nginx + fcgiwrap + cron

set -e

echo "╔══════════════════════════════════════╗"
echo "║      LLDPq Network Monitoring        ║"
echo "║      Docker Container v$(cat /var/www/html/VERSION 2>/dev/null || echo '?')        ║"
echo "╚══════════════════════════════════════╝"

# ─── VRF Setup (Cumulus switch only) ───
# If mgmt VRF exists (Cumulus Linux), route outbound traffic through it
if ip vrf show mgmt >/dev/null 2>&1; then
    MGMT_TABLE=$(ip vrf show mgmt 2>/dev/null | awk '/mgmt/{print $2}')
    if [ -n "$MGMT_TABLE" ]; then
        ip rule add pref 100 table "$MGMT_TABLE" 2>/dev/null || true
        echo "✓ mgmt VRF detected (table $MGMT_TABLE) — outbound via mgmt"
    fi
fi

# ─── SSH Key Setup ───
# Support mounting host SSH keys as read-only volume
if [ -d /home/lldpq/.ssh-mount ]; then
    # Copy mounted keys (read-only mount → writable .ssh)
    cp -n /home/lldpq/.ssh-mount/id_* /home/lldpq/.ssh/ 2>/dev/null || true
    cp -n /home/lldpq/.ssh-mount/known_hosts /home/lldpq/.ssh/ 2>/dev/null || true
    chown -R lldpq:lldpq /home/lldpq/.ssh/
    chmod 700 /home/lldpq/.ssh
    chmod 600 /home/lldpq/.ssh/id_* 2>/dev/null || true
fi

if [ -f /home/lldpq/.ssh/id_rsa ] || [ -f /home/lldpq/.ssh/id_ed25519 ]; then
    echo "✓ SSH keys found"
else
    echo "⚠ No SSH keys — use SSH Setup from web UI, or mount keys:"
    echo "  docker run ... -v ~/.ssh:/home/lldpq/.ssh-mount:ro ..."
fi

# ─── Ansible Directory Setup ───
if [ -n "$ANSIBLE_DIR" ] && [ "$ANSIBLE_DIR" != "NoNe" ] && [ -d "$ANSIBLE_DIR" ]; then
    sed -i "s|^ANSIBLE_DIR=.*|ANSIBLE_DIR=$ANSIBLE_DIR|" /etc/lldpq.conf
    chown -R lldpq:www-data "$ANSIBLE_DIR" 2>/dev/null || true
    echo "  ✓ Ansible directory: $ANSIBLE_DIR"
fi

# ─── Editor Root Setup ───
if [ -n "$EDITOR_ROOT" ] && [ -d "$EDITOR_ROOT" ]; then
    sed -i "s|^EDITOR_ROOT=.*|EDITOR_ROOT=$EDITOR_ROOT|" /etc/lldpq.conf
fi
echo "  ✓ Fabric Editor: $(grep '^EDITOR_ROOT=' /etc/lldpq.conf | cut -d= -f2)"

# ─── Shared config permissions ───
usermod -aG lldpq www-data 2>/dev/null || true
usermod -aG www-data lldpq 2>/dev/null || true
touch /etc/lldpq.conf.lock
chown root:www-data /etc/lldpq.conf /etc/lldpq.conf.lock
chmod 664 /etc/lldpq.conf /etc/lldpq.conf.lock

# ─── Single config directory (optional, backward compatible) ───
# Manage ALL user config from ONE mounted dir (like monitor-results):
#   -v /host/configs:/home/lldpq/lldpq/config
# When mounted: missing files self-seed from baked-in defaults, then the
# app-expected paths are symlinked into the dir so edits persist to the host.
# When NOT mounted: legacy individual-file mounts / baked-in files keep working.
CONFIG_DIR=/home/lldpq/lldpq/config
mkdir -p "$CONFIG_DIR"
chown lldpq:www-data "$CONFIG_DIR" 2>/dev/null || true
chmod 775 "$CONFIG_DIR" 2>/dev/null || true

if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$CONFIG_DIR" 2>/dev/null; then
    _setup_config_file() {
        local name="$1" app_path="$2" owner="$3" mode="$4"
        local src="$CONFIG_DIR/$name"
        # Seed config dir from baked-in/default file on first run
        if [ ! -f "$src" ] && [ -f "$app_path" ]; then
            cp -a "$(readlink -f "$app_path")" "$src" 2>/dev/null || cp "$app_path" "$src" 2>/dev/null || true
        fi
        # Point the app-expected path at the file in the config dir
        if [ -f "$src" ]; then
            rm -f "$app_path" 2>/dev/null || true
            ln -sf "$src" "$app_path" 2>/dev/null || true
            chown "$owner" "$src" 2>/dev/null || true
            chmod "$mode" "$src" 2>/dev/null || true
        fi
    }
    _setup_config_file devices.yaml         /home/lldpq/lldpq/devices.yaml      lldpq:www-data    664
    _setup_config_file topology.dot         /var/www/html/topology.dot          lldpq:www-data    664
    _setup_config_file topology_config.yaml /var/www/html/topology_config.yaml  lldpq:www-data    664
    _setup_config_file lldpq-users.conf     /etc/lldpq-users.conf               www-data:www-data 600
    # Scripts read topology files from the lldpq dir → keep those symlinks valid
    ln -sf /var/www/html/topology.dot /home/lldpq/lldpq/topology.dot 2>/dev/null || true
    ln -sf /var/www/html/topology_config.yaml /home/lldpq/lldpq/topology_config.yaml 2>/dev/null || true
    echo "✓ Config directory active: $CONFIG_DIR (devices.yaml, topology.dot, topology_config.yaml, lldpq-users.conf)"
fi

# ─── devices.yaml Setup ───
if [ -f /home/lldpq/lldpq/devices.yaml ]; then
    chown lldpq:www-data /home/lldpq/lldpq/devices.yaml
    chmod 664 /home/lldpq/lldpq/devices.yaml
    echo "✓ devices.yaml loaded ($(grep -c '^\s*[0-9]' /home/lldpq/lldpq/devices.yaml 2>/dev/null || echo 0) devices)"
else
    echo "⚠ No devices.yaml found"
    echo "  Mount with: -v /path/to/devices.yaml:/home/lldpq/lldpq/devices.yaml"
fi

# ─── Topology files Setup ───
# Real files in web root (editable from web UI), symlinks in lldpq dir (used by scripts)
for f in topology.dot topology_config.yaml; do
    # If file exists in web root (baked in or volume-mounted), ensure symlink
    if [ -f "/var/www/html/$f" ] && [ ! -L "/home/lldpq/lldpq/$f" ]; then
        rm -f "/home/lldpq/lldpq/$f"
        ln -sf "/var/www/html/$f" "/home/lldpq/lldpq/$f"
    fi
    # If file only exists in lldpq dir (not a symlink), move to web root
    if [ -f "/home/lldpq/lldpq/$f" ] && [ ! -L "/home/lldpq/lldpq/$f" ] && [ ! -f "/var/www/html/$f" ]; then
        mv "/home/lldpq/lldpq/$f" "/var/www/html/$f"
        ln -sf "/var/www/html/$f" "/home/lldpq/lldpq/$f"
    fi
    if [ -f "/var/www/html/$f" ]; then
        chown lldpq:www-data "/var/www/html/$f"
        chmod 664 "/var/www/html/$f"
    fi
done
echo "✓ Topology files ready"

# ─── Persistent data directories ───
for dir in /home/lldpq/lldpq/monitor-results \
           /home/lldpq/lldpq/monitor-results/fabric-tables \
           /var/www/html/hstr \
           /var/www/html/configs \
           /var/www/html/monitor-results \
           /var/www/html/topology; do
    mkdir -p "$dir"
    chown -R lldpq:www-data "$dir"
    chmod 775 "$dir"
done

# Symlink monitor-results to web root
ln -sf /home/lldpq/lldpq/monitor-results /var/www/html/monitor-results 2>/dev/null || true

# ─── Cache files (assets.sh, fabric-scan.sh, provision, AI need these writable by lldpq) ───
for f in /var/www/html/device-cache.json /var/www/html/fabric-scan-cache.json /var/www/html/discovery-cache.json /var/www/html/inventory.json /var/www/html/ai-analysis.json; do
    [ ! -f "$f" ] && echo '{}' > "$f"
    chown lldpq:www-data "$f"
    chmod 664 "$f"
done

# ─── Generated configs dir + serial mapping (ZTP config resolution) ───
mkdir -p /var/www/html/generated_config_folder
chown lldpq:www-data /var/www/html/generated_config_folder
chmod 775 /var/www/html/generated_config_folder
if [ ! -f /var/www/html/serial-mapping.txt ]; then
    printf '# Serial → Hostname mapping for ZTP config resolution\n# Format: SERIAL_NUMBER  HOSTNAME\n\n' > /var/www/html/serial-mapping.txt
fi
chown lldpq:www-data /var/www/html/serial-mapping.txt
chmod 664 /var/www/html/serial-mapping.txt

# ─── Auth Setup (self-healing: recreate if missing) ───
if [ ! -f /etc/lldpq-users.conf ]; then
    echo "  Creating default users file..."
    ADMIN_HASH=$(echo -n "admin" | openssl dgst -sha256 | awk '{print $2}')
    OPERATOR_HASH=$(echo -n "operator" | openssl dgst -sha256 | awk '{print $2}')
    echo "admin:$ADMIN_HASH:admin" > /etc/lldpq-users.conf
    echo "operator:$OPERATOR_HASH:operator" >> /etc/lldpq-users.conf
    echo "  ⚠ Default credentials: admin/admin, operator/operator"
fi
chmod 600 /etc/lldpq-users.conf
chown www-data:www-data /etc/lldpq-users.conf
mkdir -p /var/lib/lldpq/sessions
mkdir -p /var/lib/lldpq/upgrade-jobs
chown -R www-data:www-data /var/lib/lldpq
chown lldpq:www-data /var/lib/lldpq/upgrade-jobs
chmod 700 /var/lib/lldpq/sessions
chmod 775 /var/lib/lldpq/upgrade-jobs
echo "✓ Authentication ready"

# ─── Cron Setup ───
# lldpq = assets.sh + check-lldp.sh + monitor.sh + fabric-scan.sh + alerts
# lldpq-trigger = web UI refresh buttons (Refresh Assets, Refresh LLDP, etc.)
cat > /etc/cron.d/lldpq << 'CRON'
# LLDPq full run (assets + lldp + monitor + alerts) - every 10 minutes
*/10 * * * * lldpq /usr/local/bin/lldpq > /dev/null 2>&1
# Web trigger daemon (handles Refresh buttons from UI) - every minute
* * * * * lldpq /usr/local/bin/lldpq-trigger > /dev/null 2>&1
# Fabric scan (topology data for search) - every minute
* * * * * lldpq cd /home/lldpq/lldpq && ./fabric-scan.sh > /dev/null 2>&1
# Config backup - every 12 hours
0 */12 * * * lldpq /usr/local/bin/get-conf > /dev/null 2>&1
CRON
chmod 644 /etc/cron.d/lldpq

# ─── DHCP Server Setup ───
# Ensure DHCP directories and files exist
mkdir -p /var/lib/dhcp /etc/dhcp
touch /var/lib/dhcp/dhcpd.leases
[ ! -f /etc/dhcp/dhcpd.hosts ] && touch /etc/dhcp/dhcpd.hosts
chown lldpq:www-data /etc/dhcp/dhcpd.hosts
chmod 664 /etc/dhcp/dhcpd.hosts

# Default post-provision settings in lldpq.conf (if not present)
for key_val in "AUTO_BASE_CONFIG=true" "AUTO_ZTP_DISABLE=true" "AUTO_SET_HOSTNAME=true"; do
    key="${key_val%%=*}"
    grep -q "^${key}=" /etc/lldpq.conf 2>/dev/null || echo "$key_val" >> /etc/lldpq.conf
done

# Default dhcpd.conf if not configured yet (Ubuntu sample is useless)
if ! grep -q 'cumulus-provision-url\|LLDPq' /etc/dhcp/dhcpd.conf 2>/dev/null; then
    # Detect our IP for default config
    OUR_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    OUR_IP="${OUR_IP:-127.0.0.1}"
    # Detect subnet from our IP (replace last octet with 0)
    OUR_SUBNET=$(echo "$OUR_IP" | sed 's/\.[0-9]*$/.0/')
    OUR_GW=$(echo "$OUR_IP" | sed 's/\.[0-9]*$/.1/')
    
    cat > /etc/dhcp/dhcpd.conf << DHCPEOF
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
    chown lldpq:www-data /etc/dhcp/dhcpd.conf
    chmod 664 /etc/dhcp/dhcpd.conf
    echo "✓ Default DHCP config created (subnet: ${OUR_SUBNET}/24, server: ${OUR_IP})"
fi

# Write interface config if missing
if ! grep -q '^INTERFACES=' /etc/default/isc-dhcp-server 2>/dev/null; then
    echo 'INTERFACES="eth0"' > /etc/default/isc-dhcp-server
fi

# ZTP script in web root (writable by lldpq)
if [ ! -f /var/www/html/cumulus-ztp.sh ]; then
    echo '#!/bin/bash' > /var/www/html/cumulus-ztp.sh
    echo '# CUMULUS-AUTOPROVISIONING' >> /var/www/html/cumulus-ztp.sh
    echo '# Edit this script from the Provision page' >> /var/www/html/cumulus-ztp.sh
fi
chown lldpq:www-data /var/www/html/cumulus-ztp.sh
chmod 775 /var/www/html/cumulus-ztp.sh

# Base config files permissions
if [ -d /home/lldpq/lldpq/sw-base ]; then
    chown -R lldpq:lldpq /home/lldpq/lldpq/sw-base
    chmod 755 /home/lldpq/lldpq/sw-base
    find /home/lldpq/lldpq/sw-base -type f -exec chmod 644 {} \;
    # Binaries and scripts need execute
    for f in exa cmd nvc nvt motd.sh; do
        [ -f "/home/lldpq/lldpq/sw-base/$f" ] && chmod 755 "/home/lldpq/lldpq/sw-base/$f"
    done
    echo "✓ sw-base files ready ($(ls /home/lldpq/lldpq/sw-base/ 2>/dev/null | wc -l) files)"
fi

# DHCP server: only start if explicitly enabled via DHCP_AUTOSTART=true
# By default DHCP is OFF — admin enables from Provision → DHCP Server → Start
if [ "${DHCP_AUTOSTART:-false}" = "true" ] && [ -f /etc/dhcp/dhcpd.conf ]; then
    DHCP_IFACE="eth0"
    if [ -f /etc/default/isc-dhcp-server ]; then
        DHCP_IFACE=$(grep '^INTERFACES=' /etc/default/isc-dhcp-server 2>/dev/null | sed 's/INTERFACES="//;s/"//' || echo "eth0")
    fi
    dhcpd -cf /etc/dhcp/dhcpd.conf "$DHCP_IFACE" 2>/dev/null && echo "✓ DHCP server started (interface: $DHCP_IFACE)" || echo "  DHCP: not started (interface issue)"
else
    echo "  DHCP: not started (start from Provision page or set DHCP_AUTOSTART=true)"
fi

# ─── SSH Server Setup ───
echo "lldpq:lldpq" | chpasswd 2>/dev/null

# ─── Start Services ───
echo ""
echo "Starting services..."

# Start cron
service cron start > /dev/null 2>&1
echo "  ✓ cron"

# Start fcgiwrap (CGI scripts for web API)
/usr/sbin/fcgiwrap -f -s unix:/var/run/fcgiwrap.socket &
sleep 0.5
chown www-data:www-data /var/run/fcgiwrap.socket
chmod 660 /var/run/fcgiwrap.socket
echo "  ✓ fcgiwrap"

# Start SSH server (port 2033)
/usr/sbin/sshd 2>/dev/null && echo "  ✓ sshd (port 2033)" || echo "  ⚠ sshd failed to start"

# Start nginx (foreground - keeps container alive)
echo "  ✓ nginx (port 80)"
echo ""
echo "LLDPq is ready! Access: http://localhost:${LLDPQ_PORT:-80}"
echo "  SSH: ssh -p 2033 lldpq@<host-ip>"
echo ""

exec nginx -g 'daemon off;'
