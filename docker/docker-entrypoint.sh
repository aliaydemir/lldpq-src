#!/bin/bash
# LLDPq Docker Entrypoint
# Self-healing startup: ensures all required files/dirs exist with correct permissions
# Starts: nginx + fcgiwrap + cron

set -e

BACKUP_IMPORT_HELPER=/usr/local/libexec/lldpq-backup-import.py

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
mkdir -p /home/lldpq/.ssh
if [ -d /home/lldpq/.ssh-mount ]; then
    # Copy mounted keys (read-only mount → writable .ssh)
    cp -n /home/lldpq/.ssh-mount/id_* /home/lldpq/.ssh/ 2>/dev/null || true
    cp -n /home/lldpq/.ssh-mount/known_hosts /home/lldpq/.ssh/ 2>/dev/null || true
fi
# Named-volume imports performed through `docker cp` commonly arrive owned by
# root. Normalize every startup, not only the legacy read-only mount path.
chown -R lldpq:lldpq /home/lldpq/.ssh/
chmod 700 /home/lldpq/.ssh
chmod 600 /home/lldpq/.ssh/id_* 2>/dev/null || true
chmod 644 /home/lldpq/.ssh/known_hosts 2>/dev/null || true

# The default named volume and `docker cp` imports can both arrive root-owned.
# The web workflows need group access to inventory/playbooks while Ansible runs
# as the lldpq service user.
mkdir -p /home/lldpq/ansible
chown -R lldpq:www-data /home/lldpq/ansible
chmod 775 /home/lldpq/ansible

if [ -f /home/lldpq/.ssh/id_rsa ] || [ -f /home/lldpq/.ssh/id_ed25519 ]; then
    echo "✓ SSH keys found"
else
    echo "⚠ No SSH keys — use SSH Setup from web UI, or mount keys:"
    echo "  docker run ... -v ~/.ssh:/home/lldpq/.ssh-mount:ro ..."
fi

# ─── Persistent system configuration ───
# Keep mutable /etc configuration in one data directory. docker-compose mounts
# this directory as a named volume; legacy direct file bind mounts are detected
# and left untouched. A plain `docker run` remains backward compatible, with
# persistence for the lifetime of that container's writable layer.
if ! command -v mountpoint >/dev/null 2>&1; then
    echo "ERROR: mountpoint (util-linux) is required for safe volume migration; rebuild the image" >&2
    exit 1
fi
SYSTEM_CONFIG_DIR="${LLDPQ_SYSTEM_CONFIG_DIR:-/home/lldpq/lldpq/system-config}"
mkdir -p "$SYSTEM_CONFIG_DIR" /etc/dhcp /etc/default
chown lldpq:www-data "$SYSTEM_CONFIG_DIR" 2>/dev/null || true
chmod 750 "$SYSTEM_CONFIG_DIR" 2>/dev/null || true

_is_direct_mount() {
    command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$1" 2>/dev/null
}

_persist_system_file() {
    local name="$1" app_path="$2" owner="$3" mode="$4"
    local persistent="$SYSTEM_CONFIG_DIR/$name" resolved=""

    if _is_direct_mount "$app_path"; then
        echo "  ✓ Legacy direct mount retained: $app_path"
        return 0
    fi
    if [ ! -e "$persistent" ]; then
        if [ -e "$app_path" ] || [ -L "$app_path" ]; then
            resolved=$(readlink -f "$app_path" 2>/dev/null || true)
            if [ -n "$resolved" ] && [ -e "$resolved" ]; then
                cp -a "$resolved" "$persistent"
            else
                touch "$persistent"
            fi
        else
            touch "$persistent"
        fi
    fi
    rm -f "$app_path"
    ln -s "$persistent" "$app_path"
    chown "$owner" "$persistent" 2>/dev/null || true
    chmod "$mode" "$persistent" 2>/dev/null || true
}

_persist_system_file lldpq.conf /etc/lldpq.conf root:www-data 664
_persist_system_file dhcpd.conf /etc/dhcp/dhcpd.conf lldpq:www-data 664
_persist_system_file dhcpd.hosts /etc/dhcp/dhcpd.hosts lldpq:www-data 664
_persist_system_file isc-dhcp-server /etc/default/isc-dhcp-server root:root 644

# A killed Setup restore may have left /etc/lldpq.conf only partly activated.
# Recover from the persistent, hashed authority before asking lldpq-config to
# parse that file. Arguments are fixed image paths; no config data is trusted.
if [ -L "$BACKUP_IMPORT_HELPER" ] || [ ! -f "$BACKUP_IMPORT_HELPER" ] || \
   [ "$(stat -c '%u:%g:%a' -- "$BACKUP_IMPORT_HELPER" 2>/dev/null || true)" != "0:0:755" ]; then
    echo "ERROR: root-owned backup/import helper is missing or unsafe; rebuild the image" >&2
    exit 1
fi
if ! python3 "$BACKUP_IMPORT_HELPER" recover \
    --lldpq-dir /home/lldpq/lldpq \
    --user lldpq \
    --web-root /var/www/html; then
    echo "ERROR: retained LLDPq backup import could not be recovered; startup stopped" >&2
    exit 1
fi

if [ ! -x /usr/local/bin/lldpq-config ]; then
    echo "ERROR: required /usr/local/bin/lldpq-config helper is missing; rebuild the image" >&2
    exit 1
fi
if ! /usr/local/bin/lldpq-config --require-config \
    --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
    >/dev/null 2>&1; then
    echo "ERROR: persistent /etc/lldpq.conf is missing or lacks core runtime settings" >&2
    exit 1
fi
LLDPQ_CONF_REAL=$(readlink -f /etc/lldpq.conf 2>/dev/null || echo /etc/lldpq.conf)

_set_lldpq_conf_value() {
    local key="$1" value="$2" direct_mount=false
    if _is_direct_mount /etc/lldpq.conf; then
        direct_mount=true
    fi
    # A bind-mounted file cannot be replaced with rename(2) (EBUSY). Update
    # that inode in place; for the persistent-volume target use a same-folder
    # fsync + atomic replace while retaining its owner and mode.
    python3 - "$LLDPQ_CONF_REAL" "$key" "$value" "$direct_mount" <<'PYTHON'
import os
import pathlib
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
direct_mount = sys.argv[4] == "true"
if any(character in value for character in ("\x00", "\n", "\r")):
    raise SystemExit(f"invalid control character in {key}")

original = path.read_text(encoding="utf-8")
lines = original.splitlines(keepends=True)
replacement = f"{key}={value}\n"
output = []
replaced = False
for line in lines:
    if line.startswith(f"{key}="):
        if not replaced:
            output.append(replacement)
            replaced = True
        continue
    output.append(line)
if not replaced:
    if output and not output[-1].endswith("\n"):
        output[-1] += "\n"
    output.append(replacement)
content = "".join(output)

metadata = path.stat()
if direct_mount:
    with path.open("r+", encoding="utf-8") as handle:
        handle.seek(0)
        handle.write(content)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
else:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, metadata.st_mode & 0o7777)
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
PYTHON
}

# ─── Ansible Directory Setup ───
if [ -n "$ANSIBLE_DIR" ] && [ "$ANSIBLE_DIR" != "NoNe" ] && [ -d "$ANSIBLE_DIR" ]; then
    _set_lldpq_conf_value ANSIBLE_DIR "$ANSIBLE_DIR"
    chown -R lldpq:www-data "$ANSIBLE_DIR" 2>/dev/null || true
    echo "  ✓ Ansible directory: $ANSIBLE_DIR"
fi

# ─── Editor Root Setup ───
if [ -n "$EDITOR_ROOT" ] && [ -d "$EDITOR_ROOT" ]; then
    _set_lldpq_conf_value EDITOR_ROOT "$EDITOR_ROOT"
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
if [ ! -f /var/www/html/serial-mapping.txt ]; then
    printf '# Serial → Hostname mapping for ZTP config resolution\n# Format: SERIAL_NUMBER  HOSTNAME\n\n' \
        > /var/www/html/serial-mapping.txt
fi
if [ ! -f /var/www/html/display-aliases.json ]; then
    printf '{"interfaces":{},"devices":{}}\n' > /var/www/html/display-aliases.json
fi

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
    _setup_config_file notifications.yaml   /home/lldpq/lldpq/notifications.yaml lldpq:www-data   664
    _setup_config_file cumulus-ztp.sh       /var/www/html/cumulus-ztp.sh        lldpq:www-data    775
    _setup_config_file serial-mapping.txt   /var/www/html/serial-mapping.txt    lldpq:www-data    664
    _setup_config_file display-aliases.json /var/www/html/display-aliases.json  lldpq:www-data    664
    # Scripts read topology files from the lldpq dir → keep those symlinks valid
    ln -sf /var/www/html/topology.dot /home/lldpq/lldpq/topology.dot 2>/dev/null || true
    ln -sf /var/www/html/topology_config.yaml /home/lldpq/lldpq/topology_config.yaml 2>/dev/null || true
    echo "✓ Persistent application configuration directory active: $CONFIG_DIR"
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
MONITOR_SOURCE_DIR=/home/lldpq/lldpq/monitor-results
MONITOR_WEB_DIR=/var/www/html/monitor-results
MONITOR_WEB_PARENT=$(dirname "$MONITOR_WEB_DIR")
MONITOR_SEED_BACKUP="$MONITOR_WEB_PARENT/.monitor-results.seed-backup"

_remove_monitor_seed_path() {
    local path="$1"
    if [ -L "$path" ] || [ -f "$path" ]; then
        rm -f -- "$path"
    elif [ -d "$path" ]; then
        rm -rf -- "$path"
    fi
}

_seed_monitor_web_tree() {
    local source="$1" target="$2" stage
    stage=$(mktemp -d "$MONITOR_WEB_PARENT/.monitor-results.seed.XXXXXXXX") || return 1
    if ! cp -a "$source"/. "$stage"/; then
        _remove_monitor_seed_path "$stage"
        return 1
    fi
    rm -f "$stage/.gitkeep" 2>/dev/null || true

    _remove_monitor_seed_path "$MONITOR_SEED_BACKUP"
    if [ -e "$target" ] || [ -L "$target" ]; then
        if ! mv "$target" "$MONITOR_SEED_BACKUP"; then
            _remove_monitor_seed_path "$stage"
            return 1
        fi
    fi
    if mv "$stage" "$target"; then
        _remove_monitor_seed_path "$MONITOR_SEED_BACKUP"
        return 0
    fi

    _remove_monitor_seed_path "$stage"
    if [ -e "$MONITOR_SEED_BACKUP" ] || [ -L "$MONITOR_SEED_BACKUP" ]; then
        mv "$MONITOR_SEED_BACKUP" "$target" 2>/dev/null || true
    fi
    return 1
}

# Recover a seed activation interrupted between the old-tree rename and the
# new-tree activation. Both locations are on the same filesystem.
if { [ -e "$MONITOR_SEED_BACKUP" ] || [ -L "$MONITOR_SEED_BACKUP" ]; } && \
   [ ! -e "$MONITOR_WEB_DIR" ] && [ ! -L "$MONITOR_WEB_DIR" ]; then
    mv "$MONITOR_SEED_BACKUP" "$MONITOR_WEB_DIR"
elif [ -e "$MONITOR_SEED_BACKUP" ] || [ -L "$MONITOR_SEED_BACKUP" ]; then
    _remove_monitor_seed_path "$MONITOR_SEED_BACKUP"
fi

# Older images exposed the source tree through a direct symlink. Remove only
# that link through the staged activation below. monitor.sh now publishes
# source -> web as separate trees.
if [ -L "$MONITOR_WEB_DIR" ]; then
    _old_monitor_source=$(readlink -f "$MONITOR_WEB_DIR" 2>/dev/null || true)
    if [ -n "$_old_monitor_source" ] && [ -d "$_old_monitor_source" ]; then
        if ! _seed_monitor_web_tree "$_old_monitor_source" "$MONITOR_WEB_DIR"; then
            echo "ERROR: legacy monitor report tree could not be migrated; source data was retained" >&2
            exit 1
        fi
    else
        echo "ERROR: legacy monitor report link has no readable source; refusing partial migration" >&2
        exit 1
    fi
fi
mkdir -p "$MONITOR_SOURCE_DIR" "$MONITOR_WEB_DIR"
if [ ! -f "$MONITOR_WEB_DIR/.lldpq-current.json" ] && \
   find "$MONITOR_SOURCE_DIR" -mindepth 1 -maxdepth 1 ! -name .gitkeep \
       -print -quit 2>/dev/null | grep -q .; then
    if ! _seed_monitor_web_tree "$MONITOR_SOURCE_DIR" "$MONITOR_WEB_DIR"; then
        echo "ERROR: last-known-good monitor reports could not be seeded into the web tree" >&2
        exit 1
    fi
fi

for dir in "$MONITOR_SOURCE_DIR" \
           /home/lldpq/lldpq/monitor-results/fabric-tables \
           /home/lldpq/lldpq/lldp-results \
           /home/lldpq/lldpq/alert-states \
           /var/www/html/hstr \
           /var/www/html/configs \
           /var/www/html/monitor-results \
           /var/www/html/topology; do
    mkdir -p "$dir"
    chown -R lldpq:www-data "$dir"
    chmod 775 "$dir"
done

# ─── Persistent provisioning artifacts ───
GENERATED_CONFIGS_DIR=/var/www/html/generated_config_folder
PROVISION_UPLOAD_DIR=/var/www/html/provision-uploads
mkdir -p "$GENERATED_CONFIGS_DIR" "$PROVISION_UPLOAD_DIR"
chown -R lldpq:www-data "$GENERATED_CONFIGS_DIR" "$PROVISION_UPLOAD_DIR"
find "$GENERATED_CONFIGS_DIR" "$PROVISION_UPLOAD_DIR" -type d -exec chmod 775 {} \;
find "$GENERATED_CONFIGS_DIR" -type f -exec chmod 664 {} \;
find "$PROVISION_UPLOAD_DIR" -type f -exec chmod 664 {} \;

_publish_provision_link() {
    local name="$1" root_path="/var/www/html/$1"
    if [ -e "$root_path" ] || [ -L "$root_path" ]; then
        rm -f -- "$root_path"
    fi
    ln -s "provision-uploads/$name" "$root_path"
}

_migrate_legacy_provision_file() {
    local legacy="$1" name destination stage
    name=$(basename "$legacy")
    destination="$PROVISION_UPLOAD_DIR/$name"
    [ -f "$legacy" ] && [ ! -L "$legacy" ] || return 0

    if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
        stage=$(mktemp "$PROVISION_UPLOAD_DIR/.${name}.migrate.XXXXXXXX") || return 1
        if ! cp -p "$legacy" "$stage" || ! cmp -s "$legacy" "$stage"; then
            rm -f "$stage"
            echo "ERROR: legacy provisioning file could not be copied safely: $legacy" >&2
            return 1
        fi
        mv "$stage" "$destination"
    elif ! cmp -s "$legacy" "$destination"; then
        echo "ERROR: conflicting persistent provisioning file: $name" >&2
        return 1
    fi
    rm -f "$legacy"
    _publish_provision_link "$name"
}

# Move OS images left in the legacy writable container layer into the named
# volume without deleting the source until a byte-for-byte copy is present.
for legacy_image in /var/www/html/*.bin /var/www/html/*.img /var/www/html/*.iso; do
    [ -e "$legacy_image" ] || continue
    _migrate_legacy_provision_file "$legacy_image"
done

# Preserve the active generic ONIE waterfall aliases in the same volume. Old
# aliases pointed directly at the image name; root links now point at the
# persistent alias, which in turn remains relative to its image in the volume.
for onie_alias in onie-installer-x86_64 onie-installer-x86_64-mlnx onie-installer; do
    root_alias="/var/www/html/$onie_alias"
    persistent_alias="$PROVISION_UPLOAD_DIR/$onie_alias"
    if [ -L "$root_alias" ]; then
        alias_target=$(basename "$(readlink "$root_alias")")
        if [ "$alias_target" != "$onie_alias" ] && \
           [ -e "$PROVISION_UPLOAD_DIR/$alias_target" ]; then
            ln -sfn "$alias_target" "$persistent_alias"
        fi
        rm -f "$root_alias"
    elif [ -f "$root_alias" ]; then
        _migrate_legacy_provision_file "$root_alias"
    fi
    if [ -e "$persistent_alias" ] || [ -L "$persistent_alias" ]; then
        _publish_provision_link "$onie_alias"
    fi
done

# Re-publish every persisted image at the historical web-root URL expected by
# ONIE and cumulus-ztp.sh.
for stored_image in "$PROVISION_UPLOAD_DIR"/*.bin \
                    "$PROVISION_UPLOAD_DIR"/*.img \
                    "$PROVISION_UPLOAD_DIR"/*.iso; do
    [ -e "$stored_image" ] || continue
    _publish_provision_link "$(basename "$stored_image")"
done

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
# Honor allowlisted schedules from persistent lldpq.conf.
if ! LLDPQ_CONFIG_ASSIGNMENTS=$(/usr/local/bin/lldpq-config --require-config \
    --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT); then
    echo "ERROR: unable to load /etc/lldpq.conf through lldpq-config" >&2
    exit 1
fi
eval "$LLDPQ_CONFIG_ASSIGNMENTS"
LLDPQ_CRON="${LLDPQ_CRON:-*/10 * * * *}"
GETCONF_CRON="${GETCONF_CRON:-0 */12 * * *}"
if ! /usr/local/bin/lldpq-config --validate-cron "$LLDPQ_CRON"; then
    echo "ERROR: invalid LLDPQ_CRON schedule: $LLDPQ_CRON" >&2
    exit 1
fi
if ! /usr/local/bin/lldpq-config --validate-cron "$GETCONF_CRON"; then
    echo "ERROR: invalid GETCONF_CRON schedule: $GETCONF_CRON" >&2
    exit 1
fi
cat > /etc/cron.d/lldpq << CRON
# LLDPq full run (assets + lldp + monitor + alerts)
$LLDPQ_CRON lldpq /usr/local/bin/lldpq > /dev/null 2>&1
# Web trigger daemon (handles Refresh buttons from UI) - every minute
* * * * * lldpq /usr/local/bin/lldpq-trigger > /dev/null 2>&1
# Fabric scan (topology data for search) - every minute
* * * * * lldpq cd /home/lldpq/lldpq && ./fabric-scan.sh > /dev/null 2>&1
# Config backup
$GETCONF_CRON lldpq /usr/local/bin/get-conf > /dev/null 2>&1
CRON
chmod 644 /etc/cron.d/lldpq

# ─── DHCP Server Setup ───
# Ensure DHCP directories and files exist
mkdir -p /var/lib/dhcp /etc/dhcp
touch /var/lib/dhcp/dhcpd.leases
chown root:www-data /var/lib/dhcp /var/lib/dhcp/dhcpd.leases
chmod 775 /var/lib/dhcp
chmod 664 /var/lib/dhcp/dhcpd.leases
[ ! -f /etc/dhcp/dhcpd.hosts ] && touch /etc/dhcp/dhcpd.hosts
chown lldpq:www-data /etc/dhcp/dhcpd.hosts
chmod 664 /etc/dhcp/dhcpd.hosts

# Default post-provision settings in lldpq.conf (if not present)
for key_val in "AUTO_BASE_CONFIG=true" "AUTO_ZTP_DISABLE=true" "AUTO_SET_HOSTNAME=true"; do
    key="${key_val%%=*}"
    grep -q "^${key}=" /etc/lldpq.conf 2>/dev/null || echo "$key_val" >> /etc/lldpq.conf
done

_docker_dhcp_is_managed() {
    grep -Fqx '# /etc/dhcp/dhcpd.conf - Generated by LLDPq' /etc/dhcp/dhcpd.conf 2>/dev/null
}

_docker_dhcp_is_packaged_sample() {
    [ ! -s /etc/dhcp/dhcpd.conf ] && return 0
    grep -Eq '^[[:space:]]*option[[:space:]]+domain-name[[:space:]]+"example\.org";' \
        /etc/dhcp/dhcpd.conf || return 1
    ! grep -Eq '^[[:space:]]*(subnet|shared-network|host|include)[[:space:]]' \
        /etc/dhcp/dhcpd.conf
}

_render_docker_dhcp_config() {
    local output="$1" server_ip="$2" subnet gateway
    subnet=$(echo "$server_ip" | sed 's/\.[0-9]*$/.0/')
    gateway=$(echo "$server_ip" | sed 's/\.[0-9]*$/.1/')
    cat > "$output" << DHCPEOF
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

include "/etc/dhcp/dhcpd.hosts";
DHCPEOF
}

_install_docker_dhcp_config() {
    local server_ip="$1" backup_existing="${2:-false}"
    local temp_file target_file staged_file backup_file
    temp_file=$(mktemp /tmp/lldpq-dhcp.XXXXXXXX)
    _render_docker_dhcp_config "$temp_file" "$server_ip"
    if ! dhcpd -t -cf "$temp_file" >/dev/null 2>&1; then
        echo "ERROR: generated Docker DHCP configuration failed dhcpd -t" >&2
        rm -f "$temp_file"
        return 1
    fi

    target_file=$(readlink -f /etc/dhcp/dhcpd.conf 2>/dev/null || echo /etc/dhcp/dhcpd.conf)
    if [ "$backup_existing" = "true" ] && [ -s /etc/dhcp/dhcpd.conf ]; then
        if _is_direct_mount /etc/dhcp/dhcpd.conf; then
            backup_file="$SYSTEM_CONFIG_DIR/dhcpd.conf.pre-lldpq-$(date +%Y%m%d-%H%M%S)-$$.bak"
        else
            backup_file="$(dirname "$target_file")/dhcpd.conf.pre-lldpq-$(date +%Y%m%d-%H%M%S)-$$.bak"
        fi
        cp -p /etc/dhcp/dhcpd.conf "$backup_file" || {
            echo "ERROR: existing Docker DHCP config could not be backed up" >&2
            rm -f "$temp_file"
            return 1
        }
        echo "  Existing DHCP config backed up to: $backup_file"
    fi

    if _is_direct_mount /etc/dhcp/dhcpd.conf; then
        cp "$temp_file" /etc/dhcp/dhcpd.conf || { rm -f "$temp_file"; return 1; }
    else
        mkdir -p "$(dirname "$target_file")"
        staged_file=$(mktemp "$(dirname "$target_file")/.dhcpd.conf.new.XXXXXXXX")
        cp "$temp_file" "$staged_file"
        chown lldpq:www-data "$staged_file"
        chmod 664 "$staged_file"
        mv -f "$staged_file" "$target_file"
    fi
    chown lldpq:www-data /etc/dhcp/dhcpd.conf 2>/dev/null || true
    chmod 664 /etc/dhcp/dhcpd.conf
    rm -f "$temp_file"
}

OUR_IP=$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print; exit}')
OUR_IP="${OUR_IP:-127.0.0.1}"
if _docker_dhcp_is_managed; then
    if ! dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
        echo "⚠ Existing LLDPq-managed DHCP config is invalid; DHCP will stay disabled until it is repaired" >&2
        DHCP_AUTOSTART=false
    else
        echo "✓ Existing LLDPq DHCP config validated"
    fi
elif _docker_dhcp_is_packaged_sample; then
    _install_docker_dhcp_config "$OUR_IP" false
    echo "✓ Default DHCP config validated and created (server: ${OUR_IP})"
elif [ "${LLDPQ_REPLACE_DHCP_CONFIG:-false}" = "true" ]; then
    _install_docker_dhcp_config "$OUR_IP" true
    echo "✓ Foreign DHCP config explicitly replaced after validation + backup"
else
    echo "⚠ Existing non-LLDPq DHCP config preserved. Set LLDPQ_REPLACE_DHCP_CONFIG=true to replace it explicitly."
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
    if ! dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
        echo "  DHCP: not started because dhcpd.conf failed validation" >&2
        DHCP_AUTOSTART=false
    fi
fi
if [ "${DHCP_AUTOSTART:-false}" = "true" ] && [ -f /etc/dhcp/dhcpd.conf ]; then
    DHCP_IFACE="eth0"
    if [ -f /etc/default/isc-dhcp-server ]; then
        DHCP_IFACE=$(grep '^INTERFACES=' /etc/default/isc-dhcp-server 2>/dev/null | sed 's/INTERFACES="//;s/"//' || echo "eth0")
    fi
    mkdir -p /var/log/lldpq 2>/dev/null
    # -d keeps dhcpd in the foreground logging to stderr; redirect to a file so the logs
    # survive (no syslog/journald in the container) and the Provision UI can tail them.
    dhcpd -d -cf /etc/dhcp/dhcpd.conf "$DHCP_IFACE" >> /var/log/lldpq/dhcpd.log 2>&1 &
    sleep 1
    if pgrep -x dhcpd >/dev/null 2>&1; then
        echo "✓ DHCP server started (interface: $DHCP_IFACE, log: /var/log/lldpq/dhcpd.log)"
    else
        echo "  DHCP: not started (see /var/log/lldpq/dhcpd.log)"
    fi
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

# Start console PTY bridge (web SSH terminal, admin-gated) as www-data
mkdir -p /var/log/lldpq 2>/dev/null && chown www-data:www-data /var/log/lldpq 2>/dev/null || true
runuser -u www-data -- python3 /home/lldpq/lldpq/console-pty.py >> /var/log/lldpq/console.log 2>&1 &
echo "  ✓ console-pty (127.0.0.1:8765)"

# Start nginx (foreground - keeps container alive)
echo "  ✓ nginx (port 80)"
echo ""
echo "LLDPq is ready! Access: http://localhost:${LLDPQ_PORT:-80}"
echo "  SSH: ssh -p 2033 lldpq@<host-ip>"
echo ""

exec nginx -g 'daemon off;'
