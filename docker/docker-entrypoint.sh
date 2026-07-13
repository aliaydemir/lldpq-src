#!/bin/bash
# LLDPq Docker Entrypoint
# Self-healing startup: ensures all required files/dirs exist with correct permissions
# Starts: nginx + fcgiwrap + cron

set -e

BACKUP_IMPORT_HELPER=/usr/local/libexec/lldpq-backup-import.py
INSTALL_LIBRARY=/usr/local/libexec/lldpq-install-library.sh
SETUP_SAFETY_HELPER=/usr/local/libexec/lldpq-setup-safety.py

echo "╔══════════════════════════════════════╗"
echo "║      LLDPq Network Monitoring        ║"
echo "║      Docker Container v$(cat /var/www/html/VERSION 2>/dev/null || echo '?')         ║"
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
chmod 2770 "$SYSTEM_CONFIG_DIR" 2>/dev/null || true

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

# Keep shared transaction locks on stable, regular inodes. Opening with
# O_NOFOLLOW and applying ownership/mode through the descriptor prevents a
# stale or hostile symlink from redirecting startup's root operations.
_prepare_shared_lock_files() {
    python3 - "$@" <<'PYTHON'
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

# Prepare config-write recovery authority early.  Recovery runs after the core
# runtime identity is loaded, but before application-config seeding/consumers.
# Normalize this mounted state once; later broad permission repair skips it.
PROVISION_STATE_DIR="${LLDPQ_PROVISION_STATE_DIR:-/var/lib/lldpq/provision-state}"
while [ "$PROVISION_STATE_DIR" != "/" ] && \
      [ "${PROVISION_STATE_DIR%/}" != "$PROVISION_STATE_DIR" ]; do
    PROVISION_STATE_DIR="${PROVISION_STATE_DIR%/}"
done
case "$PROVISION_STATE_DIR" in
    /*) ;;
    *)
        echo "ERROR: persistent Provision state path must be absolute" >&2
        exit 1
        ;;
esac
if [ "$PROVISION_STATE_DIR" = "/" ] || [ "$PROVISION_STATE_DIR" = "/var/lib/lldpq" ]; then
    echo "ERROR: persistent Provision state path is too broad: $PROVISION_STATE_DIR" >&2
    exit 1
fi
export LLDPQ_PROVISION_STATE_DIR="$PROVISION_STATE_DIR"
if [ -L "$PROVISION_STATE_DIR" ] || \
   { [ -e "$PROVISION_STATE_DIR" ] && [ ! -d "$PROVISION_STATE_DIR" ]; }; then
    echo "ERROR: unsafe persistent Provision state path: $PROVISION_STATE_DIR" >&2
    exit 1
fi
mkdir -p "$PROVISION_STATE_DIR"
chown lldpq:www-data "$PROVISION_STATE_DIR" 2>/dev/null || true
chmod 2770 "$PROVISION_STATE_DIR" 2>/dev/null || true

CONFIG_WRITE_JOURNAL_DIR="$PROVISION_STATE_DIR/config-write-journals"
export LLDPQ_DIRECT_WRITE_STATE_DIR="$CONFIG_WRITE_JOURNAL_DIR"
if [ -L "$CONFIG_WRITE_JOURNAL_DIR" ] || \
   { [ -e "$CONFIG_WRITE_JOURNAL_DIR" ] && [ ! -d "$CONFIG_WRITE_JOURNAL_DIR" ]; }; then
    echo "ERROR: unsafe persistent config-write journal path: $CONFIG_WRITE_JOURNAL_DIR" >&2
    exit 1
fi
mkdir -p "$CONFIG_WRITE_JOURNAL_DIR"
chown lldpq:www-data "$CONFIG_WRITE_JOURNAL_DIR"
# GNU chmod preserves setgid on directories unless the numeric mode has an
# extra leading zero. This child is created under a 2770 parent, so use 00700
# to clear the inherited bit on a fresh Docker volume/writable layer.
chmod 00700 "$CONFIG_WRITE_JOURNAL_DIR"
if [ "$(stat -c '%U:%G:%a' -- "$CONFIG_WRITE_JOURNAL_DIR" 2>/dev/null || true)" != \
     "lldpq:www-data:700" ]; then
    echo "ERROR: could not secure persistent config-write journal directory" >&2
    exit 1
fi

_persist_system_file lldpq.conf /etc/lldpq.conf lldpq:www-data 660
_persist_system_file dhcpd.conf /etc/dhcp/dhcpd.conf lldpq:www-data 664
_persist_system_file dhcpd.hosts /etc/dhcp/dhcpd.hosts lldpq:www-data 664
_persist_system_file isc-dhcp-server /etc/default/isc-dhcp-server lldpq:www-data 664
_prepare_shared_lock_files /etc/lldpq.conf.lock /etc/lldpq-users.conf.lock

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
    local key="$1" value="$2" only_if_missing="${3:-false}" direct_mount=false
    if _is_direct_mount /etc/lldpq.conf; then
        direct_mount=true
    fi
    # Never truncate a live single-file bind mount.  Docker rejects replacing
    # that mountpoint with rename(2), and an in-place rewrite has no crash-safe
    # rollback boundary.  Normal system-config targets are updated under the
    # shared lock with a same-directory, durably staged atomic replacement.
    python3 - "$LLDPQ_CONF_REAL" "$key" "$value" "$direct_mount" \
        "$only_if_missing" /etc/lldpq.conf.lock <<'PYTHON_SET_LLDPQ_CONF'
import fcntl
import os
import pathlib
import stat
import tempfile
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]
direct_mount = sys.argv[4] == "true"
only_if_missing = sys.argv[5] == "true"
lock_path = pathlib.Path(sys.argv[6])
if any(character in value for character in ("\x00", "\n", "\r")):
    raise SystemExit(f"invalid control character in {key}")

lock_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
lock_flags |= getattr(os, "O_NOFOLLOW", 0)
lock_descriptor = os.open(lock_path, lock_flags)
temporary = None
try:
    lock_metadata = os.fstat(lock_descriptor)
    if not stat.S_ISREG(lock_metadata.st_mode):
        raise SystemExit("LLDPq configuration lock is not a regular file")
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)

    original = path.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    replacement = f"{key}={value}\n"
    output = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}="):
            if only_if_missing:
                output.append(line)
            elif not replaced:
                output.append(replacement)
            replaced = True
            continue
        output.append(line)
    if not replaced:
        if output and not output[-1].endswith("\n"):
            output[-1] += "\n"
        output.append(replacement)
    content = "".join(output)

    if content == original:
        raise SystemExit(0)
    if direct_mount:
        raise SystemExit(
            f"ERROR: {path} is a legacy single-file Docker mount and {key} "
            "requires a change. The live file was not modified. Remove that "
            "file mount and use the lldpq-system-config directory/named volume "
            "at /home/lldpq/lldpq/system-config, then restart."
        )

    metadata = path.stat()
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, metadata.st_mode & 0o7777)
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
        temporary = None
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if path.read_text(encoding="utf-8") != content:
            raise SystemExit("LLDPq configuration readback mismatch")
    except Exception:
        raise
finally:
    if temporary is not None:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    os.close(lock_descriptor)
PYTHON_SET_LLDPQ_CONF
}

_set_isc_dhcp_interfaces() {
    local interface="$1" direct_mount=false target
    target=$(readlink -f /etc/default/isc-dhcp-server 2>/dev/null || \
        echo /etc/default/isc-dhcp-server)
    if _is_direct_mount /etc/default/isc-dhcp-server; then
        direct_mount=true
    fi
    python3 - "$target" "$interface" "$direct_mount" <<'PYTHON_SET_ISC_DHCP_DEFAULT'
import os
import pathlib
import stat
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
interface = sys.argv[2]
direct_mount = sys.argv[3] == "true"
if not interface or any(character in interface for character in ('\x00', '\n', '\r', '"')):
    raise SystemExit("invalid DHCP interface value")
desired = f'INTERFACES="{interface}"\n'.encode("utf-8")
current = path.read_bytes()
if current == desired:
    raise SystemExit(0)
if direct_mount:
    raise SystemExit(
        "ERROR: /etc/default/isc-dhcp-server is a legacy single-file Docker "
        "mount and requires a change. The live file was not modified. Remove "
        "that file mount and use the lldpq-system-config directory/named volume "
        "at /home/lldpq/lldpq/system-config, then restart."
    )

metadata = path.stat()
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("ISC DHCP defaults target is not a regular file")
descriptor, temporary = tempfile.mkstemp(
    prefix=f".{path.name}.", dir=path.parent
)
try:
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(desired)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
    os.chown(temporary, metadata.st_uid, metadata.st_gid)
    os.replace(temporary, path)
    temporary = None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_descriptor = os.open(path.parent, directory_flags)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    if path.read_bytes() != desired:
        raise SystemExit("ISC DHCP defaults readback mismatch")
finally:
    if temporary is not None:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PYTHON_SET_ISC_DHCP_DEFAULT
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
chown lldpq:www-data /etc/lldpq.conf
chmod 660 /etc/lldpq.conf
_prepare_shared_lock_files /etc/lldpq.conf.lock /etc/lldpq-users.conf.lock

# Resolve any killed legacy direct-file editor transaction before config
# seeding, devices parsing, upgrade reconciliation, or cron startup.  The
# helper owns a fixed target allowlist and takes global -> inventory -> file
# locks; an unknown/corrupt retained authority stops startup.
_prepare_shared_lock_files /var/www/html/.inventory.lock
if [ -L "$SETUP_SAFETY_HELPER" ] || [ ! -f "$SETUP_SAFETY_HELPER" ] || \
   [ "$(stat -c '%u:%g:%a' -- "$SETUP_SAFETY_HELPER" 2>/dev/null || true)" != "0:0:755" ]; then
    echo "ERROR: root-owned setup recovery helper is missing or unsafe; rebuild the image" >&2
    exit 1
fi
if ! CONFIG_WRITE_RECOVERY=$(sudo -n -H -u lldpq /usr/bin/python3 \
    "$SETUP_SAFETY_HELPER" recover-all \
    --lldpq-dir /home/lldpq/lldpq \
    --web-root /var/www/html \
    --inventory-lock /var/www/html/.inventory.lock \
    --direct-write-state-dir "$CONFIG_WRITE_JOURNAL_DIR" 2>&1); then
    echo "ERROR: retained config-write journal could not be recovered; startup stopped" >&2
    echo "$CONFIG_WRITE_RECOVERY" >&2
    exit 1
fi
echo "✓ Persistent config-write recovery checked"

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
    _setup_config_file tracking.yaml        /home/lldpq/lldpq/tracking.yaml     lldpq:www-data    664
    _setup_config_file topology.dot         /var/www/html/topology.dot          lldpq:www-data    664
    _setup_config_file topology_config.yaml /var/www/html/topology_config.yaml  lldpq:www-data    664
    _setup_config_file lldpq-users.conf     /etc/lldpq-users.conf               www-data:www-data 600
    _setup_config_file notifications.yaml   /home/lldpq/lldpq/notifications.yaml lldpq:www-data   664
    _setup_config_file inventory.json       /var/www/html/inventory.json        lldpq:www-data    664
    _setup_config_file cumulus-ztp.sh       /var/www/html/cumulus-ztp.sh        lldpq:www-data    775
    _setup_config_file serial-mapping.txt   /var/www/html/serial-mapping.txt    lldpq:www-data    664
    _setup_config_file display-aliases.json /var/www/html/display-aliases.json  lldpq:www-data    664
    # Scripts read topology files from the lldpq dir → keep those symlinks valid
    ln -sf /var/www/html/topology.dot /home/lldpq/lldpq/topology.dot 2>/dev/null || true
    ln -sf /var/www/html/topology_config.yaml /home/lldpq/lldpq/topology_config.yaml 2>/dev/null || true
    echo "✓ Persistent application configuration directory active: $CONFIG_DIR"
fi

# Normalize the baked-in, legacy-bind, and single-config-volume layouts alike.
# chown/chmod follow the managed symlink when CONFIG_DIR is mounted.
chown lldpq:www-data /var/www/html/display-aliases.json 2>/dev/null || true
chmod 664 /var/www/html/display-aliases.json 2>/dev/null || true

# monitor-results is a persistent volume in both Compose modes. If a container
# is recreated before the next collection, restore the last fully published
# Assets input so direct analyzer/AI consumers retain the same last-known-good
# inventory as the authenticated Assets API.
PIPELINE_ASSETS_SNAPSHOT=/home/lldpq/lldpq/monitor-results/.pipeline-inputs/assets.ini
if [ ! -s /home/lldpq/lldpq/assets.ini ] && [ -s "$PIPELINE_ASSETS_SNAPSHOT" ]; then
    cp -p "$PIPELINE_ASSETS_SNAPSHOT" /home/lldpq/lldpq/assets.ini
    chown lldpq:www-data /home/lldpq/lldpq/assets.ini
    chmod 664 /home/lldpq/lldpq/assets.ini
    echo "✓ Restored last-known-good Assets snapshot from persistent monitor data"
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

# ─── Switch lifecycle tracking ───
if [ ! -f /home/lldpq/lldpq/tracking.yaml ]; then
    printf 'version: 1\ndefault_state: commissioning\nswitches: {}\n' \
        > /home/lldpq/lldpq/tracking.yaml
fi
chown lldpq:www-data /home/lldpq/lldpq/tracking.yaml
chmod 664 /home/lldpq/lldpq/tracking.yaml

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
# The discovery cache is operational Provision state rather than image content.
# Keep it in its own named volume while retaining a legacy direct bind mount.

# Persist the operator's DHCP service preference across container recreation.
# DHCP_AUTOSTART is only a first-run seed: afterwards the Provision API writes
# exactly "running\n" or "stopped\n" to this shared state file.
DHCP_DESIRED_STATE_FILE="$PROVISION_STATE_DIR/dhcp-desired-state"

_write_dhcp_desired_state() {
    local state="$1" temporary
    case "$state" in
        running|stopped) ;;
        *) return 1 ;;
    esac
    temporary=$(mktemp "$PROVISION_STATE_DIR/.dhcp-desired-state.XXXXXXXX")
    printf '%s\n' "$state" > "$temporary"
    chown lldpq:www-data "$temporary" 2>/dev/null || true
    chmod 660 "$temporary"
    mv -f "$temporary" "$DHCP_DESIRED_STATE_FILE"
}

if [ ! -e "$DHCP_DESIRED_STATE_FILE" ]; then
    case "${DHCP_AUTOSTART:-false}" in
        true) _write_dhcp_desired_state running ;;
        false|'') _write_dhcp_desired_state stopped ;;
        *)
            echo "⚠ Invalid DHCP_AUTOSTART value '${DHCP_AUTOSTART}'; defaulting to stopped" >&2
            _write_dhcp_desired_state stopped
            ;;
    esac
fi
DHCP_DESIRED_STATE=$(cat "$DHCP_DESIRED_STATE_FILE" 2>/dev/null || true)
case "$DHCP_DESIRED_STATE" in
    running|stopped) ;;
    *)
        echo "⚠ Invalid persistent DHCP desired state; resetting safely to stopped" >&2
        DHCP_DESIRED_STATE=stopped
        _write_dhcp_desired_state stopped
        ;;
esac
chown lldpq:www-data "$DHCP_DESIRED_STATE_FILE" 2>/dev/null || true
chmod 660 "$DHCP_DESIRED_STATE_FILE" 2>/dev/null || true
export LLDPQ_DHCP_DESIRED_STATE_FILE="$DHCP_DESIRED_STATE_FILE"

_persist_provision_state_file() {
    local name="$1" app_path="$2" default_content="$3"
    local persistent="$PROVISION_STATE_DIR/$name" resolved=""

    if _is_direct_mount "$app_path"; then
        echo "  ✓ Legacy direct mount retained: $app_path"
        return 0
    fi
    if [ ! -e "$persistent" ]; then
        if [ -e "$app_path" ] || [ -L "$app_path" ]; then
            resolved=$(readlink -f "$app_path" 2>/dev/null || true)
            if [ -n "$resolved" ] && [ -f "$resolved" ]; then
                cp -a "$resolved" "$persistent"
            else
                printf '%s\n' "$default_content" > "$persistent"
            fi
        else
            printf '%s\n' "$default_content" > "$persistent"
        fi
    fi
    rm -f "$app_path"
    ln -s "$persistent" "$app_path"
    chown lldpq:www-data "$persistent" 2>/dev/null || true
    chmod 664 "$persistent" 2>/dev/null || true
}

_persist_provision_state_file discovery-cache.json /var/www/html/discovery-cache.json '{}'

for f in /var/www/html/device-cache.json /var/www/html/fabric-scan-cache.json /var/www/html/discovery-cache.json /var/www/html/inventory.json; do
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
mkdir -p /var/lib/lldpq/ai
mkdir -p /var/lib/lldpq/provision-jobs
mkdir -p /var/lib/lldpq/lldp-jobs
mkdir -p /var/lib/lldpq/assets-jobs
# Keep the persistent Provision state out of the broad runtime-state chown.
# In particular, config-write recovery journals must retain their lldpq owner
# across container recreation.  Do not recursively rewrite unrelated files in
# the shared Provision volume.
chown www-data:www-data /var/lib/lldpq
for runtime_state in /var/lib/lldpq/*; do
    [ "$runtime_state" = "$PROVISION_STATE_DIR" ] && continue
    chown -R www-data:www-data "$runtime_state"
done
chown lldpq:www-data /var/lib/lldpq/upgrade-jobs
chown lldpq:www-data /var/lib/lldpq/ai
chown lldpq:www-data /var/lib/lldpq/provision-jobs
chown lldpq:www-data /var/lib/lldpq/lldp-jobs
chown lldpq:www-data /var/lib/lldpq/assets-jobs
chmod 700 /var/lib/lldpq/sessions
chmod 775 /var/lib/lldpq/upgrade-jobs
chmod 2770 /var/lib/lldpq/ai
chmod 2770 /var/lib/lldpq/provision-jobs
chmod 2770 /var/lib/lldpq/lldp-jobs
chmod 2770 /var/lib/lldpq/assets-jobs

_prepare_shared_lock_files /var/lib/lldpq/ssh-key.lock

# A Docker image update replaces application code before the persistent
# upgrade-jobs volume is mounted. Reconcile only expired pre-schema records
# here, using the same root-owned implementation as native install.sh. Current
# schema-v2 jobs remain untouched and are resumed by the scheduler below. Run
# this unconditionally: a .json symlink/FIFO/directory is itself unsafe state
# and must not bypass validation merely because `find -type f` ignores it.
if [ -L "$INSTALL_LIBRARY" ] || [ ! -f "$INSTALL_LIBRARY" ] || \
   [ "$(stat -c '%u:%g:%a' -- "$INSTALL_LIBRARY" 2>/dev/null || true)" != "0:0:755" ]; then
    echo "ERROR: root-owned LLDPq install library is missing or unsafe; rebuild the image" >&2
    exit 1
fi
echo "  Checking persistent Provision upgrade state..."
RECONCILE_DEVICES_FILE=/home/lldpq/lldpq/devices.yaml
RECONCILE_INVENTORY_FILE=/var/www/html/inventory.json
for reconcile_name in devices inventory; do
    if [ "$reconcile_name" = devices ]; then
        reconcile_path="$RECONCILE_DEVICES_FILE"
    else
        reconcile_path="$RECONCILE_INVENTORY_FILE"
    fi
    if [ -L "$reconcile_path" ]; then
        reconcile_resolved="$(readlink -f -- "$reconcile_path" 2>/dev/null || true)"
        case "$reconcile_resolved" in
            "$CONFIG_DIR"/*) ;;
            *)
                echo "ERROR: managed Provision input points outside $CONFIG_DIR: $reconcile_path" >&2
                exit 1
                ;;
        esac
        if [ ! -f "$reconcile_resolved" ] || [ -L "$reconcile_resolved" ]; then
            echo "ERROR: managed Provision input is not a regular file: $reconcile_path" >&2
            exit 1
        fi
        if [ "$reconcile_name" = devices ]; then
            RECONCILE_DEVICES_FILE="$reconcile_resolved"
        else
            RECONCILE_INVENTORY_FILE="$reconcile_resolved"
        fi
    fi
done
if ! (
    export LLDPQ_INSTALL_LIB_ONLY=true
    export LLDPQ_TEST_NO_SUDO=true
    export LLDPQ_RECONCILE_ALLOW_CURRENT_INCOMPLETE=true
    export LLDPQ_INSTALL_DIR=/home/lldpq/lldpq
    export LLDPQ_DIR=/home/lldpq/lldpq
    export LLDPQ_USER=lldpq
    export WEB_ROOT=/var/www/html
    export LLDPQ_RECONCILE_DEVICES_FILE="$RECONCILE_DEVICES_FILE"
    export LLDPQ_RECONCILE_INVENTORY_FILE="$RECONCILE_INVENTORY_FILE"
    # shellcheck disable=SC1090
    source "$INSTALL_LIBRARY"
    reconcile_stale_legacy_upgrade_jobs /var/lib/lldpq/upgrade-jobs || exit 1
    verify_upgrade_jobs_runtime_compatible /var/lib/lldpq/upgrade-jobs || exit 1
); then
    echo "ERROR: persistent Provision upgrade state is not compatible with this image" >&2
    echo "       Originals were retained; inspect the reported job before restarting." >&2
    exit 1
fi
echo "✓ Persistent Provision upgrade state verified"

# Migrate legacy Ask-AI state out of the nginx document root. Move only when
# the private destination does not already exist, then remove the public copy.
for ai_state_mapping in \
    "ai-analysis.json:analysis.json" \
    "ai-learnings.json:learnings.json" \
    "ai-analysis-snapshot.json:analysis-snapshot.json"; do
    legacy_ai_state="/var/www/html/${ai_state_mapping%%:*}"
    private_ai_state="/var/lib/lldpq/ai/${ai_state_mapping#*:}"
    if [ -f "$legacy_ai_state" ] && {
        [ ! -s "$private_ai_state" ] ||
        grep -Eq '^[[:space:]]*(\{\}|\[\])[[:space:]]*$' "$private_ai_state" 2>/dev/null
    }; then
        mv -f "$legacy_ai_state" "$private_ai_state"
    elif [ -f "$legacy_ai_state" ]; then
        rm -f "$legacy_ai_state"
    fi
done
[ -f /var/lib/lldpq/ai/analysis.json ] || printf '{}\n' > /var/lib/lldpq/ai/analysis.json
[ -f /var/lib/lldpq/ai/learnings.json ] || printf '[]\n' > /var/lib/lldpq/ai/learnings.json
[ -f /var/lib/lldpq/ai/analysis-snapshot.json ] || printf '{}\n' > /var/lib/lldpq/ai/analysis-snapshot.json
chown lldpq:www-data /var/lib/lldpq/ai/*.json
chmod 660 /var/lib/lldpq/ai/*.json
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
* * * * * www-data /usr/local/bin/lldpq-provision-scheduler > /dev/null 2>&1
# Fabric scan (topology data for search) - every minute
* * * * * lldpq cd /home/lldpq/lldpq && ./fabric-scan.sh > /dev/null 2>&1
# Config backup
$GETCONF_CRON lldpq /usr/local/bin/get-conf > /dev/null 2>&1
# Autonomous Ask-AI health analysis (minute 7: offset from the */10 full run
# so analyze never reads collection files mid-write; matches install.sh)
7 * * * * lldpq /usr/local/bin/lldpq-ai-analyze > /dev/null 2>&1
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

# Default display/post-provision settings in lldpq.conf (if not present)
for key_val in "LLDPQ_HOSTNAME=lldpq" "AUTO_BASE_CONFIG=true" \
               "AUTO_ZTP_DISABLE=true" "AUTO_SET_HOSTNAME=true"; do
    key="${key_val%%=*}"
    _set_lldpq_conf_value "$key" "${key_val#*=}" true
done

_docker_dhcp_is_managed() {
    grep -Eq '^# /etc/dhcp/dhcpd\.conf - Generated by LLDPq( Provision)?$' \
        /etc/dhcp/dhcpd.conf 2>/dev/null
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

    # A single-file bind mount cannot be replaced atomically.  If the exact
    # generated bytes are already installed this is a no-op; otherwise fail
    # before a backup, chmod, truncate, or any other live-target mutation.
    if _is_direct_mount /etc/dhcp/dhcpd.conf; then
        if cmp -s "$temp_file" /etc/dhcp/dhcpd.conf; then
            rm -f "$temp_file"
            return 0
        fi
        echo "ERROR: /etc/dhcp/dhcpd.conf is a legacy single-file Docker mount and needs an update." >&2
        echo "       The live file was not modified. Remove that file mount and use the" >&2
        echo "       lldpq-system-config directory/named volume at" >&2
        echo "       /home/lldpq/lldpq/system-config, then restart." >&2
        rm -f "$temp_file"
        return 1
    fi

    target_file=$(readlink -f /etc/dhcp/dhcpd.conf 2>/dev/null || echo /etc/dhcp/dhcpd.conf)
    if [ "$backup_existing" = "true" ] && [ -s /etc/dhcp/dhcpd.conf ]; then
        backup_file="$(dirname "$target_file")/dhcpd.conf.pre-lldpq-$(date +%Y%m%d-%H%M%S)-$$.bak"
        cp -p /etc/dhcp/dhcpd.conf "$backup_file" || {
            echo "ERROR: existing Docker DHCP config could not be backed up" >&2
            rm -f "$temp_file"
            return 1
        }
        echo "  Existing DHCP config backed up to: $backup_file"
    fi

    mkdir -p "$(dirname "$target_file")"
    staged_file=$(mktemp "$(dirname "$target_file")/.dhcpd.conf.new.XXXXXXXX")
    cp "$temp_file" "$staged_file"
    chown lldpq:www-data "$staged_file"
    chmod 664 "$staged_file"
    sync -f "$staged_file"
    mv -f "$staged_file" "$target_file"
    sync -f "$(dirname "$target_file")"
    chown lldpq:www-data /etc/dhcp/dhcpd.conf 2>/dev/null || true
    chmod 664 /etc/dhcp/dhcpd.conf
    rm -f "$temp_file"
}

_migrate_managed_dhcp_server_references() {
    local server_ip="$1" config=/etc/dhcp/dhcpd.conf hosts=/etc/dhcp/dhcpd.hosts
    local target hosts_target directory hosts_directory candidate hosts_candidate
    local validation_candidate config_changed=false hosts_changed=false
    local backup="" hosts_backup="" rollback_stage="" hosts_rollback_stage=""
    local timestamp activation_failed=false rollback_failed=false

    target=$(readlink -f "$config" 2>/dev/null || true)
    hosts_target=$(readlink -f "$hosts" 2>/dev/null || true)
    [ -n "$target" ] && [ -f "$target" ] && \
    [ -n "$hosts_target" ] && [ -f "$hosts_target" ] || {
        echo "ERROR: managed DHCP configuration/hosts target is unavailable" >&2
        return 1
    }
    directory=$(dirname "$target")
    hosts_directory=$(dirname "$hosts_target")
    candidate=$(mktemp "$directory/.dhcpd.conf.server-migration.XXXXXXXX") || {
        echo "ERROR: managed DHCP migration could not stage dhcpd.conf" >&2
        return 1
    }
    hosts_candidate=$(mktemp "$hosts_directory/.dhcpd.hosts.server-migration.XXXXXXXX") || {
        rm -f "$candidate"
        echo "ERROR: managed DHCP migration could not stage dhcpd.hosts" >&2
        return 1
    }
    if ! python3 - "$target" "$candidate" "$hosts_target" \
        "$hosts_candidate" "$server_ip" <<'PYTHON'
import ipaddress
import pathlib
import re
import sys
from urllib.parse import urlsplit, urlunsplit

config_source = pathlib.Path(sys.argv[1])
config_destination = pathlib.Path(sys.argv[2])
hosts_source = pathlib.Path(sys.argv[3])
hosts_destination = pathlib.Path(sys.argv[4])
server_ip = str(ipaddress.IPv4Address(sys.argv[5]))
directive = re.compile(
    r'(?P<prefix>(?<![A-Za-z0-9_-])option\s+'
    r'(?P<name>www-server|default-url|cumulus-provision-url)\s+)'
    r'(?P<value>"[^"\r\n]*"|[^\s;]+)(?P<suffix>\s*;)',
    re.IGNORECASE,
)

def without_comments(text):
    """Mask ISC # comments without changing offsets or quoted fragments."""
    output = list(text)
    quoted = [False] * len(text)
    quote = None
    escaped = False
    in_comment = False
    for index, character in enumerate(text):
        if in_comment:
            if character in '\r\n':
                in_comment = False
            else:
                output[index] = ' '
            continue
        if quote is not None:
            quoted[index] = True
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            quoted[index] = True
        elif character == '#':
            output[index] = ' '
            in_comment = True
    return ''.join(output), quoted

def rewrite(source, destination, require_all):
    counts = {"www-server": 0, "default-url": 0, "cumulus-provision-url": 0}
    text = source.read_text(encoding="utf-8")
    searchable, quoted = without_comments(text)
    output = []
    cursor = 0

    for match in directive.finditer(searchable):
        if quoted[match.start()]:
            continue
        name = match.group("name").lower()
        counts[name] += 1
        value_start, value_end = match.span("value")
        value = text[value_start:value_end].strip()
        if name == "www-server":
            ipaddress.IPv4Address(value)
            replacement = server_ip
        else:
            if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
                raise SystemExit(f"unexpected {name} URL syntax")
            quote = value[0]
            parsed = urlsplit(value[1:-1])
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise SystemExit(f"invalid {name} URL")
            try:
                port = parsed.port
            except ValueError as exc:
                raise SystemExit(f"invalid {name} URL port: {exc}")
            try:
                literal_host = str(ipaddress.IPv4Address(parsed.hostname))
            except ipaddress.AddressValueError:
                # Preserve operator DNS URLs exactly. The runtime guard checks
                # that their A record still targets the selected server IP.
                replacement = value
            else:
                if literal_host == server_ip:
                    replacement = value
                else:
                    netloc = server_ip + ((":" + str(port)) if port is not None else "")
                    replacement = quote + urlunsplit((
                        parsed.scheme, netloc, parsed.path,
                        parsed.query, parsed.fragment,
                    )) + quote
        output.append(text[cursor:value_start])
        output.append(replacement)
        cursor = value_end
    output.append(text[cursor:])
    if require_all:
        invalid = [name for name, count in counts.items() if count < 1]
        if invalid:
            raise SystemExit(
                "managed DHCP option missing: "
                + ", ".join(f"{name}={counts[name]}" for name in invalid)
            )
    destination.write_text("".join(output), encoding="utf-8")

rewrite(config_source, config_destination, True)
rewrite(hosts_source, hosts_destination, False)
PYTHON
    then
        rm -f "$candidate" "$hosts_candidate"
        echo "ERROR: managed DHCP server-reference migration could not be rendered" >&2
        return 1
    fi

    cmp -s "$candidate" "$target" || config_changed=true
    cmp -s "$hosts_candidate" "$hosts_target" || hosts_changed=true
    if [[ "$config_changed" == "false" && "$hosts_changed" == "false" ]]; then
        rm -f "$candidate" "$hosts_candidate"
        return 0
    fi
    if { [[ "$config_changed" == "true" ]] && _is_direct_mount "$config"; } || \
       { [[ "$hosts_changed" == "true" ]] && _is_direct_mount "$hosts"; }; then
        rm -f "$candidate" "$hosts_candidate"
        echo "ERROR: managed DHCP config/hosts direct bind mount cannot be migrated atomically." >&2
        echo "       Save a validated config from Provision before starting DHCP." >&2
        return 1
    fi

    # Validate the two candidates together by redirecting the managed include
    # in a disposable config. This catches cross-file syntax errors before any
    # live path is replaced.
    validation_candidate=$(mktemp /tmp/lldpq-dhcp-validation.XXXXXXXX) || {
        rm -f "$candidate" "$hosts_candidate"
        return 1
    }
    if ! python3 - "$candidate" "$validation_candidate" "$hosts_target" \
        "$hosts_candidate" <<'PYTHON'
import os
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
live_hosts = os.path.realpath(sys.argv[3])
staged_hosts = sys.argv[4]
pattern = re.compile(r'(^\s*include\s+")([^"]+)("\s*;)', re.MULTILINE)
count = 0

def replace(match):
    global count
    if os.path.realpath(match.group(2)) != live_hosts:
        return match.group(0)
    count += 1
    return match.group(1) + staged_hosts + match.group(3)

rendered = pattern.sub(replace, source.read_text(encoding="utf-8"))
if count != 1:
    raise SystemExit(f"managed hosts include count invalid: {count}")
destination.write_text(rendered, encoding="utf-8")
PYTHON
    then
        rm -f "$candidate" "$hosts_candidate" "$validation_candidate"
        echo "ERROR: managed DHCP validation candidate could not be rendered" >&2
        return 1
    fi
    if ! dhcpd -t -cf "$validation_candidate" >/dev/null 2>&1; then
        rm -f "$candidate" "$hosts_candidate" "$validation_candidate"
        echo "ERROR: migrated DHCP config/hosts failed dhcpd -t; originals retained" >&2
        return 1
    fi
    rm -f "$validation_candidate"

    timestamp=$(date +%Y%m%d-%H%M%S)
    if [[ "$config_changed" == "true" ]]; then
        backup="$directory/dhcpd.conf.pre-server-migration-${timestamp}-$$.bak"
        cp -p "$target" "$backup" || activation_failed=true
        chown --reference="$target" "$candidate" 2>/dev/null || true
        chmod --reference="$target" "$candidate" 2>/dev/null || true
    fi
    if [[ "$hosts_changed" == "true" ]]; then
        hosts_backup="$hosts_directory/dhcpd.hosts.pre-server-migration-${timestamp}-$$.bak"
        cp -p "$hosts_target" "$hosts_backup" || activation_failed=true
        chown --reference="$hosts_target" "$hosts_candidate" 2>/dev/null || true
        chmod --reference="$hosts_target" "$hosts_candidate" 2>/dev/null || true
    fi
    if [[ "$activation_failed" == "true" ]]; then
        rm -f "$candidate" "$hosts_candidate"
        echo "ERROR: managed DHCP config/hosts backup failed; originals retained" >&2
        return 1
    fi

    if [[ "$hosts_changed" == "true" ]] && ! mv -f "$hosts_candidate" "$hosts_target"; then
        activation_failed=true
    fi
    if [[ "$config_changed" == "true" ]] && \
       { [[ "$activation_failed" == "true" ]] || ! mv -f "$candidate" "$target"; }; then
        activation_failed=true
    fi
    rm -f "$candidate" "$hosts_candidate"

    if [[ "$activation_failed" == "true" ]] || \
        ! dhcpd -t -cf "$config" >/dev/null 2>&1; then
        if [[ "$config_changed" == "true" ]]; then
            if ! rollback_stage=$(mktemp "$directory/.dhcpd.conf.rollback.XXXXXXXX") || \
               ! cp -p "$backup" "$rollback_stage" || \
               ! mv -f "$rollback_stage" "$target"; then
                rollback_failed=true
            fi
        fi
        if [[ "$hosts_changed" == "true" ]]; then
            if ! hosts_rollback_stage=$(mktemp "$hosts_directory/.dhcpd.hosts.rollback.XXXXXXXX") || \
               ! cp -p "$hosts_backup" "$hosts_rollback_stage" || \
               ! mv -f "$hosts_rollback_stage" "$hosts_target"; then
                rollback_failed=true
            fi
        fi
        rm -f "$rollback_stage" "$hosts_rollback_stage"
        if [[ "$rollback_failed" == "true" ]]; then
            echo "ERROR: DHCP config/hosts migration failed and rollback was incomplete." >&2
            echo "       Retained backups: $backup $hosts_backup" >&2
        else
            echo "ERROR: DHCP config/hosts migration failed; retained backups restored" >&2
        fi
        return 1
    fi

    echo "✓ Managed DHCP server references migrated to $server_ip"
    [[ -z "$backup" ]] || echo "  Previous DHCP config backed up to: $backup"
    [[ -z "$hosts_backup" ]] || echo "  Previous DHCP hosts backed up to: $hosts_backup"
}

# Docker bridge networking cannot deliver DHCP broadcasts to a physical L2.
# Keep the default monitoring compose safe and require the Linux host-network
# provisioning compose to opt in with an explicit interface and server IP.
LLDPQ_DHCP_MODE="${LLDPQ_DHCP_MODE:-disabled}"
DHCP_RUNTIME_DIR=/run/lldpq
DHCP_RUNTIME_STATE="$DHCP_RUNTIME_DIR/docker-dhcp-runtime.env"
mkdir -p "$DHCP_RUNTIME_DIR"
chown root:root "$DHCP_RUNTIME_DIR"
chmod 755 "$DHCP_RUNTIME_DIR"

_valid_ipv4() {
    python3 - "$1" <<'PYTHON'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.version == 4 and not address.is_unspecified else 1)
PYTHON
}

_write_dhcp_runtime_state() {
    local enabled="$1" mode="$2" interface="${3:-}" server_ip="${4:-}"
    local temporary
    temporary=$(mktemp "$DHCP_RUNTIME_DIR/.docker-dhcp-runtime.XXXXXXXX")
    {
        printf 'DHCP_RUNTIME_ENABLED=%s\n' "$enabled"
        printf 'DHCP_RUNTIME_MODE=%s\n' "$mode"
        printf 'DHCP_RUNTIME_INTERFACE=%s\n' "$interface"
        printf 'DHCP_RUNTIME_SERVER_IP=%s\n' "$server_ip"
    } > "$temporary"
    chown root:root "$temporary"
    chmod 644 "$temporary"
    mv -f "$temporary" "$DHCP_RUNTIME_STATE"
}

_configure_dhcp_runtime() {
    local interface="${DHCP_INTERFACE:-}" server_ip="${PROVISION_SERVER_IP:-}"

    case "$LLDPQ_DHCP_MODE" in
        disabled)
            _write_dhcp_runtime_state false disabled
            DHCP_AUTOSTART=false
            export DHCP_AUTOSTART
            echo "  DHCP: disabled in Docker bridge/monitoring mode"
            echo "        Use docker-compose.provisioning.yml on a Linux host for DHCP/ONIE."
            ;;
        host)
            if [ "$(uname -s)" != "Linux" ]; then
                echo "ERROR: Docker DHCP host mode is supported only on Linux" >&2
                return 1
            fi
            if [ -z "$interface" ] || [ -z "$server_ip" ]; then
                echo "ERROR: DHCP_INTERFACE and PROVISION_SERVER_IP are required in Docker DHCP host mode" >&2
                return 1
            fi
            case "$interface" in
                *[!A-Za-z0-9_.:@-]*|lo)
                    echo "ERROR: invalid or unsafe DHCP_INTERFACE: $interface" >&2
                    return 1
                    ;;
            esac
            if ! _valid_ipv4 "$server_ip"; then
                echo "ERROR: invalid PROVISION_SERVER_IP: $server_ip" >&2
                return 1
            fi
            if ! ip link show dev "$interface" >/dev/null 2>&1; then
                echo "ERROR: DHCP_INTERFACE does not exist in the host network namespace: $interface" >&2
                return 1
            fi
            if ! ip -o -4 addr show dev "$interface" 2>/dev/null | \
                    awk '{sub(/\/.*/, "", $4); print $4}' | grep -Fqx -- "$server_ip"; then
                echo "ERROR: PROVISION_SERVER_IP $server_ip is not assigned to $interface" >&2
                return 1
            fi
            if [ "$DHCP_DESIRED_STATE" = "running" ]; then
                DHCP_AUTOSTART=true
            else
                DHCP_AUTOSTART=false
            fi
            export DHCP_AUTOSTART
            _write_dhcp_runtime_state true host "$interface" "$server_ip"
            _set_isc_dhcp_interfaces "$interface"
            echo "✓ Docker DHCP host mode: $server_ip on $interface"
            ;;
        *)
            echo "ERROR: LLDPQ_DHCP_MODE must be 'disabled' or 'host'" >&2
            return 1
            ;;
    esac
}

# Guard every real dhcpd start, including requests coming from Provision UI.
# Syntax-only `dhcpd -t` remains available in monitoring mode. This prevents a
# bridge container from reporting a locally-running but externally-useless DHCP
# process as success. The expected interface/IP state is root-owned under /run.
_install_dhcp_runtime_guard() {
    local system_dhcpd=/usr/sbin/dhcpd
    # The relocated binary must keep the basename 'dhcpd': the kernel derives
    # the process comm from the exec'd path, and pgrep/pkill -x dhcpd (used by
    # provision-api.sh and the autostart check below) match on comm.
    local real_dhcpd=/usr/libexec/lldpq-dhcpd/dhcpd

    mkdir -p /usr/libexec/lldpq-dhcpd
    if [ ! -x "$real_dhcpd" ]; then
        if [ ! -x "$system_dhcpd" ]; then
            echo "ERROR: isc-dhcp-server binary is missing" >&2
            return 1
        fi
        cp -p "$system_dhcpd" "$real_dhcpd"
        chown root:root "$real_dhcpd"
        chmod 755 "$real_dhcpd"
    fi
    rm -f "$system_dhcpd"
    cat > "$system_dhcpd" <<'GUARD'
#!/bin/bash
# LLDPq Docker DHCP runtime guard. Generated by docker-entrypoint.sh.
set -u

REAL_DHCPD=/usr/libexec/lldpq-dhcpd/dhcpd
RUNTIME_STATE=/run/lldpq/docker-dhcp-runtime.env

for argument in "$@"; do
    case "$argument" in
        -t|--version)
            exec -a dhcpd "$REAL_DHCPD" "$@"
            ;;
    esac
done

DHCP_RUNTIME_ENABLED=false
DHCP_RUNTIME_MODE=disabled
DHCP_RUNTIME_INTERFACE=
DHCP_RUNTIME_SERVER_IP=
if [ -r "$RUNTIME_STATE" ]; then
    # The file and its parent are root-owned and are not writable by CGI users.
    # shellcheck disable=SC1090
    . "$RUNTIME_STATE"
fi
if [ "$DHCP_RUNTIME_ENABLED" != "true" ] || [ "$DHCP_RUNTIME_MODE" != "host" ]; then
    echo "LLDPq: DHCP is disabled in Docker bridge/monitoring mode." >&2
    echo "Use docker-compose.provisioning.yml with DHCP_INTERFACE and PROVISION_SERVER_IP." >&2
    exit 78
fi

last_argument="${!#:-}"
if [ -z "$DHCP_RUNTIME_INTERFACE" ] || [ "$last_argument" != "$DHCP_RUNTIME_INTERFACE" ]; then
    echo "LLDPq: refusing DHCP start on '$last_argument'; expected '$DHCP_RUNTIME_INTERFACE'." >&2
    exit 78
fi
if ! ip -o -4 addr show dev "$DHCP_RUNTIME_INTERFACE" 2>/dev/null | \
        awk '{sub(/\/.*/, "", $4); print $4}' | grep -Fqx -- "$DHCP_RUNTIME_SERVER_IP"; then
    echo "LLDPq: provisioning IP $DHCP_RUNTIME_SERVER_IP is no longer assigned to $DHCP_RUNTIME_INTERFACE." >&2
    exit 78
fi

config=/etc/dhcp/dhcpd.conf
previous=
for argument in "$@"; do
    if [ "$previous" = "-cf" ]; then
        config="$argument"
        break
    fi
    previous="$argument"
done
if ! "$REAL_DHCPD" -t -cf "$config" >/dev/null 2>&1; then
    echo "LLDPq: refusing to start with an invalid DHCP configuration: $config" >&2
    exit 78
fi
# Both files may contain global, subnet, group or per-host overrides. Validate
# every active directive across free-form/multiline ISC syntax.
if ! python3 - "$config" /etc/dhcp/dhcpd.hosts \
    "$DHCP_RUNTIME_SERVER_IP" <<'PYTHON'
import ipaddress
import pathlib
import re
import socket
import sys
from urllib.parse import urlsplit

paths = [pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])]
expected = str(ipaddress.IPv4Address(sys.argv[3]))
directive = re.compile(
    r'(?<![A-Za-z0-9_-])option\s+'
    r'(www-server|default-url|cumulus-provision-url)\s+'
    r'("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s;]+)\s*;',
    re.IGNORECASE,
)

def without_comments(text):
    output = list(text)
    quoted = [False] * len(text)
    quote = None
    escaped = False
    in_comment = False
    for index, character in enumerate(text):
        if in_comment:
            if character in '\r\n':
                in_comment = False
            else:
                output[index] = ' '
            continue
        if quote is not None:
            quoted[index] = True
            if escaped:
                escaped = False
            elif character == '\\':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in "\"'":
            quote = character
            quoted[index] = True
        elif character == '#':
            output[index] = ' '
            in_comment = True
    return ''.join(output), quoted

def url_addresses(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('invalid URL')
    try:
        return {str(ipaddress.IPv4Address(parsed.hostname))}
    except ValueError:
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname, port, socket.AF_INET, socket.SOCK_STREAM,
            )
        }

try:
    main_counts = {
        'www-server': 0,
        'default-url': 0,
        'cumulus-provision-url': 0,
    }
    for path_index, path in enumerate(paths):
        text = path.read_text(encoding='utf-8')
        searchable, quoted = without_comments(text)
        for match in directive.finditer(searchable):
            if quoted[match.start()]:
                continue
            name = match.group(1).lower()
            if path_index == 0:
                main_counts[name] += 1
            value_start, value_end = match.span(2)
            value = text[value_start:value_end].strip()
            number = text.count('\n', 0, match.start()) + 1
            location = f'{path.name}:{number}'
            if name == 'www-server':
                if str(ipaddress.IPv4Address(value)) != expected:
                    raise ValueError(f'{location}: www-server is {value}')
            else:
                if len(value) < 2 or value[0] not in "\"'" or value[-1] != value[0]:
                    raise ValueError(f'{location}: malformed {name}')
                if expected not in url_addresses(value[1:-1]):
                    raise ValueError(f'{location}: {name} targets another server')
    missing = [name for name, count in main_counts.items() if count == 0]
    if missing:
        raise ValueError('main config is missing: ' + ', '.join(missing))
except (OSError, ValueError) as exc:
    print(f'LLDPq: invalid DHCP provisioning override: {exc}', file=sys.stderr)
    raise SystemExit(1)
PYTHON
then
    exit 78
fi

# exec -a keeps argv[0] as 'dhcpd'; comm comes from the exec'd path basename.
exec -a dhcpd "$REAL_DHCPD" "$@"
GUARD
    chown root:root "$system_dhcpd"
    chmod 755 "$system_dhcpd"
}

_configure_dhcp_runtime
_install_dhcp_runtime_guard

if _docker_dhcp_is_managed; then
    DHCP_MANAGED_REFERENCES_OK=true
    if [ "$LLDPQ_DHCP_MODE" = "host" ] && \
       ! _migrate_managed_dhcp_server_references "$PROVISION_SERVER_IP"; then
        DHCP_MANAGED_REFERENCES_OK=false
        DHCP_AUTOSTART=false
        echo "⚠ DHCP will stay stopped until its managed configuration is repaired" >&2
    fi
    if ! dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
        echo "⚠ Existing LLDPq-managed DHCP config is invalid; DHCP will stay disabled until it is repaired" >&2
        DHCP_AUTOSTART=false
    elif [ "$DHCP_MANAGED_REFERENCES_OK" = "true" ]; then
        echo "✓ Existing LLDPq DHCP config validated"
    else
        echo "⚠ DHCP syntax is valid, but its provisioning server references are not ready" >&2
    fi
elif _docker_dhcp_is_packaged_sample && [ "$LLDPQ_DHCP_MODE" = "host" ]; then
    DHCP_AUTOSTART=false
    echo "  DHCP: packaged sample retained; service will stay stopped"
    echo "        Save a validated network-specific config from Provision before starting DHCP."
elif _docker_dhcp_is_packaged_sample; then
    echo "  DHCP config: packaged sample retained (monitoring mode)"
elif [ "${LLDPQ_REPLACE_DHCP_CONFIG:-false}" = "true" ]; then
    if [ "$LLDPQ_DHCP_MODE" != "host" ]; then
        echo "ERROR: LLDPQ_REPLACE_DHCP_CONFIG requires Docker DHCP host mode" >&2
        exit 1
    fi
    _install_docker_dhcp_config "$PROVISION_SERVER_IP" true
    echo "✓ Foreign DHCP config explicitly replaced after validation + backup"
else
    echo "⚠ Existing non-LLDPq DHCP config preserved. Set LLDPQ_REPLACE_DHCP_CONFIG=true to replace it explicitly."
fi

# Write a legacy default only outside explicit provisioning mode. The runtime
# guard still blocks any actual bridge-mode start.
if [ "$LLDPQ_DHCP_MODE" != "host" ] && ! grep -q '^INTERFACES=' /etc/default/isc-dhcp-server 2>/dev/null; then
    _set_isc_dhcp_interfaces eth0
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

# DHCP server: start only when the persistent desired state is running and a
# network-specific config passed validation. DHCP_AUTOSTART seeds that state on
# the first container run; subsequent UI Start/Stop choices take precedence.
if [ "${DHCP_AUTOSTART:-false}" = "true" ] && [ -f /etc/dhcp/dhcpd.conf ]; then
    if ! dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1; then
        echo "  DHCP: not started because dhcpd.conf failed validation" >&2
        DHCP_AUTOSTART=false
    fi
fi
mkdir -p /var/log/lldpq
touch /var/log/lldpq/dhcpd.log
chown www-data:www-data /var/log/lldpq/dhcpd.log
chmod 664 /var/log/lldpq/dhcpd.log
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

# Start fcgiwrap (CGI scripts for web API). A Docker restart reuses the
# container writable layer, so the socket pathname can outlive the old process.
# Remove only that stale runtime artifact and do not report readiness until the
# replacement process is alive and has created a real Unix socket.
FCGIWRAP_SOCKET=/var/run/fcgiwrap.socket
rm -f -- "$FCGIWRAP_SOCKET"
/usr/sbin/fcgiwrap -f -s "unix:$FCGIWRAP_SOCKET" &
FCGIWRAP_PID=$!
FCGIWRAP_READY=false

for _ in {1..50}; do
    if ! kill -0 "$FCGIWRAP_PID" 2>/dev/null; then
        if wait "$FCGIWRAP_PID" 2>/dev/null; then
            FCGIWRAP_STATUS=0
        else
            FCGIWRAP_STATUS=$?
        fi
        rm -f -- "$FCGIWRAP_SOCKET"
        echo "ERROR: fcgiwrap exited during startup (status $FCGIWRAP_STATUS)" >&2
        exit 1
    fi
    if [ -S "$FCGIWRAP_SOCKET" ]; then
        FCGIWRAP_READY=true
        break
    fi
    sleep 0.1
done

if [ "$FCGIWRAP_READY" != true ] || ! kill -0 "$FCGIWRAP_PID" 2>/dev/null; then
    kill "$FCGIWRAP_PID" 2>/dev/null || true
    wait "$FCGIWRAP_PID" 2>/dev/null || true
    rm -f -- "$FCGIWRAP_SOCKET"
    echo "ERROR: fcgiwrap did not create a live socket within 5 seconds" >&2
    exit 1
fi

chown www-data:www-data "$FCGIWRAP_SOCKET"
chmod 660 "$FCGIWRAP_SOCKET"
if ! kill -0 "$FCGIWRAP_PID" 2>/dev/null; then
    wait "$FCGIWRAP_PID" 2>/dev/null || true
    rm -f -- "$FCGIWRAP_SOCKET"
    echo "ERROR: fcgiwrap exited before startup completed" >&2
    exit 1
fi
echo "  ✓ fcgiwrap"

# Start SSH server (port 2033)
/usr/sbin/sshd 2>/dev/null && echo "  ✓ sshd (port 2033)" || echo "  ⚠ sshd failed to start"

# Console bridge lifecycle helpers. The supervisor owns and reaps each bridge
# process, then restarts it if it exits while nginx keeps the container alive.
CONSOLE_LOG_FILE=/var/log/lldpq/console.log
CONSOLE_RESTART_DELAY=1
CONSOLE_READY_DELAY=0.2

_stop_console_bridge() {
    if [ -n "${console_bridge_pid:-}" ]; then
        kill "$console_bridge_pid" 2>/dev/null || true
        wait "$console_bridge_pid" 2>/dev/null || true
    fi
}

_supervise_console_bridge() {
    local console_bridge_pid console_status
    trap _stop_console_bridge EXIT
    trap 'exit 0' TERM INT

    while true; do
        runuser -u www-data -- python3 /home/lldpq/lldpq/console-pty.py \
            >> "$CONSOLE_LOG_FILE" 2>&1 &
        console_bridge_pid=$!
        if wait "$console_bridge_pid"; then
            console_status=0
        else
            console_status=$?
        fi
        console_bridge_pid=""
        echo "  ⚠ console-pty exited (status $console_status); restarting in ${CONSOLE_RESTART_DELAY}s" >&2
        sleep "$CONSOLE_RESTART_DELAY"
    done
}

_console_port_ready() {
    (exec 3<>/dev/tcp/127.0.0.1/8765) 2>/dev/null
}

_console_service_ready() {
    local response status body
    response=$(curl --silent --show-error --max-time 1 \
        --write-out $'\n%{http_code}' \
        'http://127.0.0.1:8765/' 2>/dev/null) || return 1
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    [ "$status" = "400" ] && [ "$body" = "invalid session id" ]
}

_wait_for_console_bridge() {
    local console_attempt
    for console_attempt in {1..50}; do
        if _console_service_ready; then
            return 0
        fi
        if ! kill -0 "$CONSOLE_SUPERVISOR_PID" 2>/dev/null; then
            return 1
        fi
        sleep "$CONSOLE_READY_DELAY"
    done
    return 1
}

# Start the supervised Console bridge (web SSH terminal, admin-gated) as
# www-data. Do not report the application ready until its TCP listener exists.
mkdir -p /var/log/lldpq 2>/dev/null && chown www-data:www-data /var/log/lldpq 2>/dev/null || true
if _console_port_ready; then
    echo "ERROR: console port 127.0.0.1:8765 is already owned by another process" >&2
    exit 1
fi
_supervise_console_bridge &
CONSOLE_SUPERVISOR_PID=$!
if ! _wait_for_console_bridge; then
    echo "ERROR: console-pty did not become ready on 127.0.0.1:8765" >&2
    kill "$CONSOLE_SUPERVISOR_PID" 2>/dev/null || true
    wait "$CONSOLE_SUPERVISOR_PID" 2>/dev/null || true
    exit 1
fi
echo "  ✓ console-pty (127.0.0.1:8765)"

# Start nginx (foreground - keeps container alive)
echo "  ✓ nginx (port 80)"
echo ""
# LLDPQ_PORT is normally a host-side compose variable and is not passed into
# the container; only print a URL when it is known. It may be 'port' or 'ip:port'.
case "${LLDPQ_PORT:-}" in
    "")  echo "LLDPq is ready! Web UI on container port 80 (use the host port published to it)" ;;
    *:*) echo "LLDPq is ready! Access: http://${LLDPQ_PORT}" ;;
    *)   echo "LLDPq is ready! Access: http://localhost:${LLDPQ_PORT}" ;;
esac
echo "  SSH: container port 2033 (reachable only if published or with host networking)"
echo ""

exec nginx -g 'daemon off;'
