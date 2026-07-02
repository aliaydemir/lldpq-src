#!/bin/bash
# provision-api.sh - Provision API (ZTP + Base Config)
# Backend for provision.html
# Called by nginx fcgiwrap

# Admin-only guard (validates session, exits 401/403 if not admin)
source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load allowlisted config data through the fixed, root-owned parser.
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# DHCP config paths
DHCP_HOSTS_FILE="${DHCP_HOSTS_FILE:-/etc/dhcp/dhcpd.hosts}"
DHCP_CONF_FILE="${DHCP_CONF_FILE:-/etc/dhcp/dhcpd.conf}"
DHCP_LEASES_FILE="${DHCP_LEASES_FILE:-/var/lib/dhcp/dhcpd.leases}"
DHCP_LOG_FILE="${DHCP_LOG_FILE:-/var/log/lldpq/dhcpd.log}"
ZTP_SCRIPT_FILE="${ZTP_SCRIPT_FILE:-${WEB_ROOT}/cumulus-ztp.sh}"
BASE_CONFIG_DIR="${BASE_CONFIG_DIR:-${LLDPQ_DIR}/sw-base}"

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)
LINES_PARAM=$(echo "$QUERY_STRING" | grep -oP '(^|&)lines=\K[0-9]+' | head -1)

# Read POST data if present (skip for file uploads — Python reads stdin directly)
POST_DATA=""
if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    # File uploads (multipart) go directly to Python via stdin — don't consume here
    case "$CONTENT_TYPE" in
        multipart/form-data*) ;;
        *) POST_DATA=$(dd bs=4096 count=$(( (CONTENT_LENGTH + 4095) / 4096 )) 2>/dev/null | head -c "$CONTENT_LENGTH") ;;
    esac
fi

# Discovery config
DISCOVERY_RANGE="${DISCOVERY_RANGE:-}"
AUTO_BASE_CONFIG="${AUTO_BASE_CONFIG:-true}"
AUTO_ZTP_DISABLE="${AUTO_ZTP_DISABLE:-true}"
AUTO_SET_HOSTNAME="${AUTO_SET_HOSTNAME:-true}"

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT
export DHCP_HOSTS_FILE DHCP_CONF_FILE DHCP_LEASES_FILE DHCP_LOG_FILE ZTP_SCRIPT_FILE BASE_CONFIG_DIR
export DISCOVERY_RANGE AUTO_BASE_CONFIG AUTO_ZTP_DISABLE AUTO_SET_HOSTNAME
export POST_DATA ACTION LINES_PARAM

python3 << 'PYTHON_SCRIPT'
import json
import sys
import os
import re
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import time

ACTION = os.environ.get('ACTION', '')
POST_DATA = os.environ.get('POST_DATA', '')
LLDPQ_DIR = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
LLDPQ_USER = os.environ.get('LLDPQ_USER', 'lldpq')
WEB_ROOT = os.environ.get('WEB_ROOT', '/var/www/html')
DHCP_HOSTS_FILE = os.environ.get('DHCP_HOSTS_FILE', '/etc/dhcp/dhcpd.hosts')
DHCP_LEASES_FILE = os.environ.get('DHCP_LEASES_FILE', '/var/lib/dhcp/dhcpd.leases')
DHCP_LOG_FILE = os.environ.get('DHCP_LOG_FILE', '/var/log/lldpq/dhcpd.log')
ZTP_SCRIPT_FILE = os.environ.get('ZTP_SCRIPT_FILE', f'{WEB_ROOT}/cumulus-ztp.sh')
BASE_CONFIG_DIR = os.environ.get('BASE_CONFIG_DIR', f'{LLDPQ_DIR}/sw-base')
DISCOVERY_RANGE = os.environ.get('DISCOVERY_RANGE', '')
AUTO_BASE_CONFIG = os.environ.get('AUTO_BASE_CONFIG', 'true') == 'true'
AUTO_ZTP_DISABLE = os.environ.get('AUTO_ZTP_DISABLE', 'true') == 'true'
AUTO_SET_HOSTNAME = os.environ.get('AUTO_SET_HOSTNAME', 'true') == 'true'
DISCOVERY_CACHE_FILE = f'{WEB_ROOT}/discovery-cache.json'
INVENTORY_FILE = f'{WEB_ROOT}/inventory.json'
SERIAL_MAPPING_FILE = f'{WEB_ROOT}/serial-mapping.txt'
GENERATED_CONFIGS_DIR = f'{WEB_ROOT}/generated_config_folder'
UPGRADE_JOBS_DIR = '/var/lib/lldpq/upgrade-jobs'

def update_lldpq_conf(key, value):
    """Update or add a key=value in /etc/lldpq.conf (with file locking)."""
    import fcntl
    conf = '/etc/lldpq.conf'
    try:
        # Use a lock file to prevent concurrent writes
        lock_path = conf + '.lock'
        lock_fd = open(lock_path, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            try:
                with open(conf, 'r') as f:
                    lines = f.readlines()
            except Exception:
                lines = []
            found = False
            for i, line in enumerate(lines):
                if line.startswith(f'{key}='):
                    lines[i] = f'{key}={value}\n'
                    found = True
                    break
            if not found:
                lines.append(f'{key}={value}\n')
            content = ''.join(lines)
            try:
                with open(conf, 'w') as f:
                    f.write(content)
            except PermissionError:
                subprocess.run(['sudo', 'tee', conf], input=content, capture_output=True, text=True, timeout=5)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
    except Exception:
        # Fallback: write without lock (better than failing silently)
        try:
            with open(conf, 'r') as f:
                lines = f.readlines()
        except Exception:
            lines = []
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f'{key}='):
                lines[i] = f'{key}={value}\n'
                found = True
                break
        if not found:
            lines.append(f'{key}={value}\n')
        content = ''.join(lines)
        try:
            with open(conf, 'w') as f:
                f.write(content)
        except PermissionError:
            subprocess.run(['sudo', 'tee', conf], input=content, capture_output=True, text=True, timeout=5)

def read_lldpq_conf_key(key, default=''):
    """Read a single key from /etc/lldpq.conf."""
    try:
        with open('/etc/lldpq.conf', 'r') as f:
            for line in f:
                if line.startswith(f'{key}='):
                    return line.strip().split('=', 1)[1]
    except Exception:
        pass
    return default

def ip_range_to_list(range_str):
    """Parse comma-separated IP ranges and single IPs to list of IPs.
    Supports: '192.168.100.10-192.168.100.249'
              '192.168.100.11-192.168.100.199,192.168.100.201-192.168.100.252'
              '10.20.30.6' (single IP)
              '192.168.100.11-192.168.100.199,10.20.30.6' (mixed)
    """
    if not range_str:
        return []
    result = []
    for segment in range_str.split(','):
        segment = segment.strip()
        if not segment:
            continue
        if '-' not in segment:
            # Single IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', segment):
                result.append(segment)
            continue
        try:
            start_s, end_s = segment.split('-', 1)
            start_parts = list(map(int, start_s.strip().split('.')))
            end_parts = list(map(int, end_s.strip().split('.')))
            if start_parts[:3] == end_parts[:3]:
                prefix = '.'.join(map(str, start_parts[:3]))
                result.extend(f'{prefix}.{i}' for i in range(start_parts[3], end_parts[3] + 1))
            else:
                import ipaddress
                start = int(ipaddress.IPv4Address(start_s.strip()))
                end = int(ipaddress.IPv4Address(end_s.strip()))
                result.extend(str(ipaddress.IPv4Address(i)) for i in range(start, end + 1))
        except Exception:
            continue
    return result

# Also check alternate path for dhcpd.hosts (some setups use dhcpd.host)
DHCP_HOSTS_ALT = DHCP_HOSTS_FILE.replace('dhcpd.hosts', 'dhcpd.host')

def get_dhcp_hosts_path():
    """Find the actual dhcpd.hosts file"""
    for p in [DHCP_HOSTS_FILE, DHCP_HOSTS_ALT]:
        if os.path.exists(p):
            return p
    # Default to primary path (will be created if needed)
    return DHCP_HOSTS_FILE

def result_json(data):
    print(json.dumps(data))
    sys.exit(0)

def error_json(msg):
    result_json({"success": False, "error": msg})

# ======================== BINDINGS ========================

def parse_dhcp_hosts(filepath):
    """Parse ISC dhcpd.hosts file into a list of bindings.
    Format: host HOSTNAME {hardware ethernet MAC; fixed-address IP; ...}
    Also handles commented-out lines (starting with #).
    """
    bindings = []
    if not os.path.exists(filepath):
        return bindings
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Match host entries (both active and commented)
    pattern = re.compile(
        r'^(\s*#?\s*)'                            # optional comment marker
        r'host\s+(\S+)\s*\{'                      # host HOSTNAME {
        r'[^}]*hardware\s+ethernet\s+([\w:]+)\s*;' # hardware ethernet MAC;
        r'[^}]*fixed-address\s+([\d.]+)\s*;'       # fixed-address IP;
        r'[^}]*\}',                                 # }
        re.MULTILINE
    )
    
    for m in pattern.finditer(content):
        prefix = m.group(1).strip()
        commented = prefix.startswith('#')
        hostname = m.group(2)
        mac = m.group(3).lower()
        ip = m.group(4)
        bindings.append({
            'hostname': hostname,
            'mac': mac,
            'ip': ip,
            'commented': commented
        })
    
    return bindings

def generate_dhcp_hosts(bindings, orig_filepath):
    """Generate ISC dhcpd.hosts file content from bindings list.
    Only writes entries with valid hostname + MAC + IP (no placeholders, no commented entries).
    Preserves the group header from original file if present.
    """
    lines = []
    
    # Try to preserve header from original file
    # Extract group header (everything before first 'host' line, or the whole content if no host lines)
    header = ""
    if os.path.exists(orig_filepath):
        with open(orig_filepath, 'r') as f:
            orig = f.read()
        first_host = re.search(r'^#?\s*host\s+', orig, re.MULTILINE)
        if first_host:
            header = orig[:first_host.start()]
        elif 'group' in orig:
            # No host lines but has group header — preserve everything except closing brace
            header = re.sub(r'\n\s*\}\s*$', '', orig.rstrip())
    
    if not header.strip():
        # Default header — use settings from dhcpd.conf if available
        server_ip = get_server_ip()
        gw = server_ip.rsplit('.', 1)[0] + '.1' if '.' in server_ip else server_ip
        # Read domain-name from dhcpd.conf if exists
        domain = 'example.com'
        conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        if os.path.exists(conf_path):
            try:
                with open(conf_path, 'r') as f:
                    conf_content = f.read()
                dm = re.search(r'option\s+domain-name\s+"([^"]*)"', conf_content)
                if dm:
                    domain = dm.group(1)
            except Exception:
                pass
        header = f"""group {{

  option domain-name "{domain}";
  option domain-name-servers {gw};
  option routers {gw};
  option www-server {server_ip};
  option default-url "http://{server_ip}/";
  option cumulus-provision-url "http://{server_ip}/cumulus-ztp.sh";

"""
    
    lines.append(header.rstrip() + '\n')
    
    skipped = 0
    for b in bindings:
        mac = b.get('mac', '').strip()
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        
        # Skip entries without complete info (no placeholder MACs, no commented entries)
        if not hostname or not ip:
            skipped += 1
            continue
        if not mac or mac == '-' or 'x' in mac.lower():
            skipped += 1
            continue
        # Skip entries where DHCP is disabled (static IP devices)
        if not b.get('dhcp', True):
            skipped += 1
            continue
        
        line = (
            f'host {hostname} '
            f'{{hardware ethernet {mac}; '
            f'fixed-address {ip}; '
            f'option host-name "{hostname}"; '
            f'option fqdn.hostname "{hostname}"; '
            f'option cumulus-provision-url "http://{get_server_ip()}/cumulus-ztp.sh";}}'
        )
        lines.append(line)
    
    # Close group if header had one
    if 'group {' in header or 'group{' in header:
        lines.append('\n}')
    
    return '\n'.join(lines) + '\n', skipped

_server_ip_cache = None

def get_server_ip():
    """Try to determine this server's IP for ZTP URL.
    Falls back to reading from existing dhcpd.conf or hosts file.
    Result is cached for the duration of the request.
    """
    global _server_ip_cache
    if _server_ip_cache is not None:
        return _server_ip_cache
    
    # Try to get from dhcpd.conf
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    if os.path.exists(conf_path):
        with open(conf_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"http://([^/]+)/', content)
        if m:
            _server_ip_cache = m.group(1)
            return _server_ip_cache
    
    # Try existing hosts file
    hosts_path = get_dhcp_hosts_path()
    if os.path.exists(hosts_path):
        with open(hosts_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"http://([^/]+)/', content)
        if m:
            _server_ip_cache = m.group(1)
            return _server_ip_cache
    
    # Fallback: try to get our own IP
    try:
        result = subprocess.run(
            ['hostname', '-I'], capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split()
        if ips:
            _server_ip_cache = ips[0]
            return _server_ip_cache
    except Exception:
        pass
    
    _server_ip_cache = '127.0.0.1'
    return _server_ip_cache

def is_valid_server_ref(value):
    if not value or '__' in value or '_' in value:
        return False
    return re.match(r'^[A-Za-z0-9.-]+(:[0-9]{1,5})?$', value) is not None

def action_list_bindings():
    """Load inventory from inventory.json (primary) or dhcpd.hosts (fallback).
    inventory.json is the source of truth — it preserves ALL entries including planned (no MAC).
    dhcpd.hosts only contains active DHCP entries with valid MACs.
    """
    # Primary: read from inventory.json (preserves planned entries)
    bindings = []
    source = 'inventory'
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, 'r') as f:
                inv_data = json.load(f)
            bindings = inv_data.get('bindings', [])
        except Exception:
            bindings = []
    
    # Fallback: read from dhcpd.hosts (legacy / first run)
    if not bindings:
        filepath = get_dhcp_hosts_path()
        bindings = parse_dhcp_hosts(filepath)
        source = 'dhcpd.hosts'
        # Legacy entries from dhcpd.hosts: skip commented entries (they are not active DHCP)
        bindings = [b for b in bindings if not b.get('commented')]
        for b in bindings:
            b['dhcp'] = True
    
    # Enrich with role from devices.yaml and serial from discovery cache
    roles = {}
    try:
        devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_file):
            import yaml
            with open(devices_file, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            for ip, info in ddata.get('devices', ddata).items():
                if ip in ('defaults', 'endpoint_hosts'):
                    continue
                if isinstance(info, str):
                    import re as _re
                    m = _re.match(r'^(.+?)\s+@(\w+)$', info.strip())
                    if m:
                        roles[m.group(1).strip()] = m.group(2).lower()
                elif isinstance(info, dict):
                    h = info.get('hostname', '')
                    r = info.get('role', '')
                    if h and r:
                        roles[h] = r.lower()
    except Exception:
        pass
    
    # Load discovery cache for serial numbers
    disc_cache = {}
    try:
        if os.path.exists(DISCOVERY_CACHE_FILE):
            with open(DISCOVERY_CACHE_FILE, 'r') as f:
                cdata = json.load(f)
            for entry in cdata.get('entries', []):
                if entry.get('ip'):
                    disc_cache[entry['ip']] = entry
    except Exception:
        pass
    
    # Enrich each binding
    for b in bindings:
        is_placeholder = 'x' in b.get('mac', '').lower() or b.get('mac', '') in ('', '-')
        # Show '-' instead of xx:xx:xx in UI
        if 'x' in b.get('mac', '').lower():
            b['mac'] = '-'
        disc = disc_cache.get(b['ip'], {})
        
        # Status: planned / active / discovered
        # - active: fully operational (has MAC, or static IP + reachable)
        # - planned: incomplete record (DHCP device without MAC, or unreachable static)
        # - discovered: reachable but not provisioned (no SSH key)
        needs_dhcp = b.get('dhcp', True)
        if is_placeholder and needs_dhcp:
            # DHCP device without MAC = always planned (waiting for MAC)
            b['inv_status'] = 'planned'
        elif is_placeholder and not needs_dhcp:
            # Static IP device without MAC — status depends on reachability
            if disc.get('device_type') == 'provisioned':
                b['inv_status'] = 'active'
            elif disc.get('device_type') and disc['device_type'] != 'unreachable':
                b['inv_status'] = 'discovered'
            else:
                b['inv_status'] = 'planned'
        elif disc.get('device_type') == 'provisioned':
            b['inv_status'] = 'active'
        elif disc.get('device_type') == 'not_provisioned':
            b['inv_status'] = 'discovered'
        elif b.get('commented'):
            b['inv_status'] = 'planned'
        else:
            b['inv_status'] = 'active'
        
        # Only overwrite role from devices.yaml if binding has no role yet
        if not b.get('role'):
            b['role'] = roles.get(b['hostname'], '')
        if not b.get('serial'):
            b['serial'] = disc.get('serial', '')
        # DHCP flag: default True for backward compat (existing entries without flag)
        if 'dhcp' not in b:
            b['dhcp'] = True
        # Base config status from discovery cache
        b['base_config'] = disc.get('post_provision', '') in ('already', 'deployed')
    
    result_json({"success": True, "bindings": bindings, "source": source})

def action_save_bindings():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    bindings = data.get('bindings', [])
    sync_devices = data.get('sync_devices', False)
    remove_devices = data.get('remove_devices', [])  # hostnames to remove from devices.yaml
    do_restart = data.get('restart_dhcp', True)  # default True for backward compat
    filepath = get_dhcp_hosts_path()
    
    # 1. Save ALL bindings to inventory.json (source of truth, includes planned)
    inv_entries = []
    for b in bindings:
        inv_entries.append({
            'hostname': b.get('hostname', ''),
            'mac': b.get('mac', ''),
            'ip': b.get('ip', ''),
            'serial': b.get('serial', ''),
            'role': b.get('role', ''),
            'inv_status': b.get('inv_status', ''),
            'dhcp': b.get('dhcp', True),
        })
    inv_data = {'bindings': inv_entries, 'timestamp': time.time()}
    try:
        with open(INVENTORY_FILE, 'w') as f:
            json.dump(inv_data, f, indent=2)
    except PermissionError:
        subprocess.run(['sudo', 'tee', INVENTORY_FILE],
                      input=json.dumps(inv_data, indent=2), capture_output=True, text=True, timeout=10)
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', INVENTORY_FILE], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '664', INVENTORY_FILE], capture_output=True, timeout=5)
    
    # 2. Write dhcpd.hosts (only complete entries with valid MAC for DHCP)
    content, skipped = generate_dhcp_hosts(bindings, filepath)
    written = len(bindings) - skipped
    
    try:
        with open(filepath, 'w') as f:
            f.write(content)
    except PermissionError:
        try:
            proc = subprocess.run(
                ['sudo', 'tee', filepath],
                input=content, capture_output=True, text=True, timeout=10
            )
            if proc.returncode != 0:
                error_json(f"Failed to write {filepath}: {proc.stderr}")
            subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', filepath], capture_output=True, timeout=5)
            subprocess.run(['sudo', 'chmod', '664', filepath], capture_output=True, timeout=5)
        except Exception as e:
            error_json(f"Failed to write {filepath}: {e}")
    
    # 3. Sync to devices.yaml: add/update complete bindings, remove deleted ones
    devices_msg = ''
    if sync_devices or remove_devices:
        devices_msg = sync_bindings_to_devices_yaml(bindings, remove_devices)
    
    # 4. Restart DHCP only if requested
    restart_ok = None
    restart_msg = ''
    if do_restart:
        restart_ok, restart_msg = restart_dhcp()
    
    result_json({
        "success": True,
        "message": f"{written} active bindings saved ({skipped} planned). {devices_msg}",
        "dhcp_restart": restart_ok,
        "dhcp_message": restart_msg,
        "written": written,
        "skipped": skipped
    })

def sync_bindings_to_devices_yaml(bindings, remove_hostnames):
    """Sync inventory bindings to devices.yaml.
    - Add/update devices that have complete info (hostname + IP + MAC)
    - Remove devices listed in remove_hostnames
    - Preserves existing comments and structure using ruamel.yaml
    """
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        return 'devices.yaml not found'
    
    try:
        from ruamel.yaml import YAML
        yaml = YAML()
        yaml.preserve_quotes = True
        with open(devices_file, 'r') as f:
            ddata = yaml.load(f) or {}
    except ImportError:
        import yaml as pyyaml
        with open(devices_file, 'r') as f:
            ddata = pyyaml.safe_load(f) or {}
        yaml = None
    
    devices = ddata.get('devices', ddata)
    added = 0
    updated = 0
    removed = 0
    
    # Build IP→hostname map from current devices.yaml
    ip_to_key = {}
    hostname_to_key = {}
    for key, info in list(devices.items()):
        if key in ('defaults', 'endpoint_hosts'):
            continue
        if isinstance(info, str):
            m = re.match(r'^(.+?)\s+@(\w+)$', info.strip())
            h = m.group(1).strip() if m else info.strip()
        elif isinstance(info, dict):
            h = info.get('hostname', str(key))
        else:
            h = str(key)
        ip_to_key[str(key)] = key
        hostname_to_key[h] = key
    
    # Remove devices
    for h in remove_hostnames:
        key = hostname_to_key.get(h)
        if key and key in devices:
            del devices[key]
            removed += 1
    
    # Add/update complete bindings (must have hostname + IP + valid MAC)
    for b in bindings:
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        mac = b.get('mac', '').strip()
        role = b.get('role', '').strip().lower()
        
        # Only sync devices with complete DHCP info
        if not hostname or not ip or not mac or mac == '-' or 'x' in mac.lower():
            continue
        
        existing_key = hostname_to_key.get(hostname) or ip_to_key.get(ip)
        
        if existing_key and existing_key in devices:
            # Update existing entry
            # If IP changed (key is old IP, binding has new IP), move to new key
            if str(existing_key) != ip:
                old_info = devices[existing_key]
                del devices[existing_key]
                # Re-create at new IP key
                if role:
                    devices[ip] = f"{hostname} @{role}"
                else:
                    devices[ip] = hostname
            else:
                # Same IP — just update role
                info = devices[existing_key]
                if isinstance(info, str):
                    if role:
                        devices[existing_key] = f"{hostname} @{role}"
                elif isinstance(info, dict):
                    if role:
                        info['role'] = role
            updated += 1
        else:
            # Add new device
            if role:
                devices[ip] = f"{hostname} @{role}"
            else:
                devices[ip] = hostname
            added += 1
    
    # Write back
    try:
        if yaml and hasattr(yaml, 'dump'):
            with open(devices_file, 'w') as f:
                yaml.dump(ddata, f)
        else:
            import yaml as pyyaml
            with open(devices_file, 'w') as f:
                pyyaml.dump(ddata, f, default_flow_style=False, allow_unicode=True)
    except PermissionError:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            if yaml and hasattr(yaml, 'dump'):
                yaml.dump(ddata, tmp)
            else:
                import yaml as pyyaml
                pyyaml.dump(ddata, tmp, default_flow_style=False, allow_unicode=True)
            tmp_path = tmp.name
        subprocess.run(['sudo', 'cp', tmp_path, devices_file], capture_output=True, timeout=5)
        os.unlink(tmp_path)
    
    parts = []
    if added: parts.append(f'{added} added')
    if updated: parts.append(f'{updated} updated')
    if removed: parts.append(f'{removed} removed')
    return f"devices.yaml: {', '.join(parts)}." if parts else ''

def restart_dhcp():
    """Restart ISC DHCP server. Returns (success, message)."""
    for svc in ['isc-dhcp-server', 'dhcpd']:
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'restart', svc],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return True, f"{svc} restarted"
        except Exception:
            continue
    
    # Try direct dhcpd restart (Docker). Use -d so dhcpd logs to stderr, redirected to
    # DHCP_LOG_FILE (no syslog/journald in the container); detach so it survives the CGI.
    try:
        # Kill existing
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
        # Find interface
        iface = 'eth0'
        isc_default = '/etc/default/isc-dhcp-server'
        if os.path.exists(isc_default):
            with open(isc_default) as f:
                m = re.search(r'INTERFACES="(\S+)"', f.read())
                if m:
                    iface = m.group(1)
        logpath = os.environ.get('DHCP_LOG_FILE', '/var/log/lldpq/dhcpd.log')
        try:
            os.makedirs(os.path.dirname(logpath), exist_ok=True)
        except Exception:
            pass
        try:
            logf = open(logpath, 'a')
        except Exception:
            logf = subprocess.DEVNULL
        conf = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        # Start detached, foreground (-d) so its packet log goes to the file.
        proc = subprocess.Popen(
            ['sudo', 'dhcpd', '-d', '-cf', conf, iface],
            stdout=logf, stderr=logf, start_new_session=True
        )
        time.sleep(0.8)
        if proc.poll() is not None and proc.returncode not in (0, None):
            return False, "dhcpd failed to start (see DHCP log)"
        return True, "dhcpd restarted (logging to %s)" % logpath
    except Exception as e:
        return False, str(e)

# ======================== DISCOVERED ========================

def action_discovered():
    """Cross-reference fabric ARP/LLDP data with DHCP bindings.
    
    Data sources (in priority order):
    1. fabric-tables/*.json — per-device ARP tables from fabric-scan.sh
       Contains eth0/mgmt ARP entries with IP→MAC mappings
    2. device-cache.json — assets data with hostname→MAC
    3. devices.yaml — known devices with IP→hostname mapping
    
    Cross-reference approach:
    - Build IP→MAC map from all ARP tables (eth0 interface = mgmt MAC)
    - For each DHCP binding (hostname, IP, MAC), look up discovered MAC by IP
    - Compare binding MAC vs discovered MAC
    """
    import glob
    
    # Load bindings
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    binding_ip_map = {b['ip']: b for b in bindings}
    
    entries = []
    discovered_ips = {}   # ip -> mac (from ARP)
    discovered_hosts = {} # hostname -> mac (from device-cache)
    
    # --- Source 1: fabric-tables ARP data ---
    # Each fabric-table JSON has "arp" list with entries like:
    # {"ip": "192.168.100.11", "mac": "54:9b:24:aa:68:16", "interface": "eth0", "vrf": "mgmt"}
    # Determine binding subnets to filter relevant ARP entries (no hardcoded prefixes)
    binding_subnets = set()
    for b in bindings:
        parts = b['ip'].split('.')
        if len(parts) == 4:
            binding_subnets.add('.'.join(parts[:3]) + '.')
    
    fabric_tables_dir = os.path.join(LLDPQ_DIR, 'monitor-results', 'fabric-tables')
    if os.path.isdir(fabric_tables_dir):
        for fpath in glob.glob(os.path.join(fabric_tables_dir, '*.json')):
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                for arp_entry in data.get('arp', []):
                    iface = arp_entry.get('interface', '')
                    ip = arp_entry.get('ip', '')
                    mac = arp_entry.get('mac', '').lower()
                    # Only mgmt interface ARP within binding subnets
                    if iface == 'eth0' and ip and mac and any(ip.startswith(s) for s in binding_subnets):
                        discovered_ips[ip] = mac
            except Exception:
                continue
    
    # --- Source 2: device-cache.json ---
    device_cache = os.path.join(WEB_ROOT, 'device-cache.json')
    if os.path.exists(device_cache):
        try:
            with open(device_cache, 'r') as f:
                dc = json.load(f)
            if isinstance(dc, dict):
                for hostname, info in dc.items():
                    if isinstance(info, dict):
                        mac = info.get('mac', '').lower()
                        ip = info.get('ip', '')
                        if mac:
                            discovered_hosts[hostname] = mac
                        if ip and mac:
                            discovered_ips[ip] = mac
        except Exception:
            pass
    
    # --- Source 3: devices.yaml for hostname→IP mapping ---
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    hostname_to_ip = {}
    if os.path.exists(devices_file):
        try:
            import yaml
            with open(devices_file, 'r') as f:
                dev_data = yaml.safe_load(f)
            devices_section = dev_data.get('devices', dev_data)
            for ip, info in devices_section.items():
                if ip in ('defaults', 'endpoint_hosts'):
                    continue
                if isinstance(info, dict):
                    hostname = info.get('hostname', str(ip))
                elif isinstance(info, str):
                    hostname = info.strip().split('@')[0].strip()
                else:
                    hostname = str(info) if info else str(ip)
                hostname_to_ip[hostname] = str(ip)
        except Exception:
            pass
    
    # --- Cross-reference ---
    seen_hostnames = set()
    
    for b in bindings:
        hostname = b['hostname']
        binding_mac = b['mac'].lower()
        binding_ip = b['ip']
        seen_hostnames.add(hostname)
        
        # Try to find discovered MAC: by IP first, then by hostname
        disc_mac = discovered_ips.get(binding_ip, '')
        source = 'ARP' if disc_mac else ''
        
        if not disc_mac:
            disc_mac = discovered_hosts.get(hostname, '')
            source = 'Cache' if disc_mac else ''
        
        entry = {
            'hostname': hostname,
            'binding_mac': b['mac'],
            'binding_ip': binding_ip,
            'discovered_mac': disc_mac,
            'source': source,
            'status': 'missing'
        }
        
        if disc_mac:
            if disc_mac == binding_mac:
                entry['status'] = 'match'
            else:
                entry['status'] = 'mismatch'
        
        entries.append(entry)
    
    # Discovered IPs not in bindings (devices seen in ARP but no DHCP binding)
    # Determine subnet from bindings to filter relevant IPs
    binding_subnets = set()
    for b in bindings:
        parts = b['ip'].split('.')
        if len(parts) == 4:
            binding_subnets.add('.'.join(parts[:3]) + '.')
    
    for ip, mac in discovered_ips.items():
        if ip not in binding_ip_map and any(ip.startswith(s) for s in binding_subnets):
            # Try to find hostname from devices.yaml
            hostname = ''
            for h, h_ip in hostname_to_ip.items():
                if h_ip == ip:
                    hostname = h
                    break
            if not hostname:
                hostname = ip  # fallback to IP
            
            if hostname not in seen_hostnames:
                entries.append({
                    'hostname': hostname,
                    'binding_mac': '',
                    'binding_ip': '',
                    'discovered_mac': mac,
                    'source': 'ARP',
                    'status': 'unbound'
                })
                seen_hostnames.add(hostname)
    
    result_json({"success": True, "entries": entries})

def action_ping_scan():
    """Parallel ping all binding IPs, then read local ARP for MAC cross-reference.
    Much more accurate than fabric-tables — gives real-time reachability + MAC match.
    """
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    if not bindings:
        error_json("No bindings to scan")
    
    # Step 1: Parallel ping all binding IPs (all-at-once, like pping)
    def ping_one(ip):
        try:
            r = subprocess.run(
                ['ping', '-c', '1', '-W', '1', '-i', '0.2', ip],
                capture_output=True, text=True, timeout=2
            )
            return ip, r.returncode == 0
        except Exception:
            return ip, False
    
    ping_results = {}  # ip -> True/False
    with ThreadPoolExecutor(max_workers=250) as executor:
        futures = {executor.submit(ping_one, b['ip']): b['ip'] for b in bindings}
        for future in as_completed(futures):
            ip, alive = future.result()
            ping_results[ip] = alive
    
    # Step 2: Read local ARP table (populated by the pings we just did)
    local_arp = {}  # ip -> mac
    try:
        r = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                # Format: IP dev IFACE lladdr MAC state
                if 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        local_arp[ip] = parts[mac_idx].lower()
    except Exception:
        pass
    
    # Step 3: Cross-reference
    entries = []
    for b in bindings:
        hostname = b['hostname']
        binding_mac = b['mac'].lower()
        binding_ip = b['ip']
        alive = ping_results.get(binding_ip, False)
        disc_mac = local_arp.get(binding_ip, '')
        
        entry = {
            'hostname': hostname,
            'binding_mac': b['mac'],
            'binding_ip': binding_ip,
            'discovered_mac': disc_mac,
            'source': 'Ping+ARP' if disc_mac else ('Ping' if alive else ''),
            'status': 'unreachable'
        }
        
        if alive and disc_mac:
            if disc_mac == binding_mac:
                entry['status'] = 'match'
            else:
                entry['status'] = 'mismatch'
        elif alive and not disc_mac:
            entry['status'] = 'match'  # alive but ARP not captured (rare)
            entry['source'] = 'Ping'
        # else: unreachable
        
        entries.append(entry)
    
    result_json({"success": True, "entries": entries, "scan_type": "ping"})

def action_subnet_scan():
    """Full subnet discovery: ping all IPs in range, ARP for MACs, SSH probe for classification,
    post-provision actions (sw-base, ztp disable, hostname set) for newly provisioned devices."""
    
    # Get discovery range
    disc_range = read_lldpq_conf_key('DISCOVERY_RANGE', DISCOVERY_RANGE)
    if not disc_range:
        # Auto-detect from dhcpd.conf subnet
        conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        try:
            with open(conf_path, 'r') as f:
                content = f.read()
            m = re.search(r'subnet\s+([\d.]+)', content)
            if m:
                prefix = '.'.join(m.group(1).split('.')[:3])
                disc_range = f'{prefix}.10-{prefix}.249'
        except Exception:
            pass
    
    if not disc_range:
        error_json("No discovery range configured. Set it in DHCP Server Configuration.")
    
    all_ips = ip_range_to_list(disc_range)
    if not all_ips:
        error_json(f"Invalid discovery range: {disc_range}")
    # Safety limit: prevent memory/timeout bombs from huge ranges
    if len(all_ips) > 1500:
        error_json(f"Discovery range too large: {len(all_ips)} IPs (max 1500). Narrow the range.")
    
    # Load inventory for cross-reference (inventory.json is source of truth, fallback to dhcpd.hosts)
    inv_bindings = []
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, 'r') as f:
                inv_bindings = json.load(f).get('bindings', [])
        except Exception:
            pass
    if not inv_bindings:
        inv_bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    binding_by_ip = {b['ip']: b for b in inv_bindings}
    binding_by_hostname = {b.get('hostname',''): b for b in inv_bindings if b.get('hostname')}
    
    # Load devices.yaml for hostname resolution + roles
    devices_yaml = {}    # ip -> hostname
    devices_roles = {}   # hostname -> role
    try:
        devices_path = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_path):
            import yaml
            with open(devices_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            devices_section = data.get('devices', data)
            if isinstance(devices_section, dict):
                for host_ip, info in devices_section.items():
                    if host_ip in ('defaults', 'endpoint_hosts'):
                        continue
                    if isinstance(info, dict):
                        hostname = info.get('hostname', str(host_ip))
                        if info.get('ip'):
                            devices_yaml[info['ip']] = hostname
                        role = info.get('role', '')
                        if role:
                            devices_roles[hostname] = role.lower()
                    elif isinstance(info, str):
                        raw = info.strip()
                        m = re.match(r'^(.+?)\s+@(\w+)$', raw)
                        if m:
                            hostname = m.group(1).strip()
                            devices_roles[hostname] = m.group(2).lower()
                        else:
                            hostname = raw
                        devices_yaml[str(host_ip)] = hostname
    except Exception:
        pass
    
    # Check if range contains non-private IPs (possible typo like 92.x instead of 192.x)
    non_private = []
    for ip in all_ips[:5]:  # sample first 5
        parts = ip.split('.')
        first = int(parts[0]) if parts else 0
        if not (first == 10 or (first == 172 and 16 <= int(parts[1]) <= 31) or (first == 192 and int(parts[1]) == 168)):
            non_private.append(ip)
    
    warning = ''
    if non_private:
        warning = f"Warning: range contains non-private IPs ({non_private[0]}...). Typo? Scan continues with short timeout."
    
    # Step 1: Parallel ping all IPs in discovery range
    # Use shorter timeout for non-private IPs to avoid long hangs on typos
    ping_timeout = 1 if non_private else 1
    ping_wait = '0.5' if non_private else '1'
    
    def ping_one(ip):
        try:
            r = subprocess.run(['ping', '-c', '1', '-W', ping_wait, '-i', '0.2', ip],
                             capture_output=True, text=True, timeout=2)
            return ip, r.returncode == 0
        except Exception:
            return ip, False
    
    ping_results = {}
    with ThreadPoolExecutor(max_workers=250) as executor:
        futures = {executor.submit(ping_one, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip, alive = future.result()
            ping_results[ip] = alive
    
    # Step 2: Read local ARP table
    local_arp = {}
    try:
        r = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        local_arp[ip] = parts[mac_idx].lower()
    except Exception:
        pass
    
    reachable_ips = [ip for ip, alive in ping_results.items() if alive]
    
    # Step 3: SSH probe reachable IPs for device classification + serial collection
    def ssh_probe(ip):
        """Try SSH with key auth as cumulus user (runs as LLDPQ_USER to use correct SSH keys).
        Returns: (ip, device_type, serial, base_deployed)"""
        try:
            r = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
                 '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                 '-o', 'LogLevel=ERROR', f'cumulus@{ip}',
                 'echo OK; sudo dmidecode -s system-serial-number 2>/dev/null | head -1; test -f /etc/lldpq-base-deployed && echo BASE_DEPLOYED || echo BASE_PENDING'],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and 'OK' in r.stdout:
                lines = r.stdout.strip().split('\n')
                serial = lines[1].strip() if len(lines) > 1 else ''
                if not serial or serial.lower() in ('', 'na', 'n/a', 'not specified', 'none'):
                    serial = ''
                base_deployed = 'BASE_DEPLOYED' in r.stdout
                return ip, 'provisioned', serial, base_deployed
            stderr = r.stderr.lower()
            if 'permission denied' in stderr:
                return ip, 'not_provisioned', '', False
            if 'connection refused' in stderr:
                return ip, 'other', '', False
            return ip, 'not_provisioned', '', False
        except subprocess.TimeoutExpired:
            return ip, 'other', '', False
        except Exception:
            return ip, 'other', '', False
    
    ssh_results = {}
    serial_results = {}
    base_results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(ssh_probe, ip): ip for ip in reachable_ips}
        for future in as_completed(futures):
            ip, device_type, serial, base_deployed = future.result()
            ssh_results[ip] = device_type
            if serial:
                serial_results[ip] = serial
            if base_deployed:
                base_results[ip] = True
    
    # Step 4: Build entries with cross-reference
    entries = []
    for ip in all_ips:
        alive = ping_results.get(ip, False)
        disc_mac = local_arp.get(ip, '')
        binding = binding_by_ip.get(ip)
        
        hostname = ''
        binding_mac = ''
        binding_ip = ip
        mac_status = ''
        
        if binding:
            hostname = binding['hostname']
            binding_mac = binding['mac']
            if alive and disc_mac:
                mac_status = 'match' if disc_mac == binding_mac.lower() else 'mismatch'
            elif alive:
                mac_status = 'match'
            else:
                mac_status = 'unreachable'
        else:
            hostname = devices_yaml.get(ip, '')
            mac_status = 'no_binding'
        
        if not alive:
            device_type = 'unreachable'
        else:
            device_type = ssh_results.get(ip, 'other')
        
        # Resolve role from devices.yaml
        entry_role = devices_roles.get(hostname, '')
        
        entry = {
            'ip': ip,
            'hostname': hostname,
            'binding_mac': binding_mac,
            'discovered_mac': disc_mac,
            'device_type': device_type,
            'mac_status': mac_status,
            'serial': serial_results.get(ip, ''),
            'role': entry_role,
            'source': 'Ping+ARP' if disc_mac else ('Ping' if alive else ''),
            'has_binding': binding is not None,
            'post_provision': 'already' if base_results.get(ip) else None,
        }
        entries.append(entry)
    
    # Step 5: Post-provision actions for newly provisioned devices
    auto_base = read_lldpq_conf_key('AUTO_BASE_CONFIG', 'true') == 'true'
    auto_ztp = read_lldpq_conf_key('AUTO_ZTP_DISABLE', 'true') == 'true'
    auto_host = read_lldpq_conf_key('AUTO_SET_HOSTNAME', 'true') == 'true'
    
    if auto_base or auto_ztp or auto_host:
        # Only post-provision devices that have a binding AND haven't been deployed yet
        provisioned_entries = [e for e in entries if e['device_type'] == 'provisioned' and e['has_binding'] and e['post_provision'] != 'already']
        
        def post_provision_one(entry):
            ip = entry['ip']
            hostname = entry['hostname']
            
            # Execute post-provision actions
            cmds = []
            
            # sw-base deploy via SCP + SSH
            scp_ok = False
            if auto_base and os.path.isdir(BASE_CONFIG_DIR):
                files_map = {
                    'bash.bashrc': ['/etc/bash.bashrc', '/home/cumulus/.bashrc'],
                    'motd.sh': ['/etc/profile.d/motd.sh'],
                    'tmux.conf': ['/home/cumulus/.tmux.conf'],
                    'nanorc': ['/home/cumulus/.nanorc'],
                    'cmd': ['/usr/local/bin/cmd'],
                    'nvc': ['/usr/local/bin/nvc'],
                    'nvt': ['/usr/local/bin/nvt'],
                    'exa': ['/usr/bin/exa'],
                }
                scp_files = []
                copy_cmds = []
                for fname, dests in files_map.items():
                    src = os.path.join(BASE_CONFIG_DIR, fname)
                    if os.path.exists(src):
                        scp_files.append(src)
                        for dest in dests:
                            copy_cmds.append(f'sudo cp /tmp/{fname} {dest}')
                            if dest.startswith('/usr/') or fname in ('cmd', 'nvc', 'nvt', 'exa', 'motd.sh'):
                                copy_cmds.append(f'sudo chmod 755 {dest}')
                # Fix shell startup: remove .bash_login (blocks .profile) and ensure .profile sources .bashrc
                copy_cmds.append('rm -f /home/cumulus/.bash_login')
                copy_cmds.append("echo '[ -f ~/.bashrc ] && . ~/.bashrc' > /home/cumulus/.profile")
                
                if scp_files:
                    try:
                        scp_r = subprocess.run(
                            ['sudo', '-u', LLDPQ_USER, 'scp', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
                             '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                             '-o', 'LogLevel=ERROR'] + scp_files + [f'cumulus@{ip}:/tmp/'],
                            capture_output=True, text=True, timeout=15
                        )
                        if scp_r.returncode == 0:
                            cmds.extend(copy_cmds)
                            scp_ok = True
                    except Exception:
                        pass
            
            # ZTP disable (wrapped in subshell so || true doesn't affect && chain)
            if auto_ztp:
                cmds.append('(sudo ztp -d 2>/dev/null || true)')
            
            # Hostname set (wrapped in subshell)
            if auto_host and hostname:
                cmds.append(f'(sudo nv set system hostname {hostname} 2>/dev/null && sudo nv config apply -y 2>/dev/null || true)')
            
            # Write marker only if base config was deployed (or if SCP wasn't needed)
            if scp_ok or not auto_base:
                cmds.append('sudo touch /etc/lldpq-base-deployed')
            
            if cmds:
                cmd_str = ' && '.join(cmds)
                try:
                    r = subprocess.run(
                        ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                         '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                         '-o', 'LogLevel=ERROR', f'cumulus@{ip}', cmd_str],
                        capture_output=True, text=True, timeout=30
                    )
                    # Only report 'deployed' if SSH command actually succeeded
                    if r.returncode == 0:
                        return ip, 'deployed'
                    else:
                        return ip, 'failed'
                except Exception:
                    return ip, 'failed'
            
            return ip, None
        
        # Run post-provision in parallel (limited workers since these are heavier)
        post_results = {}
        if provisioned_entries:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(post_provision_one, e): e['ip'] for e in provisioned_entries}
                for future in as_completed(futures):
                    ip, status = future.result()
                    post_results[ip] = status
            
            # Update entries with post-provision results
            for entry in entries:
                if entry['ip'] in post_results:
                    entry['post_provision'] = post_results[entry['ip']]
    
    # Step 6: Write cache
    cache_data = {
        'timestamp': time.time(),
        'discovery_range': disc_range,
        'entries': entries,
    }
    try:
        with open(DISCOVERY_CACHE_FILE, 'w') as f:
            json.dump(cache_data, f)
    except PermissionError:
        subprocess.run(['sudo', 'tee', DISCOVERY_CACHE_FILE],
                      input=json.dumps(cache_data), capture_output=True, text=True, timeout=5)
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', DISCOVERY_CACHE_FILE], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '664', DISCOVERY_CACHE_FILE], capture_output=True, timeout=5)
    
    result_json({
        "success": True,
        "entries": entries,
        "scan_type": "subnet",
        "discovery_range": disc_range,
        "total_ips": len(all_ips),
        "reachable": len(reachable_ips),
        "post_provision_results": {ip: s for ip, s in post_results.items()} if 'post_results' in dir() else {},
        "warning": warning,
    })

def action_get_discovery_cache():
    """Read cached discovery results."""
    if not os.path.exists(DISCOVERY_CACHE_FILE):
        result_json({"success": True, "entries": [], "stale": True, "timestamp": 0})
    
    try:
        with open(DISCOVERY_CACHE_FILE, 'r') as f:
            data = json.load(f)
        age = time.time() - data.get('timestamp', 0)
        data['success'] = True
        data['stale'] = age > 300  # stale if > 5 minutes
        data['age_seconds'] = int(age)
        result_json(data)
    except Exception as e:
        result_json({"success": True, "entries": [], "stale": True, "timestamp": 0, "error": str(e)})

def action_save_post_provision():
    """Save post-provision toggle settings."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    
    if 'auto_base_config' in data:
        update_lldpq_conf('AUTO_BASE_CONFIG', 'true' if data['auto_base_config'] else 'false')
    if 'auto_ztp_disable' in data:
        update_lldpq_conf('AUTO_ZTP_DISABLE', 'true' if data['auto_ztp_disable'] else 'false')
    if 'auto_set_hostname' in data:
        update_lldpq_conf('AUTO_SET_HOSTNAME', 'true' if data['auto_set_hostname'] else 'false')
    if 'discovery_range' in data:
        update_lldpq_conf('DISCOVERY_RANGE', data['discovery_range'])
    if 'scan_interval' in data:
        update_lldpq_conf('SCAN_INTERVAL', str(int(data['scan_interval'])))
    
    result_json({"success": True, "message": "Settings saved"})

# ======================== ZTP SCRIPT ========================

def action_get_ztp_script():
    if not os.path.exists(ZTP_SCRIPT_FILE):
        # Try alternate locations
        for alt in ['/var/www/html/cumulus-ztp.sh', f'{WEB_ROOT}/cumulus-ztp.sh']:
            if os.path.exists(alt):
                with open(alt, 'r') as f:
                    result_json({"success": True, "content": f.read(), "file": alt})
        result_json({"success": True, "content": "", "file": ZTP_SCRIPT_FILE})
    
    with open(ZTP_SCRIPT_FILE, 'r') as f:
        content = f.read()
    result_json({"success": True, "content": content, "file": ZTP_SCRIPT_FILE})

def action_save_ztp_script():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    content = data.get('content', '')
    if not content.strip():
        error_json("Script content is empty")
    
    filepath = ZTP_SCRIPT_FILE
    
    written = False
    try:
        with open(filepath, 'w') as f:
            f.write(content)
        written = True
    except PermissionError:
        pass

    if not written:
        try:
            proc = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'tee', filepath],
                input=content, capture_output=True, text=True, timeout=10
            )
            if proc.returncode != 0:
                error_json(f"Failed to write: {proc.stderr}")
        except Exception as e:
            error_json(str(e))

    # Fix permissions (always use sudo — www-data can't chmod files owned by LLDPQ_USER)
    subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', filepath], capture_output=True, timeout=5)
    subprocess.run(['sudo', 'chmod', '775', filepath], capture_output=True, timeout=5)
    
    result_json({"success": True, "message": "ZTP script saved"})

# ======================== DHCP STATUS ========================

def action_dhcp_service_status():
    """Check if DHCP service is running."""
    running = False
    
    # Try systemctl
    try:
        for svc in ['isc-dhcp-server', 'dhcpd']:
            r = subprocess.run(
                ['systemctl', 'is-active', svc],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == 'active':
                running = True
                break
    except Exception:
        pass
    
    if not running:
        # Check if dhcpd process is running
        try:
            r = subprocess.run(['pgrep', '-x', 'dhcpd'], capture_output=True, timeout=5)
            running = r.returncode == 0
        except Exception:
            pass
    
    result_json({"success": True, "running": running})

def action_dhcp_service_control():
    """Start, stop, or restart DHCP service."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    action = data.get('action', '')
    if action not in ('start', 'stop', 'restart'):
        error_json(f"Invalid action: {action}")
    
    # Try systemctl first
    for svc in ['isc-dhcp-server', 'dhcpd']:
        try:
            r = subprocess.run(
                ['sudo', 'systemctl', action, svc],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                # Stop also disables (prevent auto-start on boot)
                if action == 'stop':
                    subprocess.run(['sudo', 'systemctl', 'disable', svc],
                                   capture_output=True, text=True, timeout=10)
                    result_json({"success": True, "message": f"{svc} stopped & disabled"})
                # Start also enables
                elif action == 'start':
                    subprocess.run(['sudo', 'systemctl', 'enable', svc],
                                   capture_output=True, text=True, timeout=10)
                    result_json({"success": True, "message": f"{svc} started & enabled"})
                else:
                    result_json({"success": True, "message": f"{svc} restarted"})
        except Exception:
            continue
    
    # Fallback: direct process management (Docker)
    if action in ('stop', 'restart'):
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
        if action == 'stop':
            result_json({"success": True, "message": "dhcpd stopped"})
    
    if action in ('start', 'restart'):
        ok, msg = restart_dhcp()
        result_json({"success": ok, "message": msg, "error": "" if ok else msg})
    
    error_json("Could not control DHCP service")

def action_get_dhcp_config():
    """Read dhcpd.conf and isc-dhcp-server defaults, return parsed settings."""
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    isc_default = '/etc/default/isc-dhcp-server'
    
    config = {
        'subnet': '', 'netmask': '', 'range_start': '', 'range_end': '',
        'gateway': '', 'dns': '', 'domain': '', 'provision_url': '',
        'interface': 'eth0', 'lease_time': '172800'
    }
    
    # Parse dhcpd.conf
    if os.path.exists(conf_path):
        try:
            with open(conf_path, 'r') as f:
                content = f.read()
        except PermissionError:
            r = subprocess.run(['sudo', 'cat', conf_path], capture_output=True, text=True, timeout=5)
            content = r.stdout if r.returncode == 0 else ''
        
        # subnet X netmask Y
        m = re.search(r'subnet\s+([\d.]+)\s+netmask\s+([\d.]+)', content)
        if m:
            config['subnet'] = m.group(1)
            config['netmask'] = m.group(2)
        
        # range START END
        m = re.search(r'range\s+([\d.]+)\s+([\d.]+)', content)
        if m:
            config['range_start'] = m.group(1)
            config['range_end'] = m.group(2)
        
        # option routers
        m = re.search(r'option\s+routers\s+([\d.]+)', content)
        if m:
            config['gateway'] = m.group(1)
        
        # option domain-name-servers
        m = re.search(r'option\s+domain-name-servers\s+([\d.]+)', content)
        if m:
            config['dns'] = m.group(1)
        
        # option domain-name
        m = re.search(r'option\s+domain-name\s+"([^"]*)"', content)
        if m:
            config['domain'] = m.group(1)
        
        # cumulus-provision-url
        m = re.search(r'cumulus-provision-url\s+"([^"]*)"', content)
        if m:
            config['provision_url'] = m.group(1)
        
        # default-lease-time
        m = re.search(r'default-lease-time\s+(\d+)', content)
        if m:
            config['lease_time'] = m.group(1)
    
    # Parse interface from /etc/default/isc-dhcp-server
    if os.path.exists(isc_default):
        try:
            with open(isc_default, 'r') as f:
                isc_content = f.read()
            m = re.search(r'INTERFACES="([^"]*)"', isc_content)
            if m:
                config['interface'] = m.group(1)
        except Exception:
            pass
    
    # List network interfaces with IP addresses
    interfaces = []
    try:
        r = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            seen = set()
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    iface_name = parts[1]
                    ip_cidr = parts[3]  # e.g. 192.168.100.200/24
                    ip_addr = ip_cidr.split('/')[0]
                    if iface_name not in seen and iface_name != 'lo':
                        interfaces.append({'name': iface_name, 'ip': ip_addr})
                        seen.add(iface_name)
    except Exception:
        pass
    
    # Read discovery range and post-provision settings from lldpq.conf
    discovery_range = read_lldpq_conf_key('DISCOVERY_RANGE', '')
    # Auto-generate default from subnet if empty
    if not discovery_range and config['subnet']:
        prefix = '.'.join(config['subnet'].split('.')[:3])
        discovery_range = f'{prefix}.10-{prefix}.249'
    
    # Scan interval (default 300 = 5 min)
    scan_interval_str = read_lldpq_conf_key('SCAN_INTERVAL', '300')
    try:
        scan_interval = int(scan_interval_str)
    except ValueError:
        scan_interval = 300
    
    result_json({
        "success": True,
        "interfaces": interfaces,
        "discovery_range": discovery_range,
        "auto_base_config": read_lldpq_conf_key('AUTO_BASE_CONFIG', 'true') == 'true',
        "auto_ztp_disable": read_lldpq_conf_key('AUTO_ZTP_DISABLE', 'true') == 'true',
        "auto_set_hostname": read_lldpq_conf_key('AUTO_SET_HOSTNAME', 'true') == 'true',
        "scan_interval": scan_interval,
        **config
    })

def action_save_dhcp_config():
    """Write dhcpd.conf from settings and restart DHCP."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    subnet = data.get('subnet', '')
    netmask = data.get('netmask', '255.255.255.0')
    range_start = data.get('range_start', '')
    range_end = data.get('range_end', '')
    gateway = data.get('gateway', '')
    dns = data.get('dns', gateway)
    domain = data.get('domain', 'example.com')
    provision_url = data.get('provision_url', '')
    iface = data.get('interface', 'eth0')
    lease_time = data.get('lease_time', '172800')
    
    # Find hosts include path
    hosts_path = get_dhcp_hosts_path()
    
    # Generate dhcpd.conf
    range_line = f'    range {range_start} {range_end};' if range_start and range_end else '    # range not configured'
    prov_line = f'    option cumulus-provision-url "{provision_url}";' if provision_url else ''
    
    conf = f"""# /etc/dhcp/dhcpd.conf - Generated by LLDPq Provision

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

class "onie-vendor-classes" {{
  match if substring(option vendor-class-identifier, 0, 11) = "onie_vendor";
  option vivso.iana 01:01:01;
}}

# OOB Management subnet
shared-network OOB {{
  subnet {subnet} netmask {netmask} {{
{range_line}
    option routers {gateway};
    option domain-name "{domain}";
    option domain-name-servers {dns};
    option www-server {gateway};
    option default-url "http://{gateway}/";
{prov_line}
    default-lease-time {lease_time};
    max-lease-time     {int(lease_time) * 2};
  }}
}}

include "{hosts_path}";
"""
    
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    
    # Write dhcpd.conf
    try:
        with open(conf_path, 'w') as f:
            f.write(conf)
    except PermissionError:
        proc = subprocess.run(['sudo', 'tee', conf_path], input=conf, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            error_json(f"Failed to write dhcpd.conf: {proc.stderr}")
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', conf_path], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '664', conf_path], capture_output=True, timeout=5)
    
    # Write interface config
    isc_default = '/etc/default/isc-dhcp-server'
    isc_content = f'INTERFACES="{iface}"\n'
    try:
        with open(isc_default, 'w') as f:
            f.write(isc_content)
    except PermissionError:
        subprocess.run(['sudo', 'tee', isc_default], input=isc_content, capture_output=True, text=True, timeout=5)
    
    # Save discovery range to lldpq.conf
    discovery_range = data.get('discovery_range', '')
    if discovery_range:
        update_lldpq_conf('DISCOVERY_RANGE', discovery_range)
    
    # Save post-provision toggles
    if 'auto_base_config' in data:
        update_lldpq_conf('AUTO_BASE_CONFIG', 'true' if data['auto_base_config'] else 'false')
    if 'auto_ztp_disable' in data:
        update_lldpq_conf('AUTO_ZTP_DISABLE', 'true' if data['auto_ztp_disable'] else 'false')
    if 'auto_set_hostname' in data:
        update_lldpq_conf('AUTO_SET_HOSTNAME', 'true' if data['auto_set_hostname'] else 'false')
    
    # Restart DHCP
    ok, msg = restart_dhcp()
    result_json({
        "success": True,
        "message": f"Config saved. DHCP: {msg}",
        "dhcp_restart": ok
    })

def parse_dhcp_leases(filepath):
    """Parse ISC dhcpd.leases file."""
    leases = []
    if not os.path.exists(filepath):
        return leases
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Parse lease blocks
    lease_pattern = re.compile(
        r'lease\s+([\d.]+)\s*\{(.*?)\}',
        re.DOTALL
    )
    
    for m in lease_pattern.finditer(content):
        ip = m.group(1)
        block = m.group(2)
        
        lease = {'ip': ip, 'mac': '', 'hostname': '', 'start': '', 'end': '', 'state': 'active'}
        
        # Parse fields
        mac_m = re.search(r'hardware\s+ethernet\s+([\w:]+)', block)
        if mac_m:
            lease['mac'] = mac_m.group(1).lower()
        
        host_m = re.search(r'client-hostname\s+"([^"]*)"', block)
        if host_m:
            lease['hostname'] = host_m.group(1)
        
        start_m = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if start_m:
            lease['start'] = start_m.group(1)
        
        end_m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if end_m:
            lease['end'] = end_m.group(1)
        
        state_m = re.search(r'binding\s+state\s+(\w+)', block)
        if state_m:
            lease['state'] = state_m.group(1)
        
        leases.append(lease)
    
    # Deduplicate: keep last lease per IP (most recent)
    seen = {}
    for l in leases:
        seen[l['ip']] = l
    
    return sorted(seen.values(), key=lambda x: x['ip'])

def action_dhcp_leases():
    leases = parse_dhcp_leases(DHCP_LEASES_FILE)
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    result_json({
        "success": True,
        "leases": leases,
        "reserved_count": len(bindings)
    })


def action_dhcp_log():
    """Return the tail of the DHCP server log.
    Docker logs to DHCP_LOG_FILE (dhcpd -d). On systemd hosts we fall back to journalctl."""
    try:
        n = int(os.environ.get('LINES_PARAM') or 300)
    except Exception:
        n = 300
    n = max(20, min(n, 2000))
    text, source = '', ''
    # 1) Docker: tail the log file (read only the last chunk, efficient on big logs)
    if os.path.exists(DHCP_LOG_FILE):
        try:
            with open(DHCP_LOG_FILE, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 262144))
                chunk = f.read().decode('utf-8', 'replace')
            lines = chunk.splitlines()
            if lines:
                text = '\n'.join(lines[-n:])
                source = DHCP_LOG_FILE
        except Exception as e:
            text, source = 'Error reading %s: %s' % (DHCP_LOG_FILE, e), DHCP_LOG_FILE
    # 2) systemd host fallback: journalctl
    if not text:
        import shutil
        if shutil.which('journalctl'):
            for unit in ('isc-dhcp-server', 'dhcpd'):
                try:
                    r = subprocess.run(['sudo', 'journalctl', '-u', unit, '-n', str(n), '--no-pager'],
                                       capture_output=True, text=True, timeout=10)
                    if r.returncode == 0 and r.stdout.strip():
                        text, source = r.stdout, 'journalctl -u %s' % unit
                        break
                except Exception:
                    continue
    result_json({"success": True, "log": text, "source": source or DHCP_LOG_FILE,
                 "exists": bool(text)})

# ======================== LIST DEVICES ========================

def action_list_devices():
    """List devices from devices.yaml for base config deploy target selection."""
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    
    if not os.path.exists(devices_file):
        error_json(f"devices.yaml not found at {devices_file}")
    
    try:
        import yaml
        with open(devices_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        error_json(str(e))
    
    defaults = data.get('defaults', {})
    default_username = defaults.get('username', 'cumulus')
    
    devices_section = data.get('devices', data)
    devices = []
    
    groups = {}  # role -> [devices]
    
    for ip, info in devices_section.items():
        if ip in ('defaults', 'endpoint_hosts'):
            continue
        
        role = 'ungrouped'
        if isinstance(info, dict):
            hostname = info.get('hostname', str(ip))
            username = info.get('username', default_username)
            role = info.get('role', 'ungrouped')
        elif isinstance(info, str):
            # Format: "hostname @role" or just "hostname"
            raw = info.strip()
            if '@' in raw:
                parts = raw.split('@')
                hostname = parts[0].strip()
                role = parts[1].strip()
            else:
                hostname = raw
            username = default_username
        else:
            hostname = str(info) if info else str(ip)
            username = default_username
        
        dev = {'ip': str(ip), 'hostname': hostname, 'username': username, 'role': role}
        groups.setdefault(role, []).append(dev)
    
    # Sort devices within each group by hostname
    for role in groups:
        groups[role].sort(key=lambda x: x['hostname'])
    
    # Flat list for backward compat
    all_devices = []
    for devs in groups.values():
        all_devices.extend(devs)
    all_devices.sort(key=lambda x: x['hostname'])
    
    result_json({"success": True, "devices": all_devices, "groups": groups})

# ======================== BASE CONFIG DEPLOY ========================

# File deployment mapping: source name -> (destination, permissions, extra_dest)
FILE_DEPLOY_MAP = {
    'bash.bashrc': [
        {'dest': '/etc/bash.bashrc', 'mode': '644'},
        {'dest': '/home/cumulus/.bashrc', 'mode': '644'}
    ],
    'motd.sh': [
        {'dest': '/etc/profile.d/motd.sh', 'mode': '755'}
    ],
    'tmux.conf': [
        {'dest': '/etc/tmux.conf', 'mode': '644'}
    ],
    'nanorc': [
        {'dest': '/etc/nanorc', 'mode': '644'}
    ],
    'cmd': [
        {'dest': '/usr/local/bin/cmd', 'mode': '755'}
    ],
    'nvc': [
        {'dest': '/usr/local/bin/nvc', 'mode': '755'}
    ],
    'nvt': [
        {'dest': '/usr/local/bin/nvt', 'mode': '755'}
    ],
    'exa': [
        {'dest': '/usr/bin/exa', 'mode': '755'}
    ]
}

def deploy_to_device(device, files, disable_ztp):
    """Deploy base config files to a single device via SCP + SSH.
    Returns result dict.
    """
    ip = device['ip']
    hostname = device['hostname']
    username = device.get('username', 'cumulus')
    
    result = {
        'ip': ip,
        'hostname': hostname,
        'success': False,
        'message': '',
        'error': ''
    }
    
    ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']
    
    # Step 1: Check connectivity
    try:
        check = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts + ['-q', f'{username}@{ip}', 'echo ok'],
            capture_output=True, text=True, timeout=15
        )
        if check.returncode != 0:
            result['error'] = 'SSH connection failed (key not configured?)'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SSH connection timeout'
        return result
    except Exception as e:
        result['error'] = str(e)
        return result
    
    # Step 2: SCP files to /tmp/
    scp_files = []
    for fname in files:
        src = os.path.join(BASE_CONFIG_DIR, fname)
        if os.path.exists(src):
            scp_files.append(src)
    
    if not scp_files:
        result['error'] = 'No source files found'
        return result
    
    try:
        scp_cmd = ['sudo', '-u', LLDPQ_USER, 'scp'] + ssh_opts + scp_files + [f'{username}@{ip}:/tmp/']
        scp_result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if scp_result.returncode != 0:
            result['error'] = f'SCP failed: {scp_result.stderr.strip()[:200]}'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SCP timeout'
        return result
    except Exception as e:
        result['error'] = f'SCP error: {e}'
        return result
    
    # Step 3: SSH to move files to correct locations
    mv_commands = []
    has_bashrc = False
    for fname in files:
        if fname in FILE_DEPLOY_MAP:
            for target in FILE_DEPLOY_MAP[fname]:
                dest = target['dest']
                mode = target['mode']
                mv_commands.append(f'sudo cp /tmp/{fname} {dest} && sudo chmod {mode} {dest}')
            if fname == 'bash.bashrc':
                has_bashrc = True
    
    if has_bashrc:
        mv_commands.append('rm -f /home/cumulus/.bash_login')
        mv_commands.append("echo '[ -f ~/.bashrc ] && . ~/.bashrc' > /home/cumulus/.profile")
    
    if disable_ztp:
        mv_commands.append('sudo ztp -d 2>/dev/null || true')
    
    # Write marker so Discover tab shows "Yes" instead of "Pending"
    mv_commands.append('sudo touch /etc/lldpq-base-deployed')
    
    # Cleanup tmp files
    cleanup = ' '.join(f'/tmp/{fname}' for fname in files)
    mv_commands.append(f'rm -f {cleanup}')
    
    remote_cmd = ' && '.join(mv_commands)
    
    try:
        ssh_cmd = ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts + [f'{username}@{ip}', remote_cmd]
        ssh_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        if ssh_result.returncode != 0:
            result['error'] = f'Remote install failed: {ssh_result.stderr.strip()[:200]}'
            return result
    except subprocess.TimeoutExpired:
        result['error'] = 'SSH command timeout'
        return result
    except Exception as e:
        result['error'] = f'SSH error: {e}'
        return result
    
    result['success'] = True
    result['message'] = f'{len(files)} files deployed'
    return result

def action_deploy_base_config():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    files = data.get('files', [])
    devices = data.get('devices', [])
    disable_ztp = data.get('disable_ztp', False)
    
    # If no files specified, deploy all known files (skip missing ones)
    if not files:
        files = list(FILE_DEPLOY_MAP.keys())
    
    if not devices:
        error_json("No devices selected")
    
    # Filter to only files that exist on disk (graceful skip)
    available_files = [f for f in files if f in FILE_DEPLOY_MAP and os.path.exists(os.path.join(BASE_CONFIG_DIR, f))]
    if not available_files:
        error_json("No deploy files found in " + BASE_CONFIG_DIR)
    files = available_files
    
    # Deploy in parallel (20 workers max)
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(deploy_to_device, dev, files, disable_ztp): dev
            for dev in devices
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                dev = futures[future]
                results.append({
                    'ip': dev['ip'],
                    'hostname': dev['hostname'],
                    'success': False,
                    'error': str(e)
                })
    
    # Sort by hostname
    results.sort(key=lambda x: x['hostname'])
    
    ok = sum(1 for r in results if r['success'])
    fail = len(results) - ok
    
    result_json({
        "success": True,
        "results": results,
        "summary": {"ok": ok, "fail": fail, "total": len(results)}
    })

# ======================== OS UPGRADE ========================

def image_version_from_name(name):
    m = re.search(r'cumulus-linux-([0-9][A-Za-z0-9._-]*?)-', name)
    return m.group(1) if m else ''

def list_os_image_objects():
    images = []
    import glob as g
    for ext in ['*.bin', '*.img', '*.iso']:
        for f in g.glob(os.path.join(WEB_ROOT, ext)):
            name = os.path.basename(f)
            # Skip the ONIE HTTP-discovery serving aliases (symlinks to the active image) — they are
            # not uploadable OS images and must not clutter / be selectable in this list.
            if name.startswith('onie-installer'):
                continue
            size_bytes = os.path.getsize(f)
            images.append({
                'name': name,
                'size': f'{size_bytes / 1048576:.0f} MB' if size_bytes > 1048576 else f'{size_bytes / 1024:.0f} KB',
                'size_bytes': size_bytes,
                'version': image_version_from_name(name),
                'path': f,
            })
    images.sort(key=lambda x: x['name'])
    return images

def get_device_version(device):
    ip = device.get('ip', '')
    hostname = device.get('hostname', ip)
    username = device.get('username', 'cumulus')
    result = {
        'ip': ip,
        'hostname': hostname,
        'username': username,
        'role': device.get('role', ''),
        'reachable': False,
        'current_version': '',
        'startup_config': False,
        'base_deployed': False,
        'error': '',
    }
    try:
        cmd = (
            "echo OK; "
            "(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || grep 'RELEASE' /etc/lsb-release 2>/dev/null | cut -d= -f2 || true); "
            "test -s /etc/nvue.d/startup.yaml && echo STARTUP_OK || echo STARTUP_MISSING; "
            "test -f /etc/lldpq-base-deployed && echo BASE_DEPLOYED || echo BASE_PENDING"
        )
        r = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
             '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
             '-o', 'LogLevel=ERROR', f'{username}@{ip}', cmd],
            capture_output=True, text=True, timeout=12
        )
        if r.returncode != 0 or 'OK' not in r.stdout:
            result['error'] = (r.stderr or 'SSH failed').strip()[:200]
            return result
        lines = [x.strip() for x in r.stdout.splitlines() if x.strip()]
        result['reachable'] = True
        for line in lines:
            if line != 'OK' and not line.startswith('STARTUP_') and not line.startswith('BASE_'):
                result['current_version'] = line
                break
        result['startup_config'] = 'STARTUP_OK' in lines
        result['base_deployed'] = 'BASE_DEPLOYED' in lines
        return result
    except Exception as e:
        result['error'] = str(e)[:200]
        return result

def action_upgrade_candidates():
    devices = []
    data_holder = {}
    # Reuse devices.yaml parsing logic from list-devices without emitting JSON.
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        error_json(f"devices.yaml not found at {devices_file}")
    try:
        import yaml
        with open(devices_file, 'r') as f:
            raw = yaml.safe_load(f) or {}
        defaults = raw.get('defaults', {})
        default_username = defaults.get('username', 'cumulus')
        for ip, info in raw.get('devices', raw).items():
            if ip in ('defaults', 'endpoint_hosts'):
                continue
            role = 'ungrouped'
            if isinstance(info, dict):
                hostname = info.get('hostname', str(ip))
                username = info.get('username', default_username)
                role = info.get('role', 'ungrouped')
            elif isinstance(info, str):
                parts = info.strip().split('@')
                hostname = parts[0].strip()
                role = parts[1].strip() if len(parts) > 1 else 'ungrouped'
                username = default_username
            else:
                hostname = str(info) if info else str(ip)
                username = default_username
            devices.append({'ip': str(ip), 'hostname': hostname, 'username': username, 'role': role})
    except Exception as e:
        error_json(str(e))

    candidates = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(get_device_version, d): d for d in devices}
        for future in as_completed(futures):
            candidates.append(future.result())
    candidates.sort(key=lambda x: x.get('hostname', ''))
    result_json({'success': True, 'devices': candidates, 'images': list_os_image_objects(), 'server_ip': get_server_ip()})

def run_upgrade_precheck(device, target_version, image_name, server_ip):
    info = get_device_version(device)
    info['target_version'] = target_version
    info['precheck_ok'] = False
    checks = []
    if not info['reachable']:
        checks.append('SSH failed')
    if not info.get('current_version'):
        checks.append('Current version unknown')
    if info.get('current_version') == target_version:
        checks.append('Already at target')
    if not info.get('startup_config'):
        checks.append('startup.yaml missing')
    if not os.path.exists(os.path.join(WEB_ROOT, image_name)):
        checks.append('Image missing on server')
    if not is_valid_server_ref(server_ip):
        checks.append('Invalid image server')
    if not checks:
        try:
            r = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
                 '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                 '-o', 'LogLevel=ERROR', f"{device.get('username','cumulus')}@{device.get('ip')}",
                 'sudo nv config save && test -s /etc/nvue.d/startup.yaml && echo PRECHECK_OK'],
                capture_output=True, text=True, timeout=25
            )
            if r.returncode == 0 and 'PRECHECK_OK' in r.stdout:
                info['precheck_ok'] = True
                checks.append('OK')
            else:
                checks.append((r.stderr or 'nv config save failed').strip()[:200])
        except Exception as e:
            checks.append(str(e)[:200])
    info['checks'] = checks
    return info

def action_upgrade_precheck():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    devices = data.get('devices', [])
    target_version = data.get('target_version', '').strip()
    image_name = os.path.basename(data.get('image_name', ''))
    server_ip = data.get('server_ip', '').strip()
    if not devices or not target_version or not image_name or not server_ip:
        error_json('devices, target_version, image_name and server_ip are required')
    if not re.match(r'^[A-Za-z0-9_.-]+\.(bin|img|iso)$', image_name):
        error_json('Invalid image filename')
    if not is_valid_server_ref(server_ip):
        error_json('Invalid image server. Set a real ZTP IMAGE SERVER IP first.')
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(run_upgrade_precheck, d, target_version, image_name, server_ip): d for d in devices}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda x: x.get('hostname', ''))
    result_json({'success': True, 'results': results})

def ensure_upgrade_jobs_dir():
    os.makedirs(UPGRADE_JOBS_DIR, exist_ok=True)
    try:
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', UPGRADE_JOBS_DIR], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '775', UPGRADE_JOBS_DIR], capture_output=True, timeout=5)
    except Exception:
        pass

def job_path(job_id):
    if not re.match(r'^[a-f0-9-]{36}$', job_id):
        error_json('Invalid job id')
    return os.path.join(UPGRADE_JOBS_DIR, f'{job_id}.json')

def save_upgrade_job(job):
    ensure_upgrade_jobs_dir()
    path = job_path(job['id'])
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(job, f, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o664)
    except Exception:
        pass

def load_upgrade_job(job_id):
    path = job_path(job_id)
    if not os.path.exists(path):
        error_json('Upgrade job not found')
    with open(path, 'r') as f:
        return json.load(f)

def start_upgrade_for_device(dev, image_url, ztp_url):
    ip = dev.get('ip')
    username = dev.get('username', 'cumulus')
    remote = r'''
set -e
IMAGE_URL="$1"
ZTP_URL="$2"
sudo nv config save
test -s /etc/nvue.d/startup.yaml
sudo sh -c "nohup /usr/cumulus/bin/onie-install -fa -i $IMAGE_URL -z $ZTP_URL -t /etc/nvue.d/startup.yaml && reboot" >/tmp/lldpq-upgrade.log 2>&1 </dev/null &
echo LLDPQ_UPGRADE_STARTED
'''
    r = subprocess.run(
        ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
         '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
         '-o', 'LogLevel=ERROR', f'{username}@{ip}', 'bash -s --', image_url, ztp_url],
        input=remote, capture_output=True, text=True, timeout=35
    )
    return r.returncode == 0 and 'LLDPQ_UPGRADE_STARTED' in r.stdout, (r.stderr or r.stdout).strip()[:300]

def update_upgrade_job(job):
    now = time.time()
    image_url = f"http://{job['server_ip']}/{job['image_name']}"
    ztp_url = f"http://{job['server_ip']}/cumulus-ztp.sh"

    # Refresh active devices.
    for dev in job['devices']:
        if dev['status'] not in ('upgrading', 'waiting_reboot'):
            continue
        if now - dev.get('started_at', now) > job.get('timeout_seconds', 3600):
            dev['status'] = 'failed'
            dev['error'] = 'Upgrade timeout'
            continue
        info = get_device_version(dev)
        dev['last_check'] = int(now)
        dev['reachable'] = info.get('reachable', False)
        dev['current_version'] = info.get('current_version', dev.get('current_version', ''))
        if info.get('current_version') == job['target_version']:
            if job.get('base_config_after', True):
                files = [f for f in FILE_DEPLOY_MAP if os.path.exists(os.path.join(BASE_CONFIG_DIR, f))]
                res = deploy_to_device(dev, files, True)
                if res.get('success'):
                    dev['status'] = 'done'
                    dev['message'] = 'Upgraded and base config deployed'
                else:
                    dev['status'] = 'failed'
                    dev['error'] = 'Upgrade OK, base config failed: ' + res.get('error', '')
            else:
                dev['status'] = 'done'
                dev['message'] = 'Upgraded'
        else:
            dev['status'] = 'waiting_reboot'

    active = [d for d in job['devices'] if d['status'] in ('upgrading', 'waiting_reboot')]
    failed = [d for d in job['devices'] if d['status'] == 'failed']
    if job.get('cancelled'):
        for d in job['devices']:
            if d['status'] == 'queued':
                d['status'] = 'cancelled'
        return job
    if job.get('stop_on_failure', True) and failed:
        for d in job['devices']:
            if d['status'] == 'queued':
                d['status'] = 'blocked'
        return job
    slots = max(0, int(job.get('batch_size', 1)) - len(active))
    for dev in [d for d in job['devices'] if d['status'] == 'queued'][:slots]:
        ok, detail = start_upgrade_for_device(dev, image_url, ztp_url)
        dev['started_at'] = int(now)
        if ok:
            dev['status'] = 'upgrading'
            dev['message'] = 'Upgrade command started'
        else:
            dev['status'] = 'failed'
            dev['error'] = detail or 'Failed to start upgrade'
    if all(d['status'] in ('done', 'failed', 'cancelled', 'blocked') for d in job['devices']):
        job['complete'] = True
        job['completed_at'] = int(now)
    return job

def ensure_onie_symlinks(image_name):
    """Point the generic ONIE HTTP-discovery fallback names at the selected upgrade image.

    Some switches, after `onie-install -fa`, reboot into ONIE and re-run the default HTTP
    "waterfall" discovery against the image-server root instead of using the -i URL. That waterfall
    always descends to the arch / silicon-vendor / generic names, so serving those (as symlinks to
    the chosen image) makes the upgrade robust. Generic only — NO per-platform hardcoding — so it
    covers every x86_64 NVIDIA/Mellanox switch (SN2201, SN5600D, ...) uniformly:
      onie-installer-x86_64-mlnx  (silicon-vendor fallback — all Spectrum switches)
      onie-installer-x86_64       (arch fallback — all x86_64)
      onie-installer              (final generic)
    Extension-less only: ONIE tries "<name>" before "<name>.bin" at every level, so these are
    served first — and they don't collide with the OS-image list (which globs *.bin).
    """
    if not re.match(r'^[A-Za-z0-9_.-]+\.(bin|img|iso)$', image_name or ''):
        return []
    if not os.path.exists(os.path.join(WEB_ROOT, image_name)):
        return []
    # Only the extension-less names: ONIE requests "<name>" before "<name>.bin" at every waterfall
    # level, so the plain names are always served first. Skipping the .bin variants also keeps them
    # out of the OS-image list (which globs *.bin).
    names = [
        'onie-installer-x86_64',
        'onie-installer-x86_64-mlnx',
        'onie-installer',
    ]
    created = []
    for n in names:
        link = os.path.join(WEB_ROOT, n)
        try:
            if os.path.islink(link) or os.path.exists(link):
                os.remove(link)
            os.symlink(image_name, link)          # relative target (same dir as the image)
            created.append(n)
        except Exception:
            # www-data may not own the web root -> create via the service user (bash is whitelisted)
            rc = subprocess.run(['sudo', '-u', LLDPQ_USER, 'bash', '-c',
                                 'ln -sfn "%s" "%s"' % (image_name, link)],
                                capture_output=True, timeout=10)
            if rc.returncode == 0:
                created.append(n)
    return created


def action_upgrade_start():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    devices = data.get('devices', [])
    target_version = data.get('target_version', '').strip()
    image_name = os.path.basename(data.get('image_name', ''))
    server_ip = data.get('server_ip', '').strip()
    if not devices or not target_version or not image_name or not server_ip:
        error_json('devices, target_version, image_name and server_ip are required')
    if not re.match(r'^[A-Za-z0-9_.-]+\.(bin|img|iso)$', image_name):
        error_json('Invalid image filename')
    if not is_valid_server_ref(server_ip):
        error_json('Invalid image server. Set a real ZTP IMAGE SERVER IP first.')
    if not os.path.exists(os.path.join(WEB_ROOT, image_name)):
        error_json('Selected image not found on server')
    # Point the generic ONIE discovery fallback names at this image, so switches whose ONIE re-runs
    # HTTP waterfall discovery during the -fa install still find it (see ensure_onie_symlinks).
    ensure_onie_symlinks(image_name)
    if not os.path.exists(ZTP_SCRIPT_FILE):
        error_json('cumulus-ztp.sh not found in web root')
    with open(ZTP_SCRIPT_FILE, 'r') as f:
        ztp_content = f.read()
    if '__IMAGE_SERVER_IP__' in ztp_content or '__TARGET_OS_VERSION__' in ztp_content:
        error_json('cumulus-ztp.sh still contains placeholders. Apply Quick Settings and save ZTP script before upgrade.')
    if re.search(r'^\s*KEY=["\']?["\']?\s*$', ztp_content, re.MULTILINE) or not re.search(r'^\s*KEY=["\']ssh-', ztp_content, re.MULTILINE):
        error_json('cumulus-ztp.sh has no SSH key. Generate/import SSH key, Apply to Script, then Save before upgrade.')
    job = {
        'id': str(uuid.uuid4()),
        'created_at': int(time.time()),
        'target_version': target_version,
        'image_name': image_name,
        'server_ip': server_ip,
        'batch_size': max(1, min(int(data.get('batch_size', 1) or 1), 100)),
        'stop_on_failure': data.get('stop_on_failure', True),
        'base_config_after': data.get('base_config_after', True),
        'timeout_seconds': 3600,
        'complete': False,
        'cancelled': False,
        'devices': [],
    }
    for d in devices:
        item = dict(d)
        item['status'] = 'queued'
        item['target_version'] = target_version
        job['devices'].append(item)
    job = update_upgrade_job(job)
    save_upgrade_job(job)
    result_json({'success': True, 'job': job})

def action_upgrade_status():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    job = load_upgrade_job(data.get('job_id', ''))
    job = update_upgrade_job(job)
    save_upgrade_job(job)
    result_json({'success': True, 'job': job})

def action_upgrade_cancel():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    job = load_upgrade_job(data.get('job_id', ''))
    job['cancelled'] = True
    job = update_upgrade_job(job)
    save_upgrade_job(job)
    result_json({'success': True, 'job': job})

# ======================== SSH KEY ========================

def get_ssh_key_info():
    """Find existing SSH key for LLDPQ_USER. Returns (pub_key_content, key_type, key_file) or (None,None,None)."""
    home = os.path.expanduser(f'~{LLDPQ_USER}')
    for key_type, key_name in [('ed25519', 'id_ed25519'), ('rsa', 'id_rsa')]:
        pub_path = os.path.join(home, '.ssh', f'{key_name}.pub')
        r = subprocess.run(['sudo', '-u', LLDPQ_USER, 'cat', pub_path],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip(), key_type, pub_path
    return None, None, None

def action_get_ssh_key():
    pub_key, key_type, key_file = get_ssh_key_info()
    if pub_key:
        result_json({"success": True, "public_key": pub_key, "key_type": key_type, "key_file": key_file})
    else:
        result_json({"success": True, "public_key": "", "key_type": "", "key_file": ""})

def action_generate_ssh_key():
    home = os.path.expanduser(f'~{LLDPQ_USER}')
    ssh_dir = os.path.join(home, '.ssh')
    key_path = os.path.join(ssh_dir, 'id_ed25519')
    pub_path = key_path + '.pub'
    
    try:
        # Generate key in /tmp as www-data (no sudo needed for ssh-keygen)
        tmp_key = '/tmp/.lldpq-keygen-tmp'
        subprocess.run(['/usr/bin/rm', '-f', tmp_key, tmp_key + '.pub'], capture_output=True, timeout=5)
        result = subprocess.run(
            ['/usr/bin/ssh-keygen', '-t', 'ed25519', '-N', '', '-f', tmp_key, '-C', f'lldpq@provision'],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            error_json(f'ssh-keygen failed: {result.stderr}')
            return
        
        with open(tmp_key, 'r') as f:
            priv_content = f.read()
        with open(tmp_key + '.pub', 'r') as f:
            pub_content = f.read()
        os.unlink(tmp_key)
        os.unlink(tmp_key + '.pub')
        
        # Place keys into LLDPQ_USER's .ssh dir
        subprocess.run(['sudo', '-n', '-u', LLDPQ_USER, '/usr/bin/mkdir', '-p', '-m', '700', ssh_dir],
            capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', '-u', LLDPQ_USER, '/usr/bin/rm', '-f', key_path, pub_path],
            capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', '-u', LLDPQ_USER, '/usr/bin/tee', key_path],
            input=priv_content, capture_output=True, text=True, timeout=5)
        subprocess.run(['sudo', '-n', '-u', LLDPQ_USER, '/usr/bin/tee', pub_path],
            input=pub_content, capture_output=True, text=True, timeout=5)
        subprocess.run(['sudo', '-n', '/usr/bin/chmod', '600', key_path], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', '/usr/bin/chmod', '644', pub_path], capture_output=True, timeout=5)
        
        result_json({"success": True, "public_key": pub_content.strip(), "key_type": "ed25519", "key_file": pub_path})
    except Exception as e:
        error_json(str(e))

def action_import_ssh_key():
    """Import an existing private key (paste from another server/setup).
    All file operations run as LLDPQ_USER via sudo to ensure correct ownership.
    """
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    private_key = data.get('private_key', '').strip()
    if not private_key or 'PRIVATE KEY' not in private_key:
        error_json("Invalid private key")
    
    # Ensure newline at end
    if not private_key.endswith('\n'):
        private_key += '\n'
    
    home = os.path.expanduser(f'~{LLDPQ_USER}')
    ssh_dir = os.path.join(home, '.ssh')
    
    # Detect key type from content
    if 'ed25519' in private_key.lower() or 'ED25519' in private_key:
        key_name = 'id_ed25519'
        key_type = 'ed25519'
    elif 'RSA' in private_key:
        key_name = 'id_rsa'
        key_type = 'rsa'
    else:
        key_name = 'id_ed25519'
        key_type = 'unknown'
    
    key_path = os.path.join(ssh_dir, key_name)
    pub_path = key_path + '.pub'
    
    try:
        # Create .ssh dir as LLDPQ_USER (www-data can't write to user's home)
        subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'mkdir', '-p', ssh_dir],
            capture_output=True, timeout=5)
        subprocess.run(
            ['sudo', 'chmod', '700', ssh_dir],
            capture_output=True, timeout=5)
        
        # Write private key via sudo tee (www-data can't write to LLDPQ_USER's .ssh)
        proc = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'tee', key_path],
            input=private_key, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            error_json(f"Failed to write private key: {proc.stderr.strip()[:200]}")
        subprocess.run(['sudo', 'chmod', '600', key_path], capture_output=True, timeout=5)
        
        # Extract public key from private key
        result = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh-keygen', '-y', '-f', key_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            pub_content = result.stdout.strip() + f' {LLDPQ_USER}@imported\n'
            subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'tee', pub_path],
                input=pub_content, capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'chmod', '644', pub_path], capture_output=True, timeout=5)
        else:
            # Clean up on failure
            subprocess.run(['sudo', 'rm', '-f', key_path], capture_output=True, timeout=5)
            error_json(f"Invalid private key: {result.stderr.strip()[:200]}")
        
        # Fix ownership (with sudo)
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:{LLDPQ_USER}', key_path, pub_path],
                       capture_output=True, timeout=5)
        
        # Read public key
        r = subprocess.run(['sudo', '-u', LLDPQ_USER, 'cat', pub_path],
                          capture_output=True, text=True, timeout=5)
        pub_key = r.stdout.strip() if r.returncode == 0 else ''
        
        result_json({"success": True, "public_key": pub_key, "key_type": key_type, "key_file": pub_path})
    except Exception as e:
        error_json(str(e))

# ======================== OS IMAGES ========================

def action_list_os_images():
    """List Cumulus Linux image files in web root."""
    result_json({"success": True, "images": list_os_image_objects()})

def action_upload_os_image():
    """Handle multipart file upload for OS images.
    Reads directly from stdin (bash wrapper skips reading for multipart).
    Streams to temp file to avoid memory issues with large images.
    """
    content_type = os.environ.get('CONTENT_TYPE', '')
    
    if 'multipart/form-data' not in content_type:
        error_json("Expected multipart/form-data upload")
    
    # Parse boundary
    boundary = content_type.split('boundary=')[-1].strip()
    boundary_bytes = f'--{boundary}'.encode()
    
    # Read from stdin (not consumed by bash wrapper for multipart)
    content_length = int(os.environ.get('CONTENT_LENGTH', '0'))
    if content_length <= 0:
        error_json("No file data received (CONTENT_LENGTH=0)")
    
    # Stream stdin to temp file, then extract file body directly to destination
    # (avoids loading entire file into RAM for large OS images)
    import tempfile
    tmp_upload = None
    try:
        tmp_upload = tempfile.NamedTemporaryFile(delete=False, suffix='.upload')
        remaining = content_length
        buf_size = 65536  # 64KB chunks
        while remaining > 0:
            chunk = sys.stdin.buffer.read(min(buf_size, remaining))
            if not chunk:
                break
            tmp_upload.write(chunk)
            remaining -= len(chunk)
        tmp_upload.close()
    except Exception as e:
        if tmp_upload:
            try: os.unlink(tmp_upload.name)
            except: pass
        error_json(f"Failed to read upload data: {e}")
    
    # Find file part boundaries by reading only the header portions
    # (the multipart headers are small, only the file body is large)
    with open(tmp_upload.name, 'rb') as f:
        # Read first 8KB to find headers (boundary + Content-Disposition + blank line)
        head = f.read(8192)
        
        # Find the file part
        boundary_pos = head.find(boundary_bytes)
        if boundary_pos < 0:
            try: os.unlink(tmp_upload.name)
            except: pass
            error_json("No file found in upload (bad boundary)")
        
        # Find filename in headers
        fn_match = re.search(rb'filename="([^"]+)"', head)
        if not fn_match:
            try: os.unlink(tmp_upload.name)
            except: pass
            error_json("No filename in upload")
        filename = os.path.basename(fn_match.group(1).decode('latin-1'))
        
        # Validate extension
        if not any(filename.endswith(ext) for ext in ['.bin', '.img', '.iso']):
            try: os.unlink(tmp_upload.name)
            except: pass
            error_json(f"Invalid file type: {filename}. Only .bin, .img, .iso allowed.")
        
        # Find the end of headers (blank line = \r\n\r\n)
        body_start = head.find(b'\r\n\r\n', boundary_pos)
        if body_start < 0:
            try: os.unlink(tmp_upload.name)
            except: pass
            error_json("Malformed multipart upload")
        body_start += 4  # skip \r\n\r\n
    
    # Calculate file body size (total - header - trailing boundary)
    total_size = os.path.getsize(tmp_upload.name)
    # Trailing boundary is: \r\n--boundary--\r\n (approx)
    trailing_size = len(boundary_bytes) + 8  # generous estimate
    file_size = total_size - body_start - trailing_size
    if file_size < 0:
        file_size = total_size - body_start
    
    # Stream file body from temp to destination (chunk by chunk, no full RAM load)
    dest = os.path.join(WEB_ROOT, filename)
    try:
        with open(tmp_upload.name, 'rb') as src, open(dest, 'wb') as dst:
            src.seek(body_start)
            written = 0
            while written < file_size:
                chunk = src.read(min(65536, file_size - written))
                if not chunk:
                    break
                dst.write(chunk)
                written += len(chunk)
        # Trim any trailing boundary bytes from the end of the file
        # (read last 256 bytes and check for boundary)
        with open(dest, 'r+b') as f:
            f.seek(max(0, written - 256))
            tail = f.read()
            boundary_idx = tail.rfind(b'\r\n' + boundary_bytes)
            if boundary_idx >= 0:
                f.seek(max(0, written - 256) + boundary_idx)
                f.truncate()
        os.chmod(dest, 0o664)
        final_size = os.path.getsize(dest)
        try: os.unlink(tmp_upload.name)
        except: pass
        result_json({"success": True, "message": f"Uploaded {filename}", "size": final_size})
    except PermissionError:
        # Fallback: use sudo cp from temp file (body already extracted)
        subprocess.run(['sudo', 'cp', tmp_upload.name, dest], capture_output=True, timeout=300)
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', dest], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '664', dest], capture_output=True, timeout=5)
        try: os.unlink(tmp_upload.name)
        except: pass
        if os.path.exists(dest):
            result_json({"success": True, "message": f"Uploaded {filename} (via sudo)"})
        else:
            error_json("Write failed: permission denied")
    except Exception as e:
        try: os.unlink(tmp_upload.name)
        except: pass
        error_json(f"Upload failed: {e}")
    
    if tmp_upload:
        try: os.unlink(tmp_upload.name)
        except: pass
    error_json("No file found in upload")

def action_delete_os_image():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    name = data.get('name', '')
    if not name or '/' in name or '..' in name:
        error_json("Invalid filename")
    
    filepath = os.path.join(WEB_ROOT, name)
    if not os.path.exists(filepath):
        error_json(f"File not found: {name}")
    
    try:
        os.remove(filepath)
    except PermissionError:
        subprocess.run(['sudo', 'rm', '-f', filepath], capture_output=True, timeout=5)
    
    result_json({"success": True, "message": f"Deleted {name}"})

# ======================== SERIAL MAPPING ========================

def action_get_serial_mapping():
    """Read serial-mapping.txt and return as structured data."""
    mappings = []
    if os.path.exists(SERIAL_MAPPING_FILE):
        with open(SERIAL_MAPPING_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    mappings.append({'serial': parts[0], 'hostname': parts[1]})
    result_json({"success": True, "mappings": mappings, "file": SERIAL_MAPPING_FILE})

def action_save_serial_mapping():
    """Save serial-mapping.txt from structured data."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    mappings = data.get('mappings', [])
    lines = ["# Serial → Hostname mapping for ZTP config resolution",
             "# Format: SERIAL_NUMBER  HOSTNAME",
             ""]
    for m in mappings:
        serial = m.get('serial', '').strip()
        hostname = m.get('hostname', '').strip()
        if serial and hostname:
            lines.append(f"{serial}  {hostname}")

    content = '\n'.join(lines) + '\n'
    written = False
    try:
        with open(SERIAL_MAPPING_FILE, 'w') as f:
            f.write(content)
        written = True
    except PermissionError:
        pass

    if not written:
        subprocess.run(['sudo', '-u', LLDPQ_USER, 'tee', SERIAL_MAPPING_FILE],
                       input=content, capture_output=True, text=True, timeout=10)

    subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', SERIAL_MAPPING_FILE],
                   capture_output=True, timeout=5)
    subprocess.run(['sudo', 'chmod', '664', SERIAL_MAPPING_FILE],
                   capture_output=True, timeout=5)

    result_json({"success": True, "message": f"Saved {len(mappings)} mapping(s)"})

# ======================== GENERATED CONFIGS ========================

def action_list_generated_configs():
    """List YAML config files in generated_config_folder."""
    configs = []
    if os.path.isdir(GENERATED_CONFIGS_DIR):
        for f in sorted(os.listdir(GENERATED_CONFIGS_DIR)):
            if f.endswith(('.yaml', '.yml')):
                filepath = os.path.join(GENERATED_CONFIGS_DIR, f)
                stat = os.stat(filepath)
                hostname = f.rsplit('.', 1)[0]
                configs.append({
                    'filename': f,
                    'hostname': hostname,
                    'size': stat.st_size,
                    'mtime': int(stat.st_mtime)
                })
    result_json({"success": True, "configs": configs, "dir": GENERATED_CONFIGS_DIR})

def action_sync_generated_configs():
    """Copy generated configs from Ansible directory to web root."""
    ansible_dir = os.environ.get('ANSIBLE_DIR', '')
    if not ansible_dir:
        # Try reading from lldpq.conf
        try:
            with open('/etc/lldpq.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('ANSIBLE_DIR='):
                        ansible_dir = line.strip().split('=', 1)[1].strip('"').strip("'")
                        break
        except Exception:
            pass

    if not ansible_dir:
        error_json("ANSIBLE_DIR not configured. Set it in /etc/lldpq.conf or configure Ansible directory in install.sh")

    src_dir = os.path.join(ansible_dir, 'files', 'generated_config_folder')
    if not os.path.isdir(src_dir):
        error_json(f"Source directory not found: {src_dir}")

    # Ensure destination exists
    os.makedirs(GENERATED_CONFIGS_DIR, exist_ok=True)

    copied = 0
    errors = []
    for f in os.listdir(src_dir):
        if f.endswith(('.yaml', '.yml')):
            src = os.path.join(src_dir, f)
            dst = os.path.join(GENERATED_CONFIGS_DIR, f)
            try:
                import shutil
                shutil.copy2(src, dst)
                os.chmod(dst, 0o664)
                copied += 1
            except PermissionError:
                subprocess.run(['sudo', 'cp', src, dst], capture_output=True, timeout=5)
                subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', dst],
                               capture_output=True, timeout=5)
                subprocess.run(['sudo', 'chmod', '664', dst], capture_output=True, timeout=5)
                copied += 1
            except Exception as e:
                errors.append(f"{f}: {str(e)}")

    # Fix directory permissions
    try:
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', GENERATED_CONFIGS_DIR],
                       capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '775', GENERATED_CONFIGS_DIR],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    msg = f"Synced {copied} config(s) from {src_dir}"
    if errors:
        msg += f" ({len(errors)} error(s))"
    result_json({"success": True, "message": msg, "copied": copied, "errors": errors})

def action_upload_generated_config():
    """Upload a single YAML config file to generated_config_folder."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    filename = data.get('filename', '')
    content = data.get('content', '')

    if not filename or not content:
        error_json("Missing filename or content")
    if not filename.endswith(('.yaml', '.yml')):
        error_json("Only .yaml/.yml files allowed")
    if '/' in filename or '..' in filename:
        error_json("Invalid filename")

    # Ensure directory exists with correct permissions
    if not os.path.isdir(GENERATED_CONFIGS_DIR):
        try:
            os.makedirs(GENERATED_CONFIGS_DIR, exist_ok=True)
        except PermissionError:
            subprocess.run(['sudo', 'mkdir', '-p', GENERATED_CONFIGS_DIR], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', GENERATED_CONFIGS_DIR], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '775', GENERATED_CONFIGS_DIR], capture_output=True, timeout=5)

    dest = os.path.join(GENERATED_CONFIGS_DIR, filename)

    written = False
    try:
        with open(dest, 'w') as f:
            f.write(content)
        written = True
    except PermissionError:
        pass

    if not written:
        subprocess.run(['sudo', '-u', LLDPQ_USER, 'tee', dest],
                       input=content, capture_output=True, text=True, timeout=10)

    subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', dest], capture_output=True, timeout=5)
    subprocess.run(['sudo', 'chmod', '664', dest], capture_output=True, timeout=5)

    result_json({"success": True, "message": f"Uploaded {filename}"})

# ======================== DEPLOY GENERATED CONFIG ========================

def deploy_config_to_device(ip, hostname, server_ip):
    """SSH into switch, curl config from web server, nv config replace/apply/save."""
    config_url = f"http://{server_ip}/generated_config_folder/{hostname}.yaml"
    ssh_opts = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'LogLevel=ERROR']

    remote_cmd = (
        f'curl -sf {config_url} -o /tmp/startup.yaml && '
        f'test -s /tmp/startup.yaml && '
        f'sudo nv config replace /tmp/startup.yaml && '
        f'sudo nv config apply -y && '
        f'sudo nv config save && '
        f'rm -f /tmp/startup.yaml'
    )

    try:
        r = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts + [f'cumulus@{ip}', remote_cmd],
            capture_output=True, text=True, timeout=120
        )
        if r.returncode == 0:
            return {'ip': ip, 'hostname': hostname, 'success': True, 'message': 'Config applied'}
        return {'ip': ip, 'hostname': hostname, 'success': False, 'error': r.stderr.strip()[:200] or 'Command failed'}
    except subprocess.TimeoutExpired:
        return {'ip': ip, 'hostname': hostname, 'success': False, 'error': 'Timeout (120s)'}
    except Exception as e:
        return {'ip': ip, 'hostname': hostname, 'success': False, 'error': str(e)}

def action_deploy_generated_config():
    """Deploy generated NVUE config to one or more switches via SSH."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    devices = data.get('devices', [])
    # Single device shorthand
    if not devices and data.get('hostname') and data.get('ip'):
        devices = [{'hostname': data['hostname'], 'ip': data['ip']}]

    if not devices:
        error_json("No devices specified")

    server_ip = get_server_ip()
    if not server_ip or server_ip == '127.0.0.1':
        error_json("Cannot determine server IP for config download")

    # Validate configs exist
    for dev in devices:
        config_path = os.path.join(GENERATED_CONFIGS_DIR, f"{dev['hostname']}.yaml")
        if not os.path.exists(config_path):
            # Try .yml
            config_path = os.path.join(GENERATED_CONFIGS_DIR, f"{dev['hostname']}.yml")
            if not os.path.exists(config_path):
                error_json(f"No generated config found for {dev['hostname']}")

    # Deploy in parallel
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(deploy_config_to_device, dev['ip'], dev['hostname'], server_ip): dev
            for dev in devices
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x['hostname'])
    ok = sum(1 for r in results if r['success'])
    fail = len(results) - ok

    result_json({
        "success": True,
        "results": results,
        "summary": {"ok": ok, "fail": fail, "total": len(results)}
    })

# ======================== UPDATE ROLE ========================

def action_update_role():
    """Update device role in devices.yaml. Adds @role suffix or updates existing."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    hostname = data.get('hostname', '').strip()
    ip = data.get('ip', '').strip()
    role = data.get('role', '').strip().lower()
    
    if not hostname:
        error_json("Hostname required")
    
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        error_json("devices.yaml not found")
    
    try:
        # Read with ruamel.yaml to preserve comments
        from ruamel.yaml import YAML
        yaml = YAML()
        yaml.preserve_quotes = True
        
        with open(devices_file, 'r') as f:
            ddata = yaml.load(f)
        
        if not ddata:
            ddata = {}
        
        devices = ddata.get('devices', ddata)
        
        # Find the device by hostname
        found = False
        for dev_ip, info in devices.items():
            if dev_ip in ('defaults', 'endpoint_hosts'):
                continue
            if isinstance(info, str):
                # Parse "Hostname @role" format
                import re
                m = re.match(r'^(.+?)\s+@\w+$', info.strip())
                h = m.group(1).strip() if m else info.strip()
                if h == hostname:
                    # Update: set new value with role
                    if role:
                        devices[dev_ip] = f"{hostname} @{role}"
                    else:
                        devices[dev_ip] = hostname
                    found = True
                    break
            elif isinstance(info, dict):
                if info.get('hostname', '') == hostname:
                    if role:
                        info['role'] = role
                    elif 'role' in info:
                        del info['role']
                    found = True
                    break
        
        # If not found and we have IP, add it
        if not found and ip:
            if role:
                devices[ip] = f"{hostname} @{role}"
            else:
                devices[ip] = hostname
            found = True
        
        if not found:
            error_json(f"Device {hostname} not found in devices.yaml")
        
        # Write back
        try:
            with open(devices_file, 'w') as f:
                yaml.dump(ddata, f)
        except PermissionError:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
                yaml.dump(ddata, tmp)
                tmp_path = tmp.name
            subprocess.run(['sudo', 'cp', tmp_path, devices_file], capture_output=True, timeout=5)
            os.unlink(tmp_path)
        
        result_json({"success": True, "message": f"Role updated: {hostname} -> {role or '(none)'}"})
    
    except ImportError:
        # Fallback: use pyyaml (no comment preservation)
        import yaml as pyyaml
        with open(devices_file, 'r') as f:
            ddata = pyyaml.safe_load(f) or {}
        
        devices = ddata.get('devices', ddata)
        found = False
        for dev_ip, info in list(devices.items()):
            if dev_ip in ('defaults', 'endpoint_hosts'):
                continue
            if isinstance(info, str):
                import re
                m = re.match(r'^(.+?)\s+@\w+$', info.strip())
                h = m.group(1).strip() if m else info.strip()
                if h == hostname:
                    devices[dev_ip] = f"{hostname} @{role}" if role else hostname
                    found = True
                    break
            elif isinstance(info, dict) and info.get('hostname', '') == hostname:
                if role:
                    info['role'] = role
                elif 'role' in info:
                    del info['role']
                found = True
                break
        
        if not found and ip:
            devices[ip] = f"{hostname} @{role}" if role else hostname
            found = True
        
        if found:
            with open(devices_file, 'w') as f:
                pyyaml.dump(ddata, f, default_flow_style=False, allow_unicode=True)
            result_json({"success": True, "message": f"Role updated: {hostname} -> {role or '(none)'}"})
        else:
            error_json(f"Device {hostname} not found")
    
    except Exception as e:
        error_json(f"Failed to update role: {str(e)}")

# ======================== LIST ROLES ========================

def action_rebuild_devices_yaml():
    """Rebuild devices.yaml from inventory bindings.
    - Grouped by role (comment header per group)
    - Sorted by IP within each group
    - Active entries: normal YAML lines
    - Planned entries (no valid MAC): commented with #
    - Entries without role: placed in 'ungrouped' section
    - Preserves defaults and endpoint_hosts from existing file
    """
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    
    bindings = data.get('bindings', [])
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    
    # Read existing file to preserve defaults, endpoint_hosts, and header
    defaults_username = 'cumulus'
    endpoint_hosts = []
    if os.path.exists(devices_file):
        try:
            import yaml
            with open(devices_file, 'r') as f:
                existing = yaml.safe_load(f) or {}
            d = existing.get('defaults', {})
            if isinstance(d, dict) and d.get('username'):
                defaults_username = d['username']
            eh = existing.get('endpoint_hosts', [])
            if isinstance(eh, list):
                endpoint_hosts = eh
        except Exception:
            pass
    
    # Group bindings by role, sort by IP within each group
    from collections import defaultdict
    groups = defaultdict(list)
    for b in bindings:
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        if not hostname or not ip:
            continue
        role = b.get('role', '').strip() or 'ungrouped'
        # Use inv_status to decide: active/discovered → normal line, planned → commented
        # Static IP devices (dhcp=false) without MAC can still be active
        is_planned = b.get('inv_status', '') == 'planned'
        groups[role].append({
            'hostname': hostname,
            'ip': ip,
            'role': role,
            'planned': is_planned,
            'ip_num': sum(int(p) * (256 ** (3 - i)) for i, p in enumerate(ip.split('.'))) if ip.count('.') == 3 else 0,
        })
    
    # Sort groups alphabetically, sort entries by IP within each group
    sorted_roles = sorted(groups.keys())
    
    # Build YAML content
    lines = []
    lines.append('# devices.yaml — Auto-generated from Provision Inventory')
    lines.append(f'# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append('#')
    lines.append('')
    lines.append('defaults:')
    lines.append(f'  username: {defaults_username}')
    lines.append('')
    lines.append('devices:')
    
    active_count = 0
    planned_count = 0
    
    for role in sorted_roles:
        entries = sorted(groups[role], key=lambda e: e['ip_num'])
        lines.append('')
        lines.append(f'  # {role}')
        for e in entries:
            role_suffix = f" @{e['role']}" if e['role'] != 'ungrouped' else ''
            if e['planned']:
                lines.append(f"#  {e['ip']}: {e['hostname']}{role_suffix}")
                planned_count += 1
            else:
                lines.append(f"  {e['ip']}: {e['hostname']}{role_suffix}")
                active_count += 1
    
    # Preserve endpoint_hosts
    if endpoint_hosts:
        lines.append('')
        lines.append('endpoint_hosts:')
        for eh in endpoint_hosts:
            lines.append(f'- "{eh}"')
    
    lines.append('')
    content = '\n'.join(lines)
    
    # Write with backup
    backup_path = None
    if os.path.exists(devices_file):
        backup_path = f"{devices_file}.bak"
        try:
            import shutil
            shutil.copy2(devices_file, backup_path)
        except Exception:
            pass
    
    try:
        with open(devices_file, 'w') as f:
            f.write(content)
    except PermissionError:
        proc = subprocess.run(['sudo', 'tee', devices_file],
                            input=content, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            error_json(f"Failed to write: {proc.stderr}")
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', devices_file], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '664', devices_file], capture_output=True, timeout=5)
    
    msg = f"devices.yaml rebuilt: {active_count} active, {planned_count} planned (commented)"
    if backup_path:
        msg += f". Backup: {os.path.basename(backup_path)}"
    result_json({"success": True, "message": msg, "active": active_count, "planned": planned_count})

def action_list_roles():
    """List all unique roles from devices.yaml for dropdown population."""
    roles = set()
    try:
        devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_file):
            import yaml
            with open(devices_file, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            devices_section = ddata.get('devices', ddata)
            if isinstance(devices_section, dict):
                for ip, info in devices_section.items():
                    if ip in ('defaults', 'endpoint_hosts'):
                        continue
                    if isinstance(info, str):
                        m = re.match(r'^.+?\s+@(\w+)$', info.strip())
                        if m:
                            roles.add(m.group(1).lower())
                    elif isinstance(info, dict):
                        r = info.get('role', '')
                        if r:
                            roles.add(r.lower())
    except Exception:
        pass
    # Also include roles from inventory.json
    try:
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, 'r') as f:
                inv = json.load(f)
            for b in inv.get('bindings', []):
                r = b.get('role', '').strip().lower()
                if r:
                    roles.add(r)
    except Exception:
        pass
    result_json({"success": True, "roles": sorted(roles)})

# ======================== ZTP TAB BULK LOAD ========================

def action_load_ztp_tab():
    """Load all ZTP tab data in a single request to avoid multiple CGI startups."""
    result = {}

    # ZTP script
    try:
        if os.path.exists(ZTP_SCRIPT_FILE):
            with open(ZTP_SCRIPT_FILE, 'r') as f:
                result['ztp_script'] = {"success": True, "content": f.read(), "file": ZTP_SCRIPT_FILE}
        else:
            result['ztp_script'] = {"success": True, "content": "", "file": ZTP_SCRIPT_FILE}
    except Exception as e:
        result['ztp_script'] = {"success": False, "error": str(e)}

    # SSH key
    try:
        pub_key, key_type, key_file = get_ssh_key_info()
        result['ssh_key'] = {"success": True, "public_key": pub_key or "", "key_type": key_type or "", "key_file": key_file or ""}
    except Exception as e:
        result['ssh_key'] = {"success": False, "error": str(e)}

    # OS images
    try:
        result['os_images'] = {"success": True, "images": list_os_image_objects()}
    except Exception as e:
        result['os_images'] = {"success": False, "error": str(e)}

    # Serial mapping
    try:
        mappings = []
        if os.path.exists(SERIAL_MAPPING_FILE):
            with open(SERIAL_MAPPING_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        mappings.append({'serial': parts[0], 'hostname': parts[1]})
        result['serial_mapping'] = {"success": True, "mappings": mappings}
    except Exception as e:
        result['serial_mapping'] = {"success": False, "error": str(e)}

    # Generated configs
    try:
        configs = []
        if os.path.isdir(GENERATED_CONFIGS_DIR):
            for f in sorted(os.listdir(GENERATED_CONFIGS_DIR)):
                if f.endswith(('.yaml', '.yml')):
                    filepath = os.path.join(GENERATED_CONFIGS_DIR, f)
                    stat = os.stat(filepath)
                    configs.append({'filename': f, 'hostname': f.rsplit('.', 1)[0], 'size': stat.st_size, 'mtime': int(stat.st_mtime)})
        result['generated_configs'] = {"success": True, "configs": configs}
    except Exception as e:
        result['generated_configs'] = {"success": False, "error": str(e)}

    result['success'] = True
    result_json(result)

# ======================== ROUTER ========================

if ACTION == 'list-bindings':
    action_list_bindings()
elif ACTION == 'save-bindings':
    action_save_bindings()
elif ACTION == 'discovered':
    # Legacy: replaced by subnet-scan. Kept for backward compat.
    action_discovered()
elif ACTION == 'get-ztp-script':
    action_get_ztp_script()
elif ACTION == 'save-ztp-script':
    action_save_ztp_script()
elif ACTION == 'dhcp-service-status':
    action_dhcp_service_status()
elif ACTION == 'dhcp-service-control':
    action_dhcp_service_control()
elif ACTION == 'get-dhcp-hosts':
    hosts_path = get_dhcp_hosts_path()
    bindings = parse_dhcp_hosts(hosts_path)
    result_json({"success": True, "bindings": bindings, "file": hosts_path})
elif ACTION == 'get-dhcp-config':
    action_get_dhcp_config()
elif ACTION == 'save-dhcp-config':
    action_save_dhcp_config()
elif ACTION == 'dhcp-leases':
    action_dhcp_leases()
elif ACTION == 'dhcp-log':
    action_dhcp_log()
elif ACTION == 'list-devices':
    action_list_devices()
elif ACTION == 'deploy-base-config':
    action_deploy_base_config()
elif ACTION == 'upgrade-candidates':
    action_upgrade_candidates()
elif ACTION == 'upgrade-precheck':
    action_upgrade_precheck()
elif ACTION == 'upgrade-start':
    action_upgrade_start()
elif ACTION == 'upgrade-status':
    action_upgrade_status()
elif ACTION == 'upgrade-cancel':
    action_upgrade_cancel()
elif ACTION == 'ping-scan':
    # Legacy: replaced by subnet-scan. Kept for backward compat.
    action_ping_scan()
elif ACTION == 'subnet-scan':
    action_subnet_scan()
elif ACTION == 'discovery-cache':
    action_get_discovery_cache()
elif ACTION == 'save-post-provision':
    action_save_post_provision()
elif ACTION == 'get-ssh-key':
    action_get_ssh_key()
elif ACTION == 'generate-ssh-key':
    action_generate_ssh_key()
elif ACTION == 'import-ssh-key':
    action_import_ssh_key()
elif ACTION == 'list-os-images':
    action_list_os_images()
elif ACTION == 'upload-os-image':
    action_upload_os_image()
elif ACTION == 'delete-os-image':
    action_delete_os_image()
elif ACTION == 'get-serial-mapping':
    action_get_serial_mapping()
elif ACTION == 'save-serial-mapping':
    action_save_serial_mapping()
elif ACTION == 'list-generated-configs':
    action_list_generated_configs()
elif ACTION == 'sync-generated-configs':
    action_sync_generated_configs()
elif ACTION == 'upload-generated-config':
    action_upload_generated_config()
elif ACTION == 'deploy-generated-config':
    action_deploy_generated_config()
elif ACTION == 'load-ztp-tab':
    action_load_ztp_tab()
elif ACTION == 'update-role':
    action_update_role()
elif ACTION == 'list-roles':
    action_list_roles()
elif ACTION == 'rebuild-devices-yaml':
    action_rebuild_devices_yaml()
else:
    error_json(f"Unknown action: {ACTION}")

PYTHON_SCRIPT
