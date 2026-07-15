#!/bin/bash
# Fabric Configuration API
# Backend for fabric-config.html

# Auth guard. Most actions are admin-only; a few read-only ones (used by sidebar
# and operator-visible pages) are open to any authenticated user.
source "$(dirname "$0")/auth-guard.sh"
LLDPQ_CONFIG_WRITE_HELPER="${LLDPQ_CONFIG_WRITE_HELPER:-$(dirname "$0")/lldpq_config_write.py}"
export LLDPQ_CONFIG_WRITE_HELPER
# Shared perm-floor helper for the inventory YAML writers in the python
# heredocs below: mkstemp defaults to 0600; preserve the target's mode with a
# 0644 read floor so git/backup/ansible sweeps keep read access (same fix as
# the plan/pattern JSON writers).
LLDPQ_MODE_FLOOR_DEF='def _lldpq_mode_floor(_ffd, _fdst):
    # mkstemp defaults to 0600; keep inventory readable for git/backup sweeps
    import os as _fos
    _fmode = ((_fos.stat(_fdst).st_mode & 0o777) if _fos.path.exists(_fdst) else 0) | 0o644
    _fos.fchmod(_ffd, _fmode)'
# Shared two-phase multi-file commit for the inventory-mutating heredocs below
# (requires LLDPQ_MODE_FLOOR_DEF): dump EVERY payload to a temp file next to
# its destination first, then rename all back-to-back only after every dump
# succeeded. Renames are the only non-rollbackable step and are individually
# atomic, so a failure can no longer leave one file updated while a dependent
# file (e.g. host_vars referencing a bgp profile) was never written.
LLDPQ_ATOMIC_WRITE_DEF='def _atomic_write_many(_yaml, _writes):
    # _writes: list of (data, dst_path); stage all dumps, then rename all
    import os as _aos
    import shutil as _ash
    import tempfile as _atmp
    _staged = []
    try:
        for _data, _dst in _writes:
            _fd, _tmp = _atmp.mkstemp(dir=_aos.path.dirname(_dst), suffix=".tmp")
            _staged.append(_tmp)
            _lldpq_mode_floor(_fd, _dst)
            with _aos.fdopen(_fd, "w") as _f:
                _yaml.dump(_data, _f)
        for (_data, _dst), _tmp in zip(_writes, _staged):
            _ash.move(_tmp, _dst)
    except:
        for _tmp in _staged:
            if _aos.path.exists(_tmp):
                _aos.unlink(_tmp)
        raise'
# Shared last-resort error trap for the mutation heredocs below: an uncaught
# exception must still produce a JSON error body instead of an empty CGI
# response (the traceback keeps going to stderr for the nginx error log).
LLDPQ_JSON_EXCEPTHOOK_DEF='import sys as _hsys
def _lldpq_json_excepthook(_etype, _evalue, _etb):
    import json as _hjson
    import traceback as _htb
    _htb.print_exception(_etype, _evalue, _etb, file=_hsys.stderr)
    print(_hjson.dumps({"success": False, "error": "{}: {}".format(_etype.__name__, _evalue)}))
_hsys.excepthook = _lldpq_json_excepthook'
# Shared input validators for the inventory-mutating python heredocs below.
# Every free-form value that a template renders raw must pass one of these
# before any file is written (returns None/False on invalid input).
LLDPQ_VALIDATORS_DEF='def _v_int_range(_val, _lo, _hi):
    # Strict integer (rejects bool/float/garbage strings) within [_lo, _hi]
    if isinstance(_val, bool):
        return None
    try:
        _num = int(str(_val).strip())
    except (TypeError, ValueError):
        return None
    return _num if _lo <= _num <= _hi else None

def _v_ip_interface(_val):
    # IP address with optional /prefix (e.g. 10.0.0.1/31); returns str or None
    import ipaddress as _vip
    try:
        _vip.ip_interface(str(_val).strip())
    except (TypeError, ValueError):
        return None
    return str(_val).strip()

def _v_ip_network(_val):
    # Subnet/CIDR; returns the ipaddress network object or None
    import ipaddress as _vip
    try:
        return _vip.ip_network(str(_val).strip(), strict=False)
    except (TypeError, ValueError):
        return None

def _v_ip_address(_val):
    # Bare IP address (no /prefix); returns str or None
    import ipaddress as _vip
    try:
        _vip.ip_address(str(_val).strip())
    except (TypeError, ValueError):
        return None
    return str(_val).strip()

def _v_str_list(_val):
    # List of non-empty strings; rejects scalars (a bare string would be
    # iterated per-character by the templates). Returns cleaned list or None.
    if not isinstance(_val, list):
        return None
    _out = [str(_x).strip() for _x in _val]
    if any(not _x for _x in _out):
        return None
    return _out

def _v_name(_val):
    # Same charset as the existing device/profile name checks in this file
    import re as _vre
    return bool(_vre.match(r"^[A-Za-z0-9_.-]+$", str(_val)))

def _v_mac(_val):
    import re as _vre
    return isinstance(_val, str) and bool(_vre.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", _val))

def _v_unknown_devices(_names):
    # Refuse device names not present in the Ansible inventory or host_vars
    # (a typo would silently create an orphan host_vars file no host uses).
    # Empty result when the known set cannot be determined, so unusual
    # setups (no inventory yet) are not locked out.
    import os as _vos
    _known = set()
    _adir = _vos.environ.get("ANSIBLE_DIR", "")
    if _adir:
        for _inv in (_vos.path.join(_adir, "inventory", "inventory.ini"),
                     _vos.path.join(_adir, "inventory", "hosts")):
            if not _vos.path.isfile(_inv):
                continue
            try:
                with open(_inv) as _vf:
                    _in_group = False
                    for _ln in _vf:
                        _ln = _ln.strip()
                        if not _ln or _ln.startswith("#"):
                            continue
                        if _ln.startswith("["):
                            _in_group = _ln.endswith("]") and ":" not in _ln
                            continue
                        if _in_group:
                            _known.add(_ln.split()[0])
            except OSError:
                pass
            break
        try:
            for _fn in _vos.listdir(_vos.path.join(_adir, "inventory", "host_vars")):
                if _fn.endswith((".yaml", ".yml")):
                    _known.add(_fn.rsplit(".", 1)[0])
        except OSError:
            pass
    if not _known:
        return []
    return [_n for _n in _names if str(_n) not in _known]'
# Shared in-use/rename scan helpers for the profile-mutating heredocs below:
# ONE walk over every inventory var file the templates read (host_vars
# *.yaml/*.yml + recursive group_vars) plus the ownership/selection guards
# built on top of it, so the delete/rename cascades never diverge on coverage.
LLDPQ_REF_SCAN_DEF='def _iter_inventory_var_files(_inventory_base, _include_group_vars=True, _exclude=()):
    # host_vars *.yaml/*.yml plus (optionally) recursive group_vars
    import glob as _rglob
    import os as _ros
    _hv_dir = _ros.path.join(_inventory_base, "host_vars")
    _files = _rglob.glob(_ros.path.join(_hv_dir, "*.yaml")) + _rglob.glob(_ros.path.join(_hv_dir, "*.yml"))
    if _include_group_vars:
        _files += _rglob.glob(_ros.path.join(_inventory_base, "group_vars", "**", "*.yaml"), recursive=True)
        _files += _rglob.glob(_ros.path.join(_inventory_base, "group_vars", "**", "*.yml"), recursive=True)
    _skip = set(_ros.path.abspath(_p) for _p in _exclude)
    return [_p for _p in _files if _ros.path.abspath(_p) not in _skip]

def _scan_bgp_profile_refs(_inventory_base, _yaml, _profile):
    # Devices/VRFs whose vrfs.*.bgp.bgp_profile still points at _profile
    # (host_vars AND group_vars, which can also carry vrfs)
    import os as _ros
    _refs = []
    for _p in _iter_inventory_var_files(_inventory_base):
        try:
            with open(_p, "r") as _rf:
                _cfg = _yaml.load(_rf) or {}
        except Exception:
            continue
        if not hasattr(_cfg, "get"):
            continue
        _vrfs = _cfg.get("vrfs")
        if not hasattr(_vrfs, "items"):
            continue
        for _vn, _vc in _vrfs.items():
            if hasattr(_vc, "get"):
                _bgp = _vc.get("bgp")
                if hasattr(_bgp, "get") and _bgp.get("bgp_profile") == _profile:
                    _refs.append({"device": _ros.path.basename(_p).rsplit(".", 1)[0], "vrf": _vn})
    return _refs

def _scan_port_profile_refs(_inventory_base, _yaml, _profile):
    # Ports/bonds whose sw_port_profile still points at _profile (dangling
    # refs are silently skipped by swp_ports.j2/bonding_ports.j2, stripping
    # the bridge stanza from the port on the next deploy)
    import os as _ros
    _refs = []
    for _p in _iter_inventory_var_files(_inventory_base):
        try:
            with open(_p, "r") as _rf:
                _cfg = _yaml.load(_rf) or {}
        except Exception:
            continue
        if not hasattr(_cfg, "get"):
            continue
        for _section in ("interfaces", "bonds"):
            _sect = _cfg.get(_section)
            if not hasattr(_sect, "items"):
                continue
            for _pn, _pc in _sect.items():
                if hasattr(_pc, "get") and _pc.get("sw_port_profile") == _profile:
                    _refs.append({"device": _ros.path.basename(_p).rsplit(".", 1)[0], "port": str(_pn)})
    return _refs

def _subif_owned_by_vrf(_sub_cfg, _vrf):
    # A subinterface may carry another VRF external link; a missing vrf key
    # means the default VRF. Non-mapping configs cannot be verified -> True.
    if not hasattr(_sub_cfg, "get"):
        return True
    return _sub_cfg.get("vrf", "default") == str(_vrf)

def _find_leak_profiles(_profiles, _leak_from_vrf):
    # Deterministic route-leaking profile selection shared by create_vrf and
    # create_vrf_bulk: tenant = first profile importing FROM _leak_from_vrf;
    # shared candidates = every non-VxLAN_UNDERLAY profile with a from_vrf
    # list that does not include it (callers refuse when ambiguous instead
    # of guessing by exclusion).
    _tenant = None
    _shared = []
    for _pn, _pc in _profiles.items():
        if str(_pn).startswith("VxLAN_UNDERLAY"):
            continue
        if not hasattr(_pc, "get"):
            continue
        _af = _pc.get("ipv4_unicast_af")
        _ri = _af.get("route_import") if hasattr(_af, "get") else None
        _fv = _ri.get("from_vrf") if hasattr(_ri, "get") else None
        if not _fv:
            continue
        if _leak_from_vrf in _fv:
            if _tenant is None:
                _tenant = _pn
        else:
            _shared.append(_pn)
    return _tenant, _shared'
# Shared device-name pattern for the telemetry actions below (same charset as
# the download-file/start-clsupport/start-live-capture validators).
LLDPQ_DEVICE_NAME_RE='[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}'
export LLDPQ_DEVICE_NAME_RE
_FABRIC_ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)
case "$_FABRIC_ACTION" in
    ansible-status|list-devices)
        require_auth ;;
    *)
        require_admin ;;
esac

# Load config - read ANSIBLE_DIR from config file, but don't overwrite env var
if [[ -f /etc/lldpq.conf ]]; then
    _conf_ansible_dir=$(grep "^ANSIBLE_DIR=" /etc/lldpq.conf 2>/dev/null | cut -d= -f2)
    if [[ -n "$_conf_ansible_dir" ]]; then
        ANSIBLE_DIR="$_conf_ansible_dir"
    fi
fi
# NoNe = explicitly disabled, treat as empty
if [[ "$ANSIBLE_DIR" == "NoNe" ]]; then
    ANSIBLE_DIR=""
fi

# Export for Python scripts
export ANSIBLE_DIR

# Serialize concurrent YAML read-modify-write across admin edits.
# A single process-wide advisory lock (held on fd 9 until this CGI process
# exits) protects bgp_profiles.yaml / vlan_profiles.yaml / sw_port_profiles.yaml
# and host_vars/*.yaml from lost-update races between concurrent admins.
# Lock files live in a private service-owned dir instead of world-writable
# /tmp (same idea as $WEB_ROOT/.inventory.lock), so other local users cannot
# pre-create/squat the paths. Acquisition fails CLOSED: proceeding without
# the lock would silently re-enable the races it exists to prevent.
FABRIC_LOCK_DIR="${FABRIC_LOCK_DIR:-$(dirname "$0")/.locks}"
mkdir -p "$FABRIC_LOCK_DIR" 2>/dev/null
chmod 700 "$FABRIC_LOCK_DIR" 2>/dev/null
export FABRIC_LOCK_DIR
FABRIC_LOCK_FILE="${FABRIC_LOCK_FILE:-$FABRIC_LOCK_DIR/fabric-api.lock}"
acquire_lock() {
    if ! exec 9>>"$FABRIC_LOCK_FILE" 2>/dev/null; then
        echo '{"success": false, "error": "Could not open config lock file"}'
        exit 0
    fi
    if ! flock -w 30 9 2>/dev/null; then
        echo '{"success": false, "error": "Config lock is busy, please retry"}'
        exit 0
    fi
}

# Output JSON header
echo "Content-Type: application/json"
echo ""

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    # Parse action
    ACTION=$(echo "$query" | grep -oP 'action=\K[^&]*' | head -1)
    # Parse hostname
    HOSTNAME=$(echo "$query" | grep -oP 'hostname=\K[^&]*' | head -1 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
}

# Read the whole POST body into POST_DATA, bounded by CONTENT_LENGTH.
# 'read -r' stopped at the first newline, so pretty-printed (multi-line) JSON
# was truncated to '{' and misreported as missing fields. Bodies are also
# capped below execve's per-env-string limit (~128 KiB, E2BIG): a larger body
# would make 'python3 <<heredoc' fail to exec and return an empty response.
# Non-empty bodies must be valid JSON so malformed input is reported as such
# instead of being silently parsed to {}. Callers still 'export POST_DATA'
# themselves (migrate_port_profiles must NOT export: it hands the body to
# python via a temp file to allow bodies above the env-string limit).
read_post_body() {
    local max_body="${1:-131000}"
    if [[ "${CONTENT_LENGTH:-}" =~ ^[0-9]+$ ]] && (( CONTENT_LENGTH > max_body )); then
        echo '{"success": false, "error": "Request body too large"}'
        exit 0
    fi
    if [[ "${CONTENT_LENGTH:-}" =~ ^[0-9]+$ ]] && (( CONTENT_LENGTH > 0 )); then
        POST_DATA=$(dd bs=4096 count=$(( (CONTENT_LENGTH + 4095) / 4096 )) \
            iflag=fullblock 2>/dev/null | head -c "$CONTENT_LENGTH")
    else
        POST_DATA=$(head -c "$max_body")
    fi
    if [[ -n "$POST_DATA" ]] && \
       ! printf '%s' "$POST_DATA" | python3 -c 'import sys, json; json.load(sys.stdin)' 2>/dev/null; then
        echo '{"success": false, "error": "Invalid JSON body"}'
        exit 0
    fi
}

# List devices from inventory
# Priority: Ansible inventory -> devices.yaml fallback
list_devices() {
    # Try Ansible inventory first
    local hosts_file=""
    if [[ -n "$ANSIBLE_DIR" ]]; then
        if [[ -f "$ANSIBLE_DIR/inventory/inventory.ini" ]]; then
            hosts_file="$ANSIBLE_DIR/inventory/inventory.ini"
        elif [[ -f "$ANSIBLE_DIR/inventory/hosts" ]]; then
            hosts_file="$ANSIBLE_DIR/inventory/hosts"
        fi
    fi

    # Fallback: devices.yaml
    local lldpq_dir=""
    if [[ -f /etc/lldpq.conf ]]; then
        lldpq_dir=$(grep "^LLDPQ_DIR=" /etc/lldpq.conf | cut -d= -f2)
    fi
    lldpq_dir="${lldpq_dir:-/home/lldpq/lldpq}"
    local devices_yaml="$lldpq_dir/devices.yaml"

    export INVENTORY_FILE="$hosts_file"
    export DEVICES_YAML="$devices_yaml"

    python3 << 'PYTHON'
import sys
import json
import os
import re

hosts_file = os.environ.get('INVENTORY_FILE', '')
devices_yaml = os.environ.get('DEVICES_YAML', '')
source = None
devices = {}

# --- Try Ansible inventory first ---
if hosts_file and os.path.isfile(hosts_file):
    source = 'ansible'
    current_group = None
    skip_groups = {'local', 'all', 'ungrouped'}
    try:
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and ':' in line:
                    current_group = None
                    continue
                if line.startswith('[') and line.endswith(']'):
                    current_group = line[1:-1]
                    if ':children' in current_group or current_group in skip_groups:
                        current_group = None
                    else:
                        if current_group not in devices:
                            devices[current_group] = []
                    continue
                if current_group:
                    # Any non-section, non-comment line under a host group is a
                    # host; bare hostnames (vars in host_vars/group_vars) count.
                    parts = line.split()
                    hostname = parts[0]
                    ip = None
                    for part in parts[1:]:
                        if part.startswith('ansible_host='):
                            ip = part.split('=')[1]
                            break
                    devices[current_group].append({
                        'hostname': hostname,
                        'ip': ip
                    })
        devices = {k: v for k, v in devices.items() if v}
    except Exception as e:
        devices = {}
        source = None

# --- Fallback: devices.yaml ---
if not devices and devices_yaml and os.path.isfile(devices_yaml):
    source = 'devices.yaml'
    try:
        import yaml
        with open(devices_yaml, 'r') as f:
            config = yaml.safe_load(f)
        devs = config.get('devices', {})
        if devs:
            for ip_addr, device_config in devs.items():
                hostname = None
                role = None
                if isinstance(device_config, str):
                    # Parse "Hostname @role" format
                    match = re.match(r'^(.+?)\s+@(\w+)$', device_config.strip())
                    if match:
                        hostname = match.group(1).strip()
                        role = match.group(2).lower()
                    else:
                        hostname = device_config.strip()
                elif isinstance(device_config, dict):
                    hostname = device_config.get('hostname', str(ip_addr))
                    role = device_config.get('role', None)
                    if role:
                        role = role.lower()
                else:
                    continue
                group = role if role else 'all'
                if group not in devices:
                    devices[group] = []
                devices[group].append({
                    'hostname': hostname,
                    'ip': str(ip_addr)
                })
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Failed to parse devices.yaml: {e}'}))
        sys.exit(0)

if devices:
    print(json.dumps({
        'success': True,
        'devices': devices,
        'source': source
    }))
else:
    print(json.dumps({
        'success': False,
        'error': 'No device inventory found. Provide Ansible inventory or devices.yaml'
    }))
PYTHON
}

# Get device configuration
get_device() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        echo '{"success": false, "error": "Hostname is required"}'
        return
    fi
    
    local host_vars_file="$ANSIBLE_DIR/inventory/host_vars/${hostname}.yaml"

    export DEVICE_HOSTNAME="$hostname"

    # Python script to parse host_vars and find device info
    # Host vars file is optional - some devices (like spines) may not have it
    python3 << 'PYTHON'
import sys
import json
import yaml  # PyYAML - faster for read-only operations
import os
import re

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
hostname = os.environ.get('DEVICE_HOSTNAME', '')
if not re.match(r'^[A-Za-z0-9_.-]+$', hostname):
    print(json.dumps({'success': False, 'error': 'Invalid hostname'}))
    sys.exit(0)
host_vars_file = f"{ansible_dir}/inventory/host_vars/{hostname}.yaml"
# Fallback: try inventory.ini first, then hosts
hosts_file = None
for name in ['inventory.ini', 'hosts']:
    path = f"{ansible_dir}/inventory/{name}"
    if os.path.exists(path):
        hosts_file = path
        break
if not hosts_file:
    hosts_file = f"{ansible_dir}/inventory/hosts"  # default for error message
port_profiles_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

try:
    # Read host_vars (optional - some devices like spines may not have it)
    config = {}
    if os.path.exists(host_vars_file):
        with open(host_vars_file, 'r') as f:
            config = yaml.load(f, Loader=yaml.CSafeLoader) or {}
    
    # Find device info from hosts file
    device_info = {'hostname': hostname, 'group': None, 'ip': None}
    current_group = None
    
    with open(hosts_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('[') and line.endswith(']'):
                current_group = line[1:-1]
                if ':' in current_group:
                    current_group = None
                continue
            
            if current_group and line.split()[0] == hostname:
                device_info['group'] = current_group
                parts = line.split()
                for part in parts[1:]:
                    if part.startswith('ansible_host='):
                        device_info['ip'] = part.split('=')[1]
                        break
                break
    
    # Check for group_vars VRFs if not in host_vars
    if 'vrfs' not in config and device_info['group']:
        group_vrfs_file = f"{ansible_dir}/inventory/group_vars/{device_info['group']}/vrfs.yaml"
        if os.path.exists(group_vrfs_file):
            with open(group_vrfs_file, 'r') as f:
                group_config = yaml.load(f, Loader=yaml.CSafeLoader) or {}
                if 'vrfs' in group_config:
                    config['vrfs'] = group_config['vrfs']
    
    # Load port profiles for VLAN resolution
    port_profiles = {}
    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            pp_config = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            port_profiles = pp_config.get('sw_port_profiles', {})
    
    # Load VLAN profiles for VRF and IP resolution
    vlan_to_vrf = {}
    vlan_profiles_data = {}
    vxlan_int_mapping = {}  # VRF name -> VLAN ID for L3VNI interface
    
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            vp_config = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            
            # Load vxlan_int mapping (nscale/kddi style: vxlan_int at top level)
            if 'vxlan_int' in vp_config and isinstance(vp_config['vxlan_int'], dict):
                vxlan_int_mapping = {str(k): str(v) for k, v in vp_config['vxlan_int'].items()}
            
            vlan_profiles = vp_config.get('vlan_profiles', {})
            # Build VLAN ID to VRF mapping and VLAN profile data
            for profile_name, profile_data in vlan_profiles.items():
                if profile_data and 'vlans' in profile_data:
                    vrr_enabled = profile_data.get('vrr', {}).get('state', False)
                    vlan_ids = sorted([int(v) for v in profile_data['vlans'].keys()])
                    
                    # Build vlan_to_vrf mapping for all VLANs
                    for vlan_id, vlan_config in profile_data['vlans'].items():
                        if vlan_config and 'vrf' in vlan_config:
                            vlan_to_vrf[str(vlan_id)] = vlan_config['vrf']
                    
                    # Get first VLAN's config for description/VRF etc
                    first_vlan_id = vlan_ids[0] if vlan_ids else None
                    first_vlan_config = profile_data['vlans'].get(str(first_vlan_id)) or profile_data['vlans'].get(first_vlan_id) or {}
                    
                    # Get last VLAN's l2vni for range profiles
                    last_vlan_id = vlan_ids[-1] if vlan_ids else None
                    last_vlan_config = profile_data['vlans'].get(str(last_vlan_id)) or profile_data['vlans'].get(last_vlan_id) or {}
                    
                    # Determine VLAN ID display (single or range)
                    if len(vlan_ids) == 1:
                        vlan_id_display = str(vlan_ids[0])
                    else:
                        vlan_id_display = f"{vlan_ids[0]}-{vlan_ids[-1]}"
                    
                    # Store VLAN profile info for SVI section
                    vlan_profiles_data[profile_name] = {
                        'vlan_id': vlan_id_display,
                        'vlan_count': len(vlan_ids),
                        'description': first_vlan_config.get('description', ''),
                        'vrf': first_vlan_config.get('vrf', 'default'),
                        'l2vni': last_vlan_config.get('l2vni'),
                        'vrr_enabled': vrr_enabled,
                        'vrr_vip': first_vlan_config.get('vrr_vip'),
                        'even_ip': first_vlan_config.get('even_ip'),
                        'odd_ip': first_vlan_config.get('odd_ip'),
                        'ip': first_vlan_config.get('ip'),
                        'vlans': profile_data['vlans']  # Include raw vlans data
                    }
    
    print(json.dumps({
        'success': True,
        'config': config,
        'device_info': device_info,
        'port_profiles': port_profiles,
        'vlan_to_vrf': vlan_to_vrf,
        'vlan_profiles': vlan_profiles_data,
        'vxlan_int_mapping': vxlan_int_mapping
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Get VLAN profiles
get_vlan_profiles() {
    local vlan_file="$ANSIBLE_DIR/inventory/group_vars/all/vlan_profiles.yaml"
    
    if [[ ! -f "$vlan_file" ]]; then
        echo '{"success": false, "error": "VLAN profiles file not found"}'
        return
    fi
    
    python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

try:
    with open(vlan_file, 'r') as f:
        config = yaml.load(f, Loader=yaml.CSafeLoader) or {}
    
    print(json.dumps({
        'success': True,
        'vlan_profiles': config.get('vlan_profiles', {}),
        'vxlan_int': config.get('vxlan_int', {})
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Bulk create VLANs
bulk_create_vlans() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'vlan_profiles.yaml')

start_id = data.get('start_id', 1)
end_id = data.get('end_id', 1)
profile_name = data.get('profile_name', f'VLAN_{start_id}_{end_id}_L2')
description = data.get('description', f'L2 VLANs {start_id}-{end_id}')
l2vni_offset = data.get('l2vni_offset', 100000)

import re
if not re.match(r'^[A-Za-z0-9_.-]+$', str(profile_name)):
    print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
    exit(0)

# Validate (coerce first: form/API values may arrive as strings)
start_id = _v_int_range(start_id, 1, 4094)
end_id = _v_int_range(end_id, 1, 4094)
if start_id is None or end_id is None or start_id > end_id:
    print(json.dumps({'success': False, 'error': 'Invalid VLAN ID range'}))
    exit(0)

count = end_id - start_id + 1
if count > 500:
    print(json.dumps({'success': False, 'error': 'Maximum 500 VLANs at once'}))
    exit(0)

# Validate L2VNI offset: every generated l2vni (offset + vid) must be a valid VNI
l2vni_offset = _v_int_range(l2vni_offset, 0, 16777215)
if l2vni_offset is None or l2vni_offset + end_id > 16777215:
    print(json.dumps({'success': False, 'error': 'Invalid L2VNI offset (offset + VLAN ID must be 1-16777215)'}))
    exit(0)

# Load existing vlan profiles (keep full config to preserve other top-level keys like vxlan_int)
existing = {}
vlan_profiles = {}
if os.path.exists(vlan_file):
    with open(vlan_file, 'r') as f:
        existing = yaml.load(f) or {}
        vlan_profiles = existing.get('vlan_profiles', {})

# Check if profile name already exists
if profile_name in vlan_profiles:
    print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
    exit(0)

# Check if any VLAN ID in range already used in another profile
for pname, pdata in vlan_profiles.items():
    if pdata and 'vlans' in pdata:
        for vid in range(start_id, end_id + 1):
            if vid in pdata['vlans'] or str(vid) in pdata['vlans']:
                print(json.dumps({'success': False, 'error': f'VLAN ID {vid} already exists in profile {pname}'}))
                exit(0)

# Create the VLAN profile with multiple VLANs inside
vlans_dict = {}
for vid in range(start_id, end_id + 1):
    vlans_dict[vid] = {
        'description': f'{description}',
        'l2vni': l2vni_offset + vid
    }

new_profile = {
    'vlans': vlans_dict
}

vlan_profiles[profile_name] = new_profile
existing['vlan_profiles'] = vlan_profiles

# Write back (full config, not just vlan_profiles)
_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(vlan_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, vlan_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(existing, _tmp_f)
    shutil.move(_tmp_path, vlan_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

# created_vlans keeps VLAN IDs for display counts; created_profiles carries the
# vlan_profiles.yaml profile name(s) that assign-vlans/vlan_templates expect.
print(json.dumps({'success': True, 'message': f'Created {count} VLANs in profile {profile_name}', 'created_vlans': list(range(start_id, end_id + 1)), 'created_profiles': [profile_name]}))
PYTHON
}

# ==================== BGP PROFILES ====================

# Get VRFs that can be used for leaking (those that have profiles with route_import)
get_leaking_vrfs() {
    python3 << 'PYTHON'
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')

leaking_vrfs = []

try:
    # First, find BGP profiles that have route_import.from_vrf
    if os.path.exists(bgp_file):
        with open(bgp_file, 'r') as f:
            data = yaml.load(f) or {}
            bgp_profiles = data.get('bgp_profiles', {})
            
            # Find all VRFs mentioned in from_vrf across all profiles
            imported_vrfs = set()
            for profile_name, profile_config in bgp_profiles.items():
                ipv4_af = profile_config.get('ipv4_unicast_af', {})
                route_import = ipv4_af.get('route_import', {})
                from_vrf = route_import.get('from_vrf', [])
                for vrf in from_vrf:
                    imported_vrfs.add(vrf)
            
            # These VRFs can be leaked into
            for vrf_name in sorted(imported_vrfs):
                leaking_vrfs.append({'name': vrf_name})
    
    print(json.dumps({'success': True, 'vrfs': leaking_vrfs}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

# Get BGP profiles (filtered - exclude VxLAN_UNDERLAY*)
# ==================== VRF MANAGEMENT ====================

# Get available VRFs from all devices
get_available_vrfs() {
    python3 << 'PYTHON'
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')

# Collect all unique VRFs from all devices
vrfs = {}
parse_errors = {}

for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.load(f) or {}
            device_vrfs = host_data.get('vrfs', {})
            
            for vrf_name, vrf_config in device_vrfs.items():
                if vrf_name not in vrfs:
                    vrfs[vrf_name] = {
                        'name': vrf_name,
                        'l3vni': vrf_config.get('l3vni'),
                        'vxlan_int': vrf_config.get('vxlan_int'),
                        'bgp_profile': vrf_config.get('bgp', {}).get('bgp_profile'),
                        'device_count': 0,
                        'devices': []
                    }
                vrfs[vrf_name]['device_count'] += 1
                vrfs[vrf_name]['devices'].append(hostname)
    except Exception as e:
        parse_errors[os.path.basename(host_file)] = str(e)

_resp = {
    'success': True,
    'vrfs': list(vrfs.values())
}
if parse_errors:
    _resp['parse_errors'] = parse_errors
    _resp['warning'] = 'Some host_vars files could not be parsed: ' + ', '.join(parse_errors)
print(json.dumps(_resp))
PYTHON
}

# Create VRF in device's host_vars
create_vrf() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

device = data.get('device')
vrf_name = data.get('vrf_name')
l3vni = data.get('l3vni')
vxlan_int = data.get('vxlan_int')
bgp_asn = data.get('bgp_asn')
bgp_profile = data.get('bgp_profile')
leaking_enabled = data.get('leaking_enabled', False)
leak_from_vrf = data.get('leak_from_vrf')

if not device or not vrf_name:
    print(json.dumps({'success': False, 'error': 'Device and VRF name are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(vrf_name)):
    print(json.dumps({'success': False, 'error': 'Invalid VRF name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

if not l3vni:
    print(json.dumps({'success': False, 'error': 'L3VNI is required'}))
    sys.exit(0)

l3vni = _v_int_range(l3vni, 1, 16777215)
if l3vni is None:
    print(json.dumps({'success': False, 'error': 'Invalid L3VNI (must be 1-16777215)'}))
    sys.exit(0)

if bgp_asn:
    bgp_asn = _v_int_range(bgp_asn, 1, 4294967295)
    if bgp_asn is None:
        print(json.dumps({'success': False, 'error': 'Invalid BGP ASN (must be 1-4294967295)'}))
        sys.exit(0)

if vxlan_int and not _v_name(vxlan_int):
    print(json.dumps({'success': False, 'error': 'Invalid VXLAN interface name'}))
    sys.exit(0)

_unknown = _v_unknown_devices([device])
if _unknown:
    print(json.dumps({'success': False, 'error': f'Unknown device: {_unknown[0]}'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yml')

# Load existing host_vars and check for duplicates BEFORE touching bgp_profiles.yaml
host_data = {}
if os.path.exists(host_file):
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}

# Initialize vrfs if not exists
if 'vrfs' not in host_data:
    host_data['vrfs'] = {}

# Check if VRF already exists
if vrf_name in host_data['vrfs']:
    print(json.dumps({'success': False, 'error': f'VRF {vrf_name} already exists on this device'}))
    sys.exit(0)

# If leaking is enabled, find the appropriate profiles
tenant_profile = None
shared_profile = None
leaking_configured = False
_leak_write = None

if leaking_enabled and leak_from_vrf:
    try:
        with open(bgp_profiles_file, 'r') as f:
            bgp_data = yaml.load(f) or {}
            bgp_profiles = bgp_data.get('bgp_profiles', {})

            # Deterministic tenant/shared profile selection (shared helper,
            # identical to create_vrf_bulk); refuse when more than one shared
            # candidate matches instead of guessing by exclusion.
            tenant_profile, _shared_candidates = _find_leak_profiles(bgp_profiles, leak_from_vrf)
            if len(_shared_candidates) > 1:
                print(json.dumps({'success': False, 'error': 'Ambiguous shared profile for route leaking (' + ', '.join(str(_c) for _c in _shared_candidates) + '); resolve manually in bgp_profiles.yaml'}))
                sys.exit(0)
            shared_profile = _shared_candidates[0] if _shared_candidates else None

            # Update the shared profile to include the new tenant
            if shared_profile and shared_profile in bgp_profiles:
                ipv4_af = bgp_profiles[shared_profile].setdefault('ipv4_unicast_af', {})
                route_import = ipv4_af.setdefault('route_import', {})
                from_vrf_list = route_import.setdefault('from_vrf', [])

                if vrf_name not in from_vrf_list:
                    from_vrf_list.append(vrf_name)
                    # Stage the write; committed together with host_vars below
                    # so a failed host_vars write cannot strand a leak entry
                    # for a VRF that exists nowhere
                    _leak_write = (bgp_data, bgp_profiles_file)
                # Entry present (just added or left over from an earlier
                # attempt) -> leaking IS configured; do not report False
                leaking_configured = True

            # Use tenant_profile if found
            if tenant_profile:
                bgp_profile = tenant_profile

    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Failed to configure leaking: {str(e)}'}))
        sys.exit(0)

# Create VRF entry
vrf_entry = {
    'l3vni': l3vni,
    'lo': '{{ lo_ip }}'
}

if vxlan_int:
    vrf_entry['vxlan_int'] = vxlan_int

if bgp_asn or bgp_profile:
    vrf_entry['bgp'] = {}
    if bgp_asn:
        vrf_entry['bgp']['asn'] = bgp_asn
    if bgp_profile:
        vrf_entry['bgp']['bgp_profile'] = bgp_profile

host_data['vrfs'][vrf_name] = vrf_entry

# Write back: host_vars plus the staged bgp_profiles.yaml leak entry in one
# two-phase commit (both dumps must succeed before either file is renamed)
_target_file = host_file if os.path.exists(host_file) else os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')
_writes = [(host_data, _target_file)]
if _leak_write is not None:
    _writes.append(_leak_write)
_atomic_write_many(yaml, _writes)

result = {'success': True, 'vrf_name': vrf_name}
if leaking_enabled:
    result['leaking_configured'] = leaking_configured
    result['tenant_profile'] = tenant_profile
    result['shared_profile'] = shared_profile
    if not tenant_profile:
        result['warning'] = f'No profile found that imports from {leak_from_vrf}'

print(json.dumps(result))
PYTHON
}

# Create VRF on multiple devices (bulk)
create_vrf_bulk() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys
import glob

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

devices = data.get('devices', [])
vrf_name = data.get('vrf_name')
l3vni = data.get('l3vni')
vxlan_int = data.get('vxlan_int')
bgp_profile = data.get('bgp_profile', 'OVERLAY_LEAF')
leaking_enabled = data.get('leaking_enabled', False)
leak_from_vrf = data.get('leak_from_vrf')
loopback_ip = data.get('loopback_ip')  # Custom loopback IP with mask

if not devices or not isinstance(devices, list):
    print(json.dumps({'success': False, 'error': 'No devices specified'}))
    sys.exit(0)

if not vrf_name or not l3vni:
    print(json.dumps({'success': False, 'error': 'VRF name and L3VNI are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(vrf_name)):
    print(json.dumps({'success': False, 'error': 'Invalid VRF name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

for _d in devices:
    if not re.match(r'^[A-Za-z0-9_.-]+$', str(_d)):
        print(json.dumps({'success': False, 'error': f'Invalid device name: {_d}'}))
        sys.exit(0)

l3vni = _v_int_range(l3vni, 1, 16777215)
if l3vni is None:
    print(json.dumps({'success': False, 'error': 'Invalid L3VNI (must be 1-16777215)'}))
    sys.exit(0)

if vxlan_int and not _v_name(vxlan_int):
    print(json.dumps({'success': False, 'error': 'Invalid VXLAN interface name'}))
    sys.exit(0)

if loopback_ip and _v_ip_interface(loopback_ip) is None:
    print(json.dumps({'success': False, 'error': f'Invalid loopback IP: {loopback_ip}'}))
    sys.exit(0)

_unknown = _v_unknown_devices(devices)
if _unknown:
    print(json.dumps({'success': False, 'error': 'Unknown device(s): ' + ', '.join(str(_n) for _n in _unknown)}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')

# Handle leaking profile detection
leaking_configured = False
tenant_profile = None
shared_profile = None
leaking_error = None
_leak_write = None

if leaking_enabled and leak_from_vrf:
    try:
        with open(bgp_profiles_file, 'r') as f:
            bgp_data = yaml.load(f) or {}

        bgp_profiles = bgp_data.get('bgp_profiles', {})

        # Deterministic tenant/shared profile selection (shared helper,
        # identical to single-device create_vrf); refuse when more than one
        # shared candidate matches instead of guessing by exclusion.
        tenant_profile, _shared_candidates = _find_leak_profiles(bgp_profiles, leak_from_vrf)
        if len(_shared_candidates) > 1:
            print(json.dumps({'success': False, 'error': 'Ambiguous shared profile for route leaking (' + ', '.join(str(_c) for _c in _shared_candidates) + '); resolve manually in bgp_profiles.yaml'}))
            sys.exit(0)
        if _shared_candidates:
            shared_profile = _shared_candidates[0]
            # Add new VRF to shared profile's from_vrf list (in memory only;
            # the write is staged until at least one device got the VRF, so a
            # run that creates nothing cannot strand a leak entry)
            ipv4_af = bgp_profiles[shared_profile].setdefault('ipv4_unicast_af', {})
            route_import = ipv4_af.setdefault('route_import', {})
            from_vrf_list = route_import.setdefault('from_vrf', [])
            if vrf_name not in from_vrf_list:
                from_vrf_list.append(vrf_name)
                _leak_write = (bgp_data, bgp_profiles_file)
            else:
                # Already present from an earlier run -> leaking IS configured
                leaking_configured = True

        if tenant_profile:
            bgp_profile = tenant_profile
    except Exception as e:
        leaking_error = str(e)

# Create VRF entry
vrf_entry = {
    'l3vni': l3vni,
    'lo': loopback_ip if loopback_ip else '{{ lo_ip }}'
}

if vxlan_int:
    vrf_entry['vxlan_int'] = vxlan_int

devices_created = []
devices_skipped = []
device_errors = {}

for device in devices:
    try:
        host_file = os.path.join(host_vars_dir, f'{device}.yaml')
        if not os.path.exists(host_file):
            alt_file = os.path.join(host_vars_dir, f'{device}.yml')
            if os.path.exists(alt_file):
                host_file = alt_file

        # Load host_vars
        host_data = {}
        if os.path.exists(host_file):
            with open(host_file, 'r') as f:
                host_data = yaml.load(f) or {}

        # Get device's BGP ASN
        device_asn = None
        bgp_config = host_data.get('bgp', {})
        if isinstance(bgp_config, dict):
            device_asn = bgp_config.get('asn')

        # Initialize vrfs if not exists
        if 'vrfs' not in host_data:
            host_data['vrfs'] = {}

        # Skip devices where this VRF already exists (mirror single-device create_vrf)
        if vrf_name in host_data['vrfs']:
            devices_skipped.append(device)
            continue

        # Create device-specific VRF entry with its own ASN (nested bgp format, same as create_vrf)
        device_vrf_entry = vrf_entry.copy()
        if device_asn or bgp_profile:
            device_vrf_entry['bgp'] = {}
            if device_asn:
                device_vrf_entry['bgp']['asn'] = device_asn
            if bgp_profile:
                device_vrf_entry['bgp']['bgp_profile'] = bgp_profile

        host_data['vrfs'][vrf_name] = device_vrf_entry
        
        # Write back
        target_file = host_file if os.path.exists(host_file) else os.path.join(host_vars_dir, f'{device}.yaml')
        _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(target_file), suffix='.tmp')
        _lldpq_mode_floor(_tmp_fd, target_file)
        try:
            with os.fdopen(_tmp_fd, 'w') as _tmp_f:
                yaml.dump(host_data, _tmp_f)
            shutil.move(_tmp_path, target_file)
        except:
            if os.path.exists(_tmp_path): os.unlink(_tmp_path)
            raise
        
        devices_created.append(device)
    except Exception as e:
        device_errors[device] = str(e)  # Skip failed devices but report them

# Commit the staged bgp_profiles.yaml leak entry only after the VRF was
# actually created somewhere (dependent shared file goes last, so a device
# loop that fails everywhere cannot strand a leak entry for a missing VRF)
if _leak_write is not None and devices_created:
    try:
        _atomic_write_many(yaml, [_leak_write])
        leaking_configured = True
    except Exception as e:
        leaking_error = str(e)

result = {
    'success': len(devices_created) > 0,
    'vrf_name': vrf_name,
    'devices_created': len(devices_created),
    'devices_list': devices_created,
    'devices_skipped': devices_skipped
}

warnings = []

if device_errors:
    result['device_errors'] = device_errors
if devices_skipped:
    warnings.append('VRF already existed (skipped) on: ' + ', '.join(devices_skipped))
if not devices_created and not devices_skipped:
    result['error'] = 'VRF was not created on any device: ' + '; '.join(f'{d}: {e}' for d, e in device_errors.items())

if leaking_enabled:
    result['leaking_configured'] = leaking_configured
    result['tenant_profile'] = tenant_profile
    result['shared_profile'] = shared_profile
    if leaking_error:
        warnings.append(f'Route-leaking setup failed: {leaking_error}')
    elif not tenant_profile:
        warnings.append(f'No profile found that imports from {leak_from_vrf}')

if warnings:
    result['warning'] = '; '.join(warnings)

print(json.dumps(result))
PYTHON
}

# Assign VRFs to device
assign_vrfs() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys
import glob
import copy

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

device = data.get('device')
vrf_names = data.get('vrfs', [])

if not device or not vrf_names:
    print(json.dumps({'success': False, 'error': 'Device and VRF names are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

_unknown = _v_unknown_devices([device])
if _unknown:
    print(json.dumps({'success': False, 'error': f'Unknown device: {_unknown[0]}'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
host_file = os.path.join(host_vars_dir, f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = os.path.join(host_vars_dir, f'{device}.yml')
    if os.path.exists(alt_file):
        host_file = alt_file

# Load existing host_vars
host_data = {}
if os.path.exists(host_file):
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}

# Initialize vrfs if not exists
if 'vrfs' not in host_data:
    host_data['vrfs'] = {}

# Find VRF configs from other devices
all_vrf_configs = {}
_harvest_errors = {}
for hf in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    try:
        with open(hf, 'r') as f:
            hd = yaml.load(f) or {}
            for vrf_name, vrf_config in hd.get('vrfs', {}).items():
                if vrf_name not in all_vrf_configs:
                    all_vrf_configs[vrf_name] = vrf_config
    except Exception as e:
        _harvest_errors[os.path.basename(hf)] = str(e)

# Get this device's own BGP ASN. sferical stores it as a top-level 'bgp_asn'
# key and references it inside vrfs as the portable '{{ bgp_asn }}' string,
# so read that key first (with a legacy nested bgp.asn fallback).
device_asn = host_data.get('bgp_asn')
if device_asn is None:
    bgp_config = host_data.get('bgp', {})
    if isinstance(bgp_config, dict):
        device_asn = bgp_config.get('asn')

def _normalize_copied_asn(container, key):
    # Keep the portable '{{ bgp_asn }}' reference verbatim (it resolves to this
    # device's own bgp_asn); substitute a concrete ASN for a copied literal;
    # drop it only when this device has no ASN so the template's
    # 'asn is defined' gate stays false instead of inheriting the source's ASN.
    cur = container.get(key)
    if isinstance(cur, str) and 'bgp_asn' in cur and '{{' in cur:
        if device_asn is None:
            del container[key]
    elif device_asn is not None:
        container[key] = device_asn
    else:
        del container[key]

# Add VRFs
added = []
for vrf_name in vrf_names:
    if vrf_name not in host_data['vrfs']:
        if vrf_name in all_vrf_configs:
            vrf_config = copy.deepcopy(all_vrf_configs[vrf_name])
            # Don't copy the source device's ASN; use this device's own or omit
            if 'bgp_asn' in vrf_config:
                _normalize_copied_asn(vrf_config, 'bgp_asn')
            vrf_bgp = vrf_config.get('bgp')
            if isinstance(vrf_bgp, dict) and 'asn' in vrf_bgp:
                _normalize_copied_asn(vrf_bgp, 'asn')
            host_data['vrfs'][vrf_name] = vrf_config
            added.append(vrf_name)
        else:
            # Refuse the minimal stub when the harvest loop failed to read
            # some host_vars: the real VRF definition may live in a file we
            # could not parse, and the '{l3vni: None}' stub would be wrong
            if _harvest_errors:
                print(json.dumps({
                    'success': False,
                    'error': f'VRF {vrf_name} not found, but some host_vars could not be parsed: ' + ', '.join(_harvest_errors),
                    'parse_errors': _harvest_errors
                }))
                sys.exit(0)
            # Create minimal VRF entry
            host_data['vrfs'][vrf_name] = {'l3vni': None}
            added.append(vrf_name)

# Write back
_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, host_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(host_data, _tmp_f)
    shutil.move(_tmp_path, host_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

print(json.dumps({'success': True, 'added': added}))
PYTHON
}

# Unassign VRF from device
unassign_vrf() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

device = data.get('device')
vrf_name = data.get('vrf')

if not device or not vrf_name:
    print(json.dumps({'success': False, 'error': 'Device and VRF name are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

if vrf_name == 'default':
    print(json.dumps({'success': False, 'error': 'Cannot remove default VRF'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
host_file = os.path.join(host_vars_dir, f'{device}.yaml')

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = os.path.join(host_vars_dir, f'{device}.yml')
    if os.path.exists(alt_file):
        host_file = alt_file

if not os.path.exists(host_file):
    print(json.dumps({'success': False, 'error': 'Host vars file not found'}))
    sys.exit(0)

# Load host_vars
with open(host_file, 'r') as f:
    host_data = yaml.load(f) or {}

if 'vrfs' not in host_data or vrf_name not in host_data['vrfs']:
    print(json.dumps({'success': False, 'error': f'VRF {vrf_name} not found in device config'}))
    sys.exit(0)

# Remove VRF
del host_data['vrfs'][vrf_name]

# Write back host_vars
_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, host_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(host_data, _tmp_f)
    shutil.move(_tmp_path, host_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

# Check if any other devices still have this VRF
import glob
remaining_devices = 0
for hf in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    try:
        with open(hf, 'r') as f:
            hd = yaml.load(f) or {}
        if vrf_name in hd.get('vrfs', {}):
            remaining_devices += 1
    except:
        pass

# Only remove VRF from bgp_profiles.yaml if this was the LAST device
leaking_removed = False
_leak_cleanup_error = None
if remaining_devices == 0:
    try:
        if os.path.exists(bgp_profiles_file):
            with open(bgp_profiles_file, 'r') as f:
                bgp_data = yaml.load(f) or {}
            
            bgp_profiles = bgp_data.get('bgp_profiles', {})
            modified = False
            
            for profile_name, profile_config in bgp_profiles.items():
                ipv4_af = profile_config.get('ipv4_unicast_af', {})
                route_import = ipv4_af.get('route_import', {})
                from_vrf_list = route_import.get('from_vrf', [])
                
                if vrf_name in from_vrf_list:
                    from_vrf_list.remove(vrf_name)
                    modified = True
                    leaking_removed = True
            
            if modified:
                _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(bgp_profiles_file), suffix='.tmp')
                _lldpq_mode_floor(_tmp_fd, bgp_profiles_file)
                try:
                    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
                        yaml.dump(bgp_data, _tmp_f)
                    shutil.move(_tmp_path, bgp_profiles_file)
                except:
                    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
                    raise
    except Exception as e:
        # Surface the failure instead of silently leaving a stale
        # from_vrf leak entry behind (mirrors delete_vrf_global's file_errors)
        _leak_cleanup_error = str(e)

result = {'success': True, 'leaking_removed': leaking_removed, 'remaining_devices': remaining_devices}
if _leak_cleanup_error:
    result['leaking_cleanup_failed'] = True
    result['warning'] = f'leak cleanup failed: {_leak_cleanup_error}'
print(json.dumps(result))
PYTHON
}

# Delete VRF globally (from all devices)
delete_vrf_global() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys
import glob

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

vrf_name = data.get('vrf_name')

if not vrf_name:
    print(json.dumps({'success': False, 'error': 'VRF name is required'}))
    sys.exit(0)

if vrf_name == 'default':
    print(json.dumps({'success': False, 'error': 'Cannot delete default VRF'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')

devices_updated = []
file_errors = {}

# Remove VRF from all host_vars files
for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.load(f) or {}

        if 'vrfs' in host_data and vrf_name in host_data['vrfs']:
            del host_data['vrfs'][vrf_name]
            _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
            _lldpq_mode_floor(_tmp_fd, host_file)
            try:
                with os.fdopen(_tmp_fd, 'w') as _tmp_f:
                    yaml.dump(host_data, _tmp_f)
                shutil.move(_tmp_path, host_file)
            except:
                if os.path.exists(_tmp_path): os.unlink(_tmp_path)
                raise
            hostname = os.path.basename(host_file).replace('.yaml', '').replace('.yml', '')
            devices_updated.append(hostname)
    except Exception as e:
        file_errors[os.path.basename(host_file)] = str(e)

# Remove VRF from bgp_profiles.yaml (leaking references)
leaking_removed = False
try:
    if os.path.exists(bgp_profiles_file):
        with open(bgp_profiles_file, 'r') as f:
            bgp_data = yaml.load(f) or {}

        bgp_profiles = bgp_data.get('bgp_profiles', {})
        modified = False

        for profile_name, profile_config in bgp_profiles.items():
            ipv4_af = profile_config.get('ipv4_unicast_af', {})
            route_import = ipv4_af.get('route_import', {})
            from_vrf_list = route_import.get('from_vrf', [])

            if vrf_name in from_vrf_list:
                from_vrf_list.remove(vrf_name)
                modified = True
                leaking_removed = True

        if modified:
            _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(bgp_profiles_file), suffix='.tmp')
            _lldpq_mode_floor(_tmp_fd, bgp_profiles_file)
            try:
                with os.fdopen(_tmp_fd, 'w') as _tmp_f:
                    yaml.dump(bgp_data, _tmp_f)
                shutil.move(_tmp_path, bgp_profiles_file)
            except:
                if os.path.exists(_tmp_path): os.unlink(_tmp_path)
                raise
except Exception as e:
    file_errors['bgp_profiles.yaml'] = str(e)

result = {
    'success': not file_errors,
    'devices_updated': devices_updated,
    'leaking_removed': leaking_removed
}
if file_errors:
    result['file_errors'] = file_errors
    result['error'] = 'Some files failed to update: ' + ', '.join(file_errors.keys())

print(json.dumps(result))
PYTHON
}

# Get VRF report - VRFs with device assignments
get_vrf_report() {
    python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')

# Collect all VRFs from all devices
vrfs = {}
unique_devices = set()
parse_errors = {}

for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            device_vrfs = host_data.get('vrfs', {})
            
            if device_vrfs:
                unique_devices.add(hostname)
            
            for vrf_name, vrf_config in device_vrfs.items():
                if vrf_name not in vrfs:
                    vrfs[vrf_name] = {
                        'name': vrf_name,
                        'l3vni': vrf_config.get('l3vni'),
                        'vxlan_int': vrf_config.get('vxlan_int'),
                        'bgp_profile': vrf_config.get('bgp', {}).get('bgp_profile') if vrf_config.get('bgp') else None,
                        'devices': []
                    }
                vrfs[vrf_name]['devices'].append(hostname)
    except Exception as e:
        parse_errors[os.path.basename(host_file)] = str(e)

_resp = {
    'success': True,
    'vrfs': vrfs,
    'device_count': len(unique_devices)
}
if parse_errors:
    _resp['parse_errors'] = parse_errors
    _resp['warning'] = 'Some host_vars files could not be parsed: ' + ', '.join(parse_errors)
print(json.dumps(_resp))
PYTHON
}

# Get VLAN report - VLANs with device assignments
get_vlan_report() {
    python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
vlan_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')
host_vars_dir = os.path.join(inventory_base, 'host_vars')

# Load VLAN profiles
vlan_profiles = {}
vrfs = set()

if os.path.exists(vlan_file):
    with open(vlan_file, 'r') as f:
        data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
        vlan_profiles = data.get('vlan_profiles', {})

# Collect VRFs from VLAN profiles
for vlan_name, vlan_data in vlan_profiles.items():
    if vlan_data and 'vlans' in vlan_data:
        for vid, vinfo in vlan_data['vlans'].items():
            if vinfo and vinfo.get('vrf'):
                vrfs.add(vinfo['vrf'])

# Build VLAN to device mapping and collect unique devices
vlan_device_map = {vlan_name: [] for vlan_name in vlan_profiles.keys()}
unique_devices = set()
parse_errors = {}

# Scan all host_vars files for vlan_templates
for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')) + glob.glob(os.path.join(host_vars_dir, '*.yml')):
    hostname = os.path.basename(host_file).rsplit('.', 1)[0]
    
    try:
        with open(host_file, 'r') as f:
            host_data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            vlan_templates = host_data.get('vlan_templates', [])
            
            if vlan_templates:
                unique_devices.add(hostname)
            
            for vlan_name in vlan_templates:
                if vlan_name in vlan_device_map:
                    vlan_device_map[vlan_name].append(hostname)
                else:
                    vlan_device_map[vlan_name] = [hostname]
    except Exception as e:
        parse_errors[os.path.basename(host_file)] = str(e)

_resp = {
    'success': True,
    'vlan_profiles': vlan_profiles,
    'vlan_device_map': vlan_device_map,
    'device_count': len(unique_devices),
    'vrf_count': len(vrfs)
}
if parse_errors:
    _resp['parse_errors'] = parse_errors
    _resp['warning'] = 'Some host_vars files could not be parsed: ' + ', '.join(parse_errors)
print(json.dumps(_resp))
PYTHON
}

# Get port profiles
get_port_profiles() {
    local port_file="$ANSIBLE_DIR/inventory/group_vars/all/sw_port_profiles.yaml"
    
    if [[ ! -f "$port_file" ]]; then
        echo '{"success": false, "error": "Port profiles file not found"}'
        return
    fi
    
    python3 << 'PYTHON'
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
port_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

try:
    with open(port_file, 'r') as f:
        config = yaml.load(f) or {}
    
    print(json.dumps({
        'success': True,
        'port_profiles': config.get('sw_port_profiles', {})
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Get BGP Profiles
get_bgp_profiles() {
    local bgp_file="$ANSIBLE_DIR/inventory/group_vars/all/bgp_profiles.yaml"
    
    if [[ ! -f "$bgp_file" ]]; then
        echo '{"success": false, "error": "BGP profiles file not found"}'
        return
    fi
    
    python3 << 'PYTHON'
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

try:
    with open(bgp_file, 'r') as f:
        config = yaml.load(f) or {}

    bgp_profiles = config.get('bgp_profiles', {})
    # Filtered name list for dropdowns (exclude underlay profiles)
    profiles = [{'name': name} for name in sorted(bgp_profiles.keys())
                if not name.startswith('VxLAN_UNDERLAY')]

    print(json.dumps({
        'success': True,
        'profiles': profiles,
        'bgp_profiles': bgp_profiles,
        'infra_vrfs': config.get('infra_vrfs') or ['default']
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Create BGP Profile (using ruamel.yaml to preserve comments)
create_bgp_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import os
import re
import sys
import tempfile
import shutil
from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

profile_name = data.get('profile_name', '').strip()
redistribute_connected = data.get('redistribute_connected', True)
redistribute_static = data.get('redistribute_static', False)
export_to_evpn_type5 = data.get('export_to_evpn_type5', False)
enable_evpn = data.get('enable_evpn', False)
peer_groups = data.get('peer_groups', {})

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', profile_name):
    print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

try:
    with open(bgp_file, 'r') as f:
        config = yaml.load(f) or {}
    
    if 'bgp_profiles' not in config:
        config['bgp_profiles'] = {}
    
    if profile_name in config['bgp_profiles']:
        print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
        sys.exit(0)
    
    # Build profile entry
    profile_entry = {
        'ipv4_unicast_af': {
            'redistribute_connected_routes': redistribute_connected,
            'redistribute_static_routes': redistribute_static
        }
    }
    
    if export_to_evpn_type5:
        profile_entry['ipv4_unicast_af']['export_to_evpn_type5'] = True
    
    if enable_evpn:
        profile_entry['l2vpn_evpn_af'] = {'enable_evpn': True}
    
    if peer_groups:
        # Existing data omits enable_evpn when off - drop explicit false
        for pg_val in peer_groups.values():
            if hasattr(pg_val, 'get') and pg_val.get('enable_evpn') is False:
                pg_val.pop('enable_evpn', None)
        profile_entry['peer_groups'] = peer_groups

    config['bgp_profiles'][profile_name] = profile_entry
    
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(bgp_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, bgp_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(config, _tmp_f)
        shutil.move(_tmp_path, bgp_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({
        'success': True,
        'message': f'BGP profile {profile_name} created successfully'
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Update BGP Profile (using ruamel.yaml to preserve comments)
update_bgp_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_REF_SCAN_DEF
import json
import os
import re
import sys
import glob
import tempfile
import shutil
from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

original_name = data.get('original_name', '').strip()
profile_name = data.get('profile_name', '').strip()
redistribute_connected = data.get('redistribute_connected', True)
redistribute_static = data.get('redistribute_static', False)
export_to_evpn_type5 = data.get('export_to_evpn_type5', False)
enable_evpn = data.get('enable_evpn', False)
peer_groups = data.get('peer_groups', {})
removed_peer_groups = data.get('removed_peer_groups', []) or []

if not original_name or not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile names are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', profile_name):
    print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

try:
    with open(bgp_file, 'r') as f:
        config = yaml.load(f) or {}

    if 'bgp_profiles' not in config or original_name not in config['bgp_profiles']:
        print(json.dumps({'success': False, 'error': f'Profile {original_name} not found'}))
        sys.exit(0)

    if original_name != profile_name and profile_name in config['bgp_profiles']:
        print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
        sys.exit(0)

    # MERGE onto the existing entry so route-leaking (ipv4_unicast_af.route_import
    # from_vrf/route_map) and dict-form per-peer attributes are preserved.
    profile_entry = config['bgp_profiles'].get(original_name)
    if not hasattr(profile_entry, 'get'):
        profile_entry = {}

    af = profile_entry.get('ipv4_unicast_af')
    if not hasattr(af, 'get'):
        af = {}
        profile_entry['ipv4_unicast_af'] = af
    af['redistribute_connected_routes'] = redistribute_connected
    af['redistribute_static_routes'] = redistribute_static
    if export_to_evpn_type5:
        af['export_to_evpn_type5'] = True
    else:
        af.pop('export_to_evpn_type5', None)
    # NOTE: af['route_import'] intentionally left untouched (route leaking).

    if enable_evpn:
        evpn = profile_entry.get('l2vpn_evpn_af')
        if not hasattr(evpn, 'get'):
            evpn = {}
            profile_entry['l2vpn_evpn_af'] = evpn
        evpn['enable_evpn'] = True
    else:
        profile_entry.pop('l2vpn_evpn_af', None)

    # Merge peer_groups so existing per-peer dict attributes survive. Only the
    # peer groups the modal sends are touched; others are left intact.
    if peer_groups:
        existing_pg = profile_entry.get('peer_groups')
        if not hasattr(existing_pg, 'get'):
            existing_pg = {}
            profile_entry['peer_groups'] = existing_pg
        for pg_name, pg_val in peer_groups.items():
            # Peer-group enable_evpn: false means "off" - existing data omits
            # the key when EVPN is disabled, so remove instead of storing false.
            if hasattr(pg_val, 'get') and pg_val.get('enable_evpn') is False:
                pg_val.pop('enable_evpn', None)
                cur = existing_pg.get(pg_name)
                if hasattr(cur, 'pop'):
                    cur.pop('enable_evpn', None)
            cur = existing_pg.get(pg_name)
            if hasattr(cur, 'update') and hasattr(pg_val, 'items'):
                # Merge peers per-key: the modal sends the authoritative peer
                # set (values are {}), so keep existing attrs (weight, policy,
                # soft_reconfiguration) for retained peers and drop absent ones.
                new_peers = pg_val.pop('peers', None)
                cur.update(pg_val)
                if new_peers is not None:
                    old_peers = cur.get('peers')
                    if hasattr(new_peers, 'items') and hasattr(old_peers, 'get'):
                        merged_peers = {}
                        for p, p_val in new_peers.items():
                            prev = old_peers.get(p)
                            merged_peers[p] = prev if hasattr(prev, 'items') and not p_val else p_val
                        cur['peers'] = merged_peers
                    else:
                        cur['peers'] = new_peers
            else:
                existing_pg[pg_name] = pg_val

    # Delete peer groups the modal explicitly removed
    if removed_peer_groups:
        existing_pg = profile_entry.get('peer_groups')
        if hasattr(existing_pg, 'pop'):
            for pg_name in removed_peer_groups:
                if pg_name not in peer_groups:
                    existing_pg.pop(pg_name, None)

    # Remove old profile if renaming
    if original_name != profile_name:
        del config['bgp_profiles'][original_name]

    config['bgp_profiles'][profile_name] = profile_entry

    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(bgp_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, bgp_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(config, _tmp_f)
        shutil.move(_tmp_path, bgp_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise

    # On rename, rewrite vrfs.*.bgp.bgp_profile references in host_vars (and
    # group_vars, which can also carry vrfs) so no dangling refs are left.
    updated_hosts = []
    update_errors = {}
    if original_name != profile_name:
        inventory_base = os.path.join(ansible_dir, 'inventory')
        host_vars_dir = os.path.join(inventory_base, 'host_vars')
        ref_files = _iter_inventory_var_files(inventory_base, _exclude=(bgp_file,))
        for hv in ref_files:
            try:
                with open(hv, 'r') as f:
                    hv_cfg = yaml.load(f) or {}
            except Exception:
                continue
            if not hasattr(hv_cfg, 'get'):
                continue
            changed = False
            vrfs = hv_cfg.get('vrfs')
            if hasattr(vrfs, 'items'):
                for _vrf_name, vrf_cfg in vrfs.items():
                    if hasattr(vrf_cfg, 'get'):
                        bgp = vrf_cfg.get('bgp')
                        if hasattr(bgp, 'get') and bgp.get('bgp_profile') == original_name:
                            bgp['bgp_profile'] = profile_name
                            changed = True
            if changed:
                _hfd, _hpath = tempfile.mkstemp(dir=os.path.dirname(hv), suffix='.tmp')
                _lldpq_mode_floor(_hfd, hv)
                try:
                    with os.fdopen(_hfd, 'w') as _hf:
                        yaml.dump(hv_cfg, _hf)
                    shutil.move(_hpath, hv)
                    if os.path.dirname(hv) == host_vars_dir:
                        updated_hosts.append(os.path.basename(hv).rsplit('.', 1)[0])
                    else:
                        updated_hosts.append(os.path.relpath(hv, inventory_base))
                except Exception as _we:
                    if os.path.exists(_hpath): os.unlink(_hpath)
                    update_errors[os.path.relpath(hv, inventory_base)] = str(_we)

    _resp = {
        'success': True,
        'message': f'BGP profile {profile_name} updated successfully',
        'updated_hosts': updated_hosts
    }
    if update_errors:
        _resp['update_errors'] = update_errors
    print(json.dumps(_resp))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Delete BGP Profile (using ruamel.yaml to preserve comments)
delete_bgp_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_REF_SCAN_DEF
import json
import os
import sys
import glob
import tempfile
import shutil
from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

profile_name = data.get('profile_name', '').strip()

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

try:
    with open(bgp_file, 'r') as f:
        config = yaml.load(f) or {}

    if 'bgp_profiles' not in config or profile_name not in config['bgp_profiles']:
        print(json.dumps({'success': False, 'error': f'Profile {profile_name} not found'}))
        sys.exit(0)

    # Refuse to delete a profile that is still referenced by any VRF's
    # bgp.bgp_profile in host_vars or group_vars (group_vars can also carry
    # vrfs; a dangling ref silently drops the VRF's BGP stanza on render).
    in_use = _scan_bgp_profile_refs(f"{ansible_dir}/inventory", yaml, profile_name)
    if in_use:
        print(json.dumps({
            'success': False,
            'error': f'BGP profile {profile_name} is still in use by {len(in_use)} VRF(s)',
            'in_use': in_use
        }))
        sys.exit(0)

    del config['bgp_profiles'][profile_name]
    
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(bgp_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, bgp_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(config, _tmp_f)
        shutil.move(_tmp_path, bgp_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({
        'success': True,
        'message': f'BGP profile {profile_name} deleted successfully'
    }))

except Exception as e:
    print(json.dumps({
        'success': False,
        'error': str(e)
    }))
PYTHON
}

# Create Port Profile
create_port_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

profile_name = data.get('profile_name', '').strip()
sw_port_mode = data.get('sw_port_mode', 'access')
description = data.get('description', '')
access_vlan = data.get('access_vlan')
native_vlan = data.get('native_vlan')
trunk_allowed_vlans = data.get('trunk_allowed_vlans', [])
trunk_allowed_vlan_all = data.get('trunk_allowed_vlan_all', False)
stp_bpduguard = data.get('stp_bpduguard', True)
stp_portadminedge = data.get('stp_portadminedge', True)
stp_portautoedgedisable = data.get('stp_portautoedgedisable', True)

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', profile_name):
    print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
port_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

# Load existing
config = {}
if os.path.exists(port_file):
    with open(port_file, 'r') as f:
        config = yaml.load(f) or {}

if 'sw_port_profiles' not in config:
    config['sw_port_profiles'] = {}

if profile_name in config['sw_port_profiles']:
    print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
    sys.exit(0)

# Build profile entry
profile_entry = {
    'sw_port_mode': sw_port_mode
}

if description:
    profile_entry['description'] = description

if sw_port_mode == 'access':
    if access_vlan:
        profile_entry['access_vlan'] = int(access_vlan)
    profile_entry['stp_bpduguard'] = stp_bpduguard
    profile_entry['stp_portadminedge'] = stp_portadminedge
    profile_entry['stp_portautoedgedisable'] = stp_portautoedgedisable
elif sw_port_mode == 'trunk':
    if native_vlan:
        profile_entry['trunk_untagged'] = int(native_vlan)
    if trunk_allowed_vlan_all:
        profile_entry['trunk_allowed_vlan_all'] = True
    elif trunk_allowed_vlans:
        profile_entry['trunk_allowed_vlan_list'] = trunk_allowed_vlans

config['sw_port_profiles'][profile_name] = profile_entry

_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(port_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, port_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(config, _tmp_f)
    shutil.move(_tmp_path, port_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

print(json.dumps({'success': True, 'profile_name': profile_name}))
PYTHON
}

# Update Port Profile
update_port_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
import glob
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

original_name = data.get('original_name', '').strip()
profile_name = data.get('profile_name', '').strip()
sw_port_mode = data.get('sw_port_mode', 'access')
description = data.get('description')  # None = not submitted, '' = explicit clear
access_vlan = data.get('access_vlan')
native_vlan = data.get('native_vlan')
trunk_allowed_vlans = data.get('trunk_allowed_vlans', [])
trunk_allowed_vlan_all = data.get('trunk_allowed_vlan_all', False)
# None = not submitted by the modal (it only sends stp_* in access mode)
stp_bpduguard = data.get('stp_bpduguard')
stp_portadminedge = data.get('stp_portadminedge')
stp_portautoedgedisable = data.get('stp_portautoedgedisable')

if not original_name:
    print(json.dumps({'success': False, 'error': 'Original profile name is required'}))
    sys.exit(0)

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', profile_name):
    print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
port_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

config = {}
if os.path.exists(port_file):
    with open(port_file, 'r') as f:
        config = yaml.load(f) or {}

if 'sw_port_profiles' not in config or original_name not in config['sw_port_profiles']:
    print(json.dumps({'success': False, 'error': f'Profile {original_name} not found'}))
    sys.exit(0)

# Reject rename onto an already-existing profile name
if original_name != profile_name and profile_name in config['sw_port_profiles']:
    print(json.dumps({'success': False, 'error': f'Profile {profile_name} already exists'}))
    sys.exit(0)

# Merge on top of the existing entry so keys not covered by the modal
# (e.g. stp_* on trunk profiles) survive the edit.
existing_entry = config['sw_port_profiles'].get(original_name)
if not hasattr(existing_entry, 'get'):
    existing_entry = {}
profile_entry = existing_entry
profile_entry['sw_port_mode'] = sw_port_mode

# description: absent/None = leave unchanged, '' = explicit clear
if description is not None:
    if description:
        profile_entry['description'] = description
    else:
        profile_entry.pop('description', None)

if sw_port_mode == 'access':
    if access_vlan:
        profile_entry['access_vlan'] = int(access_vlan)
    else:
        profile_entry.pop('access_vlan', None)
    profile_entry['stp_bpduguard'] = True if stp_bpduguard is None else stp_bpduguard
    profile_entry['stp_portadminedge'] = True if stp_portadminedge is None else stp_portadminedge
    profile_entry['stp_portautoedgedisable'] = True if stp_portautoedgedisable is None else stp_portautoedgedisable
    # Access profiles carry no trunk keys
    for k in ('trunk_untagged', 'trunk_allowed_vlan_all', 'trunk_allowed_vlan_list', 'trunk_allowed_vlan_range'):
        profile_entry.pop(k, None)
elif sw_port_mode == 'trunk':
    # The modal expresses membership as trunk_allowed_vlan_list/_all only, so
    # drop any pre-existing trunk_allowed_vlan_range: template precedence is
    # all > range > list (swp_ports.j2), and a stale range would shadow the edit.
    profile_entry.pop('trunk_allowed_vlan_range', None)
    if native_vlan:
        profile_entry['trunk_untagged'] = int(native_vlan)
    else:
        profile_entry.pop('trunk_untagged', None)
    # The modal payload is authoritative for trunk membership: drop both keys
    # first, then set exactly the one submitted (neither = no tagged VLANs),
    # so an explicit empty selection cannot leave a stale key behind.
    profile_entry.pop('trunk_allowed_vlan_all', None)
    profile_entry.pop('trunk_allowed_vlan_list', None)
    if trunk_allowed_vlan_all:
        profile_entry['trunk_allowed_vlan_all'] = True
    elif trunk_allowed_vlans:
        profile_entry['trunk_allowed_vlan_list'] = trunk_allowed_vlans
    # Trunk profiles legitimately carry stp_* options, but the modal does not
    # send them in trunk mode: only set what was submitted, preserve the rest.
    if stp_bpduguard is not None:
        profile_entry['stp_bpduguard'] = stp_bpduguard
    if stp_portadminedge is not None:
        profile_entry['stp_portadminedge'] = stp_portadminedge
    if stp_portautoedgedisable is not None:
        profile_entry['stp_portautoedgedisable'] = stp_portautoedgedisable
    # Access-only key does not belong on a trunk profile
    profile_entry.pop('access_vlan', None)

# Remove old if renaming
if original_name != profile_name:
    del config['sw_port_profiles'][original_name]

config['sw_port_profiles'][profile_name] = profile_entry

_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(port_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, port_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(config, _tmp_f)
    shutil.move(_tmp_path, port_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

# On rename, rewrite sw_port_profile references in interfaces{}/bonds{} across
# every inventory var file (host_vars *.yaml/*.yml + group_vars)
updated_hosts = []
update_errors = {}
if original_name != profile_name:
    inventory_base = f"{ansible_dir}/inventory"
    host_vars_dir = os.path.join(inventory_base, 'host_vars')
    for hv in _iter_inventory_var_files(inventory_base, _exclude=(port_file,)):
        try:
            with open(hv, 'r') as f:
                hv_cfg = yaml.load(f) or {}
        except Exception:
            continue
        if not hasattr(hv_cfg, 'get'):
            continue
        changed = False
        for section in ('interfaces', 'bonds'):
            sect = hv_cfg.get(section)
            if not hasattr(sect, 'items'):
                continue
            for _pname, pcfg in sect.items():
                if hasattr(pcfg, 'get') and pcfg.get('sw_port_profile') == original_name:
                    pcfg['sw_port_profile'] = profile_name
                    changed = True
        if changed:
            _hfd, _hpath = tempfile.mkstemp(dir=os.path.dirname(hv), suffix='.tmp')
            _lldpq_mode_floor(_hfd, hv)
            try:
                with os.fdopen(_hfd, 'w') as _hf:
                    yaml.dump(hv_cfg, _hf)
                shutil.move(_hpath, hv)
                if os.path.dirname(hv) == host_vars_dir:
                    updated_hosts.append(os.path.basename(hv).rsplit('.', 1)[0])
                else:
                    updated_hosts.append(os.path.relpath(hv, inventory_base))
            except Exception as _we:
                if os.path.exists(_hpath): os.unlink(_hpath)
                update_errors[os.path.relpath(hv, inventory_base)] = str(_we)

_resp = {'success': True, 'profile_name': profile_name, 'updated_hosts': updated_hosts}
if update_errors:
    _resp['update_errors'] = update_errors
print(json.dumps(_resp))
PYTHON
}

# Delete Port Profile
delete_port_profile() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_REF_SCAN_DEF
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

profile_name = data.get('profile_name', '').strip()

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
port_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

config = {}
if os.path.exists(port_file):
    with open(port_file, 'r') as f:
        config = yaml.load(f) or {}

if 'sw_port_profiles' not in config or profile_name not in config['sw_port_profiles']:
    print(json.dumps({'success': False, 'error': f'Profile {profile_name} not found'}))
    sys.exit(0)

# Refuse to delete a profile still referenced by interfaces{}/bonds{} in
# host_vars/group_vars (same guard as delete_bgp_profile): the templates
# silently skip a dangling sw_port_profile ref, stripping the port's whole
# bridge stanza on the next deploy.
in_use = _scan_port_profile_refs(f"{ansible_dir}/inventory", yaml, profile_name)
if in_use:
    print(json.dumps({
        'success': False,
        'error': f'Port profile {profile_name} is still in use by {len(in_use)} port(s)',
        'in_use': in_use
    }))
    sys.exit(0)

del config['sw_port_profiles'][profile_name]

_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(port_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, port_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(config, _tmp_f)
    shutil.move(_tmp_path, port_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

print(json.dumps({'success': True, 'deleted': profile_name}))
PYTHON
}

# Create VLAN - adds to vlan_profiles.yaml and sw_port_profiles.yaml
create_vlan() {
    acquire_lock
    # Read POST data
    read_post_body
    export POST_DATA

    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys
from datetime import datetime

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"
port_profiles_file = f"{ansible_dir}/inventory/group_vars/all/sw_port_profiles.yaml"

try:
    # Parse POST data
    data = json.loads(os.environ.get('POST_DATA') or '{}')
    
    vlan_id = int(data.get('vlan_id'))
    profile_name = data.get('profile_name', f'VLAN_{vlan_id}')
    if not re.match(r'^[A-Za-z0-9_.-]+$', str(profile_name)):
        print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
        sys.exit(0)
    description = data.get('description', '')
    l2vni = data.get('l2vni', 100000 + vlan_id)
    stp_bpduguard = data.get('stp_bpduguard', True)
    
    # SVI/L3 configuration
    svi_enabled = data.get('svi_enabled', False)
    vrf = data.get('vrf', 'default') if svi_enabled else None
    vrr_enabled = data.get('vrr_enabled', False) if svi_enabled else False
    vrr_vip = data.get('vrr_vip', '')
    even_ip = data.get('even_ip', '')
    odd_ip = data.get('odd_ip', '')
    vrr_vmac = data.get('vrr_vmac', '')
    gateway_ip = data.get('gateway_ip', '')
    
    # Validate VLAN ID
    if vlan_id < 1 or vlan_id > 4094:
        print(json.dumps({'success': False, 'error': 'VLAN ID must be between 1 and 4094'}))
        sys.exit(0)

    # Validate L2VNI and the SVI fields the templates render raw
    l2vni = _v_int_range(l2vni, 1, 16777215)
    if l2vni is None:
        print(json.dumps({'success': False, 'error': 'Invalid L2VNI (must be 1-16777215)'}))
        sys.exit(0)
    if svi_enabled:
        if not _v_name(vrf):
            print(json.dumps({'success': False, 'error': 'Invalid VRF name'}))
            sys.exit(0)
        for _label, _ipval in (('gateway IP', gateway_ip), ('VRR VIP', vrr_vip), ('even IP', even_ip), ('odd IP', odd_ip)):
            if _ipval and _v_ip_interface(_ipval) is None:
                print(json.dumps({'success': False, 'error': f'Invalid {_label}: {_ipval}'}))
                sys.exit(0)
        if vrr_vmac and not _v_mac(vrr_vmac):
            print(json.dumps({'success': False, 'error': f'Invalid VRR VMAC: {vrr_vmac}'}))
            sys.exit(0)

    # Load existing vlan_profiles
    vlan_config = {}
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            vlan_config = yaml.load(f) or {}
    
    if 'vlan_profiles' not in vlan_config:
        vlan_config['vlan_profiles'] = {}
    
    # Check if VLAN profile already exists
    if profile_name in vlan_config['vlan_profiles']:
        print(json.dumps({'success': False, 'error': f'VLAN profile {profile_name} already exists'}))
        sys.exit(0)
    
    # Check if VLAN ID already used
    for pname, pdata in vlan_config['vlan_profiles'].items():
        if pdata and 'vlans' in pdata:
            if vlan_id in pdata['vlans'] or str(vlan_id) in pdata['vlans']:
                print(json.dumps({'success': False, 'error': f'VLAN ID {vlan_id} already exists in profile {pname}'}))
                sys.exit(0)
    
    # Build VLAN entry
    vlan_entry = {
        'description': description,
        'l2vni': l2vni
    }
    
    # Add VRF and IP info only if SVI is enabled
    if svi_enabled:
        vlan_entry['vrf'] = vrf
        vlan_entry['ipv6'] = False  # Always disabled
        
        if vrr_enabled:
            # VRR mode with VIP and Even/Odd IPs
            if vrr_vip:
                vlan_entry['vrr_vip'] = vrr_vip
            if even_ip:
                vlan_entry['even_ip'] = even_ip
            if odd_ip:
                vlan_entry['odd_ip'] = odd_ip
            if vrr_vmac:
                vlan_entry['vrr_vmac'] = vrr_vmac
        else:
            # Single gateway IP mode
            if gateway_ip:
                vlan_entry['ip'] = gateway_ip
    
    # Build profile entry
    profile_entry = {
        'vrr': {'state': vrr_enabled if svi_enabled else False},
        'vlans': {vlan_id: vlan_entry}
    }
    
    # Add to vlan_profiles
    vlan_config['vlan_profiles'][profile_name] = profile_entry

    # Load existing port_profiles BEFORE any write: a corrupt/unreadable
    # sw_port_profiles.yaml must fail the whole action while it is still
    # retryable (nothing persisted yet)
    port_config = {}
    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            port_config = yaml.load(f) or {}

    if 'sw_port_profiles' not in port_config:
        port_config['sw_port_profiles'] = {}

    # Create ACCESS_VLAN_{id} profile
    access_profile_name = f'ACCESS_VLAN_{vlan_id}'
    _writes = [(vlan_config, vlan_profiles_file)]
    if access_profile_name not in port_config['sw_port_profiles']:
        port_config['sw_port_profiles'][access_profile_name] = {
            'description': description,
            'sw_port_mode': 'access',
            'access_vlan': vlan_id,
            'stp_bpduguard': stp_bpduguard
        }
        _writes.append((port_config, port_profiles_file))

    # Two-phase commit: both files are staged first, renamed only after both
    # dumps succeeded
    _atomic_write_many(yaml, _writes)

    print(json.dumps({
        'success': True,
        'message': f'VLAN {vlan_id} created successfully',
        'vlan_profile': profile_name,
        'port_profile': access_profile_name
    }))

except json.JSONDecodeError as e:
    print(json.dumps({'success': False, 'error': f'Invalid JSON: {str(e)}'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

# Get list of VRFs for dropdown
get_vrfs() {
    python3 << 'PYTHON'
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
vlan_profiles_file = f"{ansible_dir}/inventory/group_vars/all/vlan_profiles.yaml"

vrfs = set(['default'])

try:
    # Check vxlan_int mapping for VRF names
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            config = yaml.load(f) or {}
        
        # Get VRFs from vxlan_int mapping
        if 'vxlan_int' in config:
            vrfs.update(config['vxlan_int'].keys())
        
        # Get VRFs from vlan_profiles
        if 'vlan_profiles' in config:
            for profile in config['vlan_profiles'].values():
                if profile and 'vlans' in profile:
                    for vlan in profile['vlans'].values():
                        if vlan and 'vrf' in vlan:
                            vrfs.add(vlan['vrf'])
    
    print(json.dumps({
        'success': True,
        'vrfs': sorted(list(vrfs))
    }))

except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

delete_vlan() {
    acquire_lock
    # Read POST data
    read_post_body
    export POST_DATA

    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_REF_SCAN_DEF
import json
import glob
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

# Parse POST data
data = json.loads(os.environ.get('POST_DATA') or '{}')

profile_name = data.get('profile_name', '')

if not profile_name:
    print(json.dumps({'success': False, 'error': 'Profile name is required'}))
    sys.exit(0)

# Paths
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
vlan_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')
port_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'sw_port_profiles.yaml')

# Load vlan_profiles
vlan_config = {}
if os.path.exists(vlan_profiles_file):
    with open(vlan_profiles_file, 'r') as f:
        vlan_config = yaml.load(f) or {}

if 'vlan_profiles' not in vlan_config or profile_name not in vlan_config['vlan_profiles']:
    print(json.dumps({'success': False, 'error': f'VLAN profile {profile_name} not found'}))
    sys.exit(0)

# Get ALL VLAN IDs (a profile can carry several VLANs; each has its own
# ACCESS_VLAN_{id} port profile to cascade-delete)
vlan_ids = []
profile_data = vlan_config['vlan_profiles'][profile_name]
if profile_data and 'vlans' in profile_data:
    vlan_ids = list(profile_data['vlans'].keys())

# Refuse when any port still references a cascade-deleted ACCESS_VLAN_{id}
# profile (same guard as delete_port_profile): the templates silently skip
# a dangling sw_port_profile ref, stripping the port's bridge stanza on the
# next deploy.
in_use = []
for _vid in vlan_ids:
    in_use += _scan_port_profile_refs(inventory_base, yaml, f'ACCESS_VLAN_{_vid}')
if in_use:
    print(json.dumps({
        'success': False,
        'error': f'VLAN profile {profile_name}: ACCESS_VLAN port profile(s) still in use by {len(in_use)} port(s)',
        'in_use': in_use
    }))
    sys.exit(0)

# Delete from vlan_profiles
del vlan_config['vlan_profiles'][profile_name]

# Load the corresponding port profile(s) - one per VLAN ID - BEFORE writing
# vlan_profiles, so a parse error aborts before any file was mutated
port_profile_deleted = False
port_profile_name = None
port_config = {}
_pp_changed = False
if vlan_ids:
    port_profile_name = f'ACCESS_VLAN_{vlan_ids[0]}'

    if os.path.exists(port_profiles_file):
        with open(port_profiles_file, 'r') as f:
            port_config = yaml.load(f) or {}

    if 'sw_port_profiles' in port_config:
        for _vid in vlan_ids:
            _pp = f'ACCESS_VLAN_{_vid}'
            if _pp in port_config['sw_port_profiles']:
                del port_config['sw_port_profiles'][_pp]
                _pp_changed = True

# Two-phase commit: stage both dumps, rename only after every dump succeeded
_writes = [(vlan_config, vlan_profiles_file)]
if _pp_changed:
    _writes.append((port_config, port_profiles_file))
_atomic_write_many(yaml, _writes)
if _pp_changed:
    port_profile_deleted = True

# Cascade: remove the deleted profile from vlan_templates in every inventory
# var file (host_vars *.yaml/*.yml + group_vars) so no dangling refs are left.
updated_hosts = []
update_errors = {}
host_vars_dir = os.path.join(inventory_base, 'host_vars')
for hv in _iter_inventory_var_files(inventory_base, _exclude=(vlan_profiles_file, port_profiles_file)):
    try:
        with open(hv, 'r') as f:
            hv_cfg = yaml.load(f) or {}
    except Exception:
        continue
    if not hasattr(hv_cfg, 'get'):
        continue
    templates = hv_cfg.get('vlan_templates')
    if not isinstance(templates, list) or profile_name not in templates:
        continue
    while profile_name in templates:
        templates.remove(profile_name)
    _hfd, _hpath = tempfile.mkstemp(dir=os.path.dirname(hv), suffix='.tmp')
    _lldpq_mode_floor(_hfd, hv)
    try:
        with os.fdopen(_hfd, 'w') as _hf:
            yaml.dump(hv_cfg, _hf)
        shutil.move(_hpath, hv)
        if os.path.dirname(hv) == host_vars_dir:
            updated_hosts.append(os.path.basename(hv).rsplit('.', 1)[0])
        else:
            updated_hosts.append(os.path.relpath(hv, inventory_base))
    except Exception as _we:
        if os.path.exists(_hpath): os.unlink(_hpath)
        update_errors[os.path.relpath(hv, inventory_base)] = str(_we)

_resp = {
    'success': True,
    'profile_name': profile_name,
    'port_profile': port_profile_name,
    'port_profile_deleted': port_profile_deleted,
    'updated_hosts': updated_hosts
}
if update_errors:
    _resp['update_errors'] = update_errors
print(json.dumps(_resp))
PYTHON
}

assign_vlans() {
    acquire_lock
    # Read POST data
    read_post_body
    export POST_DATA

    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

# Parse POST data
data = json.loads(os.environ.get('POST_DATA') or '{}')

device = data.get('device', '')
vlans = data.get('vlans', [])

if not device:
    print(json.dumps({'success': False, 'error': 'Device name is required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

if not vlans:
    print(json.dumps({'success': False, 'error': 'No VLANs selected'}))
    sys.exit(0)

# Path to host_vars
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

if not os.path.exists(host_vars_file):
    # Also try without .yaml
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yml')

# Load host_vars or create empty config
host_config = {}
if os.path.exists(host_vars_file):
    with open(host_vars_file, 'r') as f:
        host_config = yaml.load(f) or {}
else:
    # Create new file with .yaml extension
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

# Add VLANs to vlan_templates
if 'vlan_templates' not in host_config:
    host_config['vlan_templates'] = []

# Add new VLANs (avoid duplicates)
added = []
for vlan in vlans:
    if vlan not in host_config['vlan_templates']:
        host_config['vlan_templates'].append(vlan)
        added.append(vlan)

# Save host_vars
_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_vars_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, host_vars_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(host_config, _tmp_f)
    shutil.move(_tmp_path, host_vars_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

print(json.dumps({
    'success': True,
    'device': device,
    'added_vlans': added,
    'total_vlans': len(host_config['vlan_templates'])
}))
PYTHON
}

unassign_vlan() {
    acquire_lock
    # Read POST data
    read_post_body
    export POST_DATA

    python3 << PYTHON
$LLDPQ_JSON_EXCEPTHOOK_DEF
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

# Parse POST data
data = json.loads(os.environ.get('POST_DATA') or '{}')

device = data.get('device', '')
vlan = data.get('vlan', '')

if not device:
    print(json.dumps({'success': False, 'error': 'Device name is required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

if not vlan:
    print(json.dumps({'success': False, 'error': 'VLAN name is required'}))
    sys.exit(0)

# Path to host_vars
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')
host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')

# Try .yaml first, then .yml
if not os.path.exists(host_vars_file):
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yml')

# Load host_vars (create empty if doesn't exist)
host_config = {}
if os.path.exists(host_vars_file):
    with open(host_vars_file, 'r') as f:
        host_config = yaml.load(f) or {}
else:
    # File doesn't exist - check if we should create it
    # Use .yaml extension for new files
    host_vars_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')
    host_config = {}

# Check if VLAN is in vlan_templates
if 'vlan_templates' not in host_config or vlan not in host_config.get('vlan_templates', []):
    print(json.dumps({'success': False, 'error': f'VLAN {vlan} not found in device config (may be inherited from group_vars)'}))
    sys.exit(0)

# Remove VLAN from vlan_templates
host_config['vlan_templates'].remove(vlan)

# Save host_vars
_tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_vars_file), suffix='.tmp')
_lldpq_mode_floor(_tmp_fd, host_vars_file)
try:
    with os.fdopen(_tmp_fd, 'w') as _tmp_f:
        yaml.dump(host_config, _tmp_f)
    shutil.move(_tmp_path, host_vars_file)
except:
    if os.path.exists(_tmp_path): os.unlink(_tmp_path)
    raise

print(json.dumps({
    'success': True,
    'device': device,
    'removed_vlan': vlan
}))
PYTHON
}

update_vlan() {
    acquire_lock
    # Read POST data
    read_post_body
    export POST_DATA

    python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
import glob
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    # Parse POST data
    data = json.loads(os.environ.get('POST_DATA') or '{}')

    original_name = data.get('original_name', '')
    profile_name = data.get('profile_name', original_name)
    vlan_id = data.get('vlan_id')
    description = data.get('description', '')
    l2vni = data.get('l2vni')
    svi_enabled = data.get('svi_enabled', False)
    vrr_enabled = data.get('vrr_enabled', False)
    vrf = data.get('vrf', 'default')
    vrr_vip = data.get('vrr_vip', '')
    even_ip = data.get('even_ip', '')
    odd_ip = data.get('odd_ip', '')
    vrr_vmac = data.get('vrr_vmac', '')
    gateway_ip = data.get('gateway_ip', '')

    if not original_name:
        print(json.dumps({'success': False, 'error': 'Original profile name is required'}))
        sys.exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(profile_name)):
        print(json.dumps({'success': False, 'error': 'Invalid profile name (allowed: letters, digits, _ . -)'}))
        sys.exit(0)

    # Validate the SVI fields the templates render raw (same as create_vlan)
    if svi_enabled:
        if not _v_name(vrf):
            print(json.dumps({'success': False, 'error': 'Invalid VRF name'}))
            sys.exit(0)
        for _label, _ipval in (('gateway IP', gateway_ip), ('VRR VIP', vrr_vip), ('even IP', even_ip), ('odd IP', odd_ip)):
            if _ipval and _v_ip_interface(_ipval) is None:
                print(json.dumps({'success': False, 'error': f'Invalid {_label}: {_ipval}'}))
                sys.exit(0)
        if vrr_vmac and not _v_mac(vrr_vmac):
            print(json.dumps({'success': False, 'error': f'Invalid VRR VMAC: {vrr_vmac}'}))
            sys.exit(0)

    # Paths
    ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
    inventory_base = os.path.join(ansible_dir, 'inventory')
    vlan_profiles_file = os.path.join(inventory_base, 'group_vars', 'all', 'vlan_profiles.yaml')

    # Load vlan_profiles
    vlan_config = {}
    if os.path.exists(vlan_profiles_file):
        with open(vlan_profiles_file, 'r') as f:
            vlan_config = yaml.load(f) or {}

    if 'vlan_profiles' not in vlan_config or original_name not in vlan_config['vlan_profiles']:
        print(json.dumps({'success': False, 'error': f'VLAN profile {original_name} not found'}))
        sys.exit(0)

    is_rename = profile_name != original_name

    # Reject rename onto an already-existing profile (mirror create_vlan guard)
    if is_rename and profile_name in vlan_config['vlan_profiles']:
        print(json.dumps({'success': False, 'error': f'VLAN profile {profile_name} already exists'}))
        sys.exit(0)

    # Get existing profile data
    existing = vlan_config['vlan_profiles'][original_name]
    existing_vlans = existing.get('vlans', {}) or {}

    # Range / multi-VLAN profiles: vlan_id arrives null. Never build a null key
    # or compute '100000 + None'. Only a rename is supported for these.
    if vlan_id is None:
        if not is_rename:
            print(json.dumps({'success': False, 'error': 'Range/multi-VLAN profiles are not single-VLAN editable; only rename is supported'}))
            sys.exit(0)
        profile_entry = existing
    else:
        try:
            vlan_id = int(vlan_id)
        except (TypeError, ValueError):
            print(json.dumps({'success': False, 'error': 'Invalid VLAN ID'}))
            sys.exit(0)

        # Enforce the same 1-4094 range create_vlan does (the UI field is
        # readonly but the API must not trust the client)
        if vlan_id < 1 or vlan_id > 4094:
            print(json.dumps({'success': False, 'error': 'VLAN ID must be between 1 and 4094'}))
            sys.exit(0)

        if l2vni:
            l2vni = _v_int_range(l2vni, 1, 16777215)
            if l2vni is None:
                print(json.dumps({'success': False, 'error': 'Invalid L2VNI (must be 1-16777215)'}))
                sys.exit(0)

        # Merge onto the existing VLAN entry so schema keys the modal doesn't
        # cover (e.g. mcast_group, MLAG primary_ip/secondary_ip) survive.
        vlan_entry = existing_vlans.get(vlan_id, existing_vlans.get(str(vlan_id)))
        if not hasattr(vlan_entry, 'get'):
            vlan_entry = {}
        vlan_entry['description'] = description
        vlan_entry['l2vni'] = l2vni if l2vni else vlan_entry.get('l2vni', 100000 + vlan_id)

        if svi_enabled:
            vlan_entry['vrf'] = vrf
            vlan_entry.setdefault('ipv6', False)

            if vrr_enabled:
                for key, val in (('vrr_vip', vrr_vip), ('even_ip', even_ip), ('odd_ip', odd_ip), ('vrr_vmac', vrr_vmac)):
                    if val:
                        vlan_entry[key] = val
                    else:
                        vlan_entry.pop(key, None)
                vlan_entry.pop('ip', None)
            else:
                if gateway_ip:
                    vlan_entry['ip'] = gateway_ip
                else:
                    vlan_entry.pop('ip', None)
                for key in ('vrr_vip', 'even_ip', 'odd_ip', 'vrr_vmac'):
                    vlan_entry.pop(key, None)
        else:
            # SVI disabled: drop only the modal-managed L3 keys
            for key in ('vrf', 'ipv6', 'ip', 'vrr_vip', 'even_ip', 'odd_ip', 'vrr_vmac'):
                vlan_entry.pop(key, None)

        # Update this VLAN in the profile's existing vlans (preserve other VLANs)
        if vlan_id not in existing_vlans and str(vlan_id) in existing_vlans:
            existing_vlans[str(vlan_id)] = vlan_entry
        else:
            existing_vlans[vlan_id] = vlan_entry

        # Merge at profile level too (preserve keys other than vrr/vlans)
        profile_entry = existing
        vrr_cfg = profile_entry.get('vrr')
        if hasattr(vrr_cfg, 'get'):
            vrr_cfg['state'] = vrr_enabled if svi_enabled else False
        else:
            profile_entry['vrr'] = {'state': vrr_enabled if svi_enabled else False}
        profile_entry['vlans'] = existing_vlans

    # If profile name changed, remove old and add new
    if is_rename:
        del vlan_config['vlan_profiles'][original_name]

    vlan_config['vlan_profiles'][profile_name] = profile_entry

    # Save
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(vlan_profiles_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, vlan_profiles_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(vlan_config, _tmp_f)
        shutil.move(_tmp_path, vlan_profiles_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise

    # On rename, rewrite vlan_templates references (old -> new) in every
    # inventory var file (host_vars *.yaml/*.yml + group_vars)
    updated_hosts = []
    update_errors = {}
    if is_rename:
        host_vars_dir = os.path.join(inventory_base, 'host_vars')
        for hv in _iter_inventory_var_files(inventory_base, _exclude=(vlan_profiles_file,)):
            try:
                with open(hv, 'r') as f:
                    hv_cfg = yaml.load(f) or {}
            except Exception:
                continue
            if not hasattr(hv_cfg, 'get'):
                continue
            templates = hv_cfg.get('vlan_templates')
            if not isinstance(templates, list):
                continue
            changed = False
            for i, t in enumerate(templates):
                if t == original_name:
                    templates[i] = profile_name
                    changed = True
            if changed:
                _hfd, _hpath = tempfile.mkstemp(dir=os.path.dirname(hv), suffix='.tmp')
                _lldpq_mode_floor(_hfd, hv)
                try:
                    with os.fdopen(_hfd, 'w') as _hf:
                        yaml.dump(hv_cfg, _hf)
                    shutil.move(_hpath, hv)
                    if os.path.dirname(hv) == host_vars_dir:
                        updated_hosts.append(os.path.basename(hv).rsplit('.', 1)[0])
                    else:
                        updated_hosts.append(os.path.relpath(hv, inventory_base))
                except Exception as _we:
                    if os.path.exists(_hpath): os.unlink(_hpath)
                    update_errors[os.path.relpath(hv, inventory_base)] = str(_we)

    _resp = {
        'success': True,
        'profile_name': profile_name,
        'renamed': is_rename,
        'updated_hosts': updated_hosts
    }
    if update_errors:
        _resp['update_errors'] = update_errors
    print(json.dumps(_resp))

except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

# Bulk re-assignment of sw_port_profile across devices (Fabric Migration page).
# POST JSON: {plan_name, dry_run, changes: {device: {interfaces: {port: {old, new}},
# bonds: {bond: {old, new}}}}}. Every 'new' profile must exist in
# sw_port_profiles.yaml; a port whose current profile differs from 'old' is
# skipped (drift protection), never overwritten blindly. Applied changes are
# recorded as a plan JSON under $ANSIBLE_DIR/.migrations for audit/rollback.
migrate_port_profiles() {
    acquire_lock
    read_post_body 10485760
    # Bulk plans can exceed execve's per-env-string limit (~128 KB, E2BIG);
    # hand the body to python via a temp file instead of the environment.
    POST_DATA_FILE=$(mktemp /tmp/fabric-migrate.XXXXXX) || {
        echo '{"success": false, "error": "Cannot create temp file"}'
        return
    }
    printf '%s' "$POST_DATA" > "$POST_DATA_FILE"
    unset POST_DATA
    export POST_DATA_FILE

    python3 << 'PYTHON'
def _lldpq_mode_floor(_ffd, _fdst):
    # mkstemp defaults to 0600; keep inventory readable for git/backup sweeps
    import os as _fos
    _fmode = ((_fos.stat(_fdst).st_mode & 0o777) if _fos.path.exists(_fdst) else 0) | 0o644
    _fos.fchmod(_ffd, _fmode)
import json
import os
import re
import sys
import tempfile
import shutil
from datetime import datetime
from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True
# Emit sequences in the hand-maintained inventory house style ("  - item").
# NOTE: the other host_vars writers in this file still use ruamel defaults
# (dash at parent column); files edited by both endpoints will alternate
# list-indent styles until those writers adopt the same setting.
yaml.indent(mapping=2, sequence=4, offset=2)

NAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')


def fail(msg):
    print(json.dumps({'success': False, 'error': msg}))
    sys.exit(0)


try:
    with open(os.environ.get('POST_DATA_FILE') or '/dev/null') as _pf:
        data = json.loads(_pf.read() or '{}')
except Exception:
    fail('Invalid JSON payload')

changes = data.get('changes')
dry_run = bool(data.get('dry_run'))
plan_name = re.sub(r'[^A-Za-z0-9_-]', '-', str(data.get('plan_name') or 'migration'))[:64] or 'migration'

if not isinstance(changes, dict) or not changes:
    fail('No changes provided')

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
inventory_base = os.path.join(ansible_dir, 'inventory')

# Validate names and collect target profiles before touching any file
targets = set()
for device, sections in changes.items():
    if not NAME_RE.match(str(device)):
        fail(f'Invalid device name: {device}')
    if not isinstance(sections, dict):
        fail(f'Invalid changes for device {device}')
    for section in ('interfaces', 'bonds'):
        ports = sections.get(section) or {}
        if not isinstance(ports, dict):
            fail(f'Invalid {section} for device {device}')
        for port, mv in ports.items():
            if not NAME_RE.match(str(port)):
                fail(f'Invalid port name: {port}')
            if not isinstance(mv, dict):
                fail(f'Invalid change entry for {device}/{port}')
            new = mv.get('new')
            old = mv.get('old')
            # new == ''/null removes sw_port_profile (assignment rollback)
            if new is None:
                new = ''
                mv['new'] = ''
            if new != '' and (not isinstance(new, str) or not NAME_RE.match(new)):
                fail(f'Invalid target profile for {device}/{port}')
            # old '' = "expect no profile" guard for first-time assignments
            if old is not None and old != '' and (not isinstance(old, str) or not NAME_RE.match(old)):
                fail(f'Invalid source profile for {device}/{port}')
            if new:
                targets.add(new)

# Every target profile must exist (prevents dangling sw_port_profile refs)
spp_file = os.path.join(inventory_base, 'group_vars', 'all', 'sw_port_profiles.yaml')
try:
    with open(spp_file, 'r') as f:
        spp = yaml.load(f) or {}
except Exception as e:
    fail(f'Cannot read sw_port_profiles.yaml: {e}')
if not hasattr(spp, 'get'):
    fail('sw_port_profiles.yaml top level is not a mapping')
profiles = spp.get('sw_port_profiles') or {}
missing = sorted(t for t in targets if t not in profiles)
if missing:
    fail('Target profiles not found in sw_port_profiles.yaml: ' + ', '.join(missing))

results = {}
plan_changes = {}
total_applied = 0
total_skipped = 0

# Config generators (dotfabric) emit '#    sw_port_profile: DEFINE_IT'
# placeholders on unassigned ports; once the real key is written the stale
# comment next to it would read as a duplicate. Scrub exactly those comment
# lines, best-effort: comment plumbing varies across ruamel token layouts,
# and a survivor comment is cosmetic, never wrong YAML.
PLACEHOLDER_COMMENT_RE = re.compile(r'#\s*sw_port_profile\s*:')


def drop_placeholder_comments(*nodes):
    for node in nodes:
        try:
            items = node.ca.items
        except AttributeError:
            continue
        try:
            for key in list(items):
                toks = items.get(key) or []
                changed = False
                for i, tok in enumerate(toks):
                    group = tok if isinstance(tok, list) else [tok]
                    for j, t in enumerate(group):
                        val = getattr(t, 'value', None)
                        if not val or not PLACEHOLDER_COMMENT_RE.search(val):
                            continue
                        kept = '\n'.join(l for l in val.split('\n')
                                         if not PLACEHOLDER_COMMENT_RE.search(l))
                        if kept.strip():
                            t.value = kept if kept.endswith('\n') or not val.endswith('\n') else kept + '\n'
                        else:
                            group[j] = None
                        changed = True
                    if isinstance(tok, list):
                        toks[i] = [t for t in group if t is not None] or None
                    else:
                        toks[i] = group[0]
                if changed and not any(t for t in toks if t):
                    del items[key]
        except Exception:
            pass  # cosmetic cleanup only; never block the migration

for device, sections in changes.items():
    hv_file = os.path.join(inventory_base, 'host_vars', device + '.yaml')
    if not os.path.exists(hv_file):
        alt = os.path.join(inventory_base, 'host_vars', device + '.yml')
        if os.path.exists(alt):
            hv_file = alt
    if not os.path.exists(hv_file):
        skipped = []
        for section in ('interfaces', 'bonds'):
            for port in (sections.get(section) or {}):
                skipped.append({'section': section, 'name': port, 'reason': 'host_vars file not found'})
        total_skipped += len(skipped)
        results[device] = {'applied': 0, 'skipped': skipped, 'error': 'host_vars file not found'}
        continue

    try:
        with open(hv_file, 'r') as f:
            cfg = yaml.load(f) or {}
    except Exception as e:
        results[device] = {'applied': 0, 'skipped': [], 'error': f'Cannot parse host_vars: {e}'}
        continue
    if not hasattr(cfg, 'get'):
        results[device] = {'applied': 0, 'skipped': [], 'error': 'host_vars top level is not a mapping'}
        continue

    applied = []
    skipped = []
    for section in ('interfaces', 'bonds'):
        wanted = sections.get(section) or {}
        node = cfg.get(section) or {}
        for port, mv in wanted.items():
            new = mv['new']
            old = mv.get('old')
            entry = node.get(port) if hasattr(node, 'get') else None
            if not hasattr(entry, 'get'):
                skipped.append({'section': section, 'name': port, 'reason': 'not found in host_vars'})
                continue
            current = entry.get('sw_port_profile')
            # old '' = expect NO profile (first-time assignment drift guard);
            # old None = no check (explicit escape hatch)
            if old is not None and (current or '') != old:
                skipped.append({'section': section, 'name': port,
                                'reason': f'current profile is {current or "(none)"}, expected {old or "(none)"}'})
                continue
            if not new:
                if current is None:
                    skipped.append({'section': section, 'name': port, 'reason': 'no profile to remove'})
                    continue
                if not dry_run:
                    del entry['sw_port_profile']
                applied.append({'section': section, 'name': port, 'old': current, 'new': None})
                continue
            if current == new:
                skipped.append({'section': section, 'name': port, 'reason': 'already on target profile'})
                continue
            if not dry_run:
                entry['sw_port_profile'] = new
                if current is None:
                    drop_placeholder_comments(entry, node)
            applied.append({'section': section, 'name': port, 'old': current, 'new': new})

    if applied and not dry_run:
        _fd, _path = tempfile.mkstemp(dir=os.path.dirname(hv_file), suffix='.tmp')
        _lldpq_mode_floor(_fd, hv_file)
        try:
            with os.fdopen(_fd, 'w') as _f:
                yaml.dump(cfg, _f)
            shutil.move(_path, hv_file)
        except Exception as e:
            if os.path.exists(_path):
                os.unlink(_path)
            results[device] = {'applied': 0, 'skipped': skipped, 'error': f'Write failed: {e}'}
            continue

    total_applied += len(applied)
    total_skipped += len(skipped)
    results[device] = {'applied': len(applied), 'skipped': skipped}
    plan_changes[device] = {'applied': applied, 'skipped': skipped}

plan_id = None
if total_applied and not dry_run:
    plans_dir = os.path.join(ansible_dir, '.migrations')
    try:
        os.makedirs(plans_dir, exist_ok=True)
        plan_id = datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '_' + plan_name
        plan_record = {
            'id': plan_id,
            'name': plan_name,
            'created': datetime.now().astimezone().isoformat(timespec='seconds'),
            'total_applied': total_applied,
            'total_skipped': total_skipped,
            'changes': plan_changes,
        }
        _fd, _path = tempfile.mkstemp(dir=plans_dir, suffix='.tmp')
        os.fchmod(_fd, 0o644)  # mkstemp defaults to 0600; keep plans readable for git/backup sweeps
        with os.fdopen(_fd, 'w') as _f:
            json.dump(plan_record, _f, indent=2)
        shutil.move(_path, os.path.join(plans_dir, plan_id + '.json'))
    except Exception:
        plan_id = None  # plan record is best-effort; the host_vars edits stand

print(json.dumps({
    'success': True,
    'dry_run': dry_run,
    'plan_id': plan_id,
    'results': results,
    'total_applied': total_applied,
    'total_skipped': total_skipped,
}))
PYTHON
    rm -f "$POST_DATA_FILE"
}

list_migration_plans() {
    python3 << 'PYTHON'
import json
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
plans_dir = os.path.join(ansible_dir, '.migrations')
plans = []
if os.path.isdir(plans_dir):
    for fn in sorted(os.listdir(plans_dir), reverse=True):
        # selection-patterns.json shares this directory but is not a plan
        if not fn.endswith('.json') or fn == 'selection-patterns.json':
            continue
        try:
            with open(os.path.join(plans_dir, fn), 'r') as f:
                p = json.load(f)
            if not isinstance(p, dict) or 'changes' not in p:
                continue
            plans.append({
                'id': p.get('id') or fn[:-5],
                'name': p.get('name'),
                'created': p.get('created'),
                'devices': sorted((p.get('changes') or {}).keys()),
                'total_applied': p.get('total_applied', 0),
            })
        except Exception:
            continue
print(json.dumps({'success': True, 'plans': plans}))
PYTHON
}

get_migration_plan() {
    local plan_id
    plan_id=$(echo "$QUERY_STRING" | grep -oP 'plan=\K[^&]*' | head -1)
    export PLAN_ID="$plan_id"
    python3 << 'PYTHON'
import json
import os
import re

plan_id = os.environ.get('PLAN_ID', '')
if not re.match(r'^[A-Za-z0-9_-]+$', plan_id) or plan_id == 'selection-patterns':
    print(json.dumps({'success': False, 'error': 'Invalid plan id'}))
    raise SystemExit(0)
ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
plan_file = os.path.join(ansible_dir, '.migrations', plan_id + '.json')
if not os.path.exists(plan_file):
    print(json.dumps({'success': False, 'error': 'Plan not found'}))
    raise SystemExit(0)
try:
    with open(plan_file, 'r') as f:
        plan = json.load(f)
    print(json.dumps({'success': True, 'plan': plan}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
}

# Shared selection patterns for the Fabric Migration wizard. Stored next to
# the migration plans so they are per-project (per ANSIBLE_DIR) and shared
# across operators, instead of the old per-browser localStorage copy.
get_selection_patterns() {
    python3 << 'PYTHON'
import json
import os

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
path = os.path.join(ansible_dir, '.migrations', 'selection-patterns.json')
patterns = None
try:
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get('patterns')
    if isinstance(data, list):
        patterns = [str(p) for p in data if isinstance(p, str) and p.strip()]
except (OSError, ValueError):
    pass
print(json.dumps({'success': True, 'patterns': patterns}))
PYTHON
}

save_selection_patterns() {
    acquire_lock
    read_post_body
    export POST_DATA
    python3 << 'PYTHON'
import json
import os
import shutil
import sys
import tempfile


def fail(msg):
    print(json.dumps({'success': False, 'error': msg}))
    sys.exit(0)


try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except ValueError:
    fail('Invalid JSON payload')

patterns = data.get('patterns')
if not isinstance(patterns, list):
    fail('patterns must be a list')
clean = []
for p in patterns:
    if not isinstance(p, str):
        fail('patterns must be strings')
    p = p.strip()
    if not p:
        continue
    if len(p) > 300:
        fail('pattern too long (max 300 chars)')
    clean.append(p)
if len(clean) > 100:
    fail('too many patterns (max 100)')

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
mig_dir = os.path.join(ansible_dir, '.migrations')
path = os.path.join(mig_dir, 'selection-patterns.json')
try:
    if not clean:
        # Empty list = reset to built-in defaults
        if os.path.exists(path):
            os.unlink(path)
        print(json.dumps({'success': True, 'patterns': None}))
        sys.exit(0)
    os.makedirs(mig_dir, exist_ok=True)
    _fd, _path = tempfile.mkstemp(dir=mig_dir, suffix='.tmp')
    os.fchmod(_fd, 0o644)  # mkstemp defaults to 0600
    with os.fdopen(_fd, 'w') as f:
        json.dump({'patterns': clean}, f, indent=2)
    shutil.move(_path, path)
except OSError as e:
    fail(f'Cannot write patterns: {e}')
print(json.dumps({'success': True, 'patterns': clean}))
PYTHON
}

# Port -> design-metadata join for the Fabric Migration facet filters.
# Reads the published active P2P design (active-p2p.json, uploaded via the
# Ask-AI design flow) and returns per-device port entries carrying
# rack / RU / SU / peer straight from the cabling workbook, so ports can be
# grouped by physical location instead of description regexes. Best-effort:
# devices without design rows simply return empty lists.
get_p2p_enrichment() {
    read_post_body
    export POST_DATA
    WEB_ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
    export WEB_ROOT_DIR
    python3 << 'PYTHON'
import json
import os
import re
import sys


def fail(msg, **extra):
    out = {'success': False, 'error': msg}
    out.update(extra)
    print(json.dumps(out))
    sys.exit(0)


try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except ValueError:
    fail('Invalid JSON payload')

devices = data.get('devices')
if not isinstance(devices, list) or not devices:
    fail('No devices provided')
if len(devices) > 500:
    fail('Too many devices')
NAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
devices = [str(d) for d in devices]
for d in devices:
    if not NAME_RE.match(d):
        fail(f'Invalid device name: {d}')

web_root = os.environ.get('WEB_ROOT_DIR', '')
if web_root and web_root not in sys.path:
    sys.path.insert(0, web_root)
try:
    import ai_p2p
except Exception as e:
    fail(f'P2P module unavailable: {e}')

lldpq_dir = ''
try:
    with open('/etc/lldpq.conf') as f:
        for line in f:
            if line.startswith('LLDPQ_DIR='):
                lldpq_dir = line.strip().split('=', 1)[1]
                break
except OSError:
    pass
lldpq_dir = lldpq_dir or '/home/lldpq/lldpq'

design_path = None
for base in (os.path.join(lldpq_dir, 'monitor-results'),
             os.path.join(web_root, 'monitor-results')):
    p = os.path.join(base, 'active-p2p.json')
    if os.path.isfile(p):
        design_path = p
        break
if not design_path:
    fail('no active P2P design uploaded', no_design=True)

try:
    conns = ai_p2p.load_connections(design_path)
except Exception as e:
    fail(f'active P2P design could not be read: {e}')

# Device aliases (design name <-> live name), both directions, same file the
# Ask-AI lookups use.
alias_fwd = {}
alias_rev = {}
try:
    with open(os.path.join(web_root, 'display-aliases.json')) as fh:
        _al = (json.load(fh) or {}).get('devices') or {}
    for k, v in _al.items():
        if k and v:
            alias_fwd[str(k).strip().lower()] = str(v).strip()
            alias_rev[str(v).strip().lower()] = str(k).strip()
except Exception:
    pass

# One pass over the design: device_key -> [(side, peer_side, record)]
index = {}
for record in ai_p2p._records_of(conns):
    for side, peer in (('source', 'dest'), ('dest', 'source')):
        name = record.get(side + '_name', '')
        if not name:
            continue
        for k in ai_p2p._device_keys(name):
            index.setdefault(k, []).append((side, peer, record))

resolved = ai_p2p.resolve_port_map(conns)
SU_RE = re.compile(r'\bSU\s*[-_]?(\d+)', re.IGNORECASE)

out = {}
for dev in devices:
    low = dev.strip().lower()
    candidates = {low}
    for alt in (alias_fwd.get(low), alias_rev.get(low)):
        if alt:
            candidates.add(alt.strip().lower())
    entries = []
    seen = set()
    for cand in candidates:
        for side, peer, record in index.get(cand, []):
            port = record.get(side + '_port', '')
            os_port = ai_p2p.resolved_os_port(resolved, record.get(side + '_name', ''), port)
            # Dedup by the group-fitted OS lane when resolved: _port_key alone
            # collapses distinct X/Y/Z lanes (1/1/1 and 1/2/1 both -> '1/1').
            key = os_port or ai_p2p._port_key(port)
            if key in seen:
                continue
            seen.add(key)
            if os_port:
                # Three-part X/Y/Z ports: _port_aliases would emit every
                # candidate breakout lane; the group-fitted resolution is
                # authoritative, so ship only the exact spelling + os port.
                p_clean = str(port).strip().lower().replace(' ', '')
                aliases = sorted({p_clean, os_port})
            else:
                aliases = sorted(ai_p2p._port_aliases(port))
            sheet = record.get('sheet_name', '') or ''
            m = SU_RE.search(sheet)
            entries.append({
                'port': port,
                'os_port': os_port,
                'aliases': aliases,
                'rack': record.get(side + '_rack', ''),
                'ru': record.get(side + '_ru', ''),
                'peer': record.get(peer + '_name', ''),
                'peer_port': record.get(peer + '_port', ''),
                'peer_rack': record.get(peer + '_rack', ''),
                'peer_ru': record.get(peer + '_ru', ''),
                'su': m.group(1) if m else '',
                'sheet': sheet,
            })
    out[dev] = entries

print(json.dumps({'success': True, 'devices': out,
                  'design': os.path.basename(design_path)}))
PYTHON
}

# Per-device live-state table (ARP/MAC/routes per VRF) collected by
# fabric-scan.sh into $LLDPQ_DIR/monitor-results/fabric-tables — that tree is
# not under WEB_ROOT, so the Fabric Migration verify step reads it through
# this action instead of a static fetch.
get_fabric_table() {
    export DEVICE_HOSTNAME="$HOSTNAME"
    python3 << 'PYTHON'
import json
import os
import re

hostname = os.environ.get('DEVICE_HOSTNAME', '')
if not re.match(r'^[A-Za-z0-9_.-]+$', hostname or ''):
    print(json.dumps({'success': False, 'error': 'Invalid hostname'}))
    raise SystemExit(0)

lldpq_dir = ''
try:
    with open('/etc/lldpq.conf') as f:
        for line in f:
            if line.startswith('LLDPQ_DIR='):
                lldpq_dir = line.strip().split('=', 1)[1]
                break
except OSError:
    pass
lldpq_dir = lldpq_dir or '/home/lldpq/lldpq'

path = os.path.join(lldpq_dir, 'monitor-results', 'fabric-tables', hostname + '.json')
try:
    with open(path) as f:
        print(json.dumps({'success': True, 'table': json.load(f)}))
except (OSError, ValueError):
    print(json.dumps({'success': False, 'error': 'fabric-tables not available'}))
PYTHON
}

# Main handler
parse_query

case "$ACTION" in
    "list-devices")
        list_devices
        ;;
    "get-device")
        get_device "$HOSTNAME"
        ;;
    "get-vlan-profiles")
        get_vlan_profiles
        ;;
    "get-vlan-report")
        get_vlan_report
        ;;
    "get-port-profiles")
        get_port_profiles
        ;;
    "create-port-profile")
        create_port_profile
        ;;
    "update-port-profile")
        update_port_profile
        ;;
    "delete-port-profile")
        delete_port_profile
        ;;
    "migrate-port-profiles")
        migrate_port_profiles
        ;;
    "list-migration-plans")
        list_migration_plans
        ;;
    "get-migration-plan")
        get_migration_plan
        ;;
    "get-fabric-table")
        get_fabric_table
        ;;
    "get-selection-patterns")
        get_selection_patterns
        ;;
    "save-selection-patterns")
        save_selection_patterns
        ;;
    "get-p2p-enrichment")
        get_p2p_enrichment
        ;;
    "get-bgp-profiles")
        get_bgp_profiles
        ;;
    "create-bgp-profile")
        create_bgp_profile
        ;;
    "update-bgp-profile")
        update_bgp_profile
        ;;
    "delete-bgp-profile")
        delete_bgp_profile
        ;;
    "get-vrfs")
        get_vrfs
        ;;
    "create-vlan")
        create_vlan
        ;;
    "delete-vlan")
        delete_vlan
        ;;
    "assign-vlans")
        assign_vlans
        ;;
    "unassign-vlan")
        unassign_vlan
        ;;
    "update-vlan")
        update_vlan
        ;;
    "bulk-create-vlans")
        bulk_create_vlans
        ;;
    "get-available-vrfs")
        get_available_vrfs
        ;;
    "get-leaking-vrfs")
        get_leaking_vrfs
        ;;
    "create-vrf")
        create_vrf
        ;;
    "create-vrf-bulk")
        create_vrf_bulk
        ;;
    "assign-vrfs")
        assign_vrfs
        ;;
    "unassign-vrf")
        unassign_vrf
        ;;
    "delete-vrf-global")
        delete_vrf_global
        ;;
    "get-vrf-report")
        get_vrf_report
        ;;
    "get-all-leaked-subnets")
        # Get all leaked subnets with their target VRFs
        python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = f"{ansible_dir}/inventory/host_vars"
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

try:
    with open(bgp_file, 'r') as f:
        bgp_data = yaml.load(f, Loader=yaml.CSafeLoader)
    
    profiles = bgp_data.get('bgp_profiles', {})
    route_map_to_target = {}
    leaked_subnets = {}
    all_prefix_lists = {}  # Store prefix lists for second pass
    
    # Single pass: collect both route_map mapping AND prefix_lists
    for yaml_file in glob.glob(f"{host_vars_dir}/*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                device_data = yaml.load(f, Loader=yaml.CSafeLoader)
            if not device_data:
                continue
            
            # Collect route_map -> target_vrf mapping from VRFs
            vrfs = device_data.get('vrfs', {})
            for vrf_name, vrf_config in vrfs.items():
                if isinstance(vrf_config, dict):
                    bgp = vrf_config.get('bgp', {})
                    bgp_profile = bgp.get('bgp_profile', '')
                    if bgp_profile in profiles:
                        profile = profiles[bgp_profile]
                        ipv4_af = profile.get('ipv4_unicast_af', {})
                        route_import = ipv4_af.get('route_import', {})
                        route_map = route_import.get('route_map', '')
                        if route_map and route_map not in route_map_to_target:
                            route_map_to_target[route_map] = vrf_name
            
            # Collect prefix_lists from policies
            policies = device_data.get('policies', {})
            prefix_lists = policies.get('prefix_list', {})
            for pl_name, pl_entries in prefix_lists.items():
                if pl_name not in all_prefix_lists:
                    all_prefix_lists[pl_name] = pl_entries
        except:
            continue
    
    # Now match prefix_lists with route_maps (no file I/O needed)
    for pl_name, pl_entries in all_prefix_lists.items():
        if pl_name in route_map_to_target:
            target_vrf = route_map_to_target[pl_name]
            for seq, entry in pl_entries.items():
                subnet = entry.get('match', '')
                if subnet and subnet not in leaked_subnets:
                    leaked_subnets[subnet] = {
                        'target_vrf': target_vrf,
                        'route_map': pl_name
                    }
    
    print(json.dumps({'success': True, 'leaked_subnets': leaked_subnets}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "check-subnet-leak")
        # Check if a subnet is already leaked to any VRF
        read_post_body
        export POST_DATA
        python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob

try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    params = {}

subnet = params.get('subnet', '')

if not subnet:
    print(json.dumps({'success': False, 'error': 'Missing subnet'}))
    exit()

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = f"{ansible_dir}/inventory/host_vars"
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"

# Build route_map -> target_vrf mapping from bgp_profiles
try:
    with open(bgp_file, 'r') as f:
        bgp_data = yaml.load(f, Loader=yaml.CSafeLoader)
    
    profiles = bgp_data.get('bgp_profiles', {})
    
    # Single pass: collect both route_map->target_vrf mapping AND check prefix-lists
    route_map_to_target = {}
    leaked_to = None
    route_map_found = None
    all_prefix_list_matches = []  # Store all matches to check after we have route_map mapping
    
    for yaml_file in glob.glob(f"{host_vars_dir}/*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                device_data = yaml.load(f, Loader=yaml.CSafeLoader)
            if not device_data:
                continue
            
            # Part 1: Build route_map -> target_vrf mapping
            vrfs = device_data.get('vrfs', {})
            for vrf_name, vrf_config in vrfs.items():
                if isinstance(vrf_config, dict):
                    bgp = vrf_config.get('bgp', {})
                    bgp_profile = bgp.get('bgp_profile', '')
                    if bgp_profile in profiles:
                        profile = profiles[bgp_profile]
                        ipv4_af = profile.get('ipv4_unicast_af', {})
                        route_import = ipv4_af.get('route_import', {})
                        route_map = route_import.get('route_map', '')
                        if route_map:
                            route_map_to_target[route_map] = vrf_name
            
            # Part 2: Check prefix-lists for subnet match
            policies = device_data.get('policies', {})
            prefix_lists = policies.get('prefix_list', {})
            
            for pl_name, pl_entries in prefix_lists.items():
                if isinstance(pl_entries, dict):
                    for seq, entry in pl_entries.items():
                        if isinstance(entry, dict) and entry.get('match') == subnet:
                            all_prefix_list_matches.append(pl_name)
        except:
            continue
    
    # Now resolve matches
    for pl_name in all_prefix_list_matches:
        route_map_found = pl_name
        if pl_name in route_map_to_target:
            leaked_to = route_map_to_target[pl_name]
            break
    
    print(json.dumps({
        'success': True,
        'leaked': leaked_to is not None,
        'target_vrf': leaked_to,
        'route_map': route_map_found
    }))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "get-leaking-targets")
        # Get VRFs that can receive leaked routes (from a source VRF)
        python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"
host_vars_dir = f"{ansible_dir}/inventory/host_vars"

try:
    with open(bgp_file, 'r') as f:
        data = yaml.load(f, Loader=yaml.CSafeLoader)
    
    profiles = data.get('bgp_profiles', {})
    
    # Build profile -> route_map mapping
    profile_route_map = {}
    for profile_name, profile in profiles.items():
        ipv4_af = profile.get('ipv4_unicast_af', {})
        route_import = ipv4_af.get('route_import', {})
        from_vrfs = route_import.get('from_vrf', [])
        route_map = route_import.get('route_map', '')
        if from_vrfs and route_map:
            profile_route_map[profile_name] = {
                'from_vrfs': from_vrfs,
                'route_map': route_map
            }
    
    # Scan host_vars to find which VRF uses which profile
    vrf_profile_map = {}  # vrf_name -> profile_name
    for yaml_file in glob.glob(f"{host_vars_dir}/*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                device_data = yaml.load(f, Loader=yaml.CSafeLoader)
            if not device_data:
                continue
            vrfs = device_data.get('vrfs', {})
            for vrf_name, vrf_config in vrfs.items():
                if isinstance(vrf_config, dict):
                    bgp = vrf_config.get('bgp', {})
                    bgp_profile = bgp.get('bgp_profile', '')
                    if bgp_profile and bgp_profile in profile_route_map:
                        vrf_profile_map[vrf_name] = bgp_profile
        except:
            continue
    
    # Build leaking_map: source_vrf -> [target_vrfs with route_map]
    leaking_map = {}
    for vrf_name, profile_name in vrf_profile_map.items():
        if profile_name in profile_route_map:
            info = profile_route_map[profile_name]
            for src_vrf in info['from_vrfs']:
                if src_vrf not in leaking_map:
                    leaking_map[src_vrf] = []
                # Check if this target VRF is already added
                existing = [x for x in leaking_map[src_vrf] if x['target_vrf'] == vrf_name]
                if not existing:
                    leaking_map[src_vrf].append({
                        'target_vrf': vrf_name,
                        'route_map': info['route_map']
                    })
    
    print(json.dumps({'success': True, 'leaking_map': leaking_map}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "add-subnet-leak")
        # Add a subnet to prefix-list for leaking
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
import json
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys
import glob

# Read POST data
try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    params = {}

subnet = params.get('subnet', '')
route_map = params.get('route_map', '')

if not subnet or not route_map:
    print(json.dumps({'success': False, 'error': 'Missing subnet or route_map'}))
    sys.exit(0)

# Validate subnet before any write (the template renders it raw as a YAML key)
_subnet_net = _v_ip_network(subnet)
if _subnet_net is None:
    print(json.dumps({'success': False, 'error': f'Invalid subnet: {subnet}'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = f"{ansible_dir}/inventory/host_vars"

# Find all devices that have this prefix_list and add the subnet
devices_updated = []
errors = []

try:
    # Pass 1: load and validate every host_vars file, compute the new content
    # in memory; nothing is written until every target file staged cleanly
    _loaded = []
    for yaml_file in glob.glob(f"{host_vars_dir}/*.yaml"):
        with open(yaml_file, 'r') as f:
            content = f.read()
            device_data = yaml.load(content)
        _loaded.append((yaml_file, device_data))

    # Authoritative 'already leaked elsewhere' check under the lock: the
    # read-only check-subnet-leak action runs in a SEPARATE request, so two
    # admins can both pass it and leak the same subnet into two target VRFs.
    _bgp_file = f"{ansible_dir}/inventory/group_vars/all/bgp_profiles.yaml"
    _profiles = {}
    try:
        with open(_bgp_file, 'r') as _bf:
            _profiles = (yaml.load(_bf) or {}).get('bgp_profiles', {}) or {}
    except OSError:
        _profiles = {}
    _rm_to_target = {}
    for yaml_file, device_data in _loaded:
        if not device_data:
            continue
        _vrfs = device_data.get('vrfs', {}) or {}
        if not hasattr(_vrfs, 'items'):
            continue
        for _vn, _vc in _vrfs.items():
            if not hasattr(_vc, 'get'):
                continue
            _bp_name = _vc.get('bgp', {}).get('bgp_profile', '') if hasattr(_vc.get('bgp', {}), 'get') else ''
            _prof = _profiles.get(_bp_name) if hasattr(_profiles, 'get') else None
            if hasattr(_prof, 'get'):
                _af = _prof.get('ipv4_unicast_af', {}) or {}
                _ri = _af.get('route_import', {}) if hasattr(_af, 'get') else {}
                _rm = _ri.get('route_map', '') if hasattr(_ri, 'get') else ''
                if _rm:
                    _rm_to_target[_rm] = _vn
    for yaml_file, device_data in _loaded:
        if not device_data:
            continue
        _pols = device_data.get('policies', {}) or {}
        _pls = _pols.get('prefix_list', {}) if hasattr(_pols, 'get') else {}
        if not hasattr(_pls, 'items'):
            continue
        for _pl_name, _pl_entries in _pls.items():
            if _pl_name == route_map or _pl_name not in _rm_to_target or not hasattr(_pl_entries, 'values'):
                continue
            for _entry in _pl_entries.values():
                if hasattr(_entry, 'get') and _entry.get('match') == subnet:
                    print(json.dumps({'success': False, 'error': f'Subnet {subnet} is already leaked to {_rm_to_target[_pl_name]} via prefix-list {_pl_name}', 'devices_updated': []}))
                    sys.exit(0)

    _staged_writes = []
    _staged_hosts = []
    for yaml_file, device_data in _loaded:
        hostname = os.path.basename(yaml_file).replace('.yaml', '')

        if not device_data:
            continue

        policies = device_data.get('policies', {}) or {}
        prefix_lists = policies.get('prefix_list', {}) if hasattr(policies, 'get') else {}

        if not hasattr(prefix_lists, 'get') or route_map not in prefix_lists:
            continue

        # This device has the prefix_list, add the subnet
        prefix_list = prefix_lists[route_map]

        # A None/list-valued policy cannot carry sequence entries
        if not hasattr(prefix_list, 'items'):
            continue

        # Find the next sequence number (increment by 10), skipping
        # non-numeric bookkeeping keys such as 'type' (ipv6 lists)
        _seq_keys = [seq for seq in prefix_list.keys() if str(seq).isdigit()]
        existing_seqs = [int(seq) for seq in _seq_keys]
        _next_num = max(existing_seqs) + 10 if existing_seqs else 10
        # Keep the new key the same type as the existing sequence keys
        if _seq_keys and all(isinstance(_k, int) for _k in _seq_keys):
            next_seq = _next_num
        else:
            next_seq = str(_next_num)

        # Check if subnet already exists
        subnet_exists = any(
            hasattr(entry, 'get') and entry.get('match') == subnet
            for entry in prefix_list.values()
        )

        if subnet_exists:
            continue

        # Add the new entry (max_prefix_len follows the address family:
        # 32 for IPv4, 128 for IPv6)
        prefix_list[next_seq] = {
            'match': subnet,
            'max_prefix_len': _subnet_net.max_prefixlen
        }

        _staged_writes.append((device_data, yaml_file))
        _staged_hosts.append(hostname)

    # Pass 2: write all files only after pass 1 succeeded for every device
    if _staged_writes:
        _atomic_write_many(yaml, _staged_writes)
    devices_updated = _staged_hosts

    print(json.dumps({
        'success': True,
        'devices_updated': devices_updated,
        'count': len(devices_updated),
        'message': f"Subnet {subnet} added to prefix-list {route_map} on {len(devices_updated)} device(s)"
    }))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e), 'devices_updated': devices_updated}))
PYTHON
        ;;
    "save-dhcp-relay")
        # Save (create or update) DHCP relay entry
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    params = {}

device = params.get('device', '')
index = params.get('index')  # None for create, number for update
vrf = params.get('vrf', '')
interfaces = params.get('interfaces', [])
servers = params.get('servers', [])
upstream = params.get('upstream', [])
giaddr = params.get('giaddr', '')  # Optional gateway interface

if not device or not vrf:
    print(json.dumps({'success': False, 'error': 'Device and VRF are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

# List-typed fields the template iterates: reject scalars (a bare string
# would render per-character) and validate entries before writing anything
interfaces = _v_str_list(interfaces)
if not interfaces:
    print(json.dumps({'success': False, 'error': 'interfaces must be a non-empty list'}))
    sys.exit(0)
servers = _v_str_list(servers)
if not servers:
    print(json.dumps({'success': False, 'error': 'servers must be a non-empty list'}))
    sys.exit(0)
for _s in servers:
    if _v_ip_address(_s) is None:
        print(json.dumps({'success': False, 'error': f'Invalid DHCP server IP: {_s}'}))
        sys.exit(0)
upstream = _v_str_list(upstream)
if upstream is None:
    print(json.dumps({'success': False, 'error': 'upstream must be a list'}))
    sys.exit(0)
for _u in upstream:
    if not re.match(r'^[A-Za-z0-9_./-]+$', _u):
        print(json.dumps({'success': False, 'error': f'Invalid upstream interface: {_u}'}))
        sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = f"{ansible_dir}/inventory/host_vars"
host_file = f"{host_vars_dir}/{device}.yaml"

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = f"{host_vars_dir}/{device}.yml"
    if os.path.exists(alt_file):
        host_file = alt_file

# Require an existing host_vars file (same rule as save-evpn-mh): a typo'd
# device would otherwise silently get a brand-new orphan host_vars file
if not os.path.exists(host_file):
    print(json.dumps({'success': False, 'error': f'Host file not found: {device}.yaml'}))
    sys.exit(0)

try:
    # Load host_vars
    host_data = {}
    if os.path.exists(host_file):
        with open(host_file, 'r') as f:
            host_data = yaml.load(f) or {}
    
    # Initialize dhcp_relay if not exists
    if 'dhcp_relay' not in host_data:
        host_data['dhcp_relay'] = []
    
    # Build relay entry. 'upstream' is always emitted (even empty):
    # dhcp_relay.j2 iterates relay.upstream without an 'is defined' guard,
    # so a missing key breaks the whole device render. giaddr is guarded.
    relay_entry = {
        'vrf': vrf,
        'interfaces': interfaces,
        'servers': servers,
        'upstream': upstream
    }
    if giaddr:
        relay_entry['giaddr'] = giaddr
    
    if index is not None:
        # An explicit index must address an existing entry: falling through
        # to append on a stale/out-of-range index (e.g. after a concurrent
        # delete shifted the list) would create a second entry for a VRF,
        # and dhcp_relay.j2 renders duplicate mapping keys (invalid NVUE YAML)
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(host_data['dhcp_relay']):
            print(json.dumps({'success': False, 'error': 'DHCP relay entry not found (the list may have changed since the page was loaded); reload and retry'}))
            sys.exit(0)

    # NVUE keys DHCP relays by VRF: refuse a save that would leave two
    # entries for the same VRF (duplicate mapping key in the rendered config)
    for _i, _e in enumerate(host_data['dhcp_relay']):
        if _i != index and hasattr(_e, 'get') and _e.get('vrf') == vrf:
            print(json.dumps({'success': False, 'error': f'A DHCP relay for VRF {vrf} already exists on this device; edit that entry instead'}))
            sys.exit(0)

    if index is not None:
        # Update existing
        host_data['dhcp_relay'][index] = relay_entry
    else:
        # Create new
        host_data['dhcp_relay'].append(relay_entry)
    
    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': 'DHCP relay saved'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "delete-dhcp-relay")
        # Delete DHCP relay entry
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    params = {}

device = params.get('device', '')
index = params.get('index')

if not device or index is None:
    print(json.dumps({'success': False, 'error': 'Device and index are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_vars_dir = f"{ansible_dir}/inventory/host_vars"
host_file = f"{host_vars_dir}/{device}.yaml"

# Try .yml if .yaml doesn't exist
if not os.path.exists(host_file):
    alt_file = f"{host_vars_dir}/{device}.yml"
    if os.path.exists(alt_file):
        host_file = alt_file

try:
    # Load host_vars
    host_data = {}
    if os.path.exists(host_file):
        with open(host_file, 'r') as f:
            host_data = yaml.load(f) or {}
    
    if 'dhcp_relay' not in host_data or not isinstance(index, int) or index < 0 or index >= len(host_data['dhcp_relay']):
        print(json.dumps({'success': False, 'error': 'DHCP relay entry not found'}))
        sys.exit(0)
    
    # Delete the entry
    del host_data['dhcp_relay'][index]
    
    # If empty, remove the key
    if len(host_data['dhcp_relay']) == 0:
        del host_data['dhcp_relay']
    
    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': 'DHCP relay deleted'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "save-evpn-mh")
        # Save EVPN Multihoming configuration
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
    device = params.get('device', '')
    evpn_mh = params.get('evpn_mh', {})
    
    if not device:
        print(json.dumps({'success': False, 'error': 'Device is required'}))
        sys.exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
        print(json.dumps({'success': False, 'error': 'Invalid device name'}))
        sys.exit(0)

    if not evpn_mh.get('sysmac'):
        print(json.dumps({'success': False, 'error': 'System MAC is required'}))
        sys.exit(0)

    if not _v_mac(evpn_mh.get('sysmac')):
        print(json.dumps({'success': False, 'error': 'Invalid system MAC (expected xx:xx:xx:xx:xx:xx)'}))
        sys.exit(0)

    df_preference = _v_int_range(evpn_mh.get('df_preference', 50000), 1, 65535)
    if df_preference is None:
        print(json.dumps({'success': False, 'error': 'Invalid DF preference (must be 1-65535)'}))
        sys.exit(0)

    ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
    host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"

    if not os.path.exists(host_file):
        print(json.dumps({'success': False, 'error': f'Host file not found: {device}.yaml'}))
        sys.exit(0)

    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}

    # Set evpn_mh
    host_data['evpn_mh'] = {
        'sysmac': evpn_mh.get('sysmac'),
        'df_preference': df_preference
    }
    
    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': 'EVPN Multihoming saved'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    "delete-evpn-mh")
        # Delete EVPN Multihoming configuration
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    params = json.loads(os.environ.get('POST_DATA') or '{}')
    device = params.get('device', '')
    
    if not device:
        print(json.dumps({'success': False, 'error': 'Device is required'}))
        sys.exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
        print(json.dumps({'success': False, 'error': 'Invalid device name'}))
        sys.exit(0)

    ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
    host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"
    
    if not os.path.exists(host_file):
        print(json.dumps({'success': False, 'error': f'Host file not found: {device}.yaml'}))
        sys.exit(0)
    
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    if 'evpn_mh' not in host_data:
        print(json.dumps({'success': False, 'error': 'EVPN Multihoming not configured'}))
        sys.exit(0)
    
    # Delete evpn_mh
    del host_data['evpn_mh']
    
    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': 'EVPN Multihoming deleted'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    create-bond)
        # Create a new bond interface
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import sys
import os

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    try:
        data = json.loads(sys.stdin.read())
    except:
        print(json.dumps({'success': False, 'error': 'Invalid JSON data'}))
        sys.exit(0)

device = data.get('device', '')
bond_name = data.get('bond_name', '')
profile = data.get('profile', '')
mh_id = data.get('evpn_mh_id', '')
bond_mode = data.get('bond_mode', 'lacp')
lacp_bypass = data.get('lacp_bypass', False)
description = data.get('description', '')

if not device or not bond_name:
    print(json.dumps({'success': False, 'error': 'Device and bond name are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_./-]+$', str(bond_name)):
    print(json.dumps({'success': False, 'error': 'Invalid bond name'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"

try:
    # Load host file
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    # Initialize bonds if not exists
    if 'bonds' not in host_data:
        host_data['bonds'] = {}
    
    # Check if bond already exists
    if bond_name in host_data['bonds']:
        print(json.dumps({'success': False, 'error': f'Bond {bond_name} already exists'}))
        sys.exit(0)
    
    # Create bond entry
    bond_entry = {}
    
    if profile:
        bond_entry['sw_port_profile'] = profile
    
    if mh_id:
        bond_entry['evpn_mh_id'] = int(mh_id)
    
    if bond_mode and bond_mode != 'lacp':
        # sferical's bonding_ports.j2 reads bonds[<bond>].mode (== "static"),
        # so persist the protocol mode under 'mode', not 'bond_mode'.
        bond_entry['mode'] = bond_mode
    
    if lacp_bypass:
        bond_entry['lacp_bypass'] = True
    
    if description:
        bond_entry['description'] = description
    
    # Empty bond_members - will be added later
    bond_entry['bond_members'] = []
    
    host_data['bonds'][bond_name] = bond_entry
    
    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': f'Bond {bond_name} created'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    delete-bond)
        # Delete a bond interface
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import sys
import os

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    try:
        data = json.loads(sys.stdin.read())
    except:
        print(json.dumps({'success': False, 'error': 'Invalid JSON data'}))
        sys.exit(0)

device = data.get('device', '')
bond_name = data.get('name', '')

if not device or not bond_name:
    print(json.dumps({'success': False, 'error': 'Device and bond name are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"

try:
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    if 'bonds' not in host_data or bond_name not in host_data['bonds']:
        print(json.dumps({'success': False, 'error': f'Bond {bond_name} not found'}))
        sys.exit(0)
    
    # Get bond members to release them
    bond_members = host_data['bonds'][bond_name].get('bond_members', [])
    
    # Remove bond
    del host_data['bonds'][bond_name]
    
    # Clean up empty bonds dict
    if not host_data['bonds']:
        del host_data['bonds']
    
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': f'Bond {bond_name} deleted'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    delete-subinterface)
        # Delete a subinterface
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import sys
import os

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    try:
        data = json.loads(sys.stdin.read())
    except:
        print(json.dumps({'success': False, 'error': 'Invalid JSON data'}))
        sys.exit(0)

device = data.get('device', '')
subif_name = data.get('name', '')  # e.g., swp1.1001

if not device or not subif_name:
    print(json.dumps({'success': False, 'error': 'Device and subinterface name are required'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

# Parse parent interface and subif ID
if '.' not in subif_name:
    print(json.dumps({'success': False, 'error': 'Invalid subinterface name format'}))
    sys.exit(0)

parts = subif_name.rsplit('.', 1)
parent_if = parts[0]
subif_id = parts[1]

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"

try:
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    deleted = False
    
    # Check in interfaces -> parent -> subinterfaces
    if 'interfaces' in host_data and parent_if in host_data['interfaces']:
        iface = host_data['interfaces'][parent_if]
        if 'subinterfaces' in iface and subif_id in iface['subinterfaces']:
            del iface['subinterfaces'][subif_id]
            deleted = True
            # Clean up empty subinterfaces dict
            if not iface['subinterfaces']:
                del iface['subinterfaces']
        elif 'subinterfaces' in iface:
            # Try numeric key
            try:
                subif_id_int = int(subif_id)
                if subif_id_int in iface['subinterfaces']:
                    del iface['subinterfaces'][subif_id_int]
                    deleted = True
                    if not iface['subinterfaces']:
                        del iface['subinterfaces']
            except:
                pass
    
    if not deleted:
        print(json.dumps({'success': False, 'error': f'Subinterface {subif_name} not found'}))
        sys.exit(0)
    
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': f'Subinterface {subif_name} deleted'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    update-interface)
        # Update interface or bond settings
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import sys
import os

# Read POST data
try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    try:
        data = json.loads(sys.stdin.read())
    except:
        print(json.dumps({'success': False, 'error': 'Invalid JSON data'}))
        sys.exit(0)

device = data.get('device', '')
interface_name = data.get('interface_name', '')
interface_type = data.get('interface_type', '')  # 'l2', 'l3', 'subif', 'bond'
description = data.get('description', '')

if not device or not interface_name:
    print(json.dumps({'success': False, 'error': 'Missing device or interface_name'}))
    sys.exit(0)

if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
    print(json.dumps({'success': False, 'error': 'Invalid device name'}))
    sys.exit(0)

# interface_name becomes a YAML key the templates render raw - same charset
# check the bond member names below already get
if not re.match(r'^[A-Za-z0-9_./-]+$', str(interface_name)):
    print(json.dumps({'success': False, 'error': f'Invalid interface name: {interface_name}'}))
    sys.exit(0)

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
host_file = f"{ansible_dir}/inventory/host_vars/{device}.yaml"

try:
    # Load host file
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    if interface_type == 'bond':
        # Update bond
        if 'bonds' not in host_data:
            host_data['bonds'] = {}
        if interface_name not in host_data['bonds']:
            host_data['bonds'][interface_name] = {}
        
        bond = host_data['bonds'][interface_name]
        
        # Update profile
        profile = data.get('profile', '')
        if profile:
            bond['sw_port_profile'] = profile
        elif 'sw_port_profile' in bond:
            del bond['sw_port_profile']
        
        # Update description
        if description:
            bond['description'] = description
        elif 'description' in bond:
            del bond['description']
        
        # Update bond_members (validate: dedup, valid names, not in another bond,
        # and strip each member's own L2/L3 keys since it becomes a bond slave)
        raw_members = data.get('bond_members', []) or []
        seen = set()
        members = []
        for m in raw_members:
            m = str(m).strip()
            if not m or m in seen:
                continue
            if not re.match(r'^[A-Za-z0-9_./-]+$', m):
                print(json.dumps({'success': False, 'error': f'Invalid bond member name: {m}'}))
                sys.exit(0)
            seen.add(m)
            members.append(m)
        # Reject members already enslaved by a different bond
        for other_name, other_bond in (host_data.get('bonds') or {}).items():
            if other_name == interface_name or not hasattr(other_bond, 'get'):
                continue
            other_members = other_bond.get('bond_members') or []
            for m in members:
                if m in other_members:
                    print(json.dumps({'success': False, 'error': f'Member {m} is already in bond {other_name}'}))
                    sys.exit(0)
        # Strip each member's own L2/L3 keys
        _ifaces = host_data.get('interfaces')
        if hasattr(_ifaces, 'get'):
            for m in members:
                mi = _ifaces.get(m)
                if hasattr(mi, 'pop'):
                    for _k in ('sw_port_profile', 'ip', 'vrf'):
                        mi.pop(_k, None)
        # Always keep the key (empty list when no members): bonding_ports.j2
        # iterates bonds[bond].bond_members without an 'is defined' guard, so
        # a missing key breaks the whole device render
        bond['bond_members'] = members
        
        # Update evpn_mh_id
        mh_id = data.get('evpn_mh_id', '')
        if mh_id:
            bond['evpn_mh_id'] = int(mh_id)
        elif 'evpn_mh_id' in bond:
            del bond['evpn_mh_id']
        
        # Update bond_mode
        bond_mode = data.get('bond_mode', '')
        if bond_mode:
            bond['bond_mode'] = bond_mode
        elif 'bond_mode' in bond:
            del bond['bond_mode']
        
        # Update lacp_bypass
        lacp_bypass = data.get('lacp_bypass', False)
        if lacp_bypass:
            bond['lacp_bypass'] = True
        elif 'lacp_bypass' in bond:
            del bond['lacp_bypass']
    
    elif interface_type == 'breakout':
        # Physical port with breakout config
        if 'interfaces' not in host_data:
            host_data['interfaces'] = {}
        if interface_name not in host_data['interfaces']:
            host_data['interfaces'][interface_name] = {}
        
        iface = host_data['interfaces'][interface_name]
        
        # Update breakout
        breakout = data.get('breakout', '')
        if breakout:
            iface['breakout'] = breakout
        elif 'breakout' in iface:
            del iface['breakout']
        
        # Update description
        if description:
            iface['description'] = description
        elif 'description' in iface:
            del iface['description']
    
    elif interface_type == 'bond-member':
        # Bond member - manage bond membership
        target_bond = data.get('target_bond', '')

        # target_bond becomes a YAML key the templates render raw
        if target_bond and not re.match(r'^[A-Za-z0-9_./-]+$', str(target_bond)):
            print(json.dumps({'success': False, 'error': f'Invalid bond name: {target_bond}'}))
            sys.exit(0)

        # Remove from every bond except the target (guarantees single membership,
        # covers previous_bond and any stale membership elsewhere)
        for _bn, _b in (host_data.get('bonds') or {}).items():
            if _bn == target_bond or not hasattr(_b, 'get'):
                continue
            _bm = _b.get('bond_members')
            if _bm and interface_name in _bm:
                _bm.remove(interface_name)

        # Add to target bond
        if target_bond:
            if 'bonds' not in host_data:
                host_data['bonds'] = {}
            if target_bond not in host_data['bonds']:
                host_data['bonds'][target_bond] = {}

            bond = host_data['bonds'][target_bond]
            if 'bond_members' not in bond:
                bond['bond_members'] = []

            if interface_name not in bond['bond_members']:
                bond['bond_members'].append(interface_name)

        # Update description on interface; a bond slave must not carry its own
        # L2/L3 config, so drop sw_port_profile/ip/vrf from its interface entry.
        if 'interfaces' not in host_data:
            host_data['interfaces'] = {}
        if interface_name not in host_data['interfaces']:
            host_data['interfaces'][interface_name] = {}

        iface = host_data['interfaces'][interface_name]
        for _k in ('sw_port_profile', 'ip', 'vrf'):
            if _k in iface:
                del iface[_k]
        if description:
            iface['description'] = description
        elif 'description' in iface:
            del iface['description']
            
    elif interface_type == 'l3':
        # L3 interface
        # First, remove from any previous bond
        previous_bond = data.get('previous_bond', '')
        if previous_bond:
            if 'bonds' in host_data and previous_bond in host_data['bonds']:
                old_bond = host_data['bonds'][previous_bond]
                if 'bond_members' in old_bond and interface_name in old_bond['bond_members']:
                    old_bond['bond_members'].remove(interface_name)
        
        if 'interfaces' not in host_data:
            host_data['interfaces'] = {}
        if interface_name not in host_data['interfaces']:
            host_data['interfaces'][interface_name] = {}
        
        iface = host_data['interfaces'][interface_name]

        # Switching to L3: drop any L2 switchport profile left over
        if 'sw_port_profile' in iface:
            del iface['sw_port_profile']

        # Update IP
        ip = data.get('ip', '')
        if ip:
            if _v_ip_interface(ip) is None:
                print(json.dumps({'success': False, 'error': f'Invalid IP: {ip}'}))
                sys.exit(0)
            iface['ip'] = ip
        elif 'ip' in iface:
            del iface['ip']

        # Update VRF
        vrf = data.get('vrf', '')
        if vrf:
            if not _v_name(vrf):
                print(json.dumps({'success': False, 'error': f'Invalid VRF name: {vrf}'}))
                sys.exit(0)
            iface['vrf'] = vrf
        elif 'vrf' in iface:
            del iface['vrf']

        # Update description
        if description:
            iface['description'] = description
        elif 'description' in iface:
            del iface['description']

    elif interface_type == 'subif':
        # Subinterface - format: swp1.1001
        # First, remove from any previous bond
        previous_bond = data.get('previous_bond', '')
        if previous_bond:
            if 'bonds' in host_data and previous_bond in host_data['bonds']:
                old_bond = host_data['bonds'][previous_bond]
                if 'bond_members' in old_bond and interface_name in old_bond['bond_members']:
                    old_bond['bond_members'].remove(interface_name)
        
        if '.' in interface_name:
            parent_if, sub_id = interface_name.rsplit('.', 1)
            
            if 'interfaces' not in host_data:
                host_data['interfaces'] = {}
            if parent_if not in host_data['interfaces']:
                host_data['interfaces'][parent_if] = {}
            if 'subinterfaces' not in host_data['interfaces'][parent_if]:
                host_data['interfaces'][parent_if]['subinterfaces'] = {}
            
            subif = host_data['interfaces'][parent_if]['subinterfaces'].get(sub_id, {})
            
            # Update VLAN ID
            vlan_id = data.get('vlan_id', '')
            if vlan_id:
                _vlan = _v_int_range(vlan_id, 1, 4094)
                if _vlan is None:
                    print(json.dumps({'success': False, 'error': f'Invalid VLAN ID: {vlan_id} (must be 1-4094)'}))
                    sys.exit(0)
                subif['vlan'] = _vlan

            # Update IP
            ip = data.get('ip', '')
            if ip:
                if _v_ip_interface(ip) is None:
                    print(json.dumps({'success': False, 'error': f'Invalid IP: {ip}'}))
                    sys.exit(0)
                subif['ip'] = ip
            elif 'ip' in subif:
                del subif['ip']

            # Update VRF
            vrf = data.get('vrf', '')
            if vrf:
                if not _v_name(vrf):
                    print(json.dumps({'success': False, 'error': f'Invalid VRF name: {vrf}'}))
                    sys.exit(0)
                subif['vrf'] = vrf
            elif 'vrf' in subif:
                del subif['vrf']
            
            host_data['interfaces'][parent_if]['subinterfaces'][sub_id] = subif
            
            # Update parent description
            if description:
                host_data['interfaces'][parent_if]['description'] = description
        else:
            print(json.dumps({'success': False, 'error': 'Invalid subinterface format'}))
            sys.exit(0)
            
    elif interface_type == 'l2':
        # L2 interface
        # First, remove from any previous bond
        previous_bond = data.get('previous_bond', '')
        if previous_bond:
            if 'bonds' in host_data and previous_bond in host_data['bonds']:
                old_bond = host_data['bonds'][previous_bond]
                if 'bond_members' in old_bond and interface_name in old_bond['bond_members']:
                    old_bond['bond_members'].remove(interface_name)
        
        if 'interfaces' not in host_data:
            host_data['interfaces'] = {}
        if interface_name not in host_data['interfaces']:
            host_data['interfaces'][interface_name] = {}
        
        iface = host_data['interfaces'][interface_name]

        # Switching to L2/access: drop any L3 addressing left over
        for _k in ('ip', 'vrf'):
            if _k in iface:
                del iface[_k]

        # Update profile
        profile = data.get('profile', '')
        if profile:
            iface['sw_port_profile'] = profile
        elif 'sw_port_profile' in iface:
            del iface['sw_port_profile']

        # Update description
        if description:
            iface['description'] = description
        elif 'description' in iface:
            del iface['description']

    else:
        # Never map an unknown discriminator onto a destructive default
        # branch (the old default converted the port to L2, stripping ip/vrf)
        print(json.dumps({'success': False, 'error': f'Unknown interface_type: {interface_type}'}))
        sys.exit(0)

    # Write back
    _tmp_fd, _tmp_path = tempfile.mkstemp(dir=os.path.dirname(host_file), suffix='.tmp')
    _lldpq_mode_floor(_tmp_fd, host_file)
    try:
        with os.fdopen(_tmp_fd, 'w') as _tmp_f:
            yaml.dump(host_data, _tmp_f)
        shutil.move(_tmp_path, host_file)
    except:
        if os.path.exists(_tmp_path): os.unlink(_tmp_path)
        raise
    
    print(json.dumps({'success': True, 'message': f'{interface_type} {interface_name} updated'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON
        ;;
    add-external-peer)
        # Add a new external BGP peer
        # Creates subinterface + adds peer to BGP profile
        # If create_border_profile=true, creates OVERLAY_BORDER_XX profile with External peer group
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
import json
import re
import ipaddress
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))

try:
    device = data.get('device', '')
    vrf = data.get('vrf', '')
    interface = data.get('interface', '')  # e.g., swp1.1002
    vlan_id = data.get('vlan_id', '')
    local_ip = data.get('local_ip', '')
    remote_peer = data.get('remote_peer', '')
    weight = data.get('weight')
    policy_name = data.get('policy_name')
    policy_direction = data.get('policy_direction')
    soft_reconfiguration = data.get('soft_reconfiguration', False)
    create_border_profile = data.get('create_border_profile', False)
    border_profile_suffix = data.get('border_profile_suffix', '00')

    if not all([device, vrf, interface, local_ip, remote_peer]):
        print(json.dumps({'success': False, 'error': 'Missing required fields'}))
        exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
        print(json.dumps({'success': False, 'error': 'Invalid device name'}))
        exit(0)

    # Validate the optional peer fields written into bgp_profiles.yaml
    if weight is not None:
        weight = _v_int_range(weight, 0, 65535)
        if weight is None:
            print(json.dumps({'success': False, 'error': 'Invalid weight (must be 0-65535)'}))
            exit(0)
    if policy_name and policy_direction:
        if not re.match(r'^[A-Za-z0-9_.:-]+$', str(policy_name)):
            print(json.dumps({'success': False, 'error': f'Invalid policy name: {policy_name}'}))
            exit(0)
        if policy_direction not in ('inbound', 'outbound'):
            print(json.dumps({'success': False, 'error': 'Invalid policy direction (inbound/outbound)'}))
            exit(0)
    if create_border_profile and not re.match(r'^[A-Za-z0-9_]{1,8}$', str(border_profile_suffix)):
        print(json.dumps({'success': False, 'error': f'Invalid border profile suffix: {border_profile_suffix}'}))
        exit(0)

    # Validate remote_peer as a bare IP address
    try:
        ipaddress.ip_address(str(remote_peer))
    except ValueError:
        print(json.dumps({'success': False, 'error': f'Invalid remote peer IP: {remote_peer}'}))
        exit(0)

    # Normalize local_ip: accept CIDR as-is, otherwise validate host and append /31
    if '/' in str(local_ip):
        try:
            ipaddress.ip_interface(str(local_ip))
        except ValueError:
            print(json.dumps({'success': False, 'error': f'Invalid local IP: {local_ip}'}))
            exit(0)
        local_ip_norm = str(local_ip)
    else:
        try:
            ipaddress.ip_address(str(local_ip))
        except ValueError:
            print(json.dumps({'success': False, 'error': f'Invalid local IP: {local_ip}'}))
            exit(0)
        local_ip_norm = f'{local_ip}/31'

    # Build the peer_config the same way update-external-peer does
    peer_config = {}
    if weight is not None:
        peer_config['weight'] = int(weight)
    if policy_name and policy_direction:
        peer_config['policy'] = {'name': policy_name, 'direction': policy_direction}
    if soft_reconfiguration:
        peer_config['soft_reconfiguration'] = True
    new_peer_value = peer_config if peer_config else None

    # Parse interface name
    if '.' in interface:
        parent_if, sub_id = interface.split('.', 1)
    else:
        print(json.dumps({'success': False, 'error': 'Invalid interface format, expected swpX.VLAN'}))
        exit(0)

    # Validate VLAN part up front - int(sub_id) is used after files are written
    # (subinterface VLAN must be 1-4094 or nv config apply rejects it)
    if not sub_id.isdigit() or not 1 <= int(sub_id) <= 4094:
        print(json.dumps({'success': False, 'error': 'Invalid interface format, expected swpX.VLAN (VLAN 1-4094)'}))
        exit(0)

    # Validate parent interface (becomes an interfaces YAML key rendered raw)
    if not re.match(r'^(swp|eth|bond)[0-9]+(s[0-9]+)?$', parent_if):
        print(json.dumps({'success': False, 'error': f'Invalid parent interface: {parent_if}'}))
        exit(0)

    # 1. Update host_vars - add subinterface
    host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')
    
    if not os.path.exists(host_file):
        print(json.dumps({'success': False, 'error': f'Device file not found: {device}.yaml'}))
        exit(0)
    
    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}
    
    # Get VRF config
    vrfs = host_data.get('vrfs', {})
    if vrf not in vrfs:
        print(json.dumps({'success': False, 'error': f'VRF {vrf} not found on device'}))
        exit(0)
    
    vrf_config = vrfs[vrf]
    bgp_profile = vrf_config.get('bgp', {}).get('bgp_profile', '')
    profile_created = False

    # Refuse to overwrite an existing subinterface: it may carry another VRF's
    # external link, and this check must run before any file is written below.
    _existing_ifaces = host_data.get('interfaces', {}) or {}
    _parent_cfg = _existing_ifaces.get(parent_if, {}) if hasattr(_existing_ifaces, 'get') else {}
    _existing_subs = _parent_cfg.get('subinterfaces', {}) if hasattr(_parent_cfg, 'get') else {}
    if _existing_subs and (int(sub_id) in _existing_subs or str(sub_id) in _existing_subs):
        print(json.dumps({'success': False, 'error': f'Subinterface {parent_if}.{sub_id} already exists on {device}'}))
        exit(0)

    # Load BGP profiles
    bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
    with open(bgp_profiles_file, 'r') as f:
        bgp_data = yaml.load(f) or {}
    
    profiles = bgp_data.get('bgp_profiles', {})
    
    # Check if current profile has any fabric_exit peer group (fabric_exit: true or name == 'External')
    has_external = False
    external_pg_name = 'External'
    if bgp_profile and bgp_profile in profiles:
        peer_groups = profiles[bgp_profile].get('peer_groups', {})
        for _pg_name, _pg_config in peer_groups.items():
            if _pg_config.get('fabric_exit', False) or _pg_name == 'External':
                has_external = True
                external_pg_name = _pg_name
                break

    # Refuse if this remote_peer already exists in that peer group (do not clobber
    # the existing peer and its subinterface)
    if has_external and bgp_profile in profiles:
        _existing_peers = profiles[bgp_profile].get('peer_groups', {}).get(external_pg_name, {}).get('peers', {})
        _dup = (hasattr(_existing_peers, 'get') and remote_peer in _existing_peers) or \
               (isinstance(_existing_peers, list) and remote_peer in _existing_peers)
        if _dup:
            print(json.dumps({'success': False, 'error': f'Peer {remote_peer} already exists in {external_pg_name}'}))
            exit(0)

    # If no External and create_border_profile requested, create new OVERLAY_BORDER_XX profile
    if not has_external and create_border_profile:
        new_profile_name = f'OVERLAY_BORDER_{border_profile_suffix}'

        # bgp_profiles are shared across devices/VRFs; the suffix is only the
        # mgmt IP's last octet, so two devices can collide. Never clobber an
        # existing profile (that would silently drop another device's peers).
        if new_profile_name in profiles:
            print(json.dumps({'success': False, 'error': f'BGP profile {new_profile_name} already exists; select it for this VRF or choose a different suffix'}))
            exit(0)

        # Create new profile with External peer group (template from OVERLAY_BORDER_XX)
        profiles[new_profile_name] = {
            'ipv4_unicast_af': {
                'redistribute_connected_routes': True,
                'redistribute_static_routes': False,
                'export_to_evpn_type5': True
            },
            'peer_groups': {
                'External': {
                    'description': 'External-Connections',
                    'peer_type': 'external',
                    'enable_bfd': False,
                    'peers': {
                        remote_peer: new_peer_value
                    }
                }
            }
        }
        
        # Update VRF to use new profile (both files are committed together
        # at the end, so host_vars can never reference a profile that was
        # never written to bgp_profiles.yaml)
        if 'bgp' not in vrf_config:
            vrf_config['bgp'] = {}
        vrf_config['bgp']['bgp_profile'] = new_profile_name
        bgp_profile = new_profile_name
        profile_created = True

    elif not has_external:
        print(json.dumps({'success': False, 'error': f'External peer group not found in profile {bgp_profile}. Enable "Create Border Profile" option.'}))
        exit(0)
    
    # Create subinterface
    if 'interfaces' not in host_data:
        host_data['interfaces'] = {}
    
    if parent_if not in host_data['interfaces']:
        host_data['interfaces'][parent_if] = {'description': 'External BGP'}
    
    if 'subinterfaces' not in host_data['interfaces'][parent_if]:
        host_data['interfaces'][parent_if]['subinterfaces'] = {}
    
    # Add subinterface
    host_data['interfaces'][parent_if]['subinterfaces'][int(sub_id)] = {
        'ip': local_ip_norm,
        'vlan': int(sub_id),
        'vrf': vrf
    }

    # If profile already had a fabric_exit peer group, add peer to it
    # (in memory; bgp_data was loaded above and not written yet)
    if has_external and not profile_created:
        profile = profiles[bgp_profile]
        external_pg = profile['peer_groups'][external_pg_name]

        # Initialize peers dict if needed
        if 'peers' not in external_pg:
            external_pg['peers'] = {}

        # Handle both list and dict formats
        if isinstance(external_pg['peers'], list):
            if new_peer_value is not None:
                # Promote to dict form so the modal fields can be stored
                external_pg['peers'] = {str(p): {} for p in external_pg['peers']}
                external_pg['peers'][remote_peer] = new_peer_value
            elif remote_peer not in external_pg['peers']:
                external_pg['peers'].append(remote_peer)
        else:
            external_pg['peers'][remote_peer] = new_peer_value

    # Two-phase commit: stage both dumps first, rename both only after both
    # succeeded (no half-applied subinterface/peer edit on failure)
    _atomic_write_many(yaml, [(host_data, host_file), (bgp_data, bgp_profiles_file)])

    print(json.dumps({
        'success': True, 
        'message': f'Added external peer {remote_peer} on {device} ({interface})',
        'bgp_profile': bgp_profile,
        'profile_created': profile_created
    }))

except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'trace': traceback.format_exc()}))
PYTHON
        ;;
    delete-external-peer)
        # Delete an external BGP peer
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))

try:
    device = data.get('device', '')
    vrf = data.get('vrf', '')
    interface = data.get('interface', '')  # e.g., swp1.1002
    remote_peer = data.get('remote_peer', '')

    if not all([device, vrf, remote_peer]):
        print(json.dumps({'success': False, 'error': 'Missing required fields'}))
        sys.exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
        print(json.dumps({'success': False, 'error': 'Invalid device name'}))
        sys.exit(0)

    # 1. Update host_vars (in memory) - remove subinterface if specified.
    # All mutations are staged and committed together at the end so a failure
    # in the BGP profile phase cannot leave the subinterface removal applied.
    host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')
    subif_removed = False
    host_data = None
    _host_dirty = False

    if os.path.exists(host_file):
        with open(host_file, 'r') as f:
            host_data = yaml.load(f) or {}
    else:
        print(json.dumps({'success': False, 'error': f'Host vars file not found for device {device}'}))
        sys.exit(0)

    if host_data is not None and interface and '.' in interface:
        parent_if, sub_id = interface.split('.', 1)

        # Remove subinterface
        if 'interfaces' in host_data and parent_if in host_data['interfaces']:
            subifs = host_data['interfaces'][parent_if].get('subinterfaces', {})
            
            # Try both int and string keys
            _sub_key = None
            if int(sub_id) in subifs:
                _sub_key = int(sub_id)
            elif sub_id in subifs:
                _sub_key = sub_id
            if _sub_key is not None:
                # Ownership guard (shared with update-external-peer): never
                # delete a subinterface that belongs to another VRF, even if
                # a stale UI row or crafted POST names it.
                _sub_cfg = subifs.get(_sub_key)
                if not _subif_owned_by_vrf(_sub_cfg, vrf):
                    _owner = _sub_cfg.get('vrf', 'default') if hasattr(_sub_cfg, 'get') else 'unknown'
                    print(json.dumps({'success': False, 'error': f'Subinterface {interface} belongs to VRF {_owner}, not {vrf}; refusing to delete it'}))
                    sys.exit(0)
                del subifs[_sub_key]
                subif_removed = True
            
            # Clean up empty subinterfaces dict
            if subif_removed and not subifs:
                del host_data['interfaces'][parent_if]['subinterfaces']
            
            # Clean up empty interface dict
            if subif_removed and len(host_data['interfaces'][parent_if]) == 0:
                del host_data['interfaces'][parent_if]

        if subif_removed:
            _host_dirty = True

    # 2. Get BGP profile from VRF config (same in-memory host_data)
    bgp_profile = ''
    if host_data is not None:
        vrfs = host_data.get('vrfs', {})
        if vrf in vrfs:
            bgp_profile = vrfs[vrf].get('bgp', {}).get('bgp_profile', '')

    # 3. Remove peer from BGP profile External group
    peer_removed = False
    profile_deleted = False
    _bgp_dirty = False

    if bgp_profile:
        bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
        
        with open(bgp_profiles_file, 'r') as f:
            bgp_data = yaml.load(f) or {}
        
        profiles = bgp_data.get('bgp_profiles', {})
        
        if bgp_profile in profiles:
            profile = profiles[bgp_profile]
            peer_groups = profile.get('peer_groups', {})
            
            # Find the peer group containing this peer (fabric_exit or 'External')
            _found_pg_name = None
            for _pg_name, _pg_config in peer_groups.items():
                if not (_pg_config.get('fabric_exit', False) or _pg_name == 'External'):
                    continue
                _pg_peers = _pg_config.get('peers', {})
                if isinstance(_pg_peers, dict) and remote_peer in _pg_peers:
                    _found_pg_name = _pg_name
                    break
                elif isinstance(_pg_peers, list) and remote_peer in _pg_peers:
                    _found_pg_name = _pg_name
                    break
            
            if _found_pg_name:
                external_pg = peer_groups[_found_pg_name]
                peers = external_pg.get('peers', {})
                
                if isinstance(peers, list):
                    if remote_peer in peers:
                        peers.remove(remote_peer)
                        peer_removed = True
                else:
                    if remote_peer in peers:
                        del peers[remote_peer]
                        peer_removed = True
                
                # Check if no peers left and profile is OVERLAY_BORDER_XX
                remaining_peers = len(peers) if isinstance(peers, (list, dict)) else 0
                is_border_profile = bgp_profile.startswith('OVERLAY_BORDER_')
                
                if peer_removed and remaining_peers == 0 and is_border_profile:
                    # bgp_profiles are shared across devices/VRFs: only delete
                    # the empty border profile when no other device/VRF (host_vars
                    # or group_vars) still references it, and only repoint to a
                    # fallback profile that actually exists.
                    _other_refs = [_r for _r in _scan_bgp_profile_refs(os.path.join(ansible_dir, 'inventory'), yaml, bgp_profile)
                                   if not (_r.get('device') == device and _r.get('vrf') == vrf)]
                    if not _other_refs and 'OVERLAY_LEAF' in profiles:
                        # Delete the empty OVERLAY_BORDER_XX profile
                        del profiles[bgp_profile]
                        profile_deleted = True

                        # Update VRF to use OVERLAY_LEAF instead (same
                        # in-memory host_data, committed below)
                        if host_data is not None and vrf in host_data.get('vrfs', {}):
                            vrf_config = host_data['vrfs'][vrf]
                            if 'bgp' in vrf_config:
                                vrf_config['bgp']['bgp_profile'] = 'OVERLAY_LEAF'
                            _host_dirty = True

                # Save bgp_profiles (with or without deleted profile)
                _bgp_dirty = True

    # Two-phase commit: stage every modified file first, rename only after
    # all dumps succeeded (dependent bgp_profiles.yaml goes last)
    _writes = []
    if _host_dirty and host_data is not None:
        _writes.append((host_data, host_file))
    if _bgp_dirty:
        _writes.append((bgp_data, bgp_profiles_file))
    if _writes:
        _atomic_write_many(yaml, _writes)

    # A complete no-op (typoed device, already-deleted peer, VRF without a
    # profile) is an error unless the caller explicitly opts into
    # idempotent semantics.
    if not peer_removed and not subif_removed and not data.get('idempotent'):
        print(json.dumps({
            'success': False,
            'error': f'External peer {remote_peer} not found on {device}: no matching subinterface or BGP peer entry; nothing was deleted',
            'subinterface_removed': subif_removed,
            'peer_removed': peer_removed,
            'profile_deleted': profile_deleted
        }))
        sys.exit(0)

    print(json.dumps({
        'success': True,
        'message': f'Deleted external peer {remote_peer} from {device}',
        'subinterface_removed': subif_removed,
        'peer_removed': peer_removed,
        'profile_deleted': profile_deleted
    }))

except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'trace': traceback.format_exc()}))
PYTHON
        ;;
    update-external-peer)
        # Update an existing external BGP peer
        acquire_lock
        read_post_body
        export POST_DATA
        python3 << PYTHON
$LLDPQ_MODE_FLOOR_DEF
$LLDPQ_ATOMIC_WRITE_DEF
$LLDPQ_VALIDATORS_DEF
$LLDPQ_REF_SCAN_DEF
import json
import re
import ipaddress
from ruamel.yaml import YAML
yaml = YAML()
yaml.preserve_quotes = True
import tempfile
import shutil
import os
import sys

try:
    data = json.loads(os.environ.get('POST_DATA') or '{}')
except:
    data = {}

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))

try:
    device = data.get('device', '')
    vrf = data.get('vrf', '')
    original_peer = data.get('original_peer', '')
    interface = data.get('interface', '')  # e.g., swp1.1002, or 'lo', or bare 'swp5'
    original_interface = data.get('original_interface', '')  # previous swpX.VLAN when the interface field was edited
    local_ip = data.get('local_ip', '')
    remote_peer = data.get('remote_peer', '')
    weight = data.get('weight')  # Can be None or int
    policy_name = data.get('policy_name')  # Can be None or string
    policy_direction = data.get('policy_direction')  # Can be None or 'inbound'/'outbound'
    soft_reconfiguration = data.get('soft_reconfiguration', False)  # Boolean
    bfd_enabled = data.get('bfd_enabled')  # tri-state: absent = leave group setting unchanged

    if not all([device, vrf, interface, local_ip, remote_peer]):
        print(json.dumps({'success': False, 'error': 'Missing required fields'}))
        sys.exit(0)

    if not re.match(r'^[A-Za-z0-9_.-]+$', str(device)):
        print(json.dumps({'success': False, 'error': 'Invalid device name'}))
        sys.exit(0)

    # Validate the optional peer fields written into bgp_profiles.yaml
    if weight is not None:
        weight = _v_int_range(weight, 0, 65535)
        if weight is None:
            print(json.dumps({'success': False, 'error': 'Invalid weight (must be 0-65535)'}))
            sys.exit(0)
    if policy_name and policy_direction:
        if not re.match(r'^[A-Za-z0-9_.:-]+$', str(policy_name)):
            print(json.dumps({'success': False, 'error': f'Invalid policy name: {policy_name}'}))
            sys.exit(0)
        if policy_direction not in ('inbound', 'outbound'):
            print(json.dumps({'success': False, 'error': 'Invalid policy direction (inbound/outbound)'}))
            sys.exit(0)

    # Validate remote_peer as a bare IP address
    try:
        ipaddress.ip_address(str(remote_peer))
    except ValueError:
        print(json.dumps({'success': False, 'error': f'Invalid remote peer IP: {remote_peer}'}))
        sys.exit(0)

    # Normalize local_ip consistently with add-external-peer (append /31 when no prefix)
    if '/' in str(local_ip):
        try:
            ipaddress.ip_interface(str(local_ip))
        except ValueError:
            print(json.dumps({'success': False, 'error': f'Invalid local IP: {local_ip}'}))
            sys.exit(0)
        local_ip_norm = str(local_ip)
    else:
        try:
            ipaddress.ip_address(str(local_ip))
        except ValueError:
            print(json.dumps({'success': False, 'error': f'Invalid local IP: {local_ip}'}))
            sys.exit(0)
        local_ip_norm = f'{local_ip}/31'

    # Subinterface rewrite only applies to swpX.VLAN peers. lo/multihop and bare
    # direct-interface peers have no subinterface to rewrite.
    is_subif = ('.' in interface) and interface != 'lo'
    parent_if = sub_id = None
    if is_subif:
        parent_if, sub_id = interface.split('.', 1)
        if not sub_id.isdigit() or not 1 <= int(sub_id) <= 4094:
            print(json.dumps({'success': False, 'error': 'Invalid interface format, expected swpX.VLAN (VLAN 1-4094)'}))
            sys.exit(0)
        # Validate parent interface (becomes an interfaces YAML key rendered raw)
        if not re.match(r'^(swp|eth|bond)[0-9]+(s[0-9]+)?$', parent_if):
            print(json.dumps({'success': False, 'error': f'Invalid parent interface: {parent_if}'}))
            sys.exit(0)

    # 1. Update host_vars - update subinterface
    host_file = os.path.join(ansible_dir, 'inventory', 'host_vars', f'{device}.yaml')

    if not os.path.exists(host_file):
        print(json.dumps({'success': False, 'error': f'Device file not found: {device}.yaml'}))
        sys.exit(0)

    with open(host_file, 'r') as f:
        host_data = yaml.load(f) or {}

    # Get VRF's BGP profile
    vrfs = host_data.get('vrfs', {})
    if vrf not in vrfs:
        print(json.dumps({'success': False, 'error': f'VRF {vrf} not found on device'}))
        sys.exit(0)

    bgp_profile = vrfs[vrf].get('bgp', {}).get('bgp_profile', '')
    if not bgp_profile:
        print(json.dumps({'success': False, 'error': f'No BGP profile configured for VRF {vrf}'}))
        sys.exit(0)

    if is_subif:
        # Ownership guard (same rule as add-external-peer): only overwrite a
        # subinterface that is absent or already belongs to this VRF - it may
        # carry another VRF's external link.
        _ifaces = host_data.get('interfaces', {}) or {}
        _pcfg = _ifaces.get(parent_if, {}) if hasattr(_ifaces, 'get') else {}
        _subs = _pcfg.get('subinterfaces', {}) if hasattr(_pcfg, 'get') else {}
        _cur = None
        if hasattr(_subs, 'get'):
            _cur = _subs.get(int(sub_id))
            if _cur is None:
                _cur = _subs.get(str(sub_id))
        if _cur is not None and (not hasattr(_cur, 'get') or not _subif_owned_by_vrf(_cur, vrf)):
            _owner = _cur.get('vrf', 'default') if hasattr(_cur, 'get') else 'unknown'
            print(json.dumps({'success': False, 'error': f'Subinterface {interface} already belongs to VRF {_owner}; refusing to overwrite it'}))
            sys.exit(0)

        # When the interface field changed, drop the old subinterface in the
        # same write so no stale L3 config (and its IP) is left behind.
        if original_interface and original_interface != interface and '.' in original_interface and original_interface != 'lo':
            _old_parent, _old_sub = original_interface.split('.', 1)
            _old_pcfg = _ifaces.get(_old_parent) if hasattr(_ifaces, 'get') else None
            _old_subs = _old_pcfg.get('subinterfaces') if hasattr(_old_pcfg, 'get') else None
            if hasattr(_old_subs, 'get'):
                _old_key = None
                if _old_sub.isdigit() and int(_old_sub) in _old_subs:
                    _old_key = int(_old_sub)
                elif _old_sub in _old_subs:
                    _old_key = _old_sub
                # Only remove the old subinterface if it belongs to this VRF
                if _old_key is not None and _subif_owned_by_vrf(_old_subs.get(_old_key), vrf):
                    del _old_subs[_old_key]
                    if not _old_subs:
                        _old_pcfg.pop('subinterfaces', None)

        # Update subinterface
        if 'interfaces' not in host_data:
            host_data['interfaces'] = {}

        if parent_if not in host_data['interfaces']:
            host_data['interfaces'][parent_if] = {'description': 'External BGP'}

        if 'subinterfaces' not in host_data['interfaces'][parent_if]:
            host_data['interfaces'][parent_if]['subinterfaces'] = {}

        # Update subinterface config (staged; committed together with the
        # peer update below so an error in the BGP phase - e.g. peer not
        # found - cannot leave a half-applied subinterface edit)
        host_data['interfaces'][parent_if]['subinterfaces'][int(sub_id)] = {
            'ip': local_ip_norm,
            'vlan': int(sub_id),
            'vrf': vrf
        }

    # 2. Update BGP profile - update peer in External group
    bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
    
    with open(bgp_profiles_file, 'r') as f:
        bgp_data = yaml.load(f) or {}
    
    profiles = bgp_data.get('bgp_profiles', {})
    
    if bgp_profile not in profiles:
        print(json.dumps({'success': False, 'error': f'BGP profile {bgp_profile} not found'}))
        sys.exit(0)
    
    profile = profiles[bgp_profile]
    peer_groups = profile.get('peer_groups', {})
    
    # Find the peer group containing this peer (fabric_exit or 'External')
    _search_ip = original_peer if original_peer else remote_peer
    _found_pg_name = None
    for _pg_name, _pg_config in peer_groups.items():
        if not (_pg_config.get('fabric_exit', False) or _pg_name == 'External'):
            continue
        _pg_peers = _pg_config.get('peers', {})
        if isinstance(_pg_peers, dict) and _search_ip in _pg_peers:
            _found_pg_name = _pg_name
            break
        elif isinstance(_pg_peers, list) and _search_ip in _pg_peers:
            _found_pg_name = _pg_name
            break
    
    if not _found_pg_name:
        print(json.dumps({'success': False, 'error': f'Peer {_search_ip} not found in any fabric_exit peer group of profile {bgp_profile}'}))
        sys.exit(0)
    
    external_pg = peer_groups[_found_pg_name]
    
    # Update BFD setting for the peer group only when the request submitted
    # it: enable_bfd is group-level in a shared bgp_profiles.yaml, so a
    # caller that omits bfd_enabled must not flip BFD for every peer
    if 'bfd_enabled' in data:
        external_pg['enable_bfd'] = bool(bfd_enabled)
    
    # Update peer
    peers = external_pg.get('peers', {})
    
    if isinstance(peers, list):
        # Convert list format to dict format for weight support
        peers = {str(p): {} for p in peers}
        external_pg['peers'] = peers
    
    # Preserve the existing peer node (description and any unknown keys) across the edit
    _prev = None
    if original_peer and original_peer in peers and hasattr(peers[original_peer], 'items'):
        _prev = peers[original_peer]
    elif remote_peer in peers and hasattr(peers[remote_peer], 'items'):
        _prev = peers[remote_peer]

    # Handle peer IP change
    if original_peer and original_peer != remote_peer:
        if original_peer in peers:
            del peers[original_peer]

    # Start from the existing config so description/unknown keys survive
    peer_config = _prev if hasattr(_prev, 'items') else {}

    # Set/update the modal-controlled fields (weight, policy, soft_reconfiguration)
    if weight is not None:
        peer_config['weight'] = int(weight)
    else:
        peer_config.pop('weight', None)
    if policy_name and policy_direction:
        peer_config['policy'] = {
            'name': policy_name,
            'direction': policy_direction
        }
    else:
        peer_config.pop('policy', None)
    if soft_reconfiguration:
        peer_config['soft_reconfiguration'] = True
    else:
        peer_config.pop('soft_reconfiguration', None)
    peers[remote_peer] = peer_config if peer_config else {}

    # Two-phase commit: stage host_vars (when a subinterface was rewritten)
    # and bgp_profiles together, rename only after all dumps succeeded
    _writes = []
    if is_subif:
        _writes.append((host_data, host_file))
    _writes.append((bgp_data, bgp_profiles_file))
    _atomic_write_many(yaml, _writes)

    print(json.dumps({
        'success': True,
        'message': f'Updated external peer {remote_peer} on {device} ({interface})',
        'bgp_profile': bgp_profile,
        'bfd_updated': True
    }))

except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'trace': traceback.format_exc()}))
PYTHON
        ;;
    list-vtep-devices)
        # List all VTEP devices (devices with vtep.state: true)
        python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import sys
import glob

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))

try:
    host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
    # Fallback: try inventory.ini first, then hosts
    hosts_file = None
    for name in ['inventory.ini', 'hosts']:
        path = os.path.join(ansible_dir, 'inventory', name)
        if os.path.exists(path):
            hosts_file = path
            break

    # Build hostname -> IP mapping from hosts file
    host_ips = {}
    if hosts_file:
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('[') and '=' in line:
                    parts = line.split()
                    hostname = parts[0]
                    for part in parts[1:]:
                        if part.startswith('ansible_host='):
                            host_ips[hostname] = part.split('=')[1]
                            break
    
    # Find all devices with vtep.state: true
    vtep_devices = []
    load_errors = {}

    for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')):
        hostname = os.path.basename(host_file).replace('.yaml', '')
        
        try:
            with open(host_file, 'r') as f:
                host_data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            
            # Check if vtep.state is true
            vtep_config = host_data.get('vtep', {})
            if vtep_config.get('state', False):
                vtep_devices.append({
                    'hostname': hostname,
                    'ip': host_ips.get(hostname, '')
                })
        except (yaml.YAMLError, OSError, AttributeError) as e:
            # Surface per-file failures so partial results are visibly partial
            sys.stderr.write(f'list-vtep-devices: {os.path.basename(host_file)}: {e}\n')
            load_errors[os.path.basename(host_file)] = str(e)

    # Sort by hostname
    vtep_devices.sort(key=lambda x: x['hostname'])

    _resp = {
        'success': True,
        'devices': vtep_devices,
        'count': len(vtep_devices)
    }
    if load_errors:
        _resp['errors'] = load_errors
        _resp['warning'] = 'Some host_vars files could not be parsed: ' + ', '.join(load_errors)
    print(json.dumps(_resp))

except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'trace': traceback.format_exc()}))
PYTHON
        ;;
    list-external-peers)
        # List all external BGP peers across all devices
        python3 << 'PYTHON'
import json
import yaml  # PyYAML - faster for read-only operations
import os
import glob
import ipaddress

ansible_dir = os.environ.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))

try:
    # Load BGP profiles
    bgp_profiles_file = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all', 'bgp_profiles.yaml')
    bgp_profiles = {}
    profiles_with_external = {}
    
    if os.path.exists(bgp_profiles_file):
        with open(bgp_profiles_file, 'r') as f:
            bgp_data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
            bgp_profiles = bgp_data.get('bgp_profiles', {})
    
    # Find profiles with fabric_exit peer groups (fabric_exit: true tag or name == 'External')
    for profile_name, profile_config in bgp_profiles.items():
        peer_groups = profile_config.get('peer_groups', {})
        for pg_name, pg_config in peer_groups.items():
            if not (pg_config.get('fabric_exit', False) or pg_name == 'External'):
                continue
            
            peers_data = pg_config.get('peers', {})
            
            # Build peers dict with weight, policy, and soft_reconfiguration info
            peers_with_info = {}
            if isinstance(peers_data, dict):
                for peer_ip, peer_config in peers_data.items():
                    weight = None
                    policy_name = None
                    policy_direction = None
                    soft_reconfiguration = False
                    if isinstance(peer_config, dict):
                        weight = peer_config.get('weight')
                        soft_reconfiguration = peer_config.get('soft_reconfiguration', False)
                        policy = peer_config.get('policy', {})
                        if isinstance(policy, dict):
                            policy_name = policy.get('name')
                            policy_direction = policy.get('direction')
                    peers_with_info[peer_ip] = {
                        'weight': weight,
                        'policy_name': policy_name,
                        'policy_direction': policy_direction,
                        'soft_reconfiguration': soft_reconfiguration
                    }
            else:
                for peer_ip in peers_data:
                    peers_with_info[peer_ip] = {'weight': None, 'policy_name': None, 'policy_direction': None, 'soft_reconfiguration': False}
            
            if peers_with_info:
                if profile_name not in profiles_with_external:
                    profiles_with_external[profile_name] = []
                profiles_with_external[profile_name].append({
                    'pg_name': pg_name,
                    'peers': peers_with_info,
                    'bfd_enabled': pg_config.get('enable_bfd', False),
                    'description': pg_config.get('description', ''),
                    'update_source': pg_config.get('update_source', '')
                })
    
    # Load all devices and find those using external profiles
    peers = []
    devices = []
    host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
    
    for host_file in glob.glob(os.path.join(host_vars_dir, '*.yaml')):
        hostname = os.path.basename(host_file).replace('.yaml', '')
        
        with open(host_file, 'r') as f:
            host_data = yaml.load(f, Loader=yaml.CSafeLoader) or {}
        
        # Check VRFs for external BGP profiles
        vrfs = host_data.get('vrfs', {})
        interfaces = host_data.get('interfaces', {})
        has_external = False
        
        for vrf_name, vrf_config in vrfs.items():
            bgp_config = vrf_config.get('bgp', {})
            profile_name = bgp_config.get('bgp_profile', '')
            
            if profile_name in profiles_with_external:
                has_external = True
                
                for ext_pg in profiles_with_external[profile_name]:
                    peers_data = ext_pg['peers']
                    
                    for peer_ip, peer_info in peers_data.items():
                        local_ip = ''
                        interface_name = ''
                        
                        # Non-IP peer keys (e.g. BGP unnumbered interface names) skip subnet matching
                        try:
                            peer_addr = ipaddress.ip_address(str(peer_ip))
                        except ValueError:
                            peer_addr = None

                        # 1) Check subinterfaces (swpX.VLAN)
                        if peer_addr:
                            for if_name, if_config in interfaces.items():
                                subinterfaces = if_config.get('subinterfaces', {})
                                for sub_id, sub_config in subinterfaces.items():
                                    sub_ip = sub_config.get('ip', '')
                                    sub_vrf = sub_config.get('vrf', '')

                                    if sub_vrf == vrf_name and sub_ip and '/' in sub_ip:
                                        if peer_addr in ipaddress.ip_network(sub_ip, strict=False):
                                            local_ip = sub_ip
                                            interface_name = f"{if_name}.{sub_id}"
                                            break
                                if local_ip:
                                    break

                        # 2) Check direct interface IPs (subnet match)
                        if not local_ip and peer_addr:
                            for if_name, if_config in interfaces.items():
                                if_ip = if_config.get('ip', '')
                                if not if_ip or '/' not in if_ip:
                                    continue
                                if_vrf = if_config.get('vrf', 'default')
                                if if_vrf != vrf_name:
                                    continue
                                if peer_addr in ipaddress.ip_network(if_ip, strict=False):
                                    local_ip = if_ip
                                    interface_name = if_name
                                    break
                        
                        # 3) Fallback to update_source (eBGP multihop / loopback)
                        if not local_ip and ext_pg.get('update_source', ''):
                            local_ip = ext_pg['update_source']
                            interface_name = 'lo'
                        
                        peers.append({
                            'device': hostname,
                            'vrf': vrf_name,
                            'bgp_profile': profile_name,
                            'peer_group': ext_pg['pg_name'],
                            'interface': interface_name,
                            'local_ip': local_ip.split('/')[0] if local_ip else '',
                            'remote_peer': str(peer_ip),
                            'weight': peer_info.get('weight'),
                            'policy_name': peer_info.get('policy_name'),
                            'policy_direction': peer_info.get('policy_direction'),
                            'soft_reconfiguration': peer_info.get('soft_reconfiguration', False),
                            'bfd_enabled': ext_pg['bfd_enabled']
                        })
        
        if has_external:
            devices.append({'hostname': hostname})
    
    # Sort peers by device, then vrf
    peers.sort(key=lambda x: (x['device'], x['vrf'], x['remote_peer']))
    
    print(json.dumps({
        'success': True,
        'peers': peers,
        'devices': devices,
        'bgp_profiles': {k: {'has_external': True, 'bfd_enabled': any(pg['bfd_enabled'] for pg in v)} for k, v in profiles_with_external.items()}
    }))

except Exception as e:
    import traceback
    print(json.dumps({'success': False, 'error': str(e), 'trace': traceback.format_exc()}))
PYTHON
        ;;
    get-device-data)
        # Get all monitoring data for a specific device
        # Parse the query inside the quoted Python block.  Interpolating a
        # decoded device name into Python source made malformed query values a
        # code-injection and parser-confusion boundary.
        python3 << 'PYTHON'
import json
import math
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone


def fail(message):
    print(json.dumps({'success': False, 'error': message}))
    raise SystemExit(0)


raw_query = os.environ.get('QUERY_STRING', '')
if len(raw_query) > 4096:
    fail('Query string is too large')
try:
    query = urllib.parse.parse_qs(
        raw_query,
        keep_blank_values=True,
        encoding='utf-8',
        errors='strict',
        max_num_fields=32,
    )
except (UnicodeError, ValueError):
    fail('Invalid query string')

device_values = query.get('device', [])
if not device_values or not device_values[0].strip():
    fail('Missing device parameter')
if len(device_values) != 1:
    fail('Device parameter must be specified once')
device = device_values[0].strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

monitor_dir = os.path.join(
    os.environ.get('WEB_ROOT', '/var/www/html'), 'monitor-results'
)
try:
    max_age_minutes = float(
        os.environ.get('MONITOR_DATA_MAX_AGE_MINUTES', '30')
    )
    if not math.isfinite(max_age_minutes):
        raise ValueError('freshness window must be finite')
    max_age_seconds = max(max_age_minutes, 0.0) * 60.0
except ValueError:
    max_age_seconds = 1800.0
now = time.time()


def timestamp_epoch(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            candidate = float(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
                # Legacy BGP files used datetime.now().isoformat(), which is
                # naive local time. datetime.timestamp() preserves that
                # producer contract; replacing tzinfo with UTC would move
                # fresh data into the future on non-UTC servers. Aware values
                # retain their explicit offset through the same operation.
                candidate = parsed.timestamp()
            except ValueError:
                return None
    else:
        return None
    return candidate if math.isfinite(candidate) and candidate >= 0 else None


def iso_timestamp(epoch):
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace(
            '+00:00', 'Z'
        )
    except (OSError, OverflowError, ValueError):
        return None


def unavailable_source(path, reason, file_epoch=None):
    return {
        'status': 'unavailable',
        'available': False,
        'current': False,
        'stale': False,
        'timestamp': None,
        'file_timestamp': iso_timestamp(file_epoch),
        'age_seconds': None,
        'max_age_seconds': int(max_age_seconds),
        'record_count': None,
        'reason': reason,
    }


def source_metadata(path, embedded_timestamp=None):
    try:
        file_epoch = os.path.getmtime(path)
    except OSError:
        return unavailable_source(path, 'Source file is missing')
    embedded_epoch = timestamp_epoch(embedded_timestamp)
    if embedded_timestamp is not None and embedded_epoch is None:
        return unavailable_source(
            path, 'Source timestamp is invalid', file_epoch=file_epoch
        )
    source_epoch = embedded_epoch if embedded_epoch is not None else file_epoch
    if source_epoch > now + 300:
        return unavailable_source(
            path, 'Source timestamp is in the future', file_epoch=file_epoch
        )
    age_seconds = max(0.0, now - source_epoch)
    stale = age_seconds > max_age_seconds
    return {
        'status': 'stale' if stale else 'current',
        'available': True,
        'current': not stale,
        'stale': stale,
        'timestamp': iso_timestamp(source_epoch),
        'file_timestamp': iso_timestamp(file_epoch),
        'age_seconds': int(age_seconds),
        'max_age_seconds': int(max_age_seconds),
        'record_count': 0,
        'reason': (
            'Source is older than the configured freshness window'
            if stale else None
        ),
    }


def load_json_source(filename):
    path = os.path.join(monitor_dir, filename)
    try:
        file_epoch = os.path.getmtime(path)
    except OSError:
        return None, unavailable_source(path, 'Source file is missing')
    try:
        with open(path, 'r', encoding='utf-8') as source:
            payload = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, unavailable_source(
            path, 'Source file is unreadable or invalid', file_epoch=file_epoch
        )
    if not isinstance(payload, dict):
        return None, unavailable_source(
            path, 'Source payload must be a JSON object', file_epoch=file_epoch
        )
    return payload, None


def mark_unavailable(metadata, reason):
    metadata.update({
        'status': 'unavailable',
        'available': False,
        'current': False,
        'stale': False,
        'age_seconds': metadata.get('age_seconds'),
        'record_count': None,
        'reason': reason,
    })


def valid_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def read_pipeline_marker():
    path = os.path.join(monitor_dir, '.lldpq-stale')
    try:
        file_epoch = os.path.getmtime(path)
        with open(path, 'r', encoding='utf-8', errors='replace') as marker_file:
            content = marker_file.read(16384)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {
            'status': 'stale',
            'timestamp': iso_timestamp(timestamp_epoch(file_epoch) if 'file_epoch' in locals() else None),
            'reason': f'Could not read pipeline stale marker: {exc}',
        }
    values = {}
    for line in content.splitlines():
        key, separator, value = line.partition('=')
        if separator and key in {'status', 'timestamp', 'reason'}:
            values[key] = value.strip()
    marker_status = values.get('status') or 'stale'
    marker_epoch = timestamp_epoch(values.get('timestamp'))
    return {
        'status': marker_status,
        'timestamp': iso_timestamp(marker_epoch if marker_epoch is not None else file_epoch),
        'reason': values.get('reason') or 'Pipeline publication is not current',
    }


def read_current_manifest():
    path = os.path.join(monitor_dir, '.lldpq-current.json')
    try:
        with open(path, 'r', encoding='utf-8') as manifest_file:
            manifest = json.load(manifest_file)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get('status') != 'current'
        or manifest.get('pipeline_complete') is not True
        or not isinstance(manifest.get('analyses'), list)
        or not all(isinstance(item, str) for item in manifest.get('analyses', []))
        or not isinstance(manifest.get('skipped', []), list)
        or not all(isinstance(item, str) for item in manifest.get('skipped', []))
    ):
        return None
    completed_epoch = timestamp_epoch(manifest.get('completed_at'))
    if (
        completed_epoch is None
        or completed_epoch > now + 300
        or now - completed_epoch > max_age_seconds
    ):
        return None
    return manifest


def apply_pipeline_marker(metadata, marker):
    if not marker:
        return
    marker_reason = (
        f"Pipeline {marker.get('status', 'stale')}: "
        f"{marker.get('reason', 'publication is not current')}"
    )
    prior_reason = metadata.get('reason')
    metadata['reason'] = (
        f'{prior_reason}; {marker_reason}' if prior_reason else marker_reason
    )
    metadata['pipeline_status'] = marker.get('status')
    metadata['pipeline_timestamp'] = marker.get('timestamp')
    if metadata.get('status') != 'unavailable':
        metadata.update({
            'status': 'stale',
            'current': False,
            'stale': True,
        })


pipeline_marker = read_pipeline_marker()
current_manifest = read_current_manifest()

result = {
    'success': True,
    'device': device,
    # Null means that the source is unavailable.  An empty list/object is only
    # emitted for a valid current snapshot, avoiding false healthy zeroes.
    'optical': None,
    'logs': None,
    'bgp': None,
    'sources': {},
    'timestamps': {},
    'last_update': None,
    'pipeline': (
        {'status': 'stale', **pipeline_marker}
        if pipeline_marker else (
            {
                'status': 'current',
                'timestamp': current_manifest.get('completed_at'),
                'reason': None,
            }
            if current_manifest else None
        )
    ),
}

try:
    # Optical: current_optical_stats is the collection snapshot.  Historical
    # readings must never be presented as current device state.
    optical_data, optical_error = load_json_source('optical_history.json')
    if optical_error:
        optical_meta = optical_error
    else:
        optical_meta = source_metadata(
            os.path.join(monitor_dir, 'optical_history.json'),
            optical_data.get('last_update'),
        )
        current_stats = optical_data.get('current_optical_stats')
        manifest_analyses = set(current_manifest.get('analyses', [])) if current_manifest else set()
        manifest_skipped = set(current_manifest.get('skipped', [])) if current_manifest else set()
        if current_manifest and 'optical' in manifest_skipped:
            mark_unavailable(optical_meta, 'Optical analysis was skipped in the current pipeline')
        elif not isinstance(current_stats, dict):
            mark_unavailable(optical_meta, 'Current optical snapshot is unavailable')
        elif not current_stats:
            if (
                current_manifest
                and not pipeline_marker
                and 'optical' in manifest_analyses
                and 'optical' not in manifest_skipped
            ):
                # A completed manifest proves the analyzer intentionally
                # published an empty snapshot (for example, an all-DAC fabric).
                result['optical'] = []
                optical_meta['record_count'] = 0
                optical_meta['device_records_present'] = False
                optical_meta['empty_snapshot_validated'] = True
            else:
                mark_unavailable(optical_meta, 'Current optical snapshot is empty and unverified')
        else:
            device_optical = []
            prefix = device + ':'
            for port_key, stats in current_stats.items():
                if not isinstance(port_key, str) or not port_key.startswith(prefix):
                    continue
                if not isinstance(stats, dict):
                    continue
                port_name = port_key.split(':', 1)[1]
                if not port_name:
                    continue
                device_optical.append({
                    'port': port_name,
                    'health': stats.get('health_status', 'unknown'),
                    'rx_power_dbm': stats.get('rx_power_dbm'),
                    'tx_power_dbm': stats.get('tx_power_dbm'),
                    'temperature_c': stats.get('temperature_c'),
                    'link_margin_db': stats.get('link_margin_db'),
                    'timestamp': iso_timestamp(
                        timestamp_epoch(stats.get('last_updated'))
                    ),
                })
            result['optical'] = sorted(
                device_optical, key=lambda entry: entry['port']
            )
            optical_meta['record_count'] = len(device_optical)
            optical_meta['device_records_present'] = bool(device_optical)
    result['sources']['optical'] = optical_meta

    # Logs: require an explicit device record.  Missing/partial coverage is not
    # equivalent to a healthy device with zero events.
    log_data, log_error = load_json_source('log_summary.json')
    collection_status = ''
    if log_error:
        log_meta = log_error
    else:
        log_meta = source_metadata(
            os.path.join(monitor_dir, 'log_summary.json'),
            log_data.get('timestamp'),
        )
        coverage = log_data.get('coverage')
        collection_status = str(log_data.get('collection_status', '')).lower()
        partial_devices = set()
        current_devices = None
        if isinstance(coverage, dict):
            if isinstance(coverage.get('partial_devices'), list):
                partial_devices = {
                    name for name in coverage['partial_devices']
                    if isinstance(name, str)
                }
            if isinstance(coverage.get('current_devices'), list):
                current_devices = {
                    name for name in coverage['current_devices']
                    if isinstance(name, str)
                }
        counts_by_device = log_data.get('device_counts')
        counts = (
            counts_by_device.get(device)
            if isinstance(counts_by_device, dict) else None
        )
        if collection_status == 'unavailable':
            mark_unavailable(log_meta, 'Log collection is unavailable')
        elif device in partial_devices or (
            current_devices is not None and device not in current_devices
        ):
            mark_unavailable(log_meta, 'No complete current log collection for device')
        elif not isinstance(counts, dict):
            mark_unavailable(log_meta, 'No current log summary for device')
        elif not all(valid_count(counts.get(level)) for level in (
            'critical', 'warning', 'error', 'info'
        )):
            mark_unavailable(log_meta, 'Current log summary is malformed')
        else:
            result['logs'] = {
                level: int(counts[level])
                for level in ('critical', 'warning', 'error', 'info')
            }
            log_meta['record_count'] = sum(result['logs'].values())
    result['sources']['logs'] = log_meta
    if (
        result['sources'].get('optical', {}).get('empty_snapshot_validated')
        and collection_status == 'unavailable'
    ):
        # A completed optical analyzer with zero rows is only a trustworthy
        # all-DAC/no-optics result when the same pipeline had device telemetry.
        result['optical'] = None
        mark_unavailable(
            result['sources']['optical'],
            'Optical collection has no device telemetry in the current pipeline',
        )
    elif (
        result['sources'].get('optical', {}).get('device_records_present') is False
        and log_meta.get('status') != 'current'
    ):
        # A non-empty fabric-wide optical snapshot does not prove that this
        # particular device was collected. Only current per-device coverage
        # may turn zero matching rows into a trustworthy all-DAC/no-optics []
        # result.
        result['optical'] = None
        mark_unavailable(
            result['sources']['optical'],
            'No complete current device collection validates empty optical data',
        )

    # BGP has the same current-vs-history distinction.  Preserve the compact
    # response rows expected by existing clients while sourcing current stats.
    bgp_data, bgp_error = load_json_source('bgp_history.json')
    if bgp_error:
        bgp_meta = bgp_error
    else:
        current_bgp = bgp_data.get('current_bgp_stats')
        device_bgp = (
            current_bgp.get(device) if isinstance(current_bgp, dict) else None
        )
        data_status = (
            str(device_bgp.get('data_status', '')).strip().lower()
            if isinstance(device_bgp, dict) else ''
        )
        selected_bgp = device_bgp
        if data_status == 'stale' and isinstance(
            device_bgp.get('last_known_stats'), dict
        ):
            selected_bgp = device_bgp['last_known_stats']
        bgp_timestamp = (
            selected_bgp.get('last_update')
            if isinstance(selected_bgp, dict) else bgp_data.get('last_update')
        )
        bgp_meta = source_metadata(
            os.path.join(monitor_dir, 'bgp_history.json'), bgp_timestamp
        )
        coverage = bgp_data.get('collection_coverage')
        unavailable_devices = set()
        if isinstance(coverage, dict) and isinstance(
            coverage.get('unavailable_bgp_devices'), list
        ):
            unavailable_devices = {
                name for name in coverage['unavailable_bgp_devices']
                if isinstance(name, str)
            }
        if not isinstance(current_bgp, dict):
            mark_unavailable(bgp_meta, 'Current BGP snapshot is unavailable')
        elif not isinstance(device_bgp, dict):
            mark_unavailable(bgp_meta, 'No current BGP summary for device')
        elif data_status == 'unknown':
            mark_unavailable(
                bgp_meta,
                'BGP collection is unavailable for device: '
                + str(device_bgp.get('collection_error') or 'unknown collection state'),
            )
        elif data_status not in {'', 'current', 'stale'}:
            mark_unavailable(bgp_meta, 'Current BGP summary has an invalid data status')
        elif data_status in {'', 'current'} and device in unavailable_devices:
            mark_unavailable(bgp_meta, 'BGP collection coverage is unavailable for device')
        elif not isinstance(selected_bgp, dict) or not isinstance(
            selected_bgp.get('neighbors'), list
        ):
            mark_unavailable(bgp_meta, 'Current BGP summary is malformed')
        else:
            rows = []
            for neighbor in selected_bgp['neighbors']:
                if not isinstance(neighbor, dict):
                    continue
                rows.append({
                    'neighbor': (
                        neighbor.get('neighbor')
                        or neighbor.get('neighbor_ip')
                        or neighbor.get('neighbor_name')
                    ),
                    'state': neighbor.get('state', 'unknown'),
                    'vrf': neighbor.get('vrf', 'default'),
                    'uptime': neighbor.get('uptime'),
                    'prefixes_received': neighbor.get('prefixes_received'),
                })
            result['bgp'] = rows
            bgp_meta['record_count'] = len(rows)
            bgp_meta['data_status'] = data_status or 'legacy-current'
            if data_status == 'stale':
                collection_error = str(
                    device_bgp.get('collection_error') or 'collection is stale'
                )
                prior_reason = bgp_meta.get('reason')
                bgp_meta.update({
                    'status': 'stale',
                    'available': True,
                    'current': False,
                    'stale': True,
                    'reason': (
                        f'{prior_reason}; {collection_error}'
                        if prior_reason else collection_error
                    ),
                })
    result['sources']['bgp'] = bgp_meta

    for metadata in result['sources'].values():
        apply_pipeline_marker(metadata, pipeline_marker)

    # Keep the wire contract unambiguous for every client, not just the
    # Device Details UI: unavailable sources never carry apparently usable
    # measurements or counts. Stale sources remain visible and labeled stale.
    for source_name, payload_name in (
        ('optical', 'optical'), ('logs', 'logs'), ('bgp', 'bgp')
    ):
        if result['sources'][source_name].get('status') == 'unavailable':
            result[payload_name] = None
            result['sources'][source_name]['record_count'] = None

    source_epochs = []
    for source_name, metadata in result['sources'].items():
        result['timestamps'][source_name] = metadata.get('timestamp')
        epoch = timestamp_epoch(metadata.get('timestamp'))
        if epoch is not None:
            source_epochs.append(epoch)
    if source_epochs:
        result['last_update'] = iso_timestamp(max(source_epochs))
    statuses = {metadata['status'] for metadata in result['sources'].values()}
    if pipeline_marker:
        result['collection_status'] = 'stale'
        result['collection_reason'] = (
            f"Pipeline {pipeline_marker.get('status', 'stale')}: "
            f"{pipeline_marker.get('reason', 'publication is not current')}"
        )
    elif 'stale' in statuses:
        result['collection_status'] = 'stale'
        result['collection_reason'] = 'One or more device data sources are stale'
    elif 'current' in statuses and 'unavailable' in statuses:
        result['collection_status'] = 'partial'
        result['collection_reason'] = 'One or more device data sources are unavailable'
    elif 'current' in statuses:
        result['collection_status'] = 'current'
    else:
        result['collection_status'] = 'unavailable'

    print(json.dumps(result))

except Exception as exc:
    print(json.dumps({'success': False, 'error': str(exc)}))
PYTHON
        ;;
    download-file)
        # Download a file from a device (for cl-support bundles and PCAP files)
        # Header already printed at script start
        python3 << 'PYDOWNLOAD'
import os
import re
import json
import hashlib
import secrets
import shlex
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import PurePosixPath


def fail(message):
    print(json.dumps({'success': False, 'error': message}))
    raise SystemExit(0)


def safe_device_component(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    if len(component) > 80:
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]
        component = f'{component[:64]}_{digest}'
    return component


raw_query = os.environ.get('QUERY_STRING', '')
if len(raw_query) > 4096:
    fail('Query string is too large')
try:
    query = urllib.parse.parse_qs(
        raw_query,
        keep_blank_values=True,
        encoding='utf-8',
        errors='strict',
        max_num_fields=32,
    )
except (UnicodeError, ValueError):
    fail('Invalid query string')


def single_query_value(name):
    values = query.get(name, [])
    if not values:
        fail(f'Missing {name} parameter')
    if len(values) != 1:
        fail(f'{name.capitalize()} parameter must be specified once')
    if not values[0]:
        fail(f'Missing {name} parameter')
    return values[0]


device = single_query_value('device').strip()
file_path = single_query_value('file')

if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

if (
    len(file_path) > 512
    or '..' in file_path
    or not (
        re.fullmatch(
            r'/var/support/cl_support[A-Za-z0-9_.:-]{0,180}'
            r'\.(?:txz|tar\.xz|tar\.gz)',
            file_path,
        )
        or re.fullmatch(
            r'/tmp/capture_[A-Za-z0-9_.:-]{1,220}\.pcap',
            file_path,
        )
    )
):
    fail(
        'Only cl-support files from /var/support/ or PCAP files from /tmp/ '
        'can be downloaded'
    )

filename = PurePosixPath(file_path).name
if (
    not filename
    or filename in {'.', '..'}
    or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,239}', filename) is None
):
    fail('Invalid download filename')

# Read config from lldpq.conf (same method as run-device-command)
def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))
web_root = os.environ.get('WEB_ROOT', '/var/www/html')

# Get device IP and username
# Priority: devices.yaml (always available) -> Ansible inventory (optional)
device_ip = None
ssh_user = 'cumulus'

lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in inventory or devices.yaml'}))
    exit()

# Create downloads directory
download_dir = os.path.join(web_root, 'downloads')
os.makedirs(download_dir, exist_ok=True)

# Sweep stale local copies before staging a new one (mirrors the 60-min
# remote /tmp sweep in the capture actions): cl-support bundles are tens to
# hundreds of MB and nothing else ever prunes WEB_ROOT/downloads, so repeated
# downloads would grow the web root without bound and keep switch configs/logs
# web-served indefinitely.
try:
    _sweep_cutoff = time.time() - 60 * 60
    with os.scandir(download_dir) as _entries:
        for _entry in _entries:
            if not (_entry.name.startswith('lldpq-') or _entry.name.startswith('.download-')):
                continue
            try:
                if _entry.is_file(follow_symlinks=False) and _entry.stat(follow_symlinks=False).st_mtime < _sweep_cutoff:
                    os.unlink(_entry.path)
            except OSError:
                continue
except OSError:
    pass

storage_extension = next(
    extension for extension in ('.tar.xz', '.tar.gz', '.pcap', '.txz')
    if filename.endswith(extension)
)
storage_name = (
    f'lldpq-{safe_device_component(device)}-'
    f'{secrets.token_hex(12)}{storage_extension}'
)
local_file = os.path.join(download_dir, storage_name)

# Copy file using SSH + cat (uses same sudo -u lldpq_user as run-device-command)
temporary_file = None
try:
    ssh_command = [
        'sudo', '-u', lldpq_user,
        'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=30', '-o', 'BatchMode=yes',
        f'{ssh_user}@{device_ip}',
        f'cat -- {shlex.quote(file_path)}'
    ]

    with tempfile.NamedTemporaryFile(
        mode='wb', dir=download_dir, prefix='.download-', delete=False
    ) as output:
        temporary_file = output.name
        result = subprocess.run(
            ssh_command,
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=120,
        )

    if (
        result.returncode == 0
        and os.path.exists(temporary_file)
        and os.path.getsize(temporary_file) > 0
    ):
        os.chmod(temporary_file, 0o664)
        os.replace(temporary_file, local_file)
        temporary_file = None
        download_url = '/downloads/' + urllib.parse.quote(
            storage_name, safe='._-:'
        )
        print(json.dumps({
            'success': True,
            'download_url': download_url,
            'filename': filename,
        }))
    else:
        stderr = result.stderr.decode('utf-8', errors='replace').strip()
        print(json.dumps({
            'success': False,
            'error': ('SSH cat failed: ' + stderr)[:200],
            'exit_code': result.returncode,
        }))
except subprocess.TimeoutExpired:
    print(json.dumps({'success': False, 'error': 'Download timeout'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
finally:
    if temporary_file and os.path.exists(temporary_file):
        os.unlink(temporary_file)
PYDOWNLOAD
        exit 0
        ;;
    start-clsupport)
        # Start cl-support in background
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_CLSUPPORT'
import json
import subprocess
import re
import os
import fcntl
import hashlib
import stat

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def fail(message):
    print(json.dumps({'success': False, 'error': message}))
    raise SystemExit(0)


def lock_device_key(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
    return f'{component[:48]}_{digest}'


try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except (TypeError, ValueError, json.JSONDecodeError):
    fail('Invalid JSON body')
if not isinstance(data, dict):
    fail('JSON body must be an object')

device = data.get('device', '')
if not isinstance(device, str):
    fail('Device must be text')
device = device.strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))

# Get device IP and username from devices.yaml -> Ansible inventory fallback
device_ip = None
ssh_user = 'cumulus'

lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in devices.yaml or inventory'}))
    exit()

try:
    lock_path = (
        f'/tmp/lldpq-start-clsupport-{lock_device_key(device)}.lock'
    )
    if not hasattr(os, 'O_NOFOLLOW'):
        raise RuntimeError('Secure lock files are not supported on this host')
    lock_flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        lock_flags |= os.O_CLOEXEC
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    lock_metadata = os.fstat(lock_fd)
    if (
        not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_uid != os.geteuid()
    ):
        os.close(lock_fd)
        raise PermissionError('Unsafe cl-support lock file')
    os.fchmod(lock_fd, 0o600)
    with os.fdopen(lock_fd, 'w') as lock_file:
        # Serialize the remote check and launch so two browser sessions cannot
        # both observe "not running" and start expensive bundles concurrently.
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        ssh_base = [
            'sudo', '-u', lldpq_user,
            'ssh', '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
            f'{ssh_user}@{device_ip}',
        ]
        running = subprocess.run(
            ssh_base + ["pgrep -f '[c]l-support'"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if running.returncode == 0:
            print(json.dumps({
                'success': False,
                'error': 'cl-support is already running on this device',
                'already_running': True,
            }))
            raise SystemExit(0)
        if running.returncode != 1:
            error = (running.stderr or running.stdout or
                     f'SSH process check exited with status {running.returncode}').strip()
            print(json.dumps({
                'success': False,
                'error': error[:200],
                'exit_code': running.returncode,
            }))
            raise SystemExit(0)

        remote_cmd = (
            'nohup sudo cl-support -M -T0 '
            '> /tmp/clsupport.log 2>&1 &'
        )
        result = subprocess.run(
            ssh_base + [remote_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            print(json.dumps({
                'success': True,
                'message': 'cl-support started in background'
            }))
        else:
            error = (result.stderr or result.stdout or
                     f'SSH exited with status {result.returncode}').strip()
            print(json.dumps({
                'success': False,
                'error': error[:200],
                'exit_code': result.returncode,
            }))
except subprocess.TimeoutExpired:
    print(json.dumps({'success': False, 'error': 'SSH launch timed out'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))

PYTHON_CLSUPPORT
        exit 0
        ;;
    check-telemetry-capability)
        # Check which devices support OTLP telemetry export
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_CHECK_TELEM'
import json
import subprocess
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

_devices_yaml_errors = []

def get_device_info(device, ansible_dir, lldpq_conf):
    """Get device IP and SSH username from devices.yaml"""
    import yaml
    import re
    
    default_username = 'cumulus'
    lldpq_dir = lldpq_conf.get('LLDPQ_DIR', '')
    
    if lldpq_dir:
        devices_path = f"{lldpq_dir}/devices.yaml"
        if os.path.exists(devices_path):
            try:
                with open(devices_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    defaults = data.get('defaults', {})
                    default_username = defaults.get('username', 'cumulus')
                    
                    devices_dict = data.get('devices', {})
                    for ip, device_info in devices_dict.items():
                        if isinstance(device_info, dict):
                            hostname = device_info.get('hostname', '')
                            username = device_info.get('username', default_username)
                        else:
                            hostname = device_info.split()[0] if isinstance(device_info, str) else str(device_info)
                            username = default_username
                        
                        if hostname == device:
                            return {'ip': str(ip), 'username': username}
            except (OSError, yaml.YAMLError, AttributeError) as _dexc:
                # A corrupt/unreadable devices.yaml must not masquerade as
                # 'device not found'; remember the real cause for the callers
                _devices_yaml_errors.append(str(_dexc))
    
    # Fallback to inventory.ini
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            with open(inv_file, 'r') as f:
                for line in f:
                    if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                        match = re.search(r'ansible_host=(\S+)', line)
                        if match:
                            return {'ip': match.group(1), 'username': default_username}

    # Not found: never fall back to SSHing the raw client-supplied name
    return None

def check_device(device, device_info, lldpq_user):
    """Check if device supports telemetry export"""
    try:
        device_ip = device_info['ip']
        ssh_user = device_info['username']
        ssh_target = f"{ssh_user}@{device_ip}"
        ssh_cmd = [
            'sudo', '-u', lldpq_user,
            'ssh',
            '-T',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=10',
            '-o', 'LogLevel=ERROR',
            ssh_target,
            'nv show system telemetry export 2>&1 | head -5'
        ]
        
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr

        # SSH-level failures (connection refused, auth failure, no route) exit
        # non-zero and must never be classified as 'supported': the capability
        # was not probed at all. The remote nv pipe ends in head, so a
        # reachable device always exits 0 and is judged on its output below.
        if result.returncode != 0:
            return {'device': device, 'supported': False,
                    'error': (result.stderr or result.stdout or
                              f'SSH exited with status {result.returncode}').strip()[:200]}
        # Check if export is supported
        if "'export' is not one of" in output or "Error:" in output:
            return {'device': device, 'supported': False}
        else:
            return {'device': device, 'supported': True}
    
    except subprocess.TimeoutExpired:
        return {'device': device, 'supported': False, 'error': 'timeout'}
    except Exception as e:
        return {'device': device, 'supported': False, 'error': str(e)}

try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    data = {}

devices = data.get('devices', [])

if not devices:
    print(json.dumps({'success': False, 'error': 'Devices required'}))
    sys.exit()

# Same device-name validation the other SSH-reaching actions enforce
_device_name_re = os.environ.get('LLDPQ_DEVICE_NAME_RE') or r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}'
for device in devices:
    if not isinstance(device, str) or not re.fullmatch(_device_name_re, device):
        print(json.dumps({'success': False, 'error': f'Invalid device name: {device}'}))
        sys.exit()

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))
max_workers = int(lldpq_conf.get('TELEMETRY_MAX_PARALLEL', '25') or 25)
max_workers = max(1, min(max_workers, 50))

supported = []
unsupported = []

# Check all devices in parallel
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = {}
    for device in devices:
        device_info = get_device_info(device, ansible_dir, lldpq_conf)
        if device_info is None:
            # Device not found in devices.yaml/inventory - cannot be supported
            unsupported.append(device)
            continue
        future = executor.submit(check_device, device, device_info, lldpq_user)
        futures[future] = device
    
    for future in as_completed(futures):
        result = future.result()
        if result.get('supported'):
            supported.append(result['device'])
        else:
            unsupported.append(result['device'])

_resp = {
    'success': True,
    'supported': supported,
    'unsupported': unsupported,
    'supported_count': len(supported),
    'unsupported_count': len(unsupported)
}
if _devices_yaml_errors:
    _resp['errors'] = sorted(set(_devices_yaml_errors))
    _resp['warning'] = 'devices.yaml could not be parsed: ' + _resp['errors'][0]
print(json.dumps(_resp))

PYTHON_CHECK_TELEM
        exit 0
        ;;
    run-telemetry-commands)
        # Run telemetry commands on ALL devices in parallel
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_TELEMETRY'
import json
import subprocess
import re
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

_devices_yaml_errors = []

def get_device_info(device, ansible_dir, lldpq_conf):
    """Get device IP and SSH username from devices.yaml or inventory.ini"""
    import yaml
    
    default_username = 'cumulus'
    
    # First try devices.yaml (preferred source)
    lldpq_dir = lldpq_conf.get('LLDPQ_DIR', '')
    
    devices_paths = []
    if lldpq_dir:
        devices_paths.append(f"{lldpq_dir}/devices.yaml")
    
    for path in devices_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    # Get default username
                    defaults = data.get('defaults', {})
                    default_username = defaults.get('username', 'cumulus')
                    
                    devices_dict = data.get('devices', {})
                    for ip, device_info in devices_dict.items():
                        if isinstance(device_info, dict):
                            # Extended format: { hostname: ..., username: ..., role: ... }
                            hostname = device_info.get('hostname', '')
                            username = device_info.get('username', default_username)
                        else:
                            # Simple format: "hostname @role"
                            hostname = device_info.split()[0] if isinstance(device_info, str) else str(device_info)
                            username = default_username
                        
                        if hostname == device:
                            return {'ip': str(ip), 'username': username}
            except (OSError, yaml.YAMLError, AttributeError) as _dexc:
                # A corrupt/unreadable devices.yaml must not masquerade as
                # 'device not found'; remember the real cause for the callers
                _devices_yaml_errors.append(str(_dexc))
            break
    
    # Fallback to inventory.ini
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            with open(inv_file, 'r') as f:
                for line in f:
                    if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                        match = re.search(r'ansible_host=(\S+)', line)
                        if match:
                            return {'ip': match.group(1), 'username': default_username}

    # Not found: never fall back to SSHing the raw client-supplied name
    return None

def run_on_device(device, device_info, combined_cmd, lldpq_user):
    """Run commands on a single device"""
    try:
        device_ip = device_info['ip']
        ssh_user = device_info['username']
        ssh_target = f"{ssh_user}@{device_ip}"
        ssh_cmd = [
            'sudo', '-u', lldpq_user, 
            'ssh',
            '-T',  # Disable pseudo-tty (avoids stty errors from .bashrc)
            '-o', 'StrictHostKeyChecking=no', 
            '-o', 'ConnectTimeout=30',
            '-o', 'LogLevel=ERROR',
            ssh_target, 
            combined_cmd
        ]
        
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            return {'device': device, 'success': True, 'output': result.stdout.strip()}
        else:
            return {'device': device, 'success': False, 'error': result.stderr.strip() or 'Command failed'}
    
    except subprocess.TimeoutExpired:
        return {'device': device, 'success': False, 'error': 'Timeout (120s)'}
    except Exception as e:
        return {'device': device, 'success': False, 'error': str(e)}

try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    data = {}

devices = data.get('devices', [])
commands = data.get('commands', [])

# Support single device for backward compatibility
if not devices and data.get('device'):
    devices = [data.get('device')]

if not devices:
    print(json.dumps({'success': False, 'error': 'Devices required'}))
    sys.exit()

# Same device-name validation the other SSH-reaching actions enforce
_device_name_re = os.environ.get('LLDPQ_DEVICE_NAME_RE') or r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}'
for device in devices:
    if not isinstance(device, str) or not re.fullmatch(_device_name_re, device):
        print(json.dumps({'success': False, 'error': f'Invalid device name: {device}'}))
        sys.exit()

if not commands:
    print(json.dumps({'success': False, 'error': 'Commands required'}))
    sys.exit()

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))
max_workers = int(lldpq_conf.get('TELEMETRY_MAX_PARALLEL', '25') or 25)
max_workers = max(1, min(max_workers, 50))

# Validate commands - only allow telemetry-related nv commands
allowed_prefixes = [
    'nv set system telemetry',
    'nv unset system telemetry',
    'nv config apply'
]
for cmd in commands:
    if any(ord(ch) < 32 for ch in cmd) or re.search(r'[;&|`\$<>]', cmd):
        print(json.dumps({'success': False, 'error': f'Unsafe telemetry command: {cmd}'}))
        sys.exit()
    if not any(cmd == prefix or cmd.startswith(prefix + ' ') for prefix in allowed_prefixes):
        print(json.dumps({'success': False, 'error': f'Only telemetry commands allowed: {cmd}'}))
        sys.exit()

# Join commands with && to run sequentially on each device
combined_cmd = ' && '.join(commands)

# Run on all devices in bounded parallelism
results = []
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = {}
    for device in devices:
        device_info = get_device_info(device, ansible_dir, lldpq_conf)
        if device_info is None:
            if _devices_yaml_errors:
                result = {'device': device, 'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_errors[0]}'}
            else:
                result = {'device': device, 'success': False, 'error': 'Device not found in devices.yaml/inventory'}
            results.append(result)
            sys.stdout.write(json.dumps(result) + '\n')
            sys.stdout.flush()
            continue
        future = executor.submit(run_on_device, device, device_info, combined_cmd, lldpq_user)
        futures[future] = device
    
    for future in as_completed(futures):
        result = future.result()
        results.append(result)
        # Stream result immediately
        sys.stdout.write(json.dumps(result) + '\n')
        sys.stdout.flush()

# Final summary
success_count = sum(1 for r in results if r['success'])
print(json.dumps({
    'complete': True,
    'total': len(devices),
    'success': success_count,
    'failed': len(devices) - success_count
}))

PYTHON_TELEMETRY
        exit 0
        ;;
    prometheus-query)
        # Query Prometheus instant query
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_PROM'
import json
import urllib.request
import urllib.parse
import os

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    data = {}

query = data.get('query', '')
if not query:
    print(json.dumps({'success': False, 'error': 'Query required'}))
    exit()

lldpq_conf = read_lldpq_conf()
prometheus_url = lldpq_conf.get('PROMETHEUS_URL', 'http://localhost:9090')

try:
    url = f"{prometheus_url}/api/v1/query?query={urllib.parse.quote(query)}"
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode())
        if result.get('status') == 'success':
            print(json.dumps({'success': True, 'data': result.get('data', {})}))
        else:
            print(json.dumps({'success': False, 'error': result.get('error', 'Query failed')}))
except urllib.error.URLError as e:
    print(json.dumps({'success': False, 'error': f'Connection error: {str(e)}'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))

PYTHON_PROM
        exit 0
        ;;
    prometheus-query-range)
        # Query Prometheus range query for time series
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_PROM_RANGE'
import json
import urllib.request
import urllib.parse
import os
import time

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def parse_duration(duration_str):
    """Convert duration string like '15m', '1h', '24h' to seconds"""
    units = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    if not duration_str:
        return 900  # Default 15 minutes
    unit = duration_str[-1]
    if unit in units:
        try:
            return int(duration_str[:-1]) * units[unit]
        except:
            return 900
    return 900

try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    data = {}

query = data.get('query', '')
time_range = data.get('range', '15m')
step = data.get('step', '30s')

if not query:
    print(json.dumps({'success': False, 'error': 'Query required'}))
    exit()

lldpq_conf = read_lldpq_conf()
prometheus_url = lldpq_conf.get('PROMETHEUS_URL', 'http://localhost:9090')

try:
    duration_seconds = parse_duration(time_range)
    end_time = time.time()
    start_time = end_time - duration_seconds
    
    params = {
        'query': query,
        'start': str(start_time),
        'end': str(end_time),
        'step': step
    }
    
    url = f"{prometheus_url}/api/v1/query_range?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode())
        if result.get('status') == 'success':
            print(json.dumps({'success': True, 'data': result.get('data', {})}))
        else:
            print(json.dumps({'success': False, 'error': result.get('error', 'Query failed')}))
except urllib.error.URLError as e:
    print(json.dumps({'success': False, 'error': f'Connection error: {str(e)}'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))

PYTHON_PROM_RANGE
        exit 0
        ;;
    get-telemetry-config)
        # Return telemetry configuration and enabled status
        python3 << 'PYTHON_TELEM_CONFIG'
import json
import os
import subprocess
import fcntl
import ipaddress

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def check_stack_running(prometheus_url):
    """Check if telemetry Docker stack is running by querying Prometheus health endpoint"""
    try:
        import urllib.request
        req = urllib.request.Request(f"{prometheus_url.rstrip('/')}/-/healthy", method='GET')
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status == 200
    except:
        return False

def get_server_ips():
    """Get all non-loopback IPv4 addresses of this server"""
    import socket
    ips = []
    try:
        # Get all network interfaces
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.'):
                ips.append(ip)
        # Also try getting IPs via ip command for more complete list
        result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '127.' not in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i+1 < len(parts):
                        ip = parts[i+1].split('/')[0]
                        if ip not in ips:
                            ips.append(ip)
    except:
        pass
    return list(set(ips))

def get_device_mgmt_ips(conf):
    """Get management IPs from devices.yaml"""
    import yaml
    mgmt_ips = []
    
    # Get LLDPQ_DIR from config
    lldpq_dir = conf.get('LLDPQ_DIR', '')
    
    devices_paths = []
    if lldpq_dir:
        devices_paths.append(f"{lldpq_dir}/devices.yaml")
    
    for path in devices_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    # Format: devices: { "192.168.100.11": "hostname", ... }
                    devices = data.get('devices', {})
                    for ip_key in devices.keys():
                        # Keys are IP addresses
                        if isinstance(ip_key, str) and '.' in ip_key:
                            mgmt_ips.append(ip_key)
            except:
                pass
            break
    return mgmt_ips

def find_matching_server_ip(server_ips, device_ips):
    """Find server IP that is in same subnet as device mgmt IPs"""
    for server_ip in server_ips:
        server_parts = server_ip.rsplit('.', 1)
        if len(server_parts) != 2:
            continue
        server_subnet = server_parts[0]
        for device_ip in device_ips:
            if device_ip.startswith(server_subnet + '.'):
                return server_ip
    return server_ips[0] if server_ips else ''

lldpq_conf = read_lldpq_conf()
prometheus_url = lldpq_conf.get('PROMETHEUS_URL', 'http://localhost:9090')
telemetry_enabled = lldpq_conf.get('TELEMETRY_ENABLED', 'false').lower() == 'true'
collector_ip = lldpq_conf.get('TELEMETRY_COLLECTOR_IP', '')
collector_port = lldpq_conf.get('TELEMETRY_COLLECTOR_PORT', '4317')
collector_vrf = lldpq_conf.get('TELEMETRY_COLLECTOR_VRF', 'mgmt')
stack_running = check_stack_running(prometheus_url)

# Get server IPs and find best match
server_ips = get_server_ips()
device_ips = get_device_mgmt_ips(lldpq_conf)
suggested_ip = find_matching_server_ip(server_ips, device_ips) if not collector_ip else collector_ip

print(json.dumps({
    'success': True,
    'prometheus_url': prometheus_url,
    'telemetry_enabled': telemetry_enabled,
    'collector_ip': collector_ip,
    'collector_port': collector_port,
    'collector_vrf': collector_vrf,
    'stack_running': stack_running,
    'server_ips': server_ips,
    'suggested_ip': suggested_ip
}))

PYTHON_TELEM_CONFIG
        exit 0
        ;;
    get-active-telemetry-devices)
        # Get list of devices actively sending telemetry to Prometheus
        python3 << 'PYTHON_ACTIVE_DEVICES'
import json
import os
import urllib.request
import urllib.parse

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

try:
    # Query Prometheus for active devices (honor PROMETHEUS_URL like the
    # prometheus-query/-range actions instead of hardcoding localhost)
    lldpq_conf = read_lldpq_conf()
    prometheus_url = lldpq_conf.get('PROMETHEUS_URL', 'http://localhost:9090')
    query = 'count by (net_host_name) (cumulus_nvswitch_interface_if_out_octets)'
    url = f"{prometheus_url.rstrip('/')}/api/v1/query?query={urllib.parse.quote(query)}"
    
    req = urllib.request.Request(url, method='GET')
    req.add_header('Accept', 'application/json')
    
    with urllib.request.urlopen(req, timeout=5) as response:
        data = json.loads(response.read().decode())
        
        if data.get('status') == 'success' and data.get('data', {}).get('result'):
            devices = sorted([
                r['metric']['net_host_name'] 
                for r in data['data']['result'] 
                if r.get('metric', {}).get('net_host_name')
            ])
            print(json.dumps({'success': True, 'devices': devices}))
        else:
            print(json.dumps({'success': True, 'devices': []}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e), 'devices': []}))

PYTHON_ACTIVE_DEVICES
        exit 0
        ;;
    save-telemetry-config)
        # Save telemetry collector config (called when enabling telemetry)
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_SAVE_TELEM'
import importlib.util
import ipaddress
import json
import os


def load_config_writer():
    helper = os.environ.get(
        'LLDPQ_CONFIG_WRITE_HELPER', '/var/www/html/lldpq_config_write.py'
    )
    if not os.path.isfile(helper):
        raise RuntimeError('configuration write helper is not installed')
    spec = importlib.util.spec_from_file_location('lldpq_config_write', helper)
    if spec is None or spec.loader is None:
        raise RuntimeError('configuration write helper cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.update_lldpq_config

try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    data = {}

collector_ip = data.get('collector_ip', '')
collector_port = data.get('collector_port', '4317')
collector_vrf = data.get('collector_vrf', 'mgmt')

# Scalar fields must be text before calling str methods on them (a JSON
# number/list/null would otherwise raise and return an empty body)
if not isinstance(collector_ip, str) or not collector_ip:
    print(json.dumps({'success': False, 'error': 'Collector IP required'}))
    exit()
try:
    ipaddress.ip_address(collector_ip)
except ValueError:
    print(json.dumps({'success': False, 'error': 'Invalid collector IP'}))
    exit()
if not isinstance(collector_port, (str, int)) or isinstance(collector_port, bool) \
        or not str(collector_port).isdigit() or not (1 <= int(collector_port) <= 65535):
    print(json.dumps({'success': False, 'error': 'Invalid collector port'}))
    exit()
if not isinstance(collector_vrf, str) or not collector_vrf.replace('-', '').replace('_', '').isalnum():
    print(json.dumps({'success': False, 'error': 'Invalid collector VRF'}))
    exit()

# Merge into the latest generation only after taking the shared config lock.
config_updates = {
    'TELEMETRY_COLLECTOR_IP': collector_ip,
    'TELEMETRY_COLLECTOR_PORT': collector_port,
    'TELEMETRY_COLLECTOR_VRF': collector_vrf,
}

try:
    load_config_writer()(config_updates, quote_values=True)
    print(json.dumps({'success': True}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))

PYTHON_SAVE_TELEM
        exit 0
        ;;
    start-telemetry-stack)
        # Start Docker telemetry stack (docker-compose up -d)
        python3 << 'PYTHON_START_STACK'
import json
import os
import subprocess

# Read LLDPQ_DIR from config
lldpq_dir = None
try:
    with open('/etc/lldpq.conf', 'r') as f:
        for line in f:
            if line.startswith('LLDPQ_DIR='):
                lldpq_dir = line.strip().split('=', 1)[1].strip('"\'')
                break
except:
    pass

if not lldpq_dir:
    print(json.dumps({'success': False, 'error': 'LLDPQ_DIR not configured in /etc/lldpq.conf', 'installed': False}))
    exit()

telemetry_dir = f"{lldpq_dir}/telemetry"

if not os.path.exists(f"{telemetry_dir}/docker-compose.yaml"):
    print(json.dumps({'success': False, 'error': 'Telemetry stack not installed', 'installed': False}))
    exit()

# No 'already running' pre-check: docker-compose v1 'ps -q' also lists
# exited containers (stop-telemetry-stack uses 'stop'), so a stopped stack
# looked 'already running' and could never be restarted from the UI.
# 'up -d' is idempotent and restarts stopped containers.

# Start the stack - try docker compose first, then docker-compose
success = False
last_error = ''

for cmd in [['docker', 'compose', 'up', '-d'], ['docker-compose', 'up', '-d']]:
    try:
        result = subprocess.run(
            cmd,
            cwd=telemetry_dir,
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0:
            print(json.dumps({'success': True, 'message': 'Stack started'}))
            success = True
            break
        else:
            last_error = result.stderr
    except FileNotFoundError:
        continue
    except subprocess.TimeoutExpired:
        print(json.dumps({'success': False, 'error': 'Timeout starting stack'}))
        exit()
    except Exception as e:
        last_error = str(e)

if not success:
    print(json.dumps({'success': False, 'error': last_error or 'Could not start stack'}))

PYTHON_START_STACK
        exit 0
        ;;
    stop-telemetry-stack)
        # Stop Docker telemetry stack (docker-compose stop)
        python3 << 'PYTHON_STOP_STACK'
import json
import os
import subprocess

# Read LLDPQ_DIR from config
lldpq_dir = None
try:
    with open('/etc/lldpq.conf', 'r') as f:
        for line in f:
            if line.startswith('LLDPQ_DIR='):
                lldpq_dir = line.strip().split('=', 1)[1].strip('"\'')
                break
except:
    pass

if not lldpq_dir:
    print(json.dumps({'success': False, 'error': 'LLDPQ_DIR not configured'}))
    exit()

telemetry_dir = f"{lldpq_dir}/telemetry"

if not os.path.exists(f"{telemetry_dir}/docker-compose.yaml"):
    print(json.dumps({'success': False, 'error': 'Telemetry stack not found'}))
    exit()

# Try docker compose (newer syntax) first, then docker-compose
success = False
last_error = ''

for cmd in [['docker', 'compose', 'stop'], ['docker-compose', 'stop']]:
    try:
        result = subprocess.run(
            cmd,
            cwd=telemetry_dir,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            print(json.dumps({'success': True, 'message': 'Stack stopped'}))
            success = True
            break
        else:
            last_error = result.stderr
    except FileNotFoundError:
        continue
    except subprocess.TimeoutExpired:
        print(json.dumps({'success': False, 'error': 'Timeout stopping stack'}))
        exit()
    except Exception as e:
        last_error = str(e)

if not success:
    print(json.dumps({'success': False, 'error': last_error or 'Could not stop stack'}))

PYTHON_STOP_STACK
        exit 0
        ;;
    remove-telemetry-stack)
        # Remove Docker telemetry stack (down -v: containers + volumes) + mark disabled
        python3 << 'PYTHON_REMOVE_STACK'
import importlib.util
import json
import os
import subprocess


def load_config_helper():
    helper = os.environ.get(
        'LLDPQ_CONFIG_WRITE_HELPER', '/var/www/html/lldpq_config_write.py'
    )
    if not os.path.isfile(helper):
        raise RuntimeError('configuration write helper is not installed')
    spec = importlib.util.spec_from_file_location('lldpq_config_write', helper)
    if spec is None or spec.loader is None:
        raise RuntimeError('configuration write helper cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_lldpq_config, module.update_lldpq_config

conf_lines = []
lldpq_dir = None
try:
    read_config, update_config = load_config_helper()
    conf_lines = read_config()['content'].splitlines(keepends=True)
    for line in conf_lines:
        if line.startswith('LLDPQ_DIR='):
            lldpq_dir = line.strip().split('=', 1)[1].strip('"\'')
            break
except Exception as exc:
    print(json.dumps({
        'success': False,
        'error': f'Cannot safely read LLDPq configuration: {exc}',
    }))
    exit()

if not lldpq_dir:
    print(json.dumps({'success': False, 'error': 'LLDPQ_DIR not configured'}))
    exit()

telemetry_dir = f"{lldpq_dir}/telemetry"
removed = False
last_error = ''

if os.path.exists(f"{telemetry_dir}/docker-compose.yaml"):
    for cmd in [['docker', 'compose', 'down', '-v'], ['docker-compose', 'down', '-v']]:
        try:
            result = subprocess.run(cmd, cwd=telemetry_dir, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                removed = True
                break
            last_error = result.stderr
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print(json.dumps({'success': False, 'error': 'Timeout removing stack'}))
            exit()
        except Exception as e:
            last_error = str(e)
else:
    last_error = 'Telemetry stack files not found'

# Mark telemetry disabled with the same lock/atomic writer as every other web
# config update.  A legacy direct-file mount is rejected without touching it.
config_warning = ''
try:
    update_config({'TELEMETRY_ENABLED': 'false'}, quote_values=True)
except Exception as exc:
    config_warning = f'Telemetry stack state changed, but config was not changed: {exc}'

if removed:
    response = {
        'success': True,
        'message': 'Collector stack removed (containers + stored metrics)',
        'config_saved': not bool(config_warning),
    }
    if config_warning:
        response['warning'] = config_warning
    print(json.dumps(response))
else:
    response = {'success': False, 'error': last_error or 'Could not remove stack'}
    if config_warning:
        response['warning'] = config_warning
    print(json.dumps(response))
PYTHON_REMOVE_STACK
        exit 0
        ;;
    get-telemetry-disable-commands)
        # Generate specific unset commands based on saved config
        python3 << 'PYTHON_DISABLE_CMDS'
import json
import os

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

lldpq_conf = read_lldpq_conf()
collector_ip = lldpq_conf.get('TELEMETRY_COLLECTOR_IP', '')
collector_port = lldpq_conf.get('TELEMETRY_COLLECTOR_PORT', '4317')

if not collector_ip:
    # No saved config, use generic unset (with warning)
    print(json.dumps({
        'success': True,
        'warning': 'No saved collector IP. This will remove ALL telemetry config.',
        'commands': [
            'nv unset system telemetry',
            'nv config apply -y'
        ]
    }))
    exit()

# Specific unset commands - only remove what we configured
commands = [
    'nv unset system telemetry ai-ethernet-stats',
    'nv unset system telemetry interface-stats', 
    f'nv unset system telemetry export otlp grpc destination {collector_ip}',
    'nv unset system telemetry export otlp grpc insecure',
    'nv unset system telemetry export otlp state',
    'nv unset system telemetry export vrf',
    'nv config apply -y'
]

print(json.dumps({
    'success': True,
    'collector_ip': collector_ip,
    'commands': commands
}))

PYTHON_DISABLE_CMDS
        exit 0
        ;;
    start-live-capture)
        # Start live tcpdump capture in background, return output file path
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_LIVE'
import json
import subprocess
import re
import os
import time
import hashlib
import secrets
import shlex

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def fail(message, **extra):
    response = {'success': False, 'error': message}
    response.update(extra)
    print(json.dumps(response))
    raise SystemExit(0)


def parse_bounded_integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        fail(f'{field} must be an integer')
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        if (
            len(value) > len(str(maximum))
            or re.fullmatch(r'(?:0|[1-9][0-9]*)', value) is None
        ):
            fail(f'{field} must be an integer')
        parsed = int(value)
    else:
        fail(f'{field} must be an integer')
    if not minimum <= parsed <= maximum:
        fail(f'{field} must be between {minimum} and {maximum}')
    return parsed


def safe_device_component(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    if len(component) > 80:
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]
        component = f'{component[:64]}_{digest}'
    return component


try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except (TypeError, ValueError, json.JSONDecodeError):
    fail('Invalid JSON body')
if not isinstance(data, dict):
    fail('JSON body must be an object')

device = data.get('device', '')
iface = data.get('interface', 'any')
filter_expr = data.get('filter', '')

if not isinstance(device, str):
    fail('Device must be text')
device = device.strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

if not isinstance(iface, str) or not re.fullmatch(
    r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}', iface
):
    fail('Invalid interface name')

duration = parse_bounded_integer(data.get('duration', 30), 'Duration', 1, 300)
count = parse_bounded_integer(data.get('count', 1000), 'Count', 0, 999999)

if not isinstance(filter_expr, str):
    fail('Filter must be text')
if any(ord(char) < 32 or ord(char) == 127 for char in filter_expr):
    fail('Invalid filter expression')
filter_expr = filter_expr.strip()
filter_tokens = []
if filter_expr:
    if (
        len(filter_expr) > 256
        or not re.fullmatch(r'[A-Za-z0-9_.:/()\[\] -]+', filter_expr)
    ):
        fail('Invalid filter expression')
    filter_tokens = re.findall(r'[()]|[^() ]+', filter_expr)
    if len(filter_tokens) > 64:
        fail('Filter expression is too complex')
    depth = 0
    for token in filter_tokens:
        if token == '(':
            depth += 1
        elif token == ')':
            depth -= 1
            if depth < 0:
                fail('Invalid filter expression')
        elif token.startswith('-') or not re.fullmatch(
            r'[A-Za-z0-9_.:/\[\]-]+', token
        ):
            fail('Invalid filter expression')
    if depth != 0:
        fail('Invalid filter expression')

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))

# Get device IP and username from devices.yaml -> Ansible inventory fallback
device_ip = None
ssh_user = 'cumulus'

lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in devices.yaml or inventory'}))
    exit()

# Generate a collision-resistant output file with a shell-safe device component.
timestamp = time.strftime('%Y%m%d-%H%M%S')
safe_device = safe_device_component(device)
output_file = f'/tmp/live_{safe_device}_{timestamp}_{secrets.token_hex(6)}.txt'

# Build tcpdump command
cmd_parts = ['sudo', 'timeout', str(duration), 'tcpdump', '-l', '-i', iface, '-nnnn', '-vvv']
if count:
    cmd_parts.extend(['-c', str(count)])
cmd_parts.extend(filter_tokens)

# Quote every field before it reaches the remote shell. The outer shell remains
# necessary for backgrounding and redirection, but request data is argv data.
tcpdump_cmd = shlex.join(cmd_parts)
capture_worker = shlex.join(['setsid', 'sh', '-c', tcpdump_cmd])
remote_capture = (
    'child_pid=; '
    'terminate_child() { '
    'if [ -n "$child_pid" ]; then '
    'kill -TERM -- "-${child_pid}" 2>/dev/null; '
    'fi; exit 143; }; '
    'trap terminate_child TERM INT; '
    f'{capture_worker} > {shlex.quote(output_file)} 2>&1 & '
    'child_pid=$!; wait "$child_pid"; status=$?; '
    'trap - TERM INT; exit "$status"'
)
# Sweep leftover live/tail/pcap temp files older than 60 min before launching.
# A closed browser tab otherwise leaks these on the switch tmpfs (RAM) forever.
sweep_cmd = (
    "sudo find /tmp -maxdepth 1 \\( -name 'live_*.txt' -o "
    "-name 'tail_*.txt' -o -name 'capture_*.pcap' -o -name 'capture_*.pcap.err' \\) "
    "-mmin +60 -delete >/dev/null 2>&1; "
)
remote_cmd = (
    sweep_cmd +
    f'nohup sh -c {shlex.quote(remote_capture)} '
    f'{shlex.quote(output_file)} > /dev/null 2>&1 & echo $!'
)

ssh_command = [
    'sudo', '-u', lldpq_user,
    'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
    f'{ssh_user}@{device_ip}',
    remote_cmd
]

try:
    result = subprocess.run(
        ssh_command, capture_output=True, text=True, timeout=15
    )
except subprocess.TimeoutExpired:
    fail('SSH launch timed out')
except Exception as exc:
    fail(str(exc))

if result.returncode != 0:
    error = (result.stderr or result.stdout or
             f'SSH exited with status {result.returncode}').strip()
    fail(error[:200], exit_code=result.returncode)

pid = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ''
if re.fullmatch(r'[1-9][0-9]{0,19}', pid) is None:
    fail('Remote launch did not return a valid PID')
print(json.dumps({
    'success': True,
    'output_file': output_file,
    'pid': pid,
    'device': device,
    'duration': duration
}))

PYTHON_LIVE
        exit 0
        ;;
    start-log-tail)
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_TAIL'
import json
import subprocess
import re
import os
import time
import hashlib
import secrets
import shlex

def read_lldpq_conf():
    conf = {}
    for conf_path in ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def fail(message, **extra):
    response = {'success': False, 'error': message}
    response.update(extra)
    print(json.dumps(response))
    raise SystemExit(0)


def parse_bounded_integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        fail(f'{field} must be an integer')
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        if (
            len(value) > len(str(maximum))
            or re.fullmatch(r'(?:0|[1-9][0-9]*)', value) is None
        ):
            fail(f'{field} must be an integer')
        parsed = int(value)
    else:
        fail(f'{field} must be an integer')
    if not minimum <= parsed <= maximum:
        fail(f'{field} must be between {minimum} and {maximum}')
    return parsed


def safe_device_component(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    if len(component) > 80:
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]
        component = f'{component[:64]}_{digest}'
    return component


try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except (TypeError, ValueError, json.JSONDecodeError):
    fail('Invalid JSON body')
if not isinstance(data, dict):
    fail('JSON body must be an object')

device = data.get('device', '')
severity = data.get('severity', 'all')
keyword = data.get('keyword', '')

if not isinstance(device, str):
    fail('Device must be text')
device = device.strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

if not isinstance(severity, str) or severity not in {
    'all', 'critical', 'error', 'warning', 'info'
}:
    fail('Invalid severity')

if not isinstance(keyword, str):
    fail('Keyword must be text')
if any(ord(char) < 32 or ord(char) == 127 for char in keyword):
    fail('Invalid keyword')
keyword = keyword.strip()
if keyword and (
    len(keyword) > 128
    or re.fullmatch(r'[A-Za-z0-9 _.:/@%+,\-\[\]()]+', keyword) is None
):
    fail('Invalid keyword')

duration = parse_bounded_integer(data.get('duration', 60), 'Duration', 1, 300)

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))
lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))

device_ip = None
ssh_user = 'cumulus'

import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found'}))
    exit()

timestamp = time.strftime('%Y%m%d-%H%M%S')
safe_device = safe_device_component(device)
output_file = f'/tmp/tail_{safe_device}_{timestamp}_{secrets.token_hex(6)}.txt'

priority_map = {'critical': '0..2', 'error': '0..3', 'warning': '0..4', 'info': '0..6'}
journal_parts = [
    'sudo', 'timeout', str(duration), 'stdbuf', '-oL',
    'journalctl', '-f', '--no-pager'
]
if severity != 'all':
    journal_parts.extend(['-p', priority_map[severity]])
journal_cmd = shlex.join(journal_parts)
if keyword:
    journal_cmd += ' | ' + shlex.join([
        'stdbuf', '-oL', 'grep', '--line-buffered', '-F', '-i', '--', keyword
    ])

tail_worker = shlex.join(['setsid', 'sh', '-c', journal_cmd])
remote_tail = (
    'child_pid=; '
    'terminate_child() { '
    'if [ -n "$child_pid" ]; then '
    'kill -TERM -- "-${child_pid}" 2>/dev/null; '
    'fi; exit 143; }; '
    'trap terminate_child TERM INT; '
    f'{tail_worker} > {shlex.quote(output_file)} 2>&1 & '
    'child_pid=$!; wait "$child_pid"; status=$?; '
    'trap - TERM INT; exit "$status"'
)
# Sweep leftover live/tail/pcap temp files older than 60 min before launching.
# A closed browser tab otherwise leaks these on the switch tmpfs (RAM) forever.
sweep_cmd = (
    "sudo find /tmp -maxdepth 1 \\( -name 'live_*.txt' -o "
    "-name 'tail_*.txt' -o -name 'capture_*.pcap' -o -name 'capture_*.pcap.err' \\) "
    "-mmin +60 -delete >/dev/null 2>&1; "
)
remote_cmd = (
    sweep_cmd +
    f'nohup sh -c {shlex.quote(remote_tail)} '
    f'{shlex.quote(output_file)} > /dev/null 2>&1 & echo $!'
)

ssh_command = [
    'sudo', '-u', lldpq_user,
    'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
    f'{ssh_user}@{device_ip}',
    remote_cmd
]

try:
    result = subprocess.run(
        ssh_command, capture_output=True, text=True, timeout=15
    )
except subprocess.TimeoutExpired:
    fail('SSH launch timed out')
except Exception as exc:
    fail(str(exc))

if result.returncode != 0:
    error = (result.stderr or result.stdout or
             f'SSH exited with status {result.returncode}').strip()
    fail(error[:200], exit_code=result.returncode)

pid = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ''
if re.fullmatch(r'[1-9][0-9]{0,19}', pid) is None:
    fail('Remote launch did not return a valid PID')
print(json.dumps({
    'success': True,
    'output_file': output_file,
    'pid': pid,
    'device': device,
    'duration': duration
}))

PYTHON_TAIL
        exit 0
        ;;
    start-pcap)
        # Start a background tcpdump PCAP capture and return immediately with the
        # pcap path + poll token. This mirrors start-live-capture so a capture of
        # any duration survives the 60s fastcgi_read_timeout (the synchronous
        # run-device-command path orphaned tcpdump for Duration >= 1 min).
        read_post_body
        export POST_DATA

        python3 << 'PYTHON_PCAP'
import json
import subprocess
import re
import os
import time
import hashlib
import secrets
import shlex

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def fail(message, **extra):
    response = {'success': False, 'error': message}
    response.update(extra)
    print(json.dumps(response))
    raise SystemExit(0)


def parse_bounded_integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        fail(f'{field} must be an integer')
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        if (
            len(value) > len(str(maximum))
            or re.fullmatch(r'(?:0|[1-9][0-9]*)', value) is None
        ):
            fail(f'{field} must be an integer')
        parsed = int(value)
    else:
        fail(f'{field} must be an integer')
    if not minimum <= parsed <= maximum:
        fail(f'{field} must be between {minimum} and {maximum}')
    return parsed


try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except (TypeError, ValueError, json.JSONDecodeError):
    fail('Invalid JSON body')
if not isinstance(data, dict):
    fail('JSON body must be an object')

device = data.get('device', '')
iface = data.get('interface', 'any')
filter_expr = data.get('filter', '')

if not isinstance(device, str):
    fail('Device must be text')
device = device.strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

# Interface charset stays strict so the pcap path stays cleanup-whitelist safe.
if not isinstance(iface, str) or not re.fullmatch(
    r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}', iface
):
    fail('Invalid interface name')

duration = parse_bounded_integer(data.get('duration', 30), 'Duration', 1, 300)
count = parse_bounded_integer(data.get('count', 0), 'Count', 0, 999999)

if not isinstance(filter_expr, str):
    fail('Filter must be text')
if any(ord(char) < 32 or ord(char) == 127 for char in filter_expr):
    fail('Invalid filter expression')
filter_expr = filter_expr.strip()
filter_tokens = []
if filter_expr:
    if (
        len(filter_expr) > 256
        or not re.fullmatch(r'[A-Za-z0-9_.:/()\[\] -]+', filter_expr)
    ):
        fail('Invalid filter expression')
    filter_tokens = re.findall(r'[()]|[^() ]+', filter_expr)
    if len(filter_tokens) > 64:
        fail('Filter expression is too complex')
    depth = 0
    for token in filter_tokens:
        if token == '(':
            depth += 1
        elif token == ')':
            depth -= 1
            if depth < 0:
                fail('Invalid filter expression')
        elif token.startswith('-') or not re.fullmatch(
            r'[A-Za-z0-9_.:/\[\]-]+', token
        ):
            fail('Invalid filter expression')
    if depth != 0:
        fail('Invalid filter expression')

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))

device_ip = None
ssh_user = 'cumulus'

lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in devices.yaml or inventory'}))
    exit()

# The pcap name uses the full sanitized hostname so the existing device-bound
# Stop (pkill/rm) and download-file whitelist recognize it unchanged.
timestamp = time.strftime('%Y%m%d-%H%M%S')
capture_device = re.sub(r'[^A-Za-z0-9-]', '_', device)
pcap_file = f'/tmp/capture_{capture_device}_{timestamp}_{secrets.token_hex(6)}.pcap'

cmd_parts = ['sudo', 'timeout', str(duration), 'tcpdump', '-U', '-i', iface,
             '-nnnn', '-w', pcap_file]
if count:
    cmd_parts.extend(['-c', str(count)])
cmd_parts.extend(filter_tokens)

tcpdump_cmd = shlex.join(cmd_parts)
capture_worker = shlex.join(['setsid', 'sh', '-c', tcpdump_cmd])
# tcpdump writes the pcap through -w; keep its own stdout/stderr off that file.
remote_capture = (
    'child_pid=; '
    'terminate_child() { '
    'if [ -n "$child_pid" ]; then '
    'kill -TERM -- "-${child_pid}" 2>/dev/null; '
    'fi; exit 143; }; '
    'trap terminate_child TERM INT; '
    # Keep tcpdump's stderr so pcap-status can surface a start failure
    # (bad interface/filter) instead of reporting an empty "success".
    f'{capture_worker} > /dev/null 2> {shlex.quote(pcap_file + ".err")} & '
    'child_pid=$!; wait "$child_pid"; status=$?; '
    'trap - TERM INT; exit "$status"'
)
# Sweep leftover live/tail/pcap temp files older than 60 min before launching.
sweep_cmd = (
    "sudo find /tmp -maxdepth 1 \\( -name 'live_*.txt' -o "
    "-name 'tail_*.txt' -o -name 'capture_*.pcap' -o -name 'capture_*.pcap.err' \\) "
    "-mmin +60 -delete >/dev/null 2>&1; "
)
remote_cmd = (
    sweep_cmd +
    f'nohup sh -c {shlex.quote(remote_capture)} '
    f'{shlex.quote(pcap_file)} > /dev/null 2>&1 & echo $!'
)

ssh_command = [
    'sudo', '-u', lldpq_user,
    'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
    f'{ssh_user}@{device_ip}',
    remote_cmd
]

try:
    result = subprocess.run(
        ssh_command, capture_output=True, text=True, timeout=15
    )
except subprocess.TimeoutExpired:
    fail('SSH launch timed out')
except Exception as exc:
    fail(str(exc))

if result.returncode != 0:
    error = (result.stderr or result.stdout or
             f'SSH exited with status {result.returncode}').strip()
    fail(error[:200], exit_code=result.returncode)

pid = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ''
if re.fullmatch(r'[1-9][0-9]{0,19}', pid) is None:
    fail('Remote launch did not return a valid PID')
print(json.dumps({
    'success': True,
    'pcap_file': pcap_file,
    'pid': pid,
    'device': device,
    'duration': duration
}))

PYTHON_PCAP
        exit 0
        ;;
    pcap-status)
        # Poll a background PCAP capture: report running/finished and file size
        # so the client can enable Download once tcpdump has exited.
        read_post_body
        export POST_DATA

        python3 << 'PYTHON_PCAP_STATUS'
import json
import subprocess
import re
import os
import shlex

def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

def fail(message, **extra):
    response = {'success': False, 'error': message}
    response.update(extra)
    print(json.dumps(response))
    raise SystemExit(0)


try:
    data = json.loads(os.environ.get('POST_DATA', '{}'))
except (TypeError, ValueError, json.JSONDecodeError):
    fail('Invalid JSON body')
if not isinstance(data, dict):
    fail('JSON body must be an object')

device = data.get('device', '')
pcap_file = data.get('pcap_file', '')

if not isinstance(device, str):
    fail('Device must be text')
device = device.strip()
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    fail('Invalid device name format')

if not isinstance(pcap_file, str):
    fail('PCAP path must be text')
pcap_file = pcap_file.strip()
if (
    '..' in pcap_file
    or re.fullmatch(r'/tmp/capture_[A-Za-z0-9_.:-]{1,220}\.pcap', pcap_file) is None
):
    fail('Invalid PCAP path')

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))
lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))

device_ip = None
ssh_user = 'cumulus'

import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found'}))
    exit()

# Bracket the leading '/' and the dots so pgrep -f does not match its own
# argument text, matching only the live tcpdump/worker processes.
process_pattern = '[/]' + pcap_file[1:].replace('.', '[.]')
remote_status = (
    'st=DONE; '
    f'if sudo pgrep -f {shlex.quote(process_pattern)} >/dev/null 2>&1; '
    'then st=RUNNING; fi; '
    f'sz=$(stat -c %s {shlex.quote(pcap_file)} 2>/dev/null || echo 0); '
    # tcpdump's saved stderr, base64 on the status line so SSH banners and
    # embedded spaces/newlines cannot break the single-line parse below.
    f'err=$(tail -c 300 {shlex.quote(pcap_file + ".err")} 2>/dev/null'
    ' | base64 2>/dev/null | tr -d "\\n"); '
    "printf '%s %s %s\\n' \"$st\" \"$sz\" \"${err:--}\""
)

ssh_command = [
    'sudo', '-u', lldpq_user,
    'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
    f'{ssh_user}@{device_ip}',
    remote_status
]

try:
    result = subprocess.run(
        ssh_command, capture_output=True, text=True, timeout=15
    )
except subprocess.TimeoutExpired:
    fail('SSH status poll timed out')
except Exception as exc:
    fail(str(exc))

if result.returncode != 0:
    error = (result.stderr or result.stdout or
             f'SSH exited with status {result.returncode}').strip()
    fail(error[:200], exit_code=result.returncode)

lines = [ln.rstrip('\r') for ln in result.stdout.splitlines() if ln.strip()]
parsed = lines[-1].split() if lines else []
if len(parsed) not in (2, 3) or parsed[0] not in ('RUNNING', 'DONE'):
    fail('Could not parse capture status')
running = parsed[0] == 'RUNNING'
try:
    size = int(parsed[1])
except ValueError:
    size = 0

error_output = ''
if len(parsed) == 3 and parsed[2] != '-':
    import base64
    try:
        error_output = base64.b64decode(parsed[2]).decode('utf-8', 'replace').strip()
    except Exception:
        error_output = ''

response = {
    'success': True,
    'device': device,
    'pcap_file': pcap_file,
    'running': running,
    'finished': not running,
    'size': size
}
# Only surface tcpdump's stderr when the capture produced no data; a normal
# run also writes "listening on ..." there and that would just be noise.
if not running and size == 0 and error_output:
    response['error_output'] = error_output
print(json.dumps(response))

PYTHON_PCAP_STATUS
        exit 0
        ;;
    run-device-command)
        # Run a safe command on a device
        read_post_body
        export POST_DATA
        
        python3 << 'PYTHON_END'
import json
import subprocess
import re
import os
import fcntl
import shlex
import hashlib
import stat
from pathlib import PurePosixPath

# Parse input
post_data = os.environ.get('POST_DATA', '{}')
try:
    params = json.loads(post_data)
except:
    params = {}

device = params.get('device', '')
command = params.get('command', '')
policy = params.get('policy', '')

if not isinstance(device, str) or not isinstance(command, str):
    print(json.dumps({'success': False, 'error': 'Device and command must be text'}))
    exit()

device = device.strip()
command = command.strip()

if not device or not command:
    print(json.dumps({'success': False, 'error': 'Missing device or command'}))
    exit()

if any(ord(ch) < 32 for ch in command):
    print(json.dumps({'success': False, 'error': 'Command contains control characters'}))
    exit()

if policy not in ('', 'ai-readonly'):
    print(json.dumps({'success': False, 'error': 'Unknown command policy'}))
    exit()

# Model-generated commands have a narrower, fail-closed policy than the
# interactive Device Details command runner. Keep this boundary independent so
# tightening Ask-AI cannot break existing manual diagnostic workflows.
if policy == 'ai-readonly':
    import sys
    policy_dir = os.path.dirname(os.environ.get('SCRIPT_FILENAME', ''))
    if not policy_dir:
        policy_dir = os.environ.get('WEB_ROOT', '/var/www/html')
    if policy_dir not in sys.path:
        sys.path.insert(0, policy_dir)
    try:
        from ai_command_policy import validate_ai_readonly_command
        command_allowed, policy_error = validate_ai_readonly_command(command)
    except Exception:
        command_allowed, policy_error = False, 'Ask-AI command policy is unavailable'
    if not command_allowed:
        print(json.dumps({'success': False, 'error': policy_error}))
        exit()

FORBIDDEN_PATTERNS = [
    r'\bmlxlink\b',
    r'\bonie-install\b',
    r'\breboot\b',
    r'\bshutdown\b',
    # Block write-side nv config subcommands (apply/replace/save/delete/patch)
    r'\bnv\s+config\s+(apply|replace|save|delete|patch|edit|detach|history)\b',
    r'\bnv\s+set\b',
    r'\bnv\s+unset\b',
    r'\bztp\b',
]
for pattern in FORBIDDEN_PATTERNS:
    if re.search(pattern, command, re.IGNORECASE):
        print(json.dumps({'success': False, 'error': 'Command is not allowed from Device Details'}))
        exit()

# Security: Whitelist of allowed command patterns (checked first)
ALLOWED_PATTERNS = [
    # NVUE commands (including abbreviations: nv sh, nv sho, nv show)
    r'^nv show\b',
    r'^nv sho\b',
    r'^nv sh\b',
    r'^sudo nv show\b',
    # NVUE config (read-only show/find/diff)
    r'^nv config show\b',
    r'^nv config diff\b',
    r'^nv config find\b',
    r'^sudo nv config show\b',
    r'^sudo nv config diff\b',
    r'^sudo nv config find\b',
    # FRR/vtysh commands
    r'^sudo vtysh -c ["\']show\b',
    r'^vtysh -c ["\']show\b',
    # Layer 1 diagnostics
    r'^sudo l1-show [A-Za-z0-9_.:-]+$',
    r'^l1-show [A-Za-z0-9_.:-]+$',
    # ethtool variants
    r'^(sudo )?(/sbin/)?ethtool( -(m|S|i))? [A-Za-z0-9_.:-]+$',
    # IP/network commands
    r'^ip (?:-br |--brief )?link\b',
    r'^ip (?:-br |--brief )?addr\b',
    r'^ip (?:-br |--brief )?route\b',
    r'^ip (?:-br |--brief )?neigh\b',
    r'^sudo ip (?:-br |--brief )?link\b',
    r'^sudo ip (?:-br |--brief )?addr\b',
    r'^sudo ip (?:-br |--brief )?route\b',
    r'^sudo ip (?:-br |--brief )?neigh\b',
    r'^/sbin/bridge fdb\b',
    r'^/sbin/bridge vlan\b',
    r'^bridge fdb\b',
    r'^bridge vlan\b',
    r'^sudo (/sbin/)?bridge fdb\b',
    r'^sudo (/sbin/)?bridge vlan\b',
    r'^lldpctl\b',
    r'^sudo lldpctl\b',
    # Bonding/LAG / MLAG (read-only status only)
    r'^cat /proc/net/bonding/[A-Za-z0-9_.:-]+$',
    r'^sudo cat /proc/net/bonding/[A-Za-z0-9_.:-]+$',
    r'^clagctl$',
    r'^sudo clagctl$',
    r'^clagctl status$',
    r'^sudo clagctl status$',
    # LLDPq on-switch colored interface view (read-only)
    r'^nvt$',
    r'^/usr/local/bin/nvt$',
    # Hardware/sensors
    r'^sensors\b',
    r'^sudo sensors\b',
    r'^smonctl\b',
    r'^sudo smonctl\b',
    r'^decode-syseeprom\b',
    r'^sudo decode-syseeprom\b',
    r'^cl-resource-query\b',
    r'^sudo cl-resource-query\b',
    # Logs
    r'^cat /var/log/[A-Za-z0-9_.@:/+-]+$',
    r'^cat /tmp/live_[A-Za-z0-9_.:-]+$',
    r'^cat /tmp/tail_[A-Za-z0-9_.:-]+$',
    r'^sudo cat /var/log/[A-Za-z0-9_.@:/+-]+$',
    r'^tail\b',
    r'^sudo tail\b',
    r'^journalctl\b',
    r'^sudo journalctl\b',
    r'^dmesg\b',
    r'^sudo dmesg\b',
    # System
    r'^uptime$',
    r'^sudo uptime$',
    r'^free\b',
    r'^sudo free\b',
    r'^df\b',
    r'^sudo df\b',
    r'^ls -t /var/support/cl_support\*\.txz$',
    r'^pgrep\b',
    # Process cleanup is limited to a quoted LLDPq-owned temp path. A later
    # device-bound validator ensures the path belongs to the selected device.
    r'^sudo pkill -f "/tmp/(?:capture_[A-Za-z0-9_.:-]+\.pcap|(?:live|tail)_[A-Za-z0-9_.:-]+)"$',
    r'^find /tmp -name "(?:capture_\*\.pcap|live_\*\.txt|tail_\*\.txt)"(?: -mmin \+[0-9]+ -delete)?$',
    # Packet capture
    r'^sudo timeout ([1-9]|[1-9][0-9]|[12][0-9]{2}|300) tcpdump -U -i [A-Za-z0-9_.:-]+ -nnnn -w /tmp/capture_[A-Za-z0-9_.:-]+\.pcap( -c [1-9][0-9]{0,5})?( [A-Za-z0-9_.:/ -]+)?$',
    # Port bounce (Fabric Migration)
    r'^sudo /usr/sbin/ifdown( [A-Za-z0-9_.:-]+)+$',
    r'^sudo /usr/sbin/ifup( [A-Za-z0-9_.:-]+)+$',
    # Diagnostic bundle
    # Delete cl-support files only
    r'^sudo rm -f "/var/support/cl_support[A-Za-z0-9_.:-]+\.(?:txz|tar\.xz|tar\.gz)"$',
    r'^sudo rm -f /var/support/cl_support\*\.txz$',
    # Delete PCAP capture files
    r'^sudo rm -f "/tmp/capture_[A-Za-z0-9_.:-]+\.pcap"$',
    r'^sudo rm -f /tmp/capture_\*\.pcap$',
    r'^sudo rm -f "/tmp/live_[A-Za-z0-9_.:-]+\.txt"$',
    r'^sudo rm -f "/tmp/tail_[A-Za-z0-9_.:-]+\.txt"$',
]

# A single stderr-to-/dev/null suffix is used by the existing status polling
# commands.  Preserve that exact form, but reject every other redirection.
validation_command = command
if validation_command.endswith(' 2>/dev/null'):
    validation_command = validation_command[:-len(' 2>/dev/null')].rstrip()

# Reject shell operators before considering command prefixes.  Pipes are
# parsed separately below and only safe filter commands may appear on the RHS.
if re.search(r'[;&`$<>\\\r\n]', validation_command):
    print(json.dumps({'success': False, 'error': 'Command contains unsafe characters'}))
    exit()


def split_unquoted_pipes(text):
    """Split shell pipelines without treating quoted pattern pipes as syntax."""
    segments = []
    quote = None
    start = 0
    for index, char in enumerate(text):
        if char in ('"', "'"):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            continue
        if char == '|' and quote is None:
            if ((index > 0 and text[index - 1] == '|') or
                    (index + 1 < len(text) and text[index + 1] == '|')):
                raise ValueError('Shell logical operators are not allowed')
            segment = text[start:index].strip()
            if not segment:
                raise ValueError('Pipeline contains an empty command')
            segments.append(segment)
            start = index + 1
    if quote is not None:
        raise ValueError('Command contains an unmatched quote')
    final = text[start:].strip()
    if not final:
        raise ValueError('Pipeline contains an empty command')
    segments.append(final)
    return segments


def has_unquoted_expansion(text):
    """Detect glob/brace/tilde expansion that could create file operands."""
    quote = None
    for char in text:
        if char in ('"', "'"):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            continue
        if quote is None and char in '*?[]{}~':
            return True
    return False


try:
    pipeline = split_unquoted_pipes(validation_command)
    pipeline_tokens = [shlex.split(segment, posix=True) for segment in pipeline]
except ValueError as exc:
    print(json.dumps({'success': False, 'error': str(exc)}))
    exit()

if any(not tokens for tokens in pipeline_tokens):
    print(json.dumps({'success': False, 'error': 'Pipeline contains an empty command'}))
    exit()

if any(has_unquoted_expansion(segment) for segment in pipeline[1:]):
    print(json.dumps({
        'success': False,
        'error': 'Pipeline filters cannot use shell pathname expansion',
    }))
    exit()

base_command = pipeline[0]

# Check the source command against the whitelist.  Matching only the first
# pipeline segment prevents a safe prefix from authorizing an arbitrary RHS.
command_allowed = False
for pattern in ALLOWED_PATTERNS:
    if re.match(pattern, base_command, re.IGNORECASE):
        command_allowed = True
        break

# If not in whitelist, reject
if not command_allowed:
    print(json.dumps({'success': False, 'error': 'Command not in whitelist. Allowed: nv show, sudo vtysh -c "show...", ethtool, journalctl, uptime, dmesg'}))
    exit()


def has_parent_traversal(token):
    return '/' in token and '..' in PurePosixPath(token).parts


if any(
    has_parent_traversal(token)
    for tokens in pipeline_tokens
    for token in tokens
):
    print(json.dumps({'success': False, 'error': 'Command path traversal is not allowed'}))
    exit()


def approved_read_path(path):
    if has_parent_traversal(path):
        return False
    return bool(
        re.fullmatch(r'/proc/net/bonding/[A-Za-z0-9_.:-]+', path)
        or re.fullmatch(r'/var/log/[A-Za-z0-9_.@:/+-]+', path)
        or re.fullmatch(r'/tmp/(?:live|tail)_[A-Za-z0-9_.:-]+', path)
    )


def strip_sudo(tokens):
    return tokens[1:] if tokens and tokens[0] == 'sudo' else tokens


def safe_device_component(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    if len(component) > 80:
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:12]
        component = f'{component[:64]}_{digest}'
    return component


def lock_device_key(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
    return f'{component[:48]}_{digest}'


_using_secure_lock_dir = bool(os.environ.get('FABRIC_LOCK_DIR'))


def open_owned_lock(path):
    if not hasattr(os, 'O_NOFOLLOW'):
        raise RuntimeError('Secure lock files are not supported on this host')
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    # Locks in the private secure dir must be group-shared (0660): the CGI
    # (www-data) and CLI/admin users serialize on the same per-device file.
    mode = 0o660 if _using_secure_lock_dir else 0o600
    descriptor = os.open(path, flags, mode)
    metadata = os.fstat(descriptor)
    # In the private secure lock dir (FABRIC_LOCK_DIR, chmod 700/770) directory
    # permissions prevent squatting; O_NOFOLLOW blocks symlinks — uid check is
    # redundant and breaks cross-user sharing (www-data CGI vs aaydemir CLI).
    if not stat.S_ISREG(metadata.st_mode) or (not _using_secure_lock_dir and metadata.st_uid != os.geteuid()):
        os.close(descriptor)
        raise PermissionError('Unsafe command lock file')
    # Only the owner may fchmod; a non-owner sharing the lock must not fail.
    if metadata.st_uid == os.geteuid():
        os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, 'w')


def classify_scoped_cleanup(tokens):
    """Return the lock-bypass cleanup kind for this device, or None."""
    if len(tokens) != 4 or tokens[0] != 'sudo':
        return None
    # Browser-created PCAP names use the full sanitized hostname. Dedicated
    # live/tail builders cap long names and add a hash to stay below NAME_MAX.
    capture_device = re.sub(r'[^A-Za-z0-9-]', '_', device)
    runtime_device = safe_device_component(device)
    capture_prefix = f'/tmp/capture_{capture_device}_'
    live_prefix = f'/tmp/live_{runtime_device}_'
    tail_prefix = f'/tmp/tail_{runtime_device}_'

    if tokens[1:3] == ['pkill', '-f']:
        pattern = tokens[3]
        if '..' in pattern:
            return None
        if pattern in {live_prefix, tail_prefix}:
            return 'kill'
        if (
            pattern.startswith(capture_prefix)
            and re.fullmatch(r'/tmp/capture_[A-Za-z0-9_.:-]+\.pcap', pattern)
        ):
            return 'kill'
        if (
            pattern.startswith((live_prefix, tail_prefix))
            and re.fullmatch(r'/tmp/(?:live|tail)_[A-Za-z0-9_.:-]+\.txt', pattern)
        ):
            return 'kill'
        return None

    if tokens[1:3] == ['rm', '-f']:
        path = tokens[3]
        if '..' in path:
            return None
        if (
            path.startswith(capture_prefix)
            and re.fullmatch(r'/tmp/capture_[A-Za-z0-9_.:-]+\.pcap', path)
        ):
            return 'remove'
        if (
            path.startswith((live_prefix, tail_prefix))
            and re.fullmatch(r'/tmp/(?:live|tail)_[A-Za-z0-9_.:-]+\.txt', path)
        ):
            return 'remove'
    return None


def validate_ip_command(tokens):
    if len(tokens) < 2 or tokens[0] != 'ip':
        return False
    index = 1
    # An optional brief flag may precede the subcommand (e.g. ip -br addr show).
    if tokens[index] in {'-br', '--brief'}:
        index += 1
    if len(tokens) <= index:
        return False
    family = tokens[index]
    allowed_actions = {
        'link': {'show', 'list'},
        'addr': {'show', 'list'},
        'route': {'show', 'list', 'get'},
        'neigh': {'show', 'list', 'get'},
    }
    if family not in allowed_actions:
        return False
    return len(tokens) == index + 1 or tokens[index + 1] in allowed_actions[family]


def validate_bridge_command(tokens):
    if not tokens or tokens[0] not in {'bridge', '/sbin/bridge'}:
        return False
    if len(tokens) < 2 or tokens[1] not in {'fdb', 'vlan'}:
        return False
    return len(tokens) == 2 or tokens[2] in {'show', 'list'}


def validate_vtysh_command(tokens):
    bare = strip_sudo(tokens)
    if len(bare) != 3 or bare[:2] != ['vtysh', '-c']:
        return False
    inner = bare[2].strip()
    if not re.match(r'^show(?:\s|$)', inner, re.IGNORECASE):
        return False
    if re.search(r'[<>;&`$\\\r\n]', inner):
        return False
    if '|' not in inner:
        return True
    # FRR output modifiers are interpreted by vtysh itself inside the quoted
    # -c string, never by the shell. Permit exactly one safe filter tail.
    _head, _sep, tail = inner.partition('|')
    return bool(
        '|' not in tail
        and re.fullmatch(
            r'\s*(?:include|exclude|begin|section)\s+[A-Za-z0-9_.:/,@%+= -]{1,160}',
            tail,
            re.IGNORECASE,
        )
    )


def validate_journalctl_command(tokens):
    bare = strip_sudo(tokens)
    if not bare or bare[0] != 'journalctl':
        return False
    # Follow mode (-f/--follow) never terminates and is intentionally absent:
    # this endpoint runs synchronously and would only hit the 30s timeout.
    # The async Live Log Tail feature covers follow mode.
    flags = {
        '-k', '--dmesg', '--no-pager', '--utc', '--reverse', '--quiet',
        '--merge', '-b', '--boot', '-x', '--catalog', '--all',
        '-e', '--pager-end', '--no-full', '--full',
        '--no-hostname', '--no-tail', '--show-cursor', '--disk-usage',
        '--list-boots', '--list-fields', '--header', '--facility',
    }
    value_options = {
        '-n', '--lines', '-u', '--unit', '-p', '--priority', '-o',
        '--output', '-S', '--since', '-U', '--until', '-g', '--grep',
        '-t', '--identifier', '--cursor', '--after-cursor',
        '--namespace', '--output-fields',
    }
    # Namespace selection does not read a path and remains a read-only source
    # selector. File/directory/root/image/cursor-file and every maintenance
    # option are intentionally absent.
    index = 1
    while index < len(bare):
        token = bare[index]
        if token in flags or re.fullmatch(r'-[kxarqe]+', token):
            index += 1
            continue
        if token in value_options:
            index += 1
            if index >= len(bare) or not bare[index] or len(bare[index]) > 512:
                return False
            index += 1
            continue
        if any(
            token.startswith(option + '=')
            for option in value_options if option.startswith('--')
        ):
            _option, value = token.split('=', 1)
            if not value or len(value) > 512:
                return False
            index += 1
            continue
        if re.fullmatch(r'-(?:n|u|p|o|S|U|g|t).{1,256}', token):
            index += 1
            continue
        if re.fullmatch(
            r'[A-Z][A-Z0-9_]{1,63}=[A-Za-z0-9_.:@%+/-]{1,256}', token
        ):
            index += 1
            continue
        return False
    return True


def validate_dmesg_command(tokens):
    bare = strip_sudo(tokens)
    if not bare or bare[0] != 'dmesg':
        return False
    # Follow mode (-w/-W) never terminates and is intentionally absent: this
    # endpoint runs synchronously; the Live Log Tail feature covers follow.
    safe_flags = {
        '-T', '--ctime', '--reltime', '--notime', '-x', '--decode',
        '--nopager', '-H', '--human',
        '-k', '--kernel', '-u', '--userspace', '-P',
        '--nopager', '-L', '--color', '-J', '--json',
    }
    for token in bare[1:]:
        if token in safe_flags:
            continue
        if token.startswith(('--level=', '--facility=', '--color=', '--time-format=')):
            continue
        return False
    return True


def uses_follow_mode(tokens):
    """Detect journalctl/dmesg follow/streaming flags so the synchronous
    runner can point the user at Live Log Tail instead of a generic error."""
    bare = strip_sudo(tokens)
    if not bare:
        return False
    if bare[0] == 'journalctl':
        return any(
            token in ('-f', '--follow')
            or re.fullmatch(r'-[kxarqe]*f[kxarqfe]*', token)
            for token in bare[1:]
        )
    if bare[0] == 'dmesg':
        return any(
            token in ('-w', '-W', '--follow', '--follow-new')
            for token in bare[1:]
        )
    return False


def validate_lldpctl_command(tokens):
    bare = strip_sudo(tokens)
    if not bare or bare[0] != 'lldpctl':
        return False
    rest = bare[1:]
    if rest[:1] == ['-f']:
        if len(rest) < 2 or rest[1] not in {'plain', 'keyvalue', 'json', 'xml', 'json0'}:
            return False
        rest = rest[2:]
    return len(rest) <= 1 and (
        not rest or re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', rest[0]) is not None
    )


def validate_tcpdump_command(tokens):
    if len(tokens) < 10 or tokens[:2] != ['sudo', 'timeout']:
        return False
    try:
        duration = int(tokens[2])
    except (TypeError, ValueError):
        return False
    if not 1 <= duration <= 300 or tokens[3:6] != ['tcpdump', '-U', '-i']:
        return False
    if re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', tokens[6]) is None:
        return False
    if tokens[7:9] != ['-nnnn', '-w']:
        return False
    if re.fullmatch(r'/tmp/capture_[A-Za-z0-9_.:-]+\.pcap', tokens[9]) is None:
        return False
    index = 10
    if index < len(tokens) and tokens[index] == '-c':
        index += 1
        if index >= len(tokens) or re.fullmatch(r'[1-9][0-9]{0,5}', tokens[index]) is None:
            return False
        index += 1
    # The remaining argv is a deliberately small BPF-token subset. No token
    # may begin with '-' so tcpdump options such as -w/-F/-r/-C/-z/-Z cannot
    # be smuggled through the user-facing filter field.
    for token in tokens[index:]:
        if token.startswith('-') or re.fullmatch(r'[A-Za-z0-9_.:/-]+', token) is None:
            return False
    return True


def validate_base_argv(tokens):
    bare = strip_sudo(tokens)
    if not bare:
        return False
    executable = bare[0]
    if executable == 'killall':
        return False
    if executable == 'pkill':
        return classify_scoped_cleanup(tokens) == 'kill'
    if executable == 'rm' and len(bare) == 3 and bare[:2] == ['rm', '-f']:
        path = bare[2]
        if path == '/tmp/capture_*.pcap':
            return True
        if path.startswith(('/tmp/capture_', '/tmp/live_', '/tmp/tail_')):
            return classify_scoped_cleanup(tokens) == 'remove'
    # Read-only ip/bridge show commands are accepted with or without sudo,
    # matching the Ask-AI read-only policy.
    if executable == 'ip':
        return validate_ip_command(bare)
    if executable in {'bridge', '/sbin/bridge'}:
        return validate_bridge_command(bare)
    if executable == 'vtysh':
        return validate_vtysh_command(tokens)
    if executable == 'journalctl':
        return validate_journalctl_command(tokens)
    if executable == 'dmesg':
        return validate_dmesg_command(tokens)
    if executable == 'sensors':
        return bare == ['sensors']
    if executable in {'smonctl', 'decode-syseeprom', 'cl-resource-query'}:
        return len(bare) == 1
    if executable == 'lldpctl':
        return validate_lldpctl_command(tokens)
    if executable == 'clagctl':
        return bare in (['clagctl'], ['clagctl', 'status'])
    if executable == 'timeout' and len(bare) >= 3 and bare[2] == 'tcpdump':
        return validate_tcpdump_command(tokens)
    return True


def validate_base_paths(tokens):
    offset = 1 if tokens and tokens[0] == 'sudo' else 0
    if len(tokens) <= offset:
        return False
    executable = tokens[offset]
    args = tokens[offset + 1:]
    if executable == 'cat':
        return len(args) == 1 and approved_read_path(args[0])
    if executable == 'tail':
        paths = []
        index = 0
        value_options = {'-n', '--lines', '-c', '--bytes'}
        flag_options = {'-q', '--quiet', '--silent', '-v', '--verbose', '-z', '--zero-terminated'}
        while index < len(args):
            arg = args[index]
            if arg in value_options:
                index += 1
                if index >= len(args) or not re.fullmatch(r'[+-]?[0-9]+', args[index]):
                    return False
            elif arg in flag_options or re.fullmatch(r'-(?:[nc])?[+-]?[0-9]+', arg):
                pass
            elif arg.startswith('-'):
                return False
            else:
                paths.append(arg)
            index += 1
        return all(approved_read_path(path) for path in paths)
    return True


if not validate_base_paths(pipeline_tokens[0]):
    print(json.dumps({'success': False, 'error': 'Command may only read approved diagnostic paths'}))
    exit()

if uses_follow_mode(pipeline_tokens[0]):
    print(json.dumps({
        'success': False,
        'error': 'Follow/streaming flags never exit and would only time out here; use the Live Log Tail feature instead',
    }))
    exit()

if not validate_base_argv(pipeline_tokens[0]):
    print(json.dumps({'success': False, 'error': 'Command arguments are not allowed'}))
    exit()

scoped_cleanup_kind = (
    classify_scoped_cleanup(pipeline_tokens[0])
    if len(pipeline_tokens) == 1 else None
)


def validate_grep(args):
    value_options = {
        '-A', '-B', '-C', '-m', '--after-context', '--before-context',
        '--context', '--max-count', '-e', '--regexp',
    }
    safe_flags = re.compile(r'-(?:[ivnHhsoqwxEFG]+|[ABCm][0-9]+)$')
    positionals = []
    explicit_pattern = False
    index = 0
    while index < len(args):
        arg = args[index]
        if '/' in arg or arg in {'-f', '--file', '-r', '-R', '--recursive'}:
            return False
        if arg in value_options:
            index += 1
            if index >= len(args):
                return False
            value = args[index]
            if arg in {'-e', '--regexp'}:
                explicit_pattern = True
            elif not re.fullmatch(r'[0-9]+', value):
                return False
        elif arg.startswith('--'):
            if not re.fullmatch(
                r'--(?:color(?:=(?:never|always|auto))?|line-buffered|'
                r'binary-files=(?:binary|text|without-match)|word-regexp|'
                r'line-regexp|ignore-case|invert-match|line-number|quiet)', arg
            ):
                return False
        elif arg.startswith('-'):
            if not safe_flags.fullmatch(arg):
                return False
        else:
            positionals.append(arg)
        index += 1
    return len(positionals) == (0 if explicit_pattern else 1)


def validate_line_selector(name, args):
    if name in {'head', 'tail'}:
        value_options = {'-n', '--lines', '-c', '--bytes'}
        flags = {'-q', '--quiet', '--silent', '-v', '--verbose', '-z', '--zero-terminated'}
    else:
        value_options = set()
        flags = set()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in value_options:
            index += 1
            if index >= len(args) or not re.fullmatch(r'[+-]?[0-9]+', args[index]):
                return False
        elif arg in flags or re.fullmatch(r'-(?:[nc])?[+-]?[0-9]+', arg):
            pass
        else:
            return False
        index += 1
    return True


def validate_filter(tokens):
    name = tokens[0]
    args = tokens[1:]
    if '/' in name or name not in {
        'grep', 'head', 'tail', 'wc', 'sort', 'uniq', 'cut', 'awk', 'sed'
    }:
        return False
    if name == 'grep':
        return validate_grep(args)
    if name in {'head', 'tail'}:
        return validate_line_selector(name, args)
    if name == 'wc':
        return all(re.fullmatch(r'-[clmwL]+', arg) for arg in args)
    if name == 'sort':
        # Sorting stdin is safe; file operands and output-file options are not.
        return all(
            re.fullmatch(r'-(?:[bdfgiMhnRrSsuVz]+|k[0-9.,]+|t.)', arg)
            or re.fullmatch(r'--(?:numeric-sort|reverse|unique|stable|ignore-case)', arg)
            for arg in args
        )
    if name == 'uniq':
        return all(
            re.fullmatch(r'-(?:[cdiu]+|[fsw][0-9]+)', arg)
            for arg in args
        )
    if name == 'cut':
        return bool(args) and all(
            re.fullmatch(r'-(?:[bcf][0-9,.-]+|d.)', arg)
            or arg in {'-s', '--only-delimited', '--complement'}
            for arg in args
        )
    if name == 'awk':
        if len(args) != 1:
            return False
        program = args[0]
        return not re.search(
            r'\b(?:system|getline|close)\s*\(|\bgetline\b|@(?:include|load)|\|',
            program,
            re.IGNORECASE,
        )
    if name == 'sed':
        scripts = []
        index = 0
        while index < len(args):
            if args[index] in {'-n', '-E', '-r'}:
                index += 1
                continue
            if args[index] in {'-e', '--expression'}:
                index += 1
                if index >= len(args):
                    return False
                scripts.append(args[index])
            elif args[index].startswith('-'):
                return False
            elif scripts:
                return False
            else:
                scripts.append(args[index])
            index += 1
        if not scripts:
            return False
        for script in scripts:
            if len(script) >= 4 and script[0] == 's':
                delimiter = script[1]
                if delimiter.isalnum() or delimiter.isspace():
                    return False
                parts = script.split(delimiter)
                if len(parts) != 4 or not re.fullmatch(r'[gIp0-9]*', parts[3]):
                    return False
            elif not re.fullmatch(
                r'(?:[0-9]+(?:,[0-9$]+)?|/[^/]+/)[pd]', script
            ):
                return False
        return True
    return False


if len(pipeline_tokens) > 1:
    # Cleanup/capture commands have side effects and are never valid pipeline
    # sources, even though they are retained for existing UI workflows.
    if re.match(r'^(?:sudo (?:rm|killall|pkill|timeout)|find\b)', base_command):
        print(json.dumps({'success': False, 'error': 'This command cannot be piped'}))
        exit()
    if not all(validate_filter(tokens) for tokens in pipeline_tokens[1:]):
        print(json.dumps({
            'success': False,
            'error': 'Pipeline filters must be read-only and cannot read files',
        }))
        exit()

# Validate device name (must be a valid hostname pattern)
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    print(json.dumps({'success': False, 'error': 'Invalid device name format'}))
    exit()

# Read config from lldpq.conf
def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))

# Get device management IP and username
# Priority: devices.yaml (always available) -> Ansible inventory (optional)
device_ip = None
ssh_user = 'cumulus'

# Try devices.yaml first
lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

# Fallback to Ansible inventory
if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in inventory or devices.yaml'}))
    exit()

# ssh -tt delivers a pty, so every line arrives CRLF-terminated. Strip the
# trailing '\r' per line so JS line parsers (cl-support ls paths, VRF/port
# lists, single-value lookups) see clean values. Defined before the try so
# the TimeoutExpired handler can reuse it on partial output.
def strip_cr(text):
    if not text:
        return text
    return '\n'.join(line[:-1] if line.endswith('\r') else line
                     for line in text.split('\n'))

# journalctl/cat over many devices can push tens of MB; cap stdout so the
# JSON payload stays bounded and the browser does not freeze.
STDOUT_CAP = 512 * 1024

# Execute command via SSH using management IP
try:
    # Private service-owned lock dir (exported by the shell wrapper) instead
    # of world-writable /tmp, so other local users cannot pre-create the
    # predictable path and wedge this device via the uid check below.
    _lock_dir = os.environ.get('FABRIC_LOCK_DIR') or '/tmp'
    lock_path = f"{_lock_dir}/lldpq-run-device-command-{lock_device_key(device)}.lock"
    lock_fd = None
    # A long tcpdump owns the normal per-device command lock. Only a command
    # already proven to target this device's LLDPq temp path may bypass it, so
    # Stop can interrupt that process. Every other command keeps serialization.
    if scoped_cleanup_kind is None:
        lock_fd = open_owned_lock(lock_path)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'success': False, 'error_code': 'device_busy', 'error': 'Another command is already running on this device'}))
            exit()

    # Determine timeout based on command - longer for tcpdump, cl-support
    cmd_timeout = 30
    if 'tcpdump' in command or 'cl-support' in command:
        # Extract timeout value from command if present
        timeout_match = re.search(r'timeout\s+(\d+)', command)
        if timeout_match:
            cmd_timeout = int(timeout_match.group(1)) + 10  # Add 10s buffer
        else:
            cmd_timeout = 120  # Default 2 minutes for long commands

    execution_command = command
    if scoped_cleanup_kind == 'kill':
        # Avoid pkill matching the short-lived remote shell that contains the
        # literal requested path. `[/]tmp/...` matches the worker marker but
        # not its own bracketed pattern text. Validation has already limited
        # the marker charset, so only filename dots need regex escaping.
        marker = pipeline_tokens[0][3]
        process_pattern = '[/]' + marker[1:].replace('.', '[.]')
        execution_command = (
            f'sudo pkill -f {shlex.quote(process_pattern)}'
        )
    
    ssh_command = [
        'sudo', '-u', lldpq_user,
        'ssh', '-tt',  # Force pseudo-tty for unbuffered output
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=10',
        '-o', 'BatchMode=yes',
        '-o', 'LogLevel=ERROR',  # Suppress warnings
        f'{ssh_user}@{device_ip}',  # Use username@IP from devices.yaml/inventory
        execution_command
    ]
    
    result = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=cmd_timeout
    )
    
    stdout = strip_cr(result.stdout)
    stderr = strip_cr(result.stderr)

    if len(stdout) > STDOUT_CAP:
        stdout = stdout[:STDOUT_CAP] + '\n[output truncated at 512 KB]'

    command_ok = result.returncode == 0
    response = {
        'success': command_ok,
        'device': device,
        'command': command,
        'output': stdout,
        'error_output': stderr,
        'exit_code': result.returncode
    }
    if not command_ok:
        response['error'] = (stderr or stdout or
                             f'Command exited with status {result.returncode}').strip()[:1000]
    print(json.dumps(response))

except subprocess.TimeoutExpired as exc:
    # Return whatever the command produced before the deadline instead of
    # discarding everything it printed during the timeout window.
    partial = exc.stdout or ''
    if isinstance(partial, bytes):
        partial = partial.decode('utf-8', 'replace')
    partial = strip_cr(partial)
    if len(partial) > STDOUT_CAP:
        partial = partial[:STDOUT_CAP] + '\n[output truncated at 512 KB]'
    print(json.dumps({
        'success': False,
        'error': f'Command timed out ({cmd_timeout}s)',
        'timed_out': True,
        'output': partial,
    }))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON_END
        ;;
    run-audit-pack)
        # Run one named read-only audit pack on a device in a single SSH
        # session. Only a server-side pack NAME is accepted; the compound
        # command is composed locally from ai_audit_packs.py, whose commands
        # are individually validated against the Ask-AI read-only policy at
        # module import, so the policy surface does not widen.
        read_post_body
        export POST_DATA

        python3 << 'PYTHON_END'
import json
import subprocess
import re
import os
import sys
import fcntl
import hashlib
import stat

# Parse input
post_data = os.environ.get('POST_DATA', '{}')
try:
    params = json.loads(post_data)
except:
    params = {}

device = params.get('device', '')
pack = params.get('pack', '')

if not isinstance(device, str) or not isinstance(pack, str):
    print(json.dumps({'success': False, 'error': 'Device and pack must be text'}))
    exit()

device = device.strip()
pack = pack.strip()

if not device or not pack:
    print(json.dumps({'success': False, 'error': 'Missing device or pack'}))
    exit()

# No raw shell is accepted here: the pack name only selects a server-side
# command list and the sentinel-wrapped compound is built below.
module_dir = os.path.dirname(os.environ.get('SCRIPT_FILENAME', ''))
if not module_dir:
    module_dir = os.environ.get('WEB_ROOT', '/var/www/html')
if module_dir not in sys.path:
    sys.path.insert(0, module_dir)
try:
    from ai_audit_packs import PACKS, build_compound
except Exception:
    print(json.dumps({'success': False, 'error': 'Audit pack module is unavailable'}))
    exit()

if pack not in PACKS:
    print(json.dumps({'success': False, 'error': 'Unknown audit pack'}))
    exit()

command = build_compound(pack)

# Validate device name (must be a valid hostname pattern)
if (
    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}', device)
    or '..' in device
):
    print(json.dumps({'success': False, 'error': 'Invalid device name format'}))
    exit()


def lock_device_key(value):
    component = re.sub(r'[^A-Za-z0-9-]', '_', value)
    digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
    return f'{component[:48]}_{digest}'


_using_secure_lock_dir = bool(os.environ.get('FABRIC_LOCK_DIR'))


def open_owned_lock(path):
    if not hasattr(os, 'O_NOFOLLOW'):
        raise RuntimeError('Secure lock files are not supported on this host')
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    mode = 0o660 if _using_secure_lock_dir else 0o600
    descriptor = os.open(path, flags, mode)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or (not _using_secure_lock_dir and metadata.st_uid != os.geteuid()):
        os.close(descriptor)
        raise PermissionError('Unsafe command lock file')
    if metadata.st_uid == os.geteuid():
        os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, 'w')


# Read config from lldpq.conf (same method as run-device-command)
def read_lldpq_conf():
    conf = {}
    conf_paths = ['/etc/lldpq.conf', os.path.expanduser('~/lldpq.conf')]
    for conf_path in conf_paths:
        if os.path.exists(conf_path):
            with open(conf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, val = line.split('=', 1)
                        conf[key.strip()] = val.strip()
            break
    return conf

lldpq_conf = read_lldpq_conf()
ansible_dir = lldpq_conf.get('ANSIBLE_DIR', os.path.expanduser('~/ansible'))
lldpq_user = lldpq_conf.get('LLDPQ_USER', os.environ.get('USER', 'root'))

# Get device management IP and username
# Priority: devices.yaml (always available) -> Ansible inventory (optional)
device_ip = None
ssh_user = 'cumulus'

# Try devices.yaml first
lldpq_dir = lldpq_conf.get('LLDPQ_DIR', os.path.expanduser('~/lldpq'))
import yaml
_devices_yaml_error = None
for devices_path in [f"{lldpq_dir}/devices.yaml"]:
    if os.path.exists(devices_path):
        try:
            with open(devices_path, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            defaults = ddata.get('defaults', {})
            default_user = defaults.get('username', 'cumulus')
            for ip, info in ddata.get('devices', {}).items():
                if isinstance(info, dict):
                    hname = info.get('hostname', '')
                    uname = info.get('username', default_user)
                else:
                    hname = str(info).split()[0] if info else ''
                    uname = default_user
                if hname == device:
                    device_ip = str(ip)
                    ssh_user = uname
                    break
        except (OSError, yaml.YAMLError, AttributeError) as _dexc:
            # A corrupt/unreadable devices.yaml must not masquerade as
            # 'device not found'; remember the real cause for the error below
            _devices_yaml_error = str(_dexc)

# Fallback to Ansible inventory
if not device_ip:
    for inv_file in [f"{ansible_dir}/inventory/inventory.ini", f"{ansible_dir}/inventory/hosts"]:
        if os.path.exists(inv_file):
            try:
                with open(inv_file, 'r') as f:
                    for line in f:
                        if line.strip().startswith(device + ' ') or line.strip().startswith(device + '\t'):
                            match = re.search(r'ansible_host=(\S+)', line)
                            if match:
                                device_ip = match.group(1)
                                break
            except:
                pass
        if device_ip:
            break

if not device_ip:
    if _devices_yaml_error:
        print(json.dumps({'success': False, 'error': f'devices.yaml could not be parsed: {_devices_yaml_error}'}))
    else:
        print(json.dumps({'success': False, 'error': f'Device {device} not found in inventory or devices.yaml'}))
    exit()

# Execute the compound command via SSH using management IP
try:
    # Private service-owned lock dir (exported by the shell wrapper) instead
    # of world-writable /tmp, so other local users cannot pre-create the
    # predictable path and wedge this device via the uid check below.
    _lock_dir = os.environ.get('FABRIC_LOCK_DIR') or '/tmp'
    lock_path = f"{_lock_dir}/lldpq-run-device-command-{lock_device_key(device)}.lock"
    lock_fd = open_owned_lock(lock_path)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(json.dumps({'success': False, 'error_code': 'device_busy', 'error': 'Another command is already running on this device'}))
        exit()

    # A pack chains several short read-only commands in one session, so it
    # gets double the single-command budget while staying bounded.
    cmd_timeout = 60

    ssh_command = [
        'sudo', '-u', lldpq_user,
        'ssh', '-tt',  # Force pseudo-tty for unbuffered output
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=10',
        '-o', 'BatchMode=yes',
        '-o', 'LogLevel=ERROR',  # Suppress warnings
        f'{ssh_user}@{device_ip}',  # Use username@IP from devices.yaml/inventory
        command
    ]

    result = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True,
        timeout=cmd_timeout
    )

    # ssh -tt delivers a pty, so lines arrive CRLF-terminated; strip the
    # trailing '\r' per line so downstream JS parsers see clean values.
    def strip_cr(text):
        if not text:
            return text
        return '\n'.join(line[:-1] if line.endswith('\r') else line
                         for line in text.split('\n'))

    stdout = strip_cr(result.stdout)
    stderr = strip_cr(result.stderr)

    STDOUT_CAP = 512 * 1024
    if len(stdout) > STDOUT_CAP:
        stdout = stdout[:STDOUT_CAP] + '\n[output truncated at 512 KB]'

    command_ok = result.returncode == 0
    response = {
        'success': command_ok,
        'device': device,
        'pack': pack,
        'command': command,
        'output': stdout,
        'error_output': stderr,
        'exit_code': result.returncode
    }
    if not command_ok:
        response['error'] = (stderr or stdout or
                             f'Command exited with status {result.returncode}').strip()[:1000]
    print(json.dumps(response))

except subprocess.TimeoutExpired:
    print(json.dumps({'success': False, 'error': f'Command timed out ({cmd_timeout}s)'}))
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
PYTHON_END
        ;;
    refresh-assets)
        # Trigger assets.sh to refresh device inventory using trigger file mechanism
        # A cron job running as lldpq user watches this file and runs assets.sh
        TRIGGER_FILE="/tmp/.assets_refresh_trigger"
        
        # Create trigger file with timestamp
        echo "$(date +%s)" > "$TRIGGER_FILE" 2>/dev/null
        chmod 666 "$TRIGGER_FILE" 2>/dev/null
        
        if [ -f "$TRIGGER_FILE" ]; then
            echo '{"success": true, "message": "Assets refresh triggered. Please wait about 30 seconds."}'
        else
            echo '{"success": false, "error": "Failed to create trigger file"}'
        fi
        ;;
    "ansible-status")
        # Check if Ansible is configured and available
        if [[ -n "$ANSIBLE_DIR" ]] && [[ -d "$ANSIBLE_DIR" ]]; then
            # json.dumps keeps the response valid even if the path contains quotes/backslashes
            python3 - "$ANSIBLE_DIR" <<'PYTHON'
import json, sys
print(json.dumps({'success': True, 'configured': True, 'ansible_dir': sys.argv[1]}))
PYTHON
        else
            echo '{"success": true, "configured": false}'
        fi
        ;;
    "save-display-aliases")
        # Save DISPLAY aliases (real name -> P2P/field label) for both interfaces
        # (e.g. enP22p3s0f0np0 -> M1) and devices (e.g. tan-spine-01 -> SPINE-01).
        # Display-only (consumed by lldp.html); does not touch validation data.
        # Admin only (default auth gate at top of file). Generic: no naming hardcoded.
        ALIAS_MAX_BODY=1048576
        if [[ "${CONTENT_LENGTH:-}" =~ ^[0-9]+$ ]] && \
           (( CONTENT_LENGTH > ALIAS_MAX_BODY )); then
            echo '{"success": false, "error": "Aliases payload is too large"}'
            exit 0
        fi
        if [[ "${CONTENT_LENGTH:-}" =~ ^[0-9]+$ ]] && (( CONTENT_LENGTH > 0 )); then
            POST_DATA=$(dd bs=4096 count=$(( (CONTENT_LENGTH + 4095) / 4096 )) \
                iflag=fullblock 2>/dev/null | head -c "$CONTENT_LENGTH")
        else
            POST_DATA=$(cat)
        fi
        if [[ -x /usr/local/bin/lldpq-config ]]; then
            eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
        fi
        WEB_ROOT="${WEB_ROOT:-/var/www/html}"
        LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
        LLDPQ_USER="${LLDPQ_USER:-lldpq}"
        PROVISION_STATE_DIR="${LLDPQ_PROVISION_STATE_DIR:-/var/lib/lldpq/provision-state}"
        DIRECT_WRITE_STATE_DIR="${LLDPQ_DIRECT_WRITE_STATE_DIR:-$PROVISION_STATE_DIR/config-write-journals}"
        ALIAS_FILE="$WEB_ROOT/display-aliases.json"
        SETUP_SAFETY="$(dirname "$0")/setup_safety.py"
        if [[ ! -f "$SETUP_SAFETY" ]]; then
            echo '{"success": false, "error": "Setup safety helper is missing; repair the installation"}'
            exit 0
        fi
        ALIAS_ARGS=(
            "$SETUP_SAFETY" save-aliases
            --target "$ALIAS_FILE"
            --managed-root "$WEB_ROOT"
            --managed-root "$LLDPQ_DIR"
            --direct-write-state-dir "$DIRECT_WRITE_STATE_DIR"
        )
        # Keep the helper's stderr: when sudo itself fails (missing sudoers
        # rule, askpass suppressed by -n) stdout is empty and stderr carries
        # the only real cause.
        ALIAS_ERR_FILE=$(mktemp /tmp/lldpq-alias-stderr.XXXXXX 2>/dev/null) || ALIAS_ERR_FILE=''
        ALIAS_RESPONSE=$(printf '%s' "$POST_DATA" | \
            sudo -n -H -u "$LLDPQ_USER" /usr/bin/bash -c \
            'exec python3 "$@"' -- "${ALIAS_ARGS[@]}" 2>"${ALIAS_ERR_FILE:-/dev/null}")
        ALIAS_STATUS=$?
        ALIAS_STDERR=''
        if [[ -n "$ALIAS_ERR_FILE" ]]; then
            ALIAS_STDERR=$(head -c 200 "$ALIAS_ERR_FILE" 2>/dev/null)
            rm -f "$ALIAS_ERR_FILE"
        fi
        if (( ALIAS_STATUS == 0 )); then
            if ! sudo -n chown "${LLDPQ_USER:-lldpq}:www-data" "$ALIAS_FILE" 2>/dev/null || \
               ! sudo -n chmod 664 "$ALIAS_FILE" 2>/dev/null; then
                echo '{"success": false, "error": "Aliases were saved but file permissions could not be normalized"}'
            else
                echo "$ALIAS_RESPONSE"
            fi
        elif [[ -n "$ALIAS_RESPONSE" ]]; then
            echo "$ALIAS_RESPONSE"
        else
            # json.dumps keeps the response valid even if stderr contains quotes/backslashes
            python3 - "$ALIAS_STATUS" "$ALIAS_STDERR" <<'PYTHON'
import json, sys
status = sys.argv[1] if len(sys.argv) > 1 else '?'
stderr = (sys.argv[2] if len(sys.argv) > 2 else '').strip()
detail = f': {stderr}' if stderr else ''
print(json.dumps({'success': False, 'error': f'Alias save helper failed (exit {status}){detail}'}))
PYTHON
        fi
        ;;
    *)
        # json.dumps keeps the response valid even if the action contains quotes/backslashes
        python3 - "$ACTION" <<'PYTHON'
import json, sys
action = sys.argv[1] if len(sys.argv) > 1 else ''
print(json.dumps({'success': False, 'error': f'Unknown action: {action}'}))
PYTHON
        ;;
esac
