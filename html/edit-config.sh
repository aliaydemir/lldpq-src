#!/usr/bin/env bash
# edit-config.sh - Read/Write topology_config.yaml via CGI
# Called by nginx fcgiwrap

source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load config with fallback
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
LLDPQ_DIR="${LLDPQ_DIR:-/opt/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
PROVISION_STATE_DIR="${LLDPQ_PROVISION_STATE_DIR:-/var/lib/lldpq/provision-state}"
DIRECT_WRITE_STATE_DIR="${LLDPQ_DIRECT_WRITE_STATE_DIR:-$PROVISION_STATE_DIR/config-write-journals}"
SETUP_SAFETY="$(dirname "$0")/setup_safety.py"
# NoNe = explicitly disabled, treat as empty
if [[ "$ANSIBLE_DIR" == "NoNe" ]]; then
    ANSIBLE_DIR=""
fi

# topology_config.yaml is in web root
CONFIG_FILE="$WEB_ROOT/topology_config.yaml"

# Read request method and query string
METHOD="${REQUEST_METHOD:-GET}"
QUERY="${QUERY_STRING:-}"

# Parse action from query string
ACTION=""
if [[ "$QUERY" =~ action=([^&]+) ]]; then
    ACTION="${BASH_REMATCH[1]}"
fi

# Output headers
echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo "X-Content-Type-Options: nosniff"
echo ""

# Handle get-inventory action - return device groups
# Priority: Ansible inventory -> devices.yaml fallback
if [ "$ACTION" = "get-inventory" ]; then
    # Try Ansible inventory first
    INVENTORY_FILE=""
    if [ -n "$ANSIBLE_DIR" ]; then
        if [ -f "$ANSIBLE_DIR/inventory/inventory.ini" ]; then
            INVENTORY_FILE="$ANSIBLE_DIR/inventory/inventory.ini"
        elif [ -f "$ANSIBLE_DIR/inventory/hosts" ]; then
            INVENTORY_FILE="$ANSIBLE_DIR/inventory/hosts"
        fi
    fi

    # Fallback: devices.yaml
    DEVICES_YAML="$LLDPQ_DIR/devices.yaml"

    export INVENTORY_FILE
    export DEVICES_YAML
    python3 << 'PYEOF'
import json
import re
import os

inventory_file = os.environ.get('INVENTORY_FILE', '')
devices_yaml = os.environ.get('DEVICES_YAML', '')
groups = {}

# --- Try Ansible inventory first ---
if inventory_file and os.path.isfile(inventory_file):
    current_group = None
    try:
        with open(inventory_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                group_match = re.match(r'^\[([^\]:]+)\]', line)
                if group_match:
                    group_name = group_match.group(1)
                    if ':' not in group_name:
                        current_group = group_name
                        if current_group not in groups:
                            groups[current_group] = []
                    else:
                        current_group = None
                    continue
                if current_group:
                    host_match = re.match(r'^(\S+)', line)
                    if host_match:
                        hostname = host_match.group(1)
                        if hostname not in groups[current_group]:
                            groups[current_group].append(hostname)
    except Exception:
        groups = {}

# --- Fallback: devices.yaml ---
if not groups and devices_yaml and os.path.isfile(devices_yaml):
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
                if group not in groups:
                    groups[group] = []
                if hostname not in groups[group]:
                    groups[group].append(hostname)
    except Exception as e:
        print(json.dumps({'success': False, 'error': f'Failed to parse devices.yaml: {e}'}))
        raise SystemExit(0)

if groups:
    print(json.dumps({'success': True, 'groups': groups}))
else:
    print(json.dumps({'success': False, 'error': 'No device inventory found. Provide Ansible inventory or devices.yaml'}))
PYEOF
    exit 0
fi

# Handle validate action (requires Ansible)
if [ "$ACTION" = "validate" ]; then
    if [ -z "$ANSIBLE_DIR" ] || [ ! -d "$ANSIBLE_DIR" ]; then
        echo '{"success": false, "error": "Ansible not configured. Validation requires Ansible inventory."}'
        exit 0
    fi
    VALIDATE_SCRIPT="$LLDPQ_DIR/nv-validate.py"
    CONFIG_DIR="$ANSIBLE_DIR/files/generated_config_folder"
    
    # Parse devices parameter (comma-separated list)
    DEVICES=""
    if [[ "$QUERY" =~ devices=([^&]+) ]]; then
        DEVICES="${BASH_REMATCH[1]}"
        # URL decode
        DEVICES=$(echo "$DEVICES" | python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))')
    fi
    
    if [ ! -f "$VALIDATE_SCRIPT" ]; then
        echo '{"success": false, "error": "Validator script not found"}'
        exit 0
    fi
    
    if [ ! -d "$CONFIG_DIR" ]; then
        echo '{"success": false, "needs_generate": true, "error": "Generated config directory not found. Run Generate first to build device configs."}'
        exit 0
    fi

    # Compute a generate-state signal (missing/stale generated configs vs their
    # host_vars/group_vars sources) so the UI can warn "run Generate first"
    # before deploying freshly-templated config over stale validated bytes.
    GEN_STATE=$(CONFIG_DIR="$CONFIG_DIR" \
        HOSTVARS_DIR="$ANSIBLE_DIR/inventory/host_vars" \
        GROUPVARS_DIR="$ANSIBLE_DIR/inventory/group_vars" \
        REQ_DEVICES="$DEVICES" python3 << 'PYEOF'
import os, json, glob

config_dir = os.environ.get('CONFIG_DIR', '')
hostvars_dir = os.environ.get('HOSTVARS_DIR', '')
groupvars_dir = os.environ.get('GROUPVARS_DIR', '')
req = os.environ.get('REQ_DEVICES', '').strip()


def gen_path(dev):
    for ext in ('.yaml', '.yml'):
        p = os.path.join(config_dir, dev + ext)
        if os.path.isfile(p):
            return p
    return None


def src_mtime(dev):
    mt = 0.0
    for ext in ('.yaml', '.yml'):
        p = os.path.join(hostvars_dir, dev + ext)
        if os.path.isfile(p):
            try:
                mt = max(mt, os.path.getmtime(p))
            except OSError:
                pass
    return mt


global_mt = 0.0
if groupvars_dir and os.path.isdir(groupvars_dir):
    for root, _dirs, files in os.walk(groupvars_dir):
        for fn in files:
            if fn.endswith(('.yaml', '.yml')):
                try:
                    global_mt = max(global_mt, os.path.getmtime(os.path.join(root, fn)))
                except OSError:
                    pass

if req:
    devices = [d.strip() for d in req.split(',') if d.strip()]
else:
    devices = []
    if os.path.isdir(config_dir):
        for p in glob.glob(os.path.join(config_dir, '*.yaml')) + glob.glob(os.path.join(config_dir, '*.yml')):
            devices.append(os.path.splitext(os.path.basename(p))[0])
    devices = sorted(set(devices))

missing = []
stale = []
for dev in devices:
    gp = gen_path(dev)
    if gp is None:
        missing.append(dev)
        continue
    try:
        gmt = os.path.getmtime(gp)
    except OSError:
        missing.append(dev)
        continue
    if max(src_mtime(dev), global_mt) > gmt:
        stale.append(dev)

print(json.dumps({
    'missing_devices': sorted(set(missing)),
    'stale_devices': sorted(set(stale)),
    'needs_generate': bool(missing or stale),
}))
PYEOF
)
    # Fall back to a safe default if the probe failed for any reason.
    if ! printf '%s' "$GEN_STATE" | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
        GEN_STATE='{"missing_devices": [], "stale_devices": [], "needs_generate": false}'
    fi
    
    STDERR_FILE=$(mktemp)
    # If specific devices requested, create temp dir with symlinks
    if [ -n "$DEVICES" ]; then
        TEMP_DIR=$(mktemp -d)
        IFS=',' read -ra DEVICE_ARRAY <<< "$DEVICES"
        LINKED=0
        for device in "${DEVICE_ARRAY[@]}"; do
            device=$(echo "$device" | xargs)  # trim whitespace
            if [ -f "$CONFIG_DIR/${device}.yaml" ]; then
                ln -s "$CONFIG_DIR/${device}.yaml" "$TEMP_DIR/${device}.yaml"
                LINKED=$((LINKED + 1))
            elif [ -f "$CONFIG_DIR/${device}.yml" ]; then
                ln -s "$CONFIG_DIR/${device}.yml" "$TEMP_DIR/${device}.yml"
                LINKED=$((LINKED + 1))
            fi
        done
        if [ "$LINKED" -eq 0 ]; then
            rm -rf "$TEMP_DIR"
            rm -f "$STDERR_FILE"
            ERROR=$(printf '%s' "No generated config for $DEVICES. Run Generate first." | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            echo '{"success": false, "needs_generate": true, "generate_state": '"$GEN_STATE"', "error": '"$ERROR"'}'
            exit 0
        fi
        RESULT=$(python3 "$VALIDATE_SCRIPT" --dir "$TEMP_DIR" --json --no-topology 2>"$STDERR_FILE")
        rc=$?
        rm -rf "$TEMP_DIR"
    else
        # Run validator on all configs
        RESULT=$(python3 "$VALIDATE_SCRIPT" --dir "$CONFIG_DIR" --json 2>"$STDERR_FILE")
        rc=$?
    fi
    ERR_OUTPUT=$(cat "$STDERR_FILE")
    rm -f "$STDERR_FILE"

    if [ "$rc" -eq 0 ]; then
        echo '{"success": true, "valid": true, "generate_state": '"$GEN_STATE"', "result": '"$RESULT"'}'
    else
        # Check if it's JSON output (validation found errors)
        if echo "$RESULT" | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null; then
            echo '{"success": true, "valid": false, "generate_state": '"$GEN_STATE"', "result": '"$RESULT"'}'
        else
            # Script error - report stderr, not the JSON stdout stream
            ERROR=$(printf '%s' "$ERR_OUTPUT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            echo '{"success": false, "generate_state": '"$GEN_STATE"', "error": '"$ERROR"'}'
        fi
    fi
    exit 0
fi

if [ "$METHOD" = "GET" ]; then
    if [ ! -f "$SETUP_SAFETY" ]; then
        echo '{"success": false, "error": "Setup safety helper is missing; repair the installation"}'
        exit 0
    fi
    ARGS=("$SETUP_SAFETY" read-text --target "$CONFIG_FILE" \
        --managed-root "$WEB_ROOT" --managed-root "$LLDPQ_DIR" \
        --direct-write-state-dir "$DIRECT_WRITE_STATE_DIR")
    RESULT=$(sudo -n -H -u "$LLDPQ_USER" /usr/bin/bash -c \
        'exec python3 "$@"' -- "${ARGS[@]}" 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo "$RESULT"
    else
        echo '{"success": false, "error": "Failed to recover or read topology_config.yaml"}'
    fi
    
elif [ "$METHOD" = "POST" ]; then
    # Read POST data from stdin
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        POST_DATA=$(cat)
    fi
    
    if [ ! -f "$SETUP_SAFETY" ]; then
        echo '{"success": false, "error": "Setup safety helper is missing; repair the installation"}'
        exit 0
    fi
    ARGS=("$SETUP_SAFETY" save-topology-config --request-json --target "$CONFIG_FILE" --managed-root "$WEB_ROOT" --managed-root "$LLDPQ_DIR" --direct-write-state-dir "$DIRECT_WRITE_STATE_DIR")
    RESULT=$(printf '%s' "$POST_DATA" | sudo -n -H -u "$LLDPQ_USER" /usr/bin/bash -c 'exec python3 "$@"' -- "${ARGS[@]}" 2>/dev/null)
    if [ -z "$RESULT" ]; then
        echo '{"success": false, "error": "Failed to validate or atomically save topology_config.yaml"}'
    else
        RESULT="$RESULT" python3 -c 'import json,os
r=json.loads(os.environ["RESULT"])
if r.get("success"):
    r["message"]=("Config saved through a journaled legacy direct-file mount"
                  if r.get("atomic") is False else "Config saved successfully")
print(json.dumps(r))' 2>/dev/null || echo "$RESULT"
    fi
else
    echo "{\"success\": false, \"error\": \"Invalid method\"}"
fi
