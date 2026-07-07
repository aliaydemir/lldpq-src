#!/usr/bin/env bash
# edit-devices.sh - Read/Write devices.yaml via CGI
# Called by nginx fcgiwrap

source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load config with fallback
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
LLDPQ_HOME="${LLDPQ_DIR:-$HOME/lldpq}"
SETUP_SAFETY="$(dirname "$0")/setup_safety.py"

# devices.yaml location
DEVICES_FILE="$LLDPQ_HOME/devices.yaml"

# Read request method
METHOD="${REQUEST_METHOD:-GET}"

# Output headers
echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo "X-Content-Type-Options: nosniff"
echo ""

if [ "$METHOD" = "GET" ]; then
    DEVICES_FILE="$DEVICES_FILE" python3 - <<'PY'
import hashlib, json, os
path = os.environ['DEVICES_FILE']
try:
    raw = open(path, 'rb').read()
    print(json.dumps({'success': True, 'content': raw.decode('utf-8'),
                      'revision': hashlib.sha256(raw).hexdigest(), 'exists': True}))
except FileNotFoundError:
    print(json.dumps({'success': True, 'content': '', 'exists': False,
                      'revision': hashlib.sha256(b'').hexdigest()}))
except Exception as exc:
    print(json.dumps({'success': False, 'error': 'Cannot read devices.yaml: ' + str(exc)}))
PY
    
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
    ARGS=("$SETUP_SAFETY" save-devices --request-json --target "$DEVICES_FILE" --parser "$LLDPQ_HOME/parse_devices.py" --managed-root "$LLDPQ_HOME")
    RESULT=$(printf '%s' "$POST_DATA" | sudo -n -H -u "$LLDPQ_USER" /usr/bin/bash -c 'exec python3 "$@"' -- "${ARGS[@]}" 2>/dev/null)
    if [ -z "$RESULT" ]; then
        echo '{"success": false, "error": "Failed to validate or atomically save devices.yaml"}'
    else
        RESULT="$RESULT" python3 -c 'import json,os
r=json.loads(os.environ["RESULT"])
if r.get("success"): r["message"]="devices.yaml saved successfully"
print(json.dumps(r))' 2>/dev/null || echo "$RESULT"
    fi
else
    echo "{\"success\": false, \"error\": \"Invalid method\"}"
fi
