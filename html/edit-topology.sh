#!/usr/bin/env bash
# edit-topology.sh - Read/Write topology.dot via CGI
# Called by nginx fcgiwrap

source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load config with fallback
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
SETUP_SAFETY="$(dirname "$0")/setup_safety.py"

# topology.dot is stored in web root for www-data access
# A symlink in ~/lldpq/topology.dot points to this file
TOPOLOGY_FILE="$WEB_ROOT/topology.dot"

# Read request method
METHOD="${REQUEST_METHOD:-GET}"

# Output headers
echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo "X-Content-Type-Options: nosniff"
echo ""

if [ "$METHOD" = "GET" ]; then
    TOPOLOGY_FILE="$TOPOLOGY_FILE" python3 - <<'PY'
import hashlib, json, os
path = os.environ['TOPOLOGY_FILE']
try:
    raw = open(path, 'rb').read()
    print(json.dumps({'success': True, 'content': raw.decode('utf-8'),
                      'revision': hashlib.sha256(raw).hexdigest(), 'exists': True}))
except FileNotFoundError:
    print(json.dumps({'success': True, 'content': '', 'exists': False,
                      'revision': hashlib.sha256(b'').hexdigest()}))
except Exception as exc:
    print(json.dumps({'success': False, 'error': 'Cannot read topology.dot: ' + str(exc)}))
PY
    
elif [ "$METHOD" = "POST" ]; then
    # Read POST data from stdin
    # Use dd for reliable reading with CONTENT_LENGTH, fallback to cat
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        POST_DATA=$(cat)
    fi
    
    if [ ! -f "$SETUP_SAFETY" ]; then
        echo '{"success": false, "error": "Setup safety helper is missing; repair the installation"}'
        exit 0
    fi
    ARGS=("$SETUP_SAFETY" save-topology --request-json --target "$TOPOLOGY_FILE" --managed-root "$WEB_ROOT" --managed-root "$LLDPQ_DIR")
    # Newer installs provide a shared semantic parser. Keep Setup compatible
    # with older installs by treating it as an additive check when present.
    if [ -f "$LLDPQ_DIR/topology_edges.py" ]; then
        ARGS+=(--topology-parser "$LLDPQ_DIR/topology_edges.py")
    fi
    RESULT=$(printf '%s' "$POST_DATA" | sudo -n -H -u "$LLDPQ_USER" /usr/bin/bash -c 'exec python3 "$@"' -- "${ARGS[@]}" 2>/dev/null)
    if [ -z "$RESULT" ]; then
        echo '{"success": false, "error": "Failed to validate or atomically save topology.dot"}'
    else
        RESULT="$RESULT" python3 -c 'import json,os
r=json.loads(os.environ["RESULT"])
if r.get("success"): r["message"]="Topology saved successfully"
print(json.dumps(r))' 2>/dev/null || echo "$RESULT"
    fi
else
    echo "{\"success\": false, \"error\": \"Invalid method\"}"
fi
