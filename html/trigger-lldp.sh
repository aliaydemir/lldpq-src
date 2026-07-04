#!/usr/bin/env bash
# LLDP Web Trigger Script
# Called by nginx via fcgiwrap

source "$(dirname "$0")/auth-guard.sh"
require_auth   # any logged-in user (operator or admin) may trigger an LLDP re-check (read-only refresh)

# Set HTTP headers
echo "Content-Type: application/json"
echo "Access-Control-Allow-Methods: POST, OPTIONS"
echo "Access-Control-Allow-Headers: Content-Type"
echo ""

# Handle CORS preflight
if [[ "$REQUEST_METHOD" == "OPTIONS" ]]; then
    echo '{"status": "ok", "message": "CORS preflight"}'
    exit 0
fi

# Create trigger file
TRIGGER_FILE="/tmp/.lldp_web_trigger"
TRIGGER_NOW=$(date +%s%N 2>/dev/null || true)
[[ "$TRIGGER_NOW" =~ ^[0-9]+$ ]] || TRIGGER_NOW="$(date +%s)000000000"
TRIGGER_VALUE="${TRIGGER_NOW}.$$.$RANDOM"
TRIGGER_TEMP="${TRIGGER_FILE}.tmp.$$.$RANDOM"

# Return JSON response
if printf '%s\n' "$TRIGGER_VALUE" > "$TRIGGER_TEMP" 2>/dev/null &&
   mv -f "$TRIGGER_TEMP" "$TRIGGER_FILE" 2>/dev/null; then
    echo '{"status": "started", "message": "LLDP check triggered automatically", "note": "Analysis will complete within 1 minute."}'
else
    rm -f "$TRIGGER_TEMP" 2>/dev/null || true
    echo '{"status": "error", "message": "Failed to create trigger file"}'
fi
