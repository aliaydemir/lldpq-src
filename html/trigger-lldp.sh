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
echo "$(date +%s)" > "$TRIGGER_FILE" 2>/dev/null

# Return JSON response
if [ -f "$TRIGGER_FILE" ]; then
    echo '{"status": "started", "message": "LLDP check triggered automatically", "note": "Analysis will complete within 1 minute."}'
else
    echo '{"status": "error", "message": "Failed to create trigger file"}'
fi