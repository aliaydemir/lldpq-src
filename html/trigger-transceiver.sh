#!/usr/bin/env bash

# Trigger script for collect-transceiver-fw.sh
# Called by nginx/fcgiwrap to request an on-demand transceiver firmware scan.
# This only writes an opaque token; lldpq-trigger (running as the LLDPq user)
# performs the actual collection. The collector enforces its own lock and
# minimum interval, so this endpoint never runs mlxlink itself.

source "$(dirname "$0")/auth-guard.sh"
require_admin

echo "Content-Type: application/json"
echo "Access-Control-Allow-Methods: POST, OPTIONS"
echo "Access-Control-Allow-Headers: Content-Type"
echo ""

# Handle OPTIONS request (preflight)
if [ "$REQUEST_METHOD" = "OPTIONS" ]; then
    echo ""
    exit 0
fi

# Only allow POST requests
if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"status": "error", "message": "Only POST method is allowed"}'
    exit 1
fi

# Create trigger file for lldpq-trigger -> collect-transceiver-fw.sh
TRIGGER_FILE="/tmp/.transceiver_web_trigger"
TRIGGER_NOW=$(date +%s%N 2>/dev/null || true)
[[ "$TRIGGER_NOW" =~ ^[0-9]+$ ]] || TRIGGER_NOW="$(date +%s)000000000"
TRIGGER_VALUE="${TRIGGER_NOW}.$$.$RANDOM"
TRIGGER_TEMP="${TRIGGER_FILE}.tmp.$$.$RANDOM"

if printf '%s\n' "$TRIGGER_VALUE" > "$TRIGGER_TEMP" 2>/dev/null &&
   mv -f "$TRIGGER_TEMP" "$TRIGGER_FILE" 2>/dev/null; then
    echo '{"status": "success", "message": "Transceiver firmware analysis triggered"}'
else
    rm -f "$TRIGGER_TEMP" 2>/dev/null || true
    echo '{"status": "error", "message": "Failed to create trigger file"}'
    exit 1
fi
