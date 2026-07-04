#!/usr/bin/env bash

# Trigger script for monitor.sh
# This script is called by Nginx to trigger a monitor analysis

source "$(dirname "$0")/auth-guard.sh"
require_admin

# Set content type for JSON response
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

# Create trigger file for monitor.sh
TRIGGER_FILE="/tmp/.monitor_web_trigger"
TRIGGER_NOW=$(date +%s%N 2>/dev/null || true)
[[ "$TRIGGER_NOW" =~ ^[0-9]+$ ]] || TRIGGER_NOW="$(date +%s)000000000"
TRIGGER_VALUE="${TRIGGER_NOW}.$$.$RANDOM"
TRIGGER_TEMP="${TRIGGER_FILE}.tmp.$$.$RANDOM"

# Try to create the trigger file
if printf '%s\n' "$TRIGGER_VALUE" > "$TRIGGER_TEMP" 2>/dev/null &&
   mv -f "$TRIGGER_TEMP" "$TRIGGER_FILE" 2>/dev/null; then
    echo '{"status": "success", "message": "Monitor analysis triggered successfully"}'
else
    rm -f "$TRIGGER_TEMP" 2>/dev/null || true
    echo '{"status": "error", "message": "Failed to create trigger file"}'
    exit 1
fi
