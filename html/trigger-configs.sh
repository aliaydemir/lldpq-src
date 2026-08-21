#!/usr/bin/env bash
# Config Collection Web Trigger Script
# Called by nginx via fcgiwrap - runs get-configs.sh in background

source "$(dirname "$0")/auth-guard.sh"
require_admin

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

# Only allow POST requests
if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"status": "error", "message": "Only POST method is allowed"}'
    exit 1
fi

# The lldpq-trigger daemon runs as LLDPQ_USER and handles the actual collection.
# The token lives under /var/lib/lldpq instead of sticky /tmp so an
# unprivileged local user cannot pre-create the fixed filename and pin the
# rename below to EPERM.
TRIGGER_DIR="/var/lib/lldpq/triggers"
if ! mkdir -p -m 2770 "$TRIGGER_DIR" 2>/dev/null; then
    echo '{"status": "error", "message": "Trigger directory is unavailable"}'
    exit 1
fi
TRIGGER_FILE="$TRIGGER_DIR/.configs_web_trigger"
TRIGGER_NOW=$(date +%s%N 2>/dev/null || true)
[[ "$TRIGGER_NOW" =~ ^[0-9]+$ ]] || TRIGGER_NOW="$(date +%s)000000000"
TRIGGER_VALUE="${TRIGGER_NOW}.$$.$RANDOM"
TRIGGER_TEMP="${TRIGGER_FILE}.tmp.$$.$RANDOM"

if printf '%s\n' "$TRIGGER_VALUE" > "$TRIGGER_TEMP" 2>/dev/null &&
   mv -f "$TRIGGER_TEMP" "$TRIGGER_FILE" 2>/dev/null; then
    echo '{"status": "started", "message": "Config collection queued", "note": "Configs will be available within 1-2 minutes."}'
else
    rm -f "$TRIGGER_TEMP" 2>/dev/null || true
    echo '{"status": "error", "message": "Failed to create config collection trigger"}'
fi
