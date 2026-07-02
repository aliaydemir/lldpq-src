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

# Load config
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"

# The lldpq-trigger daemon runs as LLDPQ_USER and handles the actual collection.
TRIGGER_FILE="/tmp/.configs_web_trigger"
echo "$(date +%s)" > "$TRIGGER_FILE" 2>/dev/null

if [ -f "$TRIGGER_FILE" ]; then
    echo '{"status": "started", "message": "Config collection queued", "note": "Configs will be available within 1-2 minutes."}'
else
    echo '{"status": "error", "message": "Failed to create config collection trigger"}'
fi
