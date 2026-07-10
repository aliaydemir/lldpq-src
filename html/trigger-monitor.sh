#!/usr/bin/env bash

# Trigger script for full or page-scoped monitoring analysis.
# No scope preserves the legacy full monitor.sh request. An allowlisted scope
# is consumed by lldpq-trigger and dispatched to monitor.sh --only <scope>.

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

# Parse the optional, deliberately small query contract. Values are fixed
# identifiers, so accepting percent-encoded or repeated scope parameters would
# add ambiguity without any useful capability.
TRIGGER_SCOPE="all"
SCOPE_SEEN=false
IFS='&' read -r -a QUERY_PARTS <<< "${QUERY_STRING:-}"
for query_part in "${QUERY_PARTS[@]}"; do
    case "$query_part" in
        "") ;;
        scope=*)
            if [[ "$SCOPE_SEEN" == "true" ]]; then
                echo '{"status":"error","message":"Scope may be specified only once"}'
                exit 1
            fi
            TRIGGER_SCOPE=${query_part#scope=}
            SCOPE_SEEN=true
            ;;
        *)
            echo '{"status":"error","message":"Unsupported query parameter"}'
            exit 1
            ;;
    esac
done
case "$TRIGGER_SCOPE" in
    all) SCOPE_CODE=0 ;;
    bgp) SCOPE_CODE=1 ;;
    evpn-mh) SCOPE_CODE=9 ;;
    duplicate) SCOPE_CODE=2 ;;
    flap) SCOPE_CODE=3 ;;
    optical) SCOPE_CODE=4 ;;
    ber) SCOPE_CODE=5 ;;
    pfc-ecn) SCOPE_CODE=6 ;;
    hardware) SCOPE_CODE=7 ;;
    logs) SCOPE_CODE=8 ;;
    *)
        echo '{"status":"error","message":"Unsupported analysis scope"}'
        exit 1
        ;;
esac

# Publish one atomic latest-value request for lldpq-trigger. The legacy token-
# only format remains readable by the daemon as scope=all.
TRIGGER_FILE="${LLDPQ_MONITOR_TRIGGER_FILE:-/tmp/.monitor_web_trigger}"
TRIGGER_NOW=$(date +%s%N 2>/dev/null || true)
[[ "$TRIGGER_NOW" =~ ^[0-9]+$ ]] || TRIGGER_NOW="$(date +%s)000000000"
# The numeric sentinel keeps the request acceptable to an older daemon during
# a rolling update: it will safely run a full analysis instead of dropping the
# request. The new daemon decodes the final scope code.
TRIGGER_VALUE="${TRIGGER_NOW}.$$.$RANDOM.7246.${SCOPE_CODE}"
TRIGGER_TEMP="${TRIGGER_FILE}.tmp.$$.$RANDOM"

# Try to create the trigger file
if printf '%s\n' "$TRIGGER_VALUE" > "$TRIGGER_TEMP" 2>/dev/null &&
   mv -f "$TRIGGER_TEMP" "$TRIGGER_FILE" 2>/dev/null; then
    printf '{"status":"success","trigger_id":"%s","scope":"%s","message":"Analysis triggered successfully"}\n' \
        "$TRIGGER_VALUE" "$TRIGGER_SCOPE"
else
    rm -f "$TRIGGER_TEMP" 2>/dev/null || true
    echo '{"status": "error", "message": "Failed to create trigger file"}'
    exit 1
fi
