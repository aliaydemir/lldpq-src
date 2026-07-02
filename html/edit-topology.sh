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

# topology.dot is stored in web root for www-data access
# A symlink in ~/lldpq/topology.dot points to this file
TOPOLOGY_FILE="$WEB_ROOT/topology.dot"

# Read request method
METHOD="${REQUEST_METHOD:-GET}"

# Output headers
echo "Content-Type: application/json"
echo ""

if [ "$METHOD" = "GET" ]; then
    # Read and return topology.dot content
    if [ -f "$TOPOLOGY_FILE" ]; then
        # Escape content for JSON
        CONTENT=$(cat "$TOPOLOGY_FILE" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        echo "{\"success\": true, \"content\": $CONTENT}"
    else
        echo "{\"success\": false, \"error\": \"File not found\"}"
    fi
    
elif [ "$METHOD" = "POST" ]; then
    # Read POST data from stdin
    # Use dd for reliable reading with CONTENT_LENGTH, fallback to cat
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        POST_DATA=$(cat)
    fi
    
    # Extract content from JSON using Python
    CONTENT=$(echo "$POST_DATA" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get("content", ""))
except:
    print("")
' 2>/dev/null)
    
    if [ -n "$CONTENT" ]; then
        # Write new content (try direct, fallback to sudo tee)
        if echo "$CONTENT" > "$TOPOLOGY_FILE" 2>/dev/null; then
            sudo -n chown "${LLDPQ_USER:-lldpq}:www-data" "$TOPOLOGY_FILE" 2>/dev/null
            sudo -n chmod 664 "$TOPOLOGY_FILE" 2>/dev/null
            echo "{\"success\": true, \"message\": \"Topology saved successfully\"}"
        elif echo "$CONTENT" | sudo -n tee "$TOPOLOGY_FILE" > /dev/null 2>&1; then
            sudo -n chown "${LLDPQ_USER:-lldpq}:www-data" "$TOPOLOGY_FILE" 2>/dev/null
            sudo -n chmod 664 "$TOPOLOGY_FILE" 2>/dev/null
            echo "{\"success\": true, \"message\": \"Topology saved successfully\"}"
        else
            echo "{\"success\": false, \"error\": \"Failed to write file\"}"
        fi
    else
        echo "{\"success\": false, \"error\": \"No content provided\"}"
    fi
else
    echo "{\"success\": false, \"error\": \"Invalid method\"}"
fi
