#!/bin/bash
# Fabric Scan Cron Job - runs diff playbook daily
# Scheduled: 03:33

if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

CACHE_FILE="$WEB_ROOT/fabric-scan-cache.json"

cd "$ANSIBLE_DIR" || exit 1

# Run diff playbook and capture output
OUTPUT=$(ansible-playbook playbooks/diff_switch_configs.yaml 2>&1)
PLAYBOOK_STATUS=$?

# A failed scan must not overwrite the cache as "no pending devices"
if [[ $PLAYBOOK_STATUS -ne 0 ]]; then
    echo "fabric-scan-cron: diff playbook failed (exit $PLAYBOOK_STATUS); keeping existing cache" >&2
    printf '%s\n' "$OUTPUT" | tail -20 >&2
    exit 1
fi

# Parse pending devices from output
# Get valid hostnames from inventory for matching
VALID_HOSTS=""
if [[ -d "$ANSIBLE_DIR/inventory/host_vars" ]]; then
    VALID_HOSTS=$(ls "$ANSIBLE_DIR/inventory/host_vars/" 2>/dev/null | sed 's/\.yaml$//' | tr '\n' '|' | sed 's/|$//')
fi

PENDING=""
IN_SECTION=false
while IFS= read -r line; do
    if [[ "$line" == *"SWITCHES WITH CHANGES"* ]]; then
        IN_SECTION=true
        continue
    fi
    if [[ "$IN_SECTION" == true ]]; then
        if [[ "$line" == *"PLAY RECAP"* ]]; then
            break
        fi
        # Extract hostname - match any word followed by : and "change(s)"
        # Generic pattern: "✗ HOSTNAME: N change(s)" or "HOSTNAME: N changes"
        if [[ "$line" =~ ([A-Za-z0-9_.-]+):[[:space:]]*[0-9]+[[:space:]]+change ]]; then
            HOSTNAME="${BASH_REMATCH[1]}"
            # Validate against inventory if available
            if [[ -z "$VALID_HOSTS" ]] || [[ "$HOSTNAME" =~ ^($VALID_HOSTS)$ ]]; then
                [[ -n "$PENDING" ]] && PENDING="$PENDING,"
                PENDING="$PENDING\"$HOSTNAME\""
            fi
        fi
    fi
done <<< "$OUTPUT"

# Write JSON cache atomically so web readers never observe a partial file
TIMESTAMP=$(date +%s)000
TMP_FILE="$CACHE_FILE.tmp.$$"
if [[ -w "$CACHE_FILE" ]]; then
    echo "{\"timestamp\":$TIMESTAMP,\"pendingDevices\":[$PENDING]}" > "$TMP_FILE"
    chmod 664 "$TMP_FILE"
    mv -f "$TMP_FILE" "$CACHE_FILE"
else
    echo "{\"timestamp\":$TIMESTAMP,\"pendingDevices\":[$PENDING]}" | sudo tee "$TMP_FILE" > /dev/null
    sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$TMP_FILE"
    sudo chmod 664 "$TMP_FILE"
    sudo mv -f "$TMP_FILE" "$CACHE_FILE"
fi
