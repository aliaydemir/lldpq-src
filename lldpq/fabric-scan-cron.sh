#!/bin/bash
# Fabric Scan Cron Job - runs diff playbook daily
# Scheduled: 03:33

if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

CACHE_FILE="$WEB_ROOT/fabric-scan-cache.json"
CACHE_DIR=$(dirname "$CACHE_FILE")

# Publication stages a sibling temporary inside the cache directory and renames
# it, so it only needs privilege when this account cannot write to that
# directory. Decide once, before the playbook runs: the previous check tested the
# cache file itself, which is the wrong object for a create-and-rename and took
# the escalating branch whenever the file was merely absent. Escalation is never
# interactive because this runs from cron, where a bare sudo has no tty.
declare -a LLDPQ_PRIV=()
if [[ ! -w "$CACHE_DIR" ]]; then
    if sudo -n true 2>/dev/null; then
        LLDPQ_PRIV=(sudo -n)
    else
        echo "fabric-scan-cron: $CACHE_DIR is not writable by $(id -un) and passwordless sudo is unavailable" >&2
        exit 1
    fi
fi

cd "$ANSIBLE_DIR" || exit 1

# Use the same lock as Fabric edits, deploys, telemetry and provisioning.
FABRIC_LOCK_DIR="${FABRIC_LOCK_DIR:-$WEB_ROOT/.locks}"
FABRIC_LOCK_FILE="${FABRIC_LOCK_FILE:-$FABRIC_LOCK_DIR/fabric-api.lock}"
mkdir -p "$FABRIC_LOCK_DIR" || exit 1
chgrp "${FABRIC_LOCK_GROUP:-www-data}" "$FABRIC_LOCK_DIR" 2>/dev/null || true
chmod 2770 "$FABRIC_LOCK_DIR" 2>/dev/null || true
(umask 0007; : >>"$FABRIC_LOCK_FILE") || exit 1
chmod 660 "$FABRIC_LOCK_FILE" 2>/dev/null || true
exec 9>>"$FABRIC_LOCK_FILE" || exit 1
if ! flock -n 9; then
    echo "fabric-scan-cron: config operation in progress; keeping existing cache" >&2
    exit 75
fi
if [[ -f "$ANSIBLE_DIR/.lldpq-write-journal.json" ]]; then
    python3 "${LLDPQ_DIR:-$(dirname "$0")}/fabric_transactions.py" "$ANSIBLE_DIR" || exit 1
fi

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
    VALID_HOSTS=$(find "$ANSIBLE_DIR/inventory/host_vars" -maxdepth 1 -type f \( -name '*.yaml' -o -name '*.yml' \) -exec basename {} \; | sed -E 's/\.ya?ml$//')
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
            if [[ -z "$VALID_HOSTS" ]] || printf '%s\n' "$VALID_HOSTS" | grep -Fxq -- "$HOSTNAME"; then
                [[ -n "$PENDING" ]] && PENDING="$PENDING,"
                PENDING="$PENDING\"$HOSTNAME\""
            fi
        fi
    fi
done <<< "$OUTPUT"

# Write JSON cache atomically so web readers never observe a partial file
TIMESTAMP=$(date +%s)000
TMP_FILE="$CACHE_FILE.tmp.$$"
echo "{\"timestamp\":$TIMESTAMP,\"pendingDevices\":[$PENDING]}" | \
    "${LLDPQ_PRIV[@]}" tee "$TMP_FILE" > /dev/null
"${LLDPQ_PRIV[@]}" chown "${LLDPQ_USER:-$(whoami)}:www-data" "$TMP_FILE"
"${LLDPQ_PRIV[@]}" chmod 664 "$TMP_FILE"
"${LLDPQ_PRIV[@]}" mv -f "$TMP_FILE" "$CACHE_FILE"
