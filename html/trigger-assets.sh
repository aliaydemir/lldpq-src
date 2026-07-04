#!/usr/bin/env bash
# Assets Web Trigger / status endpoint
# Called by nginx via fcgiwrap

source "$(dirname "$0")/auth-guard.sh"
require_auth   # operators and admins may request/read this read-only refresh

echo "Content-Type: application/json"
echo "Access-Control-Allow-Methods: GET, POST, OPTIONS"
echo "Access-Control-Allow-Headers: Content-Type, Cache-Control"
echo "Cache-Control: no-store, no-cache, must-revalidate, max-age=0"
echo "Pragma: no-cache"
echo "Expires: 0"
echo ""

json_escape() {
    local value=${1-}
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

json_error() {
    printf '{"status":"error","message":"%s"}\n' "$(json_escape "$*")"
    exit 0
}

if [[ "${REQUEST_METHOD:-GET}" == "OPTIONS" ]]; then
    echo '{"status":"ok","message":"CORS preflight"}'
    exit 0
fi

# The request and status files live outside the replaceable application tree,
# so an accepted browser request remains trackable through upgrades/restarts.
ASSETS_JOB_DIR="${LLDPQ_ASSETS_JOB_DIR:-/var/lib/lldpq/assets-jobs}"
if ! mkdir -p -m 2770 "$ASSETS_JOB_DIR" 2>/dev/null; then
    json_error "Assets job directory is unavailable"
fi
chmod 2770 "$ASSETS_JOB_DIR" 2>/dev/null || true

valid_token() {
    [[ "${1-}" =~ ^[a-f0-9]{32}$ ]]
}

snapshot_field() {
    local snapshot=$1 key=$2 line
    while IFS= read -r line; do
        if [[ "${line%%=*}" == "$key" ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <<< "$snapshot"
    return 1
}

numeric_or_zero() {
    [[ "${1-}" =~ ^[0-9]+$ ]] && printf '%s' "$1" || printf '0'
}

nullable_exit_code() {
    [[ "${1-}" =~ ^[0-9]+$ ]] && printf '%s' "$1" || printf 'null'
}

write_initial_status() {
    local token=$1 state=$2 created=$3 reason=$4 exit_code=${5-}
    local completed=0 temporary
    [[ "$state" == "failure" ]] && completed=$(date +%s)
    temporary=$(mktemp "$ASSETS_JOB_DIR/.${token}.status.XXXXXXXX") || return 1
    if ! {
        printf 'token=%s\n' "$token"
        printf 'state=%s\n' "$state"
        printf 'created_at=%s\n' "$created"
        printf 'updated_at=%s\n' "$(date +%s)"
        printf 'started_at=0\n'
        printf 'completed_at=%s\n' "$completed"
        printf 'attempt=0\n'
        printf 'exit_code=%s\n' "$exit_code"
        printf 'next_retry_at=0\n'
        printf 'retry_scheduled=false\n'
        printf 'worker_pid=0\n'
        printf 'reason=%s\n' "${reason//$'\n'/ }"
    } > "$temporary" || ! chmod 0660 "$temporary" || \
       ! mv -f "$temporary" "$ASSETS_JOB_DIR/$token.status"; then
        rm -f "$temporary" 2>/dev/null || true
        return 1
    fi
}

if [[ "${REQUEST_METHOD:-GET}" == "GET" ]]; then
    token=""
    if [[ "&${QUERY_STRING:-}&" =~ \&token=([a-f0-9]{32})\& ]]; then
        token=${BASH_REMATCH[1]}
    fi
    valid_token "$token" || json_error "Invalid or missing Assets job token"

    status_file="$ASSETS_JOB_DIR/$token.status"
    [[ -f "$status_file" ]] || json_error "Assets job was not found"

    # The worker atomically replaces this file.  Read one inode once so fields
    # from two lifecycle generations can never be mixed in one response.
    if ! status_snapshot=$(cat -- "$status_file" 2>/dev/null); then
        json_error "Assets job status is temporarily unavailable"
    fi
    stored_token=$(snapshot_field "$status_snapshot" token)
    state=$(snapshot_field "$status_snapshot" state)
    [[ "$stored_token" == "$token" ]] || json_error "Assets job status is invalid"
    case "$state" in
        queued|running|success|failure) ;;
        *) json_error "Assets job status is invalid" ;;
    esac

    created_at=$(numeric_or_zero "$(snapshot_field "$status_snapshot" created_at)")
    updated_at=$(numeric_or_zero "$(snapshot_field "$status_snapshot" updated_at)")
    started_at=$(numeric_or_zero "$(snapshot_field "$status_snapshot" started_at)")
    completed_at=$(numeric_or_zero "$(snapshot_field "$status_snapshot" completed_at)")
    attempt=$(numeric_or_zero "$(snapshot_field "$status_snapshot" attempt)")
    exit_code=$(nullable_exit_code "$(snapshot_field "$status_snapshot" exit_code)")
    next_retry_at=$(numeric_or_zero "$(snapshot_field "$status_snapshot" next_retry_at)")
    retry_scheduled=$(snapshot_field "$status_snapshot" retry_scheduled)
    [[ "$retry_scheduled" == "true" ]] || retry_scheduled=false
    reason=$(snapshot_field "$status_snapshot" reason)

    printf '{"status":"%s","token":"%s","created_at":%s,"updated_at":%s,' \
        "$state" "$token" "$created_at" "$updated_at"
    printf '"started_at":%s,"completed_at":%s,"attempt":%s,' \
        "$started_at" "$completed_at" "$attempt"
    printf '"exit_code":%s,"next_retry_at":%s,"retry_scheduled":%s,"reason":"%s"}\n' \
        "$exit_code" "$next_retry_at" "$retry_scheduled" "$(json_escape "$reason")"
    exit 0
fi

[[ "${REQUEST_METHOD:-}" == "POST" ]] || json_error "Method not allowed"

token=""
if [[ -r /proc/sys/kernel/random/uuid ]]; then
    token=$(tr -d '-' < /proc/sys/kernel/random/uuid 2>/dev/null || true)
fi
if ! valid_token "$token" && [[ -r /dev/urandom ]]; then
    token=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || true)
fi
valid_token "$token" || json_error "Could not allocate an Assets job token"

created_at=$(date +%s)
request_file="$ASSETS_JOB_DIR/$token.request"
request_tmp=$(mktemp "$ASSETS_JOB_DIR/.${token}.request.XXXXXXXX") || \
    json_error "Could not queue the Assets job"

if ! write_initial_status "$token" queued "$created_at" "Waiting for the Assets worker"; then
    rm -f "$request_tmp" 2>/dev/null || true
    json_error "Could not create Assets job status"
fi

if ! {
    printf 'token=%s\n' "$token"
    printf 'created_at=%s\n' "$created_at"
} > "$request_tmp" || ! chmod 0660 "$request_tmp" || \
   ! mv -f "$request_tmp" "$request_file"; then
    rm -f "$request_tmp" 2>/dev/null || true
    write_initial_status "$token" failure "$created_at" \
        "Could not publish the Assets request" 1 || true
    json_error "Could not queue the Assets job"
fi

printf '{"status":"started","token":"%s","message":"Assets refresh queued",' "$token"
printf '"note":"Poll this token for confirmed completion."}\n'
