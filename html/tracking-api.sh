#!/usr/bin/env bash
# Authenticated, read-only effective switch lifecycle endpoint.

guard_bootstrap_error() {
    printf 'Status: 500 Internal Server Error\n'
    printf 'Content-Type: application/json; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n\n'
    printf '{"success":false,"error":"Authentication guard is unavailable"}\n'
    exit 0
}

AUTH_GUARD="$(dirname "$0")/auth-guard.sh"
[[ -r "$AUTH_GUARD" ]] || guard_bootstrap_error
source "$AUTH_GUARD" || guard_bootstrap_error
declare -F require_auth >/dev/null 2>&1 || guard_bootstrap_error
require_auth || guard_bootstrap_error

json_error() {
    local status=$1 message=$2
    printf 'Status: %s\n' "$status"
    printf 'Content-Type: application/json; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n\n'
    python3 -c 'import json,sys; print(json.dumps({"success": False, "error": sys.argv[1]}))' \
        "$message"
    exit 0
}

[[ "${REQUEST_METHOD:-GET}" == "GET" ]] || \
    json_error "405 Method Not Allowed" "GET method required"

LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
if [[ -x "$LLDPQ_CONFIG_HELPER" ]]; then
    if ! LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
        --require-key LLDPQ_DIR 2>/dev/null); then
        json_error "500 Internal Server Error" \
            "Runtime configuration is missing or unreadable"
    fi
    eval "$LLDPQ_CONFIG_ASSIGNMENTS" || \
        json_error "500 Internal Server Error" "Runtime configuration is invalid"
    unset LLDPQ_CONFIG_ASSIGNMENTS
elif [[ -z "${LLDPQ_DIR:-}" ]]; then
    json_error "500 Internal Server Error" \
        "Required runtime configuration helper is missing"
fi

DEVICES_FILE="${LLDPQ_DEVICES_FILE:-$LLDPQ_DIR/devices.yaml}"
TRACKING_FILE="${LLDPQ_TRACKING_FILE:-$LLDPQ_DIR/tracking.yaml}"

if ! payload=$(PYTHONPATH="$LLDPQ_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$DEVICES_FILE" "$TRACKING_FILE" <<'PYTHON'
import json
import sys

try:
    from tracking_config import TrackingConfigError, get_tracking_payload
except Exception:
    print(json.dumps({"success": False, "error": "Tracking API support is unavailable"}))
    raise SystemExit(1)

try:
    result = get_tracking_payload(sys.argv[1], sys.argv[2])
except TrackingConfigError as error:
    print(json.dumps({"success": False, "error": str(error)}))
    raise SystemExit(1)
except Exception:
    print(json.dumps({"success": False, "error": "Tracking configuration could not be read"}))
    raise SystemExit(1)

print(json.dumps(result, separators=(",", ":")))
PYTHON
); then
    printf 'Status: 503 Service Unavailable\n'
    printf 'Content-Type: application/json; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n\n'
    printf '%s\n' "$payload"
    exit 0
fi

printf 'Content-Type: application/json; charset=UTF-8\n'
printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n\n'
printf '%s\n' "$payload"
