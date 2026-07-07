#!/usr/bin/env bash
# Authenticated, validated Assets snapshot API.

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

ASSETS_FILE="${LLDPQ_ASSETS_FILE:-$LLDPQ_DIR/assets.ini}"
PIPELINE_ASSETS_FILE="${LLDPQ_PIPELINE_ASSETS_FILE:-$LLDPQ_DIR/monitor-results/.pipeline-inputs/assets.ini}"
DEVICES_FILE="${LLDPQ_DEVICES_FILE:-$LLDPQ_DIR/devices.yaml}"

if ! payload=$(PYTHONPATH="$LLDPQ_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$ASSETS_FILE" "$PIPELINE_ASSETS_FILE" "$DEVICES_FILE" <<'PYTHON'
import json
from pathlib import Path
import sys

try:
    from assets_api import (
        AssetReportError,
        configured_max_age_seconds,
        load_assets_payload,
    )
except Exception:
    print(json.dumps({"success": False, "error": "Assets API support is unavailable"}))
    raise SystemExit(1)

assets_candidates = []
for candidate in sys.argv[1:3]:
    resolved = str(Path(candidate))
    if resolved not in assets_candidates:
        assets_candidates.append(resolved)

errors = []
for candidate in assets_candidates:
    try:
        result = load_assets_payload(
            candidate,
            sys.argv[3],
            max_age_seconds=configured_max_age_seconds(),
        )
    except AssetReportError as error:
        errors.append(str(error))
        continue
    except Exception:
        errors.append("Assets validation failed")
        continue
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0)

message = errors[0] if errors else "Assets report is unavailable"
print(json.dumps({"success": False, "error": message}))
raise SystemExit(1)
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
