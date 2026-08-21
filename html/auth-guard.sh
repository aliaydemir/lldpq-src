#!/bin/bash
# auth-guard.sh — shared session/role guard for backend APIs
#
# Usage at the top of an *-api.sh:
#   source "$(dirname "$0")/auth-guard.sh"
#   require_auth                 # any logged-in user (admin or operator)
#   require_admin                # admin only
#
# After require_auth/require_admin, these vars are set:
#   LLDPQ_AUTH_USER, LLDPQ_AUTH_ROLE
#
# Behavior:
#   - 401 if no/expired session
#   - 403 if admin required but role is not admin

LLDPQ_GUARD_SESSIONS_DIR="/var/lib/lldpq/sessions"

_guard_get_cookie() {
    # Anchor to the exact cookie name and take the first match only, so a
    # stale scoped cookie (e.g. old_lldpq_session or a Path-scoped duplicate)
    # cannot pollute the extracted token.
    echo "$HTTP_COOKIE" | tr ';' '\n' | grep -E '^[[:space:]]*lldpq_session=' | head -n1 | cut -d'=' -f2- | tr -d ' '
}

_guard_deny() {
    local code="$1"; shift
    local msg="$*"
    echo "Status: $code"
    echo "Content-Type: application/json"
    echo ""
    echo "{\"success\": false, \"error\": \"$msg\"}"
    exit 0
}

_guard_load_session() {
    [[ -n "$LLDPQ_AUTH_ROLE" ]] && return 0
    local token=$(_guard_get_cookie)
    if [[ ! "$token" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        _guard_deny 401 "Not authenticated"
    fi
    local f="$LLDPQ_GUARD_SESSIONS_DIR/$token"
    if [[ ! -f "$f" ]]; then
        _guard_deny 401 "Not authenticated"
    fi
    local expiry=$(head -1 "$f" 2>/dev/null)
    local now=$(date +%s)
    if [[ -z "$expiry" ]] || [[ "$now" -gt "$expiry" ]]; then
        rm -f "$f" 2>/dev/null
        _guard_deny 401 "Session expired"
    fi
    LLDPQ_AUTH_USER=$(sed -n '2p' "$f" 2>/dev/null)
    LLDPQ_AUTH_ROLE=$(sed -n '3p' "$f" 2>/dev/null)
    export LLDPQ_AUTH_USER LLDPQ_AUTH_ROLE
}

require_auth() {
    _guard_load_session
}

require_admin() {
    _guard_load_session
    if [[ "$LLDPQ_AUTH_ROLE" != "admin" ]]; then
        _guard_deny 403 "Admin privileges required"
    fi
}
