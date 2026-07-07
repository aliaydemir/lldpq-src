#!/usr/bin/env bash
# Session-gated delivery for static admin-only pages.

guard_bootstrap_error() {
    printf 'Status: 500 Internal Server Error\n'
    printf 'Content-Type: text/plain; charset=UTF-8\n'
    printf 'Cache-Control: no-store\n\n'
    printf 'Authentication guard is unavailable.\n'
    exit 0
}

AUTH_GUARD="$(dirname "$0")/auth-guard.sh"
[[ -r "$AUTH_GUARD" ]] || guard_bootstrap_error
source "$AUTH_GUARD" || guard_bootstrap_error
declare -F require_auth >/dev/null 2>&1 || guard_bootstrap_error
require_auth || guard_bootstrap_error

if [[ "${LLDPQ_AUTH_ROLE:-}" != "admin" ]]; then
    printf 'Status: 403 Forbidden\n'
    printf 'Content-Type: text/html; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n'
    printf 'X-Content-Type-Options: nosniff\n\n'
    printf '%s\n' '<!doctype html><html><head><meta charset="utf-8"><title>Access denied</title><style>html,body{height:100%;margin:0;background:#1e1e1e;color:#888;font:14px "Segoe UI",sans-serif}body{display:flex;align-items:center;justify-content:center}</style></head><body>Access denied. Admin only.</body></html>'
    exit 0
fi

case "${LLDPQ_ADMIN_PAGE:-}" in
    /setup.html|/provision.html|/ai.html|/device.html|/console.html|/commands.html|\
    /vlan-report.html|/vrf-report.html|/fabric-exit.html|/fabric-config.html|\
    /fabric-editor.html|/fabric-deploy.html|/lldpq-ztp-new-device-flow.html|\
    /fabric-scan-cache.json) ;;
    *)
        printf 'Status: 404 Not Found\n'
        printf 'Content-Type: text/plain; charset=UTF-8\n\n'
        printf 'Not found.\n'
        exit 0
        ;;
esac

PAGE="$(dirname "$0")/${LLDPQ_ADMIN_PAGE#/}"
if [[ ! -f "$PAGE" || -L "$PAGE" ]]; then
    printf 'Status: 404 Not Found\n'
    printf 'Content-Type: text/plain; charset=UTF-8\n\n'
    printf 'Not found.\n'
    exit 0
fi

if [[ "$LLDPQ_ADMIN_PAGE" == *.json ]]; then
    printf 'Content-Type: application/json; charset=UTF-8\n'
else
    printf 'Content-Type: text/html; charset=UTF-8\n'
fi
printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n'
printf 'X-Content-Type-Options: nosniff\n\n'
exec /bin/cat -- "$PAGE"
