#!/usr/bin/env bash
# Public LLDP wiring-results export (JSON / CSV).
# Served at /lldp_results/export_json and /lldp_results/export_csv; the format
# is selected by the LLDPQ_EXPORT_FORMAT fastcgi param set in the nginx site.
#
# DELIBERATELY UNAUTHENTICATED (no auth-guard.sh): both endpoints are derived
# views of /lldp_results.ini, which nginx already serves statically without a
# session, and they exist precisely for headless automation (curl | jq).
# If that posture ever changes, source auth-guard.sh + require_auth here and
# pass HTTP_COOKIE through in the nginx location blocks.

json_error() {
    local status=$1 message=$2
    printf 'Status: %s\n' "$status"
    if [[ "$status" == "405 Method Not Allowed" ]]; then
        printf 'Allow: GET, HEAD\n'
    fi
    printf 'Content-Type: application/json; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n\n'
    python3 -c 'import json,sys; print(json.dumps({"success": False, "error": sys.argv[1]}))' \
        "$message"
    exit 0
}

case "${REQUEST_METHOD:-GET}" in
    GET|HEAD) ;;
    *) json_error "405 Method Not Allowed" "GET method required" ;;
esac

FORMAT="${LLDPQ_EXPORT_FORMAT:-json}"
case "$FORMAT" in
    json|csv) ;;
    *) json_error "500 Internal Server Error" "Unsupported export format" ;;
esac

# Load allowlisted config data through the fixed, root-owned parser.  A partial
# upgrade must fail explicitly instead of guessing paths.
LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
if [[ ! -x "$LLDPQ_CONFIG_HELPER" ]]; then
    json_error "500 Internal Server Error" "LLDPq runtime configuration is unavailable"
fi
if ! LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
    --require-key LLDPQ_DIR --require-key WEB_ROOT 2>/dev/null); then
    json_error "500 Internal Server Error" "LLDPq runtime configuration is unavailable"
fi
if ! eval "$LLDPQ_CONFIG_ASSIGNMENTS"; then
    json_error "500 Internal Server Error" "LLDPq runtime configuration is invalid"
fi
unset LLDPQ_CONFIG_ASSIGNMENTS

REPORT_FILE="$WEB_ROOT/lldp_results.ini"
if [[ ! -r "$REPORT_FILE" ]]; then
    printf 'Status: 503 Service Unavailable\n'
    printf 'Content-Type: application/json; charset=UTF-8\n'
    printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n'
    printf 'Retry-After: 60\n\n'
    printf '%s\n' '{"success": false, "error": "lldp_results.ini is not published yet; wait for the next collection run"}'
    exit 0
fi

export REPORT_FILE FORMAT
PYTHONPATH="$LLDPQ_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 <<'PYTHON'
import json
import os
import re
import sys

NO_STORE = "Cache-Control: no-store, no-cache, must-revalidate, max-age=0"
JSON_TYPE = "Content-Type: application/json; charset=utf-8"


def respond(status, headers, body):
    # The whole response is assembled before the first byte is written, so a
    # failure can never leave a torn header block on the socket.
    head = "\n".join([f"Status: {status}", *headers]) + "\n\n"
    sys.stdout.buffer.write(head.encode("utf-8") + body)


def respond_error(status, message):
    body = json.dumps({"success": False, "error": message}).encode("utf-8") + b"\n"
    respond(status, [JSON_TYPE, NO_STORE], body)


try:
    import lldp_export
    from lldp_report import LLDPReportError, load_lldp_report
except Exception:
    respond_error("500 Internal Server Error", "LLDP export support is unavailable")
    raise SystemExit(0)

try:
    report = load_lldp_report(os.environ["REPORT_FILE"])
except (LLDPReportError, OSError, UnicodeError) as exc:
    respond_error("500 Internal Server Error", f"LLDP report is unreadable: {exc}")
    raise SystemExit(0)

created = lldp_export.created_stamp(report)
common = [NO_STORE, f"X-LLDPQ-Report-Created: {created}"]

try:
    if os.environ.get("FORMAT") == "csv":
        body = lldp_export.build_csv(report).encode("utf-8")
        stamp = re.sub(r"[^0-9A-Za-z._-]", "_", created)
        headers = [
            "Content-Type: text/csv; charset=utf-8",
            f'Content-Disposition: attachment; filename="LLDP_Report_{stamp}.csv"',
            *common,
        ]
    else:
        payload = lldp_export.build_payload(report)
        body = json.dumps(payload).encode("utf-8") + b"\n"
        headers = [JSON_TYPE, *common]
except Exception as exc:
    respond_error("500 Internal Server Error", f"LLDP export failed: {exc}")
    raise SystemExit(0)

respond("200 OK", headers, body)
PYTHON
