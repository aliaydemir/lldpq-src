#!/usr/bin/env bash
# Public export of the latest AI analysis report: /ai/export_json.
#
# Streams /var/lib/lldpq/ai/analysis.json verbatim (the "analysis" field is
# the markdown report body; jq -r .analysis renders it).  Only the latest
# report exists — the AI pipeline overwrites this file each run.
#
# DELIBERATELY UNAUTHENTICATED (no auth-guard.sh): exposing the last analysis
# to automation without a browser session is the point of this endpoint.
# Note this is a wider posture than ai.html itself, which stays admin-only.

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

# Same resolution as html/ai-api.sh and bin/lldpq-ai-analyze.
AI_STATE_DIR="${AI_STATE_DIR:-/var/lib/lldpq/ai}"
ANALYSIS_FILE="$AI_STATE_DIR/analysis.json"

# Check directory traversability first: an untraversable state dir would make
# the -e test below fail and misreport a permissions problem as "no report".
# /var/lib/lldpq and /var/lib/lldpq/ai need g+x for www-data (install.sh
# guarantees this; a tightened deployment lands here instead of a wrong 404).
if [[ -d "$AI_STATE_DIR" && ! -x "$AI_STATE_DIR" ]]; then
    json_error "500 Internal Server Error" "AI state directory is not accessible by the web service"
fi
if [[ ! -e "$ANALYSIS_FILE" ]]; then
    json_error "404 Not Found" "No AI analysis has been generated yet"
fi
if [[ ! -r "$ANALYSIS_FILE" ]]; then
    json_error "500 Internal Server Error" "AI analysis file is not readable by the web service"
fi

MTIME_UTC=$(date -u -r "$ANALYSIS_FILE" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

printf 'Status: 200 OK\n'
printf 'Content-Type: application/json; charset=UTF-8\n'
printf 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0\n'
printf 'X-LLDPQ-Report-Created: %s\n\n' "$MTIME_UTC"
# The AI pipeline replaces analysis.json atomically, so a plain cat cannot
# observe a torn write; no validating double-read needed.
cat "$ANALYSIS_FILE"
exit 0
