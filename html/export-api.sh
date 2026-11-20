#!/usr/bin/env bash
# Public export index: /export_json.
# Enumerates every machine-readable export endpoint with freshness data so
# automation can discover reports (curl http://<host>/export_json | jq).
#
# DELIBERATELY UNAUTHENTICATED (no auth-guard.sh): the index only reveals
# report names, URLs, timestamps and headline counts — all derived from data
# the web tree already serves publicly.

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

AI_STATE_DIR="${AI_STATE_DIR:-/var/lib/lldpq/ai}"
export WEB_ROOT AI_STATE_DIR

PYTHONPATH="$LLDPQ_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 <<'PYTHON'
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

NO_STORE = "Cache-Control: no-store, no-cache, must-revalidate, max-age=0"
JSON_TYPE = "Content-Type: application/json; charset=utf-8"

# Reads only the small export/summary JSONs, never the multi-MB HTML reports;
# anything larger than this is not an index-grade artifact.
MAX_INDEX_READ_BYTES = 8 * 1024 * 1024


def respond(status, body):
    head = "\n".join([f"Status: {status}", JSON_TYPE, NO_STORE]) + "\n\n"
    sys.stdout.buffer.write(head.encode("utf-8") + body)


def iso_utc(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def read_small_json(path):
    try:
        if path.stat().st_size > MAX_INDEX_READ_BYTES:
            return None
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, UnicodeError, ValueError):
        return None


try:
    web_root = Path(os.environ["WEB_ROOT"])
    monitor_dir = web_root / "monitor-results"

    # --- monitor pipeline freshness -------------------------------------
    manifest = read_small_json(monitor_dir / ".lldpq-current.json") or {}
    stale_marker = (monitor_dir / ".lldpq-stale").exists()
    completed_at = manifest.get("completed_at")
    max_age = manifest.get("max_age_seconds")
    aged_out = False
    if completed_at and isinstance(max_age, (int, float)):
        try:
            # Python <= 3.10 fromisoformat rejects the Z suffix.
            completed = datetime.fromisoformat(
                str(completed_at).replace("Z", "+00:00")
            )
            if completed.tzinfo is None:
                completed = completed.replace(tzinfo=timezone.utc)
            aged_out = (
                datetime.now(timezone.utc) - completed
            ).total_seconds() > max_age
        except ValueError:
            pass
    monitor = {
        "status": manifest.get("status"),
        "completed_at": completed_at,
        "pipeline_complete": manifest.get("pipeline_complete"),
        "max_age_seconds": max_age,
        "analyses": manifest.get("analyses"),
        "skipped": manifest.get("skipped"),
        "stale": bool(stale_marker or aged_out),
    }

    reports = []

    # --- LLDP wiring results (published outside the monitor pipeline) ---
    lldp_entry = {
        "report": "lldp_results",
        "title": "LLDP Wiring Results",
        "export_json": "/lldp_results/export_json",
        "export_csv": "/lldp_results/export_csv",
        "available": False,
        "updated": None,
    }
    lldp_file = web_root / "lldp_results.ini"
    if lldp_file.is_file():
        lldp_entry["available"] = True
        lldp_entry["updated"] = iso_utc(lldp_file.stat().st_mtime)
        try:
            from lldp_report import parse_created_header

            with open(lldp_file, encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        created = parse_created_header(line)
                        lldp_entry["updated"] = iso_utc(created.timestamp())
                        break
        except Exception:
            pass  # mtime already set; header parse is best-effort here
    reports.append(lldp_entry)

    # --- monitor-domain exports ------------------------------------------
    try:
        from export_artifacts import EXPORT_SCHEMAS

        monitor_domains = sorted(
            set(EXPORT_SCHEMAS) - {"lldp_results", "transceiver"}
        )
    except Exception:
        monitor_domains = []
    for domain in monitor_domains:
        entry = {
            "report": domain,
            "export_json": f"/{domain}/export_json",
            "export_csv": f"/{domain}/export_csv",
            "available": False,
            "updated": None,
        }
        export_file = monitor_dir / "export" / f"{domain}.json"
        # Availability/mtime come from stat so a large-but-valid export is
        # never misreported; the parse below only enriches the entry.
        try:
            entry["available"] = export_file.is_file()
            if entry["available"]:
                entry["updated"] = iso_utc(export_file.stat().st_mtime)
        except OSError:
            pass
        payload = read_small_json(export_file)
        if payload is not None:
            entry["updated"] = iso_utc(payload.get("generated_at")) or entry["updated"]
            entry["collection_status"] = payload.get("collection_status")
            entry["counts"] = payload.get("counts")
            entry["row_count"] = payload.get(
                "row_count", len(payload.get("rows") or [])
            )
        reports.append(entry)

    # --- transceiver inventory export ------------------------------------
    entry = {
        "report": "transceiver",
        "export_json": "/transceiver/export_json",
        "export_csv": "/transceiver/export_csv",
        "available": False,
        "updated": None,
    }
    transceiver_file = monitor_dir / "transceiver-export.json"
    try:
        entry["available"] = transceiver_file.is_file()
        if entry["available"]:
            entry["updated"] = iso_utc(transceiver_file.stat().st_mtime)
    except OSError:
        pass
    payload = read_small_json(transceiver_file)
    if payload is not None:
        entry["updated"] = iso_utc(payload.get("generated_at")) or entry["updated"]
        entry["counts"] = payload.get("counts")
        entry["row_count"] = payload.get(
            "row_count", len(payload.get("rows") or [])
        )
    reports.append(entry)

    # --- predictive health export ----------------------------------------
    pred_entry = {
        "report": "predictive",
        "title": "Predictive Health Analysis",
        "export_json": "/predictive/export_json",
        "export_csv": None,
        "available": False,
        "updated": None,
    }
    pred_file = monitor_dir / "export" / "predictive.json"
    try:
        pred_entry["available"] = pred_file.is_file()
        if pred_entry["available"]:
            pred_entry["updated"] = iso_utc(pred_file.stat().st_mtime)
    except OSError:
        pass
    pred_payload = read_small_json(pred_file)
    if pred_payload is not None:
        pred_entry["updated"] = iso_utc(pred_payload.get("generated_at")) or pred_entry["updated"]
        pred_entry["counts"] = pred_payload.get("counts")
        pred_entry["row_count"] = len(pred_payload.get("rows") or [])
    reports.append(pred_entry)

    # --- latest AI analysis ------------------------------------------------
    # Must match ai-export-api.sh's contract: install.sh and Docker seed
    # analysis.json with {}, which /ai/export_json serves as 503 no-report.
    # Only a populated report carrying both "timestamp" and "analysis" is
    # available.
    entry = {
        "report": "ai",
        "title": "Latest AI Analysis",
        "export_json": "/ai/export_json",
        "export_csv": None,
        "available": False,
        "updated": None,
    }
    analysis_file = Path(os.environ["AI_STATE_DIR"]) / "analysis.json"
    try:
        if analysis_file.is_file():
            payload = read_small_json(analysis_file)
            if isinstance(payload, dict) and "timestamp" in payload and "analysis" in payload:
                entry["available"] = True
                entry["updated"] = iso_utc(analysis_file.stat().st_mtime)
    except OSError:
        pass
    reports.append(entry)

    body = json.dumps(
        {
            "success": True,
            "schema_version": 1,
            "service": "lldpq-export",
            "generated_at": iso_utc(time.time()),
            "monitor": monitor,
            "reports": reports,
        }
    ).encode("utf-8") + b"\n"
    respond("200 OK", body)
except Exception as exc:
    respond(
        "500 Internal Server Error",
        json.dumps({"success": False, "error": f"export index failed: {exc}"}).encode(
            "utf-8"
        )
        + b"\n",
    )
PYTHON
