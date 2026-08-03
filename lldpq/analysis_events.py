#!/usr/bin/env python3
"""Best-effort per-domain event sidecars for the Timeline page.

Analyzers publish compact, uniform event records into
monitor-results/events/<domain>.json so the Timeline page can merge every
domain client-side without touching the multi-megabyte history monoliths.

Contract (mirrors the lldp_neighbors.json sidecar): these files are
best-effort display enrichment, deliberately OUTSIDE the analyzer rollback
transaction — publish_events never raises, and a failed monitor run may leave
events from a generation that never published. Files are capped so a
fabric-wide fetch stays trivially small.

Event shape:
    {"ts": <epoch int>, "severity": "critical|warning|info",
     "device": str, "object": str, "kind": str, "detail": str}
"""

import json
import logging
import os
import tempfile
import time

EVENTS_SUBDIR = "events"
EVENTS_CAP = 500
RETENTION_SEC = 30 * 86400
DETAIL_MAX_LEN = 300

_SEVERITIES = ("critical", "warning", "info")


def _atomic_write(path, content):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=directory
    )
    try:
        # Web-served output: nginx must always retain read access.
        try:
            mode = os.stat(path).st_mode & 0o7777
        except FileNotFoundError:
            mode = 0o664
        os.fchmod(fd, mode | 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _normalize(event, now):
    if not isinstance(event, dict):
        return None
    try:
        ts = int(event.get("ts") or 0)
    except (TypeError, ValueError):
        return None
    if ts <= 0 or ts > now + 86400:
        return None
    severity = str(event.get("severity") or "info").lower()
    if severity not in _SEVERITIES:
        severity = "info"
    device = str(event.get("device") or "").strip()
    kind = str(event.get("kind") or "").strip()
    if not device or not kind:
        return None
    return {
        "ts": ts,
        "severity": severity,
        "device": device,
        "object": str(event.get("object") or "").strip(),
        "kind": kind,
        "detail": str(event.get("detail") or "").strip()[:DETAIL_MAX_LEN],
    }


def publish_events(result_dir, domain, new_events, cap=EVENTS_CAP, now=None):
    """Merge *new_events* into events/<domain>.json. Never raises.

    Re-reported events (log windows overlap between collection cycles)
    collapse on the full identity key, so callers can simply re-submit
    everything they currently see.
    """
    try:
        now = int(now if now is not None else time.time())
        path = os.path.join(os.path.abspath(result_dir), EVENTS_SUBDIR,
                            "%s.json" % domain)
        merged = {}
        try:
            with open(path, encoding="utf-8") as handle:
                payload = json.load(handle)
            existing = payload.get("events") if isinstance(payload, dict) else None
        except OSError:
            existing = None
        except ValueError as e:
            # Keep the unreadable sidecar as evidence instead of silently
            # rebuilding history from the current run alone.
            existing = None
            try:
                os.replace(path, path + ".bad")
                print("Warning: unreadable events sidecar %s (%s); "
                      "renamed to %s.json.bad" % (path, e, domain))
            except OSError:
                pass
        for event in (existing or []):
            normalized = _normalize(event, now)
            if normalized:
                key = (normalized["ts"], normalized["device"],
                       normalized["object"], normalized["kind"])
                merged[key] = normalized
        for event in (new_events or []):
            normalized = _normalize(event, now)
            if normalized:
                key = (normalized["ts"], normalized["device"],
                       normalized["object"], normalized["kind"])
                merged[key] = normalized
        cutoff = now - RETENTION_SEC
        events = sorted(
            (event for event in merged.values() if event["ts"] >= cutoff),
            key=lambda item: item["ts"],
        )[-max(1, int(cap)):]
        _atomic_write(path, json.dumps({
            "version": 1,
            "domain": domain,
            "updated_at": now,
            "events": events,
        }, separators=(",", ":")) + "\n")
        return True
    except Exception as e:
        logging.debug("publish_events failed: %s", e)
        return False
