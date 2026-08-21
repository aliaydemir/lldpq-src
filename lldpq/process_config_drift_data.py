#!/usr/bin/env python3
"""
Config-Drift analyzer for LLDPq.

Tracks changes to the collected device configurations over time.  get-configs
publishes exactly one current `nv config show -o commands` snapshot per device
($WEB_ROOT/configs/<host>.txt) and overwrites it in place, so this analyzer
owns the history: it keeps a per-device baseline copy, diffs the current
snapshot against it on every run, and records drift events (who changed, when
it was detected, what lines were added/removed).

Local-only analyzer: no remote collection of its own.

Inputs
    $WEB_ROOT/configs/<host>.txt         current nv-set command export
    devices.yaml                         managed device inventory

State / outputs (all under monitor-results/)
    config-drift-data/baseline/<host>.txt   last-seen config per device
    config-drift-data/config_drift_state.json
    config_drift_history.json                drift event log (pruned)
    config-drift-analysis.html               report page
    summary/config-drift-summary.json        dashboard summary
    export/config-drift.{json,csv}           public export

Copyright (c) 2024 LLDPq Project - MIT License
"""

import difflib
import hashlib
import html
import json
import os
import re
import sys
import tempfile
import time

import analysis_events
import export_artifacts

try:
    from parse_devices import get_all_devices, load_devices_yaml
except ImportError:  # Source-tree imports used by unit tests.
    from lldpq.parse_devices import get_all_devices, load_devices_yaml

RESULT_DIR = "monitor-results"
STATE_SUBDIR = "config-drift-data"
BASELINE_SUBDIR = "baseline"
STATE_FILE = "config_drift_state.json"
HISTORY_FILE = "config_drift_history.json"
OUTPUT_HTML = "config-drift-analysis.html"

HISTORY_RETENTION_SEC = 90 * 86400   # keep drift events for 90 days
HISTORY_MAX_EVENTS = 5000            # hard cap regardless of age
EVENT_DIFF_MAX_LINES = 200           # unified-diff excerpt stored per event
EXPORT_MAX_EVENTS = 1000             # newest events published in the export

# Same filename contract get-configs.sh enforces before publishing.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._()-]{0,252}$")


def _atomic_write(path, content):
    """Write text to *path* atomically (tempfile + fsync + os.replace).

    A concurrent web reader (or a mid-write kill) never observes a truncated
    or empty file. Local copy of the repo-wide pattern; a per-file helper is
    used deliberately so parallel fixers do not collide on a shared module.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=directory
    )
    try:
        # Web-served output: nginx must always retain read access, so lift
        # mkstemp's private 0600 (and any inherited restrictive mode).
        mode = (os.stat(path).st_mode & 0o7777) if os.path.exists(path) else 0o664
        os.fchmod(fd, mode | 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def get_configs_dir():
    """Resolve the collected-config directory ($WEB_ROOT/configs)."""
    override = os.environ.get("LLDPQ_CONFIG_DRIFT_CONFIGS_DIR")
    if override:
        return override
    web_root = "/var/www/html"
    try:
        with open("/etc/lldpq.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("WEB_ROOT="):
                    candidate = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if candidate:
                        web_root = candidate
                    break
    except OSError:
        pass
    return os.path.join(web_root, "configs")


def load_managed_devices(script_dir):
    """Managed `devices:` hostnames only, never endpoint_hosts."""
    config = load_devices_yaml(os.path.join(script_dir, "devices.yaml"))
    return [hostname for _addr, _user, hostname, _role in get_all_devices(config)]


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return dict(default)
        return payload
    except (OSError, ValueError):
        return dict(default)


def _read_config_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _diff_stats(previous_lines, current_lines):
    """Unified diff between two line lists: (added, removed, excerpt_lines)."""
    diff_lines = list(difflib.unified_diff(
        previous_lines, current_lines,
        fromfile="previous", tofile="current", lineterm="",
    ))
    added = sum(1 for line in diff_lines
                if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff_lines
                  if line.startswith("-") and not line.startswith("---"))
    excerpt = diff_lines[:EVENT_DIFF_MAX_LINES]
    truncated = len(diff_lines) > len(excerpt)
    return added, removed, excerpt, truncated


def _first_change_summary(excerpt):
    """First meaningful +/- line of the diff, as a compact event summary."""
    for line in excerpt:
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith(("+", "-")):
            text = line[1:].strip()
            if text:
                sign = line[0]
                return ("%s %s" % (sign, text))[:160]
    return "content changed"


class ConfigDriftAnalyzer:
    def __init__(self, result_dir=RESULT_DIR, configs_dir=None, now=None):
        self.result_dir = os.path.abspath(result_dir)
        self.configs_dir = configs_dir or get_configs_dir()
        self.state_dir = os.path.join(self.result_dir, STATE_SUBDIR)
        self.baseline_dir = os.path.join(self.state_dir, BASELINE_SUBDIR)
        self.state_path = os.path.join(self.state_dir, STATE_FILE)
        self.history_path = os.path.join(self.result_dir, HISTORY_FILE)
        self.now = int(now if now is not None else time.time())
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.managed_devices = load_managed_devices(script_dir)
        self.state = _load_json(self.state_path, {"version": 1, "hosts": {}})
        if not isinstance(self.state.get("hosts"), dict):
            self.state["hosts"] = {}
        history = _load_json(self.history_path, {"version": 1, "events": []})
        events = history.get("events")
        self.events = [event for event in events if isinstance(event, dict)] \
            if isinstance(events, list) else []
        self.new_events = 0
        self.baselines_created = 0
        self.devices_missing = []
        self.device_rows = []
        self.configs_dir_available = os.path.isdir(self.configs_dir)
        self._pending_baselines = []

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self):
        hosts_state = self.state["hosts"]
        managed = [name for name in self.managed_devices
                   if HOSTNAME_RE.match(name)]
        managed_set = set(managed)

        # Retired devices: drop baseline + state so a re-added device is
        # treated as new.  get-configs archives removed hosts separately.
        for host in sorted(set(hosts_state) - managed_set):
            hosts_state.pop(host, None)
            try:
                os.unlink(os.path.join(self.baseline_dir, "%s.txt" % host))
            except OSError:
                pass

        for host in sorted(managed, key=str.casefold):
            config_path = os.path.join(self.configs_dir, "%s.txt" % host)
            entry = hosts_state.get(host)
            if not os.path.isfile(config_path):
                self.devices_missing.append(host)
                self._append_device_row(host, entry, status="missing",
                                        collected_at=None)
                continue
            try:
                stat_result = os.stat(config_path)
                content = _read_config_text(config_path)
            except OSError:
                self.devices_missing.append(host)
                self._append_device_row(host, entry, status="missing",
                                        collected_at=None)
                continue
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            collected_at = int(stat_result.st_mtime)
            line_count = content.count("\n") + (1 if content and
                                                not content.endswith("\n") else 0)
            if entry is None or not isinstance(entry, dict):
                # First sighting: establish the baseline silently (individual
                # "baseline" events would flood the log on a fresh install).
                self._write_baseline(host, content)
                entry = {
                    "sha256": digest,
                    "collected_at": collected_at,
                    "lines": line_count,
                    "size": stat_result.st_size,
                    "first_seen_at": self.now,
                    "last_changed_at": None,
                }
                hosts_state[host] = entry
                self.baselines_created += 1
            elif entry.get("sha256") != digest:
                previous = self._read_baseline(host)
                added, removed, excerpt, truncated = _diff_stats(
                    previous.splitlines(), content.splitlines())
                self.events.append({
                    "ts": self.now,
                    "host": host,
                    "type": "modified",
                    "added": added,
                    "removed": removed,
                    "collected_at": collected_at,
                    "summary": _first_change_summary(excerpt),
                    "diff": excerpt,
                    "diff_truncated": truncated,
                })
                self.new_events += 1
                entry.update({
                    "sha256": digest,
                    "collected_at": collected_at,
                    "lines": line_count,
                    "size": stat_result.st_size,
                    "last_changed_at": self.now,
                })
                self._pending_baselines.append((host, content))
            else:
                entry["collected_at"] = collected_at
            self._append_device_row(host, entry, status="current",
                                    collected_at=collected_at)

        self._prune_events()

    def _append_device_row(self, host, entry, status, collected_at):
        entry = entry if isinstance(entry, dict) else {}
        changes_7d = sum(1 for event in self.events
                         if event.get("host") == host
                         and event.get("type") == "modified"
                         and self.now - int(event.get("ts") or 0) <= 7 * 86400)
        changes_30d = sum(1 for event in self.events
                          if event.get("host") == host
                          and event.get("type") == "modified"
                          and self.now - int(event.get("ts") or 0) <= 30 * 86400)
        self.device_rows.append({
            "host": host,
            "status": status,
            "lines": entry.get("lines"),
            "size": entry.get("size"),
            "collected_at": collected_at,
            "last_changed_at": entry.get("last_changed_at"),
            "changes_7d": changes_7d,
            "changes_30d": changes_30d,
        })

    def _baseline_path(self, host):
        return os.path.join(self.baseline_dir, "%s.txt" % host)

    def _read_baseline(self, host):
        try:
            with open(self._baseline_path(host), "r", encoding="utf-8",
                      errors="replace") as handle:
                return handle.read()
        except OSError:
            return ""

    def _write_baseline(self, host, content):
        _atomic_write(self._baseline_path(host), content)

    def _prune_events(self):
        cutoff = self.now - HISTORY_RETENTION_SEC
        pruned = [event for event in self.events
                  if int(event.get("ts") or 0) >= cutoff]
        pruned.sort(key=lambda event: int(event.get("ts") or 0))
        self.events = pruned[-HISTORY_MAX_EVENTS:]

    # ------------------------------------------------------------------
    # Persistence + report
    # ------------------------------------------------------------------
    def collection_status(self):
        if not self.configs_dir_available:
            return "unavailable"
        with_config = sum(1 for row in self.device_rows
                          if row["status"] == "current")
        if not with_config:
            return "unavailable"
        if self.devices_missing:
            return "partial"
        return "current"

    def summary_counts(self):
        changed_24h = len({event.get("host") for event in self.events
                           if event.get("type") == "modified"
                           and self.now - int(event.get("ts") or 0) <= 86400})
        changed_7d = len({event.get("host") for event in self.events
                          if event.get("type") == "modified"
                          and self.now - int(event.get("ts") or 0) <= 7 * 86400})
        return {
            "devices_expected": len(self.device_rows),
            "devices_with_config": sum(1 for row in self.device_rows
                                       if row["status"] == "current"),
            "devices_missing": len(self.devices_missing),
            "changed_24h": changed_24h,
            "changed_7d": changed_7d,
            "events_recorded": len(self.events),
            "new_events": self.new_events,
            "baselines_created": self.baselines_created,
        }

    def save_state(self):
        os.makedirs(self.baseline_dir, exist_ok=True)
        self.state["last_update"] = self.now
        _atomic_write(self.state_path,
                      json.dumps(self.state, separators=(",", ":")) + "\n")
        _atomic_write(self.history_path, json.dumps(
            {"version": 1, "last_update": self.now, "events": self.events},
            separators=(",", ":")) + "\n")
        # Timeline sidecar (best-effort; publish_events never raises).
        analysis_events.publish_events(self.result_dir, "config-drift", [
            {
                "ts": event.get("ts"),
                "severity": "warning",
                "device": event.get("host"),
                "object": "config",
                "kind": "config-modified",
                "detail": "+%s/−%s lines — %s" % (
                    event.get("added"), event.get("removed"),
                    event.get("summary")),
            }
            for event in self.events
            if event.get("type") == "modified"
        ], now=self.now)

    def export_rows(self):
        rows = []
        for event in sorted(self.events,
                            key=lambda item: int(item.get("ts") or 0),
                            reverse=True)[:EXPORT_MAX_EVENTS]:
            rows.append({
                "detected_at": _iso(event.get("ts")),
                "device": event.get("host"),
                "change_type": event.get("type"),
                "lines_added": event.get("added"),
                "lines_removed": event.get("removed"),
                "collected_at": _iso(event.get("collected_at")),
                "summary": event.get("summary"),
            })
        return rows

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def export_html(self, output_file):
        now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.now))
        status = self.collection_status()
        counts = self.summary_counts()

        machine_summary = (
            '<div data-analysis-summary="config-drift"'
            ' data-collection-status="%s"'
            ' data-devices-expected="%d"'
            ' data-devices-with-config="%d"'
            ' data-devices-missing="%d"'
            ' data-changed-24h="%d"'
            ' data-changed-7d="%d"'
            ' data-events-recorded="%d" style="display:none"></div>'
        ) % (
            status, counts["devices_expected"], counts["devices_with_config"],
            counts["devices_missing"], counts["changed_24h"],
            counts["changed_7d"], counts["events_recorded"],
        )

        coverage_banner = ""
        if status == "unavailable":
            coverage_banner = (
                "<div class='coverage-banner banner-critical'>"
                "No collected configurations found &mdash; drift cannot be "
                "evaluated. Configs are collected by <b>get-conf</b> "
                "(every 12h by default); check the schedule or trigger "
                "<i>Refresh Configs</i> from the Devices page.</div>"
            )
        elif status == "partial":
            missing_shown = ", ".join(self.devices_missing[:6])
            if len(self.devices_missing) > 6:
                missing_shown += " (+%d more)" % (len(self.devices_missing) - 6)
            coverage_banner = (
                "<div class='coverage-banner'>"
                "Partial coverage &mdash; %d/%d managed devices have a "
                "collected configuration. <span class='banner-detail'>[%s]"
                "</span></div>"
            ) % (counts["devices_with_config"], counts["devices_expected"],
                 html.escape(missing_shown))

        cards = [
            ("card-info", counts["devices_expected"], "DEVICES TRACKED", ""),
            ("card-critical" if counts["changed_24h"] else "card-excellent",
             counts["changed_24h"], "DEVICES CHANGED (24H)", "changed24"),
            ("card-warning" if counts["changed_7d"] else "card-excellent",
             counts["changed_7d"], "DEVICES CHANGED (7D)", "changed7"),
            ("card-info", counts["events_recorded"], "DRIFT EVENTS (90D)", ""),
            ("card-warning" if counts["devices_missing"] else "card-excellent",
             counts["devices_missing"], "MISSING CONFIGS", "missing"),
        ]
        cards_html = "".join(
            "<div class='summary-card %s%s'%s><div class='metric'>%s</div>"
            "<div class='metric-label'>%s</div></div>" % (
                cls, ("" if action else " noclick"),
                (" onclick=\"cardFilter('%s', this)\"" % action) if action else "",
                "{:,}".format(value) if isinstance(value, int) else value, label)
            for cls, value, label, action in cards)

        event_html = []
        for event in sorted(self.events,
                            key=lambda item: int(item.get("ts") or 0),
                            reverse=True):
            host = str(event.get("host") or "")
            ts = int(event.get("ts") or 0)
            age = self.now - ts
            diff_lines = event.get("diff") or []
            diff_text = "\n".join(str(line) for line in diff_lines)
            if event.get("diff_truncated"):
                diff_text += "\n... (diff truncated at %d lines)" % \
                    EVENT_DIFF_MAX_LINES
            detail = ""
            if diff_text.strip():
                detail = (
                    "<details><summary>diff</summary>"
                    "<pre class='diffpre'>%s</pre></details>"
                ) % html.escape(diff_text)
            event_html.append(
                "<tr data-devices='%s' data-age='%d'>"
                "<td data-sort='%d'>%s</td><td>%s</td>"
                "<td data-sort='%d'><span class='added'>+%s</span></td>"
                "<td data-sort='%d'><span class='removed'>&minus;%s</span></td>"
                "<td>%s</td><td>%s</td></tr>" % (
                    html.escape(host.lower(), quote=True), age,
                    ts, html.escape(_iso(ts)),
                    html.escape(host),
                    int(event.get("added") or 0),
                    "{:,}".format(int(event.get("added") or 0)),
                    int(event.get("removed") or 0),
                    "{:,}".format(int(event.get("removed") or 0)),
                    "<span class='mono'>%s</span>" %
                    html.escape(str(event.get("summary") or "")),
                    detail,
                ))
        if not event_html:
            event_html.append(
                "<tr><td colspan='6' class='empty'>No drift events recorded"
                " &mdash; no configuration has changed since the baseline"
                " was established.</td></tr>")

        device_html = []
        for row in self.device_rows:
            status_badge = (
                "<span class='badge badge-green'>current</span>"
                if row["status"] == "current" else
                "<span class='badge badge-orange'>missing</span>")
            changed = row["last_changed_at"]
            device_html.append(
                "<tr data-devices='%s' data-status='%s'>"
                "<td>%s</td><td>%s</td>"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%s</td>"
                "<td data-sort='%d'>%s</td>"
                "<td data-sort='%d'>%d</td><td data-sort='%d'>%d</td></tr>" % (
                    html.escape(row["host"].lower(), quote=True),
                    row["status"],
                    html.escape(row["host"]), status_badge,
                    int(row["lines"] or 0),
                    "{:,}".format(int(row["lines"] or 0)) if row["lines"]
                    else "<span class='dim'>N/A</span>",
                    int(row["collected_at"] or 0),
                    html.escape(_iso(row["collected_at"]))
                    if row["collected_at"] else "<span class='dim'>N/A</span>",
                    int(changed or 0),
                    html.escape(_iso(changed))
                    if changed else "<span class='dim'>never</span>",
                    row["changes_7d"], row["changes_7d"],
                    row["changes_30d"], row["changes_30d"],
                ))
        if not device_html:
            device_html.append(
                "<tr><td colspan='7' class='empty empty-stale'>No managed"
                " devices found in devices.yaml.</td></tr>")

        html_doc = _PAGE_TEMPLATE
        html_doc = html_doc.replace("__MACHINE_SUMMARY__", machine_summary)
        html_doc = html_doc.replace("__COVERAGE_BANNER__", coverage_banner)
        html_doc = html_doc.replace("__NOW__", html.escape(now_text))
        html_doc = html_doc.replace("__CARDS__", cards_html)
        html_doc = html_doc.replace("__EVENT_ROWS__", "\n".join(event_html))
        html_doc = html_doc.replace("__DEVICE_ROWS__", "\n".join(device_html))
        html_doc = html_doc.replace("__CONFIGS_DIR__",
                                    html.escape(self.configs_dir))
        html_doc = html_doc.replace("__RETENTION_DAYS__",
                                    str(HISTORY_RETENTION_SEC // 86400))
        html_doc = html_doc.replace(
            "__DEVICES__",
            json.dumps(sorted(row["host"] for row in self.device_rows)))
        _atomic_write(output_file, html_doc)

        summary_path = os.path.join(
            os.path.dirname(os.path.abspath(output_file)),
            "summary", "config-drift-summary.json",
        )
        generated_at = int(time.time())
        summary_counts = self.summary_counts()
        _atomic_write(summary_path, json.dumps({
            "domain": "config-drift",
            "generated_at": generated_at,
            "collection_status": status,
            **summary_counts,
        }) + "\n")

        export_artifacts.write_export(
            os.path.dirname(os.path.abspath(output_file)),
            "config-drift", self.export_rows(), summary_counts, status,
            generated_at=generated_at,
        )


def _iso(timestamp):
    if not timestamp:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(timestamp)))


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Config Drift Analysis</title>
<link rel="shortcut icon" href="/png/favicon.ico">
<link rel="stylesheet" type="text/css" href="/css/select2.min.css">
<link rel="stylesheet" type="text/css" href="/css/table-filter.css?v=20260716-tf-3">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#1e1e1e; color:#d4d4d4; padding:20px; min-height:100vh; }
.page-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; padding-bottom:15px; border-bottom:1px solid #404040; }
.page-title { font-size:24px; font-weight:600; color:#76b900; }
.header-right { display:flex; align-items:center; gap:14px; }
.last-updated { font-size:13px; color:#888; }
.btn { background:#333; color:#d4d4d4; border:1px solid #404040; padding:8px 14px; border-radius:6px; cursor:pointer; font-size:13px; }
.btn:hover { background:#3c3c3c; border-color:#76b900; }
.dashboard-section { background:#2d2d2d; border-radius:8px; margin-bottom:20px; overflow:hidden; }
.section-header { padding:12px 16px; background:#333; font-weight:600; font-size:14px; color:#76b900; border-bottom:1px solid #404040; }
.section-content { padding:16px; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.summary-card { background:#252526; padding:15px; border-radius:6px; border-left:3px solid #76b900; }
.card-excellent { border-left-color:#76b900; }
.card-info { border-left-color:#4fc3f7; }
.card-warning { border-left-color:#ff9800; }
.card-critical { border-left-color:#f44336; }
.metric { font-size:22px; font-weight:bold; color:#d4d4d4; }
.metric-label { font-size:12px; color:#888; margin-top:4px; }
table.cd-table { width:100%; border-collapse:collapse; font-size:13px; }
.cd-table th, .cd-table td { border:1px solid #404040; padding:9px 11px; text-align:left; vertical-align:top; }
.cd-table th { background:#333; color:#76b900; font-weight:600; font-size:12px; cursor:pointer; user-select:none; }
.cd-table th:hover { background:#3c3c3c; }
.cd-table tbody tr { background:#252526; }
.cd-table tbody tr:hover { background:#2d2d2d; }
.mono { font-family:'Consolas','Courier New',monospace; font-size:12px; }
.dim { color:#888; font-size:11px; }
.empty { text-align:center; color:#76b900; padding:18px; }
.empty.empty-stale { color:#ffb74d; }
.coverage-banner { margin:0 0 16px; padding:9px 12px; background:#35270f; color:#ffb74d; border:1px solid #6d511d; border-radius:6px; font-size:13px; }
.coverage-banner.banner-critical { background:#3a1e1e; color:#ff6b6b; border-color:#6d2020; }
.coverage-banner b { color:inherit; }
.coverage-banner .banner-detail { color:#c8964a; font-size:11px; }
.badge { display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px; font-weight:600; text-transform:uppercase; }
.badge-green { background:rgba(118,185,0,0.2); color:#76b900; }
.badge-red { background:rgba(244,67,54,0.2); color:#ff6b6b; }
.badge-orange { background:rgba(255,152,0,0.2); color:#ffb74d; }
.badge-gray { background:rgba(158,158,158,0.2); color:#999; }
.added { color:#76b900; font-weight:bold; }
.removed { color:#ff6b6b; font-weight:bold; }
details summary { cursor:pointer; color:#4fc3f7; font-size:12px; user-select:none; }
.diffpre { background:#1e1e1e; border:1px solid #404040; border-radius:4px; margin-top:6px; padding:10px; font-family:'Consolas','Courier New',monospace; font-size:11px; line-height:1.5; max-height:340px; overflow:auto; white-space:pre; }
.modal { display:none; position:fixed; z-index:2000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.7); }
.modal.show { display:flex; justify-content:center; align-items:center; }
.modal-box { background:#2d2d2d; border-radius:8px; width:90%; max-width:680px; max-height:82vh; overflow:auto; box-shadow:0 4px 20px rgba(0,0,0,0.5); }
.modal-head { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; background:#333; border-bottom:1px solid #444; }
.modal-head h3 { color:#76b900; font-size:16px; margin:0; }
.modal-close { background:none; border:none; color:#888; font-size:24px; cursor:pointer; }
.modal-body { padding:18px; font-size:13px; line-height:1.6; }
.modal-body h4 { color:#76b900; margin:12px 0 4px; font-size:13px; }
.modal-body code { background:#1e1e1e; padding:1px 5px; border-radius:3px; color:#e0c64a; }
.action-buttons { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.btn { padding:8px 14px; border:none; border-radius:4px; font-size:13px; font-weight:500; cursor:pointer; display:flex; align-items:center; gap:6px; }
.btn-primary { background:linear-gradient(0deg,#76b900 0%,#5a8c00 100%); color:#fff; }
.btn-primary:hover { background:linear-gradient(0deg,#8bd400 0%,#6ba000 100%); }
.btn-secondary { background:linear-gradient(0deg,#4fc3f7 0%,#0288d1 100%); color:#fff; }
.btn-secondary:hover { background:linear-gradient(0deg,#81d4fa 0%,#039be5 100%); }
.device-search-container { display:flex; align-items:center; gap:8px; }
.device-search-container .select2-container { min-width:180px; }
.device-search-container .select2-container--default .select2-selection--single { height:34px; border:1px solid #555; border-radius:4px; background:#3c3c3c; display:flex; align-items:center; }
.device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered { line-height:34px; color:#d4d4d4; padding-left:10px; font-size:13px; }
.device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow { height:34px; }
.select2-dropdown { background:#2d2d2d; border:1px solid #555; }
.select2-container--default .select2-results__option { color:#d4d4d4; padding:8px 12px; }
.select2-container--default .select2-results__option--highlighted[aria-selected] { background:#76b900; color:#000; }
.select2-container--default .select2-search--dropdown .select2-search__field { background:#3c3c3c; border:1px solid #555; color:#d4d4d4; }
.clear-search-btn { background:#f44336; color:#fff; border:none; padding:6px 10px; border-radius:4px; cursor:pointer; font-size:12px; display:none; }
.summary-card { cursor:pointer; transition:all 0.15s; }
.summary-card:hover { background:#2d2d2d; transform:translateY(-1px); }
.summary-card.active { background:#333; border-left-width:6px; }
.summary-card.noclick { cursor:default; }
.summary-card.noclick:hover { background:#252526; transform:none; }
.filter-info { display:none; text-align:center; padding:9px 14px; margin-bottom:16px; background:rgba(118,185,0,0.1); border:1px solid rgba(118,185,0,0.3); border-radius:6px; color:#76b900; font-size:13px; }
.filter-info button { margin-left:10px; padding:4px 10px; background:#76b900; color:#000; border:none; border-radius:4px; cursor:pointer; }
@keyframes spin { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }
</style>
</head>
<body>
__MACHINE_SUMMARY__
<div class="page-header">
  <div>
    <div class="page-title">Config Drift Analysis</div>
    <div class="last-updated">Last Updated: __NOW__</div>
  </div>
  <div class="action-buttons">
    <div class="device-search-container">
      <select id="deviceSearch" style="width:200px;"><option value="">Search Device...</option></select>
      <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">&#10005;</button>
    </div>
    <button class="btn btn-secondary" onclick="document.getElementById('thr').classList.add('show')" title="Sources &amp; semantics">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
      About</button>
    <button id="run-analysis" class="btn btn-secondary" onclick="runAnalysis()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>
      Run Analysis</button>
    <button class="btn btn-primary" onclick="downloadCSV()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>
      Download CSV</button>
  </div>
</div>
__COVERAGE_BANNER__
<div class="filter-info" id="filterInfo">Filtered &mdash; <span id="filterLabel"></span> <button onclick="showAllRows()">Show All</button></div>
<div class="dashboard-section">
  <div class="section-header">Summary</div>
  <div class="section-content"><div class="summary-grid">__CARDS__</div></div>
</div>
<div class="dashboard-section">
  <div class="section-header">Drift Events (most recent first)</div>
  <div class="section-content">
    <table class="cd-table" id="evt" data-filterable>
      <thead><tr><th>Detected</th><th>Device</th><th>+ Added</th><th>&minus; Removed</th><th>First Change</th><th>Diff</th></tr></thead>
      <tbody>__EVENT_ROWS__</tbody>
    </table>
  </div>
</div>
<div class="dashboard-section">
  <div class="section-header">Devices</div>
  <div class="section-content">
    <table class="cd-table" id="devt" data-filterable>
      <thead><tr><th>Device</th><th>Status</th><th>Config Lines</th><th>Last Collected</th><th>Last Change</th><th>Changes 7d</th><th>Changes 30d</th></tr></thead>
      <tbody>__DEVICE_ROWS__</tbody>
    </table>
  </div>
</div>

<div class="modal" id="thr">
  <div class="modal-box">
    <div class="modal-head"><h3>Config Drift &mdash; Sources &amp; Semantics</h3>
      <button class="modal-close" onclick="document.getElementById('thr').classList.remove('show')">&times;</button></div>
    <div class="modal-body">
      <h4>Data source</h4>
      <code>nv config show -o commands</code> per device, collected by <b>get-conf</b>
      (default: every 12 hours; also on-demand via <i>Refresh Configs</i>). The collector keeps exactly one
      current file per device under <code>__CONFIGS_DIR__</code>, so this analyzer maintains its own
      baseline copy and diffs the current snapshot against it on every monitor cycle.
      <h4>Events</h4>
      A drift event is recorded when a device's collected configuration hash changes. <b>Detected</b> is
      when this analyzer first saw the change (monitor cycle granularity); <b>Last Collected</b> is the
      collection timestamp of the file itself. Line counts are unified-diff added/removed lines; the stored
      diff excerpt is capped per event. Events are retained for __RETENTION_DAYS__ days.
      <h4>What does NOT create an event</h4>
      The first sighting of a device establishes its baseline silently. An unreachable device keeps its
      last-known-good config file, so collection failures do not create false drift.
    </div>
  </div>
</div>

<script src="/css/jquery-3.5.1.min.js"></script>
<script src="/css/select2.min.js"></script>
<script>
var CD_DEVICES = __DEVICES__;
function sortKey(cell){ if(!cell) return ''; var v=cell.getAttribute('data-sort'); return v!==null ? v : (cell.innerText||'').trim(); }
function sortTable(tid, col, numeric) {
  var t = document.getElementById(tid), tb = t.tBodies[0];
  var rows = Array.prototype.slice.call(tb.rows).filter(function(r){return !r.querySelector('.empty');});
  if (!rows.length) return;
  var asc = t.getAttribute('data-sc') != (col+(numeric?'n':''));
  t.setAttribute('data-sc', asc ? (col+(numeric?'n':'')) : '');
  rows.sort(function(a,b){
    var x=sortKey(a.cells[col]), y=sortKey(b.cells[col]);
    if (numeric){ x=parseFloat(String(x).replace(/[^0-9.\\-]/g,''))||0; y=parseFloat(String(y).replace(/[^0-9.\\-]/g,''))||0; return asc?x-y:y-x; }
    return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
  });
  rows.forEach(function(r){ tb.appendChild(r); });
}
['evt','devt'].forEach(function(tid){
  var t=document.getElementById(tid); if(!t) return;
  Array.prototype.forEach.call(t.tHead.rows[0].cells, function(th, i){
    var num = /Added|Removed|Lines|7d|30d|Detected|Collected|Change/i.test(th.innerText);
    th.addEventListener('click', function(){ sortTable(tid, i, num); });
  });
});
document.getElementById('thr').addEventListener('click', function(e){ if(e.target===this) this.classList.remove('show'); });

function allRows(){ return [].concat(
  Array.prototype.slice.call(document.querySelectorAll('#evt tbody tr')),
  Array.prototype.slice.call(document.querySelectorAll('#devt tbody tr'))); }
function setFilterInfo(label){ var fi=document.getElementById('filterInfo'); if(fi){ document.getElementById('filterLabel').textContent=label; fi.style.display='block'; } }
function showAllRows(){
  allRows().forEach(function(r){ r.style.display=''; });
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  var fi=document.getElementById('filterInfo'); if(fi) fi.style.display='none';
  var cs=document.getElementById('clearSearchBtn'); if(cs) cs.style.display='none';
  if(window.jQuery && jQuery('#deviceSearch').data('select2')) jQuery('#deviceSearch').val('').trigger('change.select2');
}
function cardFilter(kind, card){
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  if(card) card.classList.add('active');
  if(kind==='changed24'||kind==='changed7'){
    var maxAge = (kind==='changed24') ? 86400 : 604800;
    Array.prototype.slice.call(document.querySelectorAll('#evt tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      var age=parseInt(r.getAttribute('data-age')||'0',10);
      r.style.display = (age<=maxAge) ? '' : 'none';
    });
    document.getElementById('evt').scrollIntoView({behavior:'smooth', block:'start'});
    setFilterInfo((kind==='changed24'?'Events in the last 24 hours':'Events in the last 7 days'));
  } else if(kind==='missing'){
    Array.prototype.slice.call(document.querySelectorAll('#devt tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      r.style.display = (r.getAttribute('data-status')==='missing') ? '' : 'none';
    });
    document.getElementById('devt').scrollIntoView({behavior:'smooth', block:'start'});
    setFilterInfo('Devices without a collected configuration');
  }
}
function filterByDevice(dev){
  if(!dev) return;
  dev = String(dev).toLowerCase();
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  allRows().forEach(function(r){
    if(r.querySelector('.empty')) return;
    var d=(r.getAttribute('data-devices')||'').toLowerCase().split(' ');
    r.style.display = (d.indexOf(dev)>-1) ? '' : 'none';
  });
  var cs=document.getElementById('clearSearchBtn'); if(cs) cs.style.display='inline-block';
  setFilterInfo('Device: '+dev);
}
function clearDeviceSearch(){ showAllRows(); }
async function runAnalysis(){
  var b=document.getElementById('run-analysis'); var o=b.innerHTML;
  b.disabled=true; b.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="animation:spin 1s linear infinite"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg> Running...';
  try {
    var baseline = typeof window.lldpqCaptureAnalysisState === 'function'
      ? await window.lldpqCaptureAnalysisState('config-drift') : null;
    var response = await fetch('/trigger-monitor?scope=config-drift',{
      method:'POST', headers:{'Content-Type':'application/json'}
    });
    var data = await response.json();
    if(!response.ok || !data || data.status!=='success' || !data.trigger_id || data.scope!=='config-drift'){
      throw new Error((data && data.message) || 'Failed to trigger analysis.');
    }
    if(typeof window.waitForLldpqAnalysisCompletion === 'function'){
      await window.waitForLldpqAnalysisCompletion(
        baseline, {scope:'config-drift', pipelineId:data.trigger_id});
    }else{
      await new Promise(function(resolve){ setTimeout(resolve,35000); });
    }
    location.reload();
  }catch(error){
    b.disabled=false; b.innerHTML=o;
    alert('Analysis did not complete: '+(error.message||error));
  }
}
function csvEsc(v){ v=(v==null?'':String(v)); return '"'+v.replace(/"/g,'""')+'"'; }
function tableCSV(tid){
  var t=document.getElementById(tid); if(!t||!t.tHead||!t.tBodies.length) return [];
  var rows=[Array.prototype.slice.call(t.tHead.rows[0].cells).map(function(c){ return (c.innerText||'').trim().replace(/\\s+/g,' '); })];
  Array.prototype.slice.call(t.tBodies[0].rows).forEach(function(r){
    if(r.style.display==='none' || r.querySelector('.empty')) return;
    if(r.classList.contains('tf-hidden')) return;
    rows.push(Array.prototype.slice.call(r.cells).map(function(c){ return (c.innerText||'').trim().replace(/\\s+/g,' '); }));
  });
  return rows;
}
function downloadCSV(){
  var out=[];
  [['Drift Events','evt'],
   ['Devices','devt']].forEach(function(sec){
    var body=tableCSV(sec[1]);
    out.push([sec[0]]);
    if(body.length<=1){ out.push(['(no rows)']); }
    else { body.forEach(function(r){ out.push(r); }); }
    out.push([]);
  });
  var csv=out.map(function(r){ return r.map(csvEsc).join(','); }).join('\\n');
  var d=new Date(), pad=function(n){ return (n<10?'0':'')+n; };
  var ts=d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'_'+pad(d.getHours())+'-'+pad(d.getMinutes());
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8;'}); var a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='Config_Drift_Analysis_'+ts+'.csv'; document.body.appendChild(a); a.click(); a.remove();
}
document.addEventListener('DOMContentLoaded', function(){
  if(window.jQuery){
    var $s=jQuery('#deviceSearch'); var opts='<option value=""></option>';
    var escHtml=function(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
    CD_DEVICES.forEach(function(dv){ opts+='<option value="'+escHtml(dv)+'">'+escHtml(dv)+'</option>'; });
    $s.html(opts);
    $s.select2({placeholder:'Search Device...', allowClear:true, width:'200px', dropdownAutoWidth:true});
    $s.on('select2:select', function(e){ filterByDevice(e.params.data.id); });
    $s.on('select2:clear', function(){ clearDeviceSearch(); });
  }
});
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/table-filter.js?v=20260821-tf-6"></script>
<script src="/css/analysis-guard.js?v=20260731-analysis-3"></script>
</body>
</html>"""


def main():
    analyzer = ConfigDriftAnalyzer(RESULT_DIR)
    analyzer.analyze()
    output_file = os.path.join(RESULT_DIR, OUTPUT_HTML)
    analyzer.export_html(output_file)
    # Baselines land before the state (same order as the first-sighting
    # path): a crash between the two can only produce one duplicate
    # empty-diff event on the next run, never a silently stale baseline
    # that misattributes the following diff.
    for host, content in analyzer._pending_baselines:
        analyzer._write_baseline(host, content)
    analyzer.save_state()

    counts = analyzer.summary_counts()
    print("Config drift analysis complete:")
    print("  Devices tracked      : %d" % counts["devices_expected"])
    print("  With collected config: %d" % counts["devices_with_config"])
    print("  Missing configs      : %d" % counts["devices_missing"])
    print("  New drift events     : %d" % counts["new_events"])
    print("  Changed last 24h     : %d device(s)" % counts["changed_24h"])
    print("  Changed last 7d      : %d device(s)" % counts["changed_7d"])
    print("  Events retained      : %d" % counts["events_recorded"])
    if counts["baselines_created"]:
        print("  Baselines created    : %d" % counts["baselines_created"])
    print("  -> %s" % output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
