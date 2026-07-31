#!/usr/bin/env python3
"""
Routes analyzer for LLDPq.

fabric-scan already dumps every device's kernel routing/ARP/MAC tables into
monitor-results/fabric-tables/<host>.json each minute, but that data is only
searchable — nothing watches it. This analyzer derives per-device, per-VRF
route table metrics (counts, protocol breakdown, ECMP width), keeps a compact
per-device history shard, and flags sudden route-count drops and disappeared
VRFs — the early-warning signs of a blackhole.

Local-only analyzer: no remote collection of its own.

Inputs
    monitor-results/fabric-tables/<host>.json    fabric-scan snapshots
    monitor-results/fabric-tables/summary.json   scan status (freshness)
    devices.yaml                                 managed device inventory

State / outputs (all under monitor-results/)
    routes-history/<host>.json          per-device sample history (sharded)
    routes_events.json                  anomaly event log (pruned)
    routes-analysis.html                report page
    summary/routes-summary.json         dashboard summary
    export/routes.{json,csv}            public export

Copyright (c) 2024 LLDPq Project - MIT License
"""

import html
import json
import os
import re
import sys
import tempfile
import time

import export_artifacts

try:
    from parse_devices import get_all_devices, load_devices_yaml
except ImportError:  # Source-tree imports used by unit tests.
    from lldpq.parse_devices import get_all_devices, load_devices_yaml

RESULT_DIR = "monitor-results"
TABLES_SUBDIR = "fabric-tables"
HISTORY_DIR_NAME = "routes-history"
EVENTS_FILE = "routes_events.json"
OUTPUT_HTML = "routes-analysis.html"

HISTORY_MAX_RECORDS = 288            # ~48h at the 10-minute monitor cadence
EVENTS_RETENTION_SEC = 30 * 86400
EVENTS_MAX = 2000

# Sudden-drop policy: only meaningful tables (>= floor) alarm, and only on a
# loss of at least the given fraction between two consecutive samples.
DROP_MIN_ROUTES = 50
DROP_FRACTION = 0.2

# Shard files are named after inventory hostnames; refuse anything that could
# escape the shard directory or hide as a dotfile.
SHARD_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


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


def load_managed_devices(script_dir):
    config = load_devices_yaml(os.path.join(script_dir, "devices.yaml"))
    return [hostname for _addr, _user, hostname, _role in get_all_devices(config)]


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return default
    return payload if isinstance(payload, type(default)) else default


def _vrf_metrics(route_entries, arp_by_vrf, vrf):
    total = 0
    bgp = kernel = static = other = 0
    ecmp_routes = 0
    max_width = 0
    for entry in route_entries:
        if not isinstance(entry, dict):
            continue
        total += 1
        protocol = str(entry.get("protocol") or "").lower()
        if protocol == "bgp":
            bgp += 1
        elif protocol == "kernel":
            kernel += 1
        elif protocol == "static":
            static += 1
        else:
            other += 1
        nexthops = entry.get("ecmp_nexthops")
        if isinstance(nexthops, list) and len(nexthops) > 1:
            ecmp_routes += 1
            max_width = max(max_width, len(nexthops))
    return {
        "total": total, "bgp": bgp, "kernel": kernel, "static": static,
        "other": other, "ecmp": ecmp_routes, "max_width": max_width,
        "arp": arp_by_vrf.get(vrf, 0),
    }


class RoutesAnalyzer:
    def __init__(self, result_dir=RESULT_DIR, now=None):
        self.result_dir = os.path.abspath(result_dir)
        self.tables_dir = os.path.join(self.result_dir, TABLES_SUBDIR)
        self.history_dir = os.path.join(self.result_dir, HISTORY_DIR_NAME)
        self.events_path = os.path.join(self.result_dir, EVENTS_FILE)
        self.now = int(now if now is not None else time.time())
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.managed_devices = load_managed_devices(script_dir)
        events = _load_json(self.events_path, {}).get("events")
        self.events = [event for event in events if isinstance(event, dict)] \
            if isinstance(events, list) else []
        self.new_events = 0
        self.rows = []
        self.device_status = {}
        self.scan_available = os.path.isdir(self.tables_dir)
        self.scan_timestamp = None

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self):
        os.makedirs(self.history_dir, exist_ok=True)
        summary = _load_json(os.path.join(self.tables_dir, "summary.json"), {})
        self.scan_timestamp = summary.get("timestamp")

        managed = [name for name in sorted(self.managed_devices,
                                           key=str.casefold)
                   if SHARD_HOST_RE.match(name)]
        managed_set = set(managed)

        # Retired devices: drop their history shard so a stale file cannot be
        # republished for a host that left the inventory.
        try:
            for filename in os.listdir(self.history_dir):
                if not filename.endswith(".json"):
                    continue
                host = filename[:-len(".json")]
                if host not in managed_set:
                    try:
                        os.unlink(os.path.join(self.history_dir, filename))
                    except OSError:
                        pass
        except OSError:
            pass

        for host in managed:
            table_path = os.path.join(self.tables_dir, "%s.json" % host)
            snapshot = _load_json(table_path, {}) if \
                os.path.isfile(table_path) else None
            if not snapshot:
                self.device_status[host] = "missing"
                self.rows.append(self._placeholder_row(
                    host, "missing", "no fabric-scan data"))
                continue
            collection = snapshot.get("_collection") \
                if isinstance(snapshot.get("_collection"), dict) else {}
            status = str(collection.get("status") or "current")
            self.device_status[host] = status

            routes = snapshot.get("routes")
            routes = routes if isinstance(routes, dict) else {}
            arp_by_vrf = {}
            arp_entries = snapshot.get("arp")
            if isinstance(arp_entries, list):
                for entry in arp_entries:
                    if isinstance(entry, dict):
                        vrf = str(entry.get("vrf") or "default")
                        arp_by_vrf[vrf] = arp_by_vrf.get(vrf, 0) + 1

            shard_path = os.path.join(self.history_dir, "%s.json" % host)
            shard = _load_json(shard_path, {})
            history = shard.get("history")
            history = [record for record in history
                       if isinstance(record, dict)
                       and isinstance(record.get("timestamp"), (int, float))] \
                if isinstance(history, list) else []
            previous = history[-1] if history else None
            previous_vrfs = previous.get("vrfs") \
                if previous and isinstance(previous.get("vrfs"), dict) else {}

            current_vrfs = {}
            for vrf in sorted(routes, key=str.casefold):
                entries = routes.get(vrf)
                if not isinstance(entries, list):
                    continue
                metrics = _vrf_metrics(entries, arp_by_vrf, vrf)
                current_vrfs[vrf] = {"total": metrics["total"],
                                     "bgp": metrics["bgp"]}
                prev_metrics = previous_vrfs.get(vrf) \
                    if isinstance(previous_vrfs.get(vrf), dict) else None
                prev_total = int(prev_metrics.get("total")) \
                    if prev_metrics and isinstance(
                        prev_metrics.get("total"), (int, float)) else None
                delta = metrics["total"] - prev_total \
                    if prev_total is not None else None
                note = ""
                severity = "ok"
                if (prev_total is not None and prev_total >= DROP_MIN_ROUTES
                        and metrics["total"] < prev_total * (1 - DROP_FRACTION)):
                    severity = "critical"
                    note = "route count dropped %d → %d" % (
                        prev_total, metrics["total"])
                    self._record_event(host, vrf, "route-drop",
                                       prev_total, metrics["total"])
                self.rows.append({
                    "host": host, "vrf": vrf, "status": status,
                    "severity": severity, "note": note, "delta": delta,
                    **metrics,
                })

            # A VRF that had routes in the previous sample but is absent now
            # (device still reporting) is a hard failure mode, not a zero row.
            if isinstance(previous_vrfs, dict):
                for vrf in sorted(set(previous_vrfs) - set(current_vrfs),
                                  key=str.casefold):
                    prev_metrics = previous_vrfs.get(vrf)
                    prev_total = int(prev_metrics.get("total") or 0) \
                        if isinstance(prev_metrics, dict) else 0
                    if prev_total <= 0:
                        continue
                    self._record_event(host, vrf, "vrf-disappeared",
                                       prev_total, 0)
                    self.rows.append({
                        "host": host, "vrf": vrf, "status": status,
                        "severity": "critical",
                        "note": "VRF disappeared (had %d routes)" % prev_total,
                        "delta": -prev_total, "total": 0, "bgp": 0,
                        "kernel": 0, "static": 0, "other": 0, "ecmp": 0,
                        "max_width": 0, "arp": 0,
                    })

            history.append({"timestamp": self.now, "vrfs": current_vrfs})
            self._write_shard(shard_path, host, history)

        self._prune_events()

    def _placeholder_row(self, host, status, note):
        return {
            "host": host, "vrf": "-", "status": status, "severity": "warning",
            "note": note, "delta": None, "total": 0, "bgp": 0, "kernel": 0,
            "static": 0, "other": 0, "ecmp": 0, "max_width": 0, "arp": 0,
        }

    def _record_event(self, host, vrf, kind, prev, current):
        self.events.append({
            "ts": self.now, "host": host, "vrf": vrf, "kind": kind,
            "prev": prev, "current": current,
        })
        self.new_events += 1

    def _write_shard(self, shard_path, host, history):
        trimmed = [record for record in history
                   if self.now - int(record.get("timestamp") or 0)
                   <= HISTORY_MAX_RECORDS * 600 * 2][-HISTORY_MAX_RECORDS:]
        _atomic_write(shard_path, json.dumps({
            "version": 1,
            "updated_at": _iso(self.now),
            "host": host,
            "history": trimmed,
        }, separators=(",", ":")) + "\n")

    def _prune_events(self):
        cutoff = self.now - EVENTS_RETENTION_SEC
        pruned = [event for event in self.events
                  if int(event.get("ts") or 0) >= cutoff]
        pruned.sort(key=lambda event: int(event.get("ts") or 0))
        self.events = pruned[-EVENTS_MAX:]

    # ------------------------------------------------------------------
    # Persistence + report
    # ------------------------------------------------------------------
    def collection_status(self):
        if not self.scan_available:
            return "unavailable"
        reporting = sum(1 for status in self.device_status.values()
                        if status == "current")
        if not reporting:
            return "unavailable"
        if any(status != "current" for status in self.device_status.values()):
            return "partial"
        return "current"

    def summary_counts(self):
        drops_24h = sum(1 for event in self.events
                        if event.get("kind") == "route-drop"
                        and self.now - int(event.get("ts") or 0) <= 86400)
        vrf_loss_24h = sum(1 for event in self.events
                           if event.get("kind") == "vrf-disappeared"
                           and self.now - int(event.get("ts") or 0) <= 86400)
        return {
            "devices_expected": len(self.device_status),
            "devices_reporting": sum(1 for status in
                                     self.device_status.values()
                                     if status == "current"),
            "devices_stale": sum(1 for status in self.device_status.values()
                                 if status in ("stale", "unavailable")),
            "devices_missing": sum(1 for status in
                                   self.device_status.values()
                                   if status == "missing"),
            "total_routes": sum(row["total"] for row in self.rows),
            "total_bgp_routes": sum(row["bgp"] for row in self.rows),
            "vrf_count": len({row["vrf"] for row in self.rows
                              if row["vrf"] != "-"}),
            "route_drops_24h": drops_24h,
            "vrfs_disappeared_24h": vrf_loss_24h,
            "events_recorded": len(self.events),
            "new_events": self.new_events,
        }

    def save_state(self):
        _atomic_write(self.events_path, json.dumps(
            {"version": 1, "last_update": self.now, "events": self.events},
            separators=(",", ":")) + "\n")

    def export_rows(self):
        rows = []
        for row in self.rows:
            rows.append({
                "device": row["host"],
                "vrf": row["vrf"],
                "status": row["status"],
                "routes_total": row["total"],
                "routes_delta": row["delta"],
                "bgp_routes": row["bgp"],
                "kernel_routes": row["kernel"],
                "static_routes": row["static"],
                "other_routes": row["other"],
                "ecmp_routes": row["ecmp"],
                "max_ecmp_width": row["max_width"],
                "arp_entries": row["arp"],
                "note": row["note"] or None,
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
            '<div data-analysis-summary="routes"'
            ' data-collection-status="%s"'
            ' data-devices-expected="%d"'
            ' data-devices-reporting="%d"'
            ' data-devices-stale="%d"'
            ' data-total-routes="%d"'
            ' data-vrf-count="%d"'
            ' data-route-drops-24h="%d"'
            ' data-vrfs-disappeared-24h="%d" style="display:none"></div>'
        ) % (
            status, counts["devices_expected"], counts["devices_reporting"],
            counts["devices_stale"], counts["total_routes"],
            counts["vrf_count"], counts["route_drops_24h"],
            counts["vrfs_disappeared_24h"],
        )

        coverage_banner = ""
        if status == "unavailable":
            coverage_banner = (
                "<div class='coverage-banner banner-critical'>"
                "No fabric-scan data available &mdash; route tables cannot be "
                "analyzed. fabric-scan runs every minute; check that it is "
                "enabled (SKIP_FABRIC_SCAN) and that devices are reachable."
                "</div>"
            )
        elif status == "partial":
            degraded = sorted(host for host, state in
                              self.device_status.items()
                              if state != "current")
            shown = ", ".join(degraded[:6])
            if len(degraded) > 6:
                shown += " (+%d more)" % (len(degraded) - 6)
            coverage_banner = (
                "<div class='coverage-banner'>"
                "Partial coverage &mdash; %d/%d devices with a current "
                "fabric-scan snapshot; stale devices keep their last-known "
                "tables. <span class='banner-detail'>[%s]</span></div>"
            ) % (counts["devices_reporting"], counts["devices_expected"],
                 html.escape(shown))

        anomalies_now = counts["route_drops_24h"] + \
            counts["vrfs_disappeared_24h"]
        cards = [
            ("card-info", counts["total_routes"], "ROUTES (FABRIC-WIDE)", ""),
            ("card-info", counts["vrf_count"], "VRFS", ""),
            ("card-excellent" if not counts["devices_stale"] and
             not counts["devices_missing"] else "card-warning",
             "%d/%d" % (counts["devices_reporting"],
                        counts["devices_expected"]),
             "DEVICES REPORTING", "degraded"),
            ("card-critical" if anomalies_now else "card-excellent",
             anomalies_now, "ROUTE ANOMALIES (24H)", "anomaly"),
            ("card-info", counts["total_bgp_routes"], "BGP ROUTES", ""),
        ]
        cards_html = "".join(
            "<div class='summary-card %s%s'%s><div class='metric'>%s</div>"
            "<div class='metric-label'>%s</div></div>" % (
                cls, ("" if action else " noclick"),
                (" onclick=\"cardFilter('%s', this)\"" % action) if action else "",
                "{:,}".format(value) if isinstance(value, int) else value, label)
            for cls, value, label, action in cards)

        row_html = []
        for row in self.rows:
            if row["severity"] == "critical":
                badge = "<span class='badge badge-red'>critical</span>"
            elif row["status"] == "current":
                badge = "<span class='badge badge-green'>current</span>"
            elif row["status"] == "missing":
                badge = "<span class='badge badge-gray'>missing</span>"
            else:
                badge = "<span class='badge badge-orange'>%s</span>" % \
                    html.escape(row["status"])
            if row["delta"] is None:
                delta_cell = "<td data-sort='0'><span class='dim'>N/A</span></td>"
            else:
                delta = int(row["delta"])
                cls = "delta-up" if delta < 0 else "delta-muted"
                delta_cell = "<td data-sort='%d'><span class='%s'>%+d</span></td>" % (
                    delta, cls, delta)
            note = html.escape(row["note"]) if row["note"] else \
                "<span class='dim'>&mdash;</span>"
            # Real device/VRF rows are expandable: clicking fetches the
            # device's fabric-tables snapshot and renders the route table.
            detail_attrs = ""
            if row["vrf"] != "-" and row["status"] != "missing":
                detail_attrs = " data-device='%s' data-vrf='%s'" % (
                    html.escape(row["host"], quote=True),
                    html.escape(row["vrf"], quote=True))
            row_html.append(
                "<tr data-devices='%s' data-severity='%s' data-status='%s'%s>"
                "<td>%s</td><td class='mono'>%s</td><td>%s</td>"
                "<td data-sort='%d'>%s</td>%s"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%s</td>"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%s</td>"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%d</td>"
                "<td data-sort='%d'>%s</td><td>%s</td></tr>" % (
                    html.escape(row["host"].lower(), quote=True),
                    row["severity"], row["status"], detail_attrs,
                    html.escape(row["host"]),
                    html.escape(row["vrf"]), badge,
                    row["total"], "{:,}".format(row["total"]), delta_cell,
                    row["bgp"], "{:,}".format(row["bgp"]),
                    row["kernel"], "{:,}".format(row["kernel"]),
                    row["static"], "{:,}".format(row["static"]),
                    row["other"], "{:,}".format(row["other"]),
                    row["ecmp"], "{:,}".format(row["ecmp"]),
                    row["max_width"], row["max_width"],
                    row["arp"], "{:,}".format(row["arp"]),
                    note,
                ))
        if not row_html:
            row_html.append(
                "<tr><td colspan='13' class='empty empty-stale'>No route "
                "table data &mdash; fabric-scan has not produced any device "
                "snapshots yet.</td></tr>")

        event_html = []
        for event in sorted(self.events,
                            key=lambda item: int(item.get("ts") or 0),
                            reverse=True):
            kind = str(event.get("kind") or "")
            label = {"route-drop": "Route count drop",
                     "vrf-disappeared": "VRF disappeared"}.get(kind, kind)
            event_html.append(
                "<tr data-devices='%s'>"
                "<td data-sort='%d'>%s</td><td>%s</td>"
                "<td class='mono'>%s</td><td>%s</td>"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%s</td></tr>" % (
                    html.escape(str(event.get("host") or "").lower(),
                                quote=True),
                    int(event.get("ts") or 0),
                    html.escape(_iso(event.get("ts"))),
                    html.escape(str(event.get("host") or "")),
                    html.escape(str(event.get("vrf") or "")),
                    html.escape(label),
                    int(event.get("prev") or 0),
                    "{:,}".format(int(event.get("prev") or 0)),
                    int(event.get("current") or 0),
                    "{:,}".format(int(event.get("current") or 0)),
                ))
        if not event_html:
            event_html.append(
                "<tr><td colspan='6' class='empty'>No route anomalies "
                "recorded.</td></tr>")

        html_doc = _PAGE_TEMPLATE
        html_doc = html_doc.replace("__MACHINE_SUMMARY__", machine_summary)
        html_doc = html_doc.replace("__COVERAGE_BANNER__", coverage_banner)
        html_doc = html_doc.replace("__NOW__", html.escape(now_text))
        html_doc = html_doc.replace("__CARDS__", cards_html)
        html_doc = html_doc.replace("__TABLE_ROWS__", "\n".join(row_html))
        html_doc = html_doc.replace("__EVENT_ROWS__", "\n".join(event_html))
        html_doc = html_doc.replace("__DROP_PCT__",
                                    str(int(DROP_FRACTION * 100)))
        html_doc = html_doc.replace("__DROP_MIN__", str(DROP_MIN_ROUTES))
        html_doc = html_doc.replace(
            "__DEVICES__",
            json.dumps(sorted({row["host"] for row in self.rows})))
        _atomic_write(output_file, html_doc)

        summary_path = os.path.join(
            os.path.dirname(os.path.abspath(output_file)),
            "summary", "routes-summary.json",
        )
        generated_at = int(time.time())
        summary_counts = self.summary_counts()
        _atomic_write(summary_path, json.dumps({
            "domain": "routes",
            "generated_at": generated_at,
            "collection_status": status,
            **summary_counts,
        }) + "\n")

        export_artifacts.write_export(
            os.path.dirname(os.path.abspath(output_file)),
            "routes", self.export_rows(), summary_counts, status,
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
<title>Routes Analysis</title>
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
table.rt-table { width:100%; border-collapse:collapse; font-size:13px; }
.rt-table th, .rt-table td { border:1px solid #404040; padding:9px 11px; text-align:left; vertical-align:top; }
.rt-table th { background:#333; color:#76b900; font-weight:600; font-size:12px; cursor:pointer; user-select:none; }
.rt-table th:hover { background:#3c3c3c; }
.rt-table tbody tr { background:#252526; }
.rt-table tbody tr:hover { background:#2d2d2d; }
.mono { font-family:'Consolas','Courier New',monospace; font-size:12px; }
.dim { color:#888; font-size:11px; }
.empty { text-align:center; color:#76b900; padding:18px; }
.empty.empty-stale { color:#ffb74d; }
.coverage-banner { margin:0 0 16px; padding:9px 12px; background:#35270f; color:#ffb74d; border:1px solid #6d511d; border-radius:6px; font-size:13px; }
.coverage-banner.banner-critical { background:#3a1e1e; color:#ff6b6b; border-color:#6d2020; }
.coverage-banner b { color:inherit; }
.coverage-banner .banner-detail { color:#c8964a; font-size:11px; }
.delta-up { color:#ff6b6b; font-weight:bold; }
.delta-muted { color:#aaa; font-weight:bold; }
.badge { display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px; font-weight:600; text-transform:uppercase; }
.badge-green { background:rgba(118,185,0,0.2); color:#76b900; }
.badge-red { background:rgba(244,67,54,0.2); color:#ff6b6b; }
.badge-orange { background:rgba(255,152,0,0.2); color:#ffb74d; }
.badge-gray { background:rgba(158,158,158,0.2); color:#999; }
#rtt tbody tr[data-device] { cursor:pointer; }
tr.detail-row td { padding:0; white-space:normal; text-align:left; background:#202020; }
tr.tf-hidden + tr.detail-row { display:none !important; }
.detail-panel { padding:14px 20px 18px; background:#202020; border-left:3px solid #4fc3f7; }
.detail-title { color:#4fc3f7; font-weight:700; margin-bottom:10px; font-size:13px; }
.detail-empty { color:#888; }
.detail-note { color:#888; font-size:11px; margin-top:8px; }
.detail-table { width:100%; min-width:0; font-size:12px; border-collapse:collapse; }
.detail-table th, .detail-table td { border:1px solid #383838; padding:5px 8px; white-space:nowrap; text-align:left; }
.detail-table th { background:#2a2a2a; color:#9ccc65; }
.detail-table tbody tr { background:#242424; }
.detail-table td.mono, .detail-table th.mono { font-family:'Consolas','Courier New',monospace; }
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
    <div class="page-title">Routes Analysis</div>
    <div class="last-updated">Last Updated: __NOW__</div>
  </div>
  <div class="action-buttons">
    <div class="device-search-container">
      <select id="deviceSearch" style="width:200px;"><option value="">Search Device...</option></select>
      <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">&#10005;</button>
    </div>
    <button class="btn btn-secondary" onclick="document.getElementById('thr').classList.add('show')" title="Sources &amp; thresholds">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
      Thresholds</button>
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
  <div class="section-header">Route Tables (per device / VRF)</div>
  <div class="section-content">
    <table class="rt-table" id="rtt" data-filterable>
      <thead><tr><th>Device</th><th>VRF</th><th>Status</th><th>Routes</th><th>&#916;</th><th>BGP</th><th>Kernel</th><th>Static</th><th>Other</th><th>ECMP Routes</th><th>Max Width</th><th>ARP</th><th>Note</th></tr></thead>
      <tbody>__TABLE_ROWS__</tbody>
    </table>
  </div>
</div>
<div class="dashboard-section">
  <div class="section-header">Route Anomalies (most recent first)</div>
  <div class="section-content">
    <table class="rt-table" id="evt" data-filterable>
      <thead><tr><th>Detected</th><th>Device</th><th>VRF</th><th>Event</th><th>Previous</th><th>Current</th></tr></thead>
      <tbody>__EVENT_ROWS__</tbody>
    </table>
  </div>
</div>

<div class="modal" id="thr">
  <div class="modal-box">
    <div class="modal-head"><h3>Routes Analysis &mdash; Sources &amp; Thresholds</h3>
      <button class="modal-close" onclick="document.getElementById('thr').classList.remove('show')">&times;</button></div>
    <div class="modal-body">
      <h4>Data source</h4>
      <code>ip route show [vrf &lt;name&gt;]</code>, <code>ip neigh show</code> and related kernel tables,
      collected per device every minute by <b>fabric-scan</b> into
      <code>monitor-results/fabric-tables/</code>. Counts are kernel-derived (what is actually installed
      in the FIB), not FRR RIB entries; <code>linkdown</code>/<code>unreachable</code> routes are excluded
      by the collector.
      <h4>Row expand</h4>
      Click any device/VRF row to expand the <b>current route table</b> for that VRF (prefix, protocol,
      nexthops with ECMP membership, interface, metric), fetched on demand from the latest fabric-scan
      snapshot. Long tables are capped in the panel; use Search for specific prefix lookups.
      <h4>&#916; and anomalies</h4>
      <b>&#916;</b> compares this sample with the previous analyzer sample per device/VRF.
      A <b>route count drop</b> is flagged when a table that had &ge; __DROP_MIN__ routes loses more than
      __DROP_PCT__% between two consecutive samples. A <b>VRF disappeared</b> event is flagged when a VRF
      that previously carried routes vanishes while the device is still reporting. Anomalies are retained
      for 30 days.
      <h4>ECMP</h4>
      <b>ECMP Routes</b> counts prefixes with more than one nexthop; <b>Max Width</b> is the widest nexthop
      group seen in that VRF &mdash; asymmetric widths across same-role devices usually mean a missing
      uplink or a BGP session down.
      <h4>Stale devices</h4>
      A device that fails collection keeps its last-known-good snapshot and is shown with a
      <i>stale</i>/<i>unavailable</i> badge; its counts reflect the last successful scan.
    </div>
  </div>
</div>

<script src="/css/jquery-3.5.1.min.js"></script>
<script src="/css/select2.min.js"></script>
<script>
var RT_DEVICES = __DEVICES__;
// Per-device route tables live in the fabric-scan snapshots that are
// published alongside this page; each device's JSON is fetched on first
// row expand and cached as a promise to dedupe concurrent clicks.
var RT_TABLES_DIR = 'fabric-tables';
var RT_DETAIL_MAX_ROWS = 2000;
var RT_DETAIL_MAX_NEXTHOPS = 8;
var rtSnapshotCache = new Map();
function rtDeviceSnapshot(device){
  if(!device) return Promise.resolve(null);
  if(rtSnapshotCache.has(device)) return rtSnapshotCache.get(device);
  var request = fetch(RT_TABLES_DIR + '/' + encodeURIComponent(device) + '.json', {cache:'no-store'})
    .then(function(response){
      if(!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    })
    .then(function(snapshot){
      return (snapshot && typeof snapshot === 'object') ? snapshot : null;
    })
    .catch(function(){
      rtSnapshotCache.delete(device);
      return null;
    });
  rtSnapshotCache.set(device, request);
  return request;
}
function rtEsc(value){
  return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
  });
}
function rtNexthopCell(entry){
  var hops = Array.isArray(entry.ecmp_nexthops) ? entry.ecmp_nexthops : [];
  if(hops.length > 1){
    var shown = hops.slice(0, RT_DETAIL_MAX_NEXTHOPS).map(function(h){
      if(!h || typeof h !== 'object') return '';
      var ip = rtEsc(h.ip || ''), iface = rtEsc(h.interface || '');
      return ip + (iface ? ' (' + iface + ')' : '');
    }).filter(Boolean).join(', ');
    var extra = hops.length > RT_DETAIL_MAX_NEXTHOPS
      ? ' <span class="dim">+' + (hops.length - RT_DETAIL_MAX_NEXTHOPS) + ' more</span>' : '';
    return 'ECMP &times;' + hops.length + ' &mdash; ' + shown + extra;
  }
  var nexthop = rtEsc(entry.nexthop || '');
  return nexthop || '<span class="dim">direct</span>';
}
function removeDetailRows(){
  document.querySelectorAll('#rtt tr.detail-row').forEach(function(r){ r.remove(); });
}
async function toggleRouteDetails(row){
  var next = row.nextElementSibling;
  if(next && next.classList.contains('detail-row')){ next.remove(); return; }
  removeDetailRows();
  var device = row.getAttribute('data-device') || '';
  var vrf = row.getAttribute('data-vrf') || '';
  var detail = document.createElement('tr');
  detail.className = 'detail-row';
  detail.innerHTML = '<td colspan="13"><div class="detail-panel">'
    + '<div class="detail-title">Route table &mdash; ' + rtEsc(device) + ' / VRF ' + rtEsc(vrf) + '</div>'
    + '<div class="detail-body detail-empty">Loading route table&hellip;</div></div></td>';
  row.after(detail);
  var snapshot = await rtDeviceSnapshot(device);
  var body = detail.isConnected && detail.querySelector('.detail-body');
  if(!body) return;
  if(snapshot === null){
    body.textContent = 'Route table could not be loaded (fabric-scan snapshot unavailable).';
    return;
  }
  var routes = (snapshot.routes && typeof snapshot.routes === 'object') ? snapshot.routes : {};
  var entries = Array.isArray(routes[vrf]) ? routes[vrf] : [];
  if(!entries.length){
    body.textContent = 'No routes in the current snapshot for this VRF.';
    return;
  }
  body.classList.remove('detail-empty');
  var shown = entries.slice(0, RT_DETAIL_MAX_ROWS);
  var rowsHtml = shown.map(function(entry){
    if(!entry || typeof entry !== 'object') return '';
    return '<tr><td class="mono">' + rtEsc(entry.prefix || '') + '</td>'
      + '<td>' + rtEsc(entry.protocol || '') + '</td>'
      + '<td class="mono">' + rtNexthopCell(entry) + '</td>'
      + '<td class="mono">' + (rtEsc(entry.interface || '') || '<span class="dim">&mdash;</span>') + '</td>'
      + '<td>' + (rtEsc(entry.metric || '') || '<span class="dim">&mdash;</span>') + '</td></tr>';
  }).join('');
  var note = '';
  if(entries.length > shown.length){
    note = '<div class="detail-note">Showing first ' + shown.length.toLocaleString()
      + ' of ' + entries.length.toLocaleString()
      + ' routes &mdash; use Search for specific prefix lookups.</div>';
  }
  var collected = snapshot._collection && snapshot._collection.last_success;
  if(collected){
    note += '<div class="detail-note">Snapshot: ' + rtEsc(String(collected).replace('T', ' ').slice(0, 19)) + '</div>';
  }
  body.innerHTML = '<table class="detail-table"><thead><tr><th class="mono">Prefix</th>'
    + '<th>Protocol</th><th>Nexthop(s)</th><th>Interface</th><th>Metric</th></tr></thead>'
    + '<tbody>' + rowsHtml + '</tbody></table>' + note;
}
document.querySelectorAll('#rtt tbody tr[data-device]').forEach(function(row){
  row.addEventListener('click', function(event){
    if(window.getSelection && String(window.getSelection())) return;
    toggleRouteDetails(row);
  });
});
function sortKey(cell){ if(!cell) return ''; var v=cell.getAttribute('data-sort'); return v!==null ? v : (cell.innerText||'').trim(); }
function sortTable(tid, col, numeric) {
  var t = document.getElementById(tid), tb = t.tBodies[0];
  removeDetailRows();
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
['rtt','evt'].forEach(function(tid){
  var t=document.getElementById(tid); if(!t) return;
  Array.prototype.forEach.call(t.tHead.rows[0].cells, function(th, i){
    var num = /Routes|BGP|Kernel|Static|Other|Width|ARP|Previous|Current|Detected|\\u0394/i.test(th.innerText) || th.innerText.trim()==='\\u0394';
    th.addEventListener('click', function(){ sortTable(tid, i, num); });
  });
});
document.getElementById('thr').addEventListener('click', function(e){ if(e.target===this) this.classList.remove('show'); });

function allRows(){ return [].concat(
  Array.prototype.slice.call(document.querySelectorAll('#rtt tbody tr')),
  Array.prototype.slice.call(document.querySelectorAll('#evt tbody tr'))); }
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
  if(kind==='degraded'){
    Array.prototype.slice.call(document.querySelectorAll('#rtt tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      var s=r.getAttribute('data-status');
      r.style.display = (s && s!=='current') ? '' : 'none';
    });
    document.getElementById('rtt').scrollIntoView({behavior:'smooth', block:'start'});
    setFilterInfo('Devices without a current snapshot');
  } else if(kind==='anomaly'){
    Array.prototype.slice.call(document.querySelectorAll('#rtt tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      r.style.display = (r.getAttribute('data-severity')==='critical') ? '' : 'none';
    });
    document.getElementById('evt').scrollIntoView({behavior:'smooth', block:'start'});
    setFilterInfo('Route anomalies');
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
      ? await window.lldpqCaptureAnalysisState('routes') : null;
    var response = await fetch('/trigger-monitor?scope=routes',{
      method:'POST', headers:{'Content-Type':'application/json'}
    });
    var data = await response.json();
    if(!response.ok || !data || data.status!=='success' || !data.trigger_id || data.scope!=='routes'){
      throw new Error((data && data.message) || 'Failed to trigger analysis.');
    }
    if(typeof window.waitForLldpqAnalysisCompletion === 'function'){
      await window.waitForLldpqAnalysisCompletion(
        baseline, {scope:'routes', pipelineId:data.trigger_id});
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
    if(r.classList.contains('tf-hidden') || r.classList.contains('detail-row')) return;
    rows.push(Array.prototype.slice.call(r.cells).map(function(c){ return (c.innerText||'').trim().replace(/\\s+/g,' '); }));
  });
  return rows;
}
function downloadCSV(){
  var out=[];
  [['Route Tables (per device / VRF)','rtt'],
   ['Route Anomalies','evt']].forEach(function(sec){
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
  a.href=URL.createObjectURL(blob); a.download='Routes_Analysis_'+ts+'.csv'; document.body.appendChild(a); a.click(); a.remove();
}
document.addEventListener('DOMContentLoaded', function(){
  if(window.jQuery){
    var $s=jQuery('#deviceSearch'); var opts='<option value=""></option>';
    var escHtml=function(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
    RT_DEVICES.forEach(function(dv){ opts+='<option value="'+escHtml(dv)+'">'+escHtml(dv)+'</option>'; });
    $s.html(opts);
    $s.select2({placeholder:'Search Device...', allowClear:true, width:'200px', dropdownAutoWidth:true});
    $s.on('select2:select', function(e){ filterByDevice(e.params.data.id); });
    $s.on('select2:clear', function(){ clearDeviceSearch(); });
  }
});
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/table-filter.js?v=20260716-tf-3"></script>
<script src="/css/analysis-guard.js?v=20260731-analysis-3"></script>
</body>
</html>"""


def main():
    analyzer = RoutesAnalyzer(RESULT_DIR)
    analyzer.analyze()
    output_file = os.path.join(RESULT_DIR, OUTPUT_HTML)
    analyzer.export_html(output_file)
    analyzer.save_state()

    counts = analyzer.summary_counts()
    print("Routes analysis complete:")
    print("  Devices expected   : %d" % counts["devices_expected"])
    print("  Devices reporting  : %d" % counts["devices_reporting"])
    print("  Stale/unavailable  : %d" % counts["devices_stale"])
    print("  Missing snapshots  : %d" % counts["devices_missing"])
    print("  Routes (fabric)    : %d" % counts["total_routes"])
    print("  BGP routes         : %d" % counts["total_bgp_routes"])
    print("  VRFs               : %d" % counts["vrf_count"])
    print("  Route drops (24h)  : %d" % counts["route_drops_24h"])
    print("  VRFs lost (24h)    : %d" % counts["vrfs_disappeared_24h"])
    print("  -> %s" % output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
