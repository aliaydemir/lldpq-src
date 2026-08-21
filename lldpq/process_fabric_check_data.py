#!/usr/bin/env python3
"""
Fabric-Check analyzer for LLDPq.

Link-level consistency checks between connected neighbor ports:

    mtu-mismatch          running MTU differs between the two ends of a link
    speed-mismatch        negotiated speed differs between the two ends
    fec-mismatch          active FEC encoding differs between the two ends
    autoneg-mismatch      auto-negotiation setting differs between the ends
    config-mtu-mismatch   a port's running MTU differs from its configured
                          NVUE `link mtu` value

Data comes from the LLDP neighbor sidecar (lldp-results/lldp_neighbors.json),
whose `ports` map carries per-port oper/speed/mtu (sysfs) plus best-effort
fec/autoneg (ethtool, carrier-up ports) collected during the LLDP stage, and
from the collected NVUE command exports ($WEB_ROOT/configs/<host>.txt) for
configured MTU.

Local-only analyzer: no remote collection of its own.

Outputs (all under monitor-results/)
    fabric-check-analysis.html          report page
    summary/fabric-check-summary.json   dashboard summary
    export/fabric-check.{json,csv}      public export

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
OUTPUT_HTML = "fabric-check-analysis.html"

# `nv config show -o commands` compacts interface lists ("swp1-48,swp50");
# expand the final numeric run of each comma segment.
_NV_MTU_RE = re.compile(r"^nv set interface (\S+) link mtu (\d+)\s*$")
_RANGE_RE = re.compile(r"^(.*?)(\d+)-(\d+)$")
_RANGE_EXPANSION_CAP = 4096


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
    override = os.environ.get("LLDPQ_FABRIC_CHECK_CONFIGS_DIR")
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
    config = load_devices_yaml(os.path.join(script_dir, "devices.yaml"))
    return [hostname for _addr, _user, hostname, _role in get_all_devices(config)]


def expand_interface_spec(spec):
    """Expand an NVUE compacted interface list into individual port names."""
    ports = []
    for token in str(spec).split(","):
        token = token.strip()
        if not token:
            continue
        match = _RANGE_RE.match(token)
        if not match:
            ports.append(token)
            continue
        prefix, start_text, end_text = match.groups()
        start, end = int(start_text), int(end_text)
        if end < start or (end - start) >= _RANGE_EXPANSION_CAP:
            ports.append(token)
            continue
        ports.extend("%s%d" % (prefix, number)
                     for number in range(start, end + 1))
    return ports


def parse_configured_mtus(config_text):
    """{port: configured_mtu} from an `nv config show -o commands` export."""
    configured = {}
    for line in config_text.splitlines():
        match = _NV_MTU_RE.match(line.strip())
        if not match:
            continue
        spec, value = match.groups()
        for port in expand_interface_spec(spec):
            configured[port] = int(value)
    return configured


def format_speed(mbps):
    if not mbps:
        return "N/A"
    if mbps % 1000 == 0:
        return "%dG" % (mbps // 1000)
    return "%dM" % mbps


# Genuine active-FEC encodings as ethtool reports them (casefolded).  Values
# outside this set — "Not-reported", vendor oddities — mean the driver did
# not disclose the running encoding, and comparing them would fabricate
# mismatches on links whose other end reports correctly.
_COMPARABLE_FEC = frozenset(("rs", "llrs", "baser", "fc", "none", "off"))


def _comparable_fec(value):
    """Casefolded FEC encoding, or None when not genuinely comparable."""
    token = str(value or "").casefold()
    if token not in _COMPARABLE_FEC:
        return None
    # "None" and "Off" are driver-dependent spellings of the same state
    # (kernel ETHTOOL_FEC_NONE_BIT vs ETHTOOL_FEC_OFF_BIT): both mean no
    # active FEC, so they must never be reported as a mismatch.  Raw
    # per-side strings stay untouched for display.
    return "off" if token == "none" else token


class FabricCheckAnalyzer:
    def __init__(self, result_dir=RESULT_DIR, sidecar_path=None,
                 configs_dir=None, now=None):
        self.result_dir = os.path.abspath(result_dir)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.sidecar_path = sidecar_path or os.environ.get(
            "LLDPQ_FABRIC_CHECK_SIDECAR") or os.path.join(
            script_dir, "lldp-results", "lldp_neighbors.json")
        self.configs_dir = configs_dir or get_configs_dir()
        self.now = int(now if now is not None else time.time())
        self.managed_devices = load_managed_devices(script_dir)
        self.findings = []
        self.links_checked = 0
        self.links_mtu_compared = 0
        self.links_speed_compared = 0
        self.links_fec_compared = 0
        self.links_autoneg_compared = 0
        self.ports_seen = 0
        self.ports_config_compared = 0
        self.devices_covered = set()
        self.mtu_distribution = {}
        self.sidecar_created = None
        self.sidecar_state = "missing"   # missing | legacy | ok

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self):
        try:
            with open(self.sidecar_path, encoding="utf-8") as handle:
                sidecar = json.load(handle)
        except (OSError, ValueError):
            sidecar = None
        if not isinstance(sidecar, dict):
            return
        neighbors = sidecar.get("neighbors")
        ports_map = sidecar.get("ports")
        self.sidecar_created = sidecar.get("created")
        if not isinstance(neighbors, dict):
            neighbors = {}
        if not isinstance(ports_map, dict):
            # Pre-enrichment sidecar: neighbor identities exist, but no port
            # attributes were captured — checks cannot run until the next
            # LLDP collection with the PORT_MTU/PORT_SPEED sections.
            self.sidecar_state = "legacy"
            return
        self.sidecar_state = "ok"

        managed_fold = {name.casefold(): name for name in self.managed_devices}
        device_key = {}
        for device in ports_map:
            device_key[str(device).casefold()] = device

        for device, ports in ports_map.items():
            if not isinstance(ports, dict):
                continue
            if str(device).casefold() not in managed_fold:
                continue
            self.devices_covered.add(device)
            for port, attrs in ports.items():
                if not isinstance(attrs, dict):
                    continue
                self.ports_seen += 1
                mtu = attrs.get("mtu")
                if isinstance(mtu, int):
                    entry = self.mtu_distribution.setdefault(
                        mtu, {"ports": 0, "devices": set()})
                    entry["ports"] += 1
                    entry["devices"].add(device)

        # ------------------------------------------------------------------
        # Link-level checks (both ends managed, attributes from ports map)
        # ------------------------------------------------------------------
        seen_links = set()
        for device, port_neighbors in sorted(neighbors.items(),
                                             key=lambda kv: str(kv[0]).casefold()):
            if not isinstance(port_neighbors, dict):
                continue
            local_ports = ports_map.get(device)
            local_ports = local_ports if isinstance(local_ports, dict) else {}
            for port, neighbor in sorted(port_neighbors.items()):
                if not isinstance(neighbor, dict):
                    continue
                remote_name = str(neighbor.get("device") or "")
                remote_port = str(neighbor.get("port") or "")
                if not remote_name or not remote_port:
                    continue
                remote_device = device_key.get(remote_name.casefold())
                if remote_device is None:
                    continue    # unmanaged / uncollected neighbor: no attrs
                link_key = tuple(sorted((
                    (str(device).casefold(), port),
                    (remote_name.casefold(), remote_port),
                )))
                if link_key in seen_links:
                    continue
                seen_links.add(link_key)
                local_attrs = local_ports.get(port)
                remote_ports = ports_map.get(remote_device)
                remote_attrs = remote_ports.get(remote_port) \
                    if isinstance(remote_ports, dict) else None
                local_attrs = local_attrs if isinstance(local_attrs, dict) else {}
                remote_attrs = remote_attrs if isinstance(remote_attrs, dict) else {}
                self.links_checked += 1

                local_mtu = local_attrs.get("mtu")
                remote_mtu = remote_attrs.get("mtu")
                if isinstance(local_mtu, int) and isinstance(remote_mtu, int):
                    self.links_mtu_compared += 1
                    if local_mtu != remote_mtu:
                        self.findings.append({
                            "check": "mtu-mismatch", "severity": "critical",
                            "device_a": device, "port_a": port,
                            "value_a": str(local_mtu),
                            "device_b": remote_device, "port_b": remote_port,
                            "value_b": str(remote_mtu),
                            "detail": "running MTU differs between link ends",
                        })

                local_speed = local_attrs.get("speed")
                remote_speed = remote_attrs.get("speed")
                if isinstance(local_speed, int) and isinstance(remote_speed, int):
                    self.links_speed_compared += 1
                    if local_speed != remote_speed:
                        self.findings.append({
                            "check": "speed-mismatch", "severity": "critical",
                            "device_a": device, "port_a": port,
                            "value_a": format_speed(local_speed),
                            "device_b": remote_device, "port_b": remote_port,
                            "value_b": format_speed(remote_speed),
                            "detail": "negotiated speed differs between link ends",
                        })

                # FEC/autoneg are best-effort attributes (ethtool on
                # carrier-up ports); the check only runs when both ends
                # reported a genuinely comparable value.  Drivers that answer
                # "Not-reported" (some host NICs) must not fabricate a
                # mismatch against a switch that reports its real encoding.
                local_fec = _comparable_fec(local_attrs.get("fec"))
                remote_fec = _comparable_fec(remote_attrs.get("fec"))
                if local_fec and remote_fec:
                    self.links_fec_compared += 1
                    if local_fec != remote_fec:
                        self.findings.append({
                            "check": "fec-mismatch", "severity": "critical",
                            "device_a": device, "port_a": port,
                            "value_a": str(local_attrs.get("fec")),
                            "device_b": remote_device, "port_b": remote_port,
                            "value_b": str(remote_attrs.get("fec")),
                            "detail": "active FEC encoding differs between "
                                      "link ends",
                        })

                local_an = str(local_attrs.get("autoneg") or "").casefold()
                remote_an = str(remote_attrs.get("autoneg") or "").casefold()
                if local_an in ("on", "off") and remote_an in ("on", "off"):
                    self.links_autoneg_compared += 1
                    if local_an != remote_an:
                        self.findings.append({
                            "check": "autoneg-mismatch", "severity": "warning",
                            "device_a": device, "port_a": port,
                            "value_a": local_an,
                            "device_b": remote_device, "port_b": remote_port,
                            "value_b": remote_an,
                            "detail": "auto-negotiation setting differs "
                                      "between link ends",
                        })

        # ------------------------------------------------------------------
        # Configured vs running MTU (per managed port with an explicit
        # `link mtu` line in the collected NVUE command export)
        # ------------------------------------------------------------------
        for device in sorted(self.devices_covered, key=str.casefold):
            config_path = os.path.join(self.configs_dir, "%s.txt" % device)
            try:
                with open(config_path, encoding="utf-8",
                          errors="replace") as handle:
                    configured = parse_configured_mtus(handle.read())
            except OSError:
                continue
            ports = ports_map.get(device)
            ports = ports if isinstance(ports, dict) else {}
            for port, attrs in sorted(ports.items()):
                if not isinstance(attrs, dict):
                    continue
                running = attrs.get("mtu")
                expected = configured.get(port)
                if not isinstance(running, int) or expected is None:
                    continue
                self.ports_config_compared += 1
                if running != expected:
                    self.findings.append({
                        "check": "config-mtu-mismatch", "severity": "warning",
                        "device_a": device, "port_a": port,
                        "value_a": str(running),
                        "device_b": None, "port_b": None,
                        "value_b": str(expected),
                        "detail": "running MTU differs from configured "
                                  "`link mtu`",
                    })

        severity_rank = {"critical": 0, "warning": 1}
        self.findings.sort(key=lambda item: (
            severity_rank.get(item["severity"], 2), item["check"],
            str(item["device_a"]).casefold(), item["port_a"]))

    # ------------------------------------------------------------------
    # Persistence + report
    # ------------------------------------------------------------------
    def collection_status(self):
        if self.sidecar_state != "ok":
            return "unavailable"
        if not self.devices_covered:
            return "unavailable"
        missing = {name.casefold() for name in self.managed_devices} - \
            {str(name).casefold() for name in self.devices_covered}
        return "partial" if missing else "current"

    def summary_counts(self):
        by_check = {"mtu-mismatch": 0, "speed-mismatch": 0,
                    "config-mtu-mismatch": 0,
                    "fec-mismatch": 0, "autoneg-mismatch": 0}
        for finding in self.findings:
            by_check[finding["check"]] = by_check.get(finding["check"], 0) + 1
        return {
            "devices_expected": len(self.managed_devices),
            "devices_covered": len(self.devices_covered),
            "links_checked": self.links_checked,
            "links_mtu_compared": self.links_mtu_compared,
            "links_speed_compared": self.links_speed_compared,
            "links_fec_compared": self.links_fec_compared,
            "links_autoneg_compared": self.links_autoneg_compared,
            "ports_seen": self.ports_seen,
            "ports_config_compared": self.ports_config_compared,
            "mtu_mismatches": by_check["mtu-mismatch"],
            "speed_mismatches": by_check["speed-mismatch"],
            "config_mtu_mismatches": by_check["config-mtu-mismatch"],
            "fec_mismatches": by_check["fec-mismatch"],
            "autoneg_mismatches": by_check["autoneg-mismatch"],
            "findings_total": len(self.findings),
        }

    def export_rows(self):
        rows = []
        for finding in self.findings:
            rows.append({
                "check": finding["check"],
                "severity": finding["severity"],
                "device_a": finding["device_a"],
                "port_a": finding["port_a"],
                "value_a": finding["value_a"],
                "device_b": finding["device_b"],
                "port_b": finding["port_b"],
                "value_b": finding["value_b"],
                "detail": finding["detail"],
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
            '<div data-analysis-summary="fabric-check"'
            ' data-collection-status="%s"'
            ' data-devices-expected="%d"'
            ' data-devices-covered="%d"'
            ' data-links-checked="%d"'
            ' data-mtu-mismatches="%d"'
            ' data-speed-mismatches="%d"'
            ' data-config-mtu-mismatches="%d"'
            ' data-fec-mismatches="%d"'
            ' data-autoneg-mismatches="%d"'
            ' data-findings-total="%d" style="display:none"></div>'
        ) % (
            status, counts["devices_expected"], counts["devices_covered"],
            counts["links_checked"], counts["mtu_mismatches"],
            counts["speed_mismatches"], counts["config_mtu_mismatches"],
            counts["fec_mismatches"], counts["autoneg_mismatches"],
            counts["findings_total"],
        )

        coverage_banner = ""
        if status == "unavailable":
            if self.sidecar_state == "legacy":
                coverage_banner = (
                    "<div class='coverage-banner banner-critical'>"
                    "The LLDP neighbor sidecar predates port-attribute "
                    "collection &mdash; link checks need one fresh LLDP "
                    "collection cycle (runs automatically with the pipeline)."
                    "</div>"
                )
            else:
                coverage_banner = (
                    "<div class='coverage-banner banner-critical'>"
                    "No LLDP neighbor data available &mdash; link consistency "
                    "cannot be evaluated. Empty tables below do <b>not</b> "
                    "mean the fabric is consistent.</div>"
                )
        elif status == "partial":
            missing = sorted(
                name for name in self.managed_devices
                if str(name).casefold() not in
                {str(item).casefold() for item in self.devices_covered})
            shown = ", ".join(missing[:6])
            if len(missing) > 6:
                shown += " (+%d more)" % (len(missing) - 6)
            coverage_banner = (
                "<div class='coverage-banner'>"
                "Partial coverage &mdash; %d/%d managed devices in the LLDP "
                "collection; links touching missing devices are not checked. "
                "<span class='banner-detail'>[%s]</span></div>"
            ) % (counts["devices_covered"], counts["devices_expected"],
                 html.escape(shown))

        cards = [
            ("card-info", counts["links_checked"], "LINKS CHECKED", ""),
            ("card-critical" if counts["mtu_mismatches"] else "card-excellent",
             counts["mtu_mismatches"], "MTU MISMATCHES", "mtu"),
            ("card-critical" if counts["speed_mismatches"] else
             "card-excellent", counts["speed_mismatches"],
             "SPEED MISMATCHES", "speed"),
            ("card-critical" if counts["fec_mismatches"] else
             "card-excellent", counts["fec_mismatches"],
             "FEC MISMATCHES", "fec"),
            ("card-warning" if counts["autoneg_mismatches"] else
             "card-excellent", counts["autoneg_mismatches"],
             "AUTONEG MISMATCHES", "autoneg"),
            ("card-warning" if counts["config_mtu_mismatches"] else
             "card-excellent", counts["config_mtu_mismatches"],
             "CONFIG &ne; RUNNING MTU", "config"),
            ("card-info", "%d/%d" % (counts["devices_covered"],
                                     counts["devices_expected"]),
             "DEVICES COVERED", ""),
        ]
        cards_html = "".join(
            "<div class='summary-card %s%s'%s><div class='metric'>%s</div>"
            "<div class='metric-label'>%s</div></div>" % (
                cls, ("" if action else " noclick"),
                (" onclick=\"cardFilter('%s', this)\"" % action) if action else "",
                "{:,}".format(value) if isinstance(value, int) else value, label)
            for cls, value, label, action in cards)

        finding_html = []
        for finding in self.findings:
            severity = finding["severity"]
            badge = ("<span class='badge badge-red'>critical</span>"
                     if severity == "critical" else
                     "<span class='badge badge-orange'>warning</span>")
            check_label = {
                "mtu-mismatch": "MTU mismatch",
                "speed-mismatch": "Speed mismatch",
                "fec-mismatch": "FEC mismatch",
                "autoneg-mismatch": "Autoneg mismatch",
                "config-mtu-mismatch": "Config &ne; running MTU",
            }.get(finding["check"], html.escape(finding["check"]))
            devices_attr = " ".join(
                sorted({str(finding["device_a"]).lower()} |
                       ({str(finding["device_b"]).lower()}
                        if finding["device_b"] else set())))
            side_b = ("<td>%s</td><td class='mono'>%s</td>" % (
                html.escape(str(finding["device_b"])),
                html.escape(str(finding["port_b"]))
            )) if finding["device_b"] else \
                "<td><span class='dim'>&mdash;</span></td>" \
                "<td><span class='dim'>&mdash;</span></td>"
            finding_html.append(
                "<tr data-devices='%s' data-check='%s' data-severity='%s'>"
                "<td data-sort='%d'>%s</td><td>%s</td>"
                "<td>%s</td><td class='mono'>%s</td>"
                "<td class='mono'>%s</td>%s<td class='mono'>%s</td>"
                "<td>%s</td></tr>" % (
                    html.escape(devices_attr, quote=True),
                    finding["check"], severity,
                    0 if severity == "critical" else 1, badge, check_label,
                    html.escape(str(finding["device_a"])),
                    html.escape(str(finding["port_a"])),
                    html.escape(str(finding["value_a"])),
                    side_b,
                    html.escape(str(finding["value_b"])),
                    html.escape(finding["detail"]),
                ))
        if not finding_html:
            if status == "current":
                finding_html.append(
                    "<tr><td colspan='9' class='empty'>No link consistency "
                    "issues found &mdash; MTU and speed agree on every "
                    "checked link.</td></tr>")
            else:
                finding_html.append(
                    "<tr><td colspan='9' class='empty empty-stale'>No "
                    "findings &mdash; but coverage is incomplete (see banner)."
                    "</td></tr>")

        mtu_html = []
        total_mtu_ports = sum(entry["ports"] for entry in
                              self.mtu_distribution.values())
        for mtu_value in sorted(self.mtu_distribution,
                                key=lambda value:
                                -self.mtu_distribution[value]["ports"]):
            entry = self.mtu_distribution[mtu_value]
            share = (100.0 * entry["ports"] / total_mtu_ports) \
                if total_mtu_ports else 0.0
            mtu_html.append(
                "<tr><td data-sort='%d' class='mono'>%d</td>"
                "<td data-sort='%d'>%s</td><td data-sort='%d'>%d</td>"
                "<td data-sort='%.1f'>%.1f%%</td></tr>" % (
                    mtu_value, mtu_value,
                    entry["ports"], "{:,}".format(entry["ports"]),
                    len(entry["devices"]), len(entry["devices"]),
                    share, share,
                ))
        if not mtu_html:
            mtu_html.append(
                "<tr><td colspan='4' class='empty empty-stale'>No port MTU "
                "data collected yet.</td></tr>")

        html_doc = _PAGE_TEMPLATE
        html_doc = html_doc.replace("__MACHINE_SUMMARY__", machine_summary)
        html_doc = html_doc.replace("__COVERAGE_BANNER__", coverage_banner)
        html_doc = html_doc.replace("__NOW__", html.escape(now_text))
        html_doc = html_doc.replace("__CARDS__", cards_html)
        html_doc = html_doc.replace("__FINDING_ROWS__", "\n".join(finding_html))
        html_doc = html_doc.replace("__MTU_ROWS__", "\n".join(mtu_html))
        html_doc = html_doc.replace(
            "__SIDECAR_CREATED__",
            html.escape(str(self.sidecar_created or "N/A")))
        html_doc = html_doc.replace(
            "__DEVICES__",
            json.dumps(sorted(self.devices_covered, key=str.casefold)))
        _atomic_write(output_file, html_doc)

        summary_path = os.path.join(
            os.path.dirname(os.path.abspath(output_file)),
            "summary", "fabric-check-summary.json",
        )
        generated_at = int(time.time())
        summary_counts = self.summary_counts()
        _atomic_write(summary_path, json.dumps({
            "domain": "fabric-check",
            "generated_at": generated_at,
            "collection_status": status,
            **summary_counts,
        }) + "\n")

        export_artifacts.write_export(
            os.path.dirname(os.path.abspath(output_file)),
            "fabric-check", self.export_rows(), summary_counts, status,
            generated_at=generated_at,
        )


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fabric Check Analysis</title>
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
table.fc-table { width:100%; border-collapse:collapse; font-size:13px; }
.fc-table th, .fc-table td { border:1px solid #404040; padding:9px 11px; text-align:left; vertical-align:top; }
.fc-table th { background:#333; color:#76b900; font-weight:600; font-size:12px; cursor:pointer; user-select:none; }
.fc-table th:hover { background:#3c3c3c; }
.fc-table tbody tr { background:#252526; }
.fc-table tbody tr:hover { background:#2d2d2d; }
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
    <div class="page-title">Fabric Check Analysis</div>
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
  <div class="section-header">Findings (link &amp; port consistency)</div>
  <div class="section-content">
    <table class="fc-table" id="fct" data-filterable>
      <thead><tr><th>Severity</th><th>Check</th><th>Device A</th><th>Port A</th><th>Value A</th><th>Device B</th><th>Port B</th><th>Value B</th><th>Detail</th></tr></thead>
      <tbody>__FINDING_ROWS__</tbody>
    </table>
  </div>
</div>
<div class="dashboard-section">
  <div class="section-header">Fabric MTU Distribution (collected physical ports)</div>
  <div class="section-content">
    <table class="fc-table" id="mtut" data-filterable>
      <thead><tr><th>MTU</th><th>Ports</th><th>Devices</th><th>Share</th></tr></thead>
      <tbody>__MTU_ROWS__</tbody>
    </table>
  </div>
</div>

<div class="modal" id="thr">
  <div class="modal-box">
    <div class="modal-head"><h3>Fabric Check &mdash; Sources &amp; Semantics</h3>
      <button class="modal-close" onclick="document.getElementById('thr').classList.remove('show')">&times;</button></div>
    <div class="modal-body">
      <h4>Data sources</h4>
      Per-port <b>running MTU</b> and <b>negotiated speed</b> are read from sysfs during the LLDP
      collection stage and published in the LLDP neighbor sidecar (created: <code>__SIDECAR_CREATED__</code>).
      Link pairing comes from observed LLDP neighborships; both ends must be managed devices for a link
      to be checked. <b>Configured MTU</b> comes from the collected
      <code>nv config show -o commands</code> exports (<code>nv set interface &lt;port&gt; link mtu</code>,
      compacted ranges expanded).
      <h4>Checks</h4>
      <b>MTU mismatch</b> (critical) &mdash; the two ends of a link run different MTUs; large frames are
      silently dropped in one direction. <b>Speed mismatch</b> (critical) &mdash; the two ends negotiated
      different speeds; usually a breakout or autoneg problem (down/absent ports report no speed and are
      not compared). <b>Config &ne; running MTU</b> (warning) &mdash; a port's running MTU differs from its
      explicit configured value; only ports with an explicit <code>link mtu</code> line are compared,
      platform defaults are never inferred.
      <h4>MTU distribution</h4>
      Informational view of the running MTU across every collected physical port &mdash; a healthy fabric is
      strongly clustered; small islands are worth explaining (host-facing vs fabric MTU is expected,
      a lone 1500 on a fabric link is not).
      <h4>Coverage</h4>
      Speed is reported only for ports with an active link; MTU is reported for down ports too. A device
      missing from the LLDP collection removes all of its links from the checked set &mdash; the coverage
      banner and the DEVICES COVERED card make that visible.
    </div>
  </div>
</div>

<script src="/css/jquery-3.5.1.min.js"></script>
<script src="/css/select2.min.js"></script>
<script>
var FC_DEVICES = __DEVICES__;
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
['fct','mtut'].forEach(function(tid){
  var t=document.getElementById(tid); if(!t) return;
  Array.prototype.forEach.call(t.tHead.rows[0].cells, function(th, i){
    var num = /Severity|MTU|Ports|Devices|Share/i.test(th.innerText);
    th.addEventListener('click', function(){ sortTable(tid, i, num); });
  });
});
document.getElementById('thr').addEventListener('click', function(e){ if(e.target===this) this.classList.remove('show'); });

function allRows(){ return [].concat(
  Array.prototype.slice.call(document.querySelectorAll('#fct tbody tr')),
  Array.prototype.slice.call(document.querySelectorAll('#mtut tbody tr'))); }
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
  var checkMap={mtu:'mtu-mismatch', speed:'speed-mismatch', fec:'fec-mismatch', autoneg:'autoneg-mismatch', config:'config-mtu-mismatch'};
  var target=checkMap[kind];
  if(!target){ return; }
  Array.prototype.slice.call(document.querySelectorAll('#fct tbody tr')).forEach(function(r){
    if(r.querySelector('.empty')) return;
    r.style.display = (r.getAttribute('data-check')===target) ? '' : 'none';
  });
  document.getElementById('fct').scrollIntoView({behavior:'smooth', block:'start'});
  var labels={mtu:'MTU mismatches', speed:'Speed mismatches', config:'Config \\u2260 running MTU', fec:'FEC mismatches', autoneg:'Autoneg mismatches'};
  setFilterInfo(labels[kind]);
}
function filterByDevice(dev){
  if(!dev) return;
  dev = String(dev).toLowerCase();
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  Array.prototype.slice.call(document.querySelectorAll('#fct tbody tr')).forEach(function(r){
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
      ? await window.lldpqCaptureAnalysisState('fabric-check') : null;
    var response = await fetch('/trigger-monitor?scope=fabric-check',{
      method:'POST', headers:{'Content-Type':'application/json'}
    });
    var data = await response.json();
    if(!response.ok || !data || data.status!=='success' || !data.trigger_id || data.scope!=='fabric-check'){
      throw new Error((data && data.message) || 'Failed to trigger analysis.');
    }
    if(typeof window.waitForLldpqAnalysisCompletion === 'function'){
      await window.waitForLldpqAnalysisCompletion(
        baseline, {scope:'fabric-check', pipelineId:data.trigger_id});
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
  [['Findings (link & port consistency)','fct'],
   ['Fabric MTU Distribution','mtut']].forEach(function(sec){
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
  a.href=URL.createObjectURL(blob); a.download='Fabric_Check_Analysis_'+ts+'.csv'; document.body.appendChild(a); a.click(); a.remove();
}
document.addEventListener('DOMContentLoaded', function(){
  if(window.jQuery){
    var $s=jQuery('#deviceSearch'); var opts='<option value=""></option>';
    var escHtml=function(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); };
    FC_DEVICES.forEach(function(dv){ opts+='<option value="'+escHtml(dv)+'">'+escHtml(dv)+'</option>'; });
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
    analyzer = FabricCheckAnalyzer(RESULT_DIR)
    analyzer.analyze()
    output_file = os.path.join(RESULT_DIR, OUTPUT_HTML)
    analyzer.export_html(output_file)

    counts = analyzer.summary_counts()
    print("Fabric check analysis complete:")
    print("  Devices covered      : %d/%d" % (
        counts["devices_covered"], counts["devices_expected"]))
    print("  Links checked        : %d" % counts["links_checked"])
    print("  MTU mismatches       : %d" % counts["mtu_mismatches"])
    print("  Speed mismatches     : %d" % counts["speed_mismatches"])
    print("  Config != running MTU: %d" % counts["config_mtu_mismatches"])
    print("  Ports seen           : %d" % counts["ports_seen"])
    print("  -> %s" % output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
