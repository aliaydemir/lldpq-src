#!/usr/bin/env python3
"""
Process optical diagnostics data collected by monitor.sh

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from datetime import datetime
from optical_analyzer import OpticalAnalyzer, _atomic_write
from collection_freshness import (
    asset_snapshot_is_valid,
    is_current_collection,
    mark_html_collection_unavailable,
    read_asset_snapshot,
)

NO_TRANSCEIVER_DATA_RE = re.compile(
    r'\bno\s+(?:transceiver|module)\s+data(?:\s+available)?\b',
    re.IGNORECASE,
)
OPTICAL_COLLECTION_ERROR_RE = re.compile(
    r'^__LLDPQ_COLLECTION_ERROR__:'
    r'(?P<reason>OPTICAL_LINK_INVENTORY|OPTICAL_BUDGET|OPTICAL_TIMEOUT|'
    r'OPTICAL_TOOL_UNAVAILABLE)'
    r'(?::(?P<interface>[A-Za-z0-9_.:-]+))?$',
    re.MULTILINE,
)


def record_optical_state(analyzer, port_name, hostname, health_status,
                         raw_data=''):
    """Keep an explicit row when diagnostics are unavailable or unplugged."""
    analyzer.current_optical_stats[port_name] = {
        'port': port_name,
        'device': hostname,
        'health_status': health_status,
        'rx_power_dbm': None,
        'tx_power_dbm': None,
        'temperature_c': None,
        'voltage_v': None,
        'bias_current_ma': None,
        'link_margin_db': None,
        'last_updated': time.time(),
        'raw_data': raw_data[:500],
    }

def parse_optical_collection_errors(content):
    """Return validated category-local optical collection failures."""
    failures = []
    for match in OPTICAL_COLLECTION_ERROR_RE.finditer(content):
        reason = match.group('reason')
        interface = match.group('interface')
        if reason == 'OPTICAL_LINK_INVENTORY':
            if interface is not None:
                continue
        elif interface is None:
            continue
        failures.append((reason, interface))
    return failures


def _parse_optical_diagnostics_content(content):
    port_data = {}
    sections = content.split("--- Interface:")
    for section in sections[1:]:  # Skip the collection preamble.
        lines = section.strip().split('\n')
        if not lines:
            continue
        interface_match = re.match(r'(\w+)', lines[0].strip())
        if not interface_match:
            continue
        port_data[interface_match.group(1)] = '\n'.join(lines[1:])
    return port_data


def read_optical_diagnostics_file(filepath):
    """Read one optical file once and return ports plus collection failures."""
    try:
        with open(filepath, "r") as stream:
            content = stream.read()
    except Exception as exc:
        print(f"Error parsing {filepath}: {exc}")
        return {}, []
    return (
        _parse_optical_diagnostics_content(content),
        parse_optical_collection_errors(content),
    )


def parse_optical_diagnostics_file(filepath):
    """Parse optical diagnostics file, retaining the legacy dict return type."""
    port_data, _failures = read_optical_diagnostics_file(filepath)
    return port_data


def describe_optical_collection_failure(reason, interface=None):
    if reason == 'OPTICAL_LINK_INVENTORY':
        return 'Physical interface inventory was unavailable'
    if reason == 'OPTICAL_BUDGET':
        return f'Optical collection budget was exhausted at {interface}'
    if reason == 'OPTICAL_TIMEOUT':
        return f'Optical diagnostics timed out for {interface}'
    if reason == 'OPTICAL_TOOL_UNAVAILABLE':
        return f'Bounded optical diagnostics are unavailable for {interface}'
    return 'Optical diagnostics collection was incomplete'

# Per-process analyzer for parse workers: thresholds and parsing logic only,
# without the multi-megabyte history the parent keeps.
_parse_worker_analyzer = None


def _init_optical_parse_worker(result_dir):
    global _parse_worker_analyzer
    _parse_worker_analyzer = OpticalAnalyzer(result_dir, load_history=False)


def _classify_optical_file(filepath, hostname):
    """Parse one device's optical file and return merge operations.

    Runs in a worker process.  Decisions that need the parent's optical
    history (unplugged detection) are deferred as 'maybe_unplugged' ops so
    the parent resolves them during the merge.
    """
    port_data, file_failures = read_optical_diagnostics_file(filepath)
    failed_interfaces = {
        interface for _reason, interface in file_failures if interface
    }
    analyzer = _parse_worker_analyzer
    ops = []

    def updated_entries(port_name):
        stats_entry = analyzer.current_optical_stats.get(port_name)
        history = analyzer.optical_history.get(port_name)
        return stats_entry, (history[-1] if history else None)

    for interface, optical_data in port_data.items():
        port_name = f"{hostname}:{interface}"

        if interface in failed_interfaces:
            ops.append(('state', port_name, 'unknown', optical_data[:500]))
            continue

        # Skip non-optical interfaces (management, virtual interfaces)
        if any(skip_iface in interface.lower() for skip_iface in ['eth0', 'lo', 'bond', 'mgmt', 'vlan']):
            continue

        # Empty interface sections do not prove that an optical module
        # exists, so they must not become monitored optical ports.
        if not optical_data or len(optical_data.strip()) < 10:
            continue

        # The collector emits these markers for ordinary empty cages,
        # down ports and interfaces without readable module EEPROM.
        # Device-level collection coverage is tracked separately; an
        # absent DOM sample is not an optical fault or a monitored port.
        if (NO_TRANSCEIVER_DATA_RE.search(optical_data) or
            ("diagnostics-status          : N/A" in optical_data and
             "temperature" not in optical_data and "voltage" not in optical_data and
             "rx-power" not in optical_data and "tx-power" not in optical_data)):
            # ethtool reports an empty cage as a down interface with
            # no transceiver data.  A port with previous optical
            # readings that now reads empty is an unplugged module,
            # not a never-populated cage.  Previous readings live in
            # the parent's history, so the decision is deferred.
            if (NO_TRANSCEIVER_DATA_RE.search(optical_data) and
                    re.search(r'^\s*Interface\s+state\s*:\s*down\b',
                              optical_data,
                              re.IGNORECASE | re.MULTILINE)):
                ops.append(('maybe_unplugged', port_name, optical_data[:500]))
            continue

        # DAC/Copper cables do not provide optical diagnostics.  Keep
        # this check before interface-state handling so a down DAC is
        # not reclassified as a failed optical link.  Vendor identity
        # lines (SN/PN/date code) may coincidentally contain 'DAC', so
        # classify from descriptor lines only.
        if any(indicator in line
               for line in optical_data.split('\n')
               if not re.match(r'\s*(?:vendor|serial|date)',
                               line, re.IGNORECASE)
               for indicator in [
                   'Passive copper', 'Active copper', 'Copper cable',
                   'Base-CR', 'DAC', 'Twinax', 'No separable connector'
               ]):
            continue

        # Check for unplugged ports - add as "unplugged" status for troubleshooting
        if re.search(r'^\s*status\s*:\s*unplugged\b', optical_data,
                     re.IGNORECASE | re.MULTILINE):
            ops.append(('state', port_name, 'unplugged', optical_data[:500]))
            continue

        state_match = re.search(
            r'^\s*Interface\s+state\s*:\s*([^\s]+)',
            optical_data,
            re.IGNORECASE | re.MULTILINE,
        )
        interface_state = (
            state_match.group(1).strip().lower()
            if state_match else None
        )
        if interface_state in {'down', 'lowerlayerdown', 'dormant'}:
            # Preserve a DOWN row only when real DOM values remain
            # readable.  The no-data and DAC cases were excluded above.
            parsed = analyzer.parse_optical_data(optical_data)
            usable_dom = parsed is not None and any(
                parsed.get(metric) is not None for metric in (
                    'rx_power_dbm', 'tx_power_dbm', 'temperature_c',
                    'voltage_v', 'bias_current_ma'
                )
            )
            if not usable_dom:
                continue
            if analyzer.update_optical_stats(port_name, optical_data):
                stats_entry, history_entry = updated_entries(port_name)
                if stats_entry:
                    stats_entry['health_status'] = 'down'
                if history_entry:
                    history_entry['health'] = 'down'
                ops.append(('update', port_name, stats_entry, history_entry))
            continue
        if interface_state == 'unknown':
            ops.append(('state', port_name, 'unknown', optical_data[:500]))
            continue

        # Check for ports with no meaningful optical readings (N/A values, temp 0.0, etc.)
        if (("temperature                 : 0.0" in optical_data or
             "temperature                 : 0.00" in optical_data) and
            ("voltage                     : 0.0" in optical_data or
             "voltage                     : 0.00" in optical_data)):
            ops.append(('state', port_name, 'unknown', optical_data[:500]))
            continue

        # Update optical analyzer
        if analyzer.update_optical_stats(port_name, optical_data):
            ops.append(('update', port_name, *updated_entries(port_name)))

    # A well-formed timeout marker normally sits inside its interface
    # block.  Retain visibility even if a future collector emits the
    # marker without that block.
    for reason, interface in file_failures:
        if interface and interface not in port_data:
            ops.append((
                'state', f"{hostname}:{interface}", 'unknown',
                describe_optical_collection_failure(reason, interface),
            ))

    return ops, file_failures


def _merge_optical_ops(analyzer, hostname, ops):
    """Apply one file's worker ops to the parent analyzer state."""
    for op in ops:
        kind = op[0]
        if kind == 'state':
            _kind, port_name, health, snippet = op
            record_optical_state(analyzer, port_name, hostname, health, snippet)
        elif kind == 'maybe_unplugged':
            _kind, port_name, snippet = op
            if port_name in analyzer.optical_history:
                record_optical_state(
                    analyzer, port_name, hostname, 'unplugged', snippet
                )
        elif kind == 'update':
            _kind, port_name, stats_entry, history_entry = op
            if stats_entry:
                analyzer.current_optical_stats[port_name] = stats_entry
            if history_entry:
                history = analyzer.optical_history.setdefault(port_name, [])
                history.append(history_entry)
                # Keep last 100 entries, matching update_optical_stats
                if len(history) > 100:
                    analyzer.optical_history[port_name] = history[-100:]


def _optical_parse_worker_limit(task_count):
    raw = os.environ.get("OPTICAL_PARSE_MAX_PARALLEL", "")
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        value = min(8, os.cpu_count() or 2)
    return max(1, min(value, task_count))


def _classify_optical_files(result_dir, tasks):
    """Yield (hostname, ops, file_failures) per file, parallel when possible."""
    completed = 0
    workers = _optical_parse_worker_limit(len(tasks))
    if workers > 1:
        try:
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_init_optical_parse_worker,
                initargs=(result_dir,),
            ) as executor:
                futures = [
                    (hostname,
                     executor.submit(_classify_optical_file, filepath, hostname))
                    for filepath, hostname in tasks
                ]
                for hostname, future in futures:
                    ops, file_failures = future.result()
                    yield hostname, ops, file_failures
                    completed += 1
                return
        except (OSError, PermissionError, BrokenProcessPool):
            # Constrained containers can deny multiprocessing primitives.
            # Fall back to the same complete parse for the remaining files,
            # never to a skipped device.
            pass
    _init_optical_parse_worker(result_dir)
    for filepath, hostname in tasks[completed:]:
        ops, file_failures = _classify_optical_file(filepath, hostname)
        yield hostname, ops, file_failures


def process_optical_data_files(data_dir="monitor-results/optical-data"):
    """Process optical data files and update optical analyzer"""
    data_dir = os.path.abspath(data_dir)
    result_dir = os.path.dirname(data_dir.rstrip(os.sep))

    timing_enabled = os.environ.get("LLDPQ_ANALYZER_TIMING", "").lower() in {
        "1", "true", "yes", "on",
    }
    phase_started = time.monotonic()

    def finish_phase(name):
        nonlocal phase_started
        now = time.monotonic()
        if timing_enabled:
            elapsed_ms = max(0, int((now - phase_started) * 1000))
            print(
                f"__LLDPQ_ANALYZER_TIMING__:optical:{name}:{elapsed_ms}",
                flush=True,
            )
        phase_started = now

    optical_analyzer = OpticalAnalyzer(result_dir)
    finish_phase("load")
    # Historical readings remain in optical_history; only files from this
    # successful collection may populate the current snapshot.
    optical_analyzer.current_optical_stats = {}

    print("Processing optical diagnostics data")
    print(f"Data directory: {data_dir}")
    print(
        f"Using optical thresholds: RX Power min={optical_analyzer.thresholds['rx_power_min_dbm']:.1f} dBm, "
        f"warn high={optical_analyzer.thresholds.get('rx_power_warning_high_dbm', 5.0):.1f} dBm, "
        f"crit high={optical_analyzer.thresholds.get('rx_power_critical_high_dbm', 7.0):.1f} dBm, "
        f"Temperature max={optical_analyzer.thresholds['temperature_max_c']:.1f}°C"
    )

    if not os.path.exists(data_dir):
        print(f"❌ Optical data directory {data_dir} not found")
        return False

    # List files in directory
    asset_snapshot = read_asset_snapshot()
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("❌ Asset snapshot is invalid or incomplete")
        return False
    inventory_hosts = set(statuses) if snapshot_valid else set()
    current_expected_hosts = (
        {host for host, status in statuses.items() if status == "OK"}
        if snapshot_valid else set()
    )
    all_devices_unavailable = snapshot_valid and not current_expected_hosts
    files = [
        filename for filename in os.listdir(data_dir)
        if filename.endswith("_optical.txt")
        and is_current_collection(
            os.path.join(data_dir, filename),
            filename.removesuffix("_optical.txt"),
            asset_snapshot,
        )
    ]
    print(f"Found {len(files)} optical data files")

    collected_hosts = {
        filename.removesuffix("_optical.txt") for filename in files
    }
    missing_current_hosts = current_expected_hosts - collected_hosts
    if snapshot_valid and missing_current_hosts:
        print(
            "⚠ Missing current optical collections for: "
            + ", ".join(sorted(missing_current_hosts))
        )
    if not files and not all_devices_unavailable:
        print("⚠ No current optical collection files found; publishing partial coverage")

    # Process all optical diagnostic files.  The regex-heavy classification
    # fans out to worker processes; history-dependent decisions and all state
    # mutation happen here, in submission order.
    total_processed = 0
    failed_collection_hosts = set()
    collection_failures = {}
    tasks = [
        (os.path.join(data_dir, filename),
         filename.removesuffix("_optical.txt"))
        for filename in files
    ]
    for hostname, ops, file_failures in _classify_optical_files(result_dir, tasks):
        # Category-local collector failures remain per file so the optical
        # report can expose incomplete coverage without invalidating BGP,
        # BER, PFC, hardware, logs, or other complete categories.
        if file_failures:
            failed_collection_hosts.add(hostname)
            collection_failures[hostname] = [
                describe_optical_collection_failure(reason, interface)
                for reason, interface in file_failures
            ]
        total_processed += 1
        _merge_optical_ops(optical_analyzer, hostname, ops)

    print(f"\nProcessed {total_processed} files total")
    finish_phase("parse_records")

    # Save updated optical history
    optical_analyzer.save_optical_history()
    print("Optical history saved")
    finish_phase("write_history")

    # Generate web report
    output_file = os.path.join(result_dir, "optical-analysis.html")
    if snapshot_valid:
        successful_hosts = collected_hosts - failed_collection_hosts
        coverage_missing_hosts = inventory_hosts - successful_hosts
        for hostname in coverage_missing_hosts:
            if hostname not in collection_failures:
                if hostname in missing_current_hosts:
                    collection_failures[hostname] = [
                        'No current optical collection was published'
                    ]
                else:
                    collection_failures[hostname] = [
                        f'Device collection status is {statuses.get(hostname, "unavailable")}'
                    ]
        optical_analyzer.coverage_expected_hosts = len(inventory_hosts)
        optical_analyzer.coverage_collected_hosts = len(collected_hosts)
        optical_analyzer.coverage_current_hosts = len(successful_hosts)
        optical_analyzer.coverage_missing_hosts = sorted(coverage_missing_hosts)
        optical_analyzer.coverage_failures = collection_failures
    elif collection_failures:
        optical_analyzer.coverage_missing_hosts = sorted(collection_failures)
        optical_analyzer.coverage_failures = collection_failures
    optical_analyzer.export_optical_data_for_web(output_file)
    if all_devices_unavailable:
        mark_html_collection_unavailable(output_file)
    print(f"Optical analysis report generated: {output_file}")
    finish_phase("render")

    # Generate summary for dashboard
    summary = optical_analyzer.get_optical_summary()
    anomalies = optical_analyzer.detect_optical_anomalies()

    # Machine-readable dashboard summary. Additive to the HTML report and
    # carrying the same headline numbers/collection status the report embeds.
    coverage_expected = getattr(optical_analyzer, 'coverage_expected_hosts', None)
    coverage_collected = getattr(optical_analyzer, 'coverage_collected_hosts', None)
    coverage_current = getattr(optical_analyzer, 'coverage_current_hosts', None)
    if all_devices_unavailable:
        collection_status = "unavailable"
    elif isinstance(coverage_expected, int) and isinstance(coverage_current, int):
        collection_status = (
            "complete" if coverage_current >= coverage_expected else "partial"
        )
    else:
        collection_status = None
    _atomic_write(
        os.path.join(result_dir, "summary", "optical-summary.json"),
        json.dumps({
            "domain": "optical",
            "generated_at": int(time.time()),
            "collection_status": collection_status,
            "coverage_expected": coverage_expected,
            "coverage_current": coverage_current,
            "coverage_collected": coverage_collected,
            "total_devices": len({
                port.split(':', 1)[0]
                for port in optical_analyzer.current_optical_stats
            }),
            "total_ports": summary["total_ports"],
            "excellent": len(summary["excellent_ports"]),
            "good": len(summary["good_ports"]),
            "warning": len(summary["warning_ports"]),
            "critical": len(summary["critical_ports"]),
            "down": len(summary["down_ports"]),
            "unplugged": len(summary["unplugged_ports"]),
            "unknown": len(summary["unknown_ports"]),
        }) + "\n",
    )
    finish_phase("write_summary")
    print(f"Summary stats: {len(optical_analyzer.current_optical_stats)} total ports analyzed")

    print(f"\nOptical Analysis Summary:")
    print(f"  Total ports monitored: {summary['total_ports']}")
    print(f"  Excellent health: {len(summary['excellent_ports'])}")
    print(f"  Good health: {len(summary['good_ports'])}")
    print(f"  Warning level: {len(summary['warning_ports'])}")
    print(f"  Critical issues: {len(summary['critical_ports'])}")
    print(f"  No receive light / down: {len(summary['down_ports'])}")
    print(f"  Modules unplugged: {len(summary['unplugged_ports'])}")
    print(f"  Diagnostics unavailable: {len(summary['unknown_ports'])}")
    print(f"  Anomalies detected: {len(anomalies)}")

    if summary['critical_ports']:
        print("\nCritical Optical Issues (Immediate Attention):")
        for port in summary['critical_ports']:
            rx_power = f"{port['rx_power_dbm']:.2f} dBm" if port['rx_power_dbm'] is not None else "N/A"
            temp = f"{port['temperature_c']:.1f}°C" if port['temperature_c'] is not None else "N/A"
            print(f"    {port['port']}: Health={port['health'].upper()}, RX Power={rx_power}, Temp={temp}")

    if summary['warning_ports']:
        print("\n🟠 Warning Level Issues (Monitor Closely):")
        for port in summary['warning_ports'][:5]:  # Show top 5
            rx_power = f"{port['rx_power_dbm']:.2f} dBm" if port['rx_power_dbm'] is not None else "N/A"
            link_margin = f"{port['link_margin_db']:.2f} dB" if port['link_margin_db'] is not None else "N/A"
            print(f"    {port['port']}: Health={port['health'].upper()}, RX Power={rx_power}, Link Margin={link_margin}")

    if anomalies:
        print("\n⚠️ Optical Anomalies Detected:")
        for anomaly in anomalies[:3]:  # Show top 3
            print(f"    {anomaly['port']}: {anomaly['type']} - {anomaly['message']}")
            print(f"      Action: {anomaly['action']}")

    # Check for excellent performers
    if summary['excellent_ports']:
        print(f"\nExcellent Optical Health: {len(summary['excellent_ports'])} ports performing optimally")
    return True

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    print(f"[{datetime.now()}] Starting optical data processing")
    success = process_optical_data_files()
    print(f"[{datetime.now()}] Optical data processing completed")
    sys.exit(0 if success else 1)
