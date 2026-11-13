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
import analysis_sidecar
import export_artifacts
from optical_analyzer import (
    HISTORY_DIR_NAME,
    OpticalAnalyzer,
    _atomic_write,
)
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


DOM_UNREADABLE_NOTE = ('Module diagnostics could not be read although the link '
                       'is up (ethtool -m returned no data)')


def record_optical_state(analyzer, port_name, hostname, health_status,
                         raw_data='', note=None):
    """Keep an explicit row when diagnostics are unavailable or unplugged.

    ``note`` says why a row has no readings; the report lists it with the
    row's findings.
    """
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
    if note:
        analyzer.current_optical_stats[port_name]['note'] = note


def _has_optical_history(analyzer, port_name):
    """True when the port delivered optical diagnostics in an earlier run.

    A row that never held a reading (a copper pluggable once listed as
    'unknown') left history entries too; they do not make the port optical.
    """
    return any(
        entry.get('health') not in (None, 'unknown', 'unplugged')
        or any(entry.get(key) is not None for key in (
            'rx_power_dbm', 'tx_power_dbm', 'temperature_c'))
        for entry in analyzer.optical_history.get(port_name) or []
        if isinstance(entry, dict)
    )

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
        # The key is the whole interface name.  A word-only match filed the
        # block of a VLAN sub-interface ("swp6.100") under its parent "swp6"
        # and replaced the parent's module readings with it.
        interface_match = re.match(r'(\S+)', lines[0].strip())
        if not interface_match:
            continue
        port_data[interface_match.group(1)] = '\n'.join(lines[1:])
    return port_data


def _is_subinterface(interface):
    """A VLAN sub-interface (swp6.100) rides its parent's module.

    It has no cage of its own, so whatever its block holds it is never an
    optical port: no row, no state and no place among breakout siblings.
    """
    return '.' in interface


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


BREAKOUT_SUBPORT_RE = re.compile(r'swp(\d+)s(\d+)')
# Only blanks and tabs may precede the label on its line.  "^\s*" also runs
# over line ends, so a block with a long run of empty lines was rescanned
# from every one of them.
INTERFACE_STATE_RE = re.compile(
    r'^[^\S\n]*Interface\s+state\s*:\s*([^\s]+)',
    re.IGNORECASE | re.MULTILINE,
)


def _plan_breakout_cages(analyzer, port_data, failed_interfaces, hostname):
    """Plan channel ownership for every breakout cage in one device's file.

    ``ethtool -m`` returns the whole module for each swp<N>s<M>, so which
    channels a sub-port owns can only be told from its siblings, wherever
    they sit in the file (link-up ports are collected first).  Returns
    ({interface: channels per sub-port}, {interface: parsed block}); the
    parsed blocks are handed on so no block is parsed twice.  A cage that
    cannot be planned is absent from the first map and keeps the standalone
    rule (channel M+1).
    """
    cages = {}
    for interface in port_data:
        match = BREAKOUT_SUBPORT_RE.fullmatch(interface)
        if not match:
            continue
        try:
            index = int(match.group(2))
        except ValueError:
            # int() refuses a run of thousands of digits (a corrupted file).
            # A sub-port number that large is beyond any module's channels,
            # so its cage has no plan, like any suffix above the channel
            # count, and the device keeps its rows.
            index = None
        cages.setdefault(match.group(1), {})[index] = interface
    lanes_per_subport = {}
    parsed_blocks = {}
    for members in cages.values():
        if None in members:
            continue
        try:
            siblings = {}
            for index, interface in members.items():
                optical_data = port_data[interface] or ''
                params = None
                # A block without module readings (failed read, empty cage,
                # DAC) is still a sub-port; it only contributes no lanes.
                if (interface not in failed_interfaces
                        and len(optical_data.strip()) >= 10
                        and not NO_TRANSCEIVER_DATA_RE.search(optical_data)):
                    params = analyzer.parse_optical_data(optical_data)
                    if params is not None:
                        parsed_blocks[interface] = params
                state_match = INTERFACE_STATE_RE.search(optical_data)
                siblings[index] = {
                    'state': (state_match.group(1).strip().lower()
                              if state_match else None),
                    'params': params,
                }
            block = analyzer.plan_breakout_lanes(siblings)
        except Exception as exc:
            # Odd input costs the cage its plan, never the device its rows.
            # Say so: those rows are back on channel M+1.
            names = ', '.join(members[index] for index in sorted(members))
            print(f"⚠ {hostname}: breakout channels of {names[:200]} could "
                  f"not be planned ({type(exc).__name__}); each sub-port "
                  f"keeps channel M+1")
            continue
        if block is not None:
            for interface in members.values():
                lanes_per_subport[interface] = block
    return lanes_per_subport, parsed_blocks


# Per-process analyzer for parse workers: thresholds and parsing logic only,
# without the multi-megabyte history the parent keeps.
_parse_worker_analyzer = None


def _init_optical_parse_worker(result_dir):
    global _parse_worker_analyzer
    _parse_worker_analyzer = OpticalAnalyzer(result_dir, load_history=False)


def _classify_optical_file(filepath, hostname):
    """Parse one device's optical file and return merge operations.

    Runs in a worker process.  The worker owns the device's history shard
    for the whole file: it loads optical-history/<hostname>.json, applies
    every append and state decision locally (so unplugged detection sees the
    device's prior readings), writes the shard back, and returns the ops the
    parent still needs for its fabric-wide current snapshot.
    """
    port_data, file_failures = read_optical_diagnostics_file(filepath)
    failed_interfaces = {
        interface for _reason, interface in file_failures if interface
    }
    analyzer = _parse_worker_analyzer
    # The pooled worker analyzer is reused across devices (and across the
    # whole fleet in the sequential fallback); state is strictly per-file.
    # The persisted current snapshot is rebuilt from this run's data only,
    # so the shard's old current is deliberately discarded here.
    analyzer.current_optical_stats = {}
    analyzer.optical_history, _stale_current, shard = (
        analyzer.load_history_shard(hostname)
    )
    try:
        source_mtime = os.path.getmtime(filepath)
    except OSError:
        source_mtime = None
    ops = []

    def state_op(port_name, health, snippet, note=None):
        # Mirror the parent's merge locally so the shard's persisted current
        # matches the fabric snapshot for this device.
        record_optical_state(analyzer, port_name, hostname, health, snippet,
                             note)
        ops.append(('state', port_name, health, snippet, note))

    def updated_entries(port_name):
        stats_entry = analyzer.current_optical_stats.get(port_name)
        history = analyzer.optical_history.get(port_name)
        return stats_entry, (history[-1] if history else None)

    # Breakout siblings are planned together before any of them is graded.
    # Locals only: the pooled analyzer must carry nothing to the next device.
    breakout_lanes, parsed_blocks = _plan_breakout_cages(
        analyzer, port_data, failed_interfaces, hostname
    )

    for interface, optical_data in port_data.items():
        port_name = f"{hostname}:{interface}"

        if _is_subinterface(interface):
            continue

        if interface in failed_interfaces:
            state_op(port_name, 'unknown', optical_data[:500])
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
            # this device's history shard, loaded above.
            if (NO_TRANSCEIVER_DATA_RE.search(optical_data) and
                    re.search(r'^\s*Interface\s+state\s*:\s*down\b',
                              optical_data,
                              re.IGNORECASE | re.MULTILINE)):
                if _has_optical_history(analyzer, port_name):
                    state_op(port_name, 'unplugged', optical_data[:500])
            # A link that is up has a module in the cage: the same text on
            # a port that delivered diagnostics before is a module that
            # stopped answering (EEPROM I/O error, refused read), not an
            # empty cage.  Fixed copper ports never have optical history.
            elif (NO_TRANSCEIVER_DATA_RE.search(optical_data) and
                    re.search(r'^\s*Interface\s+state\s*:\s*up\b',
                              optical_data,
                              re.IGNORECASE | re.MULTILINE) and
                    _has_optical_history(analyzer, port_name)):
                state_op(port_name, 'unknown', optical_data[:500],
                         DOM_UNREADABLE_NOTE)
            continue

        # DAC/Copper cables do not provide optical diagnostics.  Keep
        # this check before interface-state handling so a down DAC is
        # not reclassified as a failed optical link.  The analyzer holds
        # the one rule that tells copper from optical (an active optical
        # cable is optical); it answers None for copper.
        parsed = parsed_blocks.get(interface)
        if parsed is None:
            parsed = analyzer.parse_optical_data(optical_data)
        if parsed is None:
            continue

        # Check for unplugged ports - add as "unplugged" status for troubleshooting
        if re.search(r'^\s*status\s*:\s*unplugged\b', optical_data,
                     re.IGNORECASE | re.MULTILINE):
            state_op(port_name, 'unplugged', optical_data[:500])
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
            usable_dom = any(
                parsed.get(metric) is not None for metric in (
                    'rx_power_dbm', 'tx_power_dbm', 'temperature_c',
                    'voltage_v', 'bias_current_ma'
                )
            )
            if not usable_dom:
                continue
            # The row is DOWN whatever the module reads; the analyzer keeps
            # the readings that can explain the outage next to the state.
            if analyzer.update_optical_stats(
                    port_name, optical_data, parsed=parsed,
                    lanes_per_subport=breakout_lanes.get(interface),
                    link_down=True):
                ops.append(('update', port_name, *updated_entries(port_name)))
            continue
        if interface_state == 'unknown':
            state_op(port_name, 'unknown', optical_data[:500])
            continue

        # Check for ports with no meaningful optical readings (N/A values, temp 0.0, etc.)
        if (("temperature                 : 0.0" in optical_data or
             "temperature                 : 0.00" in optical_data) and
            ("voltage                     : 0.0" in optical_data or
             "voltage                     : 0.00" in optical_data)):
            state_op(port_name, 'unknown', optical_data[:500])
            continue

        # A block with identity lines but no DOM value at all is not an
        # optical port (a copper type no indicator names, a module without
        # monitors) unless the port delivered diagnostics before.
        if (not any(parsed.get(metric) is not None for metric in (
                'rx_power_dbm', 'tx_power_dbm', 'temperature_c',
                'voltage_v', 'bias_current_ma'))
                and not parsed.get('bias_flags')
                and not _has_optical_history(analyzer, port_name)):
            continue

        # Update optical analyzer
        if analyzer.update_optical_stats(
                port_name, optical_data, parsed=parsed,
                lanes_per_subport=breakout_lanes.get(interface)):
            ops.append(('update', port_name, *updated_entries(port_name)))

    # A well-formed timeout marker normally sits inside its interface
    # block.  Retain visibility even if a future collector emits the
    # marker without that block.  A sub-interface's marker still makes the
    # collection incomplete (file_failures), but it is not a port.
    for reason, interface in file_failures:
        if (interface and interface not in port_data
                and not _is_subinterface(interface)):
            state_op(
                f"{hostname}:{interface}", 'unknown',
                describe_optical_collection_failure(reason, interface),
            )

    # A complete collection is the authority on which interfaces exist: a
    # history key absent from the file is a removed or renamed port
    # (breakout reconfiguration), not a down module — down and empty-cage
    # ports still appear in the file.  An incomplete collection (budget,
    # timeout, inventory failure) must not prune anything.
    if not file_failures and analyzer.optical_history:
        live = {f"{hostname}:{iface}" for iface in port_data
                if not _is_subinterface(iface)}
        analyzer.optical_history = {
            port: entries
            for port, entries in analyzer.optical_history.items()
            if port in live
        }

    # Persist this device's shard from the worker.  A device that never had
    # optical state (all-DAC racks) gets no file, so the shard directory
    # stays proportional to optical devices, not fleet size.  A shard whose
    # recorded source_mtime matches this file was already fully merged (a
    # broken-pool retry or a re-analysis without new collection); rewriting
    # it would append this file's samples to the history a second time.
    shard_error = None
    already_merged = (
        shard is not None
        and source_mtime is not None
        and shard.get("source_mtime") == source_mtime
    )
    if not already_merged and (
            analyzer.optical_history or analyzer.current_optical_stats
            or shard is not None):
        shard_error = analyzer.write_history_shard(
            hostname, source_mtime=source_mtime
        )

    return ops, file_failures, shard_error


def _merge_optical_ops(analyzer, hostname, ops):
    """Apply one file's worker ops to the parent's fabric-wide snapshot.

    History never reaches the parent: the worker already persisted it into
    the device's optical-history/<host>.json shard (including the unplugged
    decision, which needs the device's prior readings).  Only the current
    stats that feed the summary, anomaly, and report paths merge here.
    """
    for op in ops:
        kind = op[0]
        if kind == 'state':
            _kind, port_name, health, snippet = op[:4]
            record_optical_state(analyzer, port_name, hostname, health, snippet,
                                 op[4] if len(op) > 4 else None)
        elif kind == 'update':
            _kind, port_name, stats_entry, _history_entry = op
            if stats_entry:
                analyzer.current_optical_stats[port_name] = stats_entry


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
    """Yield (hostname, ops, file_failures, shard_error) per file.

    Parallel when possible; each worker also owns the device's history
    shard read/append/write.
    """
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
                    ops, file_failures, shard_error = future.result()
                    yield hostname, ops, file_failures, shard_error
                    completed += 1
                return
        except (OSError, PermissionError, BrokenProcessPool):
            # Constrained containers can deny multiprocessing primitives.
            # Fall back to the same complete parse for the remaining files,
            # never to a skipped device.
            pass
    _init_optical_parse_worker(result_dir)
    for filepath, hostname in tasks[completed:]:
        ops, file_failures, shard_error = _classify_optical_file(filepath, hostname)
        yield hostname, ops, file_failures, shard_error


def _migrate_optical_history_monolith(result_dir):
    """One-time split of the legacy monolith into per-device shards.

    Runs inside monitor.sh's analyzer transaction: on any later failure the
    monolith and the shard directory are restored together.
    """
    monolith = os.path.join(result_dir, "optical_history.json")
    if not os.path.exists(monolith):
        return True
    print("Migrating optical_history.json into optical-history/ shards...")
    migrator = OpticalAnalyzer(result_dir)  # loads the monolith whole
    if migrator._legacy_history_loaded:
        return migrator.save_optical_history()
    # Unreadable monolith: the legacy loader restarted history silently;
    # retire the corrupt document once instead of re-parsing it every run.
    print("⚠ optical_history.json is unreadable; retiring it "
          "(history restarts from this run)")
    try:
        os.unlink(monolith)
    except OSError as exc:
        print(f"❌ Could not retire corrupt optical_history.json: {exc}")
        return False
    try:
        analysis_sidecar.sidecar_path(monolith).unlink()
    except OSError:
        pass
    return True


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

    if not _migrate_optical_history_monolith(result_dir):
        return False
    # Parse workers own the per-device history shards (read, append, write);
    # the parent only ever holds the fabric-wide current snapshot, and only
    # files from this successful collection may populate it.
    optical_analyzer = OpticalAnalyzer(result_dir, load_history=False)
    finish_phase("load")

    print("Processing optical diagnostics data")
    print(f"Data directory: {data_dir}")
    # A module that prints a valid limit table is graded by it; these are
    # the generic values every other reading is held against.
    print(
        f"Using generic optical thresholds where a module prints none: RX Power min={optical_analyzer.thresholds['rx_power_min_dbm']:.1f} dBm, "
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
    shard_errors = []
    for hostname, ops, file_failures, shard_error in _classify_optical_files(
            result_dir, tasks):
        # Category-local collector failures remain per file so the optical
        # report can expose incomplete coverage without invalidating BGP,
        # BER, PFC, hardware, logs, or other complete categories.
        if file_failures:
            failed_collection_hosts.add(hostname)
            collection_failures[hostname] = [
                describe_optical_collection_failure(reason, interface)
                for reason, interface in file_failures
            ]
        if shard_error:
            shard_errors.append(shard_error)
        total_processed += 1
        _merge_optical_ops(optical_analyzer, hostname, ops)

    print(f"\nProcessed {total_processed} files total")
    finish_phase("parse_records")

    if shard_errors:
        # Fail loudly inside the analyzer transaction instead of silently
        # losing devices' history appends.
        print("❌ Optical history shard writes failed: "
              + "; ".join(shard_errors))
        return False

    # Parse workers already wrote the shards of collected devices; reconcile
    # the rest so shard consumers keep monolith semantics: retire shards of
    # devices no longer in inventory, and empty the persisted current
    # snapshot of devices without a current collection.  The directory
    # itself is contractual (validated after every run), and its timestamp
    # is the freshness heartbeat for devices that have no shard file.
    shard_dir_path = os.path.join(result_dir, HISTORY_DIR_NAME)
    os.makedirs(shard_dir_path, exist_ok=True)
    os.utime(shard_dir_path, None)
    reconcile_ok = True
    if snapshot_valid:
        reconcile_ok = optical_analyzer.prune_history_shards(
            inventory_hosts | collected_hosts
        )
    if not optical_analyzer.clear_stale_shard_current(collected_hosts):
        reconcile_ok = False
    if not reconcile_ok:
        return False
    print("Optical history shards reconciled")
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
    generated_at = int(time.time())
    summary_counts = {
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
        # The same problems with one module of a breakout cage counted once
        # (module temperature or voltage, the module pulled): one hot or
        # pulled module in a 4x split is four ports above and one here.
        **optical_analyzer.get_finding_counts(),
    }
    _atomic_write(
        os.path.join(result_dir, "summary", "optical-summary.json"),
        json.dumps({
            "domain": "optical",
            "generated_at": generated_at,
            "collection_status": collection_status,
            **summary_counts,
        }) + "\n",
    )
    export_artifacts.write_export(
        result_dir,
        "optical",
        optical_analyzer.build_export_rows(summary, anomalies),
        summary_counts,
        collection_status,
        generated_at=generated_at,
    )
    finish_phase("write_summary")
    print(f"Summary stats: {len(optical_analyzer.current_optical_stats)} total ports analyzed")

    print("\nOptical Analysis Summary:")
    print(f"  Total ports monitored: {summary['total_ports']}")
    print(f"  Excellent health: {len(summary['excellent_ports'])}")
    print(f"  Good health: {len(summary['good_ports'])}")
    print(f"  Warning level: {len(summary['warning_ports'])}")
    print(f"  Critical issues: {len(summary['critical_ports'])}")
    print(f"  Link down / no receive light: {len(summary['down_ports'])}")
    print(f"  Modules unplugged: {summary_counts['unplugged_modules']} "
          f"({len(summary['unplugged_ports'])} ports)")
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
