#!/usr/bin/env python3
"""
Process carrier transition flap detection data collected by monitor.sh
professional network monitoring

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import sys
from datetime import datetime
from link_flap_analyzer import LinkFlapAnalyzer
from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    mark_html_collection_unavailable,
    read_asset_snapshot,
)

def process_carrier_transition_files(data_dir="monitor-results/flap-data"):
    """Process carrier transition files and update flap detector"""
    data_dir = os.path.abspath(data_dir)
    result_dir = os.path.dirname(data_dir.rstrip(os.sep))
    flap_analyzer = LinkFlapAnalyzer(result_dir)

    print("Processing carrier transition data")
    print(f"Using parameters: Min delta={flap_analyzer.MIN_CARRIER_TRANSITION_DELTA} transitions, "
          f"Warning={flap_analyzer.thresholds['warning_flaps_per_hour']}/h, "
          f"Critical={flap_analyzer.thresholds['critical_flaps_per_hour']}/h")
    
    if not os.path.exists(data_dir):
        print(f"Flap data directory {data_dir} not found")
        return False

    assets_file = os.path.join(os.path.dirname(result_dir), "assets.ini")
    asset_snapshot = read_asset_snapshot(assets_file)
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    assets_authoritative = asset_snapshot_is_authoritative(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("Asset snapshot is invalid or incomplete")
        return False

    # Retired inventory entries must not retain raw files or persisted port
    # baselines forever. Non-OK current devices keep their history for when
    # they return; only hosts absent from a valid asset snapshot are retired.
    if assets_authoritative:
        for filename in os.listdir(data_dir):
            if not filename.endswith("_carrier_transitions.txt"):
                continue
            hostname = filename.removesuffix("_carrier_transitions.txt")
            if hostname not in statuses:
                try:
                    os.unlink(os.path.join(data_dir, filename))
                except OSError as exc:
                    print(f"Error pruning retired flap data {filename}: {exc}")
                    return False

        active_hosts = set(statuses)
        for attribute in (
            "flapping_hist", "carrier_transitions_lookback", "prev_cumulative",
            "prev_sample_time",
        ):
            values = getattr(flap_analyzer, attribute, {})
            for port_name in list(values):
                if port_name.split(":", 1)[0] not in active_hosts:
                    del values[port_name]

    current_files = [
        filename for filename in sorted(os.listdir(data_dir))
        if filename.endswith("_carrier_transitions.txt")
        and is_current_collection(
            os.path.join(data_dir, filename),
            filename.removesuffix("_carrier_transitions.txt"),
            asset_snapshot,
        )
    ]

    expected_current_hosts = set()
    collected_hosts = {
        filename.removesuffix("_carrier_transitions.txt")
        for filename in current_files
    }
    missing_hosts = []
    if snapshot_valid:
        expected_current_hosts = {
            host for host, status in statuses.items() if status == "OK"
        }
        missing_hosts = sorted(expected_current_hosts - collected_hosts)
        if missing_hosts:
            print(
                "Missing current carrier transition collections for: "
                + ", ".join(missing_hosts)
            )

    all_devices_unavailable = snapshot_valid and not expected_current_hosts
    if not current_files and not all_devices_unavailable:
        print("No current carrier transition collections found")
        print("Publishing flap report with unavailable device coverage")
    
    processed_devices = 0
    processing_errors = 0
    category_failed_hosts = set()
    processed_hosts = set()
    for filename in current_files:
        hostname = filename.removesuffix("_carrier_transitions.txt")
        filepath = os.path.join(data_dir, filename)

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except OSError as exc:
            print(f"Error processing {filepath}: {exc}")
            processing_errors += 1
            continue

        if not content:
            print(f"Empty current carrier transition file: {filename}")
            processing_errors += 1
            continue

        processed_interfaces = 0
        for line in content.splitlines():
            if not line or line.startswith("==="):
                continue
            if line == "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY":
                print(f"Device collection error in {filename}: {line}")
                category_failed_hosts.add(hostname)
                continue
            if "__LLDPQ_COLLECTION_ERROR__:" in line:
                print(f"Unknown device collection error in {filename}: {line}")
                processing_errors += 1
                continue
            if ":" not in line:
                print(f"Invalid carrier transition row in {filename}: {line}")
                processing_errors += 1
                continue
            interface, transitions_str = line.split(":", 1)
            interface = interface.strip()
            transitions_str = transitions_str.strip()
            try:
                transitions = int(transitions_str)
            except ValueError:
                print(f"Invalid transition count '{transitions_str}' for {interface}")
                processing_errors += 1
                continue
            if not interface or transitions < 0:
                print(f"Invalid carrier transition row in {filename}: {line}")
                processing_errors += 1
                continue
            flap_analyzer.update_carrier_transitions(
                f"{hostname}:{interface}", transitions
            )
            processed_interfaces += 1
        if processed_interfaces == 0:
            if hostname not in category_failed_hosts:
                print(f"No carrier transition rows found for current host {hostname}")
                processing_errors += 1
        else:
            processed_devices += 1
            processed_hosts.add(hostname)

    if processing_errors:
        print("Carrier transition collection was incomplete; preserving the prior report")
        return False
    if (processed_devices == 0 and not all_devices_unavailable
            and not category_failed_hosts and not missing_hosts):
        print("No usable carrier transition data was collected")
        return False

    current_hosts = processed_hosts - category_failed_hosts
    expected_hosts = set(statuses) if snapshot_valid else current_hosts
    flap_analyzer.set_collection_coverage(expected_hosts, current_hosts)
    
    # Check for flapping
    if flap_analyzer.check_flapping():
        print("link flapping detected!")
    
    # Save updated flap history
    flap_analyzer.save_flap_history()
    history_file = os.path.join(result_dir, "flap_history.json")
    if not os.path.isfile(history_file) or os.path.getsize(history_file) == 0:
        print("Flap history could not be saved")
        return False
    
    # Generate web report
    output_file = os.path.join(result_dir, "link-flap-analysis.html")
    flap_analyzer.export_flap_data_for_web(output_file)
    if all_devices_unavailable:
        mark_html_collection_unavailable(output_file)
    if not os.path.isfile(output_file) or os.path.getsize(output_file) == 0:
        print("Flap analysis report could not be generated")
        return False
    print(f"flap analysis report generated: {output_file}")
    
    # Generate summary for dashboard
    summary = flap_analyzer.get_flap_summary()
    anomalies = flap_analyzer.detect_flap_anomalies()
    
    print(f"\n Flap Detection Summary:")
    print(f"  Total ports monitored: {summary['total_ports']}")
    print(f"  Critical ports: {len(summary['critical_ports'])}")
    print(f"  Warning ports: {len(summary['warning_ports'])}")
    print(f"  Stable ports: {len(summary['ok_ports'])}")
    print(f"  Anomalies detected: {len(anomalies)}")
    
    if summary['critical_ports']:
        print("\nCritical Flapping Ports:")
        for port in summary['critical_ports']:
            print(f"    {port['port']}: {port['counters']['flap_1_hr']} flaps in last hour")
    
    if summary['warning_ports']:
        print("\nWarning Flapping Ports:")
        for port in summary['warning_ports'][:5]:  # Show top 5
            print(f"    {port['port']}: {port['counters']['flap_1_hr']} flaps in last hour")
    
    # Algorithm status
    total_problematic = len(summary['critical_ports']) + len(summary['warning_ports'])
    stability_ratio = ((summary['total_ports'] - total_problematic) / summary['total_ports'] * 100) if summary['total_ports'] > 0 else 0
    
    coverage_unavailable = bool(expected_hosts and not current_hosts)
    if all_devices_unavailable:
        print("\nNetwork Stability: UNAVAILABLE (no reachable devices)")
    elif coverage_unavailable:
        print("\nNetwork Stability: UNAVAILABLE (carrier collection incomplete)")
    elif stability_ratio >= 95:
        print(f"\nNetwork Stability: EXCELLENT ({stability_ratio:.1f}%)")
    elif stability_ratio >= 85:
        print(f"\nNetwork Stability: GOOD ({stability_ratio:.1f}%)")
    elif stability_ratio >= 70:
        print(f"\nNetwork Stability: WARNING ({stability_ratio:.1f}%)")
    else:
        print(f"\nNetwork Stability: CRITICAL ({stability_ratio:.1f}%)")
    
    print(f"\nProcessed {processed_devices} devices using algorithm")
    return True

if __name__ == "__main__":
    import logging
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        handlers=[
            logging.FileHandler('monitor-results/flap_detector.log'),
            logging.StreamHandler()
        ]
    )
    
    logging.info("Starting flap data processing")
    
    try:
        # Never synthesize random flap counters from HTML. A missing current
        # collection is a real failure so monitor.sh can preserve the LKG report.
        if not process_carrier_transition_files():
            logging.error("flap data processing failed: no complete current collection")
            sys.exit(1)
        logging.info("flap data processing completed")
    except Exception as e:
        logging.error(f"flap data processing failed: {e}")
        sys.exit(1)
