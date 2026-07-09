#!/usr/bin/env python3
"""
Process BER analysis data collected by monitor.sh
Professional network error rate analysis

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import sys
import time
from datetime import datetime
from ber_analyzer import BERAnalyzer
from collection_freshness import (
    asset_snapshot_is_authoritative,
    asset_snapshot_is_valid,
    is_current_collection,
    mark_html_collection_unavailable,
    read_asset_snapshot,
)

def parse_proc_net_dev(content):
    """Parse /proc/net/dev content to extract interface statistics"""
    interfaces = {}
    lines = content.strip().split('\n')
    
    # Skip header lines and process data lines
    for line in lines[2:]:  # First two lines are headers
        line = line.strip()
        if not line:
            continue
        
        # Split by whitespace and handle interface name with colon
        parts = line.split()
        if len(parts) >= 16:
            # Interface name might have colon at the end
            interface = parts[0].rstrip(':')
            
            try:
                interfaces[interface] = {
                    'rx_bytes': int(parts[1]),
                    'rx_packets': int(parts[2]),
                    'rx_errors': int(parts[3]),
                    'rx_dropped': int(parts[4]),
                    'rx_fifo': int(parts[5]),
                    'rx_frame': int(parts[6]),
                    'rx_compressed': int(parts[7]),
                    'rx_multicast': int(parts[8]),
                    'tx_bytes': int(parts[9]),
                    'tx_packets': int(parts[10]),
                    'tx_errors': int(parts[11]),
                    'tx_dropped': int(parts[12])
                }
            except (ValueError, IndexError) as e:
                print(f"Error parsing line for interface {interface}: {e}")
                continue
    
    return interfaces

def process_detailed_counters(content, hostname):
    """Process detailed interface counters (nv show interface counters output)"""
    detailed_stats = {}
    current_interface = None
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Look for interface headers
        if line.startswith('Interface:') or 'Interface' in line and ':' in line:
            interface_match = re.search(r'(\w+\d+)', line)
            if interface_match:
                current_interface = interface_match.group(1)
                if current_interface not in detailed_stats:
                    detailed_stats[current_interface] = {}
        
        # Parse counter values
        if current_interface and ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().lower().replace(' ', '_').replace('-', '_')
                value_str = parts[1].strip()
                
                # Extract numeric value
                value_match = re.search(r'(\d+)', value_str)
                if value_match:
                    try:
                        detailed_stats[current_interface][key] = int(value_match.group(1))
                    except ValueError:
                        pass
    
    return detailed_stats

def process_ber_data_files(data_dir="monitor-results/ber-data"):
    """Process BER data files and update BER analyzer"""
    data_dir = os.path.abspath(data_dir)
    result_dir = os.path.dirname(data_dir.rstrip(os.sep))
    ber_analyzer = BERAnalyzer(result_dir)
    # BERAnalyzer intentionally loads persisted history, baseline, and the
    # prior generation's current snapshot.  History/baseline remain useful,
    # but current evidence must start empty on every generation so a marker or
    # missing host can never republish an old port as current.
    ber_analyzer.current_ber_stats.clear()
    
    print("Processing link error analysis data")
    print(
        "Using frame-density thresholds: "
        f"Warning >= {ber_analyzer.config['frame_density_warning_threshold']:.2e}, "
        f"Critical >= {ber_analyzer.config['frame_density_critical_threshold']:.2e}"
    )
    print(
        "Using raw/pre-FEC BER thresholds: "
        f"Warning >= {ber_analyzer.config['raw_phy_ber_warning_threshold']:.2e}, "
        f"Critical >= {ber_analyzer.config['raw_phy_ber_critical_threshold']:.2e}"
    )
    print(
        "Using effective/post-FEC BER thresholds: "
        f"Warning >= {ber_analyzer.config['effective_phy_ber_warning_threshold']:.2e}, "
        f"Critical >= {ber_analyzer.config['effective_phy_ber_critical_threshold']:.2e}"
    )
    
    if not os.path.exists(data_dir):
        print(f"❌ BER data directory {data_dir} not found")
        return False
    
    processed_devices = 0
    total_interfaces_processed = 0
    processing_errors = 0
    hosts_with_interfaces = set()
    category_failed_hosts = set()
    
    assets_file = os.path.join(os.path.dirname(result_dir), "assets.ini")
    asset_snapshot = read_asset_snapshot(assets_file)
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    assets_authoritative = asset_snapshot_is_authoritative(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("❌ Asset snapshot is invalid or incomplete")
        return False

    if assets_authoritative:
        active_hosts = set(statuses)
        for filename in os.listdir(data_dir):
            for suffix in (
                "_interface_errors.txt", "_detailed_counters.txt", "_l1_show.txt"
            ):
                if filename.endswith(suffix):
                    hostname = filename.removesuffix(suffix)
                    if hostname not in active_hosts:
                        try:
                            os.unlink(os.path.join(data_dir, filename))
                        except OSError as exc:
                            print(f"❌ Could not prune retired BER data {filename}: {exc}")
                            return False
                    break
        for hostname in list(ber_analyzer.baseline_data):
            if hostname not in active_hosts:
                del ber_analyzer.baseline_data[hostname]
        for mapping in (ber_analyzer.ber_history, ber_analyzer.current_ber_stats):
            for port_name in list(mapping):
                if port_name.split(":", 1)[0] not in active_hosts:
                    del mapping[port_name]

    current_files = [
        filename for filename in os.listdir(data_dir)
        if filename.endswith("_interface_errors.txt")
        and is_current_collection(
            os.path.join(data_dir, filename),
            filename.removesuffix("_interface_errors.txt"),
            asset_snapshot,
        )
    ]
    missing_hosts = []
    if snapshot_valid:
        expected_hosts = {
            host for host, status in statuses.items() if status == "OK"
        }
        collected_hosts = {
            filename.removesuffix("_interface_errors.txt")
            for filename in current_files
        }
        missing_hosts = sorted(expected_hosts - collected_hosts)
        if missing_hosts:
            print(
                "⚠️  Missing current BER collections for: "
                + ", ".join(missing_hosts)
            )
    else:
        expected_hosts = set()
    all_devices_unavailable = snapshot_valid and not expected_hosts

    # Process all current interface error files
    for filename in current_files:
        if filename.endswith("_interface_errors.txt"):
            hostname = filename.replace("_interface_errors.txt", "")
            filepath = os.path.join(data_dir, filename)
            
            try:
                with open(filepath, "r") as f:
                    content = f.read().strip()
                
                if not content:
                    print(f"⚠️  Empty file: {filename}")
                    processing_errors += 1
                    continue

                if content.strip() == "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS":
                    print(
                        f"⚠️  Interface counter collection unavailable for {hostname}; "
                        "publishing partial BER coverage"
                    )
                    category_failed_hosts.add(hostname)
                    continue
                if "__LLDPQ_COLLECTION_ERROR__:" in content:
                    print(f"❌ Unknown collection marker in {filename}")
                    processing_errors += 1
                    continue
                
                processed_devices += 1
                
                # Parse /proc/net/dev format
                interfaces = parse_proc_net_dev(content)
                
                if not interfaces:
                    print(f"⚠️  No interface data found in {filename}")
                    processing_errors += 1
                    continue
                
                # Process detailed counters if available
                detailed_file = os.path.join(data_dir, f"{hostname}_detailed_counters.txt")
                detailed_stats = {}
                if os.path.exists(detailed_file):
                    try:
                        with open(detailed_file, "r") as f:
                            detailed_content = f.read().strip()
                        detailed_stats = process_detailed_counters(detailed_content, hostname)
                    except Exception as e:
                        print(f"⚠️  Error processing detailed counters for {hostname}: {e}")
                        processing_errors += 1
                
                # Process each interface with delta-based calculation
                processed_interfaces = 0
                for interface_name, stats in interfaces.items():
                    # Only process physical interfaces
                    if not ber_analyzer.is_physical_port(interface_name):
                        continue
                    
                    port_name = f"{hostname}:{interface_name}"
                    
                    # Calculate delta-based BER
                    (ber_value, is_baseline, delta_errors, delta_bytes,
                     delta_packets) = ber_analyzer.calculate_delta_ber(
                        hostname, interface_name, stats
                    )
                    delta_details = ber_analyzer._last_delta_details.get(port_name, {})
                    
                    if is_baseline:
                        # Create baseline record for web display
                        baseline_record = {
                            'timestamp': time.time(),
                            'ber_value': 0.0,
                            'grade': 'unknown',
                            'sample_status': (
                                'counter_reset'
                                if delta_details.get('counter_reset')
                                else 'baseline'
                            ),
                            'rx_packets': stats.get('rx_packets', 0),
                            'tx_packets': stats.get('tx_packets', 0),
                            'rx_errors': stats.get('rx_errors', 0),
                            'tx_errors': stats.get('tx_errors', 0),
                            'total_packets': stats.get('rx_packets', 0) + stats.get('tx_packets', 0),
                            'delta_errors': 0,
                            'delta_bytes': 0,
                            'delta_packets': 0,
                            'delta_rx_errors': 0,
                            'delta_tx_errors': 0,
                            'sample_duration_seconds': delta_details.get(
                                'sample_duration_seconds', 0
                            ),
                        }
                        ber_analyzer.ber_history.setdefault(port_name, []).append(
                            baseline_record
                        )
                        ber_analyzer.current_ber_stats[port_name] = baseline_record
                        processed_interfaces += 1
                        total_interfaces_processed += 1
                        continue
                    
                    # Every physical port belongs to the current snapshot. A
                    # low-traffic interval is explicitly unknown and remains
                    # accumulated against the prior baseline for a later run.
                    total_packets = stats.get('rx_packets', 0) + stats.get('tx_packets', 0)
                    if delta_packets < ber_analyzer.config['min_packets_for_analysis']:
                        ber_analyzer.current_ber_stats[port_name] = {
                            'timestamp': time.time(),
                            # Preserve the observed value for display and for
                            # immediate evaluation when an error is already
                            # present.  The low sample remains ungraded when it
                            # contains no errors, and its baseline accumulates.
                            'ber_value': ber_value,
                            'grade': 'unknown',
                            'sample_status': 'insufficient_traffic',
                            'rx_packets': stats.get('rx_packets', 0),
                            'tx_packets': stats.get('tx_packets', 0),
                            'rx_errors': stats.get('rx_errors', 0),
                            'tx_errors': stats.get('tx_errors', 0),
                            'total_packets': total_packets,
                            'delta_errors': delta_errors,
                            'delta_bytes': delta_bytes,
                            'delta_packets': delta_packets,
                            'delta_rx_errors': delta_details.get('delta_rx_errors', 0),
                            'delta_tx_errors': delta_details.get('delta_tx_errors', 0),
                            'sample_duration_seconds': delta_details.get(
                                'sample_duration_seconds', 0
                            ),
                        }
                        ber_analyzer.ber_history.setdefault(port_name, []).append(
                            ber_analyzer.current_ber_stats[port_name]
                        )
                        processed_interfaces += 1
                        total_interfaces_processed += 1
                        continue
                    
                    # Create BER record manually since we're using delta calculation
                    current_time = time.time()
                    grade = ber_analyzer.get_ber_grade(ber_value)
                    
                    ber_record = {
                        'timestamp': current_time,
                        'ber_value': ber_value,
                        'grade': grade.value,
                        'rx_packets': stats.get('rx_packets', 0),
                        'tx_packets': stats.get('tx_packets', 0),
                        'rx_errors': stats.get('rx_errors', 0),
                        'tx_errors': stats.get('tx_errors', 0),
                        'total_packets': total_packets,
                        'delta_errors': delta_errors,
                        'delta_bytes': delta_bytes,
                        'delta_packets': delta_packets,
                        'delta_rx_errors': delta_details.get('delta_rx_errors', 0),
                        'delta_tx_errors': delta_details.get('delta_tx_errors', 0),
                        'sample_duration_seconds': delta_details.get(
                            'sample_duration_seconds', 0
                        ),
                        'sample_status': 'analyzed',
                    }
                    
                    # Update current stats and history
                    if port_name not in ber_analyzer.ber_history:
                        ber_analyzer.ber_history[port_name] = []
                    ber_analyzer.ber_history[port_name].append(ber_record)
                    ber_analyzer.current_ber_stats[port_name] = ber_record
                    
                    # Per-interface logging removed for performance
                    # Only summary and critical issues are shown
                    
                    processed_interfaces += 1
                    total_interfaces_processed += 1
                if processed_interfaces > 0:
                    hosts_with_interfaces.add(hostname)
                
            except Exception as e:
                print(f"❌ Error processing {filename}: {e}")
                processing_errors += 1
    
    if (processed_devices == 0 and not all_devices_unavailable
            and not category_failed_hosts and not missing_hosts):
        print("❌ No BER data files found to process")
        return False
    missing_interface_hosts = sorted(expected_hosts - hosts_with_interfaces)
    if missing_interface_hosts:
        print(
            "⚠️  No physical interface counters for current hosts: "
            + ", ".join(missing_interface_hosts)
        )
    
    # Save baseline data once after all interfaces processed.  History is
    # saved after classification because _analyze_port enriches the current
    # record with the L1 snapshot required by the next symbol-delta sample.
    if not ber_analyzer.save_baseline_data():
        print("❌ BER baseline state could not be saved")
        return False
    if (total_interfaces_processed == 0 and not all_devices_unavailable
            and not category_failed_hosts and not missing_hosts):
        print("❌ No physical interface counters were processed")
        return False

    # Classify every port once, then reuse the exact same objects for anomaly
    # reporting and HTML generation.  This avoids repeated L1 parsing and
    # repeated mutation of current history records.
    summary = ber_analyzer.get_ber_summary()
    anomalies = ber_analyzer.detect_ber_anomalies(summary)
    if not ber_analyzer.save_ber_history():
        print("❌ BER history state could not be saved")
        return False

    for required_state in (
        os.path.join(result_dir, "ber_baseline.json"),
        os.path.join(result_dir, "ber_history.json"),
    ):
        if not os.path.isfile(required_state) or os.path.getsize(required_state) == 0:
            print(f"❌ BER state was not saved: {required_state}")
            return False
    
    print("\nLink Error / BER Analysis Summary:")
    print(f"  Total devices processed: {processed_devices}")
    print(f"  Total interfaces analyzed: {total_interfaces_processed}")
    print(f"  Excellent quality: {len(summary['excellent_ports'])}")
    print(f"  Good quality: {len(summary['good_ports'])}")
    print(f"  Warning level: {len(summary['warning_ports'])}")
    print(f"  Critical issues: {len(summary['critical_ports'])}")
    print(f"  Awaiting a complete sample: {len(summary['unknown_ports'])}")
    print(f"  Anomalies detected: {len(anomalies)}")
    
    # Show critical issues
    if summary['critical_ports']:
        print("\nCritical Link Error Issues (Immediate Attention):")
        for port_info in summary['critical_ports'][:5]:  # Show first 5
            port = port_info['port']
            ber_value = port_info['ber_value']
            rx_errors = port_info['rx_errors']
            tx_errors = port_info['tx_errors']
            print(
                f"    {port}: ErrorDensity={ber_value:.2e}, "
                f"RX_Errors={rx_errors}, TX_Errors={tx_errors}"
            )
    
    # Show anomalies
    if anomalies:
        print(f"\n⚠️  BER Anomalies Detected:")
        for anomaly in anomalies[:5]:  # Show first 5
            device = anomaly['device']
            interface = anomaly['interface']
            message = anomaly['message']
            print(f"    {device}:{interface}: {message}")
            print(f"      Action: {anomaly['action']}")
    
    # Export web report
    output_file = os.path.join(result_dir, "ber-analysis.html")
    if snapshot_valid:
        ber_analyzer.coverage_expected_hosts = len(statuses)
        ber_analyzer.coverage_current_hosts = len(hosts_with_interfaces)
    ber_analyzer.export_ber_data_for_web(
        output_file, summary=summary, anomalies=anomalies
    )
    if all_devices_unavailable:
        mark_html_collection_unavailable(output_file)
    if not os.path.isfile(output_file) or os.path.getsize(output_file) == 0:
        print("❌ BER analysis report was not generated")
        return False
    print(f"BER analysis report generated: {output_file}")
    
    # Final summary
    total_ports = summary['total_ports']
    if total_ports > 0:
        health_ratio = (len(summary['excellent_ports']) + len(summary['good_ports'])) / total_ports
        print(f"Overall network health: {health_ratio*100:.1f}% ({len(summary['excellent_ports']) + len(summary['good_ports'])}/{total_ports} ports healthy)")
    
    print(f"BER history saved")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] BER data processing completed")
    return processing_errors == 0

def main():
    """Main function"""
    try:
        return 0 if process_ber_data_files() else 1
    except KeyboardInterrupt:
        print("\n⚠️  BER analysis interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Unexpected error in BER analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
