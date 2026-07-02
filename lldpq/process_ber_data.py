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
from collection_freshness import is_current_collection, read_asset_snapshot

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
    ber_analyzer = BERAnalyzer("monitor-results")
    # Keep historical/baseline data, but rebuild the current snapshot solely
    # from this run's successful raw files.
    ber_analyzer.current_ber_stats = {}
    
    print(f"Processing BER analysis data")
    print(f"Using thresholds: Good < {ber_analyzer.config['raw_ber_threshold']:.2e}, "
          f"Warning < {ber_analyzer.config['warning_ber_threshold']:.2e}, "
          f"Critical > {ber_analyzer.config['critical_ber_threshold']:.2e}")
    
    if not os.path.exists(data_dir):
        print(f"❌ BER data directory {data_dir} not found")
        return False
    
    processed_devices = 0
    total_interfaces_processed = 0
    processing_errors = 0
    
    asset_snapshot = read_asset_snapshot()
    current_files = [
        filename for filename in os.listdir(data_dir)
        if filename.endswith("_interface_errors.txt")
        and is_current_collection(
            os.path.join(data_dir, filename),
            filename.removesuffix("_interface_errors.txt"),
            asset_snapshot,
        )
    ]

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
                baseline_interfaces = 0
                for interface_name, stats in interfaces.items():
                    # Only process physical interfaces
                    if not ber_analyzer.is_physical_port(interface_name):
                        continue
                    
                    port_name = f"{hostname}:{interface_name}"
                    
                    # Calculate delta-based BER
                    ber_value, is_baseline, delta_errors, delta_bytes = ber_analyzer.calculate_delta_ber(
                        hostname, interface_name, stats
                    )
                    
                    if is_baseline:
                        # Create baseline record for web display
                        baseline_record = {
                            'timestamp': time.time(),
                            'ber_value': 0.0,
                            'grade': 'excellent',
                            'rx_packets': stats.get('rx_packets', 0),
                            'tx_packets': stats.get('tx_packets', 0),
                            'rx_errors': stats.get('rx_errors', 0),
                            'tx_errors': stats.get('tx_errors', 0),
                            'total_packets': stats.get('rx_packets', 0) + stats.get('tx_packets', 0),
                            'delta_errors': 0,
                            'delta_bytes': 0
                        }
                        ber_analyzer.current_ber_stats[port_name] = baseline_record
                        baseline_interfaces += 1
                        processed_interfaces += 1
                        total_interfaces_processed += 1
                        continue
                    
                    # Skip interfaces with no activity since baseline
                    total_packets = stats.get('rx_packets', 0) + stats.get('tx_packets', 0)
                    if total_packets < ber_analyzer.config['min_packets_for_analysis']:
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
                        'delta_bytes': delta_bytes
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
                
                
                
            except Exception as e:
                print(f"❌ Error processing {filename}: {e}")
                processing_errors += 1
    
    if processed_devices == 0:
        print("❌ No BER data files found to process")
        ber_analyzer.save_ber_history()
        return False
    
    # Save baseline data once after all interfaces processed
    ber_analyzer.save_baseline_data()
    
    # Generate summary
    summary = ber_analyzer.get_ber_summary()
    anomalies = ber_analyzer.detect_ber_anomalies()
    
    print(f"\nBER Analysis Summary:")
    print(f"  Total devices processed: {processed_devices}")
    print(f"  Total interfaces analyzed: {total_interfaces_processed}")
    print(f"  Excellent quality: {len(summary['excellent_ports'])}")
    print(f"  Good quality: {len(summary['good_ports'])}")
    print(f"  Warning level: {len(summary['warning_ports'])}")
    print(f"  Critical issues: {len(summary['critical_ports'])}")
    print(f"  Anomalies detected: {len(anomalies)}")
    
    # Show critical issues
    if summary['critical_ports']:
        print(f"\nCritical BER Issues (Immediate Attention):")
        for port_info in summary['critical_ports'][:5]:  # Show first 5
            port = port_info['port']
            ber_value = port_info['ber_value']
            rx_errors = port_info['rx_errors']
            tx_errors = port_info['tx_errors']
            print(f"    {port}: BER={ber_value:.2e}, RX_Errors={rx_errors}, TX_Errors={tx_errors}")
    
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
    output_file = "monitor-results/ber-analysis.html"
    ber_analyzer.export_ber_data_for_web(output_file)
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
