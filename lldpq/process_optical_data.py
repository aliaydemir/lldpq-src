#!/usr/bin/env python3
"""
Process optical diagnostics data collected by monitor.sh

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import sys
from datetime import datetime
from optical_analyzer import OpticalAnalyzer
from collection_freshness import is_current_collection, read_asset_snapshot

def parse_optical_diagnostics_file(filepath):
    """Parse optical diagnostics file"""
    port_data = {}

    try:
        with open(filepath, "r") as f:
            content = f.read()

        # Split by interface sections
        sections = content.split("--- Interface:")
        
        for section in sections[1:]:  # Skip first empty section
            lines = section.strip().split('\n')
            if not lines:
                continue

            # Extract interface name from first line
            interface_line = lines[0].strip()
            interface_match = re.match(r'(\w+)', interface_line)
            if not interface_match:
                continue

            interface = interface_match.group(1)

            # Combine all data for this interface
            interface_data = '\n'.join(lines[1:])
            port_data[interface] = interface_data

    except Exception as e:
        print(f"Error parsing {filepath}: {e}")

    return port_data

def process_optical_data_files(data_dir="monitor-results/optical-data"):
    """Process optical data files and update optical analyzer"""
    optical_analyzer = OpticalAnalyzer("monitor-results")
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

    if not files:
        print("❌ No current optical collection files found")
        optical_analyzer.save_optical_history()
        return False

    # Process all optical diagnostic files
    total_processed = 0
    for filename in files:
        if filename.endswith("_optical.txt"):
            hostname = filename.replace("_optical.txt", "")
            filepath = os.path.join(data_dir, filename)


            # Parse optical diagnostics file
            port_data = parse_optical_diagnostics_file(filepath)
            total_processed += 1

            for interface, optical_data in port_data.items():
                port_name = f"{hostname}:{interface}"

                # Skip non-optical interfaces (management, virtual interfaces)
                if any(skip_iface in interface.lower() for skip_iface in ['eth0', 'lo', 'bond', 'mgmt', 'vlan']):
                    continue

                # Skip if no meaningful data (Fixed: don't filter on error-status N/A)
                if not optical_data or len(optical_data.strip()) < 10:
                    continue

                # Check for unplugged ports - add as "unplugged" status for troubleshooting
                if "status                      : unplugged" in optical_data:
                    # Add unplugged port to stats with special status
                    optical_analyzer.current_optical_stats[port_name] = {
                        'port': port_name,
                        'device': hostname,
                        'health_status': 'unplugged',
                        'rx_power_dbm': None,
                        'tx_power_dbm': None,
                        'temperature_c': None,
                        'voltage_v': None,
                        'link_margin_db': None,
                        'timestamp': datetime.now().isoformat()
                    }
                    continue

                # Check for extremely low RX power indicating link down (even if status shows plugged)
                rx_power_match = re.search(r'ch-\d+-rx-power\s*:\s*[\d.]+\s*mW\s*/\s*([-\d.]+)\s*dBm', optical_data)
                if rx_power_match:
                    rx_power_dbm = float(rx_power_match.group(1))
                    # If RX power is extremely low (< -20 dBm), mark as "down" for troubleshooting
                    if rx_power_dbm < -20.0:
                        # Try to get other values even for down ports
                        temp_match = re.search(r'temperature\s*:\s*([\d.]+)', optical_data)
                        voltage_match = re.search(r'voltage\s*:\s*([\d.]+)', optical_data)
                        optical_analyzer.current_optical_stats[port_name] = {
                            'port': port_name,
                            'device': hostname,
                            'health_status': 'down',
                            'rx_power_dbm': rx_power_dbm,
                            'tx_power_dbm': None,
                            'temperature_c': float(temp_match.group(1)) if temp_match else None,
                            'voltage_v': float(voltage_match.group(1)) if voltage_match else None,
                            'link_margin_db': None,
                            'timestamp': datetime.now().isoformat()
                        }
                        continue

                # Check for ports with no meaningful optical readings (N/A values, temp 0.0, etc.)
                if (("temperature                 : 0.0" in optical_data or 
                     "temperature                 : 0.00" in optical_data) and
                    ("voltage                     : 0.0" in optical_data or
                     "voltage                     : 0.00" in optical_data)):
                    continue

                # Skip ports without optical modules
                if ("No transceiver data available" in optical_data or
                    ("diagnostics-status          : N/A" in optical_data and
                     "temperature" not in optical_data and "voltage" not in optical_data and
                     "rx-power" not in optical_data and "tx-power" not in optical_data)):
                    continue
                
                # Skip DAC/Copper cables - they don't have optical diagnostics
                if any(indicator in optical_data for indicator in [
                    'Passive copper', 'Active copper', 'Copper cable',
                    'Base-CR', 'DAC', 'Twinax', 'No separable connector'
                ]):
                    continue

                # Update optical analyzer
                optical_analyzer.update_optical_stats(port_name, optical_data)

                # Show results
                if port_name in optical_analyzer.current_optical_stats:
                    current_optical = optical_analyzer.current_optical_stats[port_name]
                    health = current_optical['health_status']
                    rx_power = current_optical.get('rx_power_dbm')
                    temperature = current_optical.get('temperature_c')
                    voltage = current_optical.get('voltage_v')

                    rx_power_str = f"{rx_power:.2f} dBm" if rx_power is not None else "N/A"
                    temp_str = f"{temperature:.1f}°C" if temperature is not None else "N/A"
                    voltage_str = f"{voltage:.2f}V" if voltage is not None else "N/A"
                    # Per-interface logging removed for performance
                else:
                    pass  # No optical parameters detected

    print(f"\nProcessed {total_processed} files total")

    # Save updated optical history
    optical_analyzer.save_optical_history()
    print("Optical history saved")

    # Generate web report
    output_file = "monitor-results/optical-analysis.html"
    optical_analyzer.export_optical_data_for_web(output_file)
    print(f"Optical analysis report generated: {output_file}")

    # Generate summary for dashboard
    summary = optical_analyzer.get_optical_summary()
    anomalies = optical_analyzer.detect_optical_anomalies()
    print(f"Summary stats: {len(optical_analyzer.current_optical_stats)} total ports analyzed")

    print(f"\nOptical Analysis Summary:")
    print(f"  Total ports monitored: {summary['total_ports']}")
    print(f"  Excellent health: {len(summary['excellent_ports'])}")
    print(f"  Good health: {len(summary['good_ports'])}")
    print(f"  Warning level: {len(summary['warning_ports'])}")
    print(f"  Critical issues: {len(summary['critical_ports'])}")
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
