#!/usr/bin/env python3
"""
Process hardware health data collected by monitor.sh
Simplified version that uses generate_hardware_html.py

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import os
import sys
import subprocess
from datetime import datetime
from collection_freshness import (
    asset_snapshot_is_valid,
    is_current_collection,
    mark_html_collection_unavailable,
    read_asset_snapshot,
    read_collection_outcomes,
)


def mark_summary_collection_unavailable(summary_path):
    """Keep the summary JSON status equal to the HTML unavailable banner."""
    from generate_hardware_html import _atomic_write
    with open(summary_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["collection_status"] = "unavailable"
    _atomic_write(summary_path, json.dumps(payload) + "\n")


def main():
    """Main function"""
    print("Starting hardware health data processing...")
    
    data_dir = "monitor-results"
    print(f"Data directory: {os.path.abspath(data_dir)}")
    
    if not os.path.exists(data_dir):
        print(f"❌ Data directory not found: {data_dir}")
        print("💡 Run monitor.sh first to collect data")
        return 1
    
    # Check for hardware data files  
    hardware_data_dir = f"{data_dir}/hardware-data"
    processed_count = 0
    asset_snapshot = read_asset_snapshot()
    statuses, _asset_mtime, assets_available = asset_snapshot
    snapshot_valid = asset_snapshot_is_valid(asset_snapshot)
    if assets_available and not snapshot_valid:
        print("❌ Asset snapshot is invalid or incomplete")
        return 1
    try:
        collection_outcomes = read_collection_outcomes()
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"❌ Collection outcome manifest is invalid: {exc}")
        return 1
    expected_hosts = (
        {
            host for host, status in collection_outcomes.items()
            if status == "current"
        }
        if collection_outcomes is not None else
        (
            {host for host, status in statuses.items() if status == "OK"}
            if snapshot_valid else set()
        )
    )
    all_devices_unavailable = snapshot_valid and not expected_hosts
    
    if os.path.exists(hardware_data_dir):
        hardware_files = [
            f for f in os.listdir(hardware_data_dir)
            if f.endswith('_hardware.txt')
            and is_current_collection(
                os.path.join(hardware_data_dir, f),
                f.removesuffix('_hardware.txt'),
                asset_snapshot,
            )
        ]
        processed_count = len(hardware_files)
        collected_hosts = {
            filename.removesuffix('_hardware.txt') for filename in hardware_files
        }
        missing_hosts = sorted(expected_hosts - collected_hosts)
        if missing_hosts:
            print(
                "⚠ Missing current hardware collections; publishing partial coverage for: "
                + ", ".join(missing_hosts)
            )
        if processed_count > 0:
            print(f"Found {processed_count} hardware data files")
        else:
            print("No hardware data files found to process")
    else:
        print("Hardware data directory doesn't exist yet.")
    
    if processed_count == 0 and not all_devices_unavailable:
        print("❌ No current hardware collection files found")
        return 1

    # Generate the BER-style HTML from the current collection plus history.
    try:
        print("Generating BER-style hardware analysis HTML...")
        result = subprocess.run([sys.executable, "generate_hardware_html.py"], 
                              capture_output=True, text=True, cwd=".")
        if result.returncode == 0:
            print("BER-style hardware analysis HTML generated successfully!")
            print(result.stdout.strip())
            if all_devices_unavailable:
                mark_html_collection_unavailable(
                    os.path.join(data_dir, "hardware-analysis.html")
                )
                mark_summary_collection_unavailable(
                    os.path.join(data_dir, "summary", "hardware-summary.json")
                )
        else:
            print(f"❌ Error generating HTML: {result.stderr}")
            return result.returncode or 1
    except Exception as e:
        print(f"❌ Error running generate_hardware_html.py: {e}")
        return 1
    
    print(f"[{datetime.now()}] Hardware data processing completed")
    
    if processed_count == 0 and not all_devices_unavailable:
        print("\n💡 To enable hardware monitoring:")
        print("   1. Hardware data collection is not yet added to monitor.sh")
        print("   2. This will be added in the next step")
        print("   3. After updating monitor.sh, run it to collect hardware data")
        print("   4. Then run this script again to generate hardware analysis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
