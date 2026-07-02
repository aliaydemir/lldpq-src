#!/usr/bin/env python3
"""
Process hardware health data collected by monitor.sh
Simplified version that uses generate_hardware_html.py

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import sys
import subprocess
from datetime import datetime
from collection_freshness import is_current_collection, read_asset_snapshot


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
    
    if os.path.exists(hardware_data_dir):
        asset_snapshot = read_asset_snapshot()
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
        if processed_count > 0:
            print(f"Found {processed_count} hardware data files")
        else:
            print("No hardware data files found to process")
    else:
        print("Hardware data directory doesn't exist yet.")
    
    if processed_count == 0:
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
        else:
            print(f"❌ Error generating HTML: {result.stderr}")
            return result.returncode or 1
    except Exception as e:
        print(f"❌ Error running generate_hardware_html.py: {e}")
        return 1
    
    print(f"[{datetime.now()}] Hardware data processing completed")
    
    if processed_count == 0:
        print("\n💡 To enable hardware monitoring:")
        print("   1. Hardware data collection is not yet added to monitor.sh")
        print("   2. This will be added in the next step")
        print("   3. After updating monitor.sh, run it to collect hardware data")
        print("   4. Then run this script again to generate hardware analysis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
