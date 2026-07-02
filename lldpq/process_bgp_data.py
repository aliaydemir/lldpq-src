#!/usr/bin/env python3
"""
Process BGP neighbor data collected by monitor.sh

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import sys
import copy
import time
from datetime import datetime
from bgp_analyzer import BGPAnalyzer

def parse_data_file(filepath):
    """Parse data file"""
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return ""


def parse_asset_statuses(assets_file):
    """Read hostname -> collection status from assets.ini when available."""
    statuses = {}
    try:
        with open(assets_file, "r") as f:
            for line in f:
                parts = line.split()
                if not parts or parts[0] in {"Created", "DEVICE-NAME"}:
                    continue
                status = next(
                    (part.upper() for part in parts[1:]
                     if part.upper() in {"OK", "UNREACHABLE", "SSH-FAILED", "NO-INFO"}),
                    None
                )
                if status:
                    statuses[parts[0]] = status
    except OSError:
        pass
    return statuses


def get_collection_problem(filepath, hostname, assets_file, asset_statuses):
    """Return why a raw BGP file cannot represent the current collection."""
    try:
        file_mtime = os.path.getmtime(filepath)
    except OSError:
        return "collection_missing"

    try:
        max_age_minutes = float(os.environ.get("BGP_DATA_MAX_AGE_MINUTES", "30"))
    except ValueError:
        max_age_minutes = 30
    if time.time() - file_mtime > max(max_age_minutes, 0) * 60:
        return "collection_stale"

    # In the normal full run assets.ini is finalized before monitor.sh starts.
    # A BGP file older than that inventory snapshot belongs to an earlier run.
    try:
        if os.path.getmtime(assets_file) > file_mtime + 1:
            return "collection_not_refreshed"
    except OSError:
        pass

    asset_status = asset_statuses.get(hostname)
    if asset_status and asset_status != "OK":
        return f"asset_status_{asset_status.lower()}"

    return None


def get_last_known_stats(previous_stats):
    """Unwrap the most recent successful stats without nesting stale records."""
    if not previous_stats:
        return None
    if previous_stats.get("data_status") in {"stale", "unknown"}:
        previous_stats = previous_stats.get("last_known_stats")
    return copy.deepcopy(previous_stats) if previous_stats else None


def mark_collection_unavailable(analyzer, hostname, previous_stats, reason):
    """Publish an explicit stale/unknown placeholder, never stale data as current."""
    last_known = get_last_known_stats(previous_stats)
    status = "stale" if last_known else "unknown"
    analyzer.current_bgp_stats[hostname] = {
        "neighbors": [],
        "total_neighbors": 0,
        "established_neighbors": 0,
        "down_neighbors": 0,
        "last_update": last_known.get("last_update") if last_known else None,
        "data_status": status,
        "collection_checked_at": datetime.now().isoformat(),
        "collection_error": reason,
    }
    if last_known:
        analyzer.current_bgp_stats[hostname]["last_known_stats"] = last_known


def bgp_output_is_valid(analyzer, bgp_data):
    """Accept parsed neighbors or an explicit, valid zero-neighbor response."""
    if analyzer.parse_bgp_output(bgp_data):
        return True
    if re.search(r'Total number of neighbors\s+0\b', bgp_data, re.IGNORECASE):
        return True
    if re.search(
        r'no\s+(?:bgp\s+)?neighbors|bgp\s+(?:instance|process).*not configured',
        bgp_data,
        re.IGNORECASE,
    ):
        return True
    return False

def process_bgp_data_files(data_dir="monitor-results/bgp-data"):
    """Process BGP data files and update BGP analyzer"""
    data_dir = os.path.abspath(data_dir)
    result_dir = os.path.dirname(data_dir.rstrip(os.sep))
    bgp_analyzer = BGPAnalyzer(result_dir)
    previous_current_stats = copy.deepcopy(bgp_analyzer.current_bgp_stats)
    bgp_analyzer.current_bgp_stats = {}
    processed_hosts = set()
    assets_file = os.path.join(os.path.dirname(result_dir), "assets.ini")
    asset_statuses = parse_asset_statuses(assets_file)
    
    print("Processing BGP neighbor data")
    print(f"Using BGP thresholds: Down time={bgp_analyzer.thresholds['critical_down_hours']}h, "
          f"Queue threshold={bgp_analyzer.thresholds['high_queue_threshold']}")
    
    if not os.path.exists(data_dir):
        print(f"BGP data directory {data_dir} not found")
        return
    
    # Process all BGP neighbor files
    for filename in sorted(os.listdir(data_dir)):
        if filename.endswith("_bgp.txt"):
            hostname = filename.replace("_bgp.txt", "")
            filepath = os.path.join(data_dir, filename)
            processed_hosts.add(hostname)
            
            # Parse BGP data file
            bgp_data = parse_data_file(filepath)

            collection_problem = get_collection_problem(
                filepath, hostname, assets_file, asset_statuses
            )
            if collection_problem:
                mark_collection_unavailable(
                    bgp_analyzer, hostname,
                    previous_current_stats.get(hostname), collection_problem
                )
                continue

            if not bgp_data or len(bgp_data.strip()) < 50:
                mark_collection_unavailable(
                    bgp_analyzer, hostname,
                    previous_current_stats.get(hostname), "collection_empty_or_invalid"
                )
                continue

            if not bgp_output_is_valid(bgp_analyzer, bgp_data):
                mark_collection_unavailable(
                    bgp_analyzer, hostname,
                    previous_current_stats.get(hostname), "collection_parse_failed"
                )
                continue
            
            # Update BGP analyzer
            bgp_analyzer.update_bgp_stats(hostname, bgp_data)
            bgp_analyzer.current_bgp_stats[hostname].update({
                "data_status": "current",
                "collection_checked_at": datetime.now().isoformat(),
            })
            
            # Show results
            if hostname in bgp_analyzer.current_bgp_stats:
                stats = bgp_analyzer.current_bgp_stats[hostname]
                total = stats["total_neighbors"]
                established = stats["established_neighbors"]
                down = stats["down_neighbors"]
                
                # Per-device logging removed for performance
                # Only summary and critical issues are shown
    
    # Process EVPN data files
    # Devices present in the prior snapshot but absent from this collection must
    # not survive as apparently-current data.
    expected_hosts = set(previous_current_stats) | set(asset_statuses)
    for hostname in expected_hosts:
        if hostname not in processed_hosts:
            mark_collection_unavailable(
                bgp_analyzer, hostname, previous_current_stats.get(hostname),
                "collection_missing"
            )

    evpn_data_dir = os.path.join(result_dir, "evpn-data")
    if os.path.exists(evpn_data_dir):
        print("Processing EVPN data")
        for filename in os.listdir(evpn_data_dir):
            if filename.endswith("_evpn.txt"):
                hostname = filename.replace("_evpn.txt", "")
                filepath = os.path.join(evpn_data_dir, filename)
                
                # Parse EVPN data file
                evpn_data = parse_data_file(filepath)
                
                if evpn_data and len(evpn_data.strip()) > 20:
                    # Update EVPN stats
                    bgp_analyzer.update_evpn_stats(hostname, evpn_data)
    
    # Save updated BGP history
    bgp_analyzer.save_bgp_history()
    
    # Generate web report
    output_file = os.path.join(result_dir, "bgp-analysis.html")
    bgp_analyzer.export_bgp_data_for_web(output_file)
    print(f"BGP analysis report generated: {output_file}")
    
    # Generate summary for dashboard
    summary = bgp_analyzer.get_bgp_summary()
    evpn_summary = bgp_analyzer.get_evpn_summary()
    anomalies = bgp_analyzer.detect_bgp_anomalies()
    
    print(f"\n BGP Analysis Summary:")
    print(f"  Total devices: {summary['total_devices']}")
    print(f"  Total neighbors: {summary['total_neighbors']}")
    print(f"  Established: {summary['established_neighbors']}")
    print(f"  Down/Problem: {summary['down_neighbors']}")
    print(f"  Health ratio: {summary['health_ratio']:.1f}%")
    print(f"  Anomalies detected: {len(anomalies)}")
    
    print(f"\n EVPN Summary:")
    print(f"  Total VNIs: {evpn_summary['total_vnis']}")
    print(f"  L2 VNIs: {evpn_summary['l2_vnis']}")
    print(f"  L3 VNIs: {evpn_summary['l3_vnis']}")
    print(f"  Type-2 Routes (MAC/IP): {evpn_summary['type2_routes']}")
    print(f"  Type-5 Routes (IP Prefix): {evpn_summary['type5_routes']}")
    
    # Show critical issues
    critical_anomalies = [a for a in anomalies if a['severity'] == 'critical']
    if critical_anomalies:
        print(f"\nCritical BGP Issues:")
        for anomaly in critical_anomalies[:5]:  # Show first 5
            print(f"  • {anomaly['device']}: {anomaly['neighbor']} - {anomaly['message']}")

    return bgp_analyzer

if __name__ == "__main__":
    import logging
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        handlers=[
            logging.FileHandler('monitor-results/bgp_analyzer.log'),
            logging.StreamHandler()
        ]
    )
    
    logging.info("Starting BGP data processing")
    
    try:
        process_bgp_data_files()
        logging.info("BGP data processing completed")
    except Exception as e:
        logging.error(f"BGP data processing failed: {e}")
        sys.exit(1)
