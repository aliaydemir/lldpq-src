#!/usr/bin/env python3
"""
generate_topology.py - LLDP Topology Generator for LLDPq
=====================================================

PURPOSE:
    Generates a JSON topology file from LLDP data.
    Maintains backward compatibility with existing scripts.

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""
import os
import re
import json
import stat
import sys
import tempfile
import yaml
from datetime import datetime

def get_web_root():
    """Read WEB_ROOT from /etc/lldpq.conf with fallback to default"""
    web_root = "/var/www/html"  # default fallback
    try:
        with open("/etc/lldpq.conf", "r") as f:
            for line in f:
                if line.startswith("WEB_ROOT="):
                    web_root = line.strip().split("=", 1)[1]
                    break
    except (FileNotFoundError, IOError):
        pass
    return web_root

def load_topology_config(config_path="topology_config.yaml"):
    """Load device categorization configuration from YAML file"""
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            return config
    except FileNotFoundError:
        print(f"Warning: {config_path} not found, using default device categorization")
        # Return default config if file not found
        return {
            "device_categories": [
                {"pattern": "inband-fw", "layer": 1, "icon": "firewall"},
                {"pattern": "border", "layer": 2, "icon": "switch"},
                {"pattern": "spine", "layer": 3, "icon": "switch"},
                {"pattern": "leaf", "layer": 4, "icon": "switch"},
                {"pattern": "oob-fw", "layer": 5, "icon": "firewall"},
                {"pattern": "core", "layer": 6, "icon": "switch"},
                {"pattern": "switch", "layer": 7, "icon": "switch"}
            ],
            "default": {"layer": 9, "icon": "server"}
        }
    except Exception as e:
        print(f"Error loading {config_path}: {e}")
        return {"device_categories": [], "default": {"layer": 9, "icon": "server"}}

def categorize_device(device_name, config):
    """Categorize device based on configuration.
    Patterns support regex - use anchors like ^ and $ for exact matching.
    Examples:
      - "spine" matches any device containing "spine"
      - "^spine-" matches devices starting with "spine-"
      - "leaf-[0-9]+$" matches devices ending with "leaf-" followed by numbers
    """
    lower = device_name.lower()

    # Check special rules first
    for rule in config.get("special_rules", []):
        try:
            if re.search(rule["pattern"], device_name, re.IGNORECASE):
                if rule.get("type") == "stagger":
                    # Single band; the brick/zigzag (even -> lower sub-row) is drawn
                    # client-side by cyto-app.js using the staggerRow tag (see
                    # stagger_row_for). Honor the rule's layer/icon here.
                    default_layer = config.get("default", {}).get("layer", 9)
                    return rule.get("layer", default_layer), rule.get("icon", "server")
                if rule.get("type") == "even_odd_suffix":
                    try:
                        number_regex = rule.get("number_regex")
                        if number_regex:
                            # Pull the even/odd number from a capture group anywhere in the
                            # name (e.g. the rack field) — not just the trailing "-" segment.
                            m = re.search(number_regex, device_name, re.IGNORECASE)
                            if not m:
                                break  # no match -> fall through to regular patterns
                            device_number = int(m.group(1))
                        else:
                            device_number = int(device_name.split("-")[-1])
                        if device_number % 2 == 0:
                            return rule["even_layer"], rule["icon"]
                        else:
                            return rule["odd_layer"], rule["icon"]
                    except (ValueError, IndexError, re.error):
                        # If parsing fails, continue to regular patterns
                        break
        except re.error:
            # Invalid regex, fall back to substring match
            if rule["pattern"] in device_name:
                pass

    # Check each regular pattern in order (supports regex)
    for category in config.get("device_categories", []):
        try:
            if re.search(category["pattern"], lower):
                return category["layer"], category["icon"]
        except re.error:
            # Invalid regex, fall back to substring match
            if category["pattern"] in lower:
                return category["layer"], category["icon"]

    # Return default if no pattern matches
    default = config.get("default", {"layer": 9, "icon": "server"})
    return default["layer"], default["icon"]

def stagger_row_for(device_name, config):
    """Return the brick sub-row for a 'stagger' special rule:
      0 -> odd number  (upper sub-row)
      1 -> even number (lower sub-row)
      None -> device is not part of any stagger rule.
    The number comes from number_regex group 1 (e.g. the rack field); if absent,
    falls back to the trailing "-" segment. Generic: works for any naming scheme.
    """
    for rule in config.get("special_rules", []):
        if rule.get("type") != "stagger":
            continue
        try:
            if not re.search(rule["pattern"], device_name, re.IGNORECASE):
                continue
            number_regex = rule.get("number_regex")
            if number_regex:
                m = re.search(number_regex, device_name, re.IGNORECASE)
                if not m:
                    continue
                num = int(m.group(1))
            else:
                num = int(device_name.split("-")[-1])
            return 1 if num % 2 == 0 else 0
        except (ValueError, IndexError, re.error):
            continue
    return None

def append_creation_time_to_html(html_file_path):
    timestamp = datetime.now().strftime("Created on %Y-%m-%d %H-%M")
    try:
        with open(html_file_path, "r") as f:
            content = f.read()
        content_before = content
        content = re.sub(
            r'\s*<button[^>]*>Created on \d{4}-\d{2}-\d{2} \d{2}-\d{2}</button>',
            '',
            content
        )
        insert_point = content.lower().rfind('</body>')
        if insert_point != -1:
            new_div = f'        <button onclick="time()">{timestamp}</button>\n'
            new_content = content[:insert_point] + new_div + content[insert_point:]
            with open(html_file_path, "w") as f:
                f.write(new_content)
    except Exception as e:
        print(f"[ERROR] Failed to modify HTML: {e}")

def parse_assets_file(assets_file_path):
    device_info = {}
    try:
        with open(assets_file_path, 'r') as file:
            lines = file.readlines()
            for line in lines[1:]:  # Skip timestamp
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    device_name = parts[0]
                    # Skip header line
                    if device_name == "DEVICE-NAME":
                        continue
                    device_info[device_name] = {
                        "primaryIP": parts[1],
                        "mac": parts[2],
                        "serial_number": parts[3],
                        "model": parts[4],
                        "version": parts[5]
                    }
    except FileNotFoundError:
        pass
    return device_info

def parse_endpoint_hosts(devices_yaml_path):
    """
    Parse endpoint_hosts from devices.yaml file.
    Returns exact hostnames and patterns.
    Patterns are entries containing '*' (e.g., *dgx*, spine-*)
    
    devices.yaml format:
        endpoint_hosts:
          - exact-hostname
          - "*dgx*"        # pattern
          - "prod-cfw*"    # pattern
    """
    host_names = set()
    patterns = []
    try:
        with open(devices_yaml_path, 'r') as file:
            config = yaml.safe_load(file)
            
        endpoint_hosts = config.get('endpoint_hosts', [])
        if not endpoint_hosts:
            return host_names, patterns
            
        for entry in endpoint_hosts:
            if not entry or not isinstance(entry, str):
                continue
            entry = entry.strip()
            if '*' in entry:
                # Convert glob pattern to regex
                # *dgx* -> .*dgx.*
                regex_pattern = entry.replace('*', '.*')
                patterns.append(re.compile(f'^{regex_pattern}$', re.IGNORECASE))
            else:
                host_names.add(entry)
    except (FileNotFoundError, yaml.YAMLError):
        pass
    return host_names, patterns

def apply_host_patterns(patterns, all_hostnames):
    """
    Apply patterns to a list of hostnames and return matches.
    """
    matched = set()
    for hostname in all_hostnames:
        for pattern in patterns:
            if pattern.match(hostname):
                matched.add(hostname)
                break
    return matched

def scan_lldp_neighbors(directory):
    """
    Scan LLDP result files to discover all neighbor hostnames.
    This is used to apply patterns before the full LLDP parse.
    Parses the main lldp_results.ini file.
    
    Format: Port  Status  Exp-Nbr  Exp-Nbr-Port  Act-Nbr  Act-Nbr-Port  Port-Status
    We need Act-Nbr (index 4) which is the actual neighbor hostname.
    """
    all_neighbors = set()
    try:
        main_file = os.path.join(directory, "lldp_results.ini")
        if os.path.exists(main_file):
            with open(main_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip headers, separators, and empty lines
                    if not line or line.startswith('-') or line.startswith('Port') or line.startswith('=') or line.startswith('Created'):
                        continue
                    parts = line.split()
                    # Format: Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status
                    # Index:  0    1      2       3            4       5            6
                    if len(parts) >= 5:
                        # Get Act-Nbr (actual neighbor) at index 4
                        act_nbr = parts[4]
                        # Skip if it's not a valid hostname
                        if act_nbr and act_nbr not in ('None', 'N/A', '-'):
                            all_neighbors.add(act_nbr)
                        
                        # Also get Exp-Nbr (expected neighbor) at index 2
                        exp_nbr = parts[2]
                        if exp_nbr and exp_nbr not in ('None', 'N/A', '-'):
                            all_neighbors.add(exp_nbr)
    except:
        pass
    return all_neighbors

def get_lldp_field(section, field_name, regex_pattern=None):
    if regex_pattern:
        match = re.search(regex_pattern, section, re.DOTALL | re.IGNORECASE)
    else:
        match = re.search(rf'{field_name}:\s*(.+?)(?:\n\s*\S+\s*:|\Z)', section, re.DOTALL | re.IGNORECASE)

    return match.group(1).strip() if match else None

def normalize_interface_name(iface_name, known_device_names):
    """
    Normalize interface names by removing device prefixes.
    This function handles device names with dashes (e.g., GB200-1-01).
    Only removes device prefix if interface actually contains it.
    """
    best_match_device_name = None
    for device_name in known_device_names:
        # Only try to normalize if interface name actually starts with device name + dash
        device_prefix = f"{device_name}-"
        if iface_name.startswith(device_prefix):
            if best_match_device_name is None or len(device_name) > len(best_match_device_name):
                best_match_device_name = device_name

    if best_match_device_name:
        device_prefix = f"{best_match_device_name}-"
        normalized_name = iface_name[len(device_prefix):]
        return normalized_name

    # If no device prefix found, return interface name as-is
    # This handles cases like eth_rail0, enP6p3s0f0np0, etc.
    return iface_name


def parse_port_status(filepath):
    """Parse port status from LLDP result file"""
    port_status = {}
    try:
        with open(filepath, 'r') as file:
            data = file.read()
        
        # Find PORT_STATUS section
        match = re.search(r'===PORT_STATUS_START===\s*(.*?)\s*===PORT_STATUS_END===', data, re.DOTALL)
        if match:
            status_lines = match.group(1).strip().split('\n')
            for line in status_lines:
                parts = line.strip().split()
                if len(parts) == 2:
                    port_name, status = parts
                    port_status[port_name] = status  # UP, DOWN, or UNKNOWN
    except Exception:
        pass
    return port_status

def parse_port_speed(filepath):
    """Parse port speed from LLDP result file (in Mbps)"""
    port_speed = {}
    try:
        with open(filepath, 'r') as file:
            data = file.read()
        
        # Find PORT_SPEED section
        match = re.search(r'===PORT_SPEED_START===\s*(.*?)\s*===PORT_SPEED_END===', data, re.DOTALL)
        if match:
            speed_lines = match.group(1).strip().split('\n')
            for line in speed_lines:
                parts = line.strip().split()
                if len(parts) == 2:
                    port_name, speed = parts
                    try:
                        port_speed[port_name] = int(speed)  # Speed in Mbps
                    except ValueError:
                        pass
    except Exception:
        pass
    return port_speed

def format_speed(speed_mbps):
    """Format speed in Mbps to human readable (e.g., 400Gbps)"""
    if not speed_mbps or speed_mbps == 0:
        return "N/A"
    if speed_mbps >= 1000:
        return f"{speed_mbps // 1000}Gbps"
    return f"{speed_mbps}Mbps"

def parse_lldp_results(directory, device_info, hosts_only_devices):
    topology_data = {
        "links": [],
        "nodes": []
    }

    device_nodes = {}
    device_id = 0

    all_lldp_links_found = set()
    
    # Store port status and speed per device
    all_port_status = {}
    all_port_speed = {}

    known_device_names_for_normalization = set(device_info.keys())

    # Load topology configuration
    topology_config = load_topology_config()
    print(f"Loaded topology config with {len(topology_config.get('device_categories', []))} device patterns")

    for device_name, info in device_info.items():
        if "OOB-MGMT" in device_name:
            continue

        # Use configuration-based device categorization
        layer_sort_preference, dev_icon = categorize_device(device_name, topology_config)

        device_node = {
            "icon": dev_icon,
            "id": device_id,
            "layerSortPreference": layer_sort_preference,
            "name": device_name,
            "primaryIP": info.get("primaryIP", "N/A"),
            "model": info.get("model", "N/A"),
            "serial_number": info.get("serial_number", "N/A"),
            "version": info.get("version", "N/A"),
            "dcimDeviceLink": f"/device.html?device={device_name}"
        }
        _srow = stagger_row_for(device_name, topology_config)
        if _srow is not None:
            device_node["staggerRow"] = _srow
        topology_data["nodes"].append(device_node)
        device_nodes[device_name] = device_id
        device_id += 1

    # Also add host-only devices to device_nodes (they might be LLDP neighbors)
    for host_device in hosts_only_devices:
        if host_device not in device_nodes:  # Avoid duplicates
            layer_sort_preference, dev_icon = categorize_device(host_device, topology_config)
            device_node = {
                "icon": dev_icon,
                "id": device_id,
                "layerSortPreference": layer_sort_preference,
                "name": host_device,
                "primaryIP": "N/A",
                "model": "N/A",
                "serial_number": "N/A",
                "version": "N/A",
                "dcimDeviceLink": f"/device.html?device={host_device}"
            }
            _srow = stagger_row_for(host_device, topology_config)
            if _srow is not None:
                device_node["staggerRow"] = _srow
            topology_data["nodes"].append(device_node)
            device_nodes[host_device] = device_id
            device_id += 1

    link_id = 0
    reachable_devices = set()

    # First pass: collect ALL port status and speed from all devices
    for filename in os.listdir(directory):
        if not filename.endswith("_lldp_result.ini"):
            continue
        filepath = os.path.join(directory, filename)
        device_name = filename.split("_lldp_result.ini")[0]
        all_port_status[device_name] = parse_port_status(filepath)
        all_port_speed[device_name] = parse_port_speed(filepath)
        reachable_devices.add(device_name)

    # Second pass: process LLDP data and create links
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)

        if not filename.endswith("_lldp_result.ini"):
            continue

        device_name_from_lldp = filename.split("_lldp_result.ini")[0]
        
        try:
            with open(filepath, 'r') as file:
                data = file.read()
        except FileNotFoundError:
            continue

        interface_sections = re.split(r'-------------------------------------------------------------------------------', data)
        interface_sections = [s.strip() for s in interface_sections if s.strip()]

        for section in interface_sections:
            interface_name = get_lldp_field(section, "Interface", r'Interface:\s*(\S+),')
            neighbor_device = get_lldp_field(section, "SysName", r'SysName:\s*(\S+)')
            
            # Clean up FQDN suffix from neighbor device name (e.g., ".cm.cluster", ".local")
            # This matches the logic in lldp-validate.py for consistency
            if neighbor_device:
                neighbor_device = neighbor_device.split(".cm.cluster")[0]
                neighbor_device = neighbor_device.split(".local")[0]

            # ifname for Cumulus/Cisco, ifalias for FortiGate
            raw_port_id_ifname = get_lldp_field(section, "PortID", r'PortID:\s+(?:ifname|ifalias)\s+(\S+)')
            # Optimized PortDescr parsing - handle multiple formats
            raw_port_descr = None
            port_descr_full = get_lldp_field(section, "PortDescr", r'PortDescr:\s*(.*?)(?:\n|$)')

            if port_descr_full:
                # Format 1: "Interface X as <interface_name>" (HGX/NVSwitch)
                if " as " in port_descr_full:
                    as_match = re.search(r' as\s+(\S+)', port_descr_full)
                    if as_match:
                        candidate = as_match.group(1)
                        # Quick validation: avoid TLV data
                        if "," not in candidate and not candidate.startswith("TLV"):
                            raw_port_descr = candidate
                # Format 2: Direct interface name (GB200/Hosts)
                else:
                    # Extract first non-TLV word
                    candidate = port_descr_full.strip().split()[0] if port_descr_full.strip() else None
                    if candidate and "," not in candidate and not candidate.startswith("TLV"):
                        raw_port_descr = candidate

            if not interface_name or not neighbor_device:
                continue

            tgt_ifname = ""
            if raw_port_id_ifname:
                tgt_ifname = normalize_interface_name(raw_port_id_ifname, known_device_names_for_normalization)
            elif raw_port_descr:
                tgt_ifname = normalize_interface_name(raw_port_descr, known_device_names_for_normalization)

            if not tgt_ifname:
                continue

            if interface_name.lower() == "eth0" or tgt_ifname.lower() == "eth0":
                continue

            if device_name_from_lldp in device_nodes and neighbor_device in device_nodes:
                # Get port status for both source and target interfaces
                src_port_status = all_port_status.get(device_name_from_lldp, {}).get(interface_name, "N/A")
                tgt_port_status = all_port_status.get(neighbor_device, {}).get(tgt_ifname, "N/A")
                # Get port speed (in Mbps)
                src_port_speed = all_port_speed.get(device_name_from_lldp, {}).get(interface_name, 0)
                tgt_port_speed = all_port_speed.get(neighbor_device, {}).get(tgt_ifname, 0)
                
                link = {
                    "id": link_id,
                    "source": device_nodes[device_name_from_lldp],
                    "srcDevice": device_name_from_lldp,
                    "srcIfName": interface_name,
                    "srcPortStatus": src_port_status,
                    "srcPortSpeed": format_speed(src_port_speed),
                    "target": device_nodes[neighbor_device],
                    "tgtDevice": neighbor_device,
                    "tgtIfName": tgt_ifname,
                    "tgtPortStatus": tgt_port_status,
                    "tgtPortSpeed": format_speed(tgt_port_speed),
                    "is_missing": "no"
                }
                topology_data["links"].append(link)
                link_id += 1

                # Add to all_lldp_links_found for matching with topology.dot
                all_lldp_links_found.add((device_name_from_lldp, interface_name, neighbor_device, tgt_ifname))
                # Also add reverse for bidirectional matching
                all_lldp_links_found.add((neighbor_device, tgt_ifname, device_name_from_lldp, interface_name))


    # Mark unreachable managed devices as "unknown" — but NOT hosts/servers/endpoints.
    # A device is "unreachable" if it's in device_info (assets.ini) but has no LLDP file.
    # Hosts/servers (e.g. RTX, DGX) are expected to not have LLDP files — they're not switches.
    for node in topology_data["nodes"]:
        if node["name"] in device_info and \
           node["name"] not in hosts_only_devices and \
           node["name"] not in reachable_devices and \
           node["icon"] not in ("server", "host", "firewall"):
            node["icon"] = "unknown"

    return topology_data, device_nodes, link_id, all_lldp_links_found, all_port_status, all_port_speed

def parse_topology_dot_file(dot_file_path):
    defined_links = set()
    try:
        with open(dot_file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith('"') and '--' in line:
                    parts = re.findall(r'"(.*?)"', line)
                    if len(parts) == 4:
                        src_device, src_ifname, tgt_device, tgt_ifname = parts
                        defined_links.add((src_device, src_ifname, tgt_device, tgt_ifname))
    except FileNotFoundError:
        pass
    return defined_links

def generate_topology_file(output_filename, directory, assets_file_path, devices_yaml_path, dot_file_path):
    device_info = parse_assets_file(assets_file_path)
    host_names, host_patterns = parse_endpoint_hosts(devices_yaml_path)

    # First pass: add exact hostnames to device_info
    for host in host_names:
        if host not in device_info:
            device_info[host] = {
                "primaryIP": "N/A",
                "mac": "N/A",
                "serial_number": "N/A",
                "model": "N/A",
                "version": "N/A"
            }

    # Apply patterns to LLDP neighbors BEFORE parsing
    # This ensures pattern-matched hosts are included in the topology
    if host_patterns:
        all_lldp_neighbors = scan_lldp_neighbors(directory)
        pattern_matched_hosts = apply_host_patterns(host_patterns, all_lldp_neighbors)
        
        # Add pattern-matched hosts to host_names only (NOT device_info)
        # This way they'll be in hosts_only_devices and get proper icon/layer from categorize_device
        for host in pattern_matched_hosts:
            host_names.add(host)

    # hosts_only_devices = hosts in host_names but NOT in device_info (assets.ini)
    # These will get their icon/layer from topology_config.yaml via categorize_device()
    hosts_only_devices = host_names - set(device_info.keys())

    # Parse LLDP to discover all devices (now includes pattern-matched hosts)
    topology_data, device_nodes, current_link_id, all_lldp_links_found, all_port_status, all_port_speed = parse_lldp_results(directory, device_info, hosts_only_devices)

    defined_links = parse_topology_dot_file(dot_file_path)

    # Hostname matching is case-insensitive (DNS-style); interface names stay exact
    def _link_key(s_dev, s_if, t_dev, t_if):
        return (s_dev.lower(), s_if, t_dev.lower(), t_if)
    defined_links_lc = {_link_key(*dl) for dl in defined_links}
    all_lldp_links_found_lc = {_link_key(*ll) for ll in all_lldp_links_found}
    device_nodes_lc = {name.lower(): nid for name, nid in device_nodes.items()}

    for link in topology_data["links"]:
        src_device = link["srcDevice"]
        tgt_device = link["tgtDevice"]
        src_ifname = link["srcIfName"]
        tgt_ifname = link["tgtIfName"]

        forward_link_tuple = (src_device, src_ifname, tgt_device, tgt_ifname)
        reverse_link_tuple = (tgt_device, tgt_ifname, src_device, src_ifname)

        if _link_key(*forward_link_tuple) not in defined_links_lc and _link_key(*reverse_link_tuple) not in defined_links_lc:
            link["is_missing"] = "fail"

    final_links_to_add = []

    for defined_link in defined_links:
        src_device, src_ifname, tgt_device, tgt_ifname = defined_link
        forward_link_tuple = (src_device, src_ifname, tgt_device, tgt_ifname)
        reverse_link_tuple = (tgt_device, tgt_ifname, src_device, src_ifname)

        if _link_key(*forward_link_tuple) not in all_lldp_links_found_lc and _link_key(*reverse_link_tuple) not in all_lldp_links_found_lc:

            if src_device.lower() in device_nodes_lc and tgt_device.lower() in device_nodes_lc:
                # Get port status for both source and target interfaces
                src_port_status = all_port_status.get(src_device, {}).get(src_ifname, "N/A")
                tgt_port_status = all_port_status.get(tgt_device, {}).get(tgt_ifname, "N/A")
                # Get port speed (in Mbps) - for missing links, likely N/A
                src_port_speed = all_port_speed.get(src_device, {}).get(src_ifname, 0)
                tgt_port_speed = all_port_speed.get(tgt_device, {}).get(tgt_ifname, 0)
                
                link = {
                    "id": current_link_id,
                    "source": device_nodes_lc[src_device.lower()],
                    "srcDevice": src_device,
                    "srcIfName": src_ifname,
                    "srcPortStatus": src_port_status,
                    "srcPortSpeed": format_speed(src_port_speed),
                    "target": device_nodes_lc[tgt_device.lower()],
                    "tgtDevice": tgt_device,
                    "tgtIfName": tgt_ifname,
                    "tgtPortStatus": tgt_port_status,
                    "tgtPortSpeed": format_speed(tgt_port_speed),
                    "is_missing": "yes"
                }
                final_links_to_add.append(link)
                current_link_id += 1
            else:
                pass

    topology_data["links"].extend(final_links_to_add)

    unique_links_filtered = []
    seen_links_for_dedup = set()

    for link in topology_data["links"]:
        src_device = link["srcDevice"]
        tgt_device = link["tgtDevice"]
        src_ifname = link["srcIfName"]
        tgt_ifname = link["tgtIfName"]

        current_link_tuple = (src_device, src_ifname, tgt_device, tgt_ifname)
        reverse_link_tuple = (tgt_device, tgt_ifname, src_device, src_ifname)

        if current_link_tuple not in seen_links_for_dedup and reverse_link_tuple not in seen_links_for_dedup:
            unique_links_filtered.append(link)
            seen_links_for_dedup.add(current_link_tuple)
        else:
            pass

    topology_data["links"] = unique_links_filtered

    final_nodes_set = set(device_info.keys())

    for link in topology_data["links"]:
        final_nodes_set.add(link["srcDevice"])
        final_nodes_set.add(link["tgtDevice"])

    topology_data["nodes"] = [node for node in topology_data["nodes"] if node["name"] in final_nodes_set]

    # Natural sort so "...-1-2" comes before "...-1-10" (numeric-aware ordering)
    topology_data["nodes"].sort(key=lambda x: [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', x["name"])])

    id_map = {node["id"]: new_id for new_id, node in enumerate(topology_data["nodes"])}

    for node in topology_data["nodes"]:
        node["id"] = id_map[node["id"]]

    for link in topology_data["links"]:
        link["source"] = id_map[link["source"]]
        link["target"] = id_map[link["target"]]

    # Add timestamp
    topology_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M")

    output_dir = os.path.dirname(os.path.abspath(output_filename))
    temp_path = None
    try:
        existing_stat = os.stat(output_filename)
    except FileNotFoundError:
        existing_stat = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_dir,
            prefix=".topology.js.",
            delete=False,
        ) as file:
            temp_path = file.name
            os.fchmod(
                file.fileno(),
                stat.S_IMODE(existing_stat.st_mode) if existing_stat else 0o664,
            )
            if existing_stat and hasattr(os, "fchown"):
                try:
                    os.fchown(file.fileno(), existing_stat.st_uid, existing_stat.st_gid)
                except PermissionError:
                    pass
            file.write("var topologyData = ")
            json.dump(topology_data, file, indent=4)
            file.write(";")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, output_filename)
        return True
    except Exception:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise

def main():
    lldp_results_directory = "lldp-results"
    assets_file_path = "assets.ini"
    devices_yaml_path = "devices.yaml"
    dot_file_path = "topology.dot"
    
    # Get web root from config with fallback
    WEB_ROOT = get_web_root()
    output_file = f"{WEB_ROOT}/topology/topology.js"

    if not os.path.isdir(lldp_results_directory):
        print(f"Error: LLDP results directory not found: {lldp_results_directory}")
        return 1

    try:
        generate_topology_file(output_file, lldp_results_directory, assets_file_path, devices_yaml_path, dot_file_path)
        append_creation_time_to_html(f"{WEB_ROOT}/topology/main.html")
        return 0
    except Exception as exc:
        print(f"Error generating topology: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
