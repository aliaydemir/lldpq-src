#!/usr/bin/python3
"""
lldp-validate.py - LLDP Validation for LLDPq
==========================================

PURPOSE:
    Validates LLDP data and generates a report.
    Maintains backward compatibility with existing scripts.

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""
import os
import re
import subprocess
import yaml

def load_topology_config(config_path="topology_config.yaml"):
    """Load topology configuration to determine which script to use"""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('topology', 'minimal')  # Default to minimal
        except Exception as e:
            print(f"Warning: Could not read topology config: {e}")
            return 'minimal'
    else:
        print("Warning: topology_config.yaml not found, using minimal topology")
        return 'minimal'

def get_topology_script_name(config_path="topology_config.yaml"):
    """Determine which topology script to use based on config"""
    topology_type = load_topology_config(config_path)

    if topology_type == 'full':
        script_name = "generate_topology_full.py"
        print("Using full topology generation")
    else:
        script_name = "generate_topology.py"
        print("Using minimal topology generation")

    return script_name

def parse_lldp_output(filename):
    neighbors = []
    port_status = {}

    with open(filename, 'r') as file:
        content = file.read()

        # Parse LLDP neighbors
        interfaces = re.split(r'-------------------------------------------------------------------------------', content)[1:-1]
        for interface in interfaces:
            data = {}
            interface_match = re.search(r'Interface:\s+(\S+)', interface)
            sys_name_match = re.search(r'SysName:\s+([^\n]+)', interface)

            sys_descr_match = re.search(r'SysDescr:\s+([^\n]+)', interface)
            vendor = sys_descr_match.group(1) if sys_descr_match else ""

            if "Cumulus" in vendor or "Cisco" in vendor or "FortiGate" in vendor:
                # ifname for Cumulus/Cisco, ifalias for FortiGate
                port_id_match = re.search(r'PortID:\s+(?:ifname|ifalias)\s+(\S+)', interface)
            else:
                # For HGX devices, extract just the interface name from "Interface 4 as enp157s0f0np0"
                port_descr_match = re.search(r'PortDescr:\s+(.+)', interface)
                if port_descr_match:
                    port_descr = port_descr_match.group(1).strip()
                    # Extract interface name from patterns like "Interface 4 as enp157s0f0np0"
                    interface_name_match = re.search(r'as\s+(\S+)', port_descr)
                    if interface_name_match:
                        port_id_match = type('Match', (), {'group': lambda self, n: interface_name_match.group(1)})()
                    else:
                        port_id_match = port_descr_match
                else:
                    port_id_match = None
            if interface_match and sys_name_match and port_id_match:
                sys_name = sys_name_match.group(1).strip()
                if not "Cumulus" in interface:
                    sys_name = sys_name.split(".cm.cluster")[0]
                data['interface'] = interface_match.group(1).strip(',')
                data['sys_name'] = sys_name
                data['port_id'] = port_id_match.group(1).strip()
                neighbors.append(data)
            elif interface_match and port_id_match:
                data['interface'] = interface_match.group(1).strip(',')
                data['sys_name'] = "Unknown"
                data['port_id'] = port_id_match.group(1).strip()
                neighbors.append(data)
        port_status_matches = re.findall(r'===PORT_STATUS_START===(.*?)===PORT_STATUS_END===', content, re.DOTALL)
        if port_status_matches:
            port_status_section = port_status_matches[-1]
            port_status_lines = port_status_section.strip().split('\n')
            for line in port_status_lines:
                line = line.strip()
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        port_name = parts[0]
                        status = parts[-1]
                        port_status[port_name] = status

    return neighbors, port_status

def get_device_neighbors(lldp_dir):
    device_neighbors = {}
    device_port_status = {}
    files_in_order = sorted(os.listdir(lldp_dir))
    for filename in files_in_order:
        if filename.endswith("_lldp_result.ini"):
            device_name = filename.replace("_lldp_result.ini", "")
            filepath = os.path.join(lldp_dir, filename)
            neighbors, port_status = parse_lldp_output(filepath)
            device_neighbors[device_name] = neighbors
            device_port_status[device_name] = port_status
    return device_neighbors, device_port_status, files_in_order

def check_connections(topology_file, device_neighbors, device_port_status):
    with open(topology_file, 'r') as file:
        expected_connections = file.readlines()
    results = {}
    valid_devices = device_neighbors.keys()
    # Hostname matching is case-insensitive (DNS-style); interface names stay exact
    valid_devices_lower = {d.lower() for d in valid_devices}
    edge_re = re.compile(r'"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*"([^"]+)"\s*:\s*"([^"]+)"')
    for device, neighbors in device_neighbors.items():
        port_status = device_port_status.get(device, {})
        device_results = []
        in_block_comment = False
        for connection in expected_connections:
            line = connection.strip()
            if not line:
                continue
            if '/*' in line:
                in_block_comment = True
            if in_block_comment:
                if '*/' in line:
                    in_block_comment = False
                continue
            if line.startswith('#') or line.startswith('//') or '--' not in line:
                continue
            # Remove edge attributes such as [color=...]
            line = re.sub(r'\[.*?\]', '', line)
            m = edge_re.search(line)
            if m:
                left, left_interface, right, right_interface = m.groups()
            else:
                # Fallback: unquoted format (Device:Interface -- Device:Interface)
                parts = line.split('--', 1)
                if len(parts) != 2:
                    continue
                lp = parts[0].replace('"', '').strip().split(':', 1)
                rp = parts[1].replace('"', '').strip().split(':', 1)
                if len(lp) != 2 or len(rp) != 2:
                    continue
                left, left_interface = lp[0].strip(), lp[1].strip()
                right, right_interface = rp[0].strip(), rp[1].strip()
            left_is_device = left.lower() == device.lower()
            right_is_device = right.lower() == device.lower()
            if not left_is_device and not right_is_device:
                continue
            expected_interface = left_interface if left_is_device else right_interface
            expected_neighbor_sys_name = right if left_is_device else left
            expected_neighbor_port = right_interface if left_is_device else left_interface
            active_neighbor = next((n for n in neighbors if n['interface'] == expected_interface), None)
            active_neighbor_sys_name = 'None'
            active_neighbor_port = 'None'
            
            # Check if port is DOWN first - this should be considered a Fail
            interface_port_status = port_status.get(expected_interface, 'N/A')
            if interface_port_status == 'DOWN':
                status = 'Fail'
            elif not active_neighbor:
                status = 'No-Info'
            else:
                if expected_neighbor_sys_name == 'None':
                    status = 'Fail'
                    active_neighbor_sys_name = active_neighbor['sys_name']
                    active_neighbor_port = active_neighbor['port_id']
                elif active_neighbor['sys_name'].lower() == expected_neighbor_sys_name.lower() and active_neighbor['port_id'] == expected_neighbor_port:
                    status = 'Pass'
                    active_neighbor_sys_name = active_neighbor['sys_name']
                    active_neighbor_port = active_neighbor['port_id']
                else:
                    status = 'Fail'
                    active_neighbor_sys_name = active_neighbor['sys_name']
                    active_neighbor_port = active_neighbor['port_id']
            if expected_interface == 'eth0' or active_neighbor_port == 'eth0':
                continue
            # Port status was already retrieved above for DOWN check
            device_results.append({
                'Port': expected_interface,
                'interface': expected_interface,
                'Status': status,
                'Exp-Nbr': expected_neighbor_sys_name,
                'Exp-Nbr-Port': expected_neighbor_port,
                'Act-Nbr': active_neighbor_sys_name,
                'Act-Nbr-Port': active_neighbor_port,
                'Port-Status': interface_port_status
            })
        for neighbor in neighbors:
            if neighbor['interface'] == 'eth0' or neighbor['port_id'] == 'eth0':
                continue
            if neighbor['sys_name'].lower() not in valid_devices_lower:
                continue
            if not any(n['interface'] == neighbor['interface'] for n in device_results):
                # Get port status for this interface
                interface_port_status = port_status.get(neighbor['interface'], 'N/A')
                device_results.append({
                    'Port': neighbor['interface'],
                    'interface': neighbor['interface'],
                    'Status': 'Fail',
                    'Exp-Nbr': 'None',
                    'Exp-Nbr-Port': 'None',
                    'Act-Nbr': neighbor['sys_name'],
                    'Act-Nbr-Port': neighbor['port_id'],
                    'Port-Status': interface_port_status
                })
        results[device] = device_results
    return results

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    lldp_results_folder = os.path.join(script_dir, "lldp-results")
    topology_file = os.path.join(script_dir, "topology.dot")
    device_neighbors, device_port_status, files_in_order = get_device_neighbors(lldp_results_folder)
    results = check_connections(topology_file, device_neighbors, device_port_status)
    output_file_path = os.path.join(lldp_results_folder, "lldp_results.ini")
    date_str = subprocess.getoutput("date '+%Y-%m-%d %H-%M-%S'")
    script_name = get_topology_script_name()
    generate_topology_script = os.path.join(os.path.dirname(__file__), script_name)
    with open(output_file_path, 'w') as output_file:
        output_file.write(f"Created on {date_str}\n\n")
        for filename in files_in_order:
            if filename.endswith("_lldp_result.ini"):
                device = filename.replace("_lldp_result.ini", "")
                if device in results:
                    total_length = 96
                    device_length = len(device)
                    equal_count = (total_length - device_length - 2) // 2
                    equal_str = "=" * equal_count
                    header = f"{equal_str} {device} {equal_str}"
                    if len(header) < total_length:
                        header += "=" * (total_length - len(header))
                    output_file.write(header + "\n\n")
                    output_file.write("--------------------------------------------------------------------------------------------------------------------------\n")
                    output_file.write(f"{'Port':<10} {'Status':<10} {'Exp-Nbr':<28} {'Exp-Nbr-Port':<16} {'Act-Nbr':<28} {'Act-Nbr-Port':<12} {'Port-Status'}\n")
                    output_file.write("--------------------------------------------------------------------------------------------------------------------------\n")
                    for res in results[device]:
                        output_file.write(f"{res['Port']:<10} {res['Status']:<10} {res['Exp-Nbr']:<28} {res['Exp-Nbr-Port']:<16} {res['Act-Nbr']:<28} {res['Act-Nbr-Port']:<12} {res['Port-Status']}\n")
                    output_file.write("\n\n")
    subprocess.run(["sudo", "python3", generate_topology_script], check=True)
    # Clean up raw files
    for filename in files_in_order:
        if filename.endswith("_lldp_result.ini"):
            os.remove(os.path.join(lldp_results_folder, filename))

