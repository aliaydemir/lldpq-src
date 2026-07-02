#!/usr/bin/env python3
"""
parse_devices.py - YAML to Bash Array Converter for LLDPq
========================================================

PURPOSE:
    Converts devices.yaml to bash associative array format.
    Supports role-based filtering with @role syntax.

USAGE:
    python3 parse_devices.py              # all devices
    python3 parse_devices.py -r spine     # only spine devices
    python3 parse_devices.py --role leaf  # only leaf devices
    python3 parse_devices.py --list-roles # show available roles

OUTPUT:
    Bash associative array declaration that can be sourced.
    Format: declare -A devices=(["IP"]="username hostname")

DEVICE FORMAT:
    Simple:   10.10.100.10: Spine1
    With role: 10.10.100.10: Spine1 @spine
    Extended:  10.10.100.10:
                 hostname: Spine1
                 username: admin
                 role: spine

REQUIREMENTS:
    - Python 3.6+ with PyYAML (pip install pyyaml)
    - devices.yaml in same directory

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import yaml
import sys
import os
import re
import argparse
import json
import shlex

def load_devices_yaml(yaml_file="devices.yaml"):
    """Load and parse devices.yaml configuration"""
    try:
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
        if config is None:
            return {}
        if not isinstance(config, dict):
            print(f"ERROR: {yaml_file} must contain a YAML mapping", file=sys.stderr)
            sys.exit(1)
        return config
    except FileNotFoundError:
        print(f"ERROR: {yaml_file} not found", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"ERROR: Invalid YAML in {yaml_file}: {e}", file=sys.stderr)
        sys.exit(1)

def parse_inline_role(value):
    """Parse 'Hostname @role' format, returns (hostname, role)"""
    if not isinstance(value, str):
        return value, None
    
    # Match: "Hostname @role" or "Hostname"
    match = re.match(r'^(.+?)\s+@([A-Za-z0-9_.-]+)$', value.strip())
    if match:
        return match.group(1).strip(), match.group(2).lower()
    return value.strip(), None

def get_all_devices(config):
    """Parse all devices from config, returns list of (ip, username, hostname, role)"""
    defaults = config.get('defaults', {})
    if not isinstance(defaults, dict):
        print("ERROR: 'defaults' must be a YAML mapping", file=sys.stderr)
        sys.exit(1)
    default_username = defaults.get('username', 'cumulus')
    
    devices = config.get('devices', {})
    if not devices:
        return []
    if not isinstance(devices, dict):
        print("ERROR: 'devices' must be a YAML mapping", file=sys.stderr)
        sys.exit(1)
    
    result = []
    for ip, device_config in devices.items():
        if isinstance(device_config, str):
            # Simple format: IP: hostname or IP: hostname @role
            hostname, role = parse_inline_role(device_config)
            username = default_username
        elif isinstance(device_config, dict):
            # Extended format: IP: {hostname: x, username: y, role: z}
            hostname = device_config.get('hostname', 'unknown')
            username = device_config.get('username', default_username)
            role = device_config.get('role', None)
            if role:
                role = str(role).lower()
        else:
            print(f"WARNING: Invalid device config for {ip}, skipping", file=sys.stderr)
            continue
        
        fields = {
            'address': str(ip),
            'username': str(username),
            'hostname': str(hostname),
            'role': str(role) if role is not None else '',
        }
        invalid_field = next(
            (name for name, value in fields.items()
             if any(char in value for char in ('\x00', '\n', '\r'))),
            None,
        )
        if invalid_field:
            print(
                f"ERROR: Device {fields['address']!r} has unsupported control characters "
                f"in {invalid_field}",
                file=sys.stderr,
            )
            sys.exit(1)

        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:%-]*', fields['address']):
            print(
                f"ERROR: Invalid device address {fields['address']!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        if not re.fullmatch(r'[A-Za-z0-9_.@-]+', fields['username']):
            print(
                f"ERROR: Invalid SSH username for device {fields['address']!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', fields['hostname'])
                or '..' in fields['hostname']):
            print(
                f"ERROR: Invalid hostname for device {fields['address']!r}: "
                f"{fields['hostname']!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        if fields['role'] and not re.fullmatch(r'[A-Za-z0-9_.-]+', fields['role']):
            print(
                f"ERROR: Invalid role for device {fields['address']!r}",
                file=sys.stderr,
            )
            sys.exit(1)

        result.append((
            fields['address'],
            fields['username'],
            fields['hostname'],
            fields['role'] or None,
        ))
    
    return result

def generate_bash_array(devices_list):
    """Convert device list to bash array compatible with bash 3.2+"""
    
    if not devices_list:
        print("ERROR: No devices found", file=sys.stderr)
        sys.exit(1)
    
    device_ips = []
    device_entries = []
    
    for ip, username, hostname, role in devices_list:
        # Keep the legacy shell output for external callers, but quote every
        # YAML-derived value so evaluating this output cannot execute it.
        device_ips.append(shlex.quote(ip))
        device_entries.append(shlex.quote(f"{username} {hostname}"))
    
    # Generate bash arrays (compatible with older bash)
    bash_output = f"""# Device IPs
device_ips=({' '.join(device_ips)})

# Device info (username hostname)
device_info=({' '.join(device_entries)})

# Create associative array compatible function
declare -A devices
for i in "${{!device_ips[@]}}"; do
    devices["${{device_ips[i]}}"]="${{device_info[i]}}"
done"""
    
    return bash_output

def generate_nul_records(devices_list):
    """Write machine-readable NUL-delimited device records to stdout."""
    if not devices_list:
        print("ERROR: No devices found", file=sys.stderr)
        sys.exit(1)

    output = sys.stdout.buffer
    for ip, username, hostname, role in devices_list:
        for value in (ip, username, hostname, role or ''):
            output.write(value.encode('utf-8'))
            output.write(b'\0')

def generate_json_records(devices_list):
    """Write device records as JSON for non-shell consumers."""
    if not devices_list:
        print("ERROR: No devices found", file=sys.stderr)
        sys.exit(1)

    json.dump([
        {
            'address': ip,
            'username': username,
            'hostname': hostname,
            'role': role,
        }
        for ip, username, hostname, role in devices_list
    ], sys.stdout, ensure_ascii=False)
    sys.stdout.write('\n')

def list_roles(devices_list):
    """List all available roles"""
    roles = set()
    for ip, username, hostname, role in devices_list:
        if role:
            roles.add(role)
    
    if roles:
        print("Available roles:")
        for role in sorted(roles):
            count = sum(1 for d in devices_list if d[3] == role)
            print(f"  @{role} ({count} devices)")
    else:
        print("No roles defined. Use '@role' syntax in devices.yaml:")
        print("  10.10.100.10: Spine1 @spine")
        print("  10.10.100.12: Leaf1 @leaf")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Convert devices.yaml to bash array format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 parse_devices.py              # all devices
  python3 parse_devices.py -r spine     # only @spine devices
  python3 parse_devices.py --list-roles # show available roles
'''
    )
    parser.add_argument('-r', '--role', help='Filter devices by role')
    parser.add_argument('-f', '--file', help='Path to custom devices.yaml (overrides default)')
    parser.add_argument('--list-roles', action='store_true', help='List available roles')
    parser.add_argument(
        '--format',
        choices=('bash', 'nul', 'json'),
        default='bash',
        help='Output format (default: bash; internal callers should use nul)',
    )
    args = parser.parse_args()
    
    # Resolve devices.yaml path: -f flag > LLDPQ_DIR/devices.yaml > ~/lldpq/devices.yaml
    if args.file:
        yaml_file = args.file
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_file = os.path.join(script_dir, "devices.yaml")
    
    # Load configuration
    config = load_devices_yaml(yaml_file)
    
    # Get all devices
    all_devices = get_all_devices(config)
    
    if args.list_roles:
        list_roles(all_devices)
        return
    
    # Filter by role if specified
    if args.role:
        role_filter = args.role.lower()
        filtered = [d for d in all_devices if d[3] == role_filter]
        if not filtered:
            print(f"ERROR: No devices found with role '@{args.role}'", file=sys.stderr)
            list_roles(all_devices)
            sys.exit(1)
        all_devices = filtered
    
    if args.format == 'nul':
        generate_nul_records(all_devices)
    elif args.format == 'json':
        generate_json_records(all_devices)
    else:
        # Backward-compatible output for external callers.
        print(generate_bash_array(all_devices))

if __name__ == "__main__":
    main()
