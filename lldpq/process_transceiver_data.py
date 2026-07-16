#!/usr/bin/env python3
"""
Process transceiver inventory data collected by monitor.sh

Parses vendor info from ethtool -m (optical-data/) and
FW versions from mlxlink (transceiver-data/) to build
a fabric-wide transceiver inventory.

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import os
import re
import json
import tempfile
from datetime import datetime

import export_artifacts

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n


def parse_optical_vendor_info(filepath):
    """Parse vendor/model info from ethtool -m output (optical-data/*.txt)"""
    modules = {}

    try:
        with open(filepath, 'r') as f:
            content = f.read()

        sections = content.split('--- Interface:')

        for section in sections[1:]:
            lines = section.strip().split('\n')
            if not lines:
                continue

            iface_match = re.match(r'(\w+)', lines[0].strip())
            if not iface_match:
                continue

            iface = iface_match.group(1)
            data = '\n'.join(lines[1:])

            identifier = ''
            vendor = ''
            part_number = ''
            serial = ''
            vendor_rev = ''
            connector = ''

            for line in lines[1:]:
                line = line.strip()
                if line.startswith('Identifier'):
                    m = re.search(r'\((.+?)\)', line)
                    if m:
                        identifier = m.group(1).split()[0]
                    elif ':' in line:
                        identifier = line.split(':', 1)[1].strip()
                elif line.startswith('Vendor name'):
                    vendor = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line.startswith('Vendor PN'):
                    part_number = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line.startswith('Vendor SN') or line.startswith('Vendor Serial'):
                    serial = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line.startswith('Vendor rev'):
                    vendor_rev = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line.startswith('Connector'):
                    m = re.search(r'\((.+?)\)', line)
                    if m:
                        connector = m.group(1)

            if vendor or part_number:
                modules[iface] = {
                    'identifier': identifier,
                    'vendor': vendor,
                    'part_number': part_number,
                    'serial': serial,
                    'vendor_rev': vendor_rev,
                    'connector': connector
                }

    except Exception as e:
        pass

    return modules


def parse_transceiver_fw(filepath):
    """Parse mlxlink output (transceiver-data/*.txt).

    Returns: (fw_versions dict, cable_byte130 dict, status string, status detail string)
        status: 'ok', 'skipped_model', 'skipped_unknown', 'no_data',
                'failed', 'unreachable' (no file)
    """
    fw_versions = {}
    cable_byte130 = {}
    status = 'ok'
    detail = ''

    if not os.path.exists(filepath):
        return fw_versions, cable_byte130, 'unreachable', ''

    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception:
        return fw_versions, cable_byte130, 'failed', 'read_error'

    lines = content.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith('#'):
            marker = stripped.lstrip('#').strip().lower()
            if marker.startswith('skipped model'):
                status = 'skipped_model'
                detail = stripped.lstrip('#').strip()[len('skipped model'):].strip()
            elif marker.startswith('skipped unknown model'):
                status = 'skipped_unknown'
                detail = ''
            elif marker.startswith('no firmware data'):
                status = 'no_data'
                detail = ''
            elif marker.startswith('failed'):
                status = 'failed'
                detail = stripped.lstrip('#').strip()
            continue

        if '|' in stripped:
            parts = stripped.split('|')
            iface = parts[0].strip()
            for part in parts[1:]:
                part = part.strip()
                fw_match = re.search(r'FW Version\s*:\s*(.+)', part)
                if fw_match:
                    fw_versions[iface] = fw_match.group(1).strip()
                    continue

                byte_match = re.search(
                    r'(?:Cable-Byte130|CABLE_BYTE130|page\[1\]\.Byte\[130\])\s*:\s*(0x[0-9A-Fa-f]+)',
                    part
                )
                if byte_match:
                    cable_byte130[iface] = byte_match.group(1).strip()

    if fw_versions or cable_byte130:
        status = 'ok'

    return fw_versions, cable_byte130, status, detail


def process_transceiver_data(optical_dir='monitor-results/optical-data',
                              transceiver_dir='monitor-results/transceiver-data',
                              output_dir='monitor-results'):
    """Build transceiver inventory from optical + mlxlink data"""

    all_modules = []

    for filename in sorted(os.listdir(optical_dir)):
        if not filename.endswith('_optical.txt'):
            continue

        hostname = filename.replace('_optical.txt', '')
        optical_path = os.path.join(optical_dir, filename)
        transceiver_path = os.path.join(transceiver_dir, f'{hostname}_transceiver.txt')

        vendor_info = parse_optical_vendor_info(optical_path)
        fw_info, cable_byte130_info, fw_status, fw_detail = parse_transceiver_fw(transceiver_path)

        for iface, info in vendor_info.items():
            port_num_match = re.match(r'swp(\d+)', iface)
            port_num = port_num_match.group(1) if port_num_match else iface.replace('swp', '')
            fw = fw_info.get(iface, '')
            if not fw:
                for fw_iface, fw_val in fw_info.items():
                    fw_port = re.match(r'swp(\d+)', fw_iface)
                    if fw_port and fw_port.group(1) == port_num:
                        fw = fw_val
                        break

            cable_byte130 = cable_byte130_info.get(iface, '')
            if not cable_byte130:
                for byte_iface, byte_val in cable_byte130_info.items():
                    byte_port = re.match(r'swp(\d+)', byte_iface)
                    if byte_port and byte_port.group(1) == port_num:
                        cable_byte130 = byte_val
                        break

            module_status = 'ok'
            module_detail = ''
            if not fw:
                if fw_status in ('skipped_model', 'skipped_unknown', 'no_data', 'failed', 'unreachable'):
                    module_status = fw_status
                    module_detail = fw_detail

            all_modules.append({
                'device': hostname,
                'port': iface,
                'identifier': info['identifier'],
                'vendor': info['vendor'],
                'part_number': info['part_number'],
                'serial': info['serial'],
                'vendor_rev': info['vendor_rev'],
                'connector': info.get('connector', ''),
                'fw_version': fw,
                'cable_byte130': cable_byte130,
                'fw_status': module_status,
                'fw_status_detail': module_detail
            })

    # Build summary
    unique_models = set()
    devices_with_modules = set()
    fw_by_model = {}
    status_counts = {}

    for m in all_modules:
        pn = m['part_number']
        if pn:
            unique_models.add(pn)
            devices_with_modules.add(m['device'])
            if m['fw_version']:
                fw = m['fw_version']
                if pn not in fw_by_model:
                    fw_by_model[pn] = {}
                fw_by_model[pn][fw] = fw_by_model[pn].get(fw, 0) + 1
        st = m.get('fw_status', 'ok')
        status_counts[st] = status_counts.get(st, 0) + 1

    mixed_fw_models = [pn for pn, versions in fw_by_model.items() if len(versions) > 1]

    result = {
        'last_update': datetime.now().isoformat(),
        'modules': all_modules,
        'summary': {
            'total_modules': len(all_modules),
            'unique_models': len(unique_models),
            'devices_with_modules': len(devices_with_modules),
            'fw_versions': fw_by_model,
            'mixed_fw_models': mixed_fw_models,
            'status_counts': status_counts
        }
    }

    output_path = os.path.join(output_dir, 'transceiver_inventory.json')
    # Publish via tmp+fsync+rename so readers never observe partial JSON
    fd, tmp_path = tempfile.mkstemp(
        prefix='.transceiver_inventory.json.', dir=output_dir)
    try:
        mode = (os.stat(output_path).st_mode & 0o7777) if os.path.exists(output_path) else 0o664
        # Web-served output: nginx must always retain read access.
        os.fchmod(fd, mode | 0o644)
        with os.fdopen(fd, 'w') as f:
            json.dump(result, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, output_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # Public machine-readable export, published to the web tree by
    # collect-transceiver-fw.sh alongside the inventory it derives from.
    export_rows = [dict(m, device=canonical(m['device'])) for m in all_modules]
    export_artifacts.write_export(
        output_dir, 'transceiver', export_rows, result['summary'], None,
        subdir=None, basename='transceiver-export')

    print(f"Transceiver inventory: {len(all_modules)} modules across "
          f"{len(devices_with_modules)} devices, {len(unique_models)} unique models"
          f"{f', {len(mixed_fw_models)} with mixed FW' if mixed_fw_models else ''}")


if __name__ == '__main__':
    process_transceiver_data()
