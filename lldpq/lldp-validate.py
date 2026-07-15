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
import json
import os
import re
import stat
import shutil
import subprocess
import sys
import tempfile
import yaml

try:
    from topology_edges import (
        DeviceNameResolver,
        LLDPNeighbor,
        TopologyEdge,
        is_eth0,
        iter_lldp_neighbors,
        parse_topology_file,
        port_key,
    )
except ImportError:  # Source-tree imports used by unit tests.
    from lldpq.topology_edges import (
        DeviceNameResolver,
        LLDPNeighbor,
        TopologyEdge,
        is_eth0,
        iter_lldp_neighbors,
        parse_topology_file,
        port_key,
    )

try:
    from parse_devices import get_all_devices, load_devices_yaml
except ImportError:  # Source-tree imports used by unit tests.
    from lldpq.parse_devices import get_all_devices, load_devices_yaml

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


def load_managed_device_names(devices_yaml_path):
    """Return only collection-required ``devices:``, never endpoint_hosts."""
    try:
        config = load_devices_yaml(devices_yaml_path)
        return [hostname for _address, _user, hostname, _role in get_all_devices(config)]
    except SystemExit as exc:
        raise RuntimeError('Could not load managed devices.yaml inventory') from exc


def snapshot_topology(source_path, destination_directory):
    """Take one immutable run-local topology snapshot for report and graph output."""
    descriptor, snapshot_path = tempfile.mkstemp(
        prefix='.topology.snapshot.', suffix='.dot', dir=destination_directory
    )
    try:
        with os.fdopen(descriptor, 'wb') as target, open(source_path, 'rb') as source:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        return snapshot_path
    except Exception:
        try:
            os.unlink(snapshot_path)
        except FileNotFoundError:
            pass
        raise

def parse_lldp_output(filename, known_device_names=()):
    neighbors = []
    port_status = {}

    resolver = DeviceNameResolver(known_device_names)
    with open(filename, 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()

        # The topology view and wiring validator share this exact TLV parser and
        # hostname/interface normalization contract.
        for neighbor in iter_lldp_neighbors(
                content, resolver=resolver, known_device_names=known_device_names):
            neighbors.append({
                'interface': neighbor.local_port,
                'sys_name': neighbor.device or 'Unknown',
                'port_id': neighbor.remote_port or 'Unknown',
            })
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
                        status = parts[-1].upper()
                        # Device output is untrusted; anything outside the
                        # report contract would break the strict aggregate
                        # parser in the browser for every user.
                        if status not in ('UP', 'DOWN', 'UNKNOWN', 'N/A'):
                            status = 'UNKNOWN'
                        port_status[port_name] = status

    return neighbors, port_status

def get_device_neighbors(lldp_dir, known_device_names=()):
    device_neighbors = {}
    device_port_status = {}
    files_in_order = sorted(os.listdir(lldp_dir))
    for filename in files_in_order:
        if filename.endswith("_lldp_result.ini"):
            device_name = filename.replace("_lldp_result.ini", "")
            filepath = os.path.join(lldp_dir, filename)
            neighbors, port_status = parse_lldp_output(filepath, known_device_names)
            device_neighbors[device_name] = neighbors
            device_port_status[device_name] = port_status
    return device_neighbors, device_port_status, files_in_order

def _neighbor_sort_key(neighbor, resolver):
    return (
        resolver.key(neighbor.device),
        port_key(neighbor.remote_port),
        neighbor.device or '',
        neighbor.remote_port or '',
    )


def _group_neighbors(neighbors, resolver):
    grouped = {}
    seen = set()
    for raw in neighbors:
        neighbor = LLDPNeighbor(
            local_port=str(raw.get('interface') or '').strip(', '),
            device=resolver.canonical(
                str(raw.get('sys_name') or 'Unknown').strip()
            ),
            remote_port=str(raw.get('port_id') or 'Unknown').strip(),
        )
        if not neighbor.local_port:
            continue
        identity = (
            neighbor.local_port,
            resolver.key(neighbor.device),
            port_key(neighbor.remote_port),
        )
        if identity in seen:
            continue
        seen.add(identity)
        grouped.setdefault(neighbor.local_port, []).append(neighbor)
    for candidates in grouped.values():
        candidates.sort(key=lambda item: _neighbor_sort_key(item, resolver))
    return grouped


def write_neighbors_sidecar(destination_path, device_neighbors, resolver, created_at):
    """Serialize every observed LLDP neighbor for display enrichment.

    The wiring aggregate intentionally omits ports whose neighbor is an
    unmanaged endpoint host, so analysis pages (BER neighbor columns) consume
    this sidecar instead.  Best-effort artifact: it is not part of the
    rollback-capable wiring report transaction.
    """
    neighbors = {}
    for device in sorted(device_neighbors, key=str.casefold):
        grouped = _group_neighbors(device_neighbors[device], resolver)
        ports = {}
        for local_port in sorted(grouped, key=port_key):
            chosen = next(
                (candidate for candidate in grouped[local_port]
                 if candidate.device and candidate.device != 'Unknown'
                 and candidate.remote_port and candidate.remote_port != 'Unknown'),
                None,
            )
            if chosen is not None:
                ports[local_port] = {
                    'device': chosen.device,
                    'port': chosen.remote_port,
                }
        if ports:
            neighbors[device] = ports
    payload = {'version': 1, 'created': created_at, 'neighbors': neighbors}
    directory = os.path.dirname(os.path.abspath(destination_path))
    descriptor, temporary_path = tempfile.mkstemp(
        prefix='.lldp_neighbors.json.', dir=directory
    )
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            # Analysis cron jobs and the web service read this without going
            # through the publisher's chmod, so keep the readable floor here.
            os.fchmod(handle.fileno(), 0o644)
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination_path)
    except Exception:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
        raise


def check_connections(
        topology_file_or_edges, device_neighbors, device_port_status,
        managed_devices=None, resolver=None):
    """Compare normalized LLDP observations with one semantic topology.

    Results remain port-oriented for backward compatibility.  A managed device
    with no collection still receives explicit No-Info rows, while
    unmanaged endpoint hosts never get synthetic local rows.
    """
    if isinstance(topology_file_or_edges, (str, os.PathLike)):
        edges = parse_topology_file(os.fspath(topology_file_or_edges))
    else:
        edges = list(topology_file_or_edges)
        if any(not isinstance(edge, TopologyEdge) for edge in edges):
            raise TypeError('topology edges must be TopologyEdge instances')

    if managed_devices is None:
        managed_devices = list(device_neighbors)
    else:
        managed_devices = list(managed_devices)
    known_names = list(managed_devices) + list(device_neighbors)
    known_names.extend(
        name for edge in edges for name in (edge.left_device, edge.right_device)
    )
    resolver = resolver or DeviceNameResolver(known_names)
    managed_device_keys = {
        resolver.key(name) for name in managed_devices
    } - {''}

    collected_by_key = {}
    for collected_name in device_neighbors:
        key = resolver.key(collected_name)
        if key in collected_by_key and collected_by_key[key] != collected_name:
            raise ValueError(
                'Multiple LLDP collection files resolve to the same device: '
                f'{collected_by_key[key]} and {collected_name}'
            )
        collected_by_key[key] = collected_name

    ordered_devices = []
    ordered_keys = set()
    for name in managed_devices:
        key = resolver.key(name)
        if key and key not in ordered_keys:
            ordered_devices.append((resolver.canonical(name), key))
            ordered_keys.add(key)
    # Preserve compatibility for direct callers with collection inputs that are
    # not represented in devices.yaml.
    for name in device_neighbors:
        key = resolver.key(name)
        if key and key not in ordered_keys:
            ordered_devices.append((resolver.canonical(name), key))
            ordered_keys.add(key)

    results = {}
    for device, device_key in ordered_devices:
        collected_name = collected_by_key.get(device_key)
        collection_available = collected_name is not None
        raw_neighbors = device_neighbors.get(collected_name, []) if collected_name else []
        port_status = device_port_status.get(collected_name, {}) if collected_name else {}
        neighbors_by_port = _group_neighbors(raw_neighbors, resolver)
        device_results = []
        expected_local_ports = set()

        for edge in edges:
            if resolver.key(edge.left_device) == device_key:
                expected_interface = edge.left_port
                expected_neighbor_sys_name = edge.right_device
                expected_neighbor_port = edge.right_port
            elif resolver.key(edge.right_device) == device_key:
                expected_interface = edge.right_port
                expected_neighbor_sys_name = edge.left_device
                expected_neighbor_port = edge.left_port
            else:
                continue

            # Management links are deliberately excluded as a whole, whether
            # present or absent, so row counts cannot change when LLDP appears.
            if is_eth0(expected_interface) or is_eth0(expected_neighbor_port):
                continue
            expected_local_ports.add(expected_interface)
            candidates = [
                candidate for candidate in neighbors_by_port.get(expected_interface, [])
                if not is_eth0(candidate.remote_port)
            ]
            interface_port_status = str(
                port_status.get(
                    expected_interface,
                    'N/A',
                )
            ).upper()
            active_neighbor = None
            reason = ''

            if interface_port_status == 'DOWN':
                status = 'Fail'
                reason = 'Local port is down'
            elif not collection_available:
                status = 'No-Info'
                reason = 'Managed device collection unavailable'
            elif not candidates:
                status = 'No-Info'
                reason = 'No LLDP neighbor on expected port'
            else:
                exact = [
                    candidate for candidate in candidates
                    if resolver.key(candidate.device) == resolver.key(expected_neighbor_sys_name)
                    and port_key(candidate.remote_port) == port_key(expected_neighbor_port)
                ]
                if exact:
                    active_neighbor = exact[0]
                    status = 'Pass'
                    reason = 'Expected LLDP neighbor selected'
                else:
                    active_neighbor = candidates[0]
                    status = 'Fail'
                    reason = (
                        'Ambiguous LLDP neighbors on local port'
                        if len(candidates) > 1 else 'LLDP neighbor mismatch'
                    )

            device_results.append({
                'Port': expected_interface,
                'interface': expected_interface,
                'Status': status,
                'Exp-Nbr': expected_neighbor_sys_name,
                'Exp-Nbr-Port': expected_neighbor_port,
                'Act-Nbr': active_neighbor.device if active_neighbor else 'None',
                'Act-Nbr-Port': active_neighbor.remote_port if active_neighbor else 'None',
                'Port-Status': interface_port_status,
                'Reason': reason,
            })

        # An otherwise-unconfigured local port is a wiring warning only when it
        # reaches another managed device.  External endpoints commonly advertise
        # LLDP on server-facing ports without being part of the managed fabric;
        # they must not inflate wiring failures.  Configured topology ports are
        # handled above, so an explicitly modeled endpoint (or a wrong endpoint
        # on a modeled port) still receives the normal exact-match validation.
        for local_port in sorted(neighbors_by_port):
            if local_port in expected_local_ports or is_eth0(local_port):
                continue
            candidates = [
                candidate for candidate in neighbors_by_port[local_port]
                if not is_eth0(candidate.remote_port)
                and resolver.key(candidate.device) in managed_device_keys
            ]
            if not candidates:
                continue
            active_neighbor = candidates[0]
            device_results.append({
                'Port': local_port,
                'interface': local_port,
                'Status': 'Fail',
                'Exp-Nbr': 'None',
                'Exp-Nbr-Port': 'None',
                'Act-Nbr': active_neighbor.device or 'Unknown',
                'Act-Nbr-Port': active_neighbor.remote_port or 'Unknown',
                'Port-Status': str(port_status.get(local_port, 'N/A')).upper(),
                'Reason': (
                    'Ambiguous unexpected LLDP neighbors'
                    if len(candidates) > 1 else 'Unexpected LLDP neighbor'
                ),
            })
        results[device] = device_results
    return results


def write_results_report(output_file, results, created_at):
    """Serialize the backward-compatible aggregate consumed by LLDPq pages."""
    output_file.write(f"Created on {created_at}\n\n")
    for device in sorted(results, key=str.casefold):
        total_length = 96
        device_length = len(device)
        # The strict aggregate parser requires visible '=' delimiters even for
        # the longest hostname accepted by devices.yaml.
        equal_count = max(3, (total_length - device_length - 2) // 2)
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

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    lldp_results_folder = os.path.join(script_dir, "lldp-results")
    input_folder = os.environ.get("LLDPQ_LLDP_INPUT_DIR", lldp_results_folder)
    input_folder = os.path.realpath(input_folder)
    if os.path.commonpath((input_folder, os.path.realpath(lldp_results_folder))) != \
            os.path.realpath(lldp_results_folder):
        print("Error validating LLDP data: input directory is outside lldp-results")
        return 1
    topology_file = os.path.join(script_dir, "topology.dot")
    output_file_path = os.path.join(lldp_results_folder, "lldp_results.ini")
    temp_output_path = None
    topology_snapshot_path = None
    previous_output_path = None
    new_output_active = False
    stage_only = os.environ.get("LLDPQ_LLDP_STAGE_ONLY") == "1"

    try:
        managed_devices = load_managed_device_names(
            os.path.join(script_dir, 'devices.yaml')
        )
        topology_snapshot_path = snapshot_topology(topology_file, input_folder)
        topology_edges = parse_topology_file(topology_snapshot_path)
        known_device_names = list(managed_devices)
        known_device_names.extend(
            name for edge in topology_edges
            for name in (edge.left_device, edge.right_device)
        )
        resolver = DeviceNameResolver(known_device_names)
        device_neighbors, device_port_status, _files_in_order = get_device_neighbors(
            input_folder, known_device_names
        )
        results = check_connections(
            topology_edges,
            device_neighbors,
            device_port_status,
            managed_devices=managed_devices,
            resolver=resolver,
        )
        date_str = subprocess.getoutput("date '+%Y-%m-%d %H-%M-%S'")
        script_name = get_topology_script_name(
            os.path.join(script_dir, 'topology_config.yaml')
        )
        generate_topology_script = os.path.join(os.path.dirname(__file__), script_name)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=lldp_results_folder,
            prefix=".lldp_results.ini.",
            delete=False,
        ) as output_file:
            temp_output_path = output_file.name
            try:
                report_mode = stat.S_IMODE(os.stat(output_file_path).st_mode)
            except FileNotFoundError:
                report_mode = 0o664
            # Web-served output: nginx must always retain read access.
            os.fchmod(output_file.fileno(), report_mode | 0o644)
            write_results_report(output_file, results, date_str)
            output_file.flush()
            os.fsync(output_file.fileno())

        if stage_only:
            # check-lldp.sh owns the final multi-file commit.  Keep both the
            # aggregate and topology in its private collection tree so any
            # post-processing/publication failure leaves every LKG destination
            # untouched.
            staged_report = os.path.join(input_folder, "lldp_results.ini")
            staged_topology = os.path.join(input_folder, "topology.js")
            os.replace(temp_output_path, staged_report)
            temp_output_path = None
            try:
                write_neighbors_sidecar(
                    os.path.join(input_folder, "lldp_neighbors.json"),
                    device_neighbors, resolver, date_str,
                )
            except Exception as sidecar_exc:
                print(f"Warning: could not stage LLDP neighbor sidecar: {sidecar_exc}")
            subprocess.run(
                [sys.executable, generate_topology_script, input_folder,
                 staged_topology, '--topology-file', topology_snapshot_path],
                check=True,
                cwd=script_dir,
            )
            if not os.path.isfile(staged_topology) or os.path.getsize(staged_topology) == 0:
                raise RuntimeError("topology generator did not create a staged output")
            return 0

        # Compatibility path for direct validator callers: activate the complete
        # local report, retain the previous report, and roll it back if legacy
        # direct topology publication fails.
        if os.path.exists(output_file_path):
            descriptor, previous_output_path = tempfile.mkstemp(
                dir=lldp_results_folder, prefix=".lldp_results.previous."
            )
            os.close(descriptor)
            os.unlink(previous_output_path)
            os.replace(output_file_path, previous_output_path)
        os.replace(temp_output_path, output_file_path)
        temp_output_path = None
        new_output_active = True
        if input_folder != os.path.realpath(lldp_results_folder):
            shutil.copy2(
                output_file_path, os.path.join(input_folder, "lldp_results.ini")
            )
        subprocess.run(
            ["sudo", "python3", generate_topology_script, input_folder,
             '--topology-file', topology_snapshot_path],
            check=True,
            cwd=script_dir,
        )
        if previous_output_path:
            os.unlink(previous_output_path)
            previous_output_path = None
        try:
            write_neighbors_sidecar(
                os.path.join(lldp_results_folder, "lldp_neighbors.json"),
                device_neighbors, resolver, date_str,
            )
        except Exception as sidecar_exc:
            print(f"Warning: could not write LLDP neighbor sidecar: {sidecar_exc}")

        # The caller owns the private collection directory and removes it as a
        # unit.  Do not perform fallible per-file cleanup after both the report
        # and topology have already been published: a cleanup error here would
        # otherwise roll back only lldp_results.ini and leave topology.js from
        # the new run active.
        return 0
    except Exception as exc:
        if previous_output_path and os.path.exists(previous_output_path):
            try:
                if new_output_active and os.path.exists(output_file_path):
                    os.unlink(output_file_path)
                os.replace(previous_output_path, output_file_path)
                previous_output_path = None
            except OSError as restore_exc:
                print(f"CRITICAL: could not restore previous LLDP report: {restore_exc}")
        elif new_output_active and os.path.exists(output_file_path):
            try:
                os.unlink(output_file_path)
            except OSError as cleanup_exc:
                print(f"CRITICAL: could not remove failed LLDP report: {cleanup_exc}")
        print(f"Error validating LLDP data: {exc}")
        return 1
    finally:
        if temp_output_path:
            try:
                os.unlink(temp_output_path)
            except FileNotFoundError:
                pass
        if topology_snapshot_path:
            try:
                os.unlink(topology_snapshot_path)
            except OSError as cleanup_exc:
                # The report/topology transaction has already reached its
                # terminal state.  A best-effort snapshot cleanup must not
                # turn a successful publication into a failed collection.
                print(
                    f"Warning: could not remove topology snapshot: {cleanup_exc}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    sys.exit(main())
