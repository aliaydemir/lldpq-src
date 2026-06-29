#!/usr/bin/env python3
"""
generate_hardware_html.py - Hardware Analysis for LLDPq
===============================================================

PURPOSE:
    Generates a HTML file from existing hardware data.
    Maintains backward compatibility with existing scripts.

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import json
import os
import re
from datetime import datetime

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

def parse_assets_file(assets_file_path="assets.ini"):
    """Parse assets.ini file to get device model information"""
    device_info = {}
    try:
        with open(assets_file_path, 'r') as file:
            lines = file.readlines()
            print(f"Parsing assets.ini with {len(lines)} lines")
            
            header_found = False
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("Created"):
                    continue
                    
                parts = line.split()
                if len(parts) < 5:
                    continue
                    
                device_name = parts[0]
                
                # Skip header line
                if device_name == "DEVICE-NAME":
                    header_found = True
                    print(f"Found header at line {i+1}: {parts}")
                    continue
                    
                if header_found and len(parts) >= 5:
                    model = parts[4] if parts[4] != "No-Info" and parts[4] != "SSH-FAILED" else "N/A"
                    device_info[device_name] = {
                        "ip": parts[1] if len(parts) > 1 else "N/A",
                        "mac": parts[2] if len(parts) > 2 else "N/A", 
                        "serial": parts[3] if len(parts) > 3 else "N/A",
                        "model": model,
                        "release": parts[5] if len(parts) > 5 else "N/A"
                    }
                    
    except FileNotFoundError:
        print(f"❌ assets.ini file not found at {assets_file_path}")
    except Exception as e:
        print(f"❌ Error parsing assets.ini: {e}")
        
    return device_info

def parse_temperature_from_hardware_file(device_name):
    """Parse CPU and ASIC temperatures from raw hardware file"""
    
    cpu_temp = None
    asic_temp = None
    
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    
    if not os.path.exists(hardware_file):
        return cpu_temp, asic_temp
    
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()
        
        # Parse ASIC temperature: try fast Linux/hw-management sources first.
        asic_mgmt = re.search(r'^HW_MGMT_ASIC:\s*([0-9]+\.?[0-9]*)', content, re.MULTILINE)
        if asic_mgmt:
            asic_temp = float(asic_mgmt.group(1))
        else:
            asic_match = re.search(r'Ambient ASIC Temp:\s*\+?(-?\d+\.?\d*)[°C]', content)
            if asic_match:
                asic_temp = float(asic_match.group(1))
            else:
                thermal_zone_asic = re.search(r'^THERMAL_ZONE_ASIC:\s*([0-9]+\.?[0-9]*)', content, re.MULTILINE)
                if thermal_zone_asic:
                    asic_temp = float(thermal_zone_asic.group(1))
                else:
                    hwmon_asic = re.search(r'^HWMON_ASIC:\s*([0-9]+\.?[0-9]*)', content, re.MULTILINE)
                    if hwmon_asic:
                        asic_temp = float(hwmon_asic.group(1))
                    else:
                        # Passive support for already-collected NVUE output; monitor.sh does not run nv.
                        nvue_asic = re.search(
                            r'^\s*Asic-Temp-Sensor\s+(-?\d+\.?\d*)\s+',
                            content,
                            re.MULTILINE | re.IGNORECASE,
                        )
                        if nvue_asic:
                            asic_temp = float(nvue_asic.group(1))
        
        # Parse CPU temperature: prefer real CPU sensors and avoid unrelated ones (e.g., drivetemp)
        # Pattern 1: Average of CPU cores "Core 0:        +40.0°C"
        core_matches = re.findall(r'Core \d+:\s*\+?(-?\d+\.?\d*)[°C]', content)
        if core_matches:
            core_temps = [float(temp) for temp in core_matches]
            cpu_temp = sum(core_temps) / len(core_temps)
        else:
            # Pattern 2: CPU package temperature
            package_match = re.search(r'Package id \d+:\s*\+?(-?\d+\.?\d*)[°C]', content)
            if package_match:
                cpu_temp = float(package_match.group(1))
            else:
                # Pattern 3: "CPU ACPI temp:  +27.8°C"
                cpu_acpi_matches = re.findall(r'CPU ACPI temp:\s*\+?(-?\d+\.?\d*)[°C]', content)
                if cpu_acpi_matches:
                    cpu_temp = float(cpu_acpi_matches[0])
                else:
                    # Pattern 4: HW_MGMT_CPU injected by monitor.sh
                    cpu_mgmt = re.search(r'^HW_MGMT_CPU:\s*([0-9]+\.?[0-9]*)', content, re.MULTILINE)
                    if cpu_mgmt:
                        cpu_temp = float(cpu_mgmt.group(1))
                    else:
                        # Passive support for already-collected NVUE output; monitor.sh does not run nv.
                        nvue_core_matches = re.findall(
                            r'^\s*CPU-Core-Sensor-\d+\s+(-?\d+\.?\d*)\s+',
                            content,
                            re.MULTILINE | re.IGNORECASE,
                        )
                        if nvue_core_matches:
                            core_temps = [float(temp) for temp in nvue_core_matches]
                            cpu_temp = sum(core_temps) / len(core_temps)
                        else:
                            package_match = re.search(
                                r'^\s*CPU-Package-Sensor\s+(-?\d+\.?\d*)\s+',
                                content,
                                re.MULTILINE | re.IGNORECASE,
                            )
                            if package_match:
                                cpu_temp = float(package_match.group(1))
                # Intentionally not falling back to generic "temp1" to avoid picking up disks/PSU sensors
        
    except Exception as e:
        print(f"Warning: Could not parse temperatures for {device_name}: {e}")
    
    return cpu_temp, asic_temp

def parse_psu_efficiency_from_hardware_file(device_name):
    """Parse PSU efficiency from raw hardware file"""
    
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    
    if not os.path.exists(hardware_file):
        return None
    
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()
        # 1) Preferred: use PSU AC-in and DC-out rails only (avoids double counting) - supports kW/W
        psu_ac_in_w = re.findall(r'^PSU-[^\n]*220V\s+Rail\s+Pwr\s*\(in\):\s*(\d+\.?\d*)\s*([km]?W)', content, re.MULTILINE)
        # Support both 54V (most switches) and 12V (some platforms)
        psu_dc_out_w = re.findall(r'^PSU-[^\n]*(?:54V|12V)\s+Rail\s+Pwr\s*\(out\):\s*(\d+\.?\d*)\s*([km]?W)', content, re.MULTILINE)

        # Convert kW to W, handle both W and kW units
        total_psu_in = 0.0
        for value, unit in psu_ac_in_w:
            watts = float(value)
            if unit == 'kW':
                watts *= 1000
            total_psu_in += watts
            
        total_psu_out = 0.0  
        for value, unit in psu_dc_out_w:
            watts = float(value)
            if unit == 'kW':
                watts *= 1000
            total_psu_out += watts

        if total_psu_in > 0 and total_psu_out > 0:
            efficiency = (total_psu_out / total_psu_in) * 100.0
            return min(efficiency, 100.0)

        # 2) Fallback (legacy): aggregate PMIC/VR in/out if PSU rails are unavailable
        total_input_power = 0.0
        total_output_power = 0.0

        # PMIC/VR input formats (include (in) and (pin))
        input_matches_w = re.findall(r'PMIC-\d+.*\(in\):\s*(\d+\.?\d*)\s*W', content)
        input_matches_mw = re.findall(r'PMIC-\d+.*\(in\):\s*(\d+\.?\d*)\s*mW', content)
        input_matches_pin_w = re.findall(r'PMIC-\d+.*Pwr\s*\(pin\):\s*(\d+\.?\d*)\s*W', content)
        vr_input_matches_w = re.findall(r'VR IC.*pwr\s*\(in\):\s*(\d+\.?\d*)\s*W', content)
        # PMIC/VR output formats (include Rail Pwr (out) and Pwr (poutX))
        output_matches_w = re.findall(r'PMIC-\d+.*Pwr \(out\d*\):\s*(\d+\.?\d*)\s*W', content)
        output_matches_mw = re.findall(r'PMIC-\d+.*Pwr \(out\d*\):\s*(\d+\.?\d*)\s*mW', content)
        output_matches_pout_w = re.findall(r'PMIC-\d+.*Pwr\s*\(pout\d*\):\s*(\d+\.?\d*)\s*W', content)
        vr_output_matches_w = re.findall(r'^(?!PMIC-).*(?:VR|VCORE).*Rail Pwr\s*\(out\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)
        # As a last resort include generic PSU Pwr(in/out) (non-rail) if present
        psu_input_general_w = re.findall(r'^PSU-[^\n]*Pwr\s*\(in\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)
        psu_output_general_w = re.findall(r'^PSU-[^\n]*Pwr\s*\(out\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)

        for power_str in input_matches_w:
            total_input_power += float(power_str)
        for power_str in input_matches_mw:
            total_input_power += float(power_str) / 1000.0
        for power_str in input_matches_pin_w:
            total_input_power += float(power_str)
        for power_str in vr_input_matches_w:
            total_input_power += float(power_str)
        for power_str in psu_input_general_w:
            total_input_power += float(power_str)

        for power_str in output_matches_w:
            total_output_power += float(power_str)
        for power_str in output_matches_mw:
            total_output_power += float(power_str) / 1000.0
        for power_str in output_matches_pout_w:
            total_output_power += float(power_str)
        for power_str in vr_output_matches_w:
            total_output_power += float(power_str)
        for power_str in psu_output_general_w:
            total_output_power += float(power_str)

        if total_input_power > 0 and total_output_power > 0:
            efficiency = (total_output_power / total_input_power) * 100.0
            return min(efficiency, 100.0)
        
    except Exception as e:
        print(f"Warning: Could not parse PSU efficiency for {device_name}: {e}")
    
    return None

def parse_psu_power_in_out_from_hardware_file(device_name):
    """Return (total_input_watts, total_output_watts) for a device.

    Preferred sources:
      - PSU 220V Rail Pwr (in)
      - PSU 54V/12V Rail Pwr (out)
    Fallback when rails are absent:
      - PMIC/VR pin/pout and in/out aggregates
      - Generic PSU Pwr(in/out)
    """
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    if not os.path.exists(hardware_file):
        return None, None
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()

        # Enhanced PSU rails - support both W and kW units
        psu_ac_in_w = re.findall(r'^PSU-[^\n]*220V\s+Rail\s+Pwr\s*\(in\):\s*(\d+\.?\d*)\s*([km]?W)', content, re.MULTILINE)
        psu_dc_out_w = re.findall(r'^PSU-[^\n]*(?:54V|12V)\s+Rail\s+Pwr\s*\(out\):\s*(\d+\.?\d*)\s*([km]?W)', content, re.MULTILINE)

        # Convert kW to W, handle both W and kW units
        total_psu_in = 0.0
        for value, unit in psu_ac_in_w:
            watts = float(value)
            if unit == 'kW':
                watts *= 1000
            total_psu_in += watts
            
        total_psu_out = 0.0  
        for value, unit in psu_dc_out_w:
            watts = float(value)
            if unit == 'kW':
                watts *= 1000
            total_psu_out += watts


        if total_psu_in > 0 and total_psu_out > 0:
            # Sanity check: Output should never be higher than input (physics!)
            if total_psu_out > total_psu_in:
                print(f"⚠️  {device_name}: PSU output ({total_psu_out}W) > input ({total_psu_in}W) - IMPOSSIBLE!")
                return total_psu_in, total_psu_out  # Still return for debugging
            return total_psu_in, total_psu_out

        # Fallback: PMIC/VR and generic PSU Pwr(in/out)
        total_input_power = 0.0
        total_output_power = 0.0

        input_matches_w = re.findall(r'PMIC-\d+.*\(in\):\s*(\d+\.?\d*)\s*W', content)
        input_matches_mw = re.findall(r'PMIC-\d+.*\(in\):\s*(\d+\.?\d*)\s*mW', content)
        input_matches_pin_w = re.findall(r'PMIC-\d+.*Pwr\s*\(pin\):\s*(\d+\.?\d*)\s*W', content)
        vr_input_matches_w = re.findall(r'VR IC.*pwr\s*\(in\):\s*(\d+\.?\d*)\s*W', content)
        output_matches_w = re.findall(r'PMIC-\d+.*Pwr \(out\d*\):\s*(\d+\.?\d*)\s*W', content)
        output_matches_mw = re.findall(r'PMIC-\d+.*Pwr \(out\d*\):\s*(\d+\.?\d*)\s*mW', content)
        output_matches_pout_w = re.findall(r'PMIC-\d+.*Pwr\s*\(pout\d*\):\s*(\d+\.?\d*)\s*W', content)
        vr_output_matches_w = re.findall(r'^(?!PMIC-).*(?:VR|VCORE).*Rail Pwr\s*\(out\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)
        psu_input_general_w = re.findall(r'^PSU-[^\n]*Pwr\s*\(in\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)
        psu_output_general_w = re.findall(r'^PSU-[^\n]*Pwr\s*\(out\):\s*(\d+\.?\d*)\s*W', content, re.MULTILINE)

        for s in input_matches_w:
            total_input_power += float(s)
        for s in input_matches_mw:
            total_input_power += float(s) / 1000.0
        for s in input_matches_pin_w:
            total_input_power += float(s)
        for s in vr_input_matches_w:
            total_input_power += float(s)
        for s in psu_input_general_w:
            total_input_power += float(s)

        for s in output_matches_w:
            total_output_power += float(s)
        for s in output_matches_mw:
            total_output_power += float(s) / 1000.0
        for s in output_matches_pout_w:
            total_output_power += float(s)
        for s in vr_output_matches_w:
            total_output_power += float(s)
        for s in psu_output_general_w:
            total_output_power += float(s)

        if total_input_power > 0 and total_output_power > 0:
            return total_input_power, total_output_power
        return None, None
    except Exception:
        return None, None

def _parse_size_to_gib(size_str: str) -> float:
    """Convert a size token like '15Gi', '286Mi' into GiB float."""
    try:
        m = re.match(r'(\d+\.?\d*)([KMG]i)', size_str)
        if not m:
            return 0.0
        value = float(m.group(1))
        unit = m.group(2)
        if unit == 'Ki':
            return value / (1024 * 1024)
        if unit == 'Mi':
            return value / 1024
        if unit == 'Gi':
            return value
        if unit == 'Ti':
            return value * 1024
    except Exception:
        return 0.0
    return 0.0

def parse_fans_from_hardware_file(device_name):
    """Parse fan RPMs from the raw hardware file and return a dict {name: rpm}.

    Supports chassis fan tach lines and PSU fan lines, e.g.:
      "Chassis Fan Drawer-1 Tach 1: 9266 RPM"
      "PSU-1(L) Fan 1: 9632 RPM"
    """
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    if not os.path.exists(hardware_file):
        return {}
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()

        fans = {}
        # Generic matcher: any line that has "Fan" and ends with an RPM value
        # Match lines with 'fan' or 'Fan' keywords (case-insensitive)
        for name, rpm in re.findall(r'^(.*?(?:fan)[^:]*?):\s*([0-9]+)\s*RPM', content, re.MULTILINE | re.IGNORECASE):
            clean_name = name.strip()
            try:
                fans[clean_name] = int(rpm)
            except ValueError:
                continue
        return fans
    except Exception as e:
        print(f"Warning: Could not parse fans for {device_name}: {e}")
        return {}

def parse_resources_from_hardware_file(device_name):
    """Parse memory usage percent, 5‑minute CPU load, and uptime string from raw file.

    Returns dict keys possibly including: memory_usage (float), cpu_load (float), uptime (str)
    """
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    results = {}
    if not os.path.exists(hardware_file):
        return results
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()

        # Memory usage from the "Mem:" row
        # Example: Mem: 15Gi 3.9Gi 9.9Gi 286Mi 2.1Gi 11Gi
        mem_line = re.search(r'^Mem:\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)', content, re.MULTILINE)
        if mem_line:
            total_s, used_s, avail_s = mem_line.group(1), mem_line.group(2), mem_line.group(3)
            total_gi = _parse_size_to_gib(total_s)
            avail_gi = _parse_size_to_gib(avail_s)
            if total_gi > 0:
                usage_percent = (1.0 - (avail_gi / total_gi)) * 100.0
                results['memory_usage'] = max(0.0, min(100.0, usage_percent))

        # CPU load 5‑min average from CPU_INFO first line: "1.28 0.68 0.43 ..."
        cpu_line = re.search(r'^CPU_INFO:\n([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+', content, re.MULTILINE)
        if cpu_line:
            results['cpu_load'] = float(cpu_line.group(2))

        # CPU core count, so the load average can be normalized per core. Older
        # collected data (before CPU_CORES existed) simply leaves this unset.
        cores_line = re.search(r'^CPU_CORES:\s*(\d+)', content, re.MULTILINE)
        if cores_line:
            cores = int(cores_line.group(1))
            if cores > 0:
                results['cpu_cores'] = cores

        # Uptime no longer used in table; keep parser but do not require
    except Exception as e:
        print(f"Warning: Could not parse resources for {device_name}: {e}")
    return results

def grade_load_per_core(cpu_load, cpu_cores):
    """Grade the CPU load average normalized by core count.

    Load average is a per-core measure, so an absolute threshold falsely flags
    healthy multi-core switches (e.g. load 3.3 on an 8-core CPU is ~0.4/core).
    When the core count is unknown (data collected before CPU_CORES existed),
    fall back to 4 cores — a conservative minimum for a switch CPU — so we do
    not regress to the old absolute behavior.
    """
    if not isinstance(cpu_load, (int, float)):
        return None
    cores = cpu_cores if isinstance(cpu_cores, int) and cpu_cores > 0 else 4
    load_per_core = cpu_load / cores
    if load_per_core < 0.7:
        return "EXCELLENT"
    elif load_per_core < 1.0:
        return "GOOD"
    elif load_per_core < 1.5:
        return "WARNING"
    else:
        return "CRITICAL"


def calculate_device_health_grade(device_name, device_data):
    """Calculate overall health grade for a device based on our thresholds"""
    health_grades = []
    priority = {"CRITICAL": 4, "WARNING": 3, "GOOD": 2, "EXCELLENT": 1}
    
    # CPU Temperature grade
    cpu_temp, asic_temp = parse_temperature_from_hardware_file(device_name)
    if cpu_temp is not None:
        if cpu_temp < 60:
            health_grades.append("EXCELLENT")
        elif cpu_temp < 70:
            health_grades.append("GOOD")
        elif cpu_temp < 80:
            health_grades.append("WARNING")
        else:
            health_grades.append("CRITICAL")
    
    # ASIC Temperature grade  
    if asic_temp is not None:
        if asic_temp < 85:
            health_grades.append("EXCELLENT")
        elif asic_temp < 105:
            health_grades.append("GOOD")
        elif asic_temp < 115:
            health_grades.append("WARNING")
        else:
            health_grades.append("CRITICAL")
    
    parsed_resources = {}

    # Memory usage grade
    memory_usage = device_data.get("resources", {}).get("memory", {}).get("usage_percent", None)
    if memory_usage is None:
        parsed_resources = parse_resources_from_hardware_file(device_name)
        memory_usage = parsed_resources.get('memory_usage', 0)
    if memory_usage < 60:
        health_grades.append("EXCELLENT")
    elif memory_usage < 75:
        health_grades.append("GOOD")
    elif memory_usage < 85:
        health_grades.append("WARNING")
    else:
        health_grades.append("CRITICAL")
        
    # CPU Load grade
    cpu_load = device_data.get("resources", {}).get("cpu", {}).get("load_5min", None)
    if cpu_load is None:
        if not parsed_resources:
            parsed_resources = parse_resources_from_hardware_file(device_name)
        cpu_load = parsed_resources.get('cpu_load', 0)
    # Normalize the load average by CPU core count (see grade_load_per_core).
    cpu_cores = device_data.get("resources", {}).get("cpu", {}).get("cores", None)
    if not cpu_cores:
        if not parsed_resources:
            parsed_resources = parse_resources_from_hardware_file(device_name)
        cpu_cores = parsed_resources.get('cpu_cores')
    load_grade = grade_load_per_core(cpu_load, cpu_cores)
    if load_grade:
        health_grades.append(load_grade)
    
    # PSU Efficiency grade
    psu_efficiency = parse_psu_efficiency_from_hardware_file(device_name) or 0.0
    if psu_efficiency > 90:
        health_grades.append("EXCELLENT")
    elif psu_efficiency >= 50:
        health_grades.append("GOOD")
    elif psu_efficiency >= 30:
        health_grades.append("WARNING")
    elif psu_efficiency > 0:
        health_grades.append("CRITICAL")
    
    # Fan status grade
    fans = device_data.get("fans", {})
    if not fans:
        fans = parse_fans_from_hardware_file(device_name)
    if fans:
        fan_grades = []
        for fan_name, fan_speed in fans.items():
            if fan_speed > 4000:
                fan_grades.append("EXCELLENT")
            elif fan_speed >= 3000:
                fan_grades.append("GOOD")  
            elif fan_speed >= 1000:
                fan_grades.append("WARNING")
            else:
                fan_grades.append("CRITICAL")
        if fan_grades:
            fan_status = max(fan_grades, key=lambda x: priority.get(x, 0))
            health_grades.append(fan_status)
    
    # Calculate overall health grade (worst case)
    if health_grades:
        return max(health_grades, key=lambda x: priority.get(x, 0))
    else:
        return "UNKNOWN"

def generate_hardware_html():
    """Generate hardware analysis HTML using existing data"""
    
    # Parse assets.ini to get device model information
    assets_data = parse_assets_file("assets.ini")
    print(f"Loaded {len(assets_data)} device models from assets.ini")
    
    # Read existing hardware history (create empty if doesn't exist)
    hardware_history = {}
    try:
        with open("monitor-results/hardware_history.json", "r") as f:
            data = json.load(f)
            hardware_history = data.get("hardware_history", {})
        print("Loaded existing hardware history data")
    except FileNotFoundError:
        print("No hardware_history.json found - creating initial report with current data")
        hardware_history = {}
    except Exception as e:
        print(f"⚠️  Warning: Could not read hardware_history.json: {e}")
        print("Proceeding with empty history data")
        hardware_history = {}
    
    # Get latest data for each device
    latest_devices = {}
    for device_name, history in hardware_history.items():
        if history:  # If device has history entries
            latest_devices[device_name] = history[-1]  # Get the most recent entry
    
    # If no historical data, create basic entries from current hardware files
    if not latest_devices:
        print("No historical data - analyzing current hardware files directly")
        hardware_data_dir = "monitor-results/hardware-data"
        if os.path.exists(hardware_data_dir):
            for filename in os.listdir(hardware_data_dir):
                if filename.endswith('_hardware.txt'):
                    device_name = filename.replace('_hardware.txt', '')
                    # Create basic device entry with minimal data for initial run
                    latest_devices[device_name] = {
                        'device': device_name,
                        'timestamp': datetime.now().isoformat(),
                        'fans': {},  # Will be filled if needed
                        'memory_usage': 'N/A',
                        'cpu_load': 'N/A',
                        'uptime': 'N/A'
                    }
            print(f"Created basic entries for {len(latest_devices)} devices")
    
    # Calculate summary
    summary = {
        'excellent_devices': [],
        'good_devices': [],
        'warning_devices': [],
        'critical_devices': []
    }
    
    # Count devices with current hardware files
    hardware_data_dir = "monitor-results/hardware-data"
    current_device_files = 0
    if os.path.exists(hardware_data_dir):
        current_device_files = len([f for f in os.listdir(hardware_data_dir) if f.endswith('_hardware.txt')])
    
    for device_name, device_data in latest_devices.items():
        # Use our own health calculation instead of JSON's overall_grade
        overall_grade = calculate_device_health_grade(device_name, device_data)
        device_info = {
            'device': device_name,
            'health_grade': overall_grade,
            'data': device_data
        }
        
        if overall_grade == "EXCELLENT":
            summary['excellent_devices'].append(device_info)
        elif overall_grade == "GOOD":
            summary['good_devices'].append(device_info)
        elif overall_grade == "WARNING":
            summary['warning_devices'].append(device_info)
        elif overall_grade == "CRITICAL":
            summary['critical_devices'].append(device_info)
    
    # Use current device files count instead of historical count
    total_devices = current_device_files
    
    # Generate dark theme HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hardware Health Analysis</title>
    <link rel="shortcut icon" href="/png/favicon.ico">
    <link rel="stylesheet" type="text/css" href="/css/select2.min.css">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; min-height: 100vh; }}
        .page-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #404040; }}
        .page-title {{ font-size: 24px; font-weight: 600; color: #76b900; }}
        .last-updated {{ font-size: 13px; color: #888; }}
        .dashboard-section {{ background: #2d2d2d; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 12px 16px; background: #333; font-weight: 600; font-size: 14px; color: #76b900; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #404040; }}
        .section-content {{ padding: 16px; }}
        .section-content-table {{ padding: 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
        .summary-card {{ background: #252526; padding: 15px; border-radius: 6px; border-left: 3px solid #76b900; cursor: pointer; transition: all 0.2s ease; }}
        .summary-card:hover {{ background: #2d2d2d; transform: translateY(-1px); }}
        .summary-card.active {{ background: #333; border-left-width: 5px; }}
        .card-excellent {{ border-left-color: #76b900; }}
        .card-good {{ border-left-color: #8bc34a; }}
        .card-warning {{ border-left-color: #ff9800; }}
        .card-critical {{ border-left-color: #f44336; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .card-excellent .metric {{ color: #76b900; }}
        .card-good .metric {{ color: #8bc34a; }}
        .card-warning .metric {{ color: #ff9800; }}
        .card-critical .metric {{ color: #f44336; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .badge-gray {{ background: rgba(158, 158, 158, 0.2); color: #999; }}
        .hardware-excellent {{ color: #76b900; font-weight: bold; }}
        .hardware-good {{ color: #8bc34a; font-weight: bold; }}
        .hardware-warning {{ color: #ff9800; font-weight: bold; }}
        .hardware-critical {{ color: #f44336; font-weight: bold; }}
        .hardware-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .hardware-table th, .hardware-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; word-wrap: break-word; }}
        .hardware-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .hardware-table tbody tr {{ background: #252526; }}
        .hardware-table tbody tr:hover {{ background: #2d2d2d; }}
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
        .status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-left: 6px; vertical-align: middle; }}
        .status-dot.warning {{ background-color: #ff9800; }}
        .status-dot.critical {{ background-color: #f44336; }}
        .btn {{ padding: 8px 14px; border: none; border-radius: 4px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 6px; }}
        .btn-primary {{ background: linear-gradient(0deg, #76b900 0%, #5a8c00 100%); color: white; }}
        .btn-primary:hover {{ background: linear-gradient(0deg, #8bd400 0%, #6ba000 100%); }}
        .btn-secondary {{ background: linear-gradient(0deg, #4fc3f7 0%, #0288d1 100%); color: white; }}
        .btn-secondary:hover {{ background: linear-gradient(0deg, #81d4fa 0%, #039be5 100%); }}
        .action-buttons {{ display: flex; gap: 10px; align-items: center; }}
        .device-search-container {{ display: flex; align-items: center; gap: 8px; }}
        .device-search-container .select2-container {{ min-width: 200px; }}
        .device-search-container .select2-container--default .select2-selection--single {{ height: 34px; border: 1px solid #555; border-radius: 4px; background: #3c3c3c; display: flex; align-items: center; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered {{ line-height: 34px; color: #d4d4d4; padding-left: 10px; font-size: 13px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow {{ height: 34px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__placeholder {{ color: #888; }}
        .select2-dropdown {{ background: #2d2d2d; border: 1px solid #555; }}
        .select2-container--default .select2-search--dropdown .select2-search__field {{ background: #3c3c3c; border: 1px solid #555; color: #d4d4d4; }}
        .select2-container--default .select2-results__option {{ color: #d4d4d4; padding: 8px 12px; }}
        .select2-container--default .select2-results__option--highlighted[aria-selected] {{ background: #76b900; color: #000; }}
        .select2-container--default .select2-results__option[aria-selected=true] {{ background: #3c3c3c; }}
        .clear-search-btn {{ background: #f44336; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; display: none; }}
        .clear-search-btn:hover {{ background: #d32f2f; }}
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: #1e1e1e; }}
        ::-webkit-scrollbar-thumb {{ background: #404040; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #555; }}
        @keyframes spin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="page-header">
        <div>
            <div class="page-title">Hardware Health Analysis</div>
            <div class="last-updated">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="action-buttons">
            <div class="device-search-container">
                <select id="deviceSearch" style="width: 200px;"><option value="">Search Device...</option></select>
                <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">✕</button>
            </div>
            <button id="thresholds-btn" onclick="openThresholdsModal()" class="btn btn-secondary" title="Thresholds &amp; grading reference">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
                Thresholds
            </button>
            <button id="run-analysis" onclick="runAnalysis()" class="btn btn-secondary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>
                Run Analysis
            </button>
            <button id="download-csv" onclick="downloadCSV()" class="btn btn-primary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>
                Download CSV
            </button>
        </div>
    </div>
    
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            Hardware Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-devices-card">
                    <div class="metric" id="total-devices">{total_devices}</div>
                    <div class="metric-label">Total Devices</div>
                </div>
                <div class="summary-card card-excellent" id="excellent-card">
                    <div class="metric" id="excellent-devices">{len(summary['excellent_devices'])}</div>
                    <div class="metric-label">Excellent</div>
                </div>
                <div class="summary-card card-good" id="good-card">
                    <div class="metric" id="good-devices">{len(summary['good_devices'])}</div>
                    <div class="metric-label">Good</div>
                </div>
                <div class="summary-card card-warning" id="warning-card">
                    <div class="metric" id="warning-devices">{len(summary['warning_devices'])}</div>
                    <div class="metric-label">Warning</div>
                </div>
                <div class="summary-card card-critical" id="critical-card">
                    <div class="metric" id="critical-devices">{len(summary['critical_devices'])}</div>
                    <div class="metric-label">Critical</div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Device Hardware Status
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <table class="hardware-table" id="hardware-table">
                <thead>
                    <tr>
                        <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="1" data-type="hardware-status">Health <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="2" data-type="number">CPU <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="3" data-type="number">ASIC <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="4" data-type="number">Mem% <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="5" data-type="number">Load <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="6" data-type="hardware-status">Fan <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="7" data-type="number">PSU% <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="8" data-type="string">PSU Power <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="9" data-type="string">Model <span class="sort-arrow">▲▼</span></th>
                    </tr>
                </thead>
                <tbody id="hardware-data">
"""
    
    # Add all devices to table (sorted by health - problems first)
    all_devices = (summary['critical_devices'] + summary['warning_devices'] + 
                  summary['good_devices'] + summary['excellent_devices'])
    
    for device_info in all_devices:
        device_name = device_info['device']
        device_data = device_info['data']
        health_grade = device_info['health_grade']  # Already calculated in summary
        
        # Extract key metrics for display
        cpu_temp, asic_temp = parse_temperature_from_hardware_file(device_name)
        cpu_temp_str = f"{cpu_temp:.1f}°C" if cpu_temp is not None else "N/A"
        asic_temp_str = f"{asic_temp:.1f}°C" if asic_temp is not None else "N/A"
        
        # Prefer values from JSON resources; otherwise parse from raw hardware file
        memory_usage = device_data.get("resources", {}).get("memory", {}).get("usage_percent", None)
        cpu_load = device_data.get("resources", {}).get("cpu", {}).get("load_5min", None)
        cpu_cores = device_data.get("resources", {}).get("cpu", {}).get("cores", None)
        # Uptime removed from table
        uptime = None

        if memory_usage is None or cpu_load is None or cpu_cores is None or not uptime:
            parsed = parse_resources_from_hardware_file(device_name)
            if memory_usage is None:
                memory_usage = parsed.get('memory_usage', 0.0)
            if cpu_load is None:
                cpu_load = parsed.get('cpu_load', 0.0)
            if cpu_cores is None:
                cpu_cores = parsed.get('cpu_cores')
            # do not set uptime anymore
        
        # PSU Efficiency 
        psu_efficiency_parsed = parse_psu_efficiency_from_hardware_file(device_name)
        psu_efficiency = psu_efficiency_parsed if psu_efficiency_parsed is not None else 0.0
        
        # Calculate fan status for display (use JSON fans or parse from file if missing)
        fans = device_data.get("fans", {})
        if not fans:
            fans = parse_fans_from_hardware_file(device_name)
        if fans:
            priority = {"CRITICAL": 4, "WARNING": 3, "GOOD": 2, "EXCELLENT": 1}
            fan_grades_calculated = []
            for fan_name, fan_speed in fans.items():
                if fan_speed > 4000:
                    grade = "EXCELLENT"
                elif fan_speed >= 3000:
                    grade = "GOOD"  
                elif fan_speed >= 1000:
                    grade = "WARNING"
                else:
                    grade = "CRITICAL"
                fan_grades_calculated.append(grade)
            
            # Get overall fan status (worst case from all fans)
            fan_status = max(fan_grades_calculated, key=lambda x: priority.get(x, 0))
        else:
            fan_status = "N/A"
        
        # Badge class for health
        if health_grade == "EXCELLENT":
            health_badge_class = "badge badge-green"
        elif health_grade == "GOOD":
            health_badge_class = "badge badge-green"
        elif health_grade == "WARNING":
            health_badge_class = "badge badge-orange"
        elif health_grade == "CRITICAL":
            health_badge_class = "badge badge-red"
        else:
            health_badge_class = "badge badge-gray"
        
        # Badge class for fan
        if fan_status == "HEALTHY" or fan_status == "EXCELLENT" or fan_status == "GOOD":
            fan_badge_class = "badge badge-green"
        elif fan_status == "WARNING":
            fan_badge_class = "badge badge-orange"
        elif fan_status == "CRITICAL":
            fan_badge_class = "badge badge-red"
        elif fan_status != "N/A":
            fan_badge_class = "badge badge-gray"
        else:
            fan_badge_class = ""
        
        # Compute per-metric grades for dot indicators
        def grade_cpu(t):
            if t is None:
                return None
            if t < 60:
                return "EXCELLENT"
            elif t < 70:
                return "GOOD"
            elif t < 80:
                return "WARNING"
            else:
                return "CRITICAL"

        def grade_asic(t):
            if t is None:
                return None
            if t < 85:
                return "EXCELLENT"
            elif t < 105:
                return "GOOD"
            elif t < 115:
                return "WARNING"
            else:
                return "CRITICAL"

        def grade_memory(p):
            if not isinstance(p, (int, float)):
                return None
            if p < 60:
                return "EXCELLENT"
            elif p < 75:
                return "GOOD"
            elif p < 85:
                return "WARNING"
            else:
                return "CRITICAL"

        def grade_psu(eff, raw):
            # Only grade when we have parsed value
            if raw is None:
                return None
            if eff > 90:
                return "EXCELLENT"
            elif eff >= 50:
                return "GOOD"
            elif eff >= 30:
                return "WARNING"
            else:
                return "CRITICAL"

        cpu_g = grade_cpu(cpu_temp)
        asic_g = grade_asic(asic_temp)
        mem_g = grade_memory(memory_usage if isinstance(memory_usage, (int, float)) else None)
        load_g = grade_load_per_core(cpu_load if isinstance(cpu_load, (int, float)) else None, cpu_cores)
        fan_g = fan_status if fan_status in ("EXCELLENT", "GOOD", "WARNING", "CRITICAL") else None
        psu_g = grade_psu(psu_efficiency, psu_efficiency_parsed)

        def dot_for(g):
            if g == "CRITICAL":
                return '<span class="status-dot critical" title="Critical"></span>'
            if g == "WARNING":
                return '<span class="status-dot warning" title="Warning"></span>'
            return ''

        show_dots = health_grade in ("WARNING", "CRITICAL")

        cpu_cell_suffix = dot_for(cpu_g) if show_dots else ''
        asic_cell_suffix = dot_for(asic_g) if show_dots else ''
        mem_cell_suffix = dot_for(mem_g) if show_dots else ''
        load_cell_suffix = dot_for(load_g) if show_dots else ''
        fan_cell_suffix = dot_for(fan_g) if show_dots else ''
        psu_cell_suffix = dot_for(psu_g) if show_dots else ''

        # Compute PSU IN/OUT numbers for display
        psu_in_w, psu_out_w = parse_psu_power_in_out_from_hardware_file(device_name)
        psu_in_out_str = "N/A"
        if psu_in_w is not None and psu_out_w is not None:
            psu_in_out_str = f"{psu_in_w:.1f}W / {psu_out_w:.1f}W"

        # Get model information from assets
        device_model = assets_data.get(device_name, {}).get("model", "N/A")
        
        html_content += f"""
                <tr data-status="{health_grade.lower()}">
                    <td>{canonical(device_name)}</td>
                    <td><span class="{health_badge_class}">{health_grade.upper()}</span></td>
                    <td>{cpu_temp_str}{cpu_cell_suffix}</td>
                    <td>{asic_temp_str}{asic_cell_suffix}</td>
                    <td>{memory_usage if isinstance(memory_usage, (int, float)) else 0.0:.1f}%{mem_cell_suffix}</td>
                    <td>{cpu_load if isinstance(cpu_load, (int, float)) else 0.0:.2f}{load_cell_suffix}</td>
                    <td><span class="{fan_badge_class}">{fan_status}</span>{fan_cell_suffix}</td>
                    <td>{psu_efficiency:.1f}%{psu_cell_suffix}</td>
                    <td>{psu_in_out_str}</td>
                    <td>{device_model}</td>
                </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </div>
    </div>
        
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            Hardware Health Thresholds
        </div>
        <div class="section-content-table">
            <table class="hardware-table">
                <thead>
                    <tr><th>Parameter</th><th>Excellent</th><th>Good</th><th>Warning</th><th>Critical</th></tr>
                </thead>
                <tbody>
                    <tr><td>CPU Temperature</td><td>&lt; 60°C</td><td>60-70°C</td><td>70-80°C</td><td>&gt; 80°C</td></tr>
                    <tr><td>ASIC Temperature</td><td>&lt; 85°C</td><td>85-105°C</td><td>105-115°C</td><td>&gt; 115°C</td></tr>
                    <tr><td>Memory Usage</td><td>&lt; 60%</td><td>60-75%</td><td>75-85%</td><td>&gt; 85%</td></tr>
                    <tr><td>CPU Load (5min avg)</td><td>&lt; 1.0</td><td>1.0-2.0</td><td>2.0-3.0</td><td>&gt; 3.0</td></tr>
                    <tr><td>Fan Speed</td><td>&gt; 4000 RPM</td><td>3000-4000 RPM</td><td>1000-3000 RPM</td><td>&lt; 1000 RPM</td></tr>
                    <tr><td>PSU Efficiency</td><td>&gt; 90%</td><td>50-90%</td><td>30-50%</td><td>&lt; 30%</td></tr>
                </tbody>
            </table>
        </div>
    </div>

"""
    
    html_content += """
    <!-- jQuery and Select2 for device search -->
    <script src="/css/jquery-3.5.1.min.js"></script>
    <script src="/css/select2.min.js"></script>
    
    <script>
        // Filter functionality
        let currentFilter = 'ALL';
        let allRows = [];
        let deviceSearchActive = false;
        let selectedDevice = '';
        
        document.addEventListener('DOMContentLoaded', function() {
            // Store all table rows for filtering
            allRows = Array.from(document.querySelectorAll('#hardware-data tr'));
            
            // Add click events to summary cards
            setupCardEvents();
            
            // Initialize table sorting
            initTableSorting();
            
            // Initialize device search
            populateDeviceList();
            initDeviceSearch();
        });
        
        function setupCardEvents() {
            console.log('Hardware: Setting up card events...');
            
            const totalDevicesCard = document.getElementById('total-devices-card');
            if (totalDevicesCard) {
                totalDevicesCard.addEventListener('click', function() {
                    if (parseInt(document.getElementById('total-devices').textContent) > 0) {
                        filterDevices('TOTAL');
                    }
                });
            }
            
            document.getElementById('excellent-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('excellent-devices').textContent) > 0) {
                    filterDevices('EXCELLENT');
                }
            });
            
            document.getElementById('good-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('good-devices').textContent) > 0) {
                    filterDevices('GOOD');
                }
            });
            
            document.getElementById('warning-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('warning-devices').textContent) > 0) {
                    filterDevices('WARNING');
                }
            });
            
            document.getElementById('critical-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('critical-devices').textContent) > 0) {
                    filterDevices('CRITICAL');
                }
            });
        }
        
        function filterDevices(filterType) {
            currentFilter = filterType;
            
            // Clear device search when using card filters
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Clear active state from all cards
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });
            
            let filteredRows = allRows;
            let filterText = '';
            
            if (filterType === 'EXCELLENT') {
                filteredRows = allRows.filter(row => row.dataset.status === 'excellent');
                filterText = 'Showing ' + filteredRows.length + ' Excellent Devices';
                document.getElementById('excellent-card').classList.add('active');
            } else if (filterType === 'GOOD') {
                filteredRows = allRows.filter(row => row.dataset.status === 'good');
                filterText = 'Showing ' + filteredRows.length + ' Good Devices';
                document.getElementById('good-card').classList.add('active');
            } else if (filterType === 'WARNING') {
                filteredRows = allRows.filter(row => row.dataset.status === 'warning');
                filterText = 'Showing ' + filteredRows.length + ' Warning Devices';
                document.getElementById('warning-card').classList.add('active');
            } else if (filterType === 'CRITICAL') {
                filteredRows = allRows.filter(row => row.dataset.status === 'critical');
                filterText = 'Showing ' + filteredRows.length + ' Critical Devices';
                document.getElementById('critical-card').classList.add('active');
            } else if (filterType === 'TOTAL') {
                filteredRows = allRows;
                document.getElementById('total-devices-card').classList.add('active');
            }
            
            // Show filter info for all filters except TOTAL
            if (filterType !== 'ALL' && filterType !== 'TOTAL') {
                document.getElementById('filter-info').style.display = 'block';
                document.getElementById('filter-text').textContent = filterText;
            } else {
                document.getElementById('filter-info').style.display = 'none';
            }
            
            // Hide all rows first
            allRows.forEach(row => row.style.display = 'none');
            
            // Show filtered rows
            filteredRows.forEach(row => row.style.display = '');
        }
        
        function clearFilter() {
            currentFilter = 'ALL';
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });
            document.getElementById('filter-info').style.display = 'none';
            
            // Also clear device search
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }
            
            // Show all rows
            allRows.forEach(row => row.style.display = '');
        }
        
        // ===== Device Search Functions =====
        function initDeviceSearch() {
            $('#deviceSearch').select2({
                placeholder: 'Search Device...',
                allowClear: true,
                width: '250px',
                dropdownAutoWidth: true,
                matcher: function(params, data) {
                    if ($.trim(params.term) === '') return data;
                    if (typeof data.text === 'undefined') return null;
                    if (data.text.toLowerCase().indexOf(params.term.toLowerCase()) > -1) return data;
                    return null;
                }
            });
            
            $('#deviceSearch').on('select2:select', function(e) {
                const device = e.params.data.id;
                if (device) filterByDevice(device);
            });
            
            $('#deviceSearch').on('select2:clear', function(e) {
                clearDeviceSearch();
            });
        }
        
        function populateDeviceList() {
            const deviceSet = new Set();
            allRows.forEach(row => {
                const deviceName = row.cells[0]?.textContent?.trim();
                if (deviceName) deviceSet.add(deviceName);
            });
            
            const sortedDevices = Array.from(deviceSet).sort((a, b) => 
                a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
            );
            
            const select = document.getElementById('deviceSearch');
            select.innerHTML = '<option value="">Search Device...</option>';
            sortedDevices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.textContent = device;
                select.appendChild(option);
            });
        }
        
        function filterByDevice(deviceName) {
            if (!deviceName) return;
            
            selectedDevice = deviceName;
            deviceSearchActive = true;
            
            // Clear card-based filter
            currentFilter = 'ALL';
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));
            
            // Filter table rows
            let matchCount = 0;
            allRows.forEach(row => {
                const rowDeviceName = row.cells[0]?.textContent?.trim();
                if (rowDeviceName === deviceName) {
                    row.style.display = '';
                    matchCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            // Show filter info
            document.getElementById('filter-info').style.display = 'block';
            document.getElementById('filter-text').textContent = 'Showing device: ' + deviceName;
            document.getElementById('clearSearchBtn').style.display = 'inline-block';
        }
        
        function clearDeviceSearch() {
            selectedDevice = '';
            deviceSearchActive = false;
            $('#deviceSearch').val('').trigger('change');
            document.getElementById('clearSearchBtn').style.display = 'none';
            document.getElementById('filter-info').style.display = 'none';
            allRows.forEach(row => row.style.display = '');
        }
        
        // Generic table sorting functionality
        let tableSortState = { column: -1, direction: 'asc' };
        
        function initTableSorting() {
            const headers = document.querySelectorAll('.sortable');
            headers.forEach(header => {
                header.addEventListener('click', function() {
                    const column = parseInt(this.dataset.column);
                    const type = this.dataset.type;
                    
                    // Toggle sort direction
                    if (tableSortState.column === column) {
                        tableSortState.direction = tableSortState.direction === 'asc' ? 'desc' : 'asc';
                    } else {
                        tableSortState.direction = 'asc';
                    }
                    tableSortState.column = column;
                    
                    // Update header styling
                    headers.forEach(h => h.classList.remove('asc', 'desc'));
                    this.classList.add(tableSortState.direction);
                    
                    // Sort table
                    sortHardwareTable(column, tableSortState.direction, type);
                });
            });
        }
        
        function sortHardwareTable(columnIndex, direction, type) {
            const table = document.getElementById('hardware-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.rows);
            
            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();
                
                // Extract actual text for status columns (remove HTML)
                if (type === 'hardware-status') {
                    aVal = a.cells[columnIndex].querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex].querySelector('span')?.textContent || bVal;
                }
                
                let result = 0;
                
                switch(type) {
                    case 'hardware-status':
                        result = compareHardwareStatus(aVal, bVal);
                        break;
                    case 'number':
                        const numA = parseFloat(aVal.replace(/[%,]/g, ''));
                        const numB = parseFloat(bVal.replace(/[%,]/g, ''));
                        if (isNaN(numA) && isNaN(numB)) result = 0;
                        else if (isNaN(numA)) result = 1;
                        else if (isNaN(numB)) result = -1;
                        else result = numA - numB;
                        break;
                    case 'string':
                    default:
                        result = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });
                        break;
                }
                
                return direction === 'desc' ? -result : result;
            });
            
            // Clear tbody and add sorted rows back
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function compareHardwareStatus(a, b) {
            const priority = {
                'CRITICAL': 0,
                'WARNING': 1,
                'GOOD': 2,
                'EXCELLENT': 3,
                'UNKNOWN': 4
            };
            
            return (priority[a] || 5) - (priority[b] || 5);
        }

        // Run Analysis Function
        function runAnalysis() {
            const button = document.getElementById('run-analysis');
            const originalText = button.innerHTML;
            
            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/>
                </svg>
                Running...
            `;
            
            // Send POST request to trigger monitor
            fetch('/trigger-monitor', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    console.log('Monitor analysis triggered successfully');
                    // Show notification
                    const notification = document.createElement('div');
                    notification.style.cssText = `
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        background: #c87f0a;
                        color: white;
                        padding: 15px 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                        z-index: 1000;
                        font-size: 14px;
                        max-width: 350px;
                        font-family: monospace;
                    `;
                    notification.innerHTML = `
                        <strong>Monitor Analysis Started</strong><br>
                        The full system analysis is running in the background.<br>
                        <small>Page will automatically refresh in 35 seconds to show the latest results.</small>
                    `;
                    document.body.appendChild(notification);
                    // Auto-refresh page after 35 seconds
                    setTimeout(() => {
                        window.location.reload();
                    }, 35000);
                } else {
                    console.error('❌ Failed to trigger monitor analysis:', data.message);
                    alert('Failed to trigger analysis. Please try again.');
                    // Restore button
                    button.disabled = false;
                    button.innerHTML = originalText;
                }
            })
            .catch(error => {
                console.error('❌ Error triggering analysis:', error);
                alert('Error triggering analysis. Please try again.');
                // Restore button
                button.disabled = false;
                button.innerHTML = originalText;
            });
        }

        // CSV Download Function
        function downloadCSV() {
            try {
                // Get current date for filename
                const now = new Date();
                const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
                const timeStr = now.toTimeString().slice(0, 5).replace(':', '-'); // HH-MM
                const filename = `Hardware_Analysis_Report_${dateStr}_${timeStr}.csv`;
                
                // Create CSV header
                const headers = [
                    'Device',
                    'Health',
                    'CPU Temp (°C)',
                    'ASIC Temp (°C)',
                    'Memory (%)',
                    'CPU Load',
                    'Fan Status',
                    'PSU Efficiency (%)',
                    'PSU Power (IN/OUT)',
                    'Model'
                ];
                
                let csvContent = headers.join(',') + '\\n';
                
                // Get table data (only visible rows)
                const table = document.getElementById('hardware-table');
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');
                
                // Add summary stats as comments
                csvContent += `# Hardware Health Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Devices: ${document.getElementById('total-devices').textContent}\\n`;
                csvContent += `# Excellent: ${document.getElementById('excellent-devices').textContent}\\n`;
                csvContent += `# Good: ${document.getElementById('good-devices').textContent}\\n`;
                csvContent += `# Warning: ${document.getElementById('warning-devices').textContent}\\n`;
                csvContent += `# Critical: ${document.getElementById('critical-devices').textContent}\\n`;
                csvContent += `#\\n`;
                
                // Process each visible row
                rows.forEach(row => {
                    if (row.style.display !== 'none') {
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 10) {
                            const rowData = [
                                cells[0].textContent.trim(), // Device
                                cells[1].querySelector('span') ? cells[1].querySelector('span').textContent.trim() : cells[1].textContent.trim(), // Health
                                cells[2].textContent.trim(), // CPU Temp
                                cells[3].textContent.trim(), // ASIC Temp
                                cells[4].textContent.trim(), // Memory
                                cells[5].textContent.trim(), // CPU Load
                                cells[6].querySelector('span') ? cells[6].querySelector('span').textContent.trim() : cells[6].textContent.trim(), // Fan Status
                                cells[7].textContent.trim(), // PSU Efficiency
                                cells[8].textContent.trim(), // PSU Power
                                cells[9].textContent.trim()  // Model
                            ];
                            
                            // Escape commas and quotes in data
                            const escapedData = rowData.map(field => {
                                if (field.includes(',') || field.includes('"') || field.includes('\\n')) {
                                    return '"' + field.replace(/"/g, '""') + '"';
                                }
                                return field;
                            });
                            
                            csvContent += escapedData.join(',') + '\\n';
                        }
                    }
                });
                
                // Create and trigger download
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = filename;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                console.log(`CSV downloaded: ${filename}`);
                
            } catch (error) {
                console.error('❌ Error generating CSV:', error);
                alert('Error generating CSV file. Please try again.');
            }
        }
    </script>
    <!-- Thresholds reference modal: the in-page threshold/explanation sections are
         relocated in here at load time and shown via the "Thresholds" toolbar button. -->
    <div id="thresholdModal" class="threshold-modal" onclick="if(event.target===this)closeThresholdsModal()">
        <div class="threshold-modal-box">
            <div class="threshold-modal-head">
                <h2>Thresholds</h2>
                <button type="button" class="threshold-modal-close" onclick="closeThresholdsModal()" title="Close">&times;</button>
            </div>
            <div id="thresholdModalBody" class="threshold-modal-body"></div>
        </div>
    </div>
    <style>
        .threshold-modal { display:none; position:fixed; inset:0; z-index:1000; background:rgba(0,0,0,0.65); }
        .threshold-modal.open { display:flex; align-items:flex-start; justify-content:center; }
        .threshold-modal-box { background:#1e1e1e; border:1px solid #3c3c3c; border-radius:8px; width:92%; max-width:920px; margin:40px 16px; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 12px 48px rgba(0,0,0,0.55); }
        .threshold-modal-head { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-bottom:1px solid #3c3c3c; }
        .threshold-modal-head h2 { margin:0; font-size:16px; color:#e0e0e0; }
        .threshold-modal-close { background:none; border:none; color:#aaa; font-size:24px; line-height:1; cursor:pointer; padding:0 6px; }
        .threshold-modal-close:hover { color:#fff; }
        .threshold-modal-body { padding:4px 18px 18px; overflow:auto; }
        .threshold-modal-body .dashboard-section { margin:14px 0 0; }
        .threshold-modal-body .dashboard-section:first-child { margin-top:6px; }
    </style>
    <script>
        (function () {
            function buildThresholdModal() {
                var body = document.getElementById('thresholdModalBody');
                if (!body) return;
                var sections = Array.prototype.slice.call(document.querySelectorAll('.dashboard-section'));
                var start = -1;
                for (var i = 0; i < sections.length; i++) {
                    var h = sections[i].querySelector('.section-header');
                    if (h && /threshold/i.test(h.textContent)) { start = i; break; }
                }
                if (start < 0) return;
                // Move the threshold section + any trailing explanation sections into the modal.
                for (var j = start; j < sections.length; j++) { body.appendChild(sections[j]); }
            }
            window.openThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.add('open'); };
            window.closeThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.remove('open'); };
            document.addEventListener('keydown', function (e) { if (e.key === 'Escape') window.closeThresholdsModal(); });
            buildThresholdModal();
        })();
    </script>
    <script src="/p2p-alias.js"></script>
    <script src="/css/analysis-guard.js"></script>
</body>
</html>"""
    
    # Write HTML file
    with open("monitor-results/hardware-analysis.html", 'w') as f:
        f.write(html_content)
    
    print(f"Hardware analysis HTML generated with {total_devices} devices!")
    print(f"   - Excellent: {len(summary['excellent_devices'])}")
    print(f"   - Good: {len(summary['good_devices'])}")
    print(f"   - Warning: {len(summary['warning_devices'])}")
    print(f"   - Critical: {len(summary['critical_devices'])}")

if __name__ == "__main__":
    generate_hardware_html()
