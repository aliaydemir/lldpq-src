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
import html
from datetime import datetime, timezone
from collection_freshness import is_current_collection, read_asset_snapshot

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n


# One grading contract drives both the calculation and the threshold reference
# rendered in the report. Tuples are the boundaries between
# EXCELLENT/GOOD/WARNING/CRITICAL in that order. Notification warning/critical
# values are loaded below, while the extra GOOD/EXCELLENT boundaries retain
# conservative defaults unless explicitly configured.
DEFAULT_HARDWARE_THRESHOLDS = {
    "cpu_temp_c": (60.0, 75.0, 85.0),
    "asic_temp_c": (70.0, 80.0, 90.0),
    "memory_percent": (60.0, 80.0, 90.0),
    "load_per_core": (0.7, 1.0, 1.5),
    # Low values are bad for fan speed and PSU efficiency.  These tuples are
    # CRITICAL/WARNING/GOOD boundaries; values above the final boundary are
    # EXCELLENT (strictly above for compatibility with the existing grading).
    "fan_rpm": (3000.0, 4000.0, 5000.0),
    "psu_efficiency_percent": (30.0, 80.0, 90.0),
}


def _finite_number(mapping, key, fallback):
    value = mapping.get(key, fallback) if isinstance(mapping, dict) else fallback
    try:
        value = float(value)
    except (TypeError, ValueError):
        return float(fallback)
    return value if value == value and abs(value) != float("inf") else float(fallback)


def _validated_load_per_core_thresholds(configured):
    """Return one validated per-core load contract for grading and alerts.

    The older ``thresholds.system.load_average_*`` settings are absolute load
    values.  They cannot be compared with a normalized per-core value, so they
    are deliberately not treated as aliases here.  Installations without the
    explicit per-core keys keep the established safe defaults.
    """
    defaults = DEFAULT_HARDWARE_THRESHOLDS["load_per_core"]
    warning = _finite_number(
        configured, "load_per_core_warning", defaults[1]
    )
    critical = _finite_number(
        configured, "load_per_core_critical", defaults[2]
    )
    if not 0 < warning < critical:
        return defaults

    # EXCELLENT is a report-only band.  Derive a valid boundary when a custom
    # warning threshold is lower than the normal 0.7/core default.
    excellent_default = min(defaults[0], warning * 0.7)
    excellent = _finite_number(
        configured, "load_per_core_excellent", excellent_default
    )
    if not 0 <= excellent < warning:
        excellent = excellent_default
    return (excellent, warning, critical)


def load_hardware_thresholds():
    """Load the alert thresholds and safely extend them to four UI grades."""
    defaults = DEFAULT_HARDWARE_THRESHOLDS
    try:
        import yaml

        config_file = os.path.join(os.path.dirname(__file__), "notifications.yaml")
        with open(config_file, "r", encoding="utf-8") as source:
            config = yaml.safe_load(source) or {}
        configured = config.get("thresholds", {}).get("hardware", {})
        if not isinstance(configured, dict):
            raise ValueError("hardware thresholds must be a mapping")
    except Exception as exc:
        print(f"Warning: using default hardware thresholds: {exc}")
        return dict(defaults)

    def high_is_bad(key, warning_key, critical_key, excellent_default):
        warning = _finite_number(configured, warning_key, defaults[key][1])
        critical = _finite_number(configured, critical_key, defaults[key][2])
        excellent = _finite_number(
            configured,
            f"{warning_key.removesuffix('_warning')}_excellent",
            excellent_default,
        )
        values = (excellent, warning, critical)
        return values if 0 <= excellent < warning < critical else defaults[key]

    def low_is_bad(key, critical_key, warning_key, excellent_default):
        critical = _finite_number(configured, critical_key, defaults[key][0])
        warning = _finite_number(configured, warning_key, defaults[key][1])
        excellent = _finite_number(
            configured,
            f"{warning_key.removesuffix('_warning')}_excellent",
            excellent_default,
        )
        values = (critical, warning, excellent)
        return values if 0 <= critical < warning < excellent else defaults[key]

    cpu_warning = _finite_number(configured, "cpu_temp_warning", 75.0)
    asic_warning = _finite_number(configured, "asic_temp_warning", 80.0)
    memory_warning = _finite_number(configured, "memory_usage_warning", 80.0)
    fan_warning = _finite_number(configured, "fan_rpm_warning", 4000.0)
    psu_warning = _finite_number(configured, "psu_efficiency_warning", 80.0)

    return {
        "cpu_temp_c": high_is_bad(
            "cpu_temp_c", "cpu_temp_warning", "cpu_temp_critical",
            min(defaults["cpu_temp_c"][0], cpu_warning - 1.0),
        ),
        "asic_temp_c": high_is_bad(
            "asic_temp_c", "asic_temp_warning", "asic_temp_critical",
            min(70.0, asic_warning - 1.0),
        ),
        "memory_percent": high_is_bad(
            "memory_percent", "memory_usage_warning", "memory_usage_critical",
            min(defaults["memory_percent"][0], memory_warning - 1.0),
        ),
        "load_per_core": _validated_load_per_core_thresholds(configured),
        "fan_rpm": low_is_bad(
            "fan_rpm", "fan_rpm_critical", "fan_rpm_warning",
            max(5000.0, fan_warning + 1.0),
        ),
        "psu_efficiency_percent": low_is_bad(
            "psu_efficiency_percent", "psu_efficiency_critical",
            "psu_efficiency_warning", max(90.0, psu_warning + 1.0),
        ),
    }


HARDWARE_THRESHOLDS = load_hardware_thresholds()

GRADE_PRIORITY = {"CRITICAL": 4, "WARNING": 3, "GOOD": 2, "EXCELLENT": 1}
HISTORY_MAX_SKEW_SECONDS = 300.0


def grade_high_is_bad(value, threshold_key):
    """Grade a metric where higher values are worse."""
    if not isinstance(value, (int, float)):
        return None
    excellent_max, good_max, warning_max = HARDWARE_THRESHOLDS[threshold_key]
    if value < excellent_max:
        return "EXCELLENT"
    if value < good_max:
        return "GOOD"
    if value < warning_max:
        return "WARNING"
    return "CRITICAL"


def grade_low_is_bad(value, threshold_key):
    """Grade a metric where lower values are worse."""
    if not isinstance(value, (int, float)):
        return None
    critical_min, warning_min, excellent_min = HARDWARE_THRESHOLDS[threshold_key]
    if value > excellent_min:
        return "EXCELLENT"
    if value >= warning_min:
        return "GOOD"
    if value >= critical_min:
        return "WARNING"
    return "CRITICAL"


def _power_to_watts(value, unit):
    watts = float(value)
    if unit == "kW":
        return watts * 1000.0
    if unit == "mW":
        return watts / 1000.0
    return watts


def _parse_history_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # Legacy entries were written in local time.  Treat them as local for
        # the sole purpose of comparing them with the raw file mtime.
        return parsed.timestamp()
    return parsed.astimezone(timezone.utc).timestamp()


def fresh_history_entry(history, raw_file, max_skew_seconds=HISTORY_MAX_SKEW_SECONDS):
    """Return history data only when it belongs to the current raw sample."""
    if not isinstance(history, list) or not history:
        return None
    entry = history[-1]
    if not isinstance(entry, dict):
        return None
    entry_timestamp = _parse_history_timestamp(entry.get("timestamp"))
    if entry_timestamp is None:
        return None
    try:
        raw_timestamp = os.path.getmtime(raw_file)
    except OSError:
        return None
    if abs(entry_timestamp - raw_timestamp) > max(max_skew_seconds, 0.0):
        return None
    return entry


def _format_threshold(value):
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def threshold_reference_rows():
    """Render the visible reference from the same constants used for grading."""
    rows = []
    for label, key, unit in (
        ("CPU Temperature", "cpu_temp_c", "°C"),
        ("ASIC Temperature", "asic_temp_c", "°C"),
        ("Memory Usage", "memory_percent", "%"),
        ("CPU Load (5min avg per core)", "load_per_core", ""),
    ):
        excellent_max, good_max, warning_max = HARDWARE_THRESHOLDS[key]
        a, b, c = map(_format_threshold, (excellent_max, good_max, warning_max))
        rows.append(
            f"<tr><td>{label}</td>"
            f"<td>&lt; {a}{unit}</td>"
            f"<td>&ge; {a}{unit} and &lt; {b}{unit}</td>"
            f"<td>&ge; {b}{unit} and &lt; {c}{unit}</td>"
            f"<td>&ge; {c}{unit}</td></tr>"
        )
    for label, key, unit in (
        ("Fan Speed", "fan_rpm", " RPM"),
        ("PSU Efficiency", "psu_efficiency_percent", "%"),
    ):
        critical_min, warning_min, excellent_min = HARDWARE_THRESHOLDS[key]
        a, b, c = map(_format_threshold, (critical_min, warning_min, excellent_min))
        rows.append(
            f"<tr><td>{label}</td>"
            f"<td>&gt; {c}{unit}</td>"
            f"<td>&ge; {b}{unit} and &le; {c}{unit}</td>"
            f"<td>&ge; {a}{unit} and &lt; {b}{unit}</td>"
            f"<td>&lt; {a}{unit}</td></tr>"
        )
    return "\n".join(rows)

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
    """Parse the hottest CPU and ASIC sensor from the raw hardware file.

    Alerts use the maximum observed temperature because one hot core/package
    is operationally significant. The report uses the same max metric rather
    than averaging cores and disagreeing with the alert state.
    """
    
    cpu_temp = None
    asic_temp = None
    
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    
    if not os.path.exists(hardware_file):
        return cpu_temp, asic_temp
    
    try:
        with open(hardware_file, 'r') as f:
            content = f.read()
        
        asic_temperatures = []
        for pattern in (
            r'Ambient ASIC Temp:\s*\+?(-?\d+\.?\d*)[°C]',
            r'^(?:HW_MGMT_ASIC|THERMAL_ZONE_ASIC|HWMON_ASIC):\s*(-?\d+\.?\d*)',
            r'^\s*Asic-Temp-Sensor\s+(-?\d+\.?\d*)\s+',
        ):
            asic_temperatures.extend(
                float(value) for value in re.findall(
                    pattern, content, re.MULTILINE | re.IGNORECASE
                )
            )
        if asic_temperatures:
            asic_temp = max(asic_temperatures)

        # Deliberately do not use generic "temp1": it may be a disk or PSU.
        cpu_temperatures = []
        for pattern in (
            r'CPU ACPI temp:\s*\+?(-?\d+\.?\d*)[°C]',
            r'Core \d+:\s*\+?(-?\d+\.?\d*)[°C]',
            r'Package id \d+:\s*\+?(-?\d+\.?\d*)[°C]',
            r'^HW_MGMT_CPU:\s*(-?\d+\.?\d*)',
            r'^\s*CPU-Core-Sensor-\d+\s+(-?\d+\.?\d*)\s+',
            r'^\s*CPU-Package-Sensor\s+(-?\d+\.?\d*)\s+',
        ):
            cpu_temperatures.extend(
                float(value) for value in re.findall(
                    pattern, content, re.MULTILINE | re.IGNORECASE
                )
            )
        if cpu_temperatures:
            cpu_temp = max(cpu_temperatures)
        
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

        # Normalize W/kW/mW before aggregating.
        total_psu_in = 0.0
        for value, unit in psu_ac_in_w:
            total_psu_in += _power_to_watts(value, unit)
            
        total_psu_out = 0.0  
        for value, unit in psu_dc_out_w:
            total_psu_out += _power_to_watts(value, unit)

        if total_psu_in > 0 and total_psu_out > 0:
            efficiency = (total_psu_out / total_psu_in) * 100.0
            # A value above 100% is invalid telemetry, not an excellent PSU.
            return efficiency if efficiency <= 100.0 else None

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
            return efficiency if efficiency <= 100.0 else None
        
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

        # Normalize W/kW/mW before aggregating.
        total_psu_in = 0.0
        for value, unit in psu_ac_in_w:
            total_psu_in += _power_to_watts(value, unit)
            
        total_psu_out = 0.0  
        for value, unit in psu_dc_out_w:
            total_psu_out += _power_to_watts(value, unit)


        if total_psu_in > 0 and total_psu_out > 0:
            # Sanity check: Output should never be higher than input (physics!)
            if total_psu_out > total_psu_in:
                print(f"⚠️  {device_name}: PSU output ({total_psu_out}W) > input ({total_psu_in}W) - IMPOSSIBLE!")
                return None, None
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
            if total_output_power > total_input_power:
                return None, None
            return total_input_power, total_output_power
        return None, None
    except Exception:
        return None, None

def _parse_size_to_gib(size_str: str) -> float:
    """Convert a size token like '15Gi', '286Mi' into GiB float."""
    try:
        m = re.fullmatch(r'(\d+\.?\d*)([KMGT]i)', size_str)
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
        # Current collections include an explicit source-status marker between
        # the heading and /proc/loadavg.  Keep accepting marker-free legacy
        # samples, but never parse a value following an ERROR marker.
        cpu_line = re.search(
            r'^CPU_INFO:\n'
            r'(?:__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:OK\s*\n)?'
            r'([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+',
            content,
            re.MULTILINE,
        )
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


def hardware_missing_telemetry_markers(device_name):
    """Return collector-declared telemetry gaps from the current raw sample.

    The collector deliberately writes these messages when a command cannot
    provide data.  Treating them as ordinary text can otherwise allow a fresh
    history entry or a partial fallback to make an incomplete sample look
    healthy.
    """
    hardware_file = f"monitor-results/hardware-data/{device_name}_hardware.txt"
    try:
        with open(hardware_file, "r", encoding="utf-8", errors="ignore") as source:
            content = source.read().lower()
    except OSError:
        return {"hardware_file"}

    markers = set()
    for source, status in re.findall(
        r'^__LLDPQ_HARDWARE_SOURCE_STATUS__:([A-Za-z0-9_.-]+):(OK|ERROR|UNAVAILABLE)\s*$',
        content,
        re.MULTILINE | re.IGNORECASE,
    ):
        if status.upper() != "OK":
            markers.add(source.lower())
    if "no sensors available" in content:
        markers.add("sensors")
    if "no memory info" in content:
        markers.add("memory")
    if "no cpu info" in content:
        markers.add("cpu")
    return markers


def normalize_load_per_core(cpu_load, cpu_cores):
    """Return the 5-minute load average divided by logical CPU cores."""
    if (isinstance(cpu_load, bool) or
            not isinstance(cpu_load, (int, float)) or
            cpu_load < 0 or cpu_load != cpu_load or
            abs(cpu_load) == float("inf") or
            isinstance(cpu_cores, bool) or
            not isinstance(cpu_cores, (int, float)) or cpu_cores <= 0 or
            cpu_cores != cpu_cores or abs(cpu_cores) == float("inf")):
        return None
    return cpu_load / cpu_cores


def grade_load_per_core(cpu_load, cpu_cores):
    """Grade the CPU load average normalized by core count.

    Load average is a per-core measure, so an absolute threshold falsely flags
    healthy multi-core switches (e.g. load 3.3 on an 8-core CPU is ~0.4/core).
    A missing core count cannot be normalized safely.  In that case the metric
    remains unavailable instead of silently assuming a CPU size.
    """
    load_per_core = normalize_load_per_core(cpu_load, cpu_cores)
    if load_per_core is None:
        return None
    return grade_high_is_bad(load_per_core, "load_per_core")


def calculate_device_health_grade(device_name, device_data):
    """Calculate overall health grade for a device based on our thresholds"""
    health_grades = []
    # Source markers describe the primary collector command, not necessarily the
    # metric itself. Platforms commonly report SENSORS=UNAVAILABLE while the
    # hw-management/thermal-zone fallback still supplies valid CPU/ASIC values.
    # Keep every other explicit collector failure fail-closed; fresh history can
    # otherwise mask a current MEMORY/CPU_LOAD error with an older value.
    missing_markers = hardware_missing_telemetry_markers(device_name)
    required_telemetry_missing = bool(missing_markers - {"sensors"})
    
    # CPU Temperature grade
    cpu_temp, asic_temp = parse_temperature_from_hardware_file(device_name)
    cpu_grade = grade_high_is_bad(cpu_temp, "cpu_temp_c")
    if cpu_grade:
        health_grades.append(cpu_grade)
    else:
        required_telemetry_missing = True
    
    # ASIC Temperature grade
    asic_grade = grade_high_is_bad(asic_temp, "asic_temp_c")
    if asic_grade:
        health_grades.append(asic_grade)
    else:
        required_telemetry_missing = True
    
    parsed_resources = {}

    # Memory usage grade
    memory_usage = device_data.get("resources", {}).get("memory", {}).get("usage_percent", None)
    if memory_usage is None:
        parsed_resources = parse_resources_from_hardware_file(device_name)
        memory_usage = parsed_resources.get('memory_usage')
    if not isinstance(memory_usage, (int, float)):
        required_telemetry_missing = True
    else:
        health_grades.append(grade_high_is_bad(memory_usage, "memory_percent"))
        
    # CPU Load grade
    cpu_load = device_data.get("resources", {}).get("cpu", {}).get("load_5min", None)
    if cpu_load is None:
        if not parsed_resources:
            parsed_resources = parse_resources_from_hardware_file(device_name)
        cpu_load = parsed_resources.get('cpu_load')
    # Normalize the load average by CPU core count (see grade_load_per_core).
    cpu_cores = device_data.get("resources", {}).get("cpu", {}).get("cores", None)
    if not cpu_cores:
        if not parsed_resources:
            parsed_resources = parse_resources_from_hardware_file(device_name)
        cpu_cores = parsed_resources.get('cpu_cores')
    if not isinstance(cpu_cores, (int, float)) or cpu_cores <= 0:
        required_telemetry_missing = True
    load_grade = grade_load_per_core(cpu_load, cpu_cores)
    if load_grade:
        health_grades.append(load_grade)
    else:
        required_telemetry_missing = True
    
    # PSU Efficiency grade
    psu_efficiency = parse_psu_efficiency_from_hardware_file(device_name)
    psu_grade = grade_low_is_bad(psu_efficiency, "psu_efficiency_percent")
    if psu_grade:
        health_grades.append(psu_grade)
    else:
        required_telemetry_missing = True
    
    # Fan status grade
    fans = device_data.get("fans", {})
    if not fans:
        fans = parse_fans_from_hardware_file(device_name)
    if fans:
        fan_grades = [
            grade_low_is_bad(fan_speed, "fan_rpm")
            for fan_speed in fans.values()
            if isinstance(fan_speed, (int, float))
        ]
        if fan_grades:
            fan_status = max(fan_grades, key=lambda x: GRADE_PRIORITY.get(x, 0))
            health_grades.append(fan_status)
        else:
            required_telemetry_missing = True
    else:
        required_telemetry_missing = True
    
    # Calculate overall health grade (worst case)
    if health_grades:
        worst_known = max(health_grades, key=lambda x: GRADE_PRIORITY.get(x, 0))
        # Do not advertise an incomplete sample as healthy. A known warning or
        # critical condition still takes precedence over missing telemetry.
        if required_telemetry_missing and worst_known not in ("WARNING", "CRITICAL"):
            return "UNKNOWN"
        return worst_known
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
    
    # Build current devices from fresh raw files. History may enrich those
    # devices, but can never resurrect an unreachable/retired device as current.
    latest_devices = {}
    hardware_data_dir = "monitor-results/hardware-data"
    asset_snapshot = read_asset_snapshot()
    current_device_files = []
    if os.path.exists(hardware_data_dir):
        current_device_files = [
            filename for filename in os.listdir(hardware_data_dir)
            if filename.endswith('_hardware.txt')
            and is_current_collection(
                os.path.join(hardware_data_dir, filename),
                filename.removesuffix('_hardware.txt'),
                asset_snapshot,
            )
        ]
    for filename in current_device_files:
        device_name = filename.removesuffix('_hardware.txt')
        history = hardware_history.get(device_name, [])
        raw_file = os.path.join(hardware_data_dir, filename)
        history_entry = fresh_history_entry(history, raw_file)
        if history_entry is not None:
            latest_devices[device_name] = history_entry
        else:
            latest_devices[device_name] = {
                'device': device_name,
                'timestamp': datetime.fromtimestamp(
                    os.path.getmtime(raw_file), tz=timezone.utc
                ).isoformat(),
                'fans': {},
                'memory_usage': 'N/A',
                'cpu_load': 'N/A',
                'uptime': 'N/A'
            }
    print(f"Analyzing {len(latest_devices)} devices from the current collection")
    
    # Calculate summary
    summary = {
        'excellent_devices': [],
        'good_devices': [],
        'warning_devices': [],
        'critical_devices': [],
        'unknown_devices': []
    }
    
    # Count devices with current hardware files
    current_device_count = len(current_device_files)
    
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
        else:
            summary['unknown_devices'].append(device_info)
    
    # Use current device files count instead of historical count
    total_devices = current_device_count
    asset_statuses = asset_snapshot[0] if asset_snapshot else {}
    # Coverage represents the whole inventory, including devices that were
    # unreachable in this run; current data still contains only OK devices.
    expected_devices = len(asset_statuses) or total_devices
    unknown_device_count = len(summary['unknown_devices'])
    coverage_partial = (
        current_device_count < expected_devices or unknown_device_count > 0
    )
    coverage_status = "partial" if coverage_partial else "current"
    
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
        .card-unknown {{ border-left-color: #9e9e9e; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .card-excellent .metric {{ color: #76b900; }}
        .card-good .metric {{ color: #8bc34a; }}
        .card-warning .metric {{ color: #ff9800; }}
        .card-critical .metric {{ color: #f44336; }}
        .card-unknown .metric {{ color: #9e9e9e; }}
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
    <div data-analysis-summary="hardware"
         data-collection-status="{coverage_status}"
         data-coverage-expected="{expected_devices}"
         data-coverage-current="{current_device_count}"
         data-coverage-partial="{'true' if coverage_partial else 'false'}"
         data-unknown-devices="{unknown_device_count}"
         style="display:none"></div>
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
                <div class="summary-card card-unknown" id="unknown-card">
                    <div class="metric" id="unknown-devices">{unknown_device_count}</div>
                    <div class="metric-label">Unknown</div>
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
                        <th class="sortable" data-column="5" data-type="number" title="Shows raw 5-minute load; health is evaluated as raw load divided by logical CPU cores">Load <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="6" data-type="hardware-status">Fan <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="7" data-type="number">PSU% <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="8" data-type="power">PSU Power <span class="sort-arrow">▲▼</span></th>
                        <th class="sortable" data-column="9" data-type="string">Model <span class="sort-arrow">▲▼</span></th>
                    </tr>
                </thead>
                <tbody id="hardware-data">
"""
    
    # Add all devices to table (sorted by health - problems first)
    all_devices = (summary['critical_devices'] + summary['warning_devices'] +
                  summary['good_devices'] + summary['excellent_devices'] +
                  summary['unknown_devices'])
    
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
                memory_usage = parsed.get('memory_usage')
            if cpu_load is None:
                cpu_load = parsed.get('cpu_load')
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
            fan_grades_calculated = [
                grade_low_is_bad(fan_speed, "fan_rpm")
                for fan_speed in fans.values()
                if isinstance(fan_speed, (int, float))
            ]
            
            # Get overall fan status (worst case from all fans)
            fan_status = (
                max(
                    fan_grades_calculated,
                    key=lambda x: GRADE_PRIORITY.get(x, 0),
                )
                if fan_grades_calculated else "N/A"
            )
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
            return grade_high_is_bad(t, "cpu_temp_c")

        def grade_asic(t):
            return grade_high_is_bad(t, "asic_temp_c")

        def grade_memory(p):
            return grade_high_is_bad(p, "memory_percent")

        def grade_psu(eff, raw):
            # Only grade when we have parsed value
            if raw is None:
                return None
            return grade_low_is_bad(eff, "psu_efficiency_percent")

        cpu_g = grade_cpu(cpu_temp)
        asic_g = grade_asic(asic_temp)
        mem_g = grade_memory(memory_usage if isinstance(memory_usage, (int, float)) else None)
        load_g = grade_load_per_core(cpu_load if isinstance(cpu_load, (int, float)) else None, cpu_cores)
        fan_g = fan_status if fan_status in ("EXCELLENT", "GOOD", "WARNING", "CRITICAL") else None
        psu_g = grade_psu(psu_efficiency, psu_efficiency_parsed)

        def dot_for(g, title=None):
            title_attr = html.escape(title or str(g).title(), quote=True)
            if g == "CRITICAL":
                return f'<span class="status-dot critical" title="{title_attr}"></span>'
            if g == "WARNING":
                return f'<span class="status-dot warning" title="{title_attr}"></span>'
            return ''

        show_dots = health_grade in ("WARNING", "CRITICAL")

        cpu_cell_suffix = dot_for(cpu_g) if show_dots else ''
        asic_cell_suffix = dot_for(asic_g) if show_dots else ''
        mem_cell_suffix = dot_for(mem_g) if show_dots else ''
        normalized_load = normalize_load_per_core(cpu_load, cpu_cores)
        if normalized_load is not None:
            load_explanation = (
                f"Raw 5-minute load {cpu_load:.2f}; health: {cpu_load:.2f} / "
                f"{cpu_cores:g} cores = {normalized_load:.2f}/core"
            )
        elif isinstance(cpu_load, (int, float)):
            load_explanation = (
                f"Raw 5-minute load {cpu_load:.2f}; health cannot be evaluated "
                "without a valid logical CPU core count"
            )
        else:
            load_explanation = "Raw 5-minute load is unavailable"
        load_title = html.escape(load_explanation, quote=True)
        load_cell_suffix = (
            dot_for(load_g, load_explanation) if show_dots else ''
        )
        fan_cell_suffix = dot_for(fan_g) if show_dots else ''
        psu_cell_suffix = dot_for(psu_g) if show_dots else ''

        # Compute PSU IN/OUT numbers for display
        psu_in_w, psu_out_w = parse_psu_power_in_out_from_hardware_file(device_name)
        psu_in_out_str = "N/A"
        if psu_in_w is not None and psu_out_w is not None:
            psu_in_out_str = f"{psu_in_w:.1f}W / {psu_out_w:.1f}W"

        # Get model information from assets
        device_label = html.escape(str(canonical(device_name)))
        device_model = html.escape(
            str(assets_data.get(device_name, {}).get("model", "N/A"))
        )
        memory_usage_str = (f"{memory_usage:.1f}%"
                            if isinstance(memory_usage, (int, float)) else "N/A")
        cpu_load_str = (f"{cpu_load:.2f}"
                        if isinstance(cpu_load, (int, float)) else "N/A")
        psu_efficiency_str = (
            f"{psu_efficiency:.1f}%"
            if psu_efficiency_parsed is not None else "N/A"
        )
        
        html_content += f"""
                <tr data-status="{health_grade.lower()}">
                    <td>{device_label}</td>
                    <td><span class="{health_badge_class}">{health_grade.upper()}</span></td>
                    <td>{cpu_temp_str}{cpu_cell_suffix}</td>
                    <td>{asic_temp_str}{asic_cell_suffix}</td>
                    <td>{memory_usage_str}{mem_cell_suffix}</td>
                    <td title="{load_title}">{cpu_load_str}{load_cell_suffix}</td>
                    <td><span class="{fan_badge_class}">{fan_status}</span>{fan_cell_suffix}</td>
                    <td>{psu_efficiency_str}{psu_cell_suffix}</td>
                    <td>{psu_in_out_str}</td>
                    <td>{device_model}</td>
                </tr>
"""
    
    threshold_rows = threshold_reference_rows()
    html_content += f"""
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
                    {threshold_rows}
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

            document.getElementById('unknown-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('unknown-devices').textContent) > 0) {
                    filterDevices('UNKNOWN');
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
            } else if (filterType === 'UNKNOWN') {
                filteredRows = allRows.filter(row => row.dataset.status === 'unknown');
                filterText = 'Showing ' + filteredRows.length + ' Unknown Devices';
                document.getElementById('unknown-card').classList.add('active');
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
                    case 'power':
                        const powerA = parseFloat(aVal);
                        const powerB = parseFloat(bVal);
                        if (isNaN(powerA) && isNaN(powerB)) result = 0;
                        else if (isNaN(powerA)) result = 1;
                        else if (isNaN(powerB)) result = -1;
                        else result = powerA - powerB;
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
            
            const aPriority = Object.prototype.hasOwnProperty.call(priority, a) ? priority[a] : 5;
            const bPriority = Object.prototype.hasOwnProperty.call(priority, b) ? priority[b] : 5;
            return aPriority - bPriority;
        }

        // Run Analysis Function
        async function runAnalysis() {
            const button = document.getElementById('run-analysis');
            const originalText = button.innerHTML;
            let notification = null;

            const restoreButton = () => {
                button.disabled = false;
                button.innerHTML = originalText;
            };
            
            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/>
                </svg>
                Running...
            `;
            
            try {
                // Capture the current pipeline generation before starting a
                // new run, so completion means "new output is ready" rather
                // than merely "some output exists".
                const baseline = typeof window.lldpqCapturePipelineState === 'function'
                    ? await window.lldpqCapturePipelineState()
                    : null;

                const response = await fetch('/trigger-monitor', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });
                const data = await response.json();
                if (!response.ok || data.status !== 'success') {
                    throw new Error(data.message || `HTTP ${response.status}`);
                }

                console.log('Monitor analysis triggered successfully');
                notification = document.createElement('div');
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
                const completionHelperAvailable =
                    typeof window.waitForLldpqAnalysisCompletion === 'function';
                notification.innerHTML = `
                        <strong>Monitor Analysis Started</strong><br>
                        The full system analysis is running in the background.<br>
                        <small>${completionHelperAvailable
                            ? 'Page will refresh when the latest results are ready.'
                            : 'Page will automatically refresh in 35 seconds.'}</small>
                    `;
                document.body.appendChild(notification);

                if (!completionHelperAvailable) {
                    setTimeout(() => {
                        window.location.reload();
                    }, 35000);
                    return;
                }

                await window.waitForLldpqAnalysisCompletion(baseline);
                window.location.reload();
            } catch (error) {
                console.error('❌ Analysis did not complete:', error);
                if (notification) notification.remove();
                restoreButton();
                alert(`Analysis did not complete: ${error.message || error}`);
            }
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
                csvContent += `# Unknown: ${document.getElementById('unknown-devices').textContent}\\n`;
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
    print(f"   - Unknown: {len(summary['unknown_devices'])}")

if __name__ == "__main__":
    generate_hardware_html()
