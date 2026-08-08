#!/usr/bin/env python3
"""Checks a virtualised switch is graded on the telemetry it can actually have.

Cumulus VX has no ASIC die, no PSU rails and no CPU thermal diode, so those
three readings never appear.  The analyzer treated each absence as incomplete
telemetry, which graded an entire healthy lab fabric Unknown even though
memory, load and fan data were all present and good.

A physical switch missing the same readings still has a real problem, so the
detection must stay fail-closed: only an explicitly virtual sample is excused.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import generate_hardware_html as hardware


VX_SENSORS = """\
cumulus_vx_cpld-isa-0000
Adapter: ISA adapter
fan1:        6000 RPM  (min = 2500 RPM, max = 29000 RPM)
fan2:        6000 RPM  (min = 2500 RPM, max = 29000 RPM)
temp1:        +25.0°C  (low  =  +5.0°C, high = +80.0°C)
"""

PHYSICAL_SENSORS = """\
mlxsw-i2c-0-48
Adapter: i2c adapter
Chassis Fan Drawer-1 Tach 1: 8000 RPM
Chassis Fan Drawer-2 Tach 1: 8100 RPM
"""


class VirtualPlatformTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._cwd = os.getcwd()
        root = Path(self._tmp.name)
        (root / "monitor-results" / "hardware-data").mkdir(parents=True)
        os.chdir(root)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    # ---------- fixtures ----------
    def write_sample(self, device, *, virt_marker=None, sensors=VX_SENSORS,
                     memory=True, cpu=True, available="5.7Gi"):
        body = []
        if virt_marker is not None:
            body.append(f"PLATFORM_VIRT: {virt_marker}")
        body.append("HARDWARE_HEALTH:")
        body.append("__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:OK")
        body.append(sensors.rstrip("\n"))
        body.append("MEMORY_INFO:")
        if memory:
            body.append("__LLDPQ_HARDWARE_SOURCE_STATUS__:MEMORY:OK")
            # Usage is derived from the "available" column, not "used"
            body.append(
                "               total        used        free      "
                "shared  buff/cache   available\n"
                f"Mem:           7.4Gi       1.6Gi       5.0Gi       "
                f"123Mi       1.1Gi       {available}\n"
                "Swap:             0B          0B          0B")
        else:
            body.append("__LLDPQ_HARDWARE_SOURCE_STATUS__:MEMORY:ERROR")
            body.append("No memory info")
        body.append("CPU_INFO:")
        if cpu:
            body.append("__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:OK")
            body.append("0.16 0.09 0.02 1/386 64235")
            body.append("CPU_CORES: 4")
        else:
            body.append("__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:ERROR")
            body.append("No cpu info")
        Path(f"monitor-results/hardware-data/{device}_hardware.txt").write_text(
            "\n".join(body) + "\n", encoding="utf-8")

    def grade(self, device):
        return hardware.calculate_device_health_grade(device, {})

    # ---------- detection ----------
    def test_the_collector_marker_identifies_a_virtual_switch(self):
        self.write_sample("leaf-01", virt_marker="kvm")
        self.assertTrue(hardware.hardware_platform_is_virtual("leaf-01"))

    def test_physical_hardware_reports_none_and_stays_physical(self):
        self.write_sample("leaf-02", virt_marker="none",
                          sensors=PHYSICAL_SENSORS)
        self.assertFalse(hardware.hardware_platform_is_virtual("leaf-02"))

    def test_an_unreadable_marker_is_treated_as_physical(self):
        self.write_sample("leaf-03", virt_marker="unknown",
                          sensors=PHYSICAL_SENSORS)
        self.assertFalse(hardware.hardware_platform_is_virtual("leaf-03"))

    def test_older_samples_are_recognised_by_the_virtual_sensor_adapter(self):
        """Installs that collected before the marker existed still work."""
        self.write_sample("leaf-04")
        self.assertTrue(hardware.hardware_platform_is_virtual("leaf-04"))

    def test_a_physical_sample_without_a_marker_stays_physical(self):
        self.write_sample("leaf-05", sensors=PHYSICAL_SENSORS)
        self.assertFalse(hardware.hardware_platform_is_virtual("leaf-05"))

    def test_a_missing_sample_is_not_assumed_virtual(self):
        self.assertFalse(hardware.hardware_platform_is_virtual("absent"))

    # ---------- the verdict that was wrong ----------
    def test_a_healthy_virtual_switch_is_no_longer_unknown(self):
        self.write_sample("vx-01", virt_marker="kvm")
        self.assertEqual(self.grade("vx-01"), "EXCELLENT")

    def test_the_same_sample_on_physical_hardware_stays_unknown(self):
        """Absent ASIC/PSU readings on a real switch remain a real gap."""
        self.write_sample("hw-01", virt_marker="none",
                          sensors=PHYSICAL_SENSORS)
        self.assertEqual(self.grade("hw-01"), "UNKNOWN")

    # ---------- what the exemption must not hide ----------
    def test_a_virtual_switch_still_reports_a_memory_collection_failure(self):
        self.write_sample("vx-02", virt_marker="kvm", memory=False)
        self.assertEqual(self.grade("vx-02"), "UNKNOWN")

    def test_a_virtual_switch_still_reports_a_cpu_collection_failure(self):
        self.write_sample("vx-03", virt_marker="kvm", cpu=False)
        self.assertEqual(self.grade("vx-03"), "UNKNOWN")

    def test_a_virtual_switch_with_stopped_fans_is_still_critical(self):
        self.write_sample("vx-04", virt_marker="kvm", sensors=(
            "cumulus_vx_cpld-isa-0000\n"
            "Adapter: ISA adapter\n"
            "fan1:           0 RPM  (min = 2500 RPM, max = 29000 RPM)\n"
            "fan2:           0 RPM  (min = 2500 RPM, max = 29000 RPM)\n"
        ))
        self.assertEqual(self.grade("vx-04"), "CRITICAL")

    def test_a_virtual_switch_under_memory_pressure_is_still_warned(self):
        self.write_sample("vx-05", virt_marker="kvm", available="0.3Gi")
        self.assertIn(self.grade("vx-05"), ("WARNING", "CRITICAL"))

    def test_a_virtual_switch_that_does_report_a_temperature_is_graded_on_it(self):
        """The exemption skips absent readings only, never present ones."""
        self.write_sample("vx-06", virt_marker="kvm", sensors=(
            VX_SENSORS + "Core 0:      +99.0°C  (high = +80.0°C)\n"))
        self.assertEqual(self.grade("vx-06"), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
