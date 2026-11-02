"""PSU failure/redundancy regression from i04csw4; no device or webhook I/O."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_alerts
import generate_hardware_html as hardware
from hardware_environment import parse_platform_environment, START, END, SOURCE


# Includes the wrapped redundancy line in the reported CLI output. Fan and
# temperature absence for PSU3/4 must not hide the parent supplies' bad state.
REPORTED = '''Name                               Type         State
---------------------------------  -----------  -------------------------------------------------------
Asic-Temp-Sensor                    temperature  ok
CPU-Package-Sensor                  temperature  ok
FAN1                               led          green
FAN1/1                             fan          ok
PMIC-1-PSU-13V5-RAIL-IN1            voltage      ok
POWER                              led          amber
PSU1                               psu          ok
PSU1-Temp-Sensor                    temperature  ok
PSU1/FAN                           fan          ok
PSU2                               psu          ok
PSU2-Temp-Sensor                    temperature  ok
PSU2/FAN                           fan          ok
PSU3                               psu          bad
PSU3-Temp-Sensor                    temperature  absent
PSU3/FAN                           fan          absent
PSU4                               psu          bad
PSU4-Temp-Sensor                    temperature  absent
PSU4/FAN                           fan          absent
PSU-1L-12V-RAIL-OUT                 voltage      ok
PSU-2L-12V-RAIL-OUT                 voltage      ok
SYSTEM                             led          amber
ps_r_policy_check                  ps_r_policy  bad : Good PSUs - 2 :: PSU
redundancy Required PSUs - 4
'''
HEALTHY = REPORTED.replace('bad', 'ok').replace('absent', 'ok').replace('amber', 'green').replace('Good PSUs - 2', 'Good PSUs - 4')
SENSORS = '''PLATFORM_VIRT: none
__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:OK
HW_MGMT_CPU: 40.0
HW_MGMT_ASIC: 50.0
PSU-1L-220V Rail Pwr (in): 500 W
PSU-1L-12V Rail Pwr (out): 475 W
PSU-2L-220V Rail Pwr (in): 500 W
PSU-2L-12V Rail Pwr (out): 475 W
Chassis Fan Drawer-1 Tach 1: 8000 RPM
Chassis Fan Drawer-2 Tach 1: 8100 RPM
MEMORY_INFO:
__LLDPQ_HARDWARE_SOURCE_STATUS__:MEMORY:OK
Mem: 8Gi 1Gi 7Gi 0B 0B 7Gi
CPU_INFO:
__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:OK
0.1 0.1 0.1 1/100 123
CPU_CORES: 8
'''


def section(table, status='OK', closed=True):
    return f'{START}\n{SOURCE}{status}\n{table}\n' + (END + '\n' if closed else '')


class PowerParsingTests(unittest.TestCase):
    def test_reported_fault_is_critical_despite_healthy_rails_and_fans(self):
        power = parse_platform_environment(SENSORS + section(REPORTED))
        self.assertEqual(power['grade'], 'CRITICAL')
        self.assertTrue(power['complete'])
        self.assertEqual([p['name'] for p in power['psus']], ['PSU1', 'PSU2', 'PSU3', 'PSU4'])
        self.assertEqual(power['redundancy'][0]['good_psus'], 2)
        self.assertEqual(power['redundancy'][0]['required_psus'], 4)
        self.assertIn('PSU3: bad', power['summary'])
        self.assertIn('PSU4: bad', power['summary'])
        self.assertIn('2 good / 4 required', power['summary'])

    def test_good_supply_count_is_not_hardcoded_to_four(self):
        power = parse_platform_environment(section('PSU1 psu ok\nPSU2 psu ok\nps_r_policy_check ps_r_policy ok : Good PSUs - 2 :: Required PSUs - 2'))
        self.assertEqual(power['grade'], 'EXCELLENT')
        self.assertTrue(power['complete'])

    def test_optional_absent_slot_requires_an_affirmative_policy(self):
        data = 'PSU1 psu ok\nPSU2 psu absent\n'
        self.assertIsNone(parse_platform_environment(section(data))['grade'])
        power = parse_platform_environment(section(data + 'ps_r_policy_check ps_r_policy ok : Good PSUs - 1 :: Required PSUs - 1'))
        self.assertEqual(power['grade'], 'EXCELLENT')

    def test_unknown_partial_empty_and_failed_collections_never_look_healthy(self):
        cases = ['', section(''), section(HEALTHY, status='ERROR'),
                 section(HEALTHY, status='UNAVAILABLE'), section(HEALTHY, closed=False),
                 section('PSU1 psu mystery'), section('PSU1 psu ok\nPSU2 psu'),
                 section('PSU1 psu ok\nPSU1 psu ok'),
                 section('PSU1 psu ok\n' + SOURCE + 'ERROR'),
                 section('PSU1 psu ok\npolicy ps_r_policy ok : Good PSUs - 1 :: Required PSUs -')]
        for raw in cases:
            with self.subTest(raw=raw):
                result = parse_platform_environment(raw)
                self.assertIsNone(result['grade'])
                self.assertFalse(result['complete'])

    def test_explicit_fault_survives_partial_collection(self):
        power = parse_platform_environment(section('PSU3 psu bad', status='ERROR', closed=False))
        self.assertEqual(power['grade'], 'CRITICAL')
        self.assertFalse(power['complete'])

    def test_insufficient_count_overrides_ok_policy_word(self):
        data = 'PSU1 psu ok\npolicy ps_r_policy ok : Good PSUs - 1 :: Required PSUs - 2'
        self.assertEqual(parse_platform_environment(section(data))['grade'], 'CRITICAL')

    def test_led_only_warning_and_fault_grade(self):
        for state, expected in [('green', 'EXCELLENT'), ('amber', 'WARNING'), ('red', 'CRITICAL')]:
            with self.subTest(state=state):
                self.assertEqual(parse_platform_environment(section('PSU1 psu ok\nPOWER led ' + state))['grade'], expected)

    def test_unrelated_sensor_and_psu_rail_states_are_not_psu_records(self):
        result = parse_platform_environment(section('PSU1 psu ok\nPSU1-Temp-Sensor temperature absent\nPSU1/FAN fan absent\nPSU-1L-12V-RAIL-OUT voltage ok'))
        self.assertEqual(len(result['psus']), 1)
        self.assertEqual(result['grade'], 'EXCELLENT')


class PowerPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.raw = self.root / 'monitor-results/hardware-data/i04csw4_hardware.txt'
        self.raw.parent.mkdir(parents=True)
        (self.root / 'notifications.yaml').write_text('notifications:\n  enabled: true\nfrequency:\n  min_interval_minutes: 0\n  retry_interval_minutes: 0\n')
        (self.root / 'devices.yaml').write_text('devices: {}\n')

    def test_grading_rejects_reported_fault_even_at_95_percent_efficiency(self):
        self.raw.write_text(SENSORS + section(REPORTED))
        self.assertEqual(hardware.parse_psu_efficiency_from_hardware_file('i04csw4'), 95.0)
        self.assertEqual(hardware.calculate_device_health_grade('i04csw4', {}), 'CRITICAL')
        self.raw.write_text(SENSORS + section(HEALTHY))
        self.assertEqual(hardware.calculate_device_health_grade('i04csw4', {}), 'EXCELLENT')

    def test_physical_missing_power_status_is_unknown_but_vx_remains_healthy(self):
        self.raw.write_text(SENSORS)
        self.assertEqual(hardware.calculate_device_health_grade('i04csw4', {}), 'UNKNOWN')
        self.raw.write_text(SENSORS.replace('PLATFORM_VIRT: none', 'PLATFORM_VIRT: kvm') + section('', 'UNAVAILABLE'))
        self.assertEqual(hardware.calculate_device_health_grade('i04csw4', {}), 'EXCELLENT')

    def test_html_summary_export_and_history_share_the_critical_verdict(self):
        self.raw.write_text(SENSORS + section(REPORTED))
        with mock.patch.object(hardware, 'read_asset_snapshot', return_value=({}, 0, False)), \
                mock.patch.object(hardware, 'read_collection_outcomes', return_value=None), \
                mock.patch.object(hardware, 'is_current_collection', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            hardware.generate_hardware_html()
        results = self.root / 'monitor-results'
        page = (results / 'hardware-analysis.html').read_text()
        self.assertIn('data-status="critical"', page)
        self.assertIn('PSU3: bad', page)
        self.assertIn('2 good / 4 required', page)
        details = json.loads(re.search(r'window.HW_DETAILS = (.*?);</script>', page)[1])
        self.assertEqual(details['i04csw4']['power_status']['grade'], 'CRITICAL')
        summary = json.loads((results / 'summary/hardware-summary.json').read_text())
        self.assertEqual(summary['critical'], 1)
        self.assertEqual(summary['excellent'], 0)
        export = json.loads((results / 'export/hardware.json').read_text())
        self.assertEqual(export['rows'][0]['health'], 'CRITICAL')
        self.assertIn('PSU3=bad', export['rows'][0]['psus'])
        csv_rows = list(csv.DictReader(io.StringIO((results / 'export/hardware.csv').read_text())))
        self.assertEqual(csv_rows[0]['psu_status'], 'CRITICAL')
        history = json.loads((results / 'hardware_history.json').read_text())
        self.assertEqual(history['hardware_history']['i04csw4'][-1]['overall_grade'], 'CRITICAL')

    def test_alerts_deduplicate_preserve_fault_on_missing_data_and_recover(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        with mock.patch.object(checker, 'send_notification', return_value=True) as send:
            power_calls = lambda: [c for c in send.call_args_list if c.args[4] == 'power_supply']
            for table in (REPORTED, REPORTED):
                self.raw.write_text(section(table))
                checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len(power_calls()), 1)
            self.assertEqual(power_calls()[-1].args[2], 'CRITICAL')
            self.assertIn('PSU3: bad', power_calls()[-1].args[1])
            self.raw.write_text(section('', status='ERROR'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len(power_calls()), 1)
            self.assertTrue(checker.get_alert_state('i04csw4', 'power_supply').startswith('CRITICAL:'))
            # A policy or failed component disappearing is not proof of recovery.
            self.raw.write_text(section('PSU1 psu ok\nPSU2 psu ok'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len(power_calls()), 1)
            self.raw.write_text(section(HEALTHY))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len(power_calls()), 2)
            self.assertEqual(power_calls()[-1].args[2], 'RECOVERED')
            self.assertEqual(checker.get_alert_state('i04csw4', 'power_supply'), 'OK')

    def test_disabled_hardware_alerts_do_not_deliver(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        checker.config['alert_types'] = {'hardware_alerts': False}
        self.raw.write_text(section(REPORTED))
        with mock.patch.object(checker, 'send_notification') as send:
            checker.check_hardware_alerts('i04csw4')
        send.assert_not_called()

    def test_partial_warning_does_not_forget_an_earlier_critical_fault(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        with mock.patch.object(checker, 'send_notification', return_value=True) as send:
            for table in ('PSU1 psu ok\nPSU2 psu bad',
                          'PSU1 psu ok\nPOWER led amber',
                          'PSU1 psu ok\nPOWER led green'):
                self.raw.write_text(section(table))
                checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len([c for c in send.call_args_list if c.args[4] == 'power_supply']), 2)
            self.assertEqual(send.call_args.args[2], 'CRITICAL')
            self.assertIn('previous fault not fully rechecked: PSU2', send.call_args.args[1])
            self.assertIn('PSU2', checker.get_alert_state('i04csw4', 'power_supply'))
            self.raw.write_text(section('PSU1 psu ok\nPSU2 psu ok\nPOWER led green'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(send.call_args.args[2], 'RECOVERED')

    def test_escalation_bypasses_throttle_and_disabled_recovery_is_silent(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        checker.config['frequency'].update(min_interval_minutes=60, send_recovery=False)
        with mock.patch.object(checker, 'send_notification', return_value=True) as send:
            self.raw.write_text(section('PSU1 psu warning'))
            checker.check_hardware_alerts('i04csw4')
            self.raw.write_text(section('PSU1 psu bad'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(send.call_count, 2)
            self.assertEqual(send.call_args.args[2], 'CRITICAL')
            self.raw.write_text(section('PSU1 psu ok'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(send.call_count, 2)
            self.assertEqual(checker.get_alert_state('i04csw4', 'power_supply'), 'OK')
            self.raw.write_text(section('PSU1 psu bad'))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(send.call_count, 3)

    def test_initial_healthy_sample_is_silent_and_failed_delivery_retries(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        self.raw.write_text(section(HEALTHY))
        with mock.patch.object(checker, 'send_notification', return_value=False) as send:
            checker.check_hardware_alerts('i04csw4')
            send.assert_not_called()
            self.raw.write_text(section(REPORTED))
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(checker.get_alert_state('i04csw4', 'power_supply'), 'OK')
            checker.check_hardware_alerts('i04csw4')
            self.assertEqual(len([c for c in send.call_args_list if c.args[4] == 'power_supply']), 2)


class PowerCollectorTests(unittest.TestCase):
    def test_collector_publishes_bounded_success_failure_and_missing_states(self):
        source = (SCRIPT_DIR / 'monitor.sh').read_text()
        start = source.index('        echo "' + START + '"')
        end = source.index('        echo "__LLDPQ_PLATFORM_FANS_START__"', start)
        block = source[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nv = root / 'nv'
            nv.write_text('#!/bin/sh\nprintf "PSU1 psu ok\\n"\nexit "${NV_RC:-0}"\n')
            nv.chmod(0o755)
            calls = root / 'calls'
            helper = '_lldpq_run_bounded() { printf "%s\\n" "$*" > "$CALLS"; "$@"; }\n'
            for rc, expected in [(0, 'OK'), (1, 'ERROR'), (124, 'ERROR')]:
                result = subprocess.run(['/bin/sh'], input=helper + block, text=True,
                                        capture_output=True, env={'PATH': str(root), 'NV_RC': str(rc), 'CALLS': str(calls)}, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(SOURCE + expected, result.stdout)
                self.assertIn(START, result.stdout)
                self.assertIn(END, result.stdout)
                self.assertEqual(parse_platform_environment(result.stdout)['complete'], rc == 0)
                self.assertEqual(calls.read_text().strip(), 'nv show platform environment')
            nv.unlink()
            result = subprocess.run(['/bin/sh'], input=helper + block, text=True,
                                    capture_output=True, env={'PATH': str(root)}, timeout=5)
            self.assertIn(SOURCE + 'UNAVAILABLE', result.stdout)
            self.assertIsNone(parse_platform_environment(result.stdout)['grade'])
