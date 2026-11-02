"""Regression for Matt's inetsw2: FAN3/1 absent despite a positive sensor RPM."""
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
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_alerts
import generate_hardware_html as hardware
from hardware_fans import evaluate_fan_health, FAN_START, FAN_END, FAN_SOURCE
from test_hardware_power_status import SENSORS, section

REPORTED_FANS = '''Name    Fan State  Current Speed (RPM)  Max Speed  Min Speed  Fan Direction
-------- --------- -------------------- ---------- ---------- -------------
FAN1/1   ok        10540                22000      2200       F2B
FAN2/1   ok        10982                22000      2200       F2B
FAN3/1   absent    N/A                  N/A        N/A        N/A
FAN4/1   ok        10374                22000      2200       F2B
PSU1/FAN ok        8112                 16000      2500       F2B
PSU2/FAN ok        8120                 16000      2500       F2B
'''
HEALTHY_FANS = REPORTED_FANS.replace('absent    N/A                  N/A        N/A        N/A',
                                     'ok        10320                22000      2200       F2B')
POWER_OK = section('PSU1 psu ok\nPSU2 psu ok')
PHANTOM_RPM = 'Chassis Fan Drawer-3: 10320 RPM\n'


def fan_section(table, status='OK', closed=True):
    return f'{FAN_START}\n{FAN_SOURCE}{status}\n{table}\n' + (FAN_END if closed else '') + '\n'


class FanStateTests(unittest.TestCase):
    def test_reported_absent_fan_overrides_positive_sensor_rpm(self):
        result = evaluate_fan_health(fan_section(REPORTED_FANS) + PHANTOM_RPM)
        self.assertEqual(result['grade'], 'CRITICAL')
        self.assertTrue(result['complete'])
        self.assertEqual(result['summary'], 'FAN3/1: absent')
        self.assertEqual(len(result['fans']), 6)
        fan = next(f for f in result['fans'] if f['name'] == 'FAN3/1')
        self.assertEqual(fan['grade'], 'CRITICAL')
        self.assertIsNone(fan['rpm'])

    def test_parent_environment_state_also_overrides_sensor_rpm(self):
        result = evaluate_fan_health(section('FAN3/1 fan absent') + PHANTOM_RPM)
        self.assertEqual(result['grade'], 'CRITICAL')
        self.assertIsNone(result['fans'][0]['rpm'])

    def test_parent_state_uses_unambiguous_current_sensor_aliases(self):
        raw = section('FAN3/1 fan ok\nPSU1/FAN fan ok') + PHANTOM_RPM + 'PSU-1(L) Fan 1: 8112 RPM\n'
        result = evaluate_fan_health(raw)
        self.assertEqual(result['grade'], 'EXCELLENT')
        self.assertEqual([f['rpm'] for f in result['fans']], [10320, 8112])

    def test_healthy_then_stopped_slow_or_out_of_platform_limits(self):
        self.assertEqual(evaluate_fan_health(fan_section(HEALTHY_FANS))['grade'], 'EXCELLENT')
        for rpm in ('0', '2000', '3000', '23000'):
            with self.subTest(rpm=rpm):
                result = evaluate_fan_health(fan_section(HEALTHY_FANS.replace('10320', rpm)))
                self.assertEqual(result['grade'], 'CRITICAL')
                self.assertIn('FAN3/1:', result['summary'])

    def test_platform_limits_prevent_generic_rpm_false_alarm(self):
        raw = fan_section('FAN1/1 ok 2500 22000 2200 F2B\nFAN2/1 ok 2500 22000 2200 F2B')
        result = evaluate_fan_health(raw, {'fan_rpm_critical': 3000, 'fan_rpm_warning': 4000})
        self.assertEqual(result['grade'], 'EXCELLENT')

    def test_partial_unrecognized_and_malformed_data_cannot_look_healthy(self):
        cases = [fan_section(HEALTHY_FANS, status='ERROR'), fan_section(HEALTHY_FANS, closed=False),
                 fan_section(''), fan_section('FAN1/1 mystery 9000 22000 2200 F2B'),
                 fan_section('FAN1/1 ok N/A 22000 2200 F2B'), fan_section('FAN1/1 ok'),
                 fan_section(HEALTHY_FANS + 'FAN1/1 ok 10540 22000 2200 F2B'),
                 fan_section(HEALTHY_FANS + FAN_SOURCE + 'ERROR')]
        for raw in cases:
            with self.subTest(raw=raw):
                result = evaluate_fan_health(raw + PHANTOM_RPM)
                self.assertIsNone(result['grade'])
                self.assertFalse(result['complete'])

    def test_failure_survives_timeout_or_conflicting_parent_state(self):
        raw = fan_section(REPORTED_FANS, status='ERROR', closed=False)
        self.assertEqual(evaluate_fan_health(raw)['grade'], 'CRITICAL')
        raw = section('FAN3/1 fan absent') + fan_section(HEALTHY_FANS)
        result = evaluate_fan_health(raw)
        self.assertEqual(result['grade'], 'CRITICAL')
        self.assertFalse(result['complete'])
        for state in ('absent', 'bad'):
            result = evaluate_fan_health(fan_section(f'FAN3/1 {state}', status='ERROR', closed=False))
            self.assertEqual(result['grade'], 'CRITICAL')
            self.assertFalse(result['complete'])

    def test_optional_absent_psu_fan_needs_confirmed_optional_psu(self):
        fans = fan_section('FAN1/1 ok 9000 22000 2200 F2B\nPSU2/FAN absent N/A N/A N/A N/A')
        self.assertEqual(evaluate_fan_health(fans)['grade'], 'CRITICAL')
        power = section('PSU1 psu ok\nPSU2 psu absent\npolicy ps_r_policy ok : Good PSUs - 1 :: Required PSUs - 1')
        result = evaluate_fan_health(power + fans)
        self.assertEqual(result['grade'], 'EXCELLENT')
        self.assertTrue(result['fans'][1]['optional'])

    def test_legacy_and_virtual_current_rpms_still_work(self):
        self.assertEqual(evaluate_fan_health(PHANTOM_RPM)['grade'], 'EXCELLENT')
        raw = 'PLATFORM_VIRT: kvm\n' + fan_section('', status='UNAVAILABLE') + PHANTOM_RPM
        self.assertEqual(evaluate_fan_health(raw)['grade'], 'EXCELLENT')
        self.assertIsNone(evaluate_fan_health(raw.replace('kvm', 'none'))['grade'])


class FanPipelineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.raw = self.root / 'monitor-results/hardware-data/inetsw2_hardware.txt'
        self.raw.parent.mkdir(parents=True)
        (self.root / 'notifications.yaml').write_text('notifications:\n  enabled: true\nfrequency:\n  min_interval_minutes: 0\n  retry_interval_minutes: 0\n')
        (self.root / 'devices.yaml').write_text('devices: {}\n')

    def test_current_fan_state_overrides_history_in_all_report_outputs(self):
        self.raw.write_text(SENSORS + POWER_OK + fan_section(REPORTED_FANS) + PHANTOM_RPM)
        history = {'fans': {'Chassis Fan Drawer-3': 10320}}
        self.assertEqual(hardware.calculate_device_health_grade('inetsw2', history), 'CRITICAL')
        with mock.patch.object(hardware, 'read_asset_snapshot', return_value=({}, 0, False)), \
                mock.patch.object(hardware, 'read_collection_outcomes', return_value=None), \
                mock.patch.object(hardware, 'fresh_history_entry', return_value=history), \
                mock.patch.object(hardware, 'is_current_collection', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()):
            hardware.generate_hardware_html()
        results = self.root / 'monitor-results'
        page = (results / 'hardware-analysis.html').read_text()
        details = json.loads(re.search(r'window.HW_DETAILS = (.*?);</script>', page)[1])['inetsw2']
        self.assertEqual(details['health'], 'CRITICAL')
        self.assertEqual(details['fan_health']['summary'], 'FAN3/1: absent')
        self.assertNotIn('Chassis Fan Drawer-3', [f['name'] for f in details['fans']])
        summary = json.loads((results / 'summary/hardware-summary.json').read_text())
        self.assertEqual(summary['critical'], 1)
        exported = json.loads((results / 'export/hardware.json').read_text())['rows'][0]
        self.assertEqual(exported['fan_status'], 'CRITICAL')
        self.assertIn('FAN3/1=absent', exported['fan_states'])
        rows = list(csv.DictReader(io.StringIO((results / 'export/hardware.csv').read_text())))
        self.assertEqual(rows[0]['fan_status_detail'], 'FAN3/1: absent')
        recorded = json.loads((results / 'hardware_history.json').read_text())
        self.assertEqual(recorded['hardware_history']['inetsw2'][-1]['overall_grade'], 'CRITICAL')

    def test_history_rpm_cannot_hide_current_stopped_or_missing_sensors(self):
        history = {'fans': {'Chassis Fan Drawer-3': 10320}}
        self.raw.write_text(SENSORS.replace('8000 RPM', '0 RPM').replace('8100 RPM', '0 RPM') + POWER_OK)
        self.assertEqual(hardware.calculate_device_health_grade('inetsw2', history), 'CRITICAL')
        self.raw.write_text(re.sub(r'^.*RPM\n', '', SENSORS, flags=re.M) + POWER_OK)
        self.assertEqual(hardware.calculate_device_health_grade('inetsw2', history), 'UNKNOWN')

    def test_fault_deduplicates_and_requires_observed_recovery(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        with mock.patch.object(checker, 'send_notification', return_value=True) as send:
            self.raw.write_text(fan_section(HEALTHY_FANS))
            checker.check_hardware_alerts('inetsw2')
            send.assert_not_called()
            for _ in range(2):
                self.raw.write_text(fan_section(REPORTED_FANS) + PHANTOM_RPM)
                checker.check_hardware_alerts('inetsw2')
            self.assertEqual(send.call_count, 1)
            self.assertIn('FAN3/1: absent', send.call_args.args[1])
            self.assertEqual(send.call_args.args[2], 'CRITICAL')
            for raw in [fan_section('', status='ERROR') + PHANTOM_RPM,
                        fan_section(HEALTHY_FANS, status='ERROR'),
                        fan_section(re.sub(r'^FAN3/1.*\n', '', HEALTHY_FANS, flags=re.M))]:
                self.raw.write_text(raw)
                checker.check_hardware_alerts('inetsw2')
            self.assertEqual(send.call_count, 1)
            self.raw.write_text(fan_section(HEALTHY_FANS))
            checker.check_hardware_alerts('inetsw2')
            self.assertEqual(send.call_count, 2)
            self.assertEqual(send.call_args.args[2], 'RECOVERED')
            self.assertEqual(checker.get_alert_state('inetsw2', 'fan_speed'), 'OK')

    def test_alert_delivery_retries_and_stale_data_cannot_notify(self):
        checker = check_alerts.LLDPqAlerts(self.root)
        self.raw.write_text(fan_section(REPORTED_FANS))
        with mock.patch.object(checker, 'send_notification', return_value=False) as send:
            checker.check_hardware_alerts('inetsw2')
            checker.check_hardware_alerts('inetsw2')
            self.assertEqual(send.call_count, 2)
            self.assertEqual(checker.get_alert_state('inetsw2', 'fan_speed'), 'UNKNOWN')
            checker.run_manifest = {'pipeline_complete': True, 'pipeline_started_at': time.time() + 60,
                                    'completed_at': '2030-01-01T00:00:00+00:00'}
            with contextlib.redirect_stdout(io.StringIO()):
                checker.check_hardware_alerts('inetsw2')
            self.assertEqual(send.call_count, 2)
            self.assertTrue(checker.had_error)


class FanCollectorTests(unittest.TestCase):
    def test_detailed_fan_command_is_bounded_and_records_collection_failure(self):
        source = (Path(__file__).parent / 'monitor.sh').read_text()
        start = source.index('        echo "' + FAN_START + '"')
        block = source[start:source.index('        echo "HARDWARE_HEALTH:"', start)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nv = root / 'nv'
            nv.write_text('#!/bin/sh\nprintf "FAN3/1 absent N/A N/A N/A N/A\\n"\nexit "${NV_RC:-0}"\n')
            nv.chmod(0o755)
            helper = '_lldpq_run_bounded() { printf "%s\\n" "$*" > "$CALLS"; "$@"; }\n'
            for rc, status in [(0, 'OK'), (1, 'ERROR'), (124, 'ERROR')]:
                result = subprocess.run(['/bin/sh'], input=helper + block, text=True, capture_output=True,
                                        env={'PATH': str(root), 'CALLS': str(root / 'calls'), 'NV_RC': str(rc)}, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'calls').read_text().strip(), 'nv show platform environment fan')
                self.assertIn(FAN_SOURCE + status, result.stdout)
                self.assertEqual(evaluate_fan_health(result.stdout)['grade'], 'CRITICAL')
            nv.unlink()
            result = subprocess.run(['/bin/sh'], input=helper + block, text=True, capture_output=True,
                                    env={'PATH': str(root)}, timeout=5)
            self.assertIn(FAN_SOURCE + 'UNAVAILABLE', result.stdout)
            self.assertIsNone(evaluate_fan_health(result.stdout)['grade'])
