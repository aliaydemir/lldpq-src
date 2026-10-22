"""Exercise IPv6 deployment and persisted upgrade jobs without real devices.

The CGI functions, inventory locks, artifact hashes, alias publication, and job
save/load/resume logic run against a temporary filesystem. Only subprocesses
that would touch a host/device are mocked; bash syntax checks run locally.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lldpq'))


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.collector = self.root / 'collector'
        self.web = self.root / 'web'
        self.base = self.collector / 'sw-base'
        self.uploads = self.web / 'provision-uploads'
        self.generated = self.web / 'generated_config_folder'
        for directory in (self.base, self.uploads, self.generated):
            directory.mkdir(parents=True)
        self.devices = [
            {'ip': '2001:db8::10', 'hostname': 'leaf-v6', 'username': 'cumulus',
             'mac': 'aa:bb:cc:dd:ee:10', 'dhcp': False},
            {'ip': '192.0.2.10', 'hostname': 'leaf-v4', 'username': 'cumulus',
             'mac': 'aa:bb:cc:dd:ee:11', 'dhcp': False},
            {'ip': 'fe80::12%eth0', 'hostname': 'leaf-link', 'username': 'cumulus',
             'mac': 'aa:bb:cc:dd:ee:12', 'dhcp': False},
        ]
        self.inventory = self.web / 'inventory.json'
        self.inventory.write_text(json.dumps({'bindings': self.devices}))
        (self.collector / 'devices.yaml').write_text('devices: {}\n')
        (self.base / 'tmux.conf').write_text('set -g history-limit 5000\n')
        for device in self.devices:
            (self.generated / (device['hostname'] + '.yaml')).write_text('set: []\n')
        self.image_name = 'cumulus-linux-5.16.0-mlx-amd64.bin'
        (self.uploads / self.image_name).write_bytes(b'fake image contents\n')
        self.script = self.web / 'cumulus-ztp.sh'
        script = (ROOT / 'html' / 'cumulus-ztp.sh').read_text()
        script = script.replace('__IMAGE_SERVER_IP__', '192.0.2.250')
        script = script.replace('__TARGET_OS_VERSION__', '5.16.0')
        script = script.replace('KEY=""', 'KEY="ssh-ed25519 AAAA test"')
        self.script.write_text(script)
        self.original_script = script
        source = (ROOT / 'html' / 'provision-api.sh').read_text()
        body = source.split("python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
            '# ======================== ROUTER ========================', 1)[0]
        environment = {'LLDPQ_DIR': str(self.collector), 'WEB_ROOT': str(self.web),
                       'BASE_CONFIG_DIR': str(self.base), 'PROVISION_UPLOAD_DIR': str(self.uploads),
                       'ZTP_SCRIPT_FILE': str(self.script), 'PROVISION_SERVER_IP': '192.0.2.250',
                       'DHCP_HOSTS_FILE': str(self.root / 'no-dhcpd.hosts'),
                       'DHCP_CONF_FILE': str(self.root / 'no-dhcpd.conf')}
        patch = mock.patch.dict(os.environ, environment)
        patch.start()
        self.addCleanup(patch.stop)
        self.api = {}
        exec(compile(body, 'provision-api.sh', 'exec'), self.api)
        self.api.update(UPGRADE_JOBS_DIR=str(self.root / 'upgrade-jobs'),
                        DISCOVERY_JOBS_DIR=str(self.root / 'discovery-jobs'))
        self.api['launch_upgrade_worker'] = mock.Mock(return_value=123)
        self.calls = []
        self.real_run = subprocess.run
        self.remote_version = '5.15.0'
        self.remote_operation = ''
        self.remote_identity_ok = True
        self.scp_ok = True
        self.http_ok = True
        patch = mock.patch('subprocess.run', side_effect=self.run_command)
        patch.start()
        self.addCleanup(patch.stop)

    def run_command(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if argv[:4] == ['/bin/bash', '--noprofile', '--norc', '-n']:
            return self.real_run(argv, **kwargs)
        if argv[:2] in (['sudo', 'chown'], ['sudo', 'chmod']):
            return subprocess.CompletedProcess(argv, 0, '', '')
        if 'scp' in argv:
            return subprocess.CompletedProcess(argv, 0 if self.scp_ok else 1, '', 'copy failed')
        if 'ssh' in argv:
            script = (kwargs.get('input') or '')
            if 'EXPECTED_MAC=' in script and not self.remote_identity_ok:
                return subprocess.CompletedProcess(argv, 42, '', 'management MAC identity mismatch')
            if 'curl --globoff' in script and not self.http_ok:
                return subprocess.CompletedProcess(argv, 22, '', 'HTTP resource unreachable')
            if 'LLDPQ_HTTP_OK' in script:
                output = 'LLDPQ_HTTP_OK\n'
            elif 'LLDPQ_UPGRADE_PREPARED' in script:
                self.remote_operation = argv[-1]
                output = 'LLDPQ_UPGRADE_PREPARED\n'
            elif 'LLDPQ_UPGRADE_DISPATCHING' in script:
                output = 'LLDPQ_UPGRADE_DISPATCHING\nLLDPQ_UPGRADE_STARTED\n'
            elif 'LLDPQ_CONFIG_OK' in script:
                output = 'LLDPQ_CONFIG_OK\n'
            elif 'LLDPQ_BASE_OK' in script:
                output = 'LLDPQ_BASE_OK\nLLDPQ_ZTP_OK\n'
            elif 'echo OK;' in argv[-1]:
                output = ('OK\n' + self.remote_version + '\nSTARTUP_OK\nBASE_PENDING\n'
                          'UPGRADE_OPERATION=' + self.remote_operation + '\n')
            else:
                output = 'ok\n'
            return subprocess.CompletedProcess(argv, 0, output, '')
        raise AssertionError(f'Unexpected external command: {argv}')

    def action(self, name, payload):
        self.api['POST_DATA'] = json.dumps(payload)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            self.api[name]()
        return json.loads(output.getvalue().splitlines()[-1])

    def upgrade_payload(self, **overrides):
        value = {'devices': [self.devices[0]], 'target_version': '5.16.0',
                 'image_name': self.image_name, 'server_ip': '2001:db8::250',
                 'base_config_after': False}
        value.update(overrides)
        return value

    def start_job(self, **overrides):
        result = self.action('action_upgrade_start', self.upgrade_payload(**overrides))
        self.assertTrue(result['success'], result)
        return result['job']

    def test_target_lists_canonicalize_expanded_ipv6_before_ui_status_keying(self):
        (self.collector / 'devices.yaml').write_text(
            'devices:\n  "2001:0DB8:0:0:0:0:0:10": leaf-v6 @leaf\n'
            '  switch.example.test: leaf-dns @leaf\n')
        listed = self.action('action_list_devices', {})
        candidates = self.action('action_upgrade_candidates', {})
        for response in (listed, candidates):
            by_name = {row['hostname']: row['ip'] for row in response['devices']}
            self.assertEqual(by_name['leaf-v6'], '2001:db8::10')
            self.assertEqual(by_name['leaf-dns'], 'switch.example.test')

    def test_empty_inventory_upgrade_candidates_remains_valid(self):
        (self.collector / 'devices.yaml').write_text('devices:\n')
        result = self.action('action_upgrade_candidates', {})
        self.assertTrue(result['success'], result)
        self.assertEqual(result['devices'], [])

    def test_base_action_supports_ipv4_ipv6_and_scoped_scp(self):
        result = self.action('action_deploy_base_config', {'devices': self.devices,
                              'files': ['tmux.conf'], 'disable_ztp': False})
        self.assertEqual(result['summary'], {'ok': 3, 'fail': 0, 'total': 3}, result)
        destinations = [argv[-1] for argv, _ in self.calls if 'scp' in argv]
        self.assertTrue(any(value.startswith('cumulus@[2001:db8::10]:/tmp/') for value in destinations))
        self.assertTrue(any(value.startswith('cumulus@[fe80::12%eth0]:/tmp/') for value in destinations))
        self.assertTrue(any(value.startswith('cumulus@192.0.2.10:/tmp/') for value in destinations))
        ssh = [argv for argv, _ in self.calls if 'ssh' in argv]
        self.assertTrue(any('cumulus@2001:db8::10' in argv for argv in ssh))
        self.assertTrue(any('cumulus@fe80::12%eth0' in argv for argv in ssh))
        self.assertFalse(any('sudo ztp -d' in (kwargs.get('input') or '') for _, kwargs in self.calls))

    def test_base_device_identity_failure_never_copies_or_installs(self):
        self.remote_identity_ok = False
        result = self.action('action_deploy_base_config', {'devices': [self.devices[0]], 'files': ['tmux.conf']})
        self.assertEqual(result['summary']['fail'], 1)
        self.assertIn('Identity verification failed', result['results'][0]['error'])
        self.assertFalse(any('scp' in argv for argv, _ in self.calls))

    def test_base_copy_failure_cleans_stage_and_never_installs(self):
        self.scp_ok = False
        result = self.action('action_deploy_base_config', {'devices': [self.devices[0]], 'files': ['tmux.conf']})
        self.assertEqual(result['summary']['fail'], 1)
        self.assertTrue(any('rm -rf -- /tmp/lldpq-base-' in argv[-1] for argv, _ in self.calls))
        self.assertFalse(any('LLDPQ_BASE_OK' in (kwargs.get('input') or '') for _, kwargs in self.calls))

    def test_identity_authorization_normalizes_ipv6_and_rejects_stale_identity(self):
        target = dict(self.devices[0], ip='2001:0db8:0:0:0:0:0:10')
        actual = self.api['canonicalize_inventory_target'](target)
        self.assertEqual(actual['ip'], '2001:db8::10')
        with self.assertRaisesRegex(ValueError, 'MAC changed'):
            self.api['canonicalize_inventory_target'](dict(target, expected_mac='aa:bb:cc:dd:ee:ff'))
        with self.assertRaisesRegex(ValueError, 'no longer matches'):
            self.api['canonicalize_inventory_target'](dict(target, ip='2001:db8::99'))
        with self.assertRaisesRegex(ValueError, 'Invalid device IP'):
            self.api['canonicalize_inventory_target'](dict(self.devices[2], ip='fe80::12'))

    def test_equivalent_ipv6_mutations_share_lock_file(self):
        with self.api['device_mutation_lock']('2001:db8::10'):
            pass
        with self.api['device_mutation_lock']('2001:0db8:0:0:0:0:0:10'):
            pass
        self.assertEqual(len(list((self.root / 'discovery-jobs').glob('.device-deploy-*.lock'))), 1)

    def test_generated_config_ipv6_uses_exact_ssh_stdin_without_http_server(self):
        self.api['get_server_ip'] = mock.Mock(side_effect=AssertionError('IPv6 config must not require HTTP'))
        content = b'set: []\n# literal $(touch /tmp/not-executed)\n'
        (self.generated / 'leaf-v6.yaml').write_bytes(content)
        result = self.action('action_deploy_generated_config', {'devices': [self.devices[0]]})
        self.assertEqual(result['summary']['ok'], 1, result)
        script = next(kwargs['input'] for _, kwargs in self.calls if 'LLDPQ_CONFIG_OK' in (kwargs.get('input') or ''))
        self.assertNotIn('curl ', script)
        self.assertIn(base64.b64encode(content).decode(), script)
        self.assertNotIn('touch /tmp/not-executed', script)
        self.assertLess(script.index('EXPECTED_MAC='), script.index('sudo nv config replace'))

    def test_generated_config_ipv4_keeps_http_transport(self):
        result = self.action('action_deploy_generated_config', {'devices': [self.devices[1]]})
        self.assertEqual(result['summary']['ok'], 1, result)
        script = next(kwargs['input'] for _, kwargs in self.calls if 'LLDPQ_CONFIG_OK' in (kwargs.get('input') or ''))
        self.assertIn('http://192.0.2.250/generated_config_folder/leaf-v4.yaml', script)
        self.assertIn('curl -sf', script)

    def test_generated_config_duplicate_equivalent_targets_are_rejected(self):
        result = self.action('action_deploy_generated_config', {'devices': [
            self.devices[0], dict(self.devices[0], ip='2001:0db8:0:0:0:0:0:10')],
            'server_ip': '192.0.2.250'})
        self.assertFalse(result['success'])
        self.assertIn('Duplicate deploy target', result['error'])
        self.assertFalse(any('ssh' in argv for argv, _ in self.calls))

    def test_upgrade_precheck_accepts_ipv6_and_remains_read_only(self):
        result = self.action('action_upgrade_precheck', self.upgrade_payload())
        self.assertTrue(result['success'], result)
        self.assertTrue(result['results'][0]['precheck_ok'], result)
        self.assertEqual(result['results'][0]['ip'], '2001:db8::10')
        self.assertFalse(any('onie-install -fa' in (kwargs.get('input') or '') for _, kwargs in self.calls))
        self.assertFalse(any('nv config save' in (kwargs.get('input') or '') for _, kwargs in self.calls))

    def test_upgrade_precheck_reports_http_failure_before_launch(self):
        self.http_ok = False
        result = self.action('action_upgrade_precheck', self.upgrade_payload())
        self.assertFalse(result['results'][0]['precheck_ok'])
        self.assertIn('Image download is not reachable', result['results'][0]['checks'][0])
        self.api['launch_upgrade_worker'].assert_not_called()

    def test_upgrade_launch_checks_both_resources_before_config_save_or_dispatch(self):
        job = self.start_job()
        job = self.api['update_upgrade_job'](job)
        self.api['save_upgrade_job'](job)
        self.http_ok = False
        job = self.api['update_upgrade_job'](self.api['load_upgrade_job'](job['id']))
        self.assertEqual(job['devices'][0]['status'], 'failed')
        script = next(kwargs['input'] for _, kwargs in self.calls if 'LLDPQ_UPGRADE_DISPATCHING' in (kwargs.get('input') or ''))
        self.assertIn('for resource in "$IMAGE_URL" "$ZTP_URL"', script)
        self.assertLess(script.index('curl --globoff'), script.index('sudo nv config save'))
        self.assertLess(script.index('curl --globoff'), script.index('echo LLDPQ_UPGRADE_DISPATCHING'))

    def test_upgrade_pins_ipv6_override_without_changing_saved_script(self):
        job = self.start_job(server_ip='[2001:0db8:0:0:0:0:0:250]:8080')
        self.assertEqual(job['server_ip'], '[2001:db8::250]:8080')
        self.assertEqual(self.script.read_text(), self.original_script)
        pinned = Path(self.api['upgrade_ztp_artifact_path'](job)).read_text()
        self.assertIn('IMAGE_SERVER_HOSTNAME="[2001:db8::250]:8080"', pinned)
        self.api['verify_upgrade_job_ztp'](job)
        self.assertEqual(self.api['load_upgrade_job'](job['id'])['devices'][0]['ip'], '2001:db8::10')
        self.assertTrue(job['ready'])
        self.assertTrue(job['aliases_published'])
        self.api['launch_upgrade_worker'].assert_called_once_with(job['id'])
        self.assertFalse(any('ssh' in argv for argv, _ in self.calls))

    def test_legacy_saved_template_is_adapted_only_in_pinned_artifact(self):
        legacy = self.original_script
        legacy = re.sub(r'^    IMAGE_SERVER_PING_TARGET=.*$',
                        '    IMAGE_SERVER_PING_TARGET=${IMAGE_SERVER_HOSTNAME%%:*}',
                        legacy, flags=re.MULTILINE)
        legacy = legacy.replace('ping "${family_args[@]}" "$target"', 'ping "$target"')
        self.script.write_text(legacy)
        job = self.start_job(server_ip='[2001:db8::250]:8080')
        self.assertEqual(self.script.read_text(), legacy)
        pinned = Path(self.api['upgrade_ztp_artifact_path'](job)).read_text()
        self.assertIn('IMAGE_SERVER_PING_TARGET="2001:db8::250"', pinned)
        self.assertIn('if ping -6 "$target" -c2 --no-vrf-switch', pinned)
        self.assertNotIn('IMAGE_SERVER_PING_TARGET=${IMAGE_SERVER_HOSTNAME%%:*}', pinned)

    def test_unknown_custom_ping_template_requires_update_before_ipv6_upgrade(self):
        custom = self.original_script.replace('ping "${family_args[@]}" "$target"', 'custom_ping "$target"')
        self.script.write_text(custom)
        result = self.action('action_upgrade_start', self.upgrade_payload())
        self.assertFalse(result['success'])
        self.assertIn('Update the post-install script ping helper', result['error'])
        self.assertEqual(self.script.read_text(), custom)
        self.api['launch_upgrade_worker'].assert_not_called()

    def test_upgrade_ipv4_job_and_same_server_preserve_existing_behavior(self):
        job = self.start_job(devices=[self.devices[1]], server_ip='192.0.2.250')
        self.assertEqual(job['server_ip'], '192.0.2.250')
        self.assertEqual(job['devices'][0]['ip'], '192.0.2.10')
        self.api['validate_upgrade_job_state'](job, job['id'])

    def test_upgrade_rejects_duplicate_equivalent_addresses_before_job_creation(self):
        result = self.action('action_upgrade_start', self.upgrade_payload(devices=[
            self.devices[0], dict(self.devices[0], ip='2001:0db8:0:0:0:0:0:10')]))
        self.assertFalse(result['success'])
        self.assertIn('Duplicate upgrade device IP', result['error'])
        self.api['launch_upgrade_worker'].assert_not_called()

    def test_upgrade_rejects_invalid_image_server_before_any_remote_operation(self):
        for server in ('fe80::1%eth0', '[fe80::1%eth0]:8080', '::', '[2001:db8::1]:70000'):
            with self.subTest(server=server):
                result = self.action('action_upgrade_start', self.upgrade_payload(server_ip=server))
                self.assertFalse(result['success'])
                self.assertIn('Invalid image server', result['error'])
        self.api['launch_upgrade_worker'].assert_not_called()
        self.assertFalse(any('ssh' in argv for argv, _ in self.calls))

    def test_upgrade_resume_reloads_ipv6_job_and_retains_pinned_artifacts(self):
        job = self.start_job()
        self.api['launch_upgrade_worker'].reset_mock()
        job['worker_heartbeat'] -= 60
        job['worker_started_at'] -= 60
        self.api['save_upgrade_job'](job)
        self.api['resume_upgrade_workers']()
        self.api['launch_upgrade_worker'].assert_called_once_with(job['id'])
        restored = self.api['list_upgrade_jobs'](unfinished_only=True, strict=True)
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]['devices'][0]['ip'], '2001:db8::10')
        self.api['verify_upgrade_job_ztp'](restored[0])

    def test_upgrade_worker_claim_launch_and_completion_over_ipv6(self):
        job = self.start_job(base_config_after=True)
        job = self.api['update_upgrade_job'](job)
        self.assertEqual(job['devices'][0]['status'], 'starting')
        self.api['save_upgrade_job'](job)
        job = self.api['update_upgrade_job'](self.api['load_upgrade_job'](job['id']))
        self.assertEqual(job['devices'][0]['status'], 'waiting_reboot')
        self.api['save_upgrade_job'](job)
        launches = [(argv, kw) for argv, kw in self.calls if 'LLDPQ_UPGRADE_DISPATCHING' in (kw.get('input') or '')]
        self.assertEqual(len(launches), 1)
        argv, kwargs = launches[0]
        self.assertIn('cumulus@2001:db8::10', argv)
        self.assertIn(shlex.quote('http://[2001:db8::250]/' + self.image_name), argv)
        self.assertIn(shlex.quote('http://[2001:db8::250]/' + job['ztp_artifact']), argv)
        self.assertLess(kwargs['input'].index('EXPECTED_MAC='), kwargs['input'].index('sudo nv config save'))
        self.remote_version = '5.16.0'
        job = self.api['update_upgrade_job'](self.api['load_upgrade_job'](job['id']))
        self.api['save_upgrade_job'](job)
        self.assertTrue(job['complete'])
        self.assertEqual(job['devices'][0]['status'], 'done')
        self.assertTrue(any('scp' in argv for argv, _ in self.calls))

    def test_upgrade_worker_does_not_launch_after_inventory_address_changes(self):
        job = self.start_job()
        job = self.api['update_upgrade_job'](job)
        self.api['save_upgrade_job'](job)
        self.inventory.write_text(json.dumps({'bindings': [dict(self.devices[0], ip='2001:db8::99')]}))
        self.calls.clear()
        job = self.api['update_upgrade_job'](self.api['load_upgrade_job'](job['id']))
        self.assertEqual(job['devices'][0]['status'], 'starting')
        self.assertIn('no longer matches', job['devices'][0]['message'])
        self.assertFalse(any('ssh' in argv for argv, _ in self.calls))

    def test_failed_worker_launch_rolls_back_aliases_and_persists_blocked_job(self):
        self.api['launch_upgrade_worker'].side_effect = RuntimeError('worker unavailable')
        result = self.action('action_upgrade_start', self.upgrade_payload())
        self.assertFalse(result['success'])
        self.assertIn('no device upgrade was started', result['error'])
        jobs = self.api['list_upgrade_jobs'](strict=True)
        self.assertEqual(len(jobs), 1)
        self.assertTrue(jobs[0]['complete'])
        self.assertEqual(jobs[0]['devices'][0]['status'], 'blocked')
        for name in self.api['ONIE_ALIAS_NAMES']:
            self.assertFalse(os.path.lexists(self.web / name))
            self.assertFalse(os.path.lexists(self.uploads / name))
        self.assertEqual(self.script.read_text(), self.original_script)

    def test_persisted_job_rejects_equivalent_ipv6_duplicate_and_missing_scope(self):
        job = self.start_job()
        invalid = copy.deepcopy(job)
        invalid['devices'].append(dict(invalid['devices'][0], ip='2001:0db8:0:0:0:0:0:10'))
        with self.assertRaisesRegex(ValueError, 'duplicate upgrade device IP'):
            self.api['validate_upgrade_job_state'](invalid, invalid['id'])
        invalid = copy.deepcopy(job)
        invalid['devices'][0]['ip'] = 'fe80::10'
        with self.assertRaisesRegex(ValueError, 'invalid upgrade device IP'):
            self.api['validate_upgrade_job_state'](invalid, invalid['id'])


if __name__ == '__main__':
    unittest.main()
