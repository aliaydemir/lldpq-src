"""IPv6 management stays read-only to provisioning while IPv4 stays compatible.

Exercises actual extracted CGI functions with temporary files and mocked network
I/O; no SSH, ping, daemon or live device is used by these tests.
"""
import contextlib
import io
import ipaddress
import json
import os
import tempfile
from pathlib import Path
import re
import shlex
import socket
import subprocess
import types
import unittest
from unittest import mock
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
from lldpq.test_dhcp_multi_pool import ApiFixture, Emitted, ROOT, extract_source


def binding(ip='2001:db8::10', hostname='leaf-v6', **extra):
    return dict({'hostname': hostname, 'ip': ip, 'mac': '-', 'role': 'leaf',
                 'dhcp': False, 'inv_status': 'active'}, **extra)


class ManagementInventoryTests(ApiFixture):
    def setUp(self):
        super().setUp()
        self.devices = self.lldpq_dir / 'devices.yaml'
        self.devices.write_text('defaults:\n  username: cumulus\ndevices: {}\n')
        self.api.update(io=io)
        for name in ('render_inventory_devices_yaml', 'sync_bindings_to_devices_yaml',
                     'canonicalize_inventory_target', 'normalize_identity_mac',
                     'normalize_identity_serial', 'action_update_role', 'action_list_bindings'):
            exec(extract_source(name), self.api)

    def test_ipv6_defaults_to_monitor_only_and_ipv4_defaults_to_dhcp(self):
        ipv6 = binding('2001:0DB8:0:0:0:0:0:10')
        ipv6.pop('dhcp')
        ipv4 = binding('192.0.2.10', 'leaf-v4')
        ipv4.pop('dhcp')
        rows = self.api['normalize_inventory_bindings']([ipv6, ipv4])
        self.assertEqual(rows[0]['ip'], '2001:db8::10')
        self.assertFalse(rows[0]['dhcp'])
        self.assertTrue(rows[1]['dhcp'])
        self.assertFalse(self.api['normalize_inventory_bindings'](
            [binding(dhcp=True)])[0]['dhcp'])
        self.assertEqual(self.api['normalize_inventory_bindings'](
            [binding(inv_status='planned')])[0]['inv_status'], 'active')

    def test_equivalent_ipv6_addresses_cannot_make_duplicate_inventory_rows(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate ip'):
            self.api['normalize_inventory_bindings']([
                binding(), binding('2001:0db8:0:0:0:0:0:10', 'duplicate')])
        rows = self.api['normalize_inventory_bindings']([
            binding('fe80::1%eth0'), binding('fe80::1%eth1', 'other-link')])
        self.assertEqual(len(rows), 2)
        with self.assertRaisesRegex(ValueError, 'invalid IP'):
            self.api['normalize_inventory_bindings']([binding('fe80::1')])

    def test_ipv6_never_leaks_into_dhcp_even_when_raw_flag_is_true(self):
        content, skipped = self.api['generate_dhcp_hosts']([
            binding(dhcp=True, mac='aa:bb:cc:dd:ee:10')])
        self.assertNotIn('fixed-address', content)
        self.assertEqual(skipped, 1)

    def test_monitor_only_save_works_without_dhcp_installation(self):
        result = self.save_bindings([binding()], restart_dhcp=True,
                                    sync_devices=True)
        self.assertTrue(result['success'], result)
        self.assertFalse(result['dhcp_changed'])
        self.assertIsNone(result['dhcp_restart'])
        self.assertEqual(self.calls['validated'], [])
        self.assertEqual(self.calls['restarts'], [])
        self.assertFalse(self.hosts.exists())
        self.assertEqual(yaml.safe_load(self.devices.read_text())['devices'],
                         {'2001:db8::10': 'leaf-v6 @leaf'})
        self.assertFalse(json.loads(self.inventory.read_text())['bindings'][0]['dhcp'])
        self.assertEqual(self.calls['transactions'], [('inventory-save', None, None)])

    def test_mixed_monitor_edit_preserves_dhcp_bytes_without_daemon_or_pools(self):
        v4 = binding('192.0.2.11', 'leaf-v4', dhcp=True, mac='aa:bb:cc:dd:ee:11')
        self.write_inventory([v4])
        original = '# hand-maintained\nhost leaf-v4 { fixed-address 192.0.2.11; }\n'
        self.hosts.write_text(original)
        result = self.save_bindings([binding(), v4], restart_dhcp=True,
                                    sync_devices=True)
        self.assertTrue(result['success'], result)
        self.assertFalse(result['dhcp_changed'])
        self.assertEqual(self.hosts.read_text(), original)
        self.assertEqual(self.calls['validated'], [])
        self.assertEqual(self.calls['restarts'], [])
        # Removing the last IPv6 entry is also a monitoring-only change.
        result = self.save_bindings([v4], restart_dhcp=True)
        self.assertTrue(result['success'], result)
        self.assertFalse(result['dhcp_changed'])
        self.assertEqual(self.hosts.read_text(), original)

    def test_ipv4_reservation_change_still_validates_and_restarts(self):
        self.conf.write_text('subnet 192.0.2.0 netmask 255.255.255.0 {\n'
                             ' option routers 192.0.2.1; range 192.0.2.200 192.0.2.220; }\n')
        v4 = binding('192.0.2.11', 'leaf-v4', dhcp=True, mac='aa:bb:cc:dd:ee:11')
        self.write_inventory([binding(), v4])
        self.hosts.write_text(self.api['generate_dhcp_hosts']([v4])[0])
        result = self.save_bindings([binding(), dict(v4, ip='192.0.2.12')],
                                    restart_dhcp=True)
        self.assertTrue(result['success'], result)
        self.assertTrue(result['dhcp_changed'])
        self.assertTrue(self.calls['validated'])
        self.assertEqual(self.calls['restarts'], [True])
        self.assertIn('fixed-address 192.0.2.12', self.hosts.read_text())
        self.assertNotIn('2001:', self.hosts.read_text())

    def test_ipv6_save_still_rejects_stale_revision(self):
        result = self.save_bindings([binding()], revision='stale', sync_devices=True)
        self.assertFalse(result['success'], result)
        self.assertEqual(result['error_code'], 'inventory_conflict')
        self.assertFalse(self.inventory.exists())
        self.assertEqual(self.calls['transactions'], [])

    def test_equivalent_yaml_key_preserves_per_device_credentials(self):
        self.devices.write_text(yaml.safe_dump({'devices': {
            '2001:0db8:0:0:0:0:0:10': {'hostname': 'leaf-v6', 'username': 'admin',
                                      'options': {'port': 2222}}}}))
        result = self.save_bindings([binding()], sync_devices=True)
        self.assertTrue(result['success'], result)
        devices = yaml.safe_load(self.devices.read_text())['devices']
        self.assertEqual(list(devices), ['2001:db8::10'])
        self.assertEqual(devices['2001:db8::10']['username'], 'admin')
        self.assertEqual(devices['2001:db8::10']['options'], {'port': 2222})

    def test_export_sorts_numeric_ipv6_and_quotes_ambiguous_yaml_keys(self):
        rows = [binding('2001:db8::10', 'ten'), binding('2001:db8::2', 'two'),
                binding('192.0.2.1', 'v4'), binding('1:2:3:4:5:6:7:8', 'digits')]
        rendered, active, planned = self.api['render_inventory_devices_yaml'](rows)
        devices = yaml.safe_load(rendered)['devices']
        self.assertEqual(active, 4)
        self.assertEqual(planned, 0)
        self.assertEqual(list(devices), ['192.0.2.1', '1:2:3:4:5:6:7:8',
                                        '2001:db8::2', '2001:db8::10'])

    def test_list_without_mac_stays_monitorable_after_reload_and_export(self):
        self.write_inventory([binding(inv_status='planned')])
        self.api['DISCOVERY_CACHE_FILE'] = str(self.web_root / 'no-discovery.json')
        with self.assertRaises(Emitted) as emitted:
            self.api['action_list_bindings']()
        rows = emitted.exception.payload['bindings']
        self.assertEqual(rows[0]['inv_status'], 'active')
        self.assertFalse(rows[0]['dhcp'])
        rendered, active, planned = self.api['render_inventory_devices_yaml'](rows)
        self.assertEqual((active, planned), (1, 0))
        self.assertIn('2001:db8::10', yaml.safe_load(rendered)['devices'])

    def test_explicitly_commented_ipv6_stays_planned_after_reload_and_export(self):
        self.write_inventory([binding(commented=True)])
        self.api['DISCOVERY_CACHE_FILE'] = str(self.web_root / 'no-discovery.json')
        with self.assertRaises(Emitted) as emitted:
            self.api['action_list_bindings']()
        rows = emitted.exception.payload['bindings']
        self.assertEqual(rows[0]['inv_status'], 'planned')
        normalized = self.api['normalize_inventory_bindings'](rows)
        self.assertEqual(normalized[0]['inv_status'], 'planned')
        self.assertTrue(normalized[0]['commented'])
        rendered, active, planned = self.api['render_inventory_devices_yaml'](normalized)
        self.assertEqual((active, planned), (0, 1))
        self.assertEqual(yaml.safe_load(rendered)['devices'], {})
        self.assertIn('#  "2001:db8::10":', rendered)

    def test_role_add_rejects_equivalent_address_occupied_by_another_hostname(self):
        for address in ('2001:db8::10', '2001:0db8:0:0:0:0:0:10'):
            for fallback in (False, True):
                with self.subTest(address=address, pyyaml_fallback=fallback):
                    self.devices.write_text(yaml.safe_dump({'devices': {address: 'existing-leaf'}}))
                    before = self.devices.read_bytes()
                    self.api['POST_DATA'] = json.dumps(binding(hostname='other-leaf'))
                    with contextlib.ExitStack() as stack:
                        if fallback:
                            stack.enter_context(mock.patch.dict('sys.modules', {'ruamel': None, 'ruamel.yaml': None}))
                        with self.assertRaises(Emitted) as emitted:
                            self.api['action_update_role']()
                    result = emitted.exception.payload
                    self.assertFalse(result['success'], result)
                    self.assertIn('already used', result['error'])
                    self.assertEqual(self.devices.read_bytes(), before)

    def test_ipv6_is_still_rejected_by_remote_mutation_guard(self):
        with self.assertRaisesRegex(ValueError, 'Invalid device IP'):
            self.api['canonicalize_inventory_target'](binding(), [binding()])


class DurableIpv6SaveTests(unittest.TestCase):
    """Exercise real atomic-write/journal/rollback code, not transaction stubs."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.collector = self.root / 'collector'
        self.web = self.root / 'web'
        self.collector.mkdir()
        self.web.mkdir()
        self.devices = self.collector / 'devices.yaml'
        self.devices.write_text('defaults:\n  username: cumulus\ndevices: {}\n')
        self.inventory = self.web / 'inventory.json'
        self.hosts = self.root / 'dhcpd.hosts'
        self.journal = self.root / 'state' / 'transaction.json'
        source = (ROOT / 'html' / 'provision-api.sh').read_text()
        body = source.split("python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
            '# ======================== ROUTER ========================', 1)[0]
        environment = {
            'LLDPQ_DIR': str(self.collector), 'WEB_ROOT': str(self.web),
            'DHCP_HOSTS_FILE': str(self.hosts),
            'DHCP_CONF_FILE': str(self.root / 'missing-dhcpd.conf'),
            'LLDPQ_PROVISION_TRANSACTION_FILE': str(self.journal),
            'LLDPQ_DHCP_OPERATION_LOCK_FILE': str(self.web / '.dhcp-lock'),
        }
        patch = mock.patch.dict(os.environ, environment)
        patch.start()
        self.addCleanup(patch.stop)
        self.api = {}
        exec(compile(body, 'provision-api.sh', 'exec'), self.api)
        blocker = mock.patch('subprocess.run', side_effect=AssertionError('Unexpected external command'))
        self.command_mock = blocker.start()
        self.addCleanup(blocker.stop)

    def save(self):
        self.api['POST_DATA'] = json.dumps({
            'bindings': [binding()], 'sync_devices': True, 'restart_dhcp': True,
        })
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            self.api['action_save_bindings']()
        return json.loads(output.getvalue())

    def test_complete_handler_writes_inventory_and_devices_without_dhcp(self):
        result = self.save()
        self.assertTrue(result['success'], result)
        self.assertFalse(result['dhcp_changed'])
        self.assertFalse(self.hosts.exists())
        self.assertFalse(self.journal.exists())
        self.assertEqual(json.loads(self.inventory.read_text())['bindings'][0]['ip'], '2001:db8::10')
        self.assertEqual(yaml.safe_load(self.devices.read_text())['devices']['2001:db8::10'], 'leaf-v6 @leaf')
        self.command_mock.assert_not_called()

    def test_devices_write_failure_rolls_back_inventory_without_service_actions(self):
        original_devices = self.devices.read_bytes()
        original_inventory = json.dumps({'bindings': [], 'timestamp': 1})
        self.inventory.write_text(original_inventory)
        atomic_write = self.api['atomic_write_text']
        failed = False

        def fail_devices_once(path, content, mode=0o664):
            nonlocal failed
            if str(path) == str(self.devices) and not failed:
                failed = True
                raise OSError('injected devices save failure')
            return atomic_write(path, content, mode)

        self.api['atomic_write_text'] = fail_devices_once
        result = self.save()
        self.assertFalse(result['success'], result)
        self.assertTrue(result['rollback_performed'], result)
        self.assertEqual(self.devices.read_bytes(), original_devices)
        self.assertEqual(self.inventory.read_text(), original_inventory)
        self.assertFalse(self.hosts.exists())
        self.assertFalse(self.journal.exists())
        self.command_mock.assert_not_called()


class TargetParsingTests(ApiFixture):
    def targets(self, text):
        return self.api['ip_range_to_list'](text)

    def test_mixed_targets_ranges_cidr_and_overlap(self):
        self.assertEqual(self.targets('192.0.2.10,2001:db8::1-2001:db8::3,'
                                      '2001:0db8:0:0:0:0:0:2,192.0.2.4/31'),
                         ['192.0.2.10', '2001:db8::1', '2001:db8::2',
                          '2001:db8::3', '192.0.2.4', '192.0.2.5'])
        self.assertEqual(self.targets('2001:db8::/126'),
                         ['2001:db8::1', '2001:db8::2', '2001:db8::3'])
        self.assertEqual(self.targets('2001:db8::/127'), ['2001:db8::', '2001:db8::1'])

    def test_limits_are_checked_before_any_enumeration(self):
        for text in ('2001:db8::/64', '192.0.0.0/16',
                     '2001:db8::1-2001:db8::ffff',
                     '192.0.2.1,2001:db8::1-2001:db8::5dc'):
            with self.subTest(text=text):
                self.api['range'] = mock.Mock(side_effect=AssertionError('enumerated oversized range'))
                self.assertEqual(self.targets(text), [])
                self.api['range'].assert_not_called()
        self.api.pop('range')
        self.assertEqual(len(self.targets('2001:db8::1-2001:db8::5dc')), 1500)

    def test_scoped_link_local_range_and_cidr(self):
        self.assertEqual(self.targets('fe80::1%eth-mgmt-fe80::2%eth-mgmt'),
                         ['fe80::1%eth-mgmt', 'fe80::2%eth-mgmt'])
        self.assertEqual(self.targets('fe80::%eth0/126'),
                         ['fe80::1%eth0', 'fe80::2%eth0', 'fe80::3%eth0'])
        for text in ('fe80::1', 'fe80::1%eth0-fe80::3%eth1',
                     '192.0.2.1-2001:db8::1', '2001:db8::2-2001:db8::1',
                     'ff02::1%eth0', '::', '0.0.0.0', '224.0.0.1'):
            with self.subTest(text=text):
                self.assertEqual(self.targets(text), [])


class DiscoveryTests(ApiFixture):
    def setUp(self):
        super().setUp()
        self.commands = []
        self.tcp_hosts = set()
        self.ssh_hosts = set()
        self.bindings = []
        self.neighbours = ''
        self.targets = '2001:db8::10'
        self.api.update({
            'ThreadPoolExecutor': ThreadPoolExecutor, 'as_completed': as_completed,
            'shlex': shlex, 'DISCOVERY_RANGE': '', 'LLDPQ_USER': 'collector',
            'BASE_STATE_FILE': '/base-state', 'LEGACY_BASE_MARKER': '/legacy-base',
            'ZTP_STATE_FILE': '/ztp-state', 'FILE_DEPLOY_MAP': {'base': ('unused',)},
            'DISCOVERY_CACHE_FILE': str(self.web_root / 'discovery.json'),
            'read_lldpq_conf_key': lambda key, default='': self.targets if key == 'DISCOVERY_RANGE' else 'true',
            'load_canonical_inventory_bindings': lambda: self.bindings,
            'base_config_manifest': lambda files: (['base'], 'manifest'),
            'evaluate_device_identity': lambda *args: (True, ''),
            'canonical_device_mutation': mock.Mock(side_effect=AssertionError('IPv6 mutation attempted')),
            '_deploy_to_device': mock.Mock(side_effect=AssertionError('IPv6 deployment attempted')),
        })
        for name in ('normalize_identity_mac', 'run_subnet_scan'):
            exec(extract_source(name), self.api)

    def run_scan(self):
        def fake_run(command, **kwargs):
            self.commands.append(command)
            if command[0] == 'ping':
                return subprocess.CompletedProcess(command, 1, '', '')
            if command[:3] == ['ip', '-6', 'neigh']:
                return subprocess.CompletedProcess(command, 0, self.neighbours, '')
            if command[:2] == ['ip', 'neigh']:
                return subprocess.CompletedProcess(command, 0, '', '')
            if 'ssh' in command:
                host = command[-2].split('@', 1)[1]
                if host in self.ssh_hosts:
                    return subprocess.CompletedProcess(command, 0,
                        'LLDPQ_OK\nLLDPQ_SERIAL=SERIAL1\n'
                        'LLDPQ_MGMT_MAC=aa:bb:cc:dd:ee:10\n'
                        'LLDPQ_HOSTNAME=actual-leaf\n', '')
                return subprocess.CompletedProcess(command, 255, '', 'connection timed out')
            raise AssertionError(command)

        @contextlib.contextmanager
        def fake_connection(address, **kwargs):
            if address[0] not in self.tcp_hosts:
                raise OSError('blocked')
            yield object()

        with mock.patch('subprocess.run', side_effect=fake_run), \
                mock.patch('socket.create_connection', side_effect=fake_connection), \
                mock.patch('socket.if_nametoindex', return_value=7):
            return self.api['run_subnet_scan'](apply_post_provision=True)

    def test_ipv6_ssh_success_without_ping_or_tcp_never_provisions(self):
        self.bindings = [binding()]
        self.ssh_hosts = {'2001:db8::10'}
        result = self.run_scan()
        entry = result['entries'][0]
        self.assertEqual(entry['device_type'], 'provisioned')
        self.assertEqual(entry['reachability'], 'ssh')
        self.assertTrue(entry['monitor_only'])
        self.assertEqual(entry['discovered_mac'], 'aa:bb:cc:dd:ee:10')
        self.assertEqual(result['reachable'], 1)
        self.assertEqual(result['post_provision_action_results'], {})
        self.api['canonical_device_mutation'].assert_not_called()
        self.api['_deploy_to_device'].assert_not_called()
        self.assertIn(['ping', '-6', '-c', '2', '-W', '1', '-i', '0.2', '2001:db8::10'], self.commands)
        self.assertEqual(json.loads(Path(self.api['DISCOVERY_CACHE_FILE']).read_text())['entries'][0]['ip'], '2001:db8::10')

    def test_mixed_ipv4_ipv6_scans_use_family_correct_ping_and_ndp(self):
        self.targets = '192.0.2.10,2001:db8::10,fe80::1%eth0'
        self.ssh_hosts = {'2001:db8::10'}
        self.tcp_hosts = {'192.0.2.10', '2001:db8::10'}
        self.neighbours = 'fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n'
        result = self.run_scan()
        entries = {entry['ip']: entry for entry in result['entries']}
        self.assertIn('NDP', entries['fe80::1%eth0']['source'])
        self.assertTrue(entries['fe80::1%eth0']['signals']['ndp'])
        self.assertFalse(entries['fe80::1%eth0']['signals']['arp'])
        self.assertEqual(entries['192.0.2.10']['reachability'], 'tcp22')
        self.assertFalse(entries['192.0.2.10']['monitor_only'])
        pings = [command for command in self.commands if command[0] == 'ping']
        self.assertNotIn('-6', next(command for command in pings if command[-1] == '192.0.2.10'))
        self.assertTrue(all('-6' in command for command in pings if ':' in command[-1]))

    def test_ndp_wrong_interface_failed_and_stale_are_not_live_evidence(self):
        self.targets = 'fe80::1%eth0,fe80::2%eth0,fe80::3%eth0,fe80::4%eth0,fe80::5%eth0'
        self.neighbours = ('fe80::1 dev eth1 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n'
                           'fe80::2 dev eth0 lladdr aa:bb:cc:dd:ee:02 FAILED\n'
                           'fe80::3 dev eth0 lladdr aa:bb:cc:dd:ee:03 STALE\n'
                           'fe80::4 dev eth0 lladdr aa:bb:cc:dd:ee:04 PERMANENT\n'
                           'fe80::5 dev eth0 lladdr aa:bb:cc:dd:ee:05 NOARP\n')
        result = self.run_scan()
        self.assertEqual(result['reachable'], 0)
        self.assertTrue(all(entry['device_type'] == 'unreachable' for entry in result['entries']))
        ssh_ips = [command[-2] for command in self.commands if 'ssh' in command]
        self.assertEqual(sorted(ssh_ips), ['cumulus@fe80::3%eth0', 'cumulus@fe80::4%eth0', 'cumulus@fe80::5%eth0'])
        self.assertEqual(result['entries'][2]['neighbor_state'], 'STALE')

    def test_mixed_scan_keeps_ipv4_post_provision_actions_only(self):
        self.targets = '192.0.2.10,2001:db8::10'
        self.bindings = [binding('192.0.2.10', 'leaf-v4', dhcp=True), binding()]
        self.ssh_hosts = {'192.0.2.10', '2001:db8::10'}
        mutated = []

        @contextlib.contextmanager
        def authorize(device):
            mutated.append(device['ip'])
            yield device

        self.api['canonical_device_mutation'] = authorize
        self.api['remote_identity_guard_shell'] = lambda *args: 'true'
        self.api['HOSTNAME_STATE_FILE'] = '/hostname-state'
        self.api['_deploy_to_device'] = mock.Mock(return_value={'success': True})
        result = self.run_scan()
        self.assertEqual(mutated, ['192.0.2.10'])
        self.api['_deploy_to_device'].assert_called_once()
        self.assertEqual(set(result['post_provision_action_results']), {'192.0.2.10'})
        mutation_commands = [command for command in self.commands if 'ssh' in command
                             and ('sudo ztp -d' in command[-1] or 'sudo nv set system hostname' in command[-1])]
        self.assertEqual(len(mutation_commands), 2)
        self.assertTrue(all(command[-2] == 'cumulus@192.0.2.10' for command in mutation_commands))

    def test_devices_yaml_only_target_still_gets_ssh_without_icmp(self):
        (self.lldpq_dir / 'devices.yaml').write_text(yaml.safe_dump({
            'devices': {'2001:0db8:0:0:0:0:0:10': {'hostname': 'configured-leaf', 'role': 'leaf'}}}))
        self.ssh_hosts = {'2001:db8::10'}
        result = self.run_scan()
        self.assertEqual(result['entries'][0]['hostname'], 'configured-leaf')
        self.assertEqual(result['entries'][0]['device_type'], 'provisioned')
        self.assertEqual(result['entries'][0]['role'], 'leaf')

    def test_unknown_ipv6_with_tcp_ssh_but_no_ndp_is_discovered(self):
        self.tcp_hosts = self.ssh_hosts = {'2001:db8::10'}
        result = self.run_scan()
        self.assertEqual(result['entries'][0]['device_type'], 'provisioned')
        self.assertFalse(result['entries'][0]['has_binding'])
        self.assertEqual(result['entries'][0]['hostname'], 'actual-leaf')
        self.assertEqual(result['post_provision_action_results'], {})


if __name__ == '__main__':
    unittest.main()
