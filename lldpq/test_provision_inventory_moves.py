"""Exercise Provision Save through both inventory files, including IP cycles."""

import io
import itertools
import json
from unittest import mock
import sys
import unittest

import yaml

from lldpq.test_dhcp_multi_pool import ApiFixture, extract_source


class InventoryMoveTests(ApiFixture):
    def setUp(self):
        super().setUp()
        self.devices_file = self.lldpq_dir / 'devices.yaml'
        self.conf.write_text(
            'subnet 10.0.0.0 netmask 255.255.255.0 { '
            'option routers 10.0.0.254; range 10.0.0.200 10.0.0.220; }\n'
            f'include "{self.hosts}";\n')
        self.hosts.write_text('')
        self.api['io'] = io
        exec(compile(extract_source('sync_bindings_to_devices_yaml'),
                     'provision-api.sh', 'exec'), self.api)

    def original(self, count=3, flat=False):
        devices = {
            f'10.0.0.{index}': {
                'hostname': f'leaf{index}', 'username': f'admin{index}',
                'role': 'old-role', 'options': {'port': 2200 + index},
            } for index in range(1, count + 1)
        }
        document = dict(devices) if flat else {'devices': devices}
        document['defaults'] = {'username': 'cumulus'}
        document['endpoint_hosts'] = ['endpoint1']
        self.devices_file.write_text(yaml.safe_dump(document, sort_keys=False))
        return devices

    def binding(self, index, ip, hostname=None):
        return {'hostname': hostname or f'leaf{index}', 'ip': ip,
                'mac': f'aa:bb:cc:dd:ee:{index:02x}', 'role': 'leaf',
                'dhcp': True}

    def assert_saved(self, bindings, **extra):
        response = self.save_bindings(bindings, sync_devices=True,
                                      revision=self.api['inventory_revision'](),
                                      **extra)
        self.assertTrue(response['success'], response)
        self.assertTrue(self.calls['validated'])
        saved = json.loads(self.inventory.read_text())['bindings']
        self.assertEqual({b['hostname']: b['ip'] for b in saved},
                         {b['hostname']: b['ip'] for b in bindings})
        document = yaml.safe_load(self.devices_file.read_text())
        self.assertEqual(document['defaults'], {'username': 'cumulus'})
        self.assertEqual(document['endpoint_hosts'], ['endpoint1'])
        return document.get('devices', document)

    def test_swaps_and_three_host_cycles_preserve_metadata_in_every_order(self):
        for count in (2, 3):
            bindings = [self.binding(index, f'10.0.0.{index % count + 1}')
                        for index in range(1, count + 1)]
            for order in itertools.permutations(bindings):
                with self.subTest(count=count, order=[b['hostname'] for b in order]):
                    original = self.original(count)
                    devices = self.assert_saved(list(order))
                    self.assertEqual(len(devices), count)
                    for index, binding in enumerate(bindings, 1):
                        expected = dict(original[f'10.0.0.{index}'], role='leaf')
                        self.assertEqual(devices[binding['ip']], expected)

    def test_swap_survives_pyyaml_fallback_and_legacy_flat_layout(self):
        for flat in (False, True):
            with self.subTest(flat=flat), mock.patch.dict(
                    sys.modules, {'ruamel': None, 'ruamel.yaml': None}):
                self.original(2, flat=flat)
                devices = self.assert_saved([
                    self.binding(1, '10.0.0.2'), self.binding(2, '10.0.0.1')])
                self.assertEqual(devices['10.0.0.2']['username'], 'admin1')
                self.assertEqual(devices['10.0.0.1']['username'], 'admin2')

    def test_same_ip_hostname_change_keeps_overrides_and_removes_old_role(self):
        self.original(1)
        binding = dict(self.binding(1, '10.0.0.1', 'leaf-renamed'), role='')
        devices = self.assert_saved([binding])
        self.assertEqual(devices['10.0.0.1'], {
            'hostname': 'leaf-renamed', 'username': 'admin1',
            'options': {'port': 2201},
        })

    def test_new_host_at_vacated_ip_does_not_steal_moving_host_credentials(self):
        for reverse in (False, True):
            self.original(1)
            bindings = [self.binding(1, '10.0.0.2'),
                        self.binding(2, '10.0.0.1')]
            devices = self.assert_saved(bindings[::-1] if reverse else bindings)
            self.assertEqual(devices['10.0.0.2']['username'], 'admin1')
            self.assertEqual(devices['10.0.0.1'], 'leaf2 @leaf')

    def test_move_to_unrelated_monitored_host_is_rejected_without_writes(self):
        self.original(2)
        before = self.devices_file.read_bytes()
        response = self.save_bindings([self.binding(1, '10.0.0.2')],
                                      sync_devices=True)
        self.assertFalse(response['success'], response)
        self.assertIn('already used', response['error'])
        self.assertEqual(self.devices_file.read_bytes(), before)
        self.assertEqual(self.hosts.read_text(), '')
        self.assertFalse(self.inventory.exists())

    def test_explicit_remove_allows_reusing_an_occupied_ip(self):
        self.original(2)
        devices = self.assert_saved([self.binding(1, '10.0.0.2')],
                                    remove_devices=['leaf2'])
        self.assertEqual(list(devices), ['10.0.0.2'])
        self.assertEqual(devices['10.0.0.2']['username'], 'admin1')


if __name__ == '__main__':
    unittest.main()
