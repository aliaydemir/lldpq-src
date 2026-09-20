"""Run Setup's config writer through the canonical parser and Fabric reader."""

from pathlib import Path
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

from lldpq.test_dhcp_multi_pool import shell_function


ROOT = Path(__file__).resolve().parents[1]
FABRIC = (ROOT / 'html/fabric-api.sh').read_text()
SETUP = (ROOT / 'html/setup-api.sh').read_text()
LOADER = FABRIC[FABRIC.index('# Use the same data parser'):FABRIC.index('# Serialize concurrent YAML')]
WRITER = SETUP[SETUP.index('def write_conf(pairs):'):SETUP.index('# Shared error for the None')]


class FabricConfigRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.conf = self.root / 'lldpq.conf'
        self.conf.write_text('LLDPQ_USER=lldpq\nANSIBLE_DIR=NoNe\n')
        self.helper = self.root / 'config-helper'
        self.helper.write_text('#!/bin/bash\nexec ' + ' '.join(shlex.quote(x) for x in (
            sys.executable, str(ROOT / 'bin/lldpq-config'), '--config',
            str(self.conf))) + ' "$@"\n')
        self.helper.chmod(0o755)

    def save_setup(self, path):
        def install_text(content, target, *_):
            self.assertEqual(target, str(self.conf))
            self.conf.write_text(content)
            return True
        namespace = {'ensure_configuration_lock': lambda: None,
                     'config_owner': 'test', 'install_text_as_root': install_text}
        exec(WRITER.replace('/etc/lldpq.conf', str(self.conf)), namespace)
        self.assertTrue(namespace['write_conf']({'ANSIBLE_DIR': str(path)}))

    def run_reader(self, *, function='get_vlan_profiles', helper=None):
        source = LOADER.replace('/usr/local/bin/lldpq-config', str(helper or self.helper))
        if function:
            source += shell_function(FABRIC, function) + '\n' + function
        else:
            source += '\npython3 -c \'import os,json; print(json.dumps(os.environ.get("ANSIBLE_DIR")))\'\n'
        result = subprocess.run(['bash', '-c', source], text=True,
                                capture_output=True, timeout=10,
                                env=dict(os.environ, ANSIBLE_DIR='/stale/environment/value'))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_setup_saved_directories_read_real_vlan_profiles(self):
        for directory in ('ansible', 'ansible with spaces', 'ansible=a=b'):
            with self.subTest(directory=directory):
                ansible = self.root / directory
                profile = ansible / 'inventory/group_vars/all/vlan_profiles.yaml'
                profile.parent.mkdir(parents=True)
                profile.write_text('vlan_profiles: {BLUE: {vlans: {100: {}}}}\n')
                self.save_setup(ansible)
                self.assertIn('ANSIBLE_DIR="', self.conf.read_text())
                result = self.run_reader()
                self.assertTrue(result['success'], result)
                self.assertIn('BLUE', result['vlan_profiles'])

    def test_disabled_value_overrides_stale_environment(self):
        self.save_setup('NoNe')
        self.assertEqual(self.run_reader(function=None), '')

    def test_missing_helper_reports_installation_error(self):
        result = self.run_reader(helper=self.root / 'missing-helper')
        self.assertFalse(result['success'])
        self.assertIn('helper is missing', result['error'])

    def test_missing_config_reports_error_before_using_environment(self):
        self.conf.unlink()
        result = self.run_reader()
        self.assertFalse(result['success'])
        self.assertIn('configuration is missing', result['error'])

    def test_legacy_unquoted_and_duplicate_values_use_canonical_last_wins(self):
        ansible = self.root / 'ansible'
        self.conf.write_text(f'ANSIBLE_DIR=/old\nANSIBLE_DIR={ansible}\n')
        self.assertEqual(self.run_reader(function=None), str(ansible))


if __name__ == '__main__':
    unittest.main()
