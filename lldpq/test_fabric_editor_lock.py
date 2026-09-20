"""Fabric edits and Ansible's detached jobs must protect the same inventory."""

import grp
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from lldpq.test_dhcp_multi_pool import shell_function


ROOT = Path(__file__).resolve().parents[1]
FABRIC = (ROOT / 'html/fabric-api.sh').read_text()
ANSIBLE = (ROOT / 'html/ansible-api.sh').read_text()
FABRIC_LOCK = FABRIC[FABRIC.index('FABRIC_LOCK_DIR='):FABRIC.index('# Output JSON header')]
ANSIBLE_LOCK = ANSIBLE[ANSIBLE.index('FABRIC_LOCK_DIR='):ANSIBLE.index('# Fix git directory permissions')]
ANSIBLE_LOCK += shell_function(ANSIBLE, 'json_response')
ANSIBLE_LOCK += shell_function(ANSIBLE, 'acquire_deploy_lock')


@unittest.skipUnless(shutil.which('flock'), 'flock is required for runtime locking')
class FabricEditorLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'ansible-home').mkdir()
        (self.root / 'repo').mkdir()
        self.environment = dict(os.environ,
            FABRIC_LOCK_DIR=str(self.root / 'locks'),
            FABRIC_LOCK_GROUP=grp.getgrgid(os.getgid()).gr_name,
            ANSIBLE_HOME=str(self.root / 'ansible-home'),
            ANSIBLE_DIR=str(self.root / 'repo'))
        self.environment.pop('FABRIC_LOCK_FILE', None)

    def source(self, api):
        if api == 'fabric':
            return FABRIC_LOCK, 'acquire_lock'
        return ANSIBLE_LOCK, 'acquire_deploy_lock'

    def attempt(self, api, environment=None):
        source, acquire = self.source(api)
        result = subprocess.run(
            ['bash', '-c', source + '\n' + acquire +
             ' || exit 0\nprintf \'{"success":true}\\n\''],
            env=environment or self.environment, text=True,
            capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_each_editor_blocks_the_other_until_its_transaction_finishes(self):
        for holder, contender in (('fabric', 'ansible'), ('ansible', 'fabric')):
            with self.subTest(holder=holder):
                source, acquire = self.source(holder)
                process = subprocess.Popen(
                    ['bash', '-c', source + '\n' + acquire +
                     ' || exit 1\nprintf "locked\\n"\nread -r release'],
                    env=self.environment, text=True,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    self.assertEqual(process.stdout.readline(), 'locked\n')
                    denied = self.attempt(contender)
                    self.assertFalse(denied['success'], denied)
                finally:
                    process.communicate('\n', timeout=5)
                self.assertTrue(self.attempt(contender)['success'])

    def test_lock_open_failure_does_not_allow_an_edit(self):
        environment = dict(self.environment,
            FABRIC_LOCK_FILE=str(self.root / 'missing-parent' / 'lock'))
        for api in ('fabric', 'ansible'):
            result = self.attempt(api, environment)
            self.assertFalse(result['success'], result)
            self.assertIn('Could not open config lock', result['error'])

    @unittest.skipUnless(shutil.which('setsid'), 'setsid is required for detached jobs')
    def test_detached_job_holds_lock_after_cgi_process_exits(self):
        tools = self.root / 'bin'
        tools.mkdir()
        ready, release = self.root / 'ready', self.root / 'release'
        playbook = tools / 'ansible-playbook'
        playbook.write_text(f'#!{sys.executable}\n'
            'import os, pathlib, time\n'
            'pathlib.Path(os.environ["LOCK_PROBE_READY"]).touch()\n'
            'deadline = time.monotonic() + 10\n'
            'while not pathlib.Path(os.environ["LOCK_PROBE_RELEASE"]).exists():\n'
            '    if time.monotonic() >= deadline: raise SystemExit(1)\n'
            '    time.sleep(0.02)\n')
        playbook.chmod(0o755)
        environment = dict(self.environment,
            PATH=str(tools) + os.pathsep + os.environ.get('PATH', ''),
            LOCK_PROBE_READY=str(ready), LOCK_PROBE_RELEASE=str(release))
        source = ANSIBLE_LOCK + shell_function(ANSIBLE, 'start_ansible_job')
        source += '\nacquire_deploy_lock || exit 1\nstart_ansible_job deploy fake-playbook leaf1\n'
        started = subprocess.run(['bash', '-c', source], env=environment,
                                 text=True, capture_output=True, timeout=5)
        self.assertEqual(started.returncode, 0, started.stderr)
        response = json.loads(started.stdout.strip().splitlines()[-1])
        self.assertTrue(response['started'], response)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(ready.exists(), 'detached playbook did not start')
            self.assertFalse(self.attempt('fabric')['success'])
            self.assertFalse(self.attempt('ansible')['success'])
        finally:
            release.touch()
        rc_file = self.root / 'ansible-home/deploy-jobs' / (response['job_id'] + '.rc')
        deadline = time.monotonic() + 5
        while not rc_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(rc_file.exists(), 'detached playbook did not finish')
        self.assertEqual(rc_file.read_text().strip(), '0')
        self.assertTrue(self.attempt('fabric')['success'])


if __name__ == '__main__':
    unittest.main()
