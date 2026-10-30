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
            LLDPQ_DIR=str(ROOT / 'lldpq'),
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

    def test_editor_and_deploy_recover_before_using_inventory(self):
        import base64
        repo = self.root / 'repo'
        for api in ('fabric', 'ansible'):
            target = repo / 'host.yaml'
            target.write_text('new\n')
            journal = repo / '.lldpq-write-journal.json'
            journal.write_text(json.dumps({'state': 'prepared', 'entries': [{
                'path': 'host.yaml', 'staged': '.lldpq-write-abandoned',
                'old': base64.b64encode(b'old\n').decode(),
                'new': base64.b64encode(b'new\n').decode(), 'mode': 0o664,
            }]}))
            self.assertTrue(self.attempt(api)['success'])
            self.assertEqual(target.read_text(), 'old\n')
            self.assertFalse(journal.exists())

    def test_invalid_journal_blocks_both_editors(self):
        (self.root / 'repo/.lldpq-write-journal.json').write_text('{invalid')
        for api in ('fabric', 'ansible'):
            result = self.attempt(api)
            self.assertFalse(result['success'])
            self.assertIn('could not be recovered', result['error'])

    def test_cron_uses_same_lock_and_recognizes_yml_hosts(self):
        tools = self.root / 'bin'
        tools.mkdir()
        marker = self.root / 'cron-ran'
        playbook = tools / 'ansible-playbook'
        playbook.write_text('#!/bin/bash\n' +
                           'touch "$CRON_MARKER"\n' +
                           'printf "SWITCHES WITH CHANGES\\nleaf.1: 2 changes\\nPLAY RECAP\\n"\n')
        playbook.chmod(0o755)
        hosts = self.root / 'repo/inventory/host_vars'
        hosts.mkdir(parents=True)
        (hosts / 'leaf.1.yml').write_text('{}')
        web = self.root / 'web'
        web.mkdir()
        cache = web / 'fabric-scan-cache.json'
        cache.write_text('{"old":true}')
        environment = dict(self.environment, WEB_ROOT=str(web), CRON_MARKER=str(marker),
                           PATH=str(tools) + os.pathsep + os.environ['PATH'])
        source, acquire = self.source('fabric')
        holder = subprocess.Popen(['bash', '-c', source + '\n' + acquire +
                                  '\necho ready\nread -r release'],
                                  env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline(), 'ready\n')
            denied = subprocess.run(['bash', str(ROOT / 'lldpq/fabric-scan-cron.sh')],
                                    env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(denied.returncode, 75, denied.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(cache.read_text(), '{"old":true}')
        finally:
            holder.communicate('\n', timeout=5)
        result = subprocess.run(['bash', str(ROOT / 'lldpq/fabric-scan-cron.sh')],
                                env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(cache.read_text())['pendingDevices'], ['leaf.1'])

    @unittest.skipUnless(shutil.which('setsid'), 'setsid is required for detached jobs')
    def test_bounce_remains_in_detached_job_and_failure_reaches_saved_status(self):
        repo = self.root / 'repo'
        (repo / '.migrations').mkdir()
        hosts = repo / 'inventory/host_vars'
        hosts.mkdir(parents=True)
        (hosts / 'leaf1.yaml').write_text('interfaces:\n  swp1: {sw_port_profile: new}\n')
        (repo / '.migrations/plan-1.json').write_text(json.dumps({
            'id': 'plan-1', 'changes': {'leaf1': {'applied': [
                {'section': 'interfaces', 'name': 'swp1', 'new': 'new'}]}}}))
        tools = self.root / 'bin'
        tools.mkdir()
        ready, release = self.root / 'bounce-ready', self.root / 'bounce-release'
        executable = tools / 'ansible-playbook'
        executable.write_text(f'#!{sys.executable}\n' + '''
import json, os, pathlib, sys, time
if not sys.argv[1].endswith('.bounce.json'):
    sys.exit(0)
snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert snapshot[0]['vars']['lldpq_bounce_ports'] == {'leaf1': ['swp1']}
pathlib.Path(os.environ['BOUNCE_READY']).touch()
deadline = time.monotonic() + 10
while not pathlib.Path(os.environ['BOUNCE_RELEASE']).exists():
    if time.monotonic() > deadline: sys.exit(9)
    time.sleep(.02)
print('ifup failed', flush=True)
sys.exit(2)
''')
        executable.chmod(0o755)
        # No remote task exists in this fake, so skip the recovery wait.
        (tools / 'sleep').write_text('#!/bin/bash\nexit 0\n')
        (tools / 'sleep').chmod(0o755)
        environment = dict(self.environment, BOUNCE_READY=str(ready), BOUNCE_RELEASE=str(release),
                           PATH=str(tools) + os.pathsep + os.environ['PATH'])
        source = ANSIBLE_LOCK + shell_function(ANSIBLE, 'start_ansible_job')
        source += '\nacquire_deploy_lock || exit 1\nstart_ansible_job deploy fake-playbook leaf1,localhost plan-1\n'
        started = subprocess.run(['bash', '-c', source], env=environment,
                                 text=True, capture_output=True, timeout=5)
        response = json.loads(started.stdout.strip().splitlines()[-1])
        self.assertTrue(response.get('started'), response)
        state = self.root / 'ansible-home/deploy-jobs'
        rc = state / (response['job_id'] + '.rc')
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(ready.exists(), 'bounce did not start after deploy')
            self.assertFalse(self.attempt('fabric')['success'])
            self.assertFalse(rc.exists(), 'deploy reported completion before bounce')
            (repo / '.migrations/plan-1.json').write_text('{}')
        finally:
            release.touch()
        deadline = time.monotonic() + 5
        while not rc.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertEqual(rc.read_text().strip(), '2')
        self.assertIn('ifup failed', (state / (response['job_id'] + '.log')).read_text())
        self.assertTrue(self.attempt('fabric')['success'])

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
