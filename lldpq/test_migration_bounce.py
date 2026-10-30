"""Port restoration and plan snapshots, entirely on local fake devices."""
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from jinja2 import Environment
from lldpq.migration_bounce import prepare, BOUNCE_SCRIPT


def can_run_local_ansible():
    if not shutil.which('ansible-playbook'):
        return False
    try:
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(Path(tmp) / 'rpc.sock'))
        return True
    except OSError:
        return False


LOCAL_ANSIBLE = can_run_local_ansible()


class MigrationBounceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / '.migrations').mkdir()
        self.hosts = self.root / 'inventory/host_vars'
        self.hosts.mkdir(parents=True)
        (self.hosts / 'leaf1.yml').write_text('interfaces:\n  swp1:\n    sw_port_profile: new\n')
        self.plan = {'id': 'plan-1', 'changes': {'leaf1': {'applied': [
            {'section': 'interfaces', 'name': 'swp1', 'old': 'old', 'new': 'new'}]}}}
        (self.root / '.migrations/plan-1.json').write_text(json.dumps(self.plan))

    def test_snapshot_survives_plan_change_and_uses_remote_async(self):
        play = prepare(self.root, 'plan-1', 'leaf1,localhost')[0]
        (self.root / '.migrations/plan-1.json').write_text('{}')
        (self.hosts / 'leaf1.yml').unlink()
        self.assertEqual(play['vars']['lldpq_bounce_ports'], {'leaf1': ['swp1']})
        self.assertEqual(play['hosts'], ['leaf1'])
        self.assertEqual(play['tasks'][0]['async'], 240)
        self.assertGreater(play['tasks'][0]['poll'], 0)

    def test_changed_profile_and_unknown_device_reject_before_deploy(self):
        with self.assertRaisesRegex(ValueError, 'No applied migration ports'):
            prepare(self.root, 'plan-1', 'leaf2')
        (self.hosts / 'leaf1.yml').write_text('interfaces:\n  swp1:\n    sw_port_profile: other\n')
        with self.assertRaisesRegex(ValueError, 'changed since apply'):
            prepare(self.root, 'plan-1', 'leaf1')

    def run_remote(self, down_rc=0, up_failures=0):
        tools = self.root / 'bin'
        tools.mkdir()
        log, count = self.root / 'calls', self.root / 'up-count'
        scripts = {
            'ifdown': f'echo "down $*" >> {shlex.quote(str(log))}\nexit {down_rc}\n',
            'ifup': f'''echo "up $*" >> {shlex.quote(str(log))}
n=$(cat {shlex.quote(str(count))} 2>/dev/null || echo 0)
n=$((n+1))
echo "$n" > {shlex.quote(str(count))}
[ "$n" -gt {up_failures} ]
''',
            'sleep': 'exit 0\n',
        }
        for name, content in scripts.items():
            path = tools / name
            path.write_text('#!/bin/bash\n' + content)
            path.chmod(0o755)
        env = Environment()
        env.filters['quote'] = shlex.quote
        script = env.from_string(BOUNCE_SCRIPT).render(
            lldpq_bounce_ports={'leaf1': ['swp1', 'bond.12']}, inventory_hostname='leaf1')
        for name in ('ifup', 'ifdown'):
            script = script.replace('/usr/sbin/' + name, shlex.quote(str(tools / name)))
        result = subprocess.run(['bash'], input=script, text=True, capture_output=True,
                                env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']),
                                timeout=5)
        return result, log.read_text().splitlines()

    def test_success_uses_same_ports_for_down_and_up(self):
        result, calls = self.run_remote()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['down swp1 bond.12', 'up swp1 bond.12'])

    def test_partial_ifdown_failure_still_restores_but_reports_failure(self):
        result, calls = self.run_remote(down_rc=2)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(calls[-1], 'up swp1 bond.12')
        self.assertNotIn('Port bounce complete', result.stdout)

    def test_transient_ifup_failure_is_retried(self):
        result, calls = self.run_remote(up_failures=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count('up swp1 bond.12'), 2)

    def test_permanent_ifup_failure_is_never_success(self):
        result, calls = self.run_remote(up_failures=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls.count('up swp1 bond.12'), 3)
        self.assertNotIn('Port bounce complete', result.stdout)
        self.assertIn('ifup failed', result.stderr)

    def local_ansible(self, script, matching=True):
        playbook = prepare(self.root, 'plan-1', 'leaf1,localhost')
        playbook[0]['connection'] = 'local'
        playbook[0]['become'] = False
        playbook[0]['tasks'][0]['ansible.builtin.shell'] = script
        playbook[0]['tasks'][0]['poll'] = 1
        path = self.root / 'bounce.json'
        path.write_text(json.dumps(playbook))
        inventory = self.root / 'inventory.ini'
        inventory.write_text(('[all]\nleaf1' if matching else '[all]\nother') +
                             f' ansible_connection=local ansible_python_interpreter={sys.executable}\n' +
                             f'localhost ansible_connection=local ansible_python_interpreter={sys.executable}\n')
        config = self.root / 'ansible.cfg'
        config.write_text('[defaults]\nhost_key_checking = False\n')
        environment = dict(os.environ, ANSIBLE_CONFIG=str(config),
                           ANSIBLE_HOME=str(self.root / 'ansible-home'),
                           ANSIBLE_LOCAL_TEMP=str(self.root / 'local-tmp'),
                           ANSIBLE_REMOTE_TEMP=str(self.root / 'remote-tmp'),
                           ANSIBLE_ASYNC_DIR=str(self.root / 'async'),
                           ANSIBLE_NOCOLOR='1')
        return ['ansible-playbook', '-i', str(inventory), str(path), '-l', 'leaf1,localhost'], environment

    @unittest.skipUnless(LOCAL_ANSIBLE, 'Ansible and local Unix sockets are required')
    def test_ansible_requires_result_from_every_requested_device(self):
        for matching in (True, False):
            args, environment = self.local_ansible('echo local-test-only', matching)
            result = subprocess.run(args, env=environment, cwd=self.root,
                                    text=True, capture_output=True, timeout=30)
            if matching:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Port restoration was not confirmed', result.stdout + result.stderr)

    @unittest.skipUnless(LOCAL_ANSIBLE, 'Ansible and local Unix sockets are required')
    def test_remote_async_finishes_after_controller_termination(self):
        down, up = self.root / 'down', self.root / 'up'
        script = f'touch {shlex.quote(str(down))}\nsleep 2\ntouch {shlex.quote(str(up))}\n'
        args, environment = self.local_ansible(script)
        process = subprocess.Popen(args, env=environment, cwd=self.root,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 15
            while not down.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(down.exists(), 'async task did not start')
            process.terminate()
            process.communicate(timeout=5)
            deadline = time.monotonic() + 8
            while not up.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(up.exists(), 'async restoration stopped with its controller')
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
