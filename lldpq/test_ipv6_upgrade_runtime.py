"""IPv6 upgrades remain resumable through native updates and Docker restarts.

Runs the actual installer validators against temporary jobs; no device access,
package changes, system service changes or upgrade launch happens here.
"""
import ast
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import unittest

from lldpq.addressing import normalize_address, normalize_server_ref

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text()
ZTP = ROOT / 'html/cumulus-ztp.sh'
ENTRYPOINT = (ROOT / 'docker/docker-entrypoint.sh').read_text()
JOB_ID = '12345678-1234-1234-1234-123456789abc'


def installer_function(name):
    start = INSTALL.index(name + '() {')
    end = INSTALL.index('\nPYTHON\n}', start) + len('\nPYTHON\n}')
    return INSTALL[start:end]


def address_checks(name):
    source = installer_function(name).split("<<'PYTHON'\n", 1)[1].rsplit('\nPYTHON', 1)[0]
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('normalize_upgrade_address', 'valid_upgrade_server_ref')]
    namespace = {'ipaddress': ipaddress, 're': re}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<installer>', 'exec'), namespace)
    return namespace


def job(ip='2001:db8::10', server='[2001:db8::20]:8080', complete=False):
    now = int(time.time())
    result = {
        'schema_version': 2, 'id': JOB_ID, 'created_at': now,
        'worker_started_at': now, 'worker_heartbeat': now,
        'target_version': '5.14.0', 'image_name': 'cumulus-5.14.0.bin',
        'image_size': 100, 'image_sha256': 'a' * 64,
        'server_ip': server, 'batch_size': 1, 'stop_on_failure': True,
        'base_config_after': True, 'timeout_seconds': 3600,
        'complete': complete, 'cancelled': False, 'ready': True,
        'aliases_published': True,
        'onie_alias_snapshot': {
            f'{scope}:{alias}': None for scope in ('uploads', 'web')
            for alias in ('onie-installer-x86_64', 'onie-installer-x86_64-mlnx', 'onie-installer')
        },
        'ztp_artifact': f'provision-uploads/ztp-artifacts/{JOB_ID}.ztp',
        'ztp_size': 100, 'ztp_sha256': 'b' * 64,
        'devices': [{
            'ip': ip, 'hostname': 'leaf-01', 'username': 'cumulus',
            'expected_mac': 'aa:bb:cc:dd:ee:01', 'expected_serial': 'SN01',
            'target_version': '5.14.0', 'status': 'done' if complete else 'queued',
        }],
    }
    if complete:
        result['completed_at'] = now
    return result


class UpgradeRuntimeTests(unittest.TestCase):
    def run_validator(self, payload, name='verify_upgrade_jobs_runtime_compatible'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / f'{JOB_ID}.json'
            original = json.dumps(payload).encode()
            path.write_bytes(original)
            script = ('set -e\nroot_run() { "$@"; }\n' + installer_function(name)
                      + '\n' + name + ' ' + shlex.quote(directory))
            env = dict(os.environ, LLDPQ_RECONCILE_ALLOW_CURRENT_INCOMPLETE='true')
            result = subprocess.run(['bash', '-c', script], capture_output=True,
                                    text=True, timeout=10, env=env)
            self.assertEqual(path.read_bytes(), original, 'current job must not be rewritten')
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), [path.name])
            return result

    def test_native_update_accepts_completed_ipv6_job(self):
        result = self.run_validator(job(complete=True))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_docker_can_resume_current_ipv6_job_without_reconciliation(self):
        for address in ('2001:db8::10', 'fd00::10', 'fe80::10%eth0', '192.0.2.10'):
            with self.subTest(address=address):
                payload = job(ip=address)
                for name in ('reconcile_stale_legacy_upgrade_jobs',
                             'verify_upgrade_jobs_runtime_compatible'):
                    result = self.run_validator(payload, name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn('incompatible', result.stderr)
        self.assertIn('reconcile_stale_legacy_upgrade_jobs /var/lib/lldpq/upgrade-jobs', ENTRYPOINT)
        self.assertIn('verify_upgrade_jobs_runtime_compatible /var/lib/lldpq/upgrade-jobs', ENTRYPOINT)

    def test_equivalent_ipv6_jobs_cannot_bypass_duplicate_target_check(self):
        payload = job()
        duplicate = copy.deepcopy(payload['devices'][0])
        duplicate['ip'] = '2001:0DB8:0:0:0:0:0:10'
        payload['devices'].append(duplicate)
        result = self.run_validator(payload)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('duplicate upgrade device IP', result.stderr)

    def test_invalid_targets_and_server_authorities_cannot_resume(self):
        for address in ('fe80::1', '2001:db8:::1', 'fe80::1%eth0;id', '[2001:db8::1]'):
            with self.subTest(address=address):
                result = self.run_validator(job(ip=address))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('invalid upgrade device IP', result.stderr)
        for server in ('[fe80::1%eth0]', '[2001:db8::1]:65536',
                       '[2001:db8:::1]', 'http://[2001:db8::1]', '[2001:db8::1]/x'):
            with self.subTest(server=server):
                result = self.run_validator(job(server=server))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('image/server metadata', result.stderr)

    def test_lifecycle_address_checks_match_canonical_parser(self):
        for name in ('reconcile_stale_legacy_upgrade_jobs', 'verify_upgrade_jobs_runtime_compatible'):
            check = address_checks(name)['normalize_upgrade_address']
            for address in ('192.0.2.10', '2001:0DB8::10', '::ffff:192.0.2.10',
                            'fe80::10%eth0', 'fe80::10%2'):
                with self.subTest(name=name, address=address):
                    self.assertEqual(check(address), normalize_address(address))

    def test_both_lifecycle_checks_accept_valid_server_forms(self):
        for name in ('reconcile_stale_legacy_upgrade_jobs', 'verify_upgrade_jobs_runtime_compatible'):
            check = address_checks(name)['valid_upgrade_server_ref']
            for server in ('192.0.2.10', 'images.example.net:8080', '2001:db8::10',
                           '[2001:db8::10]', '[fd00::10]:80'):
                with self.subTest(name=name, server=server):
                    self.assertTrue(check(server))
            for server in ('[::]', '[ff02::1]', 'fe80::1', '[fe80::1%eth0]',
                           '192.0.2.10:0', '[::1]:70000', '[2001:db8::1]suffix',
                           'images.example.net/path', 'images@host', '999.1.2.3'):
                with self.subTest(name=name, server=server):
                    self.assertFalse(check(server))

    def test_lifecycle_server_contract_matches_runtime_helper(self):
        # A server accepted when saving a job must not strand that job at a
        # Docker restart or a later native update before new code is copied.
        cases = (
            '192.0.2.10', '192.0.2.10:8080', 'Image.Example', 'image.example.:80',
            'lldpq:00443', '2001:0db8:0:0:0:0:0:10', '[2001:db8::10]',
            '[FD00::10]:8080', '2001:db8::10:8080', '::ffff:c000:20a',
            '', None, 'http://image.example', 'host/path', 'user@host',
            'host?query', 'host#fragment', 'bad_host', '-host', 'host..test',
            'host:0', 'host:65536', 'host:', '[fd00::1]:-1', '[fd00::1]:xx',
            '[192.0.2.1]', '2001:::1', '[fd00::1', '[fd00::1]tail',
            'fe80::1', '[fe80::1%eth0]', 'fd00::1%eth0', '::', 'ff02::1',
            '0.0.0.0', '224.0.0.1', '999.1.1.1', 'host\nname',
            '[::ffff:0.0.0.0]', '[::ffff:224.0.0.1]',
        )
        for name in ('reconcile_stale_legacy_upgrade_jobs', 'verify_upgrade_jobs_runtime_compatible'):
            check = address_checks(name)['valid_upgrade_server_ref']
            for value in cases:
                with self.subTest(name=name, value=value):
                    try:
                        normalize_server_ref(value)
                        accepted = True
                    except ValueError:
                        accepted = False
                    self.assertEqual(check(value), accepted)


class PostInstallTransportTests(unittest.TestCase):
    def test_script_extracts_host_and_pings_expected_family(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'ping.args'
            for server, target, ipv6 in (
                    ('192.0.2.10', '192.0.2.10', False),
                    ('images.example.net:8080', 'images.example.net', False),
                    ('[2001:db8::10]:8080', '2001:db8::10', True),
                    ('[fd00::10]', 'fd00::10', True),
                    ('2001:db8::10', '2001:db8::10', True)):
                with self.subTest(server=server):
                    script = ('source ' + shlex.quote(str(ZTP)) + '\n'
                              'ping() { printf "%s\\0" "$@" > "$PING_LOG"; }\n'
                              'target=$(image_server_ping_target ' + shlex.quote(server) + ')\n'
                              'ping_until_reachable "$target"\n')
                    result = subprocess.run(['bash', '-c', script], capture_output=True,
                                            text=True, timeout=5,
                                            env=dict(os.environ, PING_LOG=str(log)))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = (['-6'] if ipv6 else []) + [target, '-c2', '--no-vrf-switch']
                    self.assertEqual(log.read_bytes().decode().rstrip('\0').split('\0'), expected)

    def test_nginx_has_dual_stack_listener_and_both_installations_keep_ipv4_fallback(self):
        site = (ROOT / 'etc/nginx/sites-available/lldpq').read_text()
        self.assertIn('listen 80 default_server;', site)
        self.assertIn('listen [::]:80 default_server;', site)
        for source in (INSTALL, ENTRYPOINT):
            self.assertIn('/proc/net/if_inet6', source)
            self.assertIn("sed -i '/listen \\[::]/d' /etc/nginx/sites-available/lldpq", source)


if __name__ == '__main__':
    unittest.main()
