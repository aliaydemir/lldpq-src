"""Static IPv6 recovery validation and remote probes; never contact a switch."""
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import upgrade_management as management


def config_for(section='ip'):
    return [{'set': {'interface': {'eth0': {
        'ip': {'vrf': 'mgmt'},
        section: {'address': {'2001:db8::10/64': {}}, **({'vrf': 'mgmt'} if section == 'ip' else {})},
    }}}}]


def snapshot_for(config=None, **overrides):
    import yaml
    raw = yaml.safe_dump(config if config is not None else config_for()).encode()
    result = {'family': 6, 'server': '2001:db8::10', 'client': '2001:db8::250',
              'interface': 'eth0', 'prefix': 64, 'vrf': 'mgmt', 'gateway': '',
              'startup_b64': base64.b64encode(raw).decode(),
              'startup_sha256': hashlib.sha256(raw).hexdigest()}
    result.update(overrides)
    return result


class RecoveryValidationTests(unittest.TestCase):
    def validate(self, config=None, target='2001:db8::10', **overrides):
        return management.validate_snapshot(snapshot_for(config, **overrides), target)

    def test_old_and_new_nvue_address_schemas(self):
        for section in ('ip', 'ipv6'):
            guard, message = self.validate(config_for(section))
            self.assertEqual(guard['interface'], 'eth0')
            self.assertNotIn('startup_b64', guard)
            self.assertIn('connected return path', message)

    def test_target_normalizes_expanded_ipv6(self):
        self.validate(target='2001:0DB8:0:0:0:0:0:10')

    def test_neighbor_or_vrr_occurrence_does_not_count(self):
        for node in ('neighbor', 'vrr'):
            config = config_for()
            ip_config = config[0]['set']['interface']['eth0']['ip']
            ip_config.pop('address')
            ip_config[node] = {'address': {'2001:db8::10/64': {}}}
            with self.assertRaisesRegex(ValueError, 'not saved on interface'):
                self.validate(config)

    def test_another_interface_does_not_count(self):
        config = config_for()
        config[0]['set']['interface']['swp1'] = config[0]['set']['interface'].pop('eth0')
        with self.assertRaisesRegex(ValueError, 'not saved on interface'):
            self.validate(config)

    def test_missing_prefix_mismatched_prefix_and_dynamic_only_fail(self):
        for address in ('2001:db8::10', '2001:db8::10/128', 'dhcp'):
            config = config_for()
            config[0]['set']['interface']['eth0']['ip']['address'] = {address: {}}
            with self.assertRaisesRegex(ValueError, 'not saved on interface'):
                self.validate(config)

    def test_vrf_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, 'VRF does not match'):
            self.validate(vrf='default')

    def test_eth0_implicit_mgmt_default_is_allowed(self):
        config = config_for()
        config[0]['set']['interface']['eth0']['ip'].pop('vrf')
        self.validate(config)

    def test_saved_interface_down_fails(self):
        config = config_for()
        config[0]['set']['interface']['eth0']['link'] = {'state': 'down'}
        with self.assertRaisesRegex(ValueError, 'administratively down'):
            self.validate(config)

    def test_saved_ipv6_disabled_rejected_in_old_and_new_schema(self):
        for schema in ('ip', 'ipv6'):
            for key, value in (('state', 'disabled'), ('enable', 'off'), ('enable', False)):
                config = config_for(schema)
                interface = config[0]['set']['interface']['eth0']
                section = interface['ip'].setdefault('ipv6', {}) if schema == 'ip' else interface['ipv6']
                section[key] = value
                with self.assertRaisesRegex(ValueError, 'IPv6 is disabled'):
                    self.validate(config)

    def test_offlink_client_without_saved_return_route_fails(self):
        with self.assertRaisesRegex(ValueError, 'not saved in NVUE'):
            self.validate(client='2001:db8:1::50', gateway='2001:db8::1')
        with self.assertRaisesRegex(ValueError, 'No saved connected/static'):
            self.validate(client='2001:db8:1::50')

    def test_gateway_old_new_and_linklocal(self):
        for section in ('ip', 'ipv6'):
            for gateway in ('2001:db8::1', 'fe80::1'):
                config = config_for(section)
                config[0]['set']['interface']['eth0'][section]['gateway'] = {gateway: {}}
                _, message = self.validate(config, client='2001:db8:1::50', gateway=gateway)
                self.assertIn('saved static return gateway', message)

    def test_saved_vrf_static_route_is_allowed(self):
        config = config_for()
        config[0]['set']['vrf'] = {'mgmt': {'router': {'static': {
            '2001:db8:1::/64': {'via': {'2001:db8::1': {'type': 'ipv6-address'}}}
        }}}}
        self.validate(config, client='2001:db8:1::50', gateway='2001:db8::1')

    def test_distance_nested_route_uses_lowest_preference(self):
        config = config_for()
        distances = {'5': {'via': {'2001:db8::1': {'type': 'ipv6-address'}}},
                     '10': {'via': {'2001:db8::2': {'type': 'ipv6-address'}}}}
        config[0]['set']['vrf'] = {'mgmt': {'router': {'static': {
            '::/0': {'distance': distances}
        }}}}
        self.validate(config, client='2001:db8:1::50', gateway='2001:db8::1')
        with self.assertRaisesRegex(ValueError, 'not saved in NVUE'):
            self.validate(config, client='2001:db8:1::50', gateway='2001:db8::2')

    def test_route_via_different_vrf_does_not_prove_recovery(self):
        config = config_for()
        config[0]['set']['vrf'] = {'mgmt': {'router': {'static': {
            '::/0': {'via': {'2001:db8::1': {'type': 'ipv6-address', 'vrf': 'default'}}}
        }}}}
        with self.assertRaisesRegex(ValueError, 'not saved in NVUE'):
            self.validate(config, client='2001:db8:1::50', gateway='2001:db8::1')

    def test_wrong_vrf_or_unrelated_static_route_cannot_satisfy_recovery(self):
        for vrf, prefix in (('default', '::/0'), ('mgmt', '2001:db8:2::/64')):
            config = config_for()
            config[0]['set']['vrf'] = {vrf: {'router': {'static': {
                prefix: {'via': {'2001:db8::1': {'type': 'ipv6-address'}}}
            }}}}
            with self.assertRaisesRegex(ValueError, 'not saved in NVUE'):
                self.validate(config, client='2001:db8:1::50', gateway='2001:db8::1')

    def test_unreachable_gateway_is_rejected(self):
        config = config_for()
        config[0]['set']['interface']['eth0']['ip']['gateway'] = {'2001:db8:9::1': {}}
        with self.assertRaisesRegex(ValueError, 'not on a saved IPv6 subnet'):
            self.validate(config, client='2001:db8:1::50', gateway='2001:db8:9::1')

    def test_saved_default_does_not_hide_conflicting_specific_route(self):
        config = config_for()
        config[0]['set']['interface']['eth0']['ip']['gateway'] = {'2001:db8::1': {}}
        config[0]['set']['vrf'] = {'mgmt': {'router': {'static': {
            '2001:db8:1::/64': {'via': {'2001:db8::99': {'type': 'ipv6-address'}}}
        }}}}
        with self.assertRaisesRegex(ValueError, 'not saved in NVUE'):
            self.validate(config, client='2001:db8:1::50', gateway='2001:db8::1')

    def test_wrong_target_or_checksum_fails(self):
        with self.assertRaisesRegex(ValueError, 'differs from'):
            self.validate(target='2001:db8::99')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.validate(startup_sha256='0' * 64)

    def test_dns_uses_actual_transport_family(self):
        self.validate(target='leaf.example.test')
        guard, message = management.validate_snapshot(
            {'family': 4, 'server': '192.0.2.10', 'client': '192.0.2.250'}, 'leaf.example.test')
        self.assertEqual(guard['family'], 4)
        self.assertIn('IPv4', message)

    def test_linklocal_auto_address_is_not_inferred(self):
        with self.assertRaisesRegex(ValueError, 'not saved on interface'):
            self.validate(target='fe80::10%eth1', server='fe80::10', client='fe80::250')

    def test_ambiguous_patch_sequence_rejected(self):
        config = config_for() + [{'unset': {'interface': {'eth0': {}}}}]
        with self.assertRaisesRegex(ValueError, 'Unsupported NVUE startup structure'):
            self.validate(config)


class RemoteProbeTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot_for()
        self.raw = base64.b64decode(self.snapshot['startup_b64'])
        self.addresses = [{'ifname': 'eth0', 'addr_info': [
            {'family': 'inet6', 'local': '2001:db8::10', 'prefixlen': 64}]}]
        self.route = [{'dst': '2001:db8::250', 'dev': 'eth0'}]

    def fake_run(self, argv, **kwargs):
        self.assertEqual(kwargs['timeout'], 5)
        if argv == ['ip', '-j', '-6', 'address', 'show']:
            result = self.addresses
        elif argv == ['ip', '-j', '-d', 'link', 'show', 'dev', 'eth0']:
            result = [{'ifname': 'eth0', 'master': 'mgmt'}]
        elif argv == ['ip', '-j', '-d', 'link', 'show', 'dev', 'mgmt']:
            result = [{'ifname': 'mgmt', 'linkinfo': {'info_kind': 'vrf'}}]
        elif argv == ['ip', '-j', '-6', 'route', 'get', '2001:db8::250', 'from', '2001:db8::10', 'vrf', 'mgmt']:
            result = self.route
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps(result), '')

    def execute(self, expected=None, connection='2001:db8::250 51000 2001:db8::10 22'):
        argv = ['probe', connection]
        if expected is not None:
            argv.append(base64.b64encode(json.dumps(expected).encode()).decode())
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch('subprocess.run', side_effect=self.fake_run), \
                mock.patch('builtins.open', return_value=io.BytesIO(self.raw)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            try:
                exec(compile(management.REMOTE_PROBE, '<remote probe>', 'exec'), {})
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), error.getvalue()

    def test_actual_probe_snapshot_validates(self):
        code, output, error = self.execute()
        self.assertEqual(code, 0, error)
        data = json.loads(output.removeprefix('LLDPQ_MGMT_SNAPSHOT='))
        management.validate_snapshot(data, '2001:db8::10')

    def test_final_guard_accepts_exact_validated_state(self):
        expected, _ = management.validate_snapshot(self.snapshot, '2001:db8::10')
        code, output, error = self.execute(expected)
        self.assertEqual(code, 0, error)
        self.assertIn('LLDPQ_MGMT_GUARD_OK', output)

    def test_final_guard_rejects_changed_file_or_runtime_prefix(self):
        expected, _ = management.validate_snapshot(self.snapshot, '2001:db8::10')
        self.raw += b'\n# changed after saved config validation\n'
        code, _, error = self.execute(expected)
        self.assertEqual(code, 78)
        self.assertIn('changed after validation', error)
        self.raw = base64.b64decode(self.snapshot['startup_b64'])
        self.addresses[0]['addr_info'][0]['prefixlen'] = 128
        self.assertEqual(self.execute(expected)[0], 78)

    def test_final_dns_guard_rejects_family_change(self):
        expected = {'family': 4, 'server': '192.0.2.10', 'client': '192.0.2.250'}
        self.assertEqual(self.execute(expected)[0], 78)

    def test_no_route_and_dynamic_address_fail_closed(self):
        self.route = []
        self.assertEqual(self.execute()[0], 78)
        self.route = [{'dst': '2001:db8::250', 'dev': 'eth0'}]
        self.addresses[0]['addr_info'][0]['dynamic'] = True
        self.assertEqual(self.execute()[0], 78)

    def test_probe_has_no_switch_yaml_dependency(self):
        # Executing with guarded imports proves a switch does not need PyYAML.
        original_import = __import__
        def checked_import(name, *args, **kwargs):
            if name in ('yaml', 'ruamel'):
                raise AssertionError('Remote YAML dependency')
            return original_import(name, *args, **kwargs)
        with mock.patch('builtins.__import__', side_effect=checked_import):
            self.assertEqual(self.execute()[0], 0)


class IntegrationGuardTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / 'html/provision-api.sh').read_text()
        body = source.split("python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
            '# ======================== ROUTER ========================', 1)[0]
        self.api = {}
        exec(compile(body, 'provision-api.sh', 'exec'), self.api)
        self.device = {'ip': '2001:db8::10', 'username': 'cumulus',
                       'expected_mac': 'aa:bb:cc:dd:ee:10'}
        self.calls = []

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if 'LLDPQ_MGMT_SNAPSHOT=' in kwargs.get('input', '') and 'LLDPQ_UPGRADE_DISPATCHING' not in kwargs['input']:
            stdout = 'LLDPQ_MGMT_SNAPSHOT=' + json.dumps(snapshot_for()) + '\n'
        else:
            stdout = 'LLDPQ_UPGRADE_STARTED\n'
        return subprocess.CompletedProcess(argv, 0, stdout, '')

    def test_precheck_is_read_only_and_reports_evidence(self):
        self.api.update(get_device_version=lambda _: {'reachable': True, 'current_version': '5.15', 'startup_config': True},
                        resolve_os_image_path=lambda _: True, is_valid_server_ref=lambda _: True,
                        check_upgrade_image_download=lambda *_: '')
        with mock.patch('subprocess.run', side_effect=self.command):
            result = self.api['run_upgrade_precheck'](self.device, '5.16', 'image.bin', '2001:db8::250')
        self.assertTrue(result['precheck_ok'])
        self.assertIn('Static IPv6', result['management_recovery'])
        self.assertTrue(result['checks'][0].startswith('OK: Static IPv6 '))
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('nv config save', self.calls[0][1]['input'])
        self.assertNotIn('onie-install', self.calls[0][1]['input'])

    def test_launch_saves_then_validates_and_binds_dispatch(self):
        with mock.patch('subprocess.run', side_effect=self.command):
            result = self.api['_start_upgrade_for_device'](self.device, 'http://server/image', 'http://server/hook', 'job123')
        self.assertTrue(result[0], result)
        self.assertEqual(len(self.calls), 2)
        prepare = self.calls[0][1]['input']
        dispatch = self.calls[1][1]['input']
        self.assertLess(prepare.index('EXPECTED_MAC='), prepare.index('sudo nv config save'))
        self.assertLess(prepare.index('curl --globoff'), prepare.index('sudo nv config save'))
        self.assertLess(prepare.index('sudo nv config save'), prepare.index('LLDPQ_MGMT_SNAPSHOT='))
        self.assertNotIn('sudo nv config save', dispatch)
        self.assertLess(dispatch.index('LLDPQ_MGMT_GUARD_OK'), dispatch.index('echo LLDPQ_UPGRADE_DISPATCHING'))
        self.assertIn('startup_sha256', dispatch)
        self.assertIn('-t "$LLDPQ_STARTUP_FILE"', dispatch)
        self.assertIn('ZTP_URL="$ZTP_URL" LLDPQ_STARTUP_FILE="$LLDPQ_STARTUP_FILE" nohup', dispatch)
        self.assertLess(dispatch.index('pid=$!'), dispatch.index('trap - EXIT'))
        self.assertLess(dispatch.index('trap - EXIT'), dispatch.index('sleep 1'))
        child = dispatch.split("nohup bash -c '", 1)[1]
        self.assertLess(child.index('/usr/cumulus/bin/onie-install'), child.index('rm -f -- "$LLDPQ_STARTUP_FILE"'))
        syntax = subprocess.run(['/bin/bash', '-n'], input=dispatch, capture_output=True, text=True, timeout=5)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_recovery_failure_never_dispatches(self):
        bad = snapshot_for(prefix=128)
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess(
                [], 0, 'LLDPQ_MGMT_SNAPSHOT=' + json.dumps(bad), '')) as run:
            result = self.api['_start_upgrade_for_device'](self.device, 'http://server/image', 'http://server/hook', 'job123')
        self.assertFalse(result[0])
        self.assertFalse(result[2])
        self.assertEqual(run.call_count, 1)
        self.assertNotIn('LLDPQ_UPGRADE_DISPATCHING', run.call_args.kwargs['input'])

    def test_ipv4_keeps_single_dispatch_and_original_save(self):
        with mock.patch('subprocess.run', side_effect=self.command):
            result = self.api['_start_upgrade_for_device'](dict(self.device, ip='192.0.2.10'), 'http://server/image', 'http://server/hook', 'job123')
        self.assertTrue(result[0])
        self.assertEqual(len(self.calls), 1)
        self.assertIn('sudo nv config save', self.calls[0][1]['input'])
        self.assertIn('-t /etc/nvue.d/startup.yaml', self.calls[0][1]['input'])
        self.assertNotIn('LLDPQ_STARTUP_FILE', self.calls[0][1]['input'])
        self.assertNotIn('LLDPQ_MGMT_SNAPSHOT', self.calls[0][1]['input'])

    def test_completed_operation_keeps_idempotent_retry(self):
        with mock.patch('subprocess.run', return_value=subprocess.CompletedProcess(
                [], 0, 'LLDPQ_UPGRADE_ALREADY_STARTED\n', '')) as run:
            result = self.api['_start_upgrade_for_device'](self.device, 'http://server/image', 'http://server/hook', 'job123')
        self.assertTrue(result[0])
        self.assertEqual(run.call_count, 1)


class PinnedStartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        definitions = management.REMOTE_PROBE.split('\ntry:\n    snapshot =', 1)[0]
        self.namespace = {}
        exec(compile(definitions, '<remote probe definitions>', 'exec'), self.namespace)
        self.snapshot = snapshot_for()
        self.raw = base64.b64decode(self.snapshot['startup_b64'])
        real_mkdtemp = tempfile.mkdtemp
        def local_mkdtemp(*, prefix, dir):
            self.assertEqual(dir, '/var/tmp')
            self.assertTrue(prefix.startswith('lldpq-upgrade-job123.'))
            return real_mkdtemp(prefix=prefix, dir=self.root)
        patch = mock.patch('tempfile.mkdtemp', side_effect=local_mkdtemp)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch('os.geteuid', return_value=0)
        patch.start()
        self.addCleanup(patch.stop)

    def pin(self):
        return Path(self.namespace['pin_startup'](self.snapshot, 'job123'))

    def test_manual_change_after_validation_does_not_change_installer_file(self):
        source = self.root / 'live-startup.yaml'
        source.write_bytes(self.raw)
        # The validated snapshot is already in memory when another session
        # saves NVUE. The installer must receive these original bytes.
        source.write_bytes(b'- set: {}\n# later manual save\n')
        staged = self.pin()
        self.assertEqual(staged.read_bytes(), self.raw)
        self.assertNotEqual(staged.read_bytes(), source.read_bytes())
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        self.assertEqual(staged.parent.stat().st_mode & 0o777, 0o700)
        other = self.pin()
        self.assertNotEqual(staged, other)

    def test_copy_hash_mismatch_cleans_private_snapshot_and_aborts_probe(self):
        with mock.patch('builtins.open', return_value=io.BytesIO(b'corrupted copy')):
            with self.assertRaisesRegex(ValueError, 'Staged startup snapshot checksum mismatch'):
                self.pin()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_probe_assignment_aborts_before_dispatch(self):
        # Exercise the same bash assignment/errexit contract used by launch,
        # with a probe whose staged readback actually fails checksum checking.
        definitions = management.REMOTE_PROBE.split('\ntry:\n    snapshot =', 1)[0]
        runner = definitions + '''
from unittest import mock
import io
snapshot = json.loads(sys.argv[1])
real_mkdtemp = tempfile.mkdtemp
def local_mkdtemp(*, prefix, dir):
    return real_mkdtemp(prefix=prefix, dir=sys.argv[2])
try:
    with mock.patch('os.geteuid', return_value=0), mock.patch('tempfile.mkdtemp', side_effect=local_mkdtemp), mock.patch('builtins.open', return_value=io.BytesIO(b'corrupted')):
        print(pin_startup(snapshot, 'job123'))
except Exception as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(78)
'''
        program = self.root / 'probe.py'
        program.write_text(runner)
        import shlex
        invocation = ' '.join(shlex.quote(value) for value in (
            sys.executable, str(program), json.dumps(self.snapshot), str(self.root)))
        result = subprocess.run(['/bin/bash', '-c', 'set -e\nLLDPQ_STARTUP_FILE="$(' + invocation + ')"\necho LLDPQ_UPGRADE_DISPATCHING\n'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 78)
        self.assertIn('Staged startup snapshot checksum mismatch', result.stderr)
        self.assertNotIn('LLDPQ_UPGRADE_DISPATCHING', result.stdout)
        self.assertEqual(list(self.root.iterdir()), [program])

    def test_invalid_operation_id_never_creates_directory(self):
        with self.assertRaisesRegex(ValueError, 'Invalid upgrade operation ID'):
            self.namespace['pin_startup'](self.snapshot, '../../outside')
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
