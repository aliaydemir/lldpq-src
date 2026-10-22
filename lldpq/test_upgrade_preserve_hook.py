"""Exercise the upgrade-only access hook without network or host filesystem writes."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lldpq'))
SOURCE = (ROOT / 'html/provision-api.sh').read_text().split(
    "python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
        '# ======================== ROUTER ========================', 1)[0]
NAMES = {
    'validate_ztp_script_content', 'ztp_script_public_key',
    'upgrade_literal_shell_word', 'upgrade_literal_assignment',
    'render_upgrade_preserve_hook', 'validate_upgrade_preserve_hook_content',
    'prepare_upgrade_post_install_script',
}
API = {'re': re, 'shlex': shlex, 'subprocess': subprocess}
for node in ast.parse(SOURCE).body:
    if isinstance(node, ast.FunctionDef) and node.name in NAMES:
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<api>', 'exec'), API)


class UpgradePreserveHookTests(unittest.TestCase):
    def source(self, *, password='Nvidia@123', key='ssh-ed25519 AAAA collector'):
        value = (ROOT / 'html/cumulus-ztp.sh').read_text()
        return value.replace('__TARGET_OS_VERSION__', '5.16.0').replace(
            '__IMAGE_SERVER_IP__', '192.0.2.250').replace(
                "'cumulus:Nvidia@123'", shlex.quote('cumulus:' + password)).replace(
                    'KEY=""', 'KEY=' + shlex.quote(key))

    def prepare(self, source=None, server='[2001:db8::250]:8080'):
        return API['prepare_upgrade_post_install_script'](
            self.source() if source is None else source, server)

    def test_old_and_current_templates_generate_the_same_offline_program(self):
        expected = self.prepare()
        for version in (2, 3, 4):
            source = self.source().replace('LLDPQ_ZTP_TEMPLATE_VERSION=3',
                                         f'LLDPQ_ZTP_TEMPLATE_VERSION={version}')
            source = source.replace('ping "${family_args[@]}" "$target"',
                                    'custom_site_ping "$target"')
            source += '\n# Site customization stays confined to fresh provisioning.\n'
            source += 'if false; then nv config replace custom.yaml; fi\n'
            self.assertEqual(self.prepare(source), expected)
        for command in ('curl ', 'ping ', 'nv config ', 'onie-install',
                        'serial-mapping.txt', 'generated_config_folder', 'reboot'):
            self.assertNotIn(command, expected)
        self.assertIn('LLDPQ_UPGRADE_HOOK_VERSION=1', expected)
        self.assertEqual(subprocess.run(['bash', '-n'], input=expected, text=True,
                                       capture_output=True).returncode, 0)

    def test_validator_rejects_old_full_provisioning_and_injected_hook_code(self):
        with self.assertRaisesRegex(ValueError, 'predates config preservation'):
            API['validate_upgrade_preserve_hook_content'](self.source())
        for changed in (
            self.prepare() + '\ncurl http://unavailable/config.yaml\n',
            self.prepare().replace('umask 077', 'umask 077; nv config replace evil.yaml'),
        ):
            with self.assertRaisesRegex(ValueError, 'managed config-preserving'):
                API['validate_upgrade_preserve_hook_content'](changed)

    def test_metadata_and_literal_access_values_survive_exact_validation(self):
        password = "It's a $password `literal` \\ value"
        key = 'ssh-ed25519 AAAA collector $(literal) `comment` \\ key'
        hook = self.prepare(self.source(password=password, key=key))
        self.assertEqual(API['upgrade_literal_assignment'](hook, 'CUMULUS_PASSWORD'), password)
        self.assertEqual(API['upgrade_literal_assignment'](hook, 'KEY'), key)
        self.assertEqual(API['upgrade_literal_assignment'](hook, 'IMAGE_SERVER_HOSTNAME'),
                         '[2001:db8::250]:8080')
        self.assertEqual(API['validate_upgrade_preserve_hook_content'](hook), hook)

    def test_quick_settings_double_quoted_key_escapes_match_bash_semantics(self):
        key = 'ssh-ed25519 AAAA $(literal) `comment` \\ "quoted"'
        escaped = key.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
        source = self.source().replace(shlex.quote('ssh-ed25519 AAAA collector'), '"' + escaped + '"')
        hook = self.prepare(source)
        self.assertEqual(API['upgrade_literal_assignment'](hook, 'KEY'), key)

    def test_ambiguous_credentials_cannot_start_an_upgrade(self):
        for changed in (
            self.source() + '\nKEY="ssh-ed25519 BBBB other"\n',
            self.source() + "\necho 'cumulus:different' | chpasswd\n",
            self.source().replace("echo cumulus:Nvidia@123 | chpasswd", 'custom_password_setup'),
        ):
            with self.assertRaises(ValueError):
                self.prepare(changed)

    def test_dynamic_settings_are_rejected_without_executing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / 'must-not-exist'
            dynamic = '$(touch ' + str(sentinel) + ')'
            for changed in (
                self.source().replace('KEY=' + shlex.quote('ssh-ed25519 AAAA collector'),
                                      'KEY="ssh-ed25519 AAAA ' + dynamic + '"'),
                self.source().replace("echo cumulus:Nvidia@123", 'echo "cumulus:' + dynamic + '"'),
                self.source().replace('CUMULUS_TARGET_RELEASE=5.16.0',
                                      'CUMULUS_TARGET_RELEASE=' + dynamic),
            ):
                with self.assertRaises(ValueError):
                    self.prepare(changed)
            self.assertFalse(sentinel.exists())

    def execute_offline(self, *, fail_chown=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        binaries = root / 'bin'
        binaries.mkdir()
        (root / 'etc/sudoers.d').mkdir(parents=True)
        root_keys = root / 'root/.ssh/authorized_keys'
        root_keys.parent.mkdir(parents=True)
        root_keys.write_text('ssh-ed25519 BBBB existing-key')
        (root / 'startup.yaml').write_text('set:\n- interface:\n    eth0:\n      ip:\n        address:\n          2001:db8::10/64: {}\n')
        original_startup = (root / 'startup.yaml').read_bytes()
        trace = root / 'trace'
        password = "it's $(literal) `text`"
        hook = self.prepare(self.source(password=password))
        hook = hook.replace('/etc/sudoers.d/', str(root / 'etc/sudoers.d') + '/')
        hook = hook.replace('/root/.ssh', str(root / 'root/.ssh'))
        hook = hook.replace('/home/cumulus/.ssh', str(root / 'home/cumulus/.ssh'))
        path = root / 'hook.sh'
        path.write_text(hook)
        scripts = {
            'chown': 'exit ' + ('1' if fail_chown else '0'),
            'passwd': 'printf "passwd\\n" >> "$HOOK_TRACE"',
            'chpasswd': 'cat > "$HOOK_PASSWORD"; printf "chpasswd\\n" >> "$HOOK_TRACE"',
            'visudo': 'exit 0',
        }
        for name in ('curl', 'wget', 'ping', 'nv', 'onie-install', 'reboot'):
            scripts[name] = 'printf "forbidden:' + name + '\\n" >> "$HOOK_TRACE"; exit 99'
        for name, content in scripts.items():
            command = binaries / name
            command.write_text('#!/bin/bash\n' + content + '\n')
            command.chmod(0o755)
        environment = dict(os.environ, PATH=str(binaries) + ':' + os.environ['PATH'],
                           HOOK_TRACE=str(trace), HOOK_PASSWORD=str(root / 'password'))
        runs = [subprocess.run(['bash', str(path)], env=environment, capture_output=True,
                               text=True) for _ in range(2)]
        self.assertEqual((root / 'startup.yaml').read_bytes(), original_startup)
        self.assertNotIn('forbidden:', trace.read_text() if trace.exists() else '')
        self.assertNotIn(password, ''.join(run.stdout + run.stderr for run in runs))
        return root, runs, password

    def test_hook_restores_access_offline_preserves_existing_keys_and_is_idempotent(self):
        root, runs, password = self.execute_offline()
        for run in runs:
            self.assertEqual(run.returncode, 0, run.stderr)
        expected_key = 'ssh-ed25519 AAAA collector'
        root_keys = root / 'root/.ssh/authorized_keys'
        self.assertEqual(root_keys.read_text().splitlines(),
                         ['ssh-ed25519 BBBB existing-key', expected_key])
        cumulus_keys = root / 'home/cumulus/.ssh/authorized_keys'
        self.assertEqual(cumulus_keys.read_text().splitlines(), [expected_key])
        self.assertEqual(stat.S_IMODE(root_keys.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(root_keys.parent.stat().st_mode), 0o700)
        self.assertEqual((root / 'password').read_text(), 'cumulus:' + password + '\n')
        sudoers = root / 'etc/sudoers.d/10_cumulus'
        self.assertEqual(sudoers.read_text(), 'cumulus ALL=(ALL) NOPASSWD:ALL\n')
        self.assertEqual(stat.S_IMODE(sudoers.stat().st_mode), 0o440)

    def test_key_installation_failure_fails_hook_before_password_changes(self):
        root, runs, _ = self.execute_offline(fail_chown=True)
        for run in runs:
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('Failed to restore the collector SSH key', run.stderr)
        self.assertFalse((root / 'password').exists())


if __name__ == '__main__':
    unittest.main()
