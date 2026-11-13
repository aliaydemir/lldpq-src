"""LLDPQ_SSHD: the switch for the container's own SSH service.

The entrypoint starts sshd on TCP/2033 and, before that, gives the lldpq
account (passwordless sudo) a fixed, documented password at every start.  With
--network host on a switch that listener is on the switch itself.  Nothing in
the image connects to it; `docker exec` gives the same shell.

LLDPQ_SSHD=no leaves both out: sshd is not started, the password is not written
and the account's password is locked, and the start-up and ready lines say so
instead of advertising the port.  Unset, or yes, is the behaviour of every
earlier image.  The value is read the way LLDPQ_ENTER_MGMT_VRF is.

The three pieces of the entrypoint are run for real with stand-in chpasswd,
passwd and sshd binaries; nothing here needs Linux, root or a container.
"""

from pathlib import Path
import os
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = (ROOT / 'docker/docker-entrypoint.sh').read_text()
DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
COMPOSE = (ROOT / 'docker/docker-compose.yml').read_text()
PROVISIONING_COMPOSE = (ROOT / 'docker/docker-compose.provisioning.yml').read_text()


def between(start, end):
    begin = ENTRYPOINT.index(start)
    return ENTRYPOINT[begin:ENTRYPOINT.index(end, begin)]


# Where the account's password is decided, where the service is started and
# the line under the ready message, in the order the entrypoint runs them.
SETUP_BLOCK = between('# ─── SSH Server Setup ───', '# ─── Start Services ───')
START_BLOCK = between('# Start SSH server', '# Console bridge lifecycle helpers')
READY_BLOCK = between('# LLDPQ_PORT is normally a host-side compose variable',
                      '# The VRF line is printed first thing')

ADVERTISED = '  SSH: container port 2033 (reachable only if published or with host networking)'

# The stand-ins record that they were called.  chpasswd reads "user:password"
# on stdin; only the user name is kept, so no log ever holds the password.
STAND_INS = {
    'chpasswd': '#!/bin/bash\ncut -d: -f1 >> "$CALLS/chpasswd"\n',
    'passwd': '#!/bin/bash\nprintf \'%s\\n\' "$*" >> "$CALLS/passwd"\nexit "${FAKE_PASSWD_RC:-0}"\n',
    'sshd': '#!/bin/bash\nprintf \'started %s\\n\' "$*" >> "$CALLS/sshd"\n'
            '[ "${FAKE_SSHD_RC:-0}" = 0 ] || echo "sshd: no hostkeys available" >&2\n'
            'exit "${FAKE_SSHD_RC:-0}"\n',
}


class SshdSwitchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-sshd-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / 'bin'
        self.calls = self.root / 'calls'
        self.bin.mkdir()
        self.calls.mkdir()
        for name, body in STAND_INS.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def start(self, **env):
        """Run the three blocks the way the entrypoint does, under `set -e`."""
        self.assertEqual(START_BLOCK.count('/usr/sbin/sshd'), 1)
        source = '\n'.join((
            'set -e', SETUP_BLOCK, 'echo SETUP-DONE',
            START_BLOCK.replace('/usr/sbin/sshd', f'"{self.bin}/sshd"'),
            READY_BLOCK, 'echo CONTINUED', ''))
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('FAKE_', 'LLDPQ_'))}
        environment.update(PATH=f"{self.bin}{os.pathsep}{environment['PATH']}",
                           CALLS=str(self.calls))
        environment.update(env)
        for log in self.calls.iterdir():
            log.unlink()
        result = subprocess.run(['bash', '-c', source], capture_output=True, text=True,
                                timeout=20, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SETUP-DONE\n', result.stdout)
        self.assertTrue(result.stdout.endswith('CONTINUED\n'), result.stdout)
        return result

    def called(self, name):
        log = self.calls / name
        return log.read_text().splitlines() if log.exists() else []

    def assert_enabled(self, result):
        self.assertEqual(self.called('chpasswd'), ['lldpq'])
        self.assertEqual(self.called('passwd'), [])
        self.assertEqual(self.called('sshd'), ['started '])
        self.assertIn('  ✓ sshd (port 2033)\n', result.stdout)
        self.assertIn(ADVERTISED + '\n', result.stdout)
        self.assertNotIn('disabled', result.stdout)
        self.assertNotIn('not started', result.stdout)

    def test_unset_is_the_behaviour_of_earlier_images(self):
        result = self.start()
        self.assert_enabled(result)
        self.assertEqual(result.stderr, '')
        # Set but empty is unset, as it is for LLDPQ_ENTER_MGMT_VRF.
        result = self.start(LLDPQ_SSHD='')
        self.assert_enabled(result)
        self.assertEqual(result.stderr, '')

    def test_explicit_yes_starts_the_service_without_a_remark(self):
        for value in ('yes', 'true', 'on', '1', 'YES', 'True', 'On'):
            with self.subTest(value=value):
                result = self.start(LLDPQ_SSHD=value)
                self.assert_enabled(result)
                self.assertEqual(result.stderr, '')

    def test_no_leaves_out_the_service_and_the_known_password(self):
        for value in ('no', 'false', 'off', '0', 'NO', 'No', 'False', 'OFF'):
            with self.subTest(value=value):
                result = self.start(LLDPQ_SSHD=value)
                self.assertEqual(result.stderr, '')
                self.assertEqual(self.called('sshd'), [])
                self.assertEqual(self.called('chpasswd'), [])
                # The account keeps working for sudo -u, cron and docker exec:
                # only its password is locked.
                self.assertEqual(self.called('passwd'), ['-l lldpq'])
                self.assertIn(f'  sshd: not started (LLDPQ_SSHD={value})\n', result.stdout)
                self.assertIn(f"  SSH: disabled (LLDPQ_SSHD={value}); use 'docker exec' "
                              'for a shell\n', result.stdout)
                self.assertNotIn('2033', result.stdout)

    def test_value_that_is_not_understood_is_reported_and_the_service_started(self):
        for value in ('nope', 'disabled', ' no', 'n o', 'none'):
            with self.subTest(value=value):
                result = self.start(LLDPQ_SSHD=value)
                self.assertEqual(
                    result.stderr,
                    f'⚠ LLDPQ_SSHD={value} is not understood (use yes or no); '
                    'starting the SSH service\n')
                self.assert_enabled(result)

    def test_failed_sshd_start_is_still_reported_and_not_fatal(self):
        result = self.start(FAKE_SSHD_RC='1')
        self.assertEqual(self.called('sshd'), ['started '])
        self.assertIn('  ⚠ sshd failed to start\n', result.stdout)
        self.assertNotIn('✓ sshd', result.stdout)

    def test_failed_lock_is_reported_and_start_up_carries_on(self):
        result = self.start(LLDPQ_SSHD='no', FAKE_PASSWD_RC='1')
        self.assertEqual(result.stderr,
                         '⚠ the password of the lldpq account could not be locked\n')
        self.assertEqual(self.called('sshd'), [])
        self.assertEqual(self.called('chpasswd'), [])
        self.assertIn('  SSH: disabled (LLDPQ_SSHD=no)', result.stdout)


class SshdContractTests(unittest.TestCase):
    def test_every_use_of_the_service_is_behind_the_switch(self):
        # The password write, the start and the port in the ready line exist
        # once each, in the blocks run above.
        self.assertEqual(ENTRYPOINT.count('| chpasswd'), 1)
        self.assertEqual(SETUP_BLOCK.count('| chpasswd'), 1)
        self.assertEqual(len(re.findall(r'(?m)^[^#\n]*/usr/sbin/sshd', ENTRYPOINT)), 1)
        self.assertEqual(ENTRYPOINT.count(ADVERTISED), 1)
        self.assertEqual(READY_BLOCK.count(ADVERTISED), 1)
        for block in (SETUP_BLOCK, START_BLOCK, READY_BLOCK):
            self.assertEqual(block.count('if [ "$SSHD_ENABLED" = true ]; then'), 1)
        # The switch is read before anything is started.
        self.assertLess(ENTRYPOINT.index('SSHD_ENABLED=true'),
                        ENTRYPOINT.index('service cron start'))

    def test_value_is_read_like_the_management_vrf_switch(self):
        for name, block in (('LLDPQ_SSHD', SETUP_BLOCK), ('LLDPQ_ENTER_MGMT_VRF', ENTRYPOINT)):
            self.assertIn('"${%s:-yes}" | tr \'[:upper:]\' \'[:lower:]\')' % name, block)
            self.assertIn(f'{name}=${name} is not understood (use yes or no);', block)
        for choices in ('no|false|off|0)', 'yes|true|on|1)'):
            self.assertIn(choices, SETUP_BLOCK)
            self.assertEqual(ENTRYPOINT.count(choices), 2)

    def test_image_ships_the_account_without_a_password(self):
        # useradd without -p leaves the password locked in /etc/shadow, so a
        # container that starts with LLDPQ_SSHD=no never had a usable one.
        created = re.findall(r'(?m)^RUN useradd .*\blldpq\b.*$', DOCKERFILE)
        self.assertEqual(len(created), 1)
        self.assertNotRegex(created[0], r'\s(-p|--password)\b')
        self.assertNotIn('chpasswd', DOCKERFILE)
        self.assertNotRegex(DOCKERFILE, r'\bpasswd\s')
        self.assertNotRegex(DOCKERFILE, r'\busermod\b.*\s(-p|--password)\b')

    def test_compose_files_show_the_switch_without_setting_it(self):
        # Same form as LLDPQ_ENTER_MGMT_VRF: a commented example in the service's
        # environment.  The stock files do not pass shell variables through.
        self.assertIn('      # LLDPQ_ENTER_MGMT_VRF: "no"\n', PROVISIONING_COMPOSE)
        self.assertIn('      # LLDPQ_SSHD: "no"\n', PROVISIONING_COMPOSE)
        self.assertIn('      # - LLDPQ_SSHD=no\n', COMPOSE)
        for name, text in (('docker-compose.yml', COMPOSE),
                           ('docker-compose.provisioning.yml', PROVISIONING_COMPOSE)):
            environment = text[text.index('    environment:'):text.index('\nvolumes:')]
            self.assertIn('LLDPQ_SSHD', environment, name)
            active = [line for line in text.splitlines()
                      if 'LLDPQ_SSHD' in line and not line.lstrip().startswith('#')]
            self.assertEqual(active, [], name)


if __name__ == '__main__':
    unittest.main()
