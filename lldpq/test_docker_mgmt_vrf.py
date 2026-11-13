"""Management-VRF handling of the Docker entrypoint on a Cumulus switch.

With --network host the container shares the switch's network namespace.  An
earlier entrypoint made the management network reachable by adding an unscoped
`pref 100 lookup <mgmt table>` IPv4 rule there, which captured the switch's own
lookups as well: it stopped answering ARP and ping on every in-band address.

The entrypoint now re-runs itself inside the VRF with `ip vrf exec` and adds
nothing to the host's routing policy; the only thing it changes there is
removing that old rule.  These tests pin the contract with stand-in ip, sudo,
id and curl binaries; nothing here needs Linux, a VRF or root.
"""

import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = (ROOT / 'docker/docker-entrypoint.sh').read_text()
DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
BASHRC = (ROOT / 'docker/dotf/bashrc').read_text()
DOCKER_DOC = (ROOT / 'DOCKER.md').read_text()
README = (ROOT / 'README.md').read_text()
HELPER = ROOT / 'docker/lldpq-vrf'
CURL_WRAPPER = ROOT / 'docker/curl-vrf'
MAKEFILE = (ROOT / 'Makefile').read_text()
PROVISIONING_COMPOSE = (ROOT / 'docker/docker-compose.provisioning.yml').read_text()
SELF_ENTERING_COMMANDS = ('lldpq', 'get-conf', 'send-cmd', 'pping')

ENTER_CALL = '\n_enter_mgmt_vrf "$@"\n'
# Everything the entrypoint does up to and including the VRF step.
ENTRYPOINT_HEAD = ENTRYPOINT[:ENTRYPOINT.index(ENTER_CALL) + len(ENTER_CALL)]
# The VRF definitions alone, without the call.
VRF_BLOCK = ENTRYPOINT_HEAD[ENTRYPOINT_HEAD.index('# ─── VRF Setup'):-len(ENTER_CALL)]

LEGACY_RULE = '100:\tfrom all lookup 1001 \n'
STOCK_RULES = ('1000:\tfrom all lookup [l3mdev-table] \n'
               '32765:\tfrom all lookup local \n'
               '32766:\tfrom all lookup main \n'
               '32767:\tfrom all lookup default \n')
LOOPBACK_ADDR = '9: mgmt    inet 127.0.0.1/8 scope host mgmt\\       valid_lft forever'

SEP = '\x1f'

# Each call is logged as one line of SEP-terminated arguments, so a test sees
# the exact argument vector.  The loopback probe (multi-line Python) is logged
# as one token and its source is saved for inspection.
FAKE_IP = r'''#!/bin/bash
log() { printf '%s\x1f' "$@" >> "$IP_LOG"; printf '\n' >> "$IP_LOG"; }
if [ "$1 $2 $3 $4 $5" = "vrf exec mgmt python3 -c" ]; then
    printf '%s' "$6" > "$PROBE_FILE"
    log vrf exec mgmt '<loopback-probe>'
    [ -z "${FAKE_PROBE_OUTPUT:-}" ] || printf '%s\n' "$FAKE_PROBE_OUTPUT" >&2
    exit "${FAKE_VRF_EXEC_RC:-0}"
fi
log "$@"
case "$*" in
    "vrf show mgmt")
        [ -n "${FAKE_VRF_TABLE:-}" ] || { echo "Invalid VRF" >&2; exit 1; }
        echo "mgmt $FAKE_VRF_TABLE" ;;
    "-4 rule show")
        printf '%s' "${FAKE_RULES:-}" ;;
    "-4 rule del "*)
        exit "${FAKE_RULE_DEL_RC:-0}" ;;
    "vrf identify")
        [ -z "${FAKE_CURRENT_VRF:-}" ] || echo "$FAKE_CURRENT_VRF" ;;
    "vrf identify 1")
        [ -z "${FAKE_SERVICE_VRF:-}" ] || echo "$FAKE_SERVICE_VRF" ;;
    "-4 -o addr show dev mgmt")
        [ -z "${FAKE_VRF_ADDR:-}" ] || printf '%s\n' "$FAKE_VRF_ADDR" ;;
    "vrf exec mgmt true")
        [ -z "${FAKE_VRF_USABLE_OUTPUT:-}" ] || printf '%s\n' "$FAKE_VRF_USABLE_OUTPUT" >&2
        exit "${FAKE_VRF_USABLE_RC:-0}" ;;
    "vrf exec mgmt "*)
        log reexec-marker "${LLDPQ_VRF_REEXEC:-}"
        if [ "${FAKE_VRF_EXEC_RUN:-0}" = 1 ]; then
            shift 3
            export FAKE_CURRENT_VRF=mgmt
            exec "$@"
        fi ;;
    *)
        log UNEXPECTED "$@"
        echo "unexpected ip call: $*" >&2
        exit 99 ;;
esac
'''

# Real sudo also resets the environment; this stand-in keeps it.
FAKE_SUDO = r'''#!/bin/bash
printf '%s\x1f' "$@" >> "$SUDO_LOG"; printf '\n' >> "$SUDO_LOG"
while [ $# -gt 0 ]; do
    case "$1" in
        -n) shift ;;
        -u) shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done
exec "$@"
'''

FAKE_ID = r'''#!/bin/bash
case "$*" in
    -u) echo "${FAKE_UID:-1000}" ;;
    -un) echo "${FAKE_USER:-lldpq}" ;;
    *) echo "unexpected id call: $*" >&2; exit 99 ;;
esac
'''


def args(text):
    return text.split(' ')


def shell_function(name):
    """One function of the entrypoint, up to its closing brace in the first column."""
    lines = ENTRYPOINT[ENTRYPOINT.index(f'\n{name}() {{\n') + 1:].splitlines(keepends=True)
    return ''.join(lines[:lines.index('}\n') + 1])


def syntax_sweep():
    """The Makefile's bash -n loop: its file patterns and the loop as a shell script."""
    loop = re.search(r'(?ms)^\t@(for f in (?P<files>.*?); do \\\n.*?\n\tdone)$', MAKEFILE)
    assert loop, 'the bash -n sweep is missing from the Makefile'
    patterns = loop.group('files').replace('\\\n', ' ').split()
    return patterns, loop.group(1).replace('\\\n', ' ').replace('$$', '$')


def first_line(path):
    with open(path, 'rb') as handle:
        return handle.readline(200)


# Sourced by a shell, so they carry no shebang to recognise them by.
SOURCED_BASH = ('docker/dotf/bashrc', 'lldpq/sw-base/bash.bashrc')


def source_files():
    """What git tracks or would track; without a checkout, the source directories."""
    try:
        listed = subprocess.run(
            ['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others',
             '--exclude-standard'], capture_output=True, timeout=60, check=True).stdout
        return [ROOT / os.fsdecode(name) for name in listed.split(b'\0') if name]
    except (OSError, subprocess.SubprocessError):
        files = [path for path in ROOT.iterdir() if path.is_file()]
        for top in ('bin', 'docker', 'etc', 'html', 'lldpq', 'telemetry'):
            for directory, subdirectories, names in os.walk(ROOT / top):
                subdirectories[:] = [name for name in subdirectories
                                     if not name.startswith('.')
                                     and name not in ('__pycache__', 'monitor-results')]
                files.extend(Path(directory, name) for name in names)
        return files


def bash_files():
    """Every bash file of the source tree, by shebang, plus the sourced ones."""
    found = set(SOURCED_BASH)
    for path in source_files():
        if path.is_file() and re.match(rb'#!.*\b(ba)?sh\b', first_line(path)):
            found.add(path.relative_to(ROOT).as_posix())
    return found


def _prefixes(word, shortest=1):
    # iproute2 accepts every prefix of an object name: `ip ro`, `ip rou`, `ip route`.
    return '|'.join(word[:length] for length in range(len(word), shortest - 1, -1))


# Commands that change the routing, sysctl or firewall state of whatever
# network namespace they run in.  With --network host that is the switch.
HOST_STATE_CHANGES = tuple(re.compile(pattern) for pattern in (
    r'\bip\b(\s+-\S+)*\s+(' + '|'.join((
        _prefixes('rule', 2), _prefixes('route'), _prefixes('address'), _prefixes('link'),
        _prefixes('neighbour'), 'neighbor', _prefixes('netns', 4), _prefixes('nexthop', 3),
        _prefixes('tunnel', 3), _prefixes('tuntap', 4)))
    + r')\s+(a|ad|add|d|de|del|delete|replace|change|chg|flush|set|append|prepend)\b',
    r'\bsysctl\b[^|;&#)]*\s(-\w*[wp]\w*\b|--(write|load|system)\b|[\w.]+=\S)',
    r'(>|\btee\b[^|;&]*\s)\s*["\']?/proc/sys/',
    r'\b(iptables|ip6tables|ebtables|arptables|ipset|nft)(-restore)?\s+\S',
    r'\btc\b(\s+-\S+)*\s+(qdisc|filter|class)\s+(add|del|delete|replace|change|link)\b',
))


def host_state_changes(text):
    """(line number, line) of every non-comment line holding such a command."""
    return [(number, line) for number, line in enumerate(text.splitlines(), 1)
            if not line.lstrip().startswith('#')
            and any(pattern.search(line) for pattern in HOST_STATE_CHANGES)]


class FakeHost:
    """A PATH with stand-in ip/sudo/id binaries that record how they are called."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-vrf-')
        self.root = Path(self._tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, body in (('ip', FAKE_IP), ('sudo', FAKE_SUDO), ('id', FAKE_ID)):
            self.add_binary(name, body)
        self.ip_log = self.root / 'ip.log'
        self.sudo_log = self.root / 'sudo.log'
        self.probe_file = self.root / 'probe.py'
        self.marker = self.root / 'service-vrf'
        # Stands in for /sys/class/net; empty until a test gives mgmt an ifindex.
        self.sys_net = self.root / 'sys-class-net'
        self.sys_net.mkdir()

    def set_ifindex(self, content, device='mgmt'):
        """The device's ifindex file as the kernel publishes it; None: no such device."""
        directory = self.sys_net / device
        if content is None:
            (directory / 'ifindex').unlink(missing_ok=True)
            if directory.exists():
                directory.rmdir()
            return
        directory.mkdir(exist_ok=True)
        (directory / 'ifindex').write_text(content)

    def add_binary(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def close(self):
        self._tmp.cleanup()

    def env(self, **overrides):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('FAKE_', 'LLDPQ_'))}
        env.update(PATH=f"{self.bin}{os.pathsep}{env['PATH']}",
                   IP_LOG=str(self.ip_log), SUDO_LOG=str(self.sudo_log),
                   PROBE_FILE=str(self.probe_file),
                   LLDPQ_SERVICE_VRF_FILE=str(self.marker),
                   LLDPQ_SYS_CLASS_NET=str(self.sys_net),
                   FAKE_VRF_ADDR=LOOPBACK_ADDR)
        env.update(overrides)
        return env

    @staticmethod
    def read(log):
        if not log.exists():
            return []
        # A record ends with SEP + newline; an argument may itself hold newlines.
        return [record.split(SEP) for record in log.read_text().split(SEP + '\n')[:-1]]


class FakeHostCase(unittest.TestCase):
    def setUp(self):
        self.host = FakeHost()
        self.addCleanup(self.host.close)
        self.addCleanup(self.assert_only_expected_ip_calls)

    def ip_calls(self):
        return self.host.read(self.host.ip_log)

    def sudo_calls(self):
        return self.host.read(self.host.sudo_log)

    def vrf_exec_calls(self):
        return [call for call in self.ip_calls() if call[:2] == ['vrf', 'exec']]

    def rule_deletes(self):
        return [call for call in self.ip_calls() if call[:3] == ['-4', 'rule', 'del']]

    def assert_only_expected_ip_calls(self):
        self.assertEqual([call for call in self.ip_calls() if call[0] == 'UNEXPECTED'], [])

    def fake_helper(self, pending, usable=True):
        self.host.add_binary('lldpq-vrf', textwrap.dedent(f'''\
            #!/bin/bash
            printf '%s\\x1f' "$@" >> "$IP_LOG"; printf '\\n' >> "$IP_LOG"
            case "$1" in
                --pending) exit {0 if pending else 1} ;;
                true) exit {0 if usable else 1} ;;
            esac
            '''))

    def assert_nothing_added_to_the_host(self):
        added = [call for call in self.ip_calls()
                 if re.search(r'\b(ru\w*|ro\w*|a\w*|l\w*) (a|add|replace|change|set)\b',
                              ' '.join(call)) and call[:2] != ['vrf', 'exec']]
        self.assertEqual(added, [])


class EnterManagementVrfTests(FakeHostCase):
    def run_entrypoint(self, **env):
        source = f'set -e\n{VRF_BLOCK}\n_enter_mgmt_vrf "$@"\necho CONTINUED\necho "STATUS=$MGMT_VRF_STATUS"\n'
        return subprocess.run(
            ['bash', '-c', source, '/docker-entrypoint.sh', 'first', 'second  arg', '*', ''],
            capture_output=True, text=True, timeout=20, env=self.host.env(**env))

    def test_without_a_management_vrf_nothing_happens(self):
        result = self.run_entrypoint()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'CONTINUED\nSTATUS=\n')
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.ip_calls(), [args('vrf show mgmt')])

    def test_reruns_itself_inside_the_vrf_with_its_exact_arguments(self):
        result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('CONTINUED', result.stdout)
        self.assertEqual(self.ip_calls()[-4:], [
            ['vrf', 'exec', 'mgmt', 'true'],
            ['vrf', 'exec', 'mgmt', '<loopback-probe>'],
            ['vrf', 'exec', 'mgmt', '/bin/bash', '/docker-entrypoint.sh',
             'first', 'second  arg', '*', ''],
            ['reexec-marker', '1'],
        ])
        self.assert_nothing_added_to_the_host()

    def test_second_pass_inside_the_vrf_carries_on_and_records_the_vrf(self):
        result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=LEGACY_RULE,
                                     FAKE_CURRENT_VRF='mgmt', LLDPQ_VRF_REEXEC='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        line = '✓ mgmt VRF detected (table 1001) — services run inside it'
        self.assertEqual(result.stdout, f'{line}\nCONTINUED\nSTATUS={line}\n')
        self.assertEqual(self.host.marker.read_text(), 'mgmt\n')
        self.assertEqual(self.vrf_exec_calls(), [])
        # The first pass already dealt with the old rule; do not repeat it.
        self.assertEqual(self.rule_deletes(), [])

    def test_stale_marker_is_removed_when_the_vrf_is_not_entered(self):
        self.host.marker.write_text('mgmt\n')
        self.run_entrypoint()
        self.assertFalse(self.host.marker.exists())

    def test_marker_path_that_is_not_a_plain_file_is_left_alone(self):
        # The path comes from the environment; only a file the entrypoint could
        # have written is removed or replaced.
        self.host.marker.mkdir()
        (self.host.marker / 'kept').write_text('x')
        for env in ({}, dict(FAKE_VRF_TABLE='1001', FAKE_CURRENT_VRF='mgmt',
                             LLDPQ_VRF_REEXEC='1')):
            with self.subTest(env=env):
                result = self.run_entrypoint(**env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('CONTINUED', result.stdout)
                self.assertTrue((self.host.marker / 'kept').exists())

    def test_does_not_loop_when_the_rerun_is_still_outside(self):
        result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES,
                                     LLDPQ_VRF_REEXEC='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CONTINUED\nSTATUS=⚠ mgmt VRF not entered', result.stdout)
        self.assertIn('still outside it after re-running', result.stderr)
        self.assertEqual(self.vrf_exec_calls(), [])
        self.assertFalse(self.host.marker.exists())

    def test_vrf_device_needs_the_loopback_address_itself(self):
        for address in ('', '9: mgmt    inet 192.0.2.1/24 scope global mgmt',
                        '9: mgmt    inet 127.0.0.2/8 scope host mgmt',
                        '9: mgmt    inet 127.0.0.10/8 scope host mgmt'):
            with self.subTest(address=address):
                self.host.ip_log.unlink(missing_ok=True)
                result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES,
                                             FAKE_VRF_ADDR=address)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('CONTINUED', result.stdout)
                self.assertIn('no 127.0.0.1 address', result.stderr)
                self.assertEqual(self.vrf_exec_calls(), [])

    def test_unusable_vrf_exec_keeps_the_container_starting_and_names_privileged(self):
        result = self.run_entrypoint(
            FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES, FAKE_VRF_USABLE_RC='255',
            FAKE_VRF_USABLE_OUTPUT="mkdir failed for cgroup\nFailed to load BPF prog: 'Operation not permitted'")
        self.assertEqual(result.returncode, 0, result.stderr)
        warning = ("⚠ mgmt VRF not entered: 'ip vrf exec' is not usable here (the container "
                   "needs --privileged) [reported: Failed to load BPF prog: 'Operation not "
                   "permitted']; services run in the default VRF and may not reach the "
                   "management network")
        self.assertEqual(result.stderr, warning + '\n')
        self.assertEqual(result.stdout, f'CONTINUED\nSTATUS={warning}\n')
        # The loopback probe is not attempted and nothing is re-run.
        self.assertEqual(self.vrf_exec_calls(), [['vrf', 'exec', 'mgmt', 'true']])
        self.assertFalse(self.host.marker.exists())
        self.assert_nothing_added_to_the_host()

    def test_failed_probe_keeps_the_container_starting_and_says_why(self):
        cases = (
            ('Traceback (most recent call last):\nTimeoutError: timed out',
             'timed out (does the host firewall drop loopback traffic on the mgmt device?)',
             'TimeoutError: timed out'),
            ('Traceback (most recent call last):\n'
             'ConnectionRefusedError: [Errno 111] Connection refused',
             "was refused (is the local rule ahead of the l3mdev rule in 'ip rule show'?)",
             'ConnectionRefusedError: [Errno 111] Connection refused'),
            ('Traceback (most recent call last):\n'
             'OSError: [Errno 101] Network is unreachable',
             '127.0.0.1 is not usable inside it',
             'OSError: [Errno 101] Network is unreachable'),
        )
        for output, reason, reported in cases:
            with self.subTest(reported=reported):
                self.host.ip_log.unlink(missing_ok=True)
                result = self.run_entrypoint(
                    FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES, FAKE_VRF_EXEC_RC='1',
                    FAKE_PROBE_OUTPUT=output)
                self.assertEqual(result.returncode, 0, result.stderr)
                # One line, complete on its own, and the same one at the ready message.
                self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
                self.assertIn(f'CONTINUED\nSTATUS={result.stderr}', result.stdout)
                self.assertTrue(result.stderr.startswith('⚠ mgmt VRF not entered: '))
                self.assertIn(reason, result.stderr)
                self.assertIn(f'[reported: {reported}]', result.stderr)
                self.assertNotIn('--privileged', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(self.vrf_exec_calls(), [
                    ['vrf', 'exec', 'mgmt', 'true'],
                    ['vrf', 'exec', 'mgmt', '<loopback-probe>']])
                self.assertFalse(self.host.marker.exists())
                self.assert_nothing_added_to_the_host()

    def test_probe_is_valid_python_and_passes_on_a_working_loopback(self):
        self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES)
        probe = self.host.probe_file.read_text()
        self.assertIn('127.0.0.1', probe)
        self.assertIn('settimeout', probe)
        result = subprocess.run([sys.executable, '-c', probe], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_leftover_rule_is_removed_before_entering(self):
        result = self.run_entrypoint(FAKE_VRF_TABLE='1001',
                                     FAKE_RULES=LEGACY_RULE + STOCK_RULES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('removed the unscoped mgmt VRF rule (pref 100)', result.stdout)
        calls = self.ip_calls()
        self.assertLess(calls.index(args('-4 rule del pref 100 table 1001')),
                        calls.index(['vrf', 'exec', 'mgmt', '<loopback-probe>']))

    def test_leftover_rule_is_removed_even_when_the_vrf_cannot_be_entered(self):
        result = self.run_entrypoint(FAKE_VRF_TABLE='1001',
                                     FAKE_RULES=LEGACY_RULE + STOCK_RULES,
                                     FAKE_VRF_EXEC_RC='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rule_deletes(), [args('-4 rule del pref 100 table 1001')])
        self.assertIn('CONTINUED', result.stdout)

    def test_opt_out_stays_in_the_default_vrf_but_still_removes_the_rule(self):
        for value in ('no', 'false', 'off', '0', 'NO', 'No', 'False', 'OFF'):
            with self.subTest(value=value):
                self.host.ip_log.unlink(missing_ok=True)
                result = self.run_entrypoint(FAKE_VRF_TABLE='1001',
                                             FAKE_RULES=LEGACY_RULE + STOCK_RULES,
                                             LLDPQ_ENTER_MGMT_VRF=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('CONTINUED', result.stdout)
                self.assertIn(f'LLDPQ_ENTER_MGMT_VRF={value}, services stay in the default VRF',
                              result.stdout)
                self.assertEqual(result.stderr, '')
                self.assertEqual(self.rule_deletes(),
                                 [args('-4 rule del pref 100 table 1001')])
                self.assertEqual(self.vrf_exec_calls(), [])
                self.assertFalse(self.host.marker.exists())

    def test_explicit_yes_enters_without_a_remark(self):
        for value in ('yes', 'true', 'on', '1', 'YES', 'True'):
            with self.subTest(value=value):
                self.host.ip_log.unlink(missing_ok=True)
                result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES,
                                             LLDPQ_ENTER_MGMT_VRF=value)
                self.assertEqual((result.returncode, result.stderr), (0, ''))
                self.assertEqual(self.ip_calls()[-1], ['reexec-marker', '1'])

    def test_value_that_is_not_understood_is_reported_and_the_vrf_entered(self):
        for value in ('nope', 'disabled', ' no', 'n o'):
            with self.subTest(value=value):
                self.host.ip_log.unlink(missing_ok=True)
                result = self.run_entrypoint(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES,
                                             LLDPQ_ENTER_MGMT_VRF=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stderr,
                    f'⚠ LLDPQ_ENTER_MGMT_VRF={value} is not understood (use yes or no); '
                    'entering the mgmt VRF\n')
                self.assertEqual(self.ip_calls()[-1], ['reexec-marker', '1'])

    # The ifindex of the VRF device, kept for the watchdog (VrfReplacedTests).
    def remembered_ifindex(self, **env):
        source = (f'set -e\n{VRF_BLOCK}\n_enter_mgmt_vrf "$@"\n'
                  'echo "IFINDEX=<$MGMT_VRF_IFINDEX>"\n')
        result = subprocess.run(['bash', '-c', source, '/docker-entrypoint.sh'],
                                capture_output=True, text=True, timeout=20,
                                env=self.host.env(**env))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()[-1], result.stderr

    INSIDE = dict(FAKE_VRF_TABLE='1001', FAKE_CURRENT_VRF='mgmt', LLDPQ_VRF_REEXEC='1')

    def test_ifindex_of_the_vrf_is_remembered_once_the_services_are_inside(self):
        self.host.set_ifindex('9\n')
        self.assertEqual(self.remembered_ifindex(**self.INSIDE), ('IFINDEX=<9>', ''))

    def test_no_ifindex_is_remembered_outside_the_vrf(self):
        # The device is there each time; the services are not started in it.
        self.host.set_ifindex('9\n')
        for env in ({},
                    dict(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES,
                         LLDPQ_ENTER_MGMT_VRF='no'),
                    dict(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES, FAKE_VRF_ADDR=''),
                    dict(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES, FAKE_VRF_EXEC_RC='1'),
                    dict(FAKE_VRF_TABLE='1001', FAKE_RULES=STOCK_RULES, LLDPQ_VRF_REEXEC='1')):
            with self.subTest(env=env):
                self.host.ip_log.unlink(missing_ok=True)
                self.assertEqual(self.remembered_ifindex(**env)[0], 'IFINDEX=<>')

    def test_unreadable_ifindex_leaves_the_start_alone(self):
        for content in (None, '', 'mgmt\n', '9 9\n', '-1\n'):
            with self.subTest(content=content):
                self.host.set_ifindex(content)
                self.assertEqual(self.remembered_ifindex(**self.INSIDE), ('IFINDEX=<>', ''))
                self.assertEqual(self.host.marker.read_text(), 'mgmt\n')


class TwoPassStartTests(FakeHostCase):
    """The real head of the entrypoint, run through the re-exec and back."""

    ARGS = ('first', 'two  spaces', '*', '')
    REPORT = ('echo "STATUS=$MGMT_VRF_STATUS"\n'
              'echo "RULE=$MGMT_RULE_WARNING"\n'
              'echo "HANDOVER=${LLDPQ_MGMT_RULE_WARNING-unset}"\n')

    def start(self, report=REPORT, **env):
        script = self.host.root / 'docker-entrypoint.sh'
        script.write_text(ENTRYPOINT_HEAD + 'printf "ARG<%s>\\n" "$@"\n' + report)
        return subprocess.run(
            ['bash', str(script), *self.ARGS], capture_output=True, text=True, timeout=20,
            env=self.host.env(FAKE_VRF_TABLE='1001', FAKE_VRF_EXEC_RUN='1', **env))

    def test_banner_once_arguments_intact_and_services_inside(self):
        result = self.start(FAKE_RULES=LEGACY_RULE + STOCK_RULES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(result.stdout.count('LLDPq Network Monitoring'), 1)
        line = '✓ mgmt VRF detected (table 1001) — services run inside it'
        self.assertTrue(result.stdout.endswith(
            f'{line}\nARG<first>\nARG<two  spaces>\nARG<*>\nARG<>\nSTATUS={line}\n'
            'RULE=\nHANDOVER=unset\n'), result.stdout)
        self.assertEqual(result.stdout.count('removed the unscoped mgmt VRF rule'), 1)
        self.assertEqual(self.rule_deletes(), [args('-4 rule del pref 100 table 1001')])
        self.assertEqual(self.host.marker.read_text(), 'mgmt\n')
        self.assert_nothing_added_to_the_host()

    def test_unremovable_rule_is_reported_once_and_kept_for_the_ready_message(self):
        result = self.start(FAKE_RULES=LEGACY_RULE + STOCK_RULES, FAKE_RULE_DEL_RC='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        warning = ('⚠ an earlier LLDPq image left an unscoped mgmt VRF rule (pref 100) on '
                   'this host and it could not be removed. Run on the host: '
                   'sudo ip rule del pref 100 table 1001')
        self.assertEqual(result.stderr, warning + '\n')
        self.assertIn('ARG<first>', result.stdout)
        # The re-run inside the VRF still knows, without leaving it in the
        # environment of the services.
        self.assertTrue(result.stdout.endswith(f'RULE={warning}\nHANDOVER=unset\n'),
                        result.stdout)

    def test_ifindex_is_remembered_by_the_pass_that_starts_the_services(self):
        self.host.set_ifindex('9\n')
        result = self.start(report='echo "IFINDEX=<$MGMT_VRF_IFINDEX>"\n',
                            FAKE_RULES=STOCK_RULES)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith('ARG<>\nIFINDEX=<9>\n'), result.stdout)


class VrfReplacedTests(unittest.TestCase):
    """The watchdog notices that the VRF the services were started in was re-created.

    Deleting the VRF and creating it again (ifdown/ifup of mgmt) gives a new
    device with a new ifindex, while the sockets the services opened stay bound
    to the old one.  The watchdog only says so, once per change; it restarts
    nothing.  The real loop runs here against a stand-in for /sys/class/net.
    """

    GONE = ('CRITICAL: the mgmt VRF device the services were started in (ifindex 9) is '
            'gone; the services are still bound to that old device. When the VRF is back, '
            'restart the container: docker restart lldpq')

    @staticmethod
    def replaced(now, start=9):
        return (f'CRITICAL: the mgmt VRF was re-created (ifindex {start} at start, now {now}); '
                'the services are still bound to the old device and do not use the new one. '
                'Restart the container: docker restart lldpq')

    def setUp(self):
        self.host = FakeHost()
        self.addCleanup(self.host.close)

    def watch(self, polls, start='9'):
        """Run the loop for len(polls) rounds; before each the device gets that ifindex.

        None removes the device.  Returns what the loop wrote, one list per stream.
        """
        device = self.host.sys_net / 'mgmt'
        steps = []
        for number, ifindex in enumerate(polls, 1):
            if ifindex is None:
                steps.append(f'{number}) rm -rf "{device}" ;;')
            else:
                steps.append(f'{number}) mkdir -p "{device}"; '
                             f'echo {ifindex} > "{device}/ifindex" ;;')
        source = '\n'.join((
            'set -e',
            'WATCHDOG_POLL_DELAY=0', 'WATCHDOG_STORM_LIMIT=5', 'WATCHDOG_STORM_WINDOW=60',
            'LLDPQ_MGMT_VRF=mgmt',
            f'LLDPQ_SYS_CLASS_NET="{self.host.sys_net}"',
            f'MGMT_VRF_IFINDEX={start}',
            'polls=0',
            'sleep() {',
            '    polls=$((polls + 1))',
            '    case $polls in',
            *steps,
            '        *) exit 0 ;;',
            '    esac',
            '}',
            # The other two things the loop looks after are healthy throughout.
            '_fcgiwrap_pool_healthy() { return 0; }',
            'pgrep() { return 0; }',
            '_stop_fcgiwrap() { :; }',
            '_restart_fcgiwrap() { echo ACTED: fcgiwrap restarted; }',
            '_restart_cron() { echo ACTED: cron restarted; }',
            'kill() { echo "ACTED: kill $*"; }',
            'cat() { echo read >> "$READS"; command cat "$@"; }',
            shell_function('_supervise_services'),
            '_supervise_services', ''))
        self.reads = self.host.root / 'reads'
        self.reads.unlink(missing_ok=True)
        result = subprocess.run(['bash', '-c', source], capture_output=True, text=True,
                                timeout=20, env=self.host.env(READS=str(self.reads)))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines(), result.stderr.splitlines()

    def test_unchanged_vrf_is_never_mentioned(self):
        self.assertEqual(self.watch([9, 9, 9, 9]), ([], []))
        # It was looked at on every round.
        self.assertEqual(len(self.reads.read_text().splitlines()), 4)

    def test_recreated_vrf_is_reported_once(self):
        self.assertEqual(self.watch([9, 14, 14, 14, 14]), ([], [self.replaced(14)]))

    def test_removed_vrf_is_reported_once_and_again_when_it_is_back(self):
        self.assertEqual(self.watch([9, None, None, None, 14, 14]),
                         ([], [self.GONE, self.replaced(14)]))

    def test_every_further_change_gets_its_own_line(self):
        self.assertEqual(self.watch([14, 14, 21, None, 30, 30]),
                         ([], [self.replaced(14), self.replaced(21), self.GONE,
                               self.replaced(30)]))

    def test_same_device_back_after_a_failed_read_is_not_reported_as_replaced(self):
        self.assertEqual(self.watch([None, 9, 9]), ([], [self.GONE]))

    def test_nothing_is_watched_when_the_services_run_in_the_default_vrf(self):
        # No VRF, opt-out or a VRF that could not be entered: no ifindex was
        # remembered, so the device is not even looked at.
        self.assertEqual(self.watch([9, 14, None, 21], start=''), ([], []))
        self.assertFalse(self.reads.exists())

    def test_watchdog_only_reports(self):
        # stdout stays empty in every scenario above: nothing was killed or
        # restarted.  The loop's own text agrees.
        watchdog = shell_function('_supervise_services')
        watch = watchdog[watchdog.index('if [ -n "$MGMT_VRF_IFINDEX" ]; then'):]
        commands = [line.strip() for line in watch.splitlines()
                    if line.strip() and not line.strip().startswith(('#', 'echo "CRITICAL: '))]
        self.assertEqual(commands, [
            'if [ -n "$MGMT_VRF_IFINDEX" ]; then',
            'vrf_ifindex=$(cat "$LLDPQ_SYS_CLASS_NET/$LLDPQ_MGMT_VRF/ifindex" 2>/dev/null)'
            ' || vrf_ifindex=""',
            'if [ "$vrf_ifindex" != "$vrf_ifindex_seen" ]; then',
            'vrf_ifindex_seen=$vrf_ifindex',
            'if [ -z "$vrf_ifindex" ]; then',
            'elif [ "$vrf_ifindex" != "$MGMT_VRF_IFINDEX" ]; then',
            'fi', 'fi', 'fi', 'done', '}'])
        # CRITICAL is the loudest level the loop has, and it goes to stderr.
        self.assertEqual(watch.count('echo "CRITICAL: '), 2)
        self.assertEqual(watch.count('" >&2\n'), 2)


class LegacyRuleCleanupTests(FakeHostCase):
    def cleanup(self, rules, **env):
        source = f'set -e\n{VRF_BLOCK}\n_remove_legacy_mgmt_rule mgmt 1001\necho DONE\n'
        result = subprocess.run(
            ['bash', '-c', source], capture_output=True, text=True, timeout=20,
            env=self.host.env(FAKE_RULES=rules, **env))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith('DONE\n'), result.stdout)
        return result, self.rule_deletes()

    def test_exact_rule_is_removed(self):
        result, deletes = self.cleanup(LEGACY_RULE + STOCK_RULES)
        self.assertEqual(deletes, [args('-4 rule del pref 100 table 1001')])
        self.assertIn('removed the unscoped mgmt VRF rule', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_rule_printed_with_the_table_name_is_removed(self):
        _, deletes = self.cleanup('100:\tfrom all lookup mgmt \n' + STOCK_RULES)
        self.assertEqual(deletes, [args('-4 rule del pref 100 table 1001')])

    def test_rule_printed_with_other_spacing_is_removed(self):
        _, deletes = self.cleanup('100: from all lookup 1001\n' + STOCK_RULES)
        self.assertEqual(deletes, [args('-4 rule del pref 100 table 1001')])

    def test_stock_rules_are_left_alone(self):
        result, deletes = self.cleanup(STOCK_RULES)
        self.assertEqual(deletes, [])
        self.assertEqual(result.stdout, 'DONE\n')
        self.assertEqual(result.stderr, '')

    def test_rules_with_any_selector_are_left_alone(self):
        for rule in ('100:\tfrom 10.0.0.0/8 lookup 1001 \n',
                     '100:\tfrom all to 10.0.0.0/8 lookup 1001 \n',
                     '100:\tfrom all iif swp1 lookup 1001 \n',
                     '100:\tfrom all oif eth0 lookup 1001 \n',
                     '100:\tfrom all fwmark 0x1 lookup 1001 \n',
                     '100:\tfrom all uidrange 1000-1000 lookup 1001 \n',
                     '100:\tnot from all lookup 1001 \n',
                     '100:\tfrom all lookup 1001 proto static \n',
                     '100:\tfrom all lookup mgmt suppress_prefixlength 0 \n'):
            with self.subTest(rule=rule.strip()):
                self.host.ip_log.unlink(missing_ok=True)
                result, deletes = self.cleanup(rule + STOCK_RULES)
                self.assertEqual(deletes, [])
                self.assertEqual(result.stderr, '')

    def test_other_tables_and_preferences_are_left_alone(self):
        _, deletes = self.cleanup('100:\tfrom all lookup 1002 \n'
                                  '100:\tfrom all lookup main \n'
                                  '99:\tfrom all lookup 1001 \n'
                                  '1001:\tfrom all lookup 1001 \n'
                                  '1100:\tfrom all lookup 1001 \n'
                                  '32100:\tfrom all lookup 1001 \n' + STOCK_RULES)
        self.assertEqual(deletes, [])

    def test_rule_next_to_a_scoped_rule_for_the_same_table_is_reported_not_removed(self):
        result, deletes = self.cleanup(
            LEGACY_RULE + '100:\tfrom 10.0.0.0/8 lookup 1001 \n' + STOCK_RULES)
        self.assertEqual(deletes, [])
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
        self.assertIn('it was not removed', result.stderr)
        self.assertIn('Review on the host: ip -4 rule show', result.stderr)

    def test_every_duplicate_is_removed(self):
        # Kernels older than 4.17 accepted identical rules, one per container start.
        _, deletes = self.cleanup(LEGACY_RULE * 3 + STOCK_RULES)
        self.assertEqual(deletes, [args('-4 rule del pref 100 table 1001')] * 3)

    def test_failed_delete_names_the_manual_command(self):
        result, deletes = self.cleanup(LEGACY_RULE + STOCK_RULES, FAKE_RULE_DEL_RC='2')
        self.assertEqual(deletes, [args('-4 rule del pref 100 table 1001')])
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
        self.assertIn('Run on the host: sudo ip rule del pref 100 table 1001', result.stderr)
        self.assertNotIn('removed the unscoped', result.stdout)

    def test_vrf_table_lookup_matches_the_name_exactly(self):
        self.host.add_binary('ip', '#!/bin/bash\n'
                             'printf "Name Table\\n-----\\nmgmt2 1002\\nxmgmt 1003\\nmgmt 1001\\n"\n')
        source = f'{VRF_BLOCK}\n_mgmt_vrf_table mgmt\n'
        result = subprocess.run(['bash', '-c', source], capture_output=True, text=True,
                                timeout=20, env=self.host.env())
        self.assertEqual(result.stdout, '1001\n')


class VrfHelperTests(FakeHostCase):
    def helper(self, *arguments, **env):
        return subprocess.run(['bash', str(HELPER), *arguments], capture_output=True,
                              text=True, timeout=20, env=self.host.env(**env))

    def test_plain_pass_through_when_the_services_are_not_in_a_vrf(self):
        result = self.helper('printf', '%s\n', 'a  b', '*')
        self.assertEqual((result.returncode, result.stdout), (0, 'a  b\n*\n'))
        self.assertEqual(self.ip_calls(), [args('vrf identify 1'), args('vrf identify')])
        self.assertEqual(self.sudo_calls(), [])

    def test_plain_pass_through_when_already_inside(self):
        result = self.helper('echo', 'hello', FAKE_SERVICE_VRF='mgmt',
                             FAKE_CURRENT_VRF='mgmt')
        self.assertEqual((result.returncode, result.stdout), (0, 'hello\n'))
        self.assertEqual(self.vrf_exec_calls(), [])

    def test_root_enters_the_services_vrf(self):
        result = self.helper('sh', '-c', 'echo "in=$LLDPQ_IN_VRF"; exit 7',
                             FAKE_SERVICE_VRF='mgmt', FAKE_UID='0', FAKE_VRF_EXEC_RUN='1')
        self.assertEqual((result.returncode, result.stdout), (7, 'in=mgmt\n'))
        self.assertEqual(self.vrf_exec_calls(), [
            ['vrf', 'exec', 'mgmt', 'env', 'LLDPQ_IN_VRF=mgmt',
             'sh', '-c', 'echo "in=$LLDPQ_IN_VRF"; exit 7']])
        self.assertEqual(self.sudo_calls(), [])

    def test_other_users_enter_as_root_and_drop_back(self):
        result = self.helper('sh', '-c', 'echo "in=$LLDPQ_IN_VRF"; exit 7',
                             FAKE_SERVICE_VRF='mgmt', FAKE_UID='1000', FAKE_USER='lldpq',
                             FAKE_VRF_EXEC_RUN='1')
        self.assertEqual((result.returncode, result.stdout), (7, 'in=mgmt\n'))
        self.assertEqual(self.sudo_calls()[0], [
            '-n', 'ip', 'vrf', 'exec', 'mgmt', 'sudo', '-n', '-u', 'lldpq', '--',
            'env', 'LLDPQ_IN_VRF=mgmt', 'sh', '-c', 'echo "in=$LLDPQ_IN_VRF"; exit 7'])

    def test_vrf_recorded_by_the_entrypoint_wins_over_pid_1(self):
        # With `docker run --init` PID 1 is docker-init, outside the VRF.
        self.host.marker.write_text('mgmt\n')
        result = self.helper('true', FAKE_UID='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.vrf_exec_calls()[0],
                         ['vrf', 'exec', 'mgmt', 'env', 'LLDPQ_IN_VRF=mgmt', 'true'])
        self.assertNotIn(args('vrf identify 1'), self.ip_calls())

    def test_unusable_record_falls_back_to_pid_1(self):
        for content in ('', '\n', 'mgmt; reboot\n', '$(id)\n'):
            with self.subTest(content=content):
                self.host.ip_log.unlink(missing_ok=True)
                self.host.marker.write_text(content)
                result = self.helper('echo', 'ok', FAKE_UID='0')
                self.assertEqual((result.returncode, result.stdout), (0, 'ok\n'))
                self.assertIn(args('vrf identify 1'), self.ip_calls())
                self.assertEqual(self.vrf_exec_calls(), [])

    def test_record_that_is_not_a_plain_file_is_not_read(self):
        # Reading a FIFO would block every shell start and health probe.
        os.mkfifo(self.host.marker)
        result = self.helper('echo', 'ok', FAKE_UID='0')
        self.assertEqual((result.returncode, result.stdout), (0, 'ok\n'))
        self.assertIn(args('vrf identify 1'), self.ip_calls())

    def test_pending_reports_only_a_caller_outside_the_services_vrf(self):
        self.assertEqual(self.helper('--pending').returncode, 1)
        self.assertEqual(self.helper('--pending', FAKE_CURRENT_VRF='mgmt').returncode, 1)
        self.assertEqual(self.helper('--pending', FAKE_SERVICE_VRF='mgmt').returncode, 0)
        self.assertEqual(self.helper('--pending', FAKE_SERVICE_VRF='mgmt',
                                     FAKE_CURRENT_VRF='mgmt').returncode, 1)
        self.assertEqual(self.vrf_exec_calls(), [])

    def test_missing_command_is_a_usage_error(self):
        result = self.helper()
        self.assertEqual(result.returncode, 2)
        self.assertIn('usage: lldpq-vrf', result.stderr)


class SelfEnteringShellTests(FakeHostCase):
    """The blocks that move a `docker exec` shell or command into the VRF."""

    BASHRC_BLOCK = re.search(
        r'^if \[ -z "\$\{LLDPQ_IN_VRF:-\}" \].*?^fi$', BASHRC, re.M | re.S)
    COMMAND_BLOCK = textwrap.dedent('''\
        if [ -z "${LLDPQ_IN_VRF:-}" ] && command -v lldpq-vrf >/dev/null 2>&1 &&
           lldpq-vrf --pending 2>/dev/null && lldpq-vrf true 2>/dev/null; then
            exec lldpq-vrf "$BASH" "$0" "$@"
        fi
        ''')

    def run_block(self, block, *arguments, as_command_string=False, login=False, **env):
        source = f'{block}\necho STAYED\n'
        if as_command_string:
            command = ['bash', '-c', source, 'name', *arguments]
        else:
            script = self.host.root / 'run-me'
            script.write_text(source)
            command = ['bash', *(['-l'] if login else []), str(script), *arguments]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20,
                                env=self.host.env(**env))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout, self.ip_calls()

    def bashrc(self, *arguments, **options):
        self.assertIsNotNone(self.BASHRC_BLOCK, 'VRF block is missing from the container bashrc')
        return self.run_block('BASH=/bin/bash\n' + self.BASHRC_BLOCK.group(0),
                              *arguments, **options)

    def test_interactive_shell_outside_the_services_vrf_is_moved_in(self):
        self.fake_helper(pending=True)
        stdout, calls = self.bashrc()
        self.assertEqual(stdout, '')
        self.assertEqual(calls, [['--pending'], ['true'], ['/bin/bash', '-i']])

    def test_login_shell_stays_a_login_shell(self):
        self.fake_helper(pending=True)
        # A login shell reads the profile files; keep the developer's own out.
        _, calls = self.bashrc(login=True, HOME=str(self.host.root))
        self.assertEqual(calls[-1], ['/bin/bash', '-il'])

    def test_interactive_command_string_is_taken_along(self):
        self.fake_helper(pending=True)
        stdout, calls = self.bashrc('a  b', '*', as_command_string=True)
        self.assertEqual(stdout, '')
        moved = calls[-1]
        self.assertEqual(moved[:3], ['/bin/bash', '-i', '-c'])
        self.assertIn('echo STAYED', moved[3])
        self.assertEqual(moved[4:], ['name', 'a  b', '*'])

    def test_shell_is_left_alone_when_nothing_is_pending(self):
        self.fake_helper(pending=False)
        self.assertEqual(self.bashrc(), ('STAYED\n', [['--pending']]))

    def test_shell_is_never_lost_when_the_vrf_cannot_be_entered(self):
        self.fake_helper(pending=True, usable=False)
        self.assertEqual(self.bashrc(), ('STAYED\n', [['--pending'], ['true']]))

    def test_moved_shell_does_not_try_again(self):
        self.fake_helper(pending=True)
        self.assertEqual(self.bashrc(LLDPQ_IN_VRF='mgmt'), ('STAYED\n', []))

    def test_bashrc_block_runs_only_for_interactive_shells_and_only_once(self):
        self.assertLess(BASHRC.index('[ -z "$PS1" ] && return'),
                        BASHRC.index(self.BASHRC_BLOCK.group(0)))
        self.assertEqual(BASHRC.count('if [ -z "${LLDPQ_IN_VRF:-}" ]'), 1)

    def test_commands_carry_the_block_ahead_of_their_own_work(self):
        for name in SELF_ENTERING_COMMANDS:
            with self.subTest(command=name):
                text = (ROOT / 'bin' / name).read_text()
                self.assertEqual(text.count(self.COMMAND_BLOCK), 1)
                before = text[:text.index(self.COMMAND_BLOCK)]
                code = [line for line in before.splitlines()[1:]
                        if line.strip() and not line.lstrip().startswith('#')]
                self.assertEqual(code, [])

    def test_command_outside_the_services_vrf_reruns_itself_inside(self):
        self.fake_helper(pending=True)
        stdout, calls = self.run_block(self.COMMAND_BLOCK, 'a  b', '*', '')
        self.assertEqual(stdout, '')
        self.assertEqual(calls[:2], [['--pending'], ['true']])
        # Re-run through the interpreter: "$0" alone is not always a command
        # (`bash <name>`, a copy without the execute bit, a path holding "=").
        interpreter, *rest = calls[2]
        self.assertEqual(Path(interpreter).name, 'bash')
        self.assertTrue(Path(interpreter).is_absolute())
        self.assertEqual(rest, [str(self.host.root / 'run-me'), 'a  b', '*', ''])
        self.assertEqual(len(calls), 3)

    def test_command_carries_on_where_there_is_nothing_to_enter(self):
        self.fake_helper(pending=False)
        self.assertEqual(self.run_block(self.COMMAND_BLOCK), ('STAYED\n', [['--pending']]))
        self.host.ip_log.unlink()
        self.fake_helper(pending=True, usable=False)
        self.assertEqual(self.run_block(self.COMMAND_BLOCK),
                         ('STAYED\n', [['--pending'], ['true']]))
        self.host.ip_log.unlink()
        self.fake_helper(pending=True)
        self.assertEqual(self.run_block(self.COMMAND_BLOCK, LLDPQ_IN_VRF='mgmt'),
                         ('STAYED\n', []))

    def test_command_carries_on_without_the_helper(self):
        # A native install has no lldpq-vrf at all.
        env = self.host.env()
        self.assertFalse(any((Path(directory) / 'lldpq-vrf').exists()
                             for directory in env['PATH'].split(os.pathsep) if directory))
        self.assertEqual(self.run_block(self.COMMAND_BLOCK), ('STAYED\n', []))


class CurlWrapperTests(FakeHostCase):
    """The image's curl: a `docker exec` caller joins the services' VRF first."""

    ARGS = ('-fsS', 'http://127.0.0.1/login.html', 'a  b', '*', '')

    def setUp(self):
        super().setUp()
        self.real_curl = self.host.root / 'real-curl'
        self.real_curl.write_text('#!/bin/bash\nprintf "REAL<%s>\\n" "$@"\nexit 22\n')
        self.real_curl.chmod(0o755)
        text = CURL_WRAPPER.read_text()
        self.assertEqual(text.count('/usr/bin/curl "$@"'), 2)
        self.wrapper = self.host.root / 'curl'
        self.wrapper.write_text(text.replace('/usr/bin/curl "$@"', f'"{self.real_curl}" "$@"'))
        self.real_output = ''.join(f'REAL<{argument}>\n' for argument in self.ARGS)

    def curl(self, **env):
        result = subprocess.run(['bash', str(self.wrapper), *self.ARGS], capture_output=True,
                                text=True, timeout=20, env=self.host.env(**env))
        return result.returncode, result.stdout, self.ip_calls()

    def test_caller_outside_the_services_vrf_joins_it(self):
        self.host.marker.write_text('mgmt\n')
        self.fake_helper(pending=True)
        self.assertEqual(self.curl(), (0, '', [
            ['--pending'], ['true'], [str(self.real_curl), *self.ARGS]]))

    def test_real_curl_runs_unchanged_where_no_vrf_is_recorded(self):
        # Bridge networking, or a host without a management VRF: nothing extra runs.
        self.fake_helper(pending=True)
        self.assertEqual(self.curl(), (22, self.real_output, []))

    def test_real_curl_runs_unchanged_inside_the_vrf(self):
        self.host.marker.write_text('mgmt\n')
        self.fake_helper(pending=False)
        self.assertEqual(self.curl(), (22, self.real_output, [['--pending']]))
        self.host.ip_log.unlink()
        self.fake_helper(pending=True)
        self.assertEqual(self.curl(LLDPQ_IN_VRF='mgmt'), (22, self.real_output, []))

    def test_real_curl_runs_when_the_vrf_cannot_be_entered(self):
        self.host.marker.write_text('mgmt\n')
        self.fake_helper(pending=True, usable=False)
        self.assertEqual(self.curl(), (22, self.real_output, [['--pending'], ['true']]))

    def test_image_puts_it_ahead_of_the_real_curl(self):
        self.assertIn('COPY --chown=root:root docker/curl-vrf /usr/local/bin/curl\n',
                      DOCKERFILE)
        self.assertIn('chmod 0755 /usr/local/bin/lldpq-vrf /usr/local/bin/curl\n',
                      DOCKERFILE)
        # Docker's default PATH lists /usr/local/bin first; nothing may reorder it.
        self.assertNotRegex(DOCKERFILE, r'(?m)^ENV\s+PATH\b')
        self.assertTrue(os.access(CURL_WRAPPER, os.X_OK))


class ShippedContractTests(unittest.TestCase):
    def test_nothing_shipped_adds_policy_rules(self):
        files = [ROOT / 'install.sh', ROOT / 'docker/docker-entrypoint.sh', HELPER,
                 CURL_WRAPPER,
                 ROOT / 'docker/Dockerfile', ROOT / 'docker/dotf/bashrc',
                 # docker/test-*.sh are checks a person runs on a host. The image
                 # does not ship them, and the one for a switch can put the old
                 # rule back to see it removed.
                 *sorted(path for path in (ROOT / 'docker').glob('*.sh')
                         if not path.name.startswith('test-')),
                 *sorted(path for path in (ROOT / 'bin').iterdir() if path.is_file()),
                 *sorted((ROOT / 'lldpq').glob('*.sh')),
                 *sorted((ROOT / 'html').glob('*.sh'))]
        offenders = []
        for path in files:
            for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                if re.search(r'\bip\b(\s+-\S+)*\s+ru(le)?\s+(a|add|replace)\b', line):
                    offenders.append(f'{path.relative_to(ROOT)}:{number}')
        self.assertEqual(offenders, [])
        self.assertNotIn('docker/test-', DOCKERFILE)

    # The one place that may touch the host's routing policy: the entrypoint
    # removes the rule of an earlier image, or prints the command that does.
    LEGACY_RULE_CLEANUP = 'rule del pref 100 table'

    def test_nothing_run_in_the_container_changes_host_network_state(self):
        # Everything that runs inside the container at start, from cron or in a
        # `docker exec` shell.  The collectors under lldpq/ and the CGIs under
        # html/ are left out: they hold commands that are sent to the switches.
        files = [ROOT / 'install.sh', ROOT / 'docker/docker-entrypoint.sh', HELPER,
                 CURL_WRAPPER, ROOT / 'docker/Dockerfile', ROOT / 'docker/dotf/bashrc',
                 *sorted(path for path in (ROOT / 'bin').iterdir() if path.is_file())]
        offenders, allowed = [], []
        for path in files:
            for number, line in host_state_changes(path.read_text(errors='replace')):
                if path.name == 'docker-entrypoint.sh' and self.LEGACY_RULE_CLEANUP in line:
                    allowed.append(line.strip())
                else:
                    offenders.append(f'{path.relative_to(ROOT)}:{number}: {line.strip()}')
        self.assertEqual(offenders, [])
        self.assertEqual(len(allowed), 2, allowed)
        self.assertEqual(allowed[0], 'if ! ip -4 rule del pref 100 table "$table" 2>/dev/null; then')
        self.assertTrue(allowed[1].startswith('MGMT_RULE_WARNING="'), allowed[1])
        self.assertIn('Run on the host: sudo ip rule del pref 100 table $table', allowed[1])

    def test_host_state_scan_recognises_each_kind_of_change(self):
        changes = (
            'ip rule add pref 100 table "$table"',
            'ip -4 ru a pref 100 lookup mgmt',
            'sudo ip rule del pref 32765',
            'ip route add default via 192.0.2.1 table mgmt',
            'ip -6 route replace ::/0 via 2001:db8::1',
            '/usr/sbin/ip r del 10.0.0.0/8',
            'ip route flush table 1001',
            'ip vrf exec mgmt ip ro change 10.0.0.0/8 dev eth0',
            'ip addr add 127.0.0.1/8 dev mgmt',
            'ip a flush dev eth0',
            'ip link set dev eth0 master mgmt',
            'ip link add mgmt type vrf table 1001',
            'ip l set swp1 down',
            'ip neigh flush all',
            'ip netns add lldpq',
            'ip nexthop replace id 1 via 192.0.2.1 dev eth0',
            'sysctl -w net.ipv4.tcp_l3mdev_accept=1',
            'sysctl -qw net.ipv4.udp_l3mdev_accept=1 || true',
            'sysctl net.ipv4.ip_forward=1',
            'sysctl -p /etc/sysctl.d/99-lldpq.conf',
            'echo 1 > /proc/sys/net/ipv4/tcp_l3mdev_accept',
            'echo 0 >> "/proc/sys/net/ipv4/conf/all/rp_filter"',
            'echo 1 | tee /proc/sys/net/ipv4/ip_forward',
            'iptables -I INPUT -p tcp --dport 80 -j ACCEPT',
            'ip6tables -A INPUT -j DROP',
            'iptables-restore < /etc/iptables.rules',
            'ebtables -A FORWARD -j DROP',
            'nft add rule inet filter input tcp dport 80 accept',
            'nft -f /etc/nftables.conf',
            'tc qdisc add dev eth0 root netem delay 10ms',
            'tc -s filter del dev eth0',
            'tc class replace dev eth0 classid 1:1 htb rate 1mbit',
            'RUN ip link set lo up && sysctl -w net.ipv4.ip_forward=1',
        )
        for line in changes:
            with self.subTest(line=line):
                self.assertEqual(host_state_changes(f'echo before\n    {line}\n'),
                                 [(2, f'    {line}')])
        # Reading the state, entering the VRF and a commented-out command are fine.
        harmless = (
            'ip vrf show "$1" 2>/dev/null |',
            'ip vrf identify 1',
            'counts=$(ip -4 rule show 2>/dev/null | awk -v vrf="$vrf" \'',
            'if ! ip -4 -o addr show dev "$vrf" 2>/dev/null | grep -q x; then',
            'exec ip vrf exec "$vrf" /bin/bash "$0" "$@"',
            'ip -j link show',
            'ip route get 192.0.2.1',
            'ip -4 neigh show dev eth0',
            'accept=$(sysctl -n net.ipv4.tcp_l3mdev_accept) && seen=1',
            'sysctl -a 2>/dev/null | grep rp_filter=1',
            'forward=$(cat /proc/sys/net/ipv4/ip_forward)',
            'read -r forward < /proc/sys/net/ipv4/ip_forward',
            'iptables-save > "$dir/iptables"',
            'tc -s qdisc show dev eth0',
            '# ip rule add pref 100 table "$table"',
            '    # sysctl -w net.ipv4.tcp_l3mdev_accept=1',
            'echo "the ip address and the route are set by the operator"',
        )
        for line in harmless:
            with self.subTest(line=line):
                self.assertEqual(host_state_changes(line + '\n'), [])

    def test_vrf_is_entered_before_any_other_startup_work(self):
        self.assertEqual(ENTRYPOINT.count('_enter_mgmt_vrf "$@"'), 1)
        self.assertLess(ENTRYPOINT.index(ENTER_CALL), ENTRYPOINT.index('# ─── SSH Key Setup ───'))
        self.assertIn('exec ip vrf exec "$vrf" /bin/bash "$0" "$@"', ENTRYPOINT)
        self.assertRegex(ENTRYPOINT, r'(?m)^LLDPQ_MGMT_VRF=mgmt$')

    def test_outcome_is_repeated_next_to_the_ready_message(self):
        ready = ENTRYPOINT.index('LLDPq is ready!')
        self.assertIn('[ -z "$MGMT_VRF_STATUS" ] || echo "  $MGMT_VRF_STATUS"',
                      ENTRYPOINT[ready:])
        self.assertIn('[ -z "$MGMT_RULE_WARNING" ] || echo "  $MGMT_RULE_WARNING"',
                      ENTRYPOINT[ready:])

    def swept_files(self):
        patterns, _ = syntax_sweep()
        swept = set()
        for pattern in patterns:
            matched = [path for path in ROOT.glob(pattern) if path.is_file()]
            # The loop skips what does not exist, so a stale name would go unnoticed.
            self.assertTrue(matched, f'{pattern} in the Makefile sweep matches no file')
            swept.update(path.relative_to(ROOT).as_posix() for path in matched
                         if not re.match(rb'#!.*python', first_line(path)))
        return swept

    def test_new_scripts_are_part_of_the_syntax_sweep(self):
        swept = self.swept_files()
        for name in ('docker/docker-entrypoint.sh', 'docker/lldpq-vrf', 'docker/curl-vrf',
                     'docker/dotf/bashrc',
                     *(f'bin/{command}' for command in SELF_ENTERING_COMMANDS)):
            self.assertIn(name, swept)

    def test_syntax_sweep_covers_every_bash_file(self):
        self.assertEqual(sorted(bash_files() - self.swept_files()), [])
        for name in SOURCED_BASH:
            self.assertTrue((ROOT / name).is_file(), name)

    def run_sweep(self, files):
        """Run the Makefile's loop in a scratch tree that holds only `files`."""
        _, script = syntax_sweep()
        with tempfile.TemporaryDirectory(prefix='lldpq-sweep-') as tree:
            for name, content in files.items():
                path = Path(tree, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            Path(tree, 'bin', '__pycache__').mkdir(parents=True, exist_ok=True)
            result = subprocess.run(['sh', '-c', script], cwd=tree, capture_output=True,
                                    text=True, timeout=60)
        return result.returncode, result.stdout

    def test_syntax_sweep_checks_by_content_not_by_shebang(self):
        good = '#!/usr/bin/env bash\nif true; then echo ok; fi\n'
        broken = 'if true; then\n'
        python = '#!/usr/bin/python3\nimport os\nif os.sep:\n    pass\n'
        clean = {'install.sh': good, 'bin/lldpq': good, 'bin/lldpq-config': python,
                 'bin/zzh': python.replace('/usr/bin/python3', '/usr/bin/env python3'),
                 'docker/dotf/bashrc': 'alias ll="ls -l"\n'}
        self.assertEqual(self.run_sweep(clean), (0, ''))
        for name, content in (
                # Sourced files: no shebang at all.
                ('docker/dotf/bashrc', broken),
                ('lldpq/sw-base/bash.bashrc', broken),
                # The commands that carry the VRF block.
                ('bin/pping', '#!/usr/bin/env bash\n' + broken),
                ('bin/get-conf', '#!/usr/bin/env bash\n' + broken),
                ('bin/send-cmd', '#!/usr/bin/env bash\n' + broken),
                # A script that lost its shebang is still a script.
                ('bin/lldpq', broken),
                ('lldpq/sw-base/nvc', '#!/bin/sh\n' + broken),
                # Picked up by glob, without a Makefile change.
                ('docker/test-something-new.sh', '#!/bin/bash\n' + broken),
                ('telemetry/start.sh', '#!/bin/bash\n' + broken)):
            with self.subTest(name=name):
                self.assertEqual(self.run_sweep({**clean, name: content}),
                                 (1, f'bash -n failed: {name}\n'))

    def test_image_installs_the_helper_and_probes_health_through_it(self):
        self.assertIn('COPY --chown=root:root docker/lldpq-vrf /usr/local/bin/lldpq-vrf',
                      DOCKERFILE)
        self.assertIn('chmod 0755 /usr/local/bin/lldpq-vrf', DOCKERFILE)
        self.assertEqual(len(re.findall(r'(?m)^HEALTHCHECK\b', DOCKERFILE)), 1)
        self.assertIn(
            "    CMD lldpq-vrf curl -fsS 'http://127.0.0.1:80/auth-api?action=check'"
            " | grep -q '\"authenticated\"' || exit 1\n", DOCKERFILE)
        self.assertLess(DOCKERFILE.index('/usr/local/bin/lldpq-vrf'),
                        DOCKERFILE.index('HEALTHCHECK --interval'))

    def test_collectors_do_not_describe_the_removed_rule(self):
        for name in ('check-lldp.sh', 'send-cmd.sh', 'monitor.sh', 'get-configs.sh'):
            text = (ROOT / 'lldpq' / name).read_text()
            self.assertNotRegex(text, r"adds (an? )?('ip rule'|mgmt-VRF rule)", name)
            self.assertIn('runs every service inside the mgmt VRF', text, name)

    def test_documented_probes_reach_the_services_inside_the_vrf(self):
        # `docker exec` starts outside the VRF, where the web service's loopback
        # listener is out of reach; a failing probe makes the documented update
        # roll back to an older image, which adds the routing rule again.
        for name, text in (('DOCKER.md', DOCKER_DOC), ('README.md', README)):
            joined = re.sub(r'\\\n\s*', ' ', text)
            self.assertNotRegex(joined, r'docker exec\s+(-\S+\s+)*\S+\s+curl\b', name)
        self.assertEqual(DOCKER_DOC.count('exec lldpq-vrf curl -fsS http://127.0.0.1/login.html'), 2)
        self.assertEqual(DOCKER_DOC.count('exec curl -fsS http://127.0.0.1/login.html'), 2)

    def test_documented_manual_cleanup_keeps_the_container_and_checks_first(self):
        section = DOCKER_DOC[DOCKER_DOC.index('#### Management VRF'):
                             DOCKER_DOC.index('Direct access then needs the control-plane ACL')]
        self.assertIn("ip -4 rule show | grep '^100:'", section)
        self.assertIn('sudo docker stop lldpq', section)
        self.assertNotIn('docker rm', section)
        self.assertIn('LLDPQ_ENTER_MGMT_VRF=no', section)
        self.assertIn('outbound via mgmt', section)


if __name__ == '__main__':
    unittest.main()
