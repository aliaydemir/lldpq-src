"""Owned CGI pool health and recovery, with opt-in real process/socket probes."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from lldpq.test_dhcp_multi_pool import shell_function


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'docker/docker-entrypoint.sh').read_text()
FUNCTION_NAMES = ('_fcgiwrap_pool_healthy', '_fcgiwrap_group_alive',
                  '_stop_fcgiwrap', '_start_fcgiwrap', '_restart_fcgiwrap')
FUNCTIONS = '\n'.join(shell_function(SOURCE, name) for name in FUNCTION_NAMES)


class PoolHealthTests(unittest.TestCase):
    def health(self, snapshot, workers=4):
        # Exercise process identity/counting independently of the socket gate;
        # the opt-in tests below use actual sockets and unmodified functions.
        source = shell_function(SOURCE, '_fcgiwrap_pool_healthy').replace(
            '[ -S "$FCGIWRAP_SOCKET" ]', 'true')
        source += '\nps() { printf "%s\\n" "$PROCESS_SNAPSHOT"; }\n_fcgiwrap_pool_healthy\n'
        result = subprocess.run(['bash', '-c', source], capture_output=True,
            text=True, env=dict(os.environ, FCGIWRAP_PID='100',
                FCGIWRAP_SOCKET='/unused', LLDPQ_FCGI_WORKERS=str(workers),
                PROCESS_SNAPSHOT=snapshot), timeout=5)
        return result.returncode == 0

    def test_only_live_direct_children_of_owned_master_count(self):
        leader = '100 1 100 S fcgiwrap\n'
        children = ['%d 100 100 S fcgiwrap\n' % pid for pid in range(101, 105)]
        self.assertTrue(self.health(leader + ''.join(children)))
        self.assertFalse(self.health(leader + ''.join(children[:3])))
        self.assertFalse(self.health(leader + ''.join(children[:3]) +
                                     '104 100 100 Z fcgiwrap\n'))
        self.assertFalse(self.health(leader + ''.join(children[:3]) +
                                     '204 200 200 S fcgiwrap\n'))
        self.assertFalse(self.health(''.join(children)))
        self.assertFalse(self.health(leader.replace('S fcgiwrap', 'Z fcgiwrap') +
                                     ''.join(children)))

    def test_single_worker_mode_does_not_require_forked_children(self):
        self.assertTrue(self.health('100 1 100 S fcgiwrap\n', workers=1))
        self.assertFalse(self.health('100 1 999 S fcgiwrap\n', workers=1))

    def test_failed_restarts_remain_bounded_without_exiting_watchdog(self):
        watchdog = shell_function(SOURCE, '_supervise_services')
        source = '''set -e
WATCHDOG_POLL_DELAY=0
WATCHDOG_STORM_LIMIT=2
WATCHDOG_STORM_WINDOW=60
iterations=0
sleep() { iterations=$((iterations + 1)); (( iterations < 7 )) || exit 0; }
date() { echo 100; }
pgrep() { return 1; }
_fcgiwrap_pool_healthy() { return 1; }
_restart_fcgiwrap() { echo fcgi-attempted; return 1; }
_restart_cron() { echo cron-attempted; return 1; }
_stop_fcgiwrap() { echo stopped; }
''' + watchdog + '\n_supervise_services\n'
        result = subprocess.run(['bash', '-c', source], text=True,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('fcgi-attempted'), 2)
        self.assertEqual(result.stdout.count('cron-attempted'), 2)
        self.assertIn('CRITICAL: fcgiwrap pool failed', result.stderr)
        self.assertIn('CRITICAL: cron died', result.stderr)
        self.assertIn('stopped', result.stdout)


@unittest.skipUnless(os.environ.get('LLDPQ_RUN_SOCKET_TESTS') == '1',
                     'opt-in local fcgiwrap lifecycle integration')
class PoolLifecycleTests(unittest.TestCase):
    def run_scenario(self, scenario, workers=4):
        if not shutil.which('fcgiwrap') or not shutil.which('setsid'):
            self.skipTest('fcgiwrap and setsid are required')
        with tempfile.TemporaryDirectory(dir='/tmp', prefix='lldpq-pool-') as root:
            # Native test identities do not own www-data. All process, socket,
            # health and lifecycle commands run unchanged; skip only chown.
            source = 'set -eu\nchown() { :; }\n' + FUNCTIONS.replace(
                '/usr/sbin/fcgiwrap', shlex.quote(shutil.which('fcgiwrap')))
            source += '''
FCGIWRAP_PID=""
FCGIWRAP_SOCKET="$TEST_ROOT/fcgi.sock"
trap '_stop_fcgiwrap || true' EXIT
assert_old_group_gone() {
    local FCGIWRAP_PID="$1"
    ! _fcgiwrap_group_alive
}
''' + scenario
            result = subprocess.run(['bash', '-c', source], text=True,
                capture_output=True, timeout=30,
                env=dict(os.environ, TEST_ROOT=root,
                         LLDPQ_FCGI_WORKERS=str(workers)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_worker_and_master_loss_restore_pool_without_killing_other_pool(self):
        other_command = shlex.quote(shutil.which('fcgiwrap') or 'fcgiwrap')
        self.run_scenario('''
setsid ''' + other_command + ''' -f -c 2 -s "unix:$TEST_ROOT/unrelated.sock" &
other=$!
trap '_stop_fcgiwrap || true; kill -TERM -- "-$other" 2>/dev/null || true; wait "$other" 2>/dev/null || true' EXIT
unrelated_healthy() {
    local FCGIWRAP_PID="$other" FCGIWRAP_SOCKET="$TEST_ROOT/unrelated.sock" LLDPQ_FCGI_WORKERS=2
    _fcgiwrap_pool_healthy
}
_start_fcgiwrap
_fcgiwrap_pool_healthy
unrelated_healthy
for victim in worker master; do
    old=$FCGIWRAP_PID
    if [[ "$victim" == worker ]]; then
        child=$(pgrep -P "$old" -x fcgiwrap | head -1)
        kill -TERM "$child"
    else
        kill -KILL "$old"
    fi
    for attempt in {1..100}; do
        _fcgiwrap_pool_healthy || break
        sleep .02
    done
    ! _fcgiwrap_pool_healthy
    _restart_fcgiwrap
    [[ "$old" != "$FCGIWRAP_PID" ]]
    _fcgiwrap_pool_healthy
    assert_old_group_gone "$old"
    unrelated_healthy
done
''')

    def test_single_worker_loss_restarts_without_waiting_for_nonexistent_children(self):
        self.run_scenario('''
_start_fcgiwrap
_fcgiwrap_pool_healthy
old=$FCGIWRAP_PID
kill -KILL "$old"
wait "$old" 2>/dev/null || true
! _fcgiwrap_pool_healthy
_restart_fcgiwrap
_fcgiwrap_pool_healthy
assert_old_group_gone "$old"
''', workers=1)

    def test_stale_socket_and_failed_start_do_not_leave_owned_workers(self):
        self.run_scenario('''
touch "$FCGIWRAP_SOCKET"
_start_fcgiwrap
_fcgiwrap_pool_healthy
old=$FCGIWRAP_PID
_stop_fcgiwrap
assert_old_group_gone "$old"
FCGIWRAP_SOCKET="$TEST_ROOT/missing-parent/fcgi.sock"
! _start_fcgiwrap
[[ -z "$FCGIWRAP_PID" ]]
[[ ! -e "$FCGIWRAP_SOCKET" ]]
''')


if __name__ == '__main__':
    unittest.main()
