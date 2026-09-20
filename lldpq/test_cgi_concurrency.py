"""CGI pool configuration plus optional real local socket regression.

LLDPQ_RUN_SOCKET_TESTS=1 enables the fcgiwrap/cgi-fcgi integration check.
"""

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'docker/docker-entrypoint.sh').read_text()


class CgiPoolTests(unittest.TestCase):
    def test_worker_count_is_bounded_before_starting_services(self):
        start = SOURCE.index('LLDPQ_FCGI_WORKERS="${LLDPQ_FCGI_WORKERS:-4}"')
        block = SOURCE[start:SOURCE.index('FCGIWRAP_SOCKET=', start)]
        for value, good in [('1', True), ('4', True), ('32', True), ('0', False),
                            ('01', False), ('-1', False), ('33', False), ('999999999999999', False),
                            ('4x', False)]:
            with self.subTest(value=value):
                result = subprocess.run(['bash', '-c', block],
                                        env={**os.environ, 'LLDPQ_FCGI_WORKERS': value},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, good, result.stderr)

    def test_native_socket_service_uses_same_default_pool(self):
        dropin = ROOT / 'etc/systemd/system/fcgiwrap.service.d/lldpq-workers.conf'
        self.assertIn('ExecStart=\nExecStart=/usr/sbin/fcgiwrap -f -c 4', dropin.read_text())
        install = (ROOT / 'install.sh').read_text()
        self.assertIn('snapshot_managed_tree "$LLDPQ_SRC_DIR/etc" /etc etc false', install)
        self.assertIn('restore_managed_tree /etc etc', install)
        self.assertIn('fcgiwrap.service.d/lldpq-workers.conf', (ROOT / 'uninstall.sh').read_text())

    @unittest.skipUnless(os.environ.get('LLDPQ_RUN_SOCKET_TESTS') == '1',
                         'opt-in local fcgiwrap socket integration')
    def test_slow_cgi_does_not_block_a_second_request(self):
        if not shutil.which('fcgiwrap') or not shutil.which('cgi-fcgi'):
            self.skipTest('fcgiwrap and cgi-fcgi are required')
        with tempfile.TemporaryDirectory(prefix='lldpq-cgi-', dir='/tmp') as root:
            root = Path(root)
            socket = root / 'fcgi.sock'
            entered, release = root / 'entered', root / 'release'
            slow, fast = root / 'slow.sh', root / 'fast.sh'
            slow.write_text('#!/bin/sh\ntouch "' + str(entered) + '"\n'
                            'while [ ! -f "' + str(release) + '" ]; do sleep .02; done\n'
                            'printf "Content-Type: text/plain\\r\\n\\r\\nslow\\n"\n')
            fast.write_text('#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\nfast\\n"\n')
            slow.chmod(0o755)
            fast.chmod(0o755)
            server = subprocess.Popen(['fcgiwrap', '-f', '-c', '4', '-s', 'unix:' + str(socket)],
                                      start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            clients = []
            try:
                for _ in range(100):
                    if socket.exists() or server.poll() is not None:
                        break
                    time.sleep(.02)
                if not socket.exists():
                    detail = server.communicate()[1] if server.poll() is not None else b''
                    self.fail('fcgiwrap did not bind its socket: ' + detail.decode(errors='replace'))

                def request(script):
                    child = subprocess.Popen(['cgi-fcgi', '-bind', '-connect', str(socket)],
                        env={**os.environ, 'SCRIPT_FILENAME': str(script), 'REQUEST_METHOD': 'GET',
                             'SCRIPT_NAME': '/' + script.name, 'SERVER_PROTOCOL': 'HTTP/1.1',
                             'GATEWAY_INTERFACE': 'CGI/1.1'}, stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    clients.append(child)
                    return child

                slow_request = request(slow)
                for _ in range(100):
                    if entered.exists():
                        break
                    time.sleep(.02)
                self.assertTrue(entered.exists(), 'slow request did not start')
                fast_request = request(fast)
                started = time.monotonic()
                response, _ = fast_request.communicate(timeout=3)
                print(f'Concurrent fast CGI response: {time.monotonic() - started:.3f}s')
                self.assertIn(b'fast', response)
                self.assertIsNone(slow_request.poll(), 'slow CGI must still be blocked')
                release.touch()
                self.assertIn(b'slow', slow_request.communicate(timeout=3)[0])
            finally:
                release.touch()
                for child in clients:
                    if child.poll() is None:
                        child.kill()
                    child.communicate()
                try:
                    os.killpg(server.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    server.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.communicate()


if __name__ == '__main__':
    unittest.main()
