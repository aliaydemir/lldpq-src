"""LLDPQ_HTTPS_PORT: an optional TLS listener next to plain HTTP.

The image served the web UI over plain HTTP only.  On a switch whose own SSH
server refuses port forwarding there is no tunnel to hide it in, so logins
crossed the management network in clear text.

With LLDPQ_HTTPS_PORT=<port> the entrypoint adds a TLS listener on that port to
the one nginx server block (same locations) and leaves port 80 exactly as it
is: ONIE/ZTP clients, the HEALTHCHECK and the documented probes use it.  The
certificate is the operator's pair from /etc/lldpq-tls (tls.crt, tls.key) or a
self-signed pair kept under system-config/tls.  Unset or empty, nothing
changes.  nginx is the container's main process, so whatever goes wrong ends in
one warning line and a container that serves HTTP only, never in a restart loop.

The entrypoint's own block runs here against a copy of the packaged site file,
with stand-in openssl, nginx, ss, hostname and chown binaries and no other
openssl or nginx in reach; nothing needs Linux, root or a container.  The
tests at the end use the real nginx and openssl where they are installed; the
one that starts nginx is opt-in (LLDPQ_RUN_SOCKET_TESTS=1), as elsewhere here.
"""

from pathlib import Path
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
import unittest
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = (ROOT / 'docker/docker-entrypoint.sh').read_text()
DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
PACKAGED_SITE = (ROOT / 'etc/nginx/sites-available/lldpq').read_text()
COMPOSE = (ROOT / 'docker/docker-compose.yml').read_text()
PROVISIONING_COMPOSE = (ROOT / 'docker/docker-compose.provisioning.yml').read_text()


def between(start, end):
    begin = ENTRYPOINT.index(start)
    return ENTRYPOINT[begin:ENTRYPOINT.index(end, begin)]


def shell_function(name):
    """One function of the entrypoint, up to its closing brace in the first column."""
    lines = ENTRYPOINT[ENTRYPOINT.index(f'\n{name}() {{\n') + 1:].splitlines(keepends=True)
    return ''.join(lines[:lines.index('}\n') + 1])


# The whole feature, call included, and the lines under the ready message.
HTTPS_BLOCK = between('# ─── HTTPS (optional) ───', '# Start nginx (foreground')
READY_BLOCK = between('# LLDPQ_PORT is normally a host-side compose variable',
                      '# The VRF line is printed first thing')

# The two fixed paths of the block; a run points them at scratch files.
SITE_LINE = 'HTTPS_SITE_FILE=/etc/nginx/sites-available/lldpq\n'
SUPPLIED_LINE = 'HTTPS_SUPPLIED_DIR=/etc/lldpq-tls\n'
GENERATED_LINE = 'HTTPS_GENERATED_DIR="$SYSTEM_CONFIG_DIR/tls"\n'
MARK = '# lldpq-https'

READY = 'LLDPq is ready! Web UI on container port 80 (use the host port published to it)'
HTTP_ONLY = '; the web UI is served over HTTP only'

# What the block may run besides the stand-ins.  openssl, nginx and ss are
# deliberately not among them: a test only ever reaches the stand-ins.
REAL_TOOLS = ('awk', 'grep', 'cat', 'mktemp', 'rm', 'mv', 'chmod', 'mkdir', 'dirname',
              'tr', 'cut', 'cp')

NGINX_OK = ('nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n'
            'nginx: configuration file /etc/nginx/nginx.conf test is successful')

STAND_INS = {
    # `req` writes the pair it is asked for; `x509 -checkend` says whether an
    # existing certificate is still good.
    'openssl': r'''#!/bin/bash
printf '%s\n' "$*" >> "$CALLS/openssl"
case "$1" in
    req)
        [ "${FAKE_OPENSSL_REQ_RC:-0}" = 0 ] || { echo "req: failed" >&2; exit "$FAKE_OPENSSL_REQ_RC"; }
        key="" cert=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -keyout) key=$2; shift ;;
                -out) cert=$2; shift ;;
            esac
            shift
        done
        umask >> "$CALLS/openssl-umask"
        if [ -n "${FAKE_OPENSSL_REQ_EMPTY:-}" ]; then
            : > "$key"; : > "$cert"
            exit 0
        fi
        serial=0
        [ ! -f "$CALLS/serial" ] || read -r serial < "$CALLS/serial"
        serial=$((serial + 1))
        echo "$serial" > "$CALLS/serial"
        echo "stand-in key $serial" > "$key"
        echo "stand-in certificate $serial" > "$cert" ;;
    x509)
        exit "${FAKE_CHECKEND_RC:-0}" ;;
    *)
        echo "unexpected openssl call: $*" >&2; exit 99 ;;
esac
''',
    # Keeps the site file as nginx was asked to test it.
    'nginx': r'''#!/bin/bash
printf '%s\n' "$*" >> "$CALLS/nginx"
cp "$SITE" "$CALLS/site-tested-by-nginx"
printf '%s\n' "${FAKE_NGINX_T_OUTPUT-$NGINX_OK}" >&2
exit "${FAKE_NGINX_T_RC:-0}"
''',
    # Answers for the port it is asked about, like `ss -H -ltn "sport = :PORT"`.
    'ss': r'''#!/bin/bash
(IFS='|'; printf '%s\n' "$*") >> "$CALLS/ss"
[ "${FAKE_SS_RC:-0}" = 0 ] || { echo "Cannot open netlink socket" >&2; exit "$FAKE_SS_RC"; }
asked=${!#}
for port in ${FAKE_LISTENING:-}; do
    [ "sport = :$port" != "$asked" ] || echo "LISTEN 0 511 0.0.0.0:$port 0.0.0.0:*"
done
''',
    'hostname': '#!/bin/bash\nprintf \'%s\\n\' "${FAKE_HOSTNAME-leaf-01.lab}"\n',
    'chown': '#!/bin/bash\nprintf \'%s\\n\' "$*" >> "$CALLS/chown"\nexit "${FAKE_CHOWN_RC:-0}"\n',
}


def marked(text):
    return [line for line in text.splitlines() if line.endswith(MARK)]


def unmarked(text):
    return ''.join(line for line in text.splitlines(keepends=True)
                   if not line.rstrip('\n').endswith(MARK))


class HttpsCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-https-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.bin = self.root / 'bin'
        self.tools = self.root / 'tools'
        self.calls = self.root / 'calls'
        for directory in (self.bin, self.tools, self.calls):
            directory.mkdir()
        for name, body in STAND_INS.items():
            self.add_binary(name, body)
        for name in REAL_TOOLS:
            (self.tools / name).symlink_to(shutil.which(name))
        self.site = self.root / 'site'
        self.site.write_text(PACKAGED_SITE)
        self.supplied = self.root / 'lldpq-tls'
        self.system_config = self.root / 'system-config'
        self.system_config.mkdir()
        self.generated = self.system_config / 'tls'

    def add_binary(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def block(self):
        text = HTTPS_BLOCK
        for fixed, scratch in ((SITE_LINE, f'HTTPS_SITE_FILE="{self.site}"\n'),
                               (SUPPLIED_LINE, f'HTTPS_SUPPLIED_DIR="{self.supplied}"\n')):
            self.assertEqual(text.count(fixed), 1, fixed)
            text = text.replace(fixed, scratch)
        self.assertEqual(text.count(GENERATED_LINE), 1)
        return text

    def start(self, port=None, **env):
        """Run the block and the ready lines the way the entrypoint does, under `set -e`."""
        source = '\n'.join((
            'set -e', f'SYSTEM_CONFIG_DIR="{self.system_config}"', 'SSHD_ENABLED=true',
            self.block(), READY_BLOCK, 'echo CONTINUED', ''))
        environment = {'PATH': f'{self.bin}{os.pathsep}{self.tools}',
                       'HOME': str(self.root), 'TMPDIR': str(self.root),
                       'CALLS': str(self.calls), 'SITE': str(self.site), 'NGINX_OK': NGINX_OK}
        if port is not None:
            environment['LLDPQ_HTTPS_PORT'] = port
        environment.update(env)
        for log in self.calls.iterdir():
            if log.name != 'serial':
                log.unlink()
        result = subprocess.run([shutil.which('bash'), '-c', source], capture_output=True,
                                text=True, timeout=30, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        # Whatever happened, start-up went on to the ready message and past it.
        self.assertTrue(result.stdout.startswith(READY + '\n'), result.stdout)
        self.assertTrue(result.stdout.endswith('CONTINUED\n'), result.stdout)
        return result

    def called(self, name):
        log = self.calls / name
        return log.read_text().splitlines() if log.exists() else []

    def site_text(self):
        return self.site.read_text()

    def mode(self, path):
        return stat.S_IMODE(path.stat().st_mode)

    def scratch_files(self):
        """Left-overs of a run: staged site copies and half-written pairs."""
        return sorted(path.name for path in self.root.iterdir()
                      if path.name.startswith('tmp')) + sorted(
            path.name for path in (self.generated.iterdir() if self.generated.is_dir() else ())
            if path.name.endswith('.new'))

    def assert_http_only(self, result, port, reason):
        """One warning line under the ready message, and the site as the image ships it."""
        self.assertEqual(self.site_text(), PACKAGED_SITE)
        self.assertEqual(
            result.stderr,
            f'  ⚠ HTTPS not enabled (LLDPQ_HTTPS_PORT={port}): {reason}{HTTP_ONLY}\n')
        self.assertNotIn('HTTPS', result.stdout)
        self.assertEqual(self.scratch_files(), [])

    def assert_serving(self, result, port, certificate, key):
        """The TLS twin of each port-80 line, the certificate, and the line that says so."""
        text = self.site_text()
        # Nothing of the packaged file is changed or moved: port 80 is as it was.
        self.assertEqual(unmarked(text), PACKAGED_SITE)
        self.assertEqual(marked(text), [
            f'        listen {port} ssl default_server; {MARK}',
            f'        ssl_certificate "{certificate}"; {MARK}',
            f'        ssl_certificate_key "{key}"; {MARK}',
            f'        ssl_protocols TLSv1.2 TLSv1.3; {MARK}',
            f'        listen [::]:{port} ssl default_server; {MARK}'])
        lines = text.splitlines()
        self.assertEqual(lines.index(f'        listen {port} ssl default_server; {MARK}'),
                         lines.index('        listen 80 default_server;') + 1)
        self.assertEqual(lines.index(f'        listen [::]:{port} ssl default_server; {MARK}'),
                         lines.index('        listen [::]:80 default_server;') + 1)
        # All of it inside the one server block, ahead of its first location.
        self.assertLess(lines.index('server {'), lines.index(marked(text)[0]))
        self.assertLess(lines.index(marked(text)[-1]),
                        next(number for number, line in enumerate(lines)
                             if line.lstrip().startswith('location ')))
        # nginx tested exactly this file before it was relied on.
        self.assertEqual(self.called('nginx'), ['-t'])
        self.assertEqual((self.calls / 'site-tested-by-nginx').read_text(), text)
        self.assertEqual(self.called('ss'), [f'-H|-ltn|sport = :{port}'])
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.scratch_files(), [])


class HttpsListenerTests(HttpsCase):
    def test_unset_or_empty_changes_nothing(self):
        before = self.site.stat()
        for port in (None, ''):
            with self.subTest(port=port):
                result = self.start(port)
                self.assertEqual(result.stderr, '')
                self.assertEqual(result.stdout, f'{READY}\n'
                                 '  SSH: container port 2033 (reachable only if published or '
                                 'with host networking)\nCONTINUED\n')
                # The site file is not rewritten, not even with the same bytes.
                after = self.site.stat()
                self.assertEqual((after.st_ino, after.st_mtime_ns, after.st_size),
                                 (before.st_ino, before.st_mtime_ns, before.st_size))
                self.assertEqual(self.site_text(), PACKAGED_SITE)
                # No certificate, no port check, no nginx -t.
                self.assertEqual(sorted(path.name for path in self.calls.iterdir()), [])
                self.assertFalse(self.generated.exists())
                self.assertEqual(self.scratch_files(), [])

    def test_generated_certificate(self):
        result = self.start('8443')
        certificate, key = self.generated / 'lldpq.crt', self.generated / 'lldpq.key'
        self.assert_serving(result, '8443', certificate, key)
        self.assertIn(f'{READY}\n  HTTPS: container port 8443, self-signed certificate '
                      f'{certificate}\n  SSH: container port 2033', result.stdout)
        # Checked for an earlier pair, then created: complete files, moved into place.
        self.assertEqual(self.called('openssl'), [
            'req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 -subj /CN=leaf-01.lab '
            f'-addext subjectAltName=DNS:leaf-01.lab -keyout {key}.new -out {certificate}.new'])
        self.assertEqual(key.read_text(), 'stand-in key 1\n')
        self.assertEqual(certificate.read_text(), 'stand-in certificate 1\n')
        # The key is written under a private umask and stays root's alone.
        self.assertEqual(self.called('openssl-umask'), ['0077'])
        self.assertEqual(self.mode(key), 0o600)
        self.assertEqual(self.mode(certificate), 0o644)
        self.assertEqual(self.mode(self.generated), 0o700)
        self.assertEqual(self.called('chown'), [f'root:root {self.generated}'])

    def test_supplied_certificate(self):
        self.supplied.mkdir()
        (self.supplied / 'tls.crt').write_text('operator certificate\n')
        (self.supplied / 'tls.key').write_text('operator key\n')
        (self.supplied / 'tls.key').chmod(0o640)
        result = self.start('8443')
        self.assert_serving(result, '8443', self.supplied / 'tls.crt', self.supplied / 'tls.key')
        self.assertIn(f'{READY}\n  HTTPS: container port 8443, certificate '
                      f'{self.supplied}/tls.crt\n  SSH: container port 2033', result.stdout)
        self.assertNotIn('self-signed', result.stdout)
        # The operator's files are used as they are and nothing is generated.
        self.assertEqual(self.called('openssl'), [])
        self.assertEqual(self.called('chown'), [])
        self.assertFalse(self.generated.exists())
        self.assertEqual((self.supplied / 'tls.crt').read_text(), 'operator certificate\n')
        self.assertEqual((self.supplied / 'tls.key').read_text(), 'operator key\n')
        self.assertEqual(self.mode(self.supplied / 'tls.key'), 0o640)

    def test_supplied_certificate_wins_over_an_earlier_generated_one(self):
        self.start('8443')
        self.supplied.mkdir()
        (self.supplied / 'tls.crt').write_text('operator certificate\n')
        (self.supplied / 'tls.key').write_text('operator key\n')
        result = self.start('8443')
        self.assert_serving(result, '8443', self.supplied / 'tls.crt', self.supplied / 'tls.key')
        # The generated pair is left where it is, for a start without the mount.
        self.assertEqual((self.generated / 'lldpq.key').read_text(), 'stand-in key 1\n')

    def test_restart_is_idempotent(self):
        certificate, key = self.generated / 'lldpq.crt', self.generated / 'lldpq.key'
        self.start('8443')
        first = self.site_text()
        for _ in range(3):
            result = self.start('8443')
            self.assert_serving(result, '8443', certificate, key)
            self.assertEqual(self.site_text(), first)
            # The pair of the first start is kept, only looked at.
            self.assertEqual(self.called('openssl'),
                             [f'x509 -in {certificate} -noout -checkend 86400'])
            self.assertEqual(key.read_text(), 'stand-in key 1\n')
            self.assertEqual(self.called('chown'), [])

    def test_restart_with_another_port_moves_the_listener(self):
        self.start('8443')
        result = self.start('9443')
        self.assert_serving(result, '9443', self.generated / 'lldpq.crt',
                            self.generated / 'lldpq.key')
        self.assertNotIn('8443', self.site_text())

    def test_start_without_the_variable_removes_the_lines_of_an_earlier_start(self):
        # Only a writable layer that went through an HTTPS start holds them.
        self.start('8443')
        self.assertEqual(len(marked(self.site_text())), 5)
        result = self.start()
        self.assertEqual(self.site_text(), PACKAGED_SITE)
        self.assertEqual(result.stderr, '')
        self.assertNotIn('HTTPS', result.stdout)
        self.assertEqual(self.called('nginx'), [])

    def test_ipv4_only_site_gets_an_ipv4_only_listener(self):
        # Without IPv6 the entrypoint has removed the [::] listen line by now.
        ipv4_only = ''.join(line for line in PACKAGED_SITE.splitlines(keepends=True)
                            if 'listen [::]' not in line)
        self.assertNotEqual(ipv4_only, PACKAGED_SITE)
        self.site.write_text(ipv4_only)
        result = self.start('8443')
        self.assertEqual(result.stderr, '')
        self.assertEqual(unmarked(self.site_text()), ipv4_only)
        self.assertEqual([line.split()[0:3] for line in marked(self.site_text())], [
            ['listen', '8443', 'ssl'], ['ssl_certificate', f'"{self.generated}/lldpq.crt";', '#'],
            ['ssl_certificate_key', f'"{self.generated}/lldpq.key";', '#'],
            ['ssl_protocols', 'TLSv1.2', 'TLSv1.3;']])

    def test_listen_options_and_layout_of_the_site_are_followed(self):
        # Whatever the port-80 lines look like when the image is built.
        self.site.write_text('map $a $b {\n    default "";\n}\nserver {\n'
                             '\tlisten   80;\n\tlisten [::]:80 ipv6only=on backlog=64; # v6\n'
                             '\tlisten 8080;\n\tlocation / { return 204; }\n}\n')
        original = self.site_text()
        result = self.start('443')
        self.assertEqual(result.stderr, '')
        self.assertEqual(unmarked(self.site_text()), original)
        self.assertEqual(marked(self.site_text()), [
            f'\tlisten 443 ssl; {MARK}',
            f'\tssl_certificate "{self.generated}/lldpq.crt"; {MARK}',
            f'\tssl_certificate_key "{self.generated}/lldpq.key"; {MARK}',
            f'\tssl_protocols TLSv1.2 TLSv1.3; {MARK}',
            f'\tlisten [::]:443 ssl ipv6only=on backlog=64; {MARK}'])

    def test_site_is_rewritten_the_same_by_every_awk(self):
        # The image has mawk; a developer's machine gawk or the BSD one.
        expected = None
        for name in ('mawk', 'gawk', 'awk', '/usr/bin/awk', 'busybox'):
            path = shutil.which(name)
            if not path:
                continue
            with self.subTest(awk=path):
                (self.tools / 'awk').unlink()
                if name == 'busybox':
                    (self.tools / 'awk').write_text(f'#!/bin/sh\nexec "{path}" awk "$@"\n')
                    (self.tools / 'awk').chmod(0o755)
                else:
                    (self.tools / 'awk').symlink_to(path)
                self.site.write_text(PACKAGED_SITE)
                result = self.start('8443')
                self.assert_serving(result, '8443', self.generated / 'lldpq.crt',
                                    self.generated / 'lldpq.key')
                expected = expected or self.site_text()
                self.assertEqual(self.site_text(), expected)
                self.start()
                self.assertEqual(self.site_text(), PACKAGED_SITE)

    def test_host_name_in_the_certificate_is_reduced_to_plain_characters(self):
        for reported, used in (('leaf_01/ $(id);x', 'leaf01idx'), ('', 'lldpq'),
                               ('a' * 80 + '.lab', 'a' * 63)):
            with self.subTest(reported=reported):
                shutil.rmtree(self.generated, ignore_errors=True)
                self.start('8443', FAKE_HOSTNAME=reported)
                call = self.called('openssl')[-1]
                self.assertIn(f' -subj /CN={used} -addext subjectAltName=DNS:{used} ', call)

    def test_generated_pair_about_to_expire_is_replaced(self):
        self.start('8443')
        result = self.start('8443', FAKE_CHECKEND_RC='1')
        self.assert_serving(result, '8443', self.generated / 'lldpq.crt',
                            self.generated / 'lldpq.key')
        self.assertEqual([call.split()[0] for call in self.called('openssl')], ['x509', 'req'])
        self.assertEqual((self.generated / 'lldpq.key').read_text(), 'stand-in key 2\n')
        self.assertEqual((self.generated / 'lldpq.crt').read_text(),
                         'stand-in certificate 2\n')

    def test_half_a_generated_pair_is_replaced(self):
        self.start('8443')
        (self.generated / 'lldpq.key').unlink()
        self.start('8443')
        self.assertEqual([call.split()[0] for call in self.called('openssl')], ['req'])
        self.assertEqual((self.generated / 'lldpq.key').read_text(), 'stand-in key 2\n')
        self.assertEqual((self.generated / 'lldpq.crt').read_text(),
                         'stand-in certificate 2\n')


class HttpsFailureTests(HttpsCase):
    """Each way it can go wrong: HTTP only, one warning line, start-up carries on."""

    NOT_A_PORT = 'the value is not a usable TCP port (1-65535, and not 80)'

    def test_value_that_is_not_a_port(self):
        for value in ('abc', '0', '80', '65536', '08443', '-1', '8443 ', ' 8443', '443;',
                      '8443/tcp', '99999', '99999999999999999999', '0x1bb', '８４４３'):
            with self.subTest(value=value):
                result = self.start(value)
                self.assert_http_only(result, value, self.NOT_A_PORT)
                # Nothing was looked at or created for it.
                self.assertEqual(sorted(path.name for path in self.calls.iterdir()), [])
                self.assertFalse(self.generated.exists())

    def test_highest_and_lowest_ports_are_accepted(self):
        for value in ('1', '443', '65535'):
            with self.subTest(value=value):
                result = self.start(value)
                self.assertEqual(result.stderr, '')
                self.assertIn(f'  HTTPS: container port {value}, ', result.stdout)

    def test_port_already_in_use(self):
        result = self.start('8443', FAKE_LISTENING='22 8443')
        self.assert_http_only(result, '8443', 'TCP port 8443 is already in use')
        self.assertEqual(self.called('ss'), ['-H|-ltn|sport = :8443'])
        # No certificate is created for a listener that will not exist.
        self.assertEqual(self.called('openssl'), [])
        self.assertEqual(self.called('nginx'), [])
        self.assertFalse(self.generated.exists())

    def test_other_ports_in_use_do_not_matter(self):
        result = self.start('8443', FAKE_LISTENING='22 80 2033 18443')
        self.assertEqual(result.stderr, '')
        self.assertIn('  HTTPS: container port 8443, ', result.stdout)

    def test_port_that_cannot_be_checked(self):
        reason = "TCP port 8443 could not be checked for another listener ('ss' failed)"
        result = self.start('8443', FAKE_SS_RC='255')
        self.assert_http_only(result, '8443', reason)
        (self.bin / 'ss').unlink()
        result = self.start('8443')
        self.assert_http_only(result, '8443', reason)
        self.assertEqual(self.called('nginx'), [])

    def test_missing_openssl(self):
        (self.bin / 'openssl').unlink()
        result = self.start('8443')
        self.assert_http_only(
            result, '8443', 'openssl is not available to create a certificate; mount one in '
            f'{self.supplied} (tls.crt, tls.key)')
        self.assertEqual(self.called('nginx'), [])
        self.assertFalse(self.generated.exists())

    def test_missing_openssl_does_not_matter_with_a_supplied_certificate(self):
        (self.bin / 'openssl').unlink()
        self.supplied.mkdir()
        (self.supplied / 'tls.crt').write_text('operator certificate\n')
        (self.supplied / 'tls.key').write_text('operator key\n')
        result = self.start('8443')
        self.assert_serving(result, '8443', self.supplied / 'tls.crt', self.supplied / 'tls.key')

    def test_failed_generation(self):
        reason = f'a self-signed certificate could not be created in {self.generated}'
        for env in (dict(FAKE_OPENSSL_REQ_RC='1'), dict(FAKE_OPENSSL_REQ_EMPTY='1'),
                    dict(FAKE_CHOWN_RC='1')):
            with self.subTest(env=env):
                shutil.rmtree(self.generated, ignore_errors=True)
                result = self.start('8443', **env)
                self.assert_http_only(result, '8443', reason)
                self.assertEqual(self.called('nginx'), [])
                self.assertEqual(sorted(path.name for path in self.generated.iterdir()), [])

    def test_certificate_directory_that_cannot_be_created(self):
        self.generated.write_text('not a directory\n')
        result = self.start('8443')
        self.assert_http_only(
            result, '8443', f'a self-signed certificate could not be created in {self.generated}')
        self.assertEqual(self.generated.read_text(), 'not a directory\n')

    def test_failed_generation_keeps_no_earlier_pair_half_replaced(self):
        self.start('8443')
        result = self.start('8443', FAKE_CHECKEND_RC='1', FAKE_OPENSSL_REQ_RC='1')
        self.assert_http_only(
            result, '8443', f'a self-signed certificate could not be created in {self.generated}')
        self.assertEqual((self.generated / 'lldpq.key').read_text(), 'stand-in key 1\n')
        self.assertEqual((self.generated / 'lldpq.crt').read_text(),
                         'stand-in certificate 1\n')

    def test_incomplete_supplied_pair_is_not_replaced_by_a_self_signed_one(self):
        self.supplied.mkdir()
        reason = f'{self.supplied} must hold both tls.crt and tls.key'
        for present, empty in (('tls.crt', None), ('tls.key', None), ('tls.crt', 'tls.key'),
                               ('tls.key', 'tls.crt')):
            with self.subTest(present=present, empty=empty):
                for path in self.supplied.iterdir():
                    path.unlink()
                (self.supplied / present).write_text('operator file\n')
                if empty:
                    (self.supplied / empty).write_text('')
                result = self.start('8443')
                self.assert_http_only(result, '8443', reason)
                self.assertEqual(self.called('openssl'), [])
                self.assertEqual(self.called('nginx'), [])
                self.assertFalse(self.generated.exists())

    def test_supplied_links_without_a_target_are_not_replaced_by_a_self_signed_pair(self):
        # A mounted Let's Encrypt `live/<host>` directory: the links point at
        # ../../archive, which is not part of the mount.
        self.supplied.mkdir()
        reason = f'{self.supplied} must hold both tls.crt and tls.key'
        for links in (('tls.crt', 'tls.key'), ('tls.crt',), ('tls.key',)):
            with self.subTest(links=links):
                for path in self.supplied.iterdir():
                    path.unlink()
                for name in links:
                    (self.supplied / name).symlink_to(f'../../archive/host/{name}')
                    self.assertFalse((self.supplied / name).exists())
                result = self.start('8443')
                self.assert_http_only(result, '8443', reason)
                self.assertEqual(self.called('openssl'), [])
                self.assertEqual(self.called('nginx'), [])
                self.assertFalse(self.generated.exists())

    def test_supplied_links_with_a_target_in_the_mount_are_served(self):
        self.supplied.mkdir()
        (self.supplied / 'fullchain.pem').write_text('operator certificate\n')
        (self.supplied / 'privkey.pem').write_text('operator key\n')
        (self.supplied / 'tls.crt').symlink_to('fullchain.pem')
        (self.supplied / 'tls.key').symlink_to('privkey.pem')
        result = self.start('8443')
        self.assert_serving(result, '8443', self.supplied / 'tls.crt', self.supplied / 'tls.key')
        self.assertEqual(self.called('openssl'), [])
        self.assertFalse(self.generated.exists())

    def test_supplied_key_with_a_passphrase(self):
        # Where the container has a terminal, nginx would wait there for the
        # passphrase: at `nginx -t` first, and start-up would never finish.
        self.supplied.mkdir()
        (self.supplied / 'tls.crt').write_text('operator certificate\n')
        for header in ('-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBOBgkq\n',
                       '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n'
                       'DEK-Info: AES-256-CBC,00\n'):
            with self.subTest(header=header.splitlines()[0]):
                (self.supplied / 'tls.key').write_text(header)
                result = self.start('8443')
                self.assert_http_only(
                    result, '8443', f'{self.supplied}/tls.key is protected by a passphrase')
                self.assertEqual(self.called('nginx'), [])
                self.assertEqual(self.called('openssl'), [])

    def test_site_file_that_cannot_be_written(self):
        self.site.chmod(0o444)
        self.addCleanup(self.site.chmod, 0o644)
        if os.access(self.site, os.W_OK):
            self.skipTest('running as a user that may write any file')
        result = self.start('8443')
        self.assert_http_only(
            result, '8443', f'the listener could not be added to {self.site} (no port-80 '
            'listen line, or the file cannot be written)')
        self.assertEqual(self.called('nginx'), [])

    def test_earlier_lines_that_cannot_be_removed_are_reported(self):
        self.start('8443')
        self.site.chmod(0o444)
        self.addCleanup(self.site.chmod, 0o644)
        if os.access(self.site, os.W_OK):
            self.skipTest('running as a user that may write any file')
        for port in (None, '8443'):
            with self.subTest(port=port):
                result = self.start(port)
                self.assertEqual(result.stderr, '  ⚠ the HTTPS lines of an earlier start could '
                                 f'not be removed from {self.site}\n')
                self.assertNotIn('HTTPS', result.stdout)
                self.assertEqual(len(marked(self.site_text())), 5)
                self.assertEqual(self.called('nginx'), [])

    def test_configuration_nginx_does_not_accept(self):
        # A supplied key that does not belong to the certificate, for one.
        emerg = ('nginx: [emerg] SSL_CTX_use_PrivateKey("/etc/lldpq-tls/tls.key") failed '
                 '(SSL: error:05800074:x509 certificate routines::key values mismatch)')
        result = self.start('8443', FAKE_NGINX_T_RC='1', FAKE_NGINX_T_OUTPUT=(
            'nginx: [warn] something else first\n' + emerg +
            '\nnginx: configuration file /etc/nginx/nginx.conf test failed'))
        self.assert_http_only(
            result, '8443', f'nginx does not accept the configuration [reported: {emerg}]')
        # It was the file with the listener that nginx tested and turned down.
        self.assertEqual(len(marked((self.calls / 'site-tested-by-nginx').read_text())), 5)
        result = self.start('8443', FAKE_NGINX_T_RC='1', FAKE_NGINX_T_OUTPUT='')
        self.assert_http_only(result, '8443', 'nginx does not accept the configuration '
                              '[reported: nginx -t failed]')

    def test_site_without_a_port_80_listener(self):
        for listen in ('listen 8080 default_server;', 'listen 127.0.0.1:80;', '# listen 80;',
                       'listen 80'):
            with self.subTest(listen=listen):
                text = f'server {{\n        {listen}\n        root /var/www/html;\n}}\n'
                self.site.write_text(text)
                result = self.start('8443')
                self.assertEqual(self.site_text(), text)
                self.assertEqual(
                    result.stderr,
                    '  ⚠ HTTPS not enabled (LLDPQ_HTTPS_PORT=8443): the listener could not be '
                    f'added to {self.site} (no port-80 listen line, or the file cannot be '
                    f'written){HTTP_ONLY}\n')
                self.assertEqual(self.called('nginx'), [])
                self.assertEqual(self.scratch_files(), [])

    def test_failure_on_a_restart_takes_the_earlier_listener_out(self):
        # The lines of the first start are still in the writable layer.
        self.start('8443')
        self.assertEqual(len(marked(self.site_text())), 5)
        for reason, env in (
                ('TCP port 8443 is already in use', dict(FAKE_LISTENING='8443')),
                ('nginx does not accept the configuration [reported: nginx: [emerg] no]',
                 dict(FAKE_NGINX_T_RC='1', FAKE_NGINX_T_OUTPUT='nginx: [emerg] no'))):
            with self.subTest(reason=reason):
                result = self.start('8443', **env)
                self.assert_http_only(result, '8443', reason)
                self.start('8443')
                self.assertEqual(len(marked(self.site_text())), 5)


class HttpsContractTests(unittest.TestCase):
    def test_packaged_site_has_one_server_and_the_two_port_80_lines(self):
        # The entrypoint follows these lines; a second server block or a TLS
        # listener in the packaged file would need the block looked at again.
        self.assertEqual(len(re.findall(r'(?m)^[ \t]*server[ \t]*\{', PACKAGED_SITE)), 1)
        self.assertEqual(re.findall(r'(?m)^[ \t]*listen[ \t][^;\n]*;', PACKAGED_SITE), [
            '        listen 80 default_server;', '        listen [::]:80 default_server;'])
        self.assertNotIn(MARK, PACKAGED_SITE)
        self.assertNotRegex(PACKAGED_SITE, r'(?m)^[ \t]*ssl_')

    def test_block_runs_last_before_nginx_and_after_every_other_listener(self):
        # The port check sees sshd and the console bridge only once they are
        # up, and the [::] lines are removed before they are followed.
        self.assertEqual(ENTRYPOINT.count('\n_setup_https\n'), 1)
        call = ENTRYPOINT.index('\n_setup_https\n')
        for earlier in ("sed -i '/listen \\[::]/d' /etc/nginx/sites-available/lldpq",
                        '/usr/sbin/sshd 2>/dev/null',
                        'echo "  ✓ console-pty (127.0.0.1:${CONSOLE_PTY_PORT})"',
                        's|(proxy_pass http://127\\.0\\.0\\.1:)[0-9]+(;)|'):
            self.assertLess(ENTRYPOINT.index(earlier), call, earlier)
        self.assertLess(call, ENTRYPOINT.index('LLDPq is ready!'))
        self.assertLess(call, ENTRYPOINT.index("\nexec nginx -g 'daemon off;'\n"))

    def test_plain_http_is_exactly_as_before(self):
        self.assertIn('echo "  ✓ nginx (port 80)"\n', ENTRYPOINT)
        self.assertTrue(ENTRYPOINT.endswith("\nexec nginx -g 'daemon off;'\n"))
        self.assertIn('EXPOSE 80 2033\n', DOCKERFILE)
        self.assertIn("CMD lldpq-vrf curl -fsS 'http://127.0.0.1:80/auth-api?action=check'",
                      DOCKERFILE)
        # Nothing here redirects to HTTPS or touches a cookie.
        for word in ('return 30', 'rewrite ^', 'add_header', 'Strict-Transport', 'Cookie'):
            self.assertNotIn(word, HTTPS_BLOCK, word)

    def test_listener_is_opened_by_the_nginx_that_runs_inside_the_vrf(self):
        # The entrypoint re-runs itself inside the management VRF and nginx
        # replaces that very shell, so port 80 and the HTTPS port are opened by
        # the same process in the same VRF; the block does nothing about VRFs.
        self.assertLess(ENTRYPOINT.index('\n_enter_mgmt_vrf "$@"\n'),
                        ENTRYPOINT.index('# ─── HTTPS (optional) ───'))
        self.assertEqual(len(re.findall(r'(?m)^[^#\n]*\bnginx -g\b', ENTRYPOINT)), 1)
        self.assertNotRegex(HTTPS_BLOCK, r'(?m)^[^#\n]*\b(ip|vrf)\b')

    def test_only_the_site_file_and_the_certificate_directory_are_written(self):
        self.assertEqual(HTTPS_BLOCK.count(SITE_LINE), 1)
        self.assertEqual(HTTPS_BLOCK.count(SUPPLIED_LINE), 1)
        self.assertEqual(HTTPS_BLOCK.count(GENERATED_LINE), 1)
        # The supplied directory is only read: the operator may mount it read-only.
        for line in HTTPS_BLOCK.splitlines():
            if re.match(r'\s*(rm|mv|chmod|chown|mkdir|cat|printf|echo)\b', line):
                self.assertNotIn('HTTPS_SUPPLIED_DIR', line, line)

    def test_an_optional_listener_never_ends_start_up(self):
        # (The one `exit` in the block is awk's, inside the site rewrite.)
        self.assertNotRegex(HTTPS_BLOCK, r'(?m)(^|\|\||&&|;|\bthen|\bdo)[ \t]*exit\b')
        self.assertIn("if ! report=$(nginx -t 2>&1 </dev/null); then", HTTPS_BLOCK)

    def test_outcome_is_printed_under_the_ready_message(self):
        ready = ENTRYPOINT.index('LLDPq is ready!')
        self.assertEqual(READY_BLOCK.count('case "$HTTPS_STATUS" in'), 1)
        self.assertIn('    ⚠*) echo "  $HTTPS_STATUS" >&2 ;;\n', ENTRYPOINT[ready:])
        self.assertIn('    *)  echo "  $HTTPS_STATUS" ;;\n', ENTRYPOINT[ready:])

    def test_image_already_has_openssl(self):
        # Not a package of its own in the install list: the image build itself
        # and the login CGI run it, so the feature adds no dependency.
        self.assertRegex(DOCKERFILE, r'(?m)^RUN ADMIN_HASH=\$\(echo -n "admin" \| openssl dgst ')
        self.assertIn('ADMIN_HASH=$(echo -n "admin" | openssl dgst -sha256 ',
                      ENTRYPOINT[:ENTRYPOINT.index('# ─── HTTPS (optional) ───')])
        # ss comes with iproute2, which the VRF handling needs anyway.
        self.assertRegex(DOCKERFILE, r'(?m)^    iproute2 ')

    def test_compose_files_show_the_variable_without_setting_it(self):
        self.assertIn('      # - LLDPQ_HTTPS_PORT=8443\n', COMPOSE)
        self.assertIn('      # - "8443:8443"\n', COMPOSE)
        self.assertIn('      # - ./tls:/etc/lldpq-tls:ro\n', COMPOSE)
        self.assertIn('      # LLDPQ_HTTPS_PORT: "8443"\n', PROVISIONING_COMPOSE)
        for name, text in (('docker-compose.yml', COMPOSE),
                           ('docker-compose.provisioning.yml', PROVISIONING_COMPOSE)):
            environment = text[text.index('    environment:'):text.index('\nvolumes:')]
            self.assertIn('LLDPQ_HTTPS_PORT', environment, name)
            active = [line for line in text.splitlines()
                      if re.search(r'LLDPQ_HTTPS_PORT|lldpq-tls|8443', line)
                      and not line.lstrip().startswith('#')]
            self.assertEqual(active, [], name)
        # The stock bridge stack still publishes port 80 the way it did.
        self.assertIn('      - "${LLDPQ_PORT:-80}:80"\n', COMPOSE)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


@unittest.skipUnless(shutil.which('nginx') and shutil.which('openssl'),
                     'nginx and openssl are not both installed on this host')
class RealToolsTests(unittest.TestCase):
    """The pair the entrypoint creates and the lines it adds, read by a real nginx."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-https-real-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        # Not root here: the directory cannot be handed to root.
        (self.bin / 'chown').write_text('#!/bin/sh\nexit 0\n')
        (self.bin / 'chown').chmod(0o755)
        self.site = self.root / 'site'
        self.site.write_text(PACKAGED_SITE)

    def run_functions(self, script):
        source = '\n'.join((
            'set -e', f'HTTPS_SITE_FILE="{self.site}"', f"HTTPS_SITE_MARK='{MARK}'",
            shell_function('_https_write_site'), shell_function('_https_generated_pair_usable'),
            shell_function('_https_generate_pair'), script, ''))
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run([shutil.which('bash'), '-c', source], capture_output=True,
                              text=True, timeout=60, env=environment)

    def render(self):
        """The site as rewritten, moved to loopback ports anyone may open."""
        text = self.site.read_text()
        self.http_port, self.https_port = free_port(), free_port()
        for old, new in (
                ('listen 80 default_server;',
                 f'listen 127.0.0.1:{self.http_port} default_server;'),
                (f'listen 8443 ssl default_server; {MARK}',
                 f'listen 127.0.0.1:{self.https_port} ssl default_server;'),
                ('root /var/www/html;', f'root "{self.root}/web";')):
            self.assertEqual(text.count(old), 1, old)
            text = text.replace(old, new)
        text = ''.join(line for line in text.splitlines(keepends=True)
                       if 'listen [::]' not in line)
        (self.root / 'site.conf').write_text(text)
        temp_paths = '\n'.join(f'    {name}_temp_path "{self.root}/{name}-temp";'
                               for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
        conf = self.root / 'nginx.conf'
        conf.write_text('daemon off;\nmaster_process off;\n'
                        f'pid "{self.root}/nginx.pid";\nerror_log "{self.root}/error.log";\n'
                        'events { worker_connections 64; }\nhttp {\n    access_log off;\n'
                        f'{temp_paths}\n    include "{self.root}/site.conf";\n}}\n')
        return conf

    def nginx_test(self):
        return subprocess.run(['nginx', '-t', '-p', str(self.root), '-c', str(self.render())],
                              capture_output=True, text=True, timeout=60)

    def test_generated_pair_and_added_lines_pass_nginx_t(self):
        tls = self.root / 'system config' / 'tls'
        result = self.run_functions(
            f'_https_generate_pair "{tls}/lldpq.crt" "{tls}/lldpq.key"\n'
            f'_https_generated_pair_usable "{tls}/lldpq.crt" "{tls}/lldpq.key"\n'
            f'_https_write_site 8443 "{tls}/lldpq.crt" "{tls}/lldpq.key"\n')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(sorted(path.name for path in tls.iterdir()), ['lldpq.crt', 'lldpq.key'])
        self.assertEqual(stat.S_IMODE((tls / 'lldpq.key').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(tls.stat().st_mode), 0o700)
        self.assertIn('BEGIN CERTIFICATE', (tls / 'lldpq.crt').read_text())
        self.assertIn('PRIVATE KEY', (tls / 'lldpq.key').read_text())
        dates = subprocess.run(
            ['openssl', 'x509', '-in', str(tls / 'lldpq.crt'), '-noout', '-checkend',
             str(824 * 86400)], capture_output=True, text=True, timeout=60)
        self.assertEqual(dates.returncode, 0, dates.stdout + dates.stderr)
        dates = subprocess.run(
            ['openssl', 'x509', '-in', str(tls / 'lldpq.crt'), '-noout', '-checkend',
             str(826 * 86400)], capture_output=True, text=True, timeout=60)
        self.assertEqual(dates.returncode, 1, dates.stdout + dates.stderr)
        tested = self.nginx_test()
        self.assertEqual(tested.returncode, 0, tested.stderr)

    def test_nginx_t_turns_down_a_key_that_does_not_belong_to_the_certificate(self):
        one, other = self.root / 'one', self.root / 'other'
        result = self.run_functions(
            f'_https_generate_pair "{one}/lldpq.crt" "{one}/lldpq.key"\n'
            f'_https_generate_pair "{other}/lldpq.crt" "{other}/lldpq.key"\n'
            f'_https_write_site 8443 "{one}/lldpq.crt" "{other}/lldpq.key"\n')
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        tested = self.nginx_test()
        self.assertNotEqual(tested.returncode, 0)
        self.assertIn('[emerg]', tested.stderr)

    def test_expired_certificate_is_not_reused(self):
        tls = self.root / 'tls'
        tls.mkdir()
        made = subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=old', '-keyout', str(tls / 'lldpq.key'), '-out',
             str(tls / 'lldpq.crt')], capture_output=True, text=True, timeout=60)
        self.assertEqual(made.returncode, 0, made.stderr)
        # Good for a day from its first second, so a moment later it is no
        # longer "still good a day from now".
        time.sleep(1.5)
        result = self.run_functions(
            f'if _https_generated_pair_usable "{tls}/lldpq.crt" "{tls}/lldpq.key"; '
            'then echo usable; else echo replace; fi\n')
        self.assertEqual((result.returncode, result.stdout), (0, 'replace\n'))


    @unittest.skipUnless(os.environ.get('LLDPQ_RUN_SOCKET_TESTS') == '1',
                         'opt-in local nginx socket integration')
    def test_same_page_over_http_and_over_tls(self):
        tls = self.root / 'tls'
        result = self.run_functions(
            f'_https_generate_pair "{tls}/lldpq.crt" "{tls}/lldpq.key"\n'
            f'_https_write_site 8443 "{tls}/lldpq.crt" "{tls}/lldpq.key"\n')
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        (self.root / 'web').mkdir()
        (self.root / 'web/login.html').write_text('<html>login</html>\n')
        nginx = subprocess.Popen(['nginx', '-p', str(self.root), '-c', str(self.render())],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        def stop():
            if nginx.poll() is None:
                nginx.terminate()
            nginx.wait(timeout=20)
            nginx.stderr.close()
        self.addCleanup(stop)
        for _ in range(100):
            try:
                socket.create_connection(('127.0.0.1', self.https_port), 0.2).close()
                break
            except OSError:
                if nginx.poll() is not None:
                    self.fail('nginx exited: ' + nginx.stderr.read().decode())
                time.sleep(0.05)
        else:
            self.fail('nginx did not start listening')
        with urllib.request.urlopen(f'http://127.0.0.1:{self.http_port}/login.html',
                                    timeout=10) as plain:
            self.assertEqual((plain.status, plain.read()), (200, b'<html>login</html>\n'))
        # The certificate presented is the generated one, and it verifies as such.
        self.assertEqual(
            ssl.get_server_certificate(('127.0.0.1', self.https_port)).strip(),
            (tls / 'lldpq.crt').read_text().strip())
        context = ssl.create_default_context(cafile=str(tls / 'lldpq.crt'))
        context.check_hostname = False
        with urllib.request.urlopen(f'https://127.0.0.1:{self.https_port}/login.html',
                                    timeout=10, context=context) as secure:
            self.assertEqual((secure.status, secure.read()), (200, b'<html>login</html>\n'))


if __name__ == '__main__':
    unittest.main()
