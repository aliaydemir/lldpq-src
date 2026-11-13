"""What README.md and DOCKER.md say about the follow-up changes, against the code.

Same idea as test_docs_feature_text.py: a sentence of a guide that quotes a
message, a number or a path is compared with the code that prints, sets or
serves it, so the two cannot drift apart. Behaviour itself is covered by the
tests of each change (named in the comments); here the guide is the subject.

Covered:
  * HTTPS: which login gets a `Secure` session cookie, the directive for a
    TLS-terminating proxy (checked with nginx where one that has the
    directive is installed), and a certificate link whose target is outside
    the mount;
  * the CGI worker pool: the default size, how many device commands the UI
    runs at a time, and the 60 seconds after which a gated directory answers
    500;
  * ZTP: the line Save refuses, and a typed password that was not applied;
  * which paths nginx serves without a login;
  * Backup & Restore with an empty inventory, the Ask-AI masking examples,
    Test Connection, and the telemetry line after a stale revision.
"""

import http.client
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_ai_api_contract import load_symbols
from test_auth_hardening_nginx import directive, free_port, parse_nginx, select_location
from test_docs_feature_text import flat, read, section
from test_followup_masking import REDACTION_SYMBOLS


DOCKER_DOC = read('DOCKER.md')
README = read('README.md')
ENTRYPOINT = read('docker/docker-entrypoint.sh')
SITE = read('etc/nginx/sites-available/lldpq')
HTTPS = flat(section(DOCKER_DOC, '\n## HTTPS\n', '\n## DHCP/ONIE provisioning\n'))
LOGIN_PATHS = flat(section(README, '\n### login-protected paths:\n',
                           '\n### login attempt limit:\n'))
NUMBER_WORDS = {3: 'three', 4: 'four'}
# The nginx release that introduced proxy_cookie_flags.
PROXY_COOKIE_FLAGS_SINCE = (1, 19, 3)


def site_server():
    (server,) = [block for block in parse_nginx(SITE).blocks if block.header == 'server']
    return server


class HttpsGuideTests(unittest.TestCase):
    def test_secure_flag_follows_the_listener_the_login_arrived_on(self):
        # Behaviour: test_followup_https_cookie.py runs the CGI both ways.
        auth = read('html/auth-api.sh')
        self.assertIn('if [ "$HTTPS" = "on" ]; then\n'
                      '                COOKIE_SECURE="Secure; "\n', auth)
        self.assertIn('SameSite=Strict; ${COOKIE_SECURE}$COOKIE_EXPIRY"', auth)
        self.assertIn('fastcgi_param HTTPS $https if_not_empty;',
                      section(SITE, 'location = /auth-api {', '\n        }\n'))
        self.assertIn('A login that arrives on the HTTPS port gets its session cookie with the '
                      '`Secure` flag: the browser sends it to `https://` addresses only', HTTPS)
        self.assertIn('A login over plain HTTP on port 80 gets the cookie without the flag, '
                      'as before.', HTTPS)
        self.assertNotIn('does not carry', HTTPS)
        # How long the cookie stays, and what removes it.
        self.assertIn('REMEMBER_TIMEOUT=604800 ', auth)
        self.assertIn('COOKIE_EXPIRY="Max-Age=$REMEMBER_TIMEOUT;"', auth)
        self.assertIn('Remember me (7 days)', read('html/login.html'))
        self.assertIn('echo "Set-Cookie: lldpq_session=; Path=/; HttpOnly; Max-Age=0"', auth)
        self.assertIn('Logging out over HTTPS removes the cookie; otherwise it stays until the '
                      'browser is closed, or for 7 days with **Remember me**.', HTTPS)
        # README: the same rule where the session cookie is described.
        self.assertIn('A login that arrives over TLS gets the session cookie with the `Secure` '
                      'flag', LOGIN_PATHS)
        self.assertIn('[HTTPS](DOCKER.md#https)', LOGIN_PATHS)

    def test_tls_terminating_proxy_note(self):
        # Only the connection decides: no forwarded header reaches the CGI.
        location = section(SITE, 'location = /auth-api {', '\n        }\n')
        self.assertNotIn('forwarded', (location + read('html/auth-api.sh')).lower())
        self.assertIn('Behind a reverse proxy that terminates TLS the container receives plain '
                      'HTTP and does not set the flag; forwarded headers are not read.', HTTPS)
        self.assertIn('`proxy_cookie_flags lldpq_session secure;`', HTTPS)
        self.assertIn('echo "Set-Cookie: lldpq_session=$TOKEN; ', read('html/auth-api.sh'))
        # The version ProxyDirectiveTests asks of the installed nginx.
        self.assertIn('Add the flag on the proxy, with nginx %d.%d.%d or later: '
                      '`proxy_cookie_flags ' % PROXY_COOKIE_FLAGS_SINCE, HTTPS)

    def test_secure_cookie_where_https_is_no_longer_served(self):
        # The three ways a container that served HTTPS comes to serve HTTP
        # only: no variable, a start that could not enable it, a 4.2.x image.
        self.assertIn('    [ -n "$port" ] || return 0\n',
                      section(ENTRYPOINT, '\n_setup_https() {\n', '\n}\n'))
        self.assertIn('_https_not_enabled() {\n    HTTPS_STATUS="⚠ HTTPS not enabled '
                      '(LLDPQ_HTTPS_PORT=$LLDPQ_HTTPS_PORT): $1; the web UI is served over '
                      'HTTP only"\n}\n', ENTRYPOINT)
        self.assertIn('The 4.2.x images ignore the variable, so a rollback to one serves HTTP '
                      'only.', HTTPS)
        # The cookie of the HTTPS login is what stands in the way, by its name.
        self.assertIn('echo "Set-Cookie: lldpq_session=$TOKEN; ', read('html/auth-api.sh'))
        self.assertIn('or for 7 days with **Remember me**. Where HTTPS is no longer served '
                      '(`LLDPQ_HTTPS_PORT` was removed, HTTPS could not be enabled at a later '
                      'start, or the container was rolled back to a 4.2.x image), a browser '
                      'that still holds the `Secure` cookie can log in over `http://` only '
                      'after its `lldpq_session` cookie for that host has been deleted or has '
                      'expired.', HTTPS)
        # Not a remedy for the rollback alone.
        self.assertNotIn('can log in there only after', HTTPS)

    def test_certificate_link_with_a_target_outside_the_mount(self):
        # Behaviour: test_docker_image_https.py,
        # test_supplied_links_without_a_target_are_not_replaced_by_a_self_signed_pair.
        self.assertIn('HTTPS_SUPPLIED_DIR=/etc/lldpq-tls\n', ENTRYPOINT)
        supplied = section(ENTRYPOINT, '    cert="$HTTPS_SUPPLIED_DIR/tls.crt"\n',
                           '    else\n        cert="$HTTPS_GENERATED_DIR/lldpq.crt"\n')
        # A link is "there" whatever it points at; an unreadable target is
        # the incomplete pair, and that branch never creates a certificate.
        self.assertIn('if [ -e "$cert" ] || [ -L "$cert" ] || [ -e "$key" ] || [ -L "$key" ]; '
                      'then\n', supplied)
        self.assertIn('if [ ! -s "$cert" ] || [ ! -s "$key" ]; then\n            '
                      '_https_not_enabled "$HTTPS_SUPPLIED_DIR must hold both tls.crt and '
                      'tls.key"\n            return 0\n', supplied)
        self.assertNotIn('_https_generate_pair', supplied)
        self.assertIn('A symbolic link counts as a file that is there. One whose target is '
                      'outside the mounted directory does not resolve in the container', HTTPS)
        self.assertIn('that pair is supplied but unusable, so the log carries the warning with '
                      '`/etc/lldpq-tls must hold both tls.crt and tls.key`, the web UI is served '
                      'over HTTP only and no self-signed pair is created.', HTTPS)
        self.assertIn('Links whose targets are inside the mounted directory work.', HTTPS)


def proxy_directive_unavailable():
    """Why the installed nginx cannot take the documented directive; '' when it can."""
    nginx = shutil.which('nginx')
    if not nginx:
        return 'nginx is not installed'
    banner = subprocess.run([nginx, '-v'], capture_output=True, text=True, timeout=30,
                            check=False)
    version = re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', banner.stderr + banner.stdout)
    if not version:
        return 'the version of the installed nginx could not be read'
    # Ubuntu 22.04 (the base of the image) and Debian 11 ship 1.18.
    if tuple(map(int, version.groups())) < PROXY_COOKIE_FLAGS_SINCE:
        return ('proxy_cookie_flags needs nginx %d.%d.%d or later, this is %s'
                % (PROXY_COOKIE_FLAGS_SINCE + (version.group(0),)))
    return ''


class ProxyDirectiveTests(unittest.TestCase):
    """The directive DOCKER.md gives for a TLS-terminating proxy, in nginx itself."""

    @classmethod
    def setUpClass(cls):
        reason = proxy_directive_unavailable()
        if reason:
            raise unittest.SkipTest(reason)

    def configuration(self, directory, proxy_port, upstream_port):
        (documented,) = re.findall(r'`(proxy_cookie_flags [^`]+;)`', HTTPS)
        login = re.search(r'echo "Set-Cookie: (lldpq_session=\$TOKEN; [^"]*)"',
                          read('html/auth-api.sh')).group(1)
        # What a login over plain HTTP answers, with and without "Remember me".
        cookies = {
            '/session': login.replace('$TOKEN', 'token').replace('${COOKIE_SECURE}', '')
                             .replace('$COOKIE_EXPIRY', ''),
            '/remember': login.replace('$TOKEN', 'token').replace('${COOKIE_SECURE}', '')
                              .replace('$COOKIE_EXPIRY', 'Max-Age=604800;'),
        }
        for value in cookies.values():
            assert '$' not in value and 'Secure' not in value, value
        answers = ''.join(
            f'        location = {path} {{ add_header Set-Cookie "{value}"; return 204; }}\n'
            for path, value in cookies.items())
        temp_paths = ''.join(
            f'    {name}_temp_path "{directory}/{name}-temp";\n'
            for name in ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi'))
        conf = directory / 'nginx.conf'
        conf.write_text(
            'daemon off;\nmaster_process off;\n'
            f'pid "{directory}/nginx.pid";\nerror_log "{directory}/error.log";\n'
            'events { worker_connections 64; }\n'
            f'http {{\n    access_log off;\n{temp_paths}'
            # Stands for the container, which sees plain HTTP behind the proxy.
            f'    server {{\n        listen 127.0.0.1:{upstream_port};\n{answers}    }}\n'
            f'    server {{\n        listen 127.0.0.1:{proxy_port};\n'
            f'        location / {{ proxy_pass http://127.0.0.1:{upstream_port}; '
            f'{documented} }}\n    }}\n}}\n', encoding='utf-8')
        return conf, sorted(cookies)

    def test_nginx_accepts_the_documented_directive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            conf, _ = self.configuration(directory, free_port(), free_port())
            result = subprocess.run(['nginx', '-t', '-c', str(conf), '-p', str(directory)],
                                    capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get('LLDPQ_RUN_SOCKET_TESTS') == '1',
                         'opt-in local nginx socket integration')
    def test_proxied_login_cookie_gets_the_secure_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            proxy_port, upstream_port = free_port(), free_port()
            conf, paths = self.configuration(directory, proxy_port, upstream_port)
            nginx = subprocess.Popen(['nginx', '-c', str(conf), '-p', str(directory)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for port in (upstream_port, proxy_port):
                    for path in paths:
                        for _ in range(100):
                            try:
                                connection = http.client.HTTPConnection(
                                    '127.0.0.1', port, timeout=5)
                                connection.request('GET', path)
                                break
                            except OSError:
                                time.sleep(0.05)
                        response = connection.getresponse()
                        response.read()
                        attributes = [part.strip() for part in
                                      response.getheader('Set-Cookie').split(';')]
                        with self.subTest(path=path, proxied=port == proxy_port):
                            self.assertEqual(attributes[0], 'lldpq_session=token')
                            self.assertEqual('Secure' in attributes, port == proxy_port)
                            self.assertIn('HttpOnly', attributes)
                            self.assertIn('SameSite=Strict', attributes)
            finally:
                nginx.terminate()
                nginx.wait(timeout=10)


class ProxyDirectiveConditionTests(unittest.TestCase):
    """ProxyDirectiveTests is skipped, not failed, where nginx lacks the directive."""

    def with_nginx(self, banner, call):
        """call() while the only nginx on PATH is a stand-in whose -v prints banner."""
        with tempfile.TemporaryDirectory() as temporary:
            if banner:
                stand_in = Path(temporary) / 'nginx'
                # nginx writes the version to stderr.
                stand_in.write_text(f'#!/bin/sh\necho "{banner}" >&2\n', encoding='utf-8')
                stand_in.chmod(0o755)
            with mock.patch.dict(os.environ, {'PATH': temporary}):
                return call()

    def test_condition_follows_the_version_nginx_reports(self):
        too_old = 'proxy_cookie_flags needs nginx 1.19.3 or later, this is nginx/'
        for banner, reason in (
                ('nginx version: nginx/1.18.0 (Ubuntu)', too_old + '1.18.0'),
                ('nginx version: nginx/1.14.2', too_old + '1.14.2'),
                # Numbers, not text: "1.9" sorts after "1.19".
                ('nginx version: nginx/1.9.15', too_old + '1.9.15'),
                ('nginx version: nginx/1.19.2', too_old + '1.19.2'),
                ('nginx version: nginx/1.19.3', ''),
                ('nginx version: nginx/1.24.0 (Ubuntu)', ''),
                ('nginx version: openresty/1.21.4.1',
                 'the version of the installed nginx could not be read'),
                ('', 'nginx is not installed')):
            with self.subTest(banner=banner):
                self.assertEqual(self.with_nginx(banner, proxy_directive_unavailable), reason)

    def test_class_is_skipped_with_the_nginx_of_the_image_base(self):
        with self.assertRaises(unittest.SkipTest) as skipped:
            self.with_nginx('nginx version: nginx/1.18.0 (Ubuntu)',
                            ProxyDirectiveTests.setUpClass)
        self.assertIn('needs nginx 1.19.3 or later', str(skipped.exception))
        self.assertIsNone(self.with_nginx('nginx version: nginx/1.19.3',
                                          ProxyDirectiveTests.setUpClass))


class CgiWorkerPoolGuideTests(unittest.TestCase):
    def test_pool_sizes_and_the_wait_of_a_gated_directory(self):
        # Behaviour of the two pages: test_followup_pages_frontend.mjs.
        workers = int(re.search(r'(?m)^LLDPQ_FCGI_WORKERS="\$\{LLDPQ_FCGI_WORKERS:-(\d+)\}"$',
                                ENTRYPOINT).group(1))
        native = int(re.search(
            r'(?m)^ExecStart=/usr/sbin/fcgiwrap -f -c (\d+)$',
            read('etc/systemd/system/fcgiwrap.service.d/lldpq-workers.conf')).group(1))
        self.assertEqual(workers, native)
        commands = int(re.search(r'(?m)^const POOL = (\d+);$',
                                 read('html/commands.html')).group(1))
        verify = section(read('html/fabric-migration.html'), 'async function runVerification()',
                         "command: 'sudo bridge vlan show'")
        self.assertIn("fetch('/fabric-api.sh?action=run-device-command'", verify)
        migration = int(re.search(r'await fetchPool\(devs, (\d+), ', verify).group(1))
        self.assertEqual(commands, migration)
        self.assertEqual(workers - commands, 1)
        at_a_time, default = NUMBER_WORDS[commands], NUMBER_WORDS[workers]

        # The gate sets no timeout of its own, nor does the server or the file:
        # nginx's default fastcgi_read_timeout of 60 s ends the wait, and
        # auth_request turns the 504 of the subrequest into 500.
        server = site_server()
        gate, exact = select_location(server, '/lldpq-session-gate')
        self.assertTrue(exact)
        self.assertEqual(directive(gate, 'fastcgi_pass'), 'unix:/var/run/fcgiwrap.socket')
        self.assertIsNone(directive(gate, 'fastcgi_read_timeout'))
        for scope in (server, parse_nginx(SITE)):
            self.assertEqual([statement for statement in scope.statements
                              if statement.startswith('fastcgi_')], [])
        self.assertIn('fcgiwrap; while that service is down they answer 500. While every '
                      'fcgiwrap worker is busy the request waits, and it answers 500 when no '
                      'worker has answered the check within 60 seconds.', LOGIN_PATHS)
        self.assertIn(f'The **Commands** page and the Verify step of **Fabric Migration** run '
                      f'{at_a_time} device commands at a time, so they leave one of the '
                      f'{default} default workers free; with fewer workers (Docker: '
                      f'`LLDPQ_FCGI_WORKERS` set to 1-{workers - 1}) they can still occupy the '
                      f'whole pool.', LOGIN_PATHS)
        self.assertIn(f'Runs use a bounded {at_a_time}-device client pool',
                      flat(section(README, '\n## [02i]', '\n## [02j]')))
        self.assertNotIn('four-device', README)

        linux = flat(section(DOCKER_DOC, '\n### On a Linux server\n',
                             '\n### On a Cumulus switch\n'))
        self.assertIn(f'The web API uses {default} CGI workers by default.', linux)
        self.assertIn(f'The **Commands** page and the Verify step of **Fabric Migration** run '
                      f'{at_a_time} device commands at a time, which leaves one of the '
                      f'{default} default workers to the rest of the UI. With 1 to '
                      f'{workers - 1} workers they can occupy the whole pool', linux)
        self.assertIn('gets HTTP 500 when no worker has answered it within 60 seconds (see '
                      '[login-protected paths](README.md#login-protected-paths))', linux)


class ZtpSaveGuideTests(unittest.TestCase):
    def setUp(self):
        self.ztp = flat(section(README, '\n### ZTP Tab\n', '\n### Upgrade Tab\n'))

    def test_line_with_e_and_no_hash_is_refused(self):
        api = read('html/provision-api.sh')
        # Two adjacent string literals in the API.
        pieces = re.search(r"raise ValueError\(\s*'(\"chpasswd -e\" needs [^']*)'\s*'([^']*)'\)",
                           api)
        self.assertIsNotNone(pieces)
        refused = ''.join(pieces.groups())
        self.assertEqual(refused, '"chpasswd -e" needs a crypt hash for cumulus; remove -e to '
                                  'have a clear-text password hashed on save')
        self.assertIn("'error': f'ZTP script was not saved: {exc}'", api)
        self.assertIn('the message begins `ZTP script was not saved:`. The same happens when the '
                      '`cumulus` line ends in `chpasswd -e` and its value is not a crypt hash; '
                      f'the message then continues `{refused}`.', self.ztp)

    def test_typed_password_that_was_not_applied(self):
        page = section(read('html/provision.html'), 'async function saveZTPScript() {',
                       '\n}\n')
        toast = ('ZTP script saved, but the typed password was NOT applied: click Apply to '
                 'Script, then Save')
        # The script in the editor is what is sent; the field is emptied only
        # when the typed password is the one in that script.
        self.assertIn("const content = document.getElementById('ztpEditor').value;", page)
        self.assertIn("await apiCall('save-ztp-script', { content })", page)
        self.assertIn("if (applied) document.getElementById('ztpPassword').value = '';", page)
        self.assertIn(f"else showToast('{toast}', 'error');", page)
        self.assertIn('A typed password reaches the script only through **Apply to Script**. '
                      '**Save** without it stores the script that is in the editor, keeps the '
                      f'typed password in the field and reports `{toast}`.', self.ztp)


class PathsServedWithoutLoginTests(unittest.TestCase):
    def test_readme_names_what_nginx_serves_without_a_session(self):
        exports = flat(section(README, '## [02j]', '### Discover available exports'))
        self.assertNotIn('Only the endpoints of this section are public', README)
        self.assertIn('The exports of this section are public. Everything under `/configs/`, '
                      '`/hstr/` and `/monitor-results/` needs a login', exports)
        sentence = section(exports, 'Other content is served without a login too:',
                           '`/provision-uploads/`).')
        self.assertEqual(re.findall(r'`(/[^`]*)`', sentence + '`/provision-uploads/`'),
                         ['/lldp_results.ini', '/problems-lldp_results.ini', '/topology.dot',
                          '/topology_config.yaml', '/display-aliases.json', '/cumulus-ztp.sh',
                          '/serial-mapping.txt', '/generated_config_folder/',
                          '/provision-uploads/'])
        for words in ('the login page with the scripts, styles and images of the UI',
                      '(LLDP neighbor data)',
                      'the OS images with their `onie-installer` aliases',
                      '`/generated_config_folder/` with the complete NVUE start-up '
                      'configuration of each device'):
            self.assertIn(words, sentence)

        # Where those files are: the web root, under these names.
        lldp = read('lldpq/check-lldp.sh')
        self.assertIn('"$WEB_ROOT/lldp_results.ini"', lldp)
        self.assertIn('"$WEB_ROOT/problems-lldp_results.ini"', lldp)
        self.assertIn('TOPOLOGY_FILE="$WEB_ROOT/topology.dot"', read('html/edit-topology.sh'))
        self.assertIn('CONFIG_FILE="$WEB_ROOT/topology_config.yaml"', read('html/edit-config.sh'))
        self.assertIn("alias_file = os.path.join(web_root, 'display-aliases.json')",
                      read('html/setup-api.sh'))
        provision = read('html/provision-api.sh')
        self.assertIn("f'{WEB_ROOT}/provision-uploads'", provision)
        self.assertIn("SERIAL_MAPPING_FILE = f'{WEB_ROOT}/serial-mapping.txt'", provision)
        self.assertIn("GENERATED_CONFIGS_DIR = f'{WEB_ROOT}/generated_config_folder'", provision)
        # What the ZTP script asks the server for besides itself and the
        # image: the serial-to-hostname table, then the file that replaces
        # the configuration of the device.
        ztp = read('html/cumulus-ztp.sh')
        self.assertIn('local mapping_url="http://$IMAGE_SERVER_HOSTNAME/serial-mapping.txt"\n',
                      ztp)
        self.assertIn('    for extension in yaml yml; do\n        url="http://'
                      '$IMAGE_SERVER_HOSTNAME/generated_config_folder/${hostname}.${extension}"\n',
                      ztp)
        self.assertIn('CONFIG_FILE="$WORK_DIR/startup.yaml"\n', ztp)
        self.assertIn('nv config replace "$staged"', ztp)
        aliases = re.search(r'ONIE_ALIAS_NAMES = \(([^)]*)\)', provision).group(1)
        aliases = re.findall(r"'([^']+)'", aliases)
        self.assertEqual(sorted(aliases), ['onie-installer', 'onie-installer-x86_64',
                                           'onie-installer-x86_64-mlnx'])
        login = read('html/login.html')
        assets = ['/css/auth.js', '/css/mobile.css', '/png/lldpq-banner.png']
        for asset in assets[1:]:
            self.assertIn(f'"{asset}"', login)

        # The location nginx answers each of them from has no session check,
        # hands nothing to a CGI and does not refuse the request.
        server = site_server()
        served = (['/login.html', '/lldp_results.ini', '/problems-lldp_results.ini',
                   '/topology.dot', '/topology_config.yaml', '/display-aliases.json',
                   '/cumulus-ztp.sh', '/cumulus-linux-5.11.1-mlx-amd64.bin',
                   '/serial-mapping.txt', '/generated_config_folder/leaf01.yaml',
                   '/generated_config_folder/leaf01.yml',
                   '/provision-uploads/ztp-artifacts/job-1.ztp']
                  + assets + ['/' + alias for alias in aliases])
        for uri in served:
            with self.subTest(uri=uri):
                chain, _ = select_location(server, uri)
                self.assertTrue(chain)
                for name in ('auth_request', 'fastcgi_pass', 'proxy_pass', 'return'):
                    self.assertIsNone(directive(chain, name), name)
        for uri in ('/configs/leaf01.txt', '/hstr/Problems-1.ini',
                    '/monitor-results/export/bgp.json'):
            with self.subTest(uri=uri):
                chain, _ = select_location(server, uri)
                self.assertEqual(directive(chain, 'auth_request'), '/lldpq-session-gate')


class OtherGuideSentencesTests(unittest.TestCase):
    def test_backup_bundle_of_an_empty_inventory(self):
        # Behaviour: test_followup_inventory_backup.py. DOCKER.md's sentence is
        # checked in test_docs_feature_text.py (test_empty_inventory).
        backup = flat(section(README, '\n### Backup & Restore (step 9)\n',
                              '\n### Maintenance (step 10)\n'))
        api = read('html/setup-api.sh')
        left_out = 'devices.yaml was left out of the bundle: it has no devices.'
        self.assertIn(f"left_out.append('{left_out}')", api)
        self.assertIn("and isinstance(inventory.get('devices'), dict)\n"
                      "                            and not inventory['devices']):", api)
        self.assertIn("'warnings': left_out,", api)
        self.assertIn('**Empty inventory:** `devices.yaml` is left out of the bundle while its '
                      '`devices:` mapping is empty (a new Docker deployment). The reply of the '
                      f'export lists `{left_out}` under `warnings`, and restoring that bundle '
                      "does not change the target's inventory.", backup)

    def test_ask_ai_masking_examples(self):
        contract = flat(section(README, '### AI JSON special contract', '### Ordered row columns'))
        redact = load_symbols(*REDACTION_SYMBOLS)['redact_secrets']
        value, mark = 'ZZinventedVALUE99', '***REDACTED***'
        self.assertIn('Such a keyword also counts as the last part of a name joined with `_` '
                      '(`ansible_password`, `tacacs_secret`, `snmp_community`), and so do '
                      '`..._pass` and the NVUE `md5-key`.', contract)
        for line in ('ansible_password: {}', 'tacacs_secret: {}', 'snmp_community: {}',
                     'ansible_ssh_pass: {}',
                     'nv set interface swp1 router ospf authentication md5-key {}'):
            with self.subTest(masked=line):
                self.assertEqual(redact(line.format(value)), line.format(mark))
        self.assertIn('After `_`, `community` is masked only in SNMP names, so `bgp_community` '
                      'keeps its value, and `..._md5` is taken for a checksum and left as it '
                      'is.', contract)
        self.assertIn('In JSON the string value of such a key is masked (`"password": "..."`); '
                      'objects, lists and numbers are not, so SNMP community names and SNMPv3 '
                      'keys that `nv ... -o json` prints as object keys stay readable.', contract)
        self.assertEqual(redact(f'"password": "{value}"'), f'"password": "{mark}"')
        for line in ('bgp_community: 65000:100', 'file_md5: {}', '"password": 12345',
                     '"community": {{"string": "65000:100"}}', '"community": ["65000:100"]',
                     '"readonly-community": {{"{}": {{}}}}',
                     '"auth-sha": {{"{0}": {{"encrypt-aes": {{"{0}": {{}}}}}}}}'):
            with self.subTest(kept=line):
                self.assertEqual(redact(line.format(value)), line.format(value))

    def test_test_connection_key_check(self):
        # Behaviour: test_ai_fix_gemini_key.py (no connection is attempted).
        api = read('html/ai-api.sh')
        pieces = re.search(r'error_json\("(API key contains [^"]*)"\s*"([^"]*)"\)', api)
        self.assertIsNotNone(pieces)
        what, remedy = ''.join(pieces.groups()).split('; ')
        self.assertEqual(remedy, 'paste the key as a single line')
        self.assertTrue(what.startswith('API key contains a line break'))
        self.assertIn('**Test Connection** rejects an API key that ' + what[len('API key '):]
                      + ', before it contacts the provider: ' + remedy + '.', flat(README))

    def test_telemetry_line_after_a_stale_revision(self):
        # Behaviour: test_followup_pages_frontend.mjs.
        page = read('html/telemetry.html')
        self.assertIn("result.error.includes('Stale revision')", page)
        self.assertIn('addLogEntry(`Failed: ${result.error} - LLDPq detached its own staged '
                      "change, retry`, 'error', result.device);", page)
        enable = flat(section(README, '\n### enable on switches\n', '\n### dashboard features\n'))
        self.assertIn('When that error contains `Stale revision`, the line ends in '
                      '`- LLDPq detached its own staged change, retry`.', enable)


if __name__ == '__main__':
    unittest.main()
