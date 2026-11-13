"""What DOCKER.md, README.md and the web UI's update hint tell the operator.

The guides quote log lines, error messages, variable names and limits that an
operator compares with what a switch or a container prints.  Each quoted text
is checked here against the code that prints it, so the two cannot drift
apart, and against the place in the guide where the operator looks for it.

Also covered: which published images add the management-VRF routing rule to a
switch (stated once in each guide, with the check that does not depend on the
version), and the update hint of the web UI, which used to offer one command
that leaves a container created with `docker run` on its old image.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


DOCKER_DOC = read('DOCKER.md')
README = read('README.md')
INDEX = read('html/index.html')
SETUP = read('html/setup.html')
ENTRYPOINT = read('docker/docker-entrypoint.sh')
SITE = read('etc/nginx/sites-available/lldpq')
GUIDE_URL = 'https://github.com/aliaydemir/lldpq-src/blob/main/DOCKER.md#updating'


def section(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin + len(start))]


def flat(text):
    """Prose as one line: wrapped sentences compare regardless of the wrap."""
    return re.sub(r'\s*\n[> ]*\s*', ' ', text)


MGMT_VRF = section(DOCKER_DOC, '#### Management VRF',
                   'Direct access then needs the control-plane ACL')
README_DOCKER = section(README, '\n## Docker\n', '\n## Requirements (non-Docker install)\n')


class AffectedVersionsTests(unittest.TestCase):
    def test_docker_guide_names_the_affected_images_in_the_management_vrf_note(self):
        note = flat(MGMT_VRF)
        self.assertIn('The published images from 2.2.3 (built on or after 2026-02-11) through '
                      '4.2.4 add the rule; 4.2.5 and later do not.', note)
        self.assertIn('The version number is not the definitive check.', note)
        # The two checks that are: the rule on the host, the line in the log.
        self.assertIn("ip -4 rule show | grep '^100:'", MGMT_VRF)
        self.assertIn("sudo docker logs lldpq 2>&1 | grep -m1 'outbound via mgmt'", note)
        self.assertEqual(DOCKER_DOC.count('2026-02-11'), 1)

    def test_readme_names_them_once_in_its_docker_part(self):
        part = flat(README_DOCKER)
        self.assertIn('Published images from 2.2.3 (built on or after 2026-02-11) through '
                      '4.2.4 add a routing rule to a Cumulus switch', part)
        self.assertIn('4.2.5 and later do not', part)
        self.assertIn("`ip -4 rule show | grep '^100:'`", part)
        self.assertIn('`outbound via mgmt`', part)
        self.assertIn('[Management VRF](DOCKER.md#management-vrf)', part)
        self.assertEqual(README.count('2026-02-11'), 1)

    def test_fixed_version_matches_the_entrypoint_that_no_longer_adds_the_rule(self):
        # The image described as fixed removes the rule and never adds one.
        self.assertIn('ip -4 rule del pref 100 table', ENTRYPOINT)
        self.assertNotRegex(ENTRYPOINT, r'(?m)^[^#\n]*\bip (-4 )?rule add\b')


class WebUiUpdateHintTests(unittest.TestCase):
    ONE_LINER = ('curl -fsSL https://aliaydemir.com/lldpq-amd64.tar.gz | gunzip | '
                 'docker load &amp;&amp; docker compose up -d')

    def test_popup_points_at_the_guide_instead_of_a_compose_one_liner(self):
        docker_branch = re.search(r"const upCmd = docker\s*\?\s*'([^']*)'", INDEX)
        self.assertIsNotNone(docker_branch)
        self.assertEqual(docker_branch.group(1), GUIDE_URL)
        self.assertNotIn('docker load', INDEX)
        self.assertNotIn('docker compose up', INDEX)
        intro = re.search(r'const upIntro = docker\s*\?\s*"((?:[^"\\]|\\.)*)"', INDEX).group(1)
        self.assertIn('Update on the <b style=\\"color:#d4d4d4;\\">host</b> with the steps '
                      'under <b style=\\"color:#d4d4d4;\\">Updating</b> in DOCKER.md', intro)
        self.assertIn('<code>docker run</code>', intro)
        self.assertIn('loading the new image alone leaves the old container running', intro)

    def test_setup_page_keeps_the_one_liner_for_compose_only(self):
        hint = section(SETUP, '<div id="update-docker"', '<div id="update-bare">')
        self.assertIn(f'<a href="{GUIDE_URL}"', hint)
        self.assertIn('For a <strong>Compose</strong> deployment the short form is:', hint)
        # Still the text of the copy button's source, once and unchanged.
        self.assertEqual(hint.count(f'<pre id="docker-cmd" class="run-output" '
                                    f'style="height:auto; min-height:0; padding:14px;">'
                                    f'{self.ONE_LINER}</pre>'), 1)
        self.assertEqual(SETUP.count('docker load'), 1)
        self.assertIn('Compose only: loads the new image and recreates the service', hint)
        self.assertIn('Run it from the directory containing your <code>docker-compose.yml</code>',
                      hint)
        self.assertIn('A container created with <code>docker run</code>, as on a Cumulus '
                      'switch, is not replaced by this command', hint)

    def test_guide_says_that_loading_alone_does_not_update(self):
        updating = flat(section(DOCKER_DOC, '\n## Updating\n', '\n### Compose deployments\n'))
        self.assertIn('Loading a new archive does not update a running container: `docker load` '
                      'only moves the `lldpq:latest` tag, and `sudo docker restart lldpq` starts '
                      'the image the container was created from.', updating)
        self.assertIn('`sudo docker exec lldpq cat /var/www/html/VERSION` prints the new version',
                      updating)
        self.assertIn('COPY VERSION /var/www/html/', read('docker/Dockerfile'))


class DockerGuideMatchesTheImageTests(unittest.TestCase):
    """DOCKER.md against docker-entrypoint.sh, the Dockerfile and the Compose files."""

    def quoted(self, template, **values):
        """The line the entrypoint prints, once it is in the code as `template`."""
        self.assertIn(template, ENTRYPOINT)
        for name, value in values.items():
            template = template.replace('$' + name, value)
        self.assertNotIn('$', template)
        return template

    def test_ssh_switch(self):
        cumulus_run = re.search(r'### On a Cumulus switch.*?```bash\n(.*?)```', DOCKER_DOC, re.S)
        self.assertIn('  -e LLDPQ_SSHD=no \\\n', cumulus_run.group(1))
        boundary = flat(section(DOCKER_DOC, '> **Critical security boundary:**',
                                'The commands above run LLDPq in'))
        self.assertIn('`LLDPQ_SSHD=no` turns that service off: nothing listens on TCP/2033, the '
                      'known password is not set and the account\'s password is locked.', boundary)
        self.assertIn('on a switch, start the container with `-e LLDPQ_SSHD=no` as shown above',
                      boundary)
        # The values the entrypoint accepts, and the two forms for Compose.
        self.assertIn('    no|false|off|0) SSHD_ENABLED=false ;;\n    yes|true|on|1) ;;\n',
                      ENTRYPOINT)
        self.assertIn('`no`, `false`, `off` or `0` (in any case) keep the SSH service off; '
                      'unset, empty, `yes`, `true`, `on` or `1` start it as before', boundary)
        self.assertIn('passwd -l lldpq', ENTRYPOINT)
        self.assertIn('      # LLDPQ_SSHD: "no"\n', read('docker/docker-compose.provisioning.yml'))
        self.assertIn('      # - LLDPQ_SSHD=no\n', read('docker/docker-compose.yml'))
        self.assertIn('uncomment the `LLDPQ_SSHD` line under `environment:`', boundary)
        self.assertIn('uncommenting `LLDPQ_SSHD: "no"`', DOCKER_DOC)
        for line in (
                self.quoted('  sshd: not started (LLDPQ_SSHD=$LLDPQ_SSHD)', LLDPQ_SSHD='no'),
                self.quoted("  SSH: disabled (LLDPQ_SSHD=$LLDPQ_SSHD); use 'docker exec' "
                            'for a shell', LLDPQ_SSHD='no')):
            self.assertIn(line + '\n', DOCKER_DOC)

    def test_empty_inventory(self):
        setup = section(DOCKER_DOC, '\n## First-time setup\n', '\n## HTTPS\n')
        hint = self.quoted('  No devices defined yet — add them under Assets → Edit Devices '
                           '(sample: /home/lldpq/lldpq/devices.yaml.example)')
        self.assertIn('✓ devices.yaml loaded (0 devices)\n' + hint + '\n', setup)
        self.assertIn('`devices: {}`', setup)
        dockerfile = read('docker/Dockerfile')
        self.assertIn('mv devices.yaml devices.yaml.example', dockerfile)
        self.assertIn("print \"devices: {}\"", dockerfile)
        self.assertIn('`sudo docker exec lldpq cat /home/lldpq/lldpq/devices.yaml.example`', setup)
        # Until the first device is added: the pipeline ends with one line,
        # before it marks the reports, logs a failure or starts a stage.
        prose = flat(setup)
        pipeline = read('bin/lldpq')
        printed = ('No devices in $LLDPQ_DIR/devices.yaml yet, so nothing was collected. '
                   'Add them under Assets → Edit Devices or in that file.')
        early_exit = pipeline.index(f'    echo "{printed}"\n    exit 0\n')
        for later in ('write_pipeline_report_marker collecting pipeline_collection_in_progress',
                      'mark_pipeline_reports_stale "asset discovery failed before monitoring"',
                      'run_command ./assets.sh'):
            self.assertLess(early_exit, pipeline.index(later))
        self.assertIn('>> "$LLDPQ_DIR/monitor-failures.log"', pipeline)
        self.assertIn("'LLDPQ_DIR=/home/lldpq/lldpq'", dockerfile)
        self.assertIn('\n' + printed.replace('$LLDPQ_DIR', '/home/lldpq/lldpq') + '\n', setup)
        self.assertIn('A scheduled run (every 10 minutes by default) ends at once: it does not '
                      'mark the reports stale and writes nothing to '
                      '`/home/lldpq/lldpq/monitor-failures.log`.', prose)
        self.assertIn('LLDPQ_CRON="${LLDPQ_CRON:-*/10 * * * *}"', ENTRYPOINT)
        self.assertIn('/usr/local/bin/lldpq - >> ', read('html/setup-api.sh'))
        self.assertIn('Run by hand or from **Setup → Run LLDPq**, `lldpq` prints one line and '
                      'exits with status 0:', prose)
        # Only an empty mapping is that case, and only for the pipeline: the
        # stages a page starts load the inventory themselves and fail on it.
        self.assertIn('isinstance(config.get("devices"), dict) and not devices', pipeline)
        self.assertIn('This applies only while `devices:` is a mapping without devices', prose)
        self.assertIn('echo "ERROR: No devices found" >&2\n        return 1\n',
                      read('lldpq/load_devices.sh'))
        for label, page, stage in (('Run Analysis', 'html/transceiver.html', 'lldpq/monitor.sh'),
                                   ('Refresh Assets', 'html/assets.html', 'lldpq/assets.sh'),
                                   ('Run LLDP Check', 'html/lldp.html', 'lldpq/check-lldp.sh')):
            self.assertIn(label, read(page))
            self.assertRegex(read(stage),
                             r'(?m)^load_devices "\$SCRIPT_DIR/parse_devices\.py".* \|\| exit 1$')
            self.assertIn(f'**{label}**', prose)
        self.assertIn('without devices it still ends as failed', prose)
        # Backup & Restore: the export leaves the empty inventory out; saving
        # one, or restoring a bundle that carries one, is refused.
        api = read('html/setup-api.sh')
        left_out = 'devices.yaml was left out of the bundle: it has no devices.'
        self.assertIn(f"left_out.append('{left_out}')\n                        continue\n", api)
        self.assertIn("'warnings': left_out,", api)
        self.assertIn(f'leaves `devices.yaml` out of the bundle while it has no devices (its '
                      f'reply lists `{left_out}` under `warnings`)', prose)
        refused = "devices.yaml must contain a non-empty 'devices' mapping"
        self.assertIn(refused, read('lldpq/backup_import.py'))
        self.assertIn(refused, read('html/setup_safety.py'))
        self.assertIn('Saving an inventory without devices, and restoring a bundle that carries '
                      f'one, are refused with `{refused}`.', prose)

    def test_https_listener(self):
        https = section(DOCKER_DOC, '\n## HTTPS\n', '\n## DHCP/ONIE provisioning\n')
        prose = flat(https)
        self.assertIn('- [HTTPS](#https)\n', DOCKER_DOC)
        # How to turn it on, in the three documented deployment forms.
        self.assertIn('Set `LLDPQ_HTTPS_PORT` to a TCP port (1-65535, not 80)', prose)
        self.assertIn('"the value is not a usable TCP port (1-65535, and not 80)"', ENTRYPOINT)
        compose = read('docker/docker-compose.yml')
        for commented in ('      # - LLDPQ_HTTPS_PORT=8443\n', '      # - "8443:8443"\n',
                          '      # - ./tls:/etc/lldpq-tls:ro\n'):
            self.assertIn(commented, compose)
            self.assertIn('`' + commented.strip()[2:] + '`', prose)
        self.assertIn('      # LLDPQ_HTTPS_PORT: "8443"\n',
                      read('docker/docker-compose.provisioning.yml'))
        self.assertIn('`LLDPQ_HTTPS_PORT: "8443"`', prose)
        self.assertIn('`-e LLDPQ_HTTPS_PORT=8443`', prose)
        self.assertIn('`-p 8443:8443`', prose)
        # Port 80 stays.
        self.assertIn('Port 80 stays plain HTTP and is not redirected', prose)
        self.assertIn('echo "  ✓ nginx (port 80)"', ENTRYPOINT)
        # Certificate paths.
        self.assertIn('HTTPS_SUPPLIED_DIR=/etc/lldpq-tls\n', ENTRYPOINT)
        self.assertIn('cert="$HTTPS_SUPPLIED_DIR/tls.crt"', ENTRYPOINT)
        self.assertIn('key="$HTTPS_SUPPLIED_DIR/tls.key"', ENTRYPOINT)
        self.assertIn('Mount a directory that holds `tls.crt` (PEM; the chain may follow the '
                      'certificate) and `tls.key` (PEM, no passphrase) at `/etc/lldpq-tls`', prose)
        self.assertIn('SYSTEM_CONFIG_DIR="${LLDPQ_SYSTEM_CONFIG_DIR:-/home/lldpq/lldpq/'
                      'system-config}"', ENTRYPOINT)
        self.assertIn('HTTPS_GENERATED_DIR="$SYSTEM_CONFIG_DIR/tls"', ENTRYPOINT)
        self.assertIn('cert="$HTTPS_GENERATED_DIR/lldpq.crt"', ENTRYPOINT)
        self.assertIn('`/home/lldpq/lldpq/system-config/tls/lldpq.crt` and `lldpq.key` '
                      '(RSA 2048, valid 825 days', prose)
        self.assertIn('-newkey rsa:2048 -nodes -sha256 -days 825', ENTRYPOINT)
        # The two lines under the ready message.
        self.assertIn('kind="self-signed certificate $cert"', ENTRYPOINT)
        self.assertIn(self.quoted('HTTPS: container port $port, $kind', port='8443',
                                  kind='self-signed certificate /home/lldpq/lldpq/'
                                       'system-config/tls/lldpq.crt') + '\n', https)
        reason = self.quoted('TCP port $port is already in use', port='8443')
        self.assertIn(self.quoted('⚠ HTTPS not enabled (LLDPQ_HTTPS_PORT=$LLDPQ_HTTPS_PORT): $1; '
                                  'the web UI is served over HTTP only',
                                  LLDPQ_HTTPS_PORT='8443', **{'1': reason}) + '\n', https)
        # The control-plane ACL has to permit that port, said where the rule is set.
        acl = flat(section(DOCKER_DOC, 'Direct access then needs the control-plane ACL',
                           'Where HTTP is blocked, tunnel to that port'))
        self.assertIn('the rule has to permit that port instead of, or besides, 80', acl)
        self.assertIn('the control-plane ACL has to permit it', prose)

    def test_recreated_management_vrf(self):
        note = flat(MGMT_VRF)
        for template in ('CRITICAL: the $LLDPQ_MGMT_VRF VRF was re-created',
                         'CRITICAL: the $LLDPQ_MGMT_VRF VRF device the services were started in'):
            self.assertIn('`' + self.quoted(template, LLDPQ_MGMT_VRF='mgmt') + '`', note)
        self.assertIn('Restart the container: docker restart lldpq" >&2', ENTRYPOINT)
        self.assertIn('`sudo docker logs lldpq 2>&1 | grep CRITICAL`', note)
        self.assertIn('The container does not restart by itself', note)

    def test_release_check_and_checksum(self):
        building = section(DOCKER_DOC, '\n## Building and checking an image\n',
                           '\n## Streaming telemetry\n')
        self.assertIn('- [Building and checking an image](#building-and-checking-an-image)\n',
                      DOCKER_DOC)
        self.assertTrue((ROOT / 'docker/test-mgmt-vrf-switch.sh').is_file())
        check = read('docker/test-mgmt-vrf-switch.sh')
        self.assertIn('\nsudo bash docker/test-mgmt-vrf-switch.sh\n', building)
        self.assertIn('IMAGE="${1:-${IMAGE:-lldpq:latest}}"', check)
        self.assertIn('`IMAGE=<tag>` chooses another image than `lldpq:latest`', building)
        self.assertIn('--privileged --restart no --network host', check)
        self.assertIn("printf '\\n%d checks, %d failed\\n'", check)
        self.assertIn('`<n> checks, <m> failed`', flat(building))
        self.assertIn('# Exit status: 0 every check passed, 1 a check failed, 2 cannot run here.',
                      check)
        build = read('docker/docker-build.sh')
        self.assertIn('\n./docker/docker-build.sh\n', building)
        self.assertIn('OUTPUT_FILE="$HOME/lldpq-${ARCH_LABEL}.tar.gz"', build)
        self.assertIn('CHECKSUM_FILE="${OUTPUT_FILE}.sha256"', build)
        self.assertIn('`~/lldpq-<arch>.tar.gz` and\n`~/lldpq-<arch>.tar.gz.sha256`', building)
        self.assertIn('SHA-256 not written', build)
        self.assertIn('`SHA-256 not written`', building)
        quick_start = section(DOCKER_DOC, '\n## Quick start\n', '\n### On a Linux server\n')
        self.assertIn('\nsha256sum -c lldpq-amd64.tar.gz.sha256 ', quick_start)
        self.assertIn('`shasum -a 256 -c lldpq-amd64.tar.gz.sha256`', quick_start)


class ReadmeMatchesTheCodeTests(unittest.TestCase):
    def test_login_protected_directories(self):
        auth = section(README, '\n### login-protected paths:\n', '\n### login attempt limit:\n')
        self.assertIn('Every path under `/configs/`, `/hstr/` and `/monitor-results/`', auth)
        for directory in ('configs', 'hstr', 'monitor-results'):
            block = section(SITE, f'location ^~ /{directory}/ {{', '\n        }\n')
            self.assertIn('auth_request /lldpq-session-gate;', block)
        self.assertIn('error_page 401', SITE)
        self.assertIn('HTTP 401 with the login page as its\nbody', auth)
        self.assertIn('SameSite=Strict', read('html/auth-api.sh'))
        self.assertIn('(`SameSite=Strict`)', auth)
        exports = section(README, '## [02j]', '### Discover available exports')
        self.assertIn('Everything under `/configs/`,\n`/hstr/` and `/monitor-results/` '
                      'needs a login', exports)

    def test_login_attempt_limit_values(self):
        limit = section(README, '\n### login attempt limit:\n',
                        '\n### user management (admin only):\n')
        for zone, scope in (('lldpq_login_client', 'per client address (IPv4 or IPv6)'),
                            ('lldpq_login_all', 'all addresses together')):
            rate = int(re.search(rf'zone={zone}:\S+ rate=(\d+)r/m;', SITE).group(1))
            burst = int(re.search(rf'limit_req zone={zone} burst=(\d+) nodelay;', SITE).group(1))
            self.assertIn(f'| {scope} | {burst + 1} attempts in a row | '
                          f'1 every {60 // rate} seconds |\n', limit)
            self.assertIn(f'"{zone}"', limit)
        body = '{"success": false, "error": "Too many login attempts. Wait a few seconds and try again."}'
        self.assertIn(f"return 429 '{body}';", SITE)
        self.assertIn(f'`{body}`', limit)
        self.assertIn('add_header Retry-After 10 always;', SITE)
        self.assertIn('HTTP 429 with\n`Retry-After: 10`', limit)

    def test_password_change_ends_the_other_sessions(self):
        change = section(README, '\n### change passwords:\n', '\n## [11] alerts & notifications\n')
        self.assertIn('Changing a password ends every other session of that user at once; only '
                      'the\nsession that made the change stays logged in.', change)
        first_time = section(DOCKER_DOC, '\n## First-time setup\n', '\n## HTTPS\n')
        self.assertIn("Changing a password ends that user's other sessions", first_time)

    def test_ztp_password_hash(self):
        ztp = section(README, '\n### ZTP Tab\n', '\n### Upgrade Tab\n')
        api = read('html/provision-api.sh')
        page = read('html/provision.html')
        self.assertIn("echo 'cumulus:$6$<salt>$<hash>' | chpasswd -e\n", ztp)
        self.assertIn('''return "%secho 'cumulus:%s' | chpasswd -e" % (''', api)
        self.assertIn("'openssl', 'passwd', '-6'", api)
        self.assertIn('`openssl passwd -6`', ztp)
        self.assertIn('max 128 characters', api)
        self.assertIn('at most 128 characters', ztp)
        self.assertIn("'error': f'ZTP script was not saved: {exc}'", api)
        self.assertIn('`ZTP script was not saved:`', ztp)
        self.assertIn('(stored as a hash, it cannot be shown)', page)
        self.assertIn('Password is set in clear text.', page)
        self.assertIn('`stored as a hash`, still `in clear text`', ztp)
        self.assertIn('one literal cumulus password is required', api)
        self.assertIn('`one literal cumulus password is required`', ztp)
        update =section(README, '\n### after updating from 4.2.x or earlier\n', '\n## [06]')
        self.assertIn('press **Save** once', update)

    def test_telemetry_pending_change_stop(self):
        enable = section(README, '\n### enable on switches\n', '\n### dashboard features\n')
        api = read('html/fabric-api.sh')
        message = ('Pending un-applied NVUE changes on this switch, nothing was changed. '
                   "Review them with 'nv config diff', then apply or 'nv config detach' them "
                   'and retry.')
        # The API builds the sentence from three adjacent string literals.
        pieces = re.search(r'"echo \\"(Pending un-applied[^"]*)"\s*"([^"]*)"\s*"(and retry\.)\\"',
                           api)
        self.assertIsNotNone(pieces)
        self.assertEqual(''.join(pieces.groups()), message)
        self.assertIn('\nFailed: ' + message + '\n', enable)
        self.assertIn("'{ rc=$?; nv config detach >/dev/null 2>&1; exit $rc; }'", api)
        self.assertIn('LLDPq runs `nv config detach` in the same session', enable)
        self.assertIn('timeout=120', api)
        self.assertIn('120-second timeout', enable)
        docker_telemetry = section(DOCKER_DOC, '\n## Streaming telemetry\n',
                                   '\n## Removing LLDPq completely\n')
        self.assertIn('`Failed: Pending un-applied NVUE changes`', docker_telemetry)
        self.assertIn('[enable on switches](README.md#enable-on-switches)', docker_telemetry)

    def test_pping_vrf(self):
        tools = section(README, '\n## [09] cli tools\n', '\n```bash\n# parallel ping\n')
        pping = read('bin/pping')
        printed = ("Error: cannot ping in VRF '$vrf_name': no 'vrf' command, and "
                   "'ip vrf exec $vrf_name' failed (unknown VRF, or root is needed)")
        self.assertIn(printed, pping)
        self.assertIn('`' + printed.replace('$vrf_name', '<vrf>') + '`', tools)
        self.assertIn('vrf_ping="sudo -n ip vrf exec $vrf_name timeout $timeout ping"', pping)
        self.assertIn('`sudo -n`', tools)
        self.assertIn('`-v mgmt` is not needed there', tools)
        self.assertIn('(`pping` needs no `-v mgmt` here)', MGMT_VRF)

    def test_docker_storage_driver_of_the_native_installer(self):
        telemetry = section(README, '\n### installation options\n', '\n### workflow\n')
        install = read('install.sh')
        self.assertEqual(install.count(
            'if [[ ! -f /etc/docker/daemon.json ]] && [[ "$_docker_installed_now" == "true" ]]; then'),
            2)
        printed = ('[!] Docker was already installed: /etc/docker/daemon.json and the Docker '
                   'service are left unchanged.')
        self.assertEqual(install.count(printed), 2)
        self.assertIn('`' + printed + ' ...`', telemetry)
        self.assertIn('Configuring Docker storage driver...', install)
        self.assertIn('(`Configuring Docker storage driver...`)', telemetry)
        self.assertIn('`{"storage-driver": "vfs"}`', telemetry)
        self.assertIn('`--disable-telemetry` does not touch the file.', telemetry)

    def test_ask_ai_masking_and_command_rules(self):
        self.assertIn('***REDACTED***', read('html/ai-api.sh'))
        handling = section(README, '> **Data handling:**', 'The autonomous analyzer is triggered')
        self.assertIn('are replaced\n> by `***REDACTED***`', handling)
        self.assertIn('masked\n> for every provider, Ollama included', handling)
        contract = section(README, '### AI JSON special contract', '### Ordered row columns')
        self.assertIn('`analysis.json` is written masked for every provider', contract)
        self.assertIn('x-goog-api-key', read('html/ai-api.sh'))
        self.assertIn('`x-goog-api-key` request header', README)
        security = flat(section(README, '\n### security\n', '> **Authorization:**'))
        policy = read('html/ai_command_policy.py')
        for word in ('mlxlink', 'onie-install', 'reboot', 'shutdown', 'ztp'):
            self.assertIn(rf'r"\b{word}\b"', policy)
            self.assertIn(f'`{word}`', security)
        self.assertIn(r'r"\bnv\s+config\s+(apply|replace|save|delete|patch|edit|detach|history)\b"',
                      policy)
        self.assertIn('`nv config apply|replace|save|delete|patch|edit|detach|history`', security)
        self.assertIn('"--show-fec"', policy)
        self.assertIn('`ethtool --show-fec <port>`', security)
        self.assertIn("'Command is not allowed from Device Details'", read('html/fabric-api.sh'))
        self.assertIn('`Command is not allowed from Device Details`', security)

    def test_discovery_range_fallback(self):
        discover = section(README, '\n### Discover Tab\n', '\n### Post-Provision Automation\n')
        refused = 'No discovery range configured. Set it in DHCP Server Configuration.'
        self.assertIn(f'raise ValueError("{refused}")', read('html/provision-api.sh'))
        self.assertIn(f'`{refused}`', discover)
        self.assertIn('that is not commented out', discover)


if __name__ == '__main__':
    unittest.main()
