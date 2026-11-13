"""The update, migration and clean-up scripts printed in DOCKER.md, run for real.

Operators copy these blocks from the guide to the Docker host, often a Cumulus
switch.  An image from before 4.2.5 adds a routing rule to such a switch at
every start, so what the scripts do when a replacement fails matters: they
bring that image back.  The blocks are cut out of the guide and run with
stand-in sudo, docker, ip, sleep and date commands; nothing here needs Docker,
Linux or root.

Covered:
  * the Compose update always reports that the previous image was restored,
    also when the restored image does not come up either;
  * both scripts print one WARNING line when the unscoped pref-100 rule of the
    management VRF is on the host after a rollback, and the check cannot trip
    `set -Eeuo pipefail` or the ERR trap; a longer pref-100 line is not that
    rule, and the migration waits before it looks;
  * an archive that holds the image already running: the Compose update stops
    and removes its rollback tag, the migration only warns;
  * the migration refuses to move a host-network container of a switch to a
    bridge network, and only that;
  * a failed migration does not start a container that was already stopped
    before it ran, and still restarts one that was running;
  * the rollback after a verified migration changes nothing when its stamp
    names no retained container or image;
  * the clean-up after the migration removes the stopped pre-upgrade container
    and its volumes, never the live container;
  * the follow-up blocks work in a new shell (the scripts are run from a file
    and their variables end with them), and the ACL commands use the rule ID
    the operator chose.
"""

from pathlib import Path
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKER_DOC = (ROOT / 'DOCKER.md').read_text()

STAMP = '20260708-120000'
OLD_IMAGE = 'sha256:' + 'a' * 64
NEW_IMAGE = 'sha256:' + 'b' * 64
RESTORED = 'Replacement failed; the previous image was restored.'
RULE_WARNING = ("WARNING: the routing rule '100: from all lookup mgmt' is on this host. "
                'Images before 4.2.5 add it at every start: see Management VRF in DOCKER.md '
                'before leaving the restored container running.')


def bash_blocks(text):
    """Every fenced bash block, those inside a blockquote included."""
    blocks = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        opening = re.match(r'^(> ?)?```bash\s*$', lines[index])
        index += 1
        if not opening:
            continue
        quoted = bool(opening.group(1))
        body = []
        while index < len(lines) and not re.match(r'^(> ?)?```\s*$', lines[index]):
            line = lines[index]
            if quoted:
                line = re.sub(r'^> ?', '', line)
            body.append(line)
            index += 1
        blocks.append('\n'.join(body) + '\n')
    return blocks


BLOCKS = bash_blocks(DOCKER_DOC)


def block_with(*markers):
    found = [block for block in BLOCKS if all(marker in block for marker in markers)]
    assert len(found) == 1, (markers, len(found))
    return found[0]


COMPOSE_UPDATE = block_with('compose_file=docker/docker-compose.yml', 'set -Eeuo pipefail')
COMPOSE_ROLLBACK = block_with("rollback_image='lldpq:pre-upgrade-<timestamp>'")
MIGRATION = block_with('LLDPQ_MIGRATION_OPTIONS_CONFIRMED', 'set -Eeuo pipefail')
MIGRATION_ROLLBACK = block_with('failed_container=')
CLEANUP_LOOK = block_with('old_volumes=$(')
CLEANUP_REMOVE = block_with('kept (still in use)')

# The stand-ins answer from a state directory and record every docker call
# (its first line: the readiness probe passes a multi-line script). The same
# record holds each sleep and each listing of the routing rules, in order.
STAND_INS = {
    'sudo': '#!/bin/bash\nexec "$@"\n',
    'sleep': '#!/bin/bash\nprintf \'sleep %s\\n\' "$*" >> "$STUB_STATE/calls"\nexit 0\n',
    'date': f'#!/bin/bash\necho {STAMP}\n',
    'nv': '#!/bin/bash\nprintf \'nv %s\\n\' "$*" >> "$STUB_STATE/nv-calls"\n',
    'ip': r'''#!/bin/bash
state="$STUB_STATE"
[ ! -e "$state/no-ip" ] || exit 127
case "$*" in
    'vrf show mgmt')
        if [ -e "$state/mgmt-table" ]; then
            echo "mgmt $(cat "$state/mgmt-table")"
        else
            echo 'Invalid VRF' >&2
            exit 1
        fi ;;
    '-4 rule show')
        echo 'ip -4 rule show' >> "$state/calls"
        printf '0:\tfrom all lookup local\n'
        [ ! -e "$state/rules" ] || cat "$state/rules"
        printf '1000:\tfrom all lookup [l3mdev-table]\n'
        printf '32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n' ;;
esac
''',
    'docker': r'''#!/bin/bash
state="$STUB_STATE"
printf 'docker %s\n' "$*" | head -n 1 >> "$state/calls"
has() { grep -qx -- "$1" "$state/containers" 2>/dev/null; }
drop() { grep -vx -- "$1" "$state/containers" > "$state/containers.new"
         mv "$state/containers.new" "$state/containers"; }
current() { cat "$state/current-image" 2>/dev/null; }
last="${@: -1}"
case "$1" in
    compose)
        case " $* " in
            *' up '*)
                if [ "$(current)" = old ]; then exit "${STUB_UP_OLD_RC:-0}"; fi
                exit "${STUB_UP_NEW_RC:-0}" ;;
        esac ;;
    load)
        cat > /dev/null
        echo new > "$state/current-image" ;;
    image)
        case "$2" in
            tag)
                if [ "$3" = "${STUB_MISSING_IMAGE:-}" ]; then
                    echo "Error response from daemon: No such image: $3" >&2
                    exit 1
                fi
                case "$3 $4" in
                    lldpq:pre-*' lldpq:latest') echo old > "$state/current-image" ;;
                esac ;;
            inspect)
                case "$*" in
                    *'{{.Id}}'*)
                        if [ "$(current)" = old ]; then echo "$STUB_OLD_IMAGE"
                        else echo "$STUB_NEW_IMAGE"; fi ;;
                esac ;;
        esac ;;
    container) has "$last"; exit ;;
    inspect)
        case "$*" in
            *'{{.Image}}'*) echo "$STUB_OLD_IMAGE" ;;
            *'{{.HostConfig.NetworkMode}}'*) echo "${STUB_OLD_NETWORK:-default}" ;;
            *'{{.State.Running}}'*)
                if grep -qx -- "$last" "$state/stopped" 2>/dev/null; then echo false
                else echo true; fi ;;
            *'{{range .Mounts}}'*)
                has "$last" || { echo "Error: No such object: $last" >&2; exit 1; }
                [ ! -e "$state/volumes-of-$last" ] || cat "$state/volumes-of-$last" ;;
            *) echo '[{}]' ;;
        esac ;;
    exec)
        if [ "$(current)" = old ]; then exit "${STUB_READY_OLD_RC:-0}"; fi
        exit "${STUB_READY_NEW_RC:-0}" ;;
    rename) drop "$2"; echo "$3" >> "$state/containers" ;;
    start)
        if [ -e "$state/stopped" ]; then
            grep -vx -- "$2" "$state/stopped" > "$state/stopped.new"
            mv "$state/stopped.new" "$state/stopped"
        fi ;;
    create) echo lldpq >> "$state/containers" ;;
    rm)
        shift
        force=no
        [ "$1" != -f ] || { force=yes; shift; }
        for name in "$@"; do
            if [ "$force" = no ] && grep -qx -- "$name" "$state/running" 2>/dev/null; then
                echo "Error response from daemon: cannot remove container $name: container is running" >&2
                exit 1
            fi
            drop "$name"
        done ;;
    cp)
        [ "${STUB_CP_RC:-0}" = 0 ] || exit "$STUB_CP_RC"
        case "$last" in
            *:*) ;;
            */) mkdir -p "$last" ;;
            *) [ -d "$last" ] || echo copied > "$last" ;;
        esac ;;
    volume)
        shift 2
        rc=0
        for name in "$@"; do
            case " ${STUB_VOLUMES_IN_USE:-} " in
                *" $name "*)
                    echo "Error response from daemon: remove $name: volume is in use" >&2
                    rc=1 ;;
                *) echo "$name" >> "$state/removed-volumes" ;;
            esac
        done
        exit "$rc" ;;
esac
exit 0
''',
}


class ScriptCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-docs-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / 'bin'
        self.state = self.root / 'state'
        self.home = self.root / 'home'
        self.work = self.root / 'work'
        for directory in (self.bin, self.state, self.home, self.work):
            directory.mkdir()
        for name, body in STAND_INS.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        (self.state / 'containers').write_text('lldpq\n')
        # A real archive: the scripts read its manifest with the real tar.
        manifest = b'[{"Config":"config.json","RepoTags":["lldpq:latest"],"Layers":[]}]'
        with tarfile.open(self.work / 'lldpq-amd64.tar.gz', 'w:gz') as archive:
            member = tarfile.TarInfo('manifest.json')
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))

    def switch(self, table='1001', rule=None):
        """This host has a VRF named mgmt, and optionally a pref-100 rule line."""
        (self.state / 'mgmt-table').write_text(table + '\n')
        if rule is not None:
            (self.state / 'rules').write_text(rule + '\n')

    def run_script(self, source, **env):
        script = self.work / 'script.sh'
        script.write_text(source)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('STUB_', 'LLDPQ_', 'DHCP_', 'PROVISION_'))}
        environment.update(
            PATH=f"{self.bin}{os.pathsep}{environment['PATH']}",
            HOME=str(self.home), STUB_STATE=str(self.state),
            STUB_OLD_IMAGE=OLD_IMAGE, STUB_NEW_IMAGE=NEW_IMAGE)
        environment.update(env)
        calls = self.state / 'calls'
        if calls.exists():
            calls.unlink()
        return subprocess.run([shutil.which('bash'), str(script)], capture_output=True,
                              text=True, timeout=60, env=environment, cwd=self.work)

    def timeline(self):
        """Every recorded call in order: docker, sleep and the rule listing."""
        log = self.state / 'calls'
        return log.read_text().splitlines() if log.exists() else []

    def calls(self):
        return [call for call in self.timeline() if call.startswith('docker ')]

    def called(self, pattern):
        return [call for call in self.calls() if re.search(pattern, call)]

    def warnings(self, result):
        return [line for line in result.stderr.splitlines() if line.startswith('WARNING')]


class ComposeUpdateTests(ScriptCase):
    ROLLBACK_TAG = f'lldpq:pre-upgrade-{STAMP}'

    def test_successful_update_keeps_the_rollback_tag(self):
        # The rule may still be on the switch at this point; a success is not
        # a rollback and the new image removes it.
        self.switch(rule='100:\tfrom all lookup mgmt')
        result = self.run_script(COMPOSE_UPDATE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         f'Readiness verified; rollback image retained as {self.ROLLBACK_TAG}\n')
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.called(r'^docker image tag '),
                         [f'docker image tag {OLD_IMAGE} {self.ROLLBACK_TAG}'])
        self.assertEqual(len(self.called(r' up -d --no-build --force-recreate$')), 1)
        self.assertEqual(self.called(r'^docker image rm'), [])

    def test_failed_replacement_always_says_what_was_restored(self):
        cases = {
            'the new image is not ready, the previous one is':
                (dict(STUB_READY_NEW_RC='1'), []),
            'neither image becomes ready':
                (dict(STUB_READY_NEW_RC='1', STUB_READY_OLD_RC='1'),
                 ['The previous image is not ready either.']),
            'the service cannot be recreated at all':
                (dict(STUB_UP_NEW_RC='1', STUB_UP_OLD_RC='1', STUB_READY_OLD_RC='1'),
                 ['Recreating the service from the previous image failed.',
                  'The previous image is not ready either.']),
        }
        for name, (env, extra) in cases.items():
            with self.subTest(name):
                result = self.run_script(COMPOSE_UPDATE, **env)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr.splitlines(), extra + [RESTORED])
                # The previous image was put back under lldpq:latest and started.
                tagged = self.calls().index(
                    f'docker image tag {self.ROLLBACK_TAG} lldpq:latest')
                self.assertEqual(len([call for call in self.calls()[tagged:]
                                      if call.endswith(' up -d --no-build --force-recreate')]), 1)

    def test_rollback_warns_when_the_mgmt_rule_is_on_the_host(self):
        for rule in ('100:\tfrom all lookup mgmt',
                     '100:\tfrom all lookup mgmt ',
                     '100:\tfrom all lookup 1001',      # host without a name for the table
                     '100:    from all lookup 1001  '):
            with self.subTest(rule=rule):
                self.switch(rule=rule)
                result = self.run_script(COMPOSE_UPDATE, STUB_READY_NEW_RC='1')
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.splitlines(), [RESTORED, RULE_WARNING])

    def test_rollback_without_that_rule_prints_no_warning(self):
        cases = {
            'a switch without the rule': dict(table='1001'),
            'pref 100 points at another table': dict(table='1001',
                                                     rule='100:\tfrom all lookup 254'),
            'the rule has another preference': dict(table='1001',
                                                    rule='1100:\tfrom all lookup mgmt'),
            'the rule is scoped': dict(table='1001',
                                       rule='100:\tfrom 192.0.2.1 lookup mgmt'),
            # The pattern ends at the end of the line: a table whose name or
            # number only begins like the VRF's, or a longer rule, is another rule.
            'the table name only begins with mgmt': dict(
                table='1001', rule='100:\tfrom all lookup mgmt2'),
            'the table number only begins with the VRF table': dict(
                table='1001', rule='100:\tfrom all lookup 10010'),
            'the rule goes on after the table': dict(
                table='1001', rule='100:\tfrom all lookup mgmt suppress_prefixlength 0'),
        }
        for name, host in cases.items():
            with self.subTest(name):
                self.switch(**host)
                result = self.run_script(COMPOSE_UPDATE, STUB_READY_NEW_RC='1')
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.splitlines(), [RESTORED])
        with self.subTest('a host without a mgmt VRF'):
            (self.state / 'mgmt-table').unlink()
            (self.state / 'rules').write_text('100:\tfrom all lookup mgmt\n')
            result = self.run_script(COMPOSE_UPDATE, STUB_READY_NEW_RC='1')
            self.assertEqual(result.stderr.splitlines(), [RESTORED])
        with self.subTest('a host without the ip command'):
            (self.state / 'no-ip').touch()
            result = self.run_script(COMPOSE_UPDATE, STUB_READY_NEW_RC='1')
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr.splitlines(), [RESTORED])

    def test_rule_check_does_not_trip_strict_mode_or_an_err_trap(self):
        function = re.search(r'(?ms)^warn_mgmt_rule\(\) \{\n.*?^\}\n', COMPOSE_UPDATE)
        self.assertIsNotNone(function)
        # Both scripts carry the same function.
        self.assertIn(function.group(0), MIGRATION)
        source = ("set -Eeuo pipefail\ntrap 'echo ERR-TRAP' ERR\n"
                  f'{function.group(0)}warn_mgmt_rule\necho CONTINUED\n')
        hosts = {
            'no VRF': lambda: None,
            'VRF without the rule': lambda: self.switch(),
            'VRF with the rule': lambda: self.switch(rule='100:\tfrom all lookup mgmt'),
            'no ip command': lambda: (self.state / 'no-ip').touch(),
        }
        for name, prepare in hosts.items():
            with self.subTest(name):
                prepare()
                result = self.run_script(source)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'CONTINUED\n')
                self.assertEqual(result.stderr,
                                 RULE_WARNING + '\n' if name == 'VRF with the rule' else '')

    def test_archive_with_the_running_image_stops_and_drops_the_rollback_tag(self):
        result = self.run_script(COMPOSE_UPDATE, STUB_NEW_IMAGE=OLD_IMAGE)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertEqual(
            result.stderr,
            'The archive holds the image that lldpq already runs; nothing was replaced.\n')
        self.assertEqual(self.called(r'^docker image rm'),
                         [f'docker image rm {self.ROLLBACK_TAG}'])
        self.assertEqual(self.called(r' up '), [])
        self.assertEqual(self.called(r'^docker exec'), [])

    def test_later_rollback_is_a_script_of_its_own(self):
        # The guide: keep the saved file up to and including warn_mgmt_rule,
        # then the rollback lines with the printed tag.
        head = COMPOSE_UPDATE[:COMPOSE_UPDATE.index('"${compose[@]}" config >/dev/null')]
        self.assertTrue(head.rstrip().endswith('}'))
        self.assertIn('warn_mgmt_rule() {', head)
        rollback = COMPOSE_ROLLBACK.replace('<timestamp>', '20260101-000000')
        self.switch(rule='100:\tfrom all lookup mgmt')
        result = self.run_script(head + rollback)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, RULE_WARNING + '\n')
        self.assertEqual(self.calls()[0],
                         'docker image tag lldpq:pre-upgrade-20260101-000000 lldpq:latest')
        self.assertEqual(len(self.called(r' up -d --no-build --force-recreate$')), 1)
        self.assertEqual(len(self.called(r'^docker exec lldpq sh -c')), 1)


class MigrationTests(ScriptCase):
    OLD = f'lldpq-pre-upgrade-{STAMP}'
    CONFIRMED = dict(LLDPQ_MIGRATION_OPTIONS_CONFIRMED='true')
    HOST_NETWORK_STOP = (
        'Running container unchanged. It uses host networking on a host with a mgmt VRF '
        '(a Cumulus switch), and extra_args does not: replace the -p line in extra_args '
        'with --network host and -e CONSOLE_PTY_PORT=18765, then rerun.\n')

    def with_extra_args(self, *lines):
        """The script as an operator edits it: the -p line replaced."""
        self.assertEqual(MIGRATION.count('  -p 0.0.0.0:8080:80\n'), 1)
        return MIGRATION.replace('  -p 0.0.0.0:8080:80\n',
                                 ''.join(f'  {line}\n' for line in lines))

    def assert_untouched(self):
        self.assertEqual(self.called(r'^docker (load|stop|start|rename|create|rm|image tag)'), [])
        self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')

    def assert_migrated(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'Upgrade verified. Rollback container retained as: {self.OLD}\n',
                      result.stdout)
        self.assertEqual(sorted((self.state / 'containers').read_text().split()),
                         ['lldpq', self.OLD])

    def test_first_pass_only_inspects(self):
        result = self.run_script(MIGRATION)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(result.stderr.startswith('Running container unchanged. Review '),
                        result.stderr)
        self.assert_untouched()

    def test_confirmed_migration_prints_what_the_later_steps_need(self):
        result = self.run_script(MIGRATION, **self.CONFIRMED)
        self.assert_migrated(result)
        self.assertEqual(result.stderr, '')
        self.assertIn(f'Rollback image retained as: lldpq:pre-migration-{STAMP}\n',
                      result.stdout)
        self.assertTrue(result.stdout.endswith(f'container=lldpq stamp={STAMP}\n'),
                        result.stdout)
        # The removal section's script deletes the live container and every
        # volume; the migration must not send the operator there.
        self.assertNotIn('removal section', MIGRATION)
        self.assertNotIn('Removing LLDPq completely', result.stdout)

    def test_switch_container_is_not_moved_to_a_bridge_network(self):
        self.switch()
        for name, env in (('first pass', {}), ('confirmed', self.CONFIRMED)):
            with self.subTest(name):
                result = self.run_script(MIGRATION, STUB_OLD_NETWORK='host', **env)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout.count('Upgrade verified'), 0)
                self.assertEqual(result.stderr, self.HOST_NETWORK_STOP)
                self.assert_untouched()

    def test_host_network_stop_is_limited_to_exactly_that_case(self):
        with self.subTest('host networking requested in extra_args'):
            self.switch()
            for option in ('--network host', '--network=host', '--net=host', '--net host'):
                with self.subTest(option=option):
                    (self.state / 'containers').write_text('lldpq\n')
                    result = self.run_script(
                        self.with_extra_args(option, '-e CONSOLE_PTY_PORT=18765'),
                        STUB_OLD_NETWORK='host', **self.CONFIRMED)
                    self.assert_migrated(result)
                    created = self.called(r'^docker create ')
                    self.assertEqual(len(created), 1)
                    self.assertIn(f' {option} -e CONSOLE_PTY_PORT=18765 ', created[0])
                    self.assertNotIn(' -p ', created[0])
        with self.subTest('the old container used a bridge network on a switch'):
            (self.state / 'containers').write_text('lldpq\n')
            result = self.run_script(MIGRATION, STUB_OLD_NETWORK='default', **self.CONFIRMED)
            self.assert_migrated(result)
        with self.subTest('a Linux server: host networking, no mgmt VRF'):
            (self.state / 'containers').write_text('lldpq\n')
            (self.state / 'mgmt-table').unlink()
            result = self.run_script(MIGRATION, STUB_OLD_NETWORK='host', **self.CONFIRMED)
            self.assert_migrated(result)
            self.assertIn(' -p 0.0.0.0:8080:80 ', self.called(r'^docker create ')[0])
        with self.subTest('a host without the ip command'):
            (self.state / 'containers').write_text('lldpq\n')
            (self.state / 'no-ip').touch()
            result = self.run_script(MIGRATION, STUB_OLD_NETWORK='host', **self.CONFIRMED)
            self.assert_migrated(result)

    def test_archive_with_the_running_image_is_a_warning_only(self):
        result = self.run_script(MIGRATION, STUB_NEW_IMAGE=OLD_IMAGE, **self.CONFIRMED)
        self.assert_migrated(result)
        self.assertEqual(
            result.stderr,
            'WARNING: the archive holds the image that lldpq already runs; '
            'the migration continues with that same image.\n')

    def test_failed_replacement_restarts_the_old_container_and_reports_the_rule(self):
        restarted = ('Replacement failed; the previous container was restarted '
                     '(deliberately reused mounts were not rolled back).')
        for name, rule, expected in (
                ('the rule is on the host', '100:\tfrom all lookup mgmt',
                 [restarted, RULE_WARNING]),
                ('no such rule', '100:\tfrom all lookup 254', [restarted])):
            with self.subTest(name):
                (self.state / 'containers').write_text('lldpq\n')
                self.switch(rule=rule)
                result = self.run_script(
                    self.with_extra_args('--network host', '-e CONSOLE_PTY_PORT=18765'),
                    STUB_OLD_NETWORK='host', STUB_READY_NEW_RC='1', **self.CONFIRMED)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Upgrade verified', result.stdout)
                self.assertEqual(result.stderr.splitlines(), expected)
                # The old container has its name back and was started again.
                self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')
                self.assertEqual(self.calls()[-4:-2],
                                 [f'docker rename {self.OLD} lldpq', 'docker start lldpq'])

    def test_rollback_waits_before_it_looks_for_the_rule(self):
        # An image before 4.2.5 adds the rule within its first seconds: a look
        # right after `docker start` would come too early and find nothing.
        script = self.with_extra_args('--network host', '-e CONSOLE_PTY_PORT=18765')
        for name, failure in (('the candidate does not become ready', 'STUB_READY_NEW_RC'),
                              ('the backup fails before the rename', 'STUB_CP_RC')):
            with self.subTest(name):
                (self.state / 'containers').write_text('lldpq\n')
                self.switch(rule='100:\tfrom all lookup mgmt')
                result = self.run_script(script, STUB_OLD_NETWORK='host',
                                         **{failure: '1'}, **self.CONFIRMED)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.warnings(result), [RULE_WARNING])
                timeline = self.timeline()
                restarted = len(timeline) - 1 - timeline[::-1].index('docker start lldpq')
                self.assertEqual([call for call in timeline[restarted:]
                                  if not call.startswith('docker ')],
                                 ['sleep 3', 'ip -4 rule show'])

    def test_failed_replacement_leaves_a_stopped_container_stopped(self):
        # The clean-up under Management VRF: the operator stopped the old
        # container and deleted the rule.  Its image adds the rule at every
        # start, so a rollback must not start it.
        script = self.with_extra_args('--network host', '-e CONSOLE_PTY_PORT=18765')
        host = dict(STUB_OLD_NETWORK='host', **self.CONFIRMED)
        was_running = 'docker inspect -f {{.State.Running}} lldpq'
        left_stopped = ('Replacement failed; the previous container was left stopped, as it '
                        'was before the migration (deliberately reused mounts were not '
                        'rolled back).')
        left_in_place = ('Replacement failed before the rollback rename completed; the '
                         'original container was left in place and stopped, as it was '
                         'before the migration.')

        def stopped_switch():
            (self.state / 'containers').write_text('lldpq\n')
            (self.state / 'stopped').write_text('lldpq\n')
            self.switch(rule='100:\tfrom all lookup 254')

        with self.subTest('the candidate does not become ready'):
            stopped_switch()
            result = self.run_script(script, STUB_READY_NEW_RC='1', **host)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.splitlines(), [left_stopped])
            calls = self.calls()
            # The state is read before the script stops the container itself.
            self.assertLess(calls.index(was_running), calls.index('docker stop lldpq'))
            # The old container has its name back; only the candidate was ever started.
            self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')
            rollback = calls[calls.index('docker rm -f lldpq'):]
            self.assertIn(f'docker rename {self.OLD} lldpq', rollback)
            self.assertEqual([call for call in rollback if call.startswith('docker start')], [])
            self.assertEqual(self.called(r'^docker start '), ['docker start lldpq'])
        with self.subTest('the backup fails before the rename'):
            stopped_switch()
            result = self.run_script(script, STUB_CP_RC='1', **host)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr.splitlines(), [left_in_place])
            self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')
            self.assertEqual(self.called(r'^docker (start|rename|create) '), [])
        with self.subTest('a stopped container still migrates'):
            stopped_switch()
            result = self.run_script(script, **host)
            self.assert_migrated(result)
            self.assertEqual(self.called(r'^docker start '), ['docker start lldpq'])

    def test_failure_before_the_rename_restarts_a_container_that_was_running(self):
        result = self.run_script(MIGRATION, STUB_CP_RC='1', **self.CONFIRMED)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            result.stderr,
            'Replacement failed before the rollback rename completed; the original '
            'container was left in place.\n')
        self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')
        self.assertEqual(self.called(r'^docker (start|rename|create) '), ['docker start lldpq'])

    def test_later_rollback_runs_in_a_new_shell(self):
        (self.state / 'containers').write_text(f'lldpq\n{self.OLD}\n')
        result = self.run_script('set -u\n' + MIGRATION_ROLLBACK)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.calls(), [
            f'docker container inspect {self.OLD}',
            f'docker image tag lldpq:pre-migration-{STAMP} lldpq:latest',
            'docker stop lldpq',
            f'docker rename lldpq lldpq-failed-{STAMP}',
            f'docker rename {self.OLD} lldpq',
            'docker start lldpq',
        ])

    def test_later_rollback_with_a_stamp_that_matches_nothing_changes_nothing(self):
        # The block stops and renames the live container.  With the example
        # stamp left in place, or a mistyped one, it must not get that far.
        retained = 'lldpq-pre-upgrade-20261112-101500'
        with self.subTest('no retained container carries the stamp'):
            (self.state / 'containers').write_text(f'lldpq\n{retained}\n')
            result = self.run_script('set -u\n' + MIGRATION_ROLLBACK)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.calls(), [f'docker container inspect {self.OLD}'])
            self.assertEqual((self.state / 'containers').read_text(), f'lldpq\n{retained}\n')
        with self.subTest('the rollback image is gone'):
            (self.state / 'containers').write_text(f'lldpq\n{self.OLD}\n')
            image = f'lldpq:pre-migration-{STAMP}'
            result = self.run_script('set -u\n' + MIGRATION_ROLLBACK, STUB_MISSING_IMAGE=image)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr,
                             f'Error response from daemon: No such image: {image}\n')
            self.assertEqual(self.calls(), [f'docker container inspect {self.OLD}',
                                            f'docker image tag {image} lldpq:latest'])
            self.assertEqual((self.state / 'containers').read_text(), f'lldpq\n{self.OLD}\n')


class RetainedCleanupTests(ScriptCase):
    OLD = f'lldpq-pre-upgrade-{STAMP}'
    VOLUMES = ('lldpq-data', 'shared-ansible', 'lldpq-ssh')

    def setUp(self):
        super().setUp()
        (self.state / 'containers').write_text(f'lldpq\n{self.OLD}\n')
        (self.state / f'volumes-of-{self.OLD}').write_text('\n'.join(self.VOLUMES) + '\n')
        (self.state / 'running').write_text('lldpq\n')

    def cleanup(self, prefix='', **env):
        return self.run_script(prefix + CLEANUP_LOOK + CLEANUP_REMOVE,
                               STUB_VOLUMES_IN_USE='shared-ansible', **env)

    def test_only_the_stopped_pre_upgrade_container_and_its_volumes_go(self):
        # Also under errexit: a volume that is still in use must not end the loop.
        for prefix in ('set -u\n', 'set -euo pipefail\n'):
            with self.subTest(prefix=prefix.strip()):
                self.setUp()
                result = self.cleanup(prefix)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines()[-3:], list(self.VOLUMES))
                self.assertEqual(
                    [line for line in result.stderr.splitlines() if line.startswith('kept')],
                    ['kept (still in use): shared-ansible'])
                calls = self.calls()
                # The volume names are read while the container still exists.
                self.assertLess(calls.index(next(c for c in calls if '{{range .Mounts}}' in c)),
                                calls.index(f'docker rm {self.OLD}'))
                self.assertEqual(self.called(r'^docker rm '), [f'docker rm {self.OLD}'])
                self.assertEqual(self.called(r'^docker volume rm '),
                                 [f'docker volume rm {volume}' for volume in self.VOLUMES])
                self.assertEqual((self.state / 'removed-volumes').read_text().split(),
                                 ['lldpq-data', 'lldpq-ssh'])
                self.assertEqual(calls[-1], f'docker image rm lldpq:pre-migration-{STAMP}')
                # Nothing is done to the live container.
                self.assertEqual((self.state / 'containers').read_text(), 'lldpq\n')
                self.assertEqual(self.called(r'^docker (stop|start|rename|create)\b'), [])
                self.assertEqual(self.called(r'(^| )-f( |$)|--force'), [])

    def test_a_container_that_runs_again_is_not_removed(self):
        (self.state / 'running').write_text(f'lldpq\n{self.OLD}\n')
        result = self.cleanup('set -u\n')
        self.assertIn('container is running', result.stderr)
        self.assertEqual(sorted((self.state / 'containers').read_text().split()),
                         ['lldpq', self.OLD])

    def test_guide_no_longer_points_at_the_full_removal_for_this(self):
        self.assertNotIn('use the removal section', DOCKER_DOC)
        section = DOCKER_DOC[DOCKER_DOC.index("### Legacy or direct `docker run` migration"):
                             DOCKER_DOC.index('## Building and checking an image')]
        self.assertIn('Do not use [Removing LLDPq completely]', section)


class GuideTextTests(ScriptCase):
    UPDATING = DOCKER_DOC[DOCKER_DOC.index('\n## Updating\n'):
                          DOCKER_DOC.index('\n## Building and checking an image\n')]

    def test_every_bash_block_of_the_guide_passes_bash_n(self):
        self.assertGreater(len(BLOCKS), 40)
        for number, block in enumerate(BLOCKS, 1):
            with self.subTest(block=number, first_line=block.splitlines()[0]):
                result = subprocess.run([shutil.which('bash'), '-n'], input=block,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_scripts_are_saved_to_a_file_not_pasted(self):
        self.assertIn('run it with `bash ./lldpq-update.sh`', self.UPDATING)
        self.assertIn('`bash ./lldpq-migrate.sh`', self.UPDATING)
        # Their variables end with them: nothing continues "in the same shell"
        # after a block that sets strict mode and exits.
        self.assertNotIn('In the same\nshell run', DOCKER_DOC)
        self.assertNotIn('are still present', self.UPDATING)
        for block in (MIGRATION_ROLLBACK, CLEANUP_LOOK):
            self.assertIn('container=lldpq\n', block)
            self.assertRegex(block, r'(?m)^stamp=\d{8}-\d{6}\b')

    def test_readiness_probe_comment_matches_the_image(self):
        # The image's own curl joins the VRF, so a plain docker exec does reach
        # the service; the comment used to say it cannot.
        self.assertNotIn('cannot reach it', COMPOSE_UPDATE)
        self.assertIn('lldpq-vrf\n    # starts the probe there', COMPOSE_UPDATE)

    def test_acl_commands_use_the_rule_id_the_operator_chose(self):
        self.assertNotRegex(DOCKER_DOC, r'acl-default-whitelist rule \d')
        acl_blocks = [block for block in BLOCKS if 'acl-default-whitelist' in block]
        self.assertEqual(len(acl_blocks), 3)
        for block in acl_blocks:
            with self.subTest(first_line=block.splitlines()[0]):
                log = self.state / 'nv-calls'
                if log.exists():
                    log.unlink()
                # A different ID than the example: every command has to follow it.
                result = self.run_script('set -u\n' + block.replace('rule=200', 'rule=215', 1))
                self.assertEqual(result.returncode, 0, result.stderr)
                changes = [call for call in log.read_text().splitlines() if ' acl ' in call]
                self.assertTrue(changes)
                for call in changes:
                    self.assertIn(' acl-default-whitelist rule 215', call)
                self.assertIn('nv config apply -y', log.read_text())

    def test_cumulus_update_steps_are_outside_the_management_vrf_section(self):
        heading = '\n### Cumulus switch with host networking\n'
        self.assertEqual(DOCKER_DOC.count(heading), 1)
        self.assertIn(heading, self.UPDATING)
        section = self.UPDATING[self.UPDATING.index(heading):
                                self.UPDATING.index('\n### Compose deployments\n')]
        for expected in ('--network host', '-e CONSOLE_PTY_PORT=18765', 'sudo docker rm -f lldpq',
                         "ip -4 rule show | grep '^100:'",
                         'sudo docker exec lldpq cat /var/www/html/VERSION'):
            self.assertIn(expected, section)
        self.assertIn('`docker load`\nonly moves the `lldpq:latest` tag', self.UPDATING)


if __name__ == '__main__':
    unittest.main()
