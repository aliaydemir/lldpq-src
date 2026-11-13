"""A new deployment of the Docker image starts with an empty device inventory.

lldpq/devices.yaml in the repository is a sample inventory.  The image used to
ship it as the live file, the entrypoint seeded it into a new deployment, and
cron then polled the sample's addresses from a container nobody had configured:
a lab switch logged failed logins for the sample's user from a test container.

The image build now keeps the sample as devices.yaml.example and ships its
header and defaults block with an empty device map.  An inventory that already
exists in a volume or a config directory is not touched: the entrypoint only
seeds a file that is missing.

The Dockerfile step is run for real in a scratch directory (with a stand-in
chown), and what cron starts (the pipeline and the collectors) is run against
its result with stand-in ssh and ping binaries.  The pipeline ends such a run
at once and without a failure record.  Nothing here needs Docker or a network.
"""

from pathlib import Path
import getpass
import importlib.util
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lldpq'))

import parse_devices  # noqa: E402

# What Assets → Edit Devices saves an inventory through.
_SPEC = importlib.util.spec_from_file_location('image_inventory_setup_safety',
                                               ROOT / 'html/setup_safety.py')
setup_safety = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(setup_safety)

DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
ENTRYPOINT = (ROOT / 'docker/docker-entrypoint.sh').read_text()
COMPOSE = (ROOT / 'docker/docker-compose.yml').read_text()
SAMPLE = ROOT / 'lldpq/devices.yaml'
IMAGE_DIR = '/home/lldpq/lldpq'
EXAMPLE_HINT = ('  No devices defined yet — add them under Assets → Edit Devices '
                f'(sample: {IMAGE_DIR}/devices.yaml.example)')
# The line the shipped file carries right above its empty device map.
EMPTY_MAP_HINT = ('# No devices yet. To add some here, delete the {} below and list them under '
                  'that line, indented by two spaces: IP: Hostname @role\n')

# The build step that empties the inventory, with all its continuation lines.
BUILD_STEP = re.search(r'(?m)^RUN (cd /home/lldpq/lldpq (?:\\\n.*?)+)$', DOCKERFILE)

STAND_IN = '#!/bin/bash\nprintf \'%s\\n\' "$(basename "$0") $*" >> "$CALLS"\nexit "${STAND_IN_RC:-0}"\n'


class ScratchCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-inventory-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.calls = self.root / 'calls.log'

    def stand_in(self, *names, text=STAND_IN):
        for name in names:
            path = self.bin / name
            path.write_text(text)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def env(self, **overrides):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('LLDPQ_', 'FABRIC_SCAN_', 'ASSETS_'))}
        env.update(PATH=f"{self.bin}{os.pathsep}{env['PATH']}", CALLS=str(self.calls))
        env.update(overrides)
        return env

    def recorded(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def build_inventory(self, sample_text=None):
        """Run the Dockerfile's step on a copy of the repository's sample."""
        self.assertIsNotNone(BUILD_STEP, 'the inventory step is missing from the Dockerfile')
        tree = self.root / 'image'
        tree.mkdir(exist_ok=True)
        (tree / 'devices.yaml').write_text(
            SAMPLE.read_text() if sample_text is None else sample_text)
        command = BUILD_STEP.group(1).replace('\\\n', ' ')
        self.assertEqual(command.count(f'cd {IMAGE_DIR} '), 1)
        self.stand_in('chown')
        result = subprocess.run(
            ['sh', '-c', command.replace(f'cd {IMAGE_DIR} ', f'cd "{tree}" ')],
            capture_output=True, text=True, timeout=20, env=self.env())
        return result, tree


class ImageInventoryBuildTests(ScratchCase):
    def test_build_ships_an_empty_inventory_and_keeps_the_sample(self):
        result, tree = self.build_inventory()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(sorted(path.name for path in tree.iterdir()),
                         ['devices.yaml', 'devices.yaml.example'])
        sample = SAMPLE.read_text()
        self.assertEqual((tree / 'devices.yaml.example').read_text(), sample)

        # Everything ahead of the device map is kept as written: the
        # explanatory header and the defaults block.
        head = sample[:sample.index('\ndevices:\n') + 1]
        self.assertIn('# FORMAT:', head)
        self.assertIn('\ndefaults:\n  username: ', head)
        self.assertEqual((tree / 'devices.yaml').read_text(),
                         head + EMPTY_MAP_HINT + 'devices: {}\n')

        # Same ownership and mode as every other shipped config file.
        self.assertEqual(self.recorded(),
                         ['chown lldpq:www-data devices.yaml devices.yaml.example'])
        for name in ('devices.yaml', 'devices.yaml.example'):
            self.assertEqual(stat.S_IMODE((tree / name).stat().st_mode), 0o664, name)

    def test_empty_inventory_has_no_devices_for_the_projects_parser(self):
        _, tree = self.build_inventory()
        shipped = tree / 'devices.yaml'
        self.assertEqual(parse_devices.get_all_devices(
            parse_devices.load_devices_yaml(str(shipped))), [])
        # The sample it was made from is a real inventory, so this is not vacuous.
        sample = parse_devices.get_all_devices(parse_devices.load_devices_yaml(str(SAMPLE)))
        self.assertGreater(len(sample), 0)
        text = shipped.read_text()
        for address, _username, hostname, _role in sample:
            self.assertNotIn(address, text)
            self.assertNotIn(hostname, text)

    def test_empty_device_map_is_a_mapping_not_null(self):
        # A bare `devices:` parses as null, which the installer library's
        # inventory check rejects and older Provision code crashed on.
        _, tree = self.build_inventory()
        data = yaml.safe_load((tree / 'devices.yaml').read_text())
        self.assertEqual(data, {'defaults': {'username': 'cumulus'}, 'devices': {}})

    def test_shipped_file_says_how_to_replace_the_empty_map(self):
        # The editor shows the file as it is, and a device line typed under
        # `devices: {}` is not YAML: the save is refused. The file itself says
        # that the {} has to go.
        _, tree = self.build_inventory()
        shipped = (tree / 'devices.yaml').read_text()
        self.assertEqual(shipped.splitlines()[-2:], [EMPTY_MAP_HINT.rstrip('\n'), 'devices: {}'])
        parser = str(ROOT / 'lldpq/parse_devices.py')
        device = '  192.0.2.10: leaf01 @leaf\n'
        with self.assertRaisesRegex(setup_safety.SetupSafetyError, 'Invalid devices.yaml YAML'):
            setup_safety.validate_devices(shipped + device, parser)
        # Doing what the line says gives an inventory the editor saves.
        followed = shipped.replace('devices: {}\n', 'devices:\n' + device)
        setup_safety.validate_devices(followed, parser)
        edited = tree / 'edited.yaml'
        edited.write_text(followed)
        self.assertEqual(
            parse_devices.get_all_devices(parse_devices.load_devices_yaml(str(edited))),
            [('192.0.2.10', 'cumulus', 'leaf01', 'leaf')])

    def test_build_fails_rather_than_ship_a_sample_it_cannot_empty(self):
        # Without a `devices:` key the step would copy the whole sample.
        flat = '# legacy flat inventory\n192.0.2.10: leaf01\n192.0.2.11: leaf02\n'
        result, _ = self.build_inventory(sample_text=flat)
        self.assertNotEqual(result.returncode, 0)

    def test_step_runs_on_the_copied_tree_and_nothing_later_replaces_the_file(self):
        step = DOCKERFILE.index(BUILD_STEP.group(0))
        for earlier in ('COPY lldpq/ /home/lldpq/lldpq/\n',
                        'RUN chown -R lldpq:lldpq /home/lldpq/ \\\n'):
            self.assertEqual(DOCKERFILE.count(earlier), 1)
            self.assertLess(DOCKERFILE.index(earlier), step)
        self.assertNotIn('devices.yaml', DOCKERFILE[step + len(BUILD_STEP.group(0)):])
        self.assertIn(' && mv devices.yaml devices.yaml.example ', BUILD_STEP.group(1))
        self.assertIn(" && grep -qx 'devices: {}' devices.yaml ", BUILD_STEP.group(1))
        self.assertIn(' && chmod 664 devices.yaml devices.yaml.example', BUILD_STEP.group(1))

    def test_compose_file_no_longer_promises_a_sample_inventory(self):
        self.assertNotIn('including devices/tracking/topology', COMPOSE)
        self.assertIn(f'{IMAGE_DIR}/devices.yaml.example', COMPOSE)


class EntrypointInventoryLineTests(ScratchCase):
    """The start-up line that reports the inventory."""

    BLOCK = ENTRYPOINT[ENTRYPOINT.index('# ─── devices.yaml Setup ───'):
                       ENTRYPOINT.index('# ─── Switch lifecycle tracking ───')]

    def report(self, inventory=None):
        self.stand_in('chown')
        # The block sets the file's mode as well: give it a copy to work on.
        live = self.root / 'live-devices.yaml'
        if inventory is not None:
            live.write_text(inventory.read_text())
        # The sample's path in the hint is part of the message, not a file to read.
        block = re.sub(re.escape(f'{IMAGE_DIR}/devices.yaml') + r'(?!\.example)',
                       str(live), self.BLOCK)
        result = subprocess.run(['bash', '-c', 'set -e\n' + block], capture_output=True,
                                text=True, timeout=20, env=self.env())
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        return result.stdout

    def test_empty_inventory_is_counted_once_and_points_at_the_sample(self):
        _, tree = self.build_inventory()
        self.assertEqual(self.report(tree / 'devices.yaml'),
                         f'✓ devices.yaml loaded (0 devices)\n{EXAMPLE_HINT}\n')

    def test_inventory_with_devices_is_reported_as_before(self):
        count = len(parse_devices.get_all_devices(
            parse_devices.load_devices_yaml(str(SAMPLE))))
        self.assertEqual(self.report(SAMPLE), f'✓ devices.yaml loaded ({count} devices)\n')

    def test_missing_inventory_is_reported_as_before(self):
        self.assertEqual(
            self.report(),
            '⚠ No devices.yaml found\n'
            f'  Mount with: -v /path/to/devices.yaml:{self.root}/live-devices.yaml\n')

    def seed(self, config, app_path):
        """Run the entrypoint's seeding of devices.yaml on a scratch volume."""
        function = ENTRYPOINT[ENTRYPOINT.index('    _setup_config_file() {'):
                              ENTRYPOINT.index('    _setup_config_file devices.yaml')]
        call = re.search(r'(?m)^    _setup_config_file devices\.yaml +(\S+) +(\S+) +(\S+)$',
                         ENTRYPOINT)
        self.assertEqual(call.groups(), (f'{IMAGE_DIR}/devices.yaml', 'lldpq:www-data', '664'))
        self.stand_in('chown')
        script = (f'set -e\nCONFIG_DIR="$1"\n{function}\n'
                  f'_setup_config_file devices.yaml "$2" {call.group(2)} {call.group(3)}\n')
        result = subprocess.run(['bash', '-c', script, 'seed', str(config), str(app_path)],
                                capture_output=True, text=True, timeout=20, env=self.env())
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        # The application reads the inventory through a link into the volume.
        self.assertTrue(app_path.is_symlink())
        self.assertEqual(app_path.resolve(), (config / 'devices.yaml').resolve())
        self.assertEqual([path.name for path in config.iterdir()], ['devices.yaml'])

    def test_inventory_already_in_the_volume_is_kept(self):
        # An upgrade: the volume holds the operator's inventory and the new
        # image arrives with its empty one.
        _, tree = self.build_inventory()
        config = self.root / 'config'
        config.mkdir()
        kept = 'defaults:\n  username: cumulus\ndevices:\n  192.0.2.10: leaf01 @leaf\n'
        (config / 'devices.yaml').write_text(kept)
        self.seed(config, tree / 'devices.yaml')
        self.assertEqual((config / 'devices.yaml').read_text(), kept)
        self.assertEqual((tree / 'devices.yaml').read_text(), kept)

    def test_volume_without_an_inventory_is_seeded_with_the_empty_one(self):
        _, tree = self.build_inventory()
        shipped = (tree / 'devices.yaml').read_text()
        config = self.root / 'config'
        config.mkdir()
        self.seed(config, tree / 'devices.yaml')
        self.assertEqual((config / 'devices.yaml').read_text(), shipped)
        self.assertEqual(stat.S_IMODE((config / 'devices.yaml').stat().st_mode), 0o664)
        # The next start finds the file there and leaves what was saved since.
        edited = shipped.replace('devices: {}\n', 'devices:\n  192.0.2.10: leaf01 @leaf\n')
        (config / 'devices.yaml').write_text(edited)
        self.seed(config, tree / 'devices.yaml')
        self.assertEqual((config / 'devices.yaml').read_text(), edited)
        # The sample is never what a volume is seeded from.
        self.assertNotIn('devices.yaml.example', ENTRYPOINT.replace(
            f'(sample: {IMAGE_DIR}/devices.yaml.example)', ''))


class ScheduledCollectorTests(ScratchCase):
    """What cron starts in a container nobody has configured yet."""

    # The entrypoint's cron file starts the pipeline (bin/lldpq, whose first
    # collector is assets.sh), fabric-scan.sh and get-conf (get-configs.sh).
    COLLECTORS = ('fabric-scan.sh', 'assets.sh', 'get-configs.sh')
    STARTED = ('lldpq', *COLLECTORS)

    def installation(self, inventory):
        tree = self.root / 'lldpq'
        tree.mkdir()
        for name in (*self.COLLECTORS, 'load_devices.sh', 'parse_devices.py', 'addressing.py'):
            (tree / name).write_bytes((ROOT / 'lldpq' / name).read_bytes())
            # The pipeline starts its stages as ./name.
            (tree / name).chmod(0o755)
        (tree / 'devices.yaml').write_text(inventory.read_text())
        (self.root / 'web/monitor-results').mkdir(parents=True)
        (self.root / 'tmp').mkdir()
        # get-configs.sh takes its settings from the configuration file itself;
        # without one it stops before it would reach any device.
        conf = self.root / 'lldpq.conf'
        conf.write_text(f"WEB_ROOT={self.root / 'web'}\nLLDPQ_USER={getpass.getuser()}\n")
        self.stand_in('ssh', 'ping', 'scp', 'sshpass')
        # The devices answer nothing, but chown has to work: the pipeline hands
        # its web marker to www-data, a group a test host need not have.
        self.stand_in('chown', text=STAND_IN.replace('"${STAND_IN_RC:-0}"', '0'))
        env = self.env(
            STAND_IN_RC='1', TMPDIR=str(self.root / 'tmp'),
            # The tests' interpreter has PyYAML; the one on PATH may not.
            PATH=f"{self.bin}{os.pathsep}{Path(sys.executable).parent}{os.pathsep}"
                 f"{os.environ['PATH']}",
            LLDPQ_CONFIG_HELPER=str(self.root / 'no-helper'), LLDPQ_DIR=str(tree),
            LLDPQ_CONFIG_FILE=str(conf), WEB_ROOT=str(self.root / 'web'),
            LLDPQ_MONITOR_LOCK_FILE=str(self.root / 'tmp/monitor.lock'),
            # As in the pipeline's cron line.
            LLDPQ_MONITOR_LOCK_WAIT_SECONDS='300',
            LLDPQ_AI_ANALYZER=str(self.root / 'no-analyzer'),
            FABRIC_SCAN_LOCK_FILE=str(self.root / 'tmp/fabric.lock'),
            LLDPQ_GET_CONFIGS_LOCK_FILE=str(self.root / 'tmp/configs.lock'))
        return tree, env

    def start(self, tree, env, name):
        """Run one of cron's commands; return it and the network attempts it made."""
        self.calls.unlink(missing_ok=True)
        script = ROOT / 'bin/lldpq' if name == 'lldpq' else tree / name
        # Bounded: an unconfigured container must be done at once.
        result = subprocess.run(['bash', str(script)], cwd=tree, capture_output=True,
                                text=True, timeout=60, env=env)
        return result, [call for call in self.recorded()
                        if call.startswith(('ssh ', 'ping ', 'scp '))]

    def test_empty_inventory_makes_no_ssh_or_ping_attempt(self):
        _, image = self.build_inventory()
        tree, env = self.installation(image / 'devices.yaml')
        for name in self.STARTED:
            with self.subTest(started=name):
                self.assertEqual(self.start(tree, env, name)[1], [])

    def test_sample_inventory_would_be_polled(self):
        # The reason for the change, and the proof for each command that the
        # stand-ins see a poll: without it "no attempt" above shows nothing.
        tree, env = self.installation(SAMPLE)
        first = parse_devices.get_all_devices(
            parse_devices.load_devices_yaml(str(SAMPLE)))[0][0]
        for name in self.STARTED:
            with self.subTest(started=name):
                _, calls = self.start(tree, env, name)
                self.assertTrue(any(call.startswith('ping ') and call.endswith(f' {first}')
                                    for call in calls), calls[:3])

    def test_pipeline_ends_at_once_without_a_failure_record(self):
        # No devices is not a failed collection: every scheduled run used to
        # publish a stale marker for the dashboard and add a line to a log this
        # path never trims.
        _, image = self.build_inventory()
        tree, env = self.installation(image / 'devices.yaml')
        result, calls = self.start(tree, env, 'lldpq')
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        self.assertEqual(
            result.stdout,
            f'No devices in {tree}/devices.yaml yet, so nothing was collected. '
            'Add them under Assets → Edit Devices or in that file.\n')
        self.assertEqual(calls, [])
        for left in (tree / 'monitor-results', tree / 'monitor-failures.log',
                     self.root / 'web/monitor-results/.lldpq-stale'):
            self.assertFalse(left.exists(), left)

    def test_pipeline_on_the_sample_inventory_records_its_failure_as_before(self):
        # The other side: with devices that do not answer, asset discovery
        # does fail, and that is still marked for the dashboard and logged.
        tree, env = self.installation(SAMPLE)
        result, calls = self.start(tree, env, 'lldpq')
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, '', 'Asset discovery failed; monitoring was not published.\n'))
        self.assertTrue(calls)
        marker = (tree / 'monitor-results/.lldpq-stale').read_text()
        self.assertIn('status=stale\n', marker)
        self.assertIn('reason=asset discovery failed before monitoring\n', marker)
        self.assertEqual((self.root / 'web/monitor-results/.lldpq-stale').read_text(), marker)
        self.assertEqual(len((tree / 'monitor-failures.log').read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
