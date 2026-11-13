"""A pipeline run on an inventory without devices ends quietly.

The Docker image ships an inventory whose device map is empty.  Every scheduled
run of bin/lldpq then failed in asset discovery ("No devices found"), published
a status=stale marker to the web tree and appended a line to
monitor-failures.log, a file this path never trims: 144 lines a day for a
deployment nobody had configured yet.

bin/lldpq now asks the project's parser first.  An inventory that parses and
whose devices mapping has no entries ends the run with one line on stdout and
status 0, before anything is marked, logged or collected.  Everything else is
left alone: an inventory that is missing, does not parse or has a devices key
that is not a mapping fails in asset discovery exactly as before, and a run
with devices does what it did.

That early end is for a deployment that has published no report yet.  Once a
generation is published, an inventory that is emptied fails in asset discovery
as it did before: the pages show that report, and the stale marker is the only
thing that tells them the latest collection failed.

The real bin/lldpq, load_devices.sh and parse_devices.py run here; the failing
cases also run the real assets.sh.  The later stages are stand-ins that record
that they were started.  Nothing needs a network.
"""

from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
LLDPQ_BIN = ROOT / 'bin/lldpq'

EMPTY = 'defaults:\n  username: cumulus\ndevices: {}\n'
ONE_DEVICE = 'defaults:\n  username: cumulus\ndevices:\n  192.0.2.10: leaf01 @leaf\n'
STAGES = ('assets.sh', 'check-lldp.sh', 'monitor.sh', 'fabric-scan.sh')
REASON = 'asset discovery failed before monitoring'

RECORD = '#!/bin/bash\nprintf \'%s\\n\' "$(basename "$0") $*" >> "$CALLS"\n'
STAGE = ('#!/usr/bin/env bash\n'
         'echo ran >> "$WITNESS/$(basename "$0")"\n')
# A real monitor clears the report-state marker once it has published.
MONITOR = STAGE + 'rm -f monitor-results/.lldpq-stale "$WEB_ROOT/monitor-results/.lldpq-stale"\n'
ALERTS = ('import os, sys\n'
          'with open(os.path.join(os.environ["WITNESS"], "check_alerts.py"), "a") as witness:\n'
          '    witness.write(" ".join(sys.argv[1:]) + "\\n")\n')


def executable(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PipelineCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-empty-inventory-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.tree = self.root / 'lldpq'
        self.web = self.root / 'web'
        self.bin = self.root / 'bin'
        self.witness = self.root / 'witness'
        self.calls = self.root / 'calls.log'
        # The web tree has monitor-results in an installation, so the marker is
        # published there too.
        for directory in (self.tree, self.web / 'monitor-results', self.bin, self.witness,
                          self.root / 'tmp'):
            directory.mkdir(parents=True)
        for name in ('load_devices.sh', 'parse_devices.py', 'addressing.py'):
            (self.tree / name).write_bytes((ROOT / 'lldpq' / name).read_bytes())
        for name in STAGES:
            executable(self.tree / name, MONITOR if name == 'monitor.sh' else STAGE)
        (self.tree / 'check_alerts.py').write_text(ALERTS)
        # chown hands the web marker to www-data, a group a test host need not have.
        for name in ('chown', 'ssh', 'ping'):
            executable(self.bin / name, RECORD)
        self.inventory = self.tree / 'devices.yaml'
        self.source_marker = self.tree / 'monitor-results/.lldpq-stale'
        self.web_marker = self.web / 'monitor-results/.lldpq-stale'
        self.failures = self.tree / 'monitor-failures.log'
        self.notice = (f'No devices in {self.tree}/devices.yaml yet, so nothing was collected. '
                       'Add them under Assets → Edit Devices or in that file.\n')

    def real_assets(self):
        executable(self.tree / 'assets.sh', (ROOT / 'lldpq/assets.sh').read_text())

    def run_pipeline(self, *arguments, **overrides):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('LLDPQ_', 'SKIP_', 'ASSETS_'))}
        env.update(
            # The tests' interpreter has PyYAML; the one on PATH may not.
            PATH=f"{self.bin}{os.pathsep}{Path(sys.executable).parent}{os.pathsep}{env['PATH']}",
            CALLS=str(self.calls), WITNESS=str(self.witness), TMPDIR=str(self.root / 'tmp'),
            LLDPQ_CONFIG_HELPER=str(self.root / 'no-helper'), LLDPQ_DIR=str(self.tree),
            WEB_ROOT=str(self.web), LLDPQ_MONITOR_LOCK_FILE=str(self.root / 'tmp/monitor.lock'),
            LLDPQ_AI_ANALYZER=str(self.root / 'no-analyzer'))
        env.update(overrides)
        return subprocess.run(['bash', str(LLDPQ_BIN), *arguments], cwd=self.root,
                              capture_output=True, text=True, timeout=60, env=env)

    def started(self):
        return sorted(path.name for path in self.witness.iterdir())

    def network_calls(self):
        calls = self.calls.read_text().splitlines() if self.calls.exists() else []
        return [call for call in calls if call.startswith(('ssh ', 'ping '))]

    def assert_nothing_marked_or_logged(self):
        for path in (self.source_marker, self.web_marker, self.failures):
            self.assertFalse(path.exists(), path)


class EmptyInventoryTests(PipelineCase):
    def test_run_ends_with_one_line_and_leaves_no_state(self):
        self.inventory.write_text(EMPTY)
        self.real_assets()
        result = self.run_pipeline()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, self.notice, ''))
        self.assert_nothing_marked_or_logged()
        # Not even the report directory the collecting marker would be written to.
        self.assertFalse((self.tree / 'monitor-results').exists())
        self.assertEqual(self.started(), [])
        self.assertEqual(self.network_calls(), [])

    def test_no_stage_is_started(self):
        # Every stage is a stand-in here, so a started one leaves a trace.
        self.inventory.write_text(EMPTY)
        result = self.run_pipeline()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, self.notice, ''))
        self.assertEqual(self.started(), [])
        self.assert_nothing_marked_or_logged()

    def test_scheduled_and_manual_runs_print_the_same_line(self):
        self.inventory.write_text(EMPTY)
        self.real_assets()
        runs = {
            # The scheduled line of the image and of install.sh.
            'cron': self.run_pipeline(LLDPQ_MONITOR_LOCK_WAIT_SECONDS='300'),
            'operator': self.run_pipeline(),
            'verbose': self.run_pipeline('-'),
            'skip optical': self.run_pipeline('-s'),
        }
        for name, result in runs.items():
            with self.subTest(run=name):
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, self.notice, ''))
        self.assert_nothing_marked_or_logged()

    def test_stage_skips_do_not_change_it_while_a_stage_would_read_the_inventory(self):
        # With asset discovery skipped the LLDP stage was the one that failed.
        self.inventory.write_text(EMPTY)
        for skipped in (('SKIP_ASSETS',), ('SKIP_MONITOR',),
                        ('SKIP_ASSETS', 'SKIP_LLDP', 'SKIP_MONITOR'),
                        ('SKIP_LLDP', 'SKIP_MONITOR', 'SKIP_FABRIC_SCAN'),
                        ('SKIP_ASSETS', 'SKIP_MONITOR', 'SKIP_FABRIC_SCAN'),
                        ('SKIP_ASSETS', 'SKIP_LLDP', 'SKIP_FABRIC_SCAN')):
            with self.subTest(skipped=skipped):
                result = self.run_pipeline(**{key: 'true' for key in skipped})
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, self.notice, ''))
                self.assertEqual(self.started(), [])
        self.assert_nothing_marked_or_logged()

    def test_marker_and_log_of_an_earlier_run_are_left_as_they_are(self):
        # Only a complete publication may clear the marker: it can stand for a
        # real failure, and this run has published nothing.
        self.inventory.write_text(EMPTY)
        marker = ('status=stale\ntimestamp=2026-01-01T00:00:00+00:00\n'
                  'reason=disk_full: publish staging needs ~10MB\npipeline_id=earlier\n')
        log = '2026-01-01T00:00:00+00:00 disk_full: publish staging needs ~10MB\n'
        self.source_marker.parent.mkdir()
        self.source_marker.write_text(marker)
        self.web_marker.write_text(marker)
        self.failures.write_text(log)
        result = self.run_pipeline()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, self.notice, ''))
        self.assertEqual(self.source_marker.read_text(), marker)
        self.assertEqual(self.web_marker.read_text(), marker)
        self.assertEqual(self.failures.read_text(), log)


class UnchangedPathTests(PipelineCase):
    """What must not be mistaken for the empty inventory of a new deployment."""

    PROBLEMS = {
        'no inventory file': None,
        'not YAML': 'devices: {\n',
        'empty file': '',
        'top level is a list': '- 192.0.2.10\n',
        'no devices key': 'defaults:\n  username: cumulus\n',
        'devices is null': 'defaults:\n  username: cumulus\ndevices:\n',
        'devices is an empty list': 'devices: []\n',
        'devices is a list': 'devices:\n  - 192.0.2.10\n',
        'devices is a string': 'devices: leaf01\n',
        'defaults is not a mapping': 'defaults: cumulus\ndevices: {}\n',
        'duplicate devices key': 'devices:\n  192.0.2.10: leaf01\ndevices: {}\n',
        'device without a hostname': 'devices:\n  192.0.2.10: {role: leaf}\n',
    }

    def assert_asset_discovery_failed(self, result):
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, '', 'Asset discovery failed; monitoring was not published.\n'))
        marker = self.source_marker.read_text().splitlines()
        self.assertEqual(marker[0], 'status=stale')
        self.assertEqual(marker[2], f'reason={REASON}')
        self.assertEqual(self.web_marker.read_text().splitlines(), marker)
        log = self.failures.read_text().splitlines()
        self.assertEqual(len(log), 1)
        self.assertTrue(log[0].endswith(f' {REASON}'), log)
        self.assertEqual(self.started(), [])
        self.assertEqual(self.network_calls(), [])

    def test_inventory_problems_fail_in_asset_discovery_as_before(self):
        self.real_assets()
        for name, text in self.PROBLEMS.items():
            with self.subTest(inventory=name):
                for path in (self.inventory, self.source_marker, self.web_marker, self.failures):
                    path.unlink(missing_ok=True)
                if text is not None:
                    self.inventory.write_text(text)
                self.assert_asset_discovery_failed(self.run_pipeline())

    def test_parser_that_cannot_run_fails_in_asset_discovery_as_before(self):
        self.real_assets()
        self.inventory.write_text(EMPTY)
        parser = self.tree / 'parse_devices.py'
        for name, text in (('raises', 'raise RuntimeError("broken parser")\n'),
                           ('not Python', 'this is not python\n'),
                           ('missing', None)):
            with self.subTest(parser=name):
                for path in (parser, self.source_marker, self.web_marker, self.failures):
                    path.unlink(missing_ok=True)
                if text is not None:
                    parser.write_text(text)
                self.assert_asset_discovery_failed(self.run_pipeline())

    def publish_earlier_generation(self):
        # What a completed run leaves in both trees, well before this run.
        published = time.time() - 3600
        for tree in (self.tree, self.web):
            manifest = tree / 'monitor-results/.lldpq-current.json'
            manifest.parent.mkdir(exist_ok=True)
            manifest.write_text('{"status": "current", "pipeline_id": "earlier"}\n')
            os.utime(manifest, (published, published))

    def test_inventory_emptied_after_a_report_was_published_fails_as_before(self):
        # Ending quietly here would leave that report on the pages with no
        # "latest collection failed" note, and the dashboard without a reason.
        self.real_assets()
        self.inventory.write_text(EMPTY)
        self.publish_earlier_generation()
        for name, lock_wait in (('operator', {}),
                                ('cron', {'LLDPQ_MONITOR_LOCK_WAIT_SECONDS': '300'})):
            with self.subTest(run=name):
                for path in (self.source_marker, self.web_marker, self.failures):
                    path.unlink(missing_ok=True)
                self.assert_asset_discovery_failed(self.run_pipeline(**lock_wait))

    def test_marker_of_a_killed_run_does_not_outlive_the_next_run_on_a_published_report(self):
        # A killed run leaves status=collecting behind; the pages say
        # "collection in progress" for as long as that marker stays.
        self.real_assets()
        self.inventory.write_text(EMPTY)
        self.publish_earlier_generation()
        killed = ('status=collecting\ntimestamp=2026-01-01T00:00:00+00:00\n'
                  'reason=pipeline_collection_in_progress\npipeline_id=killed\n')
        self.source_marker.write_text(killed)
        self.web_marker.write_text(killed)
        self.assert_asset_discovery_failed(self.run_pipeline())

    def test_run_with_devices_starts_every_stage_and_prints_nothing(self):
        self.inventory.write_text(ONE_DEVICE)
        result = self.run_pipeline()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.started(), sorted((*STAGES, 'check_alerts.py')))
        for name in STAGES:
            self.assertEqual((self.witness / name).read_text(), 'ran\n', name)
        self.assert_nothing_marked_or_logged()

    def test_run_with_every_inventory_stage_skipped_stays_silent(self):
        # That run reads no inventory and succeeded without output; a line on
        # stdout would turn into mail from an unredirected cron entry.
        self.inventory.write_text(EMPTY)
        result = self.run_pipeline(SKIP_ASSETS='true', SKIP_LLDP='true', SKIP_MONITOR='true',
                                   SKIP_FABRIC_SCAN='true')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        # The run went on past the stages as it always did: the fabric
        # availability pre-check is the one step no skip here turns off.
        self.assertEqual(self.started(), ['check_alerts.py'])
        self.assertEqual((self.witness / 'check_alerts.py').read_text(), '--assets-only\n')
        self.assert_nothing_marked_or_logged()

    def test_asset_discovery_pointed_at_another_inventory_runs_as_before(self):
        # assets.sh honours LLDPQ_DEVICES_FILE; devices.yaml says nothing about
        # what that stage would collect.
        self.inventory.write_text(EMPTY)
        other = self.root / 'other-devices.yaml'
        other.write_text(ONE_DEVICE)
        result = self.run_pipeline(LLDPQ_DEVICES_FILE=str(other))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        self.assertEqual(self.started(), sorted((*STAGES, 'check_alerts.py')))


if __name__ == '__main__':
    unittest.main()
