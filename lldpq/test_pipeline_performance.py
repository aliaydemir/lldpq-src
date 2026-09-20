"""Behavioral checks for bounded collection and scoped report reuse."""

import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from stage_scoped_reports import stage_baseline


class AssetsDispatchTests(unittest.TestCase):
    def run_dispatch(self, worker, limit=2, pause_before_wait=False):
        source = (HERE / 'assets.sh').read_text()
        dispatch = source[source.index('wait_for_asset_slot() {'):
                          source.index("CREATED_AT=$(date")]
        if pause_before_wait:
            dispatch = dispatch.replace('        wait_for_asset_slot',
                                        '        sleep 0.1\n        wait_for_asset_slot')
        with tempfile.TemporaryDirectory() as root:
            script = '''set -euo pipefail
declare -A devices=([slow]="test leaf1" [fast]="test leaf2" [last]="test leaf3")
device_ips=(slow fast last)
ROWS_DIR="$TEST_ROOT"
INVENTORY_FILE="$TEST_ROOT/inventory.tsv"
process_one() {
''' + worker + '\n}\n' + dispatch
            result = subprocess.run(['bash', '-c', script],
                                    env={**os.environ, 'TEST_ROOT': root,
                                         'ASSETS_MAX_PARALLEL': str(limit)},
                                    capture_output=True, text=True, timeout=10)
            files = {p.name: p.read_text() for p in Path(root).iterdir()}
        return result, files

    def test_fast_worker_frees_a_slot_before_slow_worker_finishes(self):
        version = subprocess.check_output(
            ['bash', '-c', 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"'],
            text=True)
        if tuple(map(int, version.split())) < (5, 1):
            self.skipTest('rolling wait requires Bash >=5.1; older Bash retains batching')
        result, files = self.run_dispatch('''
case "$1" in
  slow)
    for attempt in {1..100}; do
      if [[ -f "$TEST_ROOT/last_started" ]]; then
        echo observed > "$TEST_ROOT/slow_observed_refill"
        return 0
      fi
      sleep .01
    done
    return 9 ;;
  fast) sleep .02 ;;
  last) echo started > "$TEST_ROOT/last_started" ;;
esac
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('slow_observed_refill', files)

    def test_early_failure_is_not_lost_when_later_workers_succeed(self):
        result, _ = self.run_dispatch('''
case "$1" in
  slow) sleep .1 ;;
  fast) return 7 ;;
  last) return 0 ;;
esac
''')
        self.assertEqual(result.returncode, 1)
        self.assertIn('workers failed', result.stderr)

    def test_already_finished_workers_still_propagate_failure(self):
        result, _ = self.run_dispatch('[[ "$1" != fast ]]', pause_before_wait=True)
        self.assertEqual(result.returncode, 1)

    def test_parallel_limit_one_finishes_before_launching_next(self):
        result, files = self.run_dispatch('''
if [[ "$1" == slow ]]; then
    sleep .02
    echo done > "$TEST_ROOT/slow_done"
else
    [[ -f "$TEST_ROOT/slow_done" ]] || return 8
fi
''', limit=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('slow_done', files)


class ScopedReportStagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'published'
        self.stage = self.root / 'stage'
        self.source.mkdir()
        self.stage.mkdir()
        self.uid, self.gid = os.getuid(), os.getgid()

    def write(self, name, text='old', mode=0o664):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
        return path

    def stage_reports(self, overlays=()):
        return stage_baseline(self.source, self.stage, overlays, self.uid, self.gid)

    def test_unchanged_reports_are_reused_and_overlay_is_independent(self):
        unchanged = self.write('ber-history/leaf1.json', 'x' * 65536)
        replaced = self.write('summary/flap-summary.json', 'old flap')
        stats = self.stage_reports(['summary/flap-summary.json'])
        self.assertEqual(stats['reused_bytes'], 65536)
        self.assertEqual(stats['copied_bytes'], 0)
        self.assertTrue(os.path.samefile(unchanged, self.stage / 'ber-history/leaf1.json'))
        self.assertFalse((self.stage / 'summary/flap-summary.json').exists())
        (self.stage / 'summary/flap-summary.json').write_text('new flap')
        self.assertEqual(replaced.read_text(), 'old flap')
        shutil.rmtree(self.stage)
        self.assertEqual(unchanged.stat().st_size, 65536)
        self.assertEqual(replaced.read_text(), 'old flap')

    def test_markers_and_design_files_never_share_live_inodes(self):
        names = ['.lldpq-stale', '.analysis-state/flap.status', 'active-p2p.json']
        for name in names:
            self.write(name, mode=0o640 if name.startswith('.') else 0o664)
        stats = self.stage_reports()
        self.assertEqual(stats['copied_files'], 3)
        for name in names:
            self.assertFalse(os.path.samefile(self.source / name, self.stage / name))
            (self.stage / name).write_text('changed')
            self.assertEqual((self.source / name).read_text(), 'old')

    def test_normalization_does_not_modify_old_generation_permissions(self):
        old = self.write('old-mode.json', mode=0o600)
        self.stage_reports()
        self.assertEqual(old.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.stage / old.name).stat().st_mode & 0o777, 0o664)
        self.assertFalse(os.path.samefile(old, self.stage / old.name))

    def test_unsupported_linking_falls_back_to_independent_copy(self):
        original = self.write('report.json')
        with mock.patch('stage_scoped_reports.os.link', side_effect=OSError(errno.EPERM, 'unsupported')):
            stats = self.stage_reports()
        self.assertEqual(stats['copied_files'], 1)
        self.assertFalse(os.path.samefile(original, self.stage / original.name))

    def test_real_io_failure_is_not_hidden_by_retry(self):
        original = self.write('report.json')
        with mock.patch('stage_scoped_reports.os.link', side_effect=OSError(errno.ENOSPC, 'full')):
            with self.assertRaises(OSError):
                self.stage_reports()
        self.assertEqual(original.read_text(), 'old')

    def test_overlay_directory_is_not_traversed_or_linked(self):
        self.write('optical-data/leaf1.txt')
        stats = self.stage_reports(['optical-data'])
        self.assertEqual(stats['linked_files'], 0)
        self.assertFalse((self.stage / 'optical-data').exists())

    def test_symlink_baseline_artifact_is_rejected_without_following(self):
        external = self.root / 'external'
        external.write_text('outside')
        (self.source / 'escape').symlink_to(external)
        with self.assertRaises(ValueError):
            self.stage_reports()
        self.assertEqual(external.read_text(), 'outside')


if __name__ == '__main__':
    unittest.main()
