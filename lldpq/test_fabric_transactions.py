"""Fault injection against multi-file commits and restart recovery."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ruamel.yaml import YAML
from lldpq import fabric_transactions as tx


class FabricTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.first = self.root / "profile.yaml"
        self.second = self.root / "host.yaml"
        self.first.write_text("old: profile\n")
        self.second.write_text("old: host\n")
        self.first.chmod(0o664)
        self.writes = [({"new": "profile"}, self.first),
                       ({"new": "host"}, self.second)]
        self.replace = os.replace

    def test_second_replace_failure_restores_all_files_and_modes(self):
        def replace(source, target):
            if Path(target) == self.second:
                raise OSError("disk failure")
            return self.replace(source, target)
        with mock.patch.object(tx.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                tx.atomic_write_many(YAML(), self.writes, self.root)
        self.assertEqual(self.first.read_text(), "old: profile\n")
        self.assertEqual(self.second.read_text(), "old: host\n")
        self.assertEqual(self.first.stat().st_mode & 0o777, 0o664)
        self.assertFalse((self.root / tx.JOURNAL).exists())

    def crash_during_commit(self):
        script = '''
import os, sys
from pathlib import Path
from ruamel.yaml import YAML
from lldpq import fabric_transactions as tx
root = Path(sys.argv[1])
original = os.replace
def replace(source, target):
    if Path(target) == root / "host.yaml":
        os._exit(91)
    original(source, target)
os.replace = replace
tx.atomic_write_many(YAML(), [({"new": "profile"}, root / "profile.yaml"),
                             ({"new": "host"}, root / "host.yaml")], root)
'''
        result = subprocess.run([sys.executable, "-c", script, str(self.root)],
                                cwd=Path(__file__).resolve().parents[1], timeout=5)
        self.assertEqual(result.returncode, 91)
        self.assertEqual(self.first.read_text(), "new: profile\n")

    def test_process_death_recovers_before_next_mutation(self):
        self.crash_during_commit()
        with self.assertRaisesRegex(RuntimeError, "recover before reading"):
            tx.atomic_write_many(YAML(), self.writes, self.root)
        tx.recover(self.root)
        self.assertEqual(self.first.read_text(), "old: profile\n")
        self.assertEqual(self.second.read_text(), "old: host\n")
        self.assertFalse(list(self.root.glob('.lldpq-*')))
        tx.atomic_write_many(YAML(), self.writes, self.root)
        self.assertEqual(self.second.read_text(), "new: host\n")

    def test_failed_rollback_retains_journal_for_next_recovery(self):
        self.crash_during_commit()
        with mock.patch.object(tx.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                tx.recover(self.root)
        self.assertTrue((self.root / tx.JOURNAL).exists())
        tx.recover(self.root)
        self.assertEqual(self.first.read_text(), "old: profile\n")

    def test_external_edits_block_recovery_without_clobbering(self):
        self.crash_during_commit()
        self.first.write_text("external: edit\n")
        with self.assertRaisesRegex(RuntimeError, "External change"):
            tx.recover(self.root)
        self.assertEqual(self.first.read_text(), "external: edit\n")
        self.assertTrue((self.root / tx.JOURNAL).exists())

    def test_rollback_removes_new_files(self):
        self.first.unlink()
        def replace(source, target):
            if Path(target) == self.second:
                raise OSError("disk failure")
            return self.replace(source, target)
        with mock.patch.object(tx.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                tx.atomic_write_many(YAML(), self.writes, self.root)
        self.assertFalse(self.first.exists())

    def test_committed_journal_is_cleaned_without_rollback(self):
        self.crash_during_commit()
        journal = self.root / tx.JOURNAL
        data = json.loads(journal.read_text())
        data['state'] = 'committed'
        self.second.write_text('new: host\n')
        journal.write_text(json.dumps(data))
        tx.recover(self.root)
        self.assertEqual(self.first.read_text(), 'new: profile\n')
        self.assertEqual(self.second.read_text(), 'new: host\n')

    def test_migration_commits_hosts_and_rollback_record_together(self):
        source = (Path(__file__).resolve().parents[1] / 'html/fabric-api.sh').read_text()
        body = source.split('migrate_port_profiles() {', 1)[1].split(
            "python3 << 'PYTHON'\n", 1)[1].split('\nPYTHON\n', 1)[0]
        profiles = self.root / 'inventory/group_vars/all'
        profiles.mkdir(parents=True)
        (profiles / 'sw_port_profiles.yaml').write_text('sw_port_profiles:\n  new: {}\n')
        hosts = self.root / 'inventory/host_vars'
        hosts.mkdir(parents=True)
        old = 'interfaces:\n  swp1:\n    sw_port_profile: old\n'
        for host in ('leaf1', 'leaf2'):
            (hosts / (host + '.yaml')).write_text(old)
        request = self.root / 'request.json'
        request.write_text(json.dumps({'changes': {
            host: {'interfaces': {'swp1': {'old': 'old', 'new': 'new'}}}
            for host in ('leaf1', 'leaf2')}}))
        def run():
            output = io.StringIO()
            with mock.patch.dict(os.environ, ANSIBLE_DIR=str(self.root), POST_DATA_FILE=str(request)), \
                    contextlib.redirect_stdout(output):
                try:
                    exec(compile(body, 'migration', 'exec'), {})
                except SystemExit:
                    pass
            return json.loads(output.getvalue())
        def fail_second(source, target):
            if Path(target) == hosts / 'leaf2.yaml':
                raise OSError('disk failure')
            return self.replace(source, target)
        with mock.patch.object(tx.os, 'replace', side_effect=fail_second):
            result = run()
        self.assertFalse(result['success'], result)
        for path in hosts.glob('*.yaml'):
            self.assertEqual(path.read_text(), old)
        self.assertFalse(list((self.root / '.migrations').glob('*.json')))
        result = run()
        self.assertTrue(result['success'], result)
        record = json.loads((self.root / '.migrations' / (result['plan_id'] + '.json')).read_text())
        self.assertEqual(record['total_applied'], 2)
        for path in hosts.glob('*.yaml'):
            self.assertIn('sw_port_profile: new', path.read_text())
