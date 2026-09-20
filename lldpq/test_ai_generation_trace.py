"""Behavioral regressions for generation-bound AI commits and VRF path tools."""
import ast
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs

from test_ai_api_contract import load_symbols, ROOT, TREE
from test_search_api_fixes import extract_heredoc_function, extract_stdin_python_heredoc


class GenerationCommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.monitor = self.root / 'monitor-results'
        (self.monitor / '.pipeline-inputs').mkdir(parents=True)
        self.state = self.root / 'ai-state'
        self.state.mkdir()
        self.lock = self.root / 'monitor.lock'
        self.lock.touch(mode=0o644)
        self.environment = mock.patch.dict(os.environ, {'LLDPQ_MONITOR_LOCK_FILE': str(self.lock)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.devices = {'192.0.2.1': {'hostname': 'leaf1'}}
        self.ns = load_symbols(
            '_max_collection_age_seconds', '_load_json_file', '_mr_path',
            '_pipeline_generation_state', '_generation_still_current',
            '_commit_analysis_state', '_save_json_state', 'action_analyze',
        )
        self.ns.update(os=os, math=math, datetime=datetime, timezone=timezone,
                       tempfile=tempfile, LLDPQ_DIR=str(self.root),
                       WEB_ROOT=str(self.root / 'web'), AI_STATE_DIR=str(self.state),
                       ANALYSIS_FILE=str(self.state / 'analysis.json'),
                       _ensure_state_dir=lambda: None)
        self.classifications = []

        def classify(findings, covered, persist=True):
            self.classifications.append(persist)
            if persist:
                (self.state / 'findings-state.json').write_text(json.dumps(findings))
            return findings, {'resolved': 0}
        self.ns['_classified_findings_or_fallback'] = classify
        self.initial = self.publish('A')

    def publish(self, identity):
        manifest = {'pipeline_id': identity, 'status': 'current', 'pipeline_complete': True,
                    'completed_at': datetime.now(timezone.utc).isoformat(),
                    'device_count': 1, 'max_age_seconds': 1800}
        (self.monitor / '.lldpq-current.json').write_text(json.dumps(manifest))
        (self.monitor / '.pipeline-inputs/collection_status.json').write_text(json.dumps({
            'pipeline_id': identity, 'expected_devices': 1,
            'counts': {'current': 1, 'unavailable': 0, 'failed': 0},
            'devices': {'leaf1': {'status': 'current'}},
        }))
        return manifest

    def commit(self, snapshot=None):
        return self.ns['_commit_analysis_state'](
            self.devices, self.initial, {'analysis': 'A result'}, snapshot,
            findings=[], covered_devices={'leaf1'},
        )

    def test_new_completed_generation_cannot_be_replaced_by_old_analysis(self):
        self.publish('B')
        self.assertTrue(self.ns['_pipeline_generation_state']({'leaf1'})['current'])
        self.assertFalse(self.commit({'statuses': {'leaf1': 'ok'}}))
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(self.classifications, [])

    def test_same_pipeline_id_with_new_completion_is_a_different_generation(self):
        changed = dict(self.initial, completed_at=datetime.now(timezone.utc).isoformat())
        (self.monitor / '.lldpq-current.json').write_text(json.dumps(changed))
        self.assertFalse(self.commit())

    def test_collection_in_flight_skips_commit_without_waiting(self):
        with self.lock.open('r') as collector:
            fcntl.flock(collector, fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            self.assertFalse(self.commit())
            self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_lock_covers_generation_check_findings_report_and_snapshot(self):
        original_check = self.ns['_generation_still_current']
        original_save = self.ns['_save_json_state']
        attempts = []

        def assert_locked():
            with self.lock.open('r') as collector:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(collector, fcntl.LOCK_EX | fcntl.LOCK_NB)
            attempts.append(True)

        def check(*args):
            assert_locked()
            return original_check(*args)

        def save(*args):
            assert_locked()
            return original_save(*args)
        self.ns.update(_generation_still_current=check, _save_json_state=save)
        self.assertTrue(self.commit({'statuses': {'leaf1': 'ok'}}))
        self.assertEqual(len(attempts), 3)
        self.assertEqual(self.classifications, [True])
        self.assertEqual(len(list(self.state.iterdir())), 3)
        with self.lock.open('r') as collector:
            fcntl.flock(collector, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_partial_coverage_writes_report_without_trusted_snapshot(self):
        self.assertTrue(self.commit())
        self.assertTrue((self.state / 'analysis.json').exists())
        self.assertFalse((self.state / 'analysis-snapshot.json').exists())

    def test_missing_lock_does_not_create_an_ai_owned_monitor_lock(self):
        self.lock.unlink()
        self.assertFalse(self.commit())
        self.assertFalse(self.lock.exists())

    def _run_action(self, branch, switch_generation):
        result = {}
        metadata = {'complete': True, 'report_persistable': True,
                    'generation': dict(self.initial, current=True)}
        def summary():
            if switch_generation == 'summary':
                self.publish('B')
            return 'Fabric observations', self.devices, {}, metadata
        def evidence(*args, **kwargs):
            if switch_generation == 'evidence':
                self.publish('B')
            return {'records': [], 'confidence': {}}
        def llm(*args, **kwargs):
            # No monitor lock may be held over this expensive call.
            with self.lock.open('r') as collector:
                fcntl.flock(collector, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if switch_generation == 'llm':
                self.publish('B')
            return {'ok': True, 'text': 'Healthy', 'provider': 'test',
                    'model': 'test', 'fallback_used': False}
        def capture(payload):
            result.update(payload)
            raise SystemExit
        self.ns.update({
            'build_fabric_summary': summary, 'build_device_list': lambda *a: 'leaf1',
            'neutralize_untrusted_tool_tags': lambda x: x,
            'neutralize_untrusted_observation_text': lambda x: x,
            '_build_timeline': lambda *a, **k: {},
            '_collection_for_evidence': lambda *a: metadata,
            '_new_context_state': lambda: {}, '_JOB_CONTEXT': None,
            '_health_snapshot': lambda *a: {'leaf1': 'ok'},
            '_running_config_hashes': lambda: {}, '_config_drift_devices': lambda _: [],
            '_diff_snapshots': lambda *a: [], '_timeline_event_fingerprint': lambda _: (),
            'ANALYSIS_REUSE_MAX_AGE_SECONDS': 100, 'ANALYSIS_REUSE_MAX_TEXT_AGE_SECONDS': 100,
            'AI_PROVIDER': 'test', 'AI_MODEL': 'test', 'AI_FALLBACK_MODEL': '',
            '_build_evidence': evidence, 'result_json': capture,
            'build_recent_changes_context': lambda _: '', '_timeline_context': lambda _: '',
            '_FINDINGS_CONTRACT_PROMPT': '',
            '_reduce_untrusted_context_if_needed': lambda content, *a, **k: content,
            'call_llm_sync': llm, '_parse_findings_json': lambda _: ([], 'Healthy'),
            '_apply_suppressions': lambda value, _: value,
            '_covered_devices_for_findings': lambda *a: {'leaf1'},
            '_job_cancelled': lambda: False, 'redact_secrets': lambda x: x,
            'error_json': lambda message: self.fail(message),
        })
        if branch == 'reuse':
            (self.state / 'analysis-snapshot.json').write_text(json.dumps({'statuses': {'leaf1': 'ok'}}))
            (self.state / 'analysis.json').write_text(json.dumps({
                'timestamp': time.time(), 'analysis': 'Prior text', 'collection': {'complete': True},
            }))
        before = {path.name: path.read_bytes() for path in self.state.iterdir()}
        with mock.patch.dict(os.environ, {'LLDPQ_AUTH_USER': 'lldpq-ai-cron' if branch == 'scan' else ''}):
            with self.assertRaises(SystemExit):
                self.ns['action_analyze']()
        return result, before

    def test_every_action_branch_rejects_a_new_generation_without_state_mutation(self):
        for branch, change in [('reuse', 'evidence'), ('scan', 'llm'), ('synthesis', 'llm')]:
            with self.subTest(branch=branch):
                self.publish('A')
                for path in self.state.iterdir():
                    path.unlink()
                result, before = self._run_action(branch, change)
                self.assertTrue(result['success'])
                self.assertFalse(result['persisted'])
                self.assertFalse(result['snapshot_updated'])
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.state.iterdir()})
        self.assertNotIn(True, self.classifications)

    def test_generation_is_captured_before_summary_reads(self):
        result, _ = self._run_action('synthesis', 'summary')
        self.assertFalse(result['persisted'])

    def test_all_action_branches_persist_with_unchanged_generation(self):
        for branch in ('reuse', 'scan', 'synthesis'):
            with self.subTest(branch=branch):
                for path in self.state.iterdir():
                    path.unlink()
                result, _ = self._run_action(branch, None)
                self.assertTrue(result['persisted'])
                self.assertTrue(result['snapshot_updated'])


class TraceVrfTests(unittest.TestCase):
    def test_ai_trace_auto_detects_ip_vrf_and_forwards_explicit_vrf(self):
        ns = load_symbols('run_tracepath')
        ns.update(os=os, WEB_ROOT='/web')
        for src, vrf in [('10.0.0.1', ''), ('10.0.0.1', 'red'), ('leaf1', 'red')]:
            with self.subTest(src=src, vrf=vrf), mock.patch('subprocess.run') as run:
                run.return_value.stdout = 'Content-Type: application/json\n\n{"path": []}'
                self.assertTrue(ns['run_tracepath'](src, '10.0.0.2', '', vrf=vrf)[0])
                query = parse_qs(run.call_args.kwargs['env']['QUERY_STRING'])
                self.assertEqual(query.get('vrf', [''])[0], vrf)
                self.assertEqual(query['action'], ['trace-path' if src == 'leaf1' else 'trace-path-ip'])

    def test_ai_trace_reports_search_errors_as_tool_failures(self):
        ns = load_symbols('run_tracepath')
        ns.update(os=os, WEB_ROOT='/web')
        with mock.patch('subprocess.run') as run:
            run.return_value.stdout = '{"error": "specify a VRF"}'
            self.assertEqual(ns['run_tracepath']('1.1.1.1', '2.2.2.2', ''),
                             (False, 'specify a VRF'))

    def test_path_parser_accepts_optional_vrf_and_preserves_legacy_calls(self):
        assignment = next(node for node in ast.walk(TREE) if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'paths'
                                  for target in node.targets))
        ns = load_symbols()
        ns['response'] = '[PATH: 10.0.0.1 10.0.0.2]\n[PATH: leaf1 10.0.0.2 red]'
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), '<path-parser>', 'exec'), ns)
        self.assertEqual(ns['paths'], [('10.0.0.1', '10.0.0.2', ''), ('leaf1', '10.0.0.2', 'red')])

    def run_trace(self, method, tables, *args):
        source = (ROOT / 'html/search-api.sh').read_text()
        code = extract_stdin_python_heredoc(extract_heredoc_function(source, method))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_dir = root / 'monitor-results/fabric-tables'
            data_dir.mkdir(parents=True)
            for host, data in tables.items():
                (data_dir / f'{host}.json').write_text(json.dumps(data))
            (data_dir / 'summary.json').write_text(json.dumps({
                'complete': True, 'timestamp': datetime.now(timezone.utc).isoformat(),
                'status_counts': {'current': len(tables), 'stale': 0, 'unavailable': 0},
            }))
            script = root / 'trace.py'
            script.write_text(code)
            result = subprocess.run([sys.executable, str(script), *args], capture_output=True,
                                    text=True, env={**os.environ, 'LLDPQ_DIR': temp, 'WEB_ROOT': temp})
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

    def test_hostname_trace_does_not_use_foreign_or_missing_vrf_arp(self):
        for vrf in ('red', None):
            with self.subTest(vrf=vrf):
                arp = {'ip': '10.0.0.2'}
                if vrf:
                    arp['vrf'] = vrf
                result = self.run_trace('trace_path', {'leaf1': {'arp': [arp]}},
                                        '10.0.0.2', 'default', 'leaf1')
                self.assertTrue(result['path'][0].get('is_dead_end'))
                self.assertFalse(result['path'][0].get('is_destination', False))

    def test_hostname_trace_uses_matching_arp_vrf(self):
        result = self.run_trace('trace_path', {'leaf1': {'arp': [{'ip': '10.0.0.2', 'vrf': 'red'}]}},
                                '10.0.0.2', 'red', 'leaf1')
        self.assertTrue(result['path'][0]['is_destination'])

    def test_auto_ip_trace_finds_tenant_and_rejects_ambiguous_source(self):
        data = {'arp': [{'ip': '10.0.0.1', 'vrf': 'red'}, {'ip': '10.0.0.2', 'vrf': 'red'}],
                'routes': {'red': [{'prefix': '10.0.0.0/24', 'protocol': 'connected',
                                    'interface': 'vlan10', 'nexthop': ''}]}}
        result = self.run_trace('trace_path_ip', {'leaf1': data}, '10.0.0.1', '10.0.0.2', '', '')
        self.assertNotIn('error', result)
        self.assertEqual(result['vrf'], 'red')
        data['arp'].append({'ip': '10.0.0.1', 'vrf': 'blue'})
        result = self.run_trace('trace_path_ip', {'leaf1': data}, '10.0.0.1', '10.0.0.2', '', '')
        self.assertIn('multiple VRFs', result['error'])
        result = self.run_trace('trace_path_ip', {'leaf1': data}, '10.0.0.1', '10.0.0.2', 'red', '')
        self.assertNotIn('error', result)


if __name__ == '__main__':
    unittest.main()
