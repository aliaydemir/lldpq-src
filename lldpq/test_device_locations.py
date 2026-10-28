"""Location parsing, source reconciliation and Inventory activation contracts."""

import base64
import copy
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'html'))
sys.path.insert(0, str(ROOT / 'lldpq'))

import device_locations as locations
import test_inventory_api as inventory_tests
from test_ai_p2p import build_xlsx


def design(*rows):
    return {'format': locations.FORMAT, 'locations': [
        {'hostname': host, 'rack': rack, 'unit': unit} for host, rack, unit in rows]}


def cable(host='leaf01', rack='C1', unit='6-7', peer='server01', peer_rack='C2', peer_unit='10'):
    return {'source_name': host, 'source_rack': rack, 'source_ru': unit,
            'source_port': 'swp1', 'dest_name': peer, 'dest_rack': peer_rack,
            'dest_ru': peer_unit, 'dest_port': 'eth0'}


class LocationParsingTests(unittest.TestCase):
    def test_csv_headers_bom_semicolon_numeric_and_ranges(self):
        parsed = locations.parse_upload(
            '\ufeffGOOGLE hostname;Rack;U-Pos\r\n leaf01 ; C1 ; 06 - 07\r\nleaf02;C2;12\r\n'.encode(), 'rack.csv')
        self.assertEqual(parsed['locations'], design(('leaf01', 'C1', '6-7'), ('leaf02', 'C2', '12'))['locations'])

    def test_case_insensitive_identical_duplicates_merge(self):
        parsed = locations.parse_upload(b'Hostname,Rack,RU\nLeaf01,C1,6\nleaf01,c1,6.0\n', 'rack.csv')
        self.assertEqual(len(parsed['locations']), 1)
        self.assertIn('duplicate', parsed['warnings'][0])

    def test_conflicting_duplicates_rejected_with_row(self):
        with self.assertRaisesRegex(ValueError, r'CSV row 3: conflicting locations'):
            locations.parse_upload(b'Hostname,Rack,Unit\nleaf01,C1,6\nLEAF01,C2,6\n', 'rack.csv')

    def test_missing_fields_and_invalid_units_never_partially_import(self):
        for value in ('0', '-1', '7-6', '6/7', '2026-06-07', 'Jun-7', '6.5', ''):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, r'CSV row 3:'):
                locations.parse_upload(('Hostname,Rack,U-Pos\nleaf01,C1,6\nleaf02,C2,%s\n' % value).encode(), 'rack.csv')
        with self.assertRaisesRegex(ValueError, 'required'):
            locations.parse_upload(b'Hostname,Rack,U-Pos\nleaf01,,6\n', 'rack.csv')

    def test_canonical_upload_validation(self):
        for value in ({'locations': []}, {'format': locations.FORMAT, 'locations': ['bad']}, design(('leaf01', 'C1', '12-1'))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                locations.validate_design(value)

    def test_xlsx_multiple_sheets_shared_and_inline_strings(self):
        for mode in ('shared', 'inline'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'racks.xlsx'
                build_xlsx(path, [
                    ('Instructions', [['Format U-Pos as text']]),
                    ('Rack1', [['Site location list'], ['Hostname', 'Rack', 'U-Pos'], ['leaf01', 'C1', 6.0]]),
                    ('Rack2', [['GOOGLE hostname', 'Rack', 'RU'], ['leaf02', 'C2', '12-13']]),
                ], string_mode=mode)
                parsed = locations.parse_upload(path.read_bytes(), path.name)
                self.assertEqual(parsed['locations'], design(('leaf01', 'C1', '6'), ('leaf02', 'C2', '12-13'))['locations'])
                self.assertIn('Instructions', parsed['warnings'][0])

    def test_excel_date_styles_and_iso_dates_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'racks.xlsx'
            build_xlsx(path, [('Rack', [['Hostname', 'Rack', 'U-Pos'], ['leaf01', 'C1', 46210]])])
            with zipfile.ZipFile(path) as zf:
                members = {name: zf.read(name) for name in zf.namelist()}
            for style in ('builtin', 'custom', 'iso'):
                with self.subTest(style=style):
                    changed = dict(members)
                    if style == 'iso':
                        changed['xl/worksheets/sheet1.xml'] = changed['xl/worksheets/sheet1.xml'].replace(
                            b'<c r="C2"><v>46210</v></c>', b'<c r="C2" t="d"><v>2026-06-07</v></c>')
                    else:
                        changed['xl/worksheets/sheet1.xml'] = changed['xl/worksheets/sheet1.xml'].replace(b'<c r="C2">', b'<c r="C2" s="1">')
                        fmt = '<numFmts count="1"><numFmt numFmtId="164" formatCode="d-mmm"/></numFmts>' if style == 'custom' else ''
                        num = 164 if style == 'custom' else 14
                        changed['xl/styles.xml'] = ('<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">%s'
                            '<cellXfs count="2"><xf numFmtId="0"/><xf numFmtId="%d"/></cellXfs></styleSheet>' % (fmt, num)).encode()
                    stream = io.BytesIO()
                    with zipfile.ZipFile(stream, 'w') as zf:
                        for name, value in changed.items():
                            zf.writestr(name, value)
                    with self.assertRaisesRegex(ValueError, 'Rack row 2: U-Pos is an Excel date'):
                        locations.parse_upload(stream.getvalue(), 'racks.xlsx')


class LocationResolutionTests(unittest.TestCase):
    def test_both_p2p_ends_repeated_links_and_agreeing_mapping(self):
        p2p = {'connections': [cable(), cable(), cable(host='LEAF01')]}
        simple = design(('leaf01', 'c1', '6-7'), ('extra', 'C3', '15'))
        original = copy.deepcopy((p2p, simple))
        result = locations.resolve_locations(p2p, simple)
        self.assertEqual(set(result['locations']), {'leaf01', 'server01', 'extra'})
        self.assertEqual(result['locations']['leaf01']['source'], 'p2p')
        self.assertEqual(result['locations']['extra']['source'], 'locations')
        self.assertEqual(result['conflicts'], [])
        self.assertEqual((p2p, simple), original)

    def test_incomplete_p2p_falls_back_and_short_names_are_not_guessed(self):
        result = locations.resolve_locations({'connections': [cable(rack='')]}, design(('leaf01', 'C9', '2')))
        self.assertEqual(result['locations']['leaf01']['source'], 'locations')
        self.assertNotIn('leaf01.example.org', result['locations'])

    def test_conflict_between_sources_or_p2p_rows_is_omitted(self):
        for p2p, simple in (
            ({'connections': [cable()]}, design(('Leaf01', 'C9', '2'))),
            ({'connections': [cable(), cable(rack='C9')]}, {}),
        ):
            result = locations.resolve_locations(p2p, simple)
            self.assertNotIn('leaf01', result['locations'])
            self.assertEqual(len(result['conflicts']), 1)
            self.assertIn('leaf01', result['conflicts'][0]['hostname'].lower())
            self.assertIn('server01', result['locations'])

    def test_malformed_optional_metadata_is_tolerated(self):
        malformed = [None, [], 'bad', {'connections': None, 'locations': 'bad'}, {'connections': [None], 'locations': [None]}]
        for value in malformed:
            with self.subTest(value=value):
                self.assertEqual(locations.resolve_locations(value, value), {'locations': {}, 'conflicts': []})


class LocationApiTests(unittest.TestCase):
    setUpClass = classmethod(inventory_tests.InventoryApiTests.setUpClass.__func__)
    tearDown = inventory_tests.InventoryApiTests.tearDown
    seed_version = inventory_tests.InventoryApiTests.seed_version
    set_active = inventory_tests.InventoryApiTests.set_active

    def setUp(self):
        inventory_tests.InventoryApiTests.setUp(self)
        self.devices_file = self.root / 'devices.yaml'
        self.devices_file.write_text('devices:\n  192.0.2.1: Leaf01 @leaf\n')

    def run_api(self, action, **env):
        env.setdefault('DEVICES_FILE', self.devices_file)
        return inventory_tests.InventoryApiTests.run_api(self, action, **env)

    def post(self, action, payload, **env):
        path = self.root / 'body.json'
        path.write_text(json.dumps(payload))
        return self.run_api(action, POST_DATA_FILE=path, **env)

    def upload(self, content=b'Hostname,Rack,U-Pos\nleaf01,C1,6-7\nserver01,C2,12\n'):
        response = self.post('upload', {'kind': 'locations', 'filename': 'rack.csv',
                                      'content_b64': base64.b64encode(content).decode()})
        self.assertTrue(response['success'], response)
        return response['version']

    def test_template_upload_preview_explicit_activation_and_published_copy(self):
        template = self.run_api('location-template')
        self.assertTrue(template['success'], template)
        self.assertEqual(len(locations.parse_upload(template['content'].encode(), template['filename'])['locations']), 2)
        version = self.upload()
        listed = self.run_api('list')['versions']['locations']
        self.assertEqual(listed[0]['summary']['total_locations'], 2)
        self.assertFalse(listed[0]['active'])
        self.assertEqual(self.run_api('device-locations')['locations'], {})
        preview = self.run_api('preview-locations', QS_VERSION=version)
        self.assertTrue(preview['can_activate'], preview)
        self.assertEqual(preview['counts'], {'total': 2, 'matched': 1, 'unmatched': 1, 'conflicts': 0})
        self.assertEqual([r['match'] for r in preview['rows']], ['matched', 'unmatched'])
        refused = self.post('activate', {'kind': 'locations', 'version': version})
        self.assertFalse(refused['success'])
        self.assertIn('preview', refused['error'])
        activated = self.post('activate', {'kind': 'locations', 'version': version, 'confirm': preview['token']})
        self.assertTrue(activated['success'], activated)
        self.assertTrue(activated['published'], activated)
        published = self.web_root / 'monitor-results' / 'active-locations.json'
        self.assertEqual(json.loads(published.read_text())['_active_version'], version)
        resolved = self.run_api('device-locations')
        self.assertEqual(set(resolved['locations']), {'leaf01', 'server01'})
        self.assertEqual(resolved['locations']['leaf01']['unit'], '6-7')
        published.unlink()
        self.assertTrue(self.run_api('list')['republished']['locations'])
        self.assertTrue(published.exists())
        self.assertFalse(self.post('delete', {'kind': 'locations', 'version': version})['success'])

    def test_preview_token_invalidated_by_changed_active_p2p(self):
        version = self.upload()
        preview = self.run_api('preview-locations', QS_VERSION=version)
        p2p_version = '1700000001-aaaaaaaa.json'
        self.seed_version('p2p', p2p_version, {'connections': [cable()]})
        self.set_active('p2p', p2p_version)
        stale = self.post('activate', {'kind': 'locations', 'version': version, 'confirm': preview['token']})
        self.assertFalse(stale['success'], stale)
        self.assertIn('stale', stale['error'])
        updated = self.run_api('preview-locations', QS_VERSION=version)
        self.assertNotEqual(updated['token'], preview['token'])

    def test_location_conflict_preview_blocks_activation_and_preserves_current(self):
        p2p_version = '1700000001-aaaaaaaa.json'
        self.seed_version('p2p', p2p_version, {'connections': [cable()]})
        self.set_active('p2p', p2p_version)
        version = self.upload(b'Hostname,Rack,U-Pos\nleaf01,C9,2\n')
        preview = self.run_api('preview-locations', QS_VERSION=version)
        self.assertFalse(preview['can_activate'], preview)
        self.assertEqual(preview['counts']['conflicts'], 1)
        self.assertTrue(preview['rows'][0]['conflict'])
        activated = self.post('activate', {'kind': 'locations', 'version': version, 'confirm': preview['token']})
        self.assertFalse(activated['success'], activated)
        self.assertEqual(self.run_api('device-locations')['locations']['leaf01']['source'], 'p2p')

    def test_p2p_activation_stays_available_and_reports_metadata_conflict(self):
        version = self.upload(b'Hostname,Rack,U-Pos\nleaf01,C9,2\n')
        preview = self.run_api('preview-locations', QS_VERSION=version)
        activated = self.post('activate', {'kind': 'locations', 'version': version, 'confirm': preview['token']})
        self.assertTrue(activated['success'], activated)
        p2p_version = '1700000001-aaaaaaaa.json'
        self.seed_version('p2p', p2p_version, {'connections': [cable()]})
        activated = self.post('activate', {'kind': 'p2p', 'version': p2p_version})
        self.assertTrue(activated['success'], activated)
        self.assertEqual(len(activated['warnings']), 1)
        self.assertNotIn('leaf01', self.run_api('device-locations')['locations'])

    def test_unrelated_p2p_conflict_warns_without_blocking_mapping(self):
        p2p_version = '1700000001-aaaaaaaa.json'
        self.seed_version('p2p', p2p_version, {'connections': [cable(), cable(rack='C9')]})
        self.set_active('p2p', p2p_version)
        version = self.upload(b'Hostname,Rack,U-Pos\nnew-host,C5,20\n')
        preview = self.run_api('preview-locations', QS_VERSION=version)
        self.assertTrue(preview['success'], preview)
        self.assertTrue(preview['can_activate'], preview)
        self.assertEqual(preview['conflicts'], [])
        self.assertEqual(preview['counts']['conflicts'], 0)
        self.assertFalse(preview['rows'][0]['conflict'])
        self.assertTrue(any('outside this mapping' in warning for warning in preview['warnings']))
        activated = self.post('activate', {'kind': 'locations', 'version': version, 'confirm': preview['token']})
        self.assertTrue(activated['success'], activated)
        effective = self.run_api('device-locations')
        self.assertEqual(effective['locations']['new-host']['rack'], 'C5')
        self.assertNotIn('leaf01', effective['locations'])
        self.assertEqual(len(effective['conflicts']), 1)

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is required for invalid-YAML checks')
    def test_malformed_existing_inventory_is_a_preview_warning(self):
        version = self.upload()
        for invalid in ('devices: [\n', 'devices: [leaf01]\n', '- not-an-inventory\n'):
            with self.subTest(invalid=invalid):
                self.devices_file.write_text(invalid)
                preview = self.run_api('preview-locations', QS_VERSION=version)
                self.assertTrue(preview['success'], preview)
                self.assertTrue(preview['can_activate'], preview)
                self.assertEqual(preview['counts']['matched'], 0)
                self.assertTrue(any('devices.yaml could not be parsed' in warning for warning in preview['warnings']))
                self.assertFalse(any('not present' in warning for warning in preview['warnings']))

    def test_bad_canonical_upload_cannot_bypass_validation(self):
        invalid = self.post('upload', {'kind': 'locations', 'filename': 'rack.json',
                                       'data': design(('leaf01', 'C1', '7-6'))})
        self.assertFalse(invalid['success'], invalid)
        self.assertEqual(self.run_api('list')['versions']['locations'], [])


if __name__ == '__main__':
    unittest.main()
