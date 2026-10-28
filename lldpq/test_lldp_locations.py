"""Location enrichment must agree across the table and both CSV downloads."""
import json
import shutil
import subprocess
import unittest

from test_export_artifacts import (
    GOLDEN_INI, GOLDEN_ALIASES, LLDP_HTML, _csv_rows,
)
import test_export_artifacts as export_tests
import device_locations
import lldp_export
from lldp_report import parse_lldp_report


LOCATIONS = {"format": "lldpq-locations-v1", "locations": [
    {"hostname": " LEAF-01 ", "rack": "C1", "unit": "6-7"},
    {"hostname": "spine-01", "rack": "C2", "unit": "12-13"},
    {"hostname": "spine-02", "rack": "C3", "unit": "18"},
]}
P2P = {"connections": [{
    "source_name": "leaf-01", "source_port": "swp1", "source_rack": "C1", "source_ru": "6-7",
    "dest_name": "spine-01", "dest_port": "swp10", "dest_rack": "C2", "dest_ru": "12-13",
    "sheet_name": "Cabling", "row_number": 8, "seq": "20",
}]}


class LocationExportTests(unittest.TestCase):
    def setUp(self):
        self.report = parse_lldp_report(GOLDEN_INI)

    def rows(self, **kwargs):
        return _csv_rows(lldp_export.build_csv(self.report, **kwargs))

    def test_wrong_neighbor_has_its_own_location(self):
        rows = self.rows(location_design=LOCATIONS)
        mismatch = next(row for row in rows[1:] if row[1] == 'swp6')
        self.assertEqual(mismatch[12:], ['C1', '6-7', 'C2', '12-13', 'C3', '18'])
        missing = next(row for row in rows[1:] if row[1] == 'swp4')
        self.assertEqual(missing[12:], ['C1', '6-7', 'C2', '12-13', '', ''])

    def test_p2p_and_simple_mapping_produce_same_location_columns(self):
        simple = self.rows(location_design=LOCATIONS)
        combined = self.rows(p2p_design=P2P, location_design=LOCATIONS)
        self.assertEqual([r[12:] for r in simple], [r[12:] for r in combined])
        self.assertEqual(next(r for r in combined[1:] if r[1] == 'swp1')[9:12], ['Cabling', '8', '20'])
        self.assertEqual(next(r for r in self.rows(p2p_design=P2P)[1:] if r[1] == 'swp1')[12:],
                         ['C1', '6-7', 'C2', '12-13', 'C2', '12-13'])

    def test_display_aliases_never_change_location_join(self):
        raw = self.rows(location_design=LOCATIONS)
        aliased = self.rows(location_design=LOCATIONS, aliases=GOLDEN_ALIASES)
        self.assertNotEqual(raw[1][0], aliased[1][0])
        self.assertEqual([r[12:] for r in raw], [r[12:] for r in aliased])

    def test_conflicts_do_not_choose_an_arbitrary_location(self):
        conflicting = {"locations": [{"hostname": "leaf-01", "rack": "X1", "unit": "9"}]}
        rows = self.rows(p2p_design=P2P, location_design=conflicting)
        self.assertTrue(all(r[12:14] == ['', ''] for r in rows[1:]))
        resolved = device_locations.resolve_locations(P2P, conflicting)
        self.assertEqual(resolved['conflicts'][0]['hostname'], 'leaf-01')

    def test_invalid_optional_json_does_not_break_report(self):
        for malformed in ([], ['invalid'], 'invalid', {'locations': None}):
            with self.subTest(malformed=malformed):
                self.assertEqual(self.rows(location_design=malformed), self.rows())

    @unittest.skipUnless(shutil.which('node'), 'Node.js required for browser parity')
    def test_browser_csv_bytes_match_headless_for_each_source_and_alias_mode(self):
        def block(start, end):
            return LLDP_HTML.split(start, 1)[1].split(end, 1)[0]
        functions = 'function connectionLocationValues(connection)' + block(
            'function connectionLocationValues(connection)', 'async function loadDeviceLocations()')
        functions += 'const CSV_HEADERS' + block('const CSV_HEADERS', 'function renderedConnectionsInTableOrder()')
        for design in (None, P2P):
            for aliases in (None, GOLDEN_ALIASES):
                with self.subTest(p2p=bool(design), aliases=bool(aliases)):
                    records = []
                    for row, status, health in lldp_export.classified_rows(self.report):
                        records.append(dict(localDevice=row.local_device, localPort=row.local_port,
                            portStatus=row.port_status, expectedDevice=row.expected_device,
                            expectedPort=row.expected_port, actualDevice=row.actual_device,
                            actualPort=row.actual_port, renderedStatus=status, renderedHealth=health))
                    script = '''
const input = JSON.parse(require('fs').readFileSync(0,'utf8'));
const deviceLocations = input.locations;
const deviceAliasLc = input.aliases.devices, portAliasLc = input.aliases.interfaces;
const displayValue = v => v == null || ['', 'none', 'n/a'].includes(String(v).trim().toLowerCase()) ? 'N/A' : String(v).trim();
const aliasedLabel = (v, m) => m[displayValue(v).toLowerCase()] || displayValue(v);
const determineLLDPStatus = c => ({status:c.renderedStatus,health:c.renderedHealth});
const activeP2pDesignFor = c => c.localPort === 'swp1' ? input.design : null;
''' + functions + '\nprocess.stdout.write(buildLLDPCSV(input.records));'
                    result = subprocess.run(['node', '-e', script], input=json.dumps({
                        'locations': device_locations.resolve_locations(design, LOCATIONS)['locations'],
                        'aliases': lldp_export.alias_maps(aliases), 'records': records,
                        'design': design['connections'][0] if design else None,
                    }).encode(), capture_output=True, check=True)
                    self.assertEqual(result.stdout.decode(), lldp_export.build_csv(
                        self.report, p2p_design=design, aliases=aliases, location_design=LOCATIONS))


class LocationCgiTests(unittest.TestCase):
    setUp = export_tests.LLDPExportCgiTests.setUp
    _get = export_tests.LLDPExportCgiTests._get

    def test_installed_export_reads_published_location_mapping(self):
        directory = self.web / 'monitor-results'
        directory.mkdir()
        (directory / 'active-locations.json').write_text(json.dumps(LOCATIONS))
        # Use the existing CGI harness to exercise real configuration/path handling.
        _headers, output = self._get()
        self.assertIn('C1,6-7,C2,12-13', output)

    def seed_selection(self, kind, data):
        directory = self.web.parent / 'ai' / 'inventory' / kind
        directory.mkdir(parents=True)
        version = '1793025608-12345678.json'
        (directory / 'active.json').write_text(json.dumps({'active': version}))
        (directory / version).write_text(json.dumps({'data': data}))

    def test_durable_inventory_selection_survives_report_tree_replacement(self):
        self.seed_selection('locations', LOCATIONS)
        self.seed_selection('p2p', P2P)
        # No public active files: a full monitoring run just replaced the tree.
        _headers, output = self._get()
        expected = lldp_export.build_csv(parse_lldp_report(GOLDEN_INI),
            p2p_design=P2P, location_design=LOCATIONS)
        self.assertEqual(output, expected)

    def test_durable_selection_wins_over_an_old_published_cache(self):
        self.seed_selection('locations', LOCATIONS)
        directory = self.web / 'monitor-results'
        directory.mkdir()
        (directory / 'active-locations.json').write_text(json.dumps({
            'locations': [{'hostname': 'leaf-01', 'rack': 'OLD', 'unit': '1'}]}))
        _headers, output = self._get()
        self.assertNotIn('OLD', output)
        self.assertIn('C1,6-7,C2,12-13', output)


if __name__ == '__main__':
    unittest.main()
