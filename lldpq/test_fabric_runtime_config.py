"""Every CGI config reader accepts installer-generated quoted paths/users."""
import io
import os
from pathlib import Path
import unittest
from unittest import mock


class RuntimeConfigTests(unittest.TestCase):
    def test_all_readers_decode_quotes_without_expanding_values(self):
        source = (Path(__file__).resolve().parents[1] / 'html/fabric-api.sh').read_text()
        readers = source.split('def read_lldpq_conf():\n')[1:]
        self.assertGreater(len(readers), 1)
        config = '\n'.join([
            'LLDPQ_USER="lldpq"', "LLDPQ_DIR='/srv/fabric data'",
            'ANSIBLE_DIR="/srv/ansible data"', 'TELEMETRY_MAX_PARALLEL="12"',
            'PROMETHEUS_URL="http://localhost:9090"',
            'LITERAL=\'$(echo not-executed)\'', 'BROKEN="unterminated',
        ])
        for index, tail in enumerate(readers):
            with self.subTest(reader=index):
                body = 'def read_lldpq_conf():\n' + tail.split('    return conf', 1)[0] + '    return conf\n'
                namespace = {'os': os}
                exec(body, namespace)
                with mock.patch('os.path.exists', return_value=True), \
                     mock.patch('builtins.open', side_effect=lambda *a, **k: io.StringIO(config)):
                    result = namespace['read_lldpq_conf']()
                self.assertEqual(result['LLDPQ_DIR'], '/srv/fabric data')
                self.assertEqual(result['ANSIBLE_DIR'], '/srv/ansible data')
                self.assertEqual(result['LLDPQ_USER'], 'lldpq')
                self.assertEqual(result['TELEMETRY_MAX_PARALLEL'], '12')
                self.assertEqual(result['LITERAL'], '$(echo not-executed)')
                self.assertNotIn('BROKEN', result)
