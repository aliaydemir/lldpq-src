"""Download-server authorities differ from collector-local SSH destinations."""
import unittest
from lldpq.addressing import http_url, normalize_address, normalize_server_ref


class DownloadAddressingTests(unittest.TestCase):
    def test_ipv4_dns_and_ports_remain_usable(self):
        for value, canonical in (
            ('192.0.2.10', '192.0.2.10'), ('192.0.2.10:8080', '192.0.2.10:8080'),
            ('Image.Example', 'image.example'), ('image.example.:80', 'image.example.:80'),
            ('lldpq:00443', 'lldpq:443'),
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_server_ref(value), canonical)

    def test_ipv6_authorities_are_unambiguous_and_canonical(self):
        for value, canonical in (
            ('2001:0db8:0:0:0:0:0:10', '[2001:db8::10]'),
            ('[2001:db8::10]', '[2001:db8::10]'),
            ('[FD00::10]:8080', '[fd00::10]:8080'),
            ('2001:db8::10:8080', '[2001:db8::10:8080]'),
            ('::ffff:c000:20a', '[::ffff:192.0.2.10]'),
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_server_ref(value), canonical)
                self.assertEqual(normalize_server_ref(canonical), canonical)

    def test_invalid_or_nonportable_download_destinations_are_rejected(self):
        for value in ('', None, 'http://image.example', 'host/path', 'user@host',
                      'host?query', 'host#fragment', 'bad_host', '-host', 'host..test',
                      'host:0', 'host:65536', 'host:', '[fd00::1]:-1', '[fd00::1]:xx',
                      '[192.0.2.1]', '2001:::1', '[fd00::1', '[fd00::1]tail',
                      'fe80::1', '[fe80::1%eth0]', 'fd00::1%eth0', '::', 'ff02::1',
                      '0.0.0.0', '224.0.0.1', '999.1.1.1', 'host\nname',
                      '[::ffff:0.0.0.0]', '[::ffff:224.0.0.1]'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_server_ref(value)
        # A local scope is still valid for SSH/SCP device connections.
        self.assertEqual(normalize_address('fe80::1%eth0'), 'fe80::1%eth0')

    def test_download_urls_keep_server_and_path_separate(self):
        self.assertEqual(http_url('2001:db8::10', 'image.bin'), 'http://[2001:db8::10]/image.bin')
        self.assertEqual(http_url('[fd00::10]:8080', '/provision-uploads/job.ztp'),
                         'http://[fd00::10]:8080/provision-uploads/job.ztp')
        self.assertEqual(http_url('192.0.2.10', 'generated_config_folder/leaf.yaml'),
                         'http://192.0.2.10/generated_config_folder/leaf.yaml')
        self.assertEqual(http_url('image.example', 'name?x#y.bin'),
                         'http://image.example/name%3Fx%23y.bin')
        with self.assertRaises(ValueError):
            http_url('image.example', '../image.bin')


if __name__ == '__main__':
    unittest.main()
