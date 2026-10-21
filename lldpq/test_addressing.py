#!/usr/bin/env python3
"""Management addresses must stay deterministic across inventory consumers."""

import unittest

if __package__:
    from .addressing import address_family, address_sort_key, normalize_address
else:
    from addressing import address_family, address_sort_key, normalize_address


class NormalizeAddressTests(unittest.TestCase):
    def test_ipv4_and_ipv6_canonical_forms(self):
        for value, expected in (
            ("192.0.2.10", "192.0.2.10"),
            (" 2001:0DB8:0000:0000:0000:0000:0000:0010 ", "2001:db8::10"),
            ("fd00:1234::1", "fd00:1234::1"),
            ("::1", "::1"),
            ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
            ("::ffff:c000:201", "::ffff:192.0.2.1"),
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_address(value), expected)

    def test_link_local_scope_is_required_and_preserved(self):
        for value, expected in (
            ("FE80:0:0:0:0:0:0:1%eth0", "fe80::1%eth0"),
            ("fe80::1%en0", "fe80::1%en0"),
            ("fe80::1%Vlan100", "fe80::1%Vlan100"),
            ("fe80::1%bond0.100", "fe80::1%bond0.100"),
            ("fe80::1%3", "fe80::1%3"),
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize_address(value), expected)
        with self.assertRaisesRegex(ValueError, "requires a local interface"):
            normalize_address("fe80::1")

    def test_safe_existing_ssh_names_remain_unchanged(self):
        for value in ("switch.example.test", "OOB-01", "ssh_alias", "switch.example.test.", "123"):
            with self.subTest(value=value):
                self.assertEqual(normalize_address(value, allow_hostname=True), value)
                with self.assertRaises(ValueError):
                    normalize_address(value)

    def test_malformed_addresses_are_never_treated_as_dns_names(self):
        for value in (
            "2001:db8::gg", "2001:::1", "2001:db8::1::2", "192.0.2.999",
            "192.000.2.1", "[2001:db8::1]", "[2001:db8::1]:22",
            "fe80::1%", "fe80::1%eth0%en0", "fe80::1%eth 0",
            "fe80::1%/eth0", "fe80::1%-eth0", "192.0.2.1%eth0",
            "switch%eth0", "-switch", "2001:db8::1/64", "", "a\x00b", "a\nb",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_address(value, allow_hostname=True)

    def test_non_string_values_are_rejected(self):
        for value in (None, False, 123, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_address(value, allow_hostname=True)


class FamilyAndSortingTests(unittest.TestCase):
    def test_family_classifies_without_requiring_connectable_scope(self):
        for value, expected in (
            ("192.0.2.1", 4), ("2001:db8::1", 6), ("fe80::1%eth0", 6),
            ("fe80::1", 6), ("switch.example.test", 0), (None, 0), ("broken::g", 0),
        ):
            with self.subTest(value=value):
                self.assertEqual(address_family(value), expected)

    def test_numeric_sort_preserves_scope_and_handles_legacy_names(self):
        values = ["2001:db8::10", "192.0.2.10", "2001:db8::2", "192.0.2.2", "SWITCH", None]
        self.assertEqual(sorted(values, key=address_sort_key), [
            None, "SWITCH", "192.0.2.2", "192.0.2.10", "2001:db8::2", "2001:db8::10",
        ])
        self.assertEqual(address_sort_key("2001:0DB8:0:0:0:0:0:10"), address_sort_key("2001:db8::10"))
        self.assertNotEqual(address_sort_key("fe80::1%eth0"), address_sort_key("fe80::1%eth1"))


if __name__ == "__main__":
    unittest.main()
