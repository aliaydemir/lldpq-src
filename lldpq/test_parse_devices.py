#!/usr/bin/env python3
"""Per-entry validation contracts for parse_devices.py.

Two regressions are pinned here:

1. A typo'd 'hostname:' key in the extended device format used to fall back
   to a device literally named 'unknown' that was collected and SSH'd, and
   two such typos surfaced as a confusing duplicate-hostname error instead
   of naming the real problem.  The parser must fail closed with a clear
   per-entry 'missing hostname key' error (load_devices.sh consumers rely
   on the non-zero exit).

2. 'role: false' parses as YAML bool False, which skipped the '.lower()'
   branch and serialized as the string 'False' — a role that '-r false'
   (lowercased) could never match.  False and null now mean "no role";
   any other scalar is normalized with str(value).lower().
"""

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PARSER = ROOT / "lldpq" / "parse_devices.py"


def run_parser(yaml_text, *args):
    with tempfile.TemporaryDirectory() as directory:
        yaml_file = Path(directory) / "devices.yaml"
        yaml_file.write_text(yaml_text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(PARSER), "-f", str(yaml_file), *args],
            capture_output=True,
            text=True,
            check=False,
        )


def nul_records(stdout):
    """Split the NUL-delimited stream into (ip, username, hostname, role)."""
    fields = stdout.split("\0")
    assert fields[-1] == ""
    fields = fields[:-1]
    assert len(fields) % 4 == 0
    return [tuple(fields[i:i + 4]) for i in range(0, len(fields), 4)]


class MissingHostnameTests(unittest.TestCase):
    def test_typoed_hostname_key_fails_closed(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostame: Spine1\n"
            "    username: admin\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Device 10.10.100.10: missing hostname key", result.stderr)
        # No 'unknown' device may reach the collectors.
        self.assertEqual(result.stdout, "")

    def test_two_typos_do_not_report_duplicate_unknown(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostame: Spine1\n"
            "  10.10.100.11:\n"
            "    hostame: Spine2\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("missing hostname key", result.stderr)
        self.assertNotIn("Duplicate hostname", result.stderr)
        self.assertNotIn("unknown", result.stderr)

    def test_explicit_null_hostname_fails_closed(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname:\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Device 10.10.100.10: missing hostname key", result.stderr)

    def test_valid_extended_entry_still_parses(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname: Spine1\n"
            "    username: admin\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            nul_records(result.stdout),
            [("10.10.100.10", "admin", "Spine1", "")],
        )


class RoleNormalizationTests(unittest.TestCase):
    def test_role_false_means_no_role(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname: Spine1\n"
            "    role: false\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            nul_records(result.stdout),
            [("10.10.100.10", "cumulus", "Spine1", "")],
        )

    def test_role_false_is_not_filterable_as_string(self):
        # Before the fix the role serialized as 'False', which '-r false'
        # (lowercased) could never match either — now it is simply no role.
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname: Spine1\n"
            "    role: false\n",
            "--format", "nul", "-r", "false",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("No devices found with role", result.stderr)

    def test_non_string_scalar_roles_are_lowercased_strings(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname: Spine1\n"
            "    role: true\n"
            "  10.10.100.11:\n"
            "    hostname: Leaf1\n"
            "    role: SPINE\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            nul_records(result.stdout),
            [
                ("10.10.100.10", "cumulus", "Spine1", "true"),
                ("10.10.100.11", "cumulus", "Leaf1", "spine"),
            ],
        )

    def test_role_filter_matches_normalized_role(self):
        result = run_parser(
            "devices:\n"
            "  10.10.100.10:\n"
            "    hostname: Spine1\n"
            "    role: SPINE\n"
            "  10.10.100.12: Leaf1 @leaf\n",
            "--format", "nul", "-r", "spine",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            nul_records(result.stdout),
            [("10.10.100.10", "cumulus", "Spine1", "spine")],
        )


class IPv6InventoryTests(unittest.TestCase):
    def test_mixed_inventory_preserves_legacy_names_and_normalizes_ipv6(self):
        result = run_parser(
            "defaults:\n  username: admin\n"
            "devices:\n"
            "  192.0.2.10: IPv4-Switch @oob\n"
            "  '2001:0DB8:0:0:0:0:0:10': IPv6-Switch @oob\n"
            "  switch.example.test: DNS-Switch\n"
            "  ssh_alias: Alias-Switch\n"
            "  'fd00:100::11':\n    hostname: ULA-Switch\n    username: cumulus\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(nul_records(result.stdout), [
            ("192.0.2.10", "admin", "IPv4-Switch", "oob"),
            ("2001:db8::10", "admin", "IPv6-Switch", "oob"),
            ("switch.example.test", "admin", "DNS-Switch", ""),
            ("ssh_alias", "admin", "Alias-Switch", ""),
            ("fd00:100::11", "cumulus", "ULA-Switch", ""),
        ])

    def test_equivalent_ipv6_addresses_fail_before_any_output(self):
        config = (
            "devices:\n"
            "  192.0.2.10: Good-Switch\n"
            "  '2001:db8::10': First-Switch\n"
            "  '2001:0DB8:0000:0000:0000:0000:0000:0010': Second-Switch\n"
        )
        for output_format in ("nul", "json", "bash"):
            with self.subTest(output_format=output_format):
                result = run_parser(config, "--format", output_format)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Duplicate device address", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_dual_stack_does_not_create_two_records_with_same_hostname(self):
        result = run_parser(
            "devices:\n  192.0.2.10: OOB-01\n  '2001:db8::10': oob-01\n",
            "--format", "nul",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Duplicate hostname", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_link_local_addresses_keep_the_local_interface(self):
        result = run_parser(
            "devices:\n  'FE80:0:0:0:0:0:0:1%eth0': Link1\n  'fe80::1%eth1': Link2\n",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([device["address"] for device in json.loads(result.stdout)], [
            "fe80::1%eth0", "fe80::1%eth1",
        ])

    def test_invalid_or_ambiguous_literal_fails_entire_inventory(self):
        for address in ("2001:::1", "2001:db8::gg", "192.0.2.999", "fe80::1", "fe80::1%eth0%eth1"):
            with self.subTest(address=address):
                result = run_parser(
                    f"devices:\n  192.0.2.10: Good-Switch\n  '{address}': Invalid-Switch\n",
                    "--format", "nul",
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("Invalid device address", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_absolute_path_import_works_outside_project_directory(self):
        code = (
            "import importlib.util, json\n"
            f"spec = importlib.util.spec_from_file_location('isolated_devices_parser', {str(PARSER)!r})\n"
            "parser = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(parser)\n"
            "print(json.dumps(parser.get_all_devices({'devices': {'2001:0DB8::10': 'OOB-01'}})))\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-c", code], cwd=directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [["2001:db8::10", "cumulus", "OOB-01", None]])


if __name__ == "__main__":
    unittest.main()
