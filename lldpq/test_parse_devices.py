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


if __name__ == "__main__":
    unittest.main()
