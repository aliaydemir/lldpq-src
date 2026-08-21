#!/usr/bin/env python3
"""nv-validate must survive malformed-but-parseable YAML per file, not abort the run."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT = SCRIPT_DIR / "nv-validate.py"

FIXTURES = {
    # Unquoted MAC with all octets <=59 parses as a YAML-1.1 sexagesimal int
    "leaf-mac.yaml": (
        "- set:\n"
        "    mlag:\n"
        "      enable: on\n"
        "      peer-ip: linklocal\n"
        "      mac-address: 44:38:39:00:00:01\n"
    ),
    # dict value at an on/off key -> unhashable set-membership TypeError
    "leaf-onoff.yaml": (
        "- set:\n"
        "    interface:\n"
        "      swp1:\n"
        "        link:\n"
        "          auto-negotiate:\n"
        "            some: nested\n"
    ),
    # null vrf under syslog server -> None.lower() AttributeError
    "leaf-vrf.yaml": (
        "- set:\n"
        "    system:\n"
        "      syslog:\n"
        "        server:\n"
        "          1.2.3.4:\n"
        "            vrf: null\n"
    ),
    "leaf-good.yaml": (
        "- set:\n"
        "    system:\n"
        "      hostname: leaf-good\n"
    ),
}
BAD_FILES = ("leaf-mac.yaml", "leaf-onoff.yaml", "leaf-vrf.yaml")


def load_module():
    spec = importlib.util.spec_from_file_location("nv_validate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MalformedYamlSurvivalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        for name, content in FIXTURES.items():
            (root / name).write_text(content, encoding="utf-8")
        cls.proc = subprocess.run(
            [sys.executable, "-B", str(SCRIPT),
             "--dir", cls.tmp.name, "--json", "--no-topology"],
            capture_output=True, text=True,
        )
        cls.output = json.loads(cls.proc.stdout)
        cls.by_name = {Path(f["filename"]).name: f for f in cls.output["files"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_run_not_aborted_and_exit_code_reflects_errors(self):
        self.assertEqual(self.proc.returncode, 1, self.proc.stderr)
        self.assertNotIn("Traceback", self.proc.stderr)
        self.assertEqual(self.output["summary"]["total_files"], len(FIXTURES))
        self.assertFalse(self.output["valid"])

    def test_bad_files_report_per_file_errors(self):
        for name in BAD_FILES:
            entry = self.by_name[name]
            self.assertFalse(entry["valid"], name)
            self.assertGreater(entry["errors"], 0, name)
            self.assertTrue(
                any(i["severity"] == "ERROR" for i in entry["issues"]), name
            )

    def test_misparsed_mac_reported_as_invalid_mac(self):
        messages = [i["message"] for i in self.by_name["leaf-mac.yaml"]["issues"]]
        self.assertTrue(
            any("Invalid MLAG system MAC" in m for m in messages), messages
        )

    def test_healthy_file_still_validated(self):
        entry = self.by_name["leaf-good.yaml"]
        self.assertTrue(entry["valid"])
        self.assertEqual(entry["errors"], 0)

    def test_validator_internal_error_reported_per_file(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "leaf-boom.yaml"
            target.write_text(FIXTURES["leaf-good.yaml"], encoding="utf-8")
            original = module.NVUEValidator.validate

            def boom(self, yaml_content, filename):
                raise RuntimeError("boom")

            module.NVUEValidator.validate = boom
            try:
                result = module.validate_file(target)
            finally:
                module.NVUEValidator.validate = original
        self.assertFalse(result.is_valid)
        self.assertTrue(
            any("validator internal error" in i.message for i in result.issues),
            [str(i) for i in result.issues],
        )


if __name__ == "__main__":
    unittest.main()
