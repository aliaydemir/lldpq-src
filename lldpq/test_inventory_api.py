#!/usr/bin/env python3
"""Contract tests for the inventory-api.sh python heredoc (html/inventory-api.sh).

The heredoc is extracted and executed as a real subprocess with the same env
contract CGI provides (ACTION/KIND/QS_* + state dirs pointed at a tempdir),
mirroring the extract-heredoc pattern of test_lldpq_config_write.py.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_API = ROOT / "html" / "inventory-api.sh"


def extract_heredoc(source: str, marker: str) -> str:
    lines = source.splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if f"<< '{marker}'" in line or f'<< "{marker}"' in line or f"<< {marker}" in line
    ) + 1
    end = next(index for index in range(start, len(lines)) if lines[index] == marker)
    return "\n".join(lines[start:end]) + "\n"


class InventoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = INVENTORY_API.read_text(encoding="utf-8")
        cls.block = extract_heredoc(source, "PYTHON_END")
        compile(cls.block, str(INVENTORY_API), "exec")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.web_root = self.root / "web"
        self.state_dir = self.root / "ai"
        self.web_root.mkdir()
        self.state_dir.mkdir()
        self.script = self.root / "inventory_api_block.py"
        self.script.write_text(self.block, encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_api(self, action, **env_overrides):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "WEB_ROOT": str(self.web_root),
            "AI_STATE_DIR": str(self.state_dir),
            "SETUP_SAFETY": str(ROOT / "html" / "setup_safety.py"),
            "LLDPQ_DIR": str(self.root),
            "ACTION": action,
        }
        env.update({k: str(v) for k, v in env_overrides.items()})
        proc = subprocess.run(
            [sys.executable, str(self.script)],
            env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        try:
            return json.loads(proc.stdout)
        except ValueError:
            self.fail("non-JSON response: %r (stderr: %r)" % (proc.stdout, proc.stderr))

    def seed_version(self, kind, name, data, filename="design.xlsx"):
        directory = self.state_dir / "inventory" / kind
        directory.mkdir(parents=True, exist_ok=True)
        ts = int(name.split("-", 1)[0])
        wrapper = {
            "kind": kind,
            "filename": filename,
            "ts": ts,
            "sha": name.split("-", 1)[1].split(".")[0],
            "summary": {},
            "data": data,
        }
        (directory / name).write_text(json.dumps(wrapper), encoding="utf-8")
        return directory / name

    def set_active(self, kind, name):
        directory = self.state_dir / "inventory" / kind
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "active.json").write_text(
            json.dumps({"active": name, "ts": 1}), encoding="utf-8"
        )

    # ---- delete ----------------------------------------------------------

    def test_delete_removes_non_active_version(self):
        active = "1700000001-aaaaaaaa.json"
        stale = "1700000000-bbbbbbbb.json"
        self.seed_version("p2p", active, {"connections": []})
        stale_path = self.seed_version("p2p", stale, {"connections": []})
        self.set_active("p2p", active)

        result = self.run_api("delete", KIND="p2p", QS_VERSION=stale)

        self.assertTrue(result.get("success"), result)
        self.assertFalse(stale_path.exists())
        remaining = [v["version"] for v in result.get("versions", [])]
        self.assertEqual(remaining, [active])

    def test_delete_refuses_active_version(self):
        active = "1700000001-aaaaaaaa.json"
        active_path = self.seed_version("ipam", active, {"fabric": []})
        self.set_active("ipam", active)

        result = self.run_api("delete", KIND="ipam", QS_VERSION=active)

        self.assertFalse(result.get("success"))
        self.assertIn("active", result.get("error", "").lower())
        self.assertTrue(active_path.exists())

    def test_delete_rejects_malformed_version_id(self):
        result = self.run_api("delete", KIND="p2p", QS_VERSION="../../etc/passwd")
        self.assertFalse(result.get("success"))
        self.assertIn("invalid version id", result.get("error", ""))

    def test_delete_missing_version_fails(self):
        result = self.run_api("delete", KIND="p2p",
                              QS_VERSION="1700000000-cccccccc.json")
        self.assertFalse(result.get("success"))
        self.assertIn("not found", result.get("error", ""))

    def test_delete_accepts_json_body(self):
        active = "1700000001-aaaaaaaa.json"
        stale = "1700000000-bbbbbbbb.json"
        self.seed_version("p2p", active, {"connections": []})
        stale_path = self.seed_version("p2p", stale, {"connections": []})
        self.set_active("p2p", active)
        body = self.root / "body.json"
        body.write_text(json.dumps({"kind": "p2p", "version": stale}),
                        encoding="utf-8")

        result = self.run_api("delete", POST_DATA_FILE=body)

        self.assertTrue(result.get("success"), result)
        self.assertFalse(stale_path.exists())

    # ---- bootstrap-status probe -------------------------------------------

    def test_bootstrap_status_probe_is_clean_and_unavailable(self):
        result = self.run_api("bootstrap-status")
        self.assertTrue(result.get("success"))
        self.assertFalse(result.get("available"))

    # ---- validate (ipam mgmt_ip checks) -----------------------------------

    def test_validate_ipam_flags_mgmt_ip_issues(self):
        version = "1700000002-dddddddd.json"
        data = {
            "fabric": [
                {"hostname": "leaf01", "mgmt_ip": "10.0.0.1", "role": "leaf"},
                {"hostname": "leaf02", "mgmt_ip": "10.0.0.1", "role": "leaf"},
                {"hostname": "leaf03", "mgmt_ip": "10.0.0.999", "role": "leaf"},
                {"hostname": "leaf04", "role": "leaf"},
                {"hostname": "leaf05", "mgmt_ip": "10.0.0.5", "role": "leaf"},
            ],
            "subnets": [], "hosts": [], "l3_links": [], "warnings": [],
        }
        self.seed_version("ipam", version, data)
        self.set_active("ipam", version)

        result = self.run_api("validate", KIND="ipam")

        self.assertTrue(result.get("success"), result)
        issues = result["report"]["issues"]
        kinds = {i["kind"] for i in issues}
        self.assertIn("duplicate-mgmt-ip", kinds)
        self.assertIn("invalid-mgmt-ip", kinds)
        self.assertIn("missing-mgmt-ip", kinds)
        dup = next(i for i in issues if i["kind"] == "duplicate-mgmt-ip")
        self.assertEqual(dup["severity"], "error")
        self.assertIn("leaf01", dup["message"])
        self.assertIn("leaf02", dup["message"])
        invalid = next(i for i in issues if i["kind"] == "invalid-mgmt-ip")
        self.assertEqual(invalid["severity"], "error")
        self.assertIn("leaf03", invalid["message"])
        missing = next(i for i in issues if i["kind"] == "missing-mgmt-ip")
        self.assertEqual(missing["severity"], "warning")
        self.assertIn("leaf04", missing["message"])
        # A clean record raises nothing about leaf05.
        self.assertFalse(any("leaf05" in i["message"] for i in issues))

    def test_validate_ipam_clean_design_has_no_issues(self):
        version = "1700000003-eeeeeeee.json"
        data = {
            "fabric": [
                {"hostname": "leaf01", "mgmt_ip": "10.0.0.1", "role": "leaf"},
                {"hostname": "spine01", "mgmt_ip": "10.0.0.2", "role": "spine"},
            ],
            "subnets": [], "hosts": [], "l3_links": [], "warnings": [],
        }
        self.seed_version("ipam", version, data)
        self.set_active("ipam", version)

        result = self.run_api("validate", KIND="ipam")

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result["report"]["issues"], [])

    # ---- topology preview source_version -----------------------------------

    def test_topology_preview_reports_top_level_source_version(self):
        version = "1700000004-ffffffff.json"
        data = {
            "connections": [
                {"source_name": "leaf01", "source_port": "swp1",
                 "dest_name": "spine01", "dest_port": "swp1",
                 "connection_type": "fabric", "network_type": "eth"},
            ],
        }
        self.seed_version("p2p", version, data)
        self.set_active("p2p", version)

        result = self.run_api("generate-topology", QS_MODE="preview")

        self.assertTrue(result.get("success"), result)
        self.assertEqual(result.get("source_version"), version)
        self.assertIn(" -- ", result.get("preview", ""))


if __name__ == "__main__":
    unittest.main()
