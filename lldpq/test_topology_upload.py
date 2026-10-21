"""Exercise large topology requests through the real CGI and save helper.

Only privilege switching and the root-owned global lock are replaced with
unprivileged test fixtures. Parsing, stdin transport, revisions and disk writes
use the production implementations, with every writable path in a tempdir.
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "html/setup_safety.py"


class TopologyUploadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.web = self.root / "web"
        self.web.mkdir()
        self.toolbin = self.root / "bin"
        self.toolbin.mkdir()
        self.application = self.root / "application"
        self.application.mkdir()
        (self.application / "topology_edges.py").symlink_to(ROOT / "lldpq/topology_edges.py")
        self.target = self.web / "topology.dot"
        self.target.write_text('graph { "old":"swp1" -- "server":"eth0"; }\n')

        # Never consult a developer's installed config helper or invoke sudo.
        cgi = (ROOT / "html/edit-topology.sh").read_text().replace(
            "/usr/local/bin/lldpq-config", str(self.root / "not-installed")
        )
        (self.web / "edit-topology.sh").write_text(cgi)
        shutil.copyfile(ROOT / "html/auth-guard.sh", self.web / "auth-guard.sh")
        (self.web / "setup_safety.py").write_text(
            "import fcntl, os, sys\n"
            f"sys.path.insert(0, {str(HELPER.parent)!r})\n"
            "import setup_safety\n"
            "def test_global_lock():\n"
            f"    fd = os.open({str(self.root / 'global.lock')!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "    fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "    return fd\n"
            "setup_safety.acquire_global_configuration_lock = test_global_lock\n"
            "sys.exit(setup_safety._main())\n"
        )
        sudo = self.toolbin / "sudo"
        sudo.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "assert args[:3] == ['-n', '-H', '-u'] and args[4] == '/usr/bin/bash'\n"
            f"os.execv({shutil.which('bash')!r}, ['bash', *args[5:]])\n"
        )
        sudo.chmod(0o755)
        (self.toolbin / "python3").symlink_to(sys.executable)
        self.environment = {
            **{k: v for k, v in os.environ.items()
               if not k.startswith('LLDPQ_') and k not in ('POST_DATA', 'HTTP_COOKIE')},
            "PATH": str(self.toolbin) + os.pathsep + os.environ.get("PATH", ""),
            "WEB_ROOT": str(self.web), "LLDPQ_DIR": str(self.application),
            "LLDPQ_AUTH_ROLE": "admin", "LLDPQ_AUTH_USER": "test-admin",
            "LLDPQ_DIRECT_WRITE_STATE_DIR": str(self.root / "journals"),
        }

    def call(self, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        result = subprocess.run(
            ["bash", str(self.web / "edit-topology.sh")], input=body,
            env={**self.environment, "REQUEST_METHOD": "GET" if payload is None else "POST",
                 "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body))},
            capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        headers, response = result.stdout.decode().split("\n\n", 1)
        self.assertIn("Content-Type: application/json", headers)
        return json.loads(response)

    def test_twenty_four_thousand_links_save_reload_and_revision_conflict(self):
        initial = self.call()
        self.assertTrue(initial["success"], initial)
        content = "graph {\n" + "".join(
            f'"site-oob-switch-{i:05d}-management-access":"swp1" -- '
            f'"site-server-{i:05d}-management-controller":"eth0";\n'
            for i in range(24000)
        ) + "}\n"
        self.assertGreater(len(content.encode()), 2 * 1024 * 1024)
        saved = self.call({"content": content, "expected_revision": initial["revision"]})
        self.assertTrue(saved["success"], saved)
        self.assertEqual(self.target.read_text(), content)
        reloaded = self.call()
        self.assertTrue(reloaded["success"], reloaded)
        self.assertEqual(reloaded["content"], content)
        self.assertEqual(reloaded["revision"], saved["revision"])
        conflict = self.call({"content": initial["content"], "expected_revision": initial["revision"]})
        self.assertTrue(conflict.get("conflict"), conflict)
        self.assertEqual(self.target.read_text(), content)
        self.assertEqual(Path(str(self.target) + ".bak").read_text(), initial["content"])

    def test_oversized_topology_is_a_json_error_without_overwriting(self):
        initial = self.call()
        prefix = 'graph {\n"leaf":"swp1" -- "server":"eth0";\n// '
        content = prefix + 'x' * (10 * 1024 * 1024 + 1 - len(prefix) - 3) + '\n}\n'
        result = self.call({"content": content, "expected_revision": initial["revision"]})
        self.assertFalse(result["success"], result)
        self.assertIn("10 MiB", result["error"])
        self.assertEqual(self.target.read_text(), initial["content"])


class TopologyRequestPolicyTests(unittest.TestCase):
    def test_nginx_and_helper_accept_the_same_topology_request_size(self):
        spec = importlib.util.spec_from_file_location("topology_upload_safety", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        site = (ROOT / "etc/nginx/sites-available/lldpq").read_text()
        block = re.search(r"location\s*=\s*/edit-topology\s*\{([^}]+)\}", site).group(1)
        size = re.search(r"client_max_body_size\s+(\d+)m;", block)
        self.assertIsNotNone(size, "Large requests must not inherit nginx's 1 MiB default")
        self.assertEqual(int(size.group(1)) * 1024 * 1024, helper.MAX_TOPOLOGY_REQUEST_BYTES)
        # JSON can escape a one-byte control character into six ASCII bytes.
        self.assertGreater(helper.MAX_TOPOLOGY_REQUEST_BYTES, helper.MAX_TOPOLOGY_BYTES * 6)


if __name__ == "__main__":
    unittest.main()
