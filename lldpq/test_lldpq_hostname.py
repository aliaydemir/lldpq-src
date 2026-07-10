#!/usr/bin/env python3
"""Contracts for the configurable LLDPq dashboard instance name."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LldpqHostnameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = (ROOT / "install.sh").read_text(encoding="utf-8")
        cls.dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
        cls.entrypoint = (ROOT / "docker/docker-entrypoint.sh").read_text(
            encoding="utf-8"
        )
        cls.setup_api = (ROOT / "html/setup-api.sh").read_text(encoding="utf-8")
        cls.setup = (ROOT / "html/setup.html").read_text(encoding="utf-8")
        cls.auth_api = (ROOT / "html/auth-api.sh").read_text(encoding="utf-8")
        cls.auth_js = (ROOT / "html/css/auth.js").read_text(encoding="utf-8")
        cls.start = (ROOT / "html/start.html").read_text(encoding="utf-8")

    def test_config_helper_accepts_hostname(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "lldpq.conf"
            config.write_text(
                "LLDPQ_DIR=/srv/lldpq\nLLDPQ_HOSTNAME=MEL01-LLDPQ-OOB-01\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    str(ROOT / "bin/lldpq-config"),
                    "--config", str(config),
                    "--require-key", "LLDPQ_HOSTNAME",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LLDPQ_HOSTNAME=MEL01-LLDPQ-OOB-01", result.stdout)

    def test_native_and_docker_defaults_are_persistent(self):
        self.assertIn('LLDPQ_DIR|LLDPQ_USER|LLDPQ_SRC|LLDPQ_HOSTNAME|', self.install)
        self.assertIn('_LLDPQ_HOSTNAME_TO_WRITE="${LLDPQ_HOSTNAME:-lldpq}"', self.install)
        self.assertIn("'LLDPQ_HOSTNAME=lldpq'", self.dockerfile)
        self.assertIn('"LLDPQ_HOSTNAME=lldpq"', self.entrypoint)

    def test_setup_can_read_and_write_validated_name(self):
        self.assertIn("'LLDPQ_HOSTNAME', 'LLDPQ_CRON'", self.setup_api)
        self.assertIn("if action == 'get-hostname':", self.setup_api)
        self.assertIn("if action == 'set-hostname':", self.setup_api)
        self.assertIn("LLDPQ_HOSTNAME_RE.fullmatch(value)", self.setup_api)
        self.assertIn('id="lldpq-hostname"', self.setup)
        self.assertIn("async function loadHostname()", self.setup)
        self.assertIn("async function saveHostname()", self.setup)

    def test_authenticated_dashboard_uses_text_content(self):
        self.assertIn("lldpq_hostname", self.auth_api)
        self.assertIn("LLDPQ_HOSTNAME_JSON", self.auth_api)
        self.assertIn("hostname: 'lldpq'", self.auth_js)
        self.assertIn("this.hostname =", self.auth_js)
        self.assertIn('id="lldpq-dashboard-title">lldpq</h1>', self.start)
        self.assertIn(
            "document.getElementById('lldpq-dashboard-title').textContent = dashboardTitle",
            self.start,
        )
        self.assertNotIn(
            "document.getElementById('lldpq-dashboard-title').innerHTML",
            self.start,
        )


if __name__ == "__main__":
    unittest.main()
