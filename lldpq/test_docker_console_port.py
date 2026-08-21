#!/usr/bin/env python3
"""Checks the container's console bridge port can be moved off 8765.

A switch already serves its own REST API on 8765, so a container sharing the
host network could never start: the entrypoint found the port taken and exited,
and the restart policy turned that into a crash loop with no web UI at all.

console-pty.py has always read CONSOLE_PTY_PORT. The entrypoint hardcoded the
port in its readiness probes and nginx hardcoded it in the console route, so
setting the variable alone moved the listener away from where nginx looked.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "docker-entrypoint.sh"
DOCKERFILE = ROOT / "docker" / "Dockerfile"
NGINX_SITE = ROOT / "etc" / "nginx" / "sites-available" / "lldpq"
CONSOLE_PTY = ROOT / "lldpq" / "console-pty.py"


class ConsolePortContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        cls.nginx_site = NGINX_SITE.read_text(encoding="utf-8")

    def test_the_entrypoint_stays_valid_shell(self):
        subprocess.run(["bash", "-n", str(ENTRYPOINT)], check=True)

    def test_the_bridge_itself_reads_the_variable(self):
        self.assertIn(
            'os.environ.get("CONSOLE_PTY_PORT", "8765")',
            CONSOLE_PTY.read_text(encoding="utf-8"),
        )

    def test_the_entrypoint_defaults_to_the_historical_port(self):
        """An existing deployment that sets nothing must not change behaviour."""
        self.assertIn('CONSOLE_PTY_PORT="${CONSOLE_PTY_PORT:-8765}"', self.entrypoint)

    def test_the_entrypoint_exports_the_port_to_the_bridge(self):
        self.assertRegex(self.entrypoint, r'(?m)^export CONSOLE_PTY_PORT$')

    def test_no_probe_or_message_hardcodes_the_port_any_more(self):
        """The readiness probes decided whether the container lived or died."""
        console_block = self.entrypoint.split("# Console bridge lifecycle helpers")[1]
        bare_port = re.compile(r'(?<![0-9])8765(?![0-9])')
        offenders = [
            line.strip() for line in console_block.splitlines()
            if bare_port.search(line)
            and not line.strip().startswith("#")
            and "CONSOLE_PTY_PORT:-8765" not in line
        ]
        self.assertEqual(offenders, [], f"port still hardcoded: {offenders}")

    def test_a_non_numeric_port_is_rejected_instead_of_silently_ignored(self):
        self.assertIn("CONSOLE_PTY_PORT must be a port number", self.entrypoint)

    def test_a_port_outside_the_valid_range_is_rejected(self):
        self.assertIn("CONSOLE_PTY_PORT is out of range", self.entrypoint)

    def test_the_conflict_error_now_tells_the_operator_what_to_do(self):
        self.assertIn("CONSOLE_PTY_PORT=18765", self.entrypoint)

    # ---------- the nginx route must follow the listener ----------
    def test_the_packaged_site_still_ships_the_default_port(self):
        self.assertIn("proxy_pass http://127.0.0.1:8765;", self.nginx_site)

    def test_the_console_route_is_the_only_loopback_proxy(self):
        """The rewrite below is only safe while one such line exists."""
        matches = re.findall(
            r'proxy_pass http://127\.0\.0\.1:\d+;', self.nginx_site
        )
        self.assertEqual(len(matches), 1, matches)

    def test_the_rewrite_repoints_the_route_at_the_chosen_port(self):
        """Run the entrypoint's own sed against the packaged site file."""
        rewrite = re.search(
            r'"s\|\(proxy_pass http://127\\\.0\\\.0\\\.1:\)\[0-9\]\+\(;\)\|'
            r'\\1\$\{CONSOLE_PTY_PORT\}\\2\|"',
            self.entrypoint,
        )
        self.assertIsNotNone(rewrite, "console route rewrite is missing")

        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp) / "lldpq"
            site.write_text(self.nginx_site, encoding="utf-8")
            subprocess.run(
                ["sed", "-i", "-E",
                 "s|(proxy_pass http://127\\.0\\.0\\.1:)[0-9]+(;)|\\g<1>18765\\2|"
                 .replace("\\g<1>", "\\1"),
                 str(site)],
                check=True,
            )
            rewritten = site.read_text(encoding="utf-8")
        self.assertIn("proxy_pass http://127.0.0.1:18765;", rewritten)
        self.assertNotIn("proxy_pass http://127.0.0.1:8765;", rewritten)

    def test_rewriting_twice_is_stable(self):
        """A restart with a new value must not stack broken substitutions."""
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp) / "lldpq"
            site.write_text(self.nginx_site, encoding="utf-8")
            for port in ("18765", "9765"):
                subprocess.run(
                    ["sed", "-i", "-E",
                     f"s|(proxy_pass http://127\\.0\\.0\\.1:)[0-9]+(;)|\\1{port}\\2|",
                     str(site)],
                    check=True,
                )
            rewritten = site.read_text(encoding="utf-8")
        self.assertIn("proxy_pass http://127.0.0.1:9765;", rewritten)
        self.assertEqual(
            len(re.findall(r'proxy_pass http://127\.0\.0\.1:\d+;', rewritten)), 1
        )


class ServiceWatchdogContractTest(unittest.TestCase):
    """Pins the fcgiwrap/cron watchdog and the container health probe.

    Only console-pty was supervised; nginx as PID 1 kept the container
    "running" while a dead fcgiwrap turned every CGI API into a 502 and a
    dead cron silently stopped all scheduled collection, with no HEALTHCHECK
    to surface either.
    """

    @classmethod
    def setUpClass(cls):
        cls.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    def test_the_watchdog_checks_both_daemons_by_exact_name(self):
        """pgrep -x cannot be fooled by substring matches (e.g. cron in a path)."""
        parts = self.entrypoint.split("_supervise_services()")
        self.assertEqual(len(parts), 2, "watchdog function is missing")
        watchdog = parts[1]
        self.assertIn("pgrep -x fcgiwrap", watchdog)
        self.assertIn("pgrep -x cron", watchdog)

    def test_the_watchdog_runs_in_the_background_before_nginx(self):
        start = self.entrypoint.find("_supervise_services &")
        self.assertNotEqual(start, -1, "watchdog is never started")
        self.assertLess(start, self.entrypoint.find("exec nginx"))

    def test_restarts_reuse_the_exact_startup_commands(self):
        """Once at startup, once in the watchdog restart helper."""
        self.assertEqual(
            self.entrypoint.count('/usr/sbin/fcgiwrap -f -s "unix:$FCGIWRAP_SOCKET" &'),
            2,
        )
        self.assertEqual(self.entrypoint.count("service cron start"), 2)

    def test_a_restart_storm_is_capped_instead_of_looping_forever(self):
        self.assertIn("WATCHDOG_STORM_LIMIT=5", self.entrypoint)
        self.assertIn("WATCHDOG_STORM_WINDOW=60", self.entrypoint)
        self.assertIn("CRITICAL: fcgiwrap", self.entrypoint)
        self.assertIn("CRITICAL: cron", self.entrypoint)

    def test_a_capped_service_never_kills_the_container(self):
        """nginx PID 1 semantics: the watchdog gives up quietly, no exit."""
        watchdog = self.entrypoint.split("_supervise_services()")[1]
        watchdog = watchdog.split("_supervise_services &")[0]
        self.assertNotRegex(watchdog, r"(?m)^\s*exit 1\b")

    def test_the_healthcheck_exercises_nginx_fcgiwrap_and_a_cgi(self):
        """auth-api?action=check answers 200 JSON with no session cookie."""
        self.assertIn("HEALTHCHECK", self.dockerfile)
        self.assertIn("auth-api?action=check", self.dockerfile)
        self.assertIn('grep -q \'"authenticated"\'', self.dockerfile)


if __name__ == "__main__":
    unittest.main()
