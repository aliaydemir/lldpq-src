#!/usr/bin/env python3
"""Checks the console admission probe names the reason an upgrade was refused.

A WebSocket upgrade that fails reaches the browser as a bare close 1006 with no
status line, so console.html used to print a list of guesses ("unknown target,
session capacity reached, or the service is unavailable") that omitted the two
most common causes.  probe_admission() re-runs the real checks over plain HTTP;
these tests pin one distinct answer per rejection path.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_console_module(sessions_dir: Path, lldpq_dir: Path):
    """Import console-pty.py under a temporary session store and inventory."""
    import os
    os.environ["LLDPQ_SESSIONS_DIR"] = str(sessions_dir)
    os.environ["LLDPQ_CONF"] = str(lldpq_dir / "lldpq.conf")
    (lldpq_dir / "lldpq.conf").write_text(
        f"LLDPQ_DIR={lldpq_dir}\nLLDPQ_USER={os.environ.get('USER', 'lldpq')}\n"
        "ANSIBLE_DIR=none\n", encoding="utf-8")
    spec = importlib.util.spec_from_file_location(
        "console_pty_under_test", ROOT / "lldpq" / "console-pty.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConsoleProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.sessions = root / "sessions"
        cls.lldpq = root / "lldpq"
        cls.sessions.mkdir()
        cls.lldpq.mkdir()
        (cls.lldpq / "devices.yaml").write_text(
            "defaults:\n  username: cumulus\n"
            "devices:\n  192.168.100.5: OOB-CORE-01 @core\n", encoding="utf-8")
        cls.console = load_console_module(cls.sessions, cls.lldpq)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.console.SESSIONS.clear()
        for leftover in self.sessions.iterdir():
            leftover.unlink()

    # ---------- helpers ----------
    @staticmethod
    def token(seed):
        """Session tokens are 64 hex characters; anything else never validates."""
        return hashlib.sha256(seed.encode()).hexdigest()

    def make_session_cookie(self, seed, user="alice", role="admin", ttl=600):
        token = self.token(seed)
        (self.sessions / token).write_text(
            f"{int(time.time()) + ttl}\n{user}\n{role}\n", encoding="utf-8")
        return f"lldpq_session={token}"

    def probe(self, cookie="", target="OOB-CORE-01", sid=""):
        return self.console.probe_admission(cookie, target, sid)

    # ---------- one distinct answer per path ----------
    def test_admin_with_a_known_device_is_admitted(self):
        cookie = self.make_session_cookie("a")
        status, payload = self.probe(cookie)
        self.assertEqual(status, "200 OK")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["reason"], "ready")

    def test_expired_session_is_reported_as_auth(self):
        """The page turns this one into a redirect to the login screen."""
        cookie = self.make_session_cookie("b", ttl=-10)
        status, payload = self.probe(cookie)
        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(payload["reason"], "auth")

    def test_no_cookie_at_all_is_reported_as_auth(self):
        status, payload = self.probe("")
        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(payload["reason"], "auth")

    def test_signed_in_but_not_admin_names_the_role(self):
        """The cause the old message never mentioned."""
        cookie = self.make_session_cookie("c", role="operator")
        status, payload = self.probe(cookie)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(payload["reason"], "role")
        self.assertIn("operator", payload["message"])
        self.assertIn("admin", payload["message"])

    def test_unknown_device_names_both_inventories(self):
        cookie = self.make_session_cookie("d")
        status, payload = self.probe(cookie, target="NOT-A-DEVICE")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(payload["reason"], "unknown_target")
        self.assertIn("devices.yaml", payload["message"])

    def test_session_owned_by_another_login_is_distinguished(self):
        cookie = self.make_session_cookie("e", user="alice")
        self.console.SESSIONS["sid-1"] = {
            "token": self.token("f"), "user": "bob", "target": "OOB-CORE-01"}
        status, payload = self.probe(cookie, sid="sid-1")
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(payload["reason"], "session_owner")

    def test_session_bound_to_another_device_is_distinguished(self):
        cookie = self.make_session_cookie("g", user="alice")
        self.console.SESSIONS["sid-2"] = {
            "token": self.token("g"), "user": "alice", "target": "OOB-LF-10"}
        status, payload = self.probe(cookie, sid="sid-2")
        self.assertEqual(status, "409 Conflict")
        self.assertEqual(payload["reason"], "session_target")

    def test_reattaching_to_your_own_session_is_allowed(self):
        cookie = self.make_session_cookie("h", user="alice")
        self.console.SESSIONS["sid-3"] = {
            "token": self.token("h"), "user": "alice", "target": "OOB-CORE-01"}
        status, payload = self.probe(cookie, sid="sid-3")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["reason"], "attachable")

    def test_a_closing_session_does_not_block_a_fresh_one(self):
        cookie = self.make_session_cookie("i", user="alice")
        self.console.SESSIONS["sid-4"] = {
            "token": self.token("j"), "user": "bob", "target": "OOB-CORE-01",
            "closing": True}
        status, payload = self.probe(cookie, sid="sid-4")
        self.assertEqual(status, "200 OK")

    def test_capacity_is_reported_only_when_it_is_actually_reached(self):
        cookie = self.make_session_cookie("k")
        original = self.console.MAX_SESSIONS
        try:
            self.console.MAX_SESSIONS = 1
            self.console.SESSIONS["busy"] = {"token": self.token("z"), "user": "bob"}
            status, payload = self.probe(cookie)
            self.assertEqual(status, "503 Service Unavailable")
            self.assertEqual(payload["reason"], "capacity")
        finally:
            self.console.MAX_SESSIONS = original

    # ---------- the probe must not leak to non-admins ----------
    def test_non_admin_learns_nothing_about_the_inventory(self):
        cookie = self.make_session_cookie("l", role="viewer")
        _status, payload = self.probe(cookie, target="OOB-CORE-01")
        self.assertEqual(payload["reason"], "role")
        self.assertNotIn("192.168.100.5", payload["message"])
        self.assertNotIn("devices.yaml", payload["message"])

    def test_every_answer_is_json_serialisable_with_a_stable_shape(self):
        cookie = self.make_session_cookie("m")
        import json
        for target in ("OOB-CORE-01", "NOT-A-DEVICE"):
            status, payload = self.probe(cookie, target=target)
            self.assertRegex(status, r"^\d{3} ")
            self.assertEqual(set(payload), {"ok", "reason", "message"})
            json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
