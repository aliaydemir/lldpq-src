#!/usr/bin/env python3
"""Sessions that must not survive a password change.

auth-api.sh swept the target user's sessions only when an admin reset
ANOTHER user's password. There is exactly one admin account, so every change
of the admin password is a self change and the sweep never ran for it: a
session opened earlier with the default password stayed valid for up to
seven days after the operator had changed that password.

The real CGI runs here against a temporary users file and sessions
directory. A stand-in `sudo` on PATH hands the mutation to the real
lldpq/auth_users.py helper pointed at that temporary file.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
AUTH_API = ROOT / "html" / "auth-api.sh"
HELPER = ROOT / "lldpq" / "auth_users.py"

OLD_PASSWORD = "default-password"
NEW_PASSWORD = "changed-password"


def password_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


class PasswordChangeSessionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        self.users = self.tmp / "users.conf"
        self.lock = self.tmp / "users.conf.lock"
        self.sessions = self.tmp / "sessions"
        self.sessions.mkdir()
        self.users.write_text(
            f"admin:{password_hash(OLD_PASSWORD)}:admin\n"
            f"operator:{password_hash('operator-password')}:operator\n",
            encoding="utf-8",
        )
        self.users.chmod(0o600)
        # The helper refuses a lock that is not 0660 and owned by the ids it
        # is given (BSD temp directories hand new files the directory group).
        self.lock.touch()
        os.chown(self.lock, os.geteuid(), os.getegid())
        self.lock.chmod(0o660)

        source = AUTH_API.read_text(encoding="utf-8")
        for old, new in (
            ('USERS_FILE="/etc/lldpq-users.conf"', f'USERS_FILE="{self.users}"'),
            ('USERS_LOCK_FILE="/etc/lldpq-users.conf.lock"',
             f'USERS_LOCK_FILE="{self.lock}"'),
            ('LLDPQ_CONFIG_FILE="/etc/lldpq.conf"',
             f'LLDPQ_CONFIG_FILE="{self.tmp}/lldpq.conf"'),
            ('SESSIONS_DIR="/var/lib/lldpq/sessions"',
             f'SESSIONS_DIR="{self.sessions}"'),
        ):
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.cgi = self.tmp / "auth-api.sh"
        self.cgi.write_text(source, encoding="utf-8")

        # `sudo -n /usr/local/libexec/lldpq-auth-users.py` -> the real helper
        # logic, as the invoking user, on the temporary users file.
        self.fail_marker = self.tmp / "helper-must-fail"
        helper = self.tmp / "helper.py"
        helper.write_text(
            "import importlib.util, json, os, sys\n"
            f"spec = importlib.util.spec_from_file_location('auth_users', {str(HELPER)!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            f"if os.path.exists({str(self.fail_marker)!r}):\n"
            "    print(json.dumps({'success': False, 'error': 'injected failure'}))\n"
            "    sys.exit(2)\n"
            "try:\n"
            "    response = module.mutate_users(\n"
            "        json.load(sys.stdin),\n"
            f"        users_path={str(self.users)!r}, lock_path={str(self.lock)!r},\n"
            "        allowed_config_target=None,\n"
            "        owner_uid=os.geteuid(), owner_gid=os.getegid(),\n"
            "        lock_uid=os.geteuid(), lock_gid=os.getegid(),\n"
            "        direct_mount_detector=lambda path: False)\n"
            "except module.AuthUsersError as exc:\n"
            "    print(json.dumps({'success': False, 'error': str(exc)}))\n"
            "    sys.exit(2)\n"
            "print(json.dumps(response))\n",
            encoding="utf-8",
        )
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        sudo = bin_dir / "sudo"
        sudo.write_text(
            "#!/bin/bash\n"
            '[ "$1" = "-n" ] && [ "$2" = "/usr/local/libexec/lldpq-auth-users.py" ] '
            "|| { echo \"unexpected sudo call: $*\" >&2; exit 97; }\n"
            f'exec "{sys.executable}" "{helper}"\n',
            encoding="utf-8",
        )
        sudo.chmod(0o755)
        self.path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        self.counter = 0

    def session(self, user, role, expires_in=3600):
        self.counter += 1
        token = f"{self.counter:064x}"
        (self.sessions / token).write_text(
            f"{int(time.time()) + expires_in}\n{user}\n{role}\n", encoding="utf-8")
        return token

    def alive(self, token):
        return (self.sessions / token).is_file()

    def call(self, action, token=None, **form):
        body = urlencode(form)
        environment = {
            "PATH": self.path,
            "QUERY_STRING": f"action={action}",
            "REQUEST_METHOD": "POST" if form else "GET",
            "CONTENT_LENGTH": str(len(body)),
        }
        if token:
            environment["HTTP_COOKIE"] = f"lldpq_session={token}"
        result = subprocess.run(
            ["bash", str(self.cgi)], env=environment, input=body,
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        headers, payload = result.stdout.split("\n\n", 1)
        return headers, json.loads(payload)

    def authenticated(self, token):
        return self.call("check", token)[1]["authenticated"]

    def admin_hash(self):
        return self.users.read_text(encoding="utf-8").splitlines()[0].split(":")[1]

    def test_self_change_keeps_this_session_and_drops_the_users_other_ones(self):
        current = self.session("admin", "admin")
        opened_with_default_password = self.session("admin", "admin")
        remembered = self.session("admin", "admin", expires_in=7 * 86400)
        operator = self.session("operator", "operator")

        _, response = self.call(
            "change-password", current,
            target_user="admin", new_password=NEW_PASSWORD)

        self.assertIs(response["success"], True, response)
        self.assertEqual(self.admin_hash(), password_hash(NEW_PASSWORD))
        self.assertTrue(self.alive(current))
        self.assertFalse(self.alive(opened_with_default_password))
        self.assertFalse(self.alive(remembered))
        self.assertTrue(self.alive(operator))
        self.assertTrue(self.authenticated(current))
        self.assertFalse(self.authenticated(opened_with_default_password))
        self.assertFalse(self.authenticated(remembered))
        self.assertTrue(self.authenticated(operator))

    def test_admin_reset_of_another_user_drops_all_of_that_users_sessions(self):
        current = self.session("admin", "admin")
        other_admin = self.session("admin", "admin")
        operator_one = self.session("operator", "operator")
        operator_two = self.session("operator", "operator")

        _, response = self.call(
            "change-password", current,
            target_user="operator", new_password=NEW_PASSWORD)

        self.assertIs(response["success"], True, response)
        self.assertFalse(self.alive(operator_one))
        self.assertFalse(self.alive(operator_two))
        self.assertTrue(self.alive(current))
        self.assertTrue(self.alive(other_admin))

    def test_refused_or_failed_change_drops_no_session(self):
        current = self.session("admin", "admin")
        other = self.session("admin", "admin")
        operator = self.session("operator", "operator")
        before = self.admin_hash()

        # Too short: refused before the helper runs.
        _, response = self.call(
            "change-password", current, target_user="admin", new_password="short")
        self.assertIs(response["success"], False)
        # Helper failure (e.g. a legacy direct-file mount that cannot be
        # replaced atomically): the old password still works, so the other
        # sessions are still legitimate.
        self.fail_marker.touch()
        _, response = self.call(
            "change-password", current,
            target_user="admin", new_password=NEW_PASSWORD)
        self.assertIs(response["success"], False)
        # Only an admin may change passwords at all.
        self.fail_marker.unlink()
        _, response = self.call(
            "change-password", operator,
            target_user="admin", new_password=NEW_PASSWORD)
        self.assertIs(response["success"], False)

        self.assertEqual(self.admin_hash(), before)
        for token in (current, other, operator):
            self.assertTrue(self.alive(token))

    @unittest.skipUnless(shutil.which("flock"), "login needs util-linux flock")
    def test_login_with_the_old_password_does_not_outlive_the_change(self):
        def login(password):
            headers, response = self.call(
                "login", username="admin", password=password, remember="true")
            if not response["success"]:
                return None
            cookie = next(
                line for line in headers.splitlines()
                if line.startswith("Set-Cookie: lldpq_session="))
            return cookie.split("=", 1)[1].split(";", 1)[0]

        earlier = login(OLD_PASSWORD)
        current = login(OLD_PASSWORD)
        self.assertTrue(earlier and current and earlier != current)
        self.assertTrue(self.authenticated(earlier))

        _, response = self.call(
            "change-password", current,
            target_user="admin", new_password=NEW_PASSWORD)

        self.assertIs(response["success"], True, response)
        self.assertFalse(self.authenticated(earlier))
        self.assertTrue(self.authenticated(current))
        self.assertIsNone(login(OLD_PASSWORD))
        self.assertTrue(login(NEW_PASSWORD))


if __name__ == "__main__":
    unittest.main()
