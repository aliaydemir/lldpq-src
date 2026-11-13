#!/usr/bin/env python3
"""Async Ask-AI jobs never persist the admin session cookie.

The detached worker authenticates its fabric-api/search-api tool subprocesses
through the LLDPQ_AUTH_ROLE/LLDPQ_AUTH_USER that auth-guard.sh exported for the
submitting request. The chain is exercised end to end with the real
auth-guard.sh, the real submit/worker/tool functions lifted out of ai-api.sh,
and a stand-in fabric-api.sh that only runs the real guard.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_ai_api_contract import PYTHON_TEXT, ROOT, load_symbols


AUTH_GUARD = ROOT / "html" / "auth-guard.sh"
# Invented session token (auth-guard.sh accepts exactly 64 hex characters).
TOKEN = "5e" * 32
COOKIE = "theme=dark; lldpq_session=" + TOKEN
# Same first line as the real fabric-api.sh, then the guard that its
# run-device-command action uses; the reply reports what the guard saw.
STAND_IN_FABRIC_API = """#!/bin/bash
source "$(dirname "$0")/auth-guard.sh"
require_admin
echo "Content-Type: application/json"
echo ""
if [ -n "${HTTP_COOKIE:-}" ]; then seen=yes; else seen=no; fi
echo "{\\"success\\": true, \\"output\\": \\"role=$LLDPQ_AUTH_ROLE cookie=$seen\\"}"
"""


class JobCookieTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "ai"
        self.jobs = self.state / "jobs"
        self.state.mkdir()
        self.web = self.root / "web"
        self.web.mkdir()
        shutil.copy(AUTH_GUARD, self.web / "auth-guard.sh")
        (self.web / "fabric-api.sh").write_text(STAND_IN_FABRIC_API, encoding="utf-8")
        self.ns = load_symbols(
            "action_chat_submit", "action_analyze_submit",
            "action_chat_worker", "action_analyze_worker",
            "run_device_tool", "_valid_job_id", "_job_paths",
            "_purge_stale_jobs", "_load_json_file", "_job_emit", "_job_cancelled",
            "result_json", "error_json", "_JOB_CONTEXT",
            "MAX_CHAT_MESSAGE_CHARS", "JOB_MAX_AGE_SECONDS",
            "CHAT_DEADLINE_SECONDS", "WORKER_CHAT_DEADLINE_SECONDS",
        )
        self.ns.update(
            os=os, sys=sys, tempfile=tempfile,
            AI_STATE_DIR=str(self.state), JOBS_DIR=str(self.jobs),
            WEB_ROOT=str(self.web),
            POST_DATA=json.dumps({"message": "check bgp on leaf01", "history": []}),
            _ensure_state_dir=lambda: None,
            validate_history=lambda history: list(history or []),
            redact_secrets=lambda value: value,
        )

    def request_environment(self, action):
        """What the Python heredoc sees after auth-guard.sh accepted the cookie."""
        return {
            "PATH": os.environ.get("PATH", ""),
            "REQUEST_METHOD": "POST",
            "QUERY_STRING": "action=" + action,
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "42",
            "HTTP_COOKIE": COOKIE,
            "LLDPQ_AUTH_ROLE": "admin",
            "LLDPQ_AUTH_USER": "admin",
        }

    def submit(self, action):
        function = self.ns["action_" + action.replace("-", "_")]
        self.ns["_JOB_CONTEXT"] = None
        output = io.StringIO()
        with mock.patch.dict(os.environ, self.request_environment(action), clear=True), \
                mock.patch("subprocess.Popen") as popen, \
                contextlib.redirect_stdout(output), \
                self.assertRaises(SystemExit):
            function()
        reply = json.loads(output.getvalue())
        self.assertTrue(reply["success"], reply)
        job_dir = self.jobs / reply["job_id"]
        self.assertTrue((job_dir / "job.json").is_file())
        popen.assert_called_once()
        return reply["job_id"], job_dir, popen.call_args

    def run_worker(self, kind, job_id, worker_environment):
        """Run the real worker entry point under the spawned worker's env.

        The stand-in pipeline makes one device-tool call exactly like the
        real pipelines do (cookie taken from HTTP_COOKIE, possibly empty) and
        finishes through result_json.
        """
        def pipeline():
            ok, output = self.ns["run_device_tool"](
                "leaf01", "nv show system", os.environ.get("HTTP_COOKIE", "")
            )
            self.ns["result_json"]({"success": ok, "response": output})

        self.ns["_JOB_CONTEXT"] = None
        self.ns["action_chat" if kind == "chat" else "action_analyze"] = pipeline
        worker = self.ns[
            "action_chat_worker" if kind == "chat" else "action_analyze_worker"
        ]
        with mock.patch.dict(os.environ, worker_environment, clear=True), \
                mock.patch("threading.Thread"), \
                self.assertRaises(SystemExit) as finished:
            worker(job_id)
        self.assertEqual(finished.exception.code, 0)

    def assert_no_cookie_on_disk(self, job_dir):
        files = [path for path in job_dir.rglob("*") if path.is_file()]
        self.assertIn(job_dir / "job.json", files)
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(TOKEN, text, path.name)
            self.assertNotIn("lldpq_session", text, path.name)
        spec = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
        self.assertNotIn("cookie", spec)
        return spec

    def test_guard_exports_the_role_that_the_worker_inherits(self):
        sessions = self.root / "sessions"
        sessions.mkdir()
        (sessions / TOKEN).write_text(
            "%d\nadmin\nadmin\n" % (int(time.time()) + 600), encoding="utf-8"
        )
        script = (
            'source "$1"\n'
            'LLDPQ_GUARD_SESSIONS_DIR="$2"\n'
            "require_admin\n"
            # Child processes (the Python heredoc, then the worker) see both.
            "printenv LLDPQ_AUTH_ROLE\n"
            "printenv LLDPQ_AUTH_USER\n"
        )
        result = subprocess.run(
            ["bash", "-c", script, "guard-test", str(AUTH_GUARD), str(sessions)],
            env={"PATH": os.environ.get("PATH", ""), "HTTP_COOKIE": COOKIE},
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ["admin", "admin"])

    def test_guard_stand_in_rejects_a_request_without_role_or_cookie(self):
        # Control for the tests below: the stand-in really runs the guard.
        with mock.patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
            self.assertEqual(
                self.ns["run_device_tool"]("leaf01", "nv show system", ""),
                (False, "Not authenticated"),
            )

    def test_finished_jobs_hold_no_cookie_and_tools_still_authenticate(self):
        for kind, action in (("chat", "chat-submit"), ("analyze", "analyze-submit")):
            with self.subTest(action=action):
                job_id, job_dir, spawned = self.submit(action)
                spec = self.assert_no_cookie_on_disk(job_dir)
                self.assertEqual(spec["user"], "admin")

                argv = spawned.args[0]
                self.assertEqual(argv[:2], ["bash", str(self.web / "ai-api.sh")])
                self.assertEqual(
                    argv[2:],
                    ["--worker" if kind == "chat" else "--analyze-worker", job_id],
                )
                worker_environment = spawned.kwargs["env"]
                self.assertNotIn("HTTP_COOKIE", worker_environment)
                self.assertEqual(worker_environment["LLDPQ_AUTH_ROLE"], "admin")
                self.assertEqual(worker_environment["LLDPQ_AUTH_USER"], "admin")
                self.assertNotIn(TOKEN, json.dumps(worker_environment))

                self.run_worker(kind, job_id, worker_environment)
                events = [
                    json.loads(line) for line in
                    (job_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(events[-1]["event"], "result")
                # The real guard accepted the tool call on the inherited role
                # alone: no cookie reached the fabric-api subprocess.
                self.assertEqual(
                    events[-1]["result"],
                    {"success": True, "response": "role=admin cookie=no"},
                )
                self.assert_no_cookie_on_disk(job_dir)

    def test_job_spec_code_no_longer_reads_or_writes_a_cookie(self):
        self.assertEqual(PYTHON_TEXT.count("'cookie':"), 0)
        self.assertEqual(PYTHON_TEXT.count("spec.get('cookie')"), 0)


if __name__ == "__main__":
    unittest.main()
