#!/usr/bin/env python3
"""CGI JSON error-path smoke tests.

Every JSON API must answer an unknown action or a missing required parameter
with the CGI header block followed by a body that json.loads cleanly to
{"success": false, ...} — never an empty body, HTML, or a bare traceback.
The scripts run hermetically: auth-guard.sh short-circuits when
LLDPQ_AUTH_ROLE is already set in the environment (so no session file is
needed), and every state path with an env override is pointed at a per-test
temp directory.

Assertions stay at the contract level (valid JSON + success:false) rather
than pinning exact error strings: on hosts without GNU grep the `grep -oP`
action parsers extract an empty action and the request lands in the
unknown-action fallback instead of the per-action validation — both paths
must honor the same JSON contract.

Deliberately NOT exercised (documented skips, not flaky assertions):
  - setup-api.sh action dispatch: an unrecognized action falls through to
    the DEFAULT 'setup' flow (SSH key distribution across all inventory
    devices) inside its python heredoc, so on an installed host an
    unknown-action probe would not be hermetic. Only the pre-dispatch error
    paths (missing config helper / non-POST method / invalid
    Content-Length), which exit before any dispatch, are invoked.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML_DIR = ROOT / "html"
CONFIG_HELPER = ROOT / "bin" / "lldpq-config"

# CGI/request variables and LLDPq knobs a developer's shell must not leak
# into the scripts under test (same idea as test_export_artifacts.py).
SCRUBBED_KEYS = (
    "QUERY_STRING", "REQUEST_METHOD", "CONTENT_TYPE", "CONTENT_LENGTH",
    "HTTP_COOKIE", "POST_DATA", "ANSIBLE_DIR", "EDITOR_ROOT", "WEB_ROOT",
    "AI_STATE_DIR",
)
SCRUBBED_PREFIXES = ("LLDPQ_", "FABRIC_LOCK_")


def cgi_environment(**overrides):
    environment = {
        key: value for key, value in os.environ.items()
        if key not in SCRUBBED_KEYS
        and not key.startswith(SCRUBBED_PREFIXES)
    }
    environment.update(overrides)
    return environment


class CgiJsonContractCase(unittest.TestCase):
    """Shared runner + contract assertion."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)

    def run_cgi(self, script_name, environment, body=""):
        result = subprocess.run(
            ["bash", str(HTML_DIR / script_name)],
            env=environment, input=body, cwd=str(self.tmp),
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def assert_json_error(self, result, expected_status=None):
        """Header block, then a body that is JSON with success:false."""
        self.assertIn("\n\n", result.stdout, result.stdout)
        headers, body = result.stdout.split("\n\n", 1)
        self.assertIn("Content-Type: application/json", headers)
        if expected_status is not None:
            self.assertIn(f"Status: {expected_status}", headers)
        self.assertTrue(body.strip(), "empty response body")
        data = json.loads(body)
        self.assertIsInstance(data, dict, data)
        self.assertIs(data.get("success"), False, data)
        self.assertTrue(data.get("error"), data)
        return data


class FabricApiJsonContractTests(CgiJsonContractCase):
    def environment(self, query):
        ansible_dir = self.tmp / "ansible"
        ansible_dir.mkdir(exist_ok=True)
        return cgi_environment(
            LLDPQ_AUTH_ROLE="admin",
            LLDPQ_AUTH_USER="pytest",
            REQUEST_METHOD="GET",
            QUERY_STRING=query,
            ANSIBLE_DIR=str(ansible_dir),
            # Keep the top-level lock pre-create out of the repo's html/
            # directory (the default is $(dirname $0)/.locks).
            FABRIC_LOCK_DIR=str(self.tmp / "locks"),
        )

    def test_unknown_action_is_a_json_error(self):
        result = self.run_cgi(
            "fabric-api.sh",
            self.environment("action=definitely-not-an-action"),
        )
        self.assert_json_error(result)

    def test_missing_hostname_parameter_is_a_json_error(self):
        # get-device without hostname= must refuse before touching state.
        result = self.run_cgi(
            "fabric-api.sh", self.environment("action=get-device")
        )
        self.assert_json_error(result)


class AnsibleApiJsonContractTests(CgiJsonContractCase):
    def environment(self, query):
        ansible_dir = self.tmp / "ansible"
        ansible_dir.mkdir(exist_ok=True)
        return cgi_environment(
            LLDPQ_AUTH_ROLE="admin",
            LLDPQ_AUTH_USER="pytest",
            REQUEST_METHOD="GET",
            QUERY_STRING=query,
            ANSIBLE_DIR=str(ansible_dir),
            EDITOR_ROOT=str(ansible_dir),
        )

    def test_unknown_action_is_a_json_error(self):
        result = self.run_cgi(
            "ansible-api.sh",
            self.environment("action=definitely-not-an-action"),
        )
        self.assert_json_error(result)

    def test_missing_file_parameter_is_a_json_error(self):
        # read without file= resolves to the editor root itself, which is
        # not a file — either path validation or the -f check must answer
        # with a JSON error.
        result = self.run_cgi(
            "ansible-api.sh", self.environment("action=read")
        )
        self.assert_json_error(result)


class SearchApiJsonContractTests(CgiJsonContractCase):
    def environment(self, query):
        # search-api.sh fails closed without its config helper; point
        # LLDPQ_CONFIG_HELPER at the repo helper reading a temp config
        # (same wrapper idiom as test_export_artifacts.py).
        web_root = self.tmp / "web"
        web_root.mkdir(exist_ok=True)
        config = self.tmp / "lldpq.conf"
        config.write_text(
            f"LLDPQ_DIR={self.tmp / 'lldpq'}\n"
            "LLDPQ_USER=pytest\n"
            f"WEB_ROOT={web_root}\n",
            encoding="utf-8",
        )
        helper = self.tmp / "helper"
        helper.write_text(
            "#!/usr/bin/env bash\n"
            f'exec "{CONFIG_HELPER}" "$@" --config "{config}"\n',
            encoding="utf-8",
        )
        helper.chmod(0o755)
        return cgi_environment(
            LLDPQ_AUTH_ROLE="admin",
            LLDPQ_AUTH_USER="pytest",
            REQUEST_METHOD="GET",
            QUERY_STRING=query,
            LLDPQ_CONFIG_HELPER=str(helper),
        )

    def test_unknown_action_is_a_json_error(self):
        result = self.run_cgi(
            "search-api.sh",
            self.environment("action=definitely-not-an-action"),
        )
        self.assert_json_error(result)

    def test_missing_device_parameter_is_a_json_error(self):
        # get-mac without device= must refuse before any SSH attempt.
        result = self.run_cgi(
            "search-api.sh", self.environment("action=get-mac")
        )
        self.assert_json_error(result)


class SetupApiJsonContractTests(CgiJsonContractCase):
    """Pre-dispatch error paths only — see the module docstring for why the
    action dispatch itself is not probed. On a developer host the script
    exits on the missing /usr/local/bin/lldpq-config helper; on an installed
    host the same requests exit on the method/Content-Length validation.
    Both must emit the JSON error contract."""

    def environment(self, method, **extra):
        return cgi_environment(
            LLDPQ_AUTH_ROLE="admin",
            LLDPQ_AUTH_USER="pytest",
            REQUEST_METHOD=method,
            QUERY_STRING="",
            **extra,
        )

    def test_get_request_is_a_json_error(self):
        result = self.run_cgi("setup-api.sh", self.environment("GET"))
        self.assert_json_error(result)

    def test_invalid_content_length_is_a_json_error(self):
        result = self.run_cgi(
            "setup-api.sh",
            self.environment("POST", CONTENT_LENGTH="not-a-number"),
        )
        self.assert_json_error(result)


class AiExportApiJsonContractTests(CgiJsonContractCase):
    """The public /ai/export_json CGI has no actions; its unknown-request
    analogues are a rejected method and a missing/seeded analysis file. It
    honors AI_STATE_DIR, so every path runs hermetically."""

    def environment(self, method):
        state_dir = self.tmp / "ai"
        state_dir.mkdir(exist_ok=True)
        return cgi_environment(
            REQUEST_METHOD=method,
            AI_STATE_DIR=str(state_dir),
        )

    def test_rejected_method_is_a_json_error(self):
        result = self.run_cgi("ai-export-api.sh", self.environment("POST"))
        self.assert_json_error(result, expected_status="405")

    def test_missing_analysis_file_is_a_json_error(self):
        result = self.run_cgi("ai-export-api.sh", self.environment("GET"))
        self.assert_json_error(result, expected_status="404")

    def test_seeded_empty_analysis_is_a_json_error(self):
        # install.sh seeds analysis.json with {} before the first run;
        # that must surface as 503 "no report yet", not a 200 {}.
        environment = self.environment("GET")
        (self.tmp / "ai" / "analysis.json").write_text("{}", encoding="utf-8")
        result = self.run_cgi("ai-export-api.sh", environment)
        self.assert_json_error(result, expected_status="503")


if __name__ == "__main__":
    unittest.main()
