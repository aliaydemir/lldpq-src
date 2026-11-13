#!/usr/bin/env python3
"""The Gemini API key travels in the x-goog-api-key header, never in the URL.

The key below is invented for these tests.
"""

from __future__ import annotations

import json
import os
import re
import unittest
from unittest import mock

from test_ai_api_contract import PYTHON_TEXT, load_symbols


KEY = "AIzaINVENTEDkeyForTests0123456789"


class Response:
    def read(self):
        return json.dumps({
            "candidates": [{
                "content": {"parts": [{"text": "OK"}]},
                "finishReason": "STOP",
            }],
        }).encode()


def sent_request(urlopen):
    urlopen.assert_called_once()
    request = urlopen.call_args.args[0]
    headers = {name.lower(): value for name, value in request.header_items()}
    return request, headers


class GeminiKeyTransportTests(unittest.TestCase):
    def assert_key_only_in_header(self, urlopen, model):
        request, headers = sent_request(urlopen)
        self.assertEqual(
            request.full_url,
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent",
        )
        self.assertNotIn(KEY, request.full_url)
        self.assertNotIn("key=", request.full_url)
        self.assertEqual(headers["x-goog-api-key"], KEY)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertNotIn(KEY.encode(), request.data)

    def test_chat_and_analysis_request_sends_the_key_as_a_header(self):
        ns = load_symbols(
            "DEFAULT_LLM_MAX_OUTPUT_TOKENS", "_build_gemini_payload",
            "_provider_request_once",
        )
        ns.update({
            "AI_PROVIDER": "gemini",
            "AI_API_URL": "https://example.invalid/v1",
            "AI_API_KEY": KEY,
            "OLLAMA_URL": "http://localhost:11434",
            "prepare_outbound_messages": lambda messages, provider=None: messages,
        })
        with mock.patch("urllib.request.urlopen", return_value=Response()) as urlopen:
            text = ns["_provider_request_once"](
                [{"role": "user", "content": "question"}], "gemini-test", 5, 100,
            )
        self.assertEqual(text, "OK")
        self.assert_key_only_in_header(urlopen, "gemini-test")

    def connection_namespace(self, post, saved_key=""):
        ns = load_symbols("action_test_connection")
        captured = {}

        def capture(payload):
            captured.update(payload)
            raise SystemExit

        redact = load_symbols(
            "_SECRET_VALUE_PATTERN", "_TYPED_SECRET_RE", "_SECRET_RE",
            "_SNMP_CREATEUSER_RE", "_BEARER_RE", "_URI_CREDENTIAL_RE",
            "_URL_KEY_RE", "redact_secrets",
        )["redact_secrets"]
        ns.update({
            "os": os,
            "POST_DATA": json.dumps(post),
            "AI_PROVIDER": "gemini",
            "AI_MODEL": "gemini-saved",
            "AI_API_URL": "https://generativelanguage.googleapis.com",
            "AI_API_KEY": saved_key,
            "AI_PROXY_URL": "",
            "OLLAMA_URL": "http://localhost:11434",
            "_probe_configured_secondary_models": lambda _provider: {},
            "redact_secrets": redact,
            "result_json": capture,
            "error_json": lambda message: capture({"success": False, "error": message}),
        })
        return ns, captured

    def run_test_connection(self, post, saved_key="", side_effect=None):
        ns, captured = self.connection_namespace(post, saved_key)
        with mock.patch(
            "urllib.request.urlopen",
            return_value=Response(), side_effect=side_effect,
        ) as urlopen, mock.patch.dict(os.environ, {}):
            with self.assertRaises(SystemExit):
                ns["action_test_connection"]()
        return captured, urlopen

    def test_connection_test_sends_submitted_and_saved_keys_as_a_header(self):
        cases = (
            ({"provider": "gemini", "model": "gemini-test", "api_key": KEY}, ""),
            # Blank key field: the saved key for the same provider is reused.
            ({"provider": "gemini", "model": "gemini-test"}, KEY),
        )
        for post, saved_key in cases:
            with self.subTest(saved=bool(saved_key)):
                captured, urlopen = self.run_test_connection(post, saved_key)
                self.assertTrue(captured["success"], captured)
                self.assertEqual(captured["reply"], "OK")
                self.assert_key_only_in_header(urlopen, "gemini-test")
                self.assertNotIn(KEY, json.dumps(captured))

    def test_error_text_redaction_of_url_keys_is_kept(self):
        # A proxy or an older client may still echo a ?key= URL in an error.
        failure = OSError(
            "Tunnel failed for https://generativelanguage.googleapis.com/v1beta/"
            f"models/gemini-test:generateContent?key={KEY}&alt=json"
        )
        captured, _urlopen = self.run_test_connection(
            {"provider": "gemini", "model": "gemini-test", "api_key": KEY},
            side_effect=failure,
        )
        self.assertFalse(captured["success"])
        self.assertNotIn(KEY, captured["error"])
        self.assertIn("?key=***REDACTED***&alt=json", captured["error"])

    def assert_no_part_of_key(self, text, key):
        for piece in re.split("[\\r\\n\u0131]", key):
            for start in range(len(piece) - 3):
                self.assertNotIn(piece[start:start + 4], text)
        self.assertNotIn("\u0131", text)
        self.assertNotIn("u0131", text)

    def test_key_that_cannot_be_a_header_is_rejected_without_being_echoed(self):
        # http.client refuses a header value with a line break and quotes the
        # value in its error. urlopen is the real one here, with the sockets
        # blocked: without the early check that error text reaches the reply.
        keys = (
            KEY + "\n",
            KEY + "\r\n",
            KEY[:12] + "\r" + KEY[12:],
            KEY[:12] + "\n" + KEY[12:],
            # A continuation line is a legal header value: it would be sent.
            KEY + "\n extra",
            # Not encodable as latin-1: the codec error names the character.
            KEY[:12] + "\u0131" + KEY[12:],
        )
        posts = (
            {"provider": "gemini", "model": "gemini-test"},
            {"provider": "claude", "model": "claude-test",
             "api_url": "https://claude.example.invalid/v1"},
            {"provider": "openai", "model": "gpt-test",
             "api_url": "https://openai.example.invalid/v1"},
        )
        for post in posts:
            for key in keys:
                with self.subTest(provider=post["provider"], key=ascii(key[10:])):
                    ns, captured = self.connection_namespace(dict(post, api_key=key))
                    with mock.patch(
                        "socket.create_connection",
                        side_effect=OSError("sockets are blocked in this test"),
                    ) as connect, mock.patch.dict(os.environ, {}):
                        with self.assertRaises(SystemExit):
                            ns["action_test_connection"]()
                    connect.assert_not_called()
                    self.assertFalse(captured["success"])
                    self.assertIn("API key", captured["error"])
                    self.assert_no_part_of_key(
                        captured["error"] + json.dumps(captured), key
                    )

    def test_local_provider_ignores_the_key_field(self):
        # Ollama sends no key, so an odd key field must not block its test.
        ns, captured = self.connection_namespace(
            {"provider": "ollama", "model": "local-test", "api_key": KEY + "\n"}
        )
        reply = mock.Mock()
        reply.read.return_value = json.dumps({"message": {"content": "OK"}}).encode()
        with mock.patch("urllib.request.urlopen", return_value=reply) as urlopen:
            with self.assertRaises(SystemExit):
                ns["action_test_connection"]()
        self.assertTrue(captured["success"], captured)
        request, headers = sent_request(urlopen)
        self.assertEqual(request.full_url, "http://localhost:11434/api/chat")
        self.assertNotIn(KEY, json.dumps(headers) + request.data.decode())

    def test_no_call_site_builds_a_key_query_string(self):
        self.assertEqual(PYTHON_TEXT.count("?key="), 0)
        self.assertEqual(PYTHON_TEXT.count("&key="), 0)
        self.assertEqual(PYTHON_TEXT.count("'x-goog-api-key':"), 2)
        self.assertEqual(PYTHON_TEXT.count(":generateContent"), 2)


if __name__ == "__main__":
    unittest.main()
