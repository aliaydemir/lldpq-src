#!/usr/bin/env python3
"""Ask-AI secret masking: pattern coverage and provider-independent storage.

Every credential-looking value below is invented for these tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from test_ai_api_contract import PYTHON_TEXT, ROOT, load_symbols


REDACTION_SYMBOLS = (
    "_SECRET_VALUE_PATTERN",
    "_TYPED_SECRET_RE",
    "_SECRET_RE",
    "_SNMP_CREATEUSER_RE",
    "_BEARER_RE",
    "_URI_CREDENTIAL_RE",
    "_URL_KEY_RE",
    "redact_secrets",
)
FIRST = "ZZinventedVALUE99"
SECOND = "YYinventedSECOND77"
MARK = "***REDACTED***"


def redactor():
    return load_symbols(*REDACTION_SYMBOLS)["redact_secrets"]


class SecretPatternTests(unittest.TestCase):
    def setUp(self):
        self.redact = redactor()

    def assert_masked(self, line):
        masked = self.redact(line)
        for value in (FIRST, SECOND):
            self.assertNotIn(value, masked, line)
        self.assertIn(MARK, masked, line)
        # A second pass (egress gate after the pre-split pass) is a no-op.
        self.assertEqual(self.redact(masked), masked, line)
        return masked

    def test_previously_missed_patterns_are_masked(self):
        lines = (
            f"nv set system snmp-server readonly-community-v6 {FIRST} access any",
            f"nv set system snmp-server username monitor auth-sha {FIRST}",
            f"nv set system snmp-server username monitor auth-sha {FIRST} encrypt-aes {SECOND}",
            f"nv set system snmp-server username monitor auth-sha {FIRST} encrypt-des {SECOND}",
            f"nv set system snmp-server username monitor auth-sha-512 {FIRST} encrypt-aes-256 {SECOND}",
            f"createUser monitor SHA {FIRST} AES {SECOND}",
            f"createUser monitor SHA {FIRST} AES",
            f"createUser monitor MD5 {FIRST} DES {SECOND}",
            f"createUser -e 0x8000000001020304 monitor SHA-512 {FIRST} AES-256 {SECOND}",
            f"createUser monitor SHA -m {FIRST} AES -m {SECOND}",
            f"ip ospf authentication-key {FIRST}",
            f"ip ospf authentication-key 7 {FIRST}",
            f"macsec cak {FIRST}",
            f"mka_cak={FIRST}",
            f"auth_token: {FIRST}",
            f"rocommunity {FIRST} default",
            f"rwcommunity6 {FIRST} default",
            # nv config show (YAML): the secret is the key on the next line.
            f"    readonly-community-v6:\n      {FIRST}:\n        access:",
            f"      auth-sha:\n        {FIRST}:\n          encrypt-aes:\n            {SECOND}: {{}}",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assert_masked(line)

    def test_createuser_keeps_the_algorithm_names(self):
        masked = self.assert_masked(f"createUser monitor SHA {FIRST} AES {SECOND}")
        self.assertEqual(masked, f"createUser monitor SHA {MARK} AES {MARK}")

    def test_patterns_masked_before_stay_masked(self):
        lines = (
            f"nv set vrf default router bgp neighbor swp1 password {FIRST}",
            f"nv set system snmp-server readonly-community {FIRST} access any",
            f"nv set system aaa tacacs server 10.0.0.1 secret {FIRST}",
            f"nv set system snmp-server username monitor auth-md5 {FIRST}",
            f"api_key: {FIRST}",
            f"token = {FIRST}",
            f"password 0 {FIRST}",
            f"key-string 7 {FIRST}",
            f"ip ospf message-digest-key 1 md5 {FIRST}",
            f"wpa-psk {FIRST}",
            f"Authorization: Bearer {FIRST}",
            f"https://backup:{FIRST}@192.0.2.10/configs",
            f"https://example.invalid/v1/models?key={FIRST}&alt=json",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assert_masked(line)
        block = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n" + FIRST
            + "\n-----END OPENSSH PRIVATE KEY-----"
        )
        self.assertNotIn(FIRST, self.redact(block))

    def test_lines_without_secrets_stay_untouched(self):
        lines = (
            "nv set system snmp-server username monitor auth-none",
            "nv set system snmp-server listening-address localhost",
            "nv set interface swp1 link state up",
            "ip ospf authentication message-digest",
            "ip ospf area 0.0.0.0",
            "bgp community-list standard CL1 permit 65000:1",
            "max_tokens: 4096",
            "token_count 15",
            "encryption aes256 enabled",
            "macsec enabled on swp1",
            "leaf01 swp1 rx_power -3.2 dBm cable CAB-0001",
            "createUser",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.redact(line), line)

    def test_repeated_keyword_prefixes_in_one_token_stay_linear(self):
        # redact_secrets runs on untrusted text (device output, log lines,
        # model replies, chat messages). An unbounded keyword suffix rescanned
        # the rest of such a token from every repeat: several seconds each.
        for unit in ("auth-sha-", "auth-md5-", "encrypt-aes-", "encrypt-des-"):
            with self.subTest(unit=unit):
                token = unit * 4000
                self.assertEqual(self.redact_within_half_a_second(token), token)

    def redact_within_half_a_second(self, text):
        started = time.process_time()
        masked = self.redact(text)
        self.assertLess(time.process_time() - started, 0.5)
        return masked

    def test_key_prefix_runs_and_open_json_strings_stay_linear(self):
        # The same guard for the keys behind "_" and for the JSON form: long
        # runs of name characters, and a quoted value that never closes.
        unchanged = (
            "a_" * 20000,
            "_" * 40000,
            "a-" * 20000,
            "c-" * 20000,
            "r_" * 20000,
            "snmp_" * 8000,
            "ro_" * 13000,
            "x_password_" * 4000,
            "_pass" * 8000,
            "_token-" * 6000,
            "pre_shared_" * 4000,
            "auth_key-" * 5000,
            "snmp_community-" * 3000,
            '"password": "' + "a" * 40000,
            '"password": "' + '\\"' * 20000,
            '"password": "' + "\\" * 40001,
            '"password": "' * 3000,
            '"password"' + " " * 40000,
            '"password":' + " " * 40000,
            '_secret"' * 5000,
        )
        for text in unchanged:
            with self.subTest(text=text[:24], length=len(text)):
                self.assertEqual(self.redact_within_half_a_second(text), text)
        # Dense matches cost no more than misses.
        for text in (
            "bgp_password: x\n" * 2500,
            "x_secret 1 " * 4000,
            '"password": "x", ' * 2500,
            ('"password": "' + '\\"' * 50 + " ") * 60,
        ):
            with self.subTest(text=text[:24], length=len(text)):
                self.assertIn(MARK, self.redact_within_half_a_second(text))


class PersistedReportMaskingTests(unittest.TestCase):
    """analysis.json is served by the unauthenticated /ai/export_json; the
    reply is written to the job event log and the cron log."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "ai"
        self.state.mkdir()
        self.lock = self.root / "monitor.lock"
        self.lock.touch()
        environment = mock.patch.dict(
            os.environ, {"LLDPQ_MONITOR_LOCK_FILE": str(self.lock)}
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.ns = load_symbols(
            *REDACTION_SYMBOLS,
            "_redact_report", "_commit_analysis_state",
            "_save_json_state", "_load_json_file", "action_analyze",
            "FINDING_CATEGORIES", "_SEVERITY_RANK",
            "_normalize_findings", "_parse_findings_json",
        )
        self.ns.update(
            os=os, tempfile=tempfile,
            AI_PROVIDER="ollama", AI_MODEL="local-model", AI_FALLBACK_MODEL="",
            AI_STATE_DIR=str(self.state), WEB_ROOT=str(self.root / "web"),
            ANALYSIS_FILE=str(self.state / "analysis.json"),
            _ensure_state_dir=lambda: None,
            _generation_still_current=lambda *_args: True,
            _classified_findings_or_fallback=(
                lambda findings, _covered, persist=True: (
                    [dict(item, status="NEW") for item in findings or []],
                    {"resolved": 0},
                )
            ),
        )

    def stored_text(self):
        return (self.state / "analysis.json").read_text(encoding="utf-8")

    def test_commit_masks_every_text_field_for_a_local_provider(self):
        analysis = {
            "timestamp": 1.0,
            "analysis": f"leaf01 BGP password {FIRST} changed in the last diff.",
            "provider": "ollama",
            "changes": [f"leaf02: snmp readonly-community {SECOND} added"],
            "audit_verifications": [
                {"device": "leaf01", "pack": "bgp", "verdict": f"secret {FIRST}"},
            ],
            "device_count": 2,
        }
        persisted = self.ns["_commit_analysis_state"](
            {}, {}, analysis, None,
            findings=[{
                "severity": "WARNING", "category": "CONFIG", "device": "leaf01",
                "description": f"new line: auth-sha {FIRST} encrypt-aes {SECOND}",
            }],
            covered_devices={"leaf01"},
        )
        self.assertTrue(persisted)
        stored = self.stored_text()
        self.assertNotIn(FIRST, stored)
        self.assertNotIn(SECOND, stored)
        document = json.loads(stored)
        self.assertEqual(
            document["analysis"],
            f"leaf01 BGP password {MARK} changed in the last diff.",
        )
        self.assertEqual(document["findings"][0]["status"], "NEW")
        self.assertIn(MARK, document["findings"][0]["description"])
        self.assertEqual(document["device_count"], 2)
        self.assertEqual(document["timestamp"], 1.0)

        # The documented public export keeps serving the stored file as is.
        export = subprocess.run(
            ["bash", str(ROOT / "html" / "ai-export-api.sh")],
            env={
                "PATH": os.environ.get("PATH", ""),
                "REQUEST_METHOD": "GET",
                "AI_STATE_DIR": str(self.state),
            },
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(export.returncode, 0, export.stderr)
        headers, body = export.stdout.split("\n\n", 1)
        self.assertIn("Status: 200 OK", headers)
        self.assertEqual(body, stored)
        exported = json.loads(body)
        self.assertTrue(exported["analysis"].strip())
        self.assertNotIn(FIRST, body)
        self.assertNotIn(SECOND, body)

    def run_analyze(self, cron, changed_configs=("leaf01",), reply=None):
        """Drive the real action_analyze with a stand-in local model."""
        requests = []
        result = {}
        metadata = {"complete": True, "report_persistable": True}
        reply = reply or (
            "```json\n"
            + json.dumps([{
                "severity": "WARNING", "category": "CONFIG", "device": "leaf01",
                "description": f"readonly-community-v6 {SECOND} was added",
            }])
            + "\n```\n"
            + f"The drift shows neighbor swp1 password {SECOND} on leaf01."
        )

        def llm(messages, **_kwargs):
            requests.append([dict(message) for message in messages])
            return {"ok": True, "text": reply, "provider": "ollama",
                    "model": "local-model", "fallback_used": False}

        def capture(payload):
            result.update(payload)
            raise SystemExit

        self.ns.update({
            "build_fabric_summary": lambda: (
                f"leaf01 snmp rocommunity {FIRST}", {}, {}, metadata
            ),
            "build_device_list": lambda *_args: "leaf01",
            "neutralize_untrusted_tool_tags": lambda value: value,
            "neutralize_untrusted_observation_text": lambda value: value,
            "_build_timeline": lambda *_args, **_kwargs: {},
            "_collection_for_evidence": lambda *_args: metadata,
            "_new_context_state": lambda: {},
            "_JOB_CONTEXT": None,
            "_health_snapshot": lambda *_args: {"leaf01": "ok"},
            "_running_config_hashes": lambda: {},
            "_config_drift_devices": lambda _hashes: list(changed_configs),
            "_diff_snapshots": lambda *_args: [],
            "_timeline_event_fingerprint": lambda _timeline: (),
            "ANALYSIS_REUSE_MAX_AGE_SECONDS": 3600,
            "ANALYSIS_REUSE_MAX_TEXT_AGE_SECONDS": 3600,
            "_mr_path": lambda *parts: str(self.root.joinpath("mr", *parts)),
            "build_recent_changes_context": lambda _changed: (
                f"+ nv set vrf default router bgp neighbor swp1 password {FIRST}\n"
                f"+ createUser monitor SHA {FIRST} AES {FIRST}"
            ),
            "_timeline_context": lambda _timeline: "",
            "_FINDINGS_CONTRACT_PROMPT": "",
            "_reduce_untrusted_context_if_needed": (
                lambda content, *_args, **_kwargs: content
            ),
            "call_llm_sync": llm,
            "_build_evidence": lambda *_args, **_kwargs: {
                "records": [], "confidence": {},
            },
            "_apply_suppressions": lambda findings, _devices: findings,
            "_covered_devices_for_findings": lambda *_args: {"leaf01"},
            "_run_critical_drilldown": lambda *_args, **_kwargs: ("", []),
            "_build_analysis_v2": lambda *_args, **_kwargs: {},
            "_job_cancelled": lambda: False,
            "result_json": capture,
            "error_json": lambda message: self.fail(message),
        })
        user = "lldpq-ai-cron" if cron else "admin"
        with mock.patch.dict(os.environ, {"LLDPQ_AUTH_USER": user}):
            with self.assertRaises(SystemExit):
                self.ns["action_analyze"]()
        return requests, result

    def test_local_model_never_sees_secrets_and_report_is_stored_masked(self):
        for cron in (False, True):
            with self.subTest(cron=cron):
                requests, result = self.run_analyze(cron)
                # Cron runs the scan stage first, then synthesis.
                self.assertEqual(len(requests), 2 if cron else 1)
                for messages in requests:
                    sent = "\n".join(message["content"] for message in messages)
                    self.assertNotIn(FIRST, sent)
                    self.assertIn(f"password {MARK}", sent)
                    self.assertIn(f"rocommunity {MARK}", sent)
                self.assertTrue(result["success"])
                self.assertTrue(result["persisted"])
                # The reply lands in the job event log / the cron log.
                reply = json.dumps(result)
                self.assertNotIn(FIRST, reply)
                self.assertNotIn(SECOND, reply)
                self.assertIn(f"password {MARK}", result["analysis"])
                self.assertIn(MARK, result["findings"][0]["description"])
                stored = self.stored_text()
                self.assertNotIn(FIRST, stored)
                self.assertNotIn(SECOND, stored)
                document = json.loads(stored)
                self.assertEqual(document["provider"], "ollama")
                self.assertIn(f"password {MARK}", document["analysis"])
                self.assertIn(MARK, document["findings"][0]["description"])

    def test_scan_clean_reply_masks_resolved_ledger_findings(self):
        # Cron scan returns []: synthesis is skipped and the reply carries the
        # RESOLVED records of the findings ledger, whose descriptions an older
        # version may have stored unmasked for a local provider.
        self.ns["_classified_findings_or_fallback"] = (
            lambda _findings, _covered, persist=True: (
                [{
                    "severity": "WARNING", "category": "CONFIG", "device": "leaf01",
                    "description": f"neighbor swp1 password {SECOND} was added",
                    "fingerprint": "0123456789ab", "status": "RESOLVED",
                }],
                {"resolved": 1},
            )
        )
        requests, result = self.run_analyze(cron=True, reply="[]")
        self.assertEqual(len(requests), 1)
        self.assertEqual(result["stages"], ["scan"])
        self.assertIn("Fabric scan: clean", result["analysis"])
        self.assertTrue(result["persisted"])
        # The reply lands in the cron log.
        for text in (json.dumps(result), self.stored_text()):
            self.assertNotIn(FIRST, text)
            self.assertNotIn(SECOND, text)
        masked = f"neighbor swp1 password {MARK} was added"
        self.assertEqual(result["findings"][0]["status"], "RESOLVED")
        self.assertEqual(result["findings"][0]["description"], masked)
        document = json.loads(self.stored_text())
        self.assertEqual(document["findings"][0]["status"], "RESOLVED")
        self.assertEqual(document["findings"][0]["description"], masked)

    def test_report_stored_before_the_upgrade_is_masked_when_it_is_reused(self):
        # Steady state: nothing changed, so the previous text is carried
        # forward without an LLM call. A report written by an older version
        # for a local provider may still hold unmasked values.
        (self.state / "analysis-snapshot.json").write_text(
            json.dumps({"statuses": {"leaf01": "ok"}}), encoding="utf-8"
        )
        (self.state / "analysis.json").write_text(json.dumps({
            "timestamp": time.time() - 60,
            "analysis": f"leaf01: neighbor swp1 password {FIRST} is configured.",
            "provider": "ollama", "model": "local-model",
            "collection": {"complete": True},
            "findings": [{
                "severity": "INFO", "category": "CONFIG", "device": "leaf01",
                "description": f"auth_token: {SECOND}", "status": "ONGOING",
            }],
        }), encoding="utf-8")
        requests, result = self.run_analyze(cron=True, changed_configs=())
        self.assertEqual(requests, [])
        self.assertTrue(result["reused"])
        self.assertTrue(result["persisted"])
        for text in (json.dumps(result), self.stored_text()):
            self.assertNotIn(FIRST, text)
            self.assertNotIn(SECOND, text)
        document = json.loads(self.stored_text())
        self.assertEqual(
            document["analysis"],
            f"leaf01: neighbor swp1 password {MARK} is configured.",
        )
        self.assertEqual(document["findings"][0]["description"], f"auth_token: {MARK}")

    def test_only_the_analysis_path_overrides_the_local_provider_rule(self):
        # Chat with a local model keeps its unredacted context: the shared
        # egress gate stays cloud-only.
        ns = load_symbols(
            *REDACTION_SYMBOLS, "provider_is_cloud", "prepare_outbound_messages",
        )
        ns["AI_PROVIDER"] = "ollama"
        message = [{"role": "user", "content": f"password {FIRST}"}]
        self.assertIn(
            FIRST,
            ns["prepare_outbound_messages"](message, provider="ollama")[0]["content"],
        )
        self.assertNotIn(
            FIRST,
            ns["prepare_outbound_messages"](message, provider="openai")[0]["content"],
        )
        self.assertEqual(
            PYTHON_TEXT.count("redact_secrets(analysis_observations),"), 2
        )


if __name__ == "__main__":
    unittest.main()
