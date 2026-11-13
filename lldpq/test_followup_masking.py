#!/usr/bin/env python3
"""Ask-AI secret masking follow-up.

1. A value the released (4.2.x) patterns masked stays masked when keys are
   added: a new key must not take an old key as its value.
2. Keys behind "_" (ansible_password, snmp_community) and JSON-quoted keys
   with a string value are masked too.

Every credential-looking value below is invented for these tests.
"""

from __future__ import annotations

import ast
import json
import random
import re
import subprocess
import unittest

from test_ai_api_contract import ROOT, load_symbols


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

# The last commit before the key list was widened; 4.2.5 carries the same code.
RELEASED_COMMIT = "3a559dc47e5abb773a73ccd102cf7a788de17f1e"
RELEASED_VALUE = r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|\S+)'
RELEASED_TYPED = (
    r'(?i)\b(password|passwd|secret|key-string|psk|pre-?shared-?key|md5|'
    r'auth-?key|priv-?key|wpa-psk)\b'
    r'(\s*(?::|=)\s*|\s+)[0-9]{1,2}\s+' + RELEASED_VALUE
)
RELEASED_PLAIN = (
    r'(?i)\b(password|passwd|secret|community|key-string|psk|pre-?shared-?key|md5|'
    r'auth-?key|priv-?key|snmp-community|wpa-psk|api[-_]?key|token)\b'
    r'(\s*(?::|=)\s*|\s+)' + RELEASED_VALUE
)


def _keep_key(match):
    return "%s%s***REDACTED***" % (match.group(1), match.group(2))


def released_redact(text):
    """redact_secrets as released, frozen here: no git history is needed."""
    if not text:
        return text
    text = re.sub(RELEASED_TYPED, _keep_key, text)
    text = re.sub(RELEASED_PLAIN, _keep_key, text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                  '***PRIVATE KEY REDACTED***', text, flags=re.DOTALL)
    text = re.sub(r'(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)(\S+)',
                  r'\1***REDACTED***', text)
    text = re.sub(r'(?i)(https?://[^\s/@:]+:)([^\s/@]+)(@)', r'\1***REDACTED***\3', text)
    text = re.sub(r'(?i)([?&](?:key|api[-_]?key|token)=)[^&\s]+', r'\1***REDACTED***', text)
    return text


def redactor_from_commit(commit):
    """redact_secrets of html/ai-api.sh at a commit; None without that history.

    "git show" only reads the object store.
    """
    if not (ROOT / ".git").exists():
        return None
    try:
        shown = subprocess.run(
            ["git", "-C", str(ROOT), "show", commit + ":html/ai-api.sh"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if shown.returncode != 0 or "def redact_secrets(" not in shown.stdout:
        return None
    script = shown.stdout
    start = script.index("python3 << 'PYTHON_SCRIPT'") + len("python3 << 'PYTHON_SCRIPT'")
    body = script[start:script.rindex("\nPYTHON_SCRIPT")]
    wanted = set(REDACTION_SYMBOLS)
    nodes = []
    for node in ast.parse(body).body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and wanted & {
            target.id for target in node.targets if isinstance(target, ast.Name)
        }:
            nodes.append(node)
    namespace = {"re": re}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), commit, "exec"), namespace)
    return namespace


# Input the released patterns already handled, in the shapes the tool sees.
RELEASED_LINES = (
    # nv config show -o commands
    f"nv set vrf default router bgp neighbor swp1 password {FIRST}",
    f"nv set vrf default router bgp peer-group underlay password '{FIRST}'",
    f"nv set system aaa user cumulus hashed-password '{FIRST}'",
    f"nv set system aaa tacacs server 10.0.0.1 secret {FIRST}",
    f"nv set system aaa radius server 10.0.0.2 secret {FIRST}",
    f"nv set system dot1x radius server 10.0.0.3 shared-secret {FIRST}",
    f"nv set system snmp-server readonly-community {FIRST} access any",
    f"nv set system snmp-server trap-destination 10.0.0.9 community-password {FIRST} version-2c",
    f"nv set system snmp-server username monitor auth-md5 {FIRST}",
    # frr.conf
    f" neighbor swp1 password {FIRST}",
    f" neighbor 10.0.0.1 password {FIRST}",
    f" ip ospf message-digest-key 1 md5 {FIRST}",
    f"password 8 {FIRST}",
    f"enable password {FIRST}",
    f" key-string {FIRST}",
    f" key-string 7 {FIRST}",
    # nv config show (YAML): the secret is the key on the next line
    f"        readonly-community:\n          {FIRST}:\n            access:",
    f"          password: {FIRST}",
    f"          hashed-password: '{FIRST}'",
    f"              secret: {FIRST}",
    # YAML / Ansible vars
    f"password: {FIRST}",
    f"secret: \"{FIRST}\"",
    f"community: {FIRST}",
    f"api_key: {FIRST}",
    f"token: {FIRST}",
    f"- name: fabric\n  password: {FIRST}\n  psk: {SECOND}",
    # key=value env lines
    f"PASSWORD={FIRST}",
    f"TOKEN={FIRST}",
    f"API_KEY=\"{FIRST}\"",
    f"wpa-psk={FIRST}",
    # hostapd / snmptrapd / misc
    f"snmp-community {FIRST}",
    f"pre-shared-key {FIRST}",
    f"auth-key {FIRST} priv-key {SECOND}",
    f"Authorization: Bearer {FIRST}",
    f"curl -H 'Authorization: Basic {FIRST}' https://192.0.2.10/api",
    f"https://backup:{FIRST}@192.0.2.10/configs",
    f"https://example.invalid/v1/models?key={FIRST}&alt=json",
    f"https://example.invalid/hook?token={FIRST}",
    "-----BEGIN OPENSSH PRIVATE KEY-----\n" + FIRST + "\n-----END OPENSSH PRIVATE KEY-----",
    # prose and punctuation right after a quoted value
    f"password \"{FIRST}\", next",
    f"community \"{FIRST}\": rest",
    f"{{password: \"{FIRST}\"}}",
    f"secret='{FIRST}')",
    # nothing to mask
    "nv set interface swp1 link state up",
    "nv set system snmp-server listening-address localhost",
    "nv set vrf default router bgp neighbor swp1 remote-as external",
    "router bgp 65101 vrf default",
    "bgp community-list standard CL1 permit 65000:1",
    "ip ospf authentication message-digest",
    "password-obfuscation enabled",
    "secret-lifetime 30",
    "max_tokens: 4096",
    "token_count 15",
    "leaf01 swp1 rx_power -3.2 dBm cable CAB-0001",
    "agentAddress udp:161",
)

# Input with a key added after the release: next to an old key, or on its own.
ADDED_KEY_LINES = (
    f"nv set system snmp-server readonly-community-v6 {FIRST} access any",
    f"nv set system snmp-server username monitor auth-sha {FIRST} encrypt-aes {SECOND}",
    f"nv set system snmp-server username monitor auth-md5 {FIRST} encrypt-des {SECOND}",
    f"nv set interface swp51 router ospf authentication md5-key {FIRST}",
    f"rocommunity {FIRST} default",
    f"rwcommunity6 {FIRST} 2001:db8::/64",
    f"createUser monitor SHA {FIRST} AES {SECOND}",
    f"createUser monitor MD5 {FIRST} DES {SECOND}",
    f"com2sec readonly default {FIRST}",
    f" ip ospf authentication-key {FIRST}",
    f"            auth-sha:\n              {FIRST}:\n                encrypt-aes:\n"
    f"                  {SECOND}: {{}}",
    f"ansible_password: {FIRST}",
    f"ansible_become_password={FIRST}",
    f"ansible_ssh_pass={FIRST}",
    f"leaf01 ansible_host=192.0.2.11 ansible_user=cumulus ansible_password={FIRST}",
    f"bgp_password: \"{FIRST}\"",
    f"snmp_community: {FIRST}",
    f"tacacs_secret: {FIRST}\nradius_secret: {SECOND}",
    f"SNMP_RO_COMMUNITY={FIRST}",
    f"export GITLAB_TOKEN={FIRST}",
    f"AI_API_KEY={FIRST}",
    f"DB_PASSWORD=\"{FIRST}\"",
    f"{{\"username\": \"cumulus\", \"password\": \"{FIRST}\"}}",
    f"      \"hashed-password\": \"{FIRST}\",",
    f"{{\"snmp_community\": \"{FIRST}\", \"auth_token\": \"{SECOND}\"}}",
    # a new key directly in front of an old one
    f"mka_cak: secret {FIRST}",
    f"x_token password {FIRST}",
    f"readonly-community-v6 password {FIRST}",
    f"encrypt-des=auth-md5 {FIRST}",
    f"authentication-key 7 password {FIRST}",
    f"x_token authorization: Bearer {FIRST}",
    f"x_token: a=password {FIRST}",
    f"bgp_password: token: {FIRST}",
    f"ansible_password \"password\" {FIRST}",
    f"snmp_community = community {FIRST}",
    f"auth-sha https://backup:{FIRST}@192.0.2.10/configs",
    f"rocommunity https://example.invalid/v1/models?key={FIRST}",
)

# What 4.2.x returned for the reported inputs: the value was masked.
PINNED_RELEASED_RESULTS = (
    (f"mka_cak: secret {FIRST}", f"mka_cak: secret {MARK}"),
    (f"x_token password {FIRST}", f"x_token password {MARK}"),
    (f"readonly-community-v6 password {FIRST}", f"readonly-community-v6 password {MARK}"),
    (f"encrypt-des=auth-md5 {FIRST}", f"encrypt-des=auth-md5 {MARK}"),
    (f"authentication-key 7 password {FIRST}", f"authentication-key 7 password {MARK}"),
    (f"x_token authorization: Bearer {FIRST}", f"x_token authorization: Bearer {MARK}"),
    (f"x_token: a=password {FIRST}", f"x_token: a=password {MARK}"),
)

FUZZ_KEYS = (
    "password", "passwd", "secret", "community", "key-string", "psk", "pre-shared-key",
    "md5", "auth-key", "priv-key", "snmp-community", "wpa-psk", "api_key", "token",
    "readonly-community-v6", "rocommunity", "rwcommunity6", "x_token", "mka_cak", "cak",
    "auth-sha", "auth-md5", "auth-sha-512", "encrypt-aes", "encrypt-des", "md5-key",
    "authentication-key", "ansible_password", "bgp_password", "snmp_community",
    "bgp_community", "ansible_ssh_pass", "enable_secret", "key_string", "pre_shared_key",
    "\"password\"", "\"token\"", "\"snmp_community\"", "createUser", "SHA", "AES", "MD5",
    "Authorization: Bearer", "https://u:", "@h/p?key=", "&token=", "a=", "x",
)
FUZZ_SEPARATORS = (
    " ", " ", " ", ": ", "=", " = ", ":", "\n  ", ":\n    ", " 7 ", " 0 ", ",",
    "\": \"", "\":\"", "\", \"", "\"", "'", "-", "_", "{", "}",
)


def fuzz_lines(count, seed=20261112):
    """Deterministic key/separator/value chains; yields (line, values)."""
    rng = random.Random(seed)
    for index in range(count):
        parts, values = [], []
        for position in range(rng.randint(2, 7)):
            if rng.random() < 0.35:
                values.append("V%dq%dz" % (index, position))
                parts.append(values[-1])
            else:
                parts.append(rng.choice(FUZZ_KEYS))
            parts.append(rng.choice(FUZZ_SEPARATORS))
        yield "".join(parts), values


class ReleasedMaskingIsKeptTests(unittest.TestCase):
    def setUp(self):
        self.symbols = load_symbols(*REDACTION_SYMBOLS)
        self.redact = self.symbols["redact_secrets"]

    def assert_nothing_lost(self, line, values):
        released = released_redact(line)
        current = self.redact(line)
        for value in values:
            if value in line and value not in released:
                self.assertNotIn(value, current, "4.2.x masked this value: %r" % line)

    def test_frozen_reference_is_the_released_code(self):
        released = redactor_from_commit(RELEASED_COMMIT)
        if released is None:
            self.skipTest("no git history with commit %s" % RELEASED_COMMIT[:8])
        self.assertEqual(released["_TYPED_SECRET_RE"].pattern, RELEASED_TYPED)
        self.assertEqual(released["_SECRET_RE"].pattern, RELEASED_PLAIN)
        lines = list(RELEASED_LINES + ADDED_KEY_LINES)
        lines += [line for line, _values in fuzz_lines(1500)]
        for line in lines:
            self.assertEqual(released["redact_secrets"](line), released_redact(line), line)

    def test_the_released_patterns_are_applied_unchanged(self):
        self.assertEqual(self.symbols["_TYPED_SECRET_RE"].pattern, RELEASED_TYPED)
        self.assertEqual(self.symbols["_SECRET_RE"].pattern, RELEASED_PLAIN)

    def test_reported_new_key_before_old_key_keeps_the_value_masked(self):
        for line, released in PINNED_RELEASED_RESULTS:
            with self.subTest(line=line):
                self.assertEqual(released_redact(line), released)
                masked = self.redact(line)
                self.assertNotIn(FIRST, masked)
                self.assertTrue(masked.endswith(MARK), masked)

    def test_no_corpus_line_loses_masking(self):
        for line in RELEASED_LINES + ADDED_KEY_LINES:
            with self.subTest(line=line):
                self.assert_nothing_lost(line, (FIRST, SECOND))

    def test_input_without_added_keys_gives_the_released_result(self):
        # Existing installations: same text out as before, byte for byte.
        for line in RELEASED_LINES:
            with self.subTest(line=line):
                self.assertEqual(self.redact(line), released_redact(line))

    def test_random_key_chains_never_lose_masking(self):
        masked_by_release = 0
        for line, values in fuzz_lines(4000):
            released = released_redact(line)
            masked_by_release += sum(value not in released for value in values)
            self.assert_nothing_lost(line, values)
        # The chains must exercise the property, not pass because nothing matched.
        self.assertGreater(masked_by_release, 300)


class UnderscoreKeyTests(unittest.TestCase):
    """A key is the last part of a name joined with "_", as it already was
    with "-" (hashed-password, shared-secret)."""

    def setUp(self):
        self.redact = load_symbols(*REDACTION_SYMBOLS)["redact_secrets"]

    def test_keys_behind_an_underscore_are_masked(self):
        cases = (
            (f"ansible_password: {FIRST}", f"ansible_password: {MARK}"),
            (f"ansible_become_password={FIRST}", f"ansible_become_password={MARK}"),
            (f"ansible_ssh_pass={FIRST}", f"ansible_ssh_pass={MARK}"),
            (f"bgp_password: {FIRST}", f"bgp_password: {MARK}"),
            (f"BGP_PASSWORD={FIRST}", f"BGP_PASSWORD={MARK}"),
            (f"admin_passwd: {FIRST}", f"admin_passwd: {MARK}"),
            (f"snmp_community: {FIRST}", f"snmp_community: {MARK}"),
            (f"snmp_ro_community: {FIRST}", f"snmp_ro_community: {MARK}"),
            (f"SNMP_RW_COMMUNITY={FIRST}", f"SNMP_RW_COMMUNITY={MARK}"),
            (f"snmp_rocommunity: {FIRST}", f"snmp_rocommunity: {MARK}"),
            (f"ro_community: {FIRST}", f"ro_community: {MARK}"),
            (f"snmp_trap_community: {FIRST}", f"snmp_trap_community: {MARK}"),
            (f"snmpd_readonly_community = {FIRST}", f"snmpd_readonly_community = {MARK}"),
            # one name for each remaining SNMP prefix ("readwrite_" also ends
            # in "write_", so that line needs either of the two)
            (f"snmpd_community: {FIRST}", f"snmpd_community: {MARK}"),
            (f"read_community: {FIRST}", f"read_community: {MARK}"),
            (f"write_community: {FIRST}", f"write_community: {MARK}"),
            (f"readwrite_community: {FIRST}", f"readwrite_community: {MARK}"),
            (f"v2c_community: {FIRST}", f"v2c_community: {MARK}"),
            (f"tacacs_secret: {FIRST}", f"tacacs_secret: {MARK}"),
            (f"client_secret = \"{FIRST}\"", f"client_secret = {MARK}"),
            (f"wifi_psk: {FIRST}", f"wifi_psk: {MARK}"),
            (f"ospf_auth_key: {FIRST}", f"ospf_auth_key: {MARK}"),
            (f"snmp_priv_key: {FIRST}", f"snmp_priv_key: {MARK}"),
            (f"key_string: {FIRST}", f"key_string: {MARK}"),
            (f"pre_shared_key: {FIRST}", f"pre_shared_key: {MARK}"),
            (f"authentication_key: {FIRST}", f"authentication_key: {MARK}"),
            (f"openai_api_key: {FIRST}", f"openai_api_key: {MARK}"),
            (f"ospf_md5_key: {FIRST}", f"ospf_md5_key: {MARK}"),
            (f"_token: {FIRST}", f"_token: {MARK}"),
            # a numeric type in front of the value goes with it
            (f"enable_secret: 5 {FIRST}", f"enable_secret: {MARK}"),
            (f"bgp_password 7 {FIRST}", f"bgp_password {MARK}"),
            # NVUE OSPF key: no released key matches "md5-key"
            (f"nv set interface swp51 router ospf authentication md5-key {FIRST}",
             f"nv set interface swp51 router ospf authentication md5-key {MARK}"),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                masked = self.redact(line)
                self.assertEqual(masked, expected)
                # A second pass (egress gate after the pre-split pass) is a no-op.
                self.assertEqual(self.redact(masked), masked)

    def test_names_that_only_contain_a_key_keep_their_value(self):
        lines = (
            # BGP communities are diagnostics, not SNMP community names
            "bgp_community: 65000:100",
            "large_community: 65000:1:1",
            "send_community: both",
            "metro_community: 65000:100",
            # the key is not the last part of the name
            "password-obfuscation enabled",
            "secret-lifetime 30",
            "password_policy: strict",
            "secret_rotation_days: 30",
            "token_count 15",
            "max_tokens: 4096",
            "auth_key_id: 12",
            # no "_" or "-" in front of the key
            "mypassword: plain",
            "bypass: true",
            "compass: north",
            "pass: 3",
            # a checksum, not a key
            "file_md5: 9e107d9d372bb6826bd81d3542a419d6",
            "image_md5 9e107d9d372bb6826bd81d3542a419d6",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.redact(line), line)
                self.assertEqual(released_redact(line), line)


class JsonKeyTests(unittest.TestCase):
    """nv ... -o json: "key": "value". Only a string value is a secret."""

    def setUp(self):
        self.redact = load_symbols(*REDACTION_SYMBOLS)["redact_secrets"]

    def test_string_values_are_masked_and_the_document_stays_json(self):
        documents = (
            {"username": "cumulus", "password": FIRST, "role": "system-admin"},
            {"hashed-password": FIRST},
            {"snmp_community": FIRST, "ansible_password": SECOND},
            {"auth_token": FIRST, "api_key": SECOND},
            {"tacacs": {"server": {"10.0.0.1": {"secret": FIRST, "port": 49}}}},
            {"password": "a\"b\\" + FIRST, "enable": "on"},
            {"community": FIRST},
            {"md5-key": FIRST, "message-digest-key": 1},
        )
        for document in documents:
            for text in (
                json.dumps(document),
                json.dumps(document, indent=2),
                json.dumps(document, separators=(",", ":")),
            ):
                with self.subTest(text=text):
                    masked = self.redact(text)
                    self.assertNotIn(FIRST, masked)
                    self.assertNotIn(SECOND, masked)
                    self.assertEqual(self.redact(masked), masked)
                    self.assertEqual(
                        json.loads(masked),
                        json.loads(text, object_hook=self.masked_copy),
                    )

    @staticmethod
    def masked_copy(mapping):
        secret_keys = {
            "password", "hashed-password", "snmp_community", "ansible_password",
            "auth_token", "api_key", "secret", "community", "md5-key",
        }
        return {
            key: MARK if key in secret_keys and isinstance(value, str) else value
            for key, value in mapping.items()
        }

    def test_structure_and_other_value_types_are_not_touched(self):
        lines = (
            # FRR "show bgp ... json": communities are objects and lists
            '"community": {"string": "65000:100 no-export", "list": ["65000:100", "no-export"]}',
            '"largeCommunity": {"string": "65000:1:1", "list": ["65000:1:1"]}',
            '"communityList": "CL1"',
            # NVUE route-map JSON: the community is an object key
            '"set": {"community": {"65000:100": {}}}',
            '"bgp_community": "65000:100"',
            '"password": null',
            '"password": 12345',
            '"token": true',
            '"secret": {"rotation": 30}',
            '"password": ["a", "b"]',
            '"password": ""',
            '"password-obfuscation": "enabled"',
            '"token_count": "15"',
            '"max_tokens": "4096"',
            '"file_md5": "9e107d9d372bb6826bd81d3542a419d6"',
            '"hostname": "leaf01", "state": "up"',
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(self.redact(line), line)


if __name__ == "__main__":
    unittest.main()
