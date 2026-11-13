#!/usr/bin/env python3
"""Timeline/evidence detail masking (html/ai_insights.py) knows the keys that
Ask-AI's redact_secrets knows, without losing what it masked before.

Every credential-looking value below is invented for these tests.
"""

from __future__ import annotations

import re
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_insights  # noqa: E402
from ai_insights import _redacted_detail  # noqa: E402

FIRST = "ZZinventedVALUE99"
SECOND = "YYinventedSECOND77"
MARK = "[redacted]"

# The two patterns as released, frozen here as the reference.
RELEASED_ASSIGN = re.compile(
    r"(?i)\b(authorization|api[-_ ]?key|access[-_ ]?token|token|password|passwd|secret)"
    r"\s*([:=])\s*([^\s,;]+)"
)
RELEASED_NETWORK = re.compile(
    r"(?i)\b(snmp[-_ ]?community|community|key[-_ ]?string|psk|password|passwd)"
    r"(?:\s+7)?\s*(?:[:=]|\s)\s*([^\s,;]+)"
)


def released_detail(text):
    """The credential part of _redacted_detail as released."""
    text = RELEASED_ASSIGN.sub(lambda m: "%s%s[redacted]" % (m.group(1), m.group(2)), text)
    return RELEASED_NETWORK.sub(lambda m: "%s [redacted]" % m.group(1), text)


class InsightsDetailMaskingTests(unittest.TestCase):
    def test_keys_ask_ai_masks_are_masked_here_too(self):
        cases = (
            (f"snmp-server readonly-community-v6 {FIRST} access any",
             f"snmp-server readonly-community-v6 {MARK} access any"),
            (f"rocommunity {FIRST} default", f"rocommunity {MARK} default"),
            (f"rwcommunity6 {FIRST}", f"rwcommunity6 {MARK}"),
            (f"username monitor auth-sha {FIRST} encrypt-aes {SECOND}",
             f"username monitor auth-sha {MARK} encrypt-aes {MARK}"),
            (f"username monitor auth-md5 {FIRST} encrypt-des {SECOND}",
             f"username monitor auth-md5 {MARK} encrypt-des {MARK}"),
            (f"auth-sha-512 {FIRST} encrypt-aes-256 {SECOND}",
             f"auth-sha-512 {MARK} encrypt-aes-256 {MARK}"),
            (f"createUser monitor SHA {FIRST} AES {SECOND}",
             f"createUser monitor SHA {MARK} AES {MARK}"),
            (f"createUser monitor MD5 {FIRST} DES",
             f"createUser monitor MD5 {MARK} DES"),
            (f"createUser -e 0x8000000001020304 monitor SHA-512 {FIRST} AES-256 {SECOND}",
             f"createUser -e 0x8000000001020304 monitor SHA-512 {MARK} AES-256 {MARK}"),
            (f"ip ospf authentication-key {FIRST}", f"ip ospf authentication-key {MARK}"),
            (f"macsec cak {FIRST}", f"macsec cak {MARK}"),
            (f"mka_cak={FIRST}", f"mka_cak {MARK}"),
            (f"auth_token: {FIRST}", f"auth_token {MARK}"),
            (f"tacacs server 10.0.0.1 secret {FIRST}", f"tacacs server 10.0.0.1 secret {MARK}"),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(_redacted_detail(line), expected)
                # Event ids hash this text: a second pass must not move it.
                self.assertEqual(_redacted_detail(expected), expected)

    def test_text_the_released_patterns_handled_is_unchanged(self):
        lines = (
            f"token={FIRST} community {SECOND} password 7 {FIRST}",
            f"secret: {FIRST}, api_key={SECOND}",
            f"snmp community {FIRST}; key-string {SECOND}",
            f"access_token = {FIRST}",
            "bgp community-list standard CL1 permit 65000:1",
            "bgp_community 65000:100",
            "max_tokens: 4096",
            "token_count 15",
            "auth-none",
            "leaf01 swp1 rx_power -3.2 dBm cable CAB-0001",
            "BGP neighbor swp1 went from Established to Idle",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(_redacted_detail(line), released_detail(line))

    def test_new_key_before_old_key_keeps_the_value_masked(self):
        lines = (
            f"rocommunity password {FIRST}",
            f"readonly-community-v6 community {FIRST}",
            f"mka_cak: secret={FIRST}",
            f"auth-sha token={FIRST}",
            f"x_token: psk {FIRST}",
            f"authentication-key 7 password {FIRST}",
            f"encrypt-aes key-string {FIRST}",
        )
        for line in lines:
            with self.subTest(line=line):
                self.assertNotIn(FIRST, released_detail(line))
                self.assertNotIn(FIRST, _redacted_detail(line))

    def test_the_released_patterns_are_applied_unchanged(self):
        self.assertEqual(ai_insights._SECRET_ASSIGN_RE.pattern, RELEASED_ASSIGN.pattern)
        self.assertEqual(ai_insights._NETWORK_SECRET_RE.pattern, RELEASED_NETWORK.pattern)

    def test_repeated_key_parts_stay_linear(self):
        for unit in ("auth-sha-", "encrypt-aes-", "x_token_", "a_", "createUser ", "SHA-"):
            with self.subTest(unit=unit):
                text = unit * 4000
                started = time.process_time()
                _redacted_detail(text, limit=len(text) + 1)
                self.assertLess(time.process_time() - started, 0.5)


if __name__ == "__main__":
    unittest.main()
