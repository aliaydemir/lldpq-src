#!/usr/bin/env python3
"""html/ai_generate.py passes re count/maxsplit/flags by keyword.

Python 3.13 deprecated the positional form; the image's Python does not warn
yet, so the source contract below holds on every interpreter while the
behavioral test fails on the ones that already warn.
"""

from __future__ import annotations

import ast
import sys
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_generate  # noqa: E402


def _conn(src, sport, dst, dport):
    return {
        "source_name": src, "source_port": sport,
        "dest_name": dst, "dest_port": dport,
        "connection_type": "oob", "network_type": "eth",
        "unresolved": False,
    }


class RePositionalArgumentTests(unittest.TestCase):
    def test_host_family_stagger_rule_emits_no_deprecation_warning(self):
        ipam = {"format": "ipam", "subnets": [], "hosts": [], "fabric": [
            {"hostname": "oob-tor-1-%d-01" % i, "role": "oob_tor",
             "mgmt_ip": "10.0.2.%d" % i} for i in (1, 2)
        ]}
        p2p = [
            _conn("gb300-1-%d-dgx-c01" % i, "BMC", "oob-tor-1-1-01", "%d" % i)
            for i in (1, 2, 3, 4)
        ]
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            cfg = ai_generate.ipam_to_topology_config_yaml(ipam, p2p=p2p)
        # The family name is everything before the first '-' or '_'.
        self.assertIn('pattern: "gb300"', cfg)

    def test_re_calls_pass_only_pattern_and_string_positionally(self):
        # re.split(pattern, string, maxsplit, flags) and
        # re.sub/subn(pattern, repl, string, count, flags).
        positional_limit = {"split": 2, "sub": 3, "subn": 3}
        tree = ast.parse(
            (ROOT / "html" / "ai_generate.py").read_text(encoding="utf-8")
        )
        offenders = []
        checked = 0
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "re"
                    and node.func.attr in positional_limit):
                continue
            checked += 1
            if len(node.args) > positional_limit[node.func.attr]:
                offenders.append("line %d: re.%s" % (node.lineno, node.func.attr))
        self.assertGreater(checked, 0)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
