#!/usr/bin/env python3
"""Regression tests for fabric-api.sh interface/external-peer edit paths.

Covers two heredoc-embedded python bodies:
- update-interface (subif branch): YAML keys subinterfaces as int OR str;
  an edit must land on the existing entry instead of creating a duplicate
  parallel key form.
- update-external-peer: a bare local_ip (the UI strips the prefix for
  display) must preserve the existing subinterface's prefix length instead
  of silently rewriting it to /31.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import textwrap
import unittest
import tempfile
from pathlib import Path

from ruamel.yaml import YAML


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "html" / "fabric-api.sh"
SCRIPT_TEXT = SCRIPT_PATH.read_text(encoding="utf-8")
EXIT_HTML_TEXT = (ROOT / "html" / "fabric-exit.html").read_text(encoding="utf-8")


def _bash_single_quoted_var(name):
    """Extract the value of a NAME='...' bash assignment (no inner quotes)."""
    marker = name + "='"
    start = SCRIPT_TEXT.index(marker) + len(marker)
    end = SCRIPT_TEXT.index("'", start)
    return SCRIPT_TEXT[start:end]


def _heredoc_body(case_marker, opener="python3 << PYTHON\n"):
    """Extract the python heredoc body of a case branch by its case label."""
    case_start = SCRIPT_TEXT.index("\n" + case_marker + "\n")
    open_pos = SCRIPT_TEXT.index(opener, case_start)
    body_start = open_pos + len(opener)
    body_end = SCRIPT_TEXT.index("\nPYTHON\n", body_start)
    body = SCRIPT_TEXT[body_start:body_end]
    # Expand the shared defs exactly as the unquoted heredoc would
    for var in (
        "LLDPQ_MODE_FLOOR_DEF",
        "LLDPQ_ATOMIC_WRITE_DEF",
        "LLDPQ_VALIDATORS_DEF",
        "LLDPQ_REF_SCAN_DEF",
    ):
        body = body.replace("$" + var, _bash_single_quoted_var(var))
    if "$LLDPQ" in body:
        raise AssertionError("unexpanded bash variable left in heredoc body")
    return body


UPDATE_INTERFACE_BODY = _heredoc_body("    update-interface)")
UPDATE_EXTERNAL_PEER_BODY = _heredoc_body("    update-external-peer)")


def run_action(body, post_data, ansible_dir):
    """Exec a heredoc body with POST_DATA/ANSIBLE_DIR set; return its JSON."""
    saved = {k: os.environ.get(k) for k in ("POST_DATA", "ANSIBLE_DIR")}
    os.environ["POST_DATA"] = json.dumps(post_data)
    os.environ["ANSIBLE_DIR"] = str(ansible_dir)
    stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout):
            try:
                exec(compile(body, str(SCRIPT_PATH), "exec"), {"__name__": "__main__"})
            except SystemExit:
                pass
    finally:
        for key, val in saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
    out = stdout.getvalue().strip()
    return json.loads(out.splitlines()[-1])


class UpdateInterfaceSubifKeyTest(unittest.TestCase):
    """update-interface 'subif' must edit int-keyed AND str-keyed entries."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.host_vars = self.ansible_dir / "inventory" / "host_vars"
        self.host_vars.mkdir(parents=True)
        self.host_file = self.host_vars / "dev1.yaml"

    def _load_subifs(self):
        yaml = YAML()
        with open(self.host_file) as f:
            data = yaml.load(f)
        return data["interfaces"]["swp1"]["subinterfaces"]

    def test_int_keyed_subif_edit_updates_single_entry(self):
        self.host_file.write_text(textwrap.dedent("""\
            interfaces:
              swp1:
                subinterfaces:
                  1001:
                    vlan: 1001
                    ip: 10.0.0.1/31
                    vrf: extvrf
        """))
        result = run_action(UPDATE_INTERFACE_BODY, {
            "device": "dev1",
            "interface_name": "swp1.1001",
            "interface_type": "subif",
            "ip": "10.9.9.9/31",
            "vrf": "extvrf",
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        subifs = self._load_subifs()
        self.assertEqual(len(subifs), 1, dict(subifs))
        self.assertEqual(list(subifs.keys()), [1001])
        self.assertEqual(subifs[1001]["ip"], "10.9.9.9/31")
        self.assertEqual(subifs[1001]["vlan"], 1001)

    def test_str_keyed_subif_edit_still_works(self):
        self.host_file.write_text(textwrap.dedent("""\
            interfaces:
              swp1:
                subinterfaces:
                  '1001':
                    vlan: 1001
                    ip: 10.0.0.1/31
                    vrf: extvrf
        """))
        result = run_action(UPDATE_INTERFACE_BODY, {
            "device": "dev1",
            "interface_name": "swp1.1001",
            "interface_type": "subif",
            "ip": "10.9.9.9/31",
            "vrf": "extvrf",
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        subifs = self._load_subifs()
        self.assertEqual(len(subifs), 1, dict(subifs))
        self.assertEqual(list(subifs.keys()), ["1001"])
        self.assertEqual(subifs["1001"]["ip"], "10.9.9.9/31")


class UpdateExternalPeerMaskTest(unittest.TestCase):
    """update-external-peer must not rewrite a non-/31 subif mask to /31."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ansible_dir = Path(self.tmp.name)
        self.host_vars = self.ansible_dir / "inventory" / "host_vars"
        self.host_vars.mkdir(parents=True)
        self.group_all = self.ansible_dir / "inventory" / "group_vars" / "all"
        self.group_all.mkdir(parents=True)
        self.host_file = self.host_vars / "dev1.yaml"
        self.bgp_file = self.group_all / "bgp_profiles.yaml"
        self.bgp_file.write_text(textwrap.dedent("""\
            bgp_profiles:
              OVERLAY_BORDER_01:
                peer_groups:
                  External:
                    fabric_exit: true
                    peers:
                      192.0.2.2: {}
        """))

    def _load(self, path):
        yaml = YAML()
        with open(path) as f:
            return yaml.load(f)

    def test_weight_only_edit_preserves_slash30_prefix(self):
        self.host_file.write_text(textwrap.dedent("""\
            vrfs:
              extvrf:
                bgp:
                  bgp_profile: OVERLAY_BORDER_01
            interfaces:
              swp1:
                description: External BGP
                subinterfaces:
                  1002:
                    ip: 192.0.2.1/30
                    vlan: 1002
                    vrf: extvrf
        """))
        result = run_action(UPDATE_EXTERNAL_PEER_BODY, {
            "device": "dev1",
            "vrf": "extvrf",
            "original_peer": "192.0.2.2",
            "interface": "swp1.1002",
            # Bare IP, as the edit modal posts when the prefix was stripped
            "local_ip": "192.0.2.1",
            "remote_peer": "192.0.2.2",
            "weight": 100,
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        subifs = self._load(self.host_file)["interfaces"]["swp1"]["subinterfaces"]
        self.assertEqual(len(subifs), 1, dict(subifs))
        self.assertEqual(subifs[1002]["ip"], "192.0.2.1/30")
        peers = self._load(self.bgp_file)["bgp_profiles"]["OVERLAY_BORDER_01"]["peer_groups"]["External"]["peers"]
        self.assertEqual(peers["192.0.2.2"]["weight"], 100)

    def test_bare_local_ip_without_existing_subif_defaults_to_slash31(self):
        # No existing subinterface: fall back to /31 (add-external-peer semantics)
        self.host_file.write_text(textwrap.dedent("""\
            vrfs:
              extvrf:
                bgp:
                  bgp_profile: OVERLAY_BORDER_01
        """))
        result = run_action(UPDATE_EXTERNAL_PEER_BODY, {
            "device": "dev1",
            "vrf": "extvrf",
            "original_peer": "192.0.2.2",
            "interface": "swp1.1002",
            "local_ip": "192.0.2.1",
            "remote_peer": "192.0.2.2",
            "weight": 100,
        }, self.ansible_dir)
        self.assertTrue(result.get("success"), result)
        subifs = self._load(self.host_file)["interfaces"]["swp1"]["subinterfaces"]
        self.assertEqual(subifs[1002]["ip"], "192.0.2.1/31")


class ExternalPeerCidrContractTest(unittest.TestCase):
    """list-external-peers must expose the full CIDR for the edit modal."""

    def test_list_external_peers_emits_local_ip_cidr(self):
        self.assertIn("'local_ip_cidr': local_ip if local_ip else ''", SCRIPT_TEXT)
        # Existing display field must stay bare (prefix stripped)
        self.assertIn("'local_ip': local_ip.split('/')[0] if local_ip else ''", SCRIPT_TEXT)

    def test_edit_modal_prefills_from_cidr(self):
        self.assertIn("peer.local_ip_cidr || peer.local_ip || ''", EXIT_HTML_TEXT)


if __name__ == "__main__":
    unittest.main()
