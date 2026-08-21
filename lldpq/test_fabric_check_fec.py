#!/usr/bin/env python3
"""FEC / autoneg link-consistency checks (collection → sidecar → analyzer)."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPT_DIR / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PortLinkCollectionTests(unittest.TestCase):
    def test_check_lldp_ships_the_port_link_section(self):
        source = (SCRIPT_DIR / "check-lldp.sh").read_text(encoding="utf-8")
        self.assertIn("===PORT_LINK_START===", source)
        self.assertIn("===PORT_LINK_END===", source)
        # Read-only queries, carrier-up ports only, tool presence guarded.
        self.assertIn("command -v ethtool", source)
        self.assertIn("[ \\\"\\$carrier\\\" = '1' ] || continue", source)
        self.assertIn("Active FEC encodings*:", source)
        self.assertIn("Auto-negotiation:", source)


class PortLinkParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lv = _load("lldp_validate", "lldp-validate.py")

    def test_parser_keeps_safe_tokens_only(self):
        content = (
            "===PORT_LINK_START===\n"
            "swp1 fec=RS autoneg=on\n"
            "swp2 fec=None autoneg=off\n"
            "swp3 fec=unknown autoneg=unknown\n"
            "swp4 fec=Not-reported\n"
            "badline\n"
            "swp5 fec=<script> autoneg=on\n"
            "===PORT_LINK_END===\n"
        )
        parsed = self.lv._parse_port_link_section(content)
        self.assertEqual(parsed, {
            "swp1": {"fec": "RS", "autoneg": "on"},
            "swp2": {"fec": "None", "autoneg": "off"},
            "swp4": {"fec": "Not-reported"},
            "swp5": {"autoneg": "on"},
        })

    def test_sidecar_ports_map_carries_fec_and_autoneg(self):
        source = (SCRIPT_DIR / "lldp-validate.py").read_text(encoding="utf-8")
        self.assertIn("for key in ('speed', 'mtu', 'fec', 'autoneg'):", source)


class FabricCheckFecTests(unittest.TestCase):
    def _analyze(self, ports):
        fc = _load("process_fabric_check_data", "process_fabric_check_data.py")
        with tempfile.TemporaryDirectory() as tmp:
            sidecar = os.path.join(tmp, "lldp_neighbors.json")
            with open(sidecar, "w") as handle:
                json.dump({
                    "version": 1,
                    "created": "2026-08-01",
                    "neighbors": {
                        "leaf1": {
                            port: {"device": "leaf2", "port": port}
                            for port in ports["leaf1"]
                        },
                    },
                    "ports": ports,
                }, handle)
            analyzer = fc.FabricCheckAnalyzer(
                result_dir=tmp, sidecar_path=sidecar, configs_dir=tmp)
            analyzer.managed_devices = {"leaf1", "leaf2"}
            analyzer.analyze()
            return analyzer

    @staticmethod
    def _port(fec, autoneg):
        return {"oper": "UP", "speed": 100000, "mtu": 9216,
                "fec": fec, "autoneg": autoneg}

    def test_fec_and_autoneg_mismatches_are_flagged(self):
        analyzer = self._analyze({
            "leaf1": {"swp1": self._port("RS", "on")},
            "leaf2": {"swp1": self._port("LLRS", "off")},
        })
        checks = sorted(f["check"] for f in analyzer.findings)
        self.assertEqual(checks, ["autoneg-mismatch", "fec-mismatch"])
        by_check = {f["check"]: f for f in analyzer.findings}
        self.assertEqual(by_check["fec-mismatch"]["severity"], "critical")
        self.assertEqual(by_check["autoneg-mismatch"]["severity"], "warning")
        counts = analyzer.summary_counts()
        self.assertEqual(counts["fec_mismatches"], 1)
        self.assertEqual(counts["autoneg_mismatches"], 1)

    def test_matching_and_case_insensitive_values_are_clean(self):
        analyzer = self._analyze({
            "leaf1": {"swp1": self._port("RS", "on")},
            "leaf2": {"swp1": self._port("rs", "ON")},
        })
        self.assertEqual(analyzer.findings, [])
        self.assertEqual(analyzer.summary_counts()["links_fec_compared"], 1)

    def test_none_and_off_fec_are_equivalent(self):
        # Kernel ETHTOOL_FEC_NONE_BIT vs ETHTOOL_FEC_OFF_BIT: the spelling
        # varies by driver/ethtool version, both mean no active FEC.
        for side_a, side_b in (("None", "Off"), ("Off", "None")):
            analyzer = self._analyze({
                "leaf1": {"swp1": self._port(side_a, "on")},
                "leaf2": {"swp1": self._port(side_b, "on")},
            })
            self.assertEqual(analyzer.findings, [])
            self.assertEqual(
                analyzer.summary_counts()["links_fec_compared"], 1)

    def test_non_comparable_fec_values_are_skipped(self):
        # A host NIC answering "Not-reported" must not fabricate a mismatch
        # against a switch that reports its real active encoding.
        analyzer = self._analyze({
            "leaf1": {"swp1": self._port("Not-reported", "on")},
            "leaf2": {"swp1": self._port("RS", "on")},
        })
        self.assertEqual(
            [f for f in analyzer.findings if f["check"] == "fec-mismatch"],
            [])
        self.assertEqual(analyzer.summary_counts()["links_fec_compared"], 0)

    def test_missing_attributes_are_skipped(self):
        analyzer = self._analyze({
            "leaf1": {"swp1": {"oper": "UP", "speed": 100000, "mtu": 9216}},
            "leaf2": {"swp1": self._port("RS", "on")},
        })
        self.assertEqual(analyzer.findings, [])
        counts = analyzer.summary_counts()
        self.assertEqual(counts["links_fec_compared"], 0)
        self.assertEqual(counts["links_autoneg_compared"], 0)


if __name__ == "__main__":
    unittest.main()
