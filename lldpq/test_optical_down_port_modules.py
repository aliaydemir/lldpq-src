#!/usr/bin/env python3
"""Tests for optical sampling of link-down ports.

Module EEPROM is readable regardless of link state, but the collector only ran
``ethtool -m`` on ports whose operstate was ``up``.  Every other port emitted
"No transceiver data", so a seated, healthy module in a down port was reported
as unplugged and an operator was asked to replace working hardware.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data
from optical_analyzer import OpticalAnalyzer


DOM_SAMPLE = """\
        Identifier                                : 0x11 (QSFP28)
        Transceiver type                          : 100G Base-SR4
        Vendor name                               : ACME
        Vendor PN                                 : QSFP-100G-SR4
        Module temperature                        : 31.50 degrees C
        Module voltage                            : 3.2800 V
        Receiver signal average optical power (Channel 1) : 0.6982 mW / -1.56 dBm
        Transmit avg optical power (Channel 1)    : 0.7521 mW / -1.24 dBm
        Laser bias current (Channel 1)            : 7.500 mA
"""


class CollectorContractTests(unittest.TestCase):
    """The collector must sample cages on down ports too."""

    def setUp(self):
        self.source = (SCRIPT_DIR / "monitor.sh").read_text()

    def test_dom_read_is_not_gated_on_link_up_alone(self):
        self.assertIn(
            'if [ "$state" = "up" ] || '
            '[ -e "$_lldpq_net_class_root/$interface/device" ]; then',
            self.source,
            "a down port with a backing device must still be sampled",
        )

    def test_link_up_ports_are_sampled_first(self):
        self.assertRegex(
            self.source,
            r'cat "\$_lldpq_snapshot_dir/optical_up" \\\s*\n'
            r'\s*"\$_lldpq_snapshot_dir/optical_rest" \\\s*\n'
            r'\s*> "\$_lldpq_snapshot_dir/optical_ordered"',
        )

    def test_the_optical_loop_consumes_the_ordered_list(self):
        self.assertIn(
            'done < "$_lldpq_snapshot_dir/optical_ordered"', self.source
        )
        optical_section = self.source.split("SECTION 4: Optical")[1]
        self.assertNotIn(
            'done < "$_lldpq_snapshot_dir/interfaces"\n            fi',
            optical_section,
        )


class DownPortClassificationTests(unittest.TestCase):
    def _classify(self, body):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "optical-data").mkdir()
        sample = root / "optical-data" / "leaf1_optical.txt"
        sample.write_text(body)

        process_optical_data._parse_worker_analyzer = OpticalAnalyzer(
            str(root), load_history=False
        )
        ops, _failures = process_optical_data._classify_optical_file(
            str(sample), "leaf1"
        )
        return ops

    def test_a_readable_module_on_a_down_port_is_not_unplugged(self):
        ops = self._classify(
            "--- Interface: swp7\n"
            "Interface state: down\n" + DOM_SAMPLE
        )
        kinds = {op[0] for op in ops}
        self.assertNotIn(
            "maybe_unplugged", kinds,
            "a module that answered a DOM read is present, not missing",
        )
        self.assertIn("update", kinds)

    def test_an_empty_cage_on_a_down_port_is_still_reported(self):
        ops = self._classify(
            "--- Interface: swp8\n"
            "Interface state: down\n"
            "No transceiver data\n"
        )
        self.assertEqual(
            [op[0] for op in ops], ["maybe_unplugged"],
            "with down ports now sampled, silence really does mean no module",
        )

    def test_a_healthy_up_port_is_unaffected(self):
        ops = self._classify(
            "--- Interface: swp1\n"
            "Interface state: up\n" + DOM_SAMPLE
        )
        self.assertEqual([op[0] for op in ops], ["update"])


if __name__ == "__main__":
    unittest.main()
