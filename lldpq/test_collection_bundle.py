#!/usr/bin/env python3
"""Focused contracts for category-isolated collection bundle failures."""

import tempfile
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from collection_bundle import (
    CollectionBundleError,
    SECTIONS,
    split_collection_bundle,
)


class CollectionBundleIsolationTests(unittest.TestCase):
    def _paths(self, root):
        return {section: root / f"{section.lower()}.txt" for section in SECTIONS}

    def _bundle(self, marker=None, marker_section="OPTICAL_DATA"):
        records = []
        for section in SECTIONS:
            records.append(f"==={section}_START===")
            records.append(f"payload:{section}")
            if marker is not None and section == marker_section:
                records.append(marker)
            records.append(f"==={section}_END===")
        return ("\n".join(records) + "\n").encode()

    def test_optical_timeout_is_retained_without_invalidating_other_sections(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.txt"
            marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp17"
            raw.write_bytes(self._bundle(marker))
            outputs = self._paths(root)

            split_collection_bundle(raw, outputs)

            self.assertEqual(
                outputs["BGP_DATA"].read_text(), "payload:BGP_DATA\n"
            )
            optical = outputs["OPTICAL_DATA"].read_text()
            self.assertIn("payload:OPTICAL_DATA", optical)
            self.assertIn(marker, optical)

    def test_all_declared_section_local_failures_are_accepted(self):
        markers = (
            ("BGP_DATA", "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY"),
            ("EVPN_DATA", "__LLDPQ_COLLECTION_ERROR__:EVPN_VNI"),
            ("EVPN_DATA", "__LLDPQ_COLLECTION_ERROR__:EVPN_TEMPFILE"),
            ("EVPN_DATA", "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES"),
            ("FDB_DATA", "__LLDPQ_COLLECTION_ERROR__:FDB"),
            ("NEIGH_DATA", "__LLDPQ_COLLECTION_ERROR__:NEIGH"),
            ("CARRIER_DATA", "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY"),
            ("OPTICAL_DATA", "__LLDPQ_COLLECTION_ERROR__:OPTICAL_LINK_INVENTORY"),
            ("OPTICAL_DATA", "__LLDPQ_COLLECTION_ERROR__:OPTICAL_BUDGET:swp1s0"),
            ("OPTICAL_DATA", "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp2"),
            ("OPTICAL_DATA", "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TOOL_UNAVAILABLE:swp3"),
            ("BER_DATA", "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS"),
        )
        for section, marker in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                raw = root / "raw.txt"
                raw.write_bytes(self._bundle(marker, marker_section=section))
                split_collection_bundle(raw, self._paths(root))

    def test_optical_marker_in_wrong_section_remains_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw.txt"
            raw.write_bytes(self._bundle(
                "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TIMEOUT:swp1",
                marker_section="BGP_DATA",
            ))
            outputs = self._paths(root)
            for path in outputs.values():
                path.write_text("last-known-good\n")

            with self.assertRaises(CollectionBundleError):
                split_collection_bundle(raw, outputs)

            self.assertTrue(all(
                path.read_text() == "last-known-good\n" for path in outputs.values()
            ))

    def test_known_marker_to_section_mismatch_and_unknown_errors_remain_fatal(self):
        markers = (
            ("__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY", "EVPN_DATA"),
            ("__LLDPQ_COLLECTION_ERROR__:FDB", "NEIGH_DATA"),
            ("__LLDPQ_COLLECTION_ERROR__:OPTICAL_UNKNOWN:swp1", "OPTICAL_DATA"),
        )
        for marker, section in markers:
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                raw = root / "raw.txt"
                raw.write_bytes(self._bundle(marker, marker_section=section))
                with self.assertRaises(CollectionBundleError):
                    split_collection_bundle(raw, self._paths(root))


if __name__ == "__main__":
    unittest.main()
