#!/usr/bin/env python3
"""Progressive hydration on the BER / optical / flap report pages.

Pins the PFC/ECN pattern the three generators adopted: attention rows render
inline, quiet rows ship in an inert text/html payload the page hydrates in
chunks, the device dropdown is fed a complete embedded list, and detail
evidence is fetched per device instead of being embedded as a page blob.
"""

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))


class HydrationSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ber = (SCRIPT_DIR / "ber_analyzer.py").read_text(encoding="utf-8")
        cls.optical = (SCRIPT_DIR / "optical_analyzer.py").read_text(
            encoding="utf-8")
        cls.flap = (SCRIPT_DIR / "link_flap_analyzer.py").read_text(
            encoding="utf-8")

    def test_shared_sentinel_and_cap(self):
        for source in (self.ber, self.optical, self.flap):
            self.assertIn('DEFERRED_ROW_SENTINEL = "<!--=lldpq-row=-->"',
                          source)
            self.assertIn("INLINE_ROW_CAP = 5000", source)

    def test_ber_page_hydrates_and_fetches_details(self):
        self.assertIn('id="ber-deferred-rows"', self.ber)
        self.assertIn("function hydrateBerDeferredRows()", self.ber)
        self.assertIn('id="hydration-progress"', self.ber)
        # Quiet BER rows defer; attention rows stay inline.
        self.assertIn(
            'quiet = status.lower() in ("excellent", "good", "unknown")',
            self.ber)
        # The per-port detail blob is gone; details come from the shard.
        self.assertNotIn("__berPortDetails", self.ber)
        self.assertIn("window.__berDeviceList", self.ber)
        self.assertIn("fetch('ber-history/' + encodeURIComponent(device)",
                      self.ber)

    def test_optical_page_hydrates_and_fetches_details(self):
        self.assertIn('id="optical-deferred-rows"', self.optical)
        self.assertIn("function hydrateOpticalDeferredRows()", self.optical)
        self.assertIn(
            "quiet = port['health'] in ('excellent', 'good', 'unplugged', "
            "'unknown')", self.optical)
        # The raw-diagnostics blob is gone; details come from the sidecars.
        self.assertNotIn('id="optical-details-data"', self.optical)
        self.assertIn("window.__opticalDeviceList", self.optical)
        self.assertIn(
            "fetch('optical-details/' + encodeURIComponent(device)",
            self.optical)
        self.assertIn('DETAILS_DIR_NAME = "optical-details"', self.optical)
        self.assertIn("def _write_detail_sidecars", self.optical)

    def test_flap_page_hydrates(self):
        self.assertIn('id="flap-deferred-rows"', self.flap)
        self.assertIn("function hydrateFlapDeferredRows()", self.flap)
        self.assertIn("__FLAP_DEVICE_LIST_JSON__", self.flap)
        self.assertIn('(table_rows if dashboard_status != "ok" else '
                      "deferred_rows).append", self.flap)

    def test_device_filters_match_on_data_keys(self):
        # p2p-alias rewrites displayed names after hydration; the filters
        # must therefore compare data-device-key, never cell text.
        for source in (self.ber, self.optical, self.flap):
            self.assertIn("row.dataset.deviceKey === deviceKey", source)

    def test_csv_export_honors_table_filter_funnels(self):
        # table-filter.js hides rows via the tf-hidden class, never via
        # style.display; every CSV export must filter both (PFC precedent,
        # pinned in test_pfc_ecn_dashboard_contract).
        for source in (self.ber, self.optical, self.flap):
            self.assertIn("classList.contains('tf-hidden')", source)

    def test_csv_export_waits_for_hydration(self):
        # Until every deferred row lands, a DOM-walking export silently
        # truncates the CSV; the button stays disabled while hydrating.
        for source in (self.ber, self.optical, self.flap):
            self.assertIn("csvButton.disabled = !finished", source)


class TableFilterFastPathTests(unittest.TestCase):
    def test_empty_filter_pass_is_skipped(self):
        source = (SCRIPT_DIR.parent / "html" / "css" / "table-filter.js"
                  ).read_text(encoding="utf-8")
        self.assertIn("st.hadActiveFilters", source)
        self.assertIn("if (filters.size === 0 && !st.hadActiveFilters)",
                      source)

    def test_cache_bust_bumped_everywhere(self):
        stale = []
        for path in list(SCRIPT_DIR.glob("*.py")) + list(
                (SCRIPT_DIR.parent / "html").glob("*.html")):
            if path.name.startswith("test_"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "table-filter.js?v=" in text and \
                    "table-filter.js?v=20260801-tf-4" not in text:
                stale.append(path.name)
        self.assertEqual(stale, [],
                         "stale table-filter.js cache version references")


if __name__ == "__main__":
    unittest.main()
