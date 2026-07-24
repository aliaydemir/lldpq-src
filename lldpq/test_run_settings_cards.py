#!/usr/bin/env python3
"""Setup step-8 cards for collection skips and transceiver-FW settings.

Source-text contracts on setup-api.sh / setup.html (the established pattern
for step-8 settings, see test_lldpq_hostname.py) plus functional parity
checks that pin the UI validation ranges to the backup importer so they
cannot drift apart silently.
"""

import importlib.util
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SETUP_API = SCRIPT_DIR.parent / "html" / "setup-api.sh"
SETUP_HTML = SCRIPT_DIR.parent / "html" / "setup.html"
LLDPQ_CONFIG = SCRIPT_DIR.parent / "bin" / "lldpq-config"
INSTALL_SH = SCRIPT_DIR.parent / "install.sh"
README = SCRIPT_DIR.parent / "README.md"

SKIP_KEYS = (
    "SKIP_OPTICAL", "SKIP_L1", "SKIP_DUPLICATE", "SKIP_EVPN_MH",
    "SKIP_PFC_ECN", "SKIP_ASSETS", "SKIP_LLDP", "SKIP_MONITOR",
    "SKIP_FABRIC_SCAN", "SKIP_ALERTS",
)
NEW_SKIP_KEYS = tuple(k for k in SKIP_KEYS if k not in ("SKIP_OPTICAL", "SKIP_L1"))


def _load_backup_import():
    spec = importlib.util.spec_from_file_location(
        "backup_import", SCRIPT_DIR / "backup_import.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SetupApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SETUP_API.read_text(encoding="utf-8")

    def test_collection_options_actions_exist(self):
        self.assertIn("if action == 'get-collection-options':", self.source)
        self.assertIn("if action == 'set-collection-options':", self.source)
        for key in SKIP_KEYS:
            self.assertIn(f"'{key}'", self.source)

    def test_set_collection_options_requires_json_booleans(self):
        block = self.source.split("if action == 'set-collection-options':", 1)[1]
        block = block.split("if action == 'get-transceiver-fw':", 1)[0]
        self.assertIn("isinstance(v, bool)", block)
        self.assertIn("'true' if v else 'false'", block)

    def test_transceiver_actions_and_ranges(self):
        self.assertIn("if action == 'get-transceiver-fw':", self.source)
        self.assertIn("if action == 'set-transceiver-fw':", self.source)
        block = self.source.split("if action == 'set-transceiver-fw':", 1)[1]
        self.assertIn("('TRANSCEIVER_FW_MAX_PARALLEL', 1, 1000)", block)
        self.assertIn("('TRANSCEIVER_FW_MIN_INTERVAL', 0, 604800)", block)
        self.assertIn("('TRANSCEIVER_FW_SSH_TIMEOUT', 1, 86400)", block)
        # The collector splits on whitespace only; commas must be normalized.
        self.assertIn(r"re.split(r'[\s,]+', skip_models)", block)
        # The policy enum is run|skip; "collect" would be silently coerced.
        self.assertIn("('skip', 'run')", block)

    def test_new_skip_keys_ride_backup_bundles(self):
        prefs = self.source.split("LLDPQ_PREF_KEYS = (", 1)[1].split(")", 1)[0]
        for key in SKIP_KEYS:
            self.assertIn(f"'{key}'", prefs)


class SetupHtmlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SETUP_HTML.read_text(encoding="utf-8")

    def test_collection_card_elements(self):
        for element_id in (
            "co-skip-optical", "co-skip-l1", "co-skip-duplicate",
            "co-skip-evpn-mh", "co-skip-pfc-ecn", "co-skip-assets",
            "co-skip-lldp", "co-skip-monitor", "co-skip-fabric-scan",
            "co-skip-alerts", "save-collect-btn", "co-status", "co-core-warn",
        ):
            self.assertIn(f'id="{element_id}"', self.source)
        self.assertIn("async function loadCollectionOptions()", self.source)
        self.assertIn("async function saveCollectionOptions()", self.source)

    def test_core_stage_warning_reacts_to_toggle(self):
        # The staleness warning must appear on change, not only after save.
        self.assertIn("function updateCoreSkipWarning()", self.source)
        self.assertIn("el.addEventListener('change', updateCoreSkipWarning);",
                      self.source)
        warn_block = self.source.split('id="co-core-warn"', 1)[0]
        self.assertIn('class="note danger-note"', warn_block.rsplit("<div", 1)[1])

    def test_transceiver_card_elements(self):
        for element_id in (
            "tfw-skip-models", "tfw-policy", "tfw-max-parallel",
            "tfw-min-interval", "tfw-ssh-timeout", "save-tfw-btn", "tfw-status",
        ):
            self.assertIn(f'id="{element_id}"', self.source)
        self.assertIn("async function loadTransceiverFw()", self.source)
        self.assertIn("async function saveTransceiverFw()", self.source)
        # UI must post the collector's real enum value, never "collect".
        self.assertIn('<option value="run">collect anyway</option>', self.source)

    def test_cards_load_on_step_entry_and_reset_on_restore(self):
        self.assertIn("collectOptsLoaded = true; loadCollectionOptions();",
                      self.source)
        self.assertIn("transceiverFwLoaded = true; loadTransceiverFw();",
                      self.source)
        self.assertIn("collectOptsLoaded=false; transceiverFwLoaded=false;",
                      self.source)


class WiringCoverageTests(unittest.TestCase):
    """Every new key must exist in every layer or it silently disappears."""

    def test_config_helper_allowlist(self):
        source = LLDPQ_CONFIG.read_text(encoding="utf-8")
        for key in NEW_SKIP_KEYS:
            self.assertIn(f'"{key}"', source)

    def test_installer_renders_and_preserves(self):
        source = INSTALL_SH.read_text(encoding="utf-8")
        for key in NEW_SKIP_KEYS:
            self.assertIn(key, source)
        # Update-mode preservation allowlist and clean-install caller-intent
        # guard both enumerate the keys.
        self.assertIn("SKIP_DUPLICATE|", source)
        self.assertIn("_CALLER_SKIP_KEYS=(SKIP_L1 SKIP_OPTICAL SKIP_DUPLICATE",
                      source)

    def test_readme_documents_the_toggles(self):
        source = README.read_text(encoding="utf-8")
        for key in NEW_SKIP_KEYS:
            self.assertIn(key, source)


class BackupImportParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backup_import = _load_backup_import()

    def test_skip_keys_validate_as_booleans(self):
        for key in SKIP_KEYS:
            self.assertIn(key, self.backup_import._PORTABLE_BOOLEAN_KEYS)
            self.assertEqual(
                self.backup_import._validate_portable_preference(
                    key, "TRUE", lambda value: True),
                "true",
            )

    def test_transceiver_ranges_match_the_ui(self):
        ranges = self.backup_import._PORTABLE_INTEGER_RANGES
        self.assertEqual(ranges["TRANSCEIVER_FW_MAX_PARALLEL"], (1, 1000))
        self.assertEqual(ranges["TRANSCEIVER_FW_MIN_INTERVAL"], (0, 604800))
        self.assertEqual(ranges["TRANSCEIVER_FW_SSH_TIMEOUT"], (1, 86400))

    def test_unknown_model_policy_enum(self):
        def validate(key, value):
            return self.backup_import._validate_portable_preference(
                key, value, lambda cron: True)

        self.assertEqual(
            validate("TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY", "RUN"), "run")
        with self.assertRaises(Exception):
            validate("TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY", "collect")


if __name__ == "__main__":
    unittest.main()
