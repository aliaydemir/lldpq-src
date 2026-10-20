#!/usr/bin/env python3
"""BMC inventory writes, validation, and concurrent edit regression tests."""

import concurrent.futures
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bmc_config


DEVICES = "defaults:\n  username: cumulus\ndevices:\n  10.0.0.1: OOB-01 @oob_leaf\n  10.0.0.2:\n    hostname: OOB-02\n    role: oob_leaf\n"


def mapping(**changes):
    return {"switch": "OOB-01", "port": "swp1", "expected_mac": "02:00:00:00:00:01",
            "hostname": "server-01", "vlan": None, "bmc_ip": "", "enabled": True, **changes}


class BMCConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.devices = self.root / "devices.yaml"
        self.bmc = self.root / "bmc.yaml"
        self.devices.write_text(DEVICES)

    def get(self):
        return bmc_config.get_config(self.devices, self.bmc)

    def save(self, rows, revision=None):
        return bmc_config.save_config(self.devices, self.bmc, rows, revision or self.get()["revision"])

    def test_missing_inventory_defaults_to_empty_without_writing(self):
        payload = self.get()
        self.assertEqual(payload["mappings"], [])
        self.assertEqual([row["hostname"] for row in payload["switches"]], ["OOB-01", "OOB-02"])
        self.assertNotIn("username", payload["switches"][0])
        self.assertFalse(self.bmc.exists())

    def test_mac_forms_and_case_canonicalization(self):
        for value in ("02:AB:CD:EF:12:34", "02-ab-cd-ef-12-34", "02ab.cdef.1234", "02abcdef1234"):
            with self.subTest(value=value):
                result = self.save([mapping(switch="oob-01", expected_mac=value, vlan="23")])
                self.assertEqual(result["mappings"][0]["expected_mac"], "02:ab:cd:ef:12:34")
                self.assertEqual(result["mappings"][0]["switch"], "OOB-01")
                self.assertEqual(result["mappings"][0]["vlan"], 23)

    def test_reject_non_unicast_and_bad_mac_without_writes(self):
        for value in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "02:00-00:00:00:01", "bad", None):
            with self.subTest(value=value), self.assertRaises(bmc_config.BMCValidationError):
                self.save([mapping(expected_mac=value)])
        self.assertFalse(self.bmc.exists())

    def test_reject_duplicate_port_and_overlapping_mac_bindings(self):
        for other in (mapping(expected_mac="02:00:00:00:00:02"), mapping(port="swp2"),
                      mapping(switch="OOB-02", vlan=10)):
            with self.subTest(other=other), self.assertRaises(bmc_config.BMCValidationError):
                self.save([mapping(), other])

    def test_mac_can_be_reused_only_in_explicit_distinct_vlans(self):
        result = self.save([mapping(vlan=10), mapping(switch="OOB-02", vlan=20)])
        self.assertEqual(len(result["mappings"]), 2)
        with self.assertRaises(bmc_config.BMCValidationError):
            self.save([mapping(vlan=10), mapping(switch="OOB-02", vlan=10)])

    def test_disabled_binding_does_not_conflict_with_enabled_replacement(self):
        result = self.save([mapping(enabled=False), mapping(port="swp2")])
        self.assertEqual(len(result["mappings"]), 2)

    def test_only_physical_ports_and_valid_hostname_ip_vlan_accepted(self):
        invalid = [{"port": "bond1"}, {"port": "swp1/../x"}, {"port": "swp0"},
                   {"hostname": "bad name"}, {"vlan": True}, {"vlan": 4095},
                   {"vlan": 0}, {"bmc_ip": "garbage"}, {"enabled": "false"}, {"switch": "UNKNOWN"}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(bmc_config.BMCValidationError):
                self.save([mapping(**changes)])
        result = self.save([mapping(port="swp12s0", bmc_ip="2001:db8::1")])
        self.assertEqual(result["mappings"][0]["bmc_ip"], "2001:db8::1")

    def test_stale_revision_preserves_latest_writer(self):
        revision = self.get()["revision"]
        latest = self.save([mapping()], revision)
        with self.assertRaises(bmc_config.BMCConflictError) as captured:
            self.save([mapping(hostname="overwritten")], revision)
        self.assertEqual(captured.exception.revision, latest["revision"])
        self.assertEqual(self.get()["mappings"][0]["hostname"], "server-01")

    def test_simultaneous_writers_cannot_both_commit_one_revision(self):
        revision = self.get()["revision"]
        def update(hostname):
            try:
                self.save([mapping(hostname=hostname)], revision)
                return "saved"
            except bmc_config.BMCConflictError:
                return "conflict"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(update, ("server-a", "server-b")))
        self.assertCountEqual(results, ["saved", "conflict"])

    def test_inventory_change_invalidates_revision(self):
        revision = self.get()["revision"]
        self.devices.write_text(DEVICES + "  10.0.0.3: OOB-03\n")
        with self.assertRaises(bmc_config.BMCConflictError):
            self.save([mapping()], revision)

    def test_unknown_switch_remains_visible_after_inventory_removal(self):
        self.save([mapping()])
        self.devices.write_text("devices: {}\n")
        self.assertEqual(self.get()["orphaned_switches"], ["OOB-01"])
        self.assertEqual(len(self.get()["mappings"]), 1)
        self.assertEqual(self.save([])["mappings"], [])

    def test_metadata_survives_editor_roundtrip_and_is_json_safe(self):
        self.bmc.write_text("version: 1\nsite: lab\nmappings:\n" + yaml.safe_dump([
            mapping(note="rack 42", installed_on=__import__("datetime").date(2026, 10, 20))]))
        current = self.get()
        self.assertNotIn("installed_on", current["mappings"][0])
        current["mappings"][0]["hostname"] = "renamed"
        self.save(current["mappings"], current["revision"])
        saved = yaml.safe_load(self.bmc.read_text())
        self.assertEqual(saved["site"], "lab")
        self.assertEqual(saved["mappings"][0]["note"], "rack 42")
        self.assertEqual(str(saved["mappings"][0]["installed_on"]), "2026-10-20")

    def test_atomic_replace_failure_keeps_old_file_and_removes_temporary(self):
        self.save([mapping()])
        old = self.bmc.read_bytes()
        with mock.patch.object(bmc_config.os, "replace", side_effect=OSError("disk error")):
            with self.assertRaises(bmc_config.BMCConfigError):
                self.save([mapping(hostname="new")])
        self.assertEqual(self.bmc.read_bytes(), old)
        self.assertEqual(list(self.root.glob(".bmc-*.tmp")), [])

    def test_docker_symlink_preserved_and_write_target_shared_lock(self):
        target = self.root / "config" / "bmc.yaml"
        target.parent.mkdir()
        target.write_text("version: 1\nmappings: []\n")
        self.bmc.symlink_to(target)
        self.save([mapping()])
        self.assertTrue(self.bmc.is_symlink())
        self.assertEqual(len(yaml.safe_load(target.read_text())["mappings"]), 1)
        self.assertTrue(Path(str(target) + ".lock").exists())
        self.assertFalse(Path(str(self.bmc) + ".lock").exists())

    def test_unmanaged_symlink_is_rejected(self):
        target = self.root / "other.yaml"
        target.write_text("version: 1\nmappings: []\n")
        self.bmc.symlink_to(target)
        with self.assertRaises(bmc_config.BMCConfigError):
            self.save([mapping()])

    def test_restrictive_umask_still_produces_group_writable_lock(self):
        old = os.umask(0o077)
        try:
            self.save([mapping()])
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(Path(str(self.bmc) + ".lock").stat().st_mode), 0o660)
        self.assertEqual(Path(str(self.bmc) + ".lock").stat().st_gid, self.bmc.parent.stat().st_gid)

    def test_duplicate_yaml_keys_and_invalid_document_fail_closed(self):
        for content in ("version: 1\nversion: 2\n", "version: true\n", "mappings: {}\n", "[]\n"):
            self.bmc.write_text(content)
            with self.subTest(content=content), self.assertRaises(bmc_config.BMCValidationError):
                self.get()

    def test_backup_validation_does_not_require_live_inventory_membership(self):
        validated = bmc_config.validate_document({"version": 1, "mappings": [mapping(switch="future-switch")]})
        self.assertEqual(validated["mappings"][0]["switch"], "future-switch")


if __name__ == "__main__":
    unittest.main()
