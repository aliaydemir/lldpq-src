#!/usr/bin/env python3
"""BMC comparison uses current local FDB evidence, never inferred liveness."""

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bmc_results import get_results
import bmc_results
from test_bmc_config import DEVICES, mapping


NOW = datetime(2026, 10, 20, 10, 0, tzinfo=timezone.utc).timestamp()
CHECKED = "2026-10-20T09:59:00Z"
OLD = "2026-10-20T08:00:00Z"
MAC = "02:00:00:00:00:01"
OTHER = "02:00:00:00:00:02"


def fdb(mac=MAC, port="swp1", **changes):
    return {"mac": mac, "port": port, "vlan": 10, "flags": ["master"],
            "is_local": True, "is_remote": False, "is_static": False, **changes}


class BMCResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.devices = self.root / "devices.yaml"
        self.devices.write_text(DEVICES)
        self.bmc = self.root / "bmc.yaml"
        self.tables = self.root / "fabric-tables"
        self.tables.mkdir()
        self.configure(mapping())

    def configure(self, *mappings):
        self.bmc.write_text(yaml.safe_dump({"version": 1, "mappings": list(mappings)}))

    def snapshot(self, hostname="OOB-01", *, macs=None, ports=None, **changes):
        data = {"schema_version": 1, "checked_at": CHECKED, "fdb_status": "ok", "link_status": "ok",
                "ports": ports if ports is not None else {"swp1": {"operstate": "UP", "admin_up": True, "carrier": True}},
                "macs": [fdb()] if macs is None else macs, "last_seen": {}, **changes}
        payload = {"hostname": hostname, "bmc": data}
        (self.tables / f"{hostname}.json").write_text(json.dumps(payload))

    def results(self):
        return get_results(self.devices, self.bmc, self.tables, now=NOW)

    def row(self):
        return self.results()["rows"][0]

    def test_current_local_fdb_match(self):
        self.snapshot()
        row = self.row()
        self.assertEqual(row["status"], "MATCH")
        self.assertEqual(row["active_macs"], [MAC])
        self.assertEqual(row["last_seen"], CHECKED)
        self.assertEqual(self.results()["summary"]["MATCH"], 1)

    def test_quiet_mac_is_not_down_and_keeps_last_seen(self):
        self.snapshot(macs=[], last_seen={f"swp1|{MAC}|10": OLD})
        self.assertEqual(self.row()["status"], "NOT_SEEN")
        self.assertEqual(self.row()["last_seen"], OLD)
        self.assertEqual(self.row()["link_state"], "UP")

    def test_current_link_down_is_authoritative_even_without_fdb(self):
        self.snapshot(macs=[], fdb_status="error", ports={"swp1": {"operstate": "DOWN", "carrier": False}})
        self.assertEqual(self.row()["status"], "PORT_DOWN")

    def test_admin_disabled_port_reports_down_even_with_old_learned_mac(self):
        self.snapshot(ports={"swp1": {"operstate": "UP", "admin_up": False}})
        self.assertEqual(self.row()["status"], "PORT_DOWN")

    def test_current_unexpected_mac_is_mismatch(self):
        self.snapshot(macs=[fdb(OTHER)])
        self.assertEqual(self.row()["status"], "MISMATCH")

    def test_wrong_port_detected_between_configured_switches(self):
        self.configure(mapping(), mapping(switch="OOB-02", expected_mac=OTHER, hostname="server-02"))
        self.snapshot(macs=[fdb(OTHER)])
        self.snapshot(hostname="OOB-02", macs=[fdb(MAC)])
        rows = self.results()["rows"]
        self.assertEqual([row["status"] for row in rows], ["WRONG_PORT", "WRONG_PORT"])
        self.assertEqual(rows[0]["observed_locations"], [{"switch": "OOB-02", "port": "swp1", "vlan": 10}])

    def test_unconfigured_port_is_not_used_as_wrong_port_evidence(self):
        self.snapshot(macs=[fdb(port="swp48")])
        self.assertEqual(self.row()["status"], "NOT_SEEN")

    def test_known_switch_uplink_is_excluded(self):
        self.snapshot(ports={"swp1": {"operstate": "UP", "is_uplink": True}})
        self.assertEqual(self.row()["status"], "UNKNOWN")
        self.assertEqual(self.row()["active_macs"], [])

    def test_virtual_port_cannot_be_misrepresented_as_physical_link_down(self):
        self.snapshot(ports={"swp1": {"operstate": "DOWN", "is_physical": False, "kind": "vlan"}})
        self.assertEqual(self.row()["status"], "UNKNOWN")

    def test_bond_fdb_is_never_attributed_to_a_physical_member(self):
        self.snapshot(macs=[fdb(port="bond1")], ports={"swp1": {"operstate": "UP", "master": "bond1"}})
        self.assertEqual(self.row()["status"], "NOT_SEEN")

    def test_remote_self_static_and_multicast_entries_are_not_bmc_evidence(self):
        cases = [fdb(is_remote=True), fdb(is_local=False), fdb(is_static=True),
                 fdb(flags=["self"]), fdb(flags=["extern_learn"]), fdb(flags=["permanent"]),
                 fdb(dst="10.0.0.7"), fdb(port="vxlan10"), fdb(mac="01:00:5e:00:00:01")]
        for entry in cases:
            with self.subTest(entry=entry):
                self.snapshot(macs=[entry])
                self.assertEqual(self.row()["status"], "NOT_SEEN")

    def test_multiple_real_macs_kept_without_rejecting_expected_match(self):
        self.snapshot(macs=[fdb(), fdb(OTHER), fdb()])
        row = self.row()
        self.assertEqual(row["status"], "MATCH")
        self.assertEqual(row["active_macs"], [MAC, OTHER])
        self.assertEqual(row["warnings"], ["MULTIPLE_MACS"])

    def test_ambiguous_mac_on_two_bmc_ports_is_visible(self):
        self.configure(mapping(), mapping(port="swp2", expected_mac=OTHER, hostname="server-02"))
        self.snapshot(macs=[fdb(), fdb(port="swp2")],
                      ports={port: {"operstate": "UP"} for port in ("swp1", "swp2")})
        self.assertIn("AMBIGUOUS", self.row()["warnings"])
        self.assertEqual(len(self.row()["observed_locations"]), 2)

    def test_vlan_scopes_comparison_and_last_seen(self):
        self.configure(mapping(vlan=20))
        self.snapshot(macs=[fdb(vlan=10), fdb(OTHER, vlan=20)],
                      last_seen={f"swp1|{MAC}|10": CHECKED, f"swp1|{MAC}|20": OLD})
        row = self.row()
        self.assertEqual(row["status"], "MISMATCH")
        self.assertEqual(row["active_macs"], [OTHER])
        self.assertEqual(row["last_seen"], OLD)
        self.assertEqual(row["observed_locations"], [])

    def test_untagged_or_unspecified_vlan_can_match(self):
        self.snapshot(macs=[fdb(vlan=None)])
        self.assertEqual(self.row()["status"], "MATCH")

    def test_stale_mac_and_link_cannot_report_match_mismatch_or_down(self):
        for macs, port in (([fdb()], {"operstate": "UP"}), ([fdb(OTHER)], {"operstate": "UP"}), ([], {"operstate": "DOWN"})):
            self.snapshot(macs=macs, ports={"swp1": port}, checked_at=OLD)
            self.assertEqual(self.row()["status"], "STALE")
            self.assertEqual(self.row()["link_state"], "UNKNOWN")

    def test_missing_malformed_or_future_collection_is_unknown(self):
        self.assertEqual(self.row()["status"], "UNKNOWN")
        for checked in (None, "2026-10-20 09:59:00", "not a date", "2027-01-01T00:00:00Z"):
            self.snapshot(checked_at=checked)
            self.assertEqual(self.row()["status"], "UNKNOWN")
        (self.tables / "OOB-01.json").write_text("bad json")
        self.assertEqual(self.row()["status"], "UNKNOWN")

    def test_failed_link_or_fdb_never_reports_false_match_or_mismatch(self):
        for changes in ({"fdb_status": "error"}, {"link_status": "error"}, {"ports": {}}, {"macs": None}):
            self.snapshot(**changes)
            if changes == {"macs": None}:
                # Explicit malformed JSON value, bypassing fixture default.
                path = self.tables / "OOB-01.json"
                payload = json.loads(path.read_text())
                payload["bmc"]["macs"] = None
                path.write_text(json.dumps(payload))
            self.assertEqual(self.row()["status"], "UNKNOWN")

    def test_unrelated_route_collection_failure_does_not_hide_current_bmc(self):
        self.snapshot()
        path = self.tables / "OOB-01.json"
        payload = json.loads(path.read_text())
        payload.update(collection_status="stale", stale=True, collection_errors=["ROUTES_DEFAULT"])
        path.write_text(json.dumps(payload))
        self.assertEqual(self.row()["status"], "MATCH")

    def test_failed_fdb_does_not_present_cached_mac_as_active(self):
        self.snapshot(fdb_status="error")
        self.assertEqual(self.row()["status"], "UNKNOWN")
        self.assertEqual(self.row()["active_macs"], [])

    def test_real_collector_output_flows_into_comparison_after_routes_error(self):
        from bmc_collection import observe
        raw = (f"===MAC===\n{MAC} dev swp1 vlan 10 master bridge offload\n"
               "===BMC_LINK===\n" + json.dumps([{
                   "ifname": "swp1", "operstate": "UP", "flags": ["UP", "LOWER_UP"],
                   "master": "br_default", "linkinfo": {"info_slave_kind": "bridge"},
               }]) + "\n===ROUTES===\n__LLDPQ_COLLECTION_ERROR__:ROUTES_DEFAULT\n===END===\n")
        observation = observe(raw, {}, [mapping()], checked_at=CHECKED)
        (self.tables / "OOB-01.json").write_text(json.dumps({"_collection": {"status": "unavailable"}, "bmc": observation}))
        self.assertEqual(self.row()["status"], "MATCH")
        self.assertEqual(self.row()["last_seen"], CHECKED)

    def test_stale_other_switch_does_not_trigger_wrong_port(self):
        self.configure(mapping(), mapping(switch="OOB-02", expected_mac=OTHER, hostname="server-02"))
        self.snapshot(macs=[])
        self.snapshot(hostname="OOB-02", checked_at=OLD)
        self.assertEqual(self.row()["status"], "NOT_SEEN")

    def test_directory_publication_cannot_mix_switch_generations(self):
        self.configure(mapping(), mapping(switch="OOB-02", expected_mac=OTHER, hostname="server-02"))
        for remove_old in (False, True):
            with self.subTest(remove_old=remove_old):
                self.snapshot(macs=[fdb(MAC)])
                self.snapshot(hostname="OOB-02", macs=[fdb(OTHER)])
                load = bmc_results._load_observation
                def publish_after_first_read(directory_fd, hostname, now, max_age):
                    observation = load(directory_fd, hostname, now, max_age)
                    if hostname == "OOB-01":
                        previous = self.root / "old-generation"
                        self.tables.rename(previous)
                        self.tables.mkdir()
                        self.snapshot(macs=[fdb(OTHER)])
                        self.snapshot(hostname="OOB-02", macs=[fdb(MAC)])
                        if remove_old:
                            shutil.rmtree(previous)
                    return observation
                with mock.patch.object(bmc_results, "_load_observation", side_effect=publish_after_first_read):
                    rows = self.results()["rows"]
                self.assertEqual(rows[0]["status"], "MATCH")
                self.assertNotIn("AMBIGUOUS", rows[0]["warnings"])
                self.assertEqual(rows[1]["status"], "UNKNOWN" if remove_old else "MATCH")
                shutil.rmtree(self.root / "old-generation", ignore_errors=True)

    def test_disabled_and_retired_switch_mappings_remain_visible(self):
        self.configure(mapping(enabled=False))
        self.assertEqual(self.row()["status"], "DISABLED")
        self.configure(mapping())
        self.devices.write_text("devices: {}\n")
        self.assertEqual(self.row()["status"], "UNKNOWN")
        self.assertEqual(self.results()["orphaned_switches"], ["OOB-01"])


if __name__ == "__main__":
    unittest.main()
