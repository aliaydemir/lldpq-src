"""BMC source isolation, FDB semantics, history and fabric publication tests."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bmc_collection import merge_snapshots, observe, parse_fdb, parse_links
from bmc_results import get_results

ROOT = Path(__file__).resolve().parents[1]
MAC = "02:11:22:33:44:55"
ROW = {"switch": "oob1", "port": "swp1", "expected_mac": MAC,
       "hostname": "server1", "vlan": None, "enabled": True}
LINKS = [{"ifname": "swp1", "flags": ["BROADCAST", "UP", "LOWER_UP"],
          "operstate": "UP", "master": "bridge",
          "linkinfo": {"info_kind": "sx_netdev", "info_slave_kind": "bridge"}},
         {"ifname": "swp2", "flags": ["BROADCAST", "UP", "NO-CARRIER"],
          "operstate": "DOWN"},
         {"ifname": "swp3", "flags": ["BROADCAST"], "operstate": "DOWN"}]


def raw(fdb=None, links=None, route_error=False):
    fdb = f"{MAC} dev swp1 vlan 10 master bridge" if fdb is None else fdb
    links = json.dumps(LINKS) if links is None else links
    return ("===ARP===\n===VRFMAP===\n===IFACEVRF===\n===MAC===\n" + fdb +
            "\n===VTEP===\n===BOND===\n===BMC_LINK===\n" + links +
            "\n===LOOPBACKS===\n===NEXTHOPS===\n===ROUTES===\n" +
            ("__LLDPQ_COLLECTION_ERROR__:ROUTES_DEFAULT\n" if route_error else
             "VRF:default\n") + "===END===\n")


class BmcObservationTests(unittest.TestCase):
    def test_unrelated_route_failure_does_not_invalidate_bmc(self):
        result = observe(raw(route_error=True), {}, [ROW])
        self.assertEqual(result["fdb_status"], "ok")
        self.assertEqual(result["link_status"], "ok")
        self.assertEqual(result["macs"][0]["port"], "swp1")

    def test_empty_fdb_is_current_but_failed_fdb_is_unknown(self):
        empty = observe(raw(fdb=""), {}, [ROW])
        failed = observe(raw(fdb="__LLDPQ_COLLECTION_ERROR__:FDB"), {}, [ROW])
        self.assertEqual(empty["fdb_status"], "ok")
        self.assertEqual(empty["macs"], [])
        self.assertEqual(failed["fdb_status"], "error")
        self.assertEqual(failed["link_status"], "ok")

    def test_failed_link_keeps_successful_fdb_separate(self):
        result = observe(raw(links="__LLDPQ_COLLECTION_ERROR__:BMC_LINK"), {}, [ROW])
        self.assertEqual(result["fdb_status"], "ok")
        self.assertEqual(result["link_status"], "error")
        self.assertEqual(result["ports"], {})

    def test_truncated_or_malformed_source_is_unknown(self):
        for incomplete in ("===MAC===\n" + MAC + " dev swp1", "===MAC===\nbad\n===END==="):
            self.assertEqual(observe(incomplete, {}, [ROW])["fdb_status"], "error")
        for bad in ("", "{}", "[]", '[{"ifname":"swp1"}]'):
            self.assertEqual(observe(raw(links=bad), {}, [ROW])["link_status"], "error")

    def test_fdb_flags_and_non_edge_entries_are_preserved_but_not_eligible(self):
        entries = parse_fdb([
            f"{MAC} dev swp1 vlan 10 master bridge offload",
            f"{MAC} dev swp1 self permanent",
            f"{MAC} dev swp1 master bridge static",
            f"{MAC} dev vxlan100 dst 10.1.1.1 self extern_learn",
            f"{MAC} dev swp1 master bridge extern_learn",
            f"{MAC} dev bond1 vlan 10 master bridge",
            "01:00:5e:00:00:01 dev swp1 self",
        ])
        self.assertTrue(entries[0]["is_local"])
        self.assertIn("master", entries[0]["flags"])
        self.assertIn("offload", entries[0]["flags"])
        self.assertTrue(entries[1]["is_static"])
        self.assertTrue(entries[3]["is_remote"])
        self.assertTrue(all(not entry["is_local"] for entry in entries[1:]))

    def test_link_states_distinguish_admin_and_carrier(self):
        ports = parse_links([json.dumps(LINKS)], {"swp1"})
        self.assertEqual((ports["swp1"]["admin_up"], ports["swp1"]["carrier"]), (True, True))
        self.assertEqual((ports["swp2"]["admin_up"], ports["swp2"]["carrier"]), (True, False))
        self.assertEqual((ports["swp3"]["admin_up"], ports["swp3"]["carrier"]), (False, False))
        self.assertTrue(ports["swp1"]["is_uplink"])
        self.assertTrue(ports["swp1"]["is_physical"])

    def test_spectrum_physical_driver_is_accepted_but_virtual_kind_is_not(self):
        hardware = parse_links([json.dumps(LINKS)], set())
        self.assertEqual(hardware["swp1"]["kind"], "sx_netdev")
        self.assertTrue(hardware["swp1"]["is_physical"])
        virtual = dict(LINKS[0], linkinfo={"info_kind": "vlan"})
        self.assertFalse(parse_links([json.dumps([virtual])], set())["swp1"]["is_physical"])

    def test_last_seen_survives_absence_and_failure_without_refreshing(self):
        first = observe(raw(), {}, [ROW], checked_at="2026-10-20T01:00:00+00:00")
        self.assertEqual(first["last_seen"], {f"swp1|{MAC}|10": first["checked_at"]})
        missing = observe(raw(fdb=""), first, [ROW], checked_at="2026-10-20T01:05:00+00:00")
        failure = observe("", missing, [ROW], checked_at="2026-10-20T01:10:00+00:00")
        self.assertEqual(failure["last_seen"], first["last_seen"])
        self.assertEqual(failure["macs"], [])
        self.assertEqual(failure["fdb_status"], "error")
        self.assertEqual(failure["link_status"], "error")

    def test_history_prunes_removed_mappings_and_rejects_static_or_uplink(self):
        first = observe(raw(), {}, [ROW])
        self.assertEqual(observe(raw(), first, [])["last_seen"], {})
        self.assertEqual(observe(raw(), {}, [ROW], uplinks={"swp1"})["last_seen"], {})
        self.assertEqual(observe(raw(fdb=f"{MAC} dev swp1 self permanent"), {}, [ROW])["last_seen"], {})

    def test_explicit_vlan_history_does_not_accept_other_vlan(self):
        self.assertEqual(observe(raw(), {}, [dict(ROW, vlan=20)])["last_seen"], {})

    def test_merge_preserves_fabric_stale_status_and_fresh_bmc(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_dir, staged, previous = [root / name for name in ("raw", "staged", "previous")]
            for path in (raw_dir, staged, previous):
                path.mkdir()
            inventory = root / "inventory.tsv"
            inventory.write_text("10.0.0.1\tcumulus\toob1\n10.0.0.2\tcumulus\toob2\n")
            config = root / "bmc.yaml"
            config.write_text("version: 1\nmappings: " + json.dumps([ROW]) + "\n")
            old = {"arp": [{"ip": "old"}], "_collection": {"status": "stale"}}
            (staged / "oob1.json").write_text(json.dumps(old))
            (raw_dir / "oob1.txt").write_text(raw(route_error=True))
            lldp = root / "lldp.json"
            lldp.write_text(json.dumps({"neighbors": {"oob1": {"swp2": {"device": "oob2"}}}}))
            merge_snapshots(inventory, raw_dir, staged, previous, config, lldp)
            result = json.loads((staged / "oob1.json").read_text())
            self.assertEqual(result["arp"], old["arp"])
            self.assertEqual(result["_collection"]["status"], "stale")
            self.assertEqual(result["bmc"]["fdb_status"], "ok")
            self.assertTrue(result["bmc"]["ports"]["swp2"]["is_uplink"])
            unavailable = json.loads((staged / "oob2.json").read_text())
            self.assertEqual(unavailable["_collection"]["status"], "unavailable")
            self.assertEqual(unavailable["bmc"]["fdb_status"], "error")


@unittest.skipUnless(shutil.which("flock") and shutil.which("timeout"), "requires util-linux flock and timeout")
class BmcFabricIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.root / "monitor-results").mkdir()
        (self.root / "devices.yaml").write_text("devices:\n  10.0.0.1: oob1\n")
        (self.root / "bmc.yaml").write_text("version: 1\nmappings: " + json.dumps([ROW]) + "\n")
        self.snapshot = self.root / "remote.txt"
        self.snapshot.write_text(raw())
        # No SSH or switch access: the executable only emits the test fixture.
        (self.bin / "ssh").write_text('#!/bin/sh\ncat "$BMC_TEST_REMOTE"\n')
        (self.bin / "ping").write_text("#!/bin/sh\nexit 0\n")
        for path in self.bin.iterdir():
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        LLDPQ_DIR=str(self.root), LLDPQ_CONFIG_HELPER=str(self.root / "no-config"),
                        FABRIC_SCAN_MIN_INTERVAL_SECONDS="0", LLDPQ_MONITOR_LOCK_FILE=str(self.root / "global.lock"),
                        FABRIC_SCAN_LOCK_FILE=str(self.root / "fabric.lock"), BMC_TEST_REMOTE=str(self.snapshot))
        self.env.pop("LLDPQ_MONITOR_LOCK_HELD", None)

    def scan(self):
        completed = subprocess.run([shutil.which("bash"), str(ROOT / "lldpq/fabric-scan.sh")],
                                   env=self.env, text=True, capture_output=True, timeout=25)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        output = self.root / "monitor-results/fabric-tables"
        return json.loads((output / "oob1.json").read_text()), json.loads((output / "summary.json").read_text())

    def test_real_scan_keeps_fresh_bmc_when_routes_fail_then_marks_transport_unknown(self):
        first, summary = self.scan()
        self.assertTrue(summary["complete"])
        self.assertEqual(first["bmc"]["fdb_status"], "ok")
        results = get_results(self.root / "devices.yaml", self.root / "bmc.yaml",
                              self.root / "monitor-results/fabric-tables")
        self.assertEqual(results["rows"][0]["status"], "MATCH")
        self.snapshot.write_text(raw(route_error=True))
        second, summary = self.scan()
        self.assertFalse(summary["complete"])
        self.assertEqual(second["_collection"]["status"], "stale")
        self.assertEqual(second["bmc"]["fdb_status"], "ok")
        self.assertEqual(second["bmc"]["link_status"], "ok")
        self.snapshot.write_text("")
        third, summary = self.scan()
        self.assertEqual(third["bmc"]["fdb_status"], "error")
        self.assertEqual(third["bmc"]["last_seen"], second["bmc"]["last_seen"])
        self.assertEqual(third["bmc"]["macs"], [])

    def test_new_host_with_route_failure_stays_fabric_unavailable_across_scans(self):
        self.snapshot.write_text(raw(route_error=True))
        for _ in range(2):
            snapshot, summary = self.scan()
            self.assertEqual(summary["devices"][0]["status"], "unavailable")
            self.assertEqual(snapshot["_collection"]["status"], "unavailable")
            self.assertEqual(snapshot["bmc"]["fdb_status"], "ok")

    def test_missing_json_link_support_does_not_break_existing_fabric(self):
        self.snapshot.write_text(raw(links="__LLDPQ_COLLECTION_ERROR__:BMC_LINK"))
        snapshot, summary = self.scan()
        self.assertTrue(summary["complete"])
        self.assertEqual(snapshot["bmc"]["link_status"], "error")
        self.assertEqual(snapshot["bmc"]["fdb_status"], "ok")


class BmcDeploymentTests(unittest.TestCase):
    def test_update_preserves_config_and_web_write_mode(self):
        source = (ROOT / "install.sh").read_text()
        self.assertIn('sudo cp -a "$LLDPQ_INSTALL_DIR/bmc.yaml" "$_preserved_dir/"', source)
        self.assertIn('sudo cp "$_preserved_dir/bmc.yaml" "$LLDPQ_INSTALL_DIR/"', source)
        self.assertIn('sources+=("$LLDPQ_INSTALL_DIR/bmc.yaml")', source)
        self.assertIn('sudo chmod 664 "$LLDPQ_INSTALL_DIR/bmc.yaml"', source)

    def test_native_update_drains_bmc_writer_before_preserving_configuration(self):
        source = (ROOT / "install.sh").read_text()
        quiesce = "quiesce_update_web() {" + source.split("quiesce_update_web() {", 1)[1].split("\nsnapshot_update_file()", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            # Simulate one in-flight CGI: the first wait drains it.  An
            # installer that forgets BMC would return without ever waiting.
            script = r'''
INSTALL_MODE=update
WEB_ROOT=/web
LLDPQ_UPDATE_LOCK_TIMEOUT=2
touch "$BMC_TEST_DRAIN/active"
systemctl() { return 1; }
ps() {
    if [[ "$2" == 424242 ]]; then printf '/web/bmc-api.sh\n'; else printf '1\n'; fi
}
pgrep() {
    if [[ "$3" == /web/bmc-api.sh && -f "$BMC_TEST_DRAIN/active" ]]; then printf '424242\n'; fi
}
sleep() { touch "$BMC_TEST_DRAIN/waited"; rm "$BMC_TEST_DRAIN/active"; }
'''
            result = subprocess.run(["bash", "-c", script + quiesce +
                                     '\nquiesce_update_web && test -f "$BMC_TEST_DRAIN/waited"'],
                                    env=dict(os.environ, BMC_TEST_DRAIN=temporary),
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertLess(source.index("quiesce_update_web || exit 1"),
                        source.index('sudo cp -a "$LLDPQ_INSTALL_DIR/bmc.yaml" "$_preserved_dir/"'))

    def test_docker_persistent_config_uses_existing_non_destructive_seeder(self):
        source = (ROOT / "docker/docker-entrypoint.sh").read_text()
        self.assertIn('_setup_config_file bmc.yaml', source)
        self.assertIn('if [ ! -f /home/lldpq/lldpq/bmc.yaml ]; then', source)
        self.assertIn('chmod 664 /home/lldpq/lldpq/bmc.yaml', source)


if __name__ == "__main__":
    unittest.main()
