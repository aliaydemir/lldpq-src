#!/usr/bin/env python3
"""Tests for the IPAM (IP-allocation design) workbook parser (html/ai_ipam.py)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_ipam  # noqa: E402
from test_ai_p2p import build_xlsx  # noqa: E402  (shared mini-xlsx fixture builder)

SFERICAL_XLSX = Path("/Users/ali/Works/G42-DC/infos/Sferical IP Assignment v2.0.xlsx")
C42_XLSX = Path("/Users/ali/Works/G42-DC/C42_IP_Allocation_Table_v1.0.xlsx")
MISTRAL_XLSX = Path("/Users/ali/Works/G42-DC/infos/Mistral_IP_Allocation_Table_v2.9.xlsx")
NSCALE_XLSX = Path("/Users/ali/Works/G42-DC/infos/Nscale UK IP Allocation v1.7.xlsx")


# ---------------------------------------------------------------------------
# Synthetic fixture sheets (modeled on the real Sferical/C42/Nscale layouts)
# ---------------------------------------------------------------------------

# Side-by-side repeated assignment blocks (Sferical 'GB300 OOB' family) with
# a tbd IP, an invalid IP and a repeated header row inside the data area.
OOB_SHEET_ROWS = [
    ["DEVICE", "HOSTNAME", "INTERFACE", "IP ADDRESS", "MASK", "GATEWAY", "VLAN", "NOTE",
     None,
     "DEVICE", "HOSTNAME", "INTERFACE", "IP ADDRESS", "MASK", "GATEWAY", "VLAN", "NOTE"],
    ["GB300-1-1-Tray-01", "GB300-1-1-Tray-01", "BMC", "10.2.240.11", "/23", "10.2.241.254", "VLAN_8", None,
     None,
     "GB300-1-1-Tray-01", "GB300-1-1-Tray-01", "BF3BMC", "172.31.40.11", "/23", "172.31.41.254", "VLAN_4", None],
    ["GB300-1-1-Tray-02", "GB300-1-1-Tray-02", "BMC", "10.2.240.12", "/23", "10.2.241.254", "VLAN_8", None,
     None,
     "GB300-1-1-Tray-02", "GB300-1-1-Tray-02", "BF3BMC", "172.31.40.12", "/23", "172.31.41.254", "VLAN_4", None],
    ["DEVICE", "HOSTNAME", "INTERFACE", "IP ADDRESS", "MASK", "GATEWAY", "VLAN", "NOTE",
     None,
     "DEVICE", "HOSTNAME", "INTERFACE", "IP ADDRESS", "MASK", "GATEWAY", "VLAN", "NOTE"],
    ["GB300-1-1-Tray-03", "GB300-1-1-Tray-03", "BMC", "TBD", "/23", "10.2.241.254", "VLAN_8", None,
     None,
     "GB300-1-1-Tray-03", "GB300-1-1-Tray-03", "BF3BMC", "10.2.240.999", "/23", "172.31.41.254", "VLAN_4", None],
    ["GB300-1-1-Tray-04", "GB300-1-1-Tray-04", "BMC", "10.2.240.14", "/23", "10.2.241.254", "VLAN_8", None,
     None,
     "GB300-1-1-Tray-04", "GB300-1-1-Tray-04", "BF3BMC", "172.31.40.14", "/23", "172.31.41.254", "VLAN_4", None],
]

# Subnet catalog (Sferical 'IP Ranges' family) followed by a second stacked
# mini-table with a different catalog header (Nscale 'IP Ranges' family) and
# then a hostname/ASN table (Mistral 'Required Subnets' family).
RANGES_SHEET_ROWS = [
    ["VRF", "VLAN", "Network", "Network GW", "Purpose", "Description"],
    ["vpn60030", "VLAN_8", "10.2.240.0/23", "10.2.241.254", "Compute Management BMC", "note"],
    ["default", "N/A", "172.31.2.X/32", "N/A", "SuperPOD loopbacks", "template row"],
    ["L2-ONLY", "VLAN_69", "L2-ONLY", "L2-ONLY", "Vast Data Vlan", ""],
    [],
    ["Name", "Subnet", "Note"],
    ["Loopback", "10.0.0.0/8", "supernet"],
    [],
    ["Hostname", "AS Number"],
    ["tan-core-01", "4200010001"],
    ["tan-core-02", 4200010002],
]

# Fabric inventory (Sferical/Nscale 'Switches' family) with the raw
# scientific-notation ASN artifact and /32-suffixed loopbacks.
SWITCHES_SHEET_ROWS = [
    ["Fabric", "Device", "Hostname", "Role", "Management IP", "MASK", "Management GW",
     "Loopback IP", "ASN"],
    ["Inband", "SPINE-01", "tan-spine-01", "tan_spine", "172.31.44.1", "/24", "172.31.44.254",
     "172.31.2.1/32", "4.200000101E9"],
    ["Inband", "CLEAF-01", "tan-leaf-01", "tan_leaf", "172.31.44.9", "/24", "172.31.44.254",
     "172.31.2.9/32", "4200010003"],
    ["OOB", "OOB SP-01", "oob-spine-01", "oob_spine", "not-an-ip", "/24", "172.31.44.254",
     "", ""],
]

# Wide host table (C42 'Compute Fabric (Rail IPs)' family: global CIDR column).
RAIL_SHEET_ROWS = [
    ["Rack", "NVIS Hostname", "Rail0", "Rail1", "Rail2", "CIDR", "VRF / Tenant"],
    ["P1-A-01", "P1-GPU-A01ru11", "10.128.128.11", "10.128.132.11", None, "/22", "compute"],
    ["P1-A-01", "P1-GPU-A01ru12", "10.128.128.12", None, None, "/22", "compute"],
]

# Wide host table with per-column ip/net pairs (bmc_ip/bmc_net family).
BMC_SHEET_ROWS = [
    ["Server", "bmc_ip", "bmc_net", "mgmt ip"],
    ["Ctrl Node-01", "10.2.243.10", "/26", "10.2.243.70"],
]

# Generic L3 point-to-point intent table (source/dest family).
L3_SHEET_ROWS = [
    ["Source Hostname", "Source Interface", "Source IP", "Mask",
     "Destination Hostname", "Destination Interface", "Destination IP"],
    ["tan-border-01", "swp29", "192.0.2.0", "31", "fw-01", "eth1/1", "192.0.2.1"],
    ["tan-border-01", "swp30", "TBD", "31", "fw-01", "eth1/2", "192.0.2.3"],
]

# Border eBGP variant (C42 'Border External eBGP' family: no peer hostname).
BORDER_SHEET_ROWS = [
    ["Border switch", "Local ASN", "Local Port", "Local IP (/31)", "VRF",
     "Firewall Peer IP", "Firewall ASN", "Notes"],
    ["p1-border-leaf1", "4200010021", "swp29", "192.0.2.4/31", "c42", "192.0.2.5", "65100", ""],
]

CHANGELOG_SHEET_ROWS = [
    ["Version", "Date", "Author", "Summary of Changes"],
    ["v1.0", "2026-06-15", "Ali Aydemir", "First draft"],
]


def build_fixture(path):
    build_xlsx(path, [
        ("Change Log", CHANGELOG_SHEET_ROWS),
        ("IP Ranges", RANGES_SHEET_ROWS),
        ("Switches", SWITCHES_SHEET_ROWS),
        ("GB300 OOB", OOB_SHEET_ROWS),
        ("Rail IPs", RAIL_SHEET_ROWS),
        ("Pmx-Servers", BMC_SHEET_ROWS),
        ("L3 Links", L3_SHEET_ROWS),
        ("Border External eBGP", BORDER_SHEET_ROWS),
    ])


class ParseWorkbookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = Path(cls.tmp.name) / "ipam.xlsx"
        build_fixture(path)
        cls.result = ai_ipam.parse_workbook(path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _hosts(self, sheet):
        return {h["hostname"]: h for h in self.result["hosts"] if h["sheet"] == sheet}

    def test_top_level_shape(self):
        for key in ("format", "source_file", "generated_at", "total_records",
                    "subnets", "hosts", "fabric", "l3_links", "skipped_sheets", "warnings"):
            self.assertIn(key, self.result)
        self.assertEqual(self.result["format"], "ipam")
        self.assertEqual(self.result["source_file"], "ipam.xlsx")
        expected_total = (
            len(self.result["subnets"]) + len(self.result["fabric"])
            + len(self.result["l3_links"])
            + sum(len(h["assignments"]) for h in self.result["hosts"])
        )
        self.assertEqual(self.result["total_records"], expected_total)

    def test_non_data_tab_is_skipped_naturally(self):
        self.assertEqual(self.result["skipped_sheets"], ["Change Log"])

    def test_side_by_side_blocks_merge_per_host(self):
        hosts = self._hosts("GB300 OOB")
        tray1 = hosts["GB300-1-1-Tray-01"]
        self.assertEqual(len(tray1["assignments"]), 2)
        by_if = {a["role_or_interface"]: a for a in tray1["assignments"]}
        self.assertEqual(by_if["BMC"]["ip"], "10.2.240.11")
        self.assertEqual(by_if["BMC"]["prefixlen_or_mask"], "23")
        self.assertEqual(by_if["BMC"]["gateway"], "10.2.241.254")
        self.assertEqual(by_if["BMC"]["vlan"], "VLAN_8")
        self.assertEqual(by_if["BF3BMC"]["ip"], "172.31.40.11")
        # data continues after the repeated in-sheet header row
        self.assertIn("GB300-1-1-Tray-04", hosts)

    def test_blank_and_invalid_ips_excluded_with_warnings(self):
        hosts = self._hosts("GB300 OOB")
        # tray-03 BMC is TBD and BF3BMC is invalid: no assignment survives, so
        # the host carries no truth and is excluded entirely
        self.assertNotIn("GB300-1-1-Tray-03", hosts)
        ips = [a["ip"] for h in hosts.values() for a in h["assignments"]]
        self.assertNotIn("10.2.240.999", ips)
        warnings = "\n".join(self.result["warnings"])
        self.assertIn("blank/tbd", warnings)
        self.assertIn("10.2.240.999", warnings)

    def test_subnet_catalog_with_stacked_mini_tables(self):
        subnets = {s["prefix"]: s for s in self.result["subnets"]}
        record = subnets["10.2.240.0/23"]
        self.assertEqual(record["name"], "Compute Management BMC")
        self.assertEqual(record["gateway"], "10.2.241.254")
        self.assertEqual(record["vrf"], "vpn60030")
        self.assertEqual(record["vlan"], "VLAN_8")
        self.assertEqual(record["sheet"], "IP Ranges")
        # second stacked mini-table (Name|Subnet|Note) re-sniffed mid-sheet
        self.assertEqual(subnets["10.0.0.0/8"]["name"], "Loopback")
        # template/X prefixes are warned, never stored; L2-ONLY skipped quietly
        self.assertNotIn("172.31.2.X/32", subnets)
        self.assertTrue(any("172.31.2.X/32" in w for w in self.result["warnings"]))

    def test_stacked_hostname_asn_table_becomes_fabric(self):
        fabric = {f["hostname"]: f for f in self.result["fabric"] if f["sheet"] == "IP Ranges"}
        self.assertEqual(fabric["tan-core-01"]["asn"], "4200010001")
        self.assertEqual(fabric["tan-core-02"]["asn"], "4200010002")

    def test_fabric_inventory_normalizes_asn_and_loopback(self):
        fabric = {f["hostname"]: f for f in self.result["fabric"] if f["sheet"] == "Switches"}
        spine = fabric["tan-spine-01"]
        self.assertEqual(spine["asn"], "4200000101")       # 4.200000101E9 artifact
        self.assertEqual(spine["loopback_ip"], "172.31.2.1")  # /32 stripped
        self.assertEqual(spine["mgmt_ip"], "172.31.44.1")
        self.assertEqual(spine["role"], "tan_spine")
        self.assertEqual(spine["device"], "SPINE-01")
        self.assertEqual(fabric["tan-leaf-01"]["asn"], "4200010003")
        # invalid mgmt IP is warned, not stored
        self.assertNotIn("mgmt_ip", fabric["oob-spine-01"])
        self.assertTrue(any("not-an-ip" in w for w in self.result["warnings"]))

    def test_wide_host_table_with_global_cidr(self):
        hosts = self._hosts("Rail IPs")
        ru11 = {a["role_or_interface"]: a for a in hosts["P1-GPU-A01ru11"]["assignments"]}
        self.assertEqual(ru11["Rail0"]["ip"], "10.128.128.11")
        self.assertEqual(ru11["Rail0"]["prefixlen_or_mask"], "22")
        self.assertEqual(ru11["Rail1"]["ip"], "10.128.132.11")
        self.assertNotIn("Rail2", ru11)  # sparse rails skipped without warnings
        self.assertEqual(len(hosts["P1-GPU-A01ru12"]["assignments"]), 1)

    def test_wide_host_table_with_ip_net_pairs(self):
        hosts = self._hosts("Pmx-Servers")
        node = {a["role_or_interface"]: a for a in hosts["Ctrl Node-01"]["assignments"]}
        self.assertEqual(node["bmc_ip"]["ip"], "10.2.243.10")
        self.assertEqual(node["bmc_ip"]["prefixlen_or_mask"], "26")
        self.assertEqual(node["mgmt ip"]["ip"], "10.2.243.70")

    def test_l3_generic_source_dest_table(self):
        links = [l for l in self.result["l3_links"] if l["sheet"] == "L3 Links"]
        self.assertEqual(len(links), 1)  # tbd row excluded
        link = links[0]
        self.assertEqual(link["a_host"], "tan-border-01")
        self.assertEqual(link["a_if"], "swp29")
        self.assertEqual(link["a_ip"], "192.0.2.0")
        self.assertEqual(link["b_host"], "fw-01")
        self.assertEqual(link["b_if"], "eth1/1")
        self.assertEqual(link["b_ip"], "192.0.2.1")
        self.assertEqual(link["mask"], "31")

    def test_l3_border_ebgp_variant(self):
        links = [l for l in self.result["l3_links"] if l["sheet"] == "Border External eBGP"]
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["a_host"], "p1-border-leaf1")
        self.assertEqual(link["a_if"], "swp29")
        self.assertEqual(link["a_ip"], "192.0.2.4")
        self.assertEqual(link["mask"], "31")   # from the /31-suffixed cell
        self.assertEqual(link["b_ip"], "192.0.2.5")
        self.assertEqual(link["b_host"], "")   # firewall peer has no hostname
        self.assertEqual(link["a_asn"], "4200010021")
        self.assertEqual(link["b_asn"], "65100")
        self.assertEqual(link["vrf"], "c42")

    def test_lookup_ip_longest_prefix_first(self):
        result = ai_ipam.lookup_ip(self.result, "10.2.240.11")
        self.assertEqual([s["prefix"] for s in result["subnets"]],
                         ["10.2.240.0/23", "10.0.0.0/8"])
        self.assertEqual(result["hosts"][0]["hostname"], "GB300-1-1-Tray-01")
        self.assertEqual(result["hosts"][0]["assignment"]["role_or_interface"], "BMC")
        # fabric mgmt/loopback matches carry the matched field
        loop = ai_ipam.lookup_ip(self.result, "172.31.2.1")
        self.assertEqual(loop["fabric"][0]["record"]["hostname"], "tan-spine-01")
        self.assertEqual(loop["fabric"][0]["match_field"], "loopback_ip")
        # invalid query IPs return empty results, never raise
        self.assertEqual(ai_ipam.lookup_ip(self.result, "10.2.240.999")["hosts"], [])

    def test_lookup_host_case_and_fqdn_tolerant(self):
        hit = ai_ipam.lookup_host(self.result, "gb300-1-1-tray-01.dc.example.com")
        self.assertEqual(len(hit["hosts"]), 1)
        self.assertEqual(hit["hosts"][0]["hostname"], "GB300-1-1-Tray-01")
        # fabric records also match on their 'device' label alias
        via_device = ai_ipam.lookup_host(self.result, "spine-01")
        self.assertEqual(via_device["fabric"][0]["hostname"], "tan-spine-01")
        self.assertEqual(ai_ipam.lookup_host(self.result, "no-such-host"),
                         {"hostname": "no-such-host", "hosts": [], "fabric": []})

    def test_expected_bgp(self):
        bgp = ai_ipam.expected_bgp(self.result)
        self.assertEqual(bgp["tan-spine-01"], {"loopback": "172.31.2.1", "asn": "4200000101"})
        self.assertEqual(bgp["tan-core-01"], {"loopback": "", "asn": "4200010001"})
        # fabric rows without loopback and ASN are excluded from BGP truth
        self.assertNotIn("oob-spine-01", bgp)


class HelperTest(unittest.TestCase):
    def test_parse_ip(self):
        self.assertEqual(ai_ipam._parse_ip(" 10.0.0.1 "), ("10.0.0.1", None, "ok"))
        self.assertEqual(ai_ipam._parse_ip("192.0.2.0/31"), ("192.0.2.0", 31, "ok"))
        self.assertEqual(ai_ipam._parse_ip("tbd")[2], "blank")
        self.assertEqual(ai_ipam._parse_ip("L2 ONLY")[2], "blank")
        self.assertEqual(ai_ipam._parse_ip("10.0.0.256")[2], "invalid")
        self.assertEqual(ai_ipam._parse_ip("10.0.0.1/99")[2], "invalid")

    def test_parse_prefix(self):
        self.assertEqual(ai_ipam._parse_prefix("10.128.8.0/23"), ("10.128.8.0/23", "ok"))
        self.assertEqual(ai_ipam._parse_prefix("10.128.9.7/23"), ("10.128.8.0/23", "ok"))
        self.assertEqual(ai_ipam._parse_prefix("10.254.X.X/31")[1], "invalid")
        self.assertEqual(ai_ipam._parse_prefix("")[1], "blank")

    def test_norm_asn(self):
        self.assertEqual(ai_ipam._norm_asn("4.200000101E9"), "4200000101")
        self.assertEqual(ai_ipam._norm_asn("65100.0"), "65100")
        self.assertEqual(ai_ipam._norm_asn("4200010001"), "4200010001")
        self.assertEqual(ai_ipam._norm_asn("Core Switches: 42000"), "")
        self.assertEqual(ai_ipam._norm_asn(""), "")


class RealWorkbookIntegrationTest(unittest.TestCase):
    """Runs only when the real validation workbooks are present (CI safety)."""

    def test_sferical_workbook(self):
        if not SFERICAL_XLSX.exists():
            self.skipTest("Sferical validation workbook not available")
        result = ai_ipam.parse_workbook(SFERICAL_XLSX)
        self.assertGreater(len(result["hosts"]), 1000)
        self.assertGreater(len(result["subnets"]), 30)
        self.assertGreater(len(result["fabric"]), 50)
        # non-data tabs skipped naturally
        for name in ("Version", "Topology"):
            self.assertIn(name, result["skipped_sheets"])
        # spot checks verified against the raw sheet XML:
        # Switches r2: SPINE-01/tan-spine-01 172.31.44.1 172.31.2.1/32 4.200000101E9
        bgp = ai_ipam.expected_bgp(result)
        self.assertEqual(bgp["tan-spine-01"],
                         {"loopback": "172.31.2.1", "asn": "4200000101"})
        # GB300 OOB r2 block A: GB300-1-1-Tray-01 BMC 10.2.240.11 /23 VLAN_8
        hit = ai_ipam.lookup_ip(result, "10.2.240.11")
        self.assertEqual(hit["hosts"][0]["hostname"], "GB300-1-1-Tray-01")
        self.assertEqual(hit["hosts"][0]["assignment"]["role_or_interface"], "BMC")
        # IP Ranges r7: 172.31.44.0/24 gw 172.31.44.254 vrf vpn60030 VLAN_5
        self.assertEqual(hit["subnets"][0]["prefix"], "10.2.240.0/23")
        ranges = {s["prefix"]: s for s in result["subnets"] if s["sheet"] == "IP Ranges"}
        mgmt = ranges["172.31.44.0/24"]
        self.assertEqual(mgmt["gateway"], "172.31.44.254")
        self.assertEqual(mgmt["vrf"], "vpn60030")
        self.assertEqual(mgmt["vlan"], "VLAN_5")
        # GB300 OOB blocks merge: Tray-01 has BMC + BF3BMC assignments
        tray = ai_ipam.lookup_host(result, "GB300-1-1-Tray-01")
        oob = [h for h in tray["hosts"] if h["sheet"] == "GB300 OOB"]
        self.assertEqual(len(oob), 1)
        self.assertEqual({a["role_or_interface"] for a in oob[0]["assignments"]},
                         {"BMC", "BF3BMC"})

    def test_c42_workbook(self):
        if not C42_XLSX.exists():
            self.skipTest("C42 validation workbook not available")
        result = ai_ipam.parse_workbook(C42_XLSX)
        self.assertGreater(len(result["hosts"]), 1000)
        self.assertGreater(len(result["subnets"]), 10)
        self.assertGreater(len(result["fabric"]), 100)
        self.assertGreater(len(result["l3_links"]), 0)
        for name in ("READ ME & Conventions", "Change Log", "_Lists", "Audit & Validation"):
            self.assertIn(name, result["skipped_sheets"])
        # Border External eBGP r2: p1-border-leaf1 swp29 192.0.2.0/31 <-> 192.0.2.1
        link = result["l3_links"][0]
        self.assertEqual(link["a_host"], "p1-border-leaf1")
        self.assertEqual((link["a_if"], link["a_ip"], link["b_ip"]),
                         ("swp29", "192.0.2.0", "192.0.2.1"))

    def test_nscale_workbook(self):
        if not NSCALE_XLSX.exists():
            self.skipTest("Nscale validation workbook not available")
        result = ai_ipam.parse_workbook(NSCALE_XLSX)
        self.assertGreater(len(result["hosts"]), 4000)
        self.assertGreater(len(result["fabric"]), 200)
        self.assertIn("Hostnames", result["skipped_sheets"])  # no-IP tab
        # Switches r2: swi1061 tan_core 10.128.0.1 10.127.0.1/32 4.200000001E9
        bgp = ai_ipam.expected_bgp(result)
        self.assertEqual(bgp["swi1061"], {"loopback": "10.127.0.1", "asn": "4200000001"})

    def test_mistral_workbook(self):
        if not MISTRAL_XLSX.exists():
            self.skipTest("Mistral validation workbook not available")
        result = ai_ipam.parse_workbook(MISTRAL_XLSX)
        self.assertGreater(len(result["hosts"]), 15000)
        self.assertGreater(len(result["subnets"]), 1000)
        # stacked Hostname/AS Number table inside the parameters sheet
        bgp = ai_ipam.expected_bgp(result)
        self.assertGreater(len(bgp), 500)


if __name__ == "__main__":
    unittest.main()
