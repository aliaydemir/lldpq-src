#!/usr/bin/env python3
"""Per-port breakout fitting of three-part 'X/Y/Z' design ports.

One table of cases runs through html/ai_p2p.resolve_port_map and through its
browser mirror resolvePortMapJs in html/lldp.html: the width of a split is
decided per port (own rows, then the live interface inventory, then the
device-wide value), so a switch that mixes 2x/4x/8x splits gets the sub-port
names that exist, and an unsplit port written X/1/1 stays swpX when the
inventory shows it.  The generated topology.dot is then checked by the real
LLDP wiring validator, and validate_p2p must flag what the design cannot prove.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))

import ai_generate  # noqa: E402
import ai_p2p  # noqa: E402
import test_inventory_api as inventory_tests  # noqa: E402  (CGI heredoc harness)

LLDP_HTML = (ROOT / "html" / "lldp.html").read_text(encoding="utf-8")


def _rows(device, ports, peer="peer"):
    """Design rows cabling `ports` of `device` to distinct invented peers."""
    return [["%s-%d" % (peer, i), "eth1", device, port]
            for i, port in enumerate(ports)]


TWIN = ["1/1/1", "1/2/1"]                              # 2x, group style
FOUR = ["33/1/1", "33/1/2", "33/2/1", "33/2/2"]        # 4x, two groups of two
EIGHT = ["40/%d/%d" % (y, z) for y in (1, 2) for z in (1, 2, 3, 4)]


def _subs(port, count):
    """Live sub-port names swp<port>s0..s<count-1>."""
    return ["swp%ds%d" % (port, i) for i in range(count)]


# name, design rows [src, src_port, dst, dst_port], live inventory, expected
# {"device_key|design port": OS name} (the complete resolved map).
CASES = [
    ("twin port alone", _rows("LEAF-01", TWIN), None,
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1"}),
    ("mixed 2x + 4x without inventory keeps the device-wide width",
     _rows("LEAF-01", TWIN + FOUR), None,
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s2",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("mixed 2x + 4x: live sub-ports decide per port",
     _rows("LEAF-01", TWIN + FOUR),
     {"leaf-01": _subs(1, 2) + _subs(33, 4) + ["swp2", "eth0"]},
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("mixed 4x + 8x: live sub-ports decide the 4x port, rows the 8x port",
     _rows("LEAF-01", FOUR + EIGHT),
     {"LEAF-01": _subs(33, 4) + _subs(40, 8)},
     {"leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3",
      "leaf-01|40/1/1": "swp40s0", "leaf-01|40/1/2": "swp40s1",
      "leaf-01|40/1/3": "swp40s2", "leaf-01|40/1/4": "swp40s3",
      "leaf-01|40/2/1": "swp40s4", "leaf-01|40/2/2": "swp40s5",
      "leaf-01|40/2/3": "swp40s6", "leaf-01|40/2/4": "swp40s7"}),
    ("sparse rows without inventory use the device-wide width",
     _rows("SP-01", ["1/1/4", "3/1/1", "3/2/1"]), None,
     {"sp-01|1/1/4": "swp1s3", "sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("sparse rows: a complete live inventory confirms the wide split",
     _rows("SP-01", ["3/1/1", "3/2/1"]), {"sp-01": _subs(3, 8)},
     {"sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("partial inventory: the highest live index counts, not the number of names",
     _rows("SP-01", ["3/1/1", "3/2/1"]), {"sp-01": ["swp3s0", "swp3s4"]},
     {"sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("partial inventory that cannot decide falls back to the device-wide width",
     _rows("SP-01", ["1/1/4", "3/1/1", "3/2/1"]), {"sp-01": ["swp3s0"]},
     {"sp-01|1/1/4": "swp1s3", "sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("own rows that fit one breakout only outrank the inventory",
     _rows("SP-01", ["1/%d/%d" % (y, z) for y in (1, 2) for z in (1, 2, 3, 4)]),
     {"sp-01": _subs(1, 4)},
     {"sp-01|1/1/1": "swp1s0", "sp-01|1/1/2": "swp1s1", "sp-01|1/1/3": "swp1s2",
      "sp-01|1/1/4": "swp1s3", "sp-01|1/2/1": "swp1s4", "sp-01|1/2/2": "swp1s5",
      "sp-01|1/2/3": "swp1s6", "sp-01|1/2/4": "swp1s7"}),
    ("own rows reaching sub 3 in two groups can only be an 8x split",
     _rows("SP-01", ["3/1/3", "3/2/1"]), None,
     {"sp-01|3/1/3": "swp3s2", "sp-01|3/2/1": "swp3s4"}),
    ("an inventory with fewer sub-ports than the rows need does not decide",
     _rows("LEAF-01", FOUR), {"leaf-01": _subs(33, 2)},
     {"leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("four groups of one on a live 4x port",
     _rows("LEAF-01", ["7/1/1", "7/3/1"]), {"leaf-01": _subs(7, 4)},
     {"leaf-01|7/1/1": "swp7s0", "leaf-01|7/3/1": "swp7s2"}),
    ("unsplit X/1/1 without inventory keeps the sub-port spelling",
     _rows("LEAF-01", ["5/1/1"]), None, {"leaf-01|5/1/1": "swp5s0"}),
    ("unsplit X/1/1: the live switch has swpX without sub-ports",
     _rows("LEAF-01", ["5/1/1"]), {"leaf-01": ["swp5", "swp6s0"]},
     {"leaf-01|5/1/1": "swp5"}),
    ("X/1/1 on a port that is split live stays the first sub-port",
     _rows("LEAF-01", ["5/1/1"]), {"leaf-01": _subs(5, 4)},
     {"leaf-01|5/1/1": "swp5s0"}),
    ("a port the design splits keeps sub-port names on an unsplit live port",
     _rows("LEAF-01", ["5/1/1", "5/1/2"]), {"leaf-01": ["swp5"]},
     {"leaf-01|5/1/1": "swp5s0", "leaf-01|5/1/2": "swp5s1"}),
    ("an inventory without the port is no evidence",
     _rows("LEAF-01", ["5/1/1"] + TWIN + FOUR), {"leaf-01": ["swp9", "swp10s0"]},
     {"leaf-01|5/1/1": "swp5s0", "leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s2",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("another device's inventory does not leak",
     _rows("LEAF-01", TWIN + FOUR), {"leaf-02": _subs(1, 2) + _subs(33, 4)},
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s2",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("inventory in the lldp_neighbors.json 'ports' shape, FQDN vs short name",
     _rows("leaf-01.example.com", TWIN + FOUR),
     {"LEAF-01": {name: {"oper": "UP"} for name in _subs(1, 2) + _subs(33, 4)}},
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("FQDN and short spellings of one switch share the device-wide width",
     _rows("sp-01.example.com", ["1/1/4"]) + _rows("SP-01", ["3/1/1", "3/2/1"], "other"),
     None,
     {"sp-01|1/1/4": "swp1s3", "sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("zero-padded port numbers are one port",
     _rows("LEAF-01", ["01/1/1", "1/2/1"]), None,
     {"leaf-01|01/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1"}),
    ("two-part and OS spellings are not three-part ports",
     _rows("LEAF-01", ["49/1", "swp50", "51"]), {"leaf-01": ["swp49s0", "swp50"]},
     {}),
    # The highest live index counts in whatever order the inventory lists the
    # ports (the page builds it from rows sorted by status).
    ("inventory listed high to low still shows the wide split",
     _rows("SP-01", ["3/1/1", "3/2/1"]), {"sp-01": ["swp3s4", "swp3s0"]},
     {"sp-01|3/1/1": "swp3s0", "sp-01|3/2/1": "swp3s4"}),
    ("an unsplit name listed after a sub-port does not hide the split",
     _rows("LEAF-01", ["1/1/1"]), {"leaf-01": ["swp1s0", "swp1"]},
     {"leaf-01|1/1/1": "swp1s0"}),
    ("a port the design cables in two groups is not swpX on an unsplit live port",
     _rows("LEAF-01", ["5/1/1", "5/2/1"]), {"leaf-01": ["swp5"]},
     {"leaf-01|5/1/1": "swp5s0", "leaf-01|5/2/1": "swp5s1"}),
    ("inventory spelled as FQDN, upper case, with sub-interfaces and other names",
     _rows("leaf-01", TWIN + FOUR),
     {"LEAF-01.example.com": ["SWP1S0", "SWP1S1", "swp1s0.100", "swp1s3.200",
                              "xswp1s7", "swp33s0", "swp33s3"]},
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1",
      "leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s2", "leaf-01|33/2/2": "swp33s3"}),
    ("a zero-padded row and a plain row of one port share their groups",
     _rows("SP-01", ["01/1/3", "1/2/1"]), None,
     {"sp-01|01/1/3": "swp1s2", "sp-01|1/2/1": "swp1s4"}),
    ("an FQDN no other name shares a label with is keyed by its short name",
     _rows("leaf-01.example.com", TWIN), None,
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1"}),
    # Two switches that share a first label are two switches.
    ("FQDNs sharing a first label are fitted apart",
     _rows("leaf-01.site-a", TWIN) + _rows("leaf-01.site-b", ["1/1/1", "1/1/2", "1/2/1", "1/2/2"], "other"),
     None,
     {"leaf-01.site-a|1/1/1": "swp1s0", "leaf-01.site-a|1/2/1": "swp1s1",
      "leaf-01.site-b|1/1/1": "swp1s0", "leaf-01.site-b|1/1/2": "swp1s1",
      "leaf-01.site-b|1/2/1": "swp1s2", "leaf-01.site-b|1/2/2": "swp1s3"}),
    ("FQDNs sharing a first label each take their own live ports",
     _rows("leaf-01.site-a", TWIN + ["9/1/4"]) + _rows("leaf-01.site-b", TWIN, "other"),
     {"LEAF-01.SITE-A": _subs(1, 2), "leaf-01.site-b": _subs(1, 8)},
     {"leaf-01.site-a|1/1/1": "swp1s0", "leaf-01.site-a|1/2/1": "swp1s1",
      "leaf-01.site-a|9/1/4": "swp9s3",
      "leaf-01.site-b|1/1/1": "swp1s0", "leaf-01.site-b|1/2/1": "swp1s4"}),
    ("a bare name in the design makes the FQDNs sharing it one switch",
     _rows("leaf-01.site-a", ["1/1/4"]) + _rows("leaf-01.site-b", ["3/1/1", "3/2/1"], "other")
     + _rows("LEAF-01", ["5/1/1"], "third"),
     None,
     {"leaf-01|1/1/4": "swp1s3", "leaf-01|3/1/1": "swp3s0", "leaf-01|3/2/1": "swp3s4",
      "leaf-01|5/1/1": "swp5s0"}),
    ("a bare name in the inventory makes the FQDNs sharing it one switch",
     _rows("leaf-01.site-a", TWIN) + _rows("leaf-01.site-b", ["9/1/4"], "other"),
     {"leaf-01": _subs(1, 2)},
     {"leaf-01|1/1/1": "swp1s0", "leaf-01|1/2/1": "swp1s1", "leaf-01|9/1/4": "swp9s3"}),
    # Rows that stop at group 2 of a port with 4 or 8 live sub-ports: read as
    # two groups, and marked as a guess (see GUESSED).
    ("two groups on a live 4x port are two groups of two",
     _rows("LEAF-01", ["7/1/1", "7/2/1"]), {"leaf-01": _subs(7, 4)},
     {"leaf-01|7/1/1": "swp7s0", "leaf-01|7/2/1": "swp7s2"}),
    ("a third group on the same live 4x port proves one sub-port per group",
     _rows("LEAF-01", ["7/1/1", "7/2/1", "7/3/1"]), {"leaf-01": _subs(7, 4)},
     {"leaf-01|7/1/1": "swp7s0", "leaf-01|7/2/1": "swp7s1", "leaf-01|7/3/1": "swp7s2"}),
    ("two groups of two on a live 8x port are two groups of four",
     _rows("LEAF-01", FOUR), {"leaf-01": _subs(33, 8)},
     {"leaf-01|33/1/1": "swp33s0", "leaf-01|33/1/2": "swp33s1",
      "leaf-01|33/2/1": "swp33s4", "leaf-01|33/2/2": "swp33s5"}),
]

# Resolved ports whose name is a guess, per case (every other case: none).
# Only rows beyond group 1 can be one: the width was borrowed from another
# port, or the live sub-ports fit more than one group count.
GUESSED = {
    "mixed 2x + 4x without inventory keeps the device-wide width": ["leaf-01|1/2/1"],
    "sparse rows without inventory use the device-wide width": ["sp-01|3/2/1"],
    "sparse rows: a complete live inventory confirms the wide split": ["sp-01|3/2/1"],
    "partial inventory: the highest live index counts, not the number of names":
        ["sp-01|3/2/1"],
    "partial inventory that cannot decide falls back to the device-wide width":
        ["sp-01|3/2/1"],
    "an inventory without the port is no evidence": ["leaf-01|1/2/1"],
    "another device's inventory does not leak": ["leaf-01|1/2/1"],
    "FQDN and short spellings of one switch share the device-wide width":
        ["sp-01|3/2/1"],
    "inventory listed high to low still shows the wide split": ["sp-01|3/2/1"],
    "FQDNs sharing a first label each take their own live ports":
        ["leaf-01.site-b|1/2/1"],
    "a bare name in the design makes the FQDNs sharing it one switch":
        ["leaf-01|3/2/1"],
    "two groups on a live 4x port are two groups of two": ["leaf-01|7/2/1"],
    "two groups of two on a live 8x port are two groups of four":
        ["leaf-01|33/2/1", "leaf-01|33/2/2"],
}


def _records(rows):
    return [{"source_name": a, "source_port": ap, "dest_name": b, "dest_port": bp,
             "connection_type": "compute", "network_type": "eth",
             "sheet_name": "P2P", "row_number": index + 2, "unresolved": False}
            for index, (a, ap, b, bp) in enumerate(rows)]


def _python_map(rows, live):
    # A caller without an inventory keeps the one-argument call.
    resolved = (ai_p2p.resolve_port_map(_records(rows)) if live is None
                else ai_p2p.resolve_port_map(_records(rows), live))
    return {"%s|%s" % key: value for key, value in resolved.items()}


def _python_guessed(rows, live):
    _resolved, fits = ai_p2p._fit_breakout_ports(_records(rows), live)
    return sorted("%s|%s" % key for key in ai_p2p._guessed_ports(fits))


def _source_between(start, end):
    begin = LLDP_HTML.index(start)
    return LLDP_HTML[begin:LLDP_HTML.index(end, begin)]


def _browser_maps(cases):
    script = (
        _source_between("function cleanPortValue(port)", "function portAliasesJs(port)")
        + _source_between("const BREAKOUT_STEPS", "function livePortInventoryJs(connections)")
        + """
const cases = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(cases.map(c => {
    const resolved = resolvePortMapJs(c.records, c.live);
    return { map: Object.fromEntries(resolved), guessed: Array.from(resolved.guessed).sort() };
})));
""")
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps([{"records": _records(rows), "live": live}
                          for _name, rows, live, _expected in cases]).encode(),
        capture_output=True, check=True)
    return json.loads(result.stdout.decode())


class ResolverTableTests(unittest.TestCase):
    def test_python_resolver_gives_the_expected_names(self):
        for name, rows, live, expected in CASES:
            with self.subTest(case=name):
                self.assertEqual(_python_map(rows, live), expected)
                self.assertEqual(_python_guessed(rows, live),
                                 sorted(GUESSED.get(name, [])))

    def test_every_guessed_case_names_a_case_of_the_table(self):
        self.assertEqual(set(GUESSED) - {name for name, *_rest in CASES}, set())

    @unittest.skipUnless(shutil.which("node"), "Node.js required for the browser mirror")
    def test_browser_mirror_gives_the_same_answer_for_the_same_input(self):
        browser = _browser_maps(CASES)
        self.assertEqual(len(browser), len(CASES))
        for (name, rows, live, expected), got in zip(CASES, browser):
            with self.subTest(case=name):
                self.assertEqual(got["map"], expected)
                self.assertEqual(got["map"], _python_map(rows, live))
                self.assertEqual(got["guessed"], sorted(GUESSED.get(name, [])))

    def test_lookup_accepts_the_spellings_of_one_switch_only(self):
        lookup = ai_p2p.resolved_os_port
        # One switch, written as FQDN: any spelling of it finds the port.
        resolved = ai_p2p.resolve_port_map(_records(_rows("leaf-01.example.com", TWIN)))
        for name in ("leaf-01.example.com", "LEAF-01", "leaf-01", "Leaf-01.Example.Com",
                     "leaf-01.other.example"):
            with self.subTest(name=name):
                self.assertEqual(lookup(resolved, name, "1/2/1"), "swp1s1")
        # Short in the inventory, FQDN in the design.
        resolved = ai_p2p.resolve_port_map(
            _records(_rows("leaf-01.example.com", TWIN + FOUR)),
            {"LEAF-01": _subs(1, 2) + _subs(33, 4)})
        self.assertEqual(lookup(resolved, "leaf-01.example.com", "1/2/1"), "swp1s1")
        self.assertEqual(lookup(resolved, "LEAF-01", " 1/2/1 "), "swp1s1")
        # Two switches sharing a first label: only the full name is one of them.
        resolved = ai_p2p.resolve_port_map(_records(
            _rows("leaf-01.site-a", TWIN)
            + _rows("leaf-01.site-b", ["1/1/1", "1/1/2", "1/2/1", "1/2/2"], "other")))
        self.assertEqual(lookup(resolved, "LEAF-01.SITE-A", "1/2/1"), "swp1s1")
        self.assertEqual(lookup(resolved, "leaf-01.site-b", "1/2/1"), "swp1s2")
        self.assertEqual(lookup(resolved, "leaf-01", "1/2/1"), "")
        self.assertEqual(lookup(resolved, "leaf-01.site-c", "1/2/1"), "")
        self.assertEqual(lookup(resolved, "", "1/2/1"), "")
        self.assertEqual(lookup(resolved, "leaf-01.site-a", ""), "")

    def test_default_call_is_the_inventory_free_resolution(self):
        records = _records(_rows("LEAF-01", TWIN + FOUR))
        self.assertEqual(ai_p2p.resolve_port_map(records),
                         ai_p2p.resolve_port_map(records, None))
        self.assertEqual(ai_p2p.resolve_port_map(records),
                         ai_p2p.resolve_port_map(records, {}))

    def test_precise_index_follows_the_live_inventory(self):
        records = _records(_rows("LEAF-01", ["5/1/1"] + TWIN + FOUR))
        live = {"leaf-01": ["swp5"] + _subs(1, 2) + _subs(33, 4)}
        index = ai_p2p.build_port_index(records, live)
        # peer-0 is cabled to 5/1/1, peer-2 to 1/2/1 and peer-5 to 33/2/1.
        for port, peer in (("swp5", "peer-0"), ("swp1s1", "peer-2"), ("swp33s2", "peer-5")):
            with self.subTest(port=port):
                self.assertEqual(
                    index[("leaf-01", port)]["peer_device"], peer)
        # The bare port number is an alias of swpX only, never of swpXs0.
        self.assertIn(("leaf-01", "5"), index)
        self.assertNotIn(("leaf-01", "5"), ai_p2p.build_port_index(records))


# Design rows [src, src_port, dst, dst_port] and a live inventory; the design
# join of both mirrors is asked for every port in PROBES of every device.
INDEX_CASES = [
    ("mixed widths with the full inventory",
     _rows("LEAF-01", ["5/1/1"] + TWIN + FOUR),
     {"leaf-01": ["swp5"] + _subs(1, 2) + _subs(33, 4)}),
    ("mixed widths, design alone", _rows("LEAF-01", ["5/1/1"] + TWIN + FOUR), None),
    ("only the second leg is designed", _rows("LEAF-01", ["1/2/1"]),
     {"leaf-01": _subs(1, 2)}),
    ("one group per leg next to OS names on a live 4x port",
     _rows("LEAF-01", ["1/1/1", "1/2/1", "swp1s2", "swp1s3"]), {"leaf-01": _subs(1, 4)}),
    ("OS names listed before the three-part rows",
     _rows("LEAF-01", ["swp1s3", "swp1s2", "1/2/1", "1/1/1"]), {"leaf-01": _subs(1, 4)}),
    ("guessed names in workbook order", _rows("SP-01", ["3/3/1", "3/2/1", "1/1/4"]), None),
    ("two-part and plain ports", _rows("LEAF-01", ["49/1", "50", "swp51", "33/1/2"]),
     {"leaf-01": ["swp49s0", "swp50", "swp51", "swp33s1"]}),
    ("FQDNs sharing a first label",
     _rows("leaf-01.site-a", TWIN) + _rows("leaf-01.site-b", FOUR + ["1/1/2"], "other"),
     {"leaf-01.site-a": _subs(1, 2), "leaf-01.site-b": _subs(33, 4) + _subs(1, 2)}),
]
PROBES = (["swp%d" % port for port in (1, 3, 5, 33, 49, 50, 51)]
          + ["swp%ds%d" % (port, sub) for port in (1, 3, 5, 33, 49) for sub in range(8)]
          + ["1/2/1", "1/1/1", "33/2/2", "49/1", "50"])


def _python_join(rows, live):
    records = _records(rows)
    index = ai_p2p.build_port_index(records, live)
    devices = sorted({row[2] for row in rows})
    found = {}
    for device in devices:
        for port in PROBES:
            entry = ai_p2p.lookup_by_device_port(index, device, port)
            if entry is not None:
                found["%s|%s" % (device, port)] = entry["row_number"]
    return found


def _browser_joins(cases):
    """The page's own design join (buildP2pIndex + activeP2pDesignFor)."""
    script = ("""
let allConnections = [];
let portAliasLc = {}, portAliasRevLc = {}, deviceAliasLc = {}, deviceAliasRevLc = {};
const updateCsvExportAvailability = () => {};
""" + _source_between("function normalizedValue(value)", "function sameHostname(left, right)")
        + _source_between("let p2pDesignStatus = 'loading';", "function setP2pDesignStatus(status)")
        + _source_between("function deviceKeysJs(name)", "function loadP2pDesign()")
        + _source_between("function activeP2pDesignFor(conn)", "function kvRow(label, value, cls)")
        + """
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(input.cases.map(c => {
    // The report rows a switch contributes: every port it lists.
    allConnections = Object.keys(c.live || {}).flatMap(device => c.live[device].map(port => (
        { localDevice: device, localPort: port, portStatus: 'UP', actualDevice: null, actualPort: null })));
    buildP2pIndex({ connections: c.records });
    p2pDesignStatus = 'ready';
    const found = {};
    c.devices.forEach(device => input.probes.forEach(port => {
        const entry = activeP2pDesignFor({ localDevice: device, localPort: port });
        if (entry) found[device + '|' + port] = entry.row_number;
    }));
    return found;
})));
""")
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps({"probes": PROBES, "cases": [
            {"records": _records(rows), "live": live,
             "devices": sorted({row[2] for row in rows})}
            for _name, rows, live in cases]}).encode(),
        capture_output=True, check=True)
    return json.loads(result.stdout.decode())


class DesignJoinTests(unittest.TestCase):
    """Which design row a live port is joined to: ai_p2p.build_port_index
    (headless CSV, Ask-AI) and the page's buildP2pIndex answer alike."""

    def join(self, name):
        rows, live = next((rows, live) for case, rows, live in INDEX_CASES if case == name)
        return _python_join(rows, live)

    def test_live_port_finds_the_row_fitted_to_it(self):
        # Rows: 5/1/1 = 2, 1/1/1 = 3, 1/2/1 = 4, 33/1/1 .. 33/2/2 = 5 .. 8.
        join = self.join("mixed widths with the full inventory")
        self.assertEqual(
            {port: join.get("LEAF-01|" + port)
             for port in ("swp5", "swp1s0", "swp1s1", "swp1s2", "swp1s4", "swp33s2")},
            {"swp5": 2, "swp1s0": 3, "swp1s1": 4, "swp1s2": None, "swp1s4": None,
             "swp33s2": 7})

    def test_cable_on_another_leg_is_not_joined_to_the_designed_leg(self):
        join = self.join("only the second leg is designed")
        self.assertEqual(join, {"LEAF-01|swp1s1": 2, "LEAF-01|1/2/1": 2})

    def test_guessed_name_does_not_take_a_port_from_a_row_that_names_it(self):
        # 1/1/1 = 2, 1/2/1 = 3 (guessed swp1s2), swp1s2 = 4, swp1s3 = 5.
        for name, rows in (
                ("one group per leg next to OS names on a live 4x port",
                 {"swp1s0": 2, "swp1s1": 3, "swp1s2": 4, "swp1s3": 5}),
                ("OS names listed before the three-part rows",
                 {"swp1s0": 5, "swp1s1": 4, "swp1s2": 3, "swp1s3": 2})):
            with self.subTest(case=name):
                join = self.join(name)
                self.assertEqual(
                    {port: join.get("LEAF-01|" + port) for port in rows}, rows)

    def test_guessed_names_still_answer_before_tolerant_aliases(self):
        # 3/3/1 = 2 (swp3s8), 3/2/1 = 3 (swp3s4): the tolerant aliases of
        # 3/3/1 include swp3s4, the fitted name of 3/2/1 must win.
        join = self.join("guessed names in workbook order")
        self.assertEqual(join["SP-01|swp3s4"], 3)

    @unittest.skipUnless(shutil.which("node"), "Node.js required for the browser mirror")
    def test_page_joins_the_same_rows(self):
        browser = _browser_joins(INDEX_CASES)
        self.assertEqual(len(browser), len(INDEX_CASES))
        for (name, rows, live), got in zip(INDEX_CASES, browser):
            with self.subTest(case=name):
                self.assertTrue(got, "the case joins nothing")
                self.assertEqual(got, _python_join(rows, live))


def _load_lldp_validate():
    sys.path.insert(0, str(ROOT / "lldpq"))
    spec = importlib.util.spec_from_file_location(
        "audit_webb_lldp_validate", ROOT / "lldpq" / "lldp-validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TopologyDotTests(unittest.TestCase):
    """The operator-visible symptom: a correctly cabled mixed-width switch."""

    ROWS = [
        ["LEAF-01", "1/1/1", "SPINE-01", "swp1s0"],
        ["LEAF-01", "1/2/1", "SPINE-02", "swp1s0"],
        ["LEAF-01", "33/1/1", "SPINE-03", "swp1"],
        ["LEAF-01", "33/1/2", "SPINE-03", "swp2"],
        ["LEAF-01", "33/2/1", "SPINE-03", "swp3"],
        ["LEAF-01", "33/2/2", "SPINE-03", "swp4"],
        ["LEAF-01", "5/1/1", "SPINE-04", "swp5"],
    ]
    # What the switches report: LEAF-01 swp1 is split 2x, swp33 4x, swp5 not.
    LIVE = {
        "LEAF-01": [("swp1s0", "SPINE-01", "swp1s0"), ("swp1s1", "SPINE-02", "swp1s0"),
                    ("swp33s0", "SPINE-03", "swp1"), ("swp33s1", "SPINE-03", "swp2"),
                    ("swp33s2", "SPINE-03", "swp3"), ("swp33s3", "SPINE-03", "swp4"),
                    ("swp5", "SPINE-04", "swp5")],
        "SPINE-01": [("swp1s0", "LEAF-01", "swp1s0")],
        "SPINE-02": [("swp1s0", "LEAF-01", "swp1s1")],
        "SPINE-03": [("swp1", "LEAF-01", "swp33s0"), ("swp2", "LEAF-01", "swp33s1"),
                     ("swp3", "LEAF-01", "swp33s2"), ("swp4", "LEAF-01", "swp33s3")],
        "SPINE-04": [("swp5", "LEAF-01", "swp5")],
    }

    def _inventory(self):
        return {device: {port: {"oper": "UP"} for port, _nbr, _nbr_port in links}
                for device, links in self.LIVE.items()}

    def _wiring_report(self, dot):
        validator = _load_lldp_validate()
        neighbors = {
            device: [{"interface": port, "sys_name": nbr, "port_id": nbr_port}
                     for port, nbr, nbr_port in links]
            for device, links in self.LIVE.items()}
        status = {device: {port: "UP" for port, _n, _p in links}
                  for device, links in self.LIVE.items()}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "topology.dot"
            path.write_text(dot, encoding="utf-8")
            results = validator.check_connections(str(path), neighbors, status)
        return [(device, row["Port"], row["Status"])
                for device, rows in results.items() for row in rows]

    def test_live_inventory_gives_the_sub_ports_that_exist(self):
        dot = ai_generate.p2p_to_topology_dot(
            _records(self.ROWS), live_ports=self._inventory())
        self.assertIn('"LEAF-01":"swp1s1" -- "SPINE-02":"swp1s0"', dot)
        self.assertIn('"LEAF-01":"swp5" -- "SPINE-04":"swp5"', dot)
        self.assertNotIn("swp1s2", dot)
        self.assertNotIn("swp5s0", dot)
        report = self._wiring_report(dot)
        self.assertEqual(len(report), 14)
        self.assertEqual([row for row in report if row[2] != "Pass"], [])

    def test_without_inventory_the_device_wide_names_stay(self):
        dot = ai_generate.p2p_to_topology_dot(_records(self.ROWS))
        self.assertIn('"LEAF-01":"swp1s2" -- "SPINE-02":"swp1s0"', dot)
        self.assertIn('"LEAF-01":"swp5s0" -- "SPINE-04":"swp5"', dot)

    def test_two_switches_sharing_a_first_label_keep_their_own_names(self):
        rows = [["leaf-01.site-a", "1/1/1", "H1", "eth1"], ["leaf-01.site-a", "1/2/1", "H2", "eth1"],
                ["leaf-01.site-b", "1/1/1", "H3", "eth1"], ["leaf-01.site-b", "1/1/2", "H4", "eth1"],
                ["leaf-01.site-b", "1/2/1", "H5", "eth1"], ["leaf-01.site-b", "1/2/2", "H6", "eth1"]]
        dot = ai_generate.p2p_to_topology_dot(_records(rows))
        for edge in ('"leaf-01.site-a":"swp1s1" -- "H2":"eth1"',
                     '"leaf-01.site-b":"swp1s1" -- "H4":"eth1"',
                     '"leaf-01.site-b":"swp1s2" -- "H5":"eth1"',
                     '"leaf-01.site-b":"swp1s3" -- "H6":"eth1"'):
            self.assertIn(edge, dot)
        self.assertEqual(dot.count(" -- "), 6)

    def test_design_label_finds_its_switch_through_the_display_alias(self):
        rows = [["LEAF A1" if cell == "LEAF-01" else cell for cell in row]
                for row in self.ROWS]
        dot = ai_generate.p2p_to_topology_dot(
            _records(rows), device_aliases={"leaf a1": "LEAF-01"},
            live_ports=self._inventory())
        self.assertIn('"LEAF-01":"swp1s1" -- "SPINE-02":"swp1s0"', dot)
        self.assertIn('"LEAF-01":"swp5" -- "SPINE-04":"swp5"', dot)
        self.assertNotIn("LEAF A1", dot)


class ValidateWidthTests(unittest.TestCase):
    def _report(self, rows, **kwargs):
        return ai_generate.validate_p2p(
            {"connections": _records(rows), "warnings": []}, **kwargs)

    def _kinds(self, report):
        return [issue["kind"] for issue in report["issues"]]

    def test_port_resolved_against_its_own_rows_is_flagged(self):
        # swp1 is cabled 1/1/1 + 1/2/1 but mapped with the width of port 33.
        report = self._report(_rows("LEAF-01", TWIN + FOUR))
        self.assertEqual(self._kinds(report), ["breakout-width-ambiguous"])
        issue = report["issues"][0]
        self.assertEqual(issue["severity"], "warning")
        self.assertEqual((issue["device"], issue["port"]), ("LEAF-01", "swp1"))
        self.assertEqual(issue["row"], 3)  # the 1/2/1 row
        for text in ("1/2/1", "swp1s2", "swp1s1", "port 33"):
            self.assertIn(text, issue["message"])
        self.assertEqual(report["counts"]["breakout_width_warnings"], 1)

    def test_sparse_port_is_flagged_because_the_design_cannot_tell(self):
        report = self._report(_rows("SP-01", ["1/1/4", "3/1/1", "3/2/1"]))
        self.assertEqual(self._kinds(report), ["breakout-width-ambiguous"])
        self.assertIn("swp3s4", report["issues"][0]["message"])
        self.assertIn("swp3s1", report["issues"][0]["message"])

    def test_live_inventory_settles_the_names_and_reports_the_mix(self):
        report = self._report(
            _rows("LEAF-01", TWIN + FOUR),
            live_ports={"leaf-01": _subs(1, 2) + _subs(33, 4)})
        self.assertEqual(self._kinds(report), ["breakout-mixed-width"])
        issue = report["issues"][0]
        self.assertEqual(issue["severity"], "warning")
        self.assertEqual(issue["device"], "LEAF-01")
        self.assertIn("port 1 has 1", issue["message"])
        self.assertIn("port 33 has 2", issue["message"])
        self.assertEqual(report["counts"]["breakout_width_warnings"], 1)

    def test_one_proven_narrow_port_is_enough_to_call_the_switch_mixed(self):
        # Only swp1 is in the inventory; port 33 needs at least two per group.
        report = self._report(
            _rows("LEAF-01", TWIN + FOUR), live_ports={"leaf-01": _subs(1, 2)})
        self.assertEqual(self._kinds(report), ["breakout-mixed-width"])
        self.assertIn("port 33 has at least 2", report["issues"][0]["message"])

    def test_design_label_finds_its_inventory_through_the_display_alias(self):
        report = self._report(
            _rows("LEAF A1", TWIN + FOUR),
            live_ports={"leaf-01": _subs(1, 2) + _subs(33, 4)},
            device_aliases={"leaf a1": "leaf-01"})
        self.assertEqual(self._kinds(report), ["breakout-mixed-width"])
        self.assertEqual(report["issues"][0]["device"], "LEAF A1")

    def test_validation_judges_the_names_topology_dot_will_carry(self):
        # LEAF-01 5/1/1 is live as swp5; a second cable on 5 must still collide.
        rows = [["LEAF-01", "5/1/1", "SPINE-04", "swp5"],
                ["LEAF-01", "swp5", "SPINE-05", "swp5"]]
        report = self._report(rows, live_ports={"LEAF-01": ["swp5"]})
        self.assertEqual(self._kinds(report), ["duplicate-port"])
        self.assertIn("(swp5)", report["issues"][0]["message"])

    def test_live_sub_ports_that_fit_two_notations_are_reported(self):
        # 7/1/1 + 7/2/1 on a port with four live sub-ports: two groups of two
        # (the name used) or the first two of four groups of one.
        rows = _rows("LEAF-01", ["7/1/1", "7/2/1"])
        report = self._report(rows, live_ports={"leaf-01": _subs(7, 4)})
        self.assertEqual(self._kinds(report), ["breakout-width-ambiguous"])
        issue = report["issues"][0]
        self.assertEqual(
            (issue["severity"], issue["device"], issue["port"], issue["row"]),
            ("warning", "LEAF-01", "swp7", 3))
        for text in ("7/2/1 mapped to swp7s2 as 2 groups of 2",
                     "4 sub-ports on swp7", "stop at group 2",
                     "read as 4 groups of 1 they would be swp7s1"):
            self.assertIn(text, issue["message"])
        self.assertEqual(report["counts"]["breakout_width_warnings"], 1)
        # Eight live sub-ports leave three readings.
        message = self._report(
            rows, live_ports={"leaf-01": _subs(7, 8)})["issues"][0]["message"]
        for text in ("7/2/1 mapped to swp7s4 as 2 groups of 4",
                     "read as 4 groups of 2 or 8 groups of 1 they would be "
                     "swp7s2 or swp7s1"):
            self.assertIn(text, message)

    def test_fit_that_rows_or_inventory_settle_is_not_reported(self):
        settled = (
            # Rows: sub 3 in two groups can only be 8x (four per group).
            (_rows("SP-01", ["3/1/3", "3/2/1"]), None),
            (_rows("SP-01", ["40/1/1", "40/2/4"]), None),
            # Inventory: a third group on a 4x port, one sub-port per group.
            (_rows("LEAF-01", ["7/1/1", "7/2/1", "7/3/1"]), {"leaf-01": _subs(7, 4)}),
            # Inventory: two groups of two, and the rows reach sub 2.
            (_rows("LEAF-01", FOUR), {"leaf-01": _subs(33, 4)}),
            (_rows("LEAF-01", TWIN), {"leaf-01": _subs(1, 2)}),
        )
        for rows, live in settled:
            with self.subTest(ports=[row[3] for row in rows]):
                self.assertEqual(self._report(rows, live_ports=live)["issues"], [])

    def test_borrowed_width_names_the_first_port_that_shows_it(self):
        # Ports 33 and 40 both reach sub 2; the message points at one of them.
        report = self._report(
            _rows("LEAF-01", ["40/1/1", "40/1/2"] + TWIN + FOUR))
        self.assertEqual(self._kinds(report), ["breakout-width-ambiguous"])
        self.assertIn("taken from port 33 ", report["issues"][0]["message"])

    def test_warning_points_at_the_first_row_of_a_repeated_port(self):
        rows = _rows("LEAF-01", TWIN + FOUR) + [["late", "eth9", "LEAF-01", "1/2/1"]]
        report = self._report(rows)
        issue = next(issue for issue in report["issues"]
                     if issue["kind"] == "breakout-width-ambiguous")
        self.assertEqual(issue["row"], 3)

    def test_fqdns_sharing_a_first_label_are_judged_as_two_switches(self):
        # Both switches cable port 1; that is no duplicate port, and the
        # 4x port of site-b says nothing about the 2x port of site-a.
        rows = (_rows("leaf-01.site-a", TWIN)
                + _rows("leaf-01.site-b", ["1/1/1", "1/1/2", "1/2/1", "1/2/2"], "other"))
        report = self._report(rows)
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["counts"]["resolved_links"], 6)
        # FQDN and short spellings of one switch stay one switch.
        rows = (_rows("leaf-01.example.com", ["1/1/1"])
                + _rows("LEAF-01", ["1/1/1"], "other"))
        report = self._report(rows)
        self.assertEqual(self._kinds(report), ["duplicate-port"])

    def test_uniform_and_group_one_designs_stay_clean(self):
        clean = (
            _rows("LEAF-01", TWIN),
            _rows("LEAF-01", EIGHT + ["41/1/1", "41/1/2", "42/1/1"]),
            _rows("LEAF-01", FOUR + ["34/1/1", "34/1/2", "34/2/1", "34/2/2"]),
            _rows("LEAF-01", ["49/1", "swp50", "51"]),
        )
        for rows in clean:
            with self.subTest(ports=[row[3] for row in rows]):
                report = self._report(rows)
                self.assertEqual(report["issues"], [])
                self.assertEqual(report["counts"]["breakout_width_warnings"], 0)


class InventoryValidateActionTests(unittest.TestCase):
    """Inventory -> Validate runs the stored design through validate_p2p."""

    @classmethod
    def setUpClass(cls):
        cls.block = inventory_tests.extract_heredoc(
            inventory_tests.INVENTORY_API.read_text(encoding="utf-8"), "PYTHON_END")

    setUp = inventory_tests.InventoryApiTests.setUp
    tearDown = inventory_tests.InventoryApiTests.tearDown
    run_api = inventory_tests.InventoryApiTests.run_api
    seed_version = inventory_tests.InventoryApiTests.seed_version
    set_active = inventory_tests.InventoryApiTests.set_active

    def test_validate_action_shows_the_unproven_breakout_width(self):
        version = "1700000009-abcdef12.json"
        self.seed_version("p2p", version, {
            "connections": _records(_rows("LEAF-01", TWIN + FOUR)), "warnings": []})
        self.set_active("p2p", version)

        result = self.run_api("validate", KIND="p2p")

        self.assertTrue(result.get("success"), result)
        issues = result["report"]["issues"]
        self.assertEqual([issue["kind"] for issue in issues], ["breakout-width-ambiguous"])
        self.assertEqual(issues[0]["severity"], "warning")
        self.assertIn("swp1s2", issues[0]["message"])
        self.assertIn("swp1s1", issues[0]["message"])
        self.assertEqual(result["report"]["counts"]["breakout_width_warnings"], 1)


if __name__ == "__main__":
    unittest.main()
