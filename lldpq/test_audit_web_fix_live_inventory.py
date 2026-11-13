#!/usr/bin/env python3
"""Every reader of the P2P design fits breakout ports to the live switch.

A three-part design port ('1/2/1') becomes a sub-port name with a width per
port, and only the interfaces a switch reports can tell a 2x port from two
legs of a 4x port.  The LLDP stage publishes those interfaces in the 'ports'
section of lldp-results/lldp_neighbors.json.  Covered here, each through the
real code of its call site:

  - html/inventory-api.sh  generate-topology and validate (Inventory page),
  - html/fabric-api.sh     get_p2p_enrichment (Fabric Migration design join),
  - html/ai-api.sh         _p2p_precise_entry and _build_analysis_v2 (Ask-AI),
  - lldpq/lldp_export.py   build_csv (headless LLDP CSV).

A missing, unreadable or stale neighbour file must give exactly what the
site gives without one.  The sidecar is written by the real lldp-validate.py.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "html"))
sys.path.insert(0, str(ROOT / "lldpq"))

import ai_p2p  # noqa: E402
import lldp_export  # noqa: E402
import test_inventory_api as inventory_tests  # noqa: E402  (CGI heredoc harness)
from lldp_report import parse_lldp_report  # noqa: E402


def _load_lldp_validate():
    spec = importlib.util.spec_from_file_location(
        "audit_web_fix_lldp_validate", ROOT / "lldpq" / "lldp-validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LLDP_VALIDATE = _load_lldp_validate()

# LEAF-01: swp1 is a twin-port 2x split (one leg per spine), swp33 a 4x split
# written as two groups of two, swp5 is not split.  Design rows alone map
# 1/2/1 with the width of port 33 (swp1s2) and 5/1/1 to swp5s0.
DESIGN_ROWS = [
    ["LEAF-01", "1/1/1", "SPINE-01", "swp1s0"],
    ["LEAF-01", "1/2/1", "SPINE-02", "swp1s0"],
    ["LEAF-01", "33/1/1", "SPINE-03", "swp1"],
    ["LEAF-01", "33/1/2", "SPINE-03", "swp2"],
    ["LEAF-01", "33/2/1", "SPINE-03", "swp3"],
    ["LEAF-01", "33/2/2", "SPINE-03", "swp4"],
    ["LEAF-01", "5/1/1", "SPINE-04", "swp5"],
]
LIVE_PORTS = {
    "LEAF-01": ["swp1s0", "swp1s1", "swp33s0", "swp33s1", "swp33s2", "swp33s3",
                "swp5", "swp6"],
    "SPINE-01": ["swp1s0"], "SPINE-02": ["swp1s0"],
    "SPINE-03": ["swp1", "swp2", "swp3", "swp4"], "SPINE-04": ["swp5"],
}


def design(rows=DESIGN_ROWS, leaf="LEAF-01"):
    return {"connections": [
        {"source_name": leaf if a == "LEAF-01" else a, "source_port": ap,
         "dest_name": b, "dest_port": bp, "connection_type": "compute",
         "network_type": "eth", "sheet_name": "P2P", "row_number": index + 2,
         "seq": str(100 + index), "unresolved": False}
        for index, (a, ap, b, bp) in enumerate(rows)], "warnings": []}


def write_sidecar(lldpq_dir, live=LIVE_PORTS, age=0.0):
    """lldp-results/lldp_neighbors.json as the LLDP stage wrote it `age` seconds ago."""
    directory = Path(lldpq_dir) / "lldp-results"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "lldp_neighbors.json"
    stamp = time.time() - age
    LLDP_VALIDATE.write_neighbors_sidecar(
        str(path), {}, None,
        time.strftime("%Y-%m-%d %H-%M-%S", time.localtime(stamp)),
        {device: {port: "UP" for port in ports} for device, ports in live.items()},
        {})
    os.utime(path, (stamp, stamp))
    return path


# name -> how to leave the neighbour file in a state that must not be used.
def _missing(lldpq_dir):
    return None


def _stale(lldpq_dir):
    # Three hours past the limit: the stamp is local wall-clock time and may
    # read an hour off across a DST change.
    return write_sidecar(lldpq_dir, age=ai_p2p.LIVE_PORTS_MAX_AGE_SEC + 3 * 3600)


def _truncated(lldpq_dir):
    path = write_sidecar(lldpq_dir)
    path.write_text(path.read_text(encoding="utf-8")[:40], encoding="utf-8")
    return path


def _no_ports(lldpq_dir):
    path = write_sidecar(lldpq_dir)
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["ports"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _not_a_file(lldpq_dir):
    path = Path(lldpq_dir) / "lldp-results" / "lldp_neighbors.json"
    path.mkdir(parents=True)
    return path


UNUSABLE = (("missing", _missing), ("stale", _stale), ("truncated", _truncated),
            ("without ports", _no_ports), ("not a file", _not_a_file))


class LoadLivePortsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def write(self, payload, mtime=None):
        path = self.root / "lldp_neighbors.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path

    def test_fresh_sidecar_gives_its_ports_section(self):
        path = write_sidecar(self.root)
        ports = ai_p2p.load_live_ports(path)
        self.assertEqual(sorted(ports), sorted(LIVE_PORTS))
        self.assertEqual(sorted(ports["LEAF-01"]), sorted(LIVE_PORTS["LEAF-01"]))

    def test_display_alias_reaches_the_ports_of_the_switch_it_names(self):
        path = write_sidecar(self.root)
        ports = ai_p2p.load_live_ports(path, {"leaf a1": "leaf-01", "ghost": "nowhere"})
        self.assertEqual(sorted(ports["leaf a1"]), sorted(LIVE_PORTS["LEAF-01"]))
        self.assertNotIn("ghost", ports)

    def test_unusable_files_give_none(self):
        for name, spoil in UNUSABLE:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                spoil(tmp)
                self.assertIsNone(ai_p2p.load_live_ports(
                    Path(tmp) / "lldp-results" / "lldp_neighbors.json"))
        for label, payload in (("ports is a list", {"ports": ["swp1"]}),
                               ("ports is empty", {"ports": {}}),
                               ("top level is a list", [1, 2])):
            with self.subTest(label):
                self.assertIsNone(ai_p2p.load_live_ports(self.write(payload)))

    def test_age_is_taken_from_the_created_stamp(self):
        now = 1_800_000_000.0
        stamp = lambda seconds: time.strftime(  # noqa: E731
            "%Y-%m-%d %H-%M-%S", time.localtime(seconds))
        ports = {"leaf-01": {"swp1": {"oper": "UP"}}}
        limit = ai_p2p.LIVE_PORTS_MAX_AGE_SEC
        ahead = ai_p2p.LIVE_PORTS_MAX_AHEAD_SEC
        for label, created, mtime, usable in (
            ("just written", stamp(now - 60), now - 60, True),
            ("a day minus a minute old", stamp(now - limit + 60), now, True),
            ("older than a day, file touched since", stamp(now - limit - 60), now, False),
            ("an hour ahead (DST)", stamp(now + 3600), now, True),
            ("no stamp, fresh file", None, now - 60, True),
            ("no stamp, old file", None, now - limit - 60, False),
            ("unreadable stamp, old file", "yesterday", now - limit - 60, False),
            ("stamp far ahead, fresh file", stamp(now + ahead + 3600), now - 60, True),
            ("stamp far ahead, old file", stamp(now + ahead + 3600), now - limit - 60, False),
        ):
            with self.subTest(label):
                payload = {"version": 1, "ports": ports}
                if created is not None:
                    payload["created"] = created
                got = ai_p2p.load_live_ports(self.write(payload, mtime), now=now)
                self.assertEqual(got, ports if usable else None)


class InventoryPageTests(unittest.TestCase):
    """Inventory -> Generate topology.dot / Validate, through the CGI heredoc."""

    @classmethod
    def setUpClass(cls):
        cls.block = inventory_tests.extract_heredoc(
            inventory_tests.INVENTORY_API.read_text(encoding="utf-8"), "PYTHON_END")

    setUp = inventory_tests.InventoryApiTests.setUp
    tearDown = inventory_tests.InventoryApiTests.tearDown
    run_api = inventory_tests.InventoryApiTests.run_api
    seed_version = inventory_tests.InventoryApiTests.seed_version
    set_active = inventory_tests.InventoryApiTests.set_active

    def activate(self, data):
        version = "1700000009-abcdef12.json"
        self.seed_version("p2p", version, data)
        self.set_active("p2p", version)

    def preview(self):
        result = self.run_api("generate-topology", QS_SCOPE="full")
        self.assertTrue(result.get("success"), result)
        return result["preview"]

    def validate(self):
        result = self.run_api("validate", KIND="p2p")
        self.assertTrue(result.get("success"), result)
        return result["report"]

    def test_generated_topology_names_the_sub_ports_the_switch_has(self):
        self.activate(design())
        without = self.preview()
        self.assertIn('"LEAF-01":"swp1s2" -- "SPINE-02":"swp1s0"', without)
        self.assertIn('"LEAF-01":"swp5s0" -- "SPINE-04":"swp5"', without)

        write_sidecar(self.root)  # LLDPQ_DIR of the harness
        fitted = self.preview()
        self.assertIn('"LEAF-01":"swp1s1" -- "SPINE-02":"swp1s0"', fitted)
        self.assertIn('"LEAF-01":"swp5" -- "SPINE-04":"swp5"', fitted)
        self.assertNotIn("swp1s2", fitted)
        self.assertNotIn("swp5s0", fitted)
        # Nothing else moved.
        self.assertEqual(
            fitted,
            without.replace('"LEAF-01":"swp1s2"', '"LEAF-01":"swp1s1"')
                   .replace('"LEAF-01":"swp5s0"', '"LEAF-01":"swp5"'))

    def test_validate_judges_the_names_generation_will_write(self):
        self.activate(design())
        without = self.validate()
        self.assertEqual([issue["kind"] for issue in without["issues"]],
                         ["breakout-width-ambiguous"])

        write_sidecar(self.root)
        report = self.validate()
        self.assertEqual([issue["kind"] for issue in report["issues"]],
                         ["breakout-mixed-width"])
        self.assertIn("port 1 has 1", report["issues"][0]["message"])
        self.assertIn("port 33 has 2", report["issues"][0]["message"])

    def test_design_label_reaches_its_switch_through_the_display_alias(self):
        self.activate(design(leaf="LEAF A1"))
        (self.web_root / "display-aliases.json").write_text(
            json.dumps({"devices": {"LEAF-01": "LEAF A1"}}), encoding="utf-8")
        write_sidecar(self.root)
        fitted = self.preview()
        self.assertIn('"LEAF-01":"swp1s1" -- "SPINE-02":"swp1s0"', fitted)
        self.assertIn('"LEAF-01":"swp5" -- "SPINE-04":"swp5"', fitted)
        report = self.validate()
        self.assertEqual([issue["kind"] for issue in report["issues"]],
                         ["breakout-mixed-width"])
        self.assertEqual(report["issues"][0]["device"], "LEAF A1")

    def test_unusable_neighbour_file_changes_nothing(self):
        self.activate(design())
        baseline = (self.preview(), self.validate())
        for name, spoil in UNUSABLE:
            with self.subTest(name):
                shutil.rmtree(self.root / "lldp-results", ignore_errors=True)
                spoil(self.root)
                self.assertEqual((self.preview(), self.validate()), baseline)


def _shell_function_python(script, function, marker="PYTHON"):
    """The Python heredoc of one shell function of a CGI script."""
    text = (ROOT / "html" / script).read_text(encoding="utf-8")
    body = text[text.index("\n%s() {" % function):]
    opener = "python3 << '%s'\n" % marker
    start = body.index(opener) + len(opener)
    return body[start:body.index("\n%s\n" % marker, start) + 1]


class FabricMigrationJoinTests(unittest.TestCase):
    """fabric-api.sh get_p2p_enrichment: the exact-alias design join."""

    @classmethod
    def setUpClass(cls):
        cls.block = _shell_function_python("fabric-api.sh", "get_p2p_enrichment")
        compile(cls.block, "fabric-api.sh:get_p2p_enrichment", "exec")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.lldpq = self.root / "lldpq"
        self.web = self.root / "web"
        (self.web / "monitor-results").mkdir(parents=True)
        self.lldpq.mkdir()
        self.conf = self.root / "lldpq.conf"
        self.conf.write_text("LLDPQ_DIR=%s\n" % self.lldpq, encoding="utf-8")
        # The function reads /etc/lldpq.conf by its fixed path; only that
        # open() is pointed at the scratch configuration.
        self.script = self.root / "enrichment.py"
        self.script.write_text(
            "import builtins\n_open = builtins.open\n"
            "def _redirect(path, *args, **kwargs):\n"
            "    if path == '/etc/lldpq.conf':\n"
            "        path = %r\n"
            "    return _open(path, *args, **kwargs)\n"
            "builtins.open = _redirect\n" % str(self.conf) + self.block,
            encoding="utf-8")

    def publish(self, data):
        (self.web / "monitor-results" / "active-p2p.json").write_text(
            json.dumps(data), encoding="utf-8")

    def join(self, *devices):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "POST_DATA": json.dumps({"devices": list(devices)}),
               "WEB_ROOT_DIR": str(self.web),
               "PYTHONPATH": str(ROOT / "html"), "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run([sys.executable, str(self.script)], env=env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result.get("success"), result)
        return result["devices"]

    @staticmethod
    def ports(entries):
        return {entry["port"]: (entry["os_port"], entry["aliases"]) for entry in entries}

    def test_join_ships_the_sub_ports_the_switch_has(self):
        self.publish(design())
        without = self.ports(self.join("LEAF-01")["LEAF-01"])
        self.assertEqual(without["1/2/1"], ("swp1s2", ["1/2/1", "swp1s2"]))
        self.assertEqual(without["5/1/1"], ("swp5s0", ["5/1/1", "swp5s0"]))

        write_sidecar(self.lldpq)
        fitted = self.ports(self.join("LEAF-01")["LEAF-01"])
        self.assertEqual(fitted["1/2/1"], ("swp1s1", ["1/2/1", "swp1s1"]))
        self.assertEqual(fitted["5/1/1"], ("swp5", ["5/1/1", "swp5"]))
        for port in ("1/1/1", "33/1/1", "33/1/2", "33/2/1", "33/2/2"):
            self.assertEqual(fitted[port], without[port])

    def test_design_label_reaches_its_switch_through_the_display_alias(self):
        self.publish(design(leaf="LEAF A1"))
        (self.web / "display-aliases.json").write_text(
            json.dumps({"devices": {"LEAF-01": "LEAF A1"}}), encoding="utf-8")
        write_sidecar(self.lldpq)
        fitted = self.ports(self.join("LEAF-01")["LEAF-01"])
        self.assertEqual(fitted["1/2/1"][0], "swp1s1")
        self.assertEqual(fitted["5/1/1"][0], "swp5")

    def test_unusable_neighbour_file_changes_nothing(self):
        self.publish(design())
        baseline = self.join("LEAF-01", "SPINE-02")
        self.assertEqual(self.ports(baseline["LEAF-01"])["1/2/1"][0], "swp1s2")
        for name, spoil in UNUSABLE:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                spoil(tmp)
                self.conf.write_text("LLDPQ_DIR=%s\n" % tmp, encoding="utf-8")
                self.assertEqual(self.join("LEAF-01", "SPINE-02"), baseline)


class _FakeCorrelate:
    """ai_correlate stand-in that records the expected links it is given."""

    def __init__(self):
        self.links = None

    def collect_anomalies(self, mr_dir):
        return []

    def load_expected_links(self, mr_dir=None):
        return []

    def correlate(self, anomalies, links, devices):
        self.links = links
        return []


def _ask_ai_namespace(lldpq_dir, web_root, conns):
    """The Ask-AI CGI functions that read the design, bound to scratch paths."""
    text = (ROOT / "html" / "ai-api.sh").read_text(encoding="utf-8")
    marker = "python3 << 'PYTHON_SCRIPT'"
    source = text[text.index(marker) + len(marker):text.rindex("\nPYTHON_SCRIPT")]
    wanted = {"_p2p_live_ports", "_p2p_precise_entry", "_build_analysis_v2"}
    nodes = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            nodes.append(node)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
              and getattr(node.targets[0], "id", "") == "_P2P_INDEX_MEMO"):
            nodes.append(node)
    assert {getattr(node, "name", "_P2P_INDEX_MEMO") for node in nodes} == wanted | {"_P2P_INDEX_MEMO"}
    correlate = _FakeCorrelate()
    namespace = {
        "os": os, "json": json, "LLDPQ_DIR": str(lldpq_dir), "WEB_ROOT": str(web_root),
        "_p2p_module": ai_p2p, "_correlate_module": correlate,
        "_v2_active_design": lambda: (conns, None, "design"),
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "ai-api.sh", "exec"), namespace)
    return namespace, correlate


class AskAiTests(unittest.TestCase):
    """ai-api.sh: precise design lookup and the incident link keys."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.lldpq = self.root / "lldpq"
        self.web = self.root / "web"
        self.lldpq.mkdir()
        self.web.mkdir()

    def ask(self, data=None):
        conns = ai_p2p.load_connections(data or design())
        namespace, correlate = _ask_ai_namespace(self.lldpq, self.web, conns)
        return conns, namespace, correlate

    def peer_of(self, port, data=None):
        conns, namespace, _correlate = self.ask(data)
        entry = namespace["_p2p_precise_entry"](conns, "LEAF-01", port)
        return (entry["port"], entry["peer_device"]) if entry else None

    def link_keys(self, data=None):
        _conns, namespace, correlate = self.ask(data)
        namespace["_build_analysis_v2"](str(self.web), ["LEAF-01"], None, None)
        return sorted((link["a_dev"], link["a_port"], link["b_dev"], link["b_port"])
                      for link in correlate.links)

    def test_precise_lookup_answers_for_the_sub_port_the_switch_has(self):
        # Without the inventory the fitted name of 1/2/1 is swp1s2.
        self.assertEqual(self.peer_of("swp1s2"), ("1/2/1", "SPINE-02"))
        self.assertIsNone(self.peer_of("swp6"))
        write_sidecar(self.lldpq)
        self.assertEqual(self.peer_of("swp1s1"), ("1/2/1", "SPINE-02"))
        self.assertEqual(self.peer_of("swp5"), ("5/1/1", "SPINE-04"))
        # The name the design alone gave is no longer a port of this row.
        self.assertIsNone(self.peer_of("swp1s2"))

    def test_incident_links_are_keyed_by_the_sub_port_the_switch_has(self):
        without = self.link_keys()
        self.assertIn(("LEAF-01", "swp1s2", "SPINE-02", "swp1s0"), without)
        self.assertIn(("LEAF-01", "swp5s0", "SPINE-04", "swp5"), without)
        write_sidecar(self.lldpq)
        fitted = self.link_keys()
        self.assertIn(("LEAF-01", "swp1s1", "SPINE-02", "swp1s0"), fitted)
        self.assertIn(("LEAF-01", "swp5", "SPINE-04", "swp5"), fitted)
        self.assertEqual(len(fitted), len(without))
        self.assertNotIn("swp1s2", [key[1] for key in fitted])

    def test_design_label_reaches_its_switch_through_the_display_alias(self):
        (self.web / "display-aliases.json").write_text(
            json.dumps({"devices": {"LEAF-01": "LEAF A1"}}), encoding="utf-8")
        write_sidecar(self.lldpq)
        self.assertIn(("LEAF A1", "swp1s1", "SPINE-02", "swp1s0"),
                      self.link_keys(design(leaf="LEAF A1")))

    def test_unusable_neighbour_file_changes_nothing(self):
        baseline = (self.link_keys(), self.peer_of("swp1s2"), self.peer_of("swp1s1"))
        self.assertEqual(baseline[1], ("1/2/1", "SPINE-02"))
        for name, spoil in UNUSABLE:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                spoil(tmp)
                self.lldpq = Path(tmp)
                self.assertEqual(
                    (self.link_keys(), self.peer_of("swp1s2"), self.peer_of("swp1s1")),
                    baseline)

    def test_an_older_design_module_keeps_working(self):
        # ai_p2p.py is deployed separately: one without the loader must still
        # resolve the design, with the names the design alone gives.
        write_sidecar(self.lldpq)
        conns, namespace, correlate = self.ask()
        old = type("OldP2P", (), {
            "expected_links": staticmethod(ai_p2p.expected_links),
            "resolve_port_map": staticmethod(lambda conns: ai_p2p.resolve_port_map(conns)),
            "resolved_os_port": staticmethod(ai_p2p.resolved_os_port),
            "build_port_index": staticmethod(lambda conns: ai_p2p.build_port_index(conns)),
            "lookup_by_device_port": staticmethod(ai_p2p.lookup_by_device_port),
        })
        namespace["_p2p_module"] = old
        namespace["_build_analysis_v2"](str(self.web), ["LEAF-01"], None, None)
        self.assertIn(("LEAF-01", "swp1s2", "SPINE-02", "swp1s0"),
                      [(link["a_dev"], link["a_port"], link["b_dev"], link["b_port"])
                       for link in correlate.links])
        entry = namespace["_p2p_precise_entry"](conns, "LEAF-01", "swp1s2")
        self.assertEqual(entry["peer_device"], "SPINE-02")


# LEAF-01 swp1 is a 4x split written as two groups of two; another port has
# rows reaching sub 3, so the design alone maps port 1 with three per group:
# 1/2/1 -> swp1s3 and 1/2/2 -> swp1s4, although the switch has swp1s0..s3.
WIDE_ROWS = [
    ["LEAF-01", "1/1/1", "SPINE-01", "swp1"],
    ["LEAF-01", "1/1/2", "SPINE-02", "swp1"],
    ["LEAF-01", "1/2/1", "SPINE-03", "swp1"],
    ["LEAF-01", "1/2/2", "SPINE-04", "swp1"],
    ["LEAF-01", "9/1/3", "SPINE-05", "swp1"],
]
WIDE_LIVE = {"LEAF-01": ["swp1s%d" % index for index in range(4)]
             + ["swp9s%d" % index for index in range(4)]}
REPORT = """Created on 2026-08-19 10-00-00
========== LEAF-01 ==========
Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status
----------
swp1s0 Pass SPINE-01 swp1 SPINE-01 swp1 UP
swp1s1 Pass SPINE-02 swp1 SPINE-02 swp1 UP
swp1s2 Pass SPINE-03 swp1 SPINE-03 swp1 UP
swp1s3 Pass SPINE-04 swp1 SPINE-04 swp1 UP
"""


class HeadlessCsvTests(unittest.TestCase):
    """lldp_export.build_csv: the P2P Sheet / Line / SEQ columns."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.lldpq = Path(self._tmp.name)
        self.report = parse_lldp_report(REPORT)

    def p2p_lines(self, lldpq_dir=None):
        sidecar = Path(lldpq_dir or self.lldpq) / "lldp-results" / "lldp_neighbors.json"
        with mock.patch.object(lldp_export, "NEIGHBORS_FILE", sidecar):
            text = lldp_export.build_csv(self.report, p2p_design=design(WIDE_ROWS))
        rows = [line.split(",") for line in text.splitlines()[1:]]
        return {row[3]: row[16] for row in rows}

    def test_sidecar_is_looked_up_next_to_the_module(self):
        # check-lldp.sh publishes it as $LLDPQ_DIR/lldp-results/lldp_neighbors.json.
        self.assertEqual(
            lldp_export.NEIGHBORS_FILE,
            Path(lldp_export.__file__).resolve().parent / "lldp-results" / "lldp_neighbors.json")

    def test_rows_carry_the_design_line_of_the_sub_port_the_switch_has(self):
        # Design lines: 1/1/1 = 2, 1/1/2 = 3, 1/2/1 = 4, 1/2/2 = 5.  The design
        # alone puts line 4 on swp1s3, which is the port of line 5.
        without = self.p2p_lines()
        self.assertEqual((without["swp1s0"], without["swp1s1"]), ("2", "3"))
        self.assertEqual(without["swp1s3"], "4")
        write_sidecar(self.lldpq, WIDE_LIVE)
        self.assertEqual(self.p2p_lines(),
                         {"swp1s0": "2", "swp1s1": "3", "swp1s2": "4", "swp1s3": "5"})

    def test_unusable_neighbour_file_changes_nothing(self):
        baseline = self.p2p_lines()
        self.assertEqual(baseline["swp1s3"], "4")
        for name, spoil in UNUSABLE:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                spoil(tmp)
                self.assertEqual(self.p2p_lines(tmp), baseline)

    def test_report_without_a_design_does_not_read_the_sidecar(self):
        with mock.patch.object(lldp_export, "_live_ports",
                               side_effect=AssertionError("sidecar read")):
            lldp_export.build_csv(self.report)


if __name__ == "__main__":
    unittest.main()
