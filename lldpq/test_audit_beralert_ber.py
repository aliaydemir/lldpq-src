#!/usr/bin/env python3
"""Regression tests for the port set and the sample states of the BER report.

Three defects, all visible on the BER page and in its machine artifacts:

* A VLAN sub-interface (swp6.100, swp1s0.300) was accepted as a physical
  port, so one cage produced extra rows that can never carry PHY data.
* Nothing removed a port from the persisted baseline/history when it left
  the switch.  A port that was split and merged back was compared with the
  frame baseline and the PHY symbol counter of its previous instance, and
  the symbol delta was graded even across a frame-counter reset.
* An unused or down port (no packets, no errors) was counted as "awaiting a
  complete traffic sample" forever, together with the ports that really are
  still collecting one.

Every test drives the real process_ber_data_files over /proc/net/dev and
l1-show captures and reads the published artifacts.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import ber_analyzer
import process_ber_data


PROC_NET_DEV_HEADER = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|"
    "bytes    packets errs drop fifo colls carrier compressed\n"
)
ISOLATED_ENVIRONMENT = (
    "LLDPQ_ASSETS_FILE", "LLDPQ_DEVICES_FILE", "LLDPQ_COLLECTION_STATUS_FILE",
    "LLDPQ_PIPELINE_ID", "MONITOR_DATA_MAX_AGE_MINUTES",
)
HOST = "auditber-a"
BUSY = 1_000_000


def proc_net_dev(ports):
    """ports: {interface: (rx_packets, tx_packets, rx_errors, tx_errors
    [, rx_dropped])}"""
    lines = [
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0",
        "  eth0: 5000 50 0 0 0 0 0 0 5000 50 0 0 0 0 0 0",
    ]
    for name, counters in ports.items():
        rx_packets, tx_packets, rx_errors, tx_errors = counters[:4]
        rx_dropped = counters[4] if len(counters) > 4 else 0
        lines.append(
            f"{name:>6}: {rx_packets * 1000} {rx_packets} {rx_errors} "
            f"{rx_dropped} 0 0 0 0 "
            f"{tx_packets * 1000} {tx_packets} {tx_errors} 0 0 0 0 0"
        )
    return PROC_NET_DEV_HEADER + "\n".join(lines) + "\n"


def l1_show(ports):
    """ports: {interface: (raw_coef, raw_magnitude, symbol_errors)}"""
    blocks = []
    for name, (raw_coef, raw_magnitude, symbol_errors) in ports.items():
        blocks.append(
            f"Port: {name}\n"
            f"  raw_ber_coef: {raw_coef}\n"
            f"  raw_ber_magnitude: {raw_magnitude}\n"
            "  effective_ber_coef: 15\n"
            "  effective_ber_magnitude: -255\n"
            f"  phy_symbol_errors: {symbol_errors}\n"
        )
    return "".join(blocks)


class BerSiteTestCase(unittest.TestCase):
    """A throwaway result tree fed by one switch's collector files."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.results = Path(temporary.name) / "monitor-results"
        self.data = self.results / "ber-data"
        self.data.mkdir(parents=True)
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in ISOLATED_ENVIRONMENT:
            os.environ.pop(name, None)

    def collect(self, ports, l1=None, raw=None, host=HOST):
        """Publish one collection of a host and run the real analyzer."""
        counters = self.data / f"{host}_interface_errors.txt"
        counters.write_text(raw if raw is not None else proc_net_dev(ports))
        l1_file = self.data / f"{host}_l1_show.txt"
        if l1 is not None:
            l1_file.write_text(l1_show(l1))
        elif l1_file.exists():
            l1_file.unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            success = process_ber_data.process_ber_data_files(str(self.data))
        self.assertTrue(success, output.getvalue())
        return output.getvalue()

    def read_json(self, relative):
        return json.loads((self.results / relative).read_text(encoding="utf-8"))

    def rows(self):
        return {
            row["interface"]: row
            for row in self.read_json("export/ber.json")["rows"]
        }

    def page(self):
        return (self.results / "ber-analysis.html").read_text(encoding="utf-8")

    def page_metric(self, element_id):
        match = re.search(
            r'id="%s"[^>]*>\s*(\d+)' % re.escape(element_id), self.page()
        )
        self.assertIsNotNone(match, element_id)
        return int(match.group(1))

    def page_row(self, interface):
        match = re.search(
            r'<tr class="ber-row"[^>]*data-port="%s"[^>]*>.*?</tr>'
            % re.escape(f"{HOST}:{interface}"), self.page(), re.DOTALL,
        )
        self.assertIsNotNone(match, interface)
        return match.group(0)


class PhysicalPortTests(BerSiteTestCase):
    def test_only_full_swp_names_are_ports(self):
        analyzer = ber_analyzer.BERAnalyzer(str(self.results))
        verdicts = {
            name: analyzer.is_physical_port(name)
            for name in (
                "swp6", "swp1s0", "swp32s7", "swp6.100", "swp1s0.300",
                "swp6s1.300", "swp1x", "bond1", "peerlink.4094", "vlan10",
                "lo", "eth0", "mgmt", "eth1", "eth1.100", "enp3s0f0np0",
                "enp3s0.200",
            )
        }
        self.assertEqual(
            {name for name, physical in verdicts.items() if physical},
            {"swp6", "swp1s0", "swp32s7", "eth1", "enp3s0f0np0"},
        )

    def test_sub_interfaces_are_never_ber_rows(self):
        for cycle in (1, 2):
            busy = (cycle * BUSY, cycle * BUSY, 0, 0)
            self.collect({
                "swp1s0": busy, "swp1s1": busy, "swp6": busy,
                "swp6.100": busy, "swp6.200": (0, 0, 0, 0),
                "swp1s0.300": busy, "bond1": busy, "vlan10": busy,
            }, l1={"swp1s0": (1, -9, 0), "swp1s1": (1, -9, 0),
                   "swp6": (1, -9, 0)})

        self.assertEqual(sorted(self.rows()), ["swp1s0", "swp1s1", "swp6"])
        self.assertEqual(self.read_json("summary/ber-summary.json")["total_ports"], 3)
        self.assertEqual(self.page_metric("total-ports"), 3)
        self.assertNotIn("swp6.100", self.page())
        self.assertEqual(
            sorted(self.read_json("ber_baseline.json")[HOST]),
            ["swp1s0", "swp1s1", "swp6"],
        )
        self.assertEqual(
            sorted(self.read_json(f"ber-history/{HOST}.json")["current"]),
            [f"{HOST}:swp1s0", f"{HOST}:swp1s1", f"{HOST}:swp6"],
        )

    def test_state_left_by_earlier_sub_interface_rows_is_retired(self):
        self.collect({"swp6": (BUSY, BUSY, 0, 0)})
        baseline_file = self.results / "ber_baseline.json"
        baseline = json.loads(baseline_file.read_text())
        baseline[HOST]["swp6.100"] = dict(baseline[HOST]["swp6"])
        baseline_file.write_text(json.dumps(baseline))
        shard_file = self.results / "ber-history" / f"{HOST}.json"
        shard = json.loads(shard_file.read_text())
        shard["history"][f"{HOST}:swp6.100"] = list(
            shard["history"][f"{HOST}:swp6"]
        )
        shard_file.write_text(json.dumps(shard))

        self.collect({"swp6": (2 * BUSY, 2 * BUSY, 0, 0),
                      "swp6.100": (BUSY, BUSY, 0, 0)})

        self.assertEqual(list(self.read_json("ber_baseline.json")[HOST]), ["swp6"])
        self.assertEqual(
            list(self.read_json(f"ber-history/{HOST}.json")["history"]),
            [f"{HOST}:swp6"],
        )


class DepartedPortTests(BerSiteTestCase):
    def _run_split_and_merge(self, merged_packets):
        clean = (1, -9, 0)
        self.collect({"swp1": (BUSY, BUSY, 0, 0), "swp2": (BUSY, BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 500), "swp2": clean})
        self.collect({"swp1": (2 * BUSY, 2 * BUSY, 0, 0),
                      "swp2": (2 * BUSY, 2 * BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 500), "swp2": clean})
        self.assertEqual(self.rows()["swp1"]["symbol_error_delta"], 0)
        split = {f"swp1s{lane}": (10, 10, 0, 0) for lane in range(4)}
        self.collect(dict(split, swp2=(3 * BUSY, 3 * BUSY, 0, 0)),
                     l1={"swp2": clean})
        self.collect({"swp1": (merged_packets, merged_packets, 0, 0),
                      "swp2": (4 * BUSY, 4 * BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 900), "swp2": clean})

    def assert_merged_port_started_fresh(self):
        merged = self.rows()["swp1"]
        self.assertEqual(merged["sample_status"], "baseline")
        self.assertIsNone(merged["symbol_error_delta"])
        self.assertEqual(merged["status"], "UNKNOWN")
        self.assertEqual(merged["severity_reasons"], "")
        self.assertEqual(
            sorted(self.read_json("ber_baseline.json")[HOST]), ["swp1", "swp2"]
        )
        history = self.read_json(f"ber-history/{HOST}.json")["history"]
        self.assertEqual(sorted(history), [f"{HOST}:swp1", f"{HOST}:swp2"])
        self.assertEqual(len(history[f"{HOST}:swp1"]), 1)

    def test_merged_port_with_restarted_counters_starts_fresh(self):
        self._run_split_and_merge(merged_packets=5)
        self.assert_merged_port_started_fresh()

    def test_merged_port_with_higher_counters_starts_fresh(self):
        # Without pruning nothing marks this sample as a reset: the new
        # instance already carries more frames than the old baseline.
        self._run_split_and_merge(merged_packets=5 * BUSY)
        self.assert_merged_port_started_fresh()

    def test_the_fresh_port_is_graded_from_its_own_counters_afterwards(self):
        self._run_split_and_merge(merged_packets=5 * BUSY)
        self.collect({"swp1": (6 * BUSY, 6 * BUSY, 0, 0),
                      "swp2": (5 * BUSY, 5 * BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 903), "swp2": (1, -9, 0)})
        merged = self.rows()["swp1"]
        self.assertEqual(merged["sample_status"], "analyzed")
        self.assertEqual(merged["symbol_error_delta"], 3)
        self.assertEqual(merged["status"], "WARNING")

    def test_split_ports_are_removed_from_the_history_shard_once_merged(self):
        self._run_split_and_merge(merged_packets=5)
        shard = self.read_json(f"ber-history/{HOST}.json")
        self.assertFalse(
            [name for name in shard["history"] if "swp1s" in name]
        )
        self.assertFalse(
            [name for name in shard["current"] if "swp1s" in name]
        )

    def test_symbol_delta_is_not_graded_across_a_counter_reset(self):
        # The name never left the switch (split and merge between two
        # collections), so only the frame-counter reset shows the new instance.
        self.collect({"swp1": (BUSY, BUSY, 0, 0)}, l1={"swp1": (1, -9, 500)})
        self.collect({"swp1": (2 * BUSY, 2 * BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 500)})
        self.collect({"swp1": (7, 7, 0, 0)}, l1={"swp1": (1, -9, 900)})

        reset = self.rows()["swp1"]
        self.assertEqual(reset["sample_status"], "counter_reset")
        self.assertIsNone(reset["symbol_error_delta"])
        self.assertEqual(reset["status"], "UNKNOWN")
        self.assertEqual(reset["severity_reasons"], "")

        # The reset sample is the new symbol baseline: later errors count.
        self.collect({"swp1": (BUSY, BUSY, 0, 0)}, l1={"swp1": (1, -9, 905)})
        after = self.rows()["swp1"]
        self.assertEqual(after["symbol_error_delta"], 5)
        self.assertEqual(after["status"], "WARNING")

    def test_incomplete_counter_file_prunes_nothing(self):
        both = {"swp1": (BUSY, BUSY, 0, 0), "swp2": (BUSY, BUSY, 0, 0)}
        self.collect(both, l1={"swp1": (1, -9, 0), "swp2": (1, -9, 40)})
        complete = proc_net_dev({"swp1": (2 * BUSY, 2 * BUSY, 0, 0),
                                 "swp2": (2 * BUSY, 2 * BUSY, 0, 0)})
        # The capture stops in the middle of the swp2 row.
        truncated = complete[:complete.index("swp2:") + len("swp2: 2000")]
        self.assertFalse(process_ber_data.proc_net_dev_is_complete(
            truncated, process_ber_data.parse_proc_net_dev(truncated)
        ))
        self.collect(None, raw=truncated,
                     l1={"swp1": (1, -9, 0), "swp2": (1, -9, 40)})

        self.assertEqual(sorted(self.rows()), ["swp1"])
        self.assertEqual(
            sorted(self.read_json("ber_baseline.json")[HOST]), ["swp1", "swp2"]
        )
        self.assertIn(
            f"{HOST}:swp2", self.read_json(f"ber-history/{HOST}.json")["history"]
        )

        # The retained baseline and symbol counter grade the next sample.
        self.collect({"swp1": (3 * BUSY, 3 * BUSY, 0, 0),
                      "swp2": (3 * BUSY, 3 * BUSY, 0, 0)},
                     l1={"swp1": (1, -9, 0), "swp2": (1, -9, 42)})
        kept = self.rows()["swp2"]
        self.assertEqual(kept["sample_status"], "analyzed")
        self.assertEqual(kept["delta_packets"], 4 * BUSY)
        self.assertEqual(kept["symbol_error_delta"], 2)

    def test_headerless_or_marker_files_prune_nothing(self):
        both = {"swp1": (BUSY, BUSY, 0, 0), "swp2": (BUSY, BUSY, 0, 0)}
        self.collect(both)
        only_first = proc_net_dev({"swp1": (2 * BUSY, 2 * BUSY, 0, 0)})
        headerless = only_first[len(PROC_NET_DEV_HEADER):]
        self.assertFalse(process_ber_data.proc_net_dev_is_complete(
            headerless, process_ber_data.parse_proc_net_dev(headerless)
        ))
        for raw in (headerless,
                    "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS\n"):
            with self.subTest(raw=raw[:24]):
                self.collect(None, raw=raw)
                self.assertEqual(
                    sorted(self.read_json("ber_baseline.json")[HOST]),
                    ["swp1", "swp2"],
                )
        self.assertTrue(process_ber_data.proc_net_dev_is_complete(
            only_first, process_ber_data.parse_proc_net_dev(only_first)
        ))

    def test_other_hosts_keep_their_state(self):
        other = "auditber-b"
        self.collect({"swp1": (BUSY, BUSY, 0, 0)})
        self.collect({"swp9": (BUSY, BUSY, 0, 0)}, host=other)
        # Only the first host is collected again, without its old port.
        (self.data / f"{other}_interface_errors.txt").write_text(
            "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS\n"
        )
        self.collect({"swp2": (BUSY, BUSY, 0, 0)})

        baseline = self.read_json("ber_baseline.json")
        self.assertEqual(list(baseline[HOST]), ["swp2"])
        self.assertEqual(list(baseline[other]), ["swp9"])
        self.assertEqual(
            list(self.read_json(f"ber-history/{other}.json")["history"]),
            [f"{other}:swp9"],
        )

    def test_host_listing_no_port_at_all_keeps_its_baseline_and_history(self):
        self.collect({"swp1": (BUSY, BUSY, 0, 0)})
        other = "auditber-b"
        self.collect({"swp9": (BUSY, BUSY, 0, 0)}, host=other)
        # switchd stopped: the swp devices are gone, the capture is complete.
        # A listing without a single port proves nothing about the ports
        # (the flap analyzer applies the same rule), so nothing is retired.
        self.collect({}, host=other)

        self.assertEqual(list(self.read_json("ber_baseline.json")[other]),
                         ["swp9"])
        shard = self.read_json(f"ber-history/{other}.json")
        self.assertEqual(list(shard["history"]), [f"{other}:swp9"])
        self.assertEqual(shard["current"], {})


class IdlePortTests(BerSiteTestCase):
    def _collect_cycles(self, cycles=2, l1=False):
        for cycle in range(1, cycles + 1):
            self.collect({
                "swp1": (cycle * BUSY, cycle * BUSY, 0, 0),   # in service
                "swp2": (cycle * 100, cycle * 100, 0, 0),     # low traffic
                "swp3": (0, 0, 0, 0),                         # never used
                "swp4": (700, 700, 0, 0),                     # went down
            }, l1=({"swp1": (2, -10, 100), "swp2": (3, -10, 200),
                    # l1-show on a down port: no-measurement sentinel and a
                    # frozen symbol counter.
                    "swp3": (1, 0, 0), "swp4": (1, 0, 77)} if l1 else None))

    def assert_idle_ports_have_their_own_sample_state(self):
        rows = self.rows()
        self.assertEqual(rows["swp3"]["sample_status"], "idle")
        self.assertEqual(rows["swp4"]["sample_status"], "idle")
        self.assertEqual(rows["swp3"]["status"], "UNKNOWN")
        self.assertEqual(rows["swp4"]["status"], "UNKNOWN")
        self.assertEqual(rows["swp2"]["sample_status"], "insufficient_traffic")
        current = self.read_json(f"ber-history/{HOST}.json")["current"]
        self.assertEqual(current[f"{HOST}:swp3"]["sample_status"], "idle")
        self.assertEqual(current[f"{HOST}:swp4"]["sample_status"], "idle")

    def test_unused_and_down_ports_get_their_own_sample_state(self):
        self._collect_cycles()
        self.assert_idle_ports_have_their_own_sample_state()

    def test_down_port_with_frozen_l1_snapshot_is_idle(self):
        self._collect_cycles(l1=True)
        self.assert_idle_ports_have_their_own_sample_state()
        self.assertIsNone(self.rows()["swp3"]["raw_ber"])

    def test_summary_json_splits_idle_from_the_ungraded_total(self):
        self._collect_cycles()
        summary = self.read_json("summary/ber-summary.json")
        self.assertEqual(summary["unknown"], 3)
        self.assertEqual(summary["idle"], 2)
        # The dashboard requires the five grades to add up to the total.
        self.assertEqual(
            summary["excellent"] + summary["good"] + summary["warning"]
            + summary["critical"] + summary["unknown"],
            summary["total_ports"],
        )
        self.assertEqual(self.read_json("export/ber.json")["counts"]["idle"], 2)

    def test_page_words_idle_ports_separately(self):
        self._collect_cycles()
        output = self.collect({
            "swp1": (3 * BUSY, 3 * BUSY, 0, 0), "swp2": (300, 300, 0, 0),
            "swp3": (0, 0, 0, 0), "swp4": (700, 700, 0, 0),
        })
        page = self.page()
        self.assertEqual(self.page_metric("unknown-ports"), 3)
        self.assertEqual(self.page_metric("awaiting-ports"), 1)
        self.assertEqual(self.page_metric("idle-ports"), 2)
        self.assertIn(
            'data-ber-idle="2"', re.search(r"<body[^>]*>", page).group(0)
        )
        # The card counts both kinds, so it cannot be titled after one.
        self.assertIn('<div class="metric-label">Not Graded</div>', page)
        self.assertNotIn("Awaiting Sample", page)

        idle_row = self.page_row("swp3")
        self.assertIn('data-status="unknown"', idle_row)
        self.assertIn('data-idle="1"', idle_row)
        self.assertIn(">IDLE</span>", idle_row)
        self.assertNotIn(">UNKNOWN</span>", idle_row)
        awaiting_row = self.page_row("swp2")
        self.assertNotIn("data-idle", awaiting_row)
        self.assertIn(">UNKNOWN</span>", awaiting_row)

        self.assertIn("Awaiting a complete sample: 1", output)
        self.assertIn("Idle (no traffic, no errors): 2", output)

    def test_first_sample_is_awaiting_not_idle(self):
        self._collect_cycles(cycles=1)
        self.assertEqual(
            {row["sample_status"] for row in self.rows().values()}, {"baseline"}
        )
        self.assertEqual(self.read_json("summary/ber-summary.json")["idle"], 0)
        self.assertEqual(self.page_metric("awaiting-ports"), 4)

    def test_errors_without_traffic_are_not_idle(self):
        self.collect({"swp5": (0, 0, 0, 0), "swp6": (0, 0, 0, 0)})
        self.collect({"swp5": (0, 0, 3, 0), "swp6": (0, 0, 0, 0)})
        rows = self.rows()
        self.assertEqual(rows["swp5"]["sample_status"], "insufficient_traffic")
        self.assertEqual(rows["swp6"]["sample_status"], "idle")
        self.assertEqual(self.read_json("summary/ber-summary.json")["idle"], 1)

    def test_drops_without_traffic_are_not_idle(self):
        self.collect({"swp5": (0, 0, 0, 0, 0), "swp6": (0, 0, 0, 0, 0)})
        self.collect({"swp5": (0, 0, 0, 0, 9), "swp6": (0, 0, 0, 0, 0)})
        rows = self.rows()
        self.assertEqual(rows["swp5"]["delta_rx_dropped"], 9)
        self.assertEqual(rows["swp5"]["sample_status"], "insufficient_traffic")
        self.assertEqual(rows["swp6"]["sample_status"], "idle")

    def test_quiet_port_with_a_live_phy_is_graded_not_idle(self):
        # No L2 traffic, but the FEC symbol counter advances: the link is up.
        self.collect({"swp7": (0, 0, 0, 0)}, l1={"swp7": (1, -9, 10)})
        self.collect({"swp7": (0, 0, 0, 0)}, l1={"swp7": (1, -9, 12)})
        live = self.rows()["swp7"]
        self.assertEqual(live["sample_status"], "insufficient_traffic")
        self.assertEqual(live["status"], "WARNING")
        self.assertEqual(self.read_json("summary/ber-summary.json")["idle"], 0)


if __name__ == "__main__":
    unittest.main()
