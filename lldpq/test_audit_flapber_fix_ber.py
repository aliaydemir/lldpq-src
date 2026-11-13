#!/usr/bin/env python3
"""BER: idle ports after a partial sample, captures without ports, and what
the alerts say about ungraded ports.

* A port that went down after fewer packets than one sample needs kept its
  deltas against the retained baseline for good, so it was "awaiting a
  complete traffic sample" forever: the summary line stayed and, in immediate
  mode, the switch never left "BER Warning". Idle is now decided against the
  previous collection.
* A complete capture that lists no physical port at all (switchd stopped)
  erased the host's whole baseline and 24 h of history, and a run that failed
  for lack of any port had already saved the pruned baseline.
* Ports awaiting a sample made the summary a WARNING although their count is
  not part of the change signature, so the healthy summary never followed.
* "BER Recovered ... is healthy" was sent when the faulty port had only gone
  quiet.

The BER tests drive the real process_ber_data_files; the alert tests read
its report and history shard through the real LLDPqAlerts.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import time
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_ber_data  # noqa: E402
from test_audit_beralert_alerts import AlertSiteTestCase  # noqa: E402
from test_audit_beralert_alerts import HOST as ALERT_HOST  # noqa: E402
from test_audit_beralert_ber import (  # noqa: E402
    BUSY, HOST, PROC_NET_DEV_HEADER, BerSiteTestCase, proc_net_dev,
)


def counters_file(ports):
    """ports: {interface: {counter: value}} with the /proc/net/dev counters
    rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped."""
    lines = [
        "    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0",
        "  eth0: 5000 50 0 0 0 0 0 0 5000 50 0 0 0 0 0 0",
    ]
    for name, counters in ports.items():
        get = lambda key: counters.get(key, 0)  # noqa: E731
        lines.append(
            f"{name:>6}: {get('rx_packets') * 1000} {get('rx_packets')} "
            f"{get('rx_errors')} {get('rx_dropped')} 0 0 0 0 "
            f"{get('tx_packets') * 1000} {get('tx_packets')} "
            f"{get('tx_errors')} {get('tx_dropped')} 0 0 0 0"
        )
    return PROC_NET_DEV_HEADER + "\n".join(lines) + "\n"


class StoppedPartialSampleTests(BerSiteTestCase):
    """A port whose counters stop moving in the middle of a sample."""

    def collect_port(self, cycle, port="swp2", l1=None, **counters):
        """One collection: swp1 in service, *port* with the given counters
        and, with *l1*, its l1-show record (raw_coef, raw_magnitude, symbol
        errors)."""
        return self.collect(None, raw=counters_file({
            "swp1": {"rx_packets": cycle * BUSY, "tx_packets": cycle * BUSY},
            port: counters,
        }), l1=None if l1 is None else {"swp1": (1, -9, 0), port: l1})

    def sample(self, port="swp2"):
        row = self.rows()[port]
        return row["sample_status"], row["delta_packets"]

    def test_port_that_stops_after_a_few_packets_becomes_idle(self):
        observed = []
        # 400 packets after the baseline, then the link goes down.
        for cycle, packets in enumerate((700, 900, 900, 900), start=1):
            self.collect_port(cycle, rx_packets=packets, tx_packets=packets)
            observed.append(self.sample())
        self.assertEqual(observed, [
            ("baseline", 0),
            ("insufficient_traffic", 400),
            ("idle", 400),
            ("idle", 400),
        ])
        row = self.rows()["swp2"]
        self.assertEqual(row["status"], "UNKNOWN")
        summary = self.read_json("summary/ber-summary.json")
        self.assertEqual((summary["unknown"], summary["idle"]), (1, 1))
        self.assertEqual(self.page_metric("awaiting-ports"), 0)
        self.assertEqual(self.page_metric("idle-ports"), 1)
        current = self.read_json(f"ber-history/{HOST}.json")["current"]
        self.assertEqual(current[f"{HOST}:swp2"]["sample_status"], "idle")

    def test_idle_row_reads_no_traffic(self):
        for cycle, packets in enumerate((700, 900, 900), start=1):
            self.collect_port(cycle, rx_packets=packets, tx_packets=packets)
        page_row = self.page_row("swp2")
        self.assertIn('data-idle="1"', page_row)
        self.assertIn(">IDLE</span>", page_row)
        cells = [
            re.sub(r"<[^>]+>", "", cell).strip()
            for cell in re.findall(r"<td[^>]*>(.*?)</td>", page_row, re.DOTALL)
        ]
        self.assertIn("No traffic", cells)
        # Neither the progress of the abandoned sample nor a bare N/A.
        self.assertNotIn("400/1,000", page_row)

    def test_traffic_returning_ends_the_idle_state(self):
        observed = []
        for cycle, packets in enumerate((700, 900, 900, 950, 950, 1400, 1400),
                                        start=1):
            self.collect_port(cycle, rx_packets=packets, tx_packets=packets)
            observed.append(self.sample())
        self.assertEqual(observed, [
            ("baseline", 0),
            ("insufficient_traffic", 400),
            ("idle", 400),
            ("insufficient_traffic", 500),   # the link is back
            ("idle", 500),
            ("analyzed", 1400),              # the sample completed
            ("idle", 0),
        ])

    def test_errors_or_drops_on_a_stopped_port_are_not_idle(self):
        stopped = {"rx_packets": 900, "tx_packets": 900}
        cycles = iter(range(1, 100))
        counters = ("rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
        # A port of its own per counter, so every case starts from a baseline.
        for port, counter in zip(("swp2", "swp3", "swp4", "swp5"), counters):
            with self.subTest(counter=counter):
                self.collect_port(next(cycles), port,
                                  rx_packets=700, tx_packets=700)
                self.collect_port(next(cycles), port, **stopped)
                self.collect_port(next(cycles), port, **stopped)
                self.assertEqual(self.sample(port), ("idle", 400))
                # The frame counters still stand, but something moved.
                moved = dict(stopped, **{counter: 1})
                self.collect_port(next(cycles), port, **moved)
                self.assertEqual(self.sample(port),
                                 ("insufficient_traffic", 400))
                # ... and with nothing new in the next collection it is idle.
                self.collect_port(next(cycles), port, **moved)
                self.assertEqual(self.sample(port), ("idle", 400))

    def test_stale_l1_snapshot_of_a_stopped_port_is_not_graded(self):
        # l1-show keeps answering for a port that went down: the
        # no-measurement sentinel, or simply its last reading. With the
        # deltas of the abandoned sample still above zero, that snapshot was
        # graded on every run (a stale 1e-3 as CRITICAL, for good).
        snapshots = {
            "no-measurement sentinel": ("swp2", (1, 0, 42), "GOOD"),
            "last reading before the link died": ("swp3", (1, -3, 42),
                                                  "CRITICAL"),
        }
        cycles = iter(range(1, 100))
        for label, (port, l1, while_active) in snapshots.items():
            with self.subTest(label):
                self.collect_port(next(cycles), port, l1,
                                  rx_packets=700, tx_packets=700)
                # Packets moved in this interval: the reading is live.
                self.collect_port(next(cycles), port, l1,
                                  rx_packets=900, tx_packets=900)
                self.assertEqual(self.rows()[port]["status"], while_active)
                for _stopped in range(2):
                    self.collect_port(next(cycles), port, l1,
                                      rx_packets=900, tx_packets=900)
                    row = self.rows()[port]
                    self.assertEqual(
                        (row["status"], row["sample_status"],
                         row["severity_reasons"]),
                        ("UNKNOWN", "idle", ""),
                    )

    def test_live_phy_on_a_stopped_partial_sample_is_still_graded(self):
        # No frames since the previous collection, but the FEC symbol
        # counter advances: the link is up and its L1 data is current.
        for cycle, symbols in enumerate((42, 42, 44, 47), start=1):
            packets = 700 if cycle == 1 else 900
            self.collect_port(cycle, l1=(1, -9, symbols),
                              rx_packets=packets, tx_packets=packets)
        row = self.rows()["swp2"]
        self.assertEqual(row["sample_status"], "insufficient_traffic")
        self.assertEqual(row["symbol_error_delta"], 3)
        self.assertEqual(row["status"], "WARNING")
        self.assertEqual(self.read_json("summary/ber-summary.json")["idle"], 0)

    def test_transmit_drops_alone_keep_an_unused_port_out_of_idle(self):
        self.collect_port(1)
        self.collect_port(2)
        self.assertEqual(self.sample(), ("idle", 0))
        self.collect_port(3, tx_dropped=9)
        row = self.rows()["swp2"]
        self.assertEqual(row["delta_tx_dropped"], 9)
        self.assertEqual(row["delta_rx_dropped"], 0)
        self.assertEqual(row["sample_status"], "insufficient_traffic")

    def test_baseline_written_before_the_change_is_read(self):
        # An entry without the totals of the previous collection (written
        # by the earlier code in the middle of a sample) is compared with
        # the baseline itself for one run.
        self.collect_port(1, rx_packets=700, tx_packets=700)
        self.collect_port(2, rx_packets=900, tx_packets=900)
        baseline_file = self.results / "ber_baseline.json"
        baseline = json.loads(baseline_file.read_text())
        self.assertEqual(baseline[HOST]["swp2"].pop("last_seen"),
                         [900, 900, 0, 0, 0, 0])
        baseline_file.write_text(json.dumps(baseline))

        self.collect_port(3, rx_packets=900, tx_packets=900)
        self.assertEqual(self.sample(), ("insufficient_traffic", 400))
        self.collect_port(4, rx_packets=900, tx_packets=900)
        self.assertEqual(self.sample(), ("idle", 400))


class CaptureWithoutPortsTests(BerSiteTestCase):
    OTHER = "auditber-b"

    def test_capture_without_any_port_keeps_the_host_state(self):
        self.collect({"swp1": (BUSY, BUSY, 0, 0)})
        for cycle in (1, 2):
            busy = (cycle * BUSY, cycle * BUSY, 0, 0)
            self.collect({"swp8": busy, "swp9": busy}, host=self.OTHER)
        # switchd stopped: only lo and eth0 are left, the capture is complete.
        capture = proc_net_dev({})
        self.assertTrue(process_ber_data.proc_net_dev_is_complete(
            capture, process_ber_data.parse_proc_net_dev(capture)
        ))
        self.collect({}, host=self.OTHER)

        self.assertEqual(
            sorted(self.read_json("ber_baseline.json")[self.OTHER]),
            ["swp8", "swp9"],
        )
        shard = self.read_json(f"ber-history/{self.OTHER}.json")
        self.assertEqual(
            {name: len(entries) for name, entries in shard["history"].items()},
            {f"{self.OTHER}:swp8": 2, f"{self.OTHER}:swp9": 2},
        )
        # Nothing of that host is current while it lists no port.
        self.assertEqual(shard["current"], {})

        # The ports return with running counters: the sample continues from
        # the kept baseline instead of starting over.
        self.collect({"swp8": (4 * BUSY, 4 * BUSY, 0, 0),
                      "swp9": (4 * BUSY, 4 * BUSY, 0, 0)}, host=self.OTHER)
        returned = self.rows()["swp8"]
        self.assertEqual(returned["sample_status"], "analyzed")
        self.assertEqual(returned["delta_packets"], 4 * BUSY)

    def run_without_ports(self):
        (self.data / f"{HOST}_interface_errors.txt").write_text(proc_net_dev({}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            success = process_ber_data.process_ber_data_files(str(self.data))
        self.assertFalse(success)
        self.assertIn("No physical interface counters were processed",
                      output.getvalue())

    def test_failed_run_leaves_the_saved_state_alone(self):
        for cycle in (1, 2):
            busy = (cycle * BUSY, cycle * BUSY, 0, 0)
            self.collect({"swp1": busy, "swp2": busy})
        saved = {
            name: (self.results / name).read_text()
            for name in ("ber_baseline.json", f"ber-history/{HOST}.json")
        }
        # The only host lists no physical port: the run fails.
        self.run_without_ports()
        for name, content in saved.items():
            self.assertEqual((self.results / name).read_text(), content, name)

    def test_failed_first_run_writes_no_baseline(self):
        self.run_without_ports()
        self.assertFalse((self.results / "ber_baseline.json").exists())


class IncompleteCaptureTests(BerSiteTestCase):
    def test_host_whose_processing_failed_is_not_pruned(self):
        both = {"swp1": (BUSY, BUSY, 0, 0), "swp2": (BUSY, BUSY, 0, 0)}
        self.collect(both)
        baseline_file = self.results / "ber_baseline.json"
        baseline = json.loads(baseline_file.read_text())
        del baseline[HOST]["swp1"]["rx_errors"]   # damaged entry
        baseline_file.write_text(json.dumps(baseline))

        # A complete capture that no longer lists swp2 ...
        output = self.collect({"swp1": (2 * BUSY, 2 * BUSY, 0, 0)})
        # ... but the host could not be processed, so it proves nothing.
        self.assertIn(f"Error processing {HOST}_interface_errors.txt", output)
        self.assertEqual(
            sorted(self.read_json("ber_baseline.json")[HOST]), ["swp1", "swp2"]
        )
        self.assertIn(
            f"{HOST}:swp2", self.read_json(f"ber-history/{HOST}.json")["history"]
        )

    def test_capture_with_a_damaged_header_prunes_nothing(self):
        both = {"swp1": (BUSY, BUSY, 0, 0), "swp2": (BUSY, BUSY, 0, 0)}
        self.collect(both)
        # A capture that does not list swp2 any more.
        listing = proc_net_dev({"swp1": (2 * BUSY, 2 * BUSY, 0, 0)})
        first, second, rows = listing.split("\n", 2)
        damaged = {
            "first header line replaced":
                "bash: warning: here-document delimited\n" + second + "\n" + rows,
            "second header line missing": first + "\n" + rows,
        }
        for label, raw in damaged.items():
            with self.subTest(label):
                self.assertFalse(process_ber_data.proc_net_dev_is_complete(
                    raw, process_ber_data.parse_proc_net_dev(raw)
                ))
                self.collect(None, raw=raw)
                self.assertEqual(
                    sorted(self.read_json("ber_baseline.json")[HOST]),
                    ["swp1", "swp2"],
                )
        # Control: the undamaged capture does retire swp2.
        self.collect(None, raw=listing)
        self.assertEqual(sorted(self.read_json("ber_baseline.json")[HOST]),
                         ["swp1"])


class BerRecoveryWordingTests(AlertSiteTestCase):
    def setUp(self):
        super().setUp()
        # Shard era without an optical shard: the optical domain stays silent.
        (self.results / "optical-history").mkdir()

    def warn_then_stop(self, other_ports):
        """swp1 warns, then its link dies; returns the recovery run."""
        def ports(packets, errors):
            return dict(other_ports(packets),
                        swp1=(packets, packets, errors, 0))

        self.collect_ber(ports(BUSY, 0))
        self.immediate()
        # 16000 errored frames in 8e9 received bits: density 2e-6 (warning).
        self.collect_ber(ports(2 * BUSY, 16000))
        warned = self.immediate()
        self.assertEqual(warned.get_alert_state(ALERT_HOST, "ber_health"),
                         "WARNINGS")
        self.collect_ber(dict(other_ports(3 * BUSY),
                              swp1=(2 * BUSY, 2 * BUSY, 16000, 0)))
        return self.immediate()

    def test_recovery_says_that_the_quiet_port_is_not_graded(self):
        quiet = self.warn_then_stop(lambda packets: {})
        self.assertEqual(quiet.delivered, [(
            "RECOVERED", "BER Recovered",
            "Processed BER analysis reports no warning or critical "
            "condition; 1 idle port is not graded",
        )])
        self.assertEqual(quiet.get_alert_state(ALERT_HOST, "ber_health"), "OK")

    def test_recovery_counts_the_idle_ports_next_to_graded_ones(self):
        quiet = self.warn_then_stop(lambda packets: {
            "swp2": (packets, packets, 0, 0),   # in service
            "swp3": (0, 0, 0, 0),               # never used
        })
        self.assertEqual(quiet.get_device_ber_status(ALERT_HOST), "excellent")
        self.assertEqual(quiet.delivered, [(
            "RECOVERED", "BER Recovered",
            "Processed BER analysis reports no warning or critical "
            "condition; 2 idle ports are not graded",
        )])

    def test_recovery_without_idle_ports_is_healthy(self):
        self.collect_ber({"swp1": (BUSY, BUSY, 0, 0)})
        self.immediate()
        self.collect_ber({"swp1": (2 * BUSY, 2 * BUSY, 0, 0)})
        graded = self.immediate()
        self.assertEqual(graded.delivered, [(
            "RECOVERED", "BER Recovered", "Processed BER analysis is healthy",
        )])

    def test_shard_without_a_live_port_does_not_recover_a_warning(self):
        now = time.time()
        shards = {
            "empty current": {},
            "only a stale record": {f"{ALERT_HOST}:swp1": {
                "status": "excellent", "sample_status": "analyzed",
                "timestamp": now - 7 * 86400,
            }},
            "only a stale idle record": {f"{ALERT_HOST}:swp1": {
                "status": "unknown", "sample_status": "idle",
                "timestamp": now - 7 * 86400,
            }},
            "only another switch's record": {"auditalert-b:swp1": {
                "status": "excellent", "sample_status": "analyzed",
                "timestamp": now,
            }},
        }
        shard_dir = self.results / "ber-history"
        shard_dir.mkdir()
        for label, current in shards.items():
            with self.subTest(label):
                (shard_dir / f"{ALERT_HOST}.json").write_text(json.dumps({
                    "version": 1, "host": ALERT_HOST, "history": {},
                    "current": current,
                }))
                self.checker().set_alert_state(ALERT_HOST, "ber_health",
                                               "WARNINGS")
                alerts = self.immediate()
                self.assertEqual(alerts.get_device_ber_status(ALERT_HOST),
                                 "not_applicable")
                self.assertEqual(alerts.delivered, [])
                self.assertEqual(
                    alerts.get_alert_state(ALERT_HOST, "ber_health"), "WARNINGS"
                )


class StoppedPortAlertTests(AlertSiteTestCase):
    """The stopped port through the summary and the per-device alert."""

    def setUp(self):
        super().setUp()
        (self.results / "optical-history").mkdir()

    def ports(self, cycle, stopped):
        return {
            "swp1": (cycle * BUSY, cycle * BUSY, 0, 0),
            "swp2": (stopped, stopped, 0, 0),
            "swp3": (0, 0, 0, 0),   # never used
        }

    def test_device_recovers_once_the_stopped_port_is_idle(self):
        states = []
        for cycle, packets in enumerate((700, 900, 900, 900), start=1):
            self.collect_ber(self.ports(cycle, packets))
            alerts = self.immediate()
            states.append((
                alerts.get_device_ber_status(ALERT_HOST),
                alerts.get_alert_state(ALERT_HOST, "ber_health"),
                [title for _, title, _ in alerts.delivered],
            ))
        self.assertEqual(states, [
            ("unknown", "WARNING_UNKNOWN", ["BER Warning"]),   # baselines
            ("unknown", "WARNING_UNKNOWN", []),   # swp2 still collecting
            ("excellent", "OK", ["BER Recovered"]),
            ("excellent", "OK", []),
        ])

    def test_summary_does_not_list_the_stopped_port(self):
        for cycle, packets in enumerate((700, 900, 900), start=1):
            self.collect_ber(self.ports(cycle, packets))
        stats = self.checker().get_stats_from_html("ber-analysis.html")
        self.assertEqual((stats["unknown"], stats["idle"]), (2, 2))
        (severity, _title, message), = self.summary(real=("ber",))
        self.assertEqual(severity, "INFO")
        self.assertEqual(self.open_issues(message), [])
        self.assertIn("Awaiting Sample: 0     Idle: 2", message)


class AwaitingPortsInTheSummaryTests(AlertSiteTestCase):
    """Ports on their first sample are shown, not raised as an issue."""

    def test_first_samples_do_not_colour_the_summary(self):
        ports = {name: (BUSY, BUSY, 0, 0) for name in ("swp1", "swp2", "swp3")}
        self.collect_ber(ports)
        (severity, _title, message), = self.summary(real=("ber",))
        self.assertEqual(severity, "INFO")
        self.assertEqual(self.open_issues(message), [])
        self.assertIn("Awaiting Sample: 3     Idle: 0", message)

        # All graded in the next run: nothing the operator has to hear, and
        # the summary he already has is not a warning.
        self.collect_ber({name: (2 * BUSY, 2 * BUSY, 0, 0) for name in ports})
        self.assertEqual(self.summary(real=("ber",)), [])

    def test_idle_count_larger_than_the_ungraded_total_is_capped(self):
        # A report that contradicts itself must not show a negative count.
        (_severity, _title, message), = self.summary(
            {"ber": dict(excellent=3, unknown=1, idle=5)}
        )
        self.assertIn("Awaiting Sample: 0     Idle: 1", message)

    def test_switch_returning_on_its_first_samples_ends_with_a_healthy_summary(self):
        def run(ber):
            return [
                (severity, self.open_issues(message))
                for severity, _title, message in self.summary({"ber": ber})
            ]

        self.assertEqual(run({}), [("INFO", [])])
        # The switch is not collected ...
        self.assertEqual(run(dict(coverage_partial=True, coverage_current=0)), [(
            "WARNING",
            ["[WARNING] BER: partial collection coverage (0/1 devices current)"],
        )])
        # ... and returns with its four ports on the baseline sample: this
        # is the summary that announces the return, and it is the last one.
        self.assertEqual(run(dict(excellent=0, unknown=4, idle=0)),
                         [("INFO", [])])
        self.assertEqual(run({}), [])


if __name__ == "__main__":
    unittest.main()
