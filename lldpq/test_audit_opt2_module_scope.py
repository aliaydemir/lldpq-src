#!/usr/bin/env python3
"""One module of a breakout cage is one finding.

Every swp<N>s<M> of a cage answers from the same module, so a condition of
the module itself (its temperature, its voltage, the module pulled or
unreadable) arrived once per sub-port: one hot module split 4x was four
critical findings, one pulled module was "4 expected modules unplugged", and
the AI evidence for a temperature state listed only healthy power values.

Pinned here: each sub-port row keeps its own badge and the page cards keep
counting rows, but the anomaly list holds the condition once per (device,
cage) and names the sub-ports, the summary carries per-module counts next to
the per-port ones, and html/ai_correlate.py names temperature, voltage or
bias when they caused the state.  A fault of one lane stays on its sub-port.
"""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import HEALTHY, NO_DATA, OpticalFileTestCase, ROOT

sys.path.insert(0, str(ROOT / "html"))

import ai_correlate  # noqa: E402
import process_optical_data as optical  # noqa: E402
from optical_analyzer import OpticalAnalyzer  # noqa: E402


# A 400G-DR4 in a QSFP-DD cage split 4x: four media lanes, one per sub-port.
DR4_RX = [2.1, 2.2, 2.3, 2.4] + [None] * 4
DR4_TX = [1.6, 1.7, 1.8, 1.9] + [None] * 4
DR4_BIAS = [60.0] * 4 + [0.0] * 4
SUB_PORTS = [f"swp3s{index}" for index in range(4)]
NAMED = " (one module in swp3, sub-ports swp3s0, swp3s1, swp3s2, swp3s3)"


def dr4(rx=DR4_RX, **kwargs):
    kwargs.setdefault("tables", None)
    return fx.cmis(rx, DR4_TX, identifier=fx.QSFP_DD, bias=DR4_BIAS, **kwargs)


def cage(dump, state="up", ports=SUB_PORTS):
    return [(interface, state, dump) for interface in ports]


class ModuleConditionTests(OpticalFileTestCase):
    def assert_one_finding(self, health, kind, message):
        """Four rows keep the badge; the anomaly list holds one finding."""
        stats = self.parent.current_optical_stats
        self.assertEqual(
            {port: entry["health_status"] for port, entry in stats.items()},
            {f"leaf1:{interface}": health for interface in SUB_PORTS})
        anomalies = self.anomalies()
        self.assertEqual([item["type"] for item in anomalies], [kind])
        finding = anomalies[0]
        self.assertEqual(finding["message"], message + NAMED)
        self.assertEqual(finding["port"], "leaf1:swp3s0")
        self.assertEqual(finding["cage"], "leaf1:swp3")
        self.assertEqual(finding["ports"],
                         [f"leaf1:{interface}" for interface in SUB_PORTS])
        return finding

    def test_a_hot_module_is_one_critical_finding(self):
        self.rows(cage(dr4(temperature=75.0)))
        self.assert_one_finding(
            "critical", "HIGH_TEMPERATURE",
            "SFP temperature too high: 75.0°C (threshold: 70.0°C)")
        summary = self.parent.get_optical_summary()
        self.assertEqual(len(summary["critical_ports"]), 4,
                         "the cards and their row filter stay per port")
        self.assertEqual(self.parent.get_finding_counts(), {
            "critical_findings": 1, "warning_findings": 0,
            "unplugged_modules": 0})

    def test_a_warm_module_is_one_warning_finding(self):
        self.rows(cage(dr4(temperature=61.0)))
        self.assert_one_finding(
            "warning", "OPTICAL_PARAMETER_WARNING",
            "An optical power or temperature value is near its limit")
        self.assertEqual(
            self.parent.get_finding_counts()["warning_findings"], 1)
        self.assertEqual(
            len(self.parent.get_optical_summary()["warning_ports"]), 4)

    def test_a_module_beyond_its_own_temperature_limit(self):
        self.rows(cage(dr4(temperature=72.0, tables=fx.TWIN)))
        self.assert_one_finding(
            "warning", "MODULE_TEMPERATURE_HIGH",
            "Module temperature 72.00°C is above the module's high warning "
            "70.00°C")

    def test_a_module_voltage_alarm_is_one_finding(self):
        self.rows(cage(dr4(voltage=3.05, tables=fx.TWIN)))
        self.assert_one_finding(
            "critical", "MODULE_VOLTAGE_LOW",
            "Module voltage 3.0500 V is below the module's low alarm "
            "3.1000 V")
        self.assertEqual(
            self.parent.get_finding_counts()["critical_findings"], 1)

    def test_a_generic_voltage_fault_is_one_finding(self):
        self.rows(cage(dr4(voltage=2.9)))
        self.assert_one_finding(
            "critical", "VOLTAGE_OUT_OF_RANGE",
            "Module voltage out of range: 2.9000 V (limits: 3.0 to 3.6 V)")

    def test_every_sub_port_row_shows_the_finding(self):
        self.rows(cage(dr4(temperature=75.0)))
        message = ("SFP temperature too high: 75.0°C (threshold: 70.0°C)"
                   + NAMED)
        _page, details = self.publish()
        export = self.export_rows()
        for interface in SUB_PORTS:
            self.assertEqual(
                [item["message"]
                 for item in details[f"leaf1:{interface}"]["anomalies"]],
                [message])
            self.assertEqual(export[interface]["anomalies"],
                             "CRITICAL: " + message)

    def test_a_lane_fault_stays_on_its_sub_port(self):
        self.rows(cage(dr4(fx.with_lane(DR4_RX, 3, -16.0))))
        self.assertEqual(
            [(item["port"], item["type"]) for item in self.anomalies()],
            [("leaf1:swp3s2", "LOW_OPTICAL_POWER")])
        self.assertNotIn("ports", self.anomalies()[0])
        self.assertEqual(
            self.parent.get_finding_counts()["critical_findings"], 1)

    def test_a_lane_fault_next_to_a_hot_module(self):
        self.rows(cage(dr4(fx.with_lane(DR4_RX, 3, -16.0), temperature=75.0)))
        self.assertEqual(
            sorted((item["type"], tuple(item.get("ports") or [item["port"]]))
                   for item in self.anomalies()),
            [("HIGH_TEMPERATURE",
              tuple(f"leaf1:{interface}" for interface in SUB_PORTS)),
             ("LOW_OPTICAL_POWER", ("leaf1:swp3s2",))])
        # The module once, and the sub-port that has a fault of its own.
        self.assertEqual(
            self.parent.get_finding_counts()["critical_findings"], 2)

    def test_two_cages_and_two_devices_are_separate_findings(self):
        hot = dr4(temperature=75.0)
        self.parent.current_optical_stats = {}
        self.classify(cage(hot) + cage(hot, ports=["swp4s0", "swp4s1"]))
        self.classify(cage(hot, ports=["swp3s0", "swp3s1"]), hostname="leaf2")
        self.assertEqual(
            sorted(item["cage"] for item in self.anomalies()),
            ["leaf1:swp3", "leaf1:swp4", "leaf2:swp3"])
        self.assertEqual(
            self.parent.get_finding_counts()["critical_findings"], 3)
        self.assertEqual(
            len(self.parent.get_optical_summary()["critical_ports"]), 8)

    def test_an_unsplit_port_is_reported_as_before(self):
        self.rows([("swp3", "up", dr4(temperature=75.0))])
        self.assertEqual(
            [(item["port"], item["message"]) for item in self.anomalies()],
            [("leaf1:swp3",
              "SFP temperature too high: 75.0°C (threshold: 70.0°C)")])
        self.assertEqual(
            self.parent.get_finding_counts()["critical_findings"], 1)

    def test_a_hot_module_behind_a_down_sub_port_is_still_one_finding(self):
        hot = dr4(temperature=75.0)
        rows = self.rows(cage(hot, "up", SUB_PORTS[:3])
                         + cage(hot, "down", SUB_PORTS[3:]))
        self.assertEqual(rows["swp3s3"]["health_status"], "down")
        findings = [item for item in self.anomalies()
                    if item["type"] == "HIGH_TEMPERATURE"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ports"],
                         [f"leaf1:{interface}" for interface in SUB_PORTS])
        # On the down row the sentence still leads, the module follows.
        _page, details = self.publish()
        self.assertEqual(
            [item["message"]
             for item in details["leaf1:swp3s3"]["anomalies"]],
            ["Link down, receive light present", findings[0]["message"]])
        self.assertTrue(self.export_rows()["swp3s3"]["anomalies"].startswith(
            "WARNING: Link down, receive light present; CRITICAL: SFP "
            "temperature too high"))


class PulledModuleTests(OpticalFileTestCase):
    def pull(self):
        self.rows(cage(dr4()))
        return self.rows(cage(NO_DATA, "down"))

    def test_a_pulled_module_is_one_finding(self):
        rows = self.pull()
        self.assertEqual({stats["health_status"] for stats in rows.values()},
                         {"unplugged"})
        self.assertEqual(len(rows), 4)
        self.assertEqual(
            [(item["type"], item["message"], item["ports"])
             for item in self.anomalies()],
            [("OPTICAL_MODULE_UNPLUGGED",
              "Optical module is unplugged" + NAMED,
              [f"leaf1:{interface}" for interface in SUB_PORTS])])
        self.assertEqual(
            self.parent.get_finding_counts()["unplugged_modules"], 1)
        self.assertEqual(
            len(self.parent.get_optical_summary()["unplugged_ports"]), 4)

    def test_sub_ports_are_named_in_numeric_order(self):
        # Ten sub-ports would sort s0, s1, s10, s2 as text; a corrupted
        # file can also carry an index no integer conversion accepts.
        ports = ["swp7s10", "swp7s2", "swp7s0", "swp7s" + "9" * 5000]
        seeder = OpticalAnalyzer(str(self.root), load_history=False)
        seeder.optical_history = {
            f"leaf1:{interface}": [{"timestamp": 1.0, "health": "good",
                                    "rx_power_dbm": -2.0}]
            for interface in ports}
        self.assertTrue(seeder.save_optical_history())
        self.rows([(interface, "down", NO_DATA) for interface in ports])
        findings = self.anomalies()
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            [port.split(":", 1)[1][:8] for port in findings[0]["ports"]],
            ["swp7s0", "swp7s2", "swp7s10", "swp7s999"])
        self.assertEqual(findings[0]["port"], "leaf1:swp7s0")

    def test_two_unsplit_ports_are_two_modules(self):
        self.rows([("swp1", "up", fx.QSFP28_SR4), ("swp2", "up", fx.QSFP28_SR4)])
        self.rows([("swp1", "down", NO_DATA), ("swp2", "down", NO_DATA)])
        self.assertEqual(len(self.anomalies()), 2)
        self.assertEqual(
            self.parent.get_finding_counts()["unplugged_modules"], 2)

    def test_an_unreadable_module_is_one_finding(self):
        self.rows(cage(dr4()))
        rows = self.rows(cage(NO_DATA, "up"))
        self.assertEqual({stats["health_status"] for stats in rows.values()},
                         {"unknown"})
        self.assertEqual(
            [(item["type"], item["ports"]) for item in self.anomalies()],
            [("OPTICAL_DOM_UNREADABLE",
              [f"leaf1:{interface}" for interface in SUB_PORTS])])


class SummaryInputTests(OpticalFileTestCase):
    """The files the dashboard and the alerts read, written by the real run."""

    def run_pipeline(self, files):
        data_dir = self.root / "optical-data"
        for hostname, blocks in files.items():
            (data_dir / f"{hostname}_optical.txt").write_text(
                fx.device_file(blocks))
        snapshot = ({hostname: "OK" for hostname in files}, 0.0, True)
        with mock.patch.object(optical, "read_asset_snapshot",
                               return_value=snapshot), \
                mock.patch.object(optical, "asset_snapshot_is_valid",
                                  return_value=True), \
                mock.patch.object(optical, "is_current_collection",
                                  return_value=True), \
                mock.patch.dict("os.environ",
                                {"OPTICAL_PARSE_MAX_PARALLEL": "1"}), \
                mock.patch("builtins.print"):
            self.assertTrue(optical.process_optical_data_files(str(data_dir)))
        summary = json.loads(
            (self.root / "summary" / "optical-summary.json").read_text())
        page = (self.root / "optical-analysis.html").read_text()
        return summary, page

    def test_a_hot_module_and_a_pulled_module(self):
        self.run_pipeline({"leaf1": cage(dr4()),
                           "leaf2": cage(dr4(temperature=75.0))})
        summary, page = self.run_pipeline({
            "leaf1": cage(NO_DATA, "down"),
            "leaf2": cage(dr4(temperature=75.0)),
        })
        # Per port, as the cards and the row filters count.
        self.assertEqual(summary["critical"], 4)
        self.assertEqual(summary["unplugged"], 4)
        self.assertIn('id="critical-ports">4</div>', page)
        self.assertIn('id="unplugged-ports">4</div>', page)
        self.assertIn('data-optical-unplugged="4"', page)
        # Per module.
        self.assertEqual(summary["critical_findings"], 1)
        self.assertEqual(summary["warning_findings"], 0)
        self.assertEqual(summary["unplugged_modules"], 1)
        self.assertIn('data-optical-critical-findings="1"', page)
        self.assertIn('data-optical-warning-findings="0"', page)
        self.assertIn('data-optical-unplugged-modules="1"', page)
        export = json.loads(
            (self.root / "export" / "optical.json").read_text())
        self.assertEqual(export["counts"]["unplugged_modules"], 1)
        self.assertEqual(export["counts"]["unplugged"], 4)


class HealthCauseTests(OpticalFileTestCase):
    """The stored cause is the parameter that put the port in its state."""

    def test_each_parameter_is_named_for_its_own_fault(self):
        lane = fx.with_lane
        partial = dict(fx.TWIN, temperature={"high_alarm": 80.0,
                                              "high_warning": 70.0})
        cases = (
            # Graded by the module's own limits.
            (fx.cmis(lane(fx.TWIN_RX, 2, -9.0)), "critical", ["rx_power"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, -7.9)), "warning", ["rx_power"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, -6.0)), "warning", ["rx_power"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, 7.0)), "critical", ["rx_power"]),
            (fx.cmis(tx=lane(fx.TWIN_TX, 3, -6.0)), "critical", ["tx_power"]),
            (fx.cmis(tx=lane(fx.TWIN_TX, 3, 5.5)), "warning", ["tx_power"]),
            (fx.cmis(temperature=85.0), "critical", ["temperature"]),
            (fx.cmis(temperature=72.0), "warning", ["temperature"]),
            (fx.cmis(voltage=3.05), "critical", ["voltage"]),
            (fx.cmis(voltage=3.12), "warning", ["voltage"]),
            (fx.cmis(temperature=85.0, tables=partial), "critical",
             ["temperature"]),
            # Graded by the generic limits.
            (fx.cmis(lane(fx.TWIN_RX, 2, -15.0), tables=None), "critical",
             ["rx_power"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, -12.0), tables=None), "warning",
             ["rx_power"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, 5.5), tables=None), "warning",
             ["rx_power"]),
            (fx.cmis(tx=lane(fx.TWIN_TX, 3, 4.5), tables=None), "critical",
             ["tx_power"]),
            (fx.cmis(tx=lane(fx.TWIN_TX, 3, 3.5), tables=None), "warning",
             ["tx_power"]),
            (fx.cmis(temperature=75.0, tables=None), "critical",
             ["temperature"]),
            (fx.cmis(temperature=61.0, tables=None), "warning",
             ["temperature"]),
            (fx.cmis(voltage=2.9, tables=None), "critical", ["voltage"]),
            # Laser bias.
            (fx.cmis(bias=lane([212.7] * 8, 4, 405.0)), "critical",
             ["bias_current"]),
            (fx.cmis(bias=lane([212.7] * 8, 4, 390.0)), "warning",
             ["bias_current"]),
            (fx.cmis(flags={(3, "low_alarm"): True}), "warning",
             ["bias_current"]),
            # Two causes, and a warning next to the critical cause.
            (fx.cmis(lane(fx.TWIN_RX, 2, -9.0), temperature=85.0),
             "critical", ["rx_power", "temperature"]),
            (fx.cmis(lane(fx.TWIN_RX, 2, -9.0), temperature=72.0),
             "critical", ["rx_power"]),
            (fx.cmis(), "excellent", []),
        )
        for number, (dump, health, causes) in enumerate(cases):
            with self.subTest(case=number, health=health, causes=causes):
                stats = self.rows([("swp1", "up", dump)])["swp1"]
                self.assertEqual(stats["health_status"], health)
                self.assertEqual(stats["health_causes"], causes)


class AiEvidenceTests(OpticalFileTestCase):
    """html/ai_correlate.py reads the shards the worker wrote."""

    def evidence(self):
        return {(item["device"], item["port"]): item["detail"]
                for item in ai_correlate._collect_optical(str(self.root))}

    def test_a_temperature_state_names_the_temperature(self):
        self.rows(cage(dr4(temperature=61.0)))
        # One module in the cage, one entry in the AI list: the first
        # sub-port speaks for it and names the others.
        self.assertEqual(self.evidence(), {
            ("leaf1", "swp3s0"): "Optical health warning (rx=2.1dBm "
                                 "tx=1.6dBm margin=16.1dB temp=61.0C); one "
                                 "module in swp3, sub-ports swp3s0, swp3s1, "
                                 "swp3s2, swp3s3",
        })

    def test_a_voltage_state_names_the_voltage(self):
        self.rows([("swp1", "up", fx.cmis(voltage=3.05))])
        self.assertEqual(
            self.evidence()[("leaf1", "swp1")],
            "Optical health critical (rx=2.6dBm tx=2.0dBm margin=9.4dB "
            "voltage=3.05V)")

    def test_a_bias_state_names_the_bias(self):
        self.rows([("swp1", "up", fx.cmis(
            bias=fx.with_lane([212.7] * 8, 4, 405.0)))])
        self.assertEqual(
            self.evidence()[("leaf1", "swp1")],
            "Optical health critical (rx=2.6dBm tx=2.0dBm margin=9.4dB "
            "bias=405.0mA)")

    def test_a_power_state_names_no_other_parameter(self):
        self.rows([("swp1", "up", fx.cmis(
            fx.with_lane(fx.TWIN_RX, 2, -16.0)))])
        self.assertEqual(
            self.evidence()[("leaf1", "swp1")],
            "Optical health critical (rx=-16.0dBm tx=2.0dBm margin=-7.6dB)")

    def test_a_down_row_names_the_bias_alarm_behind_it(self):
        self.rows([("swp1", "down", fx.cmis(
            bias=fx.with_lane([212.7] * 8, 4, 405.0),
            flags={(4, "high_alarm"): True}))])
        self.assertEqual(
            self.evidence()[("leaf1", "swp1")],
            "Optical health down (rx=2.6dBm tx=2.0dBm margin=9.4dB "
            "bias=405.0mA)")

    def test_the_cause_is_stored_with_the_state(self):
        self.rows([("swp1", "up", fx.cmis(temperature=85.0)),
                   ("swp2", "up", fx.cmis(fx.with_lane(fx.TWIN_RX, 2, -16.0),
                                          voltage=3.05)),
                   ("swp3", "up", fx.cmis())])
        current = self.shard()["current"]
        self.assertEqual(current["leaf1:swp1"]["health_causes"],
                         ["temperature"])
        self.assertEqual(current["leaf1:swp2"]["health_causes"],
                         ["rx_power", "voltage"])
        self.assertEqual(current["leaf1:swp3"]["health_causes"], [])
        self.assertIn(current["leaf1:swp3"]["health_status"], HEALTHY)

    def test_a_record_without_causes_reads_as_before(self):
        shard_dir = self.root / "optical-history"
        shard_dir.mkdir()
        (shard_dir / "leaf9.json").write_text(json.dumps({"current": {
            "leaf9:swp1": {"health_status": "critical", "rx_power_dbm": -2.0,
                           "tx_power_dbm": -1.0, "link_margin_db": 12.0,
                           "temperature_c": 75.0}}}))
        self.assertEqual(
            self.evidence()[("leaf9", "swp1")],
            "Optical health critical (rx=-2.0dBm tx=-1.0dBm margin=12.0dB)")


if __name__ == "__main__":
    unittest.main()
