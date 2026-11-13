#!/usr/bin/env python3
"""Copper against optical, unreadable modules and OMA receive power.

Three things decided which ports the Optical page lists at all:

* The copper indicator list.  It matched 'No separable connector', which an
  active optical cable prints too, so no AOC was ever monitored; and it
  missed what ethtool prints for a 10G SFP+ DAC ('Copper pigtail', 'Passive
  Cable', 'Passive Cu cmplnce.') and for a copper SFP ('RJ45', '1000BASE-T'),
  so those became UNKNOWN optical ports with a standing warning.
* 'No transceiver data' on a link-up port.  A module that stopped answering
  vanished from the page, and returned as "unplugged" once its link dropped.
* The receive label.  A module that measures receive power as OMA prints
  'Receiver signal OMA', which was not read.

Every dump is run through the real per-device worker
(process_optical_data._classify_optical_file) as the collector writes it.
"""

from __future__ import annotations

import unittest

import test_audit_opt2_fixtures as fx
from test_audit_opt2_fixtures import HEALTHY, NO_DATA, OpticalFileTestCase
from optical_analyzer import OpticalAnalyzer


COPPER = {
    "10G SFP+ passive DAC, connector 'Copper pigtail'": fx.SFP_10G_DAC,
    "10G SFP+ passive DAC with a diagnostics page":
        fx.SFP_10G_DAC_NO_DOM_PAGE,
    "10G SFP+ passive DAC, connector 'No separable connector'":
        fx.SFP_10G_DAC_NO_SEPARABLE,
    "10G SFP+ active copper cable": fx.SFP_10G_ACC,
    "25G SFP28 DAC": fx.SFP_25G_DAC,
    "1000BASE-T SFP": fx.SFP_1000BASE_T,
    "10GBASE-T SFP+": fx.SFP_10GBASE_T,
    "40G QSFP+ DAC": fx.QSFP_40G_DAC,
    "100G QSFP28 DAC": fx.QSFP28_DAC,
    "100G QSFP28 DAC with a temperature sensor": fx.QSFP28_DAC_WITH_SENSOR,
    "CMIS DAC": fx.CMIS_DAC,
}

AOC_200G = fx.qsfp(
    connector="0x23 (No separable connector)",
    types=["Active Optical Cable with 50GAUI, 100GAUI-2 or 200GAUI-4 C2M. "
           "Providing a worst BER of 10-6 or below"],
    technology="0x00 (850 nm VCSEL)", copper_length=10, rx=fx.SR4_RX,
    tx=fx.SR4_TX, bias=fx.SR4_BIAS)
ACTIVE_OPTICAL = {
    "25G SFP28 AOC": fx.SFP28_AOC,
    "10G SFP+ AOC without an AOC code": fx.SFP_10G_AOC,
    "40G QSFP+ AOC": fx.QSFP_40G_AOC,
    "100G QSFP28 AOC": fx.QSFP28_AOC,
    "200G AOC": AOC_200G,
    "CMIS AOC": fx.CMIS_AOC,
}


class CopperTests(OpticalFileTestCase):
    def test_copper_is_not_an_optical_port_whatever_its_link_state(self):
        for label, dump in COPPER.items():
            for state in ("up", "down"):
                with self.subTest(label, state=state):
                    self.assertEqual(self.rows([("swp1", state, dump)]), {})

    def test_both_holders_of_the_rule_agree(self):
        # The analyzer answers None for copper; the per-device worker asks
        # the analyzer instead of keeping a second list.
        for label, dump in COPPER.items():
            with self.subTest(label):
                self.assertIsNone(self.worker.parse_optical_data(dump))
                self.assertFalse(
                    self.worker.update_optical_stats("leaf1:swp1", dump))
        self.assertEqual(self.worker.current_optical_stats, {})

    def test_a_leaf_with_copper_only_reports_no_unknown_port(self):
        rows = self.rows([
            ("swp1", "up", fx.SFP_1000BASE_T),
            ("swp2", "up", fx.SFP_10G_DAC),
            ("swp3", "down", fx.SFP_10G_DAC),
            ("swp4", "up", fx.SFP_10GBASE_T),
        ])
        self.assertEqual(rows, {})
        summary = self.parent.get_optical_summary()
        self.assertEqual(summary["total_ports"], 0)
        self.assertEqual(summary["unknown_ports"], [])
        # Nothing is left behind for a later "unplugged" either.
        self.assertFalse((self.root / "optical-history" / "leaf1.json").exists())

    def test_each_string_ethtool_prints_for_copper_is_enough(self):
        # One descriptor line each, next to a temperature reading (a cable
        # with a sensor), so that nothing else decides.
        descriptors = (
            fx.line("Connector", "0x21 (Copper pigtail)"),
            fx.line("Connector", "0x22 (RJ45)"),
            fx.line("Transceiver type", "Passive Cable"),
            fx.line(*fx.PASSIVE_CU),
            fx.line(*fx.ACTIVE_CU),
            fx.line("Transceiver type", "Ethernet: 1000BASE-T"),
            fx.line("Transceiver type",
                    "Extended: 10Gbase-T with SFI electrical interface"),
            fx.line("Transceiver type", "Extended: 25G Base-CR CA-N"),
            fx.line("Transceiver type",
                    "Extended: 50GBASE-CR, 100GBASE-CR2, or 200GBASE-CR4"),
            fx.line("Transceiver type", "40G Ethernet: 40G Base-CR4"),
            fx.line("Transmitter technology",
                    "0xa0 (Copper cable unequalized)"),
            fx.line("Transmitter technology",
                    "0x0a (Copper cable, unequalized)"),
            fx.line("Transceiver type",
                    "Extended: Active Copper Cable with 50GAUI, 100GAUI-2 "
                    "or 200GAUI-4 C2M. Providing a worst BER of 10-6 or "
                    "below"),
        )
        for descriptor in descriptors:
            with self.subTest(descriptor.split(":", 1)[1].strip()):
                body = "\n".join([
                    fx.line("Identifier", "0x03 (SFP)"), descriptor,
                    fx.line("Module temperature", fx.celsius(31.0)),
                    fx.line("Module voltage", fx.volts(3.3))]) + "\n"
                self.assertIsNone(self.worker.parse_optical_data(body))
                self.assertEqual(self.rows([("swp1", "up", body)]), {})

    def test_indicators_match_without_regard_to_case(self):
        # None of these blocks prints a connector line, and each carries a
        # temperature reading (a cable with a sensor).
        blocks = {
            "upper-case standard": [
                fx.line("Identifier", "0x11 (QSFP28)"),
                fx.line("Transceiver type", "100G ETHERNET: 100G BASE-CR4"),
            ],
            "lower-case technology": [
                fx.line("Identifier", "0x11 (QSFP28)"),
                fx.line("Transmitter technology",
                        "0xa0 (copper cable unequalized)"),
            ],
            "NVUE cable type": ["cable-type : passive copper cable"],
            "twinax": ["media : TWINAX"],
            "dac": ["cable : 3m dac"],
        }
        for label, lines in blocks.items():
            with self.subTest(label):
                body = "\n".join(lines + [
                    fx.line("Module temperature", fx.celsius(31.0)),
                    fx.line("Module voltage", fx.volts(3.3))]) + "\n"
                self.assertIsNone(self.worker.parse_optical_data(body))
                self.assertEqual(self.rows([("swp1", "up", body)]), {})

    def test_vendor_lines_are_not_consulted(self):
        # An indicator inside a part number proves nothing either way.  A
        # shut optic carries no light that could decide instead ...
        optic = fx.qsfp(connector="0x0c (MPO Parallel Optic)",
                        types=["100G Ethernet: 100G Base-SR4"],
                        technology="0x00 (850 nm VCSEL)", rx=[None] * 4,
                        tx=[None] * 4, bias=0.0,
                        vendor_pn="DAC-RJ45-TWINAX-BASE-T")
        self.assertEqual(self.rows([("swp1", "down", optic)])["swp1"]
                         ["health_status"], "down")
        # ... and a cable with a temperature sensor has a DOM value.
        cable = fx.qsfp(
            connector="0x23 (No separable connector)",
            types=["100G Ethernet: 100G Base-CR4 or 25G Base-CR CA-L"],
            technology="0xa0 (Copper cable unequalized)", copper_length=2,
            attenuation=True, temperature=31.0, voltage=3.3,
            vendor_pn="ACME-AOC-3M")
        self.assertEqual(self.rows([("swp2", "up", cable)]), {})
        self.assertEqual(self.rows([("swp2", "down", cable)]), {})


class ActiveOpticalCableTests(OpticalFileTestCase):
    def test_a_healthy_active_optical_cable_is_monitored(self):
        for label, dump in ACTIVE_OPTICAL.items():
            with self.subTest(label):
                rows = self.rows([("swp1", "up", dump)])
                self.assertIn(rows["swp1"]["health_status"], HEALTHY)
                self.assertIsNotNone(rows["swp1"]["rx_power_dbm"])
                self.assertIsNotNone(rows["swp1"]["tx_power_dbm"])

    def test_a_weak_lane_of_an_aoc_is_reported(self):
        rows = self.rows([("swp1", "up", fx.qsfp28_aoc(
            rx=fx.with_lane(fx.SR4_RX, 2, -15.5)))])
        self.assertEqual(rows["swp1"]["health_status"], "critical")
        self.assertEqual(rows["swp1"]["rx_power_lane"], 2)
        self.assertEqual(self.messages(), [
            "RX power too low: -15.50 dBm (threshold: -14.0 dBm)"])

    def test_a_dark_lane_of_an_aoc_is_reported(self):
        # Lane 3 receives nothing while its laser keeps running.
        rows = self.rows([("swp1", "up", fx.qsfp28_aoc(
            rx=fx.with_lane(fx.SR4_RX, 3, None)))])
        self.assertEqual(rows["swp1"]["health_status"], "critical")
        self.assertEqual(rows["swp1"]["rx_power_lane"], 3)

    def test_a_down_aoc_keeps_its_row(self):
        rows = self.rows([("swp1", "down", fx.QSFP28_AOC)])
        self.assertEqual(rows["swp1"]["health_status"], "down")

    def test_the_aoc_code_decides_even_without_light(self):
        # Shut on both ends: nothing is lit, but the type says optical.
        dark = fx.sfp(connector="0x23 (No separable connector)",
                      types=["Active Cable", fx.AOC_25G],
                      compliance=fx.ACTIVE_CU,
                      dom=(None, None, 0.0, 33.0, 3.3))
        rows = self.rows([("swp1", "down", dark)])
        self.assertEqual(rows["swp1"]["health_status"], "down")

    def test_no_separable_connector_alone_is_not_copper(self):
        # A CMIS AOC prints no AOC code.  Shut, it carries no light either:
        # only the connector line would call it a cable, and that line is
        # the one every active optical cable prints.
        shut = fx.cmis([None] * 8, [None] * 8, identifier=fx.QSFP_DD,
                       connector="0x23 (No separable connector)",
                       technology="0x00 (850 nm VCSEL)", bias=0.0,
                       temperature=38.0)
        self.assertIn("No separable connector", shut)
        rows = self.rows([("swp1", "down", shut)])
        self.assertEqual(rows["swp1"]["health_status"], "down")
        self.assertEqual(rows["swp1"]["temperature_c"], 38.0)

    def test_light_decides_for_a_cable_without_an_aoc_code(self):
        # 'Active Cable' + 'Active Cu cmplnce.' is an active copper cable
        # or a 10G AOC; only the second one carries light.
        self.assertEqual(self.rows([("swp1", "up", fx.SFP_10G_ACC)]), {})
        rows = self.rows([("swp2", "up", fx.SFP_10G_AOC)])
        self.assertIn(rows["swp2"]["health_status"], HEALTHY)


class SeparableTransceiverTests(OpticalFileTestCase):
    """Ordinary optics print 'Length (Copper ...)' lines too."""

    def test_ordinary_transceivers_are_monitored(self):
        self.assertIn("Length (Copper)", fx.SFP_10G_SR)
        self.assertIn("Length (Copper or Active cable)", fx.QSFP28_SR4)
        optics = {
            "10G SFP+ SR": fx.SFP_10G_SR,
            "100G QSFP28 SR4": fx.QSFP28_SR4,
            "CMIS OSFP": fx.cmis(),
            "CMIS QSFP-DD": fx.cmis(identifier=fx.QSFP_DD),
        }
        for label, dump in optics.items():
            with self.subTest(label):
                rows = self.rows([("swp1", "up", dump)])
                self.assertIn(rows["swp1"]["health_status"], HEALTHY)


class BlockWithoutDomTests(OpticalFileTestCase):
    # A cable type no indicator names: identity lines and nothing else.
    IDENTITY_ONLY = "\n".join([
        fx.line("Identifier", "0x03 (SFP)"),
        fx.line("Connector", "0x00 (unknown or unspecified)"),
        fx.line("Transceiver type", "FC: Twin Axial Pair (TW)"),
        fx.line("Vendor name", "ACME"),
    ]) + "\n"
    # A module without monitors: qsfp.c prints zeros and stops.
    NO_MONITORS = fx.qsfp(connector="0x0c (MPO Parallel Optic)",
                          types=["40G Ethernet: 40G Base-SR4"],
                          technology="0x00 (850 nm VCSEL)",
                          identifier="0x0d (QSFP+)", temperature=0.0,
                          voltage=0.0)

    def test_no_dom_value_and_no_optical_history_is_no_row(self):
        for label, dump in (("identity lines only", self.IDENTITY_ONLY),
                            ("0.00 C and 0.0000 V only", self.NO_MONITORS)):
            for state in ("up", "down"):
                with self.subTest(label, state=state):
                    self.assertEqual(self.rows([("swp1", state, dump)]), {})

    def test_with_optical_history_the_port_stays_visible(self):
        self.assertIn(self.rows([("swp1", "up", fx.QSFP28_SR4)])["swp1"]
                      ["health_status"], HEALTHY)
        rows = self.rows([("swp1", "up", self.NO_MONITORS)])
        self.assertEqual(rows["swp1"]["health_status"], "unknown")
        self.assertIsNone(rows["swp1"]["temperature_c"])
        self.assertIsNone(rows["swp1"]["voltage_v"])

    def test_a_row_without_readings_is_not_optical_history(self):
        # What the copper ports of the old list left behind: history
        # entries that never held a value.
        seeder = OpticalAnalyzer(str(self.root), load_history=False)
        seeder.optical_history = {"leaf1:swp1": [
            {"timestamp": 1.0, "health": "unknown", "rx_power_dbm": None,
             "tx_power_dbm": None, "temperature_c": None},
        ]}
        self.assertTrue(seeder.save_optical_history())
        self.assertEqual(self.rows([("swp1", "up", self.IDENTITY_ONLY)]), {})
        self.assertEqual(self.rows([("swp1", "up", NO_DATA)]), {})
        self.assertEqual(self.rows([("swp1", "down", NO_DATA)]), {},
                         "a cable that was never optical is not unplugged")


class UnreadableModuleTests(OpticalFileTestCase):
    NOTE = ("Module diagnostics could not be read although the link is up "
            "(ethtool -m returned no data)")

    def collect_then_fail(self, state="up"):
        self.assertEqual(
            self.rows([("swp9", "up", fx.qsfp(
                connector="0x0c (MPO Parallel Optic)",
                types=["100G Ethernet: 100G Base-SR4"],
                technology="0x00 (850 nm VCSEL)",
                rx=fx.with_lane(fx.SR4_RX, 2, -15.0), tx=fx.SR4_TX,
                bias=fx.SR4_BIAS))])["swp9"]["health_status"], "critical")
        return self.rows([("swp9", state, NO_DATA)])

    def test_a_module_that_stops_answering_on_a_link_up_port_is_unknown(self):
        rows = self.collect_then_fail()
        self.assertEqual(set(rows), {"swp9"}, "the port must not vanish")
        self.assertEqual(rows["swp9"]["health_status"], "unknown")
        self.assertEqual(
            [(item["type"], item["severity"], item["message"])
             for item in self.anomalies()],
            [("OPTICAL_DOM_UNREADABLE", "warning", self.NOTE)])

    def test_the_reason_reaches_the_page_the_export_and_the_shard(self):
        self.collect_then_fail()
        page, details = self.publish()
        self.assertEqual(
            [item["message"] for item in details["leaf1:swp9"]["anomalies"]],
            [self.NOTE])
        self.assertIn('data-health="unknown" data-port="leaf1:swp9"', page)
        row = self.export_rows()["swp9"]
        self.assertEqual(row["health"], "unknown")
        self.assertEqual(row["anomalies"], "WARNING: " + self.NOTE)
        current = self.shard()["current"]["leaf1:swp9"]
        self.assertEqual(current["health_status"], "unknown")
        # The earlier readings are kept: the module is still expected.
        self.assertEqual(len(self.shard()["history"]["leaf1:swp9"]), 1)

    def test_a_port_that_never_had_optics_stays_unmonitored(self):
        # A fixed copper port and an empty cage print the same text.
        self.assertEqual(self.rows([("swp30", "up", NO_DATA),
                                    ("swp31", "down", NO_DATA)]), {})

    def test_once_the_link_drops_the_same_text_is_an_unplugged_module(self):
        rows = self.collect_then_fail(state="down")
        self.assertEqual(rows["swp9"]["health_status"], "unplugged")


class OmaReceivePowerTests(OpticalFileTestCase):
    def sr4(self, rx=fx.SR4_RX, **kwargs):
        return fx.qsfp(connector="0x0c (MPO Parallel Optic)",
                       types=["100G Ethernet: 100G Base-SR4"],
                       technology="0x00 (850 nm VCSEL)", rx=rx, tx=fx.SR4_TX,
                       bias=fx.SR4_BIAS, rx_label="Receiver signal OMA",
                       **kwargs)

    def test_both_spellings_of_the_channel_label_are_read(self):
        dumps = {
            # qsfp.c v6.1: no blank before "(Channel".
            "Receiver signal OMA(Channel 1)": self.sr4(),
            # Later qsfp.c and cmis.c: with the blank.
            "Receiver signal OMA (Channel 1)": self.sr4(rx_blank=" "),
        }
        for spelling, dump in dumps.items():
            with self.subTest(spelling):
                self.assertIn(spelling, dump)
                stats = self.rows([("swp1", "up", dump)])["swp1"]
                self.assertEqual(stats["rx_power_lanes_dbm"], fx.SR4_RX)
                self.assertEqual(stats["rx_power_lane_ids"], [1, 2, 3, 4])
                self.assertIn(stats["health_status"], HEALTHY)

    def test_a_cmis_module_reporting_oma_is_read(self):
        dump = fx.cmis(rx_label="Receiver signal OMA")
        self.assertIn("Receiver signal OMA (Channel 8)", dump)
        stats = self.rows([("swp1", "up", dump)])["swp1"]
        self.assertEqual(stats["rx_power_lanes_dbm"], fx.TWIN_RX)
        self.assertEqual(stats["rx_power_lane_ids"], list(range(1, 9)))

    def test_an_sfp_reporting_oma_is_read(self):
        dump = fx.sfp(connector="0x07 (LC)",
                      types=["10G Ethernet: 10G Base-SR"],
                      dom=(-2.4, -2.2, 6.0, 36.0, 3.29),
                      rx_label="Receiver signal OMA")
        stats = self.rows([("swp1", "up", dump)])["swp1"]
        self.assertEqual(stats["rx_power_dbm"], -2.4)
        self.assertIsNotNone(stats["link_margin_db"])

    def test_an_oma_lane_below_the_limit_is_graded(self):
        stats = self.rows([("swp1", "up", self.sr4(
            rx=fx.with_lane(fx.SR4_RX, 2, -16.0)))])["swp1"]
        self.assertEqual(stats["health_status"], "critical")
        self.assertEqual(stats["rx_power_lane"], 2)
        self.assertEqual(stats["rx_power_dbm"], -16.0)


if __name__ == "__main__":
    unittest.main()
