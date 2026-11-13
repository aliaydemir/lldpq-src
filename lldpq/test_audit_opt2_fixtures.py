#!/usr/bin/env python3
"""``ethtool -m`` dumps for the opt2 audit tests, built from ethtool's own strings.

Every label and descriptor below is one upstream ethtool prints (sfpid.c,
sfpdiag.c, qsfp.c, cmis.c, sff-common.c; v6.1 and master were compared) with
its print formats: "\\t%-41s : %s", "%.4f mW / %.2f dBm", "%.2f degrees C /
%.2f degrees F", "%.4f V", "%.3f mA".  Vendor names, part numbers, serial
numbers and all readings are invented.

This file holds no tests; the test_audit_opt2_*.py files import it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_optical_data as optical
from optical_analyzer import OpticalAnalyzer


HEALTHY = ("good", "excellent")
KINDS = (("high_alarm", "high alarm"), ("low_alarm", "low alarm"),
         ("high_warning", "high warning"), ("low_warning", "low warning"))


def line(label, value):
    return "\t%-41s : %s" % (label, value)


def power(dbm):
    """A power reading; None is what a dark or unimplemented monitor prints."""
    if dbm is None:
        return "0.0000 mW / -inf dBm"
    return "%.4f mW / %.2f dBm" % (10 ** (dbm / 10.0), dbm)


def celsius(value):
    return "%.2f degrees C / %.2f degrees F" % (value, value * 1.8 + 32)


def volts(value):
    return "%.4f V" % value


def milliamps(value):
    return "%.3f mA" % value


def limits(high_alarm, high_warning, low_warning, low_alarm):
    return {"high_alarm": high_alarm, "high_warning": high_warning,
            "low_warning": low_warning, "low_alarm": low_alarm}


def threshold_lines(tables):
    """The block sff_show_thresholds prints, in its order."""
    out = []
    for metric, label, render in (
            ("bias", "Laser bias current", milliamps),
            ("tx_power", "Laser output power", power),
            ("temperature", "Module temperature", celsius),
            ("voltage", "Module voltage", volts),
            ("rx_power", "Laser rx power", power)):
        table = (tables or {}).get(metric)
        if not table:
            continue
        for key, words in KINDS:
            if key in table:
                out.append(line(f"{label} {words} threshold",
                                render(table[key])))
    return out


def identity(vendor_pn="ACME-0001"):
    """The vendor block every dump ends its identity section with."""
    return [
        line("Vendor name", "ACME"),
        line("Vendor OUI", "00:11:22"),
        line("Vendor PN", vendor_pn),
        line("Vendor rev", "A1"),
        line("Vendor SN", "SN0000001"),
        line("Date code", "240101"),
    ]


# --------------------------------------------------------------------------
# SFF-8472 (sfpid.c + sfpdiag.c): SFP, SFP+, SFP28
# --------------------------------------------------------------------------

def sfp(*, connector, types, copper_length=0, compliance=None,
        wavelength=850, dom=None, dom_supported=None, tables=None,
        flags=None, rx_label="Receiver signal average optical power",
        vendor_pn="ACME-SFP"):
    """One SFP-family dump.

    types: the "Transceiver type" continuation lines; compliance is the
    "Passive Cu cmplnce." / "Active Cu cmplnce." line ethtool prints instead
    of the laser wavelength for a cable; dom is (rx, tx, bias, temperature,
    voltage) and dom_supported False prints the "No" line of a module with a
    diagnostics page but no monitors.
    """
    out = [
        line("Identifier", "0x03 (SFP)"),
        line("Extended identifier",
             "0x04 (GBIC/SFP defined by 2-wire interface ID)"),
        line("Connector", connector),
        line("Transceiver codes",
             "0x00 0x00 0x00 0x00 0x00 0x04 0x00 0x00 0x00"),
    ]
    out += [line("Transceiver type", item) for item in types]
    out += [
        line("Encoding", "0x06 (64B/66B)"),
        line("BR, Nominal", "10300MBd"),
        line("Rate identifier", "0x00 (unspecified)"),
        line("Length (SMF,km)", "0km"),
        line("Length (SMF)", "0m"),
        line("Length (50um)", "0m"),
        line("Length (62.5um)", "0m"),
        line("Length (Copper)", f"{copper_length}m"),
        line("Length (OM3)", "0m"),
    ]
    if compliance:
        out.append(line(*compliance))
    else:
        out.append(line("Laser wavelength", f"{wavelength}nm"))
    out += identity(vendor_pn)
    out += [line("Option values", "0x00 0x1a"),
            line("BR margin, max", "0%"), line("BR margin, min", "0%")]
    if dom is not None:
        rx, tx, bias, temperature, voltage = dom
        out += [
            line("Optical diagnostics support", "Yes"),
            line("Laser bias current", milliamps(bias)),
            line("Laser output power", power(tx)),
            line(rx_label, power(rx)),
            line("Module temperature", celsius(temperature)),
            line("Module voltage", volts(voltage)),
            line("Alarm/warning flags implemented", "Yes"),
        ]
        for label in ("Laser bias current", "Laser output power",
                      "Module temperature", "Module voltage",
                      "Laser rx power"):
            for key, words in KINDS:
                state = "On" if (flags or {}).get((label, key)) else "Off"
                out.append(line(f"{label} {words}", state))
        out += threshold_lines(tables)
    elif dom_supported is False:
        out.append(line("Optical diagnostics support", "No"))
    return "\n".join(out) + "\n"


PASSIVE_CU = ("Passive Cu cmplnce.",
              "0x01 (SFF-8431 appendix E) [SFF-8472 rev10.4 only]")
ACTIVE_CU = ("Active Cu cmplnce.",
             "0x04 (SFF-8431 limiting) [SFF-8472 rev10.4 only]")
AOC_25G = "Extended: 100G AOC or 25GAUI C2M AOC with worst BER of 5x10^(-5)"

# 10G SFP+ passive DAC: no Base-CR line exists for it, only these.
SFP_10G_DAC = sfp(connector="0x21 (Copper pigtail)", types=["Passive Cable"],
                  copper_length=3, compliance=PASSIVE_CU)
SFP_10G_DAC_NO_DOM_PAGE = sfp(
    connector="0x21 (Copper pigtail)", types=["Passive Cable"],
    copper_length=3, compliance=PASSIVE_CU, dom_supported=False)
# The same cable with the other connector byte ethtool decodes for cables.
SFP_10G_DAC_NO_SEPARABLE = sfp(
    connector="0x23 (No separable connector)", types=["Passive Cable"],
    copper_length=3, compliance=PASSIVE_CU)
SFP_25G_DAC = sfp(connector="0x21 (Copper pigtail)",
                  types=["Passive Cable", "Extended: 25G Base-CR CA-N"],
                  copper_length=2, compliance=PASSIVE_CU)
SFP_1000BASE_T = sfp(connector="0x22 (RJ45)", types=["Ethernet: 1000BASE-T"],
                     copper_length=100, wavelength=0)
SFP_10GBASE_T = sfp(
    connector="0x22 (RJ45)",
    types=["Extended: 10Gbase-T with SFI electrical interface"],
    copper_length=30, wavelength=0)
# Byte 8 bit 3 ("Active Cable") is set for an active optical cable as well,
# and ethtool then prints the copper compliance line whatever the medium.
SFP28_AOC = sfp(connector="0x23 (No separable connector)",
                types=["Active Cable", AOC_25G], compliance=ACTIVE_CU,
                dom=(-2.1, -1.4, 6.2, 41.0, 3.31))
# A 10G SFP+ AOC has no extended code: only its DOM says it carries light.
SFP_10G_AOC = sfp(connector="0x23 (No separable connector)",
                  types=["Active Cable"], compliance=ACTIVE_CU,
                  dom=(-2.6, -1.9, 5.8, 39.0, 3.3))
# An active copper cable prints the same identity lines and no light.
SFP_10G_ACC = sfp(connector="0x23 (No separable connector)",
                  types=["Active Cable"], copper_length=7,
                  compliance=ACTIVE_CU)
SFP_10G_SR = sfp(connector="0x07 (LC)",
                 types=["10G Ethernet: 10G Base-SR"],
                 dom=(-2.4, -2.2, 6.0, 36.0, 3.29))


# --------------------------------------------------------------------------
# SFF-8636 (qsfp.c): QSFP+, QSFP28
# --------------------------------------------------------------------------

def qsfp(*, connector, types, technology, identifier="0x11 (QSFP28)",
         rx=None, tx=None, bias=6.5, temperature=38.0, voltage=3.29,
         copper_length=0, attenuation=False, tables=None, flags=None,
         rx_label="Rcvr signal avg optical power", rx_blank="",
         vendor_pn="ACME-QSFP"):
    """One SFF-8636 dump.

    Without rx the module has no monitors: ethtool prints the temperature
    and voltage lines only (0.00 / 0.0000 for a cable) and stops.  v6.1
    prints the receive label without a blank before "(Channel"; rx_blank
    " " gives the spelling of later releases.
    """
    out = [
        line("Identifier", identifier),
        line("Extended identifier", "0xcc"),
        line("Connector", connector),
        line("Transceiver codes",
             "0x80 0x00 0x00 0x00 0x00 0x00 0x00 0x00"),
    ]
    out += [line("Transceiver type", item) for item in types]
    out += [
        line("Encoding", "0x05 (64B/66B)"),
        line("BR, Nominal", "25500Mbps"),
        line("Rate identifier", "0x00"),
        line("Length (SMF,km)", "0km"),
        line("Length (OM3 50um)", "0m"),
        line("Length (OM2 50um)", "0m"),
        line("Length (OM1 62.5um)", "0m"),
        line("Length (Copper or Active cable)", f"{copper_length}m"),
        line("Transmitter technology", technology),
    ]
    if attenuation:
        out += [line("Attenuation at 2.5GHz", "4db"),
                line("Attenuation at 5.0GHz", "6db"),
                line("Attenuation at 7.0GHz", "8db"),
                line("Attenuation at 12.9GHz", "11db")]
    else:
        out += [line("Laser wavelength", "850.000nm"),
                line("Laser wavelength tolerance", "15.000nm")]
    out += identity(vendor_pn)
    out += [line("Module temperature", celsius(temperature)),
            line("Module voltage", volts(voltage))]
    if rx is None:
        return "\n".join(out) + "\n"
    biases = bias if isinstance(bias, list) else [bias] * len(rx)
    tx = tx if tx is not None else [None] * len(rx)
    out.append(line("Alarm/warning flags implemented", "Yes"))
    for channel, value in enumerate(biases, start=1):
        out.append(line(f"Laser tx bias current (Channel {channel})",
                        milliamps(value)))
    for channel, value in enumerate(tx, start=1):
        out.append(line(f"Transmit avg optical power (Channel {channel})",
                        power(value)))
    for channel, value in enumerate(rx, start=1):
        out.append(line(f"{rx_label}{rx_blank}(Channel {channel})",
                        power(value)))
    for channel in range(1, len(rx) + 1):
        for key, words in KINDS:
            state = "On" if (flags or {}).get((channel, key)) else "Off"
            out.append(line("Laser bias current %-12s (Chan %d)"
                            % (words, channel), state))
    return "\n".join(out + threshold_lines(tables)) + "\n"


SR4_RX = [-1.2, -0.9, -1.5, -1.1]
SR4_TX = [-0.8, -0.6, -1.0, -0.9]
SR4_BIAS = [6.7, 6.8, 6.6, 6.9]
QSFP28_SR4 = qsfp(connector="0x0c (MPO Parallel Optic)",
                  types=["100G Ethernet: 100G Base-SR4"],
                  technology="0x00 (850 nm VCSEL)", rx=SR4_RX, tx=SR4_TX,
                  bias=SR4_BIAS)
QSFP28_DAC = qsfp(
    connector="0x23 (No separable connector)",
    types=["100G Ethernet: 100G Base-CR4 or 25G Base-CR CA-L"],
    technology="0xa0 (Copper cable unequalized)", copper_length=2,
    attenuation=True, temperature=0.0, voltage=0.0)
QSFP_40G_DAC = qsfp(
    identifier="0x0d (QSFP+)", connector="0x23 (No separable connector)",
    types=["40G Ethernet: 40G Base-CR4"],
    technology="0xa0 (Copper cable unequalized)", copper_length=1,
    attenuation=True, temperature=0.0, voltage=0.0)
# A cable with a temperature sensor: qsfp.c then prints every channel line,
# all of them zero.
QSFP28_DAC_WITH_SENSOR = qsfp(
    connector="0x23 (No separable connector)",
    types=["100G Ethernet: 100G Base-CR4 or 25G Base-CR CA-L"],
    technology="0xa0 (Copper cable unequalized)", copper_length=2,
    attenuation=True, temperature=31.0, voltage=3.3,
    rx=[None] * 4, tx=[None] * 4, bias=0.0)
QSFP28_AOC_TYPE = ("100G Ethernet: 100G AOC or 25GAUI C2M AOC with worst "
                   "BER of 5x10^(-5)")


def qsfp28_aoc(rx=SR4_RX, tx=SR4_TX, bias=SR4_BIAS, **kwargs):
    return qsfp(connector="0x23 (No separable connector)",
                types=[QSFP28_AOC_TYPE], technology="0x00 (850 nm VCSEL)",
                copper_length=10, rx=rx, tx=tx, bias=bias, **kwargs)


QSFP28_AOC = qsfp28_aoc()
# 40G QSFP+ AOC: "Active Cable" in the type, optical transmitter technology.
QSFP_40G_AOC = qsfp(
    identifier="0x0d (QSFP+)", connector="0x23 (No separable connector)",
    types=["40G Ethernet: 40G Active Cable (XLPPI)"],
    technology="0x00 (850 nm VCSEL)", copper_length=5, rx=SR4_RX, tx=SR4_TX,
    bias=SR4_BIAS)


# --------------------------------------------------------------------------
# CMIS (cmis.c): QSFP-DD, OSFP, QSFP112
# --------------------------------------------------------------------------

OSFP = "0x19 (OSFP 8X Pluggable Transceiver)"
QSFP_DD = "0x18 (QSFP-DD Double Density 8X Pluggable Transceiver (INF-8628))"
# v6.1 has no name for the QSFP112-class identifier byte.
QSFP112 = "0x1e (reserved or unknown)"

TWIN = {
    "bias": limits(400.0, 380.0, 15.0, 10.0),
    "tx_power": limits(6.0, 5.0, -3.9, -4.9),
    "temperature": limits(80.0, 70.0, 0.0, -10.0),
    "voltage": limits(3.5, 3.465, 3.135, 3.1),
    "rx_power": limits(6.5, 5.5, -7.4, -8.4),
}
TWIN_RX = [1.04, 1.50, 2.60, 2.00, 1.20, 1.90, 2.20, 2.40]
TWIN_TX = [0.98, 1.20, 2.00, 1.50, 1.10, 1.70, 1.30, 1.90]


def cmis(rx=TWIN_RX, tx=TWIN_TX, *, identifier=OSFP,
         connector="0x28 (MPO 1x12)",
         technology="0x06 (1310 nm EML)", temperature=45.0, voltage=3.2734,
         bias=212.7, tables=TWIN, flags=None, attenuation=False,
         rx_label="Rcvr signal avg optical power", vendor_pn="ACME-OSFP"):
    """One CMIS dump; rx None leaves the channel monitors out (a cable).

    flags: {(channel, "low_alarm"): True} for the bias flag lines, printed
    with cmis.c's "(Chan %d)" spelling.
    """
    out = [
        line("Identifier", identifier),
        line("Power class", "6"),
        line("Max power", "17.00W"),
        line("Connector", connector),
        line("Cable assembly length", "0.00m"),
        line("Tx CDR bypass control", "No"),
        line("Rx CDR bypass control", "No"),
        line("Tx CDR", "Yes"),
        line("Rx CDR", "Yes"),
        line("Transmitter technology", technology),
    ]
    if attenuation:
        out += [line("Attenuation at 5GHz", "5db"),
                line("Attenuation at 7GHz", "7db"),
                line("Attenuation at 12.9GHz", "10db"),
                line("Attenuation at 25.8GHz", "17db")]
    else:
        out += [line("Laser wavelength", "1311.000nm"),
                line("Laser wavelength tolerance", "6.500nm")]
    out += identity(vendor_pn)
    out += [line("Revision compliance", "Rev. 5.0"),
            line("Module State", "0x03 (ModuleReady)")]
    if temperature is not None:
        out.append(line("Module temperature", celsius(temperature)))
    if voltage is not None:
        out.append(line("Module voltage", volts(voltage)))
    if rx is None:
        return "\n".join(out) + "\n"
    biases = bias if isinstance(bias, list) else [bias] * len(rx)
    for channel, value in enumerate(biases, start=1):
        out.append(line(f"Laser tx bias current (Channel {channel})",
                        milliamps(value)))
    for channel, value in enumerate(tx, start=1):
        out.append(line(f"Transmit avg optical power (Channel {channel})",
                        power(value)))
    for channel, value in enumerate(rx, start=1):
        out.append(line(f"{rx_label} (Channel {channel})", power(value)))
    if flags is not None:
        for channel in range(1, len(rx) + 1):
            for key, words in KINDS:
                state = "On" if flags.get((channel, key)) else "Off"
                out.append(line("Laser bias current %-12s (Chan %d)"
                                % (words, channel), state))
    return "\n".join(out + threshold_lines(tables)) + "\n"


CMIS_DAC = cmis(rx=None, identifier=QSFP_DD,
                connector="0x23 (No separable connector)",
                technology="0x0a (Copper cable, unequalized)",
                attenuation=True, temperature=0.0, voltage=0.0, tables=None)
CMIS_AOC = cmis(identifier=QSFP_DD,
                connector="0x23 (No separable connector)",
                technology="0x00 (850 nm VCSEL)")


def with_lane(values, lane, value):
    out = list(values)
    out[lane - 1] = value
    return out


def buggy_cmis_flags(lane, key="low_alarm", channels=8):
    """What ethtool prints for one flag bit with the "& chan" mask.

    cmis.c tests the flag byte against the 0-based channel index instead of
    the channel's bit, so the bit of lane 1 shows up on channels 2, 4, 6, 8.
    """
    byte = 1 << (lane - 1)
    return {(channel, key): bool(byte & (channel - 1))
            for channel in range(1, channels + 1)}


NO_DATA = "No transceiver data\n"


def device_file(blocks):
    """blocks: [(interface, operstate or None, block body)], collector order."""
    out = ["=== OPTICAL DIAGNOSTICS ==="]
    for interface, state, body in blocks:
        out.append(f"--- Interface: {interface}")
        if state is not None:
            out.append(f"Interface state: {state}")
        out.append(body.rstrip("\n"))
    return "\n".join(out) + "\n"


class OpticalFileTestCase(unittest.TestCase):
    """Runs collector-format files through the real per-device worker."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "optical-data").mkdir()
        optical._parse_worker_analyzer = OpticalAnalyzer(
            str(self.root), load_history=False)
        self.worker = optical._parse_worker_analyzer
        self.parent = OpticalAnalyzer(str(self.root), load_history=False)
        self.collections = 0

    def classify(self, blocks, hostname="leaf1"):
        """One collection of one device: ops merged into the parent too."""
        sample = self.root / "optical-data" / f"{hostname}_optical.txt"
        sample.write_text(device_file(blocks))
        # Every call is a new collection: the worker skips a file whose
        # modification time it has already merged.
        self.collections += 1
        stamp = 1_700_000_000 + 600 * self.collections
        os.utime(sample, (stamp, stamp))
        ops, failures, shard_error = optical._classify_optical_file(
            str(sample), hostname)
        self.assertIsNone(shard_error)
        optical._merge_optical_ops(self.parent, hostname, ops)
        return ops, failures

    def rows(self, blocks, hostname="leaf1"):
        """{interface: current stats} of the rows the file produced."""
        self.parent.current_optical_stats = {}
        self.classify(blocks, hostname)
        return {port.split(":", 1)[1]: stats
                for port, stats in self.parent.current_optical_stats.items()}

    def anomalies(self):
        return self.parent.detect_optical_anomalies()

    def messages(self, port=None):
        return [item["message"] for item in self.anomalies()
                if port is None or port in (item.get("ports")
                                            or [item["port"]])]

    def export_rows(self):
        summary = self.parent.get_optical_summary()
        return {row["interface"]: row for row in self.parent.build_export_rows(
            summary, self.parent.detect_optical_anomalies())}

    def publish(self):
        """(page, {port: detail}) of the report the parent writes."""
        output = self.root / "optical-analysis.html"
        self.parent.export_optical_data_for_web(str(output))
        details = {}
        for path in sorted((self.root / "optical-details").glob("*.json")):
            details.update(json.loads(path.read_text())["ports"])
        return output.read_text(), details

    def shard(self, hostname="leaf1"):
        return json.loads(
            (self.root / "optical-history" / f"{hostname}.json").read_text())

    @staticmethod
    def page_function(page, name):
        start = page.index(f"function {name}(")
        depth = 0
        for index in range(page.index("{", start), len(page)):
            if page[index] == "{":
                depth += 1
            elif page[index] == "}":
                depth -= 1
                if depth == 0:
                    return page[start:index + 1]
        raise AssertionError(f"{name} is not closed")

    def render_panel(self, page, port, data):
        """The expanded detail row, rendered by the page's own script."""
        script = "\n".join(
            self.page_function(page, name)
            for name in ("esc", "laneText", "renderDetailPanel")
        ) + """
const data = JSON.parse(require('fs').readFileSync(0, 'utf8'));
let rendered = '';
const document = { createElement: () => ({}) };
const row = {
    dataset: { port: data.port },
    classList: { add() {} },
    after(detail) { rendered = detail.innerHTML; },
};
renderDetailPanel(row, data.detail);
process.stdout.write(rendered);
"""
        result = subprocess.run(
            ["node", "-e", script],
            input=json.dumps({"port": port, "detail": data}),
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout
