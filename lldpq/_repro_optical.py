#!/usr/bin/env python3
"""Throwaway reproduction of the QSFP-DD unlit-lane grading bug."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from optical_analyzer import OpticalAnalyzer  # noqa: E402

SAMPLE = """\
        cable-type                  : Optical module
        supported-cable-length-smf  : 2.00km
        identifier                  : QSFP-DD Double Density 8X Pluggable Transceiver INF-8628
        vendor-name                 : NVIDIA
        vendor-pn                   : MMS1V00-WM
        pmd-type                    : ETH_400GBASE_CR8
        temperature                 : 43.94 degrees C
        voltage                     : 3.3015 V
        ch-1-rx-power               : 1.8909 mW / 2.77 dBm
        ch-2-rx-power               : 2.0075 mW / 3.03 dBm
        ch-3-rx-power               : 2.0394 mW / 3.10 dBm
        ch-4-rx-power               : 2.2239 mW / 3.47 dBm
        ch-5-rx-power               : 0.0000 mW / -inf dBm
        ch-6-rx-power               : 0.0000 mW / -inf dBm
        ch-7-rx-power               : 0.0000 mW / -inf dBm
        ch-8-rx-power               : 0.0000 mW / -inf dBm
        ch-1-tx-power               : 1.4868 mW / 1.72 dBm
        ch-2-tx-power               : 1.6850 mW / 2.27 dBm
        ch-3-tx-power               : 1.7249 mW / 2.37 dBm
        ch-4-tx-power               : 1.6002 mW / 2.04 dBm
        ch-5-tx-power               : 0.0000 mW / -inf dBm
        ch-6-tx-power               : 0.0000 mW / -inf dBm
        ch-7-tx-power               : 0.0000 mW / -inf dBm
        ch-8-tx-power               : 0.0000 mW / -inf dBm
        ch-1-tx-bias-current        : 70.000 mA
        ch-2-tx-bias-current        : 70.000 mA
        ch-3-tx-bias-current        : 70.000 mA
        ch-4-tx-bias-current        : 70.000 mA
        ch-5-tx-bias-current        : 0.000 mA
        ch-6-tx-bias-current        : 0.000 mA
        ch-7-tx-bias-current        : 0.000 mA
        ch-8-tx-bias-current        : 0.000 mA
"""

analyzer = OpticalAnalyzer("monitor-results", load_history=False)
analyzer.update_optical_stats("SW01:swp1", SAMPLE)
stats = analyzer.current_optical_stats["SW01:swp1"]
for key in ("health_status", "rx_power_dbm", "rx_power_lane", "tx_power_dbm",
            "tx_power_lane", "bias_current_ma", "bias_current_lane",
            "link_margin_db", "rx_power_lanes_dbm", "tx_power_lanes_dbm",
            "bias_current_lanes_ma"):
    print(f"{key:24} {stats.get(key)}")
summary = analyzer.get_optical_summary()
print("summary:", {k: (len(v) if isinstance(v, list) else v)
                   for k, v in summary.items()})
port = (summary["critical_ports"] or summary["good_ports"] or
        summary["excellent_ports"] or summary["warning_ports"] or
        summary["down_ports"])[0]
print("action:", analyzer.get_recommended_action(port))
for anomaly in analyzer.detect_optical_anomalies():
    print("anomaly:", anomaly["type"], "|", anomaly["message"], "|",
          anomaly["action"])
