#!/usr/bin/env python3
"""
Process collected duplicate IP/MAC data and generate the analysis page.

Reads monitor-results/dup-data/<host>_{dup,fdb,neigh}.txt (collected by monitor.sh)
and writes monitor-results/duplicate-analysis.html.

Copyright (c) 2024 LLDPq Project - MIT License
"""

import sys
from duplicate_analyzer import DuplicateAnalyzer


def main():
    analyzer = DuplicateAnalyzer("monitor-results")
    analyzer.parse_all()
    summary = analyzer.summary()

    output_file = "monitor-results/duplicate-analysis.html"
    analyzer.export_html(output_file)

    print("Duplicate analysis complete:")
    print("  Active IP duplicates : %d" % summary["ip_active"])
    print("  Quiesced IP dups     : %d" % summary["ip_quiesced"])
    print("  Confirmed MAC conflicts: %d" % summary["confirmed_mac_total"])
    print("  MAC DAD findings       : %d" % summary["mac_dad_total"])
    print("  Active MAC mobility    : %d" % summary["mac_mobility_active"])
    print("  MAC mobility signals   : %d" % summary["mac_mobility_total"])
    print("  APIPA endpoints      : %d (%d sightings)" % (
        summary["apipa_total"], summary["apipa_sightings"]))
    print("  VLANs with findings  : %d" % summary["vlans"])
    print("  Coverage              : %d/%d devices%s" % (
        summary["coverage_current"], summary["coverage_expected"],
        " (partial)" if summary["coverage_partial"] else "",
    ))
    if summary["coverage_failures"]:
        print("  Collection failures   : %d" % summary["coverage_failures"])
    if summary["disabled"]:
        print("  Dup-detect DISABLED  : %s" % ", ".join(summary["disabled"]))
    print("  -> %s" % output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
