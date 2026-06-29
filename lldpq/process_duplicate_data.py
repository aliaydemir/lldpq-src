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
    print("  MAC duplicates       : %d" % summary["mac_total"])
    print("  APIPA addresses      : %d" % summary["apipa_total"])
    print("  VLANs affected       : %d" % summary["vlans"])
    if summary["disabled"]:
        print("  Dup-detect DISABLED  : %s" % ", ".join(summary["disabled"]))
    print("  -> %s" % output_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
