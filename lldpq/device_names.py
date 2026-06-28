"""
device_names.py — canonical device-name spelling for consistent display.

Problem this solves: different report pages derive the device name from
different sources, which can disagree only in CASE:
  - LLDP Results / Topology use the operator-provided topology.dot spelling
    (e.g. "MEL01-DH21-ESW-LFF00901" or "tan-spine-01").
  - BGP / Optical / BER / Hardware / Flap / Logs pages use the monitor-results
    filename, which comes from the inventory (devices.yaml) and may be a
    different case.

This makes the analysis pages look inconsistent (UPPER on one page, lower on
another for the SAME switch). topology.dot is the operator's source of truth,
so we canonicalize every displayed device name to its dot spelling.

Generic & deployment-agnostic: no case is hardcoded. Whatever case the dot
uses is what gets shown (UPPER, lower, or mixed). Names not present in the dot
(hosts, oob, etc.) are returned unchanged. Display-only — never used for
matching, sorting, filtering or data keys.
"""

import os
import re

_CMAP = None  # lower(name) -> canonical spelling (per-process cache)

# Quoted device endpoints of a dot edge:  "DEV":"port" -- "DEV2":"port2"
_EDGE_RE = re.compile(r'"([^"]+)"\s*:\s*"[^"]*"\s*--\s*"([^"]+)"\s*:\s*"[^"]*"')
# Standalone node declaration:  "DEV" [ ... ]
_NODE_RE = re.compile(r'^\s*"([^"]+)"\s*\[')

_DOT_PATHS = (
    "/var/www/html/topology.dot",
    "topology.dot",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "topology.dot"),
)


def _load():
    global _CMAP
    if _CMAP is not None:
        return _CMAP
    m = {}
    for path in _DOT_PATHS:
        try:
            if not path or not os.path.exists(path):
                continue
            with open(path, "r", errors="ignore") as fh:
                text = fh.read()
            for a, b in _EDGE_RE.findall(text):
                m.setdefault(a.lower(), a)
                m.setdefault(b.lower(), b)
            for line in text.splitlines():
                node = _NODE_RE.match(line)
                if node:
                    m.setdefault(node.group(1).lower(), node.group(1))
            if m:
                break
        except Exception:
            pass
    _CMAP = m
    return m


def canonical(name):
    """Return the topology.dot spelling for `name` (case-insensitive lookup).

    Falls back to the original value when the dot is unavailable or the name is
    not a fabric device declared in the dot. Display-only.
    """
    if not name:
        return name
    return _load().get(str(name).lower(), name)
