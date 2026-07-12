#!/usr/bin/env python3
"""Named read-only audit packs for Ask-AI device diagnostics.

Each pack is an ordered list of (section, command) pairs collected in ONE SSH
session.  Every command must individually satisfy the Ask-AI read-only policy;
that is asserted at import time so any drift between these packs and
ai_command_policy fails loudly in tests.  :func:`build_compound` composes the
sentinel-labelled compound command entirely server-side — model text never
contributes shell.  :func:`analyze` turns the sectioned output into a
deterministic verdict dict; anything unparseable degrades to UNKNOWN (fail
closed).  Pure standard library.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Tuple

try:
    from ai_command_policy import validate_ai_readonly_command
except ImportError:  # imported outside WEB_ROOT (tests, CLI)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ai_command_policy import validate_ai_readonly_command


PACKS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "bgp": (
        ("bgp-summary", 'sudo vtysh -c "show bgp vrf all summary"'),
        ("bgp-failed", 'sudo vtysh -c "show bgp vrf all summary failed"'),
        ("route-summary", 'sudo vtysh -c "show ip route summary"'),
        ("frr-log", "sudo journalctl -u frr -p warning -n 80 --no-pager"),
    ),
    "evpn": (
        ("evpn-summary", 'sudo vtysh -c "show bgp l2vpn evpn summary"'),
        ("vni", 'sudo vtysh -c "show evpn vni"'),
        ("nv-evpn", "nv show evpn"),
        ("vxlan-links", "ip link show type vxlan"),
    ),
    "optical": (
        ("transceivers", "nv show platform transceiver"),
        ("interfaces", "nv show interface"),
        ("carrier-log", "sudo journalctl -k -g 'Link is' -n 100 --no-pager"),
    ),
    "mtu-path": (
        ("links-mtu", "ip link show"),
        ("routes-v4", "ip route show"),
        ("neighbors", "ip neigh show"),
        ("lldp-peers", "lldpctl -f keyvalue"),
    ),
    "pfc": (
        ("roce-config", "nv show qos roce"),
        ("qos-config-lines", "nv config find qos"),
        ("pfc-watchdog-log", "sudo journalctl -g pfc -n 50 --no-pager"),
    ),
    "hardware": (
        ("sensors", "sudo smonctl"),
        ("resources", "sudo cl-resource-query"),
        ("syseeprom", "sudo decode-syseeprom"),
        ("memory", "free -m"),
        ("root-disk", "df -h /"),
        ("kernel-log", "sudo dmesg -T --level=err,warn"),
    ),
}

_PACK_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,23}")
_SECTION_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,31}")

# Import-time validation: a pack command that drifts out of the read-only
# policy must fail loudly here (and in tests), never at request time.
for _pack, _entries in PACKS.items():
    assert _PACK_NAME_RE.fullmatch(_pack), "invalid audit pack name %r" % _pack
    assert _entries, "audit pack %s is empty" % _pack
    _names = [name for name, _cmd in _entries]
    assert len(set(_names)) == len(_names), (
        "audit pack %s has duplicate section names" % _pack
    )
    for _name, _cmd in _entries:
        assert _SECTION_NAME_RE.fullmatch(_name), (
            "audit pack %s has invalid section name %r" % (_pack, _name)
        )
        _ok, _why = validate_ai_readonly_command(_cmd)
        assert _ok, (
            "audit pack %s section %s rejected by read-only policy: %s"
            % (_pack, _name, _why)
        )


def build_compound(pack: str) -> str:
    """Compose the one-session compound command with self-labelling sentinels.

    Sections are chained with ';' so one failing command never hides the
    rest; per-section RC sentinels let :func:`analyze` distinguish a failed
    command from a genuinely quiet one.
    """
    entries = PACKS.get(pack)
    if not entries:
        raise ValueError("unknown audit pack: %r" % (pack,))
    parts = []
    for name, command in entries:
        parts.append(
            'echo "===SECTION %s==="; %s; echo "===RC %s $?==="'
            % (name, command, name)
        )
    return "; ".join(parts)


# Deterministic per-section checks. kinds:
#   confirm -> hard problem signal, warn -> soft problem signal,
#   clean   -> positive evidence,    absent -> feature-off limitation.
# Patterns must not use capturing groups (re.findall counts hits).
_RULES: Dict[str, Tuple[Dict[str, str], ...]] = {
    "bgp": (
        {
            "section": "bgp-summary",
            "kind": "confirm",
            "pattern": r"(?m)^\S+\s+4\s+\d+.*\b(?:Idle|Active|Connect|OpenSent|OpenConfirm)\b",
            "signal": "BGP peer not in Established state",
        },
        {
            "section": "bgp-summary",
            "kind": "clean",
            "pattern": r"(?m)^Total number of neighbors \d+",
            "signal": "BGP neighbor table readable",
        },
        {
            "section": "bgp-summary",
            "kind": "absent",
            "pattern": r"(?im)% ?BGP (?:instance )?not (?:found|running)",
            "signal": "BGP is not configured on this device",
        },
        {
            "section": "bgp-failed",
            "kind": "confirm",
            "pattern": r"(?m)^\S+\s+4\s+\d+.*\b(?:Idle|Active|Connect|OpenSent|OpenConfirm)\b",
            "signal": "failed BGP session listed",
        },
        {
            "section": "frr-log",
            "kind": "warn",
            "pattern": r"(?im)\b(?:hold timer expire\w*|notification|nexthop.*unreachable|error)\b",
            "signal": "recent FRR warnings/errors in journal",
        },
    ),
    "evpn": (
        {
            "section": "evpn-summary",
            "kind": "confirm",
            "pattern": r"(?m)^\S+\s+4\s+\d+.*\b(?:Idle|Active|Connect|OpenSent|OpenConfirm)\b",
            "signal": "EVPN peer not in Established state",
        },
        {
            "section": "evpn-summary",
            "kind": "absent",
            "pattern": r"(?im)% ?(?:BGP (?:instance )?not (?:found|running)|No BGP neighbors found)",
            "signal": "EVPN address-family not active on this device",
        },
        {
            "section": "vni",
            "kind": "clean",
            "pattern": r"(?im)^\s*\d+\s+L[23]\b",
            "signal": "EVPN VNIs present",
        },
        {
            "section": "vxlan-links",
            "kind": "clean",
            "pattern": r"(?m)\bvxlan\b",
            "signal": "VXLAN kernel interfaces present",
        },
    ),
    "optical": (
        {
            "section": "transceivers",
            "kind": "confirm",
            "pattern": r"(?im)\brx[-_ ]?los\b|\btx[-_ ]?fault\b",
            "signal": "transceiver rx-los/tx-fault flagged",
        },
        {
            "section": "transceivers",
            "kind": "warn",
            "pattern": r"(?im)\b(?:high|low)[- ]alarm\b",
            "signal": "transceiver DOM alarm threshold crossed",
        },
        {
            "section": "transceivers",
            "kind": "clean",
            "pattern": r"(?im)\b(?:vendor|cable-type|identifier)\b",
            "signal": "transceiver inventory readable",
        },
        {
            "section": "carrier-log",
            "kind": "warn",
            "pattern": r"Link is [Dd]own",
            "signal": "recent link-down kernel events",
        },
    ),
    "mtu-path": (
        {
            "section": "links-mtu",
            "kind": "warn",
            "pattern": r"(?m)\bNO-CARRIER\b",
            "signal": "admin-up interface without carrier",
        },
        {
            "section": "links-mtu",
            "kind": "clean",
            "pattern": r"(?m)\bmtu \d+",
            "signal": "per-interface MTU values readable",
        },
        {
            "section": "routes-v4",
            "kind": "warn",
            "pattern": r"(?m)^(?:unreachable|blackhole)\b",
            "signal": "unreachable/blackhole route installed",
        },
        {
            "section": "lldp-peers",
            "kind": "clean",
            "pattern": r"(?m)^lldp\.",
            "signal": "LLDP neighbor data readable",
        },
    ),
    "pfc": (
        {
            "section": "roce-config",
            "kind": "clean",
            "pattern": r"(?im)\b(?:lossless|lossy|roce)\b",
            "signal": "RoCE/QoS mode readable",
        },
        {
            "section": "pfc-watchdog-log",
            "kind": "warn",
            "pattern": r"(?im)\b(?:watchdog|storm)\b",
            "signal": "PFC watchdog/storm events in journal",
        },
        {
            "section": "qos-config-lines",
            "kind": "clean",
            "pattern": r"(?im)\bqos\b",
            "signal": "QoS configuration lines present",
        },
    ),
    "hardware": (
        {
            "section": "sensors",
            "kind": "confirm",
            "pattern": r"(?im)\b(?:crit\w*|fail\w*|bad)\b",
            "signal": "sensor reports critical/failed state",
        },
        {
            "section": "sensors",
            "kind": "warn",
            "pattern": r"(?im)\babsent\b",
            "signal": "sensor/module reported absent",
        },
        {
            "section": "sensors",
            "kind": "clean",
            "pattern": r"(?im)\bok\b",
            "signal": "sensors reporting OK",
        },
        {
            "section": "kernel-log",
            "kind": "warn",
            "pattern": r"(?im)\b(?:error|fail\w*|panic|oom)\b",
            "signal": "kernel errors/warnings logged",
        },
        {
            "section": "root-disk",
            "kind": "warn",
            "pattern": r"(?m)\b(?:9\d|100)%",
            "signal": "root filesystem nearly full",
        },
        {
            "section": "resources",
            "kind": "warn",
            "pattern": r"(?m)\b(?:9\d|100)(?:\.\d+)?%",
            "signal": "ASIC resource table above 90% utilization",
        },
    ),
}

for _pack, _pack_rules in _RULES.items():
    assert _pack in PACKS, "rules refer to unknown pack %r" % _pack
    for _rule in _pack_rules:
        assert _rule["section"] in {name for name, _cmd in PACKS[_pack]}, (
            "rule for %s names unknown section %r" % (_pack, _rule["section"])
        )
        assert _rule["kind"] in {"confirm", "warn", "clean", "absent"}
        assert re.compile(_rule["pattern"]).groups == 0, (
            "rule pattern for %s/%s must not capture" % (_pack, _rule["section"])
        )

_SECTION_RE = re.compile(
    r"===SECTION ([a-z0-9-]+)===\n(.*?)===RC \1 (\d+)===", re.DOTALL
)
_SECTION_MARKER_RE = re.compile(r"===SECTION ([a-z0-9-]+)===")


def _parse_sections(output: Any) -> Dict[str, Dict[str, Any]]:
    """Slice sentinel-labelled output into {section: {rc, body}}."""
    # ssh -tt delivers CRLF line endings; normalize before matching.
    text = str(output or "").replace("\r\n", "\n").replace("\r", "\n")
    sections: Dict[str, Dict[str, Any]] = {}
    for match in _SECTION_RE.finditer(text):
        sections[match.group(1)] = {
            "rc": int(match.group(3)),
            "body": match.group(2),
        }
    # A SECTION marker without its RC sentinel means the pack was cut off
    # (timeout/disconnect) inside that command; keep it visible as rc=None.
    for marker in _SECTION_MARKER_RE.finditer(text):
        sections.setdefault(marker.group(1), {"rc": None, "body": ""})
    return sections


def analyze(pack: str, sectioned_output: Any) -> Dict[str, Any]:
    """Deterministic verdict for one pack's sectioned output (fail closed)."""
    tool = "audit-pack:%s" % pack
    if pack not in PACKS:
        return {
            "tool": tool,
            "verdict": "UNKNOWN",
            "confidence": "low",
            "signals": [],
            "limitations": ["unknown audit pack"],
        }
    try:
        sections = _parse_sections(sectioned_output)
    except Exception:
        sections = {}
    if not sections:
        return {
            "tool": tool,
            "verdict": "UNKNOWN",
            "confidence": "low",
            "signals": [],
            "limitations": [
                "output contains no section sentinels (transport error or truncated)"
            ],
        }

    expected = [name for name, _cmd in PACKS[pack]]
    signals: List[str] = []
    limitations: List[str] = []
    confirmed = warned = clean = 0
    ok_sections = 0
    for name in expected:
        entry = sections.get(name)
        if entry is None:
            limitations.append("section %s missing from output" % name)
            continue
        if entry["rc"] is None:
            limitations.append(
                "section %s has no RC sentinel (pack likely cut off)" % name
            )
            continue
        if entry["rc"] != 0:
            limitations.append(
                "section %s exited rc=%d (feature absent, unsupported command, "
                "or wrong device role)" % (name, entry["rc"])
            )
            continue
        ok_sections += 1
        body = entry["body"]
        for rule in _RULES.get(pack, ()):
            if rule["section"] != name:
                continue
            hits = re.findall(rule["pattern"], body)
            if not hits:
                continue
            kind = rule["kind"]
            if kind == "absent":
                limitations.append(rule["signal"])
                continue
            note = rule["signal"]
            if len(hits) > 1:
                note = "%s (x%d)" % (note, len(hits))
            if kind == "confirm":
                confirmed += 1
                signals.append(note)
            elif kind == "warn":
                warned += 1
                signals.append(note)
            else:
                clean += 1
                signals.append("ok: %s" % note)

    if confirmed:
        verdict = "CONFIRMED"
        confidence = "high" if (confirmed >= 2 or clean) else "medium"
    elif warned:
        verdict = "WARNING"
        confidence = "medium" if ok_sections > 1 else "low"
    elif ok_sections == 0:
        verdict = "UNKNOWN"
        confidence = "low"
    else:
        verdict = "CLEAN_OR_REVIEW"
        confidence = "high" if (ok_sections == len(expected) and clean) else "medium"

    return {
        "tool": tool,
        "verdict": verdict,
        "confidence": confidence,
        "signals": signals,
        "limitations": limitations,
    }


__all__ = ["PACKS", "analyze", "build_compound"]
