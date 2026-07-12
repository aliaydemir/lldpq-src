#!/usr/bin/env python3
"""Keyed runbook knowledge base for Ask-AI.

Deep Cumulus/EVPN/RoCE troubleshooting knowledge lives here instead of the
cached system prompt.  Only :func:`kb_digest` (a ~10 line catalog) belongs in
the prompt; :func:`kb_select` runs a deterministic alias-token matcher over
the operator question and returns just the matching section bodies, optionally
gated by observed fabric capabilities (a fabric without MLAG never receives
the MLAG runbook).  Pure standard library; no model calls, no I/O.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

KB_MAX_INJECT_CHARS = 8_000

# Each entry: (key, one_liner, alias_terms, capability_gates, body).
# alias_terms are matched against lowercase alphanumeric question tokens;
# multi-word terms match as adjacent tokens.  capability_gates name keys in
# the caller's fabric-capabilities dict; a section is skipped only when every
# gate key that is PRESENT is explicitly False (tri-state: unknown keeps it).
_SECTIONS: Tuple[Tuple[str, str, Tuple[str, ...], Tuple[str, ...], str], ...] = (
    (
        "ber-fec",
        "pre/post-FEC BER thresholds, grading, FEC-mismatch symptoms",
        (
            "ber", "fec", "prefec", "postfec", "codeword", "codewords",
            "snr", "serdes", "crc", "bit error", "bit errors",
            "symbol error", "symbol errors",
        ),
        (),
        """### KB ber-fec — BER / FEC grading on Cumulus (Spectrum)
Read: `l1-show swpX` (PHY detail) or `ethtool -S swpX` / `ethtool --show-fec swpX`.
Grading (RS-FEC / PAM4 50G-per-lane links):
- Effective (post-FEC) BER: must be ~0 (<1e-15). ANY rising uncorrectable codewords => CONFIRMED bad link (CRC/packet loss).
- Raw (pre-FEC) BER: <1e-8 healthy; 1e-8..1e-6 marginal (watch; clean/reseat at next window); >1e-6 failing, FEC near its correction limit.
- NRZ 25G lanes with RS-FEC: raw <1e-9 healthy; links running without FEC must show raw ~0.
- Corrected codewords rising slowly is normal at low raw BER; uncorrectable codewords ever increasing is not.
Flow: compare BOTH ends -> check DOM (rx/tx power, bias) -> reseat/clean optic -> swap cable, then optic. One bad lane out of 4/8 usually means connector debris on that lane.
FEC mode must match the link partner: 100G-CR4/SR4 = RS-FEC(528); 200G/400G PAM4 = RS-FEC(544) mandatory. A mismatch shows as up/down flapping or a storm of symbol errors right after link-up.""",
    ),
    (
        "link-down",
        "l1-show port down-reason codes and next steps",
        (
            "flap", "flaps", "flapping", "carrier", "linkdown",
            "link down", "down reason", "no carrier", "link failure",
        ),
        (),
        """### KB link-down — decoding port down reasons
`l1-show swpX` prints an explicit Port Down Reason. Common codes:
- No cable / Cable is unplugged: nothing detected in the cage; verify seating and inventory.
- Signal not detected: cable present but no light/level; check far-end TX, RX power in DOM, dead optic, fiber polarity.
- Bad signal integrity: raw BER too high to achieve lock; dirty/damaged cable or wrong FEC mode.
- Autoneg failure: speed/FEC negotiation mismatch; pin both ends (`nv set interface swpX link speed|fec`) or fix the breakout profile.
- Remote fault: the FAR end reports its own failure; troubleshoot the peer port, not this one.
- Unsupported cable: module not accepted; check `sudo decode-syseeprom` and platform compatibility notes.
- Calibration failure: hardware/firmware level; retry, then RMA path.
Timeline: `sudo journalctl -k -g 'Link is' -n 100 --no-pager` shows flap history. Admin-down shows state DOWN with no carrier events — do not chase it as a fault.""",
    ),
    (
        "pfc-ecn",
        "RoCE lossless PFC/ECN expectations and bad patterns",
        (
            "pfc", "ecn", "roce", "rocev2", "dcqcn", "cnp", "lossless",
            "pause", "congestion", "qos", "buffer", "watchdog",
        ),
        (),
        """### KB pfc-ecn — RoCE lossless expectations (Spectrum)
Config read: `nv show qos roce`. Lossless mode => PFC on switch-priority 3, ECN/WRED on the lossless TC, CNP handled at priority 6.
Healthy under RoCE load: ECN marks increment steadily (early congestion signal); PFC pause frames stay small and near the congestion point only.
Bad patterns:
- Pause frames rising fabric-wide + throughput collapse => congestion spreading / victim flows; verify ECN thresholds are active end-to-end (host NICs included).
- PFC watchdog / storm log entries => a stuck queue; something downstream stopped draining (peer device or NIC firmware).
- Drops counted on the lossless TC => headroom/buffer misconfig or the peer is not honoring PFC; cable length vs headroom matters at 100G+.
- Lossless on some hops only: the dot1p->TC mapping must be identical on EVERY hop, including inter-switch links.
Counters: `ethtool -S swpX` prio3 pause tx/rx and per-TC drop/ECN counters.""",
    ),
    (
        "optic-dom",
        "transceiver DOM floors (rx/tx power, temp, bias)",
        (
            "dom", "ddm", "optic", "optics", "transceiver", "transceivers",
            "sfp", "sfp28", "qsfp", "qsfp28", "qsfp56", "osfp", "dbm",
            "rx power", "tx power", "light", "laser", "module",
        ),
        (),
        """### KB optic-dom — DOM floors and reading rules
Read: `ethtool -m swpX` (DOM values plus the module's own warn/alarm table) or `l1-show swpX`.
Rules of thumb (the module's alarm table wins when present):
- RX power (SR/short reach): 0..-5 dBm good; below -7 dBm warn; below about -9..-11 dBm alarm; -30/-40 dBm or '-inf' = NO light (far-end TX off, broken/dirty fiber, wrong polarity).
- TX power far below spec while bias current is normal => dying laser; near-zero bias => TX disabled or fault.
- Temperature: under ~70 C typical; 75-80 C+ alarm (airflow, cage density, high-power optic).
- Vcc ~3.3 V within +/-5%.
Per-lane spread: one lane more than ~3 dB below its siblings => dirty MPO connector on that lane. Always compare local RX against the peer's TX.
DAC/ACC copper exposes little or no DOM — missing DOM on copper is normal, never a fault by itself.""",
    ),
    (
        "evpn",
        "EVPN type-2/3/5 troubleshooting flows",
        (
            "evpn", "vxlan", "vni", "vtep", "l2vpn", "imet",
            "type 2", "type 3", "type 5", "mac mobility", "irb", "rmac",
            "arp suppression",
        ),
        ("evpn", "vxlan"),
        """### KB evpn — type-2/3/5 troubleshooting flow (FRR/Cumulus)
Order: underlay first. 1) `show bgp l2vpn evpn summary` — all peers Established. 2) VTEP reachability loopback-to-loopback. 3) `show evpn vni` — VNIs Up with the right local VTEP IP.
Type-2 (MAC/IP) — a host unreachable inside an L2VNI:
- Local side: is the MAC in `bridge fdb show` on the access port and the ARP/ND entry present?
- `show evpn mac vni <vni>`: local vs remote entries; a missing remote MAC means the ORIGIN leaf is not advertising (check its bridge/VLAN-to-VNI mapping).
- MAC mobility sequence climbing fast => duplicate MAC or L2 loop; FRR dup-addr detection may freeze the entry.
Type-3 (IMET) — BUM/ARP broken while known-unicast works:
- `show bgp l2vpn evpn route type multicast`: every remote VTEP must originate one per VNI; a missing one => that VTEP's VNI is down or route-targets filter it.
Type-5 (prefix) — inter-VRF or external routes missing:
- Needs symmetric IRB: L3VNI per tenant VRF on BOTH ends plus router-MAC. Check `show evpn rmac vni all` and `show bgp l2vpn evpn route type prefix`.
- Route received but not installed => VRF missing its L3VNI or a vni mapping mismatch.
RT/RD mismatches drop routes silently: when a route exists at the origin but not the receiver, compare route-targets (`nv show evpn`, per-VRF config) before blaming the fabric.""",
    ),
    (
        "mlag",
        "MLAG/clagd health checklist and split-brain signs",
        (
            "mlag", "clag", "clagd", "peerlink", "peer link", "split brain",
            "bond", "bonds", "lacp", "dual connected",
        ),
        ("mlag", "clag"),
        """### KB mlag — MLAG (clagd) health checks
`clagctl status` (or `nv show mlag`): verify in order:
1) Peerlink up and healthy; 2) backup IP active — it must ride out-of-band mgmt, never the peerlink; 3) roles agreed: exactly one primary;
4) bonds listed as dual-connected — a bond in 'conflicts' or single-connected means the pair disagrees (clag-id mismatch, LACP system-id, or member down);
5) conflict list: VLAN or MTU mismatch on the peerlink/bonds is the most common silent breaker.
Failure modes: peerlink loss WITH backup-ip down = split brain (both primary, duplicate MACs/ARP flaps). After reboot, clagd init-delay keeps bonds proto-down briefly — normal, not a fault.
Cross-check `cat /proc/net/bonding/<bond>`: the LACP partner system id must be identical on both MLAG members.""",
    ),
    (
        "breakout-speed",
        "breakout, speed, autoneg and FEC pitfalls",
        (
            "breakout", "autoneg", "auto neg", "lanes", "speed",
            "pam4", "nrz", "split port", "port split",
        ),
        (),
        """### KB breakout-speed — breakout / speed / autoneg pitfalls
- Breakout (`nv set interface swpX link breakout ...`) re-creates children swpXs0-3; config on the parent port does NOT migrate to them.
- Spectrum port groups: enabling breakout can force-disable the adjacent cage — a 'missing' neighbor port right after a breakout change is usually this, not a failure.
- All lanes of one cage must run the same per-lane speed; mixing 10G and 25G children fails.
- Speed mismatch symptoms: link stays down with 'Autoneg failure', or negotiates to an unexpected lower speed. For 25G/100G DAC pin speed AND FEC on both ends; optics often run with autoneg off entirely.
- PAM4 vs NRZ: 100G may be CR4/NRZ (4x25G) or CR2/CR1/PAM4; both ends must use the same PHY mode — a 100G link that refuses to come up between older and newer ASICs is usually this.
- After any change verify with `l1-show swpX`: speed, lane count, FEC mode, and the down reason if still down.""",
    ),
    (
        "mtu-fabric",
        "fabric MTU 9216 / jumbo end-to-end expectations",
        (
            "mtu", "9216", "jumbo", "jumbo frame", "jumbo frames", "mru",
            "l3 mtu", "fragment", "fragmentation", "black hole", "blackhole",
            "spectrumx", "spectrum x", "gb300",
        ),
        (),
        """### KB mtu-fabric — fabric MTU / jumbo expectations (SpectrumX / GB300)
Design norm: L2 MTU 9216 on every fabric-facing interface (leaf<->spine uplinks, peerlink, host bonds). VXLAN adds ~50B overhead, so the underlay must carry 9216+ or overlay frames silently fragment/drop.
Read: `nv show interface swpX link mtu`, `ip -d link show swpX`, or `cat /sys/class/net/swpX/mtu`.
Checkable rules:
- Every uplink and peerlink at 9216. A single hop left at 1500/9000 is the classic silent black-hole: small pings succeed while large RoCE/RDMA writes stall or drop.
- MTU must be symmetric on both ends of a link. A mismatch surfaces as clagd/LACP 'conflict' or as jumbo-only loss (small packets pass, iperf/RDMA stalls).
- L3/SVI (IRB) MTU must cover the VXLAN payload; a router MTU under 9216 breaks only the large EVPN type-5 flows.
- Host NIC MTU (GB300 ConnectX/BlueField) must match the leaf access port: a 9000 host into a 9216 fabric is fine, a 9216 host into a 1500 port is not.
Fast isolation: `ping -M do -s 8972 <peer>` across each hop — the first hop that fails names the offender.""",
    ),
    (
        "rail-topology",
        "rail symmetry, uplink ratios, subscription (SpectrumX/GB300)",
        (
            "rail", "rails", "rail optimized", "symmetry", "symmetric",
            "asymmetry", "asymmetric", "uplink", "uplinks", "oversubscription",
            "oversubscribed", "subscription", "clos", "fat tree",
            "fabric symmetry", "spectrumx", "spectrum x", "gb300", "gpu fabric",
        ),
        (),
        """### KB rail-topology — rail-optimized symmetry & uplink ratios (SpectrumX / GB300)
Rail-optimized GPU fabric: every GPU rail (NIC index) attaches to the SAME leaf position across all compute nodes; rails must stay symmetric. lldpq LLDP + speed data makes this checkable.
Checkable rules:
- Rail symmetry: for a given rail/NIC index, every node's link should land on the matching leaf. An outlier node cabled to the wrong leaf breaks rail locality (extra spine hops, congestion). Compare neighbor leaf per rail across nodes.
- Uplink-count symmetry: every leaf should have the SAME number of spine uplinks, each at the same speed. A leaf short an uplink (or slower) is oversubscribed vs its peers.
- Subscription ratio: sum(access bw) : sum(uplink bw). Non-blocking = 1:1; flag any leaf whose downlink:uplink deviates from the fabric norm.
- Spine fan-out symmetry: every spine reaches every leaf exactly once (per plane); a missing spine<->leaf link shows up as one leaf short an uplink.
- Speed uniformity: all uplinks at the design speed (400G/800G); a lone lower-speed uplink caps that leaf's fabric bandwidth.
Signal: asymmetry between otherwise-identical leaves. Read from the LLDP neighbor table plus interface speeds.""",
    ),
    (
        "roce-design",
        "measurable RoCE PFC/ECN/TC3 design norms & watermarks",
        (
            "roce", "rocev2", "pfc", "ecn", "wred", "tc3", "tc 3",
            "watermark", "watermarks", "headroom", "lossless", "dcqcn",
            "spectrumx", "spectrum x", "gb300",
        ),
        (),
        """### KB roce-design — RoCE/PFC/ECN design norms (SpectrumX / GB300)
Measurable lossless config expectations (`nv show qos roce`, `nv show qos`):
- RoCE data on switch-priority/TC 3 (dot1p 3); CNP on priority 6. The dot1p->TC mapping must be identical on EVERY hop, inter-switch links included.
- PFC enabled on TC3 only (the lossless class); other TCs stay drop/lossless-off. PFC on the wrong TC = no backpressure where it is actually needed.
- ECN/WRED (RED) active on TC3. Spectrum norm: min-threshold on the order of ~150KB, max-threshold in the ~1.5MB range, low max-drop-probability, so marks begin well before buffer exhaustion and DCQCN reacts early.
- Headroom/xoff sized to cable length + MTU; 100G+ long DACs need more. Too little headroom = drops under pause; too much = wasted buffer.
- Trust dot1p (or DSCP) end-to-end; a hop trusting L2 while the host marks DSCP loses the class.
Healthy telemetry: ECN marks climb under load, PFC pause stays small and local, zero drops on TC3. Fabric-wide rising pause or ANY TC3 drop = misconfig or a peer not honoring PFC.""",
    ),
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _normalize_tokens(text: Any) -> List[str]:
    return _TOKEN_RE.findall(str(text or "").lower())


def _section_matches(
    aliases: Sequence[str], token_set: set, normalized: str
) -> bool:
    for alias in aliases:
        if " " in alias:
            if " %s " % alias in " %s " % normalized:
                return True
        elif alias in token_set:
            return True
    return False


def _gated_off(gates: Sequence[str], fabric_caps: Optional[Mapping[str, Any]]) -> bool:
    """True only when every present gate capability is explicitly False."""
    if not gates or not isinstance(fabric_caps, Mapping):
        return False
    seen = [fabric_caps[key] for key in gates if key in fabric_caps]
    return bool(seen) and all(value is False for value in seen)


def kb_keys() -> Tuple[str, ...]:
    """Return the available section keys (for [KB: <keys>] tag validation)."""
    return tuple(key for key, _line, _aliases, _gates, _body in _SECTIONS)


def kb_digest() -> str:
    """Short catalog of available sections for the system prompt."""
    lines = [
        "Local runbook KB sections (auto-injected when the question matches; "
        "request explicitly with [KB: <keys>]):"
    ]
    for key, one_liner, _aliases, _gates, _body in _SECTIONS:
        lines.append("- %s: %s" % (key, one_liner))
    return "\n".join(lines)


def kb_select(
    question: str, fabric_caps: Optional[Mapping[str, Any]] = None
) -> List[str]:
    """Return matching section bodies for a question, bounded to ~8k chars."""
    tokens = _normalize_tokens(question)
    token_set = set(tokens)
    normalized = " ".join(tokens)
    selected: List[str] = []
    total = 0
    for key, _one_liner, aliases, gates, body in _SECTIONS:
        if key not in token_set and not _section_matches(
            aliases, token_set, normalized
        ):
            continue
        if _gated_off(gates, fabric_caps):
            continue
        if total + len(body) > KB_MAX_INJECT_CHARS:
            continue
        selected.append(body)
        total += len(body)
    return selected


# Content anchors: catch accidental section loss/bloat at import time so any
# drift fails loudly in tests rather than silently degrading answers.
for _key, _one_liner, _aliases, _gates, _body in _SECTIONS:
    assert re.fullmatch(r"[a-z0-9][a-z0-9-]{1,23}", _key), (
        "invalid KB section key %r" % _key
    )
    assert _aliases and _one_liner and _body.strip(), (
        "KB section %s is incomplete" % _key
    )
    assert len(_body) <= 1_600, "KB section %s exceeds its size budget" % _key
assert len({row[0] for row in _SECTIONS}) == len(_SECTIONS), "duplicate KB keys"
assert "1e-8" in dict((row[0], row[4]) for row in _SECTIONS)["ber-fec"]
assert len(kb_digest()) <= 1_200, "KB digest must stay prompt-sized"


__all__ = ["KB_MAX_INJECT_CHARS", "kb_digest", "kb_keys", "kb_select"]
