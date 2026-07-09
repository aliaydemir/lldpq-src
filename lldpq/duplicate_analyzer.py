#!/usr/bin/env python3
"""
Duplicate IP / MAC Analyzer for LLDPq

Fabric-wide detection of duplicate IPs and MACs in an EVPN/VXLAN OOB/in-band
network, grouped per VLAN/VNI. Combines several signals collected by monitor.sh
(per device, under monitor-results/dup-data/):

  * show evpn arp-cache vni all duplicate  -> authoritative duplicate IPs (+ EVPN seq)
  * show evpn mac vni all duplicate        -> duplicate MACs (when FRR latches them)
  * zebra log "detected as duplicate"      -> timestamped event history (recency + rate)
  * show evpn (duplicate-detection config) -> max-moves/time, enabled? (avoid false-negatives)
  * bridge fdb show                        -> same MAC LOCAL on >=2 switches (non-EVPN + location)
  * ip -4 neigh show                       -> APIPA (169.254/16 = DHCP failed) + IP<->multi-MAC

IP severity keeps authoritative DAD rows separate from historical context. MAC
severity additionally compares per-switch mobility samples against the configured
DAD move-rate policy; a small positive delta alone is not a CRITICAL conflict.

Copyright (c) 2024 LLDPq Project - MIT License
"""

import os
import re
import json
import html
import time
from datetime import datetime, timezone

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

try:
    from collection_freshness import asset_snapshot_is_valid, read_asset_snapshot
except Exception:
    asset_snapshot_is_valid = None
    read_asset_snapshot = None

MAC_RE = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SEQ_RE = re.compile(r'(\d+)\s*/\s*(\d+)\s*$')
LOG_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*[+\-]\d{2}:?\d{2})'
    r'.*?VNI\s+(?P<vni>\d+):\s+MAC\s+(?P<mac>[0-9a-fA-F:]+)\s+IP\s+(?P<ip>\S+)\s+'
    r'detected as duplicate.*?last VTEP\s+(?P<vtep>\S+)'
)

# Severity thresholds
ACTIVE_WINDOW_SEC = 3600       # a dup event within this window = actively flapping
APIPA_CRITICAL = 50            # APIPA neighbours on one switch >= this = critical
SEQ_WARN = 10                  # EVPN mobility seq >= this = the entry has moved at all (collection floor)
# A single-MAC, single-location, non-climbing mobility record is retained as history only when its
# sequence is this high. Incident counts still keep this separate from confirmed simultaneous MAC
# conflicts, so ordinary EVPN-MH churn cannot inflate the duplicate total.
SEQ_STORM = 10000
DEFAULT_DAD_MOVES = 5          # FRR default/fallback when per-switch policy is unavailable
DEFAULT_DAD_WINDOW_SEC = 180
MAC_OBSERVER_STATE_VERSION = 1
MAC_OBSERVER_STATE_TTL_SEC = 7 * 86400
LOOP_MIN_MACS = 10             # >= this many MACs flapping between the SAME endpoint pair (no dup IP) = likely L2 loop
STALE_AGE_SEC = 7 * 86400      # a quiesced dup whose EVPN sequence has not moved for this long = aged/stale
                               # (collapsed out of the main list; still available via the "aged" toggle)


def _parse_ts(s):
    """Parse an ISO8601 timestamp (with offset) into an aware datetime, or None."""
    try:
        return datetime.fromisoformat(s)
    except Exception:
        pass
    # Fallback: strip fractional seconds / normalise offset
    try:
        s2 = re.sub(r'\.\d+', '', s)
        return datetime.strptime(s2, '%Y-%m-%dT%H:%M:%S%z')
    except Exception:
        return None


class DuplicateAnalyzer:
    def __init__(self, data_dir="monitor-results"):
        self.data_dir = data_dir
        self.dup_dir = os.path.join(data_dir, "dup-data")
        self.state_file = os.path.join(self.dup_dir, "dup_seq_state.json")
        os.makedirs(self.dup_dir, exist_ok=True)

        self.vni_to_vlan = {}          # vni(str) -> vlan(str)
        self.dup_config = {}           # host -> {'enabled': bool, 'max_moves': int, 'time': int}
        self.ip_dups = {}              # (vlan, ip) -> record
        self.authoritative_ip_pairs = {}  # (vni, ip) -> hosts reporting current FRR duplicate
        self.mac_dups = {}             # (vlan, mac) -> record
        self.apipa = {}                # host -> {'total': int, 'per_vlan': {vlan: count}}
        self.fdb_local = {}            # (vlan, mac) -> {host -> port}
        self.if_desc = {}              # (host, port) -> interface description (ifalias)
        self.arp_pairs = {}            # (vlan, ip) -> {mac -> set(hosts)}
        self.mac_mob = {}              # (vlan, mac) -> {seq, seq_by_host, hosts, vteps, ports, vni}
        self.ip_mob = {}               # (vlan, ip)  -> {seq, macs, vteps, vni}
        self.log_events = {}           # (vni, ip) -> {'count': int, 'latest': dt, 'macs': set, 'vteps': set}
        self.log_events_mac = {}       # (vni, mac) -> {'count': int, 'latest': dt, 'vteps': set, 'ips': set}  (last VTEP = contender)
        self.self_vteps = {}           # host -> set(local VTEP ip)   ; used to resolve a VTEP IP -> switch name
        self.vtep2host = {}            # vtep ip -> host
        # Event age must be measured against a real clock.  Using the newest
        # line in the log as "now" made an entirely old log look current.
        self.analysis_now = datetime.now(timezone.utc)
        self.collection_meta = {}      # host -> collector timestamp/source status
        self.coverage = {
            "expected": set(), "current": set(), "mac_current": set(),
            "mac_dad_current": set(), "mac_mobility_current": set(),
            "fdb_current": set(),
            "failures": [], "partial": True,
        }
        self.prev_state = self._load_state()
        self.new_state = {}
        # Cross-cycle memory of each duplicate IP's owner ports + MACs (fast flappers rarely have
        # BOTH ends captured in one snapshot). Keyed "vlan|ip" -> {ports:{host:port}, macs:[], ts}.
        self.ip_state_file = os.path.join(self.dup_dir, "dup_ip_state.json")
        self.prev_ip_state = self._load_ip_state()
        self.new_ip_state = {}

    # ------------------------------------------------------------------ state
    def _load_state(self):
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_ip_state(self):
        try:
            with open(self.ip_state_file) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_state(self):
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.new_state, f)
        except Exception:
            pass
        try:
            with open(self.ip_state_file, "w") as f:
                json.dump(self.new_ip_state, f)
        except Exception:
            pass

    # ------------------------------------------------------------------ parse
    def _hosts(self):
        out = {}
        if not os.path.isdir(self.dup_dir):
            return out
        for fn in os.listdir(self.dup_dir):
            for suffix in ("_dup.txt", "_fdb.txt", "_neigh.txt"):
                if fn.endswith(suffix):
                    host = fn[: -len(suffix)]
                    out.setdefault(host, {})[suffix] = os.path.join(self.dup_dir, fn)
        return out

    def parse_all(self):
        for host, files in self._hosts().items():
            ch = canonical(host)
            self.collection_meta.setdefault(ch, {
                "timestamp": None, "sources": {}, "samples": {},
            })
            if "_dup.txt" in files:
                self._parse_dup(ch, self._read(files["_dup.txt"]))
            if "_fdb.txt" in files:
                fdb_read_ok, fdb_text = self._read_with_status(
                    files["_fdb.txt"]
                )
                # A successful FDB query may legitimately return no rows on
                # L3-only devices.  Section presence is guaranteed by the
                # validated collection bundle; only an explicit collector
                # error makes the sample unusable.
                fdb_ok = fdb_read_ok and \
                    "__LLDPQ_COLLECTION_ERROR__:FDB" not in fdb_text
                self.collection_meta[ch]["sources"]["FDB_LOCAL"] = (
                    "OK" if fdb_ok else "ERROR"
                )
                if fdb_ok:
                    self._parse_fdb(ch, fdb_text)
            if "_neigh.txt" in files:
                neigh_read_ok, neigh_text = self._read_with_status(
                    files["_neigh.txt"]
                )
                # An empty neighbour table is a valid current zero.  Only the
                # typed collector marker (or a local read failure) makes this
                # evidence unavailable.
                neigh_ok = neigh_read_ok and \
                    "__LLDPQ_COLLECTION_ERROR__:NEIGH" not in neigh_text
                self.collection_meta[ch]["sources"]["NEIGH"] = (
                    "OK" if neigh_ok else "ERROR"
                )
                if neigh_ok:
                    self._parse_neigh(ch, neigh_text)
        self._finalize_coverage()
        self._merge_arp_conflicts()
        self._finalize()

    @staticmethod
    def _read(path):
        _read_ok, content = DuplicateAnalyzer._read_with_status(path)
        return content

    @staticmethod
    def _read_with_status(path):
        try:
            with open(path, "r", errors="replace") as f:
                return True, f.read()
        except Exception:
            return False, ""

    def _split_sections(self, text):
        """Split a _dup.txt into the labelled sections."""
        sections = {}
        cur = None
        buf = []
        for line in text.splitlines():
            m = re.match(r'^===\s*DUP (VNI MAP|CONFIG|SELF|ARP|MAC|LOG|MACMOB|ARPMOB|IFALIAS)\s*===\s*$', line)
            if m:
                if cur is not None:
                    sections[cur] = buf
                cur = m.group(1)
                buf = []
            else:
                if cur is not None:
                    buf.append(line)
        if cur is not None:
            sections[cur] = buf
        return sections

    def _parse_dup(self, host, text):
        self._parse_collection_meta(host, text)
        sec = self._split_sections(text)
        self.collection_meta[host]["arp_section_present"] = "ARP" in sec
        self._parse_vni_map(sec.get("VNI MAP", []))
        self._parse_config(host, sec.get("CONFIG", []))
        self._parse_self(host, sec.get("SELF", []))
        # Only the explicit, successful FRR duplicate command is authoritative
        # for the IP-duplicate total.  Do not turn stale/pre-marker/error output
        # into a current duplicate.
        if self.collection_meta[host]["sources"].get("ARP_DUPLICATES") == "OK":
            self._parse_arp_dup(host, sec.get("ARP", []))
        if self.collection_meta[host]["sources"].get("MAC_DUPLICATES") == "OK":
            self._parse_mac_dup(host, sec.get("MAC", []))
        self._parse_log(sec.get("LOG", []))
        self._parse_mac_mobility(host, sec.get("MACMOB", []))
        self._parse_ip_mobility(host, sec.get("ARPMOB", []))
        self._parse_ifalias(host, sec.get("IFALIAS", []))

    def _parse_collection_meta(self, host, text):
        """Read the collector's explicit status markers without showing them."""
        meta = self.collection_meta.setdefault(host, {
            "timestamp": None, "sources": {}, "samples": {},
        })
        for line in text.splitlines():
            if line.startswith("__LLDPQ_DUP_COLLECTION_UTC__:"):
                value = line.split(":", 1)[1].strip()
                ts = _parse_ts(value) if value != "UNKNOWN" else None
                if ts is not None and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                meta["timestamp"] = ts
                continue
            match = re.fullmatch(
                r"__LLDPQ_DUP_COVERAGE__:([A-Z0-9_]+):(OK|ERROR|TRUNCATED)",
                line.strip(),
            )
            if match:
                meta["sources"][match.group(1)] = match.group(2)
                continue
            match = re.fullmatch(
                r"__LLDPQ_DUP_SAMPLE_META__:([A-Z0-9_]+):"
                r"MATCHES=([^:]+):EMITTED=([^:]+):CAP=([^:]+):TRUNCATED=([^:]+)",
                line.strip(),
            )
            if match:
                meta["samples"][match.group(1)] = {
                    "matches": match.group(2), "emitted": match.group(3),
                    "cap": match.group(4), "truncated": match.group(5),
                }

    def _finalize_coverage(self):
        """Summarize whether zero duplicates really means a complete sample."""
        expected = set(self.collection_meta)
        asset_statuses = {}
        snapshot_problem = None
        if read_asset_snapshot is not None and asset_snapshot_is_valid is not None:
            assets_path = os.path.join(
                os.path.dirname(os.path.abspath(self.data_dir)), "assets.ini"
            )
            snapshot = read_asset_snapshot(assets_path)
            statuses, _mtime, assets_available = snapshot
            if asset_snapshot_is_valid(snapshot):
                asset_statuses = {
                    canonical(host): status for host, status in statuses.items()
                }
                expected = set(asset_statuses)
            elif assets_available:
                snapshot_problem = "SNAPSHOT_INVALID"
            else:
                snapshot_problem = "SNAPSHOT_MISSING"
        else:
            snapshot_problem = "SNAPSHOT_UNAVAILABLE"

        try:
            max_age = max(float(os.environ.get("DUP_DATA_MAX_AGE_MINUTES", "30")), 0) * 60
        except ValueError:
            max_age = 30 * 60

        current = set()
        mac_current = set()
        mac_dad_current = set()
        mac_mobility_current = set()
        fdb_current = set()
        failures = []
        ip_required = ("ARP_DUPLICATES",)
        mac_required = ("MAC_DUPLICATES", "MAC_MOBILITY", "FDB_LOCAL")
        for host in sorted(expected):
            status = asset_statuses.get(host)
            if status is not None and status != "OK":
                failures.append("%s:ASSET_%s" % (host, status))
                continue

            meta = self.collection_meta.get(host)
            if not meta:
                failures.append("%s:COLLECTION_MISSING" % host)
                continue

            timestamp = meta.get("timestamp")
            timestamp_ok = timestamp is not None
            if timestamp is None and meta.get("sources", {}).get("COLLECTION_TIMESTAMP") == "OK":
                failures.append("%s:COLLECTION_TIME_INVALID" % host)
            if timestamp is not None:
                age = (self.analysis_now - timestamp).total_seconds()
                if age > max_age:
                    timestamp_ok = False
                    failures.append("%s:COLLECTION_STALE" % host)
                elif age < -300:
                    timestamp_ok = False
                    failures.append("%s:COLLECTION_TIME_FUTURE" % host)

            sources = meta.get("sources", {})
            collection_status = sources.get("COLLECTION_TIMESTAMP")
            base_ok = timestamp_ok and collection_status == "OK"
            if collection_status != "OK":
                failures.append("%s:COLLECTION_TIMESTAMP_%s" % (
                    host, collection_status or "MISSING",
                ))

            ip_ok = base_ok
            for source in ip_required:
                source_status = sources.get(source)
                if source_status != "OK":
                    ip_ok = False
                    failures.append("%s:%s_%s" % (
                        host, source, source_status or "MISSING",
                    ))
            if not meta.get("arp_section_present"):
                ip_ok = False
                failures.append("%s:ARP_SECTION_MISSING" % host)

            mac_ok = base_ok
            for source in mac_required:
                source_status = sources.get(source)
                if source_status != "OK":
                    mac_ok = False
                    failures.append("%s:%s_%s" % (
                        host, source, source_status or "MISSING",
                    ))

            # Neighbour evidence feeds APIPA and IP-to-multiple-MAC context.
            # Losing it does not invalidate authoritative FRR DAD/FDB evidence,
            # but zero findings for the combined report are necessarily partial.
            neighbour_status = sources.get("NEIGH")
            if neighbour_status != "OK":
                failures.append("%s:NEIGH_%s" % (
                    host, neighbour_status or "MISSING",
                ))

            if ip_ok:
                current.add(host)
            if base_ok and sources.get("MAC_DUPLICATES") == "OK":
                mac_dad_current.add(host)
            if base_ok and sources.get("MAC_MOBILITY") in ("OK", "TRUNCATED"):
                # Truncation makes zero incomplete, but each emitted row is
                # still valid positive mobility evidence.
                mac_mobility_current.add(host)
            if base_ok and sources.get("FDB_LOCAL") == "OK":
                fdb_current.add(host)
            if mac_ok:
                mac_current.add(host)

        # Inventory is the authority for expected devices.  Without a valid
        # snapshot we may parse rows for diagnostics, but must not publish a
        # trustworthy zero/current count.
        if snapshot_problem:
            failures.append("inventory:%s" % snapshot_problem)
            current.clear()
            mac_current.clear()
            mac_dad_current.clear()
            mac_mobility_current.clear()
            fdb_current.clear()

        failures = sorted(set(failures))
        self.coverage = {
            "expected": expected,
            "current": current,
            "mac_current": mac_current,
            "mac_dad_current": mac_dad_current,
            "mac_mobility_current": mac_mobility_current,
            "fdb_current": fdb_current,
            "failures": failures,
            "partial": bool(
                failures or current != expected or mac_current != expected
            ),
        }

    def _parse_vni_map(self, lines):
        for line in lines:
            p = line.split()
            if len(p) >= 8 and p[0].isdigit() and p[1] in ("L2", "L3"):
                self.vni_to_vlan[p[0]] = p[7]

    def _parse_config(self, host, lines):
        enabled, max_moves, t = None, None, None
        for line in lines:
            low = line.lower()
            if "duplicate address detection" in low:
                enabled = "enable" in low
            m = re.search(r'max-moves\s+(\d+),?\s+time\s+(\d+)', line, re.I)
            if m:
                max_moves, t = int(m.group(1)), int(m.group(2))
        if enabled is not None or max_moves is not None:
            self.dup_config[host] = {"enabled": bool(enabled), "max_moves": max_moves, "time": t}

    def _parse_self(self, host, lines):
        """This switch's own EVPN VTEP IP(s) -> lets us resolve a remote VTEP back to a switch name."""
        for line in lines:
            for ip in IPV4_RE.findall(line):
                self.self_vteps.setdefault(host, set()).add(ip)

    def _parse_ifalias(self, host, lines):
        """Interface descriptions ('nv set interface swpX description ...' = kernel ifalias),
        collected as 'port|description' lines. Lets each switch:port cell name the attached
        device -> which physical box is duplicating."""
        for line in lines:
            if "|" not in line:
                continue
            port, desc = line.split("|", 1)
            port, desc = port.strip(), desc.strip()
            if port and desc:
                self.if_desc[(host, port)] = desc

    def _vlan_of(self, vni):
        return self.vni_to_vlan.get(str(vni), str(vni))

    def _parse_arp_dup(self, host, lines):
        vni = None
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\s+#ARP', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Neighbor" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            neighbor = parts[0]
            if not (IPV4_RE.fullmatch(neighbor) or ":" in neighbor):
                continue
            mac_m = MAC_RE.search(line)
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            typ = "remote" if re.search(r'\bremote\b', line) else "local"
            ipv4s = [ip for ip in IPV4_RE.findall(line) if ip != neighbor]
            vtep = ipv4s[-1] if (typ == "remote" and ipv4s) else ""
            seq_m = SEQ_RE.search(line)
            seq = max(int(seq_m.group(1)), int(seq_m.group(2))) if seq_m else 0
            vlan = self._vlan_of(vni)
            rec = self.ip_dups.setdefault((vlan, neighbor), self._blank_ip(vlan, vni, neighbor))
            rec["macs"].add(mac)
            rec["authoritative_macs"].add(mac)
            rec["seq"] = max(rec["seq"], seq)
            rec["flagged"] = True
            rec["authoritative_hosts"].add(host)
            self.authoritative_ip_pairs.setdefault((str(vni), neighbor), set()).add(host)
            if typ == "local":
                rec["local_hosts"].add(host)
            if vtep:
                rec["vteps"].add(vtep)

    def _blank_ip(self, vlan, vni, ip):
        return {"vlan": vlan, "vni": str(vni), "ip": ip, "macs": set(), "seq": 0,
                "flagged": False, "local_hosts": set(), "vteps": set(),
                "authoritative_hosts": set(),
                "authoritative_macs": set(),
                "ports": set(), "apipa": False, "recency": None, "delta": None,
                "events": 0, "latest": None, "mobility": False}

    def _parse_mac_dup(self, host, lines):
        vni = None
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\s+#MAC', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Intf/Remote" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            mac_m = MAC_RE.match(line.strip())
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            typ = "remote" if re.search(r'\bremote\b', line) else "local"
            port_m = re.search(r'\b(swp\S+|bond\S+)\b', line)
            vtep_m = IPV4_RE.search(line)
            seq_m = SEQ_RE.search(line)
            seq = max(int(seq_m.group(1)), int(seq_m.group(2))) if seq_m else 0
            vlan = self._vlan_of(vni)
            rec = self.mac_dups.setdefault((vlan, mac), self._blank_mac(vlan, vni, mac))
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            rec["flagged"] = True
            rec["flagged_hosts"].add(host)
            if typ == "local" and port_m:
                rec["local"].setdefault(host, port_m.group(1))
            elif vtep_m:
                rec["vteps"].add(vtep_m.group(0))

    def _blank_mac(self, vlan, vni, mac):
        return {"vlan": vlan, "vni": str(vni), "mac": mac, "seq": 0,
                "seq_by_host": {}, "flagged": False, "flagged_hosts": set(),
                "dad_flagged": False, "dad_event": False,
                "local": {}, "vteps": set(),
                "delta": None, "fdb_multi": False, "physical_local_count": 0,
                "confirmed_conflict": False, "mobility": False,
                "mobility_only": False, "sequence_active": False,
                "seq_interval_sec": None, "seq_rate_per_min": None,
                "seq_activity_threshold": None, "seq_activity_window": None,
                "incident_type": "unknown", "activity": "settled",
                "participates_in_ip_conflict": False,
                "classification": "", "loop_count": 0}

    def _parse_log(self, lines):
        for line in lines:
            m = LOG_RE.search(line)
            if not m:
                continue
            ts = _parse_ts(m.group("ts"))
            vni = m.group("vni")
            ip = m.group("ip")
            mac = m.group("mac").lower()
            vtep = m.group("vtep")
            ev = self.log_events.setdefault((vni, ip), {"count": 0, "latest": None, "macs": set(), "vteps": set()})
            ev["count"] += 1
            ev["macs"].add(mac)
            ev["vteps"].add(vtep)
            evm = self.log_events_mac.setdefault((vni, mac), {"count": 0, "latest": None, "vteps": set(), "ips": set()})
            evm["count"] += 1
            evm["vteps"].add(vtep)
            evm["ips"].add(ip)
            if ts:
                for e in (ev, evm):
                    if e["latest"] is None or ts > e["latest"]:
                        e["latest"] = ts

    def _parse_mac_mobility(self, host, lines):
        """Parse non-zero-seq lines from 'show evpn mac vni all' (works even with DAD off)."""
        vni = None
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\b', line)
            if m:
                vni = m.group(1)
                continue
            if not vni:
                continue
            mac_m = MAC_RE.match(line.strip())
            seq_m = SEQ_RE.search(line)
            if not mac_m or not seq_m:
                continue
            seq = max(int(seq_m.group(1)), int(seq_m.group(2)))
            if seq < SEQ_WARN:
                continue
            mac = mac_m.group(0).lower()
            vlan = self._vlan_of(vni)
            rec = self.mac_mob.setdefault((vlan, mac),
                                          {"seq": 0, "seq_by_host": {}, "hosts": set(),
                                           "vteps": set(), "ports": {}, "vni": str(vni)})
            rec["seq"] = max(rec["seq"], seq)
            rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)
            rec["hosts"].add(host)
            port_m = re.search(r'\b(swp\S+|bond\S+)\b', line)
            vtep_m = IPV4_RE.search(line)
            if port_m and re.search(r'\blocal\b', line):
                rec["ports"][host] = port_m.group(1)
            elif vtep_m:
                rec["vteps"].add(vtep_m.group(0))

    def _parse_ip_mobility(self, host, lines):
        """Parse non-zero-seq lines from 'show evpn arp-cache vni all' (works even with DAD off)."""
        vni = None
        for line in lines:
            m = re.match(r'\s*VNI\s+(\d+)\b', line)
            if m:
                vni = m.group(1)
                continue
            if not vni or "Neighbor" in line or line.strip().startswith("Flags:") or not line.strip():
                continue
            parts = line.split()
            neighbor = parts[0]
            if neighbor.lower().startswith("fe80"):   # link-local: not a meaningful duplicate IP
                continue
            if not (IPV4_RE.fullmatch(neighbor) or ":" in neighbor):
                continue
            seq_m = SEQ_RE.search(line)
            mac_m = MAC_RE.search(line)
            if not seq_m or not mac_m:
                continue
            seq = max(int(seq_m.group(1)), int(seq_m.group(2)))
            if seq < SEQ_WARN:
                continue
            vlan = self._vlan_of(vni)
            rec = self.ip_mob.setdefault((vlan, neighbor),
                                         {"seq": 0, "macs": set(), "vteps": set(), "vni": str(vni)})
            rec["seq"] = max(rec["seq"], seq)
            rec["macs"].add(mac_m.group(0).lower())
            for ip in IPV4_RE.findall(line):
                if ip != neighbor:
                    rec["vteps"].add(ip)

    def _parse_fdb(self, host, text):
        for line in text.splitlines():
            if "permanent" in line or "self" in line:
                continue
            mac_m = MAC_RE.match(line.strip())
            if not mac_m:
                continue
            mac = mac_m.group(0).lower()
            dev_m = re.search(r'\bdev\s+(\S+)', line)
            vlan_m = re.search(r'\bvlan\s+(\d+)', line)
            if not dev_m or not vlan_m:
                continue
            dev = dev_m.group(1)
            vlan = vlan_m.group(1)
            is_remote = ("extern_learn" in line) or dev.startswith("vxlan")
            if is_remote or not (dev.startswith(("swp", "bond"))):
                continue
            self.fdb_local.setdefault((vlan, mac), {})[host] = dev

    def _parse_neigh(self, host, text):
        ap = self.apipa.setdefault(host, {"total": 0, "per_vlan": {}})
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            ip = parts[0]
            if not IPV4_RE.fullmatch(ip):
                continue
            dev_m = re.search(r'\bdev\s+(\S+)', line)
            mac_m = re.search(r'\blladdr\s+(' + MAC_RE.pattern + r')', line)
            dev = dev_m.group(1) if dev_m else ""
            vm = re.match(r'vlan(\d+)$', dev)
            vlan = vm.group(1) if vm else None
            if ip.startswith("169.254."):
                ap["total"] += 1
                if vlan:
                    ap["per_vlan"][vlan] = ap["per_vlan"].get(vlan, 0) + 1
                continue
            if vlan and mac_m:
                mac = mac_m.group(1).lower()
                self.arp_pairs.setdefault((vlan, ip), {}).setdefault(mac, set()).add(host)

    def _merge_arp_conflicts(self):
        """Add IP duplicates seen via cross-device ARP (>=2 distinct MACs) that EVPN
        may not have flagged, so the page is complete even outside EVPN."""
        for (vlan, ip), mac_hosts in self.arp_pairs.items():
            if len(mac_hosts) < 2:
                continue
            rec = self.ip_dups.get((vlan, ip))
            if rec is None:
                rec = self._blank_ip(vlan, vlan, ip)
                self.ip_dups[(vlan, ip)] = rec
            for mac, hosts in mac_hosts.items():
                rec["macs"].add(mac)

    # --------------------------------------------------------------- finalize
    def _recency(self, latest):
        if not latest:
            return None
        try:
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=timezone.utc)
            return (self.analysis_now - latest).total_seconds()
        except Exception:
            return None

    def _seq_delta(self, kind, key, seq):
        skey = "%s:%s" % (kind, key)
        prev = self.prev_state.get(skey, {})
        prev_seq = prev.get("seq")
        now = time.time()
        # "ts" = wall-clock of the last time this entry's sequence CHANGED (moved). If unchanged we
        # keep the old timestamp, so we can tell how long a duplicate has been quiet (for aging out
        # settled entries). Missing on old-format state -> start the clock now (conservative).
        ts = now if (prev_seq is None or seq != prev_seq) else prev.get("ts", now)
        self.new_state[skey] = {"seq": seq, "ts": ts}
        if prev_seq is None or seq < prev_seq:   # reset/boot -> no meaningful delta
            return None
        return seq - prev_seq

    def _quiet_age(self, kind, key):
        """Seconds since this entry's EVPN sequence last changed (moved), from persisted state.
        None if unknown."""
        ts = self.new_state.get("%s:%s" % (kind, key), {}).get("ts")
        return (time.time() - ts) if ts else None

    def _dad_policy(self, host):
        """Return the configured DAD move threshold for one observer."""
        cfg = self.dup_config.get(host, {})
        moves = cfg.get("max_moves")
        window = cfg.get("time")
        if not isinstance(moves, int) or moves <= 0:
            moves = DEFAULT_DAD_MOVES
        if not isinstance(window, int) or window <= 0:
            window = DEFAULT_DAD_WINDOW_SEC
        return moves, window

    def _observer_epoch(self, host):
        ts = self.collection_meta.get(host, {}).get("timestamp")
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.timestamp()
        return self.analysis_now.timestamp()

    @staticmethod
    def _mac_observer_state_key(vni, mac, host):
        return "mac-observer:%s|%s|%s" % (vni, mac, host)

    def _mac_current_hosts(self):
        """Hosts with complete MAC DAD, mobility and FDB evidence (zero trust)."""
        return set(self.coverage.get("mac_current", self.coverage.get("current", set())))

    def _mac_dad_current_hosts(self):
        return set(self.coverage.get("mac_dad_current", self.coverage.get("current", set())))

    def _mac_mobility_current_hosts(self):
        return set(self.coverage.get("mac_mobility_current", self.coverage.get("current", set())))

    def _fdb_current_hosts(self):
        return set(self.coverage.get("fdb_current", self.coverage.get("current", set())))

    def _mac_evidence_current_hosts(self):
        return (
            self._mac_dad_current_hosts()
            | self._mac_mobility_current_hosts()
            | self._fdb_current_hosts()
        )

    def _apply_mac_sequence_sample(self, rec):
        """Compare MAC mobility sequence only against the same observing switch.

        The legacy aggregate sample is accepted for one transition cycle so an
        existing deployment does not lose its visible delta.  It can establish
        a below/above-threshold signal, but all subsequent samples are strictly
        per observer and rate-normalised to the configured DAD window.
        """
        samples = []
        current_hosts = self._mac_mobility_current_hosts()
        seq_by_host = {
            host: seq for host, seq in (rec.get("seq_by_host") or {}).items()
            if host in current_hosts and isinstance(seq, int) and seq >= 0
        }
        for host, seq in sorted(seq_by_host.items()):
            key = self._mac_observer_state_key(rec["vni"], rec["mac"], host)
            previous = self.prev_state.get(key, {})
            observed_at = self._observer_epoch(host)
            prev_seq = previous.get("seq")
            prev_observed = previous.get("observed_at")
            delta = None
            interval = None
            legacy = False

            if isinstance(prev_seq, int) and isinstance(prev_observed, (int, float)):
                interval = observed_at - float(prev_observed)
                if interval > 0 and seq >= prev_seq:
                    delta = seq - prev_seq
            elif self.prev_state.get("__mac_observer_state_version__") != MAC_OBSERVER_STATE_VERSION:
                # Old state tracked only one fabric-wide maximum.  Use it once
                # for display/threshold continuity, then persist host samples.
                old = self.prev_state.get(
                    "mac:%s|%s" % (rec["vni"], rec["mac"]), {}
                )
                old_seq = old.get("seq")
                if isinstance(old_seq, int) and seq >= old_seq:
                    delta = seq - old_seq
                    legacy = True

            moves, window = self._dad_policy(host)
            rate = None
            meaningful = False
            if delta is not None:
                if interval is not None:
                    rate = delta * 60.0 / interval
                    meaningful = (
                        (interval <= window and delta >= moves)
                        or (interval > window and delta * window / interval >= moves)
                    )
                elif legacy:
                    # The old format has no observation timestamp.  Requiring
                    # the full move count is conservative and prevents +1/+2
                    # from becoming a CRITICAL alarm during migration.
                    meaningful = delta >= moves

            old_changed = previous.get("ts")
            if old_changed is None and legacy:
                old_changed = self.prev_state.get(
                    "mac:%s|%s" % (rec["vni"], rec["mac"]), {}
                ).get("ts")
            changed_at = (
                old_changed if delta == 0 and isinstance(old_changed, (int, float))
                else observed_at
            )
            self.new_state[key] = {
                "seq": seq, "observed_at": observed_at, "ts": changed_at,
            }
            samples.append({
                "host": host, "delta": delta, "interval": interval,
                "rate": rate, "moves": moves, "window": window,
                "meaningful": meaningful,
            })

        comparable = [sample for sample in samples if sample["delta"] is not None]
        active = [sample for sample in comparable if sample["meaningful"]]
        chosen_pool = active or comparable
        if chosen_pool:
            chosen = max(
                chosen_pool,
                key=lambda sample: (
                    sample["rate"] if sample["rate"] is not None else sample["delta"],
                    sample["delta"],
                ),
            )
            rec["delta"] = chosen["delta"]
            rec["seq_interval_sec"] = chosen["interval"]
            rec["seq_rate_per_min"] = chosen["rate"]
            rec["seq_activity_threshold"] = chosen["moves"]
            rec["seq_activity_window"] = chosen["window"]
        else:
            rec["delta"] = None
            rec["seq_interval_sec"] = None
            rec["seq_rate_per_min"] = None
            rec["seq_activity_threshold"] = None
            rec["seq_activity_window"] = None
        rec["sequence_active"] = bool(active)

    def _carry_mac_observer_state(self):
        """Keep temporarily absent observers without reusing aggregate migration state."""
        cutoff = self.analysis_now.timestamp() - MAC_OBSERVER_STATE_TTL_SEC
        for key, value in self.prev_state.items():
            if not key.startswith("mac-observer:") or key in self.new_state:
                continue
            if not isinstance(value, dict):
                continue
            observed_at = value.get("observed_at")
            if isinstance(observed_at, (int, float)) and observed_at >= cutoff:
                self.new_state[key] = value
        self.new_state["__mac_observer_state_version__"] = MAC_OBSERVER_STATE_VERSION

    def _finalize_mac_semantics(self, vlan, mac, rec):
        fdb_current_hosts = self._fdb_current_hosts()
        dad_current_hosts = self._mac_dad_current_hosts()
        current_fdb = {
            host: port
            for host, port in self.fdb_local.get((vlan, mac), {}).items()
            if host in fdb_current_hosts
        }
        for host, port in current_fdb.items():
            rec["local"][host] = port
        # Only simultaneous LOCAL attachment on physical switch ports confirms
        # a MAC conflict.  Bonds are normal EVPN-MH dual attachment.
        physical = {
            host: port for host, port in current_fdb.items()
            if port.startswith("swp")
        }
        rec["fdb_multi"] = len(physical) >= 2
        rec["physical_local_count"] = len(physical)
        rec["confirmed_conflict"] = rec["fdb_multi"]
        rec["dad_flagged"] = bool(
            set(rec.get("flagged_hosts", set())) & dad_current_hosts
        )
        rec["flagged"] = rec["dad_flagged"]

        # Keep the aggregate sequence sample only as a quiet-age clock.  It is
        # never used for active severity because observers may disagree.
        self._seq_delta("mac", "%s|%s" % (rec["vni"], mac), rec["seq"])
        self._apply_mac_sequence_sample(rec)

        rec["mobility_only"] = bool(
            rec.get("mobility") and not rec["confirmed_conflict"]
            and not rec["dad_flagged"] and not rec.get("dad_event")
        )
        if rec["confirmed_conflict"]:
            rec["incident_type"] = "confirmed_mac_conflict"
        elif rec.get("dad_event"):
            rec["incident_type"] = "dad_event_mac"
        elif rec["dad_flagged"]:
            rec["incident_type"] = "dad_flagged_mac"
        elif rec.get("mobility"):
            rec["incident_type"] = (
                "mac_mobility_active" if rec["sequence_active"]
                else "mac_mobility_historical"
            )
        else:
            rec["incident_type"] = "unknown"
        rec["activity"] = (
            "active" if rec["confirmed_conflict"] or rec["sequence_active"]
            or rec.get("dad_event") else "settled"
        )
        rec["severity"] = self._mac_sev(rec)

    def _finalize(self):
        for host, ips in self.self_vteps.items():
            for ip in ips:
                self.vtep2host[ip] = host

        for (vlan, ip), rec in self.ip_dups.items():
            ev = self.log_events.get((rec["vni"], ip)) or self.log_events.get((vlan, ip))
            rec["events"] = ev["count"] if ev else 0
            rec["latest"] = ev["latest"] if ev else None
            if ev:
                rec["macs"].update(ev["macs"])
                rec["vteps"].update(ev["vteps"])
            rec["recency"] = self._recency(rec["latest"])
            rec["delta"] = self._seq_delta("ip", "%s|%s" % (rec["vni"], ip), rec["seq"])
            # owner port from FDB local for any of its MACs
            for mac in rec["macs"]:
                for h, port in self.fdb_local.get((vlan, mac), {}).items():
                    rec["local_hosts"].add(h)
                    rec["ports"].add("%s:%s" % (h, port))
            rec["severity"] = self._ip_sev(rec)

        for (vlan, mac), rec in self.mac_dups.items():
            for h, port in self.fdb_local.get((vlan, mac), {}).items():
                if h in self._fdb_current_hosts():
                    rec["local"].setdefault(h, port)

        # FDB-only MAC duplicates: same MAC LOCAL on >=2 switches via PHYSICAL (swp) ports.
        # Bonds are intentionally excluded: a bond is a LAG / EVPN-MH Ethernet Segment, so a
        # dual-homed host's MAC is LOCAL on BOTH pair members BY DESIGN (FRR marks it
        # peer-active "P", seq 0/0) -- that is NOT a duplicate. Real bond/ES-level conflicts
        # are caught by FRR's own "show evpn mac vni all duplicate".
        for (vlan, mac), hosts in self.fdb_local.items():
            if (vlan, mac) in self.mac_dups:
                continue
            phys = {
                h: p for h, p in hosts.items()
                if h in self._fdb_current_hosts() and p.startswith("swp")
            }
            if len(phys) >= 2:
                rec = self._blank_mac(vlan, vlan, mac)
                rec["local"] = dict(phys)
                rec["fdb_multi"] = True
                rec["severity"] = "CRITICAL"
                self.mac_dups[(vlan, mac)] = rec

        # Mobility context (high EVPN sequence). This remains available where DAD is OFF, but it is
        # evidence of movement rather than proof of a simultaneous duplicate.
        for (vlan, ip), mob in self.ip_mob.items():
            rec = self.ip_dups.get((vlan, ip))
            if rec is None:
                # Mobility-only sighting. Treat as a duplicate only with corroboration: 2+ distinct
                # MACs (real IP conflict), a climbing sequence (active), or an extreme sequence
                # (a past storm). A single MAC with a modest stable seq is ordinary EVPN-MH
                # mobility churn, NOT a duplicate -> skip it.
                delta = self._seq_delta("ip", "%s|%s" % (mob["vni"], ip), mob["seq"])
                climbing = delta is not None and delta > 0
                if not (len(mob["macs"]) >= 2 or climbing or mob["seq"] >= SEQ_STORM):
                    continue
                rec = self._blank_ip(vlan, mob["vni"], ip)
                rec["macs"].update(mob["macs"])
                rec["vteps"].update(mob["vteps"])
                rec["mobility"] = True
                rec["delta"] = delta
                self.ip_dups[(vlan, ip)] = rec
            rec["seq"] = max(rec["seq"], mob["seq"])
            if rec["delta"] is None:
                rec["delta"] = self._seq_delta("ip", "%s|%s" % (rec["vni"], ip), rec["seq"])
            rec["severity"] = self._ip_sev(rec)

        for (vlan, mac), mob in self.mac_mob.items():
            rec = self.mac_dups.get((vlan, mac))
            if rec is None:
                rec = self._blank_mac(vlan, mob["vni"], mac)
                self.mac_dups[(vlan, mac)] = rec
            elif rec["vni"] == str(vlan) and str(mob["vni"]).isdigit():
                rec["vni"] = str(mob["vni"])
            for host, port in mob.get("ports", {}).items():
                if host in self._mac_mobility_current_hosts():
                    rec["local"].setdefault(host, port)
            rec["vteps"].update(mob["vteps"])
            rec["mobility"] = True
            rec["seq"] = max(rec["seq"], mob["seq"])
            seq_by_host = dict(mob.get("seq_by_host") or {})
            if not seq_by_host:
                # Compatibility with pre-field test fixtures / cached parsers.
                seq_by_host = {host: mob["seq"] for host in mob.get("hosts", set())}
            for host, seq in seq_by_host.items():
                rec["seq_by_host"][host] = max(rec["seq_by_host"].get(host, 0), seq)

        # Final reconciliation: attach zebra-log contenders ("last VTEP" = the OTHER end of the
        # flap) + recency to every duplicate, then (re)compute severity.
        for (vlan, ip), rec in self.ip_dups.items():
            evm = self.log_events.get((rec["vni"], ip)) or self.log_events.get((vlan, ip))
            if evm:
                # The zebra log carries the OTHER contender MAC(s) for this IP. Merge them so a
                # mobility/arp-detected IP dup (which only knows the currently-winning MAC) still
                # links to the conflicting device -> its port resolves below.
                rec["macs"].update(evm["macs"])
                rec["vteps"].update(evm["vteps"])
                if not rec["events"]:
                    rec["events"] = evm["count"]
                if rec["latest"] is None:
                    rec["latest"] = evm["latest"]
                    rec["recency"] = self._recency(evm["latest"])
            # Resolve owner ports from FDB for ALL macs now assembled. Mobility/log-detected IP dups
            # are added AFTER the early port pass, so without this they carry no port at all.
            for mac in rec["macs"]:
                for h, port in self.fdb_local.get((vlan, mac), {}).items():
                    rec["local_hosts"].add(h)
                    rec["ports"].add("%s:%s" % (h, port))
            rec["severity"] = self._ip_sev(rec)
        for (vlan, mac), rec in self.mac_dups.items():
            evm = self.log_events_mac.get((rec["vni"], mac))
            if evm:
                rec["vteps"].update(evm["vteps"])
                rec["events"] = evm["count"]
                rec["latest"] = evm["latest"]
                rec["recency"] = self._recency(evm["latest"])
                rec["dad_event"] = bool(
                    rec["recency"] is not None
                    and rec["recency"] <= ACTIVE_WINDOW_SEC
                )

        # Resolve the MAC evidence into mutually understandable classes.  A
        # low positive delta remains visible as a mobility signal, but is not
        # an active incident unless it reaches the configured moves/window.
        remove_macs = []
        for (vlan, mac), rec in self.mac_dups.items():
            self._finalize_mac_semantics(vlan, mac, rec)
            if (rec["mobility_only"] and rec["seq"] < SEQ_STORM
                    and (rec["delta"] is None or rec["delta"] <= 0)):
                remove_macs.append((vlan, mac))
        for key in remove_macs:
            self.mac_dups.pop(key, None)

        # Cross-cycle port/MAC memory for duplicate IPs: extreme flappers rarely have BOTH devices
        # captured in one snapshot, so remember each duplicate IP's owner ports + MACs and merge
        # with recent prior runs. This lets the Conflict column resolve the other end's port even
        # when this run only caught one side.
        now_ts = time.time()
        for (vlan, ip), rec in self.ip_dups.items():
            key = "%s|%s" % (vlan, ip)
            ports = {}
            for p in rec["ports"]:
                if ":" in p:
                    h, pt = p.split(":", 1)
                    ports[h] = pt
            prev = self.prev_ip_state.get(key, {})
            if prev.get("ts", 0) >= now_ts - 21600:   # remember for up to 6h
                for h, pt in (prev.get("ports") or {}).items():
                    if h not in ports:
                        ports[h] = pt
                        rec["ports"].add("%s:%s" % (h, pt))
                for m in (prev.get("macs") or []):
                    rec["macs"].add(m)
            self.new_ip_state[key] = {"ports": ports, "macs": sorted(rec["macs"]), "ts": now_ts}
            rec["severity"] = self._ip_sev(rec)

        # Cross-link only current authoritative IP evidence.  Mobility/log/history
        # context must never turn a MAC row into an alleged duplicate device.
        dup_ip_macs = {}
        for (vlan, ip), irec in self.ip_dups.items():
            if not self._is_confirmed_ip(irec):
                continue
            for m in irec.get("authoritative_macs", set()):
                dup_ip_macs.setdefault(vlan, set()).add(m)

        def _endpoints(rec):
            hosts = set(rec["local"].keys())
            for v in rec["vteps"]:
                h = self.vtep2host.get(v)
                if h:
                    hosts.add(h)
            return tuple(sorted(hosts))

        pair_count, ep_by_mac = {}, {}
        for key, rec in self.mac_dups.items():
            ep = _endpoints(rec)
            ep_by_mac[key] = ep
            if len(ep) >= 2 and (rec.get("sequence_active") or rec.get("confirmed_conflict")):
                pair_key = (rec["vlan"], ep)
                pair_count[pair_key] = pair_count.get(pair_key, 0) + 1

        for (vlan, mac), rec in self.mac_dups.items():
            has_dup_ip = mac in dup_ip_macs.get(vlan, set())
            ep = ep_by_mac[(vlan, mac)]
            if has_dup_ip:
                rec["participates_in_ip_conflict"] = True
                rec["classification"] = "ip-conflict-participant"
            elif (not rec.get("confirmed_conflict") and not rec.get("dad_flagged")
                  and len(ep) >= 2
                  and pair_count.get((vlan, ep), 0) >= LOOP_MIN_MACS):
                rec["classification"] = "loop"
                rec["loop_count"] = pair_count[(vlan, ep)]

        # Age-out: a quiesced (WARNING) duplicate whose EVPN sequence has not moved for a long time
        # AND has no recent log event is "stale" -- still real, just historical (e.g. storage VIPs
        # that rebalanced long ago). The UI collapses these out of the main list by default so it
        # stays focused on active + recently-settled duplicates. Needs to observe the entry for
        # STALE_AGE_SEC first (the quiet clock starts when we first see it).
        def _mark_stale(rec, kind, key):
            qa = self._quiet_age(kind, "%s|%s" % (rec["vni"], key))
            rec["quiet_age"] = qa
            rec["stale"] = bool(rec.get("severity") == "WARNING" and qa is not None
                                and qa >= STALE_AGE_SEC
                                and (rec.get("recency") is None or rec["recency"] >= STALE_AGE_SEC))
        for (vlan, ip), rec in self.ip_dups.items():
            _mark_stale(rec, "ip", ip)
        for (vlan, mac), rec in self.mac_dups.items():
            _mark_stale(rec, "mac", mac)

        self._carry_mac_observer_state()
        self._save_state()

    def _ip_sev(self, rec):
        # "Active now" = a duplicate/mobility event within the last hour, or a sequence that climbed
        # THIS collection cycle. A current FRR duplicate row confirms the finding, but FRR can retain
        # that DAD flag after the conflict settles; presence alone must not make it an active fire.
        active = (rec["recency"] is not None and rec["recency"] <= ACTIVE_WINDOW_SEC) or \
                 (rec["delta"] is not None and rec["delta"] > 0)
        if active:
            return "CRITICAL"
        # Settled: a confirmed conflict (2+ MACs) or an EVPN-flagged / high-seq entry that is NOT
        # moving right now is a QUIESCED duplicate -- real, but no longer flapping (e.g. storage VIP
        # pools that have rebalanced and settled). Worth listing, not an active fire.
        if len(rec["macs"]) >= 2 or rec["flagged"] or rec["seq"] >= SEQ_WARN:
            return "WARNING"
        return "OK"

    def _mac_sev(self, rec):
        if (rec.get("confirmed_conflict") or rec.get("sequence_active")
                or rec.get("dad_event")):
            return "CRITICAL"
        if rec.get("dad_flagged") or rec.get("mobility"):
            return "WARNING"
        return "OK"

    def _is_confirmed_ip(self, rec):
        """Current authoritative FRR rows only; mobility/logs are context."""
        return bool(rec.get("authoritative_hosts", set()) & self.coverage["current"])

    @staticmethod
    def _is_confirmed_mac(rec):
        return bool(rec.get("confirmed_conflict"))

    @staticmethod
    def _is_mac_dad(rec):
        return rec.get("incident_type") in ("dad_flagged_mac", "dad_event_mac")

    @staticmethod
    def _is_mac_mobility(rec):
        return rec.get("incident_type") in (
            "mac_mobility_active", "mac_mobility_historical",
        )

    # -------------------------------------------------------------- summary
    def summary(self):
        confirmed_ips = [r for r in self.ip_dups.values() if self._is_confirmed_ip(r)]
        ip_active = sum(1 for r in confirmed_ips if r.get("severity") == "CRITICAL")
        ip_quiesced = sum(1 for r in confirmed_ips if r.get("severity") == "WARNING")
        macs = list(self.mac_dups.values())
        confirmed_macs = [r for r in macs if self._is_confirmed_mac(r)]
        dad_macs = [r for r in macs if self._is_mac_dad(r)]
        mobility_macs = [r for r in macs if self._is_mac_mobility(r)]
        mobility_active = sum(
            1 for r in mobility_macs if r.get("sequence_active")
        )
        mac_total = len(confirmed_macs)
        apipa_total = sum(a["total"] for a in self.apipa.values())
        vlans = set(r["vlan"] for r in confirmed_ips) | set(r["vlan"] for r in self.mac_dups.values())
        for h, a in self.apipa.items():
            vlans |= set(a["per_vlan"].keys())
        disabled = [h for h, c in self.dup_config.items() if c.get("enabled") is False]
        return {
            "ip_active": ip_active, "ip_quiesced": ip_quiesced,
            "confirmed_ip_active": ip_active,
            # Backwards-compatible mac_total now means confirmed simultaneous
            # conflict; mobility and DAD evidence have their own counters.
            "mac_total": mac_total,
            "confirmed_mac_total": mac_total,
            "confirmed_mac_active": sum(
                1 for r in confirmed_macs if r.get("severity") == "CRITICAL"
            ),
            "mac_dad_total": len(dad_macs),
            "mac_mobility_total": len(mobility_macs),
            "mac_mobility_active": mobility_active,
            "mac_mobility_settled": len(mobility_macs) - mobility_active,
            "apipa_total": apipa_total,
            "vlans": len(vlans), "disabled": disabled,
            "ip_total": ip_active + ip_quiesced,
            "coverage_expected": len(self.coverage["expected"]),
            "coverage_ip_current": len(self.coverage["current"]),
            "coverage_current": len(
                set(self.coverage["current"]) & self._mac_current_hosts()
            ),
            "coverage_mac_current": len(self._mac_current_hosts()),
            "coverage_mac_evidence_current": len(self._mac_evidence_current_hosts()),
            "coverage_failures": len(self.coverage["failures"]),
            "coverage_partial": self.coverage["partial"],
        }

    # ---------------------------------------------------------------- web
    @staticmethod
    def _ago(seconds):
        if seconds is None:
            return "&mdash;"
        s = int(seconds)
        if s < 0:
            return "just now"
        if s < 90:
            return "%ds ago" % s
        if s < 5400:
            return "%dm ago" % (s // 60)
        if s < 172800:
            return "%dh ago" % (s // 3600)
        return "%dd ago" % (s // 86400)

    @staticmethod
    def _sev_badge(sev):
        cls = {"CRITICAL": "badge-red", "WARNING": "badge-orange", "OK": "badge-green"}.get(sev, "badge-gray")
        return '<span class="badge %s">%s</span>' % (cls, sev)

    @staticmethod
    def _seq_cell(seq, delta, active=True):
        if not seq:
            return "&mdash;"
        out = "{:,}".format(seq)
        if delta is not None and delta > 0:
            delta_class = "delta-up" if active else "delta-muted"
            out += ' <span class="%s">(+%s)</span>' % (
                delta_class, "{:,}".format(delta),
            )
        return out

    def _port_label(self, host, port):
        """'host:port' with the interface description (ifalias) dimmed on a line below, so each
        cell names the physically attached device (which box is duplicating)."""
        base = "%s:%s" % (html.escape(host), html.escape(port))
        desc = self.if_desc.get((host, port))
        if desc:
            base += "<span class='pdesc'>%s</span>" % html.escape(desc)
        return base

    def _vtep_cell(self, vteps, owner_hosts, port_map=None):
        """Render the conflicting VTEPs as switch names (resolved via vtep2host), dropping the
        owner's own VTEP so the column shows the OTHER end of the flap (the contender). When the
        conflicting MAC/IP was also captured LOCAL on that switch (port_map), show switch:port
        plus that port's interface description."""
        seen = []
        for v in sorted(vteps):
            h = self.vtep2host.get(v)
            if h and h in owner_hosts:
                continue
            if h:
                label = self._port_label(h, port_map[h]) if (port_map and port_map.get(h)) else html.escape(h)
            else:
                label = html.escape(v)
            if label not in seen:
                seen.append(label)
        return "<br>".join(seen) or "&mdash;"

    def export_html(self, output_file):
        s = self.summary()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sev_rank = {"CRITICAL": 0, "WARNING": 1, "OK": 2}
        all_devices = set()

        # ---- IP duplicate rows
        ip_rows = sorted((r for r in self.ip_dups.values() if self._is_confirmed_ip(r)),
                         key=lambda r: (sev_rank.get(r["severity"], 3), -(r["seq"]), -(r["events"])))
        ip_html = []
        for r in ip_rows:
            macs = "<br>".join(html.escape(m) for m in sorted(r["macs"])) or "&mdash;"
            owner_parts = []
            for p in sorted(r["ports"]):
                if ":" in p:
                    _h, _pt = p.split(":", 1)
                    owner_parts.append(self._port_label(_h, _pt))
                else:
                    owner_parts.append(html.escape(p))
            owner = "<br>".join(owner_parts) or \
                    ("<br>".join(html.escape(h) for h in sorted(r["local_hosts"])) or "&mdash;")
            ip_ports = {}
            for _m in r["macs"]:
                for _h, _p in self.fdb_local.get((r["vlan"], _m), {}).items():
                    ip_ports[_h] = _p
            vteps = self._vtep_cell(r["vteps"], r["local_hosts"], ip_ports)
            vlanvni = "vlan %s<br><span class='dim'>VNI %s</span>" % (html.escape(r["vlan"]), html.escape(r["vni"]))
            devs = set(r["local_hosts"]) | set(p.split(":")[0] for p in r["ports"])
            all_devices |= devs
            if len(r["macs"]) >= 2:
                note = "Confirmed &mdash; IP conflict"
                if r["severity"] != "CRITICAL":
                    note += " <span class='dim'>(quiesced)</span>"
            elif r["flagged"]:
                note = "Confirmed &mdash; EVPN DAD"
                if r["severity"] != "CRITICAL":
                    note += " <span class='dim'>(quiesced / latched)</span>"
            elif r.get("mobility"):
                # One MAC, one owner at this instant, but a very high EVPN mobility sequence: the
                # SAME MAC/IP is rapidly re-registering between locations (a flapping endpoint), not
                # two devices sharing an address. Label it distinctly so it is not read as a conflict.
                note = ("Flapping endpoint &mdash; active (EVPN mobility)"
                        if (r.get("delta") is not None and r["delta"] > 0)
                        else "Flapping endpoint &mdash; settled (EVPN mobility)")
            else:
                note = "&mdash;"
            if r.get("stale"):
                note += " <span class='dim'>(aged %dd)</span>" % int((r.get("quiet_age") or 0) // 86400)
            rowcls = " class='stale-row'" if r.get("stale") else ""
            ip_html.append(
                "<tr data-sev='%d' data-devices='%s'%s><td>%s</td><td>%s</td><td class='mono'>%s</td><td class='mono'>%s</td>"
                "<td class='mono'>%s</td><td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    sev_rank.get(r["severity"], 3), html.escape(" ".join(sorted(devs))), rowcls, self._sev_badge(r["severity"]), vlanvni,
                    html.escape(r["ip"]), macs, owner, vteps,
                    self._seq_cell(r["seq"], r["delta"]), self._ago(r["recency"]), r["events"] or "&mdash;", note))
        if not ip_html:
            ip_html.append("<tr><td colspan='10' class='empty'>No duplicate IPs detected &#10003;</td></tr>")

        # ---- MAC duplicate rows
        # Port map from related duplicate IPs: for a duplicate MAC the "other end" is often a
        # DIFFERENT MAC on the same IP, so pull that device's port from the IP-dup record -> the
        # Conflict column can then show switch:port (not just switch).
        mac_ip_ports = {}
        for (ivlan, iip), irec in self.ip_dups.items():
            if not self._is_confirmed_ip(irec):
                continue
            ports = {}
            for p in irec["ports"]:
                if ":" in p:
                    h, pt = p.split(":", 1)
                    ports[h] = pt
            for m in irec.get("authoritative_macs", set()):
                mac_ip_ports.setdefault((ivlan, m), {}).update(ports)
        mac_rows = sorted(self.mac_dups.values(),
                          key=lambda r: (sev_rank.get(r["severity"], 3), -(r["seq"])))
        mac_html = []
        for r in mac_rows:
            local = "<br>".join(self._port_label(h, p) for h, p in sorted(r["local"].items())) or "&mdash;"
            cport = dict(self.fdb_local.get((r["vlan"], r["mac"]), {}))
            cport.update(mac_ip_ports.get((r["vlan"], r["mac"]), {}))
            vteps = self._vtep_cell(r["vteps"], set(r["local"].keys()), cport)
            vlanvni = "vlan %s<br><span class='dim'>VNI %s</span>" % (html.escape(r["vlan"]), html.escape(r["vni"]))
            if r.get("classification") == "loop":
                note = "Possible loop (%d MACs)" % r.get("loop_count", 0)
            elif r.get("confirmed_conflict"):
                note = "Confirmed MAC conflict: LOCAL on %d physical switches" % r.get(
                    "physical_local_count", len(r["local"])
                )
            elif r.get("incident_type") == "dad_flagged_mac":
                note = "FRR MAC DAD flag (latched; not proven simultaneous)"
            elif r.get("incident_type") == "dad_event_mac":
                note = "Recent FRR MAC DAD event"
            elif r.get("incident_type") == "mac_mobility_active":
                note = "Active MAC mobility at/above DAD move-rate threshold"
            elif r.get("incident_type") == "mac_mobility_historical":
                if r.get("delta") is not None and r["delta"] > 0:
                    moves = r.get("seq_activity_threshold") or DEFAULT_DAD_MOVES
                    window = r.get("seq_activity_window") or DEFAULT_DAD_WINDOW_SEC
                    note = ("MAC mobility +%d; below %d moves / %ds threshold; "
                            "not a simultaneous conflict") % (
                                r["delta"], moves, window,
                            )
                else:
                    note = "Historical MAC mobility (flat); not a simultaneous conflict"
            else:
                note = ""
            if r.get("classification") == "ip-conflict-participant":
                participant = "Participant in current authoritative IP DAD finding"
                note = "%s; %s" % (note, participant) if note else participant
            note_html = html.escape(note)
            if r.get("stale"):
                note_html += " <span class='dim'>(aged %dd)</span>" % int((r.get("quiet_age") or 0) // 86400)
            rowcls = " class='stale-row'" if r.get("stale") else ""
            devs = set(r["local"].keys())
            all_devices |= devs
            if r.get("confirmed_conflict"):
                kind = "confirmed"
            elif self._is_mac_dad(r):
                kind = "dad"
            elif self._is_mac_mobility(r):
                kind = "mobility"
            else:
                kind = "context"
            mac_html.append(
                "<tr data-sev='%d' data-kind='%s' data-mobility-active='%s' data-devices='%s'%s><td>%s</td><td>%s</td><td class='mono'>%s</td><td class='mono'>%s</td>"
                "<td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td></tr>" % (
                    sev_rank.get(r["severity"], 3), kind,
                    str(bool(r.get("sequence_active"))).lower(),
                    html.escape(" ".join(sorted(devs))), rowcls,
                    self._sev_badge(r["severity"]), vlanvni,
                    html.escape(r["mac"]), local, vteps,
                    self._seq_cell(r["seq"], r.get("delta"), r.get("sequence_active", False)), note_html))
        if not mac_html:
            mac_html.append("<tr><td colspan='7' class='empty'>No MAC conflict, DAD, or mobility findings &#10003;</td></tr>")

        # ---- APIPA rows (real access VLANs only; baseline link-local filtered out)
        apipa_rows = []
        for host in sorted(self.apipa):
            for vlan, cnt in sorted(self.apipa[host]["per_vlan"].items(), key=lambda kv: -kv[1]):
                if cnt <= 0:
                    continue
                sev = "CRITICAL" if cnt >= APIPA_CRITICAL else "WARNING"
                apipa_rows.append((sev_rank[sev], sev, host, vlan, cnt))
        apipa_rows.sort()
        apipa_html = []
        for _, sev, host, vlan, cnt in apipa_rows:
            all_devices.add(host)
            apipa_html.append("<tr data-devices='%s'><td>%s</td><td class='mono'>%s</td><td>vlan %s</td><td class='mono'>%d</td></tr>" % (
                html.escape(host), self._sev_badge(sev), html.escape(host), html.escape(vlan), cnt))
        if not apipa_html:
            apipa_html.append("<tr><td colspan='4' class='empty'>No APIPA (169.254/16) addresses &#10003;</td></tr>")

        # ---- DAD / multihoming note (shown in the Thresholds modal, not as a banner)
        dad_note = ""
        if s["disabled"]:
            dad_note = ("<br><b>DAD currently off on:</b> %s (EVPN multihoming active)."
                        % html.escape(", ".join(sorted(s["disabled"]))))
        cfg_txt = "n/a"
        for c in self.dup_config.values():
            if c.get("max_moves"):
                cfg_txt = "%s moves / %ss" % (c["max_moves"], c["time"])
                break

        cards = [
            ("card-critical", s["ip_active"], "ACTIVE IP DUPLICATES", "active"),
            ("card-warning", s["ip_quiesced"], "QUIESCED IP DUPLICATES", "quiesced"),
            ("card-critical" if s["confirmed_mac_total"] else "card-excellent",
             s["confirmed_mac_total"], "CONFIRMED MAC CONFLICTS",
             "mac" if s["confirmed_mac_total"] else ""),
            ("card-warning" if s["mac_dad_total"] else "card-excellent",
             s["mac_dad_total"], "MAC DAD FINDINGS",
             "dad" if s["mac_dad_total"] else ""),
            ("card-critical" if s["mac_mobility_active"] else "card-excellent",
             s["mac_mobility_active"], "ACTIVE MAC MOBILITY",
             "mobility-active" if s["mac_mobility_active"] else ""),
            ("card-warning" if s["mac_mobility_total"] else "card-excellent",
             s["mac_mobility_total"], "MAC MOBILITY SIGNALS",
             "mobility" if s["mac_mobility_total"] else ""),
            ("card-warning" if s["apipa_total"] else "card-excellent", s["apipa_total"], "APIPA (DHCP FAILED)", "apipa"),
            ("card-info", s["vlans"], "VLANS WITH FINDINGS", ""),
            ("card-warning" if s["disabled"] else "card-excellent", len(s["disabled"]), "DUP-DETECT DISABLED", "disabled"),
        ]
        cards_html = "".join(
            "<div class='summary-card %s%s'%s><div class='metric'>%s</div><div class='metric-label'>%s</div></div>" % (
                c, ("" if act else " noclick"),
                (" onclick=\"cardFilter('%s', this)\"" % act) if act else "",
                v, l)
            for c, v, l, act in cards)

        stale_count = sum(1 for r in self.ip_dups.values()
                          if self._is_confirmed_ip(r) and r.get("stale")) + \
                      sum(1 for r in self.mac_dups.values() if r.get("stale"))
        aged_btn = ("" if not stale_count else
                    "<button id='agedBtn' class='btn btn-secondary' onclick='toggleAged()' "
                    "title='Quiesced duplicates with no EVPN movement for &ge;%dd'>Show aged (%d)</button>"
                    % (STALE_AGE_SEC // 86400, stale_count))

        html_doc = _PAGE_TEMPLATE
        if (not s["coverage_expected"]
                or (not s["coverage_ip_current"]
                    and not s["coverage_mac_evidence_current"])):
            collection_status = "unavailable"
        elif s["coverage_partial"]:
            collection_status = "partial"
        else:
            collection_status = "current"
        machine_summary = (
            '<div data-analysis-summary="duplicate"'
            ' data-collection-status="%s"'
            ' data-confirmed-ip-active="%d"'
            ' data-ip-quiesced="%d"'
            ' data-confirmed-mac-total="%d"'
            ' data-mac-dad-total="%d"'
            ' data-mac-mobility-active="%d"'
            ' data-mac-mobility-total="%d"'
            ' data-coverage-expected="%d"'
            ' data-coverage-current="%d"'
            ' data-coverage-ip-current="%d"'
            ' data-coverage-mac-current="%d"'
            ' data-coverage-mac-evidence-current="%d"'
            ' data-coverage-failures="%d"'
            ' data-coverage-partial="%s"'
            ' data-coverage-failure-details="%s" style="display:none"></div>'
        ) % (
            collection_status,
            s["confirmed_ip_active"], s["ip_quiesced"],
            s["confirmed_mac_total"], s["mac_dad_total"],
            s["mac_mobility_active"], s["mac_mobility_total"],
            s["coverage_expected"], s["coverage_current"],
            s["coverage_ip_current"],
            s["coverage_mac_current"],
            s["coverage_mac_evidence_current"],
            s["coverage_failures"], str(s["coverage_partial"]).lower(),
            html.escape(json.dumps(self.coverage["failures"]), quote=True),
        )
        html_doc = html_doc.replace("__MACHINE_SUMMARY__", machine_summary)
        html_doc = html_doc.replace("__NOW__", html.escape(now))
        html_doc = html_doc.replace("__AGED_BTN__", aged_btn)
        html_doc = html_doc.replace("__STALE_COUNT__", str(stale_count))
        html_doc = html_doc.replace("__STALE_DAYS__", str(STALE_AGE_SEC // 86400))
        html_doc = html_doc.replace("__CFG__", html.escape(cfg_txt))
        html_doc = html_doc.replace("__APIPA_CRIT__", str(APIPA_CRITICAL))
        html_doc = html_doc.replace("__DAD_NOTE__", dad_note)
        html_doc = html_doc.replace("__SEQ_WARN__", str(SEQ_WARN))
        html_doc = html_doc.replace("__SEQ_STORM__", "{:,}".format(SEQ_STORM))
        html_doc = html_doc.replace("__LOOP_MIN__", str(LOOP_MIN_MACS))
        html_doc = html_doc.replace("__CARDS__", cards_html)
        html_doc = html_doc.replace("__IP_ROWS__", "\n".join(ip_html))
        html_doc = html_doc.replace("__MAC_ROWS__", "\n".join(mac_html))
        html_doc = html_doc.replace("__APIPA_ROWS__", "\n".join(apipa_html))
        html_doc = html_doc.replace("__DEVICES__", json.dumps(sorted(all_devices)))
        with open(output_file, "w") as f:
            f.write(html_doc)


_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Duplicate IP / MAC Analysis</title>
<link rel="shortcut icon" href="/png/favicon.ico">
<link rel="stylesheet" type="text/css" href="/css/select2.min.css">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#1e1e1e; color:#d4d4d4; padding:20px; min-height:100vh; }
.page-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; padding-bottom:15px; border-bottom:1px solid #404040; }
.page-title { font-size:24px; font-weight:600; color:#76b900; }
.header-right { display:flex; align-items:center; gap:14px; }
.last-updated { font-size:13px; color:#888; }
.btn { background:#333; color:#d4d4d4; border:1px solid #404040; padding:8px 14px; border-radius:6px; cursor:pointer; font-size:13px; }
.btn:hover { background:#3c3c3c; border-color:#76b900; }
.dashboard-section { background:#2d2d2d; border-radius:8px; margin-bottom:20px; overflow:hidden; }
.section-header { padding:12px 16px; background:#333; font-weight:600; font-size:14px; color:#76b900; border-bottom:1px solid #404040; }
.section-content { padding:16px; }
.summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.summary-card { background:#252526; padding:15px; border-radius:6px; border-left:3px solid #76b900; }
.card-excellent { border-left-color:#76b900; }
.card-info { border-left-color:#4fc3f7; }
.card-warning { border-left-color:#ff9800; }
.card-critical { border-left-color:#f44336; }
.metric { font-size:22px; font-weight:bold; color:#d4d4d4; }
.metric-label { font-size:12px; color:#888; margin-top:4px; }
table.dup-table { width:100%; border-collapse:collapse; font-size:13px; }
.dup-table th, .dup-table td { border:1px solid #404040; padding:9px 11px; text-align:left; vertical-align:top; }
.dup-table th { background:#333; color:#76b900; font-weight:600; font-size:12px; cursor:pointer; user-select:none; }
.dup-table th:hover { background:#3c3c3c; }
.dup-table tbody tr { background:#252526; }
.dup-table tbody tr:hover { background:#2d2d2d; }
.mono { font-family:'Consolas','Courier New',monospace; font-size:12px; }
.dim { color:#888; font-size:11px; }
.pdesc { display:block; color:#c8964a; font-size:10px; font-style:italic; margin-top:1px; white-space:nowrap; }
tr.stale-row { opacity:0.55; }
body:not(.show-aged) tr.stale-row { display:none !important; }
.empty { text-align:center; color:#76b900; padding:18px; }
.delta-up { color:#ff6b6b; font-weight:bold; }
.delta-muted { color:#aaa; font-weight:bold; }
.badge { display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px; font-weight:600; text-transform:uppercase; }
.badge-green { background:rgba(118,185,0,0.2); color:#76b900; }
.badge-red { background:rgba(244,67,54,0.2); color:#ff6b6b; }
.badge-orange { background:rgba(255,152,0,0.2); color:#ffb74d; }
.badge-gray { background:rgba(158,158,158,0.2); color:#999; }
.modal { display:none; position:fixed; z-index:2000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.7); }
.modal.show { display:flex; justify-content:center; align-items:center; }
.modal-box { background:#2d2d2d; border-radius:8px; width:90%; max-width:680px; max-height:82vh; overflow:auto; box-shadow:0 4px 20px rgba(0,0,0,0.5); }
.modal-head { display:flex; justify-content:space-between; align-items:center; padding:14px 18px; background:#333; border-bottom:1px solid #444; }
.modal-head h3 { color:#76b900; font-size:16px; margin:0; }
.modal-close { background:none; border:none; color:#888; font-size:24px; cursor:pointer; }
.modal-body { padding:18px; font-size:13px; line-height:1.6; }
.modal-body h4 { color:#76b900; margin:12px 0 4px; font-size:13px; }
.modal-body code { background:#1e1e1e; padding:1px 5px; border-radius:3px; color:#e0c64a; }
.action-buttons { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.btn { padding:8px 14px; border:none; border-radius:4px; font-size:13px; font-weight:500; cursor:pointer; display:flex; align-items:center; gap:6px; }
.btn-primary { background:linear-gradient(0deg,#76b900 0%,#5a8c00 100%); color:#fff; }
.btn-primary:hover { background:linear-gradient(0deg,#8bd400 0%,#6ba000 100%); }
.btn-secondary { background:linear-gradient(0deg,#4fc3f7 0%,#0288d1 100%); color:#fff; }
.btn-secondary:hover { background:linear-gradient(0deg,#81d4fa 0%,#039be5 100%); }
.device-search-container { display:flex; align-items:center; gap:8px; }
.device-search-container .select2-container { min-width:180px; }
.device-search-container .select2-container--default .select2-selection--single { height:34px; border:1px solid #555; border-radius:4px; background:#3c3c3c; display:flex; align-items:center; }
.device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered { line-height:34px; color:#d4d4d4; padding-left:10px; font-size:13px; }
.device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow { height:34px; }
.select2-dropdown { background:#2d2d2d; border:1px solid #555; }
.select2-container--default .select2-results__option { color:#d4d4d4; padding:8px 12px; }
.select2-container--default .select2-results__option--highlighted[aria-selected] { background:#76b900; color:#000; }
.select2-container--default .select2-search--dropdown .select2-search__field { background:#3c3c3c; border:1px solid #555; color:#d4d4d4; }
.clear-search-btn { background:#f44336; color:#fff; border:none; padding:6px 10px; border-radius:4px; cursor:pointer; font-size:12px; display:none; }
.summary-card { cursor:pointer; transition:all 0.15s; }
.summary-card:hover { background:#2d2d2d; transform:translateY(-1px); }
.summary-card.active { background:#333; border-left-width:6px; }
.summary-card.noclick { cursor:default; }
.summary-card.noclick:hover { background:#252526; transform:none; }
.filter-info { display:none; text-align:center; padding:9px 14px; margin-bottom:16px; background:rgba(118,185,0,0.1); border:1px solid rgba(118,185,0,0.3); border-radius:6px; color:#76b900; font-size:13px; }
.filter-info button { margin-left:10px; padding:4px 10px; background:#76b900; color:#000; border:none; border-radius:4px; cursor:pointer; }
@keyframes spin { from { transform:rotate(0deg); } to { transform:rotate(360deg); } }
</style>
</head>
<body>
__MACHINE_SUMMARY__
<div class="page-header">
  <div>
    <div class="page-title">Duplicate IP / MAC Analysis</div>
    <div class="last-updated">Last Updated: __NOW__</div>
  </div>
  <div class="action-buttons">
    <div class="device-search-container">
      <select id="deviceSearch" style="width:200px;"><option value="">Search Device...</option></select>
      <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">&#10005;</button>
    </div>
    <button class="btn btn-secondary" onclick="document.getElementById('thr').classList.add('show')" title="Thresholds &amp; sources">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
      Thresholds</button>
    <button id="run-analysis" class="btn btn-secondary" onclick="runAnalysis()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>
      Run Analysis</button>
    __AGED_BTN__
    <button class="btn btn-primary" onclick="downloadCSV()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>
      Download CSV</button>
  </div>
</div>
<div class="filter-info" id="filterInfo">Filtered &mdash; <span id="filterLabel"></span> <button onclick="showAllDup()">Show All</button></div>
<div class="dashboard-section">
  <div class="section-header">Summary</div>
  <div class="section-content"><div class="summary-grid">__CARDS__</div></div>
</div>
<div class="dashboard-section">
  <div class="section-header">Duplicate IPs (per VLAN / VNI)</div>
  <div class="section-content">
    <table class="dup-table" id="ipt">
      <thead><tr><th>Severity</th><th>VLAN / VNI</th><th>IP</th><th>MAC(s)</th><th>Owner (local)</th><th>Conflict VTEP(s)</th><th>EVPN Seq (&#916;)</th><th>Last Dup Event</th><th>Events</th><th>Note</th></tr></thead>
      <tbody>__IP_ROWS__</tbody>
    </table>
  </div>
</div>
<div class="dashboard-section">
  <div class="section-header">MAC Findings &mdash; Confirmed Conflicts / DAD / Mobility (per VLAN / VNI)</div>
  <div class="section-content">
    <table class="dup-table" id="mact">
      <thead><tr><th>Severity</th><th>VLAN / VNI</th><th>MAC</th><th>Local On (switch:port)</th><th>Conflict / Observed VTEP(s)</th><th>EVPN Seq (&#916;)</th><th>Meaning</th></tr></thead>
      <tbody>__MAC_ROWS__</tbody>
    </table>
  </div>
</div>
<div class="dashboard-section">
  <div class="section-header">APIPA / DHCP-failed (169.254.0.0/16) per switch &amp; VLAN</div>
  <div class="section-content">
    <table class="dup-table" id="apt">
      <thead><tr><th>Severity</th><th>Switch</th><th>VLAN</th><th>APIPA Count</th></tr></thead>
      <tbody>__APIPA_ROWS__</tbody>
    </table>
  </div>
</div>

<div class="modal" id="thr">
  <div class="modal-box">
    <div class="modal-head"><h3>Duplicate Detection &mdash; Thresholds &amp; Sources</h3>
      <button class="modal-close" onclick="document.getElementById('thr').classList.remove('show')">&times;</button></div>
    <div class="modal-body">
      <h4>Data sources (collected per switch each cycle)</h4>
      <code>show evpn arp-cache vni all duplicate</code> &mdash; authoritative duplicate IPs + EVPN mobility sequence.<br>
      <code>show evpn mac vni all duplicate</code> &mdash; current/latched FRR MAC DAD findings.<br>
      <code>show evpn mac / arp-cache vni all</code> &mdash; mobility evidence (works with DAD off); this is shown separately from confirmed conflicts.<br>
      <code>bridge fdb show</code> &mdash; same MAC LOCAL on &ge;2 <i>physical</i> ports (bonds excluded = EVPN-MH dual-homing).<br>
      <code>ip -4 neigh show</code> &mdash; APIPA (169.254/16 = DHCP failed) + IP&harr;multi-MAC.<br>
      zebra log <code>"detected as duplicate"</code> &mdash; timestamped event history (recency &amp; rate).
      <h4>Severity</h4>
      <b>IP CRITICAL</b> &mdash; a current duplicate event or an IP sequence that increased in this
      collection cycle. A current but flat/old authoritative IP DAD row is quiesced WARNING.<br>
      <b>MAC CRITICAL</b> &mdash; a confirmed simultaneous physical MAC conflict, a recent DAD event,
      or mobility that reaches the configured move-rate threshold.<br>
      <b>MAC WARNING</b> &mdash; a latched DAD flag or below-threshold / historical mobility evidence.
      A positive MAC &#916; below policy is movement context, not proof of a duplicate.<br>
      <b>Aged</b> &mdash; a quiesced duplicate whose sequence has not moved for &ge;__STALE_DAYS__ days is
      collapsed out of the list (use <i>Show aged</i> to reveal). These persist in FRR until the address is
      removed / re-learned or its DAD flag is cleared &mdash; the tool only mirrors that state.<br>
      APIPA &mdash; CRITICAL when &ge; __APIPA_CRIT__ APIPA addresses on one switch+VLAN, else WARNING.
      <h4>Clear a resolved FRR DAD flag</h4>
      After confirming the conflict is resolved, run the targeted command on every VTEP that still reports
      the duplicate. Replace the placeholders with the row's VNI and address:<br>
      <code>sudo vtysh -c "clear evpn dup-addr vni &lt;VNI&gt; ip &lt;IP_ADDRESS&gt;"</code><br>
      For a duplicate MAC, use:<br>
      <code>sudo vtysh -c "clear evpn dup-addr vni &lt;VNI&gt; mac &lt;MAC_ADDRESS&gt;"</code><br>
      Use a targeted VNI plus IP/MAC; do not use <code>vni all</code> for routine cleanup.
      <h4>EVPN duplicate-address-detection (DAD) &amp; multihoming</h4>
      Configured threshold: <code>__CFG__</code> (max-moves / window). FRR <b>automatically disables DAD on
      switches where EVPN multihoming (Ethernet Segments / dual-homed bonds) is enabled</b> &mdash; this is
      normal, not a misconfiguration. There the EVPN <i>duplicate</i> flag &amp; zebra log are unavailable;
      movement anomalies are instead observed through the mobility sequence below (always tracked).__DAD_NOTE__
      <h4>Mobility sequence &amp; &#916; (works even with DAD off)</h4>
      Every MAC/IP carries an EVPN mobility <b>sequence</b> that increments each time it moves between
      owners. A stable / dual-homed entry stays at <code>0/0</code>. The <code>(+N)</code> next to a seq is
      the increase seen by the <b>same observing switch</b> since its previous sample. CRITICAL requires
      the configured <code>moves / window</code> rate; for example <code>+2</code> is below the default
      <code>5 moves / 180s</code> policy and is not a simultaneous duplicate. A stable single-owner entry
      is retained as history only when its sequence is extreme (&ge; __SEQ_STORM__).
      <h4>Note column &mdash; conflict vs flapping (IP table)</h4>
      <b>Confirmed &mdash; IP conflict</b> &mdash; 2+ distinct MACs claim the same IP (two devices), or
      EVPN/zebra flagged it. <b>Flapping endpoint (EVPN mobility)</b> &mdash; a <i>single</i> MAC/IP whose
      mobility sequence is very high: the same endpoint is rapidly re-registering between locations (e.g. a
      BMC dual-pathed / not bonded), NOT two devices sharing an address. "active" = climbing now, "settled" =
      high but flat. A flapping endpoint often also shows an APIPA (169.254) address because the churn breaks DHCP.
      <h4>MAC finding types</h4>
      <b>Confirmed MAC conflict</b> requires the same MAC to be simultaneously LOCAL on at least two
      physical switch ports. <b>FRR MAC DAD</b> is a current/latched DAD finding but does not by itself
      prove simultaneous owners. <b>MAC mobility</b> records moves and is not counted as a duplicate.
      <b>IP DAD participant</b> is shown only when the MAC appears in a current authoritative IP
      DAD finding. <b>Possible loop</b> &mdash; &ge; __LOOP_MIN__ active MACs moving between the same
      switch pair with no per-MAC IP duplicate (frames circulating, not a single device).
    </div>
  </div>
</div>

<script src="/css/jquery-3.5.1.min.js"></script>
<script src="/css/select2.min.js"></script>
<script>
var DUP_DEVICES = __DEVICES__;
var AGED_COUNT = __STALE_COUNT__;
function toggleAged(){ var on=document.body.classList.toggle('show-aged'); var b=document.getElementById('agedBtn'); if(b){ b.textContent = on ? 'Hide aged' : ('Show aged ('+AGED_COUNT+')'); } }
function sortTable(tid, col, numeric) {
  var t = document.getElementById(tid), tb = t.tBodies[0];
  var rows = Array.prototype.slice.call(tb.rows).filter(function(r){return !r.querySelector('.empty');});
  if (!rows.length) return;
  var asc = t.getAttribute('data-sc') != (col+(numeric?'n':''));
  t.setAttribute('data-sc', asc ? (col+(numeric?'n':'')) : '');
  rows.sort(function(a,b){
    var x=a.cells[col].innerText.trim(), y=b.cells[col].innerText.trim();
    if (numeric){ x=parseFloat(x.replace(/[^0-9.\\-]/g,''))||0; y=parseFloat(y.replace(/[^0-9.\\-]/g,''))||0; return asc?x-y:y-x; }
    return asc ? x.localeCompare(y) : y.localeCompare(x);
  });
  rows.forEach(function(r){ tb.appendChild(r); });
}
['ipt','mact','apt'].forEach(function(tid){
  var t=document.getElementById(tid); if(!t) return;
  Array.prototype.forEach.call(t.tHead.rows[0].cells, function(th, i){
    var num = /Count|Seq|Events/i.test(th.innerText);
    th.addEventListener('click', function(){ sortTable(tid, i, num); });
  });
});
document.getElementById('thr').addEventListener('click', function(e){ if(e.target===this) this.classList.remove('show'); });

function allDupRows(){ return [].concat(
  Array.prototype.slice.call(document.querySelectorAll('#ipt tbody tr')),
  Array.prototype.slice.call(document.querySelectorAll('#mact tbody tr')),
  Array.prototype.slice.call(document.querySelectorAll('#apt tbody tr'))); }
function setFilterInfo(label){ var fi=document.getElementById('filterInfo'); if(fi){ document.getElementById('filterLabel').textContent=label; fi.style.display='block'; } }
function showAllDup(){
  allDupRows().forEach(function(r){ r.style.display=''; });
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  var fi=document.getElementById('filterInfo'); if(fi) fi.style.display='none';
  var cs=document.getElementById('clearSearchBtn'); if(cs) cs.style.display='none';
  if(window.jQuery && jQuery('#deviceSearch').data('select2')) jQuery('#deviceSearch').val('').trigger('change.select2');
}
function cardFilter(kind, card){
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  if(kind==='active'||kind==='quiesced'){
    if(card) card.classList.add('active');
    var sev = (kind==='active') ? '0' : '1';
    Array.prototype.slice.call(document.querySelectorAll('#ipt tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      r.style.display = (r.getAttribute('data-sev')===sev) ? '' : 'none';
    });
    document.getElementById('ipt').scrollIntoView({behavior:'smooth', block:'start'});
    setFilterInfo((kind==='active'?'Active':'Quiesced')+' IP duplicates');
  } else if(kind==='mac'||kind==='dad'||kind==='mobility'||kind==='mobility-active'){
    if(card) card.classList.add('active');
    Array.prototype.slice.call(document.querySelectorAll('#mact tbody tr')).forEach(function(r){
      if(r.querySelector('.empty')) return;
      var rowKind=r.getAttribute('data-kind');
      var matches=(kind==='mac'&&rowKind==='confirmed') ||
        (kind==='dad'&&rowKind==='dad') ||
        (kind==='mobility'&&rowKind==='mobility') ||
        (kind==='mobility-active'&&rowKind==='mobility'&&r.getAttribute('data-mobility-active')==='true');
      r.style.display=matches?'':'none';
    });
    document.getElementById('mact').scrollIntoView({behavior:'smooth', block:'start'});
    var labels={mac:'Confirmed MAC conflicts',dad:'MAC DAD findings',mobility:'MAC mobility signals','mobility-active':'Active MAC mobility'};
    setFilterInfo(labels[kind]);
  } else if(kind==='apipa'){
    document.getElementById('apt').scrollIntoView({behavior:'smooth', block:'start'});
  }
}
function filterByDevice(dev){
  if(!dev) return;
  dev = String(dev).toLowerCase();
  document.querySelectorAll('.summary-card').forEach(function(c){ c.classList.remove('active'); });
  allDupRows().forEach(function(r){
    if(r.querySelector('.empty')) return;
    var d=(r.getAttribute('data-devices')||'').toLowerCase().split(' ');
    r.style.display = (d.indexOf(dev)>-1) ? '' : 'none';
  });
  var cs=document.getElementById('clearSearchBtn'); if(cs) cs.style.display='inline-block';
  setFilterInfo('Device: '+dev);
}
function clearDeviceSearch(){ showAllDup(); }
async function runAnalysis(){
  var b=document.getElementById('run-analysis'); var o=b.innerHTML;
  b.disabled=true; b.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="animation:spin 1s linear infinite"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg> Running...';
  try {
    var baseline = typeof window.lldpqCaptureAnalysisState === 'function'
      ? await window.lldpqCaptureAnalysisState('duplicate') : null;
    var response = await fetch('/trigger-monitor?scope=duplicate',{
      method:'POST', headers:{'Content-Type':'application/json'}
    });
    var data = await response.json();
    if(!response.ok || !data || data.status!=='success' || !data.trigger_id || data.scope!=='duplicate'){
      throw new Error((data && data.message) || 'Failed to trigger analysis.');
    }
    if(typeof window.waitForLldpqAnalysisCompletion === 'function'){
      await window.waitForLldpqAnalysisCompletion(
        baseline, {scope:'duplicate', pipelineId:data.trigger_id});
    }else{
      await new Promise(function(resolve){ setTimeout(resolve,35000); });
    }
    location.reload();
  }catch(error){
    b.disabled=false; b.innerHTML=o;
    alert('Analysis did not complete: '+(error.message||error));
  }
}
function csvEsc(v){ v=(v==null?'':String(v)); return '"'+v.replace(/"/g,'""')+'"'; }
function downloadCSV(){
  var out=[['Severity','VLAN/VNI','IP','MAC(s)','Owner','Conflict VTEP(s)','EVPN Seq','Last Dup Event','Events','Note']];
  Array.prototype.slice.call(document.querySelectorAll('#ipt tbody tr')).forEach(function(r){
    if(r.style.display==='none' || r.querySelector('.empty')) return;
    if(r.classList.contains('stale-row') && !document.body.classList.contains('show-aged')) return;
    out.push(Array.prototype.slice.call(r.cells).map(function(c){ return (c.innerText||'').trim().replace(/\\s+/g,' '); }));
  });
  var csv=out.map(function(r){ return r.map(csvEsc).join(','); }).join('\\n');
  var ts=new Date().toISOString().slice(0,16).replace('T','_').replace(/:/g,'-');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8;'}); var a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='Duplicate_Analysis_'+ts+'.csv'; document.body.appendChild(a); a.click(); a.remove();
}
document.addEventListener('DOMContentLoaded', function(){
  if(window.jQuery){
    var $s=jQuery('#deviceSearch'); var opts='<option value=""></option>';
    DUP_DEVICES.forEach(function(dv){ opts+='<option value="'+dv+'">'+dv+'</option>'; });
    $s.html(opts);
    $s.select2({placeholder:'Search Device...', allowClear:true, width:'200px', dropdownAutoWidth:true});
    $s.on('select2:select', function(e){ filterByDevice(e.params.data.id); });
    $s.on('select2:clear', function(){ clearDeviceSearch(); });
  }
});
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/analysis-guard.js?v=20260707-scoped-runner-2"></script>
</body>
</html>"""
