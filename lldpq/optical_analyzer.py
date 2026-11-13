#!/usr/bin/env python3
"""
Optical Diagnostics Analysis Module for LLDPq
Advanced SFP/QSFP monitoring and cable health assessment

Copyright (c) 2024 LLDPq Project
Licensed under MIT License - see LICENSE file for details
"""

import hashlib
import json
import time
import re
import os
import math
import html
import multiprocessing
import tempfile

import analysis_sidecar
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

# Per-device detail sidecars fetched by the report's expandable rows; file
# names come from inventory hostnames, so refuse anything that could escape
# the directory or hide as a dotfile.
DETAILS_DIR_NAME = "optical-details"
DETAIL_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Per-device history shards (PFC/BER precedent): the monolithic
# optical_history.json forced a full read-modify-rewrite of the entire
# fabric's 100-sample port history every run (hundreds of MB at scale).
# Shards are read, appended, and written inside the per-device parse
# workers, so the parent process never holds the fabric-wide history.
HISTORY_DIR_NAME = "optical-history"
SHARD_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# At fabric scale a single synchronous <tbody> freezes the tab; only rows
# that need eyes render inline, quiet rows hydrate in chunks after first
# paint (process_pfc_ecn_data.py established the pattern and the sentinel
# contract — dynamic row values are HTML-escaped, so the sentinel can never
# occur within row content).
DEFERRED_ROW_SENTINEL = "<!--=lldpq-row=-->"
INLINE_ROW_CAP = 5000

# Per-port evidence the expandable rows render (raw sample, lane identities,
# the lanes grading set aside, the module limits that graded the port, the
# monitors the module does not implement, the collected link state, the
# note of a row without readings and what a link-down row is read with: the
# lanes whose laser is driven, whether the module shows transmit light on
# any channel, the lane count its media declares).  It is rebuilt from every
# collection and no shard consumer reads it, so it stays out of the
# persisted current snapshot.
SIDECAR_ONLY_STAT_KEYS = frozenset({
    "raw_data",
    "rx_power_lane_ids",
    "tx_power_lane_ids",
    "bias_current_lane_ids",
    "inactive_lanes",
    "module_limits",
    "not_monitored",
    "link_state",
    "note",
    "lane_evidence",
})

# notifications.yaml files whose unusable optical margin was already
# reported: one run builds several analyzers and the message is wanted once.
_REPORTED_IGNORED_MARGINS = set()

try:
    import yaml
except ImportError:
    yaml = None

try:
    from device_names import canonical
except Exception:
    def canonical(_n):
        return _n

class OpticalHealth(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    DOWN = "down"
    UNPLUGGED = "unplugged"
    UNKNOWN = "unknown"


def coerce_optical_health(value: Any) -> OpticalHealth:
    """Return a known health enum for current and historical status values."""
    if isinstance(value, OpticalHealth):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith("opticalhealth."):
            normalized = normalized.split(".", 1)[1]
        try:
            return OpticalHealth(normalized)
        except ValueError:
            pass
    return OpticalHealth.UNKNOWN


def _atomic_write(path: str, content: str) -> None:
    """Write ``content`` to ``path`` atomically (tempfile + fsync + replace).

    A concurrent web reader or a mid-write termination never sees a truncated
    or empty Analysis page/state file.  A small local copy is used here on
    purpose so parallel analyzers do not share a cross-file module.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory
    )
    try:
        # Web-served output: nginx must always retain read access, so lift
        # mkstemp's private 0600 (and any inherited restrictive mode).
        mode = (os.stat(path).st_mode & 0o7777) if os.path.exists(path) else 0o664
        os.fchmod(descriptor, mode | 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if path.endswith(".json"):
            # Validation handshake: lets the post-run JSON validator prove
            # these bytes intact by hash instead of re-parsing the document.
            analysis_sidecar.publish_digest(
                path, hashlib.sha256(content.encode("utf-8")).hexdigest()
            )
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


class OpticalAnalyzer:
    # Industry standard optical power thresholds (dBm)
    DEFAULT_THRESHOLDS = {
        "rx_power_min_dbm": -14.0,      # Minimum receive power
        "rx_power_max_dbm": 7.0,        # Maximum receive power (critical high)
        # High RX thresholds: treat >5 dBm as warning, >7 dBm as critical (typical DR optics)
        "rx_power_warning_high_dbm": 5.0,
        "rx_power_critical_high_dbm": 7.0,
        "tx_power_min_dbm": -11.0,      # Minimum transmit power
        "tx_power_max_dbm": 4.0,        # Maximum transmit power
        "temperature_max_c": 70.0,      # Maximum operating temperature
        "temperature_min_c": 0.0,       # Minimum operating temperature
        "voltage_min_v": 3.0,           # Minimum supply voltage
        "voltage_max_v": 3.6,           # Maximum supply voltage
        "link_margin_min_db": 3.0       # Minimum acceptable link margin
    }
    # The limits a module prints for itself (``ethtool -m``), lowest first.
    # RX power, TX power, temperature and voltage are each graded by the
    # module's own table when all four are present and consistent; the
    # generic values above then stay out of that metric.
    MODULE_LIMIT_KEYS = ('low_alarm', 'low_warning', 'high_warning', 'high_alarm')
    MODULE_LIMIT_METRICS = ('rx_power', 'tx_power', 'temperature', 'voltage')
    # A table grades a metric only when its limits are physically plausible
    # as well as consistent.  An unprogrammed table is ordered too (-128 /
    # +128 C, 0 / 6.5535 V, 0.0001 / 6.5535 mW), and grading by it switched
    # the generic alarm off: 110 C, 2.6 V or a lane at -30 dBm read healthy.
    # The ranges hold the tables of real modules with room to spare:
    # industrial-temperature parts alarm at -45 C and up to 110 C, supply
    # limits sit between 2.7 and 3.9 V, the receive alarms of long-reach
    # optics reach about -36 dBm and amplified transmitters about +8 dBm.
    # Power is exclusive at its lower end: -40.00 dBm is 0.0001 mW, the
    # smallest value the field can hold and the floor a dark lane is read
    # as, so no reading can be below such a limit.
    MODULE_LIMIT_PLAUSIBLE = {
        'rx_power': (-40.0, 10.0),
        'tx_power': (-40.0, 10.0),
        'temperature': (-45.0, 125.0),
        'voltage': (2.5, 4.0),
    }
    # How close to a module warning limit a healthy reading is GOOD rather
    # than EXCELLENT (dB, dB, degrees C, V).  On the low side RX power uses
    # the link margin instead.
    MODULE_GOOD_BAND = {
        'rx_power': 1.0,
        'tx_power': 1.0,
        'temperature': 5.0,
        'voltage': 0.05,
    }
    # Name and number format of a module-graded metric in anomaly texts.
    MODULE_LIMIT_TEXT = {
        'rx_power': ('RX power', '{:.2f} dBm'),
        'tx_power': ('TX power', '{:.2f} dBm'),
        'temperature': ('Module temperature', '{:.2f}°C'),
        'voltage': ('Module voltage', '{:.4f} V'),
    }
    MODULE_LIMIT_ACTIONS = {
        ('rx_power', 'low'): 'Check fiber connection, clean connectors, or replace cable',
        ('rx_power', 'high'): 'Verify the far-end optic type and attenuate the link if it is too short',
        ('tx_power', 'low'): 'Inspect or replace the transceiver and verify module compatibility',
        ('tx_power', 'high'): 'Inspect or replace the transceiver and verify module compatibility',
        ('temperature', 'high'): 'Check cooling, reduce load, or replace SFP module',
    }
    # A link-down port whose transmit power reads no light while its lasers
    # are driven, on a module that shows transmit light on no channel.
    DARK_TRANSMITTER_ACTION = ('Check whether the peer receives light from '
                               'this port; replace the transceiver if it '
                               'does not')
    # The same picture on a module whose transmit monitor is seen working
    # on another channel.  A port disabled on the switch can read like this
    # on a module whose lasers stay on, hence the condition.
    DOWN_TRANSMITTER_ACTION = ('If the port is enabled on this switch, '
                               'inspect or replace the transceiver: no '
                               'light leaves although its lasers are driven')
    # Several drivers report a dark optical lane as -40 dBm (or -inf).  Keep
    # those readings as evidence; dropping them can turn a failed lane into a
    # healthy-looking average.
    DARK_POWER_DBM = -35.0
    NEGATIVE_INFINITY_FLOOR_DBM = -40.0
    # Laser bias tells a lane that is dark because it broke apart from a lane
    # that is dark because it was never equipped: a driven laser sits in the
    # milliamp range, an unequipped channel reports 0.000 mA.  The floor only
    # absorbs driver rounding, so no real bias reading can look undriven.
    LASER_OFF_BIAS_MA = 0.1
    # Match the optical media standard reported by common ethtool/NVUE
    # variants, for example ``100G Base-DR`` and ``100GBASE-DR``.  The lane
    # suffix describes optical lanes (DR4/SR4/etc.), not the host electrical
    # width of the pluggable module.
    OPTICAL_MEDIA_STANDARD_RE = re.compile(
        r'\b\d+\s*G(?:\s*[-_ ]?\s*BASE)?\s*[-_ ]*'
        r'(?P<family>DR|FR|SR|LR|ER|ZR|PSM|CWDM)'
        r'(?P<lanes>\d+)?\b',
        re.IGNORECASE,
    )
    # DR and FR without a numeric suffix are defined as a single optical
    # lane.  Other families are only treated as single-lane when the media
    # string explicitly says so (LR1/ER1/ZR1, for example).
    UNNUMBERED_SINGLE_LANE_MEDIA = frozenset({'DR', 'FR'})
    # What ethtool (sfpid.c, qsfp.c, cmis.c, sff-common.c) and NVUE print
    # for a copper assembly: a 'Copper pigtail' or 'RJ45' connector, 'Passive
    # Cable' / 'Copper cable' technology, the 'Passive Cu cmplnce.' /
    # 'Active Cu cmplnce.' line, a Base-CR or BASE-T standard.  'No separable
    # connector' is absent on purpose: an active optical cable prints it too
    # and has full DOM.
    COPPER_INDICATOR_RE = re.compile(
        r'passive\s+copper|active\s+copper|copper\s+cable|copper\s+pigtail|'
        r'\bRJ-?45\b|passive\s+cable|\bcu\s+cmplnce|base-cr|base-t|twinax|'
        r'(?<![a-z])dac(?![a-z])',
        re.IGNORECASE,
    )
    ACTIVE_OPTICAL_RE = re.compile(
        r'(?<![a-z])aoc(?![a-z])|active\s+optical', re.IGNORECASE)
    # A literal piece of every alternative above.  Plain substring tests on
    # the lowercased block find the few lines worth the regular expressions;
    # running those over every line of every block made the worker several
    # times slower.
    COPPER_TOKENS = ('copper', 'rj45', 'rj-45', 'passive', 'cmplnce',
                     'base-cr', 'base-t', 'twinax', 'dac')
    ACTIVE_OPTICAL_TOKENS = ('aoc', 'active')
    # A power or bias value that is not zero: the unit, and before it on
    # the same line a number with a digit other than 0 (or 'inf').  A limit
    # line counts too; the test only has to be certain when it says "none".
    READING_UNIT_RE = re.compile(r'm[AW]', re.IGNORECASE)
    NONZERO_VALUE_RE = re.compile(
        r'(?:[^\D0][\d.]*|inf)[^\S\n]*$', re.IGNORECASE)
    # Vendor identity fields (SN/PN/date code) may coincidentally contain an
    # indicator such as 'DAC'; the medium is told from descriptor lines only.
    IDENTITY_LINE_RE = re.compile(r'\s*(?:vendor|serial|date)', re.IGNORECASE)
    INTERFACE_STATE_RE = re.compile(
        r'^[^\S\n]*Interface\s+state\s*:\s*(\S+)',
        re.IGNORECASE | re.MULTILINE,
    )
    # Identifier bytes ethtool decodes with cmis.c (QSFP-DD, OSFP, DSFP, the
    # QSFP112-class "QSFP+ or later with CMIS", SFP-DD, SFP+ with CMIS).  The
    # byte decides; the name covers collectors that print no byte.
    CMIS_IDENTIFIER_RE = re.compile(
        r'^[^\S\n]*Identifier\s*:\s*(?:0x(?:18|19|1b|1e|1f|20)\b|'
        r'[^\n]*(?:QSFP-DD|OSFP|DSFP|QSFP112|SFP-DD|CMIS))',
        re.IGNORECASE | re.MULTILINE,
    )
    # A condition of the module itself, not of one lane: in a breakout cage
    # every sub-port reads it from the same module.
    MODULE_SCOPE_METRICS = frozenset({'temperature', 'voltage'})
    BREAKOUT_PORT_RE = re.compile(r'(?P<cage>swp\d+)s(?P<index>\d+)')

    def __init__(self, data_dir="monitor-results", load_history=True):
        self.data_dir = data_dir
        self.optical_history = {}  # port -> historical readings
        self.current_optical_stats = {}  # port -> current optical status
        self._legacy_history_loaded = False
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        self._load_network_thresholds()

        # Parse worker processes only need thresholds and parsing logic;
        # loading the multi-megabyte history in every worker would cost more
        # than the parallel parse saves.
        if load_history:
            self.load_optical_history()

    def _load_network_thresholds(self) -> None:
        """Load the configurable margin while retaining safe defaults.

        Laser bias uses the module's own thresholds and flags from ethtool.
        RX/TX power, temperature and voltage use the module's own thresholds
        when it prints a valid table and the documented defaults above
        otherwise.
        """
        if yaml is None:
            return
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'notifications.yaml'),
            os.path.join(os.path.dirname(os.path.abspath(self.data_dir)),
                         'notifications.yaml'),
        ]
        for path in dict.fromkeys(candidates):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, 'r') as stream:
                    config = yaml.safe_load(stream) or {}
                # A section whose keys are all commented out loads as None,
                # and a hand-edited file can hold any type at either level.
                thresholds = (config.get('thresholds')
                              if isinstance(config, dict) else None)
                network = (thresholds.get('network')
                           if isinstance(thresholds, dict) else None)
                value = (network.get('optical_power_margin')
                         if isinstance(network, dict) else None)
                if value is None:
                    return
                try:
                    margin = float(value)
                except (TypeError, ValueError, OverflowError):
                    margin = math.nan
                if math.isfinite(margin) and margin >= 0:
                    self.thresholds['link_margin_min_db'] = margin
                else:
                    self._report_ignored_margin(path, value)
                return
            except (OSError, TypeError, ValueError, AttributeError,
                    yaml.YAMLError):
                # Invalid or unreadable configuration deliberately keeps the
                # documented 3 dB default.
                return

    def _report_ignored_margin(self, path: str, value: Any) -> None:
        """Say once that a configured optical margin is not in effect."""
        # A parse worker reads the same file as the process that started it.
        if (multiprocessing.parent_process() is not None
                or path in _REPORTED_IGNORED_MARGINS):
            return
        _REPORTED_IGNORED_MARGINS.add(path)
        print(f"⚠️  Ignoring optical_power_margin {str(value)[:40]!r} in "
              f"{path}: it must be a number of dB, 0 or greater. Using "
              f"{self.thresholds['link_margin_min_db']} dB.")

    def load_optical_history(self):
        """Load historical optical data from per-device shards.

        A still-present monolithic optical_history.json is the authoritative
        one-time migration source: it is loaded whole, and the next
        save_optical_history() splits it into optical-history/<host>.json
        shards and retires it (monitor.sh's analyzer transaction snapshots
        both sides, so a failed run restores monolith and shard directory
        together).
        """
        monolith = f"{self.data_dir}/optical_history.json"
        try:
            with open(monolith, "r") as f:
                data = json.load(f)
            self.optical_history = data.get("optical_history", {})
            self.current_optical_stats = data.get("current_optical_stats", {})
            self._legacy_history_loaded = True
            return
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        shard_dir = os.path.join(self.data_dir, HISTORY_DIR_NAME)
        try:
            shard_names = sorted(os.listdir(shard_dir))
        except FileNotFoundError:
            return
        for name in shard_names:
            if not name.endswith(".json"):
                continue
            host = name[: -len(".json")]
            history, current, _shard = self.load_history_shard(host)
            self.optical_history.update(history)
            self.current_optical_stats.update(current)

    def history_shard_path(self, host: str) -> str:
        return os.path.join(self.data_dir, HISTORY_DIR_NAME, f"{host}.json")

    def load_history_shard(self, host: str):
        """Return (history, current, shard) for one device's shard.

        ``shard`` is the raw document (callers read idempotency metadata from
        it) or None when the file does not exist; a corrupt or unreadable
        shard yields an empty non-None dict, dropping only this device's
        history (its trends restart from the current run).

        Parse workers seed their per-file state with this.
        """
        path = self.history_shard_path(host)
        try:
            with open(path, "r") as f:
                shard = json.load(f)
        except FileNotFoundError:
            return {}, {}, None
        except (OSError, UnicodeError, json.JSONDecodeError) as e:
            print(f"Error reading optical history shard {host}.json: {e}")
            return {}, {}, {}
        if not isinstance(shard, dict):
            return {}, {}, {}
        history = shard.get("history", {})
        if not isinstance(history, dict):
            history = {}
        current = shard.get("current", {})
        if not isinstance(current, dict):
            current = {}
        return history, current, shard

    def _host_bucket(self, host: str) -> Dict[str, Dict[str, Any]]:
        """This host's slice of the in-memory history/current state.

        The persisted current snapshot drops the sidecar-only keys: that
        expandable-row evidence lives in the optical-details/ sidecars, and no
        machine consumer of the shards reads it.  The in-memory current keeps
        it (the detail sidecars are built from there).
        """
        prefix = f"{host}:"
        return {
            "history": {
                port: entries
                for port, entries in self.optical_history.items()
                if port.startswith(prefix)
            },
            "current": {
                port: {
                    key: value for key, value in stats.items()
                    if key not in SIDECAR_ONLY_STAT_KEYS
                }
                for port, stats in self.current_optical_stats.items()
                if port.startswith(prefix)
            },
        }

    def _write_history_shard(self, host: str,
                             payload: Dict[str, Any]) -> Optional[str]:
        try:
            _atomic_write(
                self.history_shard_path(host),
                json.dumps(
                    {
                        "version": 1,
                        "updated_at": time.time(),
                        "host": host,
                        **payload,
                    },
                    separators=(",", ":"), ensure_ascii=True,
                ),
            )
            return None
        except Exception as exc:
            return f"{host}: {type(exc).__name__}: {exc}"

    def write_history_shard(self, host: str,
                            source_mtime: Optional[float] = None
                            ) -> Optional[str]:
        """Persist one device's shard from the in-memory state.

        ``source_mtime`` records which collection file produced this write;
        the parse worker uses it to recognize an already-merged file and skip
        the duplicate history append (pool-retry and re-analysis cases).

        Returns an error string on failure (parse workers propagate it so
        the run fails loudly instead of silently losing history).
        """
        if not SHARD_HOST_RE.fullmatch(host):
            return f"{host!r}: unsafe shard hostname"
        payload = self._host_bucket(host)
        if source_mtime is not None:
            payload["source_mtime"] = source_mtime
        return self._write_history_shard(host, payload)

    def save_optical_history(self):
        """Persist the full in-memory state into per-device shards.

        The steady-state writer is the per-device parse worker
        (write_history_shard); this full-state path serves the one-time
        monolith migration and history-loaded compatibility flows.
        """
        try:
            shard_dir = os.path.join(self.data_dir, HISTORY_DIR_NAME)
            # The directory itself is contractual (validated after every
            # run) even when no device produced optical history this run.
            os.makedirs(shard_dir, exist_ok=True)

            hosts = {
                port.split(":", 1)[0] for port in self.optical_history
            } | {
                port.split(":", 1)[0] for port in self.current_optical_stats
            }
            unsafe_hosts = sorted(
                host for host in hosts if not SHARD_HOST_RE.fullmatch(host)
            )
            if unsafe_hosts:
                # Refusing only the unsafe names would strand them in the
                # monolith forever; drop them with a loud warning instead.
                print("Skipping unsafe optical shard hostnames: "
                      + ", ".join(unsafe_hosts))

            tasks = sorted(hosts - set(unsafe_hosts))
            errors: List[str] = []
            if tasks:
                # Small shards: json.dumps is cheap and the win is
                # overlapping the per-file fsyncs.
                workers = max(1, min(8, os.cpu_count() or 2, len(tasks)))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    for error in executor.map(self.write_history_shard, tasks):
                        if error is not None:
                            errors.append(error)
            if errors:
                print("Optical history shard writes failed: "
                      + "; ".join(errors))
                return False

            if self._legacy_history_loaded:
                # Every shard from the monolith is durably written; retire
                # the legacy document (monitor.sh's analyzer transaction
                # restores both sides together if this run later fails).
                monolith = f"{self.data_dir}/optical_history.json"
                try:
                    os.unlink(monolith)
                except FileNotFoundError:
                    pass
                try:
                    analysis_sidecar.sidecar_path(monolith).unlink()
                except OSError:
                    pass
                self._legacy_history_loaded = False
            return True
        except Exception as e:
            print(f"Error saving optical history: {e}")
            return False

    def prune_history_shards(self, active_hosts) -> bool:
        """Unlink per-device history shards for retired devices."""
        shard_dir = os.path.join(self.data_dir, HISTORY_DIR_NAME)
        try:
            shard_names = os.listdir(shard_dir)
        except FileNotFoundError:
            return True
        ok = True
        for name in shard_names:
            if not name.endswith(".json"):
                continue
            host = name[: -len(".json")]
            if host in active_hosts:
                continue
            shard_path = os.path.join(shard_dir, name)
            try:
                os.unlink(shard_path)
            except OSError as exc:
                print(f"❌ Could not prune retired optical shard {name}: {exc}")
                ok = False
                continue
            try:
                analysis_sidecar.sidecar_path(shard_path).unlink()
            except OSError:
                pass
        return ok

    def clear_stale_shard_current(self, processed_hosts) -> bool:
        """Empty the persisted current snapshot of unrefreshed shards.

        The monolith rebuilt current_optical_stats from scratch every run, so
        a device without a current collection dropped out of the persisted
        snapshot; shard consumers (alerts, AI context) must see the same:
        history survives, current does not.
        """
        shard_dir = os.path.join(self.data_dir, HISTORY_DIR_NAME)
        try:
            shard_names = sorted(os.listdir(shard_dir))
        except FileNotFoundError:
            return True
        stale = [
            name[: -len(".json")]
            for name in shard_names
            if name.endswith(".json")
            and name[: -len(".json")] not in processed_hosts
        ]

        def clear_one(host: str) -> Optional[str]:
            path = self.history_shard_path(host)
            try:
                with open(path, "r") as f:
                    shard = json.load(f)
            except FileNotFoundError:
                return None
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                return f"{host}: {type(exc).__name__}: {exc}"
            if not isinstance(shard, dict) or not shard.get("current"):
                return None
            shard["current"] = {}
            shard["updated_at"] = time.time()
            try:
                _atomic_write(
                    path,
                    json.dumps(shard, separators=(",", ":"),
                               ensure_ascii=True),
                )
                return None
            except Exception as exc:
                return f"{host}: {type(exc).__name__}: {exc}"

        errors: List[str] = []
        if stale:
            workers = max(1, min(8, os.cpu_count() or 2, len(stale)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for error in executor.map(clear_one, stale):
                    if error is not None:
                        errors.append(error)
        if errors:
            print("Optical shard current-snapshot reconcile failed: "
                  + "; ".join(errors))
            return False
        return True

    def parse_optical_data(self, optical_data: str) -> Optional[Dict[str, Any]]:
        """Parse optical output (NVUE transceiver commands) for optical parameters
        
        Returns None if this is a DAC/Copper cable (not optical)
        """
        # The one rule that tells copper from optical is _is_copper: copper
        # is named and no lane carries light or laser bias.  A copper block
        # normally holds no reading at all, and then the answer is known
        # before the per-line pass below; this is most blocks of a DAC rack.
        names_copper = self._names_copper(optical_data)
        if names_copper and not self._prints_nonzero_reading(optical_data):
            return None

        optical_params = {
            'rx_power_dbm': None,
            'tx_power_dbm': None,
            'temperature_c': None,
            'voltage_v': None,
            'bias_current_ma': None
        }

        # Preserve lane identity.  The scalar values exposed to the report are
        # selected from the worst lane below rather than averaged, so the
        # displayed value explains the resulting severity.
        rx_readings = []
        tx_readings = []
        bias_readings = []

        number = r'[-+]?(?:\d+(?:\.\d*)?|\.\d+)'
        # Both halves of a power reading are captured.  The dBm field is what
        # the report displays, but the mW field is the one that cannot be
        # spelled ambiguously, and an unlit lane is recognised from it.
        power_value = (rf'(?P<milliwatts>-?inf|{number})\s*mW\s*/\s*'
                       rf'(?P<value>-?inf|{number})\s*dBm')
        # A module that measures receive power as OMA is labelled 'Receiver
        # signal OMA' by ethtool (qsfp.c, cmis.c, sfpdiag.c), with or without
        # a blank before '(Channel N)'; it is that lane's receive power.
        rx_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-rx-power|'
            rf'(?:Rcvr|Receiver)\s+signal\s+'
            rf'(?:(?:avg|average)\s+optical\s+power|OMA)'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*{power_value}',
            re.IGNORECASE,
        )
        tx_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-tx-power|'
            rf'(?:Transmit\s+avg\s+optical\s+power|Laser\s+output\s+power)'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*{power_value}',
            re.IGNORECASE,
        )
        bias_pattern = re.compile(
            rf'(?:ch-(?P<nvue_lane>\d+)-tx-bias-current|'
            rf'Laser\s+(?:tx\s+)?bias\s+current'
            rf'(?:\s*\(\s*Channel\s+(?P<ethtool_lane>\d+)\s*\))?)'
            rf'\s*:\s*(?P<value>{number})\s*mA',
            re.IGNORECASE,
        )
        bias_threshold_pattern = re.compile(
            r'^Laser\s+(?:tx\s+)?bias\s+current\s+'
            r'(?P<direction>high|low)\s+(?P<kind>alarm|warning)\s+threshold'
            r'\s*:\s*(?P<value>\S+)\s*mA\s*$', re.IGNORECASE,
        )
        bias_flag_pattern = re.compile(
            r'^Laser\s+(?:tx\s+)?bias\s+current\s+'
            r'(?P<direction>high|low)\s+(?P<kind>alarm|warning)'
            r'(?:\s*\(\s*Chan(?:nel)?\s+(?P<lane>\d+)\s*\))?'
            r'\s*:\s*(?P<state>on|off)\s*$', re.IGNORECASE,
        )
        # The other four tables ethtool's sff_show_thresholds prints next to
        # the bias one, with the same labels for CMIS, SFF-8636 and SFF-8472
        # modules.  'Laser output power' is TX; power is printed as mW / dBm,
        # temperature as degrees C / degrees F and voltage in V.
        module_threshold_pattern = re.compile(
            r'^(?P<label>Laser\s+output\s+power|Laser\s+rx\s+power|'
            r'Module\s+temperature|Module\s+voltage)\s+'
            r'(?P<direction>high|low)\s+(?P<kind>alarm|warning)\s+threshold'
            r'\s*:\s*(?P<reading>.*)$', re.IGNORECASE,
        )
        module_threshold_metrics = {
            'laser output power': 'tx_power',
            'laser rx power': 'rx_power',
            'module temperature': 'temperature',
            'module voltage': 'voltage',
        }
        power_threshold_pattern = re.compile(power_value, re.IGNORECASE)
        temperature_threshold_pattern = re.compile(
            r'(?P<value>\S+)\s*degrees?\s*C\b.*', re.IGNORECASE)
        voltage_threshold_pattern = re.compile(
            r'(?P<value>\S+)\s*V', re.IGNORECASE)
        bias_thresholds = {}
        bias_flags = {}
        module_thresholds = {}

        def module_threshold_value(metric, reading):
            """One printed module limit, or None when it defines no limit."""
            try:
                if metric in ('rx_power', 'tx_power'):
                    match = power_threshold_pattern.fullmatch(reading)
                    # A limit the module leaves unset reads 0 mW / -inf dBm.
                    if not match or not float(match.group('milliwatts')) > 0:
                        return None
                    value = float(match.group('value'))
                elif metric == 'temperature':
                    match = temperature_threshold_pattern.fullmatch(reading)
                    if not match:
                        return None
                    value = float(match.group('value'))
                else:
                    match = voltage_threshold_pattern.fullmatch(reading)
                    # 0.0000 V is an unset limit, as 0 mW is for power.
                    if not match or not float(match.group('value')) > 0:
                        return None
                    value = float(match.group('value'))
            except ValueError:
                return None
            return value if math.isfinite(value) else None

        def lane_number(match, readings):
            value = match.groupdict().get('nvue_lane') or match.groupdict().get('ethtool_lane')
            return int(value) if value is not None else len(readings) + 1

        def power_from_match(match):
            """One lane's power in dBm, with no light floored consistently.

            Collectors spell an unlit lane as ``-inf dBm``, but some render a
            finite placeholder next to ``0.0000 mW``.  Zero milliwatts is no
            light whatever the dBm column says, so it is read first.
            """
            milliwatts = match.group('milliwatts').lower()
            if milliwatts == '-inf' or (milliwatts != 'inf'
                                        and float(milliwatts) == 0.0):
                return self.NEGATIVE_INFINITY_FLOOR_DBM
            value = match.group('value').lower()
            if value == '-inf':
                return self.NEGATIVE_INFINITY_FLOOR_DBM
            if value == 'inf':
                return abs(self.NEGATIVE_INFINITY_FLOOR_DBM)
            return float(value)

        lines = optical_data.strip().split('\n')
        for line in lines:
            line = line.strip()
            threshold_match = bias_threshold_pattern.match(line)
            if threshold_match:
                try:
                    value = float(threshold_match.group('value'))
                    if math.isfinite(value) and value >= 0:
                        key = (threshold_match.group('direction').lower() + '_'
                               + threshold_match.group('kind').lower())
                        bias_thresholds[key] = value
                except ValueError:
                    pass
            limit_match = module_threshold_pattern.match(line)
            if limit_match:
                metric = module_threshold_metrics[
                    ' '.join(limit_match.group('label').lower().split())]
                value = module_threshold_value(
                    metric, limit_match.group('reading'))
                if value is not None:
                    key = (limit_match.group('direction').lower() + '_'
                           + limit_match.group('kind').lower())
                    module_thresholds.setdefault(metric, {})[key] = value
            flag_match = bias_flag_pattern.match(line)
            if flag_match:
                lane = str(int(flag_match.group('lane') or 1))
                key = (flag_match.group('direction').lower() + '_'
                       + flag_match.group('kind').lower())
                bias_flags.setdefault(lane, {})[key] = (
                    flag_match.group('state').lower() == 'on'
                )

            # Parse temperature (NVUE format: "temperature : 48.71 degrees C" or ethtool: "Module temperature : 48.85 degrees C")
            # Exactly 0.00 C / 0.0000 V is what a module without that
            # monitor prints (ethtool prints both for a cable): not read.
            # A malformed number ('1.2.3') is no reading; it must not abort
            # the device's whole file.
            temp_match = re.search(r'(?:Module\s+)?temperature\s*:\s*([\d.-]+)\s*degrees?\s*C', line)
            if temp_match:
                try:
                    optical_params['temperature_c'] = float(temp_match.group(1)) or None
                except ValueError:
                    pass

            # Parse voltage (NVUE format: "voltage : 3.2688 V" or ethtool: "Module voltage : 3.2096 V")
            voltage_match = re.search(r'(?:Module\s+)?voltage\s*:\s*([\d.-]+)\s*V', line)
            if voltage_match:
                try:
                    optical_params['voltage_v'] = float(voltage_match.group(1)) or None
                except ValueError:
                    pass

            rx_power_match = rx_pattern.search(line)
            if rx_power_match:
                try:
                    rx_readings.append((
                        lane_number(rx_power_match, rx_readings),
                        power_from_match(rx_power_match),
                    ))
                except ValueError:
                    pass

            tx_power_match = tx_pattern.search(line)
            if tx_power_match:
                try:
                    tx_readings.append((
                        lane_number(tx_power_match, tx_readings),
                        power_from_match(tx_power_match),
                    ))
                except ValueError:
                    pass

            bias_match = bias_pattern.search(line)
            if bias_match:
                try:
                    bias_readings.append((
                        lane_number(bias_match, bias_readings),
                        float(bias_match.group('value')),
                    ))
                except ValueError:
                    pass

        # DAC/Copper cables don't have optical diagnostics.  Decided after the
        # readings are known: light or laser bias proves an optical cable
        # whatever its identity lines say.
        if names_copper and not self._lit_or_driven(
                rx_readings, tx_readings, bias_readings):
            return None

        # The collector prints the operstate into the block.  It tells a
        # monitor the module does not implement from a dark module.
        state_match = self.INTERFACE_STATE_RE.search(optical_data)
        optical_params['_interface_state'] = (
            state_match.group(1).strip().lower() if state_match else None)
        # ethtool's CMIS channel flag lines need the measured value to back
        # them (see _bias_lane_events).
        optical_params['_cmis'] = bool(
            self.CMIS_IDENTIFIER_RE.search(optical_data))

        # Reject unsupported all-zero or internally inconsistent tables, not
        # the measured current.  Partial valid limits can still prove a fault.
        bias_thresholds = self._consistent_limit_table(bias_thresholds)
        optical_params['bias_thresholds_ma'] = bias_thresholds
        optical_params['bias_flags'] = bias_flags
        # The same rule for every other table the module prints.  Set before
        # the lane readings below: the displayed lane is picked with them.
        optical_params['module_thresholds'] = {}
        # Tables set aside as implausible, as printed, for the detail row.
        optical_params['_implausible_module_tables'] = {}
        for metric in self.MODULE_LIMIT_METRICS:
            table = self._consistent_limit_table(
                module_thresholds.get(metric, {}))
            if table and not self._plausible_limit_table(metric, table):
                # Dropped whole, like an inconsistent table: the metric
                # falls back to the generic rules.
                optical_params['_implausible_module_tables'][metric] = table
                continue
            if table:
                optical_params['module_thresholds'][metric] = table
        # Every lane as collected, before the declared-single-lane filter
        # below.  A breakout sub-port shares the module with its siblings, so
        # the channels it owns are told from the whole dump.  Internal: the
        # stored stats, history and exports copy named fields only.
        optical_params['_unfiltered_lane_readings'] = {
            'rx_power': rx_readings,
            'tx_power': tx_readings,
            'bias_current': bias_readings,
        }
        self._set_lane_readings(optical_params, 'rx_power', rx_readings)
        self._set_lane_readings(optical_params, 'tx_power', tx_readings)
        self._set_lane_readings(optical_params, 'bias_current', bias_readings)
        self._select_declared_optical_lanes(optical_data, optical_params)

        return optical_params

    def _is_copper(self, optical_data, rx_readings, tx_readings,
                   bias_readings) -> bool:
        """True for a copper assembly: there is no optical path to grade.

        'AOC' / 'Active Optical' in the transceiver type, or a lane that
        carries light or laser bias, mean optical even next to a copper
        indicator: ethtool prints 'Active Cable' and 'Active Cu cmplnce.'
        for an SFP active optical cable as well.
        """
        return (self._names_copper(optical_data) and
                not self._lit_or_driven(rx_readings, tx_readings,
                                        bias_readings))

    def _descriptor_lines(self, text: str, tokens):
        """Lines of lowercased ``text`` holding a token, identity lines left out."""
        seen = set()
        for token in tokens:
            position = text.find(token)
            while position != -1:
                start = text.rfind('\n', 0, position) + 1
                end = text.find('\n', position)
                if end == -1:
                    end = len(text)
                if start not in seen:
                    seen.add(start)
                    line = text[start:end]
                    if not self.IDENTITY_LINE_RE.match(line):
                        yield line
                position = text.find(token, end)

    def _names_copper(self, optical_data: str) -> bool:
        """True when the descriptor lines name copper and no optical cable."""
        text = optical_data.lower()
        if not any(self.COPPER_INDICATOR_RE.search(line) for line in
                   self._descriptor_lines(text, self.COPPER_TOKENS)):
            return False
        return not any(self.ACTIVE_OPTICAL_RE.search(line) for line in
                       self._descriptor_lines(text, self.ACTIVE_OPTICAL_TOKENS))

    def _prints_nonzero_reading(self, optical_data: str) -> bool:
        """The block holds a mW or mA value that is not zero."""
        for unit in self.READING_UNIT_RE.finditer(optical_data):
            line_start = optical_data.rfind('\n', 0, unit.start()) + 1
            if self.NONZERO_VALUE_RE.search(optical_data, line_start,
                                            unit.start()):
                return True
        return False

    def _lit_or_driven(self, rx_readings, tx_readings, bias_readings) -> bool:
        """A lane carries light or laser bias: an optical path exists."""
        return (any(value > self.DARK_POWER_DBM
                    for _lane, value in rx_readings + tx_readings) or
                any(value > self.LASER_OFF_BIAS_MA
                    for _lane, value in bias_readings))

    @staticmethod
    def _consistent_limit_table(table):
        """``table`` unless it is all-zero or internally inconsistent."""
        ordered = [table[key] for key in
                   ('low_alarm', 'low_warning', 'high_warning', 'high_alarm')
                   if key in table]
        low_limits = [v for key, v in table.items() if key.startswith('low_')]
        high_limits = [v for key, v in table.items() if key.startswith('high_')]
        if (ordered and (not any(ordered) or ordered != sorted(ordered) or
                         (low_limits and high_limits and
                          max(low_limits) >= min(high_limits)))):
            return {}
        return table

    def _plausible_limit_table(self, metric, table) -> bool:
        """Every printed limit lies where a real module's limit can lie."""
        low, high = self.MODULE_LIMIT_PLAUSIBLE[metric]
        if metric in ('rx_power', 'tx_power'):
            return all(low < value <= high for value in table.values())
        return all(low <= value <= high for value in table.values())

    def _deciding_limits(self, optical_params, metric):
        """The module's own table for ``metric`` when it is complete.

        Only a complete table replaces the generic rules: with a side
        missing nothing would watch that side at all.
        """
        table = (optical_params.get('module_thresholds') or {}).get(metric) or {}
        if all(key in table for key in self.MODULE_LIMIT_KEYS):
            return table
        return None

    @staticmethod
    def _module_limit_event(metric, lane, value, limits):
        """The strongest module limit ``value`` is beyond, or None."""
        for direction in ('low', 'high'):
            for kind, severity in (('alarm', 'critical'), ('warning', 'warning')):
                limit = limits.get(f'{direction}_{kind}')
                if limit is None:
                    continue
                if (value < limit) if direction == 'low' else (value > limit):
                    return {
                        'metric': metric, 'lane': lane, 'value': value,
                        'threshold': limit, 'direction': direction,
                        'kind': kind, 'severity': severity,
                    }
        return None

    def _module_reading_tier(self, metric, value, limits):
        """Sortable (tier, distance) of one reading on a complete module table.

        Tier 4 is a dark receive lane, 3 beyond an alarm limit, 2 beyond a
        warning limit or under the configured link margin, 1.5 healthy but
        close to a warning limit and 1 comfortable.  Grading and the lane
        picked for display both read it, so the row shows the lane that
        explains the badge.
        """
        low_alarm, high_alarm = limits['low_alarm'], limits['high_alarm']
        low_warning, high_warning = limits['low_warning'], limits['high_warning']
        if metric == 'rx_power' and value <= self.DARK_POWER_DBM:
            return (4, low_alarm - value)
        if value < low_alarm or value > high_alarm:
            return (3, max(low_alarm - value, value - high_alarm))
        band = self.MODULE_GOOD_BAND[metric]
        low_gap = low_warning - value
        good_low_gap = (low_warning + band) - value
        if metric == 'rx_power':
            # The operator's margin counts up from the module's low alarm.
            margin = self.calculate_link_margin(value, low_alarm)
            margin_min = self.thresholds['link_margin_min_db']
            low_gap = max(low_gap, margin_min - margin)
            good_low_gap = (margin_min + 3.0) - margin
        high_gap = value - high_warning
        if low_gap > 0 or high_gap > 0:
            return (2, max(low_gap, high_gap))
        good_high_gap = value - (high_warning - band)
        if good_low_gap > 0 or good_high_gap > 0:
            return (1.5, max(good_low_gap, good_high_gap))
        return (1, max(low_gap, high_gap))

    @staticmethod
    def _module_limit_readings(optical_params):
        """metric -> [(lane or None, value)] of the readings that are graded."""
        readings = {}
        for metric in ('rx_power', 'tx_power'):
            values = optical_params.get(f'_{metric}_lanes_dbm') or []
            lanes = optical_params.get(f'_{metric}_lane_ids') or []
            if not values and optical_params.get(f'{metric}_dbm') is not None:
                values = [optical_params[f'{metric}_dbm']]
                lanes = [optical_params.get(f'{metric}_lane')]
            readings[metric] = [
                (lanes[index] if index < len(lanes) else None, value)
                for index, value in enumerate(values)
            ]
        for metric, key in (('temperature', 'temperature_c'),
                            ('voltage', 'voltage_v')):
            value = optical_params.get(key)
            readings[metric] = [(None, value)] if value is not None else []
        return readings

    def _grade_module_limits(self, optical_params):
        """What the module's own limits say about the graded readings.

        Returns (deciding, tier, events): the complete tables by metric, the
        worst tier one of their readings reached (see _module_reading_tier)
        and every printed limit a reading is beyond.  A partial table decides
        nothing, but as with bias a limit it does print can prove a fault.
        """
        tables = optical_params.get('module_thresholds') or {}
        readings = self._module_limit_readings(optical_params)
        deciding = {}
        tier = 1
        events = []
        for metric in self.MODULE_LIMIT_METRICS:
            table = tables.get(metric)
            if not table:
                continue
            limits = self._deciding_limits(optical_params, metric)
            if limits is not None:
                deciding[metric] = limits
            for lane, value in readings[metric]:
                if limits is not None:
                    tier = max(tier, self._module_reading_tier(
                        metric, value, limits)[0])
                event = self._module_limit_event(metric, lane, value, table)
                if event:
                    events.append(event)
        return deciding, tier, events

    def _assess_module_limits(self, optical_params):
        """The limits that graded a port, for its expandable detail row."""
        deciding, _tier, events = self._grade_module_limits(optical_params)
        limits = {
            'thresholds': optical_params.get('module_thresholds') or {},
            'decided': list(deciding),
            'events': events,
        }
        # Printed tables that grade nothing because they are implausible.
        ignored = optical_params.get('_implausible_module_tables')
        if ignored:
            limits['ignored'] = ignored
        return limits

    def _module_limit_message(self, event):
        """Name the reading, its lane and the module limit it is beyond."""
        label, number = self.MODULE_LIMIT_TEXT[event['metric']]
        lane = f" on lane {event['lane']}" if event.get('lane') is not None else ''
        side = 'below' if event['direction'] == 'low' else 'above'
        return (f"{label} {number.format(event['value'])}{lane} is {side} the "
                f"module's {event['direction']} {event['kind']} "
                f"{number.format(event['threshold'])}")

    @staticmethod
    def _bias_lane_events(lane, value, thresholds, flags,
                          flag_needs_value=False):
        """Keep the strongest module evidence for each direction on a lane.

        ``flag_needs_value`` is set for CMIS dumps.  ethtool tests a CMIS
        channel flag byte against the channel index instead of the
        channel's bit, so a flag of lane 1 is printed On for channels 2, 4,
        6 and 8.  The measured value and the module's limit are both in the
        dump: a flag that is On while the value is inside that limit is kept
        as 'module flag set, value in range' at warning level.  Without a
        value or a valid limit the flag is all the evidence there is and
        counts as before, as do all SFF-8636/SFF-8472 flags.
        """
        events = []
        for direction in ('low', 'high'):
            in_range_flag = None
            for kind, severity in (('alarm', 'critical'), ('warning', 'warning')):
                key = f'{direction}_{kind}'
                limit = thresholds.get(key)
                exceeded = (value is not None and limit is not None and
                            (value <= limit if direction == 'low' else value >= limit))
                flagged = flags.get(key) is True
                if (flag_needs_value and flagged and not exceeded and
                        value is not None and limit is not None):
                    in_range_flag = in_range_flag or (kind, limit)
                    continue
                if exceeded or flagged:
                    events.append({
                        'lane': lane, 'value_ma': value, 'threshold_ma': limit,
                        'direction': direction, 'kind': kind, 'severity': severity,
                        'source': 'module flag' if flagged else 'module threshold',
                    })
                    break
            else:
                if in_range_flag:
                    kind, limit = in_range_flag
                    events.append({
                        'lane': lane, 'value_ma': value, 'threshold_ma': limit,
                        'direction': direction, 'kind': kind,
                        'severity': 'warning', 'source': 'module flag',
                        'value_in_range': True,
                    })
        return events

    def _assess_bias(self, optical_params):
        """Assess selected lanes only; absent limits are not a universal limit."""
        thresholds = optical_params.get('bias_thresholds_ma') or {}
        flags = optical_params.get('bias_flags') or {}
        values = optical_params.get('_bias_current_lanes_ma') or []
        ids = optical_params.get('_bias_current_lane_ids') or []
        readings = dict(zip(ids, values))
        if not readings and optical_params.get('bias_current_ma') is not None:
            readings[optical_params.get('bias_current_lane') or 1] = optical_params['bias_current_ma']
        selected = set(readings)
        for metric in ('rx_power', 'tx_power'):
            selected.update(optical_params.get(f'_{metric}_lane_ids') or [])
        if not selected:
            selected = {int(lane) for lane in flags}
        selected.difference_update(optical_params.get('_inactive_lane_ids') or [])
        keys = {'low_alarm', 'low_warning', 'high_warning', 'high_alarm'}
        events = []
        complete = bool(selected)
        for lane in sorted(selected):
            value = readings.get(lane)
            lane_flags = flags.get(str(lane), {})
            events.extend(self._bias_lane_events(
                lane, value, thresholds, lane_flags,
                bool(optical_params.get('_cmis'))))
            complete = complete and (
                (value is not None and keys.issubset(thresholds)) or
                keys.issubset(lane_flags)
            )
        if events:
            status = ('critical' if any(e['severity'] == 'critical' for e in events)
                      else 'warning')
            reason = 'Module-reported laser bias limit or alarm flag triggered.'
            if all(e.get('value_in_range') for e in events):
                reason = ('Module bias flag set while the measured bias is '
                          'inside the module limits.')
        elif complete:
            status = 'normal'
            reason = 'No selected lane exceeds module bias limits or reports a bias alarm.'
        else:
            status = 'unknown'
            reason = ('Bias assessment unavailable or partial: module limits or flags '
                      'are missing/invalid. Other optical parameters are still assessed.')
        return {'status': status, 'reason': reason, 'events': events}

    def _declared_optical_lane_count(self, optical_data: str) -> Optional[int]:
        """Return an unambiguous optical lane count from module media text.

        A QSFP host can expose four diagnostic channels even when its optical
        media is single-lane PAM4.  In that case unused channels are commonly
        rendered as ``-40 dBm``/``0 mA`` placeholders.  Conversely, standards
        such as DR4, SR4 and LR4 have genuinely independent optical lanes and
        must retain worst-lane analysis.

        If the raw block advertises conflicting media standards, return
        ``None`` rather than guessing and potentially hiding a failed lane.
        """
        lane_counts = set()
        for match in self.OPTICAL_MEDIA_STANDARD_RE.finditer(optical_data):
            family = match.group('family').upper()
            suffix = match.group('lanes')
            if suffix is not None:
                count = int(suffix)
                if count > 0:
                    lane_counts.add(count)
            elif family in self.UNNUMBERED_SINGLE_LANE_MEDIA:
                lane_counts.add(1)

        if len(lane_counts) == 1:
            return next(iter(lane_counts))
        return None

    def _select_declared_optical_lanes(
            self, optical_data: str,
            optical_params: Dict[str, Any]) -> None:
        """Drop driver placeholder channels for declared single-lane media.

        Filtering is intentionally metadata-driven.  A dark reading or zero
        bias alone is never considered proof that a channel is unused.  Lane
        1 must also be present; otherwise all readings are preserved so an
        unfamiliar channel numbering scheme cannot mask a fault.
        """
        optical_lane_count = self._declared_optical_lane_count(optical_data)
        optical_params['_declared_optical_lane_count'] = optical_lane_count
        if optical_lane_count != 1:
            return

        for metric in ('rx_power', 'tx_power', 'bias_current'):
            lanes_key = (f'_{metric}_lanes_dbm' if metric != 'bias_current'
                         else '_bias_current_lanes_ma')
            ids_key = f'_{metric}_lane_ids'
            values = optical_params.get(lanes_key) or []
            lane_ids = optical_params.get(ids_key) or []
            if len(values) <= 1:
                continue
            readings = list(zip(lane_ids, values))
            lane_one = [item for item in readings if item[0] == 1]
            if lane_one:
                self._set_lane_readings(optical_params, metric, lane_one)

    def _lane_risk(self, metric: str, value: float,
                   limits: Optional[Dict[str, float]] = None) -> tuple:
        """Return a sortable risk tuple used to select the displayed lane.

        ``limits`` is the module's own table when it grades this metric; the
        lane is then ranked by those limits, not by the generic ones.
        """
        if limits is not None:
            return self._module_reading_tier(metric, value, limits)
        if metric == 'rx_power':
            low = self.thresholds['rx_power_min_dbm']
            high = self.thresholds['rx_power_critical_high_dbm']
            if value <= self.DARK_POWER_DBM:
                return (4, low - value)
            if value < low or value > high:
                return (3, max(low - value, value - high))
            if (self.calculate_link_margin(value) < self.thresholds['link_margin_min_db'] or
                    value > self.thresholds['rx_power_warning_high_dbm']):
                return (2, max(low + self.thresholds['link_margin_min_db'] - value,
                               value - self.thresholds['rx_power_warning_high_dbm']))
            # Healthy band: rank by distance to the boundaries that would be
            # violated next (margin floor / warning high) — the same bounds
            # tier 2 uses.  The hard (low, high) window is asymmetric, so
            # ranking by its nearest edge could name a bright-but-safe lane
            # worst while link_margin_db came from the dimmest lane.
            return (1, max(low + self.thresholds['link_margin_min_db'] - value,
                           value - self.thresholds['rx_power_warning_high_dbm']))
        if metric == 'tx_power':
            low = self.thresholds['tx_power_min_dbm']
            high = self.thresholds['tx_power_max_dbm']
            if value < low or value > high:
                return (3, max(low - value, value - high))
            if value < low + 1.0 or value > high - 1.0:
                return (2, max(low + 1.0 - value, value - (high - 1.0)))
            return (1, -min(value - low, high - value))
        # Bias without module limits has no universal numeric risk boundary.
        return (1, value)

    def _set_lane_readings(self, optical_params: Dict[str, Any], metric: str,
                           readings: List[tuple]) -> None:
        value_key = f'{metric}_dbm' if metric != 'bias_current' else 'bias_current_ma'
        lanes_key = f'_{metric}_lanes_dbm' if metric != 'bias_current' else '_bias_current_lanes_ma'
        ids_key = f'_{metric}_lane_ids'
        lane_key = f'{metric}_lane'

        optical_params[lanes_key] = [value for _lane, value in readings]
        optical_params[ids_key] = [lane for lane, _value in readings]
        optical_params[lane_key] = None
        if not readings:
            optical_params[value_key] = None
            return

        limits = self._deciding_limits(optical_params, metric)
        # A limit of an incomplete module table still raises the badge, so
        # the lane beyond it must be the displayed one as well.
        printed_limits = ((optical_params.get('module_thresholds') or {})
                          .get(metric) if limits is None else None)

        def risk(item):
            lane, value = item
            if metric != 'bias_current':
                lane_risk = self._lane_risk(metric, value, limits)
                event = (self._module_limit_event(metric, lane, value,
                                                  printed_limits)
                         if printed_limits else None)
                if event:
                    lane_risk = max(lane_risk, (
                        3 if event['severity'] == 'critical' else 2,
                        abs(value - event['threshold']),
                    ))
                return lane_risk
            events = self._bias_lane_events(
                lane, value, optical_params.get('bias_thresholds_ma') or {},
                (optical_params.get('bias_flags') or {}).get(str(lane), {}),
                bool(optical_params.get('_cmis')),
            )
            severity = max((3 if e['severity'] == 'critical' else 2
                            for e in events), default=1)
            distance = max((max(0, (e['threshold_ma'] - value
                                   if e['direction'] == 'low'
                                   else value - e['threshold_ma']))
                            for e in events if e['threshold_ma'] is not None),
                           default=0)
            return (severity, distance, value)

        lane, value = max(readings, key=risk)
        optical_params[value_key] = value
        optical_params[lane_key] = lane

    @staticmethod
    def _power_of_two_ceiling(value: int) -> int:
        """Smallest power of two that is not below ``value``."""
        power = 1
        while power < value:
            power <<= 1
        return power

    @staticmethod
    def _lane_readings_as_collected(
            optical_params: Optional[Dict[str, Any]]) -> Dict[str, List[tuple]]:
        """metric -> [(channel, value)] before any lane was filtered out."""
        params = optical_params or {}
        collected = params.get('_unfiltered_lane_readings')
        if collected is None:
            # Not a parse_optical_data result: the lane lists it carries are
            # all the evidence there is.
            collected = {}
            for metric in ('rx_power', 'tx_power', 'bias_current'):
                lanes_key = (f'_{metric}_lanes_dbm' if metric != 'bias_current'
                             else '_bias_current_lanes_ma')
                collected[metric] = zip(params.get(f'_{metric}_lane_ids') or [],
                                        params.get(lanes_key) or [])
        return {metric: list(collected.get(metric) or [])
                for metric in ('rx_power', 'tx_power', 'bias_current')}

    def plan_breakout_lanes(self, siblings: Dict[int, Dict[str, Any]]
                            ) -> Optional[int]:
        """Channels per sub-port for one breakout cage, or None.

        ``ethtool -m`` on swp<N>s<M> returns the whole module, identical for
        every sibling, so the channels a sub-port owns can only be told from
        the cage: its sub-ports share the module's channels equally and in
        order, sub-port k owning channels k*B+1 .. (k+1)*B.  B is chosen from
        the DOM itself: a link-up sub-port's channels must be in service.
        The switch side's host-lane width is deliberately not used; a module
        with fewer optical lanes than host lanes (400G-DR4 split 4x100G)
        numbers its DOM channels by optical lane, one per sub-port.

        ``siblings`` maps the suffix M of every swp<N>s<M> block the device's
        collection holds for the cage to ``{'state': <operstate or None>,
        'params': <parse_optical_data result or None>}``.  A block without
        lane readings (no module data, failed read, DAC) still counts as a
        sub-port.  None means the cage gives nothing to plan from and every
        block keeps the standalone rule (channel M+1).
        """
        tables: Dict[int, Dict[int, Dict[str, float]]] = {}
        for index, sibling in siblings.items():
            table: Dict[int, Dict[str, float]] = {}
            collected = self._lane_readings_as_collected(
                (sibling or {}).get('params'))
            for metric, readings in collected.items():
                for lane, value in readings:
                    table.setdefault(lane, {})[metric] = value
            if table:
                tables[index] = table
        if not tables:
            return None

        # A lone swpNs0 block is still one of at least two sub-ports.
        sub_ports = max(2, self._power_of_two_ceiling(
            max(len(siblings), max(siblings) + 1)))
        channels = self._power_of_two_ceiling(
            max(max(table) for table in tables.values()))

        dark, off = self.DARK_POWER_DBM, self.LASER_OFF_BIAS_MA

        def receiving(reading):
            return reading.get('rx_power', dark) > dark

        def driven(reading):
            return (reading.get('tx_power', dark) > dark or
                    reading.get('bias_current', off) > off)

        every_reading = [reading for table in tables.values()
                         for reading in table.values()]
        # A DOM side the module never shows alive (rx power not implemented,
        # no transmit monitoring) is not evidence against any block size.
        rx_seen = any(receiving(reading) for reading in every_reading)
        tx_seen = any(driven(reading) for reading in every_reading)
        # The sub-ports together must cover every channel that is alive.
        need = max((lane for table in tables.values()
                    for lane, reading in table.items()
                    if receiving(reading) or driven(reading)), default=0)
        candidates = []
        block = 1
        while sub_ports * block <= channels:
            if sub_ports * block >= need:
                candidates.append(block)
            block <<= 1
        if not candidates:
            # More sub-ports than channels: nothing to share out.
            return None

        # A sub-port's link state is judged against its own dump, read back
        # to back with that state; a sibling's dump only stands in for a
        # channel its own dump does not report.
        shared: Dict[int, Dict[str, float]] = {}
        for index in sorted(tables):
            for lane, reading in tables[index].items():
                shared.setdefault(lane, reading)

        def out_of_service(reading):
            rx = reading.get('rx_power')
            if rx_seen and rx is not None and rx <= dark:
                return True
            tx = reading.get('tx_power')
            bias = reading.get('bias_current')
            if not tx_seen or (tx is None and bias is None):
                return False
            return ((tx is None or tx <= dark) and
                    (bias is None or bias <= off))

        link_up = {
            index for index, sibling in siblings.items()
            if str((sibling or {}).get('state') or '').strip().lower() == 'up'
        }

        def refuting(block):
            """Channels a link-up sub-port would own although out of service."""
            # One pass over the reported channels, each asking for its
            # owner: walking every sub-port's block over every channel made
            # an oversized (corrupted) cage quadratic.  The block is a power
            # of two, so the owner is a shift, cheap for any channel number.
            shift = block.bit_length() - 1
            count = 0
            for lane, reading in shared.items():
                index = (lane - 1) >> shift
                if index in link_up and out_of_service(
                        tables.get(index, {}).get(lane, reading)):
                    count += 1
            return count

        # Fewest contradictions wins; when no link-up sub-port can decide,
        # the widest consistent block is used.
        return min(candidates, key=lambda block: (refuting(block), -block))

    def _select_breakout_block(self, index: int, optical_params: Dict[str, Any],
                               lanes_per_subport: int) -> None:
        """Limit sub-port ``index`` to the channel block the cage plan gave it."""
        first = index * lanes_per_subport + 1
        last = (index + 1) * lanes_per_subport
        collected = self._lane_readings_as_collected(optical_params)
        flags = optical_params.get('bias_flags') or {}
        reported = {lane for readings in collected.values()
                    for lane, _value in readings}
        reported.update(int(lane) for lane in flags)
        if not any(first <= lane <= last for lane in reported):
            # Already interface-scoped or numbered in an unfamiliar way:
            # hiding evidence would be worse than showing a sibling's lane.
            return
        optical_params['bias_flags'] = {
            lane: state for lane, state in flags.items()
            if first <= int(lane) <= last
        }
        for metric, readings in collected.items():
            self._set_lane_readings(optical_params, metric, [
                item for item in readings if first <= item[0] <= last
            ])

    def _select_breakout_lane(self, port_name: str,
                              optical_params: Dict[str, Any],
                              lanes_per_subport: Optional[int] = None) -> None:
        """Limit a breakout interface to the physical channels it owns.

        Drivers often return all cage lanes for every `swpNsM` interface.
        With the cage's plan (``lanes_per_subport``, see plan_breakout_lanes)
        the interface owns channels M*B+1 .. (M+1)*B.  Without sibling
        context channel M+1 is the only lane owned by the logical interface.
        A single returned lane is already interface-scoped and is left intact.
        """
        interface = port_name.split(':', 1)[-1]
        match = re.fullmatch(r'swp\d+s(\d+)', interface)
        if not match:
            return
        if lanes_per_subport is not None:
            self._select_breakout_block(int(match.group(1)), optical_params,
                                        lanes_per_subport)
            return
        wanted_lane = int(match.group(1)) + 1
        flags = optical_params.get('bias_flags') or {}
        # Measurement IDs determine ownership whenever available, including
        # a single already-scoped lane whose number differs from the suffix.
        # Only flags-only samples need independent breakout selection.
        has_lane_ids = any(optical_params.get(f'_{metric}_lane_ids')
                           for metric in ('rx_power', 'tx_power', 'bias_current'))
        if not has_lane_ids and len(flags) > 1 and str(wanted_lane) in flags:
            optical_params['bias_flags'] = {str(wanted_lane): flags[str(wanted_lane)]}

        for metric in ('rx_power', 'tx_power', 'bias_current'):
            lanes_key = f'_{metric}_lanes_dbm' if metric != 'bias_current' else '_bias_current_lanes_ma'
            ids_key = f'_{metric}_lane_ids'
            values = optical_params.get(lanes_key) or []
            lane_ids = optical_params.get(ids_key) or []
            if len(values) <= 1:
                continue
            readings = list(zip(lane_ids, values))
            selected = [item for item in readings if item[0] == wanted_lane]
            if selected:
                self._set_lane_readings(optical_params, metric, selected)

    def _driven_lanes(self, optical_params: Dict[str, Any]) -> List[int]:
        """The lanes of the row whose laser is driven.

        A bias reading above the laser-off floor alone does not say so: a
        laser at 0.4 mA with the module's low-bias alarm raised is off.  The
        bias has to be free of low-side evidence from the module (its limits
        and its flags, read as _bias_lane_events reads them).
        """
        thresholds = optical_params.get('bias_thresholds_ma') or {}
        flags = optical_params.get('bias_flags') or {}
        cmis = bool(optical_params.get('_cmis'))
        driven = []
        for lane, value in zip(
                optical_params.get('_bias_current_lane_ids') or [],
                optical_params.get('_bias_current_lanes_ma') or []):
            if value <= self.LASER_OFF_BIAS_MA:
                continue
            events = self._bias_lane_events(
                lane, value, thresholds, flags.get(str(lane), {}), cmis)
            if not any(event['direction'] == 'low' and
                       not event.get('value_in_range') for event in events):
                driven.append(lane)
        return driven

    def _set_aside_unmonitored_sides(self, optical_params: Dict[str, Any]) -> None:
        """Drop a power side the module does not monitor.

        SFF-8636 leaves transmit power monitoring optional, but ethtool
        prints the 'Transmit avg optical power' line of every channel
        anyway: 0.0000 mW.  Graded as a measurement that was a dead
        transmitter (-40 dBm, CRITICAL) on a port carrying traffic.

        A side that reads no light on every channel of the module is not a
        measurement when the rest of the evidence contradicts a dark module:
        the link is up, or, for the transmit side of a block that carries no
        link state at all, the lasers are driven while the port receives
        light.  The side then has no value; the detail row says so.  One
        dark lane among lit ones stays a fault, and so do the dark lanes of
        a breakout sub-port while a sibling's channels show that the monitor
        works.

        With a collected link state that is not 'up' the reading stays:
        bias, no transmit light and receive light is exactly what a failed
        transmitter looks like (the peer signals remote fault and the link
        drops).  The link-down row says what it found (_port_anomalies).
        """
        collected = self._lane_readings_as_collected(optical_params)
        state = optical_params.get('_interface_state')
        link_up = state == 'up'
        dark = self.DARK_POWER_DBM
        lasers_driven = (
            state is None and
            bool(self._driven_lanes(optical_params)) and
            any(value > dark for value in
                optical_params.get('_rx_power_lanes_dbm') or [])
        )
        unmonitored = []
        for metric in ('tx_power', 'rx_power'):
            row = optical_params.get(f'_{metric}_lanes_dbm') or []
            module = [value for _lane, value in collected[metric]]
            if not row or any(value > dark for value in row + module):
                continue
            # lasers_driven includes receive light, so it can only ever
            # excuse the transmit side; the test says so explicitly.
            if link_up or (metric == 'tx_power' and lasers_driven):
                unmonitored.append(metric)
        for metric in unmonitored:
            self._set_lane_readings(optical_params, metric, [])
        optical_params['_not_monitored'] = unmonitored

    def _select_in_service_lanes(self, optical_params: Dict[str, Any]) -> None:
        """Grade only the lanes whose laser is in service.

        A pluggable answers for one diagnostic channel per cage lane, not per
        lane the module actually lights: a QSFP-DD cage reports eight channels
        for a module wired with four, and the spare channels read 0 mW /
        ``-inf`` dBm, floored to -40 here.  Graded with the rest they made the
        worst lane of a healthy 400G port -40 dBm, so the row said CRITICAL
        and asked an operator to replace a working cable.

        Zero does not mean the same thing everywhere.  A hardware sensor
        reading 0 C was never read (no powered component is that cold), while
        a fan tray reading all zeros has genuinely stopped; here it is the
        bias current that settles it.  A dark lane drawing no bias current is
        a laser that is not driven, so the lane was never in service and must
        not be graded.  A dark lane that IS drawing bias is a lit laser whose
        light never arrived: a real fault, and it stays CRITICAL.

        When a dark lane carries no bias reading at all, the fallback is
        narrower — it is set aside only because another lane of the same
        module is carrying light.  Nothing is ever set aside when that would
        leave no lane to grade, so a module that is dark everywhere is still
        reported as such.
        """
        metrics = ('rx_power', 'tx_power', 'bias_current')
        readings = {}
        for metric in metrics:
            lanes_key = (f'_{metric}_lanes_dbm' if metric != 'bias_current'
                         else '_bias_current_lanes_ma')
            readings[metric] = list(zip(
                optical_params.get(f'_{metric}_lane_ids') or [],
                optical_params.get(lanes_key) or [],
            ))

        power_by_lane: Dict[int, List[float]] = {}
        for metric in ('rx_power', 'tx_power'):
            for lane, value in readings[metric]:
                power_by_lane.setdefault(lane, []).append(value)
        bias_by_lane = dict(readings['bias_current'])

        optical_params['_inactive_lane_ids'] = []
        # A single-lane sample has no healthy peer to be judged against, and
        # one lane is the whole port: it is always graded.
        if len(set(power_by_lane) | set(bias_by_lane)) < 2:
            return

        carrying_light = {
            lane for lane, values in power_by_lane.items()
            if any(value > self.DARK_POWER_DBM for value in values)
        }
        inactive = set()
        for lane in power_by_lane:
            if lane in carrying_light:
                continue
            bias = bias_by_lane.get(lane)
            if bias is None:
                if carrying_light:
                    inactive.add(lane)
            elif bias <= self.LASER_OFF_BIAS_MA:
                inactive.add(lane)
        if not inactive or not set(power_by_lane) - inactive:
            return

        for metric in metrics:
            kept = [item for item in readings[metric] if item[0] not in inactive]
            if len(kept) != len(readings[metric]):
                self._set_lane_readings(optical_params, metric, kept)
        optical_params['_inactive_lane_ids'] = sorted(inactive)

    def calculate_link_margin(self, rx_power_dbm: float,
                              rx_low_alarm_dbm: Optional[float] = None) -> float:
        """Calculate optical link margin

        ``rx_low_alarm_dbm`` is the module's own RX power low alarm when its
        table grades the port; the margin then counts up from that limit.
        """
        if rx_power_dbm is None:
            return 0.0
        if rx_low_alarm_dbm is not None:
            return rx_power_dbm - rx_low_alarm_dbm

        # Link margin = RX Power - Minimum sensitivity threshold
        # Using -14 dBm as a conservative minimum sensitivity for most optics
        min_sensitivity = self.thresholds['rx_power_min_dbm']
        return rx_power_dbm - min_sensitivity

    def assess_optical_health(self, optical_params: Dict[str, Any]) -> OpticalHealth:
        """Assess optical health based on parameters"""
        rx_power = optical_params.get('rx_power_dbm')
        tx_power = optical_params.get('tx_power_dbm')
        temperature = optical_params.get('temperature_c')
        voltage = optical_params.get('voltage_v')
        bias_current = optical_params.get('bias_current_ma')
        rx_lanes = optical_params.get('_rx_power_lanes_dbm') or (
            [rx_power] if rx_power is not None else []
        )
        tx_lanes = optical_params.get('_tx_power_lanes_dbm') or (
            [tx_power] if tx_power is not None else []
        )
        bias_assessment = self._assess_bias(optical_params)
        module_deciding, module_tier, module_events = (
            self._grade_module_limits(optical_params))

        # No optical data available.  Voltage alone is useful inventory
        # evidence, but it is not enough to claim a healthy optical path.
        if (all(v is None for v in [rx_power, tx_power, temperature, voltage,
                                    bias_current]) and
                not bias_assessment['events']):
            return OpticalHealth.UNKNOWN

        # Preserve an explicit link-down state when every relevant receive lane
        # is dark.  A single dark lane on a non-breakout multi-lane link remains
        # CRITICAL below, while breakout interfaces are lane-filtered first.
        # A port whose link is up is never DOWN from receive power alone: its
        # dark lanes are graded as the readings they are.
        if (rx_lanes and all(value <= self.DARK_POWER_DBM for value in rx_lanes)
                and optical_params.get('_interface_state') != 'up'):
            return OpticalHealth.DOWN

        # A metric the module grades with its own complete limit table is
        # kept away from the generic rules below: they flagged healthy optics
        # (TX above 3 dBm, 60 C) and missed lanes under the module's alarm.
        generic_rx = [] if 'rx_power' in module_deciding else rx_lanes
        generic_tx = [] if 'tx_power' in module_deciding else tx_lanes
        generic_temperature = (None if 'temperature' in module_deciding
                               else temperature)
        generic_voltage = None if 'voltage' in module_deciding else voltage

        # Critical conditions (any one triggers critical status)
        if any(value < self.thresholds['rx_power_min_dbm'] for value in generic_rx):
            return OpticalHealth.CRITICAL
        if any(value > self.thresholds.get('rx_power_critical_high_dbm', 7.0)
               for value in generic_rx):
            return OpticalHealth.CRITICAL
        if any(value < self.thresholds['tx_power_min_dbm'] or
               value > self.thresholds['tx_power_max_dbm']
               for value in generic_tx):
            return OpticalHealth.CRITICAL
        if generic_temperature is not None and generic_temperature > self.thresholds['temperature_max_c']:
            return OpticalHealth.CRITICAL
        if generic_temperature is not None and generic_temperature < self.thresholds['temperature_min_c']:
            return OpticalHealth.CRITICAL
        if generic_voltage is not None and (generic_voltage < self.thresholds['voltage_min_v'] or generic_voltage > self.thresholds['voltage_max_v']):
            return OpticalHealth.CRITICAL
        # Beyond a module alarm limit; a limit of an incomplete table counts
        # too, exactly as a partial bias table can still prove a fault.
        if module_tier >= 3 or any(event['severity'] == 'critical'
                                   for event in module_events):
            return OpticalHealth.CRITICAL
        if bias_assessment['status'] == 'critical':
            return OpticalHealth.CRITICAL

        if bias_assessment['status'] == 'warning':
            return OpticalHealth.WARNING
        # Beyond a module warning limit, or under the configured link margin
        # counted from the module's RX low alarm.
        if module_tier >= 2 or module_events:
            return OpticalHealth.WARNING

        if not rx_lanes and not tx_lanes:
            return OpticalHealth.UNKNOWN

        # Warning conditions
        warning_count = 0

        # Low link margin warning
        if generic_rx and any(
            self.calculate_link_margin(value) < self.thresholds['link_margin_min_db']
            for value in generic_rx
        ):
            warning_count += 1

        # High RX power warning (above warning high but below critical high)
        if any(value > self.thresholds.get('rx_power_warning_high_dbm', 5.0)
               for value in generic_rx):
            warning_count += 1

        # TX power near limits
        if generic_tx:
            if any(value < self.thresholds['tx_power_min_dbm'] + 1.0 or
                   value > self.thresholds['tx_power_max_dbm'] - 1.0
                   for value in generic_tx):
                warning_count += 1

        # Temperature approaching limits
        if generic_temperature is not None:
            if generic_temperature > self.thresholds['temperature_max_c'] - 10.0:
                warning_count += 1

        # Any independently meaningful threshold violation is a warning.  The
        # previous two-warning rule hid a real low-margin/high-power condition
        # behind a GOOD badge.
        if warning_count:
            return OpticalHealth.WARNING

        # GOOD is the healthy-but-near-threshold band.  It does not relax any
        # existing warning boundary above; it only distinguishes comfortable
        # readings from readings that are still valid but deserve trend
        # awareness.  The bands are derived from the configured hard limits so
        # custom optical margin settings continue to behave consistently.
        # A module-graded metric is in the band when a reading is close to
        # one of the module's warning limits.
        good_band = module_tier >= 1.5
        if generic_rx:
            good_margin = self.thresholds['link_margin_min_db'] + 3.0
            good_band = good_band or any(
                self.calculate_link_margin(value) < good_margin
                for value in generic_rx
            )
            high_warning = self.thresholds.get('rx_power_warning_high_dbm', 5.0)
            good_band = good_band or any(
                value > high_warning - 1.0 for value in generic_rx
            )
        if generic_tx:
            good_band = good_band or any(
                value < self.thresholds['tx_power_min_dbm'] + 2.0 or
                value > self.thresholds['tx_power_max_dbm'] - 2.0
                for value in generic_tx
            )
        if generic_temperature is not None:
            good_band = good_band or (
                generic_temperature > self.thresholds['temperature_max_c'] - 20.0 or
                generic_temperature < self.thresholds['temperature_min_c'] + 10.0
            )
        if generic_voltage is not None:
            good_band = good_band or (
                generic_voltage < self.thresholds['voltage_min_v'] + 0.1 or
                generic_voltage > self.thresholds['voltage_max_v'] - 0.1
            )
        if good_band:
            return OpticalHealth.GOOD
        return OpticalHealth.EXCELLENT

    def _health_causes(self, optical_params: Dict[str, Any],
                       health: OpticalHealth) -> List[str]:
        """The parameters that put a port at WARNING or CRITICAL.

        Each parameter is held against the limits that graded it in
        assess_optical_health (the module's table, else the generic rules).
        Consumers use it to name the cause and to tell a condition of the
        module (temperature, voltage) from one of a lane.
        """
        if health not in (OpticalHealth.WARNING, OpticalHealth.CRITICAL):
            return []
        floor = 3 if health == OpticalHealth.CRITICAL else 2
        deciding, _tier, events = self._grade_module_limits(optical_params)
        readings = self._module_limit_readings(optical_params)
        generic = self.thresholds

        def level(metric, value):
            limits = deciding.get(metric)
            if limits is not None or metric in ('rx_power', 'tx_power'):
                return self._lane_risk(metric, value, limits)[0]
            if metric == 'temperature':
                if (value > generic['temperature_max_c'] or
                        value < generic['temperature_min_c']):
                    return 3
                return 2 if value > generic['temperature_max_c'] - 10.0 else 1
            return (3 if (value < generic['voltage_min_v'] or
                          value > generic['voltage_max_v']) else 1)

        causes = []
        for metric in self.MODULE_LIMIT_METRICS:
            beyond = any(level(metric, value) >= floor
                         for _lane, value in readings[metric])
            beyond = beyond or any(
                event['metric'] == metric and
                (floor == 2 or event['severity'] == 'critical')
                for event in events)
            if beyond:
                causes.append(metric)
        bias = self._assess_bias(optical_params)['status']
        if bias == 'critical' or (floor == 2 and bias == 'warning'):
            causes.append('bias_current')
        return causes

    def _restate_margin_history(self, port_name: str, reference: float) -> None:
        """Keep a port's margin history on the level the new sample uses.

        ``link_margin_db`` counts from the module's RX low alarm when the
        module prints a valid RX table and from the generic sensitivity
        otherwise; a sample written before that distinction existed carries
        no reference and counted from the generic one.  A margin is the
        lowest lane's power above its reference, so moving the reference
        shifts it by a constant: earlier samples are restated instead of
        leaving a step in the series, which trend readers (Ask-AI insights
        compare consecutive samples) took for a margin that dropped on
        every such port at the upgrade.
        """
        history = self.optical_history.get(port_name) or []
        generic = self.thresholds['rx_power_min_dbm']

        def margin_and_reference(entry):
            if not isinstance(entry, dict):
                return None
            margin = entry.get('link_margin_db')
            old = entry.get('link_margin_ref_dbm', generic)
            if (isinstance(margin, bool) or isinstance(old, bool) or
                    not isinstance(margin, (int, float)) or
                    not isinstance(old, (int, float))):
                return None
            return margin, old

        # Every restatement leaves the whole series on one level, so the
        # newest sample that has a margin speaks for the rest.
        for entry in reversed(history):
            pair = margin_and_reference(entry)
            if pair is None:
                continue
            if abs(pair[1] - reference) < 1e-9:
                return
            break
        else:
            return
        for entry in history:
            pair = margin_and_reference(entry)
            if pair is None:
                continue
            entry['link_margin_db'] = round(pair[0] + pair[1] - reference, 6)
            entry['link_margin_ref_dbm'] = reference

    def update_optical_stats(self, port_name: str, optical_data: str,
                             parsed: Optional[Dict[str, Any]] = None,
                             lanes_per_subport: Optional[int] = None,
                             link_down: bool = False):
        """Update optical statistics for a port
        
        Returns False if port is DAC/Copper (skipped), True if processed

        ``parsed`` is this block's parse_optical_data result when the caller
        already holds it (it is consumed: lane selection edits it in place).
        ``lanes_per_subport`` is the breakout cage's plan from
        plan_breakout_lanes; without it a breakout interface keeps channel
        M+1.  ``link_down`` is set for a port whose collected operstate is
        down: the row is DOWN whatever the module reads, and its readings
        say why (see _down_row_reading).
        """
        optical_params = (parsed if parsed is not None
                          else self.parse_optical_data(optical_data))
        
        # Skip DAC/Copper cables - parse_optical_data returns None for these
        if optical_params is None:
            return False

        self._select_breakout_lane(port_name, optical_params,
                                   lanes_per_subport)
        # A side the module does not monitor is no reading at all; told
        # from the lanes the interface owns and from the whole module.
        self._set_aside_unmonitored_sides(optical_params)
        # After the interface owns its lanes, and never before: a breakout
        # sub-interface whose own lane is dark is still that interface's
        # verdict, not a spare channel to set aside.
        self._select_in_service_lanes(optical_params)

        health = self.assess_optical_health(optical_params)
        health_causes = self._health_causes(optical_params, health)
        if link_down:
            health = OpticalHealth.DOWN

        # Calculate additional metrics
        link_margin_db = None
        rx_lanes = optical_params.get('_rx_power_lanes_dbm') or []
        # Counted from the module's own RX low alarm when its table grades
        # the port, from the generic sensitivity otherwise.
        rx_low_alarm = (self._deciding_limits(optical_params, 'rx_power')
                        or {}).get('low_alarm')
        if rx_lanes:
            link_margin_db = min(self.calculate_link_margin(value, rx_low_alarm)
                                 for value in rx_lanes)
        elif optical_params['rx_power_dbm'] is not None:
            link_margin_db = self.calculate_link_margin(
                optical_params['rx_power_dbm'], rx_low_alarm)
        # The level the margin counts from, kept with every history sample.
        link_margin_ref_dbm = None
        if link_margin_db is not None:
            link_margin_ref_dbm = (rx_low_alarm if rx_low_alarm is not None
                                   else self.thresholds['rx_power_min_dbm'])

        # Store current stats
        self.current_optical_stats[port_name] = {
            'health_status': health.value,
            'rx_power_dbm': optical_params['rx_power_dbm'],
            'tx_power_dbm': optical_params['tx_power_dbm'],
            'temperature_c': optical_params['temperature_c'],
            'voltage_v': optical_params['voltage_v'],
            'bias_current_ma': optical_params['bias_current_ma'],
            'bias_thresholds_ma': optical_params.get('bias_thresholds_ma', {}),
            'bias_assessment': self._assess_bias(optical_params),
            'rx_power_lane': optical_params.get('rx_power_lane'),
            'tx_power_lane': optical_params.get('tx_power_lane'),
            'bias_current_lane': optical_params.get('bias_current_lane'),
            'rx_power_lanes_dbm': optical_params.get('_rx_power_lanes_dbm', []),
            'tx_power_lanes_dbm': optical_params.get('_tx_power_lanes_dbm', []),
            'bias_current_lanes_ma': optical_params.get('_bias_current_lanes_ma', []),
            # Lane identities travel with the values so the report labels the
            # lane it actually assessed instead of counting array positions.
            'rx_power_lane_ids': optical_params.get('_rx_power_lane_ids', []),
            'tx_power_lane_ids': optical_params.get('_tx_power_lane_ids', []),
            'bias_current_lane_ids': optical_params.get('_bias_current_lane_ids', []),
            'inactive_lanes': optical_params.get('_inactive_lane_ids', []),
            # Which limits graded RX/TX power, temperature and voltage, and
            # the module limits a reading is beyond (detail sidecar only).
            'module_limits': self._assess_module_limits(optical_params),
            # The power sides this module does not monitor (no value above).
            'not_monitored': optical_params.get('_not_monitored', []),
            'link_state': ('down' if link_down
                           else optical_params.get('_interface_state')),
            # What a link-down row is read with (see _down_row_keeps and
            # _down_row_reading): the lanes whose laser is driven, whether
            # any channel of the module shows transmit light (its TX monitor
            # works) and the optical lane count the media text declares.
            'lane_evidence': {
                'driven_lanes': self._driven_lanes(optical_params),
                'module_tx_light': any(
                    value > self.DARK_POWER_DBM for _lane, value in
                    self._lane_readings_as_collected(optical_params)['tx_power']),
                'declared_lanes': optical_params.get(
                    '_declared_optical_lane_count'),
            },
            # The parameters behind a WARNING, CRITICAL or DOWN state.
            'health_causes': health_causes,
            'link_margin_db': link_margin_db,
            'last_updated': time.time(),
            'raw_data': optical_data[:500]  # Store first 500 chars for debugging
        }
        if health == OpticalHealth.DOWN:
            # A dark or undriven side is what a down port looks like; only
            # the evidence that can explain the outage is kept and named.
            stats = self.current_optical_stats[port_name]
            stats['bias_assessment'] = self._down_row_bias_assessment(stats)
            stats['health_causes'] = list(dict.fromkeys(
                anomaly['metric']
                for anomaly in self._port_anomalies(port_name, stats)
                if anomaly.get('metric') and anomaly['severity'] == 'critical'
            ))

        # A row without a single reading is no sample.  Appended every run,
        # such rows pushed the readings that prove the port optical out of
        # its 100 entries: after 100 collections the port lost its row, and
        # the module's later removal was no longer reported.
        if health == OpticalHealth.UNKNOWN and all(
                optical_params[key] is None for key in
                ('rx_power_dbm', 'tx_power_dbm', 'temperature_c')):
            return True

        # Store in history
        if port_name not in self.optical_history:
            self.optical_history[port_name] = []

        # Add to history (keep last 100 entries)
        history_entry = {
            'timestamp': time.time(),
            'health': health.value,
            'rx_power_dbm': optical_params['rx_power_dbm'],
            'tx_power_dbm': optical_params['tx_power_dbm'],
            'temperature_c': optical_params['temperature_c'],
            'link_margin_db': link_margin_db,
            'link_margin_ref_dbm': link_margin_ref_dbm,
            'rx_power_lane': optical_params.get('rx_power_lane'),
            'tx_power_lane': optical_params.get('tx_power_lane'),
            'bias_current_lane': optical_params.get('bias_current_lane'),
            # The receive lanes this sample graded.  Trend readers (Ask-AI
            # insights) compare two samples only while they grade the same
            # lanes: a breakout plan change is not a drop.
            'rx_power_lane_ids': list(
                optical_params.get('_rx_power_lane_ids') or []),
        }

        if link_margin_ref_dbm is not None:
            self._restate_margin_history(port_name, link_margin_ref_dbm)
        self.optical_history[port_name].append(history_entry)
        if len(self.optical_history[port_name]) > 100:
            self.optical_history[port_name] = self.optical_history[port_name][-100:]
        
        return True

    def get_optical_summary(self) -> Dict[str, Any]:
        """Get optical analysis summary"""
        summary = {
            "total_ports": 0,
            "excellent_ports": [],
            "good_ports": [],
            "warning_ports": [],
            "critical_ports": [],
            "down_ports": [],
            "unplugged_ports": [],
            "unknown_ports": []
        }

        for port_name, stats in self.current_optical_stats.items():
            health = stats.get('health_status', 'unknown')
            health_enum = coerce_optical_health(health)

            port_info = {
                "port": port_name,
                "health": health,
                "rx_power_dbm": stats.get('rx_power_dbm'),
                "tx_power_dbm": stats.get('tx_power_dbm'),
                "temperature_c": stats.get('temperature_c'),
                "link_margin_db": stats.get('link_margin_db'),
                "voltage_v": stats.get('voltage_v'),
                "bias_current_ma": stats.get('bias_current_ma'),
                "rx_power_lane": stats.get('rx_power_lane'),
                "tx_power_lane": stats.get('tx_power_lane'),
                "bias_current_lane": stats.get('bias_current_lane')
            }

            if health_enum == OpticalHealth.EXCELLENT:
                summary["excellent_ports"].append(port_info)
            elif health_enum == OpticalHealth.GOOD:
                summary["good_ports"].append(port_info)
            elif health_enum == OpticalHealth.WARNING:
                summary["warning_ports"].append(port_info)
            elif health_enum == OpticalHealth.CRITICAL:
                summary["critical_ports"].append(port_info)
            elif health_enum == OpticalHealth.DOWN:
                summary["down_ports"].append(port_info)
            elif health_enum == OpticalHealth.UNPLUGGED:
                # An absent module is an availability/inventory state, not a
                # failed optical measurement.  Keep it visible in the table
                # without inflating either Critical or Down.
                summary["unplugged_ports"].append(port_info)
            else:
                summary["unknown_ports"].append(port_info)

        # UNKNOWN is a monitored port with incomplete diagnostics, not an
        # absent port.  Include it in coverage and in the detailed table.
        summary["total_ports"] = (len(summary["excellent_ports"]) +
                                 len(summary["good_ports"]) +
                                 len(summary["warning_ports"]) +
                                 len(summary["critical_ports"]) +
                                 len(summary["down_ports"]) +
                                 len(summary["unplugged_ports"]) +
                                 len(summary["unknown_ports"]))

        return summary

    def _down_row_lanes(self, stats: Dict[str, Any], metric: str) -> List[tuple]:
        """[(lane or None, dBm)] of one power side of a row."""
        values = stats.get(f'{metric}_lanes_dbm') or []
        lanes = stats.get(f'{metric}_lane_ids') or []
        if not values and stats.get(f'{metric}_dbm') is not None:
            values = [stats[f'{metric}_dbm']]
            lanes = [stats.get(f'{metric}_lane')]
        return [(lanes[index] if index < len(lanes) else None, value)
                for index, value in enumerate(values)]

    def _down_row_keeps(self, stats: Dict[str, Any], metric: str,
                        direction: str, lane: Optional[int] = None) -> bool:
        """Whether a critical reading can explain a DOWN row.

        A port that is shut has its lasers off and receives nothing: a dark
        or undriven side is the state itself, not its cause, and every
        parked port would list alarms.  A reading above a limit always
        counts, and so does a condition of the module.  A low power reading
        counts while that side still carries light on a lane of the port (a
        weak lane, or a dead lane next to working ones).  A transmit lane
        that reads no light counts as well when its own laser is driven and
        the module shows transmit light on another channel: the monitor
        works, so the lane's transmitter does not.
        """
        # 'high' is spelled out although light above a limit is light: no
        # table that passes the plausibility check has a limit a dark lane
        # could be above.
        if metric in self.MODULE_SCOPE_METRICS or direction == 'high':
            return True
        if any(value > self.DARK_POWER_DBM
               for _lane, value in self._down_row_lanes(stats, metric)):
            return True
        evidence = stats.get('lane_evidence') or {}
        return (metric == 'tx_power' and
                bool(evidence.get('module_tx_light')) and
                lane in (evidence.get('driven_lanes') or []))

    def _down_row_dark_transmitter(self, stats: Dict[str, Any]
                                   ) -> Optional[Dict[str, Any]]:
        """Transmit reads no light on every channel while lasers are driven.

        On a link-down port that is a failed transmitter, or a module that
        does not monitor transmit power: no channel of the module shows
        transmit light, so the dump cannot tell them apart.  Returns the
        driven lanes and their bias, or None.
        """
        evidence = stats.get('lane_evidence') or {}
        lanes = self._down_row_lanes(stats, 'tx_power')
        if (not lanes or evidence.get('module_tx_light') or
                any(value > self.DARK_POWER_DBM for _lane, value in lanes)):
            return None
        bias = dict(zip(stats.get('bias_current_lane_ids') or [],
                        stats.get('bias_current_lanes_ma') or []))
        driven = [lane for lane in evidence.get('driven_lanes') or []
                  if lane in bias]
        if not driven:
            return None
        return {'lanes': driven, 'bias_ma': [bias[lane] for lane in driven]}

    def _down_row_bias_assessment(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """The bias assessment of a DOWN row without laser-off evidence.

        A low bias reading or low-bias flag is kept only while another lane
        of the port is driven: that is a dead laser.  With no lane driven
        the lasers are simply off.
        """
        assessment = stats.get('bias_assessment') or {}
        events = assessment.get('events') or []
        low = {event['lane'] for event in events
               if event['direction'] == 'low' and not event.get('value_in_range')}
        if not low:
            return assessment
        driven = any(
            lane not in low and value > self.LASER_OFF_BIAS_MA
            for lane, value in zip(stats.get('bias_current_lane_ids') or [],
                                   stats.get('bias_current_lanes_ma') or [])
        ) or any(
            lane not in low and value > self.DARK_POWER_DBM
            for lane, value in self._down_row_lanes(stats, 'tx_power')
        )
        if driven:
            return assessment
        kept = [event for event in events
                if event['direction'] != 'low' or event.get('value_in_range')]
        if kept:
            status = ('critical' if any(e['severity'] == 'critical' for e in kept)
                      else 'warning')
            reason = assessment.get('reason', '')
        else:
            status = 'unknown'
            reason = ('The port is down and none of its lasers is driven; '
                      'low bias readings are not assessed.')
        return {'status': status, 'reason': reason, 'events': kept}

    def _down_row_reading(self, stats: Dict[str, Any]) -> tuple:
        """(sentence, action) of a DOWN row, from what its receiver reads.

        The badge says the link is down; the readings say whether light
        still arrives, which lane does not get enough, or that nothing
        arrives at all.
        """
        link_down = stats.get('link_state') == 'down'
        lanes = self._down_row_lanes(stats, 'rx_power')
        module_limits = stats.get('module_limits') or {}
        dark = self.DARK_POWER_DBM
        evidence = stats.get('lane_evidence') or {}
        # Lanes set aside as out of service (no light, no laser bias).  On a
        # link that is down such a lane is the likeliest reason, so it is
        # named, unless it is a spare channel of a wider cage: the media
        # text says the lanes in service are all the module has, or the
        # lanes set aside are exactly the upper half of its channels (a
        # four-lane module answers for eight channels in a QSFP-DD cage).
        declared = evidence.get('declared_lanes')
        inactive = stats.get('inactive_lanes') or []
        in_service = [lane for lane, _value in lanes if lane is not None]
        spare = bool(declared and len(lanes) >= declared) or (
            bool(inactive) and len(inactive) == len(in_service) and
            max(in_service) < min(inactive))
        aside = inactive if link_down and not spare else []
        aside_text = ''
        if aside:
            aside_text = ('; lane ' if len(aside) == 1 else '; lanes ') + (
                ', '.join(str(lane) for lane in aside)
                + ' without light and without laser bias')
        if not lanes:
            return ('Link down, the module reports no receive power',
                    'Check fiber connection, peer state, and transceiver')
        if all(value <= dark for _lane, value in lanes):
            return (('Link down, no' if link_down else 'No')
                    + ' receive light on any lane',
                    'Check fiber connection, peer state, and transceiver')
        # The lanes beyond the limit that grades them: the module's own
        # alarm where its table decides, the generic limit otherwise.
        if 'rx_power' in (module_limits.get('decided') or []):
            beyond = {event['lane']: event['direction']
                      for event in module_limits.get('events') or []
                      if event['metric'] == 'rx_power'
                      and event['severity'] == 'critical'}
            faulty = [(lane, value, beyond[lane]) for lane, value in lanes
                      if lane in beyond]
        else:
            low = self.thresholds['rx_power_min_dbm']
            high = self.thresholds.get('rx_power_critical_high_dbm', 7.0)
            faulty = [(lane, value, 'low' if value < low else 'high')
                      for lane, value in lanes if value < low or value > high]
        if faulty:
            parts = []
            for lane, value, _direction in faulty:
                name = f'lane {lane}' if lane is not None else 'receive power'
                parts.append(f'{name} without light' if value <= dark
                             else f'{name} at {value:.1f} dBm')
            too_low = any(direction == 'low' for _l, _v, direction in faulty)
            return ('Link down, ' + ', '.join(parts) + aside_text,
                    self.MODULE_LIMIT_ACTIONS[
                        ('rx_power', 'low' if too_low else 'high')])
        if aside and all(lane is not None for lane, _value in lanes):
            return ('Link down, light present on '
                    + ('lane ' if len(lanes) == 1 else 'lanes ')
                    + ', '.join(str(lane) for lane, _value in lanes)
                    + aside_text,
                    'Check fiber connection, peer state, and transceiver')
        sentence = ('Link down, light present on all lanes'
                    if len(lanes) > 1 else 'Link down, receive light present')
        # Receive light arrives, so the peer is alive.  A transmitter of
        # this port that reads no light while its laser is driven is the
        # nearer suspect than the peer's settings.
        transmit = self._down_row_lanes(stats, 'tx_power')
        if any(value <= dark and self._down_row_keeps(
                stats, 'tx_power', 'low', lane) for lane, value in transmit):
            return sentence, (
                self.MODULE_LIMIT_ACTIONS[('tx_power', 'low')]
                if any(value > dark for _lane, value in transmit)
                else self.DOWN_TRANSMITTER_ACTION)
        if self._down_row_dark_transmitter(stats):
            return sentence, self.DARK_TRANSMITTER_ACTION
        return (sentence,
                'Check the peer port and the link settings on both ends '
                '(admin state, speed, FEC)')

    def detect_optical_anomalies(self) -> List[Dict[str, Any]]:
        """Detect optical-related anomalies"""
        anomalies = []
        for port_name, stats in self.current_optical_stats.items():
            anomalies.extend(self._port_anomalies(port_name, stats))
        return self._merge_module_findings(anomalies)

    def _breakout_cage(self, port_name: str) -> Optional[str]:
        """'<device>:swp<N>' for a breakout sub-port, None for any other port."""
        device, _separator, interface = port_name.rpartition(':')
        match = self.BREAKOUT_PORT_RE.fullmatch(interface)
        return f"{device}:{match.group('cage')}" if match else None

    def _merge_module_findings(self, anomalies: List[Dict[str, Any]]
                               ) -> List[Dict[str, Any]]:
        """Report a condition of the module once per breakout cage.

        Every swp<N>s<M> of a cage reads the same module, so its temperature,
        its voltage or its absence arrived once per sub-port: one hot module
        in a 4x split was four findings.  One finding stays, carries the
        worst of the sub-ports' readings and names them all (``ports``);
        each row keeps its own badge.
        """
        merged = []
        groups: Dict[tuple, Dict[str, Any]] = {}
        for anomaly in anomalies:
            cage = (self._breakout_cage(anomaly['port'])
                    if anomaly.get('scope') == 'module' else None)
            if cage is None:
                merged.append(anomaly)
                continue
            key = (cage, anomaly['type'], anomaly['severity'])
            if key in groups:
                kept = groups[key]
                kept['ports'].append(anomaly['port'])
                # Each sub-port reads the module a moment apart, so the
                # values differ slightly: the finding names the worst one.
                value, worst = anomaly.get('value'), kept.get('value')
                if (isinstance(value, (int, float)) and
                        isinstance(worst, (int, float)) and
                        anomaly.get('direction') == kept.get('direction') and
                        (value < worst if kept.get('direction') == 'low'
                         else value > worst)):
                    ports = kept['ports']
                    kept.clear()
                    kept.update(anomaly, cage=cage, ports=ports)
                continue
            anomaly['cage'] = cage
            anomaly['ports'] = [anomaly['port']]
            groups[key] = anomaly
            merged.append(anomaly)

        def sub_port_index(port):
            # Numeric order without int(): a corrupted file can carry an
            # index of thousands of digits, which int() refuses.
            digits = self.BREAKOUT_PORT_RE.fullmatch(
                port.rpartition(':')[2]).group('index').lstrip('0')
            return (len(digits), digits)

        for anomaly in groups.values():
            if len(anomaly['ports']) < 2:
                continue
            anomaly['ports'].sort(key=sub_port_index)
            anomaly['port'] = anomaly['ports'][0]
            anomaly['message'] += (
                f" (one module in {anomaly['cage'].rpartition(':')[2]}, "
                "sub-ports "
                + ', '.join(port.rpartition(':')[2] for port in anomaly['ports'])
                + ')')
        return merged

    def _anomalies_by_port(self, anomalies: List[Dict[str, Any]]
                           ) -> Dict[str, List[Dict[str, Any]]]:
        """port -> its findings; a merged module finding is on every sub-port."""
        by_port: Dict[str, List[Dict[str, Any]]] = {}
        for anomaly in anomalies:
            for port in anomaly.get('ports') or [anomaly.get('port', '')]:
                by_port.setdefault(port, []).append(anomaly)
        # A merged finding sits where its first sub-port reported it; the
        # sentence of a DOWN row still leads that row's list.
        for findings in by_port.values():
            findings.sort(key=lambda item: item.get('type') != 'OPTICAL_LINK_DOWN')
        return by_port

    def get_finding_counts(self) -> Dict[str, int]:
        """Problem counts in which one module of a breakout cage counts once.

        The port counts of get_optical_summary are what the page cards and
        their row filters show, so they stay per port.  Here the sub-ports
        of a cage whose state comes from the module alone (its temperature
        or voltage, or the module pulled) are one finding.
        """
        counts = {'critical': 0, 'warning': 0, 'unplugged': 0}
        seen = set()
        for port_name, stats in self.current_optical_stats.items():
            health = coerce_optical_health(
                stats.get('health_status', 'unknown')).value
            if health not in counts:
                continue
            cage = self._breakout_cage(port_name)
            causes = stats.get('health_causes') or []
            module_scope = health == 'unplugged' or (
                causes and set(causes) <= self.MODULE_SCOPE_METRICS)
            if cage is not None and module_scope:
                if (cage, health) in seen:
                    continue
                seen.add((cage, health))
            counts[health] += 1
        return {
            'critical_findings': counts['critical'],
            'warning_findings': counts['warning'],
            'unplugged_modules': counts['unplugged'],
        }

    def _port_anomalies(self, port_name: str,
                        stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The findings of one port, before module findings are merged."""
        anomalies = []
        health = coerce_optical_health(stats.get('health_status', 'unknown'))
        down = health == OpticalHealth.DOWN

        if down:
            # The badge stays; the sentence comes from the readings and
            # the causes they show are listed below like on any row.
            message, action = self._down_row_reading(stats)
            anomalies.append({
                "port": port_name,
                "type": "OPTICAL_LINK_DOWN",
                "severity": "warning",
                "message": message,
                "action": action,
                "rx_power_dbm": stats.get('rx_power_dbm')
            })

        if health == OpticalHealth.UNPLUGGED:
            anomalies.append({
                "port": port_name,
                "type": "OPTICAL_MODULE_UNPLUGGED",
                "severity": "warning",
                "message": "Optical module is unplugged",
                "action": "Install or reseat the expected optical module",
                "scope": "module"
            })
            return anomalies

        if health == OpticalHealth.UNKNOWN and stats.get('note'):
            anomalies.append({
                "port": port_name,
                "type": "OPTICAL_DOM_UNREADABLE",
                "severity": "warning",
                "message": stats['note'],
                "action": ("Check that 'ethtool -m' answers for this port "
                           "on the switch; reseat or replace the module if "
                           "it stays unreadable"),
                "scope": "module"
            })
            return anomalies

        bias_events = (stats.get('bias_assessment') or {}).get('events', [])
        for event in bias_events:
            value = event.get('value_ma')
            limit = event.get('threshold_ma')
            measurement = f'{value:.3f} mA' if value is not None else 'reading unavailable'
            boundary = f'{limit:.3f} mA' if limit is not None else 'unavailable'
            if event.get('value_in_range'):
                flag_text = '; module flag set, value in range'
            elif event['source'] == 'module flag':
                flag_text = '; module flag is On'
            else:
                flag_text = ''
            anomalies.append({
                'port': port_name,
                'type': 'LASER_BIAS_' + event['direction'].upper(),
                'severity': event['severity'],
                'message': (
                    f"Laser bias lane {event['lane']}: {measurement}; module "
                    f"{event['direction']} {event['kind']} threshold: {boundary}"
                    + flag_text
                ),
                'action': 'Review transceiver diagnostics and module operating limits',
                'bias_current_ma': value,
                'threshold_ma': limit,
                'lane': event['lane'],
                'metric': 'bias_current',
            })

        # A reading beyond a limit the module prints for itself names
        # that limit; the generic texts below are for metrics no module
        # table graded.
        module_limits = stats.get('module_limits') or {}
        module_decided = module_limits.get('decided') or []
        limit_events = module_limits.get('events') or []
        if down:
            limit_events = [
                event for event in limit_events
                if event['severity'] == 'critical' and self._down_row_keeps(
                    stats, event['metric'], event['direction'],
                    event.get('lane'))
            ]
        # A link-down port none of whose transmit lanes shows light: a low
        # TX finding kept there rests on the driven lasers alone.
        down_transmit_dark = down and not any(
            value > self.DARK_POWER_DBM
            for _lane, value in self._down_row_lanes(stats, 'tx_power'))
        for event in limit_events:
            action = self.MODULE_LIMIT_ACTIONS.get(
                (event['metric'], event['direction']),
                'Review transceiver diagnostics and module operating limits')
            if (down_transmit_dark and event['metric'] == 'tx_power'
                    and event['direction'] == 'low'):
                action = self.DOWN_TRANSMITTER_ACTION
            anomalies.append({
                'port': port_name,
                'type': (f"MODULE_{event['metric'].upper()}_"
                         f"{event['direction'].upper()}"),
                'severity': event['severity'],
                'message': self._module_limit_message(event),
                'action': action,
                'value': event['value'],
                'threshold': event['threshold'],
                'lane': event['lane'],
                'metric': event['metric'],
                'direction': event['direction'],
            })
            if event['metric'] in self.MODULE_SCOPE_METRICS:
                anomalies[-1]['scope'] = 'module'

        # A condition of the module alone is one finding for its cage.
        causes = stats.get('health_causes') or []
        module_scope = bool(causes) and set(causes) <= self.MODULE_SCOPE_METRICS

        if health == OpticalHealth.CRITICAL or down:
            # Critical optical issues
            anomaly_count = len(anomalies)
            rx_power = (None if 'rx_power' in module_decided
                        else stats.get('rx_power_dbm'))
            tx_power = (None if 'tx_power' in module_decided
                        else stats.get('tx_power_dbm'))
            temperature = (None if 'temperature' in module_decided
                           else stats.get('temperature_c'))
            voltage = (None if 'voltage' in module_decided
                       else stats.get('voltage_v'))
            rx_high = self.thresholds.get('rx_power_critical_high_dbm', 7.0)
            tx_low = self.thresholds['tx_power_min_dbm']
            tx_high = self.thresholds['tx_power_max_dbm']

            def module_alarm(metric, direction):
                # A limit of an incomplete module table already named this
                # reading as critical; the generic text would repeat it.
                return any(event['metric'] == metric and
                           event['direction'] == direction and
                           event['severity'] == 'critical'
                           for event in limit_events)

            if (rx_power is not None and rx_power < self.thresholds['rx_power_min_dbm']
                    and (not down or self._down_row_keeps(stats, 'rx_power', 'low'))):
                anomalies.append({
                    "port": port_name,
                    "type": "LOW_OPTICAL_POWER",
                    "severity": "critical",
                    "message": f"RX power too low: {rx_power:.2f} dBm (threshold: {self.thresholds['rx_power_min_dbm']} dBm)",
                    "action": "Check fiber connection, clean connectors, or replace cable",
                    "rx_power_dbm": rx_power,
                    "metric": "rx_power"
                })

            if (rx_power is not None and rx_power > rx_high
                    and not module_alarm('rx_power', 'high')):
                anomalies.append({
                    "port": port_name,
                    "type": "HIGH_OPTICAL_POWER",
                    "severity": "critical",
                    "message": f"RX power too high: {rx_power:.2f} dBm (threshold: {rx_high} dBm)",
                    "action": self.MODULE_LIMIT_ACTIONS[('rx_power', 'high')],
                    "rx_power_dbm": rx_power,
                    "metric": "rx_power"
                })

            if down and tx_power is not None:
                # The displayed lane need not be the one that can explain
                # the outage: take the worst lane the DOWN row keeps.
                tx_power = next((
                    value for lane, value in sorted(
                        self._down_row_lanes(stats, 'tx_power'),
                        key=lambda item: self._lane_risk('tx_power', item[1]),
                        reverse=True)
                    if (value < tx_low or value > tx_high) and
                    self._down_row_keeps(
                        stats, 'tx_power',
                        'low' if value < tx_low else 'high', lane)), None)
            if tx_power is not None and (tx_power < tx_low or tx_power > tx_high):
                anomalies.append({
                    "port": port_name,
                    "type": "TX_POWER_OUT_OF_RANGE",
                    "severity": "critical",
                    "message": f"TX power out of range: {tx_power:.2f} dBm",
                    "action": (self.DOWN_TRANSMITTER_ACTION
                               if down_transmit_dark and tx_power < tx_low
                               else "Inspect or replace the transceiver and verify module compatibility"),
                    "tx_power_dbm": tx_power,
                    "metric": "tx_power"
                })

            dark_transmitter = (self._down_row_dark_transmitter(stats)
                                if down else None)
            if dark_transmitter:
                # Not graded: the dump cannot tell a failed transmitter
                # from a module without transmit power monitoring.
                bias = dark_transmitter['bias_ma']
                if len(bias) == 1:
                    drawn = f"the laser draws {bias[0]:.1f} mA"
                    where = ''
                else:
                    span = (f"{min(bias):.1f} mA" if min(bias) == max(bias)
                            else f"{min(bias):.1f} to {max(bias):.1f} mA")
                    drawn = f"the lasers draw {span}"
                    where = ' on any lane'
                anomalies.append({
                    "port": port_name,
                    "type": "TX_DARK_LASER_DRIVEN",
                    "severity": "warning",
                    "message": (f"TX reads no light{where} while {drawn} "
                                "(failed transmitter or TX power not "
                                "monitored)"),
                    "action": self.DARK_TRANSMITTER_ACTION,
                    "metric": "tx_power"
                })

            if temperature is not None and temperature > self.thresholds['temperature_max_c']:
                anomalies.append({
                    "port": port_name,
                    "type": "HIGH_TEMPERATURE",
                    "severity": "critical",
                    "message": f"SFP temperature too high: {temperature:.1f}°C (threshold: {self.thresholds['temperature_max_c']}°C)",
                    "action": "Check cooling, reduce load, or replace SFP module",
                    "temperature_c": temperature,
                    "value": temperature,
                    "direction": "high",
                    "metric": "temperature",
                    "scope": "module"
                })

            # Voltage and a temperature below the minimum are conditions of
            # the module like the one above: named with value and limit on
            # link-up and link-down rows alike, so a DOWN row lists them
            # and its stored causes carry them.
            if (temperature is not None
                    and temperature < self.thresholds['temperature_min_c']
                    and not module_alarm('temperature', 'low')):
                anomalies.append({
                    "port": port_name,
                    "type": "LOW_TEMPERATURE",
                    "severity": "critical",
                    "message": f"SFP temperature too low: {temperature:.1f}°C (threshold: {self.thresholds['temperature_min_c']}°C)",
                    "action": "Check the module's environment; replace the module if the reading is wrong",
                    "temperature_c": temperature,
                    "value": temperature,
                    "direction": "low",
                    "metric": "temperature",
                    "scope": "module"
                })

            if voltage is not None and (
                    voltage < self.thresholds['voltage_min_v'] or
                    voltage > self.thresholds['voltage_max_v']
            ) and not module_alarm(
                    'voltage',
                    'low' if voltage < self.thresholds['voltage_min_v']
                    else 'high'):
                anomalies.append({
                    "port": port_name,
                    "type": "VOLTAGE_OUT_OF_RANGE",
                    "severity": "critical",
                    "message": (f"Module voltage out of range: {voltage:.4f} V "
                                f"(limits: {self.thresholds['voltage_min_v']} "
                                f"to {self.thresholds['voltage_max_v']} V)"),
                    "action": "Reseat the transceiver; replace it or check the port's power supply if the voltage stays out of range",
                    "voltage_v": voltage,
                    "value": voltage,
                    "direction": ("low" if voltage < self.thresholds['voltage_min_v']
                                  else "high"),
                    "metric": "voltage",
                    "scope": "module"
                })

            if (not down and len(anomalies) == anomaly_count and
                    not any(e['severity'] == 'critical'
                            for e in bias_events + limit_events)):
                anomalies.append({
                    "port": port_name,
                    "type": "CRITICAL_OPTICAL_PARAMETER",
                    "severity": "critical",
                    "message": "A voltage, bias, high-RX, or lane threshold is critical",
                    "action": "Inspect the displayed worst-lane values and transceiver diagnostics"
                })
                if module_scope:
                    anomalies[-1]['scope'] = 'module'

        elif health == OpticalHealth.WARNING:
            # Warning level issues
            link_margin = stats.get('link_margin_db')
            if (isinstance(link_margin, (int, float)) and
                    link_margin < self.thresholds['link_margin_min_db']):
                margin_reference = ''
                if 'rx_power' in module_decided:
                    rx_low_alarm = ((module_limits.get('thresholds') or {})
                                    .get('rx_power') or {}).get('low_alarm')
                    if rx_low_alarm is not None:
                        margin_reference = (
                            " above the module's RX low alarm "
                            f"{rx_low_alarm:.2f} dBm")
                anomalies.append({
                    "port": port_name,
                    "type": "LOW_LINK_MARGIN",
                    "severity": "warning",
                    "message": f"Low link margin: {link_margin:.2f} dB{margin_reference} (threshold: {self.thresholds['link_margin_min_db']} dB)",
                    "action": "Monitor closely, schedule proactive maintenance",
                    "link_margin_db": link_margin,
                    "metric": "rx_power"
                })
            elif not bias_events and not limit_events:
                anomalies.append({
                    "port": port_name,
                    "type": "OPTICAL_PARAMETER_WARNING",
                    "severity": "warning",
                    "message": "An optical power or temperature value is near its limit",
                    "action": "Review the displayed worst-lane value and monitor the port"
                })
                if module_scope:
                    anomalies[-1]['scope'] = 'module'

        return anomalies

    def get_recommended_action(self, port_info: Dict[str, Any]) -> str:
        """Get recommended action for a port based on its health status and parameters"""
        health = port_info.get('health', 'unknown')

        if health == OpticalHealth.DOWN.value:
            # What to check follows from what the receiver reads.
            stats = self.current_optical_stats.get(port_info.get('port'))
            if stats:
                return self._down_row_reading(stats)[1]
            return "Check fiber connection, peer state, and transceiver"

        if health == OpticalHealth.UNPLUGGED.value:
            return "Install or reseat the expected optical module"

        if health == OpticalHealth.EXCELLENT.value:
            return ""  # No action needed for excellent health

        if health == OpticalHealth.CRITICAL.value:
            rx_power = port_info.get('rx_power_dbm')
            temperature = port_info.get('temperature_c')
            # The limits that made the port critical choose the advice: the
            # module's own alarm where its table graded the metric, the
            # generic limit otherwise.
            module_limits = (self.current_optical_stats.get(
                port_info.get('port')) or {}).get('module_limits') or {}
            module_decided = module_limits.get('decided') or []
            module_alarms = {
                (event['metric'], event['direction'])
                for event in module_limits.get('events') or []
                if event['severity'] == 'critical'
            }
            if 'rx_power' in module_decided:
                rx_power = None
            if 'temperature' in module_decided:
                temperature = None

            if (('rx_power', 'low') in module_alarms or
                    (rx_power is not None and rx_power < self.thresholds['rx_power_min_dbm'])):
                return "Check fiber connection, clean connectors, or replace cable"
            elif (('temperature', 'high') in module_alarms or
                    (temperature is not None and temperature > self.thresholds['temperature_max_c'])):
                return "Check cooling, reduce load, or replace SFP module"
            else:
                return "Investigate critical optical parameters immediately"

        if health == OpticalHealth.WARNING.value:
            link_margin = port_info.get('link_margin_db')
            if (isinstance(link_margin, (int, float)) and
                    link_margin < self.thresholds['link_margin_min_db']):
                return "Monitor closely, schedule proactive maintenance"
            else:
                return "Monitor optical parameters regularly"

        if health == OpticalHealth.GOOD.value:
            return "Continue regular monitoring"

        return "Check optical diagnostics availability"

    def _ordered_ports(self, summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Problems-first port order shared by the HTML table and export rows."""
        return (summary['critical_ports'] + summary['down_ports'] +
                summary['warning_ports'] + summary['unplugged_ports'] +
                summary['unknown_ports'] + summary['good_ports'] +
                summary['excellent_ports'])

    def build_export_rows(self, summary: Dict[str, Any],
                          anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flat export rows in the same problems-first order as the HTML table."""
        anomalies_by_port = self._anomalies_by_port(anomalies)

        all_ports = self._ordered_ports(summary)

        rows = []
        for port in all_ports:
            port_name = port['port']
            if ':' in port_name:
                device_name = port_name.split(':')[0]
                interface_name = port_name.split(':')[1]
            else:
                device_name = "unknown"
                interface_name = port_name
            stats = self.current_optical_stats.get(port_name, {})
            rows.append({
                'device': canonical(device_name),
                'interface': interface_name,
                'health': port.get('health'),
                'rx_power_dbm': port.get('rx_power_dbm'),
                'tx_power_dbm': port.get('tx_power_dbm'),
                'temperature_c': port.get('temperature_c'),
                'link_margin_db': port.get('link_margin_db'),
                'voltage_v': port.get('voltage_v'),
                'bias_current_ma': port.get('bias_current_ma'),
                'rx_lanes': ' '.join(
                    str(value) for value in (stats.get('rx_power_lanes_dbm') or [])
                ),
                'tx_lanes': ' '.join(
                    str(value) for value in (stats.get('tx_power_lanes_dbm') or [])
                ),
                'bias_lanes': ' '.join(
                    str(value) for value in (stats.get('bias_current_lanes_ma') or [])
                ),
                # The lane columns carry graded lanes only, so the lanes that
                # were found out of service are named rather than dropped
                # silently from the machine-readable snapshot.
                'inactive_lanes': ' '.join(
                    str(lane) for lane in (stats.get('inactive_lanes') or [])
                ),
                # Items are joined with '; ', so a semicolon inside a
                # message is written as a comma: the cell splits back into
                # its items on ';' alone.
                'anomalies': '; '.join(
                    f"{str(item.get('severity', '')).upper()}: "
                    f"{str(item.get('message', '')).replace(';', ',')}"
                    for item in anomalies_by_port.get(port_name, [])
                ),
                # Which module channel each value of rx_lanes, tx_lanes and
                # bias_lanes belongs to (a breakout sub-port does not start
                # at channel 1), and the lane of the headline values.
                'rx_lane_ids': ' '.join(
                    str(lane) for lane in (stats.get('rx_power_lane_ids') or [])
                ),
                'tx_lane_ids': ' '.join(
                    str(lane) for lane in (stats.get('tx_power_lane_ids') or [])
                ),
                'bias_lane_ids': ' '.join(
                    str(lane) for lane in (stats.get('bias_current_lane_ids') or [])
                ),
                'rx_power_lane': port.get('rx_power_lane'),
                'tx_power_lane': port.get('tx_power_lane'),
                'bias_current_lane': port.get('bias_current_lane'),
            })
        return rows

    def _write_detail_sidecars(self, result_dir: str,
                               details_by_host: Dict[str, Dict[str, Any]]) -> None:
        """Publish per-device detail files consumed by the report's panels.

        One optical-details/<host>.json per device keeps the report itself
        small; stale files (retired or uncollected devices) are pruned so an
        expanded row can never show another run's evidence.
        """
        details_dir = os.path.join(result_dir, DETAILS_DIR_NAME)
        os.makedirs(details_dir, exist_ok=True)
        written = set()
        now = time.time()
        for host, ports in sorted(details_by_host.items()):
            if not DETAIL_HOST_RE.fullmatch(host):
                print("⚠️  Skipping optical detail sidecar for unsafe "
                      f"hostname: {host!r}")
                continue
            _atomic_write(
                os.path.join(details_dir, f"{host}.json"),
                json.dumps(
                    {
                        "version": 1,
                        "updated_at": now,
                        "host": host,
                        "ports": ports,
                    },
                    separators=(",", ":"), ensure_ascii=True,
                ),
            )
            written.add(f"{host}.json")
        for name in os.listdir(details_dir):
            if not name.endswith(".json") or name in written:
                continue
            stale = os.path.join(details_dir, name)
            try:
                os.unlink(stale)
            except OSError:
                continue
            try:
                analysis_sidecar.sidecar_path(stale).unlink()
            except OSError:
                pass

    def export_optical_data_for_web(self, output_file: str):
        """Export optical data for web display - EXACT same styling as BGP/Link Flap"""
        summary = self.get_optical_summary()
        anomalies = self.detect_optical_anomalies()

        # Group the already-computed anomalies (exact measured values and the
        # specific remediation string) by port so they can be surfaced in the
        # expandable per-row detail panel instead of being discarded.
        anomalies_by_port = self._anomalies_by_port(anomalies)

        # True data age: the newest sample timestamp actually collected, not the
        # report-generation time.  This prevents a stale collection reading as
        # freshly healthy.  Fall back to now() when no sample carries a time.
        sample_times = [
            stats.get('last_updated')
            for stats in self.current_optical_stats.values()
            if isinstance(stats.get('last_updated'), (int, float))
        ]
        if sample_times:
            last_updated_text = datetime.fromtimestamp(
                max(sample_times)
            ).strftime('%Y-%m-%d %H:%M:%S')
        else:
            last_updated_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        expected_hosts = getattr(self, 'coverage_expected_hosts', None)
        collected_hosts = getattr(self, 'coverage_collected_hosts', None)
        current_hosts = getattr(self, 'coverage_current_hosts', None)
        missing_hosts = sorted(set(getattr(self, 'coverage_missing_hosts', []) or []))
        coverage_failures = getattr(self, 'coverage_failures', {}) or {}
        coverage_attrs = ''
        if isinstance(expected_hosts, int) and isinstance(current_hosts, int):
            coverage_status = (
                'complete' if current_hosts >= expected_hosts else 'partial'
            )
            coverage_attrs = (
                f' data-coverage-status="{coverage_status}"'
                f' data-coverage-expected="{expected_hosts}"'
                f' data-coverage-current="{current_hosts}"'
            )
            if isinstance(collected_hosts, int):
                coverage_attrs += (
                    f' data-coverage-collected="{collected_hosts}"'
                )
        coverage_attrs += (
            f' data-coverage-missing-hosts="{len(missing_hosts)}"'
            f' data-coverage-failed-hosts="{len(coverage_failures)}"'
        )
        # Machine-readable categories keep dashboard/alert consumers from
        # treating an intentionally empty cage as missing diagnostics. They are
        # attributes only and do not alter the report's visual layout.
        coverage_attrs += (
            f' data-optical-total="{summary["total_ports"]}"'
            f' data-optical-unplugged="{len(summary["unplugged_ports"])}"'
            f' data-optical-unknown="{len(summary["unknown_ports"])}"'
        )
        # The same problems with one module of a breakout cage counted once
        # (its temperature, its voltage, the module pulled); the cards and
        # their row filters stay per port.
        finding_counts = self.get_finding_counts()
        coverage_attrs += (
            f' data-optical-critical-findings="{finding_counts["critical_findings"]}"'
            f' data-optical-warning-findings="{finding_counts["warning_findings"]}"'
            f' data-optical-unplugged-modules="{finding_counts["unplugged_modules"]}"'
        )

        coverage_warning_html = ''
        if missing_hosts:
            coverage_rows = []
            for hostname in missing_hosts:
                reasons = coverage_failures.get(hostname) or [
                    'No current optical collection was published'
                ]
                rendered_reasons = '; '.join(str(reason) for reason in reasons)
                coverage_rows.append(
                    '<li><strong>' + html.escape(str(hostname)) + '</strong>: '
                    + html.escape(rendered_reasons) + '</li>'
                )
            coverage_warning_html = (
                '<div class="coverage-warning" data-optical-coverage-warning="true">'
                '<div class="coverage-warning-title">Partial optical collection</div>'
                '<p>Other monitoring categories remain current. Optical data was '
                'incomplete for:</p><ul>' + ''.join(coverage_rows) + '</ul></div>'
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Optical Diagnostics Analysis</title>
    <link rel="shortcut icon" href="/png/favicon.ico">
    <link rel="stylesheet" type="text/css" href="/css/select2.min.css">
    <link rel="stylesheet" type="text/css" href="/css/table-filter.css?v=20260716-tf-3">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1e1e1e; color: #d4d4d4; padding: 20px; min-height: 100vh; }}
        .page-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #404040; }}
        .page-title {{ font-size: 24px; font-weight: 600; color: #76b900; }}
        .last-updated {{ font-size: 13px; color: #888; }}
        .dashboard-section {{ background: #2d2d2d; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 12px 16px; background: #333; font-weight: 600; font-size: 14px; color: #76b900; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #404040; }}
        .section-content {{ padding: 16px; }}
        .section-content-table {{ padding: 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
        .summary-card {{ background: #252526; padding: 15px; border-radius: 6px; border-left: 3px solid #76b900; cursor: pointer; transition: all 0.2s ease; }}
        .summary-card:hover {{ background: #2d2d2d; transform: translateY(-1px); }}
        .summary-card.active {{ background: #333; border-left-width: 5px; }}
        .card-excellent {{ border-left-color: #76b900; }}
        .card-good {{ border-left-color: #8bc34a; }}
        .card-warning {{ border-left-color: #ff9800; }}
        .card-critical {{ border-left-color: #f44336; }}
        .card-down {{ border-left-color: #ba68c8; }}
        .card-unplugged {{ border-left-color: #78909c; }}
        .card-unknown {{ border-left-color: #9e9e9e; }}
        .card-info {{ border-left-color: #4fc3f7; }}
        .metric {{ font-size: 22px; font-weight: bold; color: #d4d4d4; }}
        .metric-label {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .badge-green {{ background: rgba(118, 185, 0, 0.2); color: #76b900; }}
        .badge-red {{ background: rgba(244, 67, 54, 0.2); color: #ff6b6b; }}
        .badge-orange {{ background: rgba(255, 152, 0, 0.2); color: #ffb74d; }}
        .badge-purple {{ background: rgba(186, 104, 200, 0.2); color: #ce93d8; }}
        .badge-gray {{ background: rgba(158, 158, 158, 0.2); color: #999; }}
        .optical-excellent {{ color: #76b900; font-weight: bold; }}
        .optical-good {{ color: #8bc34a; font-weight: bold; }}
        .optical-warning {{ color: #ff9800; font-weight: bold; }}
        .optical-critical {{ color: #f44336; font-weight: bold; }}
        .optical-down {{ color: #ba68c8; font-weight: bold; }}
        .optical-unplugged {{ color: #90a4ae; font-weight: bold; }}
        .optical-unknown {{ color: #888; }}
        .optical-table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }}
        .optical-table th, .optical-table td {{ border: 1px solid #404040; padding: 10px 12px; text-align: left; }}
        .optical-table th {{ background: #333; color: #76b900; font-weight: 600; font-size: 12px; }}
        .optical-table tbody tr {{ background: #252526; }}
        .optical-table tbody tr:hover {{ background: #2d2d2d; }}
        .optical-table td {{ word-wrap: break-word; overflow-wrap: break-word; }}
        .sortable {{ cursor: pointer; user-select: none; padding-right: 20px; }}
        .sortable:hover {{ background: #3c3c3c; }}
        .sort-arrow {{ font-size: 10px; color: #666; margin-left: 5px; opacity: 0.5; }}
        .sort-arrow::before {{ content: '▲▼'; }}
        .sortable.asc .sort-arrow::before {{ content: '▲'; color: #76b900; opacity: 1; }}
        .sortable.desc .sort-arrow::before {{ content: '▼'; color: #76b900; opacity: 1; }}
        .sortable.asc .sort-arrow, .sortable.desc .sort-arrow {{ opacity: 1; }}
        .filter-info {{ text-align: center; padding: 10px 15px; margin: 15px 16px; background: rgba(118, 185, 0, 0.1); border: 1px solid rgba(118, 185, 0, 0.3); border-radius: 6px; color: #76b900; display: none; font-size: 13px; }}
        .filter-info button {{ margin-left: 10px; padding: 4px 10px; background: #76b900; color: #000; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }}
        .btn {{ padding: 8px 14px; border: none; border-radius: 4px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; display: flex; align-items: center; gap: 6px; }}
        .btn-primary {{ background: linear-gradient(0deg, #76b900 0%, #5a8c00 100%); color: white; }}
        .btn-primary:hover {{ background: linear-gradient(0deg, #8bd400 0%, #6ba000 100%); }}
        .btn-secondary {{ background: linear-gradient(0deg, #4fc3f7 0%, #0288d1 100%); color: white; }}
        .btn-secondary:hover {{ background: linear-gradient(0deg, #81d4fa 0%, #039be5 100%); }}
        .action-buttons {{ display: flex; gap: 10px; align-items: center; }}
        .device-search-container {{ display: flex; align-items: center; gap: 8px; }}
        .device-search-container .select2-container {{ min-width: 200px; }}
        .device-search-container .select2-container--default .select2-selection--single {{ height: 34px; border: 1px solid #555; border-radius: 4px; background: #3c3c3c; display: flex; align-items: center; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__rendered {{ line-height: 34px; color: #d4d4d4; padding-left: 10px; font-size: 13px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__arrow {{ height: 34px; }}
        .device-search-container .select2-container--default .select2-selection--single .select2-selection__placeholder {{ color: #888; }}
        .select2-dropdown {{ background: #2d2d2d; border: 1px solid #555; }}
        .select2-container--default .select2-search--dropdown .select2-search__field {{ background: #3c3c3c; border: 1px solid #555; color: #d4d4d4; }}
        .select2-container--default .select2-results__option {{ color: #d4d4d4; padding: 8px 12px; }}
        .select2-container--default .select2-results__option--highlighted[aria-selected] {{ background: #76b900; color: #000; }}
        .select2-container--default .select2-results__option[aria-selected=true] {{ background: #3c3c3c; }}
        .clear-search-btn {{ background: #f44336; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; display: none; }}
        .clear-search-btn:hover {{ background: #d32f2f; }}
        .coverage-warning {{ background: rgba(255, 152, 0, 0.12); border: 1px solid #ff9800; border-radius: 6px; margin-bottom: 20px; padding: 14px 16px; color: #ffd180; }}
        .coverage-warning-title {{ color: #ffb74d; font-weight: 700; margin-bottom: 6px; }}
        .coverage-warning ul {{ margin: 8px 0 0 22px; }}
        .optical-table tbody tr.detail-parent {{ cursor: pointer; }}
        .detail-row td {{ padding: 0; border: 1px solid #404040; }}
        .detail-panel {{ padding: 14px 18px 16px; background: #202020; border-left: 3px solid #ff9800; }}
        .detail-title {{ color: #ffb300; font-weight: 700; margin-bottom: 10px; font-size: 13px; }}
        .detail-anomaly {{ margin: 6px 0; padding: 8px 10px; border-radius: 4px; background: #2a2118; border: 1px solid #6d511d; }}
        .detail-anomaly.critical {{ background: rgba(244, 67, 54, 0.1); border-color: #7a2a24; }}
        .detail-anomaly-msg {{ color: #ffd180; font-weight: 600; }}
        .detail-anomaly.critical .detail-anomaly-msg {{ color: #ff8a80; }}
        .detail-anomaly-action {{ color: #9ccc65; margin-top: 3px; }}
        .detail-lanes {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0; }}
        .detail-lane-card {{ background: #262626; border: 1px solid #3c3c3c; border-radius: 4px; padding: 8px 10px; }}
        .detail-lane-title {{ color: #76b900; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }}
        .detail-lane-values {{ color: #d4d4d4; font-family: monospace; font-size: 12px; }}
        .detail-raw {{ margin-top: 8px; }}
        .detail-raw summary {{ cursor: pointer; color: #4fc3f7; font-size: 12px; }}
        .detail-raw pre {{ margin-top: 6px; padding: 10px; background: #161616; border: 1px solid #333; border-radius: 4px; color: #b0b0b0; font-size: 11px; white-space: pre-wrap; word-break: break-word; max-height: 260px; overflow: auto; }}
        .detail-empty {{ color: #888; font-size: 12px; }}
        .empty-row td {{ text-align: center; color: #888; padding: 30px; }}
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: #1e1e1e; }}
        ::-webkit-scrollbar-thumb {{ background: #404040; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #555; }}
        @keyframes spin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body{coverage_attrs}>
    <div class="page-header">
        <div>
            <div class="page-title">Optical Diagnostics Analysis</div>
            <div class="last-updated">Last Updated: {last_updated_text}</div>
        </div>
        <div class="action-buttons">
            <div class="device-search-container">
                <select id="deviceSearch" style="width: 200px;"><option value="">Search Device...</option></select>
                <button id="clearSearchBtn" class="clear-search-btn" onclick="clearDeviceSearch()">✕</button>
            </div>
            <button id="thresholds-btn" onclick="openThresholdsModal()" class="btn btn-secondary" title="Thresholds &amp; grading reference">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3,17V19H9V17H3M3,5V7H13V5H3M13,21V19H21V17H13V15H11V21H13M7,9V11H3V13H7V15H9V9H7M21,13V11H11V13H21M15,9H17V7H21V5H17V3H15V9Z"/></svg>
                Thresholds
            </button>
            <button id="run-analysis" onclick="runAnalysis()" class="btn btn-secondary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4Z"/></svg>
                Run Analysis
            </button>
            <button id="download-csv" onclick="downloadCSV()" class="btn btn-primary">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/></svg>
                Download CSV
            </button>
        </div>
    </div>
    {coverage_warning_html}
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
            Optical Summary
        </div>
        <div class="section-content">
            <div class="summary-grid">
                <div class="summary-card card-info" id="total-ports-card">
                    <div class="metric" id="total-ports">{summary['total_ports']}</div>
                    <div class="metric-label">Total Ports</div>
                </div>
                <div class="summary-card card-excellent" id="excellent-card">
                    <div class="metric optical-excellent" id="excellent-ports">{len(summary['excellent_ports'])}</div>
                    <div class="metric-label">Excellent</div>
                </div>
                <div class="summary-card card-good" id="good-card">
                    <div class="metric optical-good" id="good-ports">{len(summary['good_ports'])}</div>
                    <div class="metric-label">Good</div>
                </div>
                <div class="summary-card card-warning" id="warning-card">
                    <div class="metric optical-warning" id="warning-ports">{len(summary['warning_ports'])}</div>
                    <div class="metric-label">Warning</div>
                </div>
                <div class="summary-card card-critical" id="critical-card">
                    <div class="metric optical-critical" id="critical-ports">{len(summary['critical_ports'])}</div>
                    <div class="metric-label">Critical</div>
                </div>
                <div class="summary-card card-down" id="down-card">
                    <div class="metric optical-down" id="down-ports">{len(summary['down_ports'])}</div>
                    <div class="metric-label">Down</div>
                </div>
                <div class="summary-card card-unplugged" id="unplugged-card">
                    <div class="metric optical-unplugged" id="unplugged-ports">{len(summary['unplugged_ports'])}</div>
                    <div class="metric-label">Unplugged</div>
                </div>
                <div class="summary-card card-unknown" id="unknown-card">
                    <div class="metric optical-unknown" id="unknown-ports">{len(summary['unknown_ports'])}</div>
                    <div class="metric-label">Unknown</div>
                </div>
            </div>
        </div>
    </div>
    
"""

        # Create one unified table for all monitored ports.  UNKNOWN rows are
        # retained so missing diagnostics cannot improve the visible coverage.
        all_ports = self._ordered_ports(summary)

        # Per-row evidence for the expandable detail panel.  Surfaces the
        # already-computed anomaly messages/actions and the raw per-lane arrays
        # that the collapsed table row cannot show.  No longer embedded in the
        # page: at fabric scale the inline JSON blob (raw diagnostics included)
        # reached tens of MB, so toggleDetails() fetches one
        # optical-details/<host>.json per device on first expand.
        details_by_host: Dict[str, Dict[str, Any]] = {}
        for port in all_ports:
            port_name = port['port']
            host = port_name.split(':')[0] if ':' in port_name else 'unknown'
            stats = self.current_optical_stats.get(port_name, {})
            details_by_host.setdefault(host, {})[port_name] = {
                'health': port.get('health'),
                'rx_lanes': stats.get('rx_power_lanes_dbm') or [],
                'tx_lanes': stats.get('tx_power_lanes_dbm') or [],
                'bias_lanes': stats.get('bias_current_lanes_ma') or [],
                'rx_lane_ids': stats.get('rx_power_lane_ids') or [],
                'tx_lane_ids': stats.get('tx_power_lane_ids') or [],
                'bias_lane_ids': stats.get('bias_current_lane_ids') or [],
                'inactive_lanes': stats.get('inactive_lanes') or [],
                'rx_lane': port.get('rx_power_lane'),
                'tx_lane': port.get('tx_power_lane'),
                'bias_lane': port.get('bias_current_lane'),
                'bias_thresholds_ma': stats.get('bias_thresholds_ma') or {},
                'bias_assessment': stats.get('bias_assessment') or {},
                'module_limits': stats.get('module_limits') or {},
                'not_monitored': stats.get('not_monitored') or [],
                'link_state': stats.get('link_state'),
                'anomalies': [
                    {
                        'severity': item.get('severity', ''),
                        'message': item.get('message', ''),
                        'action': item.get('action', ''),
                    }
                    for item in anomalies_by_port.get(port_name, [])
                ],
                'raw': stats.get('raw_data', ''),
            }
        self._write_detail_sidecars(
            os.path.dirname(os.path.abspath(output_file)), details_by_host
        )

        html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M4,1H20A1,1 0 0,1 21,2V6A1,1 0 0,1 20,7H4A1,1 0 0,1 3,6V2A1,1 0 0,1 4,1M4,9H20A1,1 0 0,1 21,10V14A1,1 0 0,1 20,15H4A1,1 0 0,1 3,14V10A1,1 0 0,1 4,9M4,17H20A1,1 0 0,1 21,18V22A1,1 0 0,1 20,23H4A1,1 0 0,1 3,22V18A1,1 0 0,1 4,17Z"/></svg>
            Optical Port Status ({len(all_ports)} total)
        </div>
        <div class="section-content-table">
            <div id="filter-info" class="filter-info">
                <span id="filter-text"></span>
                <button onclick="clearFilter()">Show All</button>
            </div>
            <div id="hydration-progress" class="filter-info" style="display:none"><span id="hydration-progress-text"></span></div>
            <table class="optical-table" id="optical-table">
                <thead>
                <tr>
                    <th class="sortable" data-column="0" data-type="string">Device <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="1" data-type="port">Port <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="2" data-type="optical-health">Health <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="3" data-type="optical-power">Rx Pwr <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="4" data-type="optical-power">Tx Pwr <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="5" data-type="temperature">Temp <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="6" data-type="optical-power">Margin <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="7" data-type="voltage">Voltage <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="8" data-type="current">Bias <span class="sort-arrow"></span></th>
                    <th class="sortable" data-column="9" data-type="string">Action <span class="sort-arrow"></span></th>
                </tr>
                </thead>
                <tbody id="optical-data">"""

        # Quiet rows are deferred into an inert payload the page hydrates in
        # chunks after first paint; the search dropdown is fed a complete
        # device list so it never misses devices whose rows are still loading.
        inline_rows: List[str] = []
        deferred_rows: List[str] = []
        device_names: Dict[str, str] = {}

        for port in all_ports:
            # Split port name into device and interface
            port_name = port['port']
            if ':' in port_name:
                device_name = port_name.split(':')[0]
                interface_name = port_name.split(':')[1]
            else:
                device_name = "unknown"
                interface_name = port_name
            
            rx_lane = port.get('rx_power_lane')
            tx_lane = port.get('tx_power_lane')
            bias_lane = port.get('bias_current_lane')
            rx_power = f"{port['rx_power_dbm']:.2f}" if port['rx_power_dbm'] is not None else "N/A"
            tx_power = f"{port['tx_power_dbm']:.2f}" if port['tx_power_dbm'] is not None else "N/A"
            if rx_lane is not None:
                rx_power += f" (L{rx_lane})"
            if tx_lane is not None:
                tx_power += f" (L{tx_lane})"
            temperature = f"{port['temperature_c']:.1f}" if port['temperature_c'] is not None else "N/A"
            link_margin = f"{port['link_margin_db']:.2f}" if port['link_margin_db'] is not None else "N/A"
            voltage = f"{port['voltage_v']:.2f}" if port['voltage_v'] is not None else "N/A"
            bias_current = f"{port['bias_current_ma']:.2f}" if port['bias_current_ma'] is not None else "N/A"
            if bias_lane is not None:
                bias_current += f" (L{bias_lane})"
            recommended_action = self.get_recommended_action(port)
            device_key = html.escape(str(device_name), quote=True)
            # Badge class based on health
            health = port['health']
            if health == 'excellent':
                badge_class = 'badge badge-green'
            elif health == 'good':
                badge_class = 'badge badge-green'
            elif health == 'warning':
                badge_class = 'badge badge-orange'
            elif health == 'critical':
                badge_class = 'badge badge-red'
            elif health == 'down':
                badge_class = 'badge badge-purple'
            elif health == 'unplugged':
                badge_class = 'badge badge-gray'
            else:
                badge_class = 'badge badge-gray'

            port_key = html.escape(str(port['port']), quote=True)
            device_names.setdefault(str(device_name), canonical(device_name))
            row_html = f"""
                <tr class="detail-parent" data-device-key="{device_key}" data-health="{port['health']}" data-port="{port_key}" onclick="toggleDetails(this)">
                    <td>{canonical(device_name)}</td>
                    <td>{interface_name}</td>
                    <td><span class="{badge_class}">{port['health'].upper()}</span></td>
                    <td>{rx_power}</td>
                    <td>{tx_power}</td>
                    <td>{temperature}</td>
                    <td>{link_margin}</td>
                    <td>{voltage}</td>
                    <td>{bias_current}</td>
                    <td>{recommended_action}</td>
                </tr>"""
            quiet = port['health'] in ('excellent', 'good', 'unplugged', 'unknown')
            (deferred_rows if quiet else inline_rows).append(row_html)

        # A pathological fabric can put >cap rows in the attention set; keep
        # first paint bounded by deferring the overflow ahead of quiet rows.
        if len(inline_rows) > INLINE_ROW_CAP:
            deferred_rows = inline_rows[INLINE_ROW_CAP:] + deferred_rows
            inline_rows = inline_rows[:INLINE_ROW_CAP]
        html_content += "".join(inline_rows)
        deferred_script = (
            f'<script type="text/html" id="optical-deferred-rows" '
            f'data-count="{len(deferred_rows)}">'
            + DEFERRED_ROW_SENTINEL.join(deferred_rows)
            + '</script>'
        ) if deferred_rows else ''

        if not all_ports:
            # Distinguish healthy-empty from stale/unavailable: a partial or
            # failed collection is already announced by the coverage banner
            # above, so this row states the empty table is not an error.
            if missing_hosts:
                empty_message = ('No optical diagnostics were collected. See the '
                                 'partial-collection notice above.')
            else:
                empty_message = ('No optical modules with diagnostics were found '
                                 '(all links are DAC/copper or no optics present).')
            html_content += f"""
                <tr class="empty-row"><td colspan="10">{html.escape(empty_message)}</td></tr>"""

        html_content += f"""
        </tbody>
            </table>
        </div>
    </div>
    {deferred_script}"""

        html_content += f"""
    <div class="dashboard-section">
        <div class="section-header">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12,15.5A3.5,3.5 0 0,1 8.5,12A3.5,3.5 0 0,1 12,8.5A3.5,3.5 0 0,1 15.5,12A3.5,3.5 0 0,1 12,15.5M19.43,12.97C19.47,12.65 19.5,12.33 19.5,12C19.5,11.67 19.47,11.34 19.43,11L21.54,9.37C21.73,9.22 21.78,8.95 21.66,8.73L19.66,5.27C19.54,5.05 19.27,4.96 19.05,5.05L16.56,6.05C16.04,5.66 15.5,5.32 14.87,5.07L14.5,2.42C14.46,2.18 14.25,2 14,2H10C9.75,2 9.54,2.18 9.5,2.42L9.13,5.07C8.5,5.32 7.96,5.66 7.44,6.05L4.95,5.05C4.73,4.96 4.46,5.05 4.34,5.27L2.34,8.73C2.21,8.95 2.27,9.22 2.46,9.37L4.57,11C4.53,11.34 4.5,11.67 4.5,12C4.5,12.33 4.53,12.65 4.57,12.97L2.46,14.63C2.27,14.78 2.21,15.05 2.34,15.27L4.34,18.73C4.46,18.95 4.73,19.03 4.95,18.95L7.44,17.94C7.96,18.34 8.5,18.68 9.13,18.93L9.5,21.58C9.54,21.82 9.75,22 10,22H14C14.25,22 14.46,21.82 14.5,21.58L14.87,18.93C15.5,18.67 16.04,18.34 16.56,17.94L19.05,18.95C19.27,19.03 19.54,18.95 19.66,18.73L21.66,15.27C21.78,15.05 21.73,14.78 21.54,14.63L19.43,12.97Z"/></svg>
            Optical Health Thresholds
        </div>
        <div class="section-content-table">
            <table class="optical-table">
                <thead>
                    <tr><th>Parameter</th><th>Min Threshold</th><th>Max Threshold</th><th>Description</th></tr>
                </thead>
                <tbody>
                    <tr><td>Module limits</td><td>Module low alarm / warning</td><td>Module high warning / alarm</td><td>RX power, TX power, temperature and voltage are graded by the limits the module prints for itself (ethtool -m) whenever its table for that parameter is complete, consistent and physically plausible (an unprogrammed table such as -128 / +128 C is ignored): a lane or module value beyond an alarm limit is Critical, beyond a warning limit is Warning, close to a warning limit is Good. The generic values in the rows below are then not applied to that parameter. Expand a port to see which limits graded it.</td></tr>
                    <tr><td>RX Power</td><td>{self.thresholds['rx_power_min_dbm']} dBm</td><td>{self.thresholds['rx_power_critical_high_dbm']} dBm</td><td>Generic limits, used when the module prints no valid RX power table (warning above {self.thresholds['rx_power_warning_high_dbm']} dBm). Received power on in-service optical lanes only; media-declared placeholder channels and lanes with no light and no laser bias current are excluded</td></tr>
                    <tr><td>TX Power</td><td>{self.thresholds['tx_power_min_dbm']} dBm</td><td>{self.thresholds['tx_power_max_dbm']} dBm</td><td>Generic transmitted optical power range, used when the module prints no valid TX power table (warning within 1 dB of either end)</td></tr>
                    <tr><td>Temperature</td><td>{self.thresholds['temperature_min_c']}°C</td><td>{self.thresholds['temperature_max_c']}°C</td><td>Generic SFP/QSFP operating temperature, used when the module prints no valid temperature table (warning within 10°C of the maximum)</td></tr>
                    <tr><td>Voltage</td><td>{self.thresholds['voltage_min_v']}V</td><td>{self.thresholds['voltage_max_v']}V</td><td>Generic supply voltage range, used when the module prints no valid voltage table</td></tr>
                    <tr><td>Link Margin</td><td>{self.thresholds['link_margin_min_db']} dB</td><td>-</td><td>Minimum margin from notifications.yaml; a lane below it is Warning. Counted from the module's RX power low alarm when the module prints a valid RX power table, otherwise from the generic {self.thresholds['rx_power_min_dbm']} dBm RX sensitivity</td></tr>
                    <tr><td>Bias Current</td><td>Module low limits</td><td>Module high limits</td><td>Module-reported warning/alarm limits and flags, in mA. Expand a port to see its limits and assessment. Without sufficient module evidence, bias assessment is unavailable; other optical parameters are still graded.</td></tr>
                    <tr><td>Down</td><td>-</td><td>{self.DARK_POWER_DBM} dBm RX</td><td>The port's link is down while its module still answers, whatever the module reads: expand the port to see whether light is present on all lanes, which lane is too low, or that no receive light arrives, and any module alarm behind the outage. Without a collected link state, a port with no receive light (at or below {self.DARK_POWER_DBM} dBm) on every in-service lane. A port whose link is up is never Down. Reported separately from Critical threshold violations</td></tr>
                </tbody>
            </table>
        </div>
    </div>
"""

        device_list_json = json.dumps(
            sorted(device_names.items()), separators=(',', ':'),
            ensure_ascii=True
        ).replace('</', '<\\/')
        html_content += f"""
    <script>window.__opticalDeviceList = {device_list_json};</script>
"""

        html_content += """
    <!-- jQuery and Select2 for device search -->
    <script src="/css/jquery-3.5.1.min.js"></script>
    <script src="/css/select2.min.js"></script>
    
    <script>
        // Filter functionality
        let currentFilter = 'ALL';
        let allRows = [];
        let deviceSearchActive = false;
        let selectedDevice = '';

        // Per-row detail evidence (anomaly messages/actions + per-lane
        // arrays + raw diagnostics) is no longer embedded in the page; each
        // device's optical-details sidecar is fetched on first row expand
        // and cached as a promise to dedupe concurrent clicks.
        const opticalDetailCache = new Map();
        function opticalDeviceDetails(device) {
            if (!device) return Promise.resolve(null);
            if (opticalDetailCache.has(device)) return opticalDetailCache.get(device);
            const request = fetch('optical-details/' + encodeURIComponent(device) + '.json', {cache: 'no-store'})
                .then(response => {
                    if (!response.ok) throw new Error('HTTP ' + response.status);
                    return response.json();
                })
                .then(state => (state && typeof state === 'object' &&
                    state.ports && typeof state.ports === 'object') ? state.ports : {})
                .catch(() => {
                    opticalDetailCache.delete(device);
                    return null;
                });
            opticalDetailCache.set(device, request);
            return request;
        }

        function esc(value) {
            return String(value === null || value === undefined ? '' : value)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }

        function removeDetailRows() {
            document.querySelectorAll('#optical-data tr.detail-row').forEach(r => r.remove());
            document.querySelectorAll('#optical-data tr.detail-parent').forEach(
                r => r.classList.remove('expanded')
            );
        }

        // Lane identity comes from the sample, not from the array position:
        // the values listed here are the assessed lanes, which on a
        // breakout interface or a partly equipped module are not lanes 1..N.
        function laneText(values, unit, ids) {
            if (!values || !values.length) return 'N/A';
            return values.map((v, i) => 'L' + ((ids && ids[i]) ?? (i + 1)) + ': ' +
                (typeof v === 'number' ? v.toFixed(2) : esc(v)) + unit).join('  ');
        }

        let opticalDetailToken = 0;
        function toggleDetails(row) {
            if (!row.classList.contains('detail-parent')) return;
            const next = row.nextElementSibling;
            const wasOpen = next && next.classList.contains('detail-row');
            removeDetailRows();
            if (wasOpen) { opticalDetailToken++; return; }

            const token = ++opticalDetailToken;
            opticalDeviceDetails(row.dataset.deviceKey || '').then(function(ports) {
                // The panel may have been superseded (or its row sorted away)
                // while the sidecar loaded.
                if (token !== opticalDetailToken || !document.body.contains(row)) return;
                renderDetailPanel(row, (ports || {})[row.dataset.port || ''] || {});
            });
        }

        function renderDetailPanel(row, data) {
            const port = row.dataset.port || '';
            let inner = '<div class="detail-panel">';
            inner += '<div class="detail-title">' + esc(port) + ' — ' +
                esc(String(data.health || 'unknown').toUpperCase()) + '</div>';

            const anomalies = data.anomalies || [];
            if (anomalies.length) {
                anomalies.forEach(a => {
                    const crit = a.severity === 'critical' ? ' critical' : '';
                    inner += '<div class="detail-anomaly' + crit + '">' +
                        '<div class="detail-anomaly-msg">' + esc(a.message) + '</div>' +
                        (a.action ? '<div class="detail-anomaly-action">Action: ' +
                            esc(a.action) + '</div>' : '') + '</div>';
                });
            } else {
                inner += '<div class="detail-empty">No anomalies recorded for this port.</div>';
            }

            inner += '<div class="detail-lanes">';
            inner += '<div class="detail-lane-card"><div class="detail-lane-title">RX Power (worst L' +
                esc(data.rx_lane ?? '-') + ')</div><div class="detail-lane-values">' +
                esc(laneText(data.rx_lanes, ' dBm', data.rx_lane_ids)) + '</div></div>';
            inner += '<div class="detail-lane-card"><div class="detail-lane-title">TX Power (worst L' +
                esc(data.tx_lane ?? '-') + ')</div><div class="detail-lane-values">' +
                esc(laneText(data.tx_lanes, ' dBm', data.tx_lane_ids)) + '</div></div>';
            inner += '<div class="detail-lane-card"><div class="detail-lane-title">Bias Current (worst L' +
                esc(data.bias_lane ?? '-') + ')</div><div class="detail-lane-values">' +
                esc(laneText(data.bias_lanes, ' mA', data.bias_lane_ids)) + '</div>';
            const biasLimits = data.bias_thresholds_ma || {};
            const biasAssessment = data.bias_assessment || {};
            inner += '<div class="detail-empty">Module bias limits:</div><div class="detail-lane-values">';
            [
                ['low_alarm', 'Low alarm'], ['low_warning', 'Low warning'],
                ['high_warning', 'High warning'], ['high_alarm', 'High alarm']
            ].forEach(([key, label]) => {
                const value = biasLimits[key];
                inner += esc(label) + ': ' +
                    (typeof value === 'number' && Number.isFinite(value)
                        ? esc(value.toFixed(3)) + ' mA' : 'Unavailable') + '<br>';
            });
            inner += '</div><div class="detail-empty">Bias assessment: ' +
                esc(String(biasAssessment.status || 'unknown').toUpperCase()) +
                '<br>' + esc(biasAssessment.reason ||
                    'Bias assessment unavailable: module limits and flags were not recorded.') +
                '</div></div>';
            inner += '</div>';

            // Which limits graded each parameter: the module's own table
            // when it prints a complete one, the generic values otherwise.
            const moduleLimits = data.module_limits;
            if (moduleLimits && Array.isArray(moduleLimits.decided)) {
                const limitTables = moduleLimits.thresholds || {};
                // A table the module prints but that no real module could
                // mean (an unprogrammed one) grades nothing.
                const ignoredTables = moduleLimits.ignored || {};
                inner += '<div class="detail-empty">Limits used for grading:</div>' +
                    '<div class="detail-lane-values">';
                [
                    ['rx_power', 'RX power', ' dBm', 2], ['tx_power', 'TX power', ' dBm', 2],
                    ['temperature', 'Temperature', ' C', 2], ['voltage', 'Voltage', ' V', 4]
                ].forEach(([key, label, unit, digits]) => {
                    const limitText = table => [
                        ['low_alarm', 'low alarm'], ['low_warning', 'low warning'],
                        ['high_warning', 'high warning'], ['high_alarm', 'high alarm']
                    ].filter(([name]) => typeof table[name] === 'number' && Number.isFinite(table[name]))
                        .map(([name, text]) => text + ' ' + table[name].toFixed(digits) + unit)
                        .join(', ');
                    const printed = limitText(limitTables[key] || {});
                    const ignored = limitText(ignoredTables[key] || {});
                    let source = 'generic limits (the module prints no valid table)';
                    if (moduleLimits.decided.includes(key)) {
                        source = 'module limits: ' + printed;
                    } else if (printed) {
                        source = 'generic limits; the module prints only ' + printed +
                            ', which can still raise an alarm';
                    } else if (ignored) {
                        source = 'generic limits (module table ignored: implausible; it prints ' +
                            ignored + ')';
                    }
                    inner += esc(label) + ': ' + esc(source) + '<br>';
                });
                inner += '</div>';
            }

            // A power side this module does not monitor has no value: it
            // read no light on every lane while the link was up or, on a
            // port without a collected link state, while the lasers were
            // driven and light arrived, so it was not graded.
            const notMonitored = data.not_monitored || [];
            if (notMonitored.length) {
                const sideNames = {tx_power: 'TX power', rx_power: 'RX power'};
                const contradiction = data.link_state === 'up'
                    ? 'although the link is up'
                    : 'although the lasers draw bias and the port receives light';
                inner += '<div class="detail-empty">Not monitored by this module, not graded: ' +
                    esc(notMonitored.map(side => sideNames[side] || side).join(', ')) +
                    ' (reads no light on every lane ' + contradiction + ').</div>';
            }

            const inactive = data.inactive_lanes || [];
            if (inactive.length) {
                inner += '<div class="detail-empty">Not in service, excluded from grading: ' +
                    esc(inactive.map(l => 'L' + l).join(', ')) +
                    ' (no light and no laser bias current).</div>';
            }

            if (data.raw) {
                inner += '<details class="detail-raw"><summary>Raw diagnostics (truncated)</summary>' +
                    '<pre>' + esc(data.raw) + '</pre></details>';
            }
            inner += '</div>';

            const detail = document.createElement('tr');
            detail.className = 'detail-row';
            detail.innerHTML = '<td colspan="10">' + inner + '</td>';
            row.after(detail);
            row.classList.add('expanded');
        }

        document.addEventListener('DOMContentLoaded', function() {
            // Store all data table rows for filtering (skip placeholder rows)
            allRows = Array.from(document.querySelectorAll('#optical-data tr.detail-parent'));

            // Add click events to summary cards
            setupCardEvents();

            // Initialize table sorting
            initTableSorting();

            // Initialize device search
            populateDeviceList();
            initDeviceSearch();

            // Stream the deferred quiet rows in after first paint.
            hydrateOpticalDeferredRows();
        });

        // True when rows landed after the user's last explicit sort; the
        // hydrator restores the chosen order once, at the end.
        let rowsAppendedSinceSort = false;

        // Mirrors the active card/device filter for rows that arrive during
        // chunked hydration. Matches on data attributes only, so it stays
        // correct when p2p-alias rewrites the displayed device names later.
        function opticalRowHidden(row) {
            if (deviceSearchActive && selectedDevice) {
                return row.dataset.deviceKey !== selectedDevice;
            }
            if (currentFilter !== 'ALL' && currentFilter !== 'TOTAL') {
                return row.dataset.health !== currentFilter.toLowerCase();
            }
            return false;
        }

        function updateHydrationProgress(done, total, finished) {
            const csvButton = document.getElementById('download-csv');
            if (csvButton) {
                // The export walks the DOM; until every deferred row lands
                // a CSV would be silently truncated.
                csvButton.disabled = !finished;
                csvButton.title = finished ? '' : 'Rows are still loading…';
            }
            const box = document.getElementById('hydration-progress');
            if (!box) return;
            if (finished) { box.style.display = 'none'; return; }
            box.style.display = 'block';
            document.getElementById('hydration-progress-text').textContent =
                'Loading port rows: ' + done.toLocaleString() + ' / '
                + total.toLocaleString()
                + ' — search, sort and CSV cover loaded rows until this finishes.';
        }

        // Chunked hydration of the deferred quiet rows. The inline table
        // carries only rows that need attention, so first paint is instant;
        // the rest stream into the tbody in batches that never block input.
        function hydrateOpticalDeferredRows() {
            const HYDRATION_CHUNK_ROWS = 1500;
            const SENTINEL = '<!--=lldpq-row=-->';
            const el = document.getElementById('optical-deferred-rows');
            const body = document.getElementById('optical-data');
            if (!el || !body) { updateHydrationProgress(0, 0, true); return; }
            const total = parseInt(el.dataset.count || '0', 10) || 0;
            const raw = el.textContent;
            el.remove();
            let pos = 0;
            let done = 0;

            function nextChunk() {
                if (pos >= raw.length) {
                    updateHydrationProgress(total, total, true);
                    // Restore the user's chosen order in one pass, but only
                    // when chunks actually landed after the sort.
                    if (tableSortState.column >= 0 && rowsAppendedSinceSort) {
                        const th = document.querySelector(
                            '.sortable[data-column="' + tableSortState.column + '"]');
                        sortOpticalTable(tableSortState.column,
                                         tableSortState.direction,
                                         th ? th.dataset.type : 'string');
                    }
                    return;
                }
                let end = pos;
                let count = 0;
                while (count < HYDRATION_CHUNK_ROWS && end < raw.length) {
                    const i = raw.indexOf(SENTINEL, end);
                    end = i === -1 ? raw.length : i + SENTINEL.length;
                    count++;
                }
                // Strip the join sentinels before insertion: comment nodes
                // interleaved with rows make later sorts pathologically slow.
                body.insertAdjacentHTML(
                    'beforeend', raw.slice(pos, end).replaceAll(SENTINEL, ''));
                pos = end;
                done = Math.min(total, done + count);
                rowsAppendedSinceSort = true;
                const kids = body.children;
                const filtered = (deviceSearchActive && selectedDevice)
                    || (currentFilter !== 'ALL' && currentFilter !== 'TOTAL');
                for (let i = kids.length - count; i < kids.length; i++) {
                    allRows.push(kids[i]);
                    if (filtered) {
                        kids[i].style.display = opticalRowHidden(kids[i]) ? 'none' : '';
                    }
                }
                updateHydrationProgress(done, total, false);
                setTimeout(nextChunk, 30);
            }

            updateHydrationProgress(0, total, false);
            // Give first paint and the rest of DOMContentLoaded room to
            // finish before the background build starts.
            setTimeout(nextChunk, 80);
        }

        function setupCardEvents() {
            document.getElementById('total-ports-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('total-ports').textContent) > 0) {
                    filterPorts('TOTAL');
                }
            });

            document.getElementById('excellent-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('excellent-ports').textContent) > 0) {
                    filterPorts('EXCELLENT');
                }
            });

            document.getElementById('good-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('good-ports').textContent) > 0) {
                    filterPorts('GOOD');
                }
            });

            document.getElementById('warning-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('warning-ports').textContent) > 0) {
                    filterPorts('WARNING');
                }
            });

            document.getElementById('critical-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('critical-ports').textContent) > 0) {
                    filterPorts('CRITICAL');
                }
            });

            document.getElementById('down-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('down-ports').textContent) > 0) {
                    filterPorts('DOWN');
                }
            });

            document.getElementById('unplugged-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('unplugged-ports').textContent) > 0) {
                    filterPorts('UNPLUGGED');
                }
            });

            document.getElementById('unknown-card').addEventListener('click', function() {
                if (parseInt(document.getElementById('unknown-ports').textContent) > 0) {
                    filterPorts('UNKNOWN');
                }
            });
        }

        function filterPorts(filterType) {
            currentFilter = filterType;
            removeDetailRows();

            // Clear device search when using card filters
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }

            // Clear active state from all cards
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });

            let filteredRows = allRows;
            let filterText = '';

            if (filterType === 'EXCELLENT') {
                filteredRows = allRows.filter(row => row.dataset.health === 'excellent');
                filterText = `Showing ${filteredRows.length} Excellent Ports`;
                document.getElementById('excellent-card').classList.add('active');
            } else if (filterType === 'GOOD') {
                filteredRows = allRows.filter(row => row.dataset.health === 'good');
                filterText = `Showing ${filteredRows.length} Good Ports`;
                document.getElementById('good-card').classList.add('active');
            } else if (filterType === 'WARNING') {
                filteredRows = allRows.filter(row => row.dataset.health === 'warning');
                filterText = `Showing ${filteredRows.length} Warning Ports`;
                document.getElementById('warning-card').classList.add('active');
            } else if (filterType === 'CRITICAL') {
                filteredRows = allRows.filter(row => row.dataset.health === 'critical');
                filterText = `Showing ${filteredRows.length} Critical Ports`;
                document.getElementById('critical-card').classList.add('active');
            } else if (filterType === 'DOWN') {
                filteredRows = allRows.filter(row => row.dataset.health === 'down');
                filterText = `Showing ${filteredRows.length} Down Ports`;
                document.getElementById('down-card').classList.add('active');
            } else if (filterType === 'UNPLUGGED') {
                filteredRows = allRows.filter(row => row.dataset.health === 'unplugged');
                filterText = `Showing ${filteredRows.length} Unplugged Ports`;
                document.getElementById('unplugged-card').classList.add('active');
            } else if (filterType === 'UNKNOWN') {
                filteredRows = allRows.filter(row => row.dataset.health === 'unknown');
                filterText = `Showing ${filteredRows.length} Unknown Ports`;
                document.getElementById('unknown-card').classList.add('active');
            } else if (filterType === 'TOTAL') {
                filteredRows = allRows;
                document.getElementById('total-ports-card').classList.add('active');
            }

            // Show filter info for all filters except TOTAL
            if (filterType !== 'ALL' && filterType !== 'TOTAL') {
                document.getElementById('filter-info').style.display = 'block';
                document.getElementById('filter-text').textContent = filterText;
            } else {
                document.getElementById('filter-info').style.display = 'none';
            }

            // Hide all rows first
            allRows.forEach(row => row.style.display = 'none');

            // Show filtered rows
            filteredRows.forEach(row => row.style.display = '');
        }

        function clearFilter() {
            currentFilter = 'ALL';
            removeDetailRows();
            document.querySelectorAll('.summary-card').forEach(card => {
                card.classList.remove('active');
            });
            document.getElementById('filter-info').style.display = 'none';

            // Also clear device search
            if (deviceSearchActive) {
                selectedDevice = '';
                deviceSearchActive = false;
                $('#deviceSearch').val('').trigger('change');
                document.getElementById('clearSearchBtn').style.display = 'none';
            }

            // Show all rows
            allRows.forEach(row => row.style.display = '');
        }
        
        // ===== Device Search Functions =====
        function initDeviceSearch() {
            $('#deviceSearch').select2({
                placeholder: 'Search Device...',
                allowClear: true,
                width: '250px',
                dropdownAutoWidth: true,
                matcher: function(params, data) {
                    if ($.trim(params.term) === '') return data;
                    if (typeof data.text === 'undefined') return null;
                    if (data.text.toLowerCase().indexOf(params.term.toLowerCase()) > -1) return data;
                    return null;
                }
            });
            
            $('#deviceSearch').on('select2:select', function(e) {
                const device = e.params.data.id;
                if (device) filterByDevice(device);
            });
            
            $('#deviceSearch').on('select2:clear', function(e) {
                clearDeviceSearch();
            });
        }
        
        function populateDeviceList() {
            // Complete embedded [raw key, display name] list: the dropdown
            // must never miss devices whose rows are still hydrating.
            const pairs = Array.isArray(window.__opticalDeviceList) ? window.__opticalDeviceList : [];
            pairs.sort((a, b) =>
                String(a[1]).localeCompare(String(b[1]), undefined, { numeric: true, sensitivity: 'base' })
            );

            const select = document.getElementById('deviceSearch');
            select.innerHTML = '<option value="">Search Device...</option>';
            pairs.forEach(pair => {
                const option = document.createElement('option');
                option.value = pair[0];
                option.textContent = pair[1];
                select.appendChild(option);
            });
        }
        
        function filterByDevice(deviceKey) {
            if (!deviceKey) return;

            selectedDevice = deviceKey;
            deviceSearchActive = true;
            removeDetailRows();

            // Clear card-based filter
            currentFilter = 'ALL';
            document.querySelectorAll('.summary-card').forEach(card => card.classList.remove('active'));

            // Match on data-device-key so this keeps working when p2p-alias
            // rewrites the displayed device names.
            let matchCount = 0;
            let displayName = deviceKey;
            allRows.forEach(row => {
                if (row.dataset.deviceKey === deviceKey) {
                    if (matchCount === 0) displayName = row.cells[0]?.textContent?.trim() || deviceKey;
                    row.style.display = '';
                    matchCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            if (matchCount === 0) {
                const pair = (window.__opticalDeviceList || []).find(p => p[0] === deviceKey);
                if (pair) displayName = pair[1];
            }

            // Show filter info
            document.getElementById('filter-info').style.display = 'block';
            document.getElementById('filter-text').textContent = 'Showing ports for device: ' + displayName + ' (' + matchCount + ' ports)';
            document.getElementById('clearSearchBtn').style.display = 'inline-block';
        }
        
        function clearDeviceSearch() {
            selectedDevice = '';
            deviceSearchActive = false;
            removeDetailRows();
            $('#deviceSearch').val('').trigger('change');
            document.getElementById('clearSearchBtn').style.display = 'none';
            document.getElementById('filter-info').style.display = 'none';
            allRows.forEach(row => row.style.display = '');
        }

        // Generic table sorting functionality
        let tableSortState = { column: -1, direction: 'asc' };

        function initTableSorting() {
            const headers = document.querySelectorAll('.sortable');
            headers.forEach(header => {
                header.addEventListener('click', function() {
                    const column = parseInt(this.dataset.column);
                    const type = this.dataset.type;

                    // Toggle sort direction
                    if (tableSortState.column === column) {
                        tableSortState.direction = tableSortState.direction === 'asc' ? 'desc' : 'asc';
                    } else {
                        tableSortState.direction = 'asc';
                    }
                    tableSortState.column = column;

                    // Update header styling
                    headers.forEach(h => h.classList.remove('asc', 'desc'));
                    this.classList.add(tableSortState.direction);

                    // Sort table
                    sortOpticalTable(column, tableSortState.direction, type);
                });
            });
        }

        function sortOpticalTable(columnIndex, direction, type) {
            const table = document.getElementById('optical-table');
            const tbody = table.querySelector('tbody');
            removeDetailRows();
            const rows = Array.from(tbody.rows).filter(
                row => !row.classList.contains('empty-row')
            );

            rows.sort((a, b) => {
                let aVal = a.cells[columnIndex].textContent.trim();
                let bVal = b.cells[columnIndex].textContent.trim();

                // Extract actual text for health columns (remove HTML)
                if (type === 'optical-health') {
                    aVal = a.cells[columnIndex].querySelector('span')?.textContent || aVal;
                    bVal = b.cells[columnIndex].querySelector('span')?.textContent || bVal;
                }

                let result = 0;

                switch(type) {
                    case 'optical-power':
                    case 'temperature':
                    case 'voltage':
                    case 'current':
                        result = compareOpticalValue(aVal, bVal);
                        break;
                    case 'port':
                        result = comparePort(aVal, bVal);
                        break;
                    case 'optical-health':
                        result = compareOpticalHealth(aVal, bVal);
                        break;
                    case 'string':
                    default:
                        result = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: 'base' });
                        break;
                }

                return direction === 'desc' ? -result : result;
            });

            // Clear tbody and add sorted rows back
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
            rowsAppendedSinceSort = false;
        }

        function comparePort(a, b) {
            if (a === 'N/A') return 1;
            if (b === 'N/A') return -1;

            // Handle port sorting (swp1, swp10, swp1s0, etc.)
            const extractPortNumber = (port) => {
                const match = port.match(/swp(\\d+)(?:s(\\d+))?/);
                if (match) {
                    const mainPort = parseInt(match[1]);
                    const subPort = match[2] ? parseInt(match[2]) : 0;
                    return mainPort * 1000 + subPort;
                }
                return port.localeCompare(b, undefined, { numeric: true });
            };

            return extractPortNumber(a) - extractPortNumber(b);
        }

        function compareOpticalHealth(a, b) {
            const priority = {
                'CRITICAL': 0,
                'DOWN': 1,
                'UNPLUGGED': 2,
                'WARNING': 3,
                'GOOD': 4,
                'EXCELLENT': 5,
                'UNKNOWN': 6
            };

            return (priority[a] ?? 5) - (priority[b] ?? 5);
        }

        function compareOpticalValue(a, b) {
            // Handle 'N/A' values
            if (a === 'N/A' && b === 'N/A') return 0;
            if (a === 'N/A') return 1;
            if (b === 'N/A') return -1;

            // Parse numerical values (handle negative numbers)
            const numA = parseFloat(a);
            const numB = parseFloat(b);

            if (isNaN(numA) && isNaN(numB)) return 0;
            if (isNaN(numA)) return 1;
            if (isNaN(numB)) return -1;

            return numA - numB;
        }

        // Run Analysis Function
        async function runAnalysis() {
            const button = document.getElementById('run-analysis');
            const originalText = button.innerHTML;
            let notification = null;

            // Disable button and show loading
            button.disabled = true;
            button.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style="animation: spin 1s linear infinite;">
                    <path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M12,6A6,6 0 0,0 6,12A6,6 0 0,0 12,18A6,6 0 0,0 18,12A6,6 0 0,0 12,6M12,8A4,4 0 0,1 16,12A4,4 0 0,1 12,16A4,4 0 0,1 8,12A4,4 0 0,1 12,8Z"/>
                </svg>
                Running...
            `;

            try {
                // Capture the current pipeline generation before triggering a
                // new one.  The shared analysis guard resolves only after a
                // newer complete generation has been published.
                let baseline = null;
                if (typeof window.lldpqCaptureAnalysisState === 'function') {
                    baseline = await window.lldpqCaptureAnalysisState('optical');
                }

                const response = await fetch('/trigger-monitor?scope=optical', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await response.json();
                if (!response.ok || data.status !== 'success' || !data.trigger_id || data.scope !== 'optical') {
                    throw new Error(data.message || 'Failed to trigger monitor analysis');
                }

                console.log('✅ Monitor analysis triggered successfully');
                notification = document.createElement('div');
                    notification.style.cssText = `
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        background: #c87f0a;
                        color: white;
                        padding: 15px 20px;
                        border-radius: 8px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                        z-index: 1000;
                        font-size: 14px;
                        max-width: 350px;
                        font-family: monospace;
                    `;
                    notification.innerHTML = `
                        <strong>✅ Monitor Analysis Started</strong><br>
                        The optical analysis is running in the background.<br>
                        <small>Page will refresh after the new optical results are completely published.</small>
                    `;
                document.body.appendChild(notification);

                if (typeof window.waitForLldpqAnalysisCompletion === 'function') {
                    await window.waitForLldpqAnalysisCompletion(
                        baseline, { scope: 'optical', pipelineId: data.trigger_id }
                    );
                } else {
                    // Compatibility fallback for older installations that do
                    // not yet provide analysis-guard.js completion polling.
                    await new Promise(resolve => setTimeout(resolve, 35000));
                }

                window.location.reload();
            } catch (error) {
                console.error('❌ Error triggering analysis:', error);
                if (notification) notification.remove();
                alert('Analysis did not complete: ' + (error.message || error));
                button.disabled = false;
                button.innerHTML = originalText;
            }
        }

        // CSV Download Function
        function downloadCSV() {
            try {
                // Get current date for filename
                const now = new Date();
                const dateStr = now.toISOString().slice(0, 10); // YYYY-MM-DD
                const timeStr = now.toTimeString().slice(0, 5).replace(':', '-'); // HH-MM
                const filename = `Optical_Analysis_Report_${dateStr}_${timeStr}.csv`;

                // Read headers and cells from the same table so Device/Action
                // and future columns cannot become shifted or truncated.
                const table = document.getElementById('optical-table');
                const headers = Array.from(table.querySelectorAll('thead th')).map(th =>
                    th.textContent.replace('▲▼', '').trim()
                );

                // Get table data (only visible data rows)
                const tbody = table.querySelector('tbody');
                const rows = tbody.querySelectorAll('tr');

                // Summary comments come BEFORE the header row so a spreadsheet or
                // parser that skips leading '#' lines reads a clean header.
                let csvContent = '';
                csvContent += `# Optical Diagnostics Summary Report\\n`;
                csvContent += `# Generated: ${now.toLocaleString()}\\n`;
                csvContent += `# Total Ports: ${document.getElementById('total-ports').textContent}\\n`;
                csvContent += `# Excellent: ${document.getElementById('excellent-ports').textContent}\\n`;
                csvContent += `# Good: ${document.getElementById('good-ports').textContent}\\n`;
                csvContent += `# Warning: ${document.getElementById('warning-ports').textContent}\\n`;
                csvContent += `# Critical: ${document.getElementById('critical-ports').textContent}\\n`;
                csvContent += `# Down: ${document.getElementById('down-ports').textContent}\\n`;
                csvContent += `# Unplugged: ${document.getElementById('unplugged-ports').textContent}\\n`;
                csvContent += `# Unknown: ${document.getElementById('unknown-ports').textContent}\\n`;

                // Note when the export reflects an active filter so the totals
                // above cannot be mistaken for the exported (filtered) rows.
                const filterInfo = document.getElementById('filter-info');
                const filtered = filterInfo && filterInfo.style.display !== 'none';
                if (filtered) {
                    const filterText = document.getElementById('filter-text').textContent.trim();
                    csvContent += `# NOTE: Rows below reflect the active filter (${filterText}); summary counts above are for the full fabric.\\n`;
                }
                csvContent += `#\\n`;
                csvContent += headers.join(',') + '\\n';

                // Process each visible data row (skip detail/empty placeholder rows)
                rows.forEach(row => {
                    if (row.classList.contains('detail-row') ||
                        row.classList.contains('empty-row')) {
                        return;
                    }
                    // table-filter.js funnels hide rows via the tf-hidden
                    // class, never via style.display; honor both so the
                    // export matches the visible table.
                    if (row.style.display !== 'none' && !row.classList.contains('tf-hidden')) {
                        const cells = row.querySelectorAll('td');
                        if (cells.length) {
                            const rowData = Array.from(cells).map(cell =>
                                cell.textContent.trim()
                            );

                            // Escape commas and quotes in data
                            const escapedData = rowData.map(field => {
                                if (field.includes(',') || field.includes('"') || field.includes('\\n')) {
                                    return '"' + field.replace(/"/g, '""') + '"';
                                }
                                return field;
                            });

                            csvContent += escapedData.join(',') + '\\n';
                        }
                    }
                });

                // Create and trigger download
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = filename;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);

                console.log(`✅ CSV downloaded: ${filename}`);

            } catch (error) {
                console.error('❌ Error generating CSV:', error);
                alert('Error generating CSV file. Please try again.');
            }
        }
    </script>
    <!-- Thresholds reference modal: the in-page threshold/explanation sections are
         relocated in here at load time and shown via the "Thresholds" toolbar button. -->
    <div id="thresholdModal" class="threshold-modal" onclick="if(event.target===this)closeThresholdsModal()">
        <div class="threshold-modal-box">
            <div class="threshold-modal-head">
                <h2>Thresholds</h2>
                <button type="button" class="threshold-modal-close" onclick="closeThresholdsModal()" title="Close">&times;</button>
            </div>
            <div id="thresholdModalBody" class="threshold-modal-body"></div>
        </div>
    </div>
    <style>
        .threshold-modal { display:none; position:fixed; inset:0; z-index:1000; background:rgba(0,0,0,0.65); }
        .threshold-modal.open { display:flex; align-items:flex-start; justify-content:center; }
        .threshold-modal-box { background:#1e1e1e; border:1px solid #3c3c3c; border-radius:8px; width:92%; max-width:920px; margin:40px 16px; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 12px 48px rgba(0,0,0,0.55); }
        .threshold-modal-head { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-bottom:1px solid #3c3c3c; }
        .threshold-modal-head h2 { margin:0; font-size:16px; color:#e0e0e0; }
        .threshold-modal-close { background:none; border:none; color:#aaa; font-size:24px; line-height:1; cursor:pointer; padding:0 6px; }
        .threshold-modal-close:hover { color:#fff; }
        .threshold-modal-body { padding:4px 18px 18px; overflow:auto; }
        .threshold-modal-body .dashboard-section { margin:14px 0 0; }
        .threshold-modal-body .dashboard-section:first-child { margin-top:6px; }
    </style>
    <script>
        (function () {
            function buildThresholdModal() {
                var body = document.getElementById('thresholdModalBody');
                if (!body) return;
                var sections = Array.prototype.slice.call(document.querySelectorAll('.dashboard-section'));
                var start = -1;
                for (var i = 0; i < sections.length; i++) {
                    var h = sections[i].querySelector('.section-header');
                    if (h && /threshold/i.test(h.textContent)) { start = i; break; }
                }
                if (start < 0) return;
                // Move the threshold section + any trailing explanation sections into the modal.
                for (var j = start; j < sections.length; j++) { body.appendChild(sections[j]); }
            }
            window.openThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.add('open'); };
            window.closeThresholdsModal = function () { var m = document.getElementById('thresholdModal'); if (m) m.classList.remove('open'); };
            document.addEventListener('keydown', function (e) { if (e.key === 'Escape') window.closeThresholdsModal(); });
            buildThresholdModal();
        })();
    </script>
    <script src="/p2p-alias.js"></script>
    <script src="/css/table-filter.js?v=20260821-tf-6"></script>
    <script src="/css/analysis-guard.js?v=20260731-analysis-3"></script>
</body>
</html>"""

        _atomic_write(output_file, html_content)

if __name__ == "__main__":
    analyzer = OpticalAnalyzer()
    print("Optical analyzer initialized")
    print(f"Monitoring {len(analyzer.current_optical_stats)} ports")
