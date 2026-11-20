#!/usr/bin/env python3
"""LLDPq Multi-Domain Predictive Health Analyzer.

Scores every physical port, RoCEv2 congestion port, switch chassis, and
localized hardware thermal/fan sensor across existing ``monitor-results/``
telemetry using a two-tier CPU-only hybrid model (Tier-1 physics + peer-group
MAD scorer fused with a lightweight pure-Python stdlib GBDT classifier).

Publishes atomic JSON snapshots (nginx-readable 0644) under the target
``monitor-results/`` directory:

- ``export/predictive.json``         (actionable risk rows + metadata)
- ``summary/predictive-summary.json`` (fleet KPI counts by severity & family)

Pure Python standard library only — zero PyTorch, NumPy, or network I/O.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from predictive_engine import (  # noqa: E402
    ALL_FAMILIES,
    FAMILY_CONGESTION,
    FAMILY_HARDWARE_CONTROL,
    FAMILY_PHYSICAL,
    FeatureExtractor,
    LLDPqSnapshotLoader,
    PredictiveRiskModel,
    PredictiveRiskSignal,
)

SCHEMA_VERSION = 1
DEFAULT_MODEL_PATH = SCRIPT_DIR / "predictive_model.json"

EXPORT_COLUMNS: tuple[str, ...] = (
    "entity_key",
    "device",
    "port",
    "family",
    "domains",
    "severity",
    "risk_score",
    "horizon_hours",
    "confidence",
    "peer_zscore",
    "early_warning",
    "raw_status",
    "role_classification",
    "top_reasons",
    "recommended_action",
    "slope_metrics",
    "tier_scores",
)

_NOMINAL_RAW_STATUSES = frozenset({
    "ok",
    "good",
    "excellent",
    "normal",
    "healthy",
    "nominal",
    "up",
    "established",
    "pass",
    "info",
})

_SEVERITY_RANK = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomically write JSON with mode 0664 so CLI, cron, nginx, and ai_correlate share access."""
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o664)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _load_model(model_path: Path | None) -> tuple[PredictiveRiskModel, str, str]:
    """Load trained hybrid model if present, else fall back cleanly to Day-1 Tier-1."""
    if model_path is not None and model_path.is_file():
        model = PredictiveRiskModel.load(model_path)
        meta = getattr(model, "metadata", {}) or {}
        version = str(meta.get("model_version") or "1.0.0")
        mode = str(meta.get("mode") or ("hybrid" if model.is_trained else "day1_tier1"))
        return model, version, mode
    return PredictiveRiskModel(backend="native_gbdt"), "day1-tier1", "day1_tier1"


def _is_early_warning(signal: PredictiveRiskSignal, raw_status: str) -> bool:
    """True when predictive risk is WARNING/CRITICAL before raw LLDPq thresholds fire."""
    if signal.severity not in ("WARNING", "CRITICAL"):
        return False
    norm = (raw_status or "").strip().lower()
    return norm in _NOMINAL_RAW_STATUSES


def _signal_to_row(signal: PredictiveRiskSignal, raw_status: str) -> dict[str, Any]:
    early = _is_early_warning(signal, raw_status)
    return {
        "entity_key": signal.entity_key,
        "device": signal.device,
        "port": signal.port,
        "family": signal.family,
        "domains": list(signal.domains),
        "severity": signal.severity,
        "risk_score": round(float(signal.risk_score), 2),
        "horizon_hours": int(signal.horizon_hours),
        "confidence": round(float(signal.confidence), 3),
        "peer_zscore": round(float(signal.peer_zscore), 3),
        "early_warning": early,
        "raw_status": raw_status or "unknown",
        "role_classification": signal.role_classification,
        "top_reasons": list(signal.top_reasons),
        "recommended_action": signal.recommended_action,
        "slope_metrics": {k: round(float(v), 5) for k, v in (signal.slope_metrics or {}).items()},
        "tier_scores": {k: round(float(v), 2) for k, v in (signal.tier_scores or {}).items()},
    }


def _latest_matching(series: Any, predicate: Any, *, max_age_sec: float | None = None) -> Any | None:
    if not series:
        return None
    latest_ts = getattr(series[-1], "timestamp", 0.0) or 0.0
    for item in reversed(series):
        if max_age_sec is not None and (latest_ts - (getattr(item, "timestamp", 0.0) or 0.0)) > max_age_sec:
            break
        if predicate(item):
            return item
    return None


def _build_raw_status_map(snapshot: Any) -> dict[tuple[str, str], str]:
    """Map (family, entity_key) -> aggregated raw LLDPq status across underlying domains.

    An entity is only considered ``nominal`` (eligible for ``early_warning=True``)
    when NONE of the underlying LLDPq domain analyzers have already raised a
    warning/critical/down/mismatch alert within the active collection window.
    """
    active_win = 3600.0
    bad_tokens = ("critical", "error", "bad", "down", "fail", "failed", "fault")
    warn_tokens = ("warning", "warn", "degraded", "marginal")
    mapping: dict[tuple[str, str], str] = {}

    for key, series in (getattr(snapshot, "physical", None) or {}).items():
        if not series:
            continue
        opt_lat = _latest_matching(
            series,
            lambda s: str(getattr(s, "health_status", "") or "").strip().lower() not in ("", "unknown"),
        )
        ber_lat = _latest_matching(
            series,
            lambda s: str(getattr(s, "ber_grade", "") or "").strip().lower() not in ("", "unknown"),
        )
        flap_lat = _latest_matching(
            series,
            lambda s: (getattr(s, "flaps_1h", 0) or 0) > 0
            or (getattr(s, "flaps_24h", 0) or 0) > 0
            or (getattr(s, "flaps_5m", 0) or 0) > 0,
            max_age_sec=active_win,
        )
        mm_lat = _latest_matching(
            series,
            lambda s: bool(
                getattr(s, "mtu_mismatch", False)
                or getattr(s, "speed_mismatch", False)
                or getattr(s, "fec_mismatch", False)
                or getattr(s, "autoneg_mismatch", False)
                or getattr(s, "config_mtu_mismatch", False)
            ),
            max_age_sec=active_win,
        )
        statuses: list[str] = []
        if opt_lat is not None:
            statuses.append(str(getattr(opt_lat, "health_status", "")).strip().lower())
        if ber_lat is not None:
            statuses.append(str(getattr(ber_lat, "ber_grade", "")).strip().lower())
        if flap_lat is not None:
            f1 = int(getattr(flap_lat, "flaps_1h", 0) or 0)
            f24 = int(getattr(flap_lat, "flaps_24h", 0) or 0)
            if f1 >= 5 or f24 >= 20:
                statuses.append("critical")
            elif f1 >= 1 or f24 >= 5:
                statuses.append("warning")
        if mm_lat is not None:
            if getattr(mm_lat, "mtu_mismatch", False) or getattr(mm_lat, "speed_mismatch", False):
                statuses.append("critical")
            else:
                statuses.append("warning")

        if any(s in bad_tokens for s in statuses):
            mapping[(FAMILY_PHYSICAL, key)] = "critical"
        elif any(s in warn_tokens for s in statuses):
            mapping[(FAMILY_PHYSICAL, key)] = "warning"
        elif any(s == "unplugged" for s in statuses):
            mapping[(FAMILY_PHYSICAL, key)] = "unplugged"
        elif statuses:
            mapping[(FAMILY_PHYSICAL, key)] = statuses[0]

    for key, series in (getattr(snapshot, "congestion", None) or {}).items():
        if not series:
            continue
        latest = series[-1]
        sig = str(getattr(latest, "signal", None) or "").strip().lower()
        if sig == "quiet":
            mapping[(FAMILY_CONGESTION, key)] = "ok"
        elif sig in ("loss", "combined"):
            mapping[(FAMILY_CONGESTION, key)] = "critical"
        elif sig == "pfc":
            mapping[(FAMILY_CONGESTION, key)] = "warning"
        elif sig:
            mapping[(FAMILY_CONGESTION, key)] = sig

    for key, series in (getattr(snapshot, "hardware_control", None) or {}).items():
        if not series:
            continue
        hw_lat = (
            _latest_matching(
                series,
                lambda s: (
                    getattr(s, "asic_temp_c", None) is not None
                    or getattr(s, "cpu_temp_c", None) is not None
                    or getattr(s, "psu_efficiency", None) is not None
                    or str(getattr(s, "psu_status", "unknown")).lower() != "unknown"
                    or str(getattr(s, "fan_status", "unknown")).lower() != "unknown"
                    or bool(getattr(s, "fan_rpms", None))
                    or int(getattr(s, "fan_failed_count", 0) or 0) > 0
                    or int(getattr(s, "psu_failed_count", 0) or 0) > 0
                    or not bool(getattr(s, "psu_redundancy_ok", True))
                ),
            )
            or series[-1]
        )
        grade_lat = _latest_matching(
            series,
            lambda s: str(getattr(s, "overall_grade", "unknown") or "unknown").strip().lower() not in ("", "unknown"),
        )
        bgp_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "bgp_total_neighbors", 0) or 0) > 0
                or int(getattr(s, "bgp_down_neighbors", 0) or 0) > 0
                or int(getattr(s, "bgp_flaps_1h", 0) or 0) > 0
                or int(getattr(s, "bgp_update_storms", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )
        evpn_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "evpn_mh_total_es", 0) or 0) > 0
                or int(getattr(s, "evpn_mh_critical_es", 0) or 0) > 0
                or int(getattr(s, "evpn_mh_warning_es", 0) or 0) > 0
                or int(getattr(s, "evpn_mh_inconsistent_es", 0) or 0) > 0
                or int(getattr(s, "evpn_mh_bypass_es", 0) or 0) > 0
                or int(getattr(s, "lacp_desync_count", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )
        routes_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "routes_total", 0) or 0) > 0
                or float(getattr(s, "routes_drop_fraction", 0.0) or 0.0) > 0.0
                or int(getattr(s, "vrf_disappeared_count", 0) or 0) > 0
                or int(getattr(s, "ecmp_width_drop", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )
        dup_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "dup_ip_active", 0) or 0) > 0
                or int(getattr(s, "dup_mac_confirmed", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )
        log_lat = _latest_matching(
            series,
            lambda s: int(getattr(s, "log_critical_count", 0) or 0) > 0,
            max_age_sec=active_win,
        )
        sys_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "reboots_24h", 0) or 0) > 0
                or int(getattr(s, "critical_service_restarts_24h", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )
        bmc_lat = _latest_matching(
            series,
            lambda s: (
                int(getattr(s, "bmc_mismatch_count", 0) or 0) > 0
                or int(getattr(s, "bmc_sensor_faults", 0) or 0) > 0
            ),
            max_age_sec=active_win,
        )

        hw_grade = str(getattr(grade_lat, "overall_grade", "") or "").strip().lower() if grade_lat else ""
        fan_failed = int(getattr(hw_lat, "fan_failed_count", 0) or 0)
        psu_failed = int(getattr(hw_lat, "psu_failed_count", 0) or 0)
        psu_ok = bool(getattr(hw_lat, "psu_redundancy_ok", True))

        is_crit = (
            hw_grade in bad_tokens
            or fan_failed > 0
            or psu_failed > 0
            or not psu_ok
            or (bgp_lat is not None and int(getattr(bgp_lat, "bgp_down_neighbors", 0) or 0) > 0)
            or (
                evpn_lat is not None
                and (
                    int(getattr(evpn_lat, "evpn_mh_critical_es", 0) or 0) > 0
                    or int(getattr(evpn_lat, "evpn_mh_inconsistent_es", 0) or 0) > 0
                    or int(getattr(evpn_lat, "evpn_mh_bypass_es", 0) or 0) > 0
                    or int(getattr(evpn_lat, "lacp_desync_count", 0) or 0) > 0
                )
            )
            or (
                routes_lat is not None
                and (
                    int(getattr(routes_lat, "vrf_disappeared_count", 0) or 0) > 0
                    or float(getattr(routes_lat, "routes_drop_fraction", 0.0) or 0.0) >= 0.25
                )
            )
            or (dup_lat is not None)
            or (log_lat is not None)
        )
        is_warn = (
            hw_grade in warn_tokens
            or (
                bgp_lat is not None
                and (
                    int(getattr(bgp_lat, "bgp_flaps_1h", 0) or 0) >= 3
                    or int(getattr(bgp_lat, "bgp_update_storms", 0) or 0) > 0
                )
            )
            or (evpn_lat is not None and int(getattr(evpn_lat, "evpn_mh_warning_es", 0) or 0) > 0)
            or (
                routes_lat is not None
                and (
                    float(getattr(routes_lat, "routes_drop_fraction", 0.0) or 0.0) >= 0.10
                    or int(getattr(routes_lat, "ecmp_width_drop", 0) or 0) >= 2
                )
            )
            or (sys_lat is not None)
            or (bmc_lat is not None)
        )

        if is_crit:
            mapping[(FAMILY_HARDWARE_CONTROL, key)] = "critical"
        elif is_warn:
            mapping[(FAMILY_HARDWARE_CONTROL, key)] = "warning"
        elif hw_grade and hw_grade != "unknown":
            mapping[(FAMILY_HARDWARE_CONTROL, key)] = hw_grade

        for sensor in getattr(series[-1], "sensors", None) or ():
            s_status = str(getattr(sensor, "status", None) or "").strip().lower()
            if s_status and s_status != "unknown":
                mapping[(FAMILY_HARDWARE_CONTROL, sensor.entity_key)] = s_status
    return mapping


def analyze_monitor_results(
    monitor_dir: str | Path,
    *,
    output_dir: str | Path | None = None,
    model_path: str | Path | None = None,
    min_risk: float = 40.0,
    include_info: bool = False,
    max_rows: int = 2000,
    now: float | None = None,
) -> dict[str, Any]:
    """Run multi-domain predictive health analysis over an LLDPq monitor-results directory.

    Parameters
    ----------
    monitor_dir:
        Directory containing LLDPq artifacts (``export/*.json``, ``*-history/``,
        ``summary/``, etc.). Read-only.
    output_dir:
        Destination directory where ``export/predictive.json`` and
        ``summary/predictive-summary.json`` are written. Defaults to
        ``monitor_dir``.
    model_path:
        Optional path to ``predictive_model.json``. Defaults to
        ``<script_dir>/predictive_model.json`` if present, else Day-1 Tier-1 mode.
    min_risk:
        Minimum risk score (0..100) included in ``export/predictive.json`` rows
        when ``include_info`` is False. Default ``40.0`` (WARNING + CRITICAL).
    include_info:
        When True, include INFO rows (up to ``max_rows``) in addition to
        WARNING/CRITICAL rows.
    max_rows:
        Hard cap on exported rows to keep web hydration snappy on large fabrics.
    now:
        Optional UNIX epoch override for deterministic tests.
    """
    t0 = time.monotonic()
    src_root = Path(monitor_dir).resolve()
    dst_root = Path(output_dir).resolve() if output_dir is not None else src_root
    resolved_model = Path(model_path).resolve() if model_path is not None else DEFAULT_MODEL_PATH

    model, model_version, model_mode = _load_model(resolved_model if resolved_model.is_file() else None)
    loader = LLDPqSnapshotLoader()
    snapshot = loader.load(src_root)

    extractor = FeatureExtractor()
    features = extractor.extract_all(snapshot)
    raw_status_map = _build_raw_status_map(snapshot)
    signals = model.predict_features(features)

    total_scored = len(signals)
    family_totals = {fam: 0 for fam in ALL_FAMILIES}
    family_actionable = {fam: {"critical": 0, "warning": 0, "info": 0, "early_warning": 0} for fam in ALL_FAMILIES}
    sev_counts = {"critical": 0, "warning": 0, "info": 0}
    early_warning_count = 0
    affected_devices: set[str] = set()
    rows: list[dict[str, Any]] = []

    for sig in signals:
        family_totals[sig.family] = family_totals.get(sig.family, 0) + 1
        sev_key = sig.severity.lower()
        sev_counts[sev_key] = sev_counts.get(sev_key, 0) + 1
        fam_bucket = family_actionable.setdefault(
            sig.family, {"critical": 0, "warning": 0, "info": 0, "early_warning": 0}
        )
        fam_bucket[sev_key] = fam_bucket.get(sev_key, 0) + 1

        raw_status = raw_status_map.get((sig.family, sig.entity_key), "")
        early = _is_early_warning(sig, raw_status)
        if early:
            early_warning_count += 1
            fam_bucket["early_warning"] += 1

        is_actionable = sig.severity in ("CRITICAL", "WARNING") or sig.risk_score >= min_risk
        if sig.severity in ("CRITICAL", "WARNING") and sig.device:
            affected_devices.add(sig.device)

        if include_info or is_actionable:
            rows.append(_signal_to_row(sig, raw_status))

    rows.sort(
        key=lambda r: (
            _SEVERITY_RANK.get(r["severity"], 9),
            -float(r["risk_score"]),
            -abs(float(r["peer_zscore"])),
            r["device"],
            r["port"] or "",
            r["family"],
        )
    )
    truncated = len(rows) > max_rows
    if truncated:
        rows = rows[:max_rows]

    generated_epoch = float(now) if now is not None else time.time()
    generated_iso = datetime.fromtimestamp(generated_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)

    counts = {
        "total_scored": total_scored,
        "actionable": sev_counts["critical"] + sev_counts["warning"],
        "critical": sev_counts["critical"],
        "warning": sev_counts["warning"],
        "info": sev_counts["info"],
        "early_warning": early_warning_count,
        "affected_devices": len(affected_devices),
        "exported_rows": len(rows),
    }

    export_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "domain": "predictive",
        "generated_at": generated_iso,
        "generated_epoch": round(generated_epoch, 3),
        "collection_status": "ok" if total_scored > 0 else "empty",
        "model_version": model_version,
        "model_mode": model_mode,
        "elapsed_ms": elapsed_ms,
        "truncated": truncated,
        "counts": counts,
        "by_family": {
            fam: {
                "total": family_totals.get(fam, 0),
                **family_actionable.get(fam, {"critical": 0, "warning": 0, "info": 0, "early_warning": 0}),
            }
            for fam in ALL_FAMILIES
        },
        "columns": list(EXPORT_COLUMNS),
        "row_count": len(rows),
        "rows": rows,
    }

    summary_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "domain": "predictive",
        "generated_at": generated_iso,
        "generated_epoch": round(generated_epoch, 3),
        "status": (
            "critical"
            if sev_counts["critical"] > 0
            else ("warning" if sev_counts["warning"] > 0 else "ok")
        ),
        "model_version": model_version,
        "model_mode": model_mode,
        "elapsed_ms": elapsed_ms,
        "counts": counts,
        "by_family": export_payload["by_family"],
        "top_risks": rows[:15],
    }

    export_path = dst_root / "export" / "predictive.json"
    summary_path = dst_root / "summary" / "predictive-summary.json"
    _atomic_write_json(export_path, export_payload)
    _atomic_write_json(summary_path, summary_payload)

    return {
        "export_path": str(export_path),
        "summary_path": str(summary_path),
        "counts": counts,
        "by_family": export_payload["by_family"],
        "elapsed_ms": elapsed_ms,
        "model_version": model_version,
        "model_mode": model_mode,
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run LLDPq multi-domain predictive health analysis on monitor-results."
    )
    parser.add_argument(
        "--monitor-dir",
        default=str(SCRIPT_DIR / "monitor-results"),
        help="Input monitor-results directory (default: lldpq/monitor-results).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for export/predictive.json and summary/predictive-summary.json "
        "(default: same as --monitor-dir).",
    )
    parser.add_argument(
        "--model",
        default=str(DEFAULT_MODEL_PATH),
        help="Path to predictive_model.json (falls back to Day-1 Tier-1 if missing).",
    )
    parser.add_argument(
        "--min-risk",
        type=float,
        default=40.0,
        help="Minimum risk score (0-100) to include in export rows (default: 40.0).",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="Include INFO-level entities in export rows (up to --max-rows).",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=2000,
        help="Maximum rows written to export/predictive.json (default: 2000).",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    model_arg = Path(args.model) if args.model else None
    result = analyze_monitor_results(
        args.monitor_dir,
        output_dir=args.output_dir,
        model_path=model_arg,
        min_risk=args.min_risk,
        include_info=args.include_info,
        max_rows=args.max_rows,
    )
    c = result["counts"]
    print(
        f"Predictive health ({result['model_mode']} v{result['model_version']}): "
        f"scored={c['total_scored']} critical={c['critical']} warning={c['warning']} "
        f"early_warning={c['early_warning']} devices={c['affected_devices']} "
        f"elapsed={result['elapsed_ms']}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
