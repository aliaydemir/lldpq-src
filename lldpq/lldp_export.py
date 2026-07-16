#!/usr/bin/env python3
"""Payload builders for /lldp_results/export_json and /lldp_results/export_csv.

Served on request by html/lldp-export-api.sh from the already-published
``lldp_results.ini`` (the exact file lldp.html renders), so the export is
always byte-in-sync with the page without touching check-lldp.sh's publish
transaction.

The status/health classification is a verbatim Python port of
``determineLLDPStatus`` (html/lldp.html:1012-1107) and the CSV mirrors the
page's Download CSV button (``CSV_HEADERS``/``canonicalConnectionRow``/
``buildLLDPCSV``, html/lldp.html:2289-2326) for its default problems-first
table order.  ``build_payload`` cross-checks the classification against
``LLDPReport.counts`` — the two encode the same contract, and a mismatch
means one of them drifted, which must surface as a loud error, never as a
silently wrong export.
"""

from __future__ import annotations

from typing import Any

import export_artifacts
from lldp_report import LLDPReport, LLDPRow

DOMAIN = "lldp_results"

# Display headers of the page's Download CSV (html/lldp.html:2290-2293).
CSV_HEADERS = (
    "Local Device", "Local Port", "Port Status", "Expected Neighbor",
    "Expected Port", "Active Neighbor", "Active Port", "Status",
    "Connection Health",
)

# Fresh-page default table order (html/lldp.html LLDP_STATUS_PRIORITY).
_STATUS_PRIORITY = {"FAILED": 0, "NO INFO": 1, "WARNING": 2, "SUCCESS": 3}

_COUNT_KEY_BY_STATUS = {
    "SUCCESS": "successful",
    "FAILED": "failed",
    "WARNING": "warnings",
    "NO INFO": "no_info",
}


class LLDPExportDriftError(RuntimeError):
    """classify() and LLDPReport.counts disagree — a port of the contract drifted."""


def _normalized(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _missing(value: Any) -> bool:
    return _normalized(value).lower() in ("", "none", "n/a")


def _same_hostname(left: Any, right: Any) -> bool:
    return (
        not _missing(left)
        and not _missing(right)
        and _normalized(left).lower() == _normalized(right).lower()
    )


def classify(row: LLDPRow) -> tuple[str, str]:
    """Verbatim port of determineLLDPStatus (html/lldp.html:1012-1107)."""
    lldp_status = _normalized(row.status).lower()
    port_status = _normalized(row.port_status).upper()

    if _missing(row.local_port):
        return "FAILED", "Local Port Not Defined"
    if lldp_status == "pass":
        return "SUCCESS", "LLDP Connection Verified"
    if lldp_status == "no-info":
        if port_status == "DOWN":
            return "NO INFO", "Local Port is DOWN"
        return "NO INFO", "No LLDP Response Received"
    if lldp_status == "fail":
        if port_status == "DOWN":
            return "FAILED", "Local Port is DOWN"
        if _missing(row.actual_device) or _missing(row.expected_device):
            return "WARNING", "Unexpected Connection"
        if (
            _same_hostname(row.actual_device, row.expected_device)
            and not _missing(row.actual_port)
            and not _missing(row.expected_port)
            and _normalized(row.actual_port) != _normalized(row.expected_port)
        ):
            return (
                "WARNING",
                f"Port Mismatch: Expected {row.expected_port}, "
                f"Got {row.actual_port}",
            )
        if not _same_hostname(row.actual_device, row.expected_device):
            return (
                "WARNING",
                f"Wrong Device: Expected {row.expected_device}, "
                f"Got {row.actual_device}",
            )
        return "WARNING", "Unexpected Connection"
    return "WARNING", f"Unknown Status: {row.status}"


def classified_rows(report: LLDPReport) -> list[tuple[LLDPRow, str, str]]:
    """(row, status, health) triples in the page's default problems-first order."""
    items = [(row, *classify(row)) for row in report.rows]
    items.sort(key=lambda item: _STATUS_PRIORITY.get(item[1], 4))  # stable
    return items


def _verify_counts(
    report: LLDPReport, items: list[tuple[LLDPRow, str, str]]
) -> dict[str, int]:
    tallies = {"successful": 0, "failed": 0, "warnings": 0, "no_info": 0}
    for _row, status, _health in items:
        tallies[_COUNT_KEY_BY_STATUS[status]] += 1
    expected = report.counts.as_dict()
    if tallies != expected:
        raise LLDPExportDriftError(
            f"classification tallies {tallies} != LLDPReport.counts {expected}"
        )
    tallies["total"] = len(items)
    return tallies


def created_stamp(report: LLDPReport) -> str:
    """The report's own 'Created on' value (data age, not request time)."""
    return report.created_header.removeprefix("Created on ").strip()


def _optional(value: Any) -> Any:
    return None if _missing(value) else _normalized(value)


def build_payload(report: LLDPReport) -> dict[str, Any]:
    items = classified_rows(report)
    counts = _verify_counts(report, items)
    rows = []
    for row, status, health in items:
        rows.append(
            {
                "local_device": row.local_device,
                "local_port": _optional(row.local_port),
                "port_status": _optional(row.port_status),
                "expected_device": _optional(row.expected_device),
                "expected_port": _optional(row.expected_port),
                "actual_device": _optional(row.actual_device),
                "actual_port": _optional(row.actual_port),
                "lldp_status": row.status,
                "status": status,
                "connection_health": health,
            }
        )
    payload = export_artifacts.build_payload(
        DOMAIN, rows, counts, None,
        generated_at=report.created_at.timestamp(),
    )
    payload["created"] = created_stamp(report)
    return payload


def build_csv(report: LLDPReport) -> str:
    """Byte-parity with the page's Download CSV of the freshly loaded table."""
    items = classified_rows(report)
    lines = [",".join(export_artifacts.csv_field(h) for h in CSV_HEADERS)]
    for row, status, health in items:
        cells = (
            row.local_device, row.local_port, row.port_status,
            row.expected_device, row.expected_port,
            row.actual_device, row.actual_port, status, health,
        )
        lines.append(",".join(export_artifacts.csv_field(cell) for cell in cells))
    return "\r\n".join(lines) + "\r\n"


__all__ = (
    "CSV_HEADERS",
    "DOMAIN",
    "LLDPExportDriftError",
    "build_csv",
    "build_payload",
    "classified_rows",
    "classify",
    "created_stamp",
)
