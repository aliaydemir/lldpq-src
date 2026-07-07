#!/usr/bin/env python3
"""Strict parser for LLDPq aggregate ``lldp_results.ini`` reports.

The aggregate report is consumed by several independent surfaces.  Keeping the
row and timestamp contract here prevents a truncated report from being counted
as healthy by one consumer and ignored by another.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path
import re
from typing import Iterable, Optional, Union


class LLDPReportError(ValueError):
    """Raised when an aggregate LLDP report violates its on-disk schema."""


_LEGACY_CREATED_RE = re.compile(
    r"^Created on (\d{4}-\d{2}-\d{2} \d{2}-\d{2}(?:-\d{2})?)$"
)
_AWARE_CREATED_RE = re.compile(
    r"^Created on "
    r"(\d{4}-\d{2}-\d{2})[T ]"
    r"(\d{2})(?::|-)(\d{2})(?::|-)(\d{2})"
    r"(\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})$",
    re.IGNORECASE,
)
_DEVICE_HEADER_RE = re.compile(r"^=+\s+(\S+)\s+=+$")
_SEPARATOR_RE = re.compile(r"^-{3,}$")

_COLUMN_HEADER = (
    "Port",
    "Status",
    "Exp-Nbr",
    "Exp-Nbr-Port",
    "Act-Nbr",
    "Act-Nbr-Port",
    "Port-Status",
)
_VALID_STATUSES = frozenset(("Pass", "Fail", "No-Info"))
_VALID_PORT_STATUSES = frozenset(("UP", "DOWN", "UNKNOWN", "N/A"))


@dataclass(frozen=True)
class LLDPRow:
    local_device: str
    local_port: str
    status: str
    expected_device: str
    expected_port: str
    actual_device: str
    actual_port: str
    port_status: str


@dataclass(frozen=True)
class LLDPCounts:
    total: int
    successful: int
    failed: int
    warnings: int
    no_info: int

    def __post_init__(self) -> None:
        classified = self.successful + self.failed + self.warnings + self.no_info
        if self.total != classified:
            raise ValueError(
                f"LLDP count invariant failed: total={self.total}, classified={classified}"
            )

    def as_dict(self, *, include_total: bool = False) -> dict[str, int]:
        result = {
            "successful": self.successful,
            "failed": self.failed,
            "warnings": self.warnings,
            "no_info": self.no_info,
        }
        if include_total:
            result["total"] = self.total
        return result


@dataclass(frozen=True)
class LLDPReport:
    created_at: datetime
    created_header: str
    rows: tuple[LLDPRow, ...]

    @property
    def timestamp_is_timezone_aware(self) -> bool:
        return self.created_at.tzinfo is not None

    @property
    def counts(self) -> LLDPCounts:
        successful = 0
        failed = 0
        warnings = 0
        no_info = 0

        for row in self.rows:
            if row.local_port.strip().lower() in {"", "none", "n/a"}:
                # Wiring treats an absent local endpoint as a malformed topology
                # row and therefore as a hard failure regardless of raw status.
                failed += 1
            elif row.status == "Pass":
                successful += 1
            elif row.status == "No-Info":
                no_info += 1
            elif row.port_status == "DOWN":
                failed += 1
            else:
                # This is the Wiring Results contract: a physically non-DOWN
                # Fail is a wrong/unexpected-neighbor warning.
                warnings += 1

        return LLDPCounts(
            total=len(self.rows),
            successful=successful,
            failed=failed,
            warnings=warnings,
            no_info=no_info,
        )


def parse_created_header(
    line: str, *, legacy_timezone: Optional[tzinfo] = None
) -> datetime:
    """Parse a legacy local timestamp or a timezone-aware timestamp.

    Legacy headers intentionally remain naive by default so ``datetime.timestamp``
    keeps the historical process-local interpretation used by ``check_alerts``.
    Callers may provide ``legacy_timezone`` when they have an explicit deployment
    timezone.  Aware headers must include ``Z`` or a numeric UTC offset and may
    use either ISO separators or the report-safe ``HH-MM-SS +HHMM`` form.
    """

    header = line.strip()
    legacy_match = _LEGACY_CREATED_RE.fullmatch(header)
    if legacy_match:
        value = legacy_match.group(1)
        timestamp_format = (
            "%Y-%m-%d %H-%M-%S" if value.count("-") == 4 else "%Y-%m-%d %H-%M"
        )
        try:
            parsed = datetime.strptime(value, timestamp_format)
        except ValueError as exc:
            raise LLDPReportError("invalid legacy Created timestamp") from exc
        return parsed.replace(tzinfo=legacy_timezone) if legacy_timezone else parsed

    aware_match = _AWARE_CREATED_RE.fullmatch(header)
    if aware_match:
        date, hour, minute, second, fraction, raw_offset = aware_match.groups()
        if raw_offset.upper() == "Z":
            offset = "+00:00"
        else:
            offset_digits = raw_offset[1:].replace(":", "")
            if int(offset_digits[:2]) > 23 or int(offset_digits[2:]) > 59:
                raise LLDPReportError("invalid timezone-aware Created timestamp")
            offset = raw_offset if ":" in raw_offset else (
                raw_offset[:3] + ":" + raw_offset[3:]
            )
        normalized = (
            f"{date}T{hour}:{minute}:{second}{fraction or ''}{offset}"
        )
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise LLDPReportError("invalid timezone-aware Created timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise LLDPReportError("timezone-aware Created timestamp lacks an offset")
        return parsed

    raise LLDPReportError("missing or unsupported Created timestamp")


def _nonempty_lines(text: str) -> Iterable[tuple[int, str]]:
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if line:
            yield line_number, line


def parse_lldp_report(
    text: str,
    *,
    legacy_timezone: Optional[tzinfo] = None,
    require_rows: bool = True,
) -> LLDPReport:
    """Parse one complete aggregate report and reject partial/malformed rows."""

    if not isinstance(text, str):
        raise TypeError("LLDP report text must be a string")

    lines = list(_nonempty_lines(text))
    if not lines:
        raise LLDPReportError("LLDP report is empty")

    first_line_number, created_header = lines[0]
    if first_line_number < 1:  # Defensive; enumerate always starts at one.
        raise LLDPReportError("invalid Created header location")
    created_at = parse_created_header(
        created_header, legacy_timezone=legacy_timezone
    )

    current_device: Optional[str] = None
    rows: list[LLDPRow] = []
    for line_number, line in lines[1:]:
        device_match = _DEVICE_HEADER_RE.fullmatch(line)
        if device_match:
            current_device = device_match.group(1)
            continue
        if _SEPARATOR_RE.fullmatch(line):
            continue

        parts = tuple(line.split())
        if parts == _COLUMN_HEADER:
            if current_device is None:
                raise LLDPReportError(
                    f"line {line_number}: column header appears before a device"
                )
            continue
        if current_device is None:
            raise LLDPReportError(
                f"line {line_number}: data appears before a device header"
            )
        if len(parts) != 7:
            raise LLDPReportError(
                f"line {line_number}: expected 7 LLDP columns, got {len(parts)}"
            )

        (
            local_port,
            status,
            expected_device,
            expected_port,
            actual_device,
            actual_port,
            raw_port_status,
        ) = parts
        if status not in _VALID_STATUSES:
            raise LLDPReportError(
                f"line {line_number}: unsupported LLDP status {status!r}"
            )
        port_status = raw_port_status.upper()
        if port_status not in _VALID_PORT_STATUSES:
            raise LLDPReportError(
                f"line {line_number}: unsupported port status {raw_port_status!r}"
            )

        rows.append(
            LLDPRow(
                local_device=current_device,
                local_port=local_port,
                status=status,
                expected_device=expected_device,
                expected_port=expected_port,
                actual_device=actual_device,
                actual_port=actual_port,
                port_status=port_status,
            )
        )

    if require_rows and not rows:
        raise LLDPReportError("LLDP report contains no port rows")

    return LLDPReport(
        created_at=created_at,
        created_header=created_header,
        rows=tuple(rows),
    )


def load_lldp_report(
    path: Union[str, Path],
    *,
    legacy_timezone: Optional[tzinfo] = None,
    require_rows: bool = True,
) -> LLDPReport:
    """Read and parse an aggregate report from ``path``."""

    report_path = Path(path)
    return parse_lldp_report(
        report_path.read_text(encoding="utf-8"),
        legacy_timezone=legacy_timezone,
        require_rows=require_rows,
    )


__all__ = (
    "LLDPCounts",
    "LLDPReport",
    "LLDPReportError",
    "LLDPRow",
    "load_lldp_report",
    "parse_created_header",
    "parse_lldp_report",
)
