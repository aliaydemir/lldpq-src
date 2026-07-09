#!/usr/bin/env python3
"""Validate and split one LLDPq remote collection bundle in one pass.

The collector writes a fixed, ordered set of marker-delimited sections.  This
module keeps the validation contract that used to be implemented by one full
Python scan followed by one ``awk`` scan per section, while staging every
requested output during the validation scan.  Destination files are replaced
only after the complete input has passed validation.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import BinaryIO, Dict, Mapping, Optional, Sequence, Tuple, Union


SECTIONS: Tuple[str, ...] = (
    "HTML_OUTPUT",
    "BGP_DATA",
    "EVPN_DATA",
    "DUP_DATA",
    "FDB_DATA",
    "NEIGH_DATA",
    "CARRIER_DATA",
    "OPTICAL_DATA",
    "BER_DATA",
    "L1_DATA",
    "PFC_ECN_DATA",
    "HARDWARE_DATA",
    "LOG_DATA",
)

COLLECTION_ERROR_PREFIX = b"__LLDPQ_COLLECTION_ERROR__:"

# Individual monitoring commands are category data.  A command failure must
# remain visible to its owning analyzer, but it must not invalidate unrelated
# complete sections collected through the same SSH session.  Keep this
# allowlist strict: unknown markers and known markers in the wrong section
# retain the fail-closed whole-bundle behavior.
ISOLATED_SECTION_ERROR_PATTERNS = {
    "BGP_DATA": (
        re.compile(rb"^BGP_SUMMARY$"),
    ),
    "EVPN_DATA": (
        re.compile(rb"^EVPN_(?:VNI|TEMPFILE|ROUTES)$"),
    ),
    "FDB_DATA": (
        re.compile(rb"^FDB$"),
    ),
    "NEIGH_DATA": (
        re.compile(rb"^NEIGH$"),
    ),
    "CARRIER_DATA": (
        re.compile(rb"^LINK_INVENTORY$"),
    ),
    "OPTICAL_DATA": (
        re.compile(rb"^OPTICAL_LINK_INVENTORY$"),
        re.compile(
            rb"^OPTICAL_(?:BUDGET|TIMEOUT|TOOL_UNAVAILABLE):"
            rb"[A-Za-z0-9_.:-]+$"
        ),
    ),
    "BER_DATA": (
        re.compile(rb"^INTERFACE_COUNTERS$"),
    ),
}


class CollectionBundleError(Exception):
    """Raised when a bundle cannot be safely split."""


def _is_isolated_section_error(section: Optional[str], marker: bytes) -> bool:
    """Return whether *marker* is an allowlisted category-local failure."""
    if section is None or not marker.startswith(COLLECTION_ERROR_PREFIX):
        return False
    payload = marker[len(COLLECTION_ERROR_PREFIX):]
    return any(
        pattern.fullmatch(payload)
        for pattern in ISOLATED_SECTION_ERROR_PATTERNS.get(section, ())
    )


def _markers(section: str) -> Tuple[bytes, bytes]:
    return (
        f"==={section}_START===".encode("ascii"),
        f"==={section}_END===".encode("ascii"),
    )


PathValue = Union[os.PathLike[str], str]


def _validate_outputs(outputs: Mapping[str, PathValue]) -> Dict[str, Path]:
    missing = [section for section in SECTIONS if section not in outputs]
    extra = [section for section in outputs if section not in SECTIONS]
    if missing or extra or len(outputs) != len(SECTIONS):
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("unknown=" + ",".join(extra))
        raise CollectionBundleError(
            "output sections must match the collection layout"
            + (": " + " ".join(details) if details else "")
        )

    normalized = {section: Path(outputs[section]) for section in SECTIONS}
    absolute = [os.path.abspath(os.fspath(path)) for path in normalized.values()]
    if len(set(absolute)) != len(absolute):
        raise CollectionBundleError("collection output destinations must be unique")
    return normalized


def _temporary_outputs(
    destinations: Mapping[str, Path],
) -> Tuple[Dict[str, Path], Dict[str, BinaryIO]]:
    temporary_paths: Dict[str, Path] = {}
    handles: Dict[str, BinaryIO] = {}
    try:
        for section in SECTIONS:
            destination = destinations[section]
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=os.fspath(destination.parent),
            )
            # Shell redirection creates these collection artifacts as normal
            # data files.  Keep that mode instead of mkstemp's private 0600.
            os.fchmod(descriptor, 0o644)
            temporary_paths[section] = Path(name)
            handles[section] = os.fdopen(descriptor, "wb")
    except BaseException:
        for handle in handles.values():
            try:
                handle.close()
            except OSError:
                pass
        for path in temporary_paths.values():
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return temporary_paths, handles


def _cleanup(
    temporary_paths: Mapping[str, Path], handles: Mapping[str, BinaryIO]
) -> None:
    for handle in handles.values():
        if not handle.closed:
            try:
                handle.close()
            except OSError:
                pass
    for path in temporary_paths.values():
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def split_collection_bundle(
    raw_file: PathValue,
    outputs: Mapping[str, PathValue],
) -> None:
    """Validate *raw_file* and atomically replace all section *outputs*.

    Marker lines are not copied.  Body records are emitted with a trailing LF,
    matching the previous ``awk ... { print }`` extraction.  Bytes other than
    the record-separating LF are preserved, including CR and non-UTF-8 bytes.
    No destination is changed when validation or staging fails.
    """

    raw_path = Path(raw_file)
    destinations = _validate_outputs(outputs)
    raw_absolute = os.path.abspath(os.fspath(raw_path))
    if raw_absolute in {
        os.path.abspath(os.fspath(path)) for path in destinations.values()
    }:
        raise CollectionBundleError("collection input cannot also be an output")

    try:
        raw_handle = raw_path.open("rb")
    except OSError as exc:
        raise CollectionBundleError(f"cannot read collection bundle: {exc}") from exc

    try:
        temporary_paths, handles = _temporary_outputs(destinations)
    except OSError as exc:
        raw_handle.close()
        raise CollectionBundleError(f"cannot stage collection sections: {exc}") from exc

    start_markers: Dict[bytes, str] = {}
    end_markers: Dict[bytes, str] = {}
    starts = {section: [] for section in SECTIONS}
    ends = {section: [] for section in SECTIONS}
    for section in SECTIONS:
        start_marker, end_marker = _markers(section)
        start_markers[start_marker] = section
        end_markers[end_marker] = section

    command_errors = []
    active_section = None
    try:
        # Iterating a binary file is bounded-memory and, unlike splitlines(),
        # preserves a CR before LF exactly as the old awk extractor did.
        for line_number, record in enumerate(raw_handle):
            line = record[:-1] if record.endswith(b"\n") else record
            if (line.startswith(COLLECTION_ERROR_PREFIX)
                    and not _is_isolated_section_error(active_section, line)):
                command_errors.append(line)

            start_section = start_markers.get(line)
            if start_section is not None:
                starts[start_section].append(line_number)
                active_section = start_section
                continue

            end_section = end_markers.get(line)
            if end_section is not None:
                ends[end_section].append(line_number)
                if active_section == end_section:
                    active_section = None
                continue

            if active_section is not None:
                handles[active_section].write(line)
                handles[active_section].write(b"\n")

        if command_errors:
            rendered = ", ".join(
                value.decode("utf-8", errors="replace") for value in command_errors
            )
            raise CollectionBundleError(
                "remote collection command failures: " + rendered
            )

        previous_end = -1
        for section in SECTIONS:
            section_starts = starts[section]
            section_ends = ends[section]
            if len(section_starts) != 1 or len(section_ends) != 1:
                raise CollectionBundleError(
                    f"invalid {section} marker count: "
                    f"start={len(section_starts)} end={len(section_ends)}"
                )
            if not previous_end < section_starts[0] < section_ends[0]:
                raise CollectionBundleError(
                    f"out-of-order collection section: {section}"
                )
            previous_end = section_ends[0]

        for section in SECTIONS:
            handles[section].close()
        raw_handle.close()

        # Every destination gets a same-directory rename, so readers see
        # either its complete old content or its complete new content.
        for section in SECTIONS:
            os.replace(temporary_paths[section], destinations[section])
    except BaseException:
        raw_handle.close()
        _cleanup(temporary_paths, handles)
        raise


def _parse_output(value: Sequence[str]) -> Tuple[str, Path]:
    section, destination = value
    return section, Path(destination)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and split an LLDPq collection bundle"
    )
    parser.add_argument("raw_file", type=Path)
    parser.add_argument(
        "--output",
        action="append",
        nargs=2,
        metavar=("SECTION", "PATH"),
        required=True,
        help="section name and destination path; specify all 13 sections",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    outputs: Dict[str, Path] = {}
    for raw_output in args.output:
        section, destination = _parse_output(raw_output)
        if section in outputs:
            parser.error(f"duplicate --output section: {section}")
        outputs[section] = destination

    try:
        split_collection_bundle(args.raw_file, outputs)
    except CollectionBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"cannot split collection bundle: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
