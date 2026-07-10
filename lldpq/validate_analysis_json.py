#!/usr/bin/env python3
"""Validate analyzer JSON artifacts concurrently without changing them."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
import json
import os
from pathlib import Path
import sys
import time
from typing import List, Optional, Sequence, Tuple


ValidationResult = Tuple[str, int, Optional[str]]


def _validate_one(root: Path, relative: str) -> ValidationResult:
    started = time.perf_counter()
    error: Optional[str] = None
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        error = "unsafe relative path"
    else:
        try:
            with (root / path).open("r", encoding="utf-8") as handle:
                json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
            error = str(exc)
    elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))
    return relative, elapsed_ms, error


def validate_json_files(
    root: Path,
    relatives: Sequence[str],
    *,
    max_workers: int = 2,
) -> List[ValidationResult]:
    """Return validation results in the exact input order."""
    if not relatives:
        return []
    workers = max(1, min(int(max_workers), 2, len(relatives)))
    if workers == 1:
        return [_validate_one(root, relative) for relative in relatives]
    try:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_validate_one, root, relative)
                for relative in relatives
            ]
            return [future.result() for future in futures]
    except (OSError, PermissionError, BrokenProcessPool):
        # Constrained containers can deny multiprocessing primitives. Fall
        # back to the same complete sequential parse, never to a skipped check.
        return [_validate_one(root, relative) for relative in relatives]


def _worker_limit() -> int:
    raw = os.environ.get("MONITOR_JSON_VALIDATE_MAX_PARALLEL", "2")
    try:
        value = int(raw)
    except ValueError:
        value = 4
    return max(1, min(value, 2))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("root", type=Path)
    parser.add_argument("relative", nargs="*")
    args = parser.parse_args(argv)
    results = validate_json_files(
        args.root.resolve(), args.relative, max_workers=_worker_limit()
    )
    if results:
        print("JSON validation timings (parallel):")
    failed = False
    for relative, elapsed_ms, error in results:
        print(f"  {relative:<34} {elapsed_ms // 1000}.{elapsed_ms % 1000:03d}s")
        if error is not None:
            print(
                f"Invalid analysis JSON {relative}: {error}",
                file=sys.stderr,
            )
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
