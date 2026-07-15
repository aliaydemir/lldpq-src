#!/usr/bin/env python3
"""Producer/validator sha256 handshake for large analyzer JSON artifacts.

Analyzers emit their JSON state through json.dump/json.dumps (or an encoder
walking the same containers), so a successfully written file is valid JSON by
construction.  Post-run validation therefore only needs to prove the bytes on
disk are exactly the bytes the producer wrote — a torn, truncated or corrupted
file — which a sha256 comparison establishes at sequential-read speed instead
of a full JSON parse (the parse of a multi-hundred-MB history dominated the
validation phase wall time).

A missing or mismatching sidecar is never an error by itself: the validator
falls back to the complete JSON parse, so older files, rolled-back state and
files from producers that do not emit sidecars keep the original guarantee.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from typing import Optional, Union

SIDECAR_SUFFIX = ".sha256"

_READ_CHUNK = 1 << 20


def sidecar_path(path: Union[str, Path]) -> Path:
    path = Path(path)
    return path.with_name(path.name + SIDECAR_SUFFIX)


def file_sha256(path: Union[str, Path]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sidecar(path: Union[str, Path]) -> None:
    """Hash ``path`` and atomically publish its ``.sha256`` sidecar."""
    try:
        publish_digest(path, file_sha256(path))
    except OSError:
        pass


def publish_digest(path: Union[str, Path], digest: str) -> None:
    """Atomically publish a producer-computed sha256 sidecar for ``path``.

    Best-effort by design: the sidecar is an optimization handshake, so a
    failure to write it must never fail the analyzer that already produced a
    good artifact.  Callers therefore do not need to guard this call.
    """
    path = Path(path)
    destination = sidecar_path(path)
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=str(path.parent)
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                # sha256sum-compatible line for manual verification.
                handle.write(f"{digest}  {path.name}\n")
                handle.flush()
                os.fsync(handle.fileno())
            # Web-served result trees require group/other read access
            # (mkstemp creates 0600).
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
    except OSError:
        try:
            destination.unlink()
        except OSError:
            pass


def read_sidecar_digest(path: Union[str, Path]) -> Optional[str]:
    try:
        first_line = sidecar_path(path).read_text(encoding="utf-8").splitlines()[0]
    except (OSError, UnicodeError, IndexError):
        return None
    digest = first_line.split()[0] if first_line.split() else ""
    if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
        return digest
    return None


def sidecar_matches(path: Union[str, Path]) -> bool:
    """True only when a well-formed sidecar matches the file's current bytes."""
    expected = read_sidecar_digest(path)
    if expected is None:
        return False
    try:
        return file_sha256(path) == expected
    except OSError:
        return False
