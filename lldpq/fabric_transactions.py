"""Recoverable Fabric file writes. Callers must hold fabric-api.lock exclusively.

The journal is durable before the first replacement. Until the commit marker is
durable, recovery restores every original file, including after process death.
Recovery must run before reading inventory, never after building new payloads.
"""
import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile

JOURNAL = ".lldpq-write-journal.json"


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _stage(path, content, mode, owner=None):
    fd, temporary = tempfile.mkstemp(prefix=".lldpq-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            if owner:
                try:
                    os.fchown(handle.fileno(), *owner)
                except PermissionError:
                    pass
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        return Path(temporary)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _replace(path, content, mode, owner=None):
    staged = _stage(path, content, mode, owner)
    try:
        os.replace(staged, path)
        _sync_dir(path.parent)
    finally:
        staged.unlink(missing_ok=True)


def _encode(content):
    return None if content is None else base64.b64encode(content).decode("ascii")


def _decode(content):
    return None if content is None else base64.b64decode(content, validate=True)


def recover(root):
    """Finish a committed transaction or roll back an interrupted one."""
    root = Path(root).resolve()
    journal = root / JOURNAL
    if not journal.exists():
        return
    data = json.loads(journal.read_text())
    if data.get("state") not in ("prepared", "committed"):
        raise RuntimeError("Invalid Fabric transaction journal; recovery required")
    entries = data["entries"]
    if data["state"] == "prepared":
        # Check every destination first; never silently overwrite a change by
        # an external writer that does not participate in the Fabric lock.
        for entry in entries:
            path = root / entry["path"]
            if not path.resolve().is_relative_to(root):
                raise RuntimeError("Transaction destination is outside inventory")
            current = path.read_bytes() if path.exists() else None
            if current not in (_decode(entry["old"]), _decode(entry["new"])):
                raise RuntimeError(f"External change at {path}; recovery required")
        for entry in entries:
            path = root / entry["path"]
            original = _decode(entry["old"])
            if original is None:
                path.unlink(missing_ok=True)
                _sync_dir(path.parent)
            elif not path.exists() or path.read_bytes() != original:
                _replace(path, original, entry["mode"], entry.get("owner"))
    # Staged siblings may survive a killed worker. Only remove paths recorded
    # by this journal, after data recovery has succeeded.
    for entry in entries:
        staged = root / entry["staged"]
        if staged.resolve().is_relative_to(root):
            staged.unlink(missing_ok=True)
    journal.unlink()
    _sync_dir(root)


def atomic_write_many(yaml, writes, root):
    serialized = []
    for data, destination in writes:
        stream = io.StringIO()
        yaml.dump(data, stream)
        serialized.append((stream.getvalue().encode("utf-8"), destination))
    atomic_write_bytes(serialized, root)


def atomic_write_bytes(writes, root):
    root = Path(root).resolve()
    journal = root / JOURNAL
    if journal.exists():
        raise RuntimeError("Pending Fabric transaction: recover before reading inventory")
    entries, staged_files = [], []
    try:
        seen = set()
        for content, destination in writes:
            path = Path(destination).resolve()
            if not path.is_relative_to(root) or path in seen:
                raise ValueError(f"Invalid or duplicate transaction destination: {path}")
            seen.add(path)
            stat = path.stat() if path.exists() else None
            mode = stat.st_mode & 0o777 if stat else 0o644
            owner = [stat.st_uid, stat.st_gid] if stat else None
            staged = _stage(path, content, mode | 0o644, owner)
            staged_files.append(staged)
            entries.append({"path": str(path.relative_to(root)),
                            "staged": str(staged.relative_to(root)),
                            "mode": mode, "owner": owner,
                            "old": _encode(path.read_bytes() if stat else None),
                            "new": _encode(content)})
        if not entries:
            return
        transaction = {"state": "prepared", "entries": entries}
        _replace(journal, json.dumps(transaction).encode(), 0o660)
        for entry, staged in zip(entries, staged_files):
            destination = root / entry["path"]
            os.replace(staged, destination)
            _sync_dir(destination.parent)
        transaction["state"] = "committed"
        _replace(journal, json.dumps(transaction).encode(), 0o660)
    except BaseException:
        if journal.exists():
            recover(root)  # Fail closed and retain journal if rollback fails.
        raise
    else:
        recover(root)
    finally:
        for staged in staged_files:
            staged.unlink(missing_ok=True)


if __name__ == "__main__":
    recover(sys.argv[1])
