#!/usr/bin/env bash
# LLDPq Topology Check Script - OPTIMIZED VERSION
# Single SSH session per device + Parallel limits
#
# Copyright (c) 2024 LLDPq Project - Licensed under MIT License

set -o pipefail

# Share the pipeline lock with bin/lldpq and monitor.sh.  The wrapper exports
# the inherited marker while keeping descriptor 9 open; a direct invocation
# takes the same non-blocking lock instead of racing report publication.
lock_is_inherited=false
if [[ "${LLDPQ_MONITOR_LOCK_HELD:-0}" == "1" ]] && { : >&9; } 2>/dev/null; then
    lock_is_inherited=true
fi
if [[ "$lock_is_inherited" != "true" ]]; then
    LOCK_FILE="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    if ! command -v flock >/dev/null 2>&1; then
        echo "Error: flock is required for safe LLDP collection" >&2
        exit 1
    fi
    exec 9>"$LOCK_FILE" || exit 1
    if ! flock -n 9; then
        echo "Monitoring is already running; this LLDP invocation was skipped." >&2
        exit 75
    fi
    export LLDPQ_MONITOR_LOCK_HELD=1
fi

# Start timing
START_TIME=$(date +%s)
echo "Starting LLDP check at $(date)"

DATE=$(date '+%Y-%m-%d--%H-%M')

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"

# === TUNING PARAMETERS ===
MAX_PARALLEL="${LLDP_MAX_PARALLEL:-100}"  # Maximum parallel SSH connections
case "$MAX_PARALLEL" in
    ''|*[!0-9]*|0) MAX_PARALLEL=100 ;;
esac
SSH_TIMEOUT=30    # SSH connection timeout in seconds

recover_lldp_outputs() {
    local recovery_marker="$SCRIPT_DIR/lldp-results/.lldpq-lldp-recovery"
    sudo python3 - "$recovery_marker" "$SCRIPT_DIR" <<'PYTHON'
import hashlib
import json
import os
import re
import stat
import sys

marker = os.path.abspath(sys.argv[1])
script_dir = os.path.abspath(sys.argv[2])
marker_parent = os.path.dirname(marker)
marker_name = os.path.basename(marker)
marker_parent_fd = None
trusted_marker_fd = None
trusted_marker_stat = None
trusted_marker_bytes = None

def lexists(path):
    # exists() follows links and would misclassify a dangling backup symlink as
    # absent. Recovery must instead stop on every ambiguous filesystem object.
    return os.path.lexists(path)

def regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode) and not os.path.islink(path)
    except FileNotFoundError:
        return False

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def fsync_file(path):
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def fail(message):
    raise RuntimeError(message)

def trusted_read_authority():
    """Open, authorize and read one immutable marker descriptor."""
    global marker_parent_fd, trusted_marker_fd
    global trusted_marker_stat, trusted_marker_bytes
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    marker_parent_fd = os.open(marker_parent, directory_flags)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    trusted_marker_fd = os.open(marker_name, flags, dir_fd=marker_parent_fd)
    trusted_marker_stat = os.fstat(trusted_marker_fd)
    current = os.stat(marker_name, dir_fd=marker_parent_fd, follow_symlinks=False)
    if ((current.st_dev, current.st_ino) !=
            (trusted_marker_stat.st_dev, trusted_marker_stat.st_ino)):
        fail("LLDP recovery marker changed while it was opened")
    if not stat.S_ISREG(trusted_marker_stat.st_mode):
        fail("LLDP recovery marker is not a regular file")
    if trusted_marker_stat.st_uid != os.geteuid():
        fail("LLDP recovery marker owner is not authoritative")
    if trusted_marker_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        fail("LLDP recovery marker is writable by an untrusted principal")
    if trusted_marker_stat.st_size <= 0 or trusted_marker_stat.st_size > 2 * 1024 * 1024:
        fail("LLDP recovery marker size is invalid")
    with os.fdopen(os.dup(trusted_marker_fd), "rb") as handle:
        trusted_marker_bytes = handle.read(2 * 1024 * 1024 + 1)
    if len(trusted_marker_bytes) != trusted_marker_stat.st_size:
        fail("LLDP recovery marker changed while it was read")
    return json.loads(trusted_marker_bytes.decode("utf-8"))

def clear_trusted_authority():
    """Unlink only the inode read above and prove the unlink is durable."""
    current = os.stat(marker_name, dir_fd=marker_parent_fd, follow_symlinks=False)
    if ((current.st_dev, current.st_ino) !=
            (trusted_marker_stat.st_dev, trusted_marker_stat.st_ino)):
        fail("LLDP recovery marker was swapped before authority removal")
    os.unlink(marker_name, dir_fd=marker_parent_fd)
    try:
        os.fsync(marker_parent_fd)
    except OSError as sync_error:
        # Keep a live authority when unlink durability is unknown. The next
        # invocation can verify the already-restored generation and retry.
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(marker_name, flags, 0o600, dir_fd=marker_parent_fd)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(trusted_marker_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException as restore_error:
            raise RuntimeError(
                f"LLDP marker unlink was not durable and authority recreation failed: "
                f"{sync_error}; {restore_error}"
            ) from sync_error
        raise RuntimeError(
            f"LLDP marker unlink was not durable; authority was retained: {sync_error}"
        ) from sync_error

try:
    expected_marker = os.path.join(
        script_dir, "lldp-results", ".lldpq-lldp-recovery"
    )
    if marker != expected_marker:
        fail("LLDP recovery marker is outside the installation result tree")
    # Production publication runs under sudo. The descriptor remains open
    # until removal so path swaps cannot change which authority was trusted.
    payload = trusted_read_authority()
    if set(payload) != {"version", "status", "web_root", "records"}:
        fail("LLDP recovery marker has an unexpected schema")
    if payload["version"] != 2 or payload["status"] != "rollback-required":
        fail("LLDP recovery marker has an unsupported state")
    web_root = payload["web_root"]
    if (not isinstance(web_root, str) or not os.path.isabs(web_root)
            or web_root != os.path.normpath(web_root) or web_root == os.sep
            or "\x00" in web_root):
        fail("LLDP recovery marker has an unsafe recorded web root")
    local_root = os.path.join(script_dir, "lldp-results")
    expected_destinations = [
        os.path.join(local_root, "lldp_results.ini"),
        os.path.join(local_root, "raw-problems-lldp_results.ini"),
        os.path.join(local_root, "problems-lldp_results.ini"),
        os.path.join(local_root, "down-lldp_results.ini"),
        os.path.join(web_root, "lldp_results.ini"),
        os.path.join(web_root, "problems-lldp_results.ini"),
        os.path.join(web_root, "topology", "topology.js"),
    ]
    records = payload["records"]
    if not isinstance(records, list) or len(records) != len(expected_destinations):
        fail("LLDP recovery journal is incomplete")

    required = {
        "index", "stage", "destination", "backup", "original",
        "original_sha256", "stage_sha256",
    }
    checksum = re.compile(r"[0-9a-f]{64}")
    prepared = []
    for index, (record, expected_destination) in enumerate(
            zip(records, expected_destinations)
    ):
        if not isinstance(record, dict) or set(record) != required:
            fail(f"invalid LLDP recovery record {index}")
        if record["index"] != index or record["destination"] != expected_destination:
            fail(f"LLDP recovery destination mismatch in record {index}")
        destination_parent = os.path.dirname(expected_destination)
        destination_name = os.path.basename(expected_destination)
        if (not os.path.isdir(destination_parent)
                or os.path.islink(destination_parent)):
            fail(f"unsafe LLDP destination directory in record {index}")
        stage = record["stage"]
        backup = record["backup"]
        if (not isinstance(stage, str) or not os.path.isabs(stage)
                or os.path.dirname(stage) != destination_parent
                or not os.path.basename(stage).startswith(
                    f".{destination_name}.lldpq-new."
                )):
            fail(f"unsafe LLDP stage path in record {index}")
        staged_hash = record["stage_sha256"]
        if not isinstance(staged_hash, str) or not checksum.fullmatch(staged_hash):
            fail(f"invalid LLDP staged checksum in record {index}")

        original = record["original"]
        original_hash = record["original_sha256"]
        if original == "present":
            if (not isinstance(original_hash, str)
                    or not checksum.fullmatch(original_hash)
                    or not isinstance(backup, str) or not os.path.isabs(backup)
                    or os.path.dirname(backup) != destination_parent
                    or not os.path.basename(backup).startswith(
                        f".{destination_name}.lldpq-old."
                    )):
                fail(f"invalid LLDP original journal in record {index}")
        elif original == "missing":
            if original_hash is not None or backup is not None:
                fail(f"invalid missing-state journal in record {index}")
        else:
            fail(f"invalid LLDP presence journal in record {index}")

        backup_exists = backup is not None and lexists(backup)
        destination_exists = lexists(expected_destination)
        stage_exists = lexists(stage)

        # This is a complete preflight: no rollback path changes until every
        # record, backup, destination and leftover stage is provably ours.
        if backup_exists:
            if (not regular(backup) or digest(backup) != original_hash
                    or (destination_exists and not regular(expected_destination))):
                fail(f"invalid LLDP backup in record {index}")
        elif original == "present":
            if (not destination_exists or not regular(expected_destination)
                    or digest(expected_destination) != original_hash):
                fail(f"LLDP original cannot be proven in record {index}")
        elif destination_exists:
            if (not regular(expected_destination)
                    or digest(expected_destination) != staged_hash):
                fail(f"unexpected originally-missing LLDP destination {index}")
        if stage_exists and (not regular(stage) or digest(stage) != staged_hash):
            fail(f"invalid LLDP stage in record {index}")

        prepared.append({
            "original": original,
            "destination": expected_destination,
            "backup": backup,
            "backup_exists": backup_exists,
            "stage": stage,
            "stage_exists": stage_exists,
        })

    # os.replace/unlink make each step repeatable. If this process is killed,
    # the untouched marker drives the same validation and remaining operations.
    for record in reversed(prepared):
        if record["original"] == "present" and record["backup_exists"]:
            os.replace(record["backup"], record["destination"])
        elif record["original"] == "missing" and lexists(record["destination"]):
            os.unlink(record["destination"])
    for record in prepared:
        if record["stage_exists"] and lexists(record["stage"]):
            os.unlink(record["stage"])

    directories = {os.path.dirname(value) for value in expected_destinations}
    for record in prepared:
        destination = record["destination"]
        if record["original"] == "present":
            if not regular(destination):
                fail(f"restored LLDP destination disappeared: {destination}")
            fsync_file(destination)
        elif lexists(destination):
            fail(f"originally-missing LLDP destination remains: {destination}")
    for directory in directories:
        fsync_directory(directory)
    fsync_directory(os.path.dirname(marker))

    clear_trusted_authority()
except BaseException as exc:
    print(f"CRITICAL: LLDP publication recovery failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PYTHON
}

mkdir -p "$SCRIPT_DIR/lldp-results" || exit 1
if [[ -e "$SCRIPT_DIR/lldp-results/.lldpq-lldp-recovery" ||
      -L "$SCRIPT_DIR/lldp-results/.lldpq-lldp-recovery" ]]; then
    echo "Recovering interrupted LLDP publication..." >&2
    if ! recover_lldp_outputs; then
        echo "CRITICAL: unresolved LLDP publication recovery remains at" >&2
        echo "  $SCRIPT_DIR/lldp-results/.lldpq-lldp-recovery" >&2
        exit 1
    fi
fi
if [[ "${LLDPQ_RECOVERY_ONLY:-0}" == "1" ]]; then
    exit 0
fi

# Parse the current runtime configuration only after a retained journal has
# restored the destinations it recorded. A changed/malformed WEB_ROOT must not
# strand or redirect an older transaction.
LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
if [[ -z "${WEB_ROOT:-}" ]]; then
    if [[ ! -x "$LLDPQ_CONFIG_HELPER" ]]; then
        echo "Error: runtime config helper is missing: $LLDPQ_CONFIG_HELPER" >&2
        exit 1
    fi
    if ! LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config \
            --require-key WEB_ROOT --require-key LLDPQ_USER 2>/dev/null); then
        echo "Error: required runtime configuration is missing or invalid" >&2
        exit 1
    fi
    eval "$LLDPQ_CONFIG_ASSIGNMENTS" || exit 1
    unset LLDPQ_CONFIG_ASSIGNMENTS
fi
[[ -n "${WEB_ROOT:-}" ]] || { echo "Error: WEB_ROOT is not configured" >&2; exit 1; }
LLDPQ_USER="${LLDPQ_USER:-$(whoami)}"
load_devices "$SCRIPT_DIR/parse_devices.py" || exit 1

unreachable_hosts_file=$(mktemp)
active_jobs_file=$(mktemp)
completed_count_file=$(mktemp)
echo "0" > "$completed_count_file"
postprocess_dir=""
collection_dir=""
declare -a collection_pids=()

cleanup_check_lldp() {
    local pid
    # If the parent is interrupted, stop and reap every collector before its
    # private generation directory is removed. Otherwise an orphaned SSH job
    # can wake up later and write into a path that cleanup already deleted.
    for pid in "${collection_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${collection_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    collection_pids=()
    rm -f "$unreachable_hosts_file" "$active_jobs_file" \
        "$completed_count_file" "$completed_count_file.lock"
    [[ -n "$postprocess_dir" ]] && rm -rf "$postprocess_dir"
    [[ -n "$collection_dir" ]] && rm -rf "$collection_dir"
}
trap cleanup_check_lldp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

publish_web_file() {
    local source_file="$1" destination_file="$2" temp_file
    temp_file=$(sudo mktemp "$(dirname "$destination_file")/.lldpq-publish.XXXXXXXXXX") || return 1
    if ! sudo cp "$source_file" "$temp_file" ||
       ! sudo chown "${LLDPQ_USER:-$(whoami)}:www-data" "$temp_file" ||
       ! sudo chmod 664 "$temp_file" ||
       ! sudo mv -fT "$temp_file" "$destination_file"; then
        sudo rm -f "$temp_file" 2>/dev/null || true
        return 1
    fi
}

commit_lldp_outputs() {
    local recovery_marker="$SCRIPT_DIR/lldp-results/.lldpq-lldp-recovery"
    sudo python3 - "$LLDPQ_USER" "$recovery_marker" "$WEB_ROOT" \
        "$collection_dir/lldp_results.ini" "$SCRIPT_DIR/lldp-results/lldp_results.ini" \
        "$raw_problems" "$SCRIPT_DIR/lldp-results/raw-problems-lldp_results.ini" \
        "$problems" "$SCRIPT_DIR/lldp-results/problems-lldp_results.ini" \
        "$down" "$SCRIPT_DIR/lldp-results/down-lldp_results.ini" \
        "$collection_dir/lldp_results.ini" "$WEB_ROOT/lldp_results.ini" \
        "$problems" "$WEB_ROOT/problems-lldp_results.ini" \
        "$collection_dir/topology.js" "$WEB_ROOT/topology/topology.js" <<'PYTHON'
import grp
import hashlib
import json
import os
import pwd
import shutil
import signal
import stat
import sys
import tempfile

user = sys.argv[1]
recovery_marker = os.path.abspath(sys.argv[2])
recorded_web_root = os.path.abspath(sys.argv[3])
items = [
    (os.path.abspath(source), os.path.abspath(destination))
    for source, destination in zip(sys.argv[4::2], sys.argv[5::2])
]
if not items or len(sys.argv[4:]) % 2:
    raise SystemExit("invalid LLDP publication list")
local_root = os.path.dirname(recovery_marker)
expected_destinations = [
    os.path.join(local_root, "lldp_results.ini"),
    os.path.join(local_root, "raw-problems-lldp_results.ini"),
    os.path.join(local_root, "problems-lldp_results.ini"),
    os.path.join(local_root, "down-lldp_results.ini"),
    os.path.join(recorded_web_root, "lldp_results.ini"),
    os.path.join(recorded_web_root, "problems-lldp_results.ini"),
    os.path.join(recorded_web_root, "topology", "topology.js"),
]
if ([destination for _source, destination in items] != expected_destinations
        or recorded_web_root == os.sep):
    raise SystemExit("unsafe LLDP publication destination set")

user_entry = pwd.getpwnam(user)
uid = user_entry.pw_uid
try:
    gid = grp.getgrnam("www-data").gr_gid
except KeyError:
    # Isolated non-Linux test hosts need not provide the web-service group.
    gid = user_entry.pw_gid
records = []
authority_owned = False

class AuthorityClearError(RuntimeError):
    """Authority could not be removed with proven directory durability."""

def lexists(path):
    return os.path.lexists(path)

def regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode) and not os.path.islink(path)
    except FileNotFoundError:
        return False

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def fsync_file(path):
    with open(path, "rb") as handle:
        os.fsync(handle.fileno())

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def cleanup_path(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

def write_recovery_authority():
    global authority_owned
    marker_parent = os.path.dirname(recovery_marker)
    os.makedirs(marker_parent, exist_ok=True)
    if lexists(recovery_marker):
        raise RuntimeError("existing LLDP recovery authority must not be overwritten")
    descriptor, temporary = tempfile.mkstemp(
        prefix=".lldpq-lldp-recovery.", dir=marker_parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({
                "version": 2,
                "status": "rollback-required",
                "web_root": recorded_web_root,
                "records": records,
            }, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # link(2) creates the authority only when the destination does not
        # already exist. Unlike replace(), this is an atomic no-overwrite
        # transition even if another actor races the earlier lexists check.
        os.link(temporary, recovery_marker, follow_symlinks=False)
        authority_owned = True
        fsync_directory(marker_parent)
        os.unlink(temporary)
        fsync_directory(marker_parent)
    except BaseException:
        cleanup_path(temporary)
        raise

def clear_recovery_authority():
    global authority_owned
    marker_parent = os.path.dirname(recovery_marker)
    marker_name = os.path.basename(recovery_marker)
    directory_fd = None
    marker_fd = None
    try:
        directory_fd = os.open(
            marker_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        marker_fd = os.open(
            marker_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        trusted_stat = os.fstat(marker_fd)
        current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((trusted_stat.st_dev, trusted_stat.st_ino) !=
                (current.st_dev, current.st_ino)
                or not stat.S_ISREG(trusted_stat.st_mode)
                or trusted_stat.st_uid != os.geteuid()
                or trusted_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise AuthorityClearError("LLDP authority changed before commit")
        with os.fdopen(os.dup(marker_fd), "rb") as handle:
            marker_bytes = handle.read(2 * 1024 * 1024 + 1)
        if len(marker_bytes) != trusted_stat.st_size:
            raise AuthorityClearError("LLDP authority changed while being read")
        marker_payload = json.loads(marker_bytes.decode("utf-8"))
        if marker_payload != {
            "version": 2,
            "status": "rollback-required",
            "web_root": recorded_web_root,
            "records": records,
        }:
            raise AuthorityClearError("LLDP authority content no longer matches the transaction")
        current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((trusted_stat.st_dev, trusted_stat.st_ino) !=
                (current.st_dev, current.st_ino)):
            raise AuthorityClearError("LLDP authority was swapped before unlink")
        os.unlink(marker_name, dir_fd=directory_fd)
        try:
            os.fsync(directory_fd)
        except OSError as sync_error:
            # Recreate a live, fsynced marker and leave every backup untouched.
            # The next locked invocation will perform the idempotent rollback.
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                descriptor = os.open(marker_name, flags, 0o600, dir_fd=directory_fd)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(marker_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException as restore_error:
                raise AuthorityClearError(
                    f"LLDP authority unlink was not durable and recreation failed: "
                    f"{sync_error}; {restore_error}"
                ) from sync_error
            raise AuthorityClearError(
                f"LLDP authority unlink was not durable; recovery payload retained: {sync_error}"
            ) from sync_error
        authority_owned = False
    except AuthorityClearError:
        raise
    except BaseException as exc:
        raise AuthorityClearError(f"LLDP authority could not be cleared: {exc}") from exc
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        if directory_fd is not None:
            os.close(directory_fd)

def rollback_records():
    prepared = []
    # Validate all remaining transaction objects before modifying any path.
    for record in records:
        original = record["original"]
        destination = record["destination"]
        backup = record["backup"]
        stage = record["stage"]
        backup_exists = backup is not None and lexists(backup)
        destination_exists = lexists(destination)
        stage_exists = lexists(stage)
        if backup_exists:
            if (original != "present" or not regular(backup)
                    or digest(backup) != record["original_sha256"]
                    or (destination_exists and not regular(destination))):
                raise RuntimeError(f"invalid LLDP rollback backup: {backup}")
        elif original == "present":
            if (not destination_exists or not regular(destination)
                    or digest(destination) != record["original_sha256"]):
                raise RuntimeError(f"LLDP original cannot be proven: {destination}")
        elif destination_exists:
            if not regular(destination) or digest(destination) != record["stage_sha256"]:
                raise RuntimeError(f"unexpected LLDP rollback destination: {destination}")
        if stage_exists and (
                not regular(stage) or digest(stage) != record["stage_sha256"]
        ):
            raise RuntimeError(f"invalid LLDP rollback stage: {stage}")
        prepared.append((record, backup_exists, stage_exists))

    for record, backup_exists, _stage_exists in reversed(prepared):
        if record["original"] == "present" and backup_exists:
            os.replace(record["backup"], record["destination"])
        elif record["original"] == "missing" and lexists(record["destination"]):
            os.unlink(record["destination"])
    for record, _backup_exists, stage_exists in prepared:
        if stage_exists and lexists(record["stage"]):
            os.unlink(record["stage"])

    for record, _backup_exists, _stage_exists in prepared:
        if record["original"] == "present":
            fsync_file(record["destination"])
        elif lexists(record["destination"]):
            raise RuntimeError(
                f"originally-missing LLDP destination remains: {record['destination']}"
            )
    for directory in {os.path.dirname(record["destination"]) for record in records}:
        fsync_directory(directory)
    fsync_directory(os.path.dirname(recovery_marker))
    clear_recovery_authority()

def verify_committed_generation():
    for record in records:
        destination = record["destination"]
        backup = record["backup"]
        if (lexists(record["stage"]) or not regular(destination)
                or digest(destination) != record["stage_sha256"]):
            raise RuntimeError(f"incomplete LLDP activation: {destination}")
        if record["original"] == "present":
            if (backup is None or not lexists(backup) or not regular(backup)
                    or digest(backup) != record["original_sha256"]):
                raise RuntimeError(f"invalid LLDP rollback copy: {backup}")
        elif backup is not None:
            raise RuntimeError("unexpected LLDP backup for a missing destination")
        fsync_file(destination)
    for directory in {os.path.dirname(record["destination"]) for record in records}:
        fsync_directory(directory)

def sync_backup_phase():
    """Make every original->backup copy durable before new-file activation."""
    directories = set()
    for record in records:
        destination = record["destination"]
        directories.add(os.path.dirname(destination))
        if record["original"] == "present":
            if not regular(destination):
                raise RuntimeError(
                    f"LLDP destination is no longer a regular file: {destination}"
                )
            backup = record["backup"]
            if (backup is None or not lexists(backup) or not regular(backup)
                    or digest(backup) != record["original_sha256"]):
                raise RuntimeError(f"LLDP backup phase is incomplete: {backup}")
            fsync_file(backup)
        elif lexists(destination):
            raise RuntimeError(
                f"unexpected LLDP destination before activation: {destination}"
            )
    for directory in directories:
        fsync_directory(directory)

for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(signum, signal.SIG_IGN)

if lexists(recovery_marker):
    raise SystemExit("unresolved LLDP recovery authority already exists")

try:
    # Prepare every replacement and backup copy beside its destination before
    # touching any LKG path. Activation then consists only of same-filesystem
    # atomic replaces of destinations that remain served the whole time.
    for index, (source, destination) in enumerate(items):
        if not regular(source) or os.stat(source).st_size == 0:
            raise RuntimeError(f"invalid staged LLDP output: {source}")
        destination_parent = os.path.dirname(destination)
        os.makedirs(destination_parent, exist_ok=True)
        if os.path.islink(destination_parent) or not os.path.isdir(destination_parent):
            raise RuntimeError(f"unsafe LLDP destination directory: {destination_parent}")
        if lexists(destination) and not regular(destination):
            raise RuntimeError(f"LLDP destination is not a regular file: {destination}")

        descriptor, stage = tempfile.mkstemp(
            prefix=f".{os.path.basename(destination)}.lldpq-new.",
            dir=destination_parent,
        )
        os.close(descriptor)
        shutil.copyfile(source, stage)
        os.chmod(stage, 0o664)
        os.chown(stage, uid, gid)
        fsync_file(stage)

        if lexists(destination):
            # The backup is a copy, so the served destination stays in place
            # until its atomic replacement: readers never observe an absence
            # window. The copy happens before the authority exists and never
            # touches a destination, so a partial copy is a stray temp file,
            # not a rollback obstacle.
            original = "present"
            original_hash = digest(destination)
            descriptor, backup = tempfile.mkstemp(
                prefix=f".{os.path.basename(destination)}.lldpq-old.",
                dir=destination_parent,
            )
            os.close(descriptor)
            shutil.copyfile(destination, backup)
        else:
            original = "missing"
            original_hash = None
            backup = None
        records.append({
            "index": index,
            "stage": stage,
            "destination": destination,
            "backup": backup,
            "original": original,
            "original_sha256": original_hash,
            "stage_sha256": digest(stage),
        })

    # The complete JSON authority is flushed before the first destination
    # replace, which makes a SIGKILL at every subsequent instruction
    # recoverable. Every destination is only ever atomically replaced by its
    # staged file, so published paths exist continuously throughout the commit.
    write_recovery_authority()

    sync_backup_phase()
    for record in records:
        os.replace(record["stage"], record["destination"])

    verify_committed_generation()
    clear_recovery_authority()
except BaseException as exc:
    rollback_error = None
    if isinstance(exc, AuthorityClearError):
        rollback_error = "authority durability is unresolved; recovery payload retained"
    elif authority_owned and lexists(recovery_marker):
        try:
            rollback_records()
        except BaseException as recovery_exc:
            rollback_error = recovery_exc
    elif not authority_owned:
        for record in records:
            for leftover in (record["stage"], record["backup"]):
                try:
                    if leftover is not None and lexists(leftover):
                        cleanup_path(leftover)
                except OSError:
                    pass
    if rollback_error is not None:
        print(
            f"CRITICAL: LLDP rollback is incomplete; recovery marker: "
            f"{recovery_marker}: {rollback_error}",
            file=sys.stderr,
        )
    print(f"LLDP publication failed: {exc}", file=sys.stderr)
    raise SystemExit(1)

# The new generation is fully active. Old copies are cleanup-only now.
for record in records:
    backup = record["backup"]
    if backup is not None and lexists(backup):
        try:
            if not regular(backup):
                raise OSError("backup is no longer a regular file")
            os.unlink(backup)
        except OSError as exc:
            print(f"Warning: obsolete LLDP backup remains at {backup}: {exc}", file=sys.stderr)
PYTHON
}

# Total device count for progress
TOTAL_DEVICES=${#devices[@]}

# SSH options with multiplexing
SSH_OPTS="-o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPath=~/.ssh/cm-%r@%h:%p -o ControlPersist=60 -o BatchMode=yes -o ConnectTimeout=$SSH_TIMEOUT"

# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds 'ip rule' for mgmt VRF so plain ping works. No ip vrf exec needed.
PING="ping"

ping_test() {
    local device=$1
    $PING -c 1 -W 0.5 "$device" > /dev/null 2>&1
}

# ============================================================================
# OPTIMIZED: Single SSH session collects ALL LLDP data
# ============================================================================
execute_commands_optimized() {
    local device=$1
    local user=$2
    local hostname=$3
    
    local output_file="$collection_dir/${hostname}_lldp_result.ini"
    local temporary_file="$collection_dir/.${hostname}.tmp.${BASHPID:-$$}"

    # Single SSH connection collects everything into this run's private tree.
    if timeout 180 ssh $SSH_OPTS -T -q "$user@$device" "
        echo '=========================================${hostname}========================================='
        echo ''
        
        # LLDP data
        sudo lldpctl 2>/dev/null || echo '__LLDPQ_LLDP_COLLECTION_ERROR__'
        
        # Port status
        echo ''
        echo '===PORT_STATUS_START==='
        # Report every relevant physical data interface.  Cumulus swp devices
        # are retained even when their sysfs driver does not expose a device
        # link; enp/enP/ens-style HGX and host NICs are included through it.
        # Known management and virtual interfaces cannot satisfy topology endpoints.
        for port in /sys/class/net/*; do
            [ -d \"\$port\" ] || continue
            port_name=\$(basename \"\$port\")
            case \"\$port_name\" in
                lo|eth0|mgmt*|docker*|veth*|virbr*|br-*|cni*|flannel*|\
                vxlan*|vni*|vrf*|dummy*|tun*|tap*) continue ;;
            esac
            if [ ! -e \"\$port/device\" ]; then
                case \"\$port_name\" in
                    swp*) ;;
                    *) continue ;;
                esac
            fi
            oper_state=\$(cat \"\$port/operstate\" 2>/dev/null || echo 'unknown')
            carrier=\$(cat \"\$port/carrier\" 2>/dev/null || echo '0')
            
            if [ \"\$oper_state\" = 'up' ] && [ \"\$carrier\" = '1' ]; then
                echo \"\$port_name UP\"
            elif [ \"\$oper_state\" = 'down' ] || [ \"\$carrier\" = '0' ]; then
                echo \"\$port_name DOWN\"
            else
                echo \"\$port_name UNKNOWN\"
            fi
        done | sort -V
        echo '===PORT_STATUS_END==='
        
        # Port speed. Use the same physical-interface selection as the status
        # section so host/HGX NICs do not become speed=N/A merely because their
        # kernel name is not swp*.
        echo ''
        echo '===PORT_SPEED_START==='
        for port in /sys/class/net/*; do
            [ -d \"\$port\" ] || continue
            port_name=\$(basename \"\$port\")
            case \"\$port_name\" in
                lo|eth0|mgmt*|docker*|veth*|virbr*|br-*|cni*|flannel*|\
                vxlan*|vni*|vrf*|dummy*|tun*|tap*) continue ;;
            esac
            if [ ! -e \"\$port/device\" ]; then
                case \"\$port_name\" in
                    swp*) ;;
                    *) continue ;;
                esac
            fi
            speed=\$(cat \"\$port/speed\" 2>/dev/null || echo '0')
            if [ \"\$speed\" -gt 0 ] 2>/dev/null; then
                echo \"\$port_name \$speed\"
            fi
        done | sort -V
        echo '===PORT_SPEED_END==='
        echo ''
    " > "$temporary_file" 2>/dev/null &&
       ! grep -q '__LLDPQ_LLDP_COLLECTION_ERROR__' "$temporary_file" &&
       grep -q '===PORT_STATUS_END===' "$temporary_file"; then
        mv "$temporary_file" "$output_file"
        return 0
    fi

    rm -f "$temporary_file"
    write_unavailable_lldp_input "$hostname" || return 1
    # The caller distinguishes an authoritative SSH/LLDP failure from a local
    # publication error. The former is valid current No-Info evidence.
    return 2
}

write_unavailable_lldp_input() {
    local hostname="$1"
    cat > "$collection_dir/${hostname}_lldp_result.ini" <<EOF
=========================================${hostname}=========================================

__LLDPQ_LLDP_UNAVAILABLE__
===PORT_STATUS_START===
===PORT_STATUS_END===
EOF
}

process_device() {
    local device=$1
    local user=$2
    local hostname=$3
    local ssh_status
    
    # ICMP is only a hint: many otherwise reachable devices intentionally drop
    # echo requests. Always try the authoritative SSH collection before
    # classifying this inventory member as unavailable.
    ping_test "$device" || true
    if execute_commands_optimized "$device" "$user" "$hostname"; then
        ssh_status=0
    else
        ssh_status=$?
    fi
    if [[ $ssh_status -eq 2 ]]; then
        echo "$device $hostname" >> "$unreachable_hosts_file"
    elif [[ $ssh_status -ne 0 ]]; then
        return 1
    fi
    
    # Update progress counter (thread-safe with flock)
    (
        flock -x 200
        count=$(cat "$completed_count_file")
        count=$((count + 1))
        echo "$count" > "$completed_count_file"
        printf "\rCollecting [%d/%d]" "$count" "$TOTAL_DEVICES"
    ) 200>"$completed_count_file.lock"
}

# ============================================================================
# PARALLEL EXECUTION WITH LIMITS
# ============================================================================
collection_dir=$(mktemp -d "$SCRIPT_DIR/lldp-results/.collection.XXXXXX") || exit 1
chmod 700 "$collection_dir" || exit 1
echo "Devices: $TOTAL_DEVICES"

job_count=0
for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    
    # Start job in background
    process_device "$device" "$user" "$hostname" 9>&- &
    collection_pids+=("$!")
    
    job_count=$((job_count + 1))
    
    # Limit parallel jobs
    if [ $job_count -ge $MAX_PARALLEL ]; then
        wait -n 2>/dev/null || wait
        job_count=$((job_count - 1))
    fi
done

# Wait for all remaining jobs
wait
collection_pids=()

echo ""
echo ""

# Background exit statuses are not sufficient on every supported Bash
# version. Verify one complete current input for every inventory member before
# the validator can replace the aggregate report.
collection_incomplete=0
for device in "${!devices[@]}"; do
    IFS=' ' read -r _user hostname <<< "${devices[$device]}"
    input_file="$collection_dir/${hostname}_lldp_result.ini"
    if [[ ! -f "$input_file" || ! -s "$input_file" ]] ||
       [[ $(grep -Fxc '===PORT_STATUS_START===' "$input_file" 2>/dev/null) -ne 1 ]] ||
       [[ $(grep -Fxc '===PORT_STATUS_END===' "$input_file" 2>/dev/null) -ne 1 ]]; then
        echo "Incomplete LLDP collection input for $hostname" >&2
        collection_incomplete=1
    fi
done
if [[ $collection_incomplete -ne 0 ]]; then
    echo "LLDP collection was incomplete; previous reports were preserved." >&2
    exit 1
fi

# Show unreachable hosts
if [ -s "$unreachable_hosts_file" ]; then
    echo -e "\e[0;36mUnreachable hosts:\e[0m"
    echo ""
    while IFS= read -r host; do
        IFS=' ' read -r ip hostname <<< "$host"
        printf "\e[31m[%-14s]\t\e[0;31m[%-1s]\e[0m\n" "$ip" "$hostname"
    done < "$unreachable_hosts_file"
    echo ""
fi

# Run validation
echo "Validating..."
if ! LLDPQ_LLDP_INPUT_DIR="$collection_dir" LLDPQ_LLDP_STAGE_ONLY=1 \
        /usr/bin/python3 ./lldp-validate.py; then
    echo "LLDP validation/topology generation failed; existing reports and raw inputs were preserved." >&2
    exit 1
fi

# Process the staged aggregate; no canonical or web path is touched until every
# derived report and topology file is ready for one rollback-capable commit.
postprocess_dir=$(mktemp -d "$SCRIPT_DIR/lldp-results/.post.XXXXXX") || exit 1
raw_problems="$postprocess_dir/raw-problems-lldp_results.ini"
problems="$postprocess_dir/problems-lldp_results.ini"
down="$postprocess_dir/down-lldp_results.ini"

# Column-aware filtering: banners/headers/separators are kept structurally and
# data rows are selected on the Status field, so hostnames or neighbor names
# containing 'Pass'/'Fail'/'No-Info' can never be misclassified by substring.
if ! awk 'NR == 1 || /^[=-]/ || !NF || $1 == "Port" { print; next } $2 != "Pass"' \
        "$collection_dir/lldp_results.ini" > "$raw_problems"; then
    echo "Failed to derive LLDP problem input" >&2
    exit 1
fi
if ! awk '
    function flush_section() {
        if (banner == "" || !keep) return
        if (!started) { if (created != "") print created; started = 1 }
        printf "\n%s\n%s", banner, body
    }
    NR == 1 && /^Created on/ { created = $0; next }
    /^===/ { flush_section(); banner = $0; body = ""; keep = 0; next }
    banner == "" || !NF { next }
    {
        body = body $0 "\n"
        if ($0 !~ /^[=-]/ && $1 != "Port" && ($2 == "Fail" || $2 == "No-Info")) keep = 1
    }
    END { flush_section() }
' "$raw_problems" > "$problems"; then
    echo "Failed to build LLDP problem report" >&2
    exit 1
fi
if [ ! -s "$problems" ]; then
    head -n 1 "$raw_problems" >> "$problems" || exit 1
    echo -e "\nGood news, there are no problematic ports..." >> "$problems" || exit 1
fi
if ! grep -q "Created on" "$problems"; then
    header=$(head -n 1 "$raw_problems") || exit 1
    { printf '%s\n' "$header"; cat "$problems"; } > "$problems.with-header" || exit 1
    mv "$problems.with-header" "$problems" || exit 1
fi

if ! awk 'BEGIN{RS="\n\n"; ORS="\n\n"} /No-Info/ && !/Fail/' "$problems" > "$down"; then
    echo "Failed to build LLDP down-port report" >&2
    exit 1
fi
if [ ! -s "$down" ]; then
    head -n 1 "$raw_problems" >> "$down" || exit 1
    echo -e "\nGood news, there are no DOWN ports..." >> "$down" || exit 1
fi
if ! grep -q "Created on" "$down"; then
    header=$(head -n 1 "$raw_problems") || exit 1
    { printf '%s\n' "$header"; cat "$down"; } > "$down.with-header" || exit 1
    mv "$down.with-header" "$down" || exit 1
fi

# Archive the previous problem report before activation. An archive copy is
# additive; a later transaction failure still leaves every served LKG file.
echo "Publishing LLDP generation..."
sudo mkdir -p "$WEB_ROOT/hstr" || exit 1
if [[ -f "$WEB_ROOT/problems-lldp_results.ini" ]]; then
    publish_web_file \
        "$WEB_ROOT/problems-lldp_results.ini" \
        "$WEB_ROOT/hstr/Problems-${DATE}.ini" || exit 1
fi
if ! commit_lldp_outputs; then
    echo "LLDP generation was not activated; last-known-good files were preserved." >&2
    exit 1
fi

# Remove obsolete top-level raw inputs from versions predating private staging,
# but only after the new local+web+topology generation is fully active.
find "$SCRIPT_DIR/lldp-results" -maxdepth 1 -type f \
    -name '*_lldp_result.ini' -delete || \
    echo "Warning: one or more legacy LLDP raw files could not be removed" >&2

# Cleanup old history files (keep 1 per day for last 30 days)
folder_path="$WEB_ROOT/hstr"
cd "$folder_path" || exit 1
declare -a keep_files
for i in {1..30}; do
    start_date=$(date -d "$i days ago" '+%Y-%m-%d 00:00:00')
    end_date=$(date -d "$((i - 1)) days ago" '+%Y-%m-%d 00:00:00')
    file=$(find . -type f -name "*.ini" -newermt "$start_date" ! -newermt "$end_date" | sort | head -n 1)
    if [ -n "$file" ]; then
        keep_files+=("$file")
    fi
done
recent_files=$(find . -type f -name "*.ini" -mtime -1)
for file in $recent_files; do
    keep_files+=("$file")
done
find . -type f -name "*.ini" | while read file; do
    if [[ ! " ${keep_files[@]} " =~ " ${file} " ]]; then
        sudo rm "$file"
    fi
done

# Show timing
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo ""
echo "Done: ${DURATION}s"
exit 0
