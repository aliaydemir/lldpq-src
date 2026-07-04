#!/usr/bin/env bash
# Monitor Script - OPTIMIZED VERSION
# Single SSH session per device + Parallel limits + Parallel analysis
#
# Copyright (c) 2024 LLDPq Project
# Licensed under MIT License - see LICENSE file for details

set -o pipefail

# The wrapper holds this lock for the full collection pipeline. Direct callers
# of monitor.sh acquire the same lock here. Trust the inherited marker only
# when its lock descriptor is actually open.
lock_is_inherited=false
if [[ "${LLDPQ_MONITOR_LOCK_HELD:-0}" == "1" ]] && { : >&9; } 2>/dev/null; then
    lock_is_inherited=true
fi
if [[ "$lock_is_inherited" != "true" ]]; then
    LOCK_FILE="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    if ! command -v flock >/dev/null 2>&1; then
        echo "Error: flock is required for safe monitoring" >&2
        exit 1
    fi
    exec 9>"$LOCK_FILE" || exit 1
    if ! flock -n 9; then
        echo "Monitoring is already running; this invocation was skipped." >&2
        exit 75
    fi
    export LLDPQ_MONITOR_LOCK_HELD=1
fi

# Start timing
START_TIME=$(date +%s)
echo "Starting monitoring at $(date)"

DATE=$(date '+%Y-%m-%d %H-%M-%S')
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"

cd "$SCRIPT_DIR" || exit 1

normalize_bool() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        true|1|yes|y|on) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

# Parse flags
SKIP_OPTICAL="${SKIP_OPTICAL:-false}"
SKIP_L1="${SKIP_L1:-true}"
while getopts "s" opt; do
    case $opt in
        s) SKIP_OPTICAL=true ;;
    esac
done
SKIP_OPTICAL="$(normalize_bool "$SKIP_OPTICAL")"
SKIP_L1="$(normalize_bool "$SKIP_L1")"

# === TUNING PARAMETERS ===
MAX_PARALLEL="${MONITOR_MAX_PARALLEL:-${MAX_PARALLEL:-100}}"  # Maximum parallel SSH connections
case "$MAX_PARALLEL" in
    ''|*[!0-9]*|0) MAX_PARALLEL=100 ;;
esac
SSH_TIMEOUT=60   # SSH connection timeout in seconds

mkdir -p \
    "$SCRIPT_DIR/monitor-results/flap-data" \
    "$SCRIPT_DIR/monitor-results/bgp-data" \
    "$SCRIPT_DIR/monitor-results/evpn-data" \
    "$SCRIPT_DIR/monitor-results/dup-data" \
    "$SCRIPT_DIR/monitor-results/optical-data" \
    "$SCRIPT_DIR/monitor-results/ber-data" \
    "$SCRIPT_DIR/monitor-results/hardware-data" \
    "$SCRIPT_DIR/monitor-results/log-data" || exit 1

unreachable_hosts_file=$(mktemp) || exit 1
active_jobs_file=$(mktemp) || {
    rm -f "$unreachable_hosts_file"
    exit 1
}
completed_file=""
analysis_log_dir=""
bundle_parent="$SCRIPT_DIR/.monitor-bundles"
bundle_root=""
monitor_run_started=false
analysis_backup_dir=""
analysis_transaction_active=false
recovery_bundle_must_be_preserved=false

analysis_artifacts=(
    .lldpq-current.json
    .pipeline-inputs/assets.ini .pipeline-inputs/lldp_results.ini
    bgp-analysis.html bgp_history.json
    link-flap-analysis.html flap_history.json
    optical-analysis.html optical_history.json
    ber-analysis.html ber_history.json ber_baseline.json
    hardware-analysis.html
    log-analysis.html log_summary.json
    duplicate-analysis.html dup-data/dup_seq_state.json dup-data/dup_ip_state.json
)

snapshot_analysis_state() {
    local relative source backup status
    analysis_backup_dir="$bundle_root/analysis-backup"
    mkdir -p "$analysis_backup_dir/files" || return 1
    : > "$analysis_backup_dir/manifest" || return 1
    for relative in "${analysis_artifacts[@]}"; do
        source="$SCRIPT_DIR/monitor-results/$relative"
        backup="$analysis_backup_dir/files/$relative"
        status=missing
        if [[ -e "$source" || -L "$source" ]]; then
            [[ -f "$source" && ! -L "$source" ]] || {
                echo "Refusing non-file analysis artifact: $source" >&2
                return 1
            }
            mkdir -p "$(dirname "$backup")" || return 1
            cp -a "$source" "$backup" || return 1
            [[ -f "$backup" && ! -L "$backup" ]] || {
                echo "Analyzer backup is not a regular file: $backup" >&2
                return 1
            }
            status=present
        fi
        printf '%s\t%s\n' "$status" "$relative" \
            >> "$analysis_backup_dir/manifest" || return 1
    done
    # Flush the complete snapshot, then create and flush its authority marker
    # before any analyzer can mutate state. Recovery therefore fails closed
    # across SIGKILL and power loss, not merely normal shell exits.
    python3 - "$analysis_backup_dir" \
        "$bundle_root/.retain-analysis-recovery" <<'PYTHON' || return 1
import os
import sys

backup_root, marker = sys.argv[1:]
directories = []
for root, _subdirs, files in os.walk(backup_root):
    directories.append(root)
    for name in files:
        path = os.path.join(root, name)
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, "rb") as handle:
                os.fsync(handle.fileno())
for directory in reversed(directories):
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
with open(marker, "w", encoding="utf-8") as handle:
    handle.write("status=rollback-required\n")
    handle.flush()
    os.fsync(handle.fileno())
descriptor = os.open(os.path.dirname(marker), os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PYTHON
    analysis_transaction_active=true
}

validate_analysis_recovery_authority() {
    local marker="$bundle_root/.retain-analysis-recovery"
    local authority_line line_count
    [[ ( -e "$marker" || -L "$marker" ) && -f "$marker" && ! -L "$marker" ]] || {
        echo "Analyzer recovery authority is missing or unsafe: $marker" >&2
        return 1
    }
    IFS= read -r authority_line < "$marker" || return 1
    line_count=$(awk 'END { print NR }' "$marker") || return 1
    if [[ "$authority_line" != "status=rollback-required" || "$line_count" != "1" ]]; then
        echo "Analyzer recovery authority is malformed: $marker" >&2
        return 1
    fi
    return 0
}

rollback_analysis_state() {
    local status relative destination backup restore_temp failed=false
    [[ "$analysis_transaction_active" == "true" ]] || return 0
    validate_analysis_recovery_authority || return 1
    if ! validate_analysis_backup_manifest; then
        echo "Analyzer recovery manifest is missing or invalid: $analysis_backup_dir" >&2
        return 1
    fi
    while IFS=$'\t' read -r status relative; do
        [[ -n "$relative" ]] || continue
        destination="$SCRIPT_DIR/monitor-results/$relative"
        backup="$analysis_backup_dir/files/$relative"
        if [[ -d "$destination" && ! -L "$destination" ]]; then
            echo "Could not restore analysis artifact over directory: $destination" >&2
            failed=true
            continue
        fi
        if [[ "$status" == "present" ]]; then
            mkdir -p "$(dirname "$destination")" || { failed=true; continue; }
            # Prepare the recovery copy beside its destination and replace only
            # after the copy is complete. A disk/permission failure therefore
            # cannot destroy either the previous artifact or the sole backup.
            restore_temp=$(mktemp \
                "$(dirname "$destination")/.$(basename "$destination").rollback.XXXXXXXXXX") || {
                failed=true
                continue
            }
            if ! cp -a -- "$backup" "$restore_temp" ||
               ! mv -f -- "$restore_temp" "$destination"; then
                rm -f -- "$restore_temp" 2>/dev/null || true
                failed=true
            fi
        else
            rm -f -- "$destination" || failed=true
        fi
    done < "$analysis_backup_dir/manifest"
    # Do not permit the caller to clear authority or discard the only backup
    # until every restored file and every affected destination directory is
    # durable. Missing-state removals are verified with lexists in Python.
    if [[ "$failed" == "false" ]] && ! python3 - \
            "$SCRIPT_DIR/monitor-results" "$analysis_backup_dir/manifest" <<'PYTHON'
import os
import stat
import sys

results_root = os.path.abspath(sys.argv[1])
manifest = sys.argv[2]
directories = set()

def lexists(path):
    return os.path.lexists(path)

for line in open(manifest, "r", encoding="utf-8"):
    status, relative = line.rstrip("\n").split("\t", 1)
    destination = os.path.join(results_root, relative)
    directory = os.path.dirname(destination)
    while not os.path.isdir(directory):
        if lexists(directory) or directory == results_root:
            raise SystemExit(f"unsafe analyzer destination directory: {directory}")
        parent = os.path.dirname(directory)
        if os.path.commonpath((results_root, parent)) != results_root:
            raise SystemExit("analyzer destination escaped its result root")
        directory = parent
    if os.path.islink(directory):
        raise SystemExit(f"analyzer destination directory is a symlink: {directory}")
    directories.add(directory)
    if status == "present":
        mode = os.lstat(destination).st_mode
        if not stat.S_ISREG(mode) or os.path.islink(destination):
            raise SystemExit(f"restored analyzer artifact is unsafe: {destination}")
        with open(destination, "rb") as handle:
            os.fsync(handle.fileno())
    elif status == "missing":
        if lexists(destination):
            raise SystemExit(f"removed analyzer artifact still exists: {destination}")
    else:
        raise SystemExit("invalid analyzer recovery manifest state")

for directory in directories:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PYTHON
    then
        failed=true
    fi
    if [[ "$failed" == "false" ]]; then
        analysis_transaction_active=false
        return 0
    fi
    return 1
}

validate_analysis_backup_manifest() {
    local manifest="$analysis_backup_dir/manifest"
    local status relative extra expected expected_artifact backup count=0 valid=true
    local -A seen=()
    [[ -f "$manifest" && ! -L "$manifest" ]] || return 1

    while IFS=$'\t' read -r status relative extra; do
        [[ -z "${extra:-}" && ( "$status" == "present" || "$status" == "missing" ) ]] || {
            valid=false
            continue
        }
        expected=false
        for expected_artifact in "${analysis_artifacts[@]}"; do
            if [[ "$relative" == "$expected_artifact" ]]; then
                expected=true
                break
            fi
        done
        if [[ "$expected" != "true" || -n "${seen[$relative]+x}" ]]; then
            valid=false
            continue
        fi
        seen["$relative"]=1
        ((count++))
        backup="$analysis_backup_dir/files/$relative"
        if [[ "$status" == "present" && ( ! -f "$backup" || -L "$backup" ) ]]; then
            valid=false
        elif [[ "$status" == "missing" && ( -e "$backup" || -L "$backup" ) ]]; then
            valid=false
        fi
    done < "$manifest" || return 1

    [[ "$valid" == "true" && "$count" -eq "${#analysis_artifacts[@]}" ]] || return 1
    for expected_artifact in "${analysis_artifacts[@]}"; do
        [[ -n "${seen[$expected_artifact]+x}" ]] || return 1
    done
    return 0
}

commit_analysis_state() {
    # Publication succeeded: remove the recovery authority first. If the
    # process is killed afterwards, a leftover backup is ordinary garbage and
    # must never be mistaken for an incomplete rollback on the next run.
    rm -f -- "$bundle_root/.retain-analysis-recovery" || return 1
    # Make authority removal durable before deleting its rollback payload. If
    # this sync fails, retain the backup rather than risk a resurrected marker
    # after power loss with no data behind it.
    if ! python3 - "$bundle_root" <<'PYTHON'
import os
import sys
descriptor = os.open(sys.argv[1], os.O_RDONLY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PYTHON
    then
        echo "Warning: analyzer authority removal could not be synced; retaining rollback payload" >&2
        analysis_transaction_active=false
        recovery_bundle_must_be_preserved=true
        return 0
    fi
    analysis_transaction_active=false
    if [[ -n "$analysis_backup_dir" ]]; then
        rm -rf -- "$analysis_backup_dir" || return 1
        analysis_backup_dir=""
    fi
}

cleanup_monitor_temp() {
    local status=$? preserve_bundle="$recovery_bundle_must_be_preserved"
    if [[ "$analysis_transaction_active" == "true" ]]; then
        if ! rollback_analysis_state; then
            preserve_bundle=true
            echo "CRITICAL: analyzer state rollback was incomplete; recovery snapshot retained at $bundle_root" >&2
        fi
    fi
    if [[ $status -ne 0 && "$monitor_run_started" == "true" && \
          -f "${stale_marker:-}" ]] && \
       grep -q '^status=collecting$' "$stale_marker" 2>/dev/null; then
        mark_reports_stale "monitor exited unexpectedly with status $status" || true
    fi
    [[ -n "$unreachable_hosts_file" ]] && rm -f "$unreachable_hosts_file"
    [[ -n "$active_jobs_file" ]] && rm -f "$active_jobs_file"
    [[ -n "$completed_file" ]] && rm -f "$completed_file"
    [[ -n "$analysis_log_dir" ]] && rm -rf "$analysis_log_dir"
    if [[ -n "$bundle_root" ]] && \
       find "$bundle_root" -name '.retain-device-recovery' -print -quit \
           2>/dev/null | grep -q .; then
        preserve_bundle=true
        echo "CRITICAL: device bundle recovery data retained at $bundle_root" >&2
    fi
    if [[ -n "$bundle_root" && "$preserve_bundle" != "true" ]]; then
        rm -rf "$bundle_root"
    fi
    [[ -d "$bundle_parent" ]] && rmdir "$bundle_parent" 2>/dev/null || true
}

terminate_monitor() {
    local status=$1 pid
    trap - HUP INT TERM
    # Stop direct background workers. Their per-device EXIT traps discard
    # uncommitted bundles; workers close the global lock descriptor so a slow
    # descendant can never hold the next scheduled run behind this process.
    while IFS= read -r pid; do
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
    done < <(jobs -pr)
    wait 2>/dev/null || true
    if [[ "$monitor_run_started" == "true" ]]; then
        mark_reports_stale "monitor interrupted with status $status" || true
    fi
    exit "$status"
}
trap cleanup_monitor_temp EXIT
trap 'terminate_monitor 129' HUP
trap 'terminate_monitor 130' INT
trap 'terminate_monitor 143' TERM

stale_marker="$SCRIPT_DIR/monitor-results/.lldpq-stale"

mark_reports_stale() {
    local reason=$1
    local failure_time
    failure_time=$(date -Is)
    {
        printf 'status=stale\n'
        printf 'timestamp=%s\n' "$failure_time"
        printf 'reason=%s\n' "$reason"
    } > "$stale_marker"
    printf '%s %s\n' "$failure_time" "$reason" >> "$SCRIPT_DIR/monitor-failures.log"
    echo "Monitoring failed; last-known-good web reports were preserved: $reason" >&2
    if [[ -d "$WEB_ROOT/monitor-results" ]]; then
        if [[ ! "$stale_marker" -ef "$WEB_ROOT/monitor-results/.lldpq-stale" ]]; then
            sudo cp "$stale_marker" \
                "$WEB_ROOT/monitor-results/.lldpq-stale" 2>/dev/null || true
        fi
    fi
}

mark_reports_in_progress() {
    local started_at
    started_at=$(date -Is) || return 1
    {
        printf 'status=collecting\n'
        printf 'timestamp=%s\n' "$started_at"
        printf 'reason=monitoring_in_progress\n'
    } > "$stale_marker" || return 1
    if [[ -d "$WEB_ROOT/monitor-results" ]]; then
        if [[ ! "$stale_marker" -ef "$WEB_ROOT/monitor-results/.lldpq-stale" ]]; then
            sudo cp "$stale_marker" \
                "$WEB_ROOT/monitor-results/.lldpq-stale" 2>/dev/null || return 1
        fi
    fi
}

clear_stale_marker() {
    if [[ -d "$WEB_ROOT/monitor-results" ]]; then
        sudo rm -f "$WEB_ROOT/monitor-results/.lldpq-stale" 2>/dev/null || return 1
    fi
    # Source is the alert authority; clear it last so alerts remain fail-closed
    # until both the web activation and marker cleanup have succeeded.
    rm -f "$stale_marker" || return 1
    return 0
}

write_current_manifest() {
    local manifest="$SCRIPT_DIR/monitor-results/.lldpq-current.json"
    local completed_at
    completed_at=$(date -Is) || return 1
    python3 - "$manifest" "$completed_at" "$device_count" \
        "$SKIP_OPTICAL" "${LLDPQ_PIPELINE_ID:-}" \
        "${LLDPQ_PIPELINE_STARTED_AT:-}" \
        "${LLDPQ_ASSETS_FILE:-$SCRIPT_DIR/assets.ini}" \
        "$SCRIPT_DIR/lldp-results/lldp_results.ini" \
        "${analysis_labels[@]}" <<'PYTHON'
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

destination = Path(sys.argv[1])
pipeline_id = sys.argv[5].strip()
pipeline_started = sys.argv[6].strip()
source_paths = {
    "assets": Path(sys.argv[7]),
    "lldp": Path(sys.argv[8]),
}

if bool(pipeline_id) != bool(pipeline_started):
    raise SystemExit("incomplete pipeline identity")
if pipeline_id and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", pipeline_id):
    raise SystemExit("invalid pipeline identity")

started_epoch = None
if pipeline_started:
    try:
        started_epoch = int(pipeline_started)
    except ValueError:
        raise SystemExit("invalid pipeline start time")
    if started_epoch <= 0:
        raise SystemExit("invalid pipeline start time")

def read_stable(path):
    if not path.is_file():
        return None, None
    before = path.stat()
    content = path.read_bytes()
    after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise RuntimeError(f"source changed while fingerprinting: {path}")
    try:
        first_line = content.decode("utf-8").splitlines()[0]
    except (UnicodeError, IndexError) as exc:
        raise RuntimeError(f"source cannot be read: {path}: {exc}") from exc
    return content, {
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "created_header": first_line,
    }

def atomic_snapshot(path, content, mtime_ns):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o664)
        os.utime(temporary, ns=(mtime_ns, mtime_ns))
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

pipeline_complete = bool(pipeline_id)
sources = {}
if pipeline_complete:
    source_content = {}
    source_identities = {}
    for name, path in source_paths.items():
        content, identity = read_stable(path)
        if content is None:
            raise SystemExit(f"pipeline source missing: {name}")
        if identity["mtime_ns"] / 1_000_000_000 + 2 < started_epoch:
            raise SystemExit(f"{name} source predates this pipeline")
        source_content[name] = content
        source_identities[name] = identity

    snapshot_paths = {
        "assets": destination.parent / ".pipeline-inputs" / "assets.ini",
        "lldp": destination.parent / ".pipeline-inputs" / "lldp_results.ini",
    }
    for name, snapshot_path in snapshot_paths.items():
        atomic_snapshot(
            snapshot_path, source_content[name],
            source_identities[name]["mtime_ns"],
        )
        _content, identity = read_stable(snapshot_path)
        identity["path"] = str(snapshot_path.relative_to(destination.parent))
        sources[name] = identity

payload = {
    "status": "current",
    "completed_at": sys.argv[2],
    "device_count": int(sys.argv[3]),
    "analyses": sys.argv[9:],
    "skipped": ["optical"] if sys.argv[4] == "true" else [],
    "pipeline_complete": pipeline_complete,
    "pipeline_id": pipeline_id or None,
    "pipeline_started_at": started_epoch,
    "sources": sources,
}
temporary = destination.with_name(
    f".{destination.name}.tmp.{os.getpid()}"
)
try:
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
except Exception:
    temporary.unlink(missing_ok=True)
    raise
PYTHON
}

atomic_exchange_paths() {
    local first=$1 second=$2
    sudo python3 - "$first" "$second" <<'PYTHON'
import ctypes
import os
import sys

AT_FDCWD = -100
RENAME_EXCHANGE = 2
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = getattr(libc, "renameat2", None)
if renameat2 is None:
    raise SystemExit(2)
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p,
                      ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
result = renameat2(
    AT_FDCWD, os.fsencode(sys.argv[1]),
    AT_FDCWD, os.fsencode(sys.argv[2]),
    RENAME_EXCHANGE,
)
if result != 0:
    error = ctypes.get_errno()
    # Exit 2 tells the shell to use its rollback-capable compatibility path.
    if error in {22, 38, 95}:
        raise SystemExit(2)
    raise OSError(error, os.strerror(error))
PYTHON
}

publish_monitor_results() {
    local source_dir="$SCRIPT_DIR/monitor-results"
    local destination_dir="$WEB_ROOT/monitor-results"
    local stage_dir backup_dir=""
    local old_hup old_int old_term fallback_status

    restore_publish_traps() {
        if [[ -n "$old_hup" ]]; then eval "$old_hup"; else trap - HUP; fi
        if [[ -n "$old_int" ]]; then eval "$old_int"; else trap - INT; fi
        if [[ -n "$old_term" ]]; then eval "$old_term"; else trap - TERM; fi
    }

    # Copy into a complete sibling tree first. A failed/partial copy never
    # touches the currently served directory. The final moves stay on the web
    # filesystem and rollback the old directory if activation fails. This also
    # self-heals the legacy Docker layout where destination_dir is a symlink to
    # source_dir: the symlink itself is exchanged for the independent tree.
    stage_dir=$(sudo mktemp -d "$WEB_ROOT/.monitor-results.new.XXXXXXXXXX") || return 1
    if ! sudo cp -a "$source_dir/." "$stage_dir/"; then
        sudo rm -rf "$stage_dir" 2>/dev/null || true
        return 1
    fi

    if [[ "$SKIP_OPTICAL" == "true" ]]; then
        # Keep the private history for a future enabled run, but never republish
        # an old aggregate/history as though it belonged to this skipped run.
        if ! sudo rm -f "$stage_dir/optical_history.json" \
                "$stage_dir/optical-analysis.html" ||
           ! sudo tee "$stage_dir/optical-analysis.html" >/dev/null <<'EOF'
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Optical Analysis - Skipped</title>
<link rel="stylesheet" type="text/css" href="/css/styles2.css"></head>
<body data-analysis-status="skipped"><h1>Optical Diagnostics</h1>
<p style="color:#ff9800;font-weight:bold">Optical collection was skipped for this monitoring run.</p>
</body></html>
EOF
        then
            sudo rm -rf "$stage_dir" 2>/dev/null || true
            return 1
        fi
    fi

    if ! sudo chown -R "${LLDPQ_USER:-$(whoami)}:www-data" "$stage_dir" ||
       ! sudo find "$stage_dir" -type d -exec chmod 775 {} \; ||
       ! sudo find "$stage_dir" -type f -exec chmod 664 {} \;; then
        sudo rm -rf "$stage_dir" 2>/dev/null || true
        return 1
    fi

    if [[ -e "$destination_dir" || -L "$destination_dir" ]]; then
        # Linux renameat2(RENAME_EXCHANGE) swaps the complete trees without a
        # moment where /monitor-results is absent.  Keep the portable fallback
        # for older kernels/filesystems and roll it back on activation failure.
        if atomic_exchange_paths "$stage_dir" "$destination_dir" 2>/dev/null; then
            if ! sudo rm -rf "$stage_dir"; then
                echo "Warning: previous monitor web tree remains at $stage_dir" >&2
            fi
            return 0
        fi

        old_hup=$(trap -p HUP)
        old_int=$(trap -p INT)
        old_term=$(trap -p TERM)
        trap '' HUP INT TERM
        backup_dir="${stage_dir}.previous"
        if ! sudo mv -T "$destination_dir" "$backup_dir"; then
            restore_publish_traps
            sudo rm -rf "$stage_dir" 2>/dev/null || true
            return 1
        fi
    fi

    if ! sudo mv -T "$stage_dir" "$destination_dir"; then
        fallback_status=1
        if [[ -n "$backup_dir" ]]; then
            if ! sudo mv -T "$backup_dir" "$destination_dir" 2>/dev/null; then
                echo "CRITICAL: monitor web rollback is retained at $backup_dir" >&2
            fi
        fi
        sudo rm -rf "$stage_dir" 2>/dev/null || true
        [[ -n "$backup_dir" ]] && restore_publish_traps
        return "$fallback_status"
    fi

    if [[ -n "$backup_dir" ]]; then
        if ! sudo rm -rf "$backup_dir"; then
            echo "Warning: previous monitor web tree remains at $backup_dir" >&2
        fi
        restore_publish_traps
    fi
    return 0
}

# SSH options with multiplexing
SSH_OPTS="-o StrictHostKeyChecking=no -o ControlMaster=auto -o ControlPath=~/.ssh/cm-%r@%h:%p -o ControlPersist=60 -o BatchMode=yes -o ConnectTimeout=$SSH_TIMEOUT"

# Ping command - on Cumulus switches with Docker --privileged, the entrypoint
# adds 'ip rule' for mgmt VRF so plain ping works. No ip vrf exec needed.
PING="ping"

ping_test() {
    local device=$1
    local hostname=$2
    $PING -c 1 -W 0.5 "$device" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "$device $hostname" >> "$unreachable_hosts_file"
        return 1
    fi
    return 0
}

clear_current_device_artifacts() {
    local hostname=$1
    rm -f -- \
        "$SCRIPT_DIR/monitor-results/${hostname}.html" \
        "$SCRIPT_DIR/monitor-results/bgp-data/${hostname}_bgp.txt" \
        "$SCRIPT_DIR/monitor-results/evpn-data/${hostname}_evpn.txt" \
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_dup.txt" \
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_fdb.txt" \
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_neigh.txt" \
        "$SCRIPT_DIR/monitor-results/flap-data/${hostname}_"* \
        "$SCRIPT_DIR/monitor-results/optical-data/${hostname}_optical.txt" \
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_interface_errors.txt" \
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_detailed_counters.txt" \
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_l1_show.txt" \
        "$SCRIPT_DIR/monitor-results/hardware-data/${hostname}_hardware.txt" \
        "$SCRIPT_DIR/monitor-results/log-data/${hostname}_logs.txt"
}

write_unreachable_device_report() {
    local device=$1 hostname=$2
    local html_file="$SCRIPT_DIR/monitor-results/${hostname}.html"
    local html_temp="${html_file}.tmp.${BASHPID:-$$}"
    cat > "$html_temp" <<EOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Monitor Results - ${hostname}</title>
<link rel="stylesheet" type="text/css" href="/css/styles2.css"></head>
<body><h1>Monitor Results - ${hostname}</h1>
<p style="color:#ff9800;font-weight:bold">Current collection unavailable</p>
<p>Device ${hostname} (${device}) did not respond during the collection at ${DATE}.</p>
<p>Previous measurements were intentionally not presented as current.</p>
</body></html>
EOF
    [[ -s "$html_temp" ]] || { rm -f "$html_temp"; return 1; }
    mv -f "$html_temp" "$html_file"
}

validate_collection_bundle() {
    local raw_file=$1
    python3 - "$raw_file" <<'PYTHON'
import sys
from pathlib import Path

sections = (
    "HTML_OUTPUT", "BGP_DATA", "EVPN_DATA", "DUP_DATA", "FDB_DATA",
    "NEIGH_DATA", "CARRIER_DATA", "OPTICAL_DATA", "BER_DATA", "L1_DATA",
    "HARDWARE_DATA", "LOG_DATA",
)
try:
    lines = Path(sys.argv[1]).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines()
except OSError as exc:
    print(f"cannot read collection bundle: {exc}", file=sys.stderr)
    raise SystemExit(1)

command_errors = [
    line for line in lines if line.startswith("__LLDPQ_COLLECTION_ERROR__:")
]
if command_errors:
    print(
        "remote collection command failures: " + ", ".join(command_errors),
        file=sys.stderr,
    )
    raise SystemExit(1)

previous_end = -1
for section in sections:
    start_marker = f"==={section}_START==="
    end_marker = f"==={section}_END==="
    starts = [index for index, line in enumerate(lines) if line == start_marker]
    ends = [index for index, line in enumerate(lines) if line == end_marker]
    if len(starts) != 1 or len(ends) != 1:
        print(
            f"invalid {section} marker count: start={len(starts)} end={len(ends)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not (previous_end < starts[0] < ends[0]):
        print(f"out-of-order collection section: {section}", file=sys.stderr)
        raise SystemExit(1)
    previous_end = ends[0]
PYTHON
}

extract_collection_section() {
    local raw_file=$1 section=$2 destination=$3
    awk -v start="===${section}_START===" -v end="===${section}_END===" '
        $0 == start { inside=1; next }
        $0 == end { if (inside) { found_end=1; exit } }
        inside { print }
        END { if (!found_end) exit 1 }
    ' "$raw_file" > "$destination"
}

restore_bundle_commit_traps() {
    if [[ -n "${commit_hup_trap:-}" ]]; then eval "$commit_hup_trap"; else trap - HUP; fi
    if [[ -n "${commit_int_trap:-}" ]]; then eval "$commit_int_trap"; else trap - INT; fi
    if [[ -n "${commit_term_trap:-}" ]]; then eval "$commit_term_trap"; else trap - TERM; fi
}

# Restore one interrupted per-device publication from its durable journal.
# The marker is intentionally data, not shell syntax: startup validates every
# recorded path and checksum against the hostname-derived destination set
# before it changes anything.  The operation is idempotent, so SIGKILL during
# recovery merely leaves the same authority for the next invocation.
recover_device_bundle() {
    local stage_dir=$1
    local marker="$stage_dir/.retain-device-recovery"
    python3 - "$marker" "$stage_dir" "$SCRIPT_DIR" <<'PYTHON'
import hashlib
import json
import os
import re
import stat
import sys

marker, stage_dir, script_dir = map(os.path.abspath, sys.argv[1:])

def lexists(path):
    # Unlike exists(), this also detects a dangling symlink.  A symlink in a
    # recovery slot is ambiguity, never evidence that the backup is absent.
    return os.path.lexists(path)

def is_regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
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

try:
    if marker != os.path.join(stage_dir, ".retain-device-recovery"):
        fail("device recovery marker is outside its stage")
    if not is_regular(marker) or os.path.islink(marker):
        fail("device recovery marker is missing or not a regular file")
    if not os.path.isdir(stage_dir) or os.path.islink(stage_dir):
        fail("device recovery stage is not a real directory")
    backup_dir = os.path.join(stage_dir, ".previous")
    if not os.path.isdir(backup_dir) or os.path.islink(backup_dir):
        fail("device recovery backup directory is missing or unsafe")

    marker_stat = os.lstat(marker)
    with open(marker, "rb") as handle:
        marker_bytes = handle.read(2 * 1024 * 1024 + 1)
    if len(marker_bytes) != marker_stat.st_size:
        fail("device recovery marker changed while it was read")
    payload = json.loads(marker_bytes.decode("utf-8"))
    if set(payload) != {"version", "status", "hostname", "records"}:
        fail("device recovery marker has an unexpected schema")
    if payload["version"] != 1 or payload["status"] != "rollback-required":
        fail("device recovery marker has an unsupported state")
    hostname = payload["hostname"]
    if not isinstance(hostname, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,252}", hostname
    ) or ".." in hostname:
        fail("device recovery hostname is invalid")

    source_names = [
        "device.html", "bgp.txt", "evpn.txt", "dup.txt", "fdb.txt",
        "neigh.txt", "carrier.txt", "optical.txt", "ber.txt", "l1.txt",
        "hardware.txt", "logs.txt",
    ]
    destinations = [
        f"monitor-results/{hostname}.html",
        f"monitor-results/bgp-data/{hostname}_bgp.txt",
        f"monitor-results/evpn-data/{hostname}_evpn.txt",
        f"monitor-results/dup-data/{hostname}_dup.txt",
        f"monitor-results/dup-data/{hostname}_fdb.txt",
        f"monitor-results/dup-data/{hostname}_neigh.txt",
        f"monitor-results/flap-data/{hostname}_carrier_transitions.txt",
        f"monitor-results/optical-data/{hostname}_optical.txt",
        f"monitor-results/ber-data/{hostname}_interface_errors.txt",
        f"monitor-results/ber-data/{hostname}_l1_show.txt",
        f"monitor-results/hardware-data/{hostname}_hardware.txt",
        f"monitor-results/log-data/{hostname}_logs.txt",
        f"monitor-results/ber-data/{hostname}_detailed_counters.txt",
    ]
    destinations = [os.path.join(script_dir, value) for value in destinations]
    records = payload["records"]
    if not isinstance(records, list) or len(records) != len(destinations):
        fail("device recovery journal is incomplete")

    prepared = []
    hash_pattern = re.compile(r"[0-9a-f]{64}")
    required_keys = {
        "index", "destination", "backup", "source", "original",
        "original_sha256", "staged_sha256",
    }
    for index, (record, expected_destination) in enumerate(
            zip(records, destinations)
    ):
        if not isinstance(record, dict) or set(record) != required_keys:
            fail(f"invalid device recovery record {index}")
        expected_backup = os.path.join(backup_dir, str(index))
        expected_source = (
            os.path.join(stage_dir, source_names[index])
            if index < len(source_names) else None
        )
        if (record["index"] != index
                or record["destination"] != expected_destination
                or record["backup"] != expected_backup
                or record["source"] != expected_source):
            fail(f"device recovery path mismatch in record {index}")
        original = record["original"]
        original_hash = record["original_sha256"]
        staged_hash = record["staged_sha256"]
        if original not in {"present", "missing"}:
            fail(f"invalid original state in record {index}")
        if original == "present":
            if not isinstance(original_hash, str) or not hash_pattern.fullmatch(original_hash):
                fail(f"invalid original checksum in record {index}")
        elif original_hash is not None:
            fail(f"unexpected original checksum in record {index}")
        if expected_source is None:
            if staged_hash is not None:
                fail(f"unexpected staged checksum in record {index}")
        elif not isinstance(staged_hash, str) or not hash_pattern.fullmatch(staged_hash):
            fail(f"invalid staged checksum in record {index}")

        backup_exists = lexists(expected_backup)
        destination_exists = lexists(expected_destination)
        source_exists = expected_source is not None and lexists(expected_source)

        # Validate the complete transaction before beginning a rollback.  In
        # particular, lexists() makes a dangling backup symlink a hard error.
        if backup_exists:
            if original != "present" or not is_regular(expected_backup) \
                    or os.path.islink(expected_backup) \
                    or digest(expected_backup) != original_hash:
                fail(f"invalid device backup in record {index}")
            if destination_exists and (
                    not is_regular(expected_destination)
                    or os.path.islink(expected_destination)
            ):
                fail(f"unsafe current destination in record {index}")
        elif original == "present":
            if (not destination_exists or not is_regular(expected_destination)
                    or os.path.islink(expected_destination)
                    or digest(expected_destination) != original_hash):
                fail(f"original device artifact cannot be proven in record {index}")
        elif destination_exists:
            if (expected_source is None or not is_regular(expected_destination)
                    or os.path.islink(expected_destination)
                    or digest(expected_destination) != staged_hash):
                fail(f"unexpected artifact at originally-missing destination {index}")

        if source_exists and (
                not is_regular(expected_source) or os.path.islink(expected_source)
                or digest(expected_source) != staged_hash
        ):
            fail(f"invalid staged device artifact in record {index}")
        prepared.append((
            original, expected_destination, expected_backup, backup_exists,
            expected_source, source_exists,
        ))

    # Every input was proven above. Each rename/unlink is independently
    # repeatable, and the marker remains authoritative until all old files and
    # their parent directories have been flushed.
    for original, destination, backup, backup_exists, _source, _source_exists in prepared:
        if original == "present" and backup_exists:
            os.replace(backup, destination)
        elif original == "missing" and lexists(destination):
            os.unlink(destination)
    for _original, _destination, _backup, _backup_exists, source, source_exists in prepared:
        if source is not None and source_exists and lexists(source):
            os.unlink(source)

    destination_directories = set()
    for original, destination, _backup, _backup_exists, _source, _source_exists in prepared:
        destination_directories.add(os.path.dirname(destination))
        if original == "present":
            if not is_regular(destination) or os.path.islink(destination):
                fail(f"restored device artifact disappeared: {destination}")
            fsync_file(destination)
        elif lexists(destination):
            fail(f"originally-missing device artifact remains: {destination}")
    for directory in destination_directories:
        fsync_directory(directory)
    fsync_directory(backup_dir)
    fsync_directory(stage_dir)

    current_marker_stat = os.lstat(marker)
    if ((marker_stat.st_dev, marker_stat.st_ino) !=
            (current_marker_stat.st_dev, current_marker_stat.st_ino)):
        fail("device recovery marker was swapped before removal")
    os.unlink(marker)
    try:
        fsync_directory(stage_dir)
    except OSError as sync_error:
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(marker_bytes)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException as restore_error:
            fail(
                f"device marker unlink was not durable and recreation failed: "
                f"{sync_error}; {restore_error}"
            )
        fail(f"device marker unlink was not durable; authority retained: {sync_error}")
except BaseException as exc:
    print(f"CRITICAL: device bundle recovery failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
PYTHON
}

commit_device_bundle() {
    local stage_dir=$1 hostname=$2
    local backup_dir="$stage_dir/.previous"
    local index destination source restore_temp restore_failed
    local commit_hup_trap commit_int_trap commit_term_trap
    commit_hup_trap=$(trap -p HUP)
    commit_int_trap=$(trap -p INT)
    commit_term_trap=$(trap -p TERM)
    # Do not allow an external signal to split the short activation/rollback
    # sequence. The caller's traps are restored before this function returns.
    trap '' HUP INT TERM
    local -a sources=(
        "$stage_dir/device.html"
        "$stage_dir/bgp.txt"
        "$stage_dir/evpn.txt"
        "$stage_dir/dup.txt"
        "$stage_dir/fdb.txt"
        "$stage_dir/neigh.txt"
        "$stage_dir/carrier.txt"
        "$stage_dir/optical.txt"
        "$stage_dir/ber.txt"
        "$stage_dir/l1.txt"
        "$stage_dir/hardware.txt"
        "$stage_dir/logs.txt"
    )
    local -a destinations=(
        "$SCRIPT_DIR/monitor-results/${hostname}.html"
        "$SCRIPT_DIR/monitor-results/bgp-data/${hostname}_bgp.txt"
        "$SCRIPT_DIR/monitor-results/evpn-data/${hostname}_evpn.txt"
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_dup.txt"
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_fdb.txt"
        "$SCRIPT_DIR/monitor-results/dup-data/${hostname}_neigh.txt"
        "$SCRIPT_DIR/monitor-results/flap-data/${hostname}_carrier_transitions.txt"
        "$SCRIPT_DIR/monitor-results/optical-data/${hostname}_optical.txt"
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_interface_errors.txt"
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_l1_show.txt"
        "$SCRIPT_DIR/monitor-results/hardware-data/${hostname}_hardware.txt"
        "$SCRIPT_DIR/monitor-results/log-data/${hostname}_logs.txt"
        # Retired legacy extract: back it up for rollback, but do not replace it.
        "$SCRIPT_DIR/monitor-results/ber-data/${hostname}_detailed_counters.txt"
    )

    mark_device_recovery() {
        local marker="$stage_dir/.retain-device-recovery"
        python3 - "$marker" "$stage_dir" "$backup_dir" "$hostname" \
            "${#sources[@]}" "${sources[@]}" "${destinations[@]}" <<'PYTHON'
import hashlib
import json
import os
import stat
import sys
import tempfile

marker, stage_dir, backup_dir = map(os.path.abspath, sys.argv[1:4])
hostname = sys.argv[4]
source_count = int(sys.argv[5])
sources = [os.path.abspath(value) for value in sys.argv[6:6 + source_count]]
destinations = [os.path.abspath(value) for value in sys.argv[6 + source_count:]]
if len(destinations) != source_count + 1:
    raise SystemExit("invalid device publication layout")

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

def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

if lexists(marker):
    raise SystemExit("device recovery authority already exists")
records = []
for index, destination in enumerate(destinations):
    source = sources[index] if index < source_count else None
    if source is not None:
        if not regular(source):
            raise SystemExit(f"invalid staged device artifact: {source}")
        staged_hash = digest(source)
        with open(source, "rb") as handle:
            os.fsync(handle.fileno())
    else:
        staged_hash = None
    backup = os.path.join(backup_dir, str(index))
    if lexists(backup):
        raise SystemExit(f"unexpected pre-existing device backup: {backup}")
    if lexists(destination):
        if not regular(destination):
            raise SystemExit(f"unsafe device destination: {destination}")
        original = "present"
        original_hash = digest(destination)
    else:
        original = "missing"
        original_hash = None
    sidecar = os.path.join(backup_dir, f"{index}.{original}")
    with open(sidecar, "x", encoding="ascii") as handle:
        handle.write(f"{original}\n")
        handle.flush()
        os.fsync(handle.fileno())
    records.append({
        "index": index,
        "destination": destination,
        "backup": backup,
        "source": source,
        "original": original,
        "original_sha256": original_hash,
        "staged_sha256": staged_hash,
    })

sync_directory(backup_dir)
descriptor, temporary = tempfile.mkstemp(
    prefix=".retain-device-recovery.", dir=stage_dir
)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump({
            "version": 1,
            "status": "rollback-required",
            "hostname": hostname,
            "records": records,
        }, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, marker)
    sync_directory(stage_dir)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PYTHON
    }

    clear_device_recovery() {
        local marker="$stage_dir/.retain-device-recovery"
        python3 - "$marker" "${destinations[@]}" <<'PYTHON'
import hashlib
import json
import os
import re
import stat
import sys

marker = os.path.abspath(sys.argv[1])
destinations = [os.path.abspath(path) for path in sys.argv[2:]]

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

marker_stat = os.lstat(marker)
with open(marker, "rb") as handle:
    marker_bytes = handle.read(2 * 1024 * 1024 + 1)
if len(marker_bytes) != marker_stat.st_size:
    raise SystemExit("device recovery authority changed while being read")
payload = json.loads(marker_bytes.decode("utf-8"))
records = payload.get("records")
if (payload.get("version") != 1 or payload.get("status") != "rollback-required"
        or not isinstance(records, list) or len(records) != len(destinations)):
    raise SystemExit("invalid device recovery authority")
for index, (record, destination) in enumerate(zip(records, destinations)):
    if record.get("index") != index or record.get("destination") != destination:
        raise SystemExit(f"device recovery destination mismatch: {index}")
    stage = record.get("source")
    staged_hash = record.get("staged_sha256")
    if index < len(destinations) - 1:
        if (not isinstance(stage, str) or lexists(stage)
                or not isinstance(staged_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", staged_hash)
                or not regular(destination) or digest(destination) != staged_hash):
            raise SystemExit(f"device generation is incomplete: {index}")
    elif stage is not None or staged_hash is not None or lexists(destination):
        raise SystemExit("retired device artifact was not removed")
    backup = record.get("backup")
    if record.get("original") == "present":
        original_hash = record.get("original_sha256")
        # The rollback copy must still be real and complete until authority is
        # removed; lexists catches a dangling symlink instead of treating it as
        # a missing file.
        if (not isinstance(backup, str) or not lexists(backup)
                or not regular(backup) or digest(backup) != original_hash):
            raise SystemExit(f"device rollback copy is invalid: {index}")
    elif record.get("original") != "missing" or lexists(backup):
        raise SystemExit(f"device rollback presence journal is invalid: {index}")
    if index < len(destinations) - 1:
        with open(destination, "rb") as handle:
            os.fsync(handle.fileno())
directories = {os.path.dirname(path) for path in destinations}
for directory in directories:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
current_marker_stat = os.lstat(marker)
if ((marker_stat.st_dev, marker_stat.st_ino) !=
        (current_marker_stat.st_dev, current_marker_stat.st_ino)):
    raise SystemExit("device recovery authority was swapped before removal")
os.unlink(marker)
try:
    descriptor = os.open(os.path.dirname(marker), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError as sync_error:
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(marker_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException as restore_error:
        raise SystemExit(
            f"device marker unlink was not durable and recreation failed: "
            f"{sync_error}; {restore_error}"
        )
    raise SystemExit(
        f"device marker unlink was not durable; recovery payload retained: {sync_error}"
    )
PYTHON
    }

    sync_device_backup_phase() {
        local marker="$stage_dir/.retain-device-recovery"
        python3 - "$marker" "$backup_dir" "${destinations[@]}" <<'PYTHON'
import hashlib
import json
import os
import stat
import sys

marker = os.path.abspath(sys.argv[1])
backup_dir = os.path.abspath(sys.argv[2])
destinations = [os.path.abspath(value) for value in sys.argv[3:]]

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

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

if not regular(marker):
    raise SystemExit("device recovery authority is missing before backup sync")
with open(marker, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
records = payload.get("records")
if (set(payload) != {"version", "status", "hostname", "records"}
        or payload.get("version") != 1
        or payload.get("status") != "rollback-required"
        or not isinstance(records, list) or len(records) != len(destinations)):
    raise SystemExit("invalid device recovery authority before backup sync")

directories = set()
for index, (record, destination) in enumerate(zip(records, destinations)):
    backup = os.path.join(backup_dir, str(index))
    if (record.get("index") != index or record.get("destination") != destination
            or record.get("backup") != backup):
        raise SystemExit(f"device backup phase path mismatch: {index}")
    if lexists(destination):
        raise SystemExit(f"device old destination still exists: {destination}")
    directories.add(os.path.dirname(destination))
    if record.get("original") == "present":
        if (not lexists(backup) or not regular(backup)
                or digest(backup) != record.get("original_sha256")):
            raise SystemExit(f"device backup phase is incomplete: {index}")
        with open(backup, "rb") as handle:
            os.fsync(handle.fileno())
    elif record.get("original") != "missing" or lexists(backup):
        raise SystemExit(f"device presence journal is inconsistent: {index}")

fsync_directory(backup_dir)
for directory in directories:
    fsync_directory(directory)
PYTHON
    }

    for source in "${sources[@]}"; do
        if [[ ! -f "$source" || -L "$source" ]]; then
            restore_bundle_commit_traps
            return 1
        fi
    done

    if ! mkdir -p "$backup_dir"; then
        restore_bundle_commit_traps
        return 1
    fi
    # Recovery authority must be durable before the first LKG destination move;
    # SIGKILL at any later point therefore leaves a blocker plus the journal.
    if ! mark_device_recovery; then
        rm -f -- "$stage_dir/.retain-device-recovery" 2>/dev/null || true
        restore_bundle_commit_traps
        return 1
    fi

    for index in "${!destinations[@]}"; do
        destination=${destinations[$index]}
        if [[ -f "$backup_dir/$index.present" ]]; then
            mv -f "$destination" "$backup_dir/$index" || {
                if ! recover_device_bundle "$stage_dir"; then
                    echo "CRITICAL: previous device bundle retained at $stage_dir" >&2
                fi
                restore_bundle_commit_traps
                return 1
            }
        fi
    done

    # The rollback generation must be on stable storage before any new file is
    # activated. Otherwise a power loss can persist the new rename while losing
    # the preceding old->backup rename on another destination directory.
    if ! sync_device_backup_phase; then
        if ! recover_device_bundle "$stage_dir"; then
            echo "CRITICAL: previous device bundle retained at $stage_dir" >&2
        fi
        restore_bundle_commit_traps
        return 1
    fi

    for index in "${!sources[@]}"; do
        source=${sources[$index]}
        destination=${destinations[$index]}
        if ! mv -f "$source" "$destination"; then
            # Keep an authority marker before rollback.  If any remove/copy/move
            # fails, the complete backup journal survives cleanup for recovery.
            if ! recover_device_bundle "$stage_dir"; then
                echo "CRITICAL: previous device bundle retained at $stage_dir" >&2
            fi
            restore_bundle_commit_traps
            return 1
        fi
    done
    if ! clear_device_recovery; then
        if [[ ! -e "$stage_dir/.retain-device-recovery" &&
              ! -L "$stage_dir/.retain-device-recovery" ]]; then
            printf 'status=authority-clear-failed\n' \
                > "$stage_dir/.retain-device-recovery" 2>/dev/null || true
        fi
        echo "Could not durably clear device commit recovery authority; recovery payload retained at $stage_dir" >&2
        restore_bundle_commit_traps
        return 1
    fi
    if ! rm -rf "$backup_dir"; then
        # Activation is complete. Failure to discard the obsolete copy is
        # cleanup-only and must not turn a fully committed bundle into a false
        # failed run; the caller/parent cleanup retries it.
        echo "Warning: obsolete device backup remains at $backup_dir" >&2
    fi
    restore_bundle_commit_traps
    return 0
}

# ============================================================================
# OPTIMIZED: Single SSH session collects ALL data
# ============================================================================
execute_commands_optimized() {
    local device=$1
    local user=$2
    local hostname=$3
    local bundle_stage html_temp raw_file carrier_body optical_body

    bundle_stage=$(mktemp -d \
        "$bundle_root/device-${hostname}.XXXXXXXX") || return 1
    # This function runs inside a per-device background subshell. Clean any
    # pre-commit stage on normal return or signal; the commit function masks
    # signals only for its short rollback-capable activation window.
    trap 'if [[ -n "${bundle_stage:-}" && ! -f "$bundle_stage/.retain-device-recovery" ]]; then rm -rf -- "$bundle_stage"; fi' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    html_temp="$bundle_stage/device.html"
    raw_file="$bundle_stage/raw.txt"
    carrier_body="$bundle_stage/carrier.body"
    optical_body="$bundle_stage/optical.body"
    
    # Arrays to store timing data for summary
    declare -a section_names
    declare -a section_times
    
    # Progress output removed for performance
    
    # Create HTML header
    cat > "$html_temp" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Monitor Results - ${hostname}</title>
    <link rel="stylesheet" type="text/css" href="/css/styles2.css">
    <style>
        .config-content {
            background: #1a1a1a;
            border: 1px solid #43453B;
            border-radius: 12px;
            margin: 30px 0;
            padding: 25px;
            min-height: 400px;
            font-family: 'Fira Code', 'Courier New', Courier, monospace;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            overflow-x: auto;
        }
        .comment { color: #6a9955; font-style: italic; }
        .keyword { color: #569cd6; font-weight: bold; }
        .string { color: #ce9178; }
        .number { color: #d7ba7d; }
        .ip-number { color: #ffffff; }
        .variable { color: #9cdcfe; }
        .operator { color: #d4d4d4; }
        .section { color: #dcdcaa; font-weight: bold; }
        .interface { color: #4ec9b0; }
        .ip-address { color: #ffffff; }
        .default { color: #569cd6; }
    </style>
</head>
<body>
    <h1><font color="#b57614">Monitor Results - ${hostname}</font></h1>
    <h3 class='interface-info'>
    <pre>
    <span style="color:tomato;">Created on $DATE</span>

EOF

    if [[ ! -s "$html_temp" ]]; then
        echo "Could not create staged HTML report for ${hostname}" >&2
        rm -rf "$bundle_stage"
        return 1
    fi

    # =========================================================================
    # SINGLE SSH SESSION - Collect ALL data at once
    # =========================================================================
    # Verbose output removed for performance
    local ssh_start=$(date +%s)
    
    timeout 300 ssh $SSH_OPTS -q "$user@$device" '
        HOSTNAME_VAR="'"$hostname"'"
        SKIP_OPTICAL="'"$SKIP_OPTICAL"'"
        SKIP_L1="'"$SKIP_L1"'"
        
        # =====================================================================
        # SECTION 1: Interface Overview (for HTML)
        # =====================================================================
        echo "===HTML_OUTPUT_START==="
        
        echo "<h1></h1><h1><font color=\"#b57614\">Port Status '"$hostname"'</font></h1><h3></h3>"
        printf "<span style=\"color:green;\">%-14s %-12s %-12s %s</span>\n" "Interface" "State" "Link" "Description"
        
        for interface in $(ip link show | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}" | sort -V); do
            if [ -e "/sys/class/net/$interface" ]; then
                state=$(cat /sys/class/net/$interface/operstate 2>/dev/null || echo "unknown")
                link_status=$([ "$state" = "up" ] && echo "up" || echo "down")
                color=$([ "$link_status" = "up" ] && echo "lime" || echo "red")
                description=$(ip link show "$interface" | grep -o "alias.*" | sed "s/alias //")
                [ -z "$description" ] && description="No description"
                # Interface aliases are configuration data, not HTML. Encode
                # the text before it is appended to the generated report.
                description=$(printf "%s" "$description" | sed "s/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g")
                printf "<span style=\"color:steelblue;\">%-14s</span> <span style=\"color:%s;\">%-12s</span> <span style=\"color:%s;\">%-12s</span> %s\n" "$interface" "$color" "$state" "$color" "$link_status" "$description"
            fi
        done

        echo "<h1></h1><h1><font color=\"#b57614\">Interface IP Addresses '"$hostname"'</font></h1><h3></h3>"
        printf "<span style=\"color:green;\">%-20s %-18s %s</span>\n" "Interface" "IPv4" "IPv6 Global"
        
        for interface in $(ip addr show | grep "^[0-9]*:" | cut -d: -f2 | cut -d@ -f1); do
            interface=$(echo "$interface" | xargs)
            ipv4=$(ip addr show "$interface" 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+" | head -1)
            ipv6=$(ip addr show "$interface" 2>/dev/null | grep "inet6.*scope global" | grep -o "[0-9a-f:]\+/[0-9]\+" | head -1)
            if [ -n "$ipv4" ] || [ -n "$ipv6" ]; then
                [ -z "$ipv4" ] && ipv4="-"
                [ -z "$ipv6" ] && ipv6="-"
                printf "<span style=\"color:steelblue;\">%-20s</span> <span style=\"color:orange;\">%-18s</span> <span style=\"color:cyan;\">%s</span>\n" "$interface" "$ipv4" "$ipv6"
            fi
        done

        echo "<h1></h1><h1><font color=\"#b57614\">VLAN Configuration Table '"$hostname"'</font></h1><h3></h3>"
        echo "<pre style=\"font-family:monospace;\">"
        printf "<span style=\"color:green;\">%-20s %-12s %s</span>\n" "PORT" "PVID" "VLANs"
        sudo /usr/sbin/bridge vlan 2>/dev/null | \
          awk '\''BEGIN{cp=""}
               NR==1||NF==0{next}
               NF>=2{
                 if(cp!="") print cp "|" p "|" v
                 cp=$1; p=""; v=$2
                 if($3=="PVID") p=$2
                 next
               }
               NF==1{ v=v"," $1 }
               NF>2&&$3=="PVID"{ p=$2; v=v"," $2 }
               END{ if(cp!="") print cp "|" p "|" v }'\'' | \
          awk -F"|" '\''{
                if($1~/^vxlan/) { n="9999" } else { n="5000" }
                printf "%s|%s|%s|%s\n", n, $1, $2, $3
           }'\'' | sort -t"|" -k1,1n -k2,2V | \
          awk -F"|" '\''{
               port_colored = "<span style=\"color:steelblue;\">" $2 "</span>"
               if($3 != "") { pvid_colored = "PVID=<span style=\"color:lime;\">" $3 "</span>" }
               else { pvid_colored = "PVID=<span style=\"color:gray;\">N/A</span>" }
               vlan_colored = $4
               gsub(/([0-9]+)/, "<span style=\"color:tomato;\">&</span>", vlan_colored)
               port_pad = 20 - length($2)
               if($3 != "") { pvid_text_len = length("PVID=" $3) } else { pvid_text_len = length("PVID=N/A") }
               pvid_pad = 12 - pvid_text_len
               printf "%s%*s %s%*s VLANs=%s\n", port_colored, port_pad, "", pvid_colored, pvid_pad, "", vlan_colored
          }'\''
        echo "</pre>"

        echo "<h1></h1><h1><font color=\"#b57614\">ARP Table '"$hostname"'</font></h1><h3></h3>"
        ip neighbour | grep -E -v "fe80" | sort -t "." -k1,1n -k2,2n -k3,3n -k4,4n | sed -E "s/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/<span style=\"color:tomato;\">\1<\/span>/; s/dev ([^ ]+)/dev <span style=\"color:steelblue;\">\1<\/span>/; s/lladdr ([0-9a-f:]+)/lladdr <span style=\"color:tomato;\">\1<\/span>/"
        
        echo "<h1></h1><h1><font color=\"#b57614\">MAC Table '"$hostname"'</font></h1><h3></h3>"
        sudo /usr/sbin/bridge fdb 2>/dev/null | grep -E -v "00:00:00:00:00:00" | sort | sed -E "s/^([0-9a-f:]+)/<span style=\"color:tomato;\">\1<\/span>/; s/dev ([^ ]+)/dev <span style=\"color:steelblue;\">\1<\/span>/; s/vlan ([0-9]+)/vlan <span style=\"color:red;\">\1<\/span>/; s/dst ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/dst <span style=\"color:lime;\">\1<\/span>/"
        
        echo "<h1></h1><h1><font color=\"#b57614\">BGP Status '"$hostname"'</font></h1><h3></h3>"
        sudo vtysh -c "show bgp vrf all sum" 2>/dev/null | sed -E "s/(VRF\s+)([a-zA-Z0-9_-]+)/\1<span style=\"color:tomato;\">\2<\/span>/g; s/Total number of neighbors ([0-9]+)/Total number of neighbors <span style=\"color:steelblue;\">\1<\/span>/g; s/(\S+)\s+(\S+)\s+Summary/<span style=\"color:lime;\">\1 \2<\/span> Summary/g; s/\b(Active|Idle)\b/<span style=\"color:red;\">\1<\/span>/g"
        
        echo "===HTML_OUTPUT_END==="
        
        # =====================================================================
        # SECTION 2: BGP Data (for analysis)
        # =====================================================================
        echo "===BGP_DATA_START==="
        if ! sudo vtysh -c "show bgp vrf all sum" 2>/dev/null; then
            echo "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY"
        fi
        echo "===BGP_DATA_END==="
        
        # =====================================================================
        # SECTION 2b: EVPN Data (for EVPN route counts)
        # =====================================================================
        echo "===EVPN_DATA_START==="
        # VNI summary - full output
        echo "=== EVPN VNI SUMMARY ==="
        if ! sudo vtysh -c "show evpn vni" 2>/dev/null; then
            echo "__LLDPQ_COLLECTION_ERROR__:EVPN_VNI"
        fi
        # Exact Type-2 and Type-5 route counts.  Do not truncate a combined
        # sample: the analysis needs counts, not thousands of route rows.
        echo "=== EVPN TYPE COUNTS ==="
        _evpn_tmp=$(mktemp /tmp/lldpq-evpn.XXXXXXXX) || {
            echo "__LLDPQ_COLLECTION_ERROR__:EVPN_TEMPFILE"
            _evpn_tmp=""
        }
        if [ -n "$_evpn_tmp" ]; then
            if sudo vtysh -c "show bgp l2vpn evpn" > "$_evpn_tmp" 2>/dev/null; then
                awk '\''
                    index($0, "[2]:") { type2++ }
                    index($0, "[5]:") { type5++ }
                    END {
                        printf "__LLDPQ_EVPN_ROUTE_COUNT__:2:%d\n", type2 + 0
                        printf "__LLDPQ_EVPN_ROUTE_COUNT__:5:%d\n", type5 + 0
                    }
                '\'' "$_evpn_tmp"
            else
                echo "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES"
            fi
            rm -f "$_evpn_tmp"
        fi
        echo "===EVPN_DATA_END==="
        
        # =====================================================================
        # SECTION 2c: Duplicate IP/MAC Data (EVPN dup-detection + FDB + neighbours)
        # =====================================================================
        echo "===DUP_DATA_START==="
        _dup_collection_utc=$(date -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)
        if [ -n "$_dup_collection_utc" ]; then
            echo "__LLDPQ_DUP_COLLECTION_UTC__:${_dup_collection_utc}"
            echo "__LLDPQ_DUP_COVERAGE__:COLLECTION_TIMESTAMP:OK"
        else
            echo "__LLDPQ_DUP_COLLECTION_UTC__:UNKNOWN"
            echo "__LLDPQ_DUP_COVERAGE__:COLLECTION_TIMESTAMP:ERROR"
        fi
        _dup_run() {
            _dup_label="$1"
            shift
            if "$@" 2>/dev/null; then
                echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:OK"
            else
                echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
            fi
        }
        _dup_filter() {
            _dup_label="$1"
            _dup_pattern="$2"
            _dup_cap=800
            shift 2
            _dup_tmp=$(mktemp /tmp/lldpq-dup.XXXXXXXX) || {
                echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_cap}:TRUNCATED=UNKNOWN"
                echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
                return
            }
            _dup_match_tmp=$(mktemp /tmp/lldpq-dup-match.XXXXXXXX) || {
                rm -f "$_dup_tmp"
                echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_cap}:TRUNCATED=UNKNOWN"
                echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
                return
            }
            if "$@" > "$_dup_tmp" 2>/dev/null; then
                grep -Ei "$_dup_pattern" "$_dup_tmp" > "$_dup_match_tmp"
                _dup_grep_status=$?
                if [ "$_dup_grep_status" -eq 0 ] || [ "$_dup_grep_status" -eq 1 ]; then
                    _dup_matches=$(awk "END { print NR }" "$_dup_match_tmp")
                    case "$_dup_matches" in
                        ""|*[!0-9]*)
                            echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_cap}:TRUNCATED=UNKNOWN"
                            echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
                            ;;
                        *)
                            if [ "$_dup_matches" -gt "$_dup_cap" ]; then
                                sed -n "1,${_dup_cap}p" "$_dup_match_tmp"
                                _dup_emitted=$_dup_cap
                                _dup_truncated=YES
                                _dup_coverage=TRUNCATED
                            else
                                cat "$_dup_match_tmp"
                                _dup_emitted=$_dup_matches
                                _dup_truncated=NO
                                _dup_coverage=OK
                            fi
                            echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=${_dup_matches}:EMITTED=${_dup_emitted}:CAP=${_dup_cap}:TRUNCATED=${_dup_truncated}"
                            echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:${_dup_coverage}"
                            ;;
                    esac
                else
                    echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_cap}:TRUNCATED=UNKNOWN"
                    echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
                fi
            else
                echo "__LLDPQ_DUP_SAMPLE_META__:${_dup_label}:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_cap}:TRUNCATED=UNKNOWN"
                echo "__LLDPQ_DUP_COVERAGE__:${_dup_label}:ERROR"
            fi
            rm -f "$_dup_tmp" "$_dup_match_tmp"
        }
        echo "=== DUP VNI MAP ==="
        _dup_run VNI_MAP sudo vtysh -c "show evpn vni"
        echo "=== DUP CONFIG ==="
        _dup_filter CONFIG "duplicate|max-moves[[:space:]]+[0-9]+|time[[:space:]]+[0-9]+|freeze|warning-only" sudo vtysh -c "show evpn"
        echo "=== DUP SELF ==="
        _dup_filter SELF "Local Vtep Ip" sudo vtysh -c "show evpn vni detail"
        echo "=== DUP ARP ==="
        _dup_run ARP_DUPLICATES sudo vtysh -c "show evpn arp-cache vni all duplicate"
        echo "=== DUP MAC ==="
        _dup_run MAC_DUPLICATES sudo vtysh -c "show evpn mac vni all duplicate"
        echo "=== DUP LOG ==="
        if sudo test -r /var/log/frr/frr.log 2>/dev/null; then
            _dup_log_cap=300
            _dup_log_tmp=$(mktemp /tmp/lldpq-dup-log.XXXXXXXX) || {
                echo "__LLDPQ_DUP_SAMPLE_META__:FRR_LOG:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_log_cap}:TRUNCATED=UNKNOWN"
                echo "__LLDPQ_DUP_COVERAGE__:FRR_LOG:ERROR"
                _dup_log_tmp=""
            }
            if [ -n "$_dup_log_tmp" ]; then
                sudo grep -i "detected as duplicate" /var/log/frr/frr.log \
                    > "$_dup_log_tmp" 2>/dev/null
                _dup_log_status=$?
                if [ "$_dup_log_status" -eq 0 ] || [ "$_dup_log_status" -eq 1 ]; then
                    _dup_log_matches=$(awk "END { print NR }" "$_dup_log_tmp")
                    case "$_dup_log_matches" in
                        ""|*[!0-9]*)
                            echo "__LLDPQ_DUP_SAMPLE_META__:FRR_LOG:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_log_cap}:TRUNCATED=UNKNOWN"
                            echo "__LLDPQ_DUP_COVERAGE__:FRR_LOG:ERROR"
                            ;;
                        *)
                            if [ "$_dup_log_matches" -gt "$_dup_log_cap" ]; then
                                tail -n "$_dup_log_cap" "$_dup_log_tmp"
                                _dup_log_emitted=$_dup_log_cap
                                _dup_log_truncated=YES
                                _dup_log_coverage=TRUNCATED
                            else
                                cat "$_dup_log_tmp"
                                _dup_log_emitted=$_dup_log_matches
                                _dup_log_truncated=NO
                                _dup_log_coverage=OK
                            fi
                            echo "__LLDPQ_DUP_SAMPLE_META__:FRR_LOG:MATCHES=${_dup_log_matches}:EMITTED=${_dup_log_emitted}:CAP=${_dup_log_cap}:TRUNCATED=${_dup_log_truncated}"
                            echo "__LLDPQ_DUP_COVERAGE__:FRR_LOG:${_dup_log_coverage}"
                            ;;
                    esac
                else
                    echo "__LLDPQ_DUP_SAMPLE_META__:FRR_LOG:MATCHES=UNKNOWN:EMITTED=0:CAP=${_dup_log_cap}:TRUNCATED=UNKNOWN"
                    echo "__LLDPQ_DUP_COVERAGE__:FRR_LOG:ERROR"
                fi
                rm -f "$_dup_log_tmp"
            fi
        else
            echo "__LLDPQ_DUP_SAMPLE_META__:FRR_LOG:MATCHES=UNKNOWN:EMITTED=0:CAP=300:TRUNCATED=UNKNOWN"
            echo "__LLDPQ_DUP_COVERAGE__:FRR_LOG:ERROR"
        fi
        # MAC / IP mobility: entries whose EVPN sequence number is >= 10 (a 2+ digit local or
        # remote seq). Works even where dup-address-detection is OFF (EVPN-MH), because the
        # mobility sequence is ALWAYS tracked. Stable MACs (0/0) and normal failovers (<10)
        # are filtered out on-device to keep this small.
        echo "=== DUP MACMOB ==="
        _dup_filter MAC_MOBILITY "^VNI |[0-9][0-9]+/[0-9]+$|/[0-9][0-9]+$" sudo vtysh -c "show evpn mac vni all"
        echo "=== DUP ARPMOB ==="
        _dup_filter ARP_MOBILITY "^VNI |[0-9][0-9]+/[0-9]+$|/[0-9][0-9]+$" sudo vtysh -c "show evpn arp-cache vni all"
        # Interface descriptions (nv set interface swpX description = kernel ifalias): names the
        # device attached to each switch:port so the analysis can show WHICH box is duplicating.
        echo "=== DUP IFALIAS ==="
        for _f in /sys/class/net/*/ifalias; do _a=$(cat "$_f" 2>/dev/null); [ -n "$_a" ] && echo "$(basename "$(dirname "$_f")")|$_a"; done
        echo "__LLDPQ_DUP_COVERAGE__:IFALIAS:OK"
        unset -f _dup_run _dup_filter 2>/dev/null || true
        echo "===DUP_DATA_END==="
        
        echo "===FDB_DATA_START==="
        _fdb_output=$(sudo /usr/sbin/bridge fdb show 2>/dev/null)
        _fdb_status=$?
        if [ "$_fdb_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:FDB"
        else
            printf "%s\n" "$_fdb_output" | grep -E -v "00:00:00:00:00:00" || true
        fi
        echo "===FDB_DATA_END==="
        
        echo "===NEIGH_DATA_START==="
        if ! ip -4 neighbour show 2>/dev/null; then
            echo "__LLDPQ_COLLECTION_ERROR__:NEIGH"
        fi
        echo "===NEIGH_DATA_END==="
        
        # =====================================================================
        # SECTION 3: Carrier Transitions (for flap analysis)
        # =====================================================================
        echo "===CARRIER_DATA_START==="
        _link_output=$(ip link show 2>/dev/null)
        _link_status=$?
        if [ "$_link_status" -ne 0 ]; then
            echo "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY"
        fi
        all_interfaces=$(printf "%s\n" "$_link_output" | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}")
        for interface in $all_interfaces; do
            if [ -e "/sys/class/net/$interface" ]; then
                carrier_count=$(cat /sys/class/net/$interface/carrier_changes 2>/dev/null || echo "0")
                echo "$interface:$carrier_count"
            fi
        done
        echo "===CARRIER_DATA_END==="
        
        # =====================================================================
        # SECTION 4: Optical Transceiver Data (skippable with -s flag)
        # =====================================================================
        echo "===OPTICAL_DATA_START==="
        if [ "$SKIP_OPTICAL" != "true" ]; then
            _optical_links=$(ip link show 2>/dev/null)
            _optical_links_status=$?
            if [ "$_optical_links_status" -ne 0 ]; then
                echo "__LLDPQ_COLLECTION_ERROR__:OPTICAL_LINK_INVENTORY"
            else
                all_interfaces=$(printf "%s\n" "$_optical_links" | awk "/^[0-9]+: swp[0-9]+[s0-9]*/ {gsub(/:/, \"\", \$2); print \$2}")
                for interface in $all_interfaces; do
                    echo "--- Interface: $interface"
                    if [ ! -e "/sys/class/net/$interface" ]; then
                        echo "Interface state: unknown"
                        echo "No transceiver data"
                        continue
                    fi
                    state=$(cat "/sys/class/net/$interface/operstate" 2>/dev/null || echo "unknown")
                    echo "Interface state: ${state:-unknown}"
                    if [ "$state" = "up" ]; then
                        ethtool_output=$(sudo ethtool -m "$interface" 2>/dev/null || true)
                        if [ -n "$ethtool_output" ]; then
                            echo "$ethtool_output"
                        else
                            echo "No transceiver data"
                        fi
                    else
                        echo "No transceiver data"
                    fi
                done
            fi
        fi
        echo "===OPTICAL_DATA_END==="
        
        # =====================================================================
        # SECTION 5: BER/Interface Statistics
        # =====================================================================
        echo "===BER_DATA_START==="
        if ! cat /proc/net/dev 2>/dev/null; then
            echo "__LLDPQ_COLLECTION_ERROR__:INTERFACE_COUNTERS"
        fi
        echo "===BER_DATA_END==="
        
        # =====================================================================
        # SECTION 6: L1-Show (if available)
        # =====================================================================
        echo "===L1_DATA_START==="
        if [ "$SKIP_L1" = "true" ]; then
            echo "l1-show skipped"
        elif command -v l1-show >/dev/null 2>&1; then
            sudo l1-show all -p 2>/dev/null || echo "l1-show failed"
        else
            echo "l1-show not available"
        fi
        echo "===L1_DATA_END==="
        
        # =====================================================================
        # SECTION 7: Hardware Health (with fallback)
        # =====================================================================
        echo "===HARDWARE_DATA_START==="
        echo "HARDWARE_HEALTH:"
        if command -v sensors >/dev/null 2>&1; then
            _hardware_output=$(sensors 2>/dev/null)
            _hardware_status=$?
            if [ "$_hardware_status" -eq 0 ]; then
                echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:OK"
                printf "%s\n" "$_hardware_output"
            else
                echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:ERROR"
                echo "No sensors available"
            fi
        else
            echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:UNAVAILABLE"
            echo "No sensors available"
        fi
        echo "HW_MGMT_THERMAL:"
        asic_raw=""
        for asic_file in /var/run/hw-management/thermal/asic /run/hw-management/thermal/asic /var/run/hw-management/thermal/asic1 /run/hw-management/thermal/asic1; do
            if [ -e "$asic_file" ]; then
                asic_raw=$(sudo -n cat "$asic_file" 2>/dev/null || cat "$asic_file" 2>/dev/null || echo "")
                if [ -n "$asic_raw" ]; then
                    break
                fi
            fi
        done
        if [ -n "$asic_raw" ]; then
            awk "BEGIN{printf \"HW_MGMT_ASIC: %.1f\n\", $asic_raw/1000}"
        else
            # Fallback: Try alternative ASIC temperature sources
            echo "ASIC_FALLBACK_DEBUG:"
            # Check thermal zones
            for zone in /sys/class/thermal/thermal_zone*/type; do
                if [ -r "$zone" ]; then
                    zone_type=$(cat "$zone" 2>/dev/null)
                    if echo "$zone_type" | grep -qi "asic\|switch\|mlxsw"; then
                        zone_dir=$(dirname "$zone")
                        temp_file="$zone_dir/temp"
                        if [ -r "$temp_file" ]; then
                            temp_raw=$(cat "$temp_file" 2>/dev/null)
                            if [ -n "$temp_raw" ] && [ "$temp_raw" -gt 0 ]; then
                                awk "BEGIN{printf \"THERMAL_ZONE_ASIC: %.1f\n\", $temp_raw/1000}"
                                break
                            fi
                        fi
                    fi
                fi
            done
            # Check hwmon for ASIC
            for hwmon in /sys/class/hwmon/hwmon*/temp*_label; do
                if [ -r "$hwmon" ]; then
                    label=$(cat "$hwmon" 2>/dev/null)
                    if echo "$label" | grep -qi "asic\|switch"; then
                        temp_file=$(echo "$hwmon" | sed "s/_label$/_input/")
                        if [ -r "$temp_file" ]; then
                            temp_raw=$(cat "$temp_file" 2>/dev/null)
                            if [ -n "$temp_raw" ] && [ "$temp_raw" -gt 0 ]; then
                                awk "BEGIN{printf \"HWMON_ASIC: %.1f\n\", $temp_raw/1000}"
                                break
                            fi
                        fi
                    fi
                fi
            done
        fi
        cpu_raw=""
        for cpu_file in /var/run/hw-management/thermal/cpu_pack /run/hw-management/thermal/cpu_pack; do
            if [ -e "$cpu_file" ]; then
                cpu_raw=$(sudo -n cat "$cpu_file" 2>/dev/null || cat "$cpu_file" 2>/dev/null || echo "")
                if [ -n "$cpu_raw" ]; then
                    break
                fi
            fi
        done
        if [ -n "$cpu_raw" ]; then
            awk "BEGIN{printf \"HW_MGMT_CPU: %.1f\n\", $cpu_raw/1000}"
        fi
        echo "MEMORY_INFO:"
        _hardware_output=$(free -h 2>/dev/null)
        _hardware_status=$?
        if [ "$_hardware_status" -eq 0 ]; then
            echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:MEMORY:OK"
            printf "%s\n" "$_hardware_output"
        else
            echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:MEMORY:ERROR"
            echo "No memory info"
        fi
        echo "CPU_INFO:"
        _hardware_output=$(cat /proc/loadavg 2>/dev/null)
        _hardware_status=$?
        if [ "$_hardware_status" -eq 0 ]; then
            echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:OK"
            printf "%s\n" "$_hardware_output"
        else
            echo "__LLDPQ_HARDWARE_SOURCE_STATUS__:CPU_LOAD:ERROR"
            echo "No CPU info"
        fi
        echo "CPU_CORES: $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 0)"
        echo "===HARDWARE_DATA_END==="
        
        # =====================================================================
        # SECTION 8: System Logs (comprehensive)
        # =====================================================================
        echo "===LOG_DATA_START==="
        echo "=== COMPREHENSIVE SYSTEM LOGS ==="
        _lldpq_log_status() {
            printf "__LLDPQ_LOG_SOURCE_STATUS__:%s:%s\n" "$1" "$2"
        }
        
        # FRR Routing Logs
        echo "FRR_ROUTING_LOGS:"
        if systemctl is-active --quiet frr 2>/dev/null; then
            _source_output=$(sudo journalctl -u frr --since="2 hours ago" --no-pager --lines=200 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status FRR OK
                printf "%s\n" "$_source_output" | grep -E "(ERROR|WARN|CRIT|FAIL|DOWN|BGP|neighbor|peer)" || echo "No recent FRR routing issues"
            else
                _lldpq_log_status FRR ERROR
            fi
        elif [ -f "/var/log/frr/frr.log" ]; then
            _source_output=$(sudo cat /var/log/frr/frr.log 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status FRR OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -Ei "(error|warn|crit|fail|down|bgp)" || echo "No recent FRR routing issues"
            else
                _lldpq_log_status FRR ERROR
            fi
        else
            _lldpq_log_status FRR UNAVAILABLE
            echo "FRR service/log not available"
        fi
        
        # Switch daemon logs
        echo "SWITCHD_LOGS:"
        if systemctl is-active --quiet switchd 2>/dev/null; then
            _source_output=$(sudo journalctl -u switchd --since="2 hours ago" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status SWITCHD OK
                printf "%s\n" "$_source_output" | grep -E "(ERROR|WARN|CRIT|FAIL|EXCEPT|port|link|vlan)" || echo "No recent switchd issues"
            else
                _lldpq_log_status SWITCHD ERROR
            fi
        elif [ -f "/var/log/switchd.log" ]; then
            _source_output=$(sudo cat /var/log/switchd.log 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status SWITCHD OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -Ei "(error|warn|crit|fail|except)" || echo "No recent switchd issues"
            else
                _lldpq_log_status SWITCHD ERROR
            fi
        else
            _lldpq_log_status SWITCHD UNAVAILABLE
            echo "Switchd service/log not available"
        fi
        
        # NVUE configuration logs
        echo "NVUE_CONFIG_LOGS:"
        if systemctl is-active --quiet nvued 2>/dev/null; then
            _source_output=$(sudo journalctl -u nvued --since="2 hours ago" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status NVUE OK
                printf "%s\n" "$_source_output" | grep -E "(ERROR|WARN|FAIL|EXCEPT|config|commit|rollback)" || echo "No recent NVUE config issues"
            else
                _lldpq_log_status NVUE ERROR
            fi
        elif [ -f "/var/log/nvued.log" ]; then
            _source_output=$(sudo cat /var/log/nvued.log 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status NVUE OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -E "(ERROR|WARN|FAIL|EXCEPT|config|commit|rollback)" || echo "No recent NVUE config issues"
            else
                _lldpq_log_status NVUE ERROR
            fi
        else
            _lldpq_log_status NVUE UNAVAILABLE
            echo "NVUE log not found"
        fi
        
        # Spanning Tree Protocol logs
        echo "MSTPD_STP_LOGS:"
        if systemctl is-active --quiet mstpd 2>/dev/null; then
            _source_output=$(sudo journalctl -u mstpd --since="2 hours ago" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status MSTPD OK
                printf "%s\n" "$_source_output" | grep -E "(ERROR|WARN|TOPOLOGY|CHANGE|port|state|bridge)" || echo "No recent STP issues"
            else
                _lldpq_log_status MSTPD ERROR
            fi
        elif [ -f "/var/log/mstpd" ]; then
            _source_output=$(sudo cat /var/log/mstpd 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status MSTPD OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -E "(ERROR|WARN|TOPOLOGY|CHANGE|port|state|bridge)" || echo "No recent STP issues"
            else
                _lldpq_log_status MSTPD ERROR
            fi
        else
            _lldpq_log_status MSTPD UNAVAILABLE
            echo "MSTPD log not found"
        fi
        
        # MLAG coordination logs
        echo "CLAGD_MLAG_LOGS:"
        if systemctl is-active --quiet clagd 2>/dev/null; then
            _source_output=$(sudo journalctl -u clagd --since="2 hours ago" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status CLAGD OK
                printf "%s\n" "$_source_output" | grep -E "(ERROR|WARN|FAIL|CONFLICT|PEER|bond|backup|primary)" || echo "No recent MLAG issues"
            else
                _lldpq_log_status CLAGD ERROR
            fi
        elif [ -f "/var/log/clagd.log" ]; then
            _source_output=$(sudo cat /var/log/clagd.log 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status CLAGD OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -E "(ERROR|WARN|FAIL|CONFLICT|PEER|bond|backup|primary)" || echo "No recent MLAG issues"
            else
                _lldpq_log_status CLAGD ERROR
            fi
        else
            _lldpq_log_status CLAGD UNAVAILABLE
            echo "CLAG log not found"
        fi
        
        # Authentication and security logs
        echo "AUTH_SECURITY_LOGS:"
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            _source_output=$(sudo journalctl --since="2 hours ago" --grep="FAIL|ERROR|INVALID|DENIED|ATTACK|authentication|unauthorized" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status AUTH OK
                printf "%s\n" "$_source_output" | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|--since|--grep|swp\|bond\|vlan\|carrier\|link|vtysh|sudo.*authentication.*grantor=pam_permit|USER_AUTH.*res=success)" || echo "No recent auth issues"
            else
                _lldpq_log_status AUTH ERROR
            fi
        elif [ -f "/var/log/auth.log" ]; then
            _source_output=$(sudo cat /var/log/auth.log 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                _lldpq_log_status AUTH OK
                printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -30 | grep -E "(FAIL|ERROR|INVALID|DENIED|ATTACK|authentication|unauthorized)" | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|--since|swp\|bond\|vlan\|carrier\|link|vtysh|sudo.*authentication.*grantor=pam_permit|USER_AUTH.*res=success)" || echo "No recent auth issues"
            else
                _lldpq_log_status AUTH ERROR
            fi
        else
            _lldpq_log_status AUTH UNAVAILABLE
            echo "Auth log not found"
        fi
        
        # System critical logs
        echo "SYSTEM_CRITICAL_LOGS:"
        CRITICAL_LOGS=""
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            CRITICAL_LOGS=$(sudo journalctl --since="2 hours ago" --priority=0..3 --grep="ERROR|CRIT|ALERT|EMERG|FAIL|kernel|oom|segfault" --no-pager --lines=50 2>/dev/null)
            _source_status=$?
        elif [ -f "/var/log/syslog" ]; then
            _source_output=$(sudo cat /var/log/syslog 2>/dev/null)
            _source_status=$?
            if [ "$_source_status" -eq 0 ]; then
                CRITICAL_LOGS=$(printf "%s\n" "$_source_output" | grep "$(date '\''+%b %d'\'')" | tail -50 | grep -E "(ERROR|CRIT|ALERT|EMERG|FAIL|kernel|oom|segfault)" || true)
            fi
        else
            _source_status=2
        fi
        if [ "$_source_status" -eq 0 ]; then
            _lldpq_log_status SYSTEM_CRITICAL OK
        elif [ "$_source_status" -eq 2 ]; then
            _lldpq_log_status SYSTEM_CRITICAL UNAVAILABLE
        else
            _lldpq_log_status SYSTEM_CRITICAL ERROR
        fi
        if [ -n "$CRITICAL_LOGS" ]; then
            echo "$CRITICAL_LOGS"
        else
            echo "No system critical logs"
        fi
        
        # High priority journalctl logs
        echo "JOURNALCTL_PRIORITY_LOGS:"
        _source_output=$(sudo journalctl --since="3 hours ago" --priority=0..3 --no-pager --lines=75 2>/dev/null)
        _source_status=$?
        if [ "$_source_status" -eq 0 ]; then
            _lldpq_log_status JOURNAL_PRIORITY OK
            printf "%s\n" "$_source_output" | grep -Ei "(CRIT|ALERT|EMERG|ERROR|fail|crash|panic)" || echo "No high priority journal logs"
        else
            _lldpq_log_status JOURNAL_PRIORITY ERROR
        fi
        
        # Hardware and kernel critical messages
        echo "DMESG_HARDWARE_LOGS:"
        _source_output=$(sudo dmesg --since="3 hours ago" --level=crit,alert,emerg 2>/dev/null)
        _source_status=$?
        if [ "$_source_status" -eq 0 ]; then
            _lldpq_log_status DMESG OK
            if [ -n "$_source_output" ]; then printf "%s\n" "$_source_output" | tail -40; else echo "No critical hardware logs"; fi
        else
            _lldpq_log_status DMESG ERROR
        fi
        
        # Network interface state changes
        echo "NETWORK_INTERFACE_LOGS:"
        _source_output=$(sudo journalctl --since="3 hours ago" --grep="swp|bond|vlan|carrier|link.*up|link.*down|port.*up|port.*down" --no-pager --lines=40 2>/dev/null)
        _source_status=$?
        if [ "$_source_status" -eq 0 ]; then
            _lldpq_log_status NETWORK_INTERFACE OK
            printf "%s\n" "$_source_output" | grep -v -E "(journalctl|monitor\.sh|monitor2\.sh|sudo.*journalctl)" || echo "No interface state changes"
        else
            _lldpq_log_status NETWORK_INTERFACE ERROR
        fi
        
        echo "===LOG_DATA_END==="
        
        
    ' > "$raw_file" 2>/dev/null
    local ssh_status=$?

    if [[ $ssh_status -ne 0 ]] || ! validate_collection_bundle "$raw_file"; then
        echo "Data collection failed for ${hostname} (ssh status ${ssh_status})" >&2
        rm -rf "$bundle_stage"
        if [[ $ssh_status -ne 0 ]]; then
            return "$ssh_status"
        fi
        return 1
    fi
    
    local ssh_end=$(date +%s)
    local ssh_duration=$((ssh_end - ssh_start))
    section_names+=("SSH Data Collection")
    section_times+=("$ssh_duration")
    
    # =========================================================================
    # Parse raw data into separate files
    # =========================================================================
    local parse_start=$(date +%s)
    
    if ! extract_collection_section "$raw_file" HTML_OUTPUT \
            "$bundle_stage/html.body" ||
       ! cat "$bundle_stage/html.body" >> "$html_temp" ||
       ! extract_collection_section "$raw_file" BGP_DATA \
            "$bundle_stage/bgp.txt" ||
       ! extract_collection_section "$raw_file" EVPN_DATA \
            "$bundle_stage/evpn.txt" ||
       ! extract_collection_section "$raw_file" DUP_DATA \
            "$bundle_stage/dup.txt" ||
       ! extract_collection_section "$raw_file" FDB_DATA \
            "$bundle_stage/fdb.txt" ||
       ! extract_collection_section "$raw_file" NEIGH_DATA \
            "$bundle_stage/neigh.txt" ||
       ! extract_collection_section "$raw_file" CARRIER_DATA "$carrier_body" ||
       ! extract_collection_section "$raw_file" OPTICAL_DATA "$optical_body" ||
       ! extract_collection_section "$raw_file" BER_DATA \
            "$bundle_stage/ber.txt" ||
       ! extract_collection_section "$raw_file" L1_DATA \
            "$bundle_stage/l1.txt" ||
       ! extract_collection_section "$raw_file" HARDWARE_DATA \
            "$bundle_stage/hardware.txt" ||
       ! extract_collection_section "$raw_file" LOG_DATA \
            "$bundle_stage/logs.txt"; then
        echo "Could not stage the complete collection bundle for ${hostname}" >&2
        rm -rf "$bundle_stage"
        return 1
    fi

    {
        echo "=== CARRIER TRANSITIONS ==="
        cat "$carrier_body"
    } > "$bundle_stage/carrier.txt" || {
        rm -rf "$bundle_stage"
        return 1
    }
    {
        echo "=== OPTICAL DIAGNOSTICS ==="
        cat "$optical_body"
    } > "$bundle_stage/optical.txt" || {
        rm -rf "$bundle_stage"
        return 1
    }
    rm -f "$raw_file" "$bundle_stage/html.body" "$carrier_body" "$optical_body"
    
    local parse_end=$(date +%s)
    local parse_duration=$((parse_end - parse_start))
    section_names+=("Data Processing")
    section_times+=("$parse_duration")
    
    # Add config section to HTML
    local config_start=$(date +%s)
    
    cat >> "$html_temp" << EOF

<h1></h1><h1><font color="#b57614">Device Configuration - ${hostname}</font></h1><h3></h3>
EOF

    if [ -f "$WEB_ROOT/configs/${hostname}.txt" ]; then
        echo "<h2><font color='steelblue'>NV Set Commands</font></h2>" >> "$html_temp"
        echo "<div class='config-content' id='config-content'>" >> "$html_temp"
        cat "$WEB_ROOT/configs/${hostname}.txt" | sed '
            s/</\&lt;/g; s/>/\&gt;/g;
            s/^#.*/<span class="comment">&<\/span>/;
            /description/ {
                s/\(.*\)\(description\s\+\)\(.*\)$/\1\2<span class="comment">\3<\/span>/;
            }
        ' >> "$html_temp"
        echo "</div>" >> "$html_temp"
    else
        echo "<p><span style='color: orange;'>⚠️  Configuration not available for ${hostname}</span></p>" >> "$html_temp"
    fi
    
    # Close HTML
    cat >> "$html_temp" << EOF
    </pre>
    </h3>
    <span style="color:tomato;">Created on $DATE</span>
</body>
</html>
EOF

    if ! grep -q '</html>' "$html_temp"; then
        echo "Staged HTML report is incomplete for ${hostname}" >&2
        rm -rf "$bundle_stage"
        return 1
    fi

    local config_end=$(date +%s)
    local config_duration=$((config_end - config_start))
    section_names+=("Configuration Section")
    section_times+=("$config_duration")

    if ! commit_device_bundle "$bundle_stage" "$hostname"; then
        echo "Could not activate the collection bundle for ${hostname}" >&2
        if [[ ! -f "$bundle_stage/.retain-device-recovery" ]]; then
            rm -rf "$bundle_stage"
        fi
        return 1
    fi
    rm -rf "$bundle_stage"

    # Silent completion - no per-device output for performance
    return 0
}

process_device() {
    local device=$1
    local user=$2
    local hostname=$3
    ping_test "$device" "$hostname"
    if [ $? -eq 0 ]; then
        execute_commands_optimized "$device" "$user" "$hostname"
        return $?
    fi
    # Do not let a previous raw snapshot or per-device page look current. The
    # aggregate run may still succeed for the rest of the fabric, while this
    # device gets an explicit unavailable page and asset status.
    clear_current_device_artifacts "$hostname" || return 1
    write_unreachable_device_report "$device" "$hostname"
}

# ============================================================================
# PARALLEL EXECUTION WITH LIMIT
# ============================================================================
# Parallel monitoring started
mkdir -p "$bundle_parent" || exit 1
chmod 700 "$bundle_parent" || exit 1
# The process-wide flock is already held. Ordinary old staging trees are safe
# to remove, but a rollback-failure tree is the only recovery copy and must be
# retried before a new collection can advance analyzer state.
while IFS= read -r -d '' previous_bundle; do
    bundle_root="$previous_bundle"
    retained_recovery_failed=false
    recovery_bundle_must_be_preserved=false
    analysis_marker="$previous_bundle/.retain-analysis-recovery"
    if [[ -e "$analysis_marker" || -L "$analysis_marker" ]]; then
        if ! validate_analysis_recovery_authority; then
            echo "CRITICAL: retained analyzer authority is unsafe: $bundle_root" >&2
            retained_recovery_failed=true
            recovery_bundle_must_be_preserved=true
        else
            analysis_backup_dir="$bundle_root/analysis-backup"
            analysis_transaction_active=true
            if ! rollback_analysis_state; then
                echo "CRITICAL: retained analyzer recovery still cannot be restored: $bundle_root" >&2
                retained_recovery_failed=true
                recovery_bundle_must_be_preserved=true
            fi
        fi
    fi
    if [[ "$retained_recovery_failed" != "true" ]] &&
       find "$previous_bundle" -name '.retain-device-recovery' -print -quit \
            2>/dev/null | grep -q .; then
        device_recovery_failed=false
        while IFS= read -r -d '' device_marker; do
            device_stage=${device_marker%/.retain-device-recovery}
            if ! recover_device_bundle "$device_stage"; then
                device_recovery_failed=true
                break
            fi
        done < <(find "$previous_bundle" -mindepth 2 -maxdepth 2 -type f \
            -name '.retain-device-recovery' -print0)
        if [[ "$device_recovery_failed" == "true" ]] ||
           find "$previous_bundle" -name '.retain-device-recovery' -print -quit \
               2>/dev/null | grep -q .; then
            echo "CRITICAL: unresolved device bundle recovery is retained at $bundle_root" >&2
            echo "Refusing a new collection so the last-known-good raw bundle is not lost." >&2
            retained_recovery_failed=true
        fi
    fi
    if [[ "$retained_recovery_failed" == "true" ]]; then
        exit 1
    fi
    rm -rf -- "$bundle_root" || exit 1
    bundle_root=""
    analysis_backup_dir=""
done < <(find "$bundle_parent" -mindepth 1 -maxdepth 1 -type d \
    -name 'run-*' -print0)
# Recovery does not depend on the current inventory. Parse it only after every
# retained transaction has been settled, so a temporarily malformed inventory
# can never prevent restoration of the prior last-known-good generation.
# Runtime configuration is likewise delayed until recovery is complete; the
# local journals encode and validate their own fixed destinations.
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
bundle_root=$(mktemp -d "$bundle_parent/run-XXXXXXXX") || exit 1
chmod 700 "$bundle_root" || exit 1

monitor_run_started=true
if ! mark_reports_in_progress; then
    echo "Could not mark monitoring reports as in-progress" >&2
    exit 1
fi

total_devices=${#devices[@]}
completed_file="/tmp/monitor_completed_$$"
echo "0" > "$completed_file"

# Simple parallel execution without animation (animation causes hangs)
declare -a collection_pids=()
declare -a collection_labels=()
declare -a collection_failures=()
next_collection_wait=0
active_collection_jobs=0
device_count=0

wait_for_collection_job() {
    local index=$1
    local status
    if wait "${collection_pids[$index]}"; then
        status=0
    else
        status=$?
        collection_failures+=("${collection_labels[$index]}:${status}")
    fi
    return 0
}

for device in "${!devices[@]}"; do
    IFS=' ' read -r user hostname <<< "${devices[$device]}"
    
    process_device "$device" "$user" "$hostname" 9>&- &
    collection_pids+=("$!")
    collection_labels+=("$hostname")
    ((active_collection_jobs++))
    ((device_count++))
    
    # Wait if we hit the parallel limit
    if [ "$active_collection_jobs" -ge "$MAX_PARALLEL" ]; then
        wait_for_collection_job "$next_collection_wait"
        ((next_collection_wait++))
        ((active_collection_jobs--))
    fi
done

# Wait for all remaining jobs
while [ "$next_collection_wait" -lt "${#collection_pids[@]}" ]; do
    wait_for_collection_job "$next_collection_wait"
    ((next_collection_wait++))
done
echo "Collected $device_count devices"
data_collection_end=$(date +%s)
data_collection_duration=$((data_collection_end - START_TIME))

if [ "${#collection_failures[@]}" -gt 0 ]; then
    failure_text="collection jobs failed: ${collection_failures[*]}"
    mark_reports_stale "$failure_text"
    exit 1
fi

# ============================================================================
# PARALLEL ANALYSIS PHASE
# ============================================================================
echo "Analyzing..."
analysis_start=$(date +%s)

if ! snapshot_analysis_state; then
    mark_reports_stale "could not snapshot analyzer state"
    exit 1
fi

# Run all analyses in parallel and retain each status/log independently.
analysis_log_dir=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-analysis.XXXXXX") || exit 1
declare -a analysis_pids=()
declare -a analysis_labels=()
declare -a analysis_logs=()
declare -a analysis_failures=()

start_analysis() {
    local label=$1
    shift
    local log_file="$analysis_log_dir/${label}.log"
    "$@" >"$log_file" 2>&1 9>&- &
    analysis_pids+=("$!")
    analysis_labels+=("$label")
    analysis_logs+=("$log_file")
}

validate_analysis_outputs() {
    local marker="$1" relative path
    local -a required=(
        bgp-analysis.html bgp_history.json
        link-flap-analysis.html flap_history.json
        ber-analysis.html ber_history.json ber_baseline.json
        hardware-analysis.html
        log-analysis.html log_summary.json
        duplicate-analysis.html dup-data/dup_seq_state.json dup-data/dup_ip_state.json
    )
    local -a json_files=(
        bgp_history.json flap_history.json ber_history.json ber_baseline.json
        log_summary.json dup-data/dup_seq_state.json dup-data/dup_ip_state.json
    )
    if [[ "$SKIP_OPTICAL" != "true" ]]; then
        required+=(optical-analysis.html optical_history.json)
        json_files+=(optical_history.json)
    fi

    for relative in "${required[@]}"; do
        path="$SCRIPT_DIR/monitor-results/$relative"
        if [[ ! -f "$path" || ! -s "$path" || "$path" -ot "$marker" ]]; then
            echo "Analysis output missing, empty, or not refreshed: $relative" >&2
            return 1
        fi
    done

    python3 - "$SCRIPT_DIR/monitor-results" "${json_files[@]}" <<'PYTHON'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
for relative in sys.argv[2:]:
    path = root / relative
    try:
        with path.open("r", encoding="utf-8") as handle:
            json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
        print(f"Invalid analysis JSON {relative}: {exc}", file=sys.stderr)
        raise SystemExit(1)
PYTHON
}

analysis_output_marker="$analysis_log_dir/.analysis-start"
: > "$analysis_output_marker" || exit 1
start_analysis bgp python3 process_bgp_data.py
start_analysis flap python3 process_flap_data.py
if [[ "$SKIP_OPTICAL" != "true" ]]; then
    start_analysis optical python3 process_optical_data.py
fi
start_analysis ber python3 process_ber_data.py
start_analysis hardware python3 process_hardware_data.py
start_analysis log python3 process_log_data.py
start_analysis duplicate python3 process_duplicate_data.py

for index in "${!analysis_pids[@]}"; do
    if wait "${analysis_pids[$index]}"; then
        status=0
    else
        status=$?
        analysis_failures+=("${analysis_labels[$index]}:${status}")
        echo "Analysis '${analysis_labels[$index]}' failed with status ${status}:" >&2
        tail -20 "${analysis_logs[$index]}" >&2 || true
    fi
done

analysis_end=$(date +%s)
analysis_duration=$((analysis_end - analysis_start))

if [ "${#analysis_failures[@]}" -gt 0 ]; then
    failure_text="analysis jobs failed: ${analysis_failures[*]}"
    rollback_analysis_state || failure_text="$failure_text; analyzer rollback incomplete"
    mark_reports_stale "$failure_text"
    exit 1
fi

if ! validate_analysis_outputs "$analysis_output_marker"; then
    rollback_analysis_state || true
    mark_reports_stale "analysis outputs were incomplete"
    exit 1
fi

if ! write_current_manifest; then
    rollback_analysis_state || true
    mark_reports_stale "could not write current-run manifest"
    exit 1
fi

# ============================================================================
# COPY RESULTS
# ============================================================================
# Keep the local in-progress marker until the complete web tree is active.
# check_alerts reads the source tree and must never accept a manifest whose web
# publication can still fail.
if ! publish_monitor_results; then
    rollback_analysis_state || true
    mark_reports_stale "report publication failed"
    exit 1
fi
if ! commit_analysis_state; then
    mark_reports_stale "published reports but could not remove analyzer rollback snapshot"
    exit 1
fi
if ! clear_stale_marker; then
    mark_reports_stale "could not clear stale report marker"
    exit 1
fi

# Calculate execution time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo "Done: ${#devices[@]} devices, ${MINUTES}m${SECONDS}s (collect:${data_collection_duration}s, analyze:${analysis_duration}s)"
exit 0
