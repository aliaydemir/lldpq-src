#!/bin/bash
# provision-api.sh - Provision API (ZTP + Base Config)
# Backend for provision.html
# Called by nginx fcgiwrap

# Upgrade workers are internal detached processes started by this CGI.  They do
# not emit HTTP and must not depend on a browser request remaining open.
UPGRADE_WORKER_MODE=false
UPGRADE_JOB_ID=""
DISCOVERY_WORKER_MODE=false
DISCOVERY_SCHEDULE_MODE=false
UPGRADE_RESUME_MODE=false
DISCOVERY_JOB_ID=""
case "${1:-}" in
    --upgrade-worker)
        [[ "${2:-}" =~ ^[a-f0-9-]{36}$ ]] || exit 2
        UPGRADE_WORKER_MODE=true
        UPGRADE_JOB_ID="$2"
        ;;
    --discovery-worker)
        [[ "${2:-}" =~ ^[a-f0-9-]{36}$ ]] || exit 2
        DISCOVERY_WORKER_MODE=true
        DISCOVERY_JOB_ID="$2"
        ;;
    --discovery-schedule)
        DISCOVERY_SCHEDULE_MODE=true
        ;;
    --upgrade-resume)
        UPGRADE_RESUME_MODE=true
        ;;
    *)
        # Admin-only guard (validates session, exits 401/403 if not admin)
        source "$(dirname "$0")/auth-guard.sh"
        require_admin
        ;;
esac

# Load allowlisted config data through the fixed, root-owned parser.
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# DHCP config paths
DHCP_HOSTS_FILE="${DHCP_HOSTS_FILE:-/etc/dhcp/dhcpd.hosts}"
DHCP_CONF_FILE="${DHCP_CONF_FILE:-/etc/dhcp/dhcpd.conf}"
DHCP_LEASES_FILE="${DHCP_LEASES_FILE:-/var/lib/dhcp/dhcpd.leases}"
DHCP_LOG_FILE="${DHCP_LOG_FILE:-/var/log/lldpq/dhcpd.log}"
ZTP_SCRIPT_FILE="${ZTP_SCRIPT_FILE:-${WEB_ROOT}/cumulus-ztp.sh}"
BASE_CONFIG_DIR="${BASE_CONFIG_DIR:-${LLDPQ_DIR}/sw-base}"
PROVISION_UPLOAD_DIR="${PROVISION_UPLOAD_DIR:-${WEB_ROOT}/provision-uploads}"

POST_DATA=""
POST_DATA_FILE=""
LINES_PARAM=""
PROVISION_UPLOAD_FD=""
if [[ "$UPGRADE_WORKER_MODE" == true ]]; then
    ACTION="upgrade-worker"
elif [[ "$DISCOVERY_WORKER_MODE" == true ]]; then
    ACTION="discovery-worker"
elif [[ "$DISCOVERY_SCHEDULE_MODE" == true ]]; then
    ACTION="discovery-schedule"
elif [[ "$UPGRADE_RESUME_MODE" == true ]]; then
    ACTION="upgrade-resume"
else
    # Output JSON header
    echo "Content-Type: application/json"
    echo ""

    # Parse query string
    ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)
    LINES_PARAM=$(echo "$QUERY_STRING" | grep -oP '(^|&)lines=\K[0-9]+' | head -1)

    # Read POST data if present (multipart uploads use a preserved request-body FD)
    if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        # Preserve the original CGI request body before the Python heredoc
        # replaces stdin with the embedded source code.
        case "$CONTENT_TYPE" in
            multipart/form-data*) exec 3<&0; PROVISION_UPLOAD_FD=3 ;;
            *)
                if [ "$CONTENT_LENGTH" -gt 65536 ]; then
                    # Bodies this large overflow the kernel per-string env limit
                    # (MAX_ARG_STRLEN) on exec; spool them to a temp file instead.
                    POST_DATA_FILE=$(mktemp /tmp/lldpq-provision-request.XXXXXX) || POST_DATA_FILE=""
                    if [ -n "$POST_DATA_FILE" ]; then
                        trap 'rm -f "$POST_DATA_FILE"' EXIT
                        head -c "$CONTENT_LENGTH" > "$POST_DATA_FILE"
                    fi
                else
                    POST_DATA=$(head -c "$CONTENT_LENGTH")
                fi
                ;;
        esac
    fi
fi

# Discovery config
DISCOVERY_RANGE="${DISCOVERY_RANGE:-}"
AUTO_BASE_CONFIG="${AUTO_BASE_CONFIG:-true}"
AUTO_ZTP_DISABLE="${AUTO_ZTP_DISABLE:-true}"
AUTO_SET_HOSTNAME="${AUTO_SET_HOSTNAME:-true}"

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT
export DHCP_HOSTS_FILE DHCP_CONF_FILE DHCP_LEASES_FILE DHCP_LOG_FILE ZTP_SCRIPT_FILE BASE_CONFIG_DIR
export PROVISION_UPLOAD_DIR
export DISCOVERY_RANGE AUTO_BASE_CONFIG AUTO_ZTP_DISABLE AUTO_SET_HOSTNAME
export POST_DATA POST_DATA_FILE ACTION LINES_PARAM UPGRADE_JOB_ID UPGRADE_WORKER_MODE
export DISCOVERY_JOB_ID DISCOVERY_WORKER_MODE DISCOVERY_SCHEDULE_MODE UPGRADE_RESUME_MODE
export PROVISION_UPLOAD_FD
export PROVISION_API_SCRIPT="${BASH_SOURCE[0]}"

python3 << 'PYTHON_SCRIPT'
import json
import sys
import os
import re
import shlex
import subprocess
import fcntl
import stat
import tempfile
import uuid
import hashlib
import base64
import ipaddress
import io
import socket
import shutil
import pwd
import grp
from urllib.parse import urlparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

import time

ACTION = os.environ.get('ACTION', '')
POST_DATA = os.environ.get('POST_DATA', '')
POST_DATA_FILE = os.environ.get('POST_DATA_FILE', '')
if not POST_DATA and POST_DATA_FILE:
    # Large request bodies are spooled to a temp file by the shell wrapper
    # because they exceed the kernel per-string environment limit on exec.
    try:
        with open(POST_DATA_FILE, 'r') as post_fh:
            POST_DATA = post_fh.read()
    except OSError:
        POST_DATA = ''
LLDPQ_DIR = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
LLDPQ_USER = os.environ.get('LLDPQ_USER', 'lldpq')
WEB_ROOT = os.environ.get('WEB_ROOT', '/var/www/html')
DHCP_HOSTS_FILE = os.environ.get('DHCP_HOSTS_FILE', '/etc/dhcp/dhcpd.hosts')
DHCP_LEASES_FILE = os.environ.get('DHCP_LEASES_FILE', '/var/lib/dhcp/dhcpd.leases')
DHCP_LOG_FILE = os.environ.get('DHCP_LOG_FILE', '/var/log/lldpq/dhcpd.log')
ISC_DHCP_DEFAULT_FILE = os.environ.get('ISC_DHCP_DEFAULT_FILE', '/etc/default/isc-dhcp-server')
ZTP_SCRIPT_FILE = os.environ.get('ZTP_SCRIPT_FILE', f'{WEB_ROOT}/cumulus-ztp.sh')
BASE_CONFIG_DIR = os.environ.get('BASE_CONFIG_DIR', f'{LLDPQ_DIR}/sw-base')
PROVISION_UPLOAD_DIR = os.environ.get('PROVISION_UPLOAD_DIR', f'{WEB_ROOT}/provision-uploads')
ZTP_ARTIFACTS_DIR = os.environ.get(
    'ZTP_ARTIFACTS_DIR', os.path.join(PROVISION_UPLOAD_DIR, 'ztp-artifacts')
)
ZTP_ARTIFACT_GRACE_SECONDS = 86400
DISCOVERY_RANGE = os.environ.get('DISCOVERY_RANGE', '')
AUTO_BASE_CONFIG = os.environ.get('AUTO_BASE_CONFIG', 'true') == 'true'
AUTO_ZTP_DISABLE = os.environ.get('AUTO_ZTP_DISABLE', 'true') == 'true'
AUTO_SET_HOSTNAME = os.environ.get('AUTO_SET_HOSTNAME', 'true') == 'true'
DISCOVERY_CACHE_FILE = f'{WEB_ROOT}/discovery-cache.json'
INVENTORY_FILE = f'{WEB_ROOT}/inventory.json'
SERIAL_MAPPING_FILE = f'{WEB_ROOT}/serial-mapping.txt'
GENERATED_CONFIGS_DIR = f'{WEB_ROOT}/generated_config_folder'
UPGRADE_JOBS_DIR = '/var/lib/lldpq/upgrade-jobs'
UPGRADE_JOB_SCHEMA_VERSION = 2
UPGRADE_JOB_ID_PATTERN = (
    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
)
DISCOVERY_JOBS_DIR = '/var/lib/lldpq/provision-jobs'
UPGRADE_JOB_ID = os.environ.get('UPGRADE_JOB_ID', '')
DISCOVERY_JOB_ID = os.environ.get('DISCOVERY_JOB_ID', '')
PROVISION_API_SCRIPT = os.path.abspath(os.environ.get('PROVISION_API_SCRIPT', 'provision-api.sh'))
INVENTORY_LOCK_FILE = f'{WEB_ROOT}/.inventory.lock'
PROVISION_TRANSACTION_FILE = os.environ.get(
    'LLDPQ_PROVISION_TRANSACTION_FILE',
    os.path.join(DISCOVERY_JOBS_DIR, '.config-transaction.json'),
)
DHCP_OPERATION_LOCK_FILE = os.environ.get(
    'LLDPQ_DHCP_OPERATION_LOCK_FILE', f'{WEB_ROOT}/.dhcp-operation.lock'
)
DHCP_DESIRED_STATE_FILE = os.environ.get(
    'LLDPQ_DHCP_DESIRED_STATE_FILE',
    '/var/lib/lldpq/provision-state/dhcp-desired-state',
)
LLDPQ_CONF_FILE = os.environ.get('LLDPQ_CONF_FILE', '/etc/lldpq.conf')


def _mountinfo_path(value):
    """Decode one mountpoint field from Linux /proc/self/mountinfo."""
    for escaped, plain in (
        ('\\040', ' '), ('\\011', '\t'), ('\\012', '\n'), ('\\134', '\\')
    ):
        value = value.replace(escaped, plain)
    return os.path.normpath(value)


def is_direct_file_mount(path):
    """True only when the resolved file itself, not its directory, is mounted."""
    resolved = os.path.normpath(os.path.abspath(os.path.realpath(path)))
    try:
        metadata = os.stat(resolved, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            return False
        with open('/proc/self/mountinfo', 'r', encoding='utf-8') as mountinfo:
            for line in mountinfo:
                fields = line.split(' - ', 1)[0].split()
                if len(fields) >= 5 and _mountinfo_path(fields[4]) == resolved:
                    return True
    except OSError:
        return False
    return False


def direct_file_mount_error(path):
    return OSError(
        'Provision cannot transactionally replace the legacy direct-file mount '
        f'{path}. Preserve the current file, remove its individual bind mount, '
        'and mount /home/lldpq/lldpq/config as a directory or named volume.'
    )

def _read_text_with_privileged_fallback(path, missing_ok=False):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return handle.read()
    except FileNotFoundError:
        if missing_ok:
            return ''
        raise
    except PermissionError:
        result = subprocess.run(
            ['sudo', 'cat', path], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            if missing_ok and not os.path.exists(path):
                return ''
            raise OSError(result.stderr.strip() or f'Could not read {path}')
        return result.stdout


def update_lldpq_conf_values(updates):
    """Atomically update a set of allowlisted-style key/value settings."""
    if not updates:
        return
    normalized = {}
    for key, value in updates.items():
        key = str(key).strip()
        value = str(value)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', key):
            raise ValueError(f'Invalid configuration key: {key}')
        if '\n' in value or '\r' in value or '\x00' in value:
            raise ValueError(f'Invalid value for {key}')
        normalized[key] = value

    with _exclusive_regular_lock(CONFIG_LOCK_FILE, DEFAULT_CONFIG_LOCK_FILE):
        original = _read_text_with_privileged_fallback(
            LLDPQ_CONF_FILE, missing_ok=True
        )
        lines = original.splitlines(keepends=True)
        found = set()
        for index, line in enumerate(lines):
            for key, value in normalized.items():
                if key not in found and line.startswith(f'{key}='):
                    lines[index] = f'{key}={value}\n'
                    found.add(key)
                    break
        if lines and not lines[-1].endswith(('\n', '\r')):
            lines[-1] += '\n'
        for key, value in normalized.items():
            if key not in found:
                lines.append(f'{key}={value}\n')
        content = ''.join(lines)
        try:
            mode = stat.S_IMODE(os.stat(LLDPQ_CONF_FILE).st_mode)
        except OSError:
            mode = 0o660
        atomic_write_text(LLDPQ_CONF_FILE, content, mode)
        if _read_text_with_privileged_fallback(LLDPQ_CONF_FILE) != content:
            raise OSError('lldpq.conf readback mismatch')


def update_lldpq_conf(key, value):
    update_lldpq_conf_values({key: value})

def read_lldpq_conf_key(key, default=''):
    """Read a single key from /etc/lldpq.conf."""
    try:
        with open(LLDPQ_CONF_FILE, 'r') as f:
            for line in f:
                if line.startswith(f'{key}='):
                    return line.strip().split('=', 1)[1]
    except Exception:
        pass
    return default

def ip_range_to_list(range_str):
    """Parse comma-separated IP ranges and single IPs to list of IPs.
    Supports: '192.168.100.10-192.168.100.249'
              '192.168.100.11-192.168.100.199,192.168.100.201-192.168.100.252'
              '10.20.30.6' (single IP)
              '192.168.100.11-192.168.100.199,10.20.30.6' (mixed)
    """
    if not range_str:
        return []
    result = []
    for segment in range_str.split(','):
        segment = segment.strip()
        if not segment:
            continue
        try:
            if '-' not in segment:
                result.append(str(ipaddress.IPv4Address(segment)))
                continue
            start_s, end_s = segment.split('-', 1)
            start = int(ipaddress.IPv4Address(start_s.strip()))
            end = int(ipaddress.IPv4Address(end_s.strip()))
            if end < start:
                return []
            # Fail early before constructing an accidentally huge list.
            if end - start + 1 > 1500:
                return []
            result.extend(str(ipaddress.IPv4Address(value))
                          for value in range(start, end + 1))
        except ipaddress.AddressValueError:
            return []
        if len(result) > 1500:
            return []
    # Preserve first-seen order while removing overlap between segments.
    return list(dict.fromkeys(result))

# Also check alternate path for dhcpd.hosts (some setups use dhcpd.host)
DHCP_HOSTS_ALT = DHCP_HOSTS_FILE.replace('dhcpd.hosts', 'dhcpd.host')

def get_dhcp_hosts_path():
    """Find the actual dhcpd.hosts file"""
    for p in [DHCP_HOSTS_FILE, DHCP_HOSTS_ALT]:
        if os.path.exists(p):
            return p
    # Default to primary path (will be created if needed)
    return DHCP_HOSTS_FILE

def result_json(data):
    print(json.dumps(data))
    sys.exit(0)

def error_json(msg):
    result_json({"success": False, "error": msg})


@contextmanager
def exclusive_file_lock(path):
    """Hold an exclusive advisory lock for a complete multi-file operation."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    handle = open(path, 'a+')
    try:
        try:
            os.chmod(path, 0o664)
        except OSError:
            pass
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


@contextmanager
def dhcp_operation_lock():
    """Reject overlapping DHCP lifecycle/config transactions across clients."""
    os.makedirs(os.path.dirname(DHCP_OPERATION_LOCK_FILE) or '.', exist_ok=True)
    handle = open(DHCP_OPERATION_LOCK_FILE, 'a+')
    try:
        try:
            os.chmod(DHCP_OPERATION_LOCK_FILE, 0o664)
        except OSError:
            pass
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def run_with_dhcp_operation_lock(callback):
    try:
        with dhcp_operation_lock():
            return callback()
    except BlockingIOError:
        result_json({
            'success': False,
            'error_code': 'dhcp_busy',
            'error': 'Another DHCP operation is already in progress',
        })


def fsync_directory(path, strict=False):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        if strict:
            raise


def atomic_write_text(path, content, mode=0o664):
    """Write text with same-directory replace; fail loudly on every fallback."""
    logical_path = os.path.abspath(path)
    if os.path.islink(logical_path):
        path = os.path.realpath(logical_path)
    normalized_path = os.path.abspath(path)
    is_lldpq_config = logical_path == '/etc/lldpq.conf'
    expected_owner = None
    if is_lldpq_config:
        mode = 0o660
        try:
            expected_owner = (
                pwd.getpwnam(LLDPQ_USER).pw_uid,
                grp.getgrnam('www-data').gr_gid,
            )
        except KeyError as exc:
            raise OSError(f'Could not resolve LLDPq config ownership: {exc}') from exc
    directory = os.path.dirname(path) or '.'
    encoded = content.encode('utf-8')

    # A file bind mount is itself a mountpoint, so rename(2) cannot replace it.
    # Provision may update several inventory/DHCP files in one durable
    # transaction; discovering EBUSY after an earlier target was activated can
    # also make rollback hit EBUSY.  Reject a changing legacy target before the
    # first pathname mutation.  Setup's validated editor owns the explicitly
    # journaled compatibility path for service-owned app configuration.
    if is_direct_file_mount(normalized_path):
        try:
            current = _read_text_with_privileged_fallback(normalized_path)
        except OSError:
            current = None
        if current == content:
            return
        raise direct_file_mount_error(logical_path)

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix='.%s.' % os.path.basename(path),
                                        suffix='.tmp', dir=directory)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        if expected_owner is not None:
            chown = subprocess.run(
                ['sudo', 'chown', f'{expected_owner[0]}:{expected_owner[1]}', tmp_path],
                capture_output=True, text=True, timeout=5,
            )
            if chown.returncode != 0:
                raise OSError(
                    chown.stderr.strip() or f'Could not chown stage for {path}'
                )
        os.replace(tmp_path, path)
        tmp_path = None
        if expected_owner is None:
            os.chmod(path, mode)
        if expected_owner is not None:
            installed = os.stat(path, follow_symlinks=False)
            if (
                (installed.st_uid, installed.st_gid) != expected_owner
                or stat.S_IMODE(installed.st_mode) != mode
            ):
                raise OSError(f'Atomic replacement metadata mismatch for {path}')
        fsync_directory(directory)
        return
    except (OSError, subprocess.SubprocessError):
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        tmp_path = None
        # Docker persists /etc/lldpq.conf through a symlink into a writable
        # system-config volume. Replacing the logical symlink through the
        # privileged fallback would sever persistence; fail instead.
        if is_lldpq_config and logical_path != normalized_path:
            raise

    # Root-owned compatibility path.  Never copy directly over the live file:
    # that truncates it before the new bytes are durable and can leave a
    # partial config after power loss.  Only fixed, sudoers-allowlisted targets
    # may use this path; the final operation is a same-directory atomic rename.
    privileged_targets = {
        '/etc/lldpq.conf',
        '/etc/dhcp/dhcpd.conf',
        '/etc/dhcp/dhcpd.hosts',
        '/etc/dhcp/dhcpd.host',
        '/etc/default/isc-dhcp-server',
    }
    if logical_path not in privileged_targets:
        raise OSError(
            f'Atomic replacement is not permitted for root-owned target {path}'
        )
    root_stage = logical_path + '.lldpq-root-stage'
    fd, staged = tempfile.mkstemp(prefix='lldpq-write-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        proc = subprocess.run(
            ['sudo', 'cp', '--remove-destination', '--', staged, root_stage],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            raise OSError(proc.stderr.strip() or f'Could not stage {path}')
        chmod = subprocess.run(['sudo', 'chmod', format(mode, 'o'), root_stage],
                               capture_output=True, text=True, timeout=5)
        if chmod.returncode != 0:
            raise OSError(chmod.stderr.strip() or f'Could not chmod stage for {path}')
        if expected_owner is not None:
            chown = subprocess.run(
                ['sudo', 'chown', f'{expected_owner[0]}:{expected_owner[1]}', root_stage],
                capture_output=True, text=True, timeout=5,
            )
            if chown.returncode != 0:
                raise OSError(
                    chown.stderr.strip() or f'Could not chown stage for {path}'
                )
        synced = subprocess.run(
            ['sudo', 'sync', '-f', root_stage], capture_output=True,
            text=True, timeout=15,
        )
        if synced.returncode != 0:
            raise OSError(
                synced.stderr.strip() or f'Could not sync stage for {path}'
            )
        replace = subprocess.run(
            ['sudo', 'mv', '-fT', '--', root_stage, logical_path],
            capture_output=True, text=True, timeout=15,
        )
        if replace.returncode != 0:
            raise OSError(
                replace.stderr.strip() or f'Could not atomically replace {path}'
            )
        parent_synced = subprocess.run(
            ['sudo', 'sync', '-f', os.path.dirname(logical_path) or '/'],
            capture_output=True, text=True, timeout=15,
        )
        if parent_synced.returncode != 0:
            raise OSError(
                parent_synced.stderr.strip() or
                f'Could not sync parent directory for {path}'
            )
        if _read_text_with_privileged_fallback(logical_path) != content:
            raise OSError(f'Atomic replacement readback mismatch for {path}')
        if expected_owner is not None:
            installed = os.stat(logical_path, follow_symlinks=False)
            if (
                (installed.st_uid, installed.st_gid) != expected_owner
                or stat.S_IMODE(installed.st_mode) != mode
            ):
                raise OSError(f'Atomic replacement metadata mismatch for {path}')
    finally:
        try:
            os.unlink(staged)
        except OSError:
            pass
        # A failed chmod/mv may leave the fixed stage behind.  It is never a
        # live config, but remove it so a later transaction cannot inherit it.
        subprocess.run(
            ['sudo', 'rm', '-f', root_stage], capture_output=True,
            text=True, timeout=5,
        )


def run_checked(command, *, input_text=None, timeout=15):
    result = subprocess.run(
        command, input=input_text, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or 'command failed').strip()
        raise OSError(detail[:500])
    return result


def ensure_managed_directory(path, mode=0o775):
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
    except PermissionError:
        run_checked(['sudo', 'mkdir', '-p', path], timeout=10)
    run_checked(['sudo', 'chown', f'{LLDPQ_USER}:www-data', path], timeout=5)
    run_checked(['sudo', 'chmod', format(mode, 'o'), path], timeout=5)


def write_managed_text(path, content, mode=0o664):
    """Atomically write and verify a text artifact owned by the service user."""
    atomic_write_text(path, content, mode)
    run_checked(
        ['sudo', 'chown', f'{LLDPQ_USER}:www-data', path], timeout=5
    )
    run_checked(['sudo', 'chmod', format(mode, 'o'), path], timeout=5)
    if _read_text_with_privileged_fallback(path) != content:
        raise OSError(f'Write verification failed for {path}')


def snapshot_file(path):
    if not os.path.exists(path):
        return {'exists': False, 'content': b'', 'mode': 0o664}
    try:
        with open(path, 'rb') as handle:
            content = handle.read()
    except PermissionError:
        result = subprocess.run(
            ['sudo', 'cat', path], capture_output=True, timeout=10
        )
        if result.returncode != 0:
            detail = (result.stderr or b'').decode('utf-8', 'replace').strip()
            raise OSError(detail or f'Could not snapshot {path}')
        content = result.stdout
    return {
        'exists': True,
        'content': content,
        'mode': os.stat(path).st_mode & 0o777,
    }


def restore_file_snapshot(path, snapshot):
    if snapshot.get('exists'):
        atomic_write_text(path, snapshot.get('content', b'').decode('utf-8'),
                          snapshot.get('mode', 0o664))
        return
    if not os.path.exists(path):
        return
    try:
        os.unlink(path)
    except PermissionError:
        proc = subprocess.run(['sudo', 'rm', '-f', path], capture_output=True,
                              text=True, timeout=5)
        if proc.returncode != 0:
            raise OSError(proc.stderr.strip() or f'Could not remove {path}')


def _transaction_allowed_paths():
    """Return only paths that Provision is allowed to recover from a journal."""
    paths = {
        os.path.abspath(INVENTORY_FILE),
        os.path.abspath(get_dhcp_hosts_path()),
        os.path.abspath(os.path.join(LLDPQ_DIR, 'devices.yaml')),
        os.path.abspath(os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')),
        os.path.abspath(ISC_DHCP_DEFAULT_FILE),
    }
    # Transactions store resolved symlink targets so Docker's persistent
    # volume backing files are recovered rather than replacing the links.
    return paths | {os.path.realpath(path) for path in paths}


def _encode_transaction_snapshot(snapshot):
    content = snapshot.get('content', b'')
    if isinstance(content, str):
        content = content.encode('utf-8')
    return {
        'exists': bool(snapshot.get('exists')),
        'mode': int(snapshot.get('mode', 0o664)),
        'content_b64': base64.b64encode(content).decode('ascii'),
        'sha256': hashlib.sha256(content).hexdigest(),
    }


def _decode_transaction_snapshot(encoded):
    try:
        content = base64.b64decode(
            str(encoded.get('content_b64', '')).encode('ascii'), validate=True
        )
        expected = str(encoded.get('sha256', ''))
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError('snapshot checksum mismatch')
        mode = int(encoded.get('mode', 0o664))
        if mode < 0 or mode > 0o777:
            raise ValueError('invalid snapshot mode')
        return {
            'exists': bool(encoded.get('exists')),
            'mode': mode,
            'content': content,
        }
    except Exception as exc:
        raise RuntimeError(f'Invalid Provision transaction snapshot: {exc}') from exc


def _write_provision_transaction(journal):
    os.makedirs(os.path.dirname(PROVISION_TRANSACTION_FILE) or '.', exist_ok=True)
    content = json.dumps(journal, indent=2) + '\n'
    if len(content.encode('utf-8')) > 32 * 1024 * 1024:
        raise RuntimeError('Provision transaction is unexpectedly large')
    atomic_write_text(PROVISION_TRANSACTION_FILE, content, 0o600)
    fsync_directory(
        os.path.dirname(PROVISION_TRANSACTION_FILE) or '.', strict=True
    )


def _load_provision_transaction():
    if not os.path.exists(PROVISION_TRANSACTION_FILE):
        return None
    if os.path.islink(PROVISION_TRANSACTION_FILE):
        raise RuntimeError('Provision transaction marker must not be a symlink')
    if os.path.getsize(PROVISION_TRANSACTION_FILE) > 32 * 1024 * 1024:
        raise RuntimeError('Provision transaction marker is unexpectedly large')
    with open(PROVISION_TRANSACTION_FILE, 'r', encoding='utf-8') as handle:
        journal = json.load(handle)
    if journal.get('version') != 1 or not isinstance(journal.get('entries'), list):
        raise RuntimeError('Unsupported Provision transaction marker')
    if journal.get('phase') not in ('prepared', 'activating', 'committed'):
        raise RuntimeError('Invalid Provision transaction phase')
    allowed = _transaction_allowed_paths()
    seen = set()
    for entry in journal['entries']:
        path = os.path.abspath(str(entry.get('path', '')))
        if path not in allowed or path in seen:
            raise RuntimeError('Provision transaction contains an invalid target')
        seen.add(path)
        entry['path'] = path
        _decode_transaction_snapshot(entry.get('old', {}))
        _decode_transaction_snapshot(entry.get('new', {}))
    return journal


def _clear_provision_transaction():
    try:
        os.unlink(PROVISION_TRANSACTION_FILE)
    except FileNotFoundError:
        return
    fsync_directory(
        os.path.dirname(PROVISION_TRANSACTION_FILE) or '.', strict=True
    )


def begin_provision_transaction(kind, candidates, service_before, service_after):
    """Durably record old/new generations before the first live write."""
    if os.path.exists(PROVISION_TRANSACTION_FILE):
        raise RuntimeError(
            'A previous Provision transaction requires recovery before saving'
        )

    # Preflight every candidate before publishing the transaction authority or
    # changing the first target.  A legacy single-file Docker bind mount cannot
    # participate in rename-based atomic activation/rollback.  Unchanged
    # direct-mounted members are harmless no-ops; changing ones must migrate to
    # the documented config-directory volume first.
    for candidate_path, candidate_content, _candidate_mode in candidates:
        resolved_candidate = os.path.abspath(candidate_path)
        if os.path.islink(resolved_candidate):
            resolved_candidate = os.path.realpath(resolved_candidate)
        if not is_direct_file_mount(resolved_candidate):
            continue
        current = snapshot_file(resolved_candidate)
        candidate_bytes = candidate_content.encode('utf-8')
        if not current.get('exists') or current.get('content') != candidate_bytes:
            raise direct_file_mount_error(candidate_path)

    entries = []
    allowed = _transaction_allowed_paths()
    for path, content, mode in candidates:
        path = os.path.abspath(path)
        if os.path.islink(path):
            path = os.path.realpath(path)
        if path not in allowed:
            raise RuntimeError(f'Refusing unmanaged transaction target: {path}')
        old = snapshot_file(path)
        new_bytes = content.encode('utf-8')
        entries.append({
            'path': path,
            'old': _encode_transaction_snapshot(old),
            'new': _encode_transaction_snapshot({
                'exists': True, 'content': new_bytes, 'mode': mode,
            }),
        })
    journal = {
        'version': 1,
        'id': str(uuid.uuid4()),
        'kind': str(kind),
        'phase': 'prepared',
        'created_at': int(time.time()),
        'service_before': service_before,
        'service_after': service_after,
        'entries': entries,
    }
    _write_provision_transaction(journal)
    return journal


def mark_provision_transaction(journal, phase):
    if phase not in ('activating', 'committed'):
        raise ValueError('Invalid Provision transaction phase transition')
    previous_phase = journal.get('phase')
    journal['phase'] = phase
    journal['updated_at'] = int(time.time())
    try:
        _write_provision_transaction(journal)
    except Exception:
        journal['phase'] = previous_phase
        raise


def _apply_provision_transaction_generation(journal, generation):
    for entry in journal['entries']:
        snapshot = _decode_transaction_snapshot(entry[generation])
        restore_file_snapshot(entry['path'], snapshot)
        target = (
            os.path.realpath(entry['path'])
            if os.path.islink(entry['path']) else entry['path']
        )
        fsync_directory(os.path.dirname(target) or '.', strict=True)
        if snapshot['exists']:
            current = snapshot_file(entry['path'])
            if current['content'] != snapshot['content']:
                raise RuntimeError(
                    f'Provision transaction readback mismatch: {entry["path"]}'
                )


def sync_provision_transaction_targets(journal):
    """Verify and require durability for every activated transaction target."""
    for entry in journal['entries']:
        path = entry['path']
        expected = _decode_transaction_snapshot(entry['new'])
        current = snapshot_file(path)
        if not current.get('exists') or current.get('content') != expected['content']:
            raise RuntimeError(f'Provision transaction readback mismatch: {path}')
        target = os.path.realpath(path) if os.path.islink(path) else path
        fsync_directory(os.path.dirname(target) or '.', strict=True)


def _restore_dhcp_service_state(state):
    if state == 'running':
        ok, detail = restart_dhcp()
        if not ok:
            raise RuntimeError(detail or 'Could not restore running DHCP state')
    elif state == 'stopped':
        stop_dhcp_best_effort()
        if dhcp_is_running():
            raise RuntimeError('Could not restore stopped DHCP state')


def rollback_provision_transaction(journal):
    _apply_provision_transaction_generation(journal, 'old')
    _restore_dhcp_service_state(journal.get('service_before'))
    _clear_provision_transaction()


def recover_pending_provision_transaction():
    """Recover a crash-interrupted inventory/DHCP transaction on re-entry."""
    os.makedirs(os.path.dirname(DHCP_OPERATION_LOCK_FILE) or '.', exist_ok=True)
    os.makedirs(os.path.dirname(INVENTORY_LOCK_FILE) or '.', exist_ok=True)
    dhcp_lock = open(DHCP_OPERATION_LOCK_FILE, 'a+')
    lock = None
    try:
        # Match the save path's DHCP -> inventory lock order. Taking these even
        # when no marker was visible closes the check-then-write race with a
        # transaction that is just about to publish its durable authority.
        fcntl.flock(dhcp_lock.fileno(), fcntl.LOCK_EX)
        lock = open(INVENTORY_LOCK_FILE, 'a+')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if not os.path.exists(PROVISION_TRANSACTION_FILE):
            return False
        journal = _load_provision_transaction()
        if journal is None:
            return False
        if journal['phase'] == 'committed':
            _apply_provision_transaction_generation(journal, 'new')
            _restore_dhcp_service_state(journal.get('service_after'))
            _clear_provision_transaction()
        else:
            rollback_provision_transaction(journal)
        return True
    finally:
        if lock is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
        fcntl.flock(dhcp_lock.fileno(), fcntl.LOCK_UN)
        dhcp_lock.close()


def inventory_revision():
    digest = hashlib.sha256()
    for path in (INVENTORY_FILE, get_dhcp_hosts_path(),
                 os.path.join(LLDPQ_DIR, 'devices.yaml')):
        digest.update(path.encode('utf-8') + b'\0')
        try:
            with open(path, 'rb') as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
        except FileNotFoundError:
            digest.update(b'<missing>')
    return 'sha256:' + digest.hexdigest()


def is_valid_provision_hostname(value):
    """Match the existing Inventory hostname contract without URL metacharacters."""
    return bool(re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', str(value or '')
    ))


def normalize_inventory_bindings(bindings):
    """Validate and normalize the canonical inventory before any file write."""
    if not isinstance(bindings, list):
        raise ValueError('bindings must be a list')
    if len(bindings) > 10000:
        raise ValueError('inventory is too large (max 10000 entries)')
    normalized = []
    seen = {'hostname': {}, 'ip': {}, 'mac': {}, 'serial': {}}

    def unique(kind, value, hostname):
        if not value:
            return
        key = value.lower()
        previous = seen[kind].get(key)
        if previous:
            raise ValueError(f'Duplicate {kind} "{value}" ({previous}, {hostname})')
        seen[kind][key] = hostname

    for index, raw in enumerate(bindings, 1):
        if not isinstance(raw, dict):
            raise ValueError(f'Inventory row {index} must be an object')
        hostname = str(raw.get('hostname', '')).strip()
        mac = str(raw.get('mac', '')).strip().lower()
        ip = str(raw.get('ip', '')).strip()
        serial = str(raw.get('serial', '')).strip()
        role = str(raw.get('role', '')).strip().lower()
        raw_dhcp = raw.get('dhcp', True)
        if not isinstance(raw_dhcp, bool):
            raise ValueError(f'Inventory row {index} has an invalid DHCP flag')
        dhcp = raw_dhcp
        if not is_valid_provision_hostname(hostname):
            raise ValueError(f'Inventory row {index} has an invalid hostname')
        if ip:
            try:
                ip = str(ipaddress.IPv4Address(ip))
            except ipaddress.AddressValueError:
                raise ValueError(f'Inventory row {index} has an invalid IPv4 address: {ip}')
        placeholder_mac = not mac or mac == '-' or 'x' in mac
        if placeholder_mac:
            mac = '-'
        elif not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
            raise ValueError(f'Inventory row {index} has an invalid MAC address: {mac}')
        if role and not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}', role):
            raise ValueError(f'Inventory row {index} has an invalid role: {role}')
        if serial and (len(serial) > 128 or re.search(r'[\x00-\x1f\x7f]', serial)):
            raise ValueError(f'Inventory row {index} has an invalid serial number')
        if not ip and not placeholder_mac:
            raise ValueError(f'Inventory row {index} has a MAC but no IP address')
        unique('hostname', hostname, hostname)
        unique('ip', ip, hostname)
        if not placeholder_mac:
            unique('mac', mac, hostname)
        unique('serial', serial, hostname)
        normalized.append({
            'hostname': hostname,
            'mac': mac,
            'ip': ip,
            'serial': serial,
            'role': role,
            'inv_status': str(raw.get('inv_status', '')).strip(),
            'dhcp': dhcp,
        })
    return normalized


def normalize_identity_mac(value):
    value = str(value or '').strip().lower()
    if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        return value
    return ''


def normalize_identity_serial(value):
    value = str(value or '').strip()
    if value.lower() in ('', 'na', 'n/a', 'not specified', 'none'):
        return ''
    return value


def normalize_serial_mappings(mappings):
    """Validate a one-to-one serial-to-hostname config-selection map."""
    if not isinstance(mappings, list):
        raise ValueError('mappings must be a list')
    if len(mappings) > 10000:
        raise ValueError('serial mapping is too large (max 10000 entries)')
    normalized = []
    seen_serials = {}
    seen_hostnames = {}
    for index, raw in enumerate(mappings, 1):
        if not isinstance(raw, dict):
            raise ValueError(f'Serial mapping row {index} must be an object')
        raw_serial = raw.get('serial', '')
        raw_hostname = raw.get('hostname', '')
        if not isinstance(raw_serial, str) or not isinstance(raw_hostname, str):
            raise ValueError(f'Serial mapping row {index} must contain text values')
        serial = normalize_identity_serial(raw_serial)
        hostname = raw_hostname.strip()
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', serial):
            raise ValueError(f'Serial mapping row {index} has an invalid serial number')
        if not is_valid_provision_hostname(hostname):
            raise ValueError(f'Serial mapping row {index} has an invalid hostname')
        serial_key = serial.casefold()
        hostname_key = hostname.casefold()
        if serial_key in seen_serials:
            raise ValueError(
                f'Duplicate serial "{serial}" (rows {seen_serials[serial_key]} and {index})'
            )
        if hostname_key in seen_hostnames:
            raise ValueError(
                f'Duplicate hostname "{hostname}" '
                f'(rows {seen_hostnames[hostname_key]} and {index})'
            )
        seen_serials[serial_key] = index
        seen_hostnames[hostname_key] = index
        normalized.append({'serial': serial, 'hostname': hostname})
    return normalized


def evaluate_device_identity(binding, observed_mac='', observed_serial=''):
    """Require at least one live identity match and reject every live mismatch."""
    expected_mac = normalize_identity_mac(binding.get('mac', ''))
    expected_serial = normalize_identity_serial(binding.get('serial', ''))
    observed_mac = normalize_identity_mac(observed_mac)
    observed_serial = normalize_identity_serial(observed_serial)
    matches = []
    mismatches = []

    if expected_mac and observed_mac:
        if expected_mac == observed_mac:
            matches.append('MAC')
        else:
            mismatches.append(
                f'MAC expected {expected_mac}, observed {observed_mac}'
            )
    if expected_serial and observed_serial:
        if expected_serial == observed_serial:
            matches.append('serial')
        else:
            mismatches.append(
                f'serial expected {expected_serial}, observed {observed_serial}'
            )

    if mismatches:
        return False, 'Identity mismatch: ' + '; '.join(mismatches)
    if matches:
        return True, 'Verified by ' + ' and '.join(matches)
    if not expected_mac and not expected_serial:
        return False, 'Inventory has no MAC or serial for identity verification'
    return False, 'Live MAC/serial identity could not be verified'


def remote_identity_guard_shell(expected_mac='', expected_serial=''):
    """Return a fail-closed shell guard for use immediately before mutation."""
    expected_mac = normalize_identity_mac(expected_mac)
    expected_serial = normalize_identity_serial(expected_serial)
    if not expected_mac and not expected_serial:
        return "echo 'Device identity is not configured' >&2; exit 42"
    return f'''EXPECTED_MAC={shlex.quote(expected_mac)}
EXPECTED_SERIAL={shlex.quote(expected_serial)}
ACTUAL_MAC="$(cat /sys/class/net/eth0/address 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]' || true)"
ACTUAL_SERIAL="$(sudo dmidecode -s system-serial-number 2>/dev/null | head -1 || true)"
IDENTITY_MATCHES=0
if [ -n "$EXPECTED_MAC" ] && [ -n "$ACTUAL_MAC" ]; then
  if [ "$EXPECTED_MAC" != "$ACTUAL_MAC" ]; then
    echo "Device identity mismatch: expected MAC $EXPECTED_MAC, observed $ACTUAL_MAC" >&2
    exit 42
  fi
  IDENTITY_MATCHES=$((IDENTITY_MATCHES + 1))
fi
if [ -n "$EXPECTED_SERIAL" ] && [ -n "$ACTUAL_SERIAL" ]; then
  if [ "$EXPECTED_SERIAL" != "$ACTUAL_SERIAL" ]; then
    echo "Device identity mismatch: expected serial $EXPECTED_SERIAL, observed $ACTUAL_SERIAL" >&2
    exit 42
  fi
  IDENTITY_MATCHES=$((IDENTITY_MATCHES + 1))
fi
if [ "$IDENTITY_MATCHES" -eq 0 ]; then
  echo 'Live device identity could not be verified' >&2
  exit 42
fi
echo LLDPQ_IDENTITY_OK'''


@contextmanager
def inventory_shared_lock():
    """Keep inventory identity assignments stable through a remote mutation."""
    lock = open(INVENTORY_LOCK_FILE, 'a+')
    fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
    try:
        yield
    finally:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _load_canonical_inventory_bindings_unlocked():
    bindings = []
    if os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        bindings = payload.get('bindings', [])
    if not bindings:
        bindings = [
            binding for binding in parse_dhcp_hosts(get_dhcp_hosts_path())
            if not binding.get('commented')
        ]
    return normalize_inventory_bindings(bindings)


def load_canonical_inventory_bindings():
    """Read a normalized inventory snapshot under the shared inventory lock."""
    with inventory_shared_lock():
        return _load_canonical_inventory_bindings_unlocked()


def canonicalize_inventory_target(device, bindings=None):
    """Resolve hostname+IP to current inventory identity and reject stale input."""
    hostname = str(device.get('hostname', '')).strip()
    raw_ip = str(device.get('ip', '')).strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
        raise ValueError('Invalid device hostname')
    try:
        ip = str(ipaddress.IPv4Address(raw_ip))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f'Invalid device IP: {raw_ip}') from exc
    if bindings is None:
        bindings = load_canonical_inventory_bindings()
    binding = next((
        item for item in bindings
        if item.get('hostname', '').lower() == hostname.lower()
        and item.get('ip') == ip
    ), None)
    if binding is None:
        raise ValueError(
            f'{hostname} at {ip} no longer matches the current inventory'
        )
    current_mac = normalize_identity_mac(binding.get('mac', ''))
    current_serial = normalize_identity_serial(binding.get('serial', ''))
    if not current_mac and not current_serial:
        raise ValueError(
            f'{binding["hostname"]} has no inventory MAC or serial for identity verification'
        )
    requested_mac = normalize_identity_mac(device.get('expected_mac', ''))
    requested_serial = normalize_identity_serial(device.get('expected_serial', ''))
    if requested_mac and requested_mac != current_mac:
        raise ValueError('Inventory MAC changed after target selection')
    if requested_serial and requested_serial != current_serial:
        raise ValueError('Inventory serial changed after target selection')
    canonical = dict(device)
    canonical.update({
        'hostname': binding['hostname'], 'ip': binding['ip'],
        'expected_mac': current_mac, 'expected_serial': current_serial,
    })
    return canonical

# ======================== BINDINGS ========================

def parse_dhcp_hosts(filepath):
    """Parse ISC dhcpd.hosts file into a list of bindings.
    Format: host HOSTNAME {hardware ethernet MAC; fixed-address IP; ...}
    Also handles commented-out lines (starting with #).
    """
    bindings = []
    if not os.path.exists(filepath):
        return bindings

    with open(filepath, 'r') as f:
        content = f.read()

    # Match host entries (both active and commented)
    pattern = re.compile(
        r'^(\s*#?\s*)'                            # optional comment marker
        r'host\s+(\S+)\s*\{'                      # host HOSTNAME {
        r'[^}]*hardware\s+ethernet\s+([\w:]+)\s*;' # hardware ethernet MAC;
        r'[^}]*fixed-address\s+([\d.]+)\s*;'       # fixed-address IP;
        r'[^}]*\}',                                 # }
        re.MULTILINE
    )

    for m in pattern.finditer(content):
        prefix = m.group(1).strip()
        commented = prefix.startswith('#')
        hostname = m.group(2)
        mac = m.group(3).lower()
        ip = m.group(4)
        bindings.append({
            'hostname': hostname,
            'mac': mac,
            'ip': ip,
            'commented': commented
        })

    return bindings

def generate_dhcp_hosts(bindings, orig_filepath):
    """Generate ISC dhcpd.hosts file content from bindings list.
    Only writes entries with valid hostname + MAC + IP (no placeholders, no commented entries).
    Preserves the group header from original file if present.
    """
    lines = []
    
    # Try to preserve header from original file
    # Extract group header (everything before first 'host' line, or the whole content if no host lines)
    header = ""
    if os.path.exists(orig_filepath):
        with open(orig_filepath, 'r') as f:
            orig = f.read()
        first_host = re.search(r'^#?\s*host\s+', orig, re.MULTILINE)
        if first_host:
            header = orig[:first_host.start()]
        elif 'group' in orig:
            # No host lines but has group header — preserve everything except closing brace
            header = re.sub(r'\n\s*\}\s*$', '', orig.rstrip())
    
    provision_url = get_provision_url()

    if not header.strip():
        # Default header — use settings from dhcpd.conf if available
        server_ip = os.environ.get('PROVISION_SERVER_IP', '').strip()
        gw = ''
        dns = ''
        domain = 'example.com'
        default_url = ''
        conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        if os.path.exists(conf_path):
            try:
                with open(conf_path, 'r') as f:
                    conf_content = f.read()
                dm = re.search(r'option\s+domain-name\s+"([^"]*)"', conf_content)
                if dm:
                    domain = dm.group(1)
                router_match = re.search(r'option\s+routers\s+([0-9.]+)', conf_content)
                dns_match = re.search(
                    r'option\s+domain-name-servers\s+([0-9.]+)', conf_content
                )
                server_match = re.search(
                    r'option\s+www-server\s+(?!code\b)([0-9.]+)', conf_content
                )
                default_match = re.search(
                    r'option\s+default-url\s+(?!code\b)"([^"]+)"', conf_content
                )
                if router_match:
                    gw = router_match.group(1)
                if dns_match:
                    dns = dns_match.group(1)
                if server_match and not server_ip:
                    server_ip = server_match.group(1)
                if default_match:
                    default_url = default_match.group(1)
            except Exception:
                pass
        if not server_ip:
            parsed = urlparse(provision_url)
            try:
                server_ip = str(ipaddress.IPv4Address(parsed.hostname or ''))
            except ipaddress.AddressValueError:
                try:
                    server_ip = socket.gethostbyname(parsed.hostname or '')
                except OSError:
                    server_ip = get_server_ip()
        if not gw:
            gw = server_ip.rsplit('.', 1)[0] + '.1' if '.' in server_ip else server_ip
        if not dns:
            dns = gw
        if not default_url:
            parsed = urlparse(provision_url)
            default_url = f'{parsed.scheme}://{parsed.netloc}/'
        header = f"""group {{

  option domain-name "{domain}";
  option domain-name-servers {dns};
  option routers {gw};
  option www-server {server_ip};
  option default-url "{default_url}";
  option cumulus-provision-url "{provision_url}";

"""
    
    lines.append(header.rstrip() + '\n')
    
    skipped = 0
    for b in bindings:
        mac = b.get('mac', '').strip()
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        
        # Skip entries without complete info (no placeholder MACs, no commented entries)
        if not hostname or not ip:
            skipped += 1
            continue
        if not mac or mac == '-' or 'x' in mac.lower():
            skipped += 1
            continue
        # Skip entries where DHCP is disabled (static IP devices)
        if not b.get('dhcp', True):
            skipped += 1
            continue
        
        line = (
            f'host {hostname} '
            f'{{hardware ethernet {mac}; '
            f'fixed-address {ip}; '
            f'option host-name "{hostname}"; '
            f'option fqdn.hostname "{hostname}"; '
            f'option cumulus-provision-url "{provision_url}";}}'
        )
        lines.append(line)
    
    # Close group if header had one
    if 'group {' in header or 'group{' in header:
        lines.append('\n}')
    
    return '\n'.join(lines) + '\n', skipped

_server_ip_cache = None
_provision_url_cache = None

def get_provision_url():
    """Return the canonical absolute provisioning URL without rewriting it."""
    global _provision_url_cache
    if _provision_url_cache is not None:
        return _provision_url_cache

    paths = [
        os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf'),
        get_dhcp_hosts_path(),
    ]
    for path in paths:
        try:
            with open(path, 'r') as handle:
                content = handle.read()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        match = re.search(
            r'option\s+cumulus-provision-url\s+(?!code\b)"([^"]+)"',
            content,
        )
        if not match:
            continue
        candidate = match.group(1).strip()
        parsed = urlparse(candidate)
        if parsed.scheme in ('http', 'https') and parsed.hostname:
            _provision_url_cache = candidate
            return _provision_url_cache

    server_ref = os.environ.get('PROVISION_SERVER_IP', '').strip() or get_server_ip()
    _provision_url_cache = f'http://{server_ref}/cumulus-ztp.sh'
    return _provision_url_cache

def get_server_ip():
    """Try to determine this server's IP for ZTP URL.
    Falls back to reading from existing dhcpd.conf or hosts file.
    Result is cached for the duration of the request.
    """
    global _server_ip_cache
    if _server_ip_cache is not None:
        return _server_ip_cache

    runtime_ip = os.environ.get('PROVISION_SERVER_IP', '').strip()
    try:
        if runtime_ip:
            _server_ip_cache = str(ipaddress.IPv4Address(runtime_ip))
            return _server_ip_cache
    except ipaddress.AddressValueError:
        pass
    
    # Try to get from dhcpd.conf
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    if os.path.exists(conf_path):
        with open(conf_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"https?://([^/]+)/', content)
        if m:
            _server_ip_cache = m.group(1)
            return _server_ip_cache
    
    # Try existing hosts file
    hosts_path = get_dhcp_hosts_path()
    if os.path.exists(hosts_path):
        with open(hosts_path, 'r') as f:
            content = f.read()
        m = re.search(r'cumulus-provision-url\s+"https?://([^/]+)/', content)
        if m:
            _server_ip_cache = m.group(1)
            return _server_ip_cache
    
    # Fallback: try to get our own IP
    try:
        result = subprocess.run(
            ['hostname', '-I'], capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split()
        if ips:
            _server_ip_cache = ips[0]
            return _server_ip_cache
    except Exception:
        pass
    
    _server_ip_cache = '127.0.0.1'
    return _server_ip_cache

def is_valid_server_ref(value):
    if not value or '__' in value or '_' in value:
        return False
    return re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]{1,5})?', value) is not None

def action_list_bindings():
    """Load inventory from inventory.json (primary) or dhcpd.hosts (fallback).
    inventory.json is the source of truth — it preserves ALL entries including planned (no MAC).
    dhcpd.hosts only contains active DHCP entries with valid MACs.
    """
    # Keep all three canonical inventory files stable until the response has
    # been assembled.  The handle intentionally remains live until result_json
    # terminates this short-lived CGI process.
    inventory_read_lock = open(INVENTORY_LOCK_FILE, 'a+')
    fcntl.flock(inventory_read_lock.fileno(), fcntl.LOCK_SH)

    # Primary: read from inventory.json (preserves planned entries)
    bindings = []
    source = 'inventory'
    if os.path.exists(INVENTORY_FILE):
        try:
            with open(INVENTORY_FILE, 'r') as f:
                inv_data = json.load(f)
            bindings = inv_data.get('bindings', [])
        except Exception:
            bindings = []
    
    # Fallback: read from dhcpd.hosts (legacy / first run)
    if not bindings:
        filepath = get_dhcp_hosts_path()
        bindings = parse_dhcp_hosts(filepath)
        source = 'dhcpd.hosts'
        # Legacy entries from dhcpd.hosts: skip commented entries (they are not active DHCP)
        bindings = [b for b in bindings if not b.get('commented')]
        for b in bindings:
            b['dhcp'] = True
    
    # Enrich with role from devices.yaml and serial from discovery cache
    roles = {}
    try:
        devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_file):
            import yaml
            with open(devices_file, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            for ip, info in ddata.get('devices', ddata).items():
                if ip in ('defaults', 'endpoint_hosts'):
                    continue
                if isinstance(info, str):
                    import re as _re
                    m = _re.match(r'^(.+?)\s+@([A-Za-z0-9_.-]+)$', info.strip())
                    if m:
                        roles[m.group(1).strip()] = m.group(2).lower()
                elif isinstance(info, dict):
                    h = info.get('hostname', '')
                    r = info.get('role', '')
                    if h and r:
                        roles[h] = r.lower()
    except Exception:
        pass
    
    # Load discovery cache for serial numbers
    disc_cache = {}
    try:
        if os.path.exists(DISCOVERY_CACHE_FILE):
            with open(DISCOVERY_CACHE_FILE, 'r') as f:
                cdata = json.load(f)
            for entry in cdata.get('entries', []):
                if entry.get('ip'):
                    disc_cache[entry['ip']] = entry
    except Exception:
        pass
    
    # Enrich each binding
    for b in bindings:
        is_placeholder = 'x' in b.get('mac', '').lower() or b.get('mac', '') in ('', '-')
        # Show '-' instead of xx:xx:xx in UI
        if 'x' in b.get('mac', '').lower():
            b['mac'] = '-'
        disc = disc_cache.get(b['ip'], {})
        
        # Status: planned / active / discovered
        # - active: fully operational (has MAC, or static IP + reachable)
        # - planned: incomplete record (DHCP device without MAC, or unreachable static)
        # - discovered: reachable but not provisioned (no SSH key)
        needs_dhcp = b.get('dhcp', True)
        if is_placeholder and needs_dhcp:
            # DHCP device without MAC = always planned (waiting for MAC)
            b['inv_status'] = 'planned'
        elif is_placeholder and not needs_dhcp:
            # Static IP device without MAC — status depends on reachability
            if disc.get('device_type') == 'provisioned':
                b['inv_status'] = 'active'
            elif disc.get('device_type') and disc['device_type'] != 'unreachable':
                b['inv_status'] = 'discovered'
            else:
                b['inv_status'] = 'planned'
        elif disc.get('device_type') == 'provisioned':
            b['inv_status'] = 'active'
        elif disc.get('device_type') == 'not_provisioned':
            b['inv_status'] = 'discovered'
        elif b.get('commented'):
            b['inv_status'] = 'planned'
        else:
            b['inv_status'] = 'active'
        
        # Only overwrite role from devices.yaml if binding has no role yet
        if not b.get('role'):
            b['role'] = roles.get(b['hostname'], '')
        if not b.get('serial'):
            b['serial'] = disc.get('serial', '')
        # DHCP flag: default True for backward compat (existing entries without flag)
        if 'dhcp' not in b:
            b['dhcp'] = True
        # Base config status from discovery cache
        b['base_config'] = disc.get('post_provision', '') in ('already', 'deployed')
    
    result_json({"success": True, "bindings": bindings, "source": source,
                 "revision": inventory_revision()})


def render_inventory_devices_yaml(bindings):
    """Render the existing grouped Inventory Export format without writing."""
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    defaults_username = 'cumulus'
    endpoint_hosts = []
    if os.path.exists(devices_file):
        import yaml
        with open(devices_file, 'r') as handle:
            existing = yaml.safe_load(handle) or {}
        defaults = existing.get('defaults', {})
        if isinstance(defaults, dict) and defaults.get('username'):
            defaults_username = defaults['username']
        existing_endpoints = existing.get('endpoint_hosts', [])
        if isinstance(existing_endpoints, list):
            endpoint_hosts = existing_endpoints

    from collections import defaultdict
    groups = defaultdict(list)
    for binding in bindings:
        hostname = binding.get('hostname', '').strip()
        ip = binding.get('ip', '').strip()
        if not hostname or not ip:
            continue
        role = binding.get('role', '').strip() or 'ungrouped'
        has_mac = bool(
            binding.get('mac') and binding.get('mac') != '-' and
            'x' not in binding.get('mac', '').lower()
        )
        planned = bool(
            binding.get('inv_status') == 'planned' or
            (binding.get('dhcp', True) and not has_mac)
        )
        groups[role].append({
            'hostname': hostname,
            'ip': ip,
            'role': role,
            'planned': planned,
            'ip_num': int(ipaddress.IPv4Address(ip)),
        })

    lines = [
        '# devices.yaml — Auto-generated from Provision Inventory',
        f'# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}',
        '#', '', 'defaults:', f'  username: {defaults_username}', '',
        'devices:',
    ]
    active_count = 0
    planned_count = 0
    for role in sorted(groups):
        lines.extend(('', f'  # {role}'))
        for entry in sorted(groups[role], key=lambda item: item['ip_num']):
            suffix = f" @{entry['role']}" if entry['role'] != 'ungrouped' else ''
            if entry['planned']:
                lines.append(f"#  {entry['ip']}: {entry['hostname']}{suffix}")
                planned_count += 1
            else:
                lines.append(f"  {entry['ip']}: {entry['hostname']}{suffix}")
                active_count += 1
    if endpoint_hosts:
        lines.extend(('', 'endpoint_hosts:'))
        for endpoint in endpoint_hosts:
            lines.append(f'- "{endpoint}"')
    lines.append('')
    content = '\n'.join(lines)
    import yaml as verify_yaml
    verify_yaml.safe_load(content)
    return content, active_count, planned_count

def _action_save_bindings_locked():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    try:
        bindings = normalize_inventory_bindings(data.get('bindings', []))
    except ValueError as exc:
        error_json(str(exc))
    sync_devices = data.get('sync_devices', False)
    rebuild_devices = data.get('rebuild_devices', False)
    remove_devices = data.get('remove_devices', [])  # hostnames to remove from devices.yaml
    do_restart = data.get('restart_dhcp', True)  # default True for backward compat
    client_revision = str(data.get('revision', '')).strip()
    first_run = bool(data.get('first_run', False))

    # Hold the canonical inventory lock before reading dhcpd.hosts or
    # devices.yaml to build candidates.  This prevents DHCP Save from changing
    # either input between render/validation and commit.
    inventory_lock = open(INVENTORY_LOCK_FILE, 'a+')
    try:
        os.chmod(INVENTORY_LOCK_FILE, 0o664)
    except OSError:
        pass
    fcntl.flock(inventory_lock.fileno(), fcntl.LOCK_EX)
    initial_revision = inventory_revision()
    filepath = get_dhcp_hosts_path()
    content, skipped = generate_dhcp_hosts(bindings, filepath)
    written = len(bindings) - skipped
    inv_data = {'bindings': bindings, 'timestamp': time.time()}
    inv_content = json.dumps(inv_data, indent=2) + '\n'
    # Round-trip before entering the transaction.
    json.loads(inv_content)

    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    devices_content = None
    devices_msg = ''
    rebuilt_active = None
    rebuilt_planned = None
    if rebuild_devices:
        if remove_devices:
            error_json('remove_devices cannot be combined with rebuild_devices')
        if not os.path.exists(devices_file):
            error_json('devices.yaml not found; inventory was not changed')
        devices_content, rebuilt_active, rebuilt_planned = \
            render_inventory_devices_yaml(bindings)
        devices_msg = (
            f'devices.yaml rebuilt: {rebuilt_active} active, '
            f'{rebuilt_planned} planned (commented).'
        )
    elif sync_devices or remove_devices:
        if not isinstance(remove_devices, list) or not all(isinstance(x, str) for x in remove_devices):
            error_json('remove_devices must be a list of hostnames')
        if os.path.exists(devices_file):
            devices_content, devices_msg = sync_bindings_to_devices_yaml(
                bindings, remove_devices, write=False
            )
        else:
            error_json('devices.yaml not found; inventory was not changed')

    restart_ok = None
    restart_msg = ''
    rollback_performed = False
    paths = [INVENTORY_FILE, filepath]
    if devices_content is not None:
        paths.append(devices_file)

    try:
        current_revision = inventory_revision()
        # Callers that omit 'revision' opt out of the client-side conflict check
        # (legacy API behavior); the initial-vs-current server check still applies.
        if current_revision != initial_revision or (
            (not first_run) and client_revision and client_revision != current_revision
        ):
            result_json({
                'success': False,
                'error_code': 'inventory_conflict',
                'error': 'Inventory changed on the server. Reload before saving.',
                'revision': current_revision,
            })

        # Validate the generated reservation file against the live DHCP config
        # before changing any inventory file.
        try:
            validate_dhcp_hosts_candidate(content, filepath)
        except Exception as exc:
            result_json({'success': False, 'error': str(exc),
                         'rollback_performed': False})
        was_running = dhcp_is_running() if do_restart else None
        service_before = (
            'running' if was_running else 'stopped'
        ) if do_restart else None
        candidates = [
            (INVENTORY_FILE, inv_content, 0o664),
            (filepath, content, 0o664),
        ]
        if devices_content is not None:
            candidates.append((devices_file, devices_content, 0o664))
        journal = None
        try:
            journal = begin_provision_transaction(
                'inventory-save', candidates, service_before,
                'running' if do_restart else None,
            )
            mark_provision_transaction(journal, 'activating')
            atomic_write_text(INVENTORY_FILE, inv_content, 0o664)
            atomic_write_text(filepath, content, 0o664)
            if devices_content is not None:
                atomic_write_text(devices_file, devices_content, 0o664)
            sync_provision_transaction_targets(journal)
            if do_restart:
                restart_ok, restart_msg = restart_dhcp()
                if not restart_ok:
                    raise RuntimeError('DHCP restart failed: ' + restart_msg)
            mark_provision_transaction(journal, 'committed')
            _clear_provision_transaction()
        except Exception as exc:
            detail = str(exc)
            if journal and journal.get('phase') == 'committed':
                detail += '; data was committed but transaction cleanup is pending'
            elif journal:
                try:
                    rollback_provision_transaction(journal)
                    rollback_performed = True
                except Exception as restore_exc:
                    detail += '; rollback pending recovery: ' + str(restore_exc)
            result_json({
                'success': False,
                'error': detail,
                'rollback_performed': rollback_performed,
            })

        new_revision = inventory_revision()
    finally:
        fcntl.flock(inventory_lock.fileno(), fcntl.LOCK_UN)
        inventory_lock.close()

    result_json({
        "success": True,
        "message": f"{written} active bindings saved ({skipped} planned). {devices_msg}",
        "dhcp_restart": restart_ok,
        "dhcp_message": restart_msg,
        "written": written,
        "skipped": skipped,
        "active": rebuilt_active,
        "planned": rebuilt_planned,
        "revision": new_revision,
        "rollback_performed": rollback_performed,
    })


def action_save_bindings():
    """Serialize Inventory saves that also request a DHCP restart."""
    try:
        payload = json.loads(POST_DATA)
    except Exception:
        return _action_save_bindings_locked()
    if payload.get('restart_dhcp', True):
        return run_with_dhcp_operation_lock(_action_save_bindings_locked)
    return _action_save_bindings_locked()

def sync_bindings_to_devices_yaml(bindings, remove_hostnames, write=True):
    """Sync inventory bindings to devices.yaml.
    - Add/update DHCP devices with a MAC and static devices with hostname + IP
    - Remove devices listed in remove_hostnames
    - Preserves existing comments and structure using ruamel.yaml
    """
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        return 'devices.yaml not found'
    
    try:
        from ruamel.yaml import YAML
        yaml = YAML()
        yaml.preserve_quotes = True
        with open(devices_file, 'r') as f:
            ddata = yaml.load(f) or {}
    except ImportError:
        import yaml as pyyaml
        with open(devices_file, 'r') as f:
            ddata = pyyaml.safe_load(f) or {}
        yaml = None
    
    devices = ddata.get('devices', ddata)
    added = 0
    updated = 0
    removed = 0
    
    # Build IP→hostname map from current devices.yaml
    ip_to_key = {}
    hostname_to_key = {}
    for key, info in list(devices.items()):
        if key in ('defaults', 'endpoint_hosts'):
            continue
        if isinstance(info, str):
            m = re.match(r'^(.+?)\s+@([A-Za-z0-9_.-]+)$', info.strip())
            h = m.group(1).strip() if m else info.strip()
        elif isinstance(info, dict):
            h = info.get('hostname', str(key))
        else:
            h = str(key)
        ip_to_key[str(key)] = key
        hostname_to_key[h] = key
    
    # Remove devices
    for h in remove_hostnames:
        key = hostname_to_key.get(h)
        if key and key in devices:
            del devices[key]
            removed += 1
    
    # Add/update complete bindings. Static devices do not require a MAC.
    for b in bindings:
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        mac = b.get('mac', '').strip()
        role = b.get('role', '').strip().lower()
        
        has_mac = bool(mac and mac != '-' and 'x' not in mac.lower())
        if not hostname or not ip or (b.get('dhcp', True) and not has_mac):
            continue
        
        existing_key = hostname_to_key.get(hostname) or ip_to_key.get(ip)
        
        if existing_key and existing_key in devices:
            # Update existing entry
            # If IP changed (key is old IP, binding has new IP), move to new key
            if str(existing_key) != ip:
                old_info = devices[existing_key]
                del devices[existing_key]
                # Re-create at new IP key
                if role:
                    devices[ip] = f"{hostname} @{role}"
                else:
                    devices[ip] = hostname
            else:
                # Same IP — just update role
                info = devices[existing_key]
                if isinstance(info, str):
                    devices[existing_key] = f"{hostname} @{role}" if role else hostname
                elif isinstance(info, dict):
                    if role:
                        info['role'] = role
                    else:
                        info.pop('role', None)
            updated += 1
        else:
            # Add new device
            if role:
                devices[ip] = f"{hostname} @{role}"
            else:
                devices[ip] = hostname
            added += 1
    
    parts = []
    if added: parts.append(f'{added} added')
    if updated: parts.append(f'{updated} updated')
    if removed: parts.append(f'{removed} removed')
    message = f"devices.yaml: {', '.join(parts)}." if parts else ''
    output = io.StringIO()
    if yaml and hasattr(yaml, 'dump'):
        yaml.dump(ddata, output)
    else:
        import yaml as pyyaml
        pyyaml.safe_dump(ddata, output, default_flow_style=False,
                         allow_unicode=True, sort_keys=False)
    rendered = output.getvalue()
    # Parse the rendered result before it can replace the live inventory.
    import yaml as verify_yaml
    verify_yaml.safe_load(rendered)
    if not write:
        return rendered, message
    atomic_write_text(devices_file, rendered, 0o664)
    return message


def validate_dhcp_config_candidate(conf_content, hosts_content=None,
                                   live_hosts_path=None, require_binary=True):
    """Syntax-check a complete DHCP candidate without touching live files."""
    dhcpd = shutil.which('dhcpd') or '/usr/sbin/dhcpd'
    if not os.path.exists(dhcpd):
        if require_binary:
            raise RuntimeError('dhcpd executable is not installed')
        return
    with tempfile.TemporaryDirectory(prefix='lldpq-dhcp-validate-') as temp_dir:
        rendered = conf_content
        if hosts_content is not None and live_hosts_path:
            staged_hosts = os.path.join(temp_dir, 'dhcpd.hosts')
            with open(staged_hosts, 'w') as handle:
                handle.write(hosts_content)
                handle.flush()
                os.fsync(handle.fileno())
            include_pattern = r'include\s+"' + re.escape(live_hosts_path) + r'"\s*;'
            rendered, count = re.subn(
                include_pattern,
                'include "' + staged_hosts + '";',
                rendered,
            )
            if count == 0:
                raise RuntimeError('DHCP config does not include the managed hosts file')
        staged_conf = os.path.join(temp_dir, 'dhcpd.conf')
        with open(staged_conf, 'w') as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        result = subprocess.run([dhcpd, '-t', '-cf', staged_conf],
                                capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or 'dhcpd validation failed').strip()
            raise RuntimeError('DHCP validation failed: ' + detail[:500])


def validate_dhcp_hosts_candidate(hosts_content, live_hosts_path):
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    if not os.path.exists(conf_path):
        return
    try:
        with open(conf_path, 'r') as handle:
            conf_content = handle.read()
    except PermissionError:
        result = subprocess.run(['sudo', 'cat', conf_path], capture_output=True,
                                text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError('Could not read DHCP config for validation')
        conf_content = result.stdout
    validate_dhcp_config_candidate(conf_content, hosts_content,
                                   live_hosts_path, require_binary=False)


def rewrite_dhcp_hosts_server_options(content, server_ip, server_base_url,
                                      provision_url):
    """Keep per-binding ONIE overrides aligned with the saved server URL."""
    content = re.sub(
        r'(?m)^(\s*option\s+www-server\s+)(?!code\b)[^;]+;',
        lambda match: match.group(1) + str(server_ip) + ';', content,
    )
    content = re.sub(
        r'(?m)^(\s*option\s+default-url\s+)(?!code\b)"[^"]*"\s*;',
        lambda match: match.group(1) + f'"{server_base_url}";', content,
    )
    content = re.sub(
        r'(option\s+cumulus-provision-url\s+)"[^"]*"\s*;',
        lambda match: match.group(1) + f'"{provision_url}";', content,
    )
    return content


def dhcp_is_running():
    try:
        for svc in ('isc-dhcp-server', 'dhcpd'):
            result = subprocess.run(['systemctl', 'is-active', svc],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip() == 'active':
                return True
    except Exception:
        pass
    try:
        return subprocess.run(['pgrep', '-x', 'dhcpd'], capture_output=True,
                              timeout=5).returncode == 0
    except Exception:
        return False


def stop_dhcp_best_effort():
    for svc in ('isc-dhcp-server', 'dhcpd'):
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', svc], capture_output=True,
                           text=True, timeout=10)
        except Exception:
            pass
    try:
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
    except Exception:
        pass


def persist_docker_dhcp_desired_state(running):
    """Persist the Docker DHCP lifecycle choice across container recreation."""
    mode = os.environ.get('LLDPQ_DHCP_MODE', '').strip().lower()
    if mode not in ('disabled', 'host'):
        return
    atomic_write_text(
        DHCP_DESIRED_STATE_FILE,
        'running\n' if running else 'stopped\n',
        0o664,
    )


def restart_dhcp():
    """Restart ISC DHCP server. Returns (success, message)."""
    if os.environ.get('LLDPQ_DHCP_MODE', '').strip().lower() == 'disabled':
        return False, ('DHCP is disabled in Docker bridge/monitoring mode; '
                       'use docker-compose.provisioning.yml on a Linux host')
    for svc in ['isc-dhcp-server', 'dhcpd']:
        try:
            result = subprocess.run(
                ['sudo', 'systemctl', 'restart', svc],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                verify = subprocess.run(['systemctl', 'is-active', svc],
                                        capture_output=True, text=True, timeout=5)
                if verify.returncode == 0 and verify.stdout.strip() == 'active':
                    return True, f"{svc} restarted"
        except Exception:
            continue
    
    # Try direct dhcpd restart (Docker). Use -d so dhcpd logs to stderr, redirected to
    # DHCP_LOG_FILE (no syslog/journald in the container); detach so it survives the CGI.
    try:
        # Kill existing
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
        # Find interface
        iface = 'eth0'
        isc_default = ISC_DHCP_DEFAULT_FILE
        if os.path.exists(isc_default):
            with open(isc_default) as f:
                m = re.search(r'INTERFACES="(\S+)"', f.read())
                if m:
                    iface = m.group(1)
        logpath = os.environ.get('DHCP_LOG_FILE', '/var/log/lldpq/dhcpd.log')
        try:
            os.makedirs(os.path.dirname(logpath), exist_ok=True)
        except Exception:
            pass
        try:
            logf = open(logpath, 'a')
        except Exception:
            logf = subprocess.DEVNULL
        conf = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        # Start detached, foreground (-d) so its packet log goes to the file.
        proc = subprocess.Popen(
            ['sudo', 'dhcpd', '-d', '-cf', conf, iface],
            stdout=logf, stderr=logf, start_new_session=True
        )
        time.sleep(0.8)
        if proc.poll() is not None and proc.returncode not in (0, None):
            return False, "dhcpd failed to start (see DHCP log)"
        return True, "dhcpd restarted (logging to %s)" % logpath
    except Exception as e:
        return False, str(e)

# ======================== DISCOVERED ========================

def action_discovered():
    """Cross-reference fabric ARP/LLDP data with DHCP bindings.
    
    Data sources (in priority order):
    1. fabric-tables/*.json — per-device ARP tables from fabric-scan.sh
       Contains eth0/mgmt ARP entries with IP→MAC mappings
    2. device-cache.json — assets data with hostname→MAC
    3. devices.yaml — known devices with IP→hostname mapping
    
    Cross-reference approach:
    - Build IP→MAC map from all ARP tables (eth0 interface = mgmt MAC)
    - For each DHCP binding (hostname, IP, MAC), look up discovered MAC by IP
    - Compare binding MAC vs discovered MAC
    """
    import glob
    
    # Load bindings
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    binding_ip_map = {b['ip']: b for b in bindings}
    
    entries = []
    discovered_ips = {}   # ip -> mac (from ARP)
    discovered_hosts = {} # hostname -> mac (from device-cache)
    
    # --- Source 1: fabric-tables ARP data ---
    # Each fabric-table JSON has "arp" list with entries like:
    # {"ip": "192.168.100.11", "mac": "54:9b:24:aa:68:16", "interface": "eth0", "vrf": "mgmt"}
    # Determine binding subnets to filter relevant ARP entries (no hardcoded prefixes)
    binding_subnets = set()
    for b in bindings:
        parts = b['ip'].split('.')
        if len(parts) == 4:
            binding_subnets.add('.'.join(parts[:3]) + '.')
    
    fabric_tables_dir = os.path.join(LLDPQ_DIR, 'monitor-results', 'fabric-tables')
    if os.path.isdir(fabric_tables_dir):
        for fpath in glob.glob(os.path.join(fabric_tables_dir, '*.json')):
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                for arp_entry in data.get('arp', []):
                    iface = arp_entry.get('interface', '')
                    ip = arp_entry.get('ip', '')
                    mac = arp_entry.get('mac', '').lower()
                    # Only mgmt interface ARP within binding subnets
                    if iface == 'eth0' and ip and mac and any(ip.startswith(s) for s in binding_subnets):
                        discovered_ips[ip] = mac
            except Exception:
                continue
    
    # --- Source 2: device-cache.json ---
    device_cache = os.path.join(WEB_ROOT, 'device-cache.json')
    if os.path.exists(device_cache):
        try:
            with open(device_cache, 'r') as f:
                dc = json.load(f)
            if isinstance(dc, dict):
                for hostname, info in dc.items():
                    if isinstance(info, dict):
                        mac = info.get('mac', '').lower()
                        ip = info.get('ip', '')
                        if mac:
                            discovered_hosts[hostname] = mac
                        if ip and mac:
                            discovered_ips[ip] = mac
        except Exception:
            pass
    
    # --- Source 3: devices.yaml for hostname→IP mapping ---
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    hostname_to_ip = {}
    if os.path.exists(devices_file):
        try:
            import yaml
            with open(devices_file, 'r') as f:
                dev_data = yaml.safe_load(f)
            devices_section = dev_data.get('devices', dev_data)
            for ip, info in devices_section.items():
                if ip in ('defaults', 'endpoint_hosts'):
                    continue
                if isinstance(info, dict):
                    hostname = info.get('hostname', str(ip))
                elif isinstance(info, str):
                    hostname = info.strip().split('@')[0].strip()
                else:
                    hostname = str(info) if info else str(ip)
                hostname_to_ip[hostname] = str(ip)
        except Exception:
            pass
    
    # --- Cross-reference ---
    seen_hostnames = set()
    
    for b in bindings:
        hostname = b['hostname']
        binding_mac = b['mac'].lower()
        binding_ip = b['ip']
        seen_hostnames.add(hostname)
        
        # Try to find discovered MAC: by IP first, then by hostname
        disc_mac = discovered_ips.get(binding_ip, '')
        source = 'ARP' if disc_mac else ''
        
        if not disc_mac:
            disc_mac = discovered_hosts.get(hostname, '')
            source = 'Cache' if disc_mac else ''
        
        entry = {
            'hostname': hostname,
            'binding_mac': b['mac'],
            'binding_ip': binding_ip,
            'discovered_mac': disc_mac,
            'source': source,
            'status': 'missing'
        }
        
        if disc_mac:
            if disc_mac == binding_mac:
                entry['status'] = 'match'
            else:
                entry['status'] = 'mismatch'
        
        entries.append(entry)
    
    # Discovered IPs not in bindings (devices seen in ARP but no DHCP binding)
    # Determine subnet from bindings to filter relevant IPs
    binding_subnets = set()
    for b in bindings:
        parts = b['ip'].split('.')
        if len(parts) == 4:
            binding_subnets.add('.'.join(parts[:3]) + '.')
    
    for ip, mac in discovered_ips.items():
        if ip not in binding_ip_map and any(ip.startswith(s) for s in binding_subnets):
            # Try to find hostname from devices.yaml
            hostname = ''
            for h, h_ip in hostname_to_ip.items():
                if h_ip == ip:
                    hostname = h
                    break
            if not hostname:
                hostname = ip  # fallback to IP
            
            if hostname not in seen_hostnames:
                entries.append({
                    'hostname': hostname,
                    'binding_mac': '',
                    'binding_ip': '',
                    'discovered_mac': mac,
                    'source': 'ARP',
                    'status': 'unbound'
                })
                seen_hostnames.add(hostname)
    
    result_json({"success": True, "entries": entries})

def action_ping_scan():
    """Parallel ping all binding IPs, then read local ARP for MAC cross-reference.
    Much more accurate than fabric-tables — gives real-time reachability + MAC match.
    """
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    if not bindings:
        error_json("No bindings to scan")
    
    # Step 1: use two ICMP samples and an independent TCP/22 probe.  ICMP is a
    # signal, not the sole reachability decision (many management networks
    # intentionally filter it).
    def ping_one(ip):
        try:
            r = subprocess.run(
                ['ping', '-c', '2', '-W', '1', '-i', '0.2', ip],
                capture_output=True, text=True, timeout=4
            )
            return ip, r.returncode == 0
        except Exception:
            return ip, False

    def tcp_one(ip):
        try:
            with socket.create_connection((ip, 22), timeout=0.75):
                return ip, True
        except OSError:
            return ip, False
    
    ping_results = {}  # ip -> True/False
    with ThreadPoolExecutor(max_workers=250) as executor:
        futures = {executor.submit(ping_one, b['ip']): b['ip'] for b in bindings}
        for future in as_completed(futures):
            ip, alive = future.result()
            ping_results[ip] = alive
    tcp_results = {}
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(tcp_one, b['ip']): b['ip'] for b in bindings}
        for future in as_completed(futures):
            ip, reachable = future.result()
            tcp_results[ip] = reachable
    
    # Step 2: Read local ARP table (populated by the pings we just did)
    local_arp = {}  # ip -> mac
    try:
        r = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                # Format: IP dev IFACE lladdr MAC state
                if 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        local_arp[ip] = parts[mac_idx].lower()
    except Exception:
        pass
    
    # Step 3: Cross-reference
    entries = []
    for b in bindings:
        hostname = b['hostname']
        binding_mac = b['mac'].lower()
        binding_ip = b['ip']
        icmp_alive = ping_results.get(binding_ip, False)
        tcp_alive = tcp_results.get(binding_ip, False)
        disc_mac = local_arp.get(binding_ip, '')
        alive = bool(icmp_alive or tcp_alive or disc_mac)
        
        entry = {
            'hostname': hostname,
            'binding_mac': b['mac'],
            'binding_ip': binding_ip,
            'discovered_mac': disc_mac,
            'source': '+'.join(name for name, present in (
                ('ICMP', icmp_alive), ('ARP', bool(disc_mac)),
                ('TCP22', tcp_alive)
            ) if present),
            'status': 'unreachable'
        }
        
        if alive and disc_mac:
            if disc_mac == binding_mac:
                entry['status'] = 'match'
            else:
                entry['status'] = 'mismatch'
        elif alive and not disc_mac:
            # Reachable does not prove the expected L2 identity.  Do not turn
            # missing ARP evidence into a false MAC match.
            entry['status'] = 'unknown'
        # else: unreachable
        
        entries.append(entry)
    
    result_json({"success": True, "entries": entries, "scan_type": "ping"})

def run_subnet_scan(apply_post_provision=True):
    """Full subnet discovery: ping all IPs in range, ARP for MACs, SSH probe for classification,
    post-provision actions (sw-base, ztp disable, hostname set) for newly provisioned devices."""
    
    # Get discovery range
    disc_range = read_lldpq_conf_key('DISCOVERY_RANGE', DISCOVERY_RANGE)
    if not disc_range:
        # Auto-detect from dhcpd.conf subnet
        conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
        try:
            with open(conf_path, 'r') as f:
                content = f.read()
            m = re.search(r'subnet\s+([\d.]+)', content)
            if m:
                prefix = '.'.join(m.group(1).split('.')[:3])
                disc_range = f'{prefix}.10-{prefix}.249'
        except Exception:
            pass
    
    if not disc_range:
        raise ValueError("No discovery range configured. Set it in DHCP Server Configuration.")
    
    all_ips = ip_range_to_list(disc_range)
    if not all_ips:
        raise ValueError(f"Invalid discovery range: {disc_range}")
    # Safety limit: prevent memory/timeout bombs from huge ranges
    if len(all_ips) > 1500:
        raise ValueError(f"Discovery range too large: {len(all_ips)} IPs (max 1500). Narrow the range.")
    
    # Use one normalized inventory snapshot for discovery. Every mutation is
    # re-authorized against the current snapshot again immediately beforehand.
    inv_bindings = load_canonical_inventory_bindings()
    binding_by_ip = {b['ip']: b for b in inv_bindings}
    binding_by_hostname = {b.get('hostname',''): b for b in inv_bindings if b.get('hostname')}
    
    # Load devices.yaml for hostname resolution + roles
    devices_yaml = {}    # ip -> hostname
    devices_roles = {}   # hostname -> role
    try:
        devices_path = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_path):
            import yaml
            with open(devices_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            devices_section = data.get('devices', data)
            if isinstance(devices_section, dict):
                for host_ip, info in devices_section.items():
                    if host_ip in ('defaults', 'endpoint_hosts'):
                        continue
                    if isinstance(info, dict):
                        hostname = info.get('hostname', str(host_ip))
                        if info.get('ip'):
                            devices_yaml[info['ip']] = hostname
                        role = info.get('role', '')
                        if role:
                            devices_roles[hostname] = role.lower()
                    elif isinstance(info, str):
                        raw = info.strip()
                        m = re.match(r'^(.+?)\s+@(\w+)$', raw)
                        if m:
                            hostname = m.group(1).strip()
                            devices_roles[hostname] = m.group(2).lower()
                        else:
                            hostname = raw
                        devices_yaml[str(host_ip)] = hostname
    except Exception:
        pass
    
    # Check if range contains non-private IPs (possible typo like 92.x instead of 192.x)
    non_private = []
    for ip in all_ips[:5]:  # sample first 5
        parts = ip.split('.')
        first = int(parts[0]) if parts else 0
        if not (first == 10 or (first == 172 and 16 <= int(parts[1]) <= 31) or (first == 192 and int(parts[1]) == 168)):
            non_private.append(ip)
    
    warning = ''
    if non_private:
        warning = f"Warning: range contains non-private IPs ({non_private[0]}...). Typo? Scan continues with short timeout."
    
    # Step 1: ICMP is a useful signal, but never the sole reachability gate.
    # Two samples reduce one-packet false negatives; TCP/ARP/SSH below remain
    # authoritative when ICMP is filtered.
    ping_wait = '0.5' if non_private else '1'
    
    def ping_one(ip):
        try:
            r = subprocess.run(['ping', '-c', '2', '-W', ping_wait, '-i', '0.2', ip],
                             capture_output=True, text=True, timeout=4)
            return ip, r.returncode == 0
        except Exception:
            return ip, False
    
    ping_results = {}
    with ThreadPoolExecutor(max_workers=250) as executor:
        futures = {executor.submit(ping_one, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip, alive = future.result()
            ping_results[ip] = alive
    
    # Step 2: Read local ARP table
    local_arp = {}
    try:
        r = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if 'lladdr' in parts:
                    ip = parts[0]
                    mac_idx = parts.index('lladdr') + 1
                    if mac_idx < len(parts):
                        local_arp[ip] = parts[mac_idx].lower()
    except Exception:
        pass
    
    # TCP/22 is probed independently so ICMP-filtered devices are still
    # classified. Keep the timeout short and concurrency bounded.
    def tcp22_one(ip):
        try:
            with socket.create_connection((ip, 22), timeout=0.75):
                return ip, True
        except OSError:
            return ip, False

    tcp_results = {}
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(tcp22_one, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip, is_open = future.result()
            tcp_results[ip] = is_open

    # Inventory addresses always receive an SSH attempt even when neither ICMP
    # nor the short TCP probe answered. Unknown addresses need at least one
    # positive network signal to avoid a full-range slow SSH sweep.
    probe_ips = [
        ip for ip in all_ips
        if ping_results.get(ip) or tcp_results.get(ip) or ip in local_arp or ip in binding_by_ip
    ]

    # Step 3: SSH probe candidates for classification + per-action state.
    def ssh_probe(ip):
        """Try SSH with key auth as cumulus user (runs as LLDPQ_USER to use correct SSH keys).
        Returns: (ip, device_type, serial, base_deployed)"""
        try:
            r = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
                 '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                 '-o', 'LogLevel=ERROR', f'cumulus@{ip}',
                 "echo LLDPQ_OK; "
                 "printf 'LLDPQ_SERIAL=%s\\n' \"$(sudo dmidecode -s system-serial-number 2>/dev/null | head -1)\"; "
                 "printf 'LLDPQ_MGMT_MAC=%s\\n' \"$(cat /sys/class/net/eth0/address 2>/dev/null | head -1)\"; "
                 f"printf 'LLDPQ_BASE_HASH=%s\\n' \"$(sudo head -n 1 {shlex.quote(BASE_STATE_FILE)} 2>/dev/null || true)\"; "
                 f"test -f {LEGACY_BASE_MARKER} && echo LLDPQ_LEGACY_BASE=1 || echo LLDPQ_LEGACY_BASE=0; "
                 f"test -f {ZTP_STATE_FILE} && echo LLDPQ_ZTP_DISABLED=1 || echo LLDPQ_ZTP_DISABLED=0; "
                 "printf 'LLDPQ_HOSTNAME=%s\\n' \"$(hostname)\""],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and 'LLDPQ_OK' in r.stdout:
                values = {}
                for line in r.stdout.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        values[key.strip()] = value.strip()
                serial = values.get('LLDPQ_SERIAL', '')
                if not serial or serial.lower() in ('', 'na', 'n/a', 'not specified', 'none'):
                    serial = ''
                return {
                    'ip': ip, 'device_type': 'provisioned', 'serial': serial,
                    'ssh_seen': True,
                    'management_mac': normalize_identity_mac(
                        values.get('LLDPQ_MGMT_MAC', '')
                    ),
                    'base_hash': values.get('LLDPQ_BASE_HASH', ''),
                    'legacy_base': values.get('LLDPQ_LEGACY_BASE') == '1',
                    'ztp_disabled': values.get('LLDPQ_ZTP_DISABLED') == '1',
                    'actual_hostname': values.get('LLDPQ_HOSTNAME', ''),
                }
            stderr = r.stderr.lower()
            if 'permission denied' in stderr:
                return {'ip': ip, 'device_type': 'not_provisioned', 'serial': '', 'ssh_seen': True}
            if 'connection refused' in stderr:
                return {'ip': ip, 'device_type': 'other', 'serial': '', 'ssh_seen': True}
            return {'ip': ip, 'device_type': 'other', 'serial': '', 'ssh_seen': False}
        except subprocess.TimeoutExpired:
            return {'ip': ip, 'device_type': 'other', 'serial': '', 'ssh_seen': False}
        except Exception:
            return {'ip': ip, 'device_type': 'other', 'serial': '', 'ssh_seen': False}

    ssh_results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(ssh_probe, ip): ip for ip in probe_ips}
        for future in as_completed(futures):
            probe = future.result()
            ssh_results[probe['ip']] = probe

    reachable_ips = [
        ip for ip in all_ips
        if ping_results.get(ip) or tcp_results.get(ip) or ip in local_arp
        or ssh_results.get(ip, {}).get('ssh_seen')
    ]

    # Step 4: Build entries with cross-reference
    entries = []
    for ip in all_ips:
        icmp_alive = ping_results.get(ip, False)
        tcp_open = tcp_results.get(ip, False)
        disc_mac = local_arp.get(ip, '')
        probe = ssh_results.get(ip, {})
        alive = bool(icmp_alive or tcp_open or disc_mac or probe.get('ssh_seen'))
        binding = binding_by_ip.get(ip)
        
        hostname = ''
        binding_mac = ''
        binding_serial = ''
        binding_ip = ip
        mac_status = ''
        identity_verified = False
        identity_error = ''
        
        if binding:
            hostname = binding['hostname']
            binding_mac = binding['mac']
            binding_serial = binding.get('serial', '')
            if alive and disc_mac:
                mac_status = 'match' if disc_mac == binding_mac.lower() else 'mismatch'
            elif alive:
                mac_status = 'unknown'
            else:
                mac_status = 'unreachable'
            identity_verified, identity_error = evaluate_device_identity(
                binding,
                probe.get('management_mac') or disc_mac,
                probe.get('serial', ''),
            )
        else:
            hostname = devices_yaml.get(ip, '')
            mac_status = 'no_binding'
        
        if not alive:
            device_type = 'unreachable'
        else:
            device_type = probe.get('device_type', 'other')
        
        # Resolve role from devices.yaml
        entry_role = devices_roles.get(hostname, '')
        
        entry = {
            'ip': ip,
            'hostname': hostname,
            'binding_mac': binding_mac,
            'binding_serial': binding_serial,
            'discovered_mac': disc_mac,
            'device_type': device_type,
            'mac_status': mac_status,
            'serial': probe.get('serial', ''),
            'role': entry_role,
            'source': '+'.join(name for name, present in (
                ('ICMP', icmp_alive), ('ARP', bool(disc_mac)),
                ('TCP22', tcp_open), ('SSH', bool(probe.get('ssh_seen')))
            ) if present),
            'has_binding': binding is not None,
            'identity_verified': identity_verified,
            'identity_error': identity_error,
            'post_provision': 'already' if (probe.get('base_hash') or probe.get('legacy_base')) else None,
            'base_manifest': probe.get('base_hash', ''),
            'legacy_base': bool(probe.get('legacy_base')),
            'ztp_disabled': bool(probe.get('ztp_disabled')),
            'actual_hostname': probe.get('actual_hostname', ''),
            'reachability': 'ssh' if probe.get('ssh_seen') else (
                'tcp22' if tcp_open else ('arp' if disc_mac else ('icmp' if icmp_alive else 'none'))
            ),
            'signals': {'icmp': icmp_alive, 'arp': bool(disc_mac),
                        'tcp22': tcp_open, 'ssh': bool(probe.get('ssh_seen'))},
        }
        entries.append(entry)
    
    # Step 5: Apply each requested post-provision action independently. Legacy
    # aggregate markers are treated as already complete to avoid surprising
    # mass redeployment during migration.
    auto_base = read_lldpq_conf_key('AUTO_BASE_CONFIG', 'true') == 'true'
    auto_ztp = read_lldpq_conf_key('AUTO_ZTP_DISABLE', 'true') == 'true'
    auto_host = read_lldpq_conf_key('AUTO_SET_HOSTNAME', 'true') == 'true'
    try:
        available_base_files, current_base_manifest = base_config_manifest(
            list(FILE_DEPLOY_MAP.keys())
        )
    except Exception:
        available_base_files, current_base_manifest = [], ''

    if apply_post_provision and (auto_base or auto_ztp or auto_host):
        def pending_post_provision_actions(entry):
            # Discovery is allowed to finish a genuinely new/incomplete
            # provisioning run.  A changed local sw-base manifest is an
            # upgrade concern and must not turn a routine Scan into a rollout
            # across every existing device.
            base_complete = bool(
                entry.get('base_manifest') or entry.get('legacy_base')
            )
            return {
                'base_config': bool(
                    auto_base and current_base_manifest and not base_complete
                ),
                'ztp_disable': bool(
                    auto_ztp and not entry.get('ztp_disabled')
                ),
                'hostname': bool(
                    auto_host and entry.get('hostname') and
                    entry.get('actual_hostname') != entry.get('hostname')
                ),
            }

        def has_pending_post_provision_action(entry):
            return any(pending_post_provision_actions(entry).values())

        def initial_post_provision_actions(entry, block_pending=False):
            pending = pending_post_provision_actions(entry)
            actions = {
                'base_config': (
                    'skipped' if not auto_base or not current_base_manifest
                    else 'already'
                ),
                'ztp_disable': 'skipped' if not auto_ztp else 'already',
                'hostname': 'skipped' if not auto_host else 'already',
            }
            if block_pending:
                for action_name, is_pending in pending.items():
                    if is_pending:
                        actions[action_name] = 'blocked'
            return actions, pending

        provisioned_entries = [
            e for e in entries
            if e['device_type'] == 'provisioned' and e['has_binding']
            and e.get('identity_verified')
            and has_pending_post_provision_action(e)
        ]
        blocked_entries = [
            e for e in entries
            if e['device_type'] == 'provisioned' and e['has_binding']
            and not e.get('identity_verified')
            and has_pending_post_provision_action(e)
        ]

        def post_provision_one_locked(entry, canonical):
            ip = canonical['ip']
            hostname = canonical['hostname']
            identity_guard = remote_identity_guard_shell(
                canonical.get('expected_mac', ''),
                canonical.get('expected_serial', ''),
            )
            actions, pending = initial_post_provision_actions(entry)
            changed = False

            # Presence of either generation's marker means automatic
            # post-provisioning has already completed.  Manifest drift is
            # handled by the explicit Base Config deployment workflow, not by
            # a discovery scan.
            needs_base = pending['base_config']
            # The old aggregate marker only proves that the legacy base copy
            # ran.  It says nothing about ZTP or hostname, so those two steps
            # must use their own observed state.
            needs_ztp = pending['ztp_disable']
            needs_hostname = pending['hostname']

            if needs_base:
                result = _deploy_to_device(
                    dict(canonical, username='cumulus'),
                    available_base_files, False
                )
                actions['base_config'] = 'success' if result.get('success') else 'failed'
                changed = changed or result.get('success', False)

            ssh_base = [
                'sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                f'cumulus@{ip}'
            ]
            if needs_ztp:
                command = (
                    "set -e; " + identity_guard + "; sudo ztp -d; "
                    f"printf '%s\\n' disabled | sudo tee {ZTP_STATE_FILE} >/dev/null; "
                    f"test \"$(sudo cat {ZTP_STATE_FILE})\" = disabled"
                )
                try:
                    result = subprocess.run(ssh_base + [command], capture_output=True,
                                            text=True, timeout=30)
                    actions['ztp_disable'] = 'success' if result.returncode == 0 else 'failed'
                    changed = changed or result.returncode == 0
                except Exception:
                    actions['ztp_disable'] = 'failed'

            if needs_hostname:
                quoted_hostname = shlex.quote(hostname)
                command = (
                    "set -e; " + identity_guard + "; "
                    f"sudo nv set system hostname {quoted_hostname}; "
                    "sudo nv config apply -y; "
                    f"test \"$(hostname)\" = {quoted_hostname}; "
                    f"printf '%s\\n' {quoted_hostname} | sudo tee {HOSTNAME_STATE_FILE} >/dev/null"
                )
                try:
                    result = subprocess.run(ssh_base + [command], capture_output=True,
                                            text=True, timeout=45)
                    actions['hostname'] = 'success' if result.returncode == 0 else 'failed'
                    changed = changed or result.returncode == 0
                except Exception:
                    actions['hostname'] = 'failed'

            failed = any(value == 'failed' for value in actions.values())
            status = 'failed' if failed else ('deployed' if changed else 'already')
            return ip, status, actions

        def post_provision_one(entry):
            requested = {
                'ip': entry['ip'], 'hostname': entry['hostname'],
                'username': 'cumulus',
                'expected_mac': entry.get('binding_mac', ''),
                'expected_serial': entry.get('binding_serial', ''),
            }
            try:
                # One lock covers legacy adoption, base copy, ZTP and hostname
                # so NVUE mutations cannot interleave for the same switch.
                with canonical_device_mutation(requested) as canonical:
                    return post_provision_one_locked(entry, canonical)
            except Exception as exc:
                entry['identity_error'] = f'Target authorization failed: {exc}'
                actions, _pending = initial_post_provision_actions(
                    entry, block_pending=True
                )
                return entry['ip'], 'failed', actions

        # Run post-provision in parallel (limited workers since these are heavier)
        post_results = {}
        post_action_results = {}
        for entry in blocked_entries:
            actions, _pending = initial_post_provision_actions(
                entry, block_pending=True
            )
            post_results[entry['ip']] = 'failed'
            post_action_results[entry['ip']] = actions
        if provisioned_entries:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(post_provision_one, e): e['ip'] for e in provisioned_entries}
                for future in as_completed(futures):
                    ip, status, actions = future.result()
                    post_results[ip] = status
                    post_action_results[ip] = actions

        # Update both executed and identity-blocked entries with aggregate state.
        for entry in entries:
            if entry['ip'] in post_results:
                actions = post_action_results[entry['ip']]
                base_status = actions.get('base_config')
                if base_status == 'success':
                    entry['post_provision'] = 'deployed'
                elif base_status == 'failed':
                    entry['post_provision'] = 'failed'
                elif base_status == 'already':
                    entry['post_provision'] = 'already'
                entry['post_provision_overall'] = post_results[entry['ip']]
                entry['post_provision_actions'] = actions

    # Step 6: Write cache
    cache_data = {
        'timestamp': time.time(),
        'discovery_range': disc_range,
        'entries': entries,
    }
    atomic_write_text(DISCOVERY_CACHE_FILE,
                      json.dumps(cache_data, indent=2) + '\n', 0o664)

    return {
        "success": True,
        "entries": entries,
        "scan_type": "subnet",
        "discovery_range": disc_range,
        "total_ips": len(all_ips),
        "reachable": len(reachable_ips),
        "post_provision_results": {
            entry['ip']: (
                entry.get('post_provision_overall') or
                entry.get('post_provision') or 'skipped'
            )
            for entry in entries
            if 'post_results' in dir() and entry['ip'] in post_results
        },
        "post_provision_overall_results": post_results if 'post_results' in dir() else {},
        "post_provision_action_results": post_action_results if 'post_action_results' in dir() else {},
        "warning": warning,
    }


def action_subnet_scan():
    """Backward-compatible synchronous endpoint using the shared scan core."""
    try:
        ensure_discovery_jobs_dir()
        with exclusive_file_lock(os.path.join(DISCOVERY_JOBS_DIR, '.scan.lock')):
            result_json(run_subnet_scan())
    except Exception as exc:
        error_json(str(exc))

def action_get_discovery_cache():
    """Read cached discovery results."""
    if not os.path.exists(DISCOVERY_CACHE_FILE):
        result_json({"success": True, "entries": [], "stale": True, "timestamp": 0})

    try:
        with open(DISCOVERY_CACHE_FILE, 'r') as f:
            data = json.load(f)
        age = time.time() - data.get('timestamp', 0)
        data['success'] = True
        data['stale'] = age > 300  # stale if > 5 minutes
        data['age_seconds'] = int(age)
        result_json(data)
    except Exception as e:
        result_json({"success": True, "entries": [], "stale": True, "timestamp": 0, "error": str(e)})


# ======================== DISCOVERY JOBS ========================

def ensure_discovery_jobs_dir():
    os.makedirs(DISCOVERY_JOBS_DIR, mode=0o2770, exist_ok=True)
    try:
        os.chmod(DISCOVERY_JOBS_DIR, 0o2770)
    except OSError:
        pass


def discovery_job_path(job_id):
    if not re.fullmatch(r'[a-f0-9-]{36}', job_id or ''):
        raise ValueError('Invalid discovery job id')
    return os.path.join(DISCOVERY_JOBS_DIR, f'{job_id}.json')


@contextmanager
def discovery_job_lock(job_id):
    ensure_discovery_jobs_dir()
    lock_path = discovery_job_path(job_id) + '.lock'
    with exclusive_file_lock(lock_path):
        yield


@contextmanager
def discovery_coordinator_lock():
    ensure_discovery_jobs_dir()
    with exclusive_file_lock(os.path.join(DISCOVERY_JOBS_DIR, '.coordinator.lock')):
        yield


def save_discovery_job(job):
    ensure_discovery_jobs_dir()
    path = discovery_job_path(job['id'])
    content = json.dumps(job, indent=2) + '\n'
    atomic_write_text(path, content, 0o664)


def load_discovery_job(job_id):
    path = discovery_job_path(job_id)
    if not os.path.exists(path):
        raise FileNotFoundError('Discovery job not found')
    with open(path, 'r') as handle:
        return json.load(handle)


def _bounded_env_int(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _remove_completed_discovery_job(job_id, allow_invalid=False):
    """Move one idle completed job out of the live namespace, then delete it."""
    path = discovery_job_path(job_id)
    lock_path = path + '.lock'
    worker_path = path + '.worker.lock'
    job_lock = open(lock_path, 'a+')
    worker_lock = open(worker_path, 'a+')
    tomb = None
    try:
        try:
            fcntl.flock(job_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(worker_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        try:
            job = load_discovery_job(job_id)
        except Exception:
            if not allow_invalid:
                return False
            job = {'complete': True}
        if not job.get('complete'):
            return False
        tomb = os.path.join(
            DISCOVERY_JOBS_DIR, f'.gc-{job_id}-{uuid.uuid4().hex}'
        )
        os.mkdir(tomb, 0o700)
        # Remove the JSON name first. New status readers then fail closed
        # instead of attaching to a half-removed completed job.
        for source in (path, lock_path, worker_path):
            if os.path.lexists(source):
                os.replace(source, os.path.join(tomb, os.path.basename(source)))
        fsync_directory(DISCOVERY_JOBS_DIR)
    finally:
        try:
            fcntl.flock(worker_lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            fcntl.flock(job_lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        worker_lock.close()
        job_lock.close()
    if tomb:
        shutil.rmtree(tomb, ignore_errors=True)
        fsync_directory(DISCOVERY_JOBS_DIR)
        return True
    return False


def prune_discovery_jobs():
    """Bound completed history and reap old orphan lock/GC artifacts."""
    ensure_discovery_jobs_dir()
    keep_count = _bounded_env_int(
        'LLDPQ_DISCOVERY_JOB_RETENTION_COUNT', 100, 10, 1000
    )
    keep_seconds = _bounded_env_int(
        'LLDPQ_DISCOVERY_JOB_RETENTION_SECONDS', 7 * 86400, 3600, 90 * 86400
    )
    recent_grace = _bounded_env_int(
        'LLDPQ_DISCOVERY_JOB_RECENT_GRACE_SECONDS', 600, 60, 86400
    )
    orphan_grace = _bounded_env_int(
        'LLDPQ_DISCOVERY_JOB_ORPHAN_GRACE_SECONDS', 3600, 300, 7 * 86400
    )
    now = time.time()
    removed = 0
    with exclusive_file_lock(os.path.join(DISCOVERY_JOBS_DIR, '.gc.lock')):
        completed = []
        for name in os.listdir(DISCOVERY_JOBS_DIR):
            match = re.fullmatch(r'([a-f0-9-]{36})\.json', name)
            if not match:
                continue
            path = os.path.join(DISCOVERY_JOBS_DIR, name)
            try:
                job = load_discovery_job(match.group(1))
                if not job.get('complete'):
                    continue
                finished = float(
                    job.get('completed_at') or job.get('created_at') or
                    os.path.getmtime(path)
                )
                completed.append((finished, match.group(1), False))
            except Exception:
                # A freshly written file may be observed between directory
                # enumeration and replace. Only old malformed files are reaped.
                try:
                    if now - os.path.getmtime(path) > orphan_grace:
                        completed.append((0, match.group(1), True))
                except OSError:
                    pass
        completed.sort(reverse=True)
        for index, (finished, job_id, invalid) in enumerate(completed):
            age = now - finished if finished else keep_seconds + 1
            if age < recent_grace:
                continue
            if index < keep_count and age <= keep_seconds:
                continue
            if _remove_completed_discovery_job(job_id, allow_invalid=invalid):
                removed += 1

        live_ids = {
            match.group(1)
            for name in os.listdir(DISCOVERY_JOBS_DIR)
            if (match := re.fullmatch(r'([a-f0-9-]{36})\.json', name))
        }
        for name in os.listdir(DISCOVERY_JOBS_DIR):
            artifact = os.path.join(DISCOVERY_JOBS_DIR, name)
            lock_match = re.fullmatch(
                r'([a-f0-9-]{36})\.json(?:\.worker)?\.lock', name
            )
            is_old_gc = name.startswith('.gc-')
            if not is_old_gc and (
                not lock_match or lock_match.group(1) in live_ids
            ):
                continue
            try:
                if now - os.path.getmtime(artifact) <= orphan_grace:
                    continue
                if is_old_gc and os.path.isdir(artifact):
                    shutil.rmtree(artifact)
                    removed += 1
                    continue
                handle = open(artifact, 'a+')
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    tomb = os.path.join(
                        DISCOVERY_JOBS_DIR, f'.gc-orphan-{uuid.uuid4().hex}'
                    )
                    os.replace(artifact, tomb)
                except BlockingIOError:
                    continue
                finally:
                    handle.close()
                os.unlink(tomb)
                removed += 1
            except (FileNotFoundError, IsADirectoryError, OSError):
                continue
        if removed:
            fsync_directory(DISCOVERY_JOBS_DIR)
    return removed


def list_discovery_jobs(unfinished_only=False):
    ensure_discovery_jobs_dir()
    prune_discovery_jobs()
    jobs = []
    for name in os.listdir(DISCOVERY_JOBS_DIR):
        match = re.fullmatch(r'([a-f0-9-]{36})\.json', name)
        if not match:
            continue
        try:
            job = load_discovery_job(match.group(1))
        except Exception:
            continue
        if unfinished_only and job.get('complete'):
            continue
        jobs.append(job)
    return jobs


def launch_discovery_worker(job_id):
    env = os.environ.copy()
    for key in ('CONTENT_LENGTH', 'CONTENT_TYPE', 'QUERY_STRING', 'REQUEST_METHOD',
                'PROVISION_UPLOAD_FD'):
        env.pop(key, None)
    proc = subprocess.Popen(
        ['/bin/bash', PROVISION_API_SCRIPT, '--discovery-worker', job_id],
        env=env, start_new_session=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
    )
    return proc.pid


def start_discovery_job(trigger='manual', apply_post_provision=True):
    with discovery_coordinator_lock():
        active = list_discovery_jobs(unfinished_only=True)
        if active:
            return max(active, key=lambda item: int(item.get('created_at', 0))), True
        now = int(time.time())
        job = {
            'id': str(uuid.uuid4()),
            'created_at': now,
            'trigger': trigger,
            'apply_post_provision': bool(apply_post_provision),
            'status': 'queued',
            'complete': False,
            'worker_started_at': now,
            'worker_heartbeat': now,
        }
        with discovery_job_lock(job['id']):
            save_discovery_job(job)
        try:
            launch_discovery_worker(job['id'])
        except Exception as exc:
            with discovery_job_lock(job['id']):
                job['status'] = 'failed'
                job['complete'] = True
                job['completed_at'] = int(time.time())
                job['error'] = 'Could not start discovery worker: ' + str(exc)[:300]
                save_discovery_job(job)
        return job, False


def run_discovery_worker(job_id):
    ensure_discovery_jobs_dir()
    worker_path = discovery_job_path(job_id) + '.worker.lock'
    worker = open(worker_path, 'a+')
    try:
        try:
            fcntl.flock(worker.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        with discovery_job_lock(job_id):
            job = load_discovery_job(job_id)
            if job.get('complete'):
                return
            job['status'] = 'running'
            job['started_at'] = int(time.time())
            job['worker_heartbeat'] = int(time.time())
            save_discovery_job(job)
        try:
            with exclusive_file_lock(os.path.join(DISCOVERY_JOBS_DIR, '.scan.lock')):
                result = run_subnet_scan(job.get('apply_post_provision', True))
            with discovery_job_lock(job_id):
                job = load_discovery_job(job_id)
                job['status'] = 'success'
                job['complete'] = True
                job['completed_at'] = int(time.time())
                job['worker_heartbeat'] = int(time.time())
                job['result'] = result
                job.pop('error', None)
                save_discovery_job(job)
        except BaseException as exc:
            with discovery_job_lock(job_id):
                job = load_discovery_job(job_id)
                job['status'] = 'failed'
                job['complete'] = True
                job['completed_at'] = int(time.time())
                job['worker_heartbeat'] = int(time.time())
                job['error'] = str(exc)[:500]
                save_discovery_job(job)
    finally:
        try:
            fcntl.flock(worker.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        worker.close()


def action_discovery_start():
    apply_actions = True
    if POST_DATA:
        try:
            data = json.loads(POST_DATA)
            apply_actions = data.get('apply_post_provision', True) is not False
        except Exception:
            error_json('Invalid JSON data')
    job, reused = start_discovery_job('manual', apply_actions)
    result_json({'success': True, 'job': job, 'reused': reused})


def action_discovery_status():
    try:
        data = json.loads(POST_DATA)
        job_id = data.get('job_id', '')
        with discovery_job_lock(job_id):
            job = load_discovery_job(job_id)
    except Exception as exc:
        error_json(str(exc))
    if not job.get('complete'):
        heartbeat = max(int(job.get('worker_heartbeat', 0) or 0),
                        int(job.get('worker_started_at', 0) or 0))
        if time.time() - heartbeat > 120:
            try:
                launch_discovery_worker(job['id'])
            except Exception:
                pass
    result_json({'success': True, 'job': job})


def action_discovery_active():
    try:
        active = list_discovery_jobs(unfinished_only=True)
    except Exception as exc:
        error_json(str(exc))
    job = max(active, key=lambda item: int(item.get('created_at', 0))) if active else None
    result_json({'success': True, 'job': job})


def run_discovery_schedule():
    """Cheap once-per-minute due/resume check called outside the browser."""
    try:
        interval = int(read_lldpq_conf_key('SCAN_INTERVAL', '300'))
    except ValueError:
        interval = 300
    if interval <= 0:
        return
    active = list_discovery_jobs(unfinished_only=True)
    if active:
        job = max(active, key=lambda item: int(item.get('created_at', 0)))
        heartbeat = max(int(job.get('worker_heartbeat', 0) or 0),
                        int(job.get('worker_started_at', 0) or 0))
        if time.time() - heartbeat > 120:
            try:
                launch_discovery_worker(job['id'])
            except Exception:
                pass
        return
    last_success = 0
    try:
        with open(DISCOVERY_CACHE_FILE, 'r') as handle:
            last_success = float((json.load(handle) or {}).get('timestamp', 0) or 0)
    except Exception:
        pass
    if time.time() - last_success >= interval:
        # Scheduled discovery is deliberately read-only.  Post-provision
        # actions remain available from an explicit operator-triggered scan,
        # but must never begin merely because cron became active after an
        # install or upgrade.
        start_discovery_job('schedule', False)


def action_save_post_provision():
    """Save post-provision toggle settings."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")

    discovery_range = str(data.get('discovery_range', '')).strip() if 'discovery_range' in data else None
    if discovery_range:
        parsed_ips = ip_range_to_list(discovery_range)
        if not parsed_ips or len(parsed_ips) > 1500:
            error_json('Invalid discovery range (maximum 1500 addresses)')
    scan_interval = None
    if 'scan_interval' in data:
        try:
            scan_interval = int(data['scan_interval'])
        except (TypeError, ValueError):
            error_json('Invalid scan interval')
        if scan_interval < 0 or scan_interval > 86400:
            error_json('Scan interval must be between 0 and 86400 seconds')

    updates = {}
    if 'auto_base_config' in data:
        updates['AUTO_BASE_CONFIG'] = 'true' if data['auto_base_config'] else 'false'
    if 'auto_ztp_disable' in data:
        updates['AUTO_ZTP_DISABLE'] = 'true' if data['auto_ztp_disable'] else 'false'
    if 'auto_set_hostname' in data:
        updates['AUTO_SET_HOSTNAME'] = 'true' if data['auto_set_hostname'] else 'false'
    if discovery_range is not None:
        updates['DISCOVERY_RANGE'] = discovery_range
    if scan_interval is not None:
        updates['SCAN_INTERVAL'] = str(scan_interval)

    try:
        update_lldpq_conf_values(updates)
    except Exception as exc:
        result_json({
            'success': False,
            'error_code': 'write_failed',
            'error': f'Settings were not saved: {exc}',
        })

    result_json({"success": True, "message": "Settings saved"})

# ======================== ZTP SCRIPT ========================

def action_get_ztp_script():
    if not os.path.exists(ZTP_SCRIPT_FILE):
        # Try alternate locations
        for alt in ['/var/www/html/cumulus-ztp.sh', f'{WEB_ROOT}/cumulus-ztp.sh']:
            if os.path.exists(alt):
                with open(alt, 'r') as f:
                    result_json({"success": True, "content": f.read(), "file": alt})
        result_json({"success": True, "content": "", "file": ZTP_SCRIPT_FILE})
    
    with open(ZTP_SCRIPT_FILE, 'r') as f:
        content = f.read()
    result_json({"success": True, "content": content, "file": ZTP_SCRIPT_FILE})


def validate_ztp_script_content(content):
    """Reject malformed or non-ZTP Bash before replacing the served script."""
    if not isinstance(content, str) or not content.strip():
        raise ValueError('Script content is empty')
    if '\x00' in content:
        raise ValueError('Script contains a NUL byte')
    if len(content.encode('utf-8')) > 512 * 1024:
        raise ValueError('Script is too large (max 512 KiB)')
    if 'CUMULUS-AUTOPROVISIONING' not in content:
        raise ValueError('Script is missing the CUMULUS-AUTOPROVISIONING marker')
    try:
        check = subprocess.run(
            ['/bin/bash', '--noprofile', '--norc', '-n'],
            input=content, capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Bash syntax validation timed out') from exc
    if check.returncode != 0:
        detail = (check.stderr or check.stdout or 'invalid Bash syntax').strip()
        raise ValueError(detail[-500:])
    return content


def is_current_ztp_template(content):
    """Require executable v2 capabilities, not marker/helper substrings alone."""
    version = re.search(r'LLDPQ_ZTP_TEMPLATE_VERSION=(\d+)', content or '')
    if not version or int(version.group(1)) < 2:
        return False
    required_functions = (
        'get_current_release',
        'is_valid_serial',
        'select_hostname_from_mapping',
        'resolve_hostname',
        'find_config_url',
        'apply_generated_config',
        'init_ztp',
        'main',
    )
    for name in required_functions:
        declaration = re.compile(
            rf'^\s*(?:function\s+{re.escape(name)}\s*(?:\(\))?'
            rf'|{re.escape(name)}\s*\(\s*\))\s*\{{',
            re.MULTILINE,
        )
        if not declaration.search(content):
            return False
    main_guard = re.search(
        r'if\s+\[\[\s*"\$\{BASH_SOURCE\[0\]\}"\s*==\s*"\$0"\s*\]\]'
        r'\s*;?\s*then',
        content,
    )
    main_call = re.search(r'^\s*main\s+"\$@"\s*$', content, re.MULTILINE)
    return bool(main_guard and main_call)


def ztp_script_public_key(content):
    """Return the configured OpenSSH public key, or empty when invalid."""
    key_pattern = re.compile(
        r'^(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-[A-Za-z0-9._-]+'
        r'|sk-(?:ssh-ed25519|ecdsa-sha2-[A-Za-z0-9._-]+)@openssh\.com)'
        r'\s+[A-Za-z0-9+/=]+(?:\s+.*)?$'
    )
    for line in (content or '').splitlines():
        if not re.match(r'^\s*KEY=', line):
            continue
        try:
            fields = shlex.split(line.strip(), posix=True)
        except ValueError:
            return ''
        if len(fields) != 1 or not fields[0].startswith('KEY='):
            return ''
        key = fields[0][4:]
        return key if key_pattern.fullmatch(key) else ''
    return ''


def ztp_script_static_setting(content, name):
    """Read one literal Quick Settings assignment without evaluating Bash."""
    if not re.fullmatch(r'[A-Z][A-Z0-9_]*', name):
        return ''
    assignments = []
    for line in (content or '').splitlines():
        if not re.match(rf'^\s*{re.escape(name)}=', line):
            continue
        try:
            fields = shlex.split(line.strip(), posix=True)
        except ValueError:
            return ''
        if len(fields) != 1 or not fields[0].startswith(name + '='):
            return ''
        assignments.append(fields[0].split('=', 1)[1])
    return assignments[0] if len(assignments) == 1 else ''


def action_save_ztp_script():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    if not isinstance(data, dict) or 'content' not in data:
        result_json({
            'success': False, 'error_code': 'invalid_ztp_script',
            'error': 'ZTP script was not saved: content must be provided',
        })
    content = data.get('content', '')
    try:
        content = validate_ztp_script_content(content)
    except ValueError as exc:
        result_json({
            'success': False, 'error_code': 'invalid_ztp_script',
            'error': f'ZTP script was not saved: {exc}',
        })

    filepath = ZTP_SCRIPT_FILE

    try:
        write_managed_text(filepath, content, 0o775)
    except Exception as exc:
        result_json({
            'success': False, 'error_code': 'write_failed',
            'error': f'ZTP script was not saved: {exc}',
        })
    
    result_json({"success": True, "message": "ZTP script saved"})

# ======================== DHCP STATUS ========================

def action_dhcp_service_status():
    """Check if DHCP service is running."""
    running = False
    
    # Try systemctl
    try:
        for svc in ['isc-dhcp-server', 'dhcpd']:
            r = subprocess.run(
                ['systemctl', 'is-active', svc],
                capture_output=True, text=True, timeout=5
            )
            if r.stdout.strip() == 'active':
                running = True
                break
    except Exception:
        pass
    
    if not running:
        # Check if dhcpd process is running
        try:
            r = subprocess.run(['pgrep', '-x', 'dhcpd'], capture_output=True, timeout=5)
            running = r.returncode == 0
        except Exception:
            pass
    
    result_json({"success": True, "running": running})

def _action_dhcp_service_control_locked():
    """Start, stop, or restart DHCP service."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    action = data.get('action', '')
    if action not in ('start', 'stop', 'restart'):
        error_json(f"Invalid action: {action}")
    
    # Try systemctl first (native install).  Docker falls through to direct
    # process management and persists the operator's desired lifecycle state.
    for svc in ['isc-dhcp-server', 'dhcpd']:
        try:
            r = subprocess.run(
                ['sudo', 'systemctl', action, svc],
                capture_output=True, text=True, timeout=15
            )
            if r.returncode == 0:
                # Stop also disables (prevent auto-start on boot)
                if action == 'stop':
                    subprocess.run(['sudo', 'systemctl', 'disable', svc],
                                   capture_output=True, text=True, timeout=10)
                    result_json({"success": True, "message": f"{svc} stopped & disabled"})
                # Start also enables
                elif action == 'start':
                    subprocess.run(['sudo', 'systemctl', 'enable', svc],
                                   capture_output=True, text=True, timeout=10)
                    result_json({"success": True, "message": f"{svc} started & enabled"})
                else:
                    result_json({"success": True, "message": f"{svc} restarted"})
        except Exception:
            continue
    
    # Fallback: direct process management (Docker/non-systemd).
    if action in ('stop', 'restart'):
        subprocess.run(['sudo', 'pkill', '-x', 'dhcpd'], capture_output=True, timeout=5)
        if action == 'stop':
            if dhcp_is_running():
                error_json('dhcpd did not stop')
            try:
                persist_docker_dhcp_desired_state(False)
            except Exception as exc:
                # Avoid a stopped service unexpectedly returning after a
                # recreate when the preference could not be recorded.
                restart_dhcp()
                error_json(f'dhcpd stopped but desired state could not be saved: {exc}')
            result_json({"success": True, "message": "dhcpd stopped"})
    
    if action in ('start', 'restart'):
        ok, msg = restart_dhcp()
        if ok:
            try:
                persist_docker_dhcp_desired_state(True)
            except Exception as exc:
                stop_dhcp_best_effort()
                result_json({"success": False,
                             "error": f'DHCP start rolled back because desired state could not be saved: {exc}',
                             "message": msg})
        result_json({"success": ok, "message": msg, "error": "" if ok else msg})
    
    error_json("Could not control DHCP service")


def action_dhcp_service_control():
    return run_with_dhcp_operation_lock(_action_dhcp_service_control_locked)

def action_get_dhcp_config():
    """Read dhcpd.conf and isc-dhcp-server defaults, return parsed settings."""
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    isc_default = ISC_DHCP_DEFAULT_FILE
    
    config = {
        'subnet': '', 'netmask': '', 'range_start': '', 'range_end': '',
        'gateway': '', 'dns': '', 'domain': '', 'provision_url': '',
        'interface': 'eth0', 'lease_time': '172800'
    }
    
    # Parse dhcpd.conf
    if os.path.exists(conf_path):
        try:
            with open(conf_path, 'r') as f:
                content = f.read()
        except PermissionError:
            r = subprocess.run(['sudo', 'cat', conf_path], capture_output=True, text=True, timeout=5)
            content = r.stdout if r.returncode == 0 else ''
        
        # subnet X netmask Y
        m = re.search(r'subnet\s+([\d.]+)\s+netmask\s+([\d.]+)', content)
        if m:
            config['subnet'] = m.group(1)
            config['netmask'] = m.group(2)
        
        # range START END
        m = re.search(r'range\s+([\d.]+)\s+([\d.]+)', content)
        if m:
            config['range_start'] = m.group(1)
            config['range_end'] = m.group(2)
        
        # option routers
        m = re.search(r'option\s+routers\s+([\d.]+)', content)
        if m:
            config['gateway'] = m.group(1)
        
        # option domain-name-servers
        m = re.search(r'option\s+domain-name-servers\s+([\d.]+)', content)
        if m:
            config['dns'] = m.group(1)
        
        # option domain-name
        m = re.search(r'option\s+domain-name\s+"([^"]*)"', content)
        if m:
            config['domain'] = m.group(1)
        
        # cumulus-provision-url
        m = re.search(r'cumulus-provision-url\s+"([^"]*)"', content)
        if m:
            config['provision_url'] = m.group(1)
        
        # default-lease-time
        m = re.search(r'default-lease-time\s+(\d+)', content)
        if m:
            config['lease_time'] = m.group(1)
    
    # Parse interface from /etc/default/isc-dhcp-server
    if os.path.exists(isc_default):
        try:
            with open(isc_default, 'r') as f:
                isc_content = f.read()
            m = re.search(r'INTERFACES="([^"]*)"', isc_content)
            if m:
                config['interface'] = m.group(1)
        except Exception:
            pass
    
    # List network interfaces with IP addresses
    interfaces = []
    try:
        r = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            seen = set()
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    iface_name = parts[1]
                    ip_cidr = parts[3]  # e.g. 192.168.100.200/24
                    ip_addr = ip_cidr.split('/')[0]
                    if iface_name not in seen and iface_name != 'lo':
                        interfaces.append({'name': iface_name, 'ip': ip_addr})
                        seen.add(iface_name)
    except Exception:
        pass
    
    # Read discovery range and post-provision settings from lldpq.conf
    discovery_range = read_lldpq_conf_key('DISCOVERY_RANGE', '')
    # Auto-generate default from subnet if empty
    if not discovery_range and config['subnet']:
        prefix = '.'.join(config['subnet'].split('.')[:3])
        discovery_range = f'{prefix}.10-{prefix}.249'
    
    # Scan interval (default 300 = 5 min)
    scan_interval_str = read_lldpq_conf_key('SCAN_INTERVAL', '300')
    try:
        scan_interval = int(scan_interval_str)
    except ValueError:
        scan_interval = 300
    
    result_json({
        "success": True,
        "interfaces": interfaces,
        "discovery_range": discovery_range,
        "auto_base_config": read_lldpq_conf_key('AUTO_BASE_CONFIG', 'true') == 'true',
        "auto_ztp_disable": read_lldpq_conf_key('AUTO_ZTP_DISABLE', 'true') == 'true',
        "auto_set_hostname": read_lldpq_conf_key('AUTO_SET_HOSTNAME', 'true') == 'true',
        "scan_interval": scan_interval,
        **config
    })

def _action_save_dhcp_config_locked():
    """Validate, activate and verify DHCP configuration transactionally."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    try:
        subnet_text = str(data.get('subnet', '')).strip()
        netmask_text = str(data.get('netmask', '255.255.255.0')).strip()
        network = ipaddress.IPv4Network(f'{subnet_text}/{netmask_text}', strict=False)
        if str(network.network_address) != subnet_text:
            raise ValueError(f'Subnet must be the network address ({network.network_address})')
        gateway = ipaddress.IPv4Address(str(data.get('gateway', '')).strip())
        if gateway not in network or gateway in (network.network_address, network.broadcast_address):
            raise ValueError('Gateway must be a usable address inside the DHCP subnet')
        dns_text = str(data.get('dns', '')).strip() or str(gateway)
        dns = ipaddress.IPv4Address(dns_text)
        range_start_text = str(data.get('range_start', '')).strip()
        range_end_text = str(data.get('range_end', '')).strip()
        if bool(range_start_text) != bool(range_end_text):
            raise ValueError('Dynamic range start and end must be set together')
        range_start = range_end = None
        if range_start_text:
            range_start = ipaddress.IPv4Address(range_start_text)
            range_end = ipaddress.IPv4Address(range_end_text)
            if range_start not in network or range_end not in network:
                raise ValueError('Dynamic range must stay inside the DHCP subnet')
            if range_start in (network.network_address, network.broadcast_address) or \
               range_end in (network.network_address, network.broadcast_address):
                raise ValueError('Dynamic range cannot use network or broadcast addresses')
            if int(range_start) > int(range_end):
                raise ValueError('Dynamic range start must not be after range end')
        lease_time = int(str(data.get('lease_time', '172800')).strip())
        if lease_time < 60 or lease_time > 31536000:
            raise ValueError('Lease time must be between 60 and 31536000 seconds')
        domain = str(data.get('domain', 'example.com')).strip() or 'example.com'
        if len(domain) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', domain):
            raise ValueError('Invalid DHCP domain name')
        iface = str(data.get('interface', '')).strip()
        if not iface or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', iface):
            raise ValueError('Invalid DHCP listen interface')
        interface_names = set()
        link_result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True,
                                     text=True, timeout=5)
        if link_result.returncode == 0:
            for line in link_result.stdout.splitlines():
                match = re.match(r'^\d+:\s+([^:@]+)', line)
                if match:
                    interface_names.add(match.group(1))
        if interface_names and iface not in interface_names:
            raise ValueError(f'DHCP interface does not exist: {iface}')

        docker_dhcp_mode = os.environ.get('LLDPQ_DHCP_MODE', '').strip().lower()
        runtime_iface = os.environ.get('DHCP_INTERFACE', '').strip()
        runtime_server_ip = None
        if docker_dhcp_mode == 'host':
            if not runtime_iface:
                raise ValueError('Docker DHCP host mode is missing DHCP_INTERFACE')
            if iface != runtime_iface:
                raise ValueError(
                    f'Docker DHCP host mode is bound to interface {runtime_iface}'
                )
            try:
                runtime_server_ip = ipaddress.IPv4Address(
                    os.environ.get('PROVISION_SERVER_IP', '').strip()
                )
            except ipaddress.AddressValueError as exc:
                raise ValueError(
                    'Docker DHCP host mode is missing a valid PROVISION_SERVER_IP'
                ) from exc

        provision_url = str(data.get('provision_url', '')).strip()
        if not provision_url:
            default_server = runtime_server_ip or get_server_ip()
            provision_url = f'http://{default_server}/cumulus-ztp.sh'
        parsed_url = urlparse(provision_url)
        if parsed_url.scheme not in ('http', 'https') or not parsed_url.hostname:
            raise ValueError('Provision URL must be an absolute HTTP or HTTPS URL')
        try:
            server_ip = ipaddress.IPv4Address(parsed_url.hostname)
        except ipaddress.AddressValueError:
            # Keep the operator's DNS URL intact, but DHCP option 72 requires
            # a concrete IPv4 address.
            try:
                server_ip = ipaddress.IPv4Address(
                    socket.gethostbyname(parsed_url.hostname)
                )
            except (OSError, ipaddress.AddressValueError) as exc:
                raise ValueError(
                    f'Provision URL hostname does not resolve to IPv4: {parsed_url.hostname}'
                ) from exc
        if runtime_server_ip is not None and server_ip != runtime_server_ip:
            resolved_addresses = {str(server_ip)}
            try:
                resolved_addresses.update(
                    item[4][0] for item in socket.getaddrinfo(
                        parsed_url.hostname, parsed_url.port or 80,
                        socket.AF_INET, socket.SOCK_STREAM,
                    )
                )
            except (OSError, ValueError):
                pass
            if str(runtime_server_ip) not in resolved_addresses:
                raise ValueError(
                    'Provision URL must resolve to Docker PROVISION_SERVER_IP '
                    f'({runtime_server_ip})'
                )
            server_ip = runtime_server_ip
        server_base_url = f'{parsed_url.scheme}://{parsed_url.netloc}/'

        discovery_range = str(data.get('discovery_range', '')).strip()
        if discovery_range:
            discovery_ips = ip_range_to_list(discovery_range)
            if not discovery_ips or len(discovery_ips) > 1500:
                raise ValueError('Invalid discovery range (maximum 1500 addresses)')
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        error_json(str(exc))
    except Exception as exc:
        error_json(f'DHCP configuration validation failed: {exc}')

    # Find hosts include path
    hosts_path = get_dhcp_hosts_path()
    range_line = f'    range {range_start} {range_end};' if range_start is not None else '    # range not configured'
    prov_line = f'    option cumulus-provision-url "{provision_url}";' if provision_url else ''
    conf = f"""# /etc/dhcp/dhcpd.conf - Generated by LLDPq

ddns-update-style none;
authoritative;
log-facility local7;

option www-server code 72 = ip-address;
option default-url code 114 = text;
option cumulus-provision-url code 239 = text;
option space onie code width 1 length width 1;
option onie.installer_url code 1 = text;
option onie.updater_url   code 2 = text;
option onie.machine       code 3 = text;
option onie.arch          code 4 = text;
option onie.machine_rev   code 5 = text;

option space vivso code width 4 length width 1;
option vivso.onie code 42623 = encapsulate onie;
option vivso.iana code 0 = string;
option op125 code 125 = encapsulate vivso;

class "onie-vendor-classes" {{
  match if substring(option vendor-class-identifier, 0, 11) = "onie_vendor";
  option vivso.iana 01:01:01;
}}

# OOB Management subnet
shared-network OOB {{
  subnet {network.network_address} netmask {network.netmask} {{
{range_line}
    option routers {gateway};
    option domain-name "{domain}";
    option domain-name-servers {dns};
    option www-server {server_ip};
    option default-url "{server_base_url}";
{prov_line}
    default-lease-time {lease_time};
    max-lease-time     {lease_time * 2};
  }}
}}

include "{hosts_path}";
"""
    conf_path = os.environ.get('DHCP_CONF_FILE', '/etc/dhcp/dhcpd.conf')
    isc_default = ISC_DHCP_DEFAULT_FILE
    isc_content = f'INTERFACES="{iface}"\n'

    # Inventory Save updates the included hosts file.  Lock before reading it
    # so validation, snapshots, activation and rollback are one serializable
    # transaction with inventory edits.
    inventory_lock = open(INVENTORY_LOCK_FILE, 'a+')
    try:
        os.chmod(INVENTORY_LOCK_FILE, 0o664)
    except OSError:
        pass
    fcntl.flock(inventory_lock.fileno(), fcntl.LOCK_EX)

    try:
        try:
            with open(hosts_path, 'r') as handle:
                hosts_content = handle.read()
        except FileNotFoundError:
            hosts_content = ''
        hosts_content = rewrite_dhcp_hosts_server_options(
            hosts_content, server_ip, server_base_url, provision_url
        )

        # dhcpd -t accepts reservations inside a dynamic pool.  Reject those
        # overlaps explicitly because they can assign the gateway, server or a
        # fixed device address to an unrelated client.
        if range_start is not None:
            pool_start, pool_end = int(range_start), int(range_end)
            protected = {str(gateway): 'gateway'}
            if server_ip in network:
                protected[str(server_ip)] = 'provision server'
            for address in re.findall(
                r'\bfixed-address\s+([0-9.]+)\s*;', hosts_content
            ):
                try:
                    reserved = ipaddress.IPv4Address(address)
                except ipaddress.AddressValueError:
                    continue
                protected[str(reserved)] = 'fixed reservation'
            overlaps = [
                f'{address} ({label})' for address, label in protected.items()
                if pool_start <= int(ipaddress.IPv4Address(address)) <= pool_end
            ]
            if overlaps:
                raise ValueError(
                    'Dynamic range overlaps protected address(es): ' + ', '.join(overlaps)
                )

        validate_dhcp_config_candidate(
            conf, hosts_content, hosts_path, require_binary=True
        )

        # Preserve Docker symlink-backed persistent targets instead of
        # replacing the symlink itself.
        conf_target = os.path.realpath(conf_path) if os.path.islink(conf_path) else conf_path
        default_target = os.path.realpath(isc_default) if os.path.islink(isc_default) else isc_default
        hosts_target = os.path.realpath(hosts_path) if os.path.islink(hosts_path) else hosts_path
    except Exception as exc:
        result_json({
            'success': False,
            'error': f'DHCP configuration was not changed: {exc}',
            'validated': False,
            'rollback_performed': False,
        })

    rollback_performed = False
    was_running = dhcp_is_running()
    # Inventory Save also writes dhcpd.hosts.  One shared lock prevents either
    # transaction from rolling back over the other's newer reservations.
    journal = None
    try:
        try:
            service_state = 'running' if was_running else 'stopped'
            journal = begin_provision_transaction(
                'dhcp-config-save', [
                    (conf_target, conf, 0o664),
                    (default_target, isc_content, 0o664),
                    (hosts_target, hosts_content, 0o664),
                ], service_state, service_state,
            )
            mark_provision_transaction(journal, 'activating')
            atomic_write_text(conf_target, conf, 0o664)
            atomic_write_text(default_target, isc_content, 0o664)
            atomic_write_text(hosts_target, hosts_content, 0o664)
            with open(conf_target, 'r') as handle:
                if handle.read() != conf:
                    raise RuntimeError('DHCP config readback mismatch')
            with open(default_target, 'r') as handle:
                if handle.read() != isc_content:
                    raise RuntimeError('DHCP interface config readback mismatch')
            sync_provision_transaction_targets(journal)
            if was_running:
                ok, msg = restart_dhcp()
                if not ok:
                    raise RuntimeError(msg or 'DHCP failed to restart')
            else:
                ok, msg = True, 'configuration saved; service remains stopped'
            mark_provision_transaction(journal, 'committed')
            _clear_provision_transaction()
        except Exception as exc:
            detail = f'DHCP activation failed: {exc}'
            if journal and journal.get('phase') == 'committed':
                detail += '; data was committed but transaction cleanup is pending'
            elif journal:
                try:
                    rollback_provision_transaction(journal)
                    rollback_performed = True
                except Exception as restore_exc:
                    detail += '; rollback pending recovery: ' + str(restore_exc)
            result_json({
                'success': False,
                'error': detail,
                'dhcp_restart': False,
                'validated': True,
                'rollback_performed': rollback_performed,
            })
    finally:
        fcntl.flock(inventory_lock.fileno(), fcntl.LOCK_UN)
        inventory_lock.close()

    # Persist related settings only after the DHCP transaction completed, and
    # never report a full success if that separate atomic write failed.
    related_updates = {}
    if discovery_range:
        related_updates['DISCOVERY_RANGE'] = discovery_range
    if 'auto_base_config' in data:
        related_updates['AUTO_BASE_CONFIG'] = 'true' if data['auto_base_config'] else 'false'
    if 'auto_ztp_disable' in data:
        related_updates['AUTO_ZTP_DISABLE'] = 'true' if data['auto_ztp_disable'] else 'false'
    if 'auto_set_hostname' in data:
        related_updates['AUTO_SET_HOSTNAME'] = 'true' if data['auto_set_hostname'] else 'false'
    try:
        update_lldpq_conf_values(related_updates)
    except Exception as exc:
        result_json({
            'success': False,
            'error_code': 'write_failed',
            'error': (
                'DHCP configuration was saved, but related Provision settings '
                f'were not saved: {exc}'
            ),
            'dhcp_restart': bool(was_running),
            'validated': True,
            'rollback_performed': rollback_performed,
        })
    result_json({
        "success": True,
        "message": f"Config saved. DHCP: {msg}",
        "dhcp_restart": bool(was_running),
        "validated": True,
        "rollback_performed": rollback_performed,
        "server_ip": str(server_ip),
    })


def action_save_dhcp_config():
    return run_with_dhcp_operation_lock(_action_save_dhcp_config_locked)

def parse_dhcp_leases(filepath):
    """Parse ISC dhcpd.leases file."""
    leases = []
    if not os.path.exists(filepath):
        return leases
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Parse lease blocks
    lease_pattern = re.compile(
        r'lease\s+([\d.]+)\s*\{(.*?)\}',
        re.DOTALL
    )
    
    for m in lease_pattern.finditer(content):
        ip = m.group(1)
        block = m.group(2)
        
        lease = {'ip': ip, 'mac': '', 'hostname': '', 'start': '', 'end': '', 'state': 'active'}
        
        # Parse fields
        mac_m = re.search(r'hardware\s+ethernet\s+([\w:]+)', block)
        if mac_m:
            lease['mac'] = mac_m.group(1).lower()
        
        host_m = re.search(r'client-hostname\s+"([^"]*)"', block)
        if host_m:
            lease['hostname'] = host_m.group(1)
        
        start_m = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if start_m:
            lease['start'] = start_m.group(1)
        
        end_m = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+)', block)
        if end_m:
            lease['end'] = end_m.group(1)
        
        state_m = re.search(r'binding\s+state\s+(\w+)', block)
        if state_m:
            lease['state'] = state_m.group(1)
        
        leases.append(lease)
    
    # Deduplicate: keep last lease per IP (most recent)
    seen = {}
    for l in leases:
        seen[l['ip']] = l
    
    return sorted(seen.values(), key=lambda x: x['ip'])

def action_dhcp_leases():
    leases = parse_dhcp_leases(DHCP_LEASES_FILE)
    bindings = parse_dhcp_hosts(get_dhcp_hosts_path())
    result_json({
        "success": True,
        "leases": leases,
        "reserved_count": len(bindings)
    })


def action_dhcp_log():
    """Return the tail of the DHCP server log.
    Docker logs to DHCP_LOG_FILE (dhcpd -d). On systemd hosts we fall back to journalctl."""
    try:
        n = int(os.environ.get('LINES_PARAM') or 300)
    except Exception:
        n = 300
    n = max(20, min(n, 2000))
    text, source = '', ''
    # 1) Docker: tail the log file (read only the last chunk, efficient on big logs)
    if os.path.exists(DHCP_LOG_FILE):
        try:
            with open(DHCP_LOG_FILE, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 262144))
                chunk = f.read().decode('utf-8', 'replace')
            lines = chunk.splitlines()
            if lines:
                text = '\n'.join(lines[-n:])
                source = DHCP_LOG_FILE
        except Exception as e:
            text, source = 'Error reading %s: %s' % (DHCP_LOG_FILE, e), DHCP_LOG_FILE
    # 2) systemd host fallback: journalctl
    if not text:
        import shutil
        if shutil.which('journalctl'):
            for unit in ('isc-dhcp-server', 'dhcpd'):
                try:
                    r = subprocess.run(['sudo', 'journalctl', '-u', unit, '-n', str(n), '--no-pager'],
                                       capture_output=True, text=True, timeout=10)
                    if r.returncode == 0 and r.stdout.strip():
                        text, source = r.stdout, 'journalctl -u %s' % unit
                        break
                except Exception:
                    continue
    result_json({"success": True, "log": text, "source": source or DHCP_LOG_FILE,
                 "exists": bool(text)})

# ======================== LIST DEVICES ========================

def action_list_devices():
    """List devices from devices.yaml for base config deploy target selection."""
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    
    if not os.path.exists(devices_file):
        error_json(f"devices.yaml not found at {devices_file}")
    
    try:
        import yaml
        with open(devices_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        error_json(str(e))
    
    defaults = data.get('defaults', {})
    default_username = defaults.get('username', 'cumulus')
    
    devices_section = data.get('devices', data)
    devices = []
    
    groups = {}  # role -> [devices]
    
    for ip, info in devices_section.items():
        if ip in ('defaults', 'endpoint_hosts'):
            continue
        
        role = 'ungrouped'
        if isinstance(info, dict):
            hostname = info.get('hostname', str(ip))
            username = info.get('username', default_username)
            role = info.get('role', 'ungrouped')
        elif isinstance(info, str):
            # Format: "hostname @role" or just "hostname"
            raw = info.strip()
            if '@' in raw:
                parts = raw.split('@')
                hostname = parts[0].strip()
                role = parts[1].strip()
            else:
                hostname = raw
            username = default_username
        else:
            hostname = str(info) if info else str(ip)
            username = default_username
        
        dev = {'ip': str(ip), 'hostname': hostname, 'username': username, 'role': role}
        groups.setdefault(role, []).append(dev)
    
    # Sort devices within each group by hostname
    for role in groups:
        groups[role].sort(key=lambda x: x['hostname'])
    
    # Flat list for backward compat
    all_devices = []
    for devs in groups.values():
        all_devices.extend(devs)
    all_devices.sort(key=lambda x: x['hostname'])
    
    result_json({"success": True, "devices": all_devices, "groups": groups})

# ======================== BASE CONFIG DEPLOY ========================

# File deployment mapping: source name -> (destination, permissions, extra_dest)
FILE_DEPLOY_MAP = {
    'bash.bashrc': [
        {'dest': '/etc/bash.bashrc', 'mode': '644'},
        {'dest': '/home/cumulus/.bashrc', 'mode': '644'}
    ],
    'motd.sh': [
        {'dest': '/etc/profile.d/motd.sh', 'mode': '755'}
    ],
    'tmux.conf': [
        {'dest': '/etc/tmux.conf', 'mode': '644'},
        {'dest': '/home/cumulus/.tmux.conf', 'mode': '644'}
    ],
    'nanorc': [
        {'dest': '/etc/nanorc', 'mode': '644'},
        {'dest': '/home/cumulus/.nanorc', 'mode': '644'}
    ],
    'cmd': [
        {'dest': '/usr/local/bin/cmd', 'mode': '755'}
    ],
    'nvc': [
        {'dest': '/usr/local/bin/nvc', 'mode': '755'}
    ],
    'nvt': [
        {'dest': '/usr/local/bin/nvt', 'mode': '755'}
    ],
    'exa': [
        {'dest': '/usr/bin/exa', 'mode': '755'}
    ]
}

BASE_STATE_FILE = '/etc/lldpq-base-config.sha256'
ZTP_STATE_FILE = '/etc/lldpq-ztp-disabled'
HOSTNAME_STATE_FILE = '/etc/lldpq-hostname-target'
LEGACY_BASE_MARKER = '/etc/lldpq-base-deployed'


def base_config_manifest(files):
    digest = hashlib.sha256()
    selected = []
    for fname in sorted(set(files)):
        if fname not in FILE_DEPLOY_MAP:
            continue
        source = os.path.join(BASE_CONFIG_DIR, fname)
        if not os.path.isfile(source):
            continue
        selected.append(fname)
        digest.update(fname.encode('utf-8') + b'\0')
        for target in FILE_DEPLOY_MAP[fname]:
            digest.update(target['dest'].encode('utf-8') + b'\0')
            digest.update(target['mode'].encode('ascii') + b'\0')
        with open(source, 'rb') as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
    if not selected:
        raise ValueError('No source files found')
    return selected, digest.hexdigest()


def verify_and_migrate_legacy_base_state(
        ip, username, files, manifest, expected_mac='', expected_serial=''):
    """Verify legacy deployments before adopting the new manifest marker."""
    expectations = []
    for filename in files:
        source = os.path.join(BASE_CONFIG_DIR, filename)
        if not os.path.isfile(source):
            return False
        source_hash = sha256_file(source)
        for target in FILE_DEPLOY_MAP.get(filename, []):
            expectations.append((
                target['dest'], target['mode'], source_hash,
            ))
    if not expectations:
        return False

    identity_guard = remote_identity_guard_shell(expected_mac, expected_serial)
    commands = ['set -e', identity_guard]
    for index, (destination, _mode, _digest) in enumerate(expectations):
        quoted = shlex.quote(destination)
        commands.append(
            f"printf 'LLDPQ_CHECK_{index}='; "
            f"sudo sha256sum -- {quoted} | awk '{{printf $1}}'; "
            f"printf ':'; sudo stat -c '%a\\n' -- {quoted}"
        )
    try:
        result = subprocess.run(
            [
                'sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                f'{username}@{ip}', '; '.join(commands),
            ],
            capture_output=True, text=True, timeout=45,
        )
    except Exception:
        return False
    if result.returncode != 0:
        return False

    observed = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r'LLDPQ_CHECK_(\d+)=([0-9a-f]{64}):([0-7]{3,4})', line.strip())
        if match:
            observed[int(match.group(1))] = (match.group(2), match.group(3).lstrip('0') or '0')
    for index, (_destination, mode, digest) in enumerate(expectations):
        expected_mode = mode.lstrip('0') or '0'
        if observed.get(index) != (digest, expected_mode):
            return False

    quoted_manifest = shlex.quote(manifest)
    command = (
        f"set -e; {identity_guard}; printf '%s\\n' {quoted_manifest} | "
        f"sudo tee {BASE_STATE_FILE} >/dev/null; "
        f"test \"$(sudo cat {BASE_STATE_FILE})\" = {quoted_manifest}"
    )
    try:
        migrated = subprocess.run(
            [
                'sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                f'{username}@{ip}', command,
            ],
            capture_output=True, text=True, timeout=20,
        )
        return migrated.returncode == 0
    except Exception:
        return False

def _deploy_to_device(device, files, disable_ztp):
    """Deploy base config files to a single device via SCP + SSH.
    Returns result dict.
    """
    ip = device['ip']
    hostname = device['hostname']
    username = device.get('username', 'cumulus')
    expected_mac = normalize_identity_mac(device.get('expected_mac', ''))
    expected_serial = normalize_identity_serial(device.get('expected_serial', ''))
    # Every configuration mutation is fail-closed. Callers must resolve a
    # current canonical inventory identity before reaching this function.
    identity_guard = remote_identity_guard_shell(expected_mac, expected_serial)

    result = {
        'ip': ip,
        'hostname': hostname,
        'success': False,
        'message': '',
        'error': '',
        'steps': {'connect': 'pending', 'scp': 'pending', 'files': 'pending',
                  'ztp_disable': 'pending' if disable_ztp else 'skipped',
                  'state_write': 'pending'}
    }

    try:
        files, manifest = base_config_manifest(files)
    except ValueError as exc:
        result['error'] = str(exc)
        return result
    remote_dir = f'/tmp/lldpq-base-{uuid.uuid4().hex}'
    ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']

    def ssh_run(command, timeout=30, script_input=None):
        return subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts +
            [f'{username}@{ip}', command],
            input=script_input, capture_output=True, text=True, timeout=timeout
        )

    def cleanup_remote_stage():
        try:
            ssh_run(f'rm -rf -- {shlex.quote(remote_dir)}', timeout=10)
        except Exception:
            pass

    # Step 1: Check connectivity and create a private staging directory.
    try:
        check_script = '\n'.join(filter(None, [
            'set -eu',
            identity_guard,
            f'mkdir -m 700 -- {shlex.quote(remote_dir)}',
            'echo ok',
        ])) + '\n'
        check = ssh_run('bash -s', timeout=15, script_input=check_script)
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or '').strip()[-300:]
            if check.returncode == 42 or 'identity' in detail.lower():
                result['error'] = 'Identity verification failed: ' + detail
            else:
                result['error'] = 'SSH connection failed (key not configured?)'
            return result
        result['steps']['connect'] = 'success'
    except subprocess.TimeoutExpired:
        result['error'] = 'SSH connection timeout'
        return result
    except Exception as e:
        result['error'] = str(e)
        return result
    
    # Step 2: SCP the exact manifest to the private staging directory.
    scp_files = [os.path.join(BASE_CONFIG_DIR, fname) for fname in files]
    try:
        scp_cmd = ['sudo', '-u', LLDPQ_USER, 'scp'] + ssh_opts + scp_files + [f'{username}@{ip}:{remote_dir}/']
        scp_result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if scp_result.returncode != 0:
            cleanup_remote_stage()
            result['error'] = f'SCP failed: {scp_result.stderr.strip()[:200]}'
            return result
        result['steps']['scp'] = 'success'
    except subprocess.TimeoutExpired:
        cleanup_remote_stage()
        result['error'] = 'SCP timeout'
        return result
    except Exception as e:
        cleanup_remote_stage()
        result['error'] = f'SCP error: {e}'
        return result
    
    # Step 3: Install and verify through a fail-fast remote script. Optional
    # actions cannot change the exit status of preceding file operations.
    install_commands = []
    has_bashrc = False
    for fname in files:
        for target in FILE_DEPLOY_MAP[fname]:
            source = f'{remote_dir}/{fname}'
            install_commands.append(
                f"sudo install -m {target['mode']} -- {shlex.quote(source)} {shlex.quote(target['dest'])}"
            )
        if fname == 'bash.bashrc':
            has_bashrc = True

    if has_bashrc:
        install_commands.append('rm -f /home/cumulus/.bash_login')
        install_commands.append("printf '%s\\n' '[ -f ~/.bashrc ] && . ~/.bashrc' > /home/cumulus/.profile")

    install_commands.extend([
        f"printf '%s\\n' {shlex.quote(manifest)} | sudo tee {BASE_STATE_FILE} >/dev/null",
        f'sudo touch {LEGACY_BASE_MARKER}',
        f"test \"$(sudo cat {BASE_STATE_FILE})\" = {shlex.quote(manifest)}",
        "echo LLDPQ_BASE_OK",
    ])
    if disable_ztp:
        install_commands.extend([
            'sudo ztp -d',
            f"printf '%s\\n' disabled | sudo tee {ZTP_STATE_FILE} >/dev/null",
            f"test \"$(sudo cat {ZTP_STATE_FILE})\" = disabled",
            'echo LLDPQ_ZTP_OK',
        ])

    remote_script = '\n'.join([
        'set -eu',
        identity_guard,
        f'STAGE={shlex.quote(remote_dir)}',
        "cleanup() { rm -rf -- \"$STAGE\"; }",
        'trap cleanup EXIT',
        'test -d "$STAGE"',
        *install_commands,
    ]) + '\n'
    try:
        ssh_result = ssh_run('bash -s', timeout=45, script_input=remote_script)
        base_ok = 'LLDPQ_BASE_OK' in ssh_result.stdout
        ztp_ok = not disable_ztp or 'LLDPQ_ZTP_OK' in ssh_result.stdout
        if base_ok:
            result['steps']['files'] = 'success'
            result['steps']['state_write'] = 'success'
        if disable_ztp and ztp_ok:
            result['steps']['ztp_disable'] = 'success'
        if ssh_result.returncode != 0 or not base_ok or not ztp_ok:
            detail = (ssh_result.stderr or ssh_result.stdout or 'remote command failed').strip()
            if ssh_result.returncode == 0:
                missing = []
                if not base_ok:
                    missing.append('base verification')
                if not ztp_ok:
                    missing.append('ZTP verification')
                detail = 'missing success marker: ' + ', '.join(missing)
            result['error'] = f'Remote install failed: {detail[-300:]}'
            return result
    except subprocess.TimeoutExpired:
        cleanup_remote_stage()
        result['error'] = 'SSH command timeout'
        return result
    except Exception as e:
        cleanup_remote_stage()
        result['error'] = f'SSH error: {e}'
        return result
    
    result['success'] = True
    result['manifest'] = manifest
    result['message'] = f'{len(files)} files deployed'
    return result


@contextmanager
def device_mutation_lock(ip):
    """Serialize all LLDPq configuration mutations for one target IP."""
    ip = str(ip or '')
    os.makedirs(DISCOVERY_JOBS_DIR, exist_ok=True)
    device_key = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:24]
    lock_path = os.path.join(
        DISCOVERY_JOBS_DIR, f'.device-deploy-{device_key}.lock'
    )
    with exclusive_file_lock(lock_path):
        yield


@contextmanager
def canonical_device_mutation(device):
    """Pin current inventory assignment and serialize one device mutation."""
    with inventory_shared_lock():
        bindings = _load_canonical_inventory_bindings_unlocked()
        canonical = canonicalize_inventory_target(device, bindings)
        with device_mutation_lock(canonical['ip']):
            yield canonical


def deploy_to_device(device, files, disable_ztp):
    """Authorize and serialize irreversible base-config writes per switch."""
    try:
        with canonical_device_mutation(device) as canonical:
            return _deploy_to_device(canonical, files, disable_ztp)
    except Exception as exc:
        return {
            'ip': str(device.get('ip', '')),
            'hostname': str(device.get('hostname', '')),
            'success': False,
            'error': f'Target authorization failed: {exc}',
        }

def action_deploy_base_config():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    files = data.get('files', [])
    devices = data.get('devices', [])
    disable_ztp = data.get('disable_ztp', False)
    
    # If no files specified, deploy all known files (skip missing ones)
    if not files:
        files = list(FILE_DEPLOY_MAP.keys())
    
    if not isinstance(devices, list) or not devices:
        error_json("No devices selected")
    if len(devices) > 1000:
        error_json('Too many devices selected')
    requested_devices = []
    for device in devices:
        if not isinstance(device, dict):
            error_json('Invalid device target')
        hostname = str(device.get('hostname', '')).strip()
        raw_ip = str(device.get('ip', '')).strip()
        username = str(device.get('username', 'cumulus')).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
            error_json('Invalid device hostname')
        try:
            ip = str(ipaddress.IPv4Address(raw_ip))
        except ipaddress.AddressValueError:
            error_json(f'Invalid device IP: {raw_ip}')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
            error_json('Invalid SSH username')
        requested_devices.append({
            'hostname': hostname, 'ip': ip, 'username': username,
        })
    
    # Filter to only files that exist on disk (graceful skip)
    available_files = [f for f in files if f in FILE_DEPLOY_MAP and os.path.exists(os.path.join(BASE_CONFIG_DIR, f))]
    if not available_files:
        error_json("No deploy files found in " + BASE_CONFIG_DIR)
    files = available_files
    
    # Deploy in parallel (20 workers max)
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(deploy_to_device, dev, files, disable_ztp): dev
            for dev in requested_devices
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                dev = futures[future]
                results.append({
                    'ip': dev['ip'],
                    'hostname': dev['hostname'],
                    'success': False,
                    'error': str(e)
                })
    
    # Sort by hostname
    results.sort(key=lambda x: x['hostname'])
    
    ok = sum(1 for r in results if r['success'])
    fail = len(results) - ok
    
    result_json({
        "success": True,
        "results": results,
        "summary": {"ok": ok, "fail": fail, "total": len(results)}
    })

# ======================== OS UPGRADE ========================

def image_version_from_name(name):
    m = re.search(r'cumulus-linux-([0-9][A-Za-z0-9._-]*?)-', name)
    return m.group(1) if m else ''


def valid_os_image_name(name):
    return bool(re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:bin|img|iso)', name or ''))


def resolve_os_image_path(name):
    """Prefer persistent storage while retaining native legacy compatibility."""
    if not valid_os_image_name(name):
        return None
    persistent = os.path.join(PROVISION_UPLOAD_DIR, name)
    if os.path.isfile(persistent):
        return persistent
    legacy = os.path.join(WEB_ROOT, name)
    if os.path.isfile(legacy):
        return legacy
    return None


def publish_provision_root_link(name):
    """Expose a persistent upload at the historical web-root URL."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', name or ''):
        return False
    stored = os.path.join(PROVISION_UPLOAD_DIR, name)
    if not os.path.lexists(stored):
        return False
    link = os.path.join(WEB_ROOT, name)
    relative_target = os.path.relpath(stored, WEB_ROOT)
    try:
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(relative_target, link)
        return True
    except Exception:
        command = 'ln -sfn -- %s %s' % (
            shlex.quote(relative_target), shlex.quote(link)
        )
        result = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0


def publish_uploaded_image(stage, destination, filename, expected_size):
    """Atomically publish an upload and restore the old image on any failure."""
    rollback_path = None
    legacy_rollback_path = None
    legacy_path = os.path.join(WEB_ROOT, filename)

    def hardlink_snapshot(source, snapshot):
        try:
            os.link(source, snapshot)
            return
        except PermissionError:
            command = 'ln -- %s %s' % (
                shlex.quote(source), shlex.quote(snapshot)
            )
            result = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise OSError(
                    result.stderr.strip() or 'Could not snapshot legacy image'
                )

    def restore_legacy_snapshot(snapshot, target):
        try:
            if os.path.lexists(target):
                os.unlink(target)
            os.replace(snapshot, target)
            return
        except PermissionError:
            command = 'mv -f -- %s %s' % (
                shlex.quote(snapshot), shlex.quote(target)
            )
            result = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise OSError(
                    result.stderr.strip() or 'Could not restore legacy image'
                )

    with upgrade_coordinator_lock():
        if any(
            job.get('image_name') == filename
            for job in list_upgrade_jobs(strict=True)
            if upgrade_job_holds_provision_resources(job)
        ):
            raise RuntimeError(
                'This image is in use by an active upgrade job and cannot be replaced'
            )

        if os.path.lexists(destination):
            if not os.path.isfile(destination):
                raise RuntimeError('Upload destination is not a regular file')
            rollback_path = os.path.join(
                os.path.dirname(destination),
                f'.{filename}.rollback-{os.getpid()}-{uuid.uuid4().hex}',
            )
            # Same-filesystem hard link: O(1) even for multi-gigabyte images.
            os.link(destination, rollback_path)

        # A pre-persistence native install may still keep the only old image
        # as a regular WEB_ROOT file. publish_provision_root_link replaces that
        # path, so snapshot it independently before touching either location.
        if os.path.abspath(legacy_path) != os.path.abspath(destination) and \
           os.path.isfile(legacy_path) and not os.path.islink(legacy_path):
            legacy_rollback_path = os.path.join(
                WEB_ROOT,
                f'.{filename}.rollback-{os.getpid()}-{uuid.uuid4().hex}',
            )
            hardlink_snapshot(legacy_path, legacy_rollback_path)

        try:
            os.replace(stage, destination)
            os.chmod(destination, 0o664)
            actual_size = os.path.getsize(destination)
            if actual_size != expected_size:
                raise RuntimeError(
                    f'Published image size mismatch ({actual_size}/{expected_size} bytes)'
                )
            fsync_directory(os.path.dirname(destination))
            if not publish_provision_root_link(filename):
                raise RuntimeError(
                    'web-root compatibility link could not be published'
                )
            return actual_size
        except Exception:
            if rollback_path and os.path.exists(rollback_path):
                os.replace(rollback_path, destination)
                rollback_path = None
                # Re-publish the historical URL for the restored image.
                publish_provision_root_link(filename)
            else:
                try:
                    os.unlink(destination)
                except FileNotFoundError:
                    pass
            if legacy_rollback_path and os.path.exists(legacy_rollback_path):
                restore_legacy_snapshot(legacy_rollback_path, legacy_path)
                legacy_rollback_path = None
            fsync_directory(os.path.dirname(destination))
            raise
        finally:
            if rollback_path:
                remove_upload_temp(rollback_path)
            if legacy_rollback_path:
                try:
                    os.unlink(legacy_rollback_path)
                except OSError:
                    subprocess.run(
                        ['sudo', '-u', LLDPQ_USER, 'rm', '-f', legacy_rollback_path],
                        capture_output=True, timeout=10,
                    )


def list_os_image_objects():
    images = []
    seen = set()
    import glob as g
    for image_root in (PROVISION_UPLOAD_DIR, WEB_ROOT):
        for ext in ['*.bin', '*.img', '*.iso']:
            for f in g.glob(os.path.join(image_root, ext)):
                name = os.path.basename(f)
                # Root-level compatibility links point back into persistent
                # storage; list each image once from its canonical location.
                if name.startswith('onie-installer') or name in seen or not os.path.isfile(f):
                    continue
                seen.add(name)
                size_bytes = os.path.getsize(f)
                images.append({
                    'name': name,
                    'size': f'{size_bytes / 1048576:.0f} MB' if size_bytes > 1048576 else f'{size_bytes / 1024:.0f} KB',
                    'size_bytes': size_bytes,
                    'version': image_version_from_name(name),
                    'path': f,
                })
    images.sort(key=lambda x: x['name'])
    return images

def get_device_version(device):
    ip = device.get('ip', '')
    hostname = device.get('hostname', ip)
    username = device.get('username', 'cumulus')
    result = {
        'ip': ip,
        'hostname': hostname,
        'username': username,
        'role': device.get('role', ''),
        'reachable': False,
        'current_version': '',
        'startup_config': False,
        'base_deployed': False,
        'upgrade_exit': None,
        'upgrade_operation': '',
        'upgrade_log': '',
        'error': '',
    }
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', str(username or '')):
        result['error'] = 'Invalid SSH username'
        return result
    try:
        cmd = (
            "echo OK; "
            "(grep '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || grep 'RELEASE' /etc/lsb-release 2>/dev/null | cut -d= -f2 || true); "
            "test -s /etc/nvue.d/startup.yaml && echo STARTUP_OK || echo STARTUP_MISSING; "
            "test -f /etc/lldpq-base-deployed && echo BASE_DEPLOYED || echo BASE_PENDING; "
            "test -s /tmp/lldpq-upgrade.operation && printf 'UPGRADE_OPERATION=%s\\n' \"$(cat /tmp/lldpq-upgrade.operation)\" || true; "
            "test -s /tmp/lldpq-upgrade.exit && printf 'UPGRADE_EXIT=%s\\n' \"$(cat /tmp/lldpq-upgrade.exit)\" || true; "
            "test -s /tmp/lldpq-upgrade.log && printf 'UPGRADE_LOG=%s\\n' \"$(tail -1 /tmp/lldpq-upgrade.log | tr '\\r\\n' '  ')\" || true"
        )
        r = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
             '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
             '-o', 'LogLevel=ERROR', f'{username}@{ip}', cmd],
            capture_output=True, text=True, timeout=12
        )
        if r.returncode != 0 or 'OK' not in r.stdout:
            result['error'] = (r.stderr or 'SSH failed').strip()[:200]
            return result
        lines = [x.strip() for x in r.stdout.splitlines() if x.strip()]
        result['reachable'] = True
        for line in lines:
            if line.startswith('UPGRADE_EXIT='):
                try:
                    result['upgrade_exit'] = int(line.split('=', 1)[1])
                except ValueError:
                    pass
                continue
            if line.startswith('UPGRADE_OPERATION='):
                result['upgrade_operation'] = line.split('=', 1)[1][:100]
                continue
            if line.startswith('UPGRADE_LOG='):
                result['upgrade_log'] = line.split('=', 1)[1][:300]
                continue
            if not result['current_version'] and line != 'OK' and \
               not line.startswith('STARTUP_') and not line.startswith('BASE_'):
                result['current_version'] = line
                continue
        result['startup_config'] = 'STARTUP_OK' in lines
        result['base_deployed'] = 'BASE_DEPLOYED' in lines
        return result
    except Exception as e:
        result['error'] = str(e)[:200]
        return result

def action_upgrade_candidates():
    devices = []
    data_holder = {}
    # Reuse devices.yaml parsing logic from list-devices without emitting JSON.
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        error_json(f"devices.yaml not found at {devices_file}")
    try:
        import yaml
        with open(devices_file, 'r') as f:
            raw = yaml.safe_load(f) or {}
        defaults = raw.get('defaults', {})
        default_username = defaults.get('username', 'cumulus')
        for ip, info in raw.get('devices', raw).items():
            if ip in ('defaults', 'endpoint_hosts'):
                continue
            role = 'ungrouped'
            if isinstance(info, dict):
                hostname = info.get('hostname', str(ip))
                username = info.get('username', default_username)
                role = info.get('role', 'ungrouped')
            elif isinstance(info, str):
                parts = info.strip().split('@')
                hostname = parts[0].strip()
                role = parts[1].strip() if len(parts) > 1 else 'ungrouped'
                username = default_username
            else:
                hostname = str(info) if info else str(ip)
                username = default_username
            devices.append({'ip': str(ip), 'hostname': hostname, 'username': username, 'role': role})
    except Exception as e:
        error_json(str(e))

    candidates = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(get_device_version, d): d for d in devices}
        for future in as_completed(futures):
            candidates.append(future.result())
    candidates.sort(key=lambda x: x.get('hostname', ''))
    result_json({'success': True, 'devices': candidates, 'images': list_os_image_objects(), 'server_ip': get_server_ip()})

def run_upgrade_precheck(device, target_version, image_name, server_ip):
    info = get_device_version(device)
    info['target_version'] = target_version
    info['precheck_ok'] = False
    checks = []
    if not info['reachable']:
        checks.append('SSH failed')
    if not info.get('current_version'):
        checks.append('Current version unknown')
    if info.get('current_version') == target_version:
        checks.append('Already at target')
    if not info.get('startup_config'):
        checks.append('startup.yaml missing')
    if not resolve_os_image_path(image_name):
        checks.append('Image missing on server')
    if not is_valid_server_ref(server_ip):
        checks.append('Invalid image server')
    if not checks:
        # Precheck is deliberately read-only. The guarded launch path performs
        # nv config save immediately before onie-install on the verified device.
        info['precheck_ok'] = True
        checks.append('OK')
    info['checks'] = checks
    return info

def action_upgrade_precheck():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    if not isinstance(data, dict):
        error_json('Upgrade precheck request must be an object')
    devices = data.get('devices', [])
    target_version = data.get('target_version', '').strip()
    image_name = os.path.basename(data.get('image_name', ''))
    server_ip = data.get('server_ip', '').strip()
    if not devices or not target_version or not image_name or not server_ip:
        error_json('devices, target_version, image_name and server_ip are required')
    if not valid_os_image_name(image_name):
        error_json('Invalid image filename')
    if not is_valid_server_ref(server_ip):
        error_json('Invalid image server. Set a real ZTP IMAGE SERVER IP first.')
    if not isinstance(devices, list):
        error_json('Upgrade devices must be a list')
    try:
        inventory = load_canonical_inventory_bindings()
    except Exception as exc:
        error_json(f'Could not load current inventory: {exc}')
    canonical_devices = []
    for device in devices:
        if not isinstance(device, dict):
            error_json('Each upgrade device must be an object')
        username = str(device.get('username', 'cumulus')).strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
            error_json('Invalid SSH username')
        try:
            canonical = canonicalize_inventory_target(device, inventory)
        except ValueError as exc:
            error_json(f'Upgrade target authorization failed: {exc}')
        canonical['username'] = username
        canonical_devices.append(canonical)
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                run_upgrade_precheck, d, target_version, image_name, server_ip
            ): d for d in canonical_devices
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda x: x.get('hostname', ''))
    result_json({'success': True, 'results': results})

def ensure_upgrade_jobs_dir():
    os.makedirs(UPGRADE_JOBS_DIR, exist_ok=True)
    try:
        subprocess.run(['sudo', 'chown', f'{LLDPQ_USER}:www-data', UPGRADE_JOBS_DIR], capture_output=True, timeout=5)
        subprocess.run(['sudo', 'chmod', '775', UPGRADE_JOBS_DIR], capture_output=True, timeout=5)
    except Exception:
        pass


@contextmanager
def upgrade_coordinator_lock():
    ensure_upgrade_jobs_dir()
    with exclusive_file_lock(os.path.join(UPGRADE_JOBS_DIR, '.coordinator.lock')):
        yield


def validate_upgrade_job_state(job, expected_id):
    """Validate persisted state at every list/load boundary.

    Missing schema_version is accepted only for completed historical jobs. An
    unfinished unversioned job must be reconciled by the installer before this
    runtime is activated; otherwise a direct status/worker call could bypass
    list_upgrade_jobs() and execute an unknown state-machine contract.
    """
    if not isinstance(job, dict) or job.get('id') != expected_id or \
            not isinstance(job.get('devices'), list) or not job['devices']:
        raise ValueError('job schema/id mismatch')
    if not isinstance(job.get('complete'), bool):
        raise ValueError('job complete flag is invalid')
    schema_version = job.get('schema_version')
    if schema_version is None:
        if not job['complete']:
            raise ValueError('unfinished upgrade job has no supported schema version')
        # Truly old terminal records remain displayable. The immediately
        # previous current contract is field-compatible with v2 and is fully
        # validated below even though it predates the explicit version tag.
        if not {
                'image_size', 'image_sha256', 'ready', 'aliases_published',
                'onie_alias_snapshot', 'ztp_artifact', 'ztp_size',
                'ztp_sha256',
        }.intersection(job):
            return
    elif isinstance(schema_version, bool) or not isinstance(schema_version, int) or \
            schema_version != UPGRADE_JOB_SCHEMA_VERSION:
        raise ValueError('unsupported upgrade job schema version')

    # Installer-reconciled pre-v4 jobs are immutable terminal history, not
    # resumable v2 worker state. Keep that deliberately narrow subtype
    # viewable while requiring every native v2 job to carry the full contract.
    reconciliation = job.get('legacy_reconciliation')
    if reconciliation is not None:
        if not job['complete'] or not isinstance(reconciliation, dict) or \
                reconciliation.get('action') != 'expired-job-reconciled-for-update' or \
                not re.fullmatch(r'[0-9a-f]{64}', str(reconciliation.get('original_sha256', ''))) or \
                not isinstance(reconciliation.get('backup_file'), str) or \
                '/' in reconciliation['backup_file'] or '\\' in reconciliation['backup_file'] or \
                any(not isinstance(item, dict) or item.get('status') not in
                    ('done', 'failed', 'cancelled', 'blocked')
                    for item in job['devices']):
            raise ValueError('invalid reconciled legacy upgrade state')
        return

    required = {
        'created_at', 'target_version', 'image_name', 'image_size',
        'image_sha256', 'server_ip', 'batch_size', 'stop_on_failure',
        'base_config_after', 'timeout_seconds', 'cancelled', 'ready',
        'aliases_published', 'onie_alias_snapshot', 'worker_started_at',
        'worker_heartbeat', 'ztp_artifact', 'ztp_size', 'ztp_sha256',
    }
    missing = sorted(required.difference(job))
    if missing:
        raise ValueError('upgrade job is missing: ' + ', '.join(missing))

    def positive_int(value, label, maximum=None):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or \
                (maximum is not None and value > maximum):
            raise ValueError(f'invalid {label}')

    def timestamp_int(value, label):
        positive_int(value, label)
        if value > int(time.time()) + 300:
            raise ValueError(f'invalid {label}')

    timestamp_int(job['created_at'], 'created_at')
    timestamp_int(job['worker_started_at'], 'worker_started_at')
    timestamp_int(job['worker_heartbeat'], 'worker_heartbeat')
    positive_int(job['image_size'], 'image_size')
    positive_int(job['ztp_size'], 'ztp_size')
    positive_int(job['batch_size'], 'batch_size', 100)
    positive_int(job['timeout_seconds'], 'timeout_seconds', 7 * 86400)
    if job['complete']:
        timestamp_int(job.get('completed_at'), 'completed_at')
    for key in ('stop_on_failure', 'base_config_after', 'cancelled',
                'ready', 'aliases_published'):
        if not isinstance(job[key], bool):
            raise ValueError(f'invalid {key}')
    if job['ready'] != job['aliases_published']:
        raise ValueError('inconsistent readiness/alias state')
    if not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,99}', str(job['target_version'])) or \
            not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:bin|img|iso)', str(job['image_name'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['image_sha256'])) or \
            not re.fullmatch(r'[0-9a-f]{64}', str(job['ztp_sha256'])) or \
            not is_valid_server_ref(str(job['server_ip'])):
        raise ValueError('invalid upgrade image/server metadata')
    expected_ztp = (
        f'provision-uploads/ztp-artifacts/{expected_id}.ztp'
    )
    if job['ztp_artifact'] != expected_ztp:
        raise ValueError('invalid upgrade ZTP artifact reference')
    snapshot = job['onie_alias_snapshot']
    expected_snapshot = {
        f'{scope}:{name}'
        for scope in ('uploads', 'web') for name in ONIE_ALIAS_NAMES
    }
    if not isinstance(snapshot, dict) or set(snapshot) != expected_snapshot or any(
            value is not None and (
                not isinstance(value, str) or
                not re.fullmatch(r'(?:provision-uploads/)?[A-Za-z0-9_.-]+', value)
            ) for value in snapshot.values()):
        raise ValueError('invalid ONIE alias rollback snapshot')

    statuses = {
        'queued', 'starting', 'upgrading', 'waiting_reboot',
        'done', 'failed', 'cancelled', 'blocked',
    }
    seen_ips = set()
    for item in job['devices']:
        if not isinstance(item, dict) or item.get('status') not in statuses:
            raise ValueError('invalid upgrade device state')
        try:
            ip = str(ipaddress.IPv4Address(str(item.get('ip', ''))))
        except ipaddress.AddressValueError as exc:
            raise ValueError('invalid upgrade device IP') from exc
        if ip in seen_ips:
            raise ValueError('duplicate upgrade device IP')
        seen_ips.add(ip)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',
                            str(item.get('hostname', ''))) or \
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',
                                 str(item.get('username', ''))) or \
                item.get('target_version') != job['target_version']:
            raise ValueError('invalid upgrade device identity')
        raw_expected_mac = str(item.get('expected_mac', '') or '')
        expected_mac = normalize_identity_mac(raw_expected_mac)
        expected_serial = normalize_identity_serial(item.get('expected_serial', ''))
        if raw_expected_mac.strip() and not expected_mac:
            raise ValueError('upgrade device has invalid MAC identity evidence')
        if not expected_mac and not expected_serial:
            raise ValueError('upgrade device has no identity evidence')
        if item['status'] in ('starting', 'upgrading', 'waiting_reboot') and (
                not re.fullmatch(UPGRADE_JOB_ID_PATTERN,
                                 str(item.get('operation_id', ''))) or
                item.get('claimed_at') is None):
            raise ValueError('invalid active upgrade device state')
        for key in ('claimed_at', 'remote_prepared_at', 'launch_attempted_at',
                    'started_at', 'last_check'):
            if item.get(key) is not None:
                timestamp_int(item[key], key)
        if item['status'] in ('upgrading', 'waiting_reboot') and any(
                item.get(key) is None
                for key in ('remote_prepared_at', 'launch_attempted_at', 'started_at')):
            raise ValueError('invalid launched upgrade device state')
    all_terminal = all(
        item['status'] in ('done', 'failed', 'cancelled', 'blocked')
        for item in job['devices']
    )
    if job['complete'] and not all_terminal:
        raise ValueError('upgrade completion/device states disagree')


def strict_upgrade_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f'duplicate JSON key: {key}')
        value[key] = item
    return value


def read_upgrade_job_state(path):
    """Read one stable regular job without following a replacement symlink."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('upgrade job is not a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('upgrade job changed while opening')
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise ValueError('upgrade job is unexpectedly large')
            chunks.append(chunk)
        after = os.lstat(path)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('upgrade job changed while reading')
        return json.loads(
            b''.join(chunks).decode('utf-8'),
            object_pairs_hook=strict_upgrade_json_object,
        )
    finally:
        os.close(descriptor)


def list_upgrade_jobs(unfinished_only=False, strict=False):
    ensure_upgrade_jobs_dir()
    jobs = []
    try:
        names = os.listdir(UPGRADE_JOBS_DIR)
    except OSError as exc:
        if strict:
            raise RuntimeError(
                f'Upgrade job directory is unreadable: {exc}'
            ) from exc
        return jobs
    for name in names:
        match = re.fullmatch(f'({UPGRADE_JOB_ID_PATTERN})\\.json', name)
        if not match:
            if strict and name.endswith('.json'):
                raise RuntimeError(
                    f'Upgrade job state has an invalid filename: {name}'
                )
            continue
        try:
            job = read_upgrade_job_state(
                os.path.join(UPGRADE_JOBS_DIR, name)
            )
            validate_upgrade_job_state(job, match.group(1))
        except Exception as exc:
            if strict:
                raise RuntimeError(
                    f'Upgrade job state is unreadable: {name}: {exc}'
                ) from exc
            continue
        if unfinished_only and job.get('complete'):
            continue
        jobs.append(job)
    return jobs


def upgrade_job_holds_provision_resources(job, now=None):
    """Keep uncertain remote installers isolated through the artifact grace."""
    if job.get('alias_rollback_failed'):
        return True
    if not job.get('complete'):
        return True
    uncertain = any(
        item.get('launch_attempted_at') and (
            item.get('launch_uncertain') or
            'timeout' in str(item.get('error', '')).lower()
        )
        for item in job.get('devices', [])
    )
    if not uncertain:
        return False
    completed_at = float(job.get('completed_at', 0) or 0)
    return not completed_at or \
        float(now or time.time()) - completed_at < ZTP_ARTIFACT_GRACE_SECONDS


def reject_provision_source_change_during_upgrade():
    """Keep mapping/config inputs stable for every device in one upgrade job."""
    try:
        jobs = list_upgrade_jobs(strict=True)
    except RuntimeError as exc:
        result_json({
            'success': False,
            'error_code': 'upgrade_state_invalid',
            'error': str(exc),
        })
    active = [job for job in jobs if upgrade_job_holds_provision_resources(job)]
    if not active:
        return
    newest = max(active, key=lambda item: int(item.get('created_at', 0)))
    result_json({
        'success': False,
        'error_code': 'upgrade_active',
        'error': 'Provisioning mappings/configs are locked while an upgrade job is active',
        'job': newest,
    })


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def upgrade_ztp_artifact_name(job_id):
    if not re.fullmatch(UPGRADE_JOB_ID_PATTERN, str(job_id or '')):
        raise ValueError('Invalid upgrade job id for ZTP artifact')
    return f'{job_id}.ztp'


def create_upgrade_ztp_artifact(job_id, content):
    """Publish the exact validated ZTP bytes used by one upgrade job."""
    name = upgrade_ztp_artifact_name(job_id)
    ensure_managed_directory(ZTP_ARTIFACTS_DIR, 0o775)
    path = os.path.join(ZTP_ARTIFACTS_DIR, name)
    if os.path.lexists(path):
        raise RuntimeError('Upgrade ZTP artifact already exists')
    try:
        write_managed_text(path, content, 0o644)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return {
        'ztp_artifact': f'provision-uploads/ztp-artifacts/{name}',
        'ztp_size': os.path.getsize(path),
        'ztp_sha256': sha256_file(path),
    }


def upgrade_ztp_artifact_path(job):
    relative = str(job.get('ztp_artifact', ''))
    try:
        expected_name = upgrade_ztp_artifact_name(job.get('id', ''))
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    expected_relative = f'provision-uploads/ztp-artifacts/{expected_name}'
    if relative != expected_relative:
        raise RuntimeError('Upgrade job has no valid pinned ZTP artifact')
    return os.path.join(ZTP_ARTIFACTS_DIR, expected_name)


def verify_upgrade_job_ztp(job):
    path = upgrade_ztp_artifact_path(job)
    if not os.path.isfile(path):
        raise RuntimeError('Pinned upgrade ZTP artifact is no longer available')
    if os.path.getsize(path) != int(job.get('ztp_size', -1)):
        raise RuntimeError('Pinned upgrade ZTP artifact size changed')
    if sha256_file(path) != job.get('ztp_sha256'):
        raise RuntimeError('Pinned upgrade ZTP artifact content changed')


def cleanup_upgrade_ztp_artifact(job):
    try:
        path = upgrade_ztp_artifact_path(job)
    except RuntimeError:
        return
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return True
    except PermissionError:
        result = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'rm', '-f', path],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0 and not os.path.lexists(path)
    except OSError:
        return False


def gc_upgrade_ztp_artifacts(jobs=None, now=None):
    """Remove only unreferenced/terminal artifacts after a reboot-safe grace."""
    if not os.path.isdir(ZTP_ARTIFACTS_DIR):
        return {'removed': [], 'errors': []}
    now = float(now or time.time())
    jobs = list_upgrade_jobs(strict=True) if jobs is None else jobs
    keep = set()
    for job in jobs:
        try:
            name = upgrade_ztp_artifact_name(job.get('id', ''))
        except ValueError:
            continue
        completed_at = float(job.get('completed_at', 0) or 0)
        if upgrade_job_holds_provision_resources(job, now) or \
                not completed_at or \
                now - completed_at < ZTP_ARTIFACT_GRACE_SECONDS:
            keep.add(name)

    removed = []
    errors = []
    for name in os.listdir(ZTP_ARTIFACTS_DIR):
        if not re.fullmatch(f'{UPGRADE_JOB_ID_PATTERN}\\.ztp', name) or name in keep:
            continue
        path = os.path.join(ZTP_ARTIFACTS_DIR, name)
        try:
            if now - os.path.getmtime(path) < ZTP_ARTIFACT_GRACE_SECONDS:
                continue
        except OSError as exc:
            errors.append(f'{name}: {exc}')
            continue
        synthetic = {
            'id': name[:-4],
            'ztp_artifact': f'provision-uploads/ztp-artifacts/{name}',
        }
        if cleanup_upgrade_ztp_artifact(synthetic):
            removed.append(name)
        else:
            errors.append(f'{name}: could not remove artifact')
    if errors:
        print('ZTP artifact cleanup warning: ' + '; '.join(errors), file=sys.stderr)
    return {'removed': removed, 'errors': errors}

def job_path(job_id):
    if not re.fullmatch(UPGRADE_JOB_ID_PATTERN, str(job_id or '')):
        error_json('Invalid job id')
    return os.path.join(UPGRADE_JOBS_DIR, f'{job_id}.json')

@contextmanager
def upgrade_job_lock(job_id):
    """Serialize API, cancellation and worker access to one job."""
    ensure_upgrade_jobs_dir()
    lock_path = job_path(job_id) + '.lock'
    handle = open(lock_path, 'a+')
    try:
        try:
            os.chmod(lock_path, 0o664)
        except OSError:
            pass
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()

def save_upgrade_job(job):
    ensure_upgrade_jobs_dir()
    validate_upgrade_job_state(job, str(job.get('id', '')))
    path = job_path(job['id'])
    fd, tmp = tempfile.mkstemp(prefix=f'.{job["id"]}.', suffix='.tmp', dir=UPGRADE_JOBS_DIR)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(job, f, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
        os.chmod(path, 0o664)
        try:
            dir_fd = os.open(UPGRADE_JOBS_DIR, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def load_upgrade_job(job_id):
    path = job_path(job_id)
    if not os.path.exists(path):
        error_json('Upgrade job not found')
    try:
        job = read_upgrade_job_state(path)
        validate_upgrade_job_state(job, job_id)
        return job
    except Exception as exc:
        error_json(f'Upgrade job state is invalid: {exc}')

def launch_upgrade_worker(job_id):
    """Start a browser-independent worker; its lifetime lock prevents duplicates."""
    env = os.environ.copy()
    for key in ('CONTENT_LENGTH', 'CONTENT_TYPE', 'QUERY_STRING', 'REQUEST_METHOD'):
        env.pop(key, None)
    proc = subprocess.Popen(
        ['/bin/bash', PROVISION_API_SCRIPT, '--upgrade-worker', job_id],
        env=env,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    return proc.pid

def _start_upgrade_for_device(dev, image_url, ztp_url, operation_id):
    ip = dev.get('ip')
    username = dev.get('username', 'cumulus')
    remote = 'set -e\n' + remote_identity_guard_shell(
        dev.get('expected_mac', ''), dev.get('expected_serial', '')
    ) + '\n' + r'''
IMAGE_URL="$1"
ZTP_URL="$2"
OPERATION_ID="$3"
sudo nv config save
test -s /etc/nvue.d/startup.yaml

# A worker can die after the remote process starts but before local state is
# committed.  Reusing the persisted operation ID makes that retry idempotent.
current_operation="$(sudo cat /tmp/lldpq-upgrade.operation 2>/dev/null || true)"
if [ "$current_operation" != "$OPERATION_ID" ]; then
  if pgrep -f '/usr/cumulus/bin/onie-install' >/dev/null 2>&1; then
    echo "another LLDPq upgrade operation is already running" >&2
    exit 75
  fi
  # Exit/log files belong to the previous operation. Keeping them would make
  # the new ID look "already started" before onie-install is dispatched.
  sudo rm -f /tmp/lldpq-upgrade.exit /tmp/lldpq-upgrade.log
fi
if [ "$current_operation" = "$OPERATION_ID" ]; then
  if pgrep -f '/usr/cumulus/bin/onie-install' >/dev/null 2>&1 || \
     [ -s /tmp/lldpq-upgrade.exit ]; then
    echo LLDPQ_UPGRADE_ALREADY_STARTED
    exit 0
  fi
fi
sudo rm -f /tmp/lldpq-upgrade.exit /tmp/lldpq-upgrade.log
printf '%s\n' "$OPERATION_ID" | sudo tee /tmp/lldpq-upgrade.operation >/dev/null
echo LLDPQ_UPGRADE_DISPATCHING
sudo -n env IMAGE_URL="$IMAGE_URL" ZTP_URL="$ZTP_URL" nohup bash -c '
  /usr/cumulus/bin/onie-install -fa -i "$IMAGE_URL" -z "$ZTP_URL" -t /etc/nvue.d/startup.yaml
  rc=$?
  if [ "$rc" -eq 0 ]; then
    reboot
    rc=$?
  fi
  printf "%s\n" "$rc" >/tmp/lldpq-upgrade.exit
  exit "$rc"
' >/tmp/lldpq-upgrade.log 2>&1 </dev/null &
pid=$!
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  wait "$pid" || true
  tail -20 /tmp/lldpq-upgrade.log 2>/dev/null || true
  exit 1
fi
echo LLDPQ_UPGRADE_STARTED
'''
    try:
        r = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
             '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
             '-o', 'LogLevel=ERROR', f'{username}@{ip}', 'bash -s --', image_url,
             ztp_url, operation_id],
            input=remote, capture_output=True, text=True, timeout=35
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ''
        stderr = exc.stderr or ''
        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8', 'replace')
        if isinstance(stderr, bytes):
            stderr = stderr.decode('utf-8', 'replace')
        ambiguous = 'LLDPQ_UPGRADE_DISPATCHING' in stdout
        detail = (stderr or stdout or 'Upgrade launch timed out').strip()[:300]
        return False, detail, ambiguous
    except Exception as exc:
        return False, str(exc)[:300], False
    started = (
        r.returncode == 0 and
        ('LLDPQ_UPGRADE_STARTED' in r.stdout or
         'LLDPQ_UPGRADE_ALREADY_STARTED' in r.stdout)
    )
    detail = (r.stderr or r.stdout).strip()[:300]
    # A normal remote non-zero exit is definitive (for example missing ONIE
    # binary or immediate install failure). Only SSH transport loss after the
    # dispatch marker leaves the launch outcome uncertain.
    ambiguous = (
        not started and r.returncode == 255 and
        'LLDPQ_UPGRADE_DISPATCHING' in r.stdout
    )
    return started, detail, ambiguous


def start_upgrade_for_device(dev, image_url, ztp_url, operation_id):
    """Reauthorize inventory and live identity in the launch SSH session."""
    try:
        with canonical_device_mutation(dev) as canonical:
            return _start_upgrade_for_device(
                canonical, image_url, ztp_url, operation_id
            )
    except Exception as exc:
        return False, f'Target authorization failed: {exc}'[:300], False


def _prepare_upgrade_operation(dev, operation_id):
    """Idempotently reserve the remote operation marker before launch."""
    ip = dev.get('ip')
    username = dev.get('username', 'cumulus')
    remote = 'set -e\n' + remote_identity_guard_shell(
        dev.get('expected_mac', ''), dev.get('expected_serial', '')
    ) + '\n' + r'''
OPERATION_ID="$1"
current_operation="$(sudo cat /tmp/lldpq-upgrade.operation 2>/dev/null || true)"
if [ "$current_operation" != "$OPERATION_ID" ]; then
  if pgrep -f '/usr/cumulus/bin/onie-install' >/dev/null 2>&1; then
    echo "another LLDPq upgrade operation is already running" >&2
    exit 75
  fi
  sudo rm -f /tmp/lldpq-upgrade.exit /tmp/lldpq-upgrade.log
fi
printf '%s\n' "$OPERATION_ID" | sudo tee /tmp/lldpq-upgrade.operation >/dev/null
test "$(sudo cat /tmp/lldpq-upgrade.operation)" = "$OPERATION_ID"
echo LLDPQ_UPGRADE_PREPARED
'''
    try:
        result = subprocess.run(
            [
                'sudo', '-u', LLDPQ_USER, 'ssh', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=8', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
                f'{username}@{ip}', 'bash -s --', operation_id,
            ],
            input=remote, capture_output=True, text=True, timeout=20,
        )
        ok = result.returncode == 0 and 'LLDPQ_UPGRADE_PREPARED' in result.stdout
        return ok, (result.stderr or result.stdout).strip()[:300]
    except Exception as exc:
        return False, str(exc)[:300]


def prepare_upgrade_operation(dev, operation_id):
    """Reauthorize inventory and live identity before reserving a launch."""
    try:
        with canonical_device_mutation(dev) as canonical:
            return _prepare_upgrade_operation(canonical, operation_id)
    except Exception as exc:
        return False, f'Target authorization failed: {exc}'[:300]


def verify_upgrade_job_image(job):
    """Ensure every batch uses the exact image captured when the job began."""
    image_path = resolve_os_image_path(job.get('image_name', ''))
    if not image_path:
        raise RuntimeError('Upgrade image is no longer available')
    actual_size = os.path.getsize(image_path)
    if actual_size != int(job.get('image_size', -1)):
        raise RuntimeError('Upgrade image size changed after the job started')
    actual_hash = sha256_file(image_path)
    if actual_hash != job.get('image_sha256'):
        raise RuntimeError('Upgrade image content changed after the job started')


def start_claimed_upgrade(job, dev, image_url, ztp_url):
    """Authorize, launch and merge one crash-safe `starting` claim."""
    job_id = job['id']
    operation_id = dev.get('operation_id', '')

    def current_device(current):
        return next(
            (item for item in current.get('devices', [])
             if item.get('ip') == dev.get('ip')),
            None,
        )

    with upgrade_job_lock(job_id):
        current = load_upgrade_job(job_id)
        current_dev = current_device(current)
        if current_dev is None:
            return dict(dev, status='failed', error='Device disappeared from upgrade job')
        launch_attempted = bool(current_dev.get('launch_attempted_at'))
        if current.get('cancelled') and not launch_attempted:
            current_dev['status'] = 'cancelled'
            current_dev.pop('operation_id', None)
            finalize_upgrade_job(current)
            save_upgrade_job(current)
            return dict(current_dev)
        if current_dev.get('status') != 'starting' or \
           current_dev.get('operation_id') != operation_id:
            return dict(current_dev)
        if current.get('stop_on_failure', True) and any(
            item.get('status') == 'failed' for item in current.get('devices', [])
        ) and not launch_attempted:
            current_dev['status'] = 'blocked'
            current_dev['error'] = 'Blocked after an earlier upgrade failure'
            current_dev.pop('operation_id', None)
            finalize_upgrade_job(current)
            save_upgrade_job(current)
            return dict(current_dev)
        remote_prepared = bool(current_dev.get('remote_prepared_at'))

    # Establish the operation marker first. Repeating this after a crash is
    # harmless and proves that a later persisted launch authorization belongs
    # to this exact job/device operation.
    if not remote_prepared:
        prepared, prepare_detail = prepare_upgrade_operation(dev, operation_id)
        with upgrade_job_lock(job_id):
            current = load_upgrade_job(job_id)
            current_dev = current_device(current)
            if current_dev is None:
                return dict(dev, status='failed', error='Device disappeared from upgrade job')
            if current_dev.get('status') != 'starting' or \
               current_dev.get('operation_id') != operation_id:
                return dict(current_dev)
            if current.get('cancelled') and not current_dev.get('launch_attempted_at'):
                current_dev['status'] = 'cancelled'
                current_dev.pop('operation_id', None)
                finalize_upgrade_job(current)
                save_upgrade_job(current)
                return dict(current_dev)
            if not prepared:
                current_dev['prepare_attempts'] = int(
                    current_dev.get('prepare_attempts', 0)
                ) + 1
                current_dev['message'] = (
                    'Waiting to prepare upgrade operation: ' +
                    (prepare_detail or 'SSH unavailable')
                )[:500]
                if time.time() - float(current_dev.get('claimed_at', time.time())) > 300:
                    current_dev['status'] = 'failed'
                    current_dev['error'] = current_dev['message']
                save_upgrade_job(current)
                return dict(current_dev)
            current_dev['remote_prepared_at'] = int(time.time())
            current_dev.pop('prepare_attempts', None)
            launch_attempted = bool(current_dev.get('launch_attempted_at'))
            save_upgrade_job(current)

    if launch_attempted:
        info = get_device_version(dev)
        if info.get('current_version') == job['target_version']:
            launch_status = 'upgrading'
            ok, detail = True, 'Target version detected after worker recovery'
        elif not info.get('reachable'):
            launch_status = 'waiting_reboot'
            ok, detail = True, 'Launch state uncertain; waiting for device reboot'
        elif info.get('upgrade_operation') != operation_id:
            launch_status = 'failed'
            ok = False
            detail = (
                'Previous launch was not confirmed and the device returned '
                'without the target version; automatic relaunch was blocked'
            )
        else:
            ok, detail, ambiguous = start_upgrade_for_device(
                dev, image_url, ztp_url, operation_id
            )
            launch_status = 'upgrading' if ok else (
                'waiting_reboot' if ambiguous else 'failed'
            )
    else:
        with upgrade_job_lock(job_id):
            current = load_upgrade_job(job_id)
            current_dev = current_device(current)
            if current_dev is None:
                return dict(dev, status='failed', error='Device disappeared from upgrade job')
            if current_dev.get('status') != 'starting' or \
               current_dev.get('operation_id') != operation_id:
                return dict(current_dev)
            if current.get('cancelled'):
                current_dev['status'] = 'cancelled'
                current_dev.pop('operation_id', None)
                finalize_upgrade_job(current)
                save_upgrade_job(current)
                return dict(current_dev)
            attempted_at = int(time.time())
            current_dev['launch_attempted_at'] = attempted_at
            current_dev['started_at'] = attempted_at
            save_upgrade_job(current)
        ok, detail, ambiguous = start_upgrade_for_device(
            dev, image_url, ztp_url, operation_id
        )
        # Once authorization is persisted, a lost SSH response is ambiguous:
        # the device may already be rebooting. Let version/marker probes decide
        # instead of reporting a false immediate failure.
        launch_status = 'upgrading' if ok else (
            'waiting_reboot' if ambiguous else 'failed'
        )

    with upgrade_job_lock(job_id):
        current = load_upgrade_job(job_id)
        current_dev = current_device(current)
        if current_dev is None:
            return dict(dev, status='failed', error='Device disappeared from upgrade job')
        if current_dev.get('status') != 'starting':
            return dict(current_dev)
        current_dev['status'] = launch_status
        if launch_status == 'waiting_reboot':
            current_dev['launch_uncertain'] = True
            current_dev['message'] = detail or 'Launch response unavailable; waiting for reboot'
            current_dev.pop('error', None)
        elif ok:
            current_dev['message'] = detail or 'Upgrade command started'
            current_dev.pop('error', None)
            current_dev.pop('launch_uncertain', None)
        else:
            current_dev['error'] = detail or 'Failed to start upgrade'
        save_upgrade_job(current)
        return dict(current_dev)

def update_upgrade_job(job):
    now = time.time()
    # A newly persisted job is not claimable until its ONIE aliases and pinned
    # artifacts have been published successfully by action_upgrade_start.
    if job.get('ready', True) is False:
        return job
    image_url = f"http://{job['server_ip']}/{job['image_name']}"
    ztp_path = str(job.get('ztp_artifact', '')).lstrip('/')
    ztp_url = f"http://{job['server_ip']}/{ztp_path}"

    # A queued device is first committed as `starting` with an operation ID.
    # Only a later worker pass performs the irreversible remote launch.  This
    # closes the crash window that previously left a launched device queued.
    starting = [d for d in job['devices'] if d['status'] == 'starting']
    if starting:
        try:
            with upgrade_coordinator_lock():
                verify_upgrade_job_image(job)
                verify_upgrade_job_ztp(job)
                if len(ensure_onie_symlinks(job.get('image_name', ''))) != \
                        len(ONIE_ALIAS_NAMES):
                    raise RuntimeError('Could not verify ONIE fallback image aliases')
            # Upload/delete reject images used by an unfinished job, so the
            # coordinator is needed only for the hash snapshot—not slow SSH.
            for dev in starting:
                dev.update(start_claimed_upgrade(
                    job, dev, image_url, ztp_url
                ))
        except Exception as exc:
            for dev in starting:
                if dev.get('status') == 'starting':
                    dev['status'] = 'failed'
                    dev['error'] = str(exc)[:500]

    # Refresh active devices.
    for dev in job['devices']:
        if dev['status'] not in ('upgrading', 'waiting_reboot'):
            continue
        if now - dev.get('started_at', now) > job.get('timeout_seconds', 3600):
            dev['status'] = 'failed'
            dev['error'] = 'Upgrade timeout'
            continue
        info = get_device_version(dev)
        dev['last_check'] = int(now)
        dev['reachable'] = info.get('reachable', False)
        dev['current_version'] = info.get('current_version', dev.get('current_version', ''))
        if info.get('upgrade_exit') not in (None, 0) and \
           info.get('current_version') != job['target_version']:
            dev['status'] = 'failed'
            detail = info.get('upgrade_log') or 'onie-install exited before reaching target version'
            dev['error'] = f"Upgrade command exited ({info['upgrade_exit']}): {detail}"[:500]
            continue
        if info.get('reachable') and dev.get('launch_uncertain') and \
           info.get('current_version') != job['target_version']:
            if info.get('upgrade_operation') == dev.get('operation_id'):
                # Same operation marker: retrying the remote wrapper is
                # idempotent (it either observes the running/exited process or
                # launches the prepared operation that never started).
                dev['status'] = 'starting'
                dev['message'] = 'Rechecking prepared upgrade launch'
                continue
            dev['status'] = 'failed'
            dev['error'] = (
                'Upgrade launch could not be confirmed after the device returned '
                'on its previous version'
            )
            continue
        if info.get('current_version') == job['target_version']:
            # A matching live version is authoritative proof that an ambiguous
            # launch completed. Do not keep the whole provisioning surface
            # locked for the artifact grace period after verified success.
            dev.pop('launch_uncertain', None)
            dev.pop('message', None)
            if job.get('base_config_after', True):
                files = [f for f in FILE_DEPLOY_MAP if os.path.exists(os.path.join(BASE_CONFIG_DIR, f))]
                res = deploy_to_device(dev, files, True)
                if res.get('success'):
                    dev['status'] = 'done'
                    dev['message'] = 'Upgraded and base config deployed'
                else:
                    dev['status'] = 'failed'
                    dev['error'] = 'Upgrade OK, base config failed: ' + res.get('error', '')
            else:
                dev['status'] = 'done'
                dev['message'] = 'Upgraded'
        else:
            dev['status'] = 'waiting_reboot'

    active = [
        d for d in job['devices']
        if d['status'] in ('starting', 'upgrading', 'waiting_reboot')
    ]
    failed = [d for d in job['devices'] if d['status'] == 'failed']
    if job.get('cancelled'):
        for d in job['devices']:
            if d['status'] == 'queued':
                d['status'] = 'cancelled'
        finalize_upgrade_job(job, now)
        return job
    if job.get('stop_on_failure', True) and failed:
        for d in job['devices']:
            if d['status'] == 'queued':
                d['status'] = 'blocked'
        finalize_upgrade_job(job, now)
        return job
    slots = max(0, int(job.get('batch_size', 1)) - len(active))
    for dev in [d for d in job['devices'] if d['status'] == 'queued'][:slots]:
        dev['status'] = 'starting'
        dev['operation_id'] = str(uuid.uuid4())
        dev['claimed_at'] = int(now)
    finalize_upgrade_job(job, now)
    return job

def finalize_upgrade_job(job, now=None):
    if all(d['status'] in ('done', 'failed', 'cancelled', 'blocked') for d in job['devices']):
        job['complete'] = True
        job.setdefault('completed_at', int(now or time.time()))

def run_upgrade_worker(job_id):
    """Advance a persisted upgrade job until terminal, independently of UI polling."""
    ensure_upgrade_jobs_dir()
    worker_lock_path = job_path(job_id) + '.worker.lock'
    worker_lock = open(worker_lock_path, 'a+')
    try:
        try:
            os.chmod(worker_lock_path, 0o664)
        except OSError:
            pass
        try:
            fcntl.flock(worker_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return

        while True:
            try:
                # Hold the per-job lock only for state snapshots/commits. Device
                # SSH, version probes and base deployment happen outside it so
                # Status and Cancel remain responsive.
                with upgrade_job_lock(job_id):
                    job = load_upgrade_job(job_id)
                    if job.get('complete'):
                        return
                    if job.get('ready', True) is False:
                        return
                    job['worker_heartbeat'] = int(time.time())
                    job.pop('worker_error', None)
                    save_upgrade_job(job)
                updated = update_upgrade_job(job)
                with upgrade_job_lock(job_id):
                    current = load_upgrade_job(job_id)
                    if current.get('complete') or \
                            current.get('ready', True) is False:
                        return
                    if current.get('cancelled'):
                        updated['cancelled'] = True
                        current_by_ip = {
                            item.get('ip'): item
                            for item in current.get('devices', [])
                        }
                        for item in updated['devices']:
                            current_item = current_by_ip.get(item.get('ip'), {})
                            # Cancel may have won while the worker was probing
                            # or merely claiming a queued device. Preserve that
                            # terminal state instead of committing `starting`.
                            if current_item.get('status') == 'cancelled' and \
                               item.get('status') in ('queued', 'starting'):
                                item['status'] = 'cancelled'
                                item.pop('operation_id', None)
                            elif item['status'] == 'queued':
                                item['status'] = 'cancelled'
                        finalize_upgrade_job(updated)
                    updated['worker_heartbeat'] = int(time.time())
                    save_upgrade_job(updated)
                    if updated.get('complete'):
                        return
            except Exception as exc:
                try:
                    with upgrade_job_lock(job_id):
                        job = load_upgrade_job(job_id)
                        job['worker_heartbeat'] = int(time.time())
                        job['worker_error'] = str(exc)[:300]
                        save_upgrade_job(job)
                except Exception:
                    pass
            time.sleep(15)
    finally:
        try:
            fcntl.flock(worker_lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        worker_lock.close()

ONIE_ALIAS_NAMES = (
    'onie-installer-x86_64',
    'onie-installer-x86_64-mlnx',
    'onie-installer',
)


def snapshot_onie_aliases():
    """Capture app-managed symlink targets so a failed start can roll back."""
    snapshot = {}
    for directory in (PROVISION_UPLOAD_DIR, WEB_ROOT):
        for name in ONIE_ALIAS_NAMES:
            path = os.path.join(directory, name)
            if not os.path.lexists(path):
                snapshot[path] = None
            elif os.path.islink(path):
                snapshot[path] = os.readlink(path)
            else:
                raise RuntimeError(
                    f'Refusing to replace non-symlink ONIE alias: {path}'
                )
    return snapshot


def serialize_onie_alias_snapshot(snapshot):
    """Persist only the six known alias targets; never persist arbitrary paths."""
    serialized = {}
    expected_keys = set()
    for scope, directory in (
        ('uploads', PROVISION_UPLOAD_DIR), ('web', WEB_ROOT)
    ):
        for name in ONIE_ALIAS_NAMES:
            key = f'{scope}:{name}'
            expected_keys.add(key)
            path = os.path.join(directory, name)
            if path not in snapshot:
                raise RuntimeError('ONIE alias snapshot is incomplete')
            target = snapshot[path]
            if target is not None and not re.fullmatch(
                r'(?:provision-uploads/)?[A-Za-z0-9_.-]+', target
            ):
                raise RuntimeError('ONIE alias snapshot has an unsafe target')
            serialized[key] = target
    if set(serialized) != expected_keys:
        raise RuntimeError('ONIE alias snapshot schema mismatch')
    return serialized


def deserialize_onie_alias_snapshot(serialized):
    if not isinstance(serialized, dict):
        raise RuntimeError('Upgrade job has no ONIE alias rollback snapshot')
    snapshot = {}
    expected_keys = set()
    for scope, directory in (
        ('uploads', PROVISION_UPLOAD_DIR), ('web', WEB_ROOT)
    ):
        for name in ONIE_ALIAS_NAMES:
            key = f'{scope}:{name}'
            expected_keys.add(key)
            if key not in serialized:
                raise RuntimeError('ONIE alias rollback snapshot is incomplete')
            target = serialized[key]
            if target is not None and (
                not isinstance(target, str) or
                not re.fullmatch(
                    r'(?:provision-uploads/)?[A-Za-z0-9_.-]+', target
                )
            ):
                raise RuntimeError('ONIE alias rollback target is unsafe')
            snapshot[os.path.join(directory, name)] = target
    if set(serialized) != expected_keys:
        raise RuntimeError('ONIE alias rollback snapshot schema mismatch')
    return snapshot


def _publish_symlink(path, target):
    directory = os.path.dirname(path)
    staged = os.path.join(
        directory, f'.{os.path.basename(path)}.{uuid.uuid4().hex}.tmp'
    )
    try:
        os.symlink(target, staged)
        os.replace(staged, path)
        return True
    except Exception:
        try:
            if os.path.lexists(staged):
                os.unlink(staged)
        except OSError:
            pass
        command = 'ln -sfn -- %s %s' % (
            shlex.quote(target), shlex.quote(path)
        )
        result = subprocess.run(
            ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0 and os.path.islink(path) and \
            os.readlink(path) == target


def restore_onie_aliases(snapshot):
    errors = []
    for path, target in snapshot.items():
        try:
            if target is None:
                if os.path.islink(path):
                    try:
                        os.unlink(path)
                    except PermissionError:
                        result = subprocess.run(
                            ['sudo', '-u', LLDPQ_USER, 'rm', '-f', path],
                            capture_output=True, text=True, timeout=10,
                        )
                        if result.returncode != 0 or os.path.lexists(path):
                            raise RuntimeError('could not remove replacement symlink')
                elif os.path.lexists(path):
                    raise RuntimeError('replacement is not a symlink')
            elif not _publish_symlink(path, target):
                raise RuntimeError('could not restore symlink')
        except Exception as exc:
            errors.append(f'{path}: {exc}')
    if errors:
        print('ONIE alias rollback warning: ' + '; '.join(errors), file=sys.stderr)
    return not errors


def ensure_onie_symlinks(image_name):
    """Point the generic ONIE HTTP-discovery fallback names at the selected upgrade image.

    Some switches, after `onie-install -fa`, reboot into ONIE and re-run the default HTTP
    "waterfall" discovery against the image-server root instead of using the -i URL. That waterfall
    always descends to the arch / silicon-vendor / generic names, so serving those (as symlinks to
    the chosen image) makes the upgrade robust. Generic only — NO per-platform hardcoding — so it
    covers every x86_64 NVIDIA/Mellanox switch (SN2201, SN5600D, ...) uniformly:
      onie-installer-x86_64-mlnx  (silicon-vendor fallback — all Spectrum switches)
      onie-installer-x86_64       (arch fallback — all x86_64)
      onie-installer              (final generic)
    Extension-less only: ONIE tries "<name>" before "<name>.bin" at every level, so these are
    served first — and they don't collide with the OS-image list (which globs *.bin).
    """
    if not valid_os_image_name(image_name):
        return []
    image_path = resolve_os_image_path(image_name)
    if not image_path:
        return []
    # Only the extension-less names: ONIE requests "<name>" before "<name>.bin" at every waterfall
    # level, so the plain names are always served first. Skipping the .bin variants also keeps them
    # out of the OS-image list (which globs *.bin).
    created = []
    persistent_image = os.path.dirname(os.path.realpath(image_path)) == os.path.realpath(PROVISION_UPLOAD_DIR)
    if persistent_image and not publish_provision_root_link(image_name):
        return []
    for n in ONIE_ALIAS_NAMES:
        if persistent_image:
            link = os.path.join(PROVISION_UPLOAD_DIR, n)
            try:
                if os.path.lexists(link):
                    os.remove(link)
                os.symlink(image_name, link)
                if publish_provision_root_link(n):
                    created.append(n)
                continue
            except Exception:
                command = 'ln -sfn -- %s %s' % (
                    shlex.quote(image_name), shlex.quote(link)
                )
                rc = subprocess.run(
                    ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
                    capture_output=True, timeout=10,
                )
                if rc.returncode == 0 and publish_provision_root_link(n):
                    created.append(n)
                continue

        link = os.path.join(WEB_ROOT, n)
        try:
            if os.path.lexists(link):
                os.remove(link)
            os.symlink(image_name, link)          # relative target (same dir as the image)
            created.append(n)
        except Exception:
            # www-data may not own the web root -> create via the service user (bash is whitelisted)
            command = 'ln -sfn -- %s %s' % (shlex.quote(image_name), shlex.quote(link))
            rc = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'bash', '-c', command],
                capture_output=True, timeout=10,
            )
            if rc.returncode == 0:
                created.append(n)
    return created


def action_upgrade_start():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    if not isinstance(data, dict):
        error_json('Upgrade request must be an object')
    devices = data.get('devices', [])
    target_version = data.get('target_version', '').strip()
    image_name = os.path.basename(data.get('image_name', ''))
    server_ip = data.get('server_ip', '').strip()
    if not devices or not target_version or not image_name or not server_ip:
        error_json('devices, target_version, image_name and server_ip are required')
    if not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,99}', target_version):
        error_json('Invalid target version')
    for flag in ('stop_on_failure', 'base_config_after'):
        if flag in data and not isinstance(data[flag], bool):
            error_json(f'{flag} must be true or false')
    if not valid_os_image_name(image_name):
        error_json('Invalid image filename')
    if not is_valid_server_ref(server_ip):
        error_json('Invalid image server. Set a real ZTP IMAGE SERVER IP first.')
    image_path = resolve_os_image_path(image_name)
    if not image_path:
        error_json('Selected image not found on server')
    if os.path.getsize(image_path) <= 0:
        error_json('Selected image is empty')
    detected_version = image_version_from_name(image_name)
    if detected_version and detected_version != target_version:
        error_json(f'Target version {target_version} does not match selected image version {detected_version}')
    if not os.path.exists(ZTP_SCRIPT_FILE):
        error_json('cumulus-ztp.sh not found in web root')
    with open(ZTP_SCRIPT_FILE, 'r') as f:
        ztp_content = f.read()
    try:
        validate_ztp_script_content(ztp_content)
    except ValueError as exc:
        error_json(
            'cumulus-ztp.sh is not a valid ZTP Bash script. '
            f'Apply Quick Settings and save it before upgrade: {exc}'
        )
    if not is_current_ztp_template(ztp_content):
        error_json(
            'cumulus-ztp.sh uses a legacy or incomplete template. '
            'Apply Quick Settings, confirm the hardened-template upgrade, '
            'and save before starting device upgrade.'
        )
    if '__IMAGE_SERVER_IP__' in ztp_content or '__TARGET_OS_VERSION__' in ztp_content:
        error_json('cumulus-ztp.sh still contains placeholders. Apply Quick Settings and save ZTP script before upgrade.')
    if not ztp_script_public_key(ztp_content):
        error_json('cumulus-ztp.sh has no SSH key. Generate/import SSH key, Apply to Script, then Save before upgrade.')
    script_target = ztp_script_static_setting(
        ztp_content, 'CUMULUS_TARGET_RELEASE'
    )
    if script_target != target_version:
        error_json(
            f'ZTP target {script_target or "is invalid"} does not match '
            f'the selected upgrade target {target_version}. Use the image '
            'from the ZTP tab and save the script before upgrade.'
        )
    script_server = ztp_script_static_setting(
        ztp_content, 'IMAGE_SERVER_HOSTNAME'
    )
    if script_server.lower() != server_ip.lower():
        error_json(
            f'ZTP image server {script_server or "is invalid"} does not match '
            f'the upgrade server {server_ip}. Apply Quick Settings and save '
            'the script before upgrade.'
        )

    try:
        batch_size = max(1, min(int(data.get('batch_size', 1) or 1), 100))
    except (TypeError, ValueError):
        error_json('Upgrade batch size must be a number from 1 to 100')

    normalized_devices = []
    seen_ips = set()
    if not isinstance(devices, list):
        error_json('Upgrade devices must be a list')
    try:
        inventory = load_canonical_inventory_bindings()
    except Exception as exc:
        error_json(f'Could not load current inventory: {exc}')
    for d in devices:
        if not isinstance(d, dict):
            error_json('Each upgrade device must be an object')
        username = str(d.get('username', 'cumulus')).strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', username):
            error_json('Invalid SSH username')
        try:
            item = canonicalize_inventory_target(d, inventory)
        except ValueError as exc:
            error_json(f'Upgrade target authorization failed: {exc}')
        ip = item['ip']
        if ip in seen_ips:
            error_json(f'Duplicate upgrade device IP: {ip}')
        seen_ips.add(ip)
        item['ip'] = ip
        item['username'] = username
        item['status'] = 'queued'
        item['target_version'] = target_version
        normalized_devices.append(item)

    with upgrade_coordinator_lock():
        try:
            all_jobs = list_upgrade_jobs(strict=True)
        except RuntimeError as exc:
            error_json(str(exc))
        gc_upgrade_ztp_artifacts(all_jobs)
        active_jobs = [
            job for job in all_jobs
            if upgrade_job_holds_provision_resources(job)
        ]
        if active_jobs:
            active = max(active_jobs, key=lambda item: int(item.get('created_at', 0)))
            result_json({
                'success': False,
                'error_code': 'upgrade_active',
                'error': 'Another upgrade job is already active',
                'job': active,
            })

        try:
            alias_snapshot = snapshot_onie_aliases()
            serialized_alias_snapshot = serialize_onie_alias_snapshot(
                alias_snapshot
            )
        except Exception as exc:
            error_json('Could not snapshot ONIE aliases: ' + str(exc)[:300])

        now = int(time.time())
        job = {
            'schema_version': UPGRADE_JOB_SCHEMA_VERSION,
            'id': str(uuid.uuid4()),
            'created_at': now,
            'target_version': target_version,
            'image_name': image_name,
            'image_size': os.path.getsize(image_path),
            'image_sha256': sha256_file(image_path),
            'server_ip': server_ip,
            'batch_size': batch_size,
            'stop_on_failure': data.get('stop_on_failure', True),
            'base_config_after': data.get('base_config_after', True),
            'timeout_seconds': 3600,
            'complete': False,
            'cancelled': False,
            'ready': False,
            'aliases_published': False,
            'onie_alias_snapshot': serialized_alias_snapshot,
            'worker_started_at': now,
            'worker_heartbeat': now,
            'devices': normalized_devices,
        }
        try:
            job.update(create_upgrade_ztp_artifact(job['id'], ztp_content))
            with upgrade_job_lock(job['id']):
                save_upgrade_job(job)
        except Exception as exc:
            cleanup_upgrade_ztp_artifact(job)
            error_json('Could not pin the validated ZTP script: ' + str(exc)[:300])

        try:
            # The exact image URL is primary, but ONIE waterfall aliases are
            # published transactionally for platforms that fall back to them.
            aliases = ensure_onie_symlinks(image_name)
            if len(aliases) != len(ONIE_ALIAS_NAMES):
                raise RuntimeError('Could not publish all ONIE fallback image aliases')
            job['aliases_published'] = True
            job['ready'] = True
            with upgrade_job_lock(job['id']):
                save_upgrade_job(job)
        except Exception as exc:
            rollback_ok = True
            if alias_snapshot is not None:
                rollback_ok = restore_onie_aliases(alias_snapshot)
            with upgrade_job_lock(job['id']):
                job = load_upgrade_job(job['id'])
                for item in job['devices']:
                    if item['status'] == 'queued' or (
                        item['status'] == 'starting' and
                        not item.get('launch_attempted_at')
                    ):
                        item['status'] = 'blocked'
                job['worker_error'] = 'Could not publish ONIE aliases: ' + str(exc)[:200]
                if not rollback_ok:
                    job['alias_rollback_failed'] = True
                finalize_upgrade_job(job)
                save_upgrade_job(job)
            error_json(job['worker_error'] + '; no device upgrade was started')
        try:
            launch_upgrade_worker(job['id'])
        except Exception as exc:
            rollback_ok = True
            if alias_snapshot is not None:
                rollback_ok = restore_onie_aliases(alias_snapshot)
            with upgrade_job_lock(job['id']):
                job = load_upgrade_job(job['id'])
                for item in job['devices']:
                    if item['status'] == 'queued' or (
                        item['status'] == 'starting' and
                        not item.get('launch_attempted_at')
                    ):
                        item['status'] = 'blocked'
                job['worker_error'] = 'Could not start upgrade worker: ' + str(exc)[:200]
                if not rollback_ok:
                    job['alias_rollback_failed'] = True
                finalize_upgrade_job(job)
                save_upgrade_job(job)
            error_json(job['worker_error'] + '; no device upgrade was started')
    result_json({'success': True, 'job': job})

def action_upgrade_status():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    job_id = data.get('job_id', '')
    with upgrade_job_lock(job_id):
        job = load_upgrade_job(job_id)
    if not job.get('complete') and job.get('ready', True):
        # Status remains observational, but it may replace a worker that died
        # after a service/process restart. The lifetime flock rejects duplicate
        # workers when the original is merely busy in a long device check.
        heartbeat = max(
            int(job.get('worker_heartbeat', 0) or 0),
            int(job.get('worker_started_at', 0) or 0),
        )
        if time.time() - heartbeat > 45:
            with upgrade_coordinator_lock():
                with upgrade_job_lock(job_id):
                    current = load_upgrade_job(job_id)
                if not current.get('complete') and current.get('ready', True):
                    try:
                        launch_upgrade_worker(job_id)
                    except Exception:
                        pass
    result_json({'success': True, 'job': job})

def action_upgrade_active():
    """Recover the newest unfinished job after a browser reload."""
    with upgrade_coordinator_lock():
        try:
            candidates = list_upgrade_jobs(unfinished_only=True, strict=True)
        except RuntimeError as exc:
            error_json(str(exc))
        if not candidates:
            result_json({'success': True, 'job': None})
        job = max(candidates, key=lambda item: int(item.get('created_at', 0)))
        # Coordinator serialization prevents recovery from observing a job in
        # the middle of its alias/artifact initialization transaction.
        if job.get('ready', True):
            try:
                launch_upgrade_worker(job['id'])
            except Exception:
                pass
    result_json({'success': True, 'job': job})


def resume_upgrade_workers():
    """Restart interrupted persisted workers without waiting for a browser."""
    try:
        with upgrade_coordinator_lock():
            jobs = list_upgrade_jobs(strict=True)
            gc_upgrade_ztp_artifacts(jobs)
    except Exception as exc:
        print(f'ZTP artifact cleanup warning: {exc}', file=sys.stderr)
        return
    for job in [item for item in jobs if not item.get('complete')]:
        if job.get('ready', True) is False:
            if time.time() - float(job.get('created_at', time.time())) <= 120:
                continue
            alias_snapshot = None
            try:
                with upgrade_coordinator_lock():
                    with upgrade_job_lock(job['id']):
                        current = load_upgrade_job(job['id'])
                    if current.get('complete'):
                        continue
                    if current.get('ready', True):
                        job = current
                    else:
                        alias_snapshot = deserialize_onie_alias_snapshot(
                            current.get('onie_alias_snapshot')
                        )
                        verify_upgrade_job_image(current)
                        verify_upgrade_job_ztp(current)
                        if len(ensure_onie_symlinks(current.get('image_name', ''))) != \
                                len(ONIE_ALIAS_NAMES):
                            raise RuntimeError('Could not recover ONIE aliases')
                        with upgrade_job_lock(job['id']):
                            current = load_upgrade_job(job['id'])
                            if current.get('complete') or current.get('cancelled'):
                                raise RuntimeError('Upgrade was cancelled during recovery')
                            current['aliases_published'] = True
                            current['ready'] = True
                            current['worker_heartbeat'] = int(time.time())
                            current.pop('worker_error', None)
                            save_upgrade_job(current)
                        job = current
            except Exception as exc:
                rollback_ok = True
                if alias_snapshot is not None:
                    rollback_ok = restore_onie_aliases(alias_snapshot)
                try:
                    with upgrade_job_lock(job['id']):
                        current = load_upgrade_job(job['id'])
                        if not current.get('complete'):
                            for item in current.get('devices', []):
                                if item.get('status') in ('queued', 'starting') and \
                                        not item.get('launch_attempted_at'):
                                    item['status'] = 'blocked'
                            current['worker_error'] = (
                                'Upgrade initialization recovery failed: ' +
                                str(exc)[:200]
                            )
                            finalize_upgrade_job(current)
                        if not rollback_ok:
                            current['alias_rollback_failed'] = True
                        save_upgrade_job(current)
                except Exception:
                    pass
                continue
        heartbeat = max(int(job.get('worker_heartbeat', 0) or 0),
                        int(job.get('worker_started_at', 0) or 0))
        if time.time() - heartbeat <= 45:
            continue
        try:
            launch_upgrade_worker(job['id'])
        except Exception:
            continue

def action_upgrade_cancel():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    job_id = data.get('job_id', '')
    with upgrade_coordinator_lock():
        with upgrade_job_lock(job_id):
            job = load_upgrade_job(job_id)
        if job.get('ready', True) is False:
            try:
                snapshot = deserialize_onie_alias_snapshot(
                    job.get('onie_alias_snapshot')
                )
                if not restore_onie_aliases(snapshot):
                    raise RuntimeError('ONIE alias rollback was incomplete')
            except Exception as exc:
                error_json('Could not safely cancel initializing upgrade: ' + str(exc))
        with upgrade_job_lock(job_id):
            job = load_upgrade_job(job_id)
            job['cancelled'] = True
            for item in job['devices']:
                if item['status'] == 'queued' or (
                    item['status'] == 'starting' and
                    not item.get('launch_attempted_at')
                ):
                    item['status'] = 'cancelled'
                    item.pop('operation_id', None)
            finalize_upgrade_job(job)
            save_upgrade_job(job)
    result_json({'success': True, 'job': job})

# ======================== SSH KEY ========================

DEFAULT_CONFIG_LOCK_FILE = '/etc/lldpq.conf.lock'
DEFAULT_SSH_KEY_LOCK_FILE = '/var/lib/lldpq/ssh-key.lock'
CONFIG_LOCK_FILE = os.environ.get(
    'LLDPQ_CONFIG_LOCK_FILE', DEFAULT_CONFIG_LOCK_FILE
)
SSH_KEY_LOCK_FILE = os.environ.get(
    'LLDPQ_SSH_KEY_LOCK_FILE', DEFAULT_SSH_KEY_LOCK_FILE
)


@contextmanager
def _exclusive_regular_lock(path, production_path):
    """Lock one pre-seeded regular file without following a symlink."""
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(
            f'Required transaction lock is unavailable: {path}'
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IWOTH:
        raise RuntimeError(
            f'Transaction lock has unsafe type or permissions: {path}'
        )
    if (os.path.abspath(path) == production_path
            and metadata.st_uid != 0):
        raise RuntimeError(
            f'Production transaction lock is not root-owned: {path}'
        )

    flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = None
    locked = False
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino) !=
                (metadata.st_dev, metadata.st_ino)
                or not stat.S_ISREG(opened.st_mode)):
            os.close(descriptor)
            descriptor = None
            raise RuntimeError(f'Transaction lock changed while opening: {path}')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise RuntimeError(f'Could not acquire transaction lock: {path}') from exc
    try:
        yield
    finally:
        if descriptor is not None:
            try:
                if locked:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _run_key_command(command, *, input_text=None, timeout=15):
    """Run one key-management command and turn every failure into an error."""
    try:
        result = subprocess.run(
            command, input=input_text, capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('SSH key operation timed out') from exc
    except OSError as exc:
        raise RuntimeError(f'Could not run SSH key operation: {exc}') from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip()[:240]
        raise RuntimeError(detail or f'SSH key operation failed ({result.returncode})')
    return result


def _as_collector(command, *, input_text=None, timeout=15):
    """Run a checked argv command as the configured collector account."""
    return _run_key_command(
        ['sudo', '-n', '-u', LLDPQ_USER] + list(command),
        input_text=input_text, timeout=timeout,
    )


def _public_key_identity(value):
    """Return the algorithm/blob pair; comments are deliberately ignored."""
    parts = (value or '').strip().split()
    if len(parts) < 2:
        raise RuntimeError('Derived SSH public key is invalid')
    return tuple(parts[:2])


def _validate_private_key_content(private_key):
    """Validate an unencrypted private key before any installed key is touched."""
    if not isinstance(private_key, str) or not private_key.strip():
        raise RuntimeError('Invalid private key')
    if len(private_key.encode('utf-8')) > 256 * 1024:
        raise RuntimeError('Private key is too large')
    if '\x00' in private_key:
        raise RuntimeError('Private key contains NUL bytes')

    with tempfile.TemporaryDirectory(prefix='lldpq-key-validate-') as temp_dir:
        candidate = os.path.join(temp_dir, 'candidate')
        with open(candidate, 'w', encoding='utf-8', newline='') as handle:
            handle.write(private_key)
            if not private_key.endswith('\n'):
                handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(candidate, 0o600)
        try:
            derived = _run_key_command(
                ['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', candidate],
                timeout=10,
            ).stdout.strip()
        except RuntimeError as exc:
            raise RuntimeError(
                'Invalid or passphrase-protected private key; import an '
                'unencrypted OpenSSH key.'
            ) from exc

    algorithm = _public_key_identity(derived)[0]
    if algorithm == 'ssh-ed25519':
        return 'ed25519', 'id_ed25519', derived
    if algorithm == 'ssh-rsa':
        return 'rsa', 'id_rsa', derived
    raise RuntimeError(f'Unsupported SSH private key type: {algorithm}')


def _cleanup_collector_key_paths(paths):
    if not paths:
        return
    try:
        _as_collector(['/usr/bin/rm', '-f', '--'] + list(paths), timeout=10)
    except RuntimeError:
        pass


def _install_collector_key_pair(private_key, public_key, key_name, ssh_dir=None):
    """Activate one collector pair, retiring the other algorithm with rollback."""
    if key_name not in ('id_ed25519', 'id_rsa'):
        raise RuntimeError('Unsupported collector key target')
    if _public_key_identity(public_key) != _public_key_identity(
            _validate_private_key_content(private_key)[2]):
        raise RuntimeError('SSH private/public key pair does not match')

    ssh_dir = ssh_dir or os.path.join(os.path.expanduser(f'~{LLDPQ_USER}'), '.ssh')
    private_path = os.path.join(ssh_dir, key_name)
    public_path = private_path + '.pub'
    other_key_name = 'id_rsa' if key_name == 'id_ed25519' else 'id_ed25519'
    other_private_path = os.path.join(ssh_dir, other_key_name)
    other_public_path = other_private_path + '.pub'
    token = uuid.uuid4().hex
    staged_private = os.path.join(ssh_dir, f'.{key_name}.stage.{token}')
    staged_public = staged_private + '.pub'
    backup_private = os.path.join(ssh_dir, f'.{key_name}.backup.{token}')
    backup_public = backup_private + '.pub'
    backup_other_private = os.path.join(
        ssh_dir, f'.{other_key_name}.backup.{token}'
    )
    backup_other_public = backup_other_private + '.pub'
    activated = False

    activate_script = r'''
set -u
private_path=$1
public_path=$2
other_private_path=$3
other_public_path=$4
staged_private=$5
staged_public=$6
backup_private=$7
backup_public=$8
backup_other_private=$9
backup_other_public=${10}
target_started=0

restore_one() {
    backup=$1
    destination=$2
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        rm -f -- "$destination" || rollback_failed=1
        mv -f -- "$backup" "$destination" || rollback_failed=1
    fi
}

rollback() {
    rollback_failed=0
    if [ "$target_started" -eq 1 ]; then
        rm -f -- "$private_path" "$public_path" || rollback_failed=1
    fi
    restore_one "$backup_private" "$private_path"
    restore_one "$backup_public" "$public_path"
    restore_one "$backup_other_private" "$other_private_path"
    restore_one "$backup_other_public" "$other_public_path"
    rm -f -- "$staged_private" "$staged_public" || rollback_failed=1
    return "$rollback_failed"
}

if [ -e "$backup_private" ] || [ -L "$backup_private" ] || \
   [ -e "$backup_public" ] || [ -L "$backup_public" ] || \
   [ -e "$backup_other_private" ] || [ -L "$backup_other_private" ] || \
   [ -e "$backup_other_public" ] || [ -L "$backup_other_public" ]; then
    exit 90
fi
if [ -e "$private_path" ] || [ -L "$private_path" ]; then
    if ! mv -- "$private_path" "$backup_private"; then rollback; exit 91; fi
fi
if [ -e "$public_path" ] || [ -L "$public_path" ]; then
    if ! mv -- "$public_path" "$backup_public"; then rollback; exit 92; fi
fi
if [ -e "$other_private_path" ] || [ -L "$other_private_path" ]; then
    if ! mv -- "$other_private_path" "$backup_other_private"; then rollback; exit 93; fi
fi
if [ -e "$other_public_path" ] || [ -L "$other_public_path" ]; then
    if ! mv -- "$other_public_path" "$backup_other_public"; then rollback; exit 94; fi
fi
if ! mv -- "$staged_private" "$private_path"; then rollback; exit 95; fi
target_started=1
if ! mv -- "$staged_public" "$public_path"; then rollback; exit 96; fi
if ! chmod 600 "$private_path" || ! chmod 644 "$public_path"; then rollback; exit 97; fi
'''
    rollback_script = r'''
set -u
private_path=$1
public_path=$2
other_private_path=$3
other_public_path=$4
backup_private=$5
backup_public=$6
backup_other_private=$7
backup_other_public=$8
staged_private=$9
staged_public=${10}
rollback_failed=0
rm -f -- "$private_path" "$public_path" "$staged_private" "$staged_public" || rollback_failed=1
restore_one() {
    backup=$1
    destination=$2
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        rm -f -- "$destination" || rollback_failed=1
        mv -f -- "$backup" "$destination" || rollback_failed=1
    fi
}
restore_one "$backup_private" "$private_path"
restore_one "$backup_public" "$public_path"
restore_one "$backup_other_private" "$other_private_path"
restore_one "$backup_other_public" "$other_public_path"
exit "$rollback_failed"
'''

    # Backup/restore owns the global configuration lock while replacing the
    # whole config + SSH-key bundle. Always acquire in global -> key order so a
    # Setup key action can neither race that restore nor deadlock with it.
    with _exclusive_regular_lock(
            CONFIG_LOCK_FILE, DEFAULT_CONFIG_LOCK_FILE), \
         _exclusive_regular_lock(
            SSH_KEY_LOCK_FILE, DEFAULT_SSH_KEY_LOCK_FILE):
        try:
            _as_collector([
                '/bin/bash', '-c',
                'umask 077; mkdir -p -- "$1" && chmod 700 "$1"',
                'lldpq-key-dir', ssh_dir,
            ])
            _as_collector(['/usr/bin/tee', staged_private], input_text=private_key)
            _as_collector(['/usr/bin/tee', staged_public], input_text=public_key)
            _as_collector([
                '/bin/bash', '-c',
                'chmod 600 "$1" && chmod 644 "$2"; '
                'sync -f "$1" "$2" 2>/dev/null || true',
                'lldpq-key-stage', staged_private, staged_public,
            ])

            staged_derived = _as_collector([
                '/usr/bin/ssh-keygen', '-y', '-P', '', '-f', staged_private,
            ], timeout=10).stdout.strip()
            if _public_key_identity(staged_derived) != _public_key_identity(public_key):
                raise RuntimeError('Staged SSH private/public key pair does not match')

            _as_collector([
                '/bin/bash', '-c', activate_script, 'lldpq-key-activate',
                private_path, public_path, other_private_path, other_public_path,
                staged_private, staged_public, backup_private, backup_public,
                backup_other_private, backup_other_public,
            ], timeout=20)
            activated = True

            installed_derived = _as_collector([
                '/usr/bin/ssh-keygen', '-y', '-P', '', '-f', private_path,
            ], timeout=10).stdout.strip()
            installed_public = _as_collector(
                ['/usr/bin/cat', public_path], timeout=5,
            ).stdout.strip()
            if (_public_key_identity(installed_derived) != _public_key_identity(public_key)
                    or _public_key_identity(installed_public) != _public_key_identity(public_key)):
                raise RuntimeError('Installed SSH key pair failed verification')

            _cleanup_collector_key_paths((
                backup_private, backup_public,
                backup_other_private, backup_other_public,
            ))
            return installed_public
        except Exception:
            if activated:
                try:
                    _as_collector([
                        '/bin/bash', '-c', rollback_script, 'lldpq-key-rollback',
                        private_path, public_path, other_private_path,
                        other_public_path, backup_private, backup_public,
                        backup_other_private, backup_other_public,
                        staged_private, staged_public,
                    ], timeout=20)
                except RuntimeError as rollback_error:
                    raise RuntimeError(
                        'SSH key installation failed and rollback was incomplete: '
                        + str(rollback_error)
                    )
            else:
                # The activation script restores backups on ordinary failure.
                # Never delete backup paths here: if that rollback itself was
                # interrupted, they are the last copy of the old working key.
                _cleanup_collector_key_paths((staged_private, staged_public))
            raise


def get_ssh_key_info():
    """Return only an installed, readable and matching collector key pair."""
    home = os.path.expanduser(f'~{LLDPQ_USER}')
    for key_type, key_name in [('ed25519', 'id_ed25519'), ('rsa', 'id_rsa')]:
        private_path = os.path.join(home, '.ssh', key_name)
        pub_path = os.path.join(home, '.ssh', f'{key_name}.pub')
        try:
            derived = _as_collector([
                '/usr/bin/ssh-keygen', '-y', '-P', '', '-f', private_path,
            ], timeout=10).stdout.strip()
            public = _as_collector(['/usr/bin/cat', pub_path], timeout=5).stdout.strip()
            if _public_key_identity(derived) == _public_key_identity(public):
                return public, key_type, pub_path
        except RuntimeError:
            continue
    return None, None, None

def action_get_ssh_key():
    pub_key, key_type, key_file = get_ssh_key_info()
    if pub_key:
        result_json({"success": True, "public_key": pub_key, "key_type": key_type, "key_file": key_file})
    else:
        result_json({"success": True, "public_key": "", "key_type": "", "key_file": ""})

def action_generate_ssh_key():
    try:
        with tempfile.TemporaryDirectory(prefix='lldpq-keygen-') as temp_dir:
            candidate = os.path.join(temp_dir, 'id_ed25519')
            _run_key_command([
                '/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                '-f', candidate, '-C', 'lldpq@provision',
            ], timeout=15)
            with open(candidate, encoding='utf-8') as handle:
                private_key = handle.read()
            with open(candidate + '.pub', encoding='utf-8') as handle:
                generated_public = handle.read().strip()

        key_type, key_name, derived = _validate_private_key_content(private_key)
        if _public_key_identity(generated_public) != _public_key_identity(derived):
            raise RuntimeError('Generated SSH key pair failed validation')
        public_key = derived + f' {LLDPQ_USER}@provision\n'
        installed_public = _install_collector_key_pair(
            private_key, public_key, key_name,
        )
        pub_path = os.path.join(
            os.path.expanduser(f'~{LLDPQ_USER}'), '.ssh', key_name + '.pub'
        )
        result_json({"success": True, "public_key": installed_public,
                     "key_type": key_type, "key_file": pub_path})
    except Exception as e:
        error_json(str(e))

def action_import_ssh_key():
    """Import an existing private key (paste from another server/setup).
    All file operations run as LLDPQ_USER via sudo to ensure correct ownership.
    """
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    if not isinstance(data, dict):
        error_json("Invalid JSON data")

    private_key = data.get('private_key', '')
    if not isinstance(private_key, str):
        error_json("Invalid private key")
    if not private_key.endswith('\n'):
        private_key += '\n'

    try:
        key_type, key_name, derived = _validate_private_key_content(private_key)
        public_key = derived + f' {LLDPQ_USER}@imported\n'
        installed_public = _install_collector_key_pair(
            private_key, public_key, key_name,
        )
        pub_path = os.path.join(
            os.path.expanduser(f'~{LLDPQ_USER}'), '.ssh', key_name + '.pub'
        )
        result_json({"success": True, "public_key": installed_public,
                     "key_type": key_type, "key_file": pub_path})
    except Exception as e:
        error_json(str(e))

# ======================== OS IMAGES ========================

def action_list_os_images():
    """List Cumulus Linux image files in web root."""
    result_json({"success": True, "images": list_os_image_objects()})


def multipart_boundary_bytes(content_type):
    """Return the RFC multipart delimiter bytes from a Content-Type value."""
    match = re.search(
        r'(?:^|;)\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))',
        content_type or '', re.IGNORECASE,
    )
    boundary = (match.group(1) or match.group(2)) if match else ''
    if not boundary or len(boundary) > 200 or '\r' in boundary or '\n' in boundary:
        raise ValueError('Missing or invalid multipart boundary')
    try:
        return b'--' + boundary.encode('ascii')
    except UnicodeEncodeError as exc:
        raise ValueError('Multipart boundary must be ASCII') from exc


def multipart_file_part(upload_path, boundary_bytes, header_limit=65536):
    """Locate a single browser-uploaded file part without reading its body."""
    total_size = os.path.getsize(upload_path)
    with open(upload_path, 'rb') as upload:
        head = upload.read(min(total_size, header_limit + 1))

    # Browsers place the opening delimiter at byte zero.  Retain support for a
    # standards-compliant preamble, but only accept a delimiter at line start.
    opening = boundary_bytes + b'\r\n'
    if head.startswith(opening):
        boundary_pos = 0
    else:
        preamble_marker = b'\r\n' + opening
        preamble_pos = head.find(preamble_marker)
        boundary_pos = preamble_pos + 2 if preamble_pos >= 0 else -1
    if boundary_pos < 0:
        raise ValueError('No file found in upload (bad boundary)')

    header_start = boundary_pos + len(opening)
    header_end = head.find(b'\r\n\r\n', header_start)
    if header_end < 0 or header_end > header_limit:
        raise ValueError('Malformed multipart upload headers')
    headers = head[header_start:header_end]
    filename_match = re.search(rb'filename="([^"]+)"', headers, re.IGNORECASE)
    if not filename_match:
        raise ValueError('No filename in upload')
    filename = os.path.basename(filename_match.group(1).decode('latin-1'))
    body_start = header_end + 4

    # The file ends immediately before the CRLF which introduces the real
    # closing delimiter.  Validate it at EOF instead of estimating its size or
    # searching/trimming arbitrary bytes from the binary payload.
    closing = b'\r\n' + boundary_bytes + b'--'
    closing_pos = -1
    with open(upload_path, 'rb') as upload:
        for trailer in (closing + b'\r\n', closing):
            if total_size < len(trailer):
                continue
            candidate = total_size - len(trailer)
            upload.seek(candidate)
            if upload.read(len(trailer)) == trailer:
                closing_pos = candidate
                break
    if closing_pos < body_start:
        raise ValueError('Malformed multipart upload (closing boundary missing)')
    return filename, body_start, closing_pos


def remove_upload_temp(path):
    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def action_upload_os_image():
    """Handle multipart file upload for OS images.
    Streams the preserved CGI body to disk and publishes the extracted image
    with an atomic replacement, without loading the image into memory.
    """
    content_type = os.environ.get('CONTENT_TYPE', '')
    if not re.match(r'^\s*multipart/form-data(?:\s*;|\s*$)', content_type, re.IGNORECASE):
        error_json("Expected multipart/form-data upload")

    try:
        boundary_bytes = multipart_boundary_bytes(content_type)
        content_length = int(os.environ.get('CONTENT_LENGTH', '0'))
    except (TypeError, ValueError) as exc:
        error_json(str(exc))
    if content_length <= 0:
        error_json("No file data received (CONTENT_LENGTH=0)")

    tmp_upload_path = None
    body_temp_path = None
    stage = None
    try:
        upload_fd = int(os.environ.get('PROVISION_UPLOAD_FD', '-1'))
        if upload_fd < 0:
            raise RuntimeError('Upload request body is unavailable')
        upload_stream = os.fdopen(upload_fd, 'rb', closefd=False)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.upload') as tmp_upload:
            tmp_upload_path = tmp_upload.name
            remaining = content_length
            while remaining:
                chunk = upload_stream.read(min(65536, remaining))
                if not chunk:
                    raise ValueError(
                        f'Incomplete upload body ({content_length - remaining}/{content_length} bytes)'
                    )
                tmp_upload.write(chunk)
                remaining -= len(chunk)
            tmp_upload.flush()
            os.fsync(tmp_upload.fileno())

        filename, body_start, body_end = multipart_file_part(
            tmp_upload_path, boundary_bytes
        )
        if not valid_os_image_name(filename):
            raise ValueError(
                f"Invalid file type: {filename}. Only .bin, .img, .iso allowed."
            )
        file_size = body_end - body_start
        dest = os.path.join(PROVISION_UPLOAD_DIR, filename)

        body_fd, body_temp_path = tempfile.mkstemp(suffix='.' + filename)
        with open(tmp_upload_path, 'rb') as src, os.fdopen(body_fd, 'wb') as dst:
            src.seek(body_start)
            written = 0
            while written < file_size:
                chunk = src.read(min(65536, file_size - written))
                if not chunk:
                    raise ValueError(
                        f'Incomplete image extraction ({written}/{file_size} bytes)'
                    )
                dst.write(chunk)
                written += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())

        os.makedirs(PROVISION_UPLOAD_DIR, mode=0o775, exist_ok=True)
        stage = os.path.join(
            PROVISION_UPLOAD_DIR, f'.{filename}.upload-{os.getpid()}-{uuid.uuid4().hex}'
        )
        with open(body_temp_path, 'rb') as src, open(stage, 'xb') as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if os.path.getsize(stage) != file_size:
            raise RuntimeError('staged image size mismatch')
        os.chmod(stage, 0o664)
        final_size = publish_uploaded_image(stage, dest, filename, file_size)
        stage = None
        result_json({"success": True, "message": f"Uploaded {filename}", "size": final_size})
    except PermissionError:
        # Repair legacy upload-directory ownership, then retain the same staged
        # atomic publish semantics.  Never copy directly over an existing image.
        remove_upload_temp(stage)
        stage = None
        if not body_temp_path or not os.path.isfile(body_temp_path):
            error_json("Write failed before the uploaded image body could be extracted")
        mkdir_result = subprocess.run(
            ['sudo', 'mkdir', '-p', PROVISION_UPLOAD_DIR], capture_output=True, timeout=10
        )
        dir_chown_result = subprocess.run(
            ['sudo', 'chown', f'{LLDPQ_USER}:www-data', PROVISION_UPLOAD_DIR],
            capture_output=True, timeout=5,
        ) if mkdir_result.returncode == 0 else mkdir_result
        dir_chmod_result = subprocess.run(
            ['sudo', 'chmod', '775', PROVISION_UPLOAD_DIR], capture_output=True, timeout=5
        ) if dir_chown_result.returncode == 0 else dir_chown_result
        if dir_chmod_result.returncode != 0:
            error_json("Write failed: permission denied")

        stage = os.path.join(
            PROVISION_UPLOAD_DIR, f'.{filename}.upload-{os.getpid()}-{uuid.uuid4().hex}'
        )
        copy_result = subprocess.run(
            ['sudo', 'cp', body_temp_path, stage], capture_output=True, timeout=300
        )
        chown_result = subprocess.run(
            ['sudo', 'chown', f'{LLDPQ_USER}:www-data', stage], capture_output=True, timeout=5
        ) if copy_result.returncode == 0 else copy_result
        chmod_result = subprocess.run(
            ['sudo', 'chmod', '664', stage], capture_output=True, timeout=5
        ) if chown_result.returncode == 0 else chown_result
        if chmod_result.returncode != 0:
            error_json("Write failed: permission denied")
        try:
            with open(stage, 'rb') as staged:
                os.fsync(staged.fileno())
            if os.path.getsize(stage) != file_size:
                raise RuntimeError('staged image size mismatch')
            final_size = publish_uploaded_image(stage, dest, filename, file_size)
            stage = None
        except Exception as exc:
            error_json(f"Write failed: {exc}")
        result_json({"success": True, "message": f"Uploaded {filename} (via sudo)",
                     "size": final_size})
    except Exception as e:
        error_json(f"Upload failed: {e}")
    finally:
        remove_upload_temp(stage)
        remove_upload_temp(tmp_upload_path)
        remove_upload_temp(body_temp_path)

def action_delete_os_image():
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    name = data.get('name', '')
    if not valid_os_image_name(name):
        error_json("Invalid filename")

    filepath = resolve_os_image_path(name)
    if not filepath:
        error_json(f"File not found: {name}")

    # Serialize delete with job creation and batch launch.  The CGI exits via
    # result_json/error_json, which closes this process-local lock handle.
    ensure_upgrade_jobs_dir()
    image_lock_path = os.path.join(UPGRADE_JOBS_DIR, '.coordinator.lock')
    image_lock = open(image_lock_path, 'a+')
    fcntl.flock(image_lock.fileno(), fcntl.LOCK_EX)
    try:
        active_image_jobs = [
            job for job in list_upgrade_jobs(strict=True)
            if upgrade_job_holds_provision_resources(job)
        ]
    except RuntimeError as exc:
        error_json(str(exc))
    if any(job.get('image_name') == name for job in active_image_jobs):
        error_json('This image is in use by an active upgrade job and cannot be deleted')

    def remove_path(path):
        if not os.path.lexists(path):
            return True
        try:
            os.remove(path)
            return True
        except PermissionError:
            result = subprocess.run(
                ['sudo', 'rm', '-f', path], capture_output=True, timeout=5
            )
            return result.returncode == 0 and not os.path.lexists(path)

    if not remove_path(filepath):
        error_json(f"Could not delete {name}")
    root_link = os.path.join(WEB_ROOT, name)
    if os.path.abspath(filepath) != os.path.abspath(root_link) and not remove_path(root_link):
        error_json(f"Image deleted but web link could not be removed: {name}")

    # Remove persistent/root ONIE aliases only when they selected this image.
    for alias in ('onie-installer-x86_64', 'onie-installer-x86_64-mlnx', 'onie-installer'):
        persistent_alias = os.path.join(PROVISION_UPLOAD_DIR, alias)
        if os.path.islink(persistent_alias) and os.path.basename(os.readlink(persistent_alias)) == name:
            remove_path(persistent_alias)
            remove_path(os.path.join(WEB_ROOT, alias))
        root_alias = os.path.join(WEB_ROOT, alias)
        if os.path.islink(root_alias) and os.path.basename(os.readlink(root_alias)) == name:
            remove_path(root_alias)
    
    result_json({"success": True, "message": f"Deleted {name}"})

# ======================== SERIAL MAPPING ========================

def action_get_serial_mapping():
    """Read serial-mapping.txt and return as structured data."""
    mappings = []
    if os.path.exists(SERIAL_MAPPING_FILE):
        with open(SERIAL_MAPPING_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    mappings.append({'serial': parts[0], 'hostname': parts[1]})
    result_json({"success": True, "mappings": mappings, "file": SERIAL_MAPPING_FILE})

def action_save_serial_mapping():
    """Save serial-mapping.txt from structured data."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    if not isinstance(data, dict) or 'mappings' not in data:
        result_json({
            'success': False, 'error_code': 'invalid_mapping',
            'error': 'Serial mapping was not saved: mappings must be provided',
        })
    try:
        mappings = normalize_serial_mappings(data['mappings'])
    except ValueError as exc:
        result_json({
            'success': False, 'error_code': 'invalid_mapping',
            'error': f'Serial mapping was not saved: {exc}',
        })
    lines = ["# Serial → Hostname mapping for ZTP config resolution",
             "# Format: SERIAL_NUMBER  HOSTNAME",
             ""]
    for m in mappings:
        lines.append(f"{m['serial']}  {m['hostname']}")

    content = '\n'.join(lines) + '\n'
    with upgrade_coordinator_lock():
        reject_provision_source_change_during_upgrade()
        try:
            write_managed_text(SERIAL_MAPPING_FILE, content, 0o664)
        except Exception as exc:
            result_json({
                'success': False, 'error_code': 'write_failed',
                'error': f'Serial mapping was not saved: {exc}',
            })

    result_json({
        "success": True,
        "message": f"Saved {len(mappings)} mapping(s)",
        "saved": len(mappings),
    })

# ======================== GENERATED CONFIGS ========================

def valid_generated_config_name(filename):
    return bool(re.fullmatch(
        r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}\.ya?ml', str(filename or '')
    ))

def action_list_generated_configs():
    """List YAML config files in generated_config_folder."""
    configs = []
    if os.path.isdir(GENERATED_CONFIGS_DIR):
        for f in sorted(os.listdir(GENERATED_CONFIGS_DIR)):
            if valid_generated_config_name(f):
                filepath = os.path.join(GENERATED_CONFIGS_DIR, f)
                stat = os.stat(filepath)
                hostname = f.rsplit('.', 1)[0]
                configs.append({
                    'filename': f,
                    'hostname': hostname,
                    'size': stat.st_size,
                    'mtime': int(stat.st_mtime)
                })
    result_json({"success": True, "configs": configs, "dir": GENERATED_CONFIGS_DIR})

def action_sync_generated_configs():
    """Copy generated configs from Ansible directory to web root."""
    ansible_dir = os.environ.get('ANSIBLE_DIR', '')
    if not ansible_dir:
        # Try reading from lldpq.conf
        try:
            with open('/etc/lldpq.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('ANSIBLE_DIR='):
                        ansible_dir = line.strip().split('=', 1)[1].strip('"').strip("'")
                        break
        except Exception:
            pass

    if not ansible_dir:
        error_json("ANSIBLE_DIR not configured. Set it in /etc/lldpq.conf or configure Ansible directory in install.sh")

    src_dir = os.path.join(ansible_dir, 'files', 'generated_config_folder')
    if not os.path.isdir(src_dir):
        error_json(f"Source directory not found: {src_dir}")

    copied = 0
    errors = []
    with upgrade_coordinator_lock():
        reject_provision_source_change_during_upgrade()
        try:
            ensure_managed_directory(GENERATED_CONFIGS_DIR, 0o775)
        except Exception as exc:
            error_json(f'Could not prepare generated config directory: {exc}')

        for f in os.listdir(src_dir):
            if f.endswith(('.yaml', '.yml')):
                src = os.path.join(src_dir, f)
                dst = os.path.join(GENERATED_CONFIGS_DIR, f)
                if not valid_generated_config_name(f):
                    errors.append(f'{f}: invalid generated config filename')
                    continue
                try:
                    with open(src, 'r', encoding='utf-8') as handle:
                        content = handle.read()
                    write_managed_text(dst, content, 0o664)
                    copied += 1
                except Exception as e:
                    errors.append(f"{f}: {str(e)}")

    msg = f"Synced {copied} config(s) from {src_dir}"
    if errors:
        msg += f" ({len(errors)} error(s))"
    result_json({
        "success": not errors,
        "message": msg,
        "error": '; '.join(errors) if errors else '',
        "copied": copied,
        "errors": errors,
    })

def action_upload_generated_config():
    """Upload a single YAML config file to generated_config_folder."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    filename = data.get('filename', '')
    content = data.get('content', '')

    if not filename or not content:
        error_json("Missing filename or content")
    if not filename.endswith(('.yaml', '.yml')):
        error_json("Only .yaml/.yml files allowed")
    if not valid_generated_config_name(filename):
        error_json("Invalid filename")

    dest = os.path.join(GENERATED_CONFIGS_DIR, filename)

    with upgrade_coordinator_lock():
        reject_provision_source_change_during_upgrade()
        try:
            ensure_managed_directory(GENERATED_CONFIGS_DIR, 0o775)
        except Exception as exc:
            error_json(f'Could not prepare generated config directory: {exc}')
        try:
            write_managed_text(dest, content, 0o664)
        except Exception as exc:
            result_json({
                'success': False, 'error_code': 'write_failed',
                'error': f'Generated config was not uploaded: {exc}',
            })

    result_json({"success": True, "message": f"Uploaded {filename}"})

# ======================== DEPLOY GENERATED CONFIG ========================

def deploy_config_to_device(device, server_ip):
    """Verify one canonical target, then replace its NVUE config over SSH."""
    try:
        with canonical_device_mutation(device) as canonical:
            ip = canonical['ip']
            hostname = canonical['hostname']
            filename = str(device.get('config_filename', ''))
            if filename not in (hostname + '.yaml', hostname + '.yml') or \
                    not valid_generated_config_name(filename):
                raise ValueError('Generated config no longer matches target hostname')
            if not os.path.isfile(os.path.join(GENERATED_CONFIGS_DIR, filename)):
                raise ValueError(f'Generated config is no longer available: {filename}')
            config_url = f"http://{server_ip}/generated_config_folder/{filename}"
            ssh_opts = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                        '-o', 'StrictHostKeyChecking=no', '-o',
                        'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR']
            remote_script = '\n'.join([
                'set -eu',
                remote_identity_guard_shell(
                    canonical.get('expected_mac', ''),
                    canonical.get('expected_serial', ''),
                ),
                f'CONFIG_URL={shlex.quote(config_url)}',
                'TMP="$(mktemp /tmp/lldpq-startup.XXXXXX.yaml)"',
                'cleanup() { rm -f -- "$TMP"; }',
                'trap cleanup EXIT',
                'curl -sf -- "$CONFIG_URL" -o "$TMP"',
                'test -s "$TMP"',
                'sudo nv config replace "$TMP"',
                'sudo nv config apply -y',
                'sudo nv config save',
                'echo LLDPQ_CONFIG_OK',
            ]) + '\n'
            r = subprocess.run(
                ['sudo', '-u', LLDPQ_USER, 'ssh'] + ssh_opts +
                [f'cumulus@{ip}', 'bash -s'],
                input=remote_script, capture_output=True, text=True, timeout=120
            )
        if r.returncode == 0 and 'LLDPQ_CONFIG_OK' in r.stdout:
            return {'ip': ip, 'hostname': hostname, 'success': True, 'message': 'Config applied'}
        detail = (r.stderr or r.stdout or 'Command failed').strip()[-300:]
        if r.returncode == 42 or 'identity' in detail.lower():
            detail = 'Identity verification failed: ' + detail
        return {'ip': ip, 'hostname': hostname, 'success': False, 'error': detail}
    except subprocess.TimeoutExpired:
        return {
            'ip': str(device.get('ip', '')),
            'hostname': str(device.get('hostname', '')),
            'success': False, 'error': 'Timeout (120s)',
        }
    except Exception as e:
        return {
            'ip': str(device.get('ip', '')),
            'hostname': str(device.get('hostname', '')),
            'success': False, 'error': f'Target authorization failed: {e}',
        }

def action_deploy_generated_config():
    """Deploy generated NVUE config to one or more switches via SSH."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")

    devices = data.get('devices', [])
    # Single device shorthand
    if not devices and data.get('hostname') and data.get('ip'):
        devices = [{'hostname': data['hostname'], 'ip': data['ip']}]

    if not devices:
        error_json("No devices specified")

    server_ip = get_server_ip()
    if not is_valid_server_ref(server_ip) or server_ip == '127.0.0.1':
        error_json("Cannot determine server IP for config download")

    try:
        inventory = load_canonical_inventory_bindings()
    except Exception as exc:
        error_json(f'Could not load current inventory: {exc}')
    by_target = {
        (binding.get('hostname', '').lower(), binding.get('ip', '')): binding
        for binding in inventory
        if binding.get('hostname') and binding.get('ip')
    }
    canonical_devices = []
    seen_ips = set()
    for requested in devices:
        if not isinstance(requested, dict):
            error_json('Invalid device target')
        hostname = str(requested.get('hostname', '')).strip()
        raw_ip = str(requested.get('ip', '')).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
            error_json('Invalid device hostname')
        try:
            ip = str(ipaddress.IPv4Address(raw_ip))
        except ipaddress.AddressValueError:
            error_json(f'Invalid device IP: {raw_ip}')
        binding = by_target.get((hostname.lower(), ip))
        if not binding:
            result_json({
                'success': False,
                'error_code': 'target_not_in_inventory',
                'error': (
                    f'{hostname} at {ip} no longer matches the current inventory. '
                    'Refresh discovery before deploying.'
                ),
            })
        if ip in seen_ips:
            error_json(f'Duplicate deploy target: {ip}')
        seen_ips.add(ip)
        expected_mac = normalize_identity_mac(binding.get('mac', ''))
        expected_serial = normalize_identity_serial(binding.get('serial', ''))
        if not expected_mac and not expected_serial:
            result_json({
                'success': False,
                'error_code': 'identity_unverifiable',
                'error': f'{hostname} has no inventory MAC or serial for identity verification',
            })
        config_filename = ''
        for suffix in ('.yaml', '.yml'):
            candidate = hostname + suffix
            if os.path.isfile(os.path.join(GENERATED_CONFIGS_DIR, candidate)):
                config_filename = candidate
                break
        if not config_filename:
            error_json(f'No generated config found for {hostname}')
        canonical_devices.append({
            'hostname': binding['hostname'],
            'ip': binding['ip'],
            'expected_mac': expected_mac,
            'expected_serial': expected_serial,
            'config_filename': config_filename,
        })

    # Deploy in parallel
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(deploy_config_to_device, dev, server_ip): dev
            for dev in canonical_devices
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x['hostname'])
    ok = sum(1 for r in results if r['success'])
    fail = len(results) - ok

    result_json({
        "success": True,
        "results": results,
        "summary": {"ok": ok, "fail": fail, "total": len(results)}
    })

# ======================== UPDATE ROLE ========================

def action_update_role():
    """Update device role in devices.yaml. Adds @role suffix or updates existing."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON data")
    
    hostname = data.get('hostname', '').strip()
    ip = data.get('ip', '').strip()
    role = data.get('role', '').strip().lower()
    
    if not hostname or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', hostname):
        error_json("Valid hostname required")
    if role and not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,63}', role):
        error_json("Invalid role")
    if ip:
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            error_json("Invalid IP address")
    
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    if not os.path.exists(devices_file):
        error_json("devices.yaml not found")

    # Every devices.yaml writer participates in the inventory transaction.
    # This endpoint terminates via result_json/error_json, so the short-lived
    # CGI process releases this handle on every response path.
    role_lock = open(INVENTORY_LOCK_FILE, 'a+')
    fcntl.flock(role_lock.fileno(), fcntl.LOCK_EX)
    
    try:
        # Read with ruamel.yaml to preserve comments
        from ruamel.yaml import YAML
        yaml = YAML()
        yaml.preserve_quotes = True
        
        with open(devices_file, 'r') as f:
            ddata = yaml.load(f)
        
        if not ddata:
            ddata = {}
        
        devices = ddata.get('devices', ddata)
        
        # Find the device by hostname
        found = False
        for dev_ip, info in devices.items():
            if dev_ip in ('defaults', 'endpoint_hosts'):
                continue
            if isinstance(info, str):
                # Parse "Hostname @role" format
                import re
                m = re.match(r'^(.+?)\s+@([A-Za-z0-9_.-]+)$', info.strip())
                h = m.group(1).strip() if m else info.strip()
                if h == hostname:
                    # Update: set new value with role
                    if role:
                        devices[dev_ip] = f"{hostname} @{role}"
                    else:
                        devices[dev_ip] = hostname
                    found = True
                    break
            elif isinstance(info, dict):
                if info.get('hostname', '') == hostname:
                    if role:
                        info['role'] = role
                    elif 'role' in info:
                        del info['role']
                    found = True
                    break
        
        # If not found and we have IP, add it
        if not found and ip:
            if role:
                devices[ip] = f"{hostname} @{role}"
            else:
                devices[ip] = hostname
            found = True
        
        if not found:
            error_json(f"Device {hostname} not found in devices.yaml")
        
        # Render and validate completely before the atomic replacement.
        output = io.StringIO()
        yaml.dump(ddata, output)
        content = output.getvalue()
        import yaml as verify_yaml
        verify_yaml.safe_load(content)
        atomic_write_text(devices_file, content, 0o664)
        
        result_json({"success": True,
                     "message": f"Role updated: {hostname} -> {role or '(none)'}",
                     "revision": inventory_revision()})
    
    except ImportError:
        # Fallback: use pyyaml (no comment preservation)
        import yaml as pyyaml
        with open(devices_file, 'r') as f:
            ddata = pyyaml.safe_load(f) or {}
        
        devices = ddata.get('devices', ddata)
        found = False
        for dev_ip, info in list(devices.items()):
            if dev_ip in ('defaults', 'endpoint_hosts'):
                continue
            if isinstance(info, str):
                import re
                m = re.match(r'^(.+?)\s+@([A-Za-z0-9_.-]+)$', info.strip())
                h = m.group(1).strip() if m else info.strip()
                if h == hostname:
                    devices[dev_ip] = f"{hostname} @{role}" if role else hostname
                    found = True
                    break
            elif isinstance(info, dict) and info.get('hostname', '') == hostname:
                if role:
                    info['role'] = role
                elif 'role' in info:
                    del info['role']
                found = True
                break
        
        if not found and ip:
            devices[ip] = f"{hostname} @{role}" if role else hostname
            found = True
        
        if found:
            content = pyyaml.safe_dump(
                ddata, default_flow_style=False, allow_unicode=True,
                sort_keys=False,
            )
            pyyaml.safe_load(content)
            atomic_write_text(devices_file, content, 0o664)
            result_json({"success": True,
                         "message": f"Role updated: {hostname} -> {role or '(none)'}",
                         "revision": inventory_revision()})
        else:
            error_json(f"Device {hostname} not found")
    
    except Exception as e:
        error_json(f"Failed to update role: {str(e)}")

# ======================== LIST ROLES ========================

def action_rebuild_devices_yaml():
    """Rebuild devices.yaml from inventory bindings.
    - Grouped by role (comment header per group)
    - Sorted by IP within each group
    - Active entries: normal YAML lines
    - Planned entries (no valid MAC): commented with #
    - Entries without role: placed in 'ungrouped' section
    - Preserves defaults and endpoint_hosts from existing file
    """
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    
    try:
        bindings = normalize_inventory_bindings(data.get('bindings', []))
    except ValueError as exc:
        error_json(str(exc))
    client_revision = str(data.get('revision', '')).strip()
    first_run = bool(data.get('first_run', False))
    initial_revision = inventory_revision()
    # Callers that omit 'revision' opt out of the conflict check (legacy API behavior).
    if (not first_run) and client_revision and client_revision != initial_revision:
        result_json({'success': False, 'error_code': 'inventory_conflict',
                     'error': 'Inventory changed on the server. Reload before rebuilding.',
                     'revision': initial_revision})
    devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
    
    # Read existing file to preserve defaults, endpoint_hosts, and header
    defaults_username = 'cumulus'
    endpoint_hosts = []
    if os.path.exists(devices_file):
        try:
            import yaml
            with open(devices_file, 'r') as f:
                existing = yaml.safe_load(f) or {}
            d = existing.get('defaults', {})
            if isinstance(d, dict) and d.get('username'):
                defaults_username = d['username']
            eh = existing.get('endpoint_hosts', [])
            if isinstance(eh, list):
                endpoint_hosts = eh
        except Exception:
            pass
    
    # Group bindings by role, sort by IP within each group
    from collections import defaultdict
    groups = defaultdict(list)
    for b in bindings:
        hostname = b.get('hostname', '').strip()
        ip = b.get('ip', '').strip()
        if not hostname or not ip:
            continue
        role = b.get('role', '').strip() or 'ungrouped'
        # Use inv_status to decide: active/discovered → normal line, planned → commented
        # Static IP devices (dhcp=false) without MAC can still be active
        is_planned = b.get('inv_status', '') == 'planned'
        groups[role].append({
            'hostname': hostname,
            'ip': ip,
            'role': role,
            'planned': is_planned,
            'ip_num': sum(int(p) * (256 ** (3 - i)) for i, p in enumerate(ip.split('.'))) if ip.count('.') == 3 else 0,
        })
    
    # Sort groups alphabetically, sort entries by IP within each group
    sorted_roles = sorted(groups.keys())
    
    # Build YAML content
    lines = []
    lines.append('# devices.yaml — Auto-generated from Provision Inventory')
    lines.append(f'# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append('#')
    lines.append('')
    lines.append('defaults:')
    lines.append(f'  username: {defaults_username}')
    lines.append('')
    lines.append('devices:')
    
    active_count = 0
    planned_count = 0
    
    for role in sorted_roles:
        entries = sorted(groups[role], key=lambda e: e['ip_num'])
        lines.append('')
        lines.append(f'  # {role}')
        for e in entries:
            role_suffix = f" @{e['role']}" if e['role'] != 'ungrouped' else ''
            if e['planned']:
                lines.append(f"#  {e['ip']}: {e['hostname']}{role_suffix}")
                planned_count += 1
            else:
                lines.append(f"  {e['ip']}: {e['hostname']}{role_suffix}")
                active_count += 1
    
    # Preserve endpoint_hosts
    if endpoint_hosts:
        lines.append('')
        lines.append('endpoint_hosts:')
        for eh in endpoint_hosts:
            lines.append(f'- "{eh}"')
    
    lines.append('')
    content = '\n'.join(lines)
    
    # Commit only if none of the canonical inventory files changed while the
    # candidate was being rendered.
    backup_path = None
    with exclusive_file_lock(INVENTORY_LOCK_FILE):
        current_revision = inventory_revision()
        if current_revision != initial_revision:
            result_json({'success': False, 'error_code': 'inventory_conflict',
                         'error': 'Inventory changed while devices.yaml was being rebuilt.',
                         'revision': current_revision})
        if os.path.exists(devices_file):
            backup_path = f"{devices_file}.bak"
            try:
                shutil.copy2(devices_file, backup_path)
            except Exception:
                backup_path = None
        try:
            import yaml as verify_yaml
            verify_yaml.safe_load(content)
            atomic_write_text(devices_file, content, 0o664)
        except Exception as exc:
            error_json(f"Failed to write: {exc}")
    
    msg = f"devices.yaml rebuilt: {active_count} active, {planned_count} planned (commented)"
    if backup_path:
        msg += f". Backup: {os.path.basename(backup_path)}"
    result_json({"success": True, "message": msg, "active": active_count,
                 "planned": planned_count, "revision": inventory_revision()})

def action_list_roles():
    """List all unique roles from devices.yaml for dropdown population."""
    roles = set()
    try:
        devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_file):
            import yaml
            with open(devices_file, 'r') as f:
                ddata = yaml.safe_load(f) or {}
            devices_section = ddata.get('devices', ddata)
            if isinstance(devices_section, dict):
                for ip, info in devices_section.items():
                    if ip in ('defaults', 'endpoint_hosts'):
                        continue
                    if isinstance(info, str):
                        m = re.match(r'^.+?\s+@(\w+)$', info.strip())
                        if m:
                            roles.add(m.group(1).lower())
                    elif isinstance(info, dict):
                        r = info.get('role', '')
                        if r:
                            roles.add(r.lower())
    except Exception:
        pass
    # Also include roles from inventory.json
    try:
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, 'r') as f:
                inv = json.load(f)
            for b in inv.get('bindings', []):
                r = b.get('role', '').strip().lower()
                if r:
                    roles.add(r)
    except Exception:
        pass
    result_json({"success": True, "roles": sorted(roles)})

# ======================== HANDOVER TRACKING ========================

def _load_tracking_support():
    """Load the lifecycle helper from the configured LLDPq installation."""
    if LLDPQ_DIR not in sys.path:
        sys.path.insert(0, LLDPQ_DIR)
    try:
        from tracking_config import (
            TrackingConfigError,
            TrackingConflictError,
            TrackingValidationError,
            get_tracking_payload,
            save_tracking,
        )
    except Exception as exc:
        raise RuntimeError("Tracking API support is unavailable") from exc
    return (
        TrackingConfigError,
        TrackingConflictError,
        TrackingValidationError,
        get_tracking_payload,
        save_tracking,
    )


def action_get_tracking():
    """Return the effective state of every switch in devices.yaml."""
    try:
        (
            TrackingConfigError,
            _TrackingConflictError,
            TrackingValidationError,
            get_tracking_payload,
            _save_tracking,
        ) = _load_tracking_support()
    except Exception:
        result_json({
            'success': False,
            'error_code': 'tracking_unavailable',
            'error': 'Tracking API support is unavailable',
        })
    try:
        payload = get_tracking_payload(
            os.path.join(LLDPQ_DIR, 'devices.yaml'),
            os.path.join(LLDPQ_DIR, 'tracking.yaml'),
        )
        result_json(payload)
    except TrackingValidationError as exc:
        result_json({
            'success': False,
            'error_code': 'tracking_validation',
            'error': str(exc),
        })
    except TrackingConfigError as exc:
        result_json({
            'success': False,
            'error_code': 'tracking_unavailable',
            'error': str(exc),
        })
    except Exception:
        result_json({
            'success': False,
            'error_code': 'tracking_unavailable',
            'error': 'Tracking configuration could not be read',
        })


def _save_tracking_as_collector(request):
    """Run the atomic writer as LLDPQ_USER, which owns the 0750 config dir."""
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9._-]*[$]?', LLDPQ_USER):
        raise RuntimeError('Configured LLDPq service user is invalid')
    helper = os.path.join(LLDPQ_DIR, 'tracking_config.py')
    if not os.path.isfile(helper):
        raise RuntimeError('Tracking API support is unavailable')
    helper_arguments = [
        sys.executable,
        helper,
        'save-json',
        '--devices', os.path.join(LLDPQ_DIR, 'devices.yaml'),
        '--tracking', os.path.join(LLDPQ_DIR, 'tracking.yaml'),
        '--changed-by', os.environ.get('LLDPQ_AUTH_USER', ''),
        '--file-group', 'www-data',
    ]
    try:
        service_account = pwd.getpwnam(LLDPQ_USER)
    except KeyError as exc:
        raise RuntimeError('Configured LLDPq service user is unavailable') from exc
    if os.geteuid() == service_account.pw_uid:
        command = helper_arguments
    else:
        # Native installs intentionally keep LLDPQ_DIR at 0750.  The existing
        # sudoers policy permits this fixed bash launcher as LLDPQ_USER; all
        # variable values remain positional argv and are never shell-expanded.
        command = [
            'sudo', '-n', '-H', '-u', LLDPQ_USER,
            '/usr/bin/bash', '-c', 'exec "$@"', '--',
        ] + helper_arguments
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(request, separators=(',', ':')),
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Tracking save timed out') from exc
    except OSError as exc:
        raise RuntimeError('Tracking writer could not be started') from exc
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError('Tracking writer failed')
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError('Tracking writer returned an invalid response') from exc
    if not isinstance(payload, dict) or 'success' not in payload:
        raise RuntimeError('Tracking writer returned an invalid response')
    return payload


def action_save_tracking():
    """Atomically replace the desired handed-over switch set."""
    if os.environ.get('REQUEST_METHOD', 'GET').upper() != 'POST':
        result_json({
            'success': False,
            'error_code': 'method_not_allowed',
            'error': 'POST method required',
        })
    try:
        request = json.loads(POST_DATA)
    except (TypeError, ValueError):
        result_json({
            'success': False,
            'error_code': 'tracking_validation',
            'error': 'Invalid JSON',
        })
    if not isinstance(request, dict):
        result_json({
            'success': False,
            'error_code': 'tracking_validation',
            'error': 'JSON body must be an object',
        })

    try:
        # Backup/restore and Setup editors own the global configuration lock;
        # Provision inventory writers own the inventory lock.  Take both in
        # the installer's canonical global -> inventory order so neither can
        # replace devices/tracking between revision validation and publish.
        with _exclusive_regular_lock(
                CONFIG_LOCK_FILE, DEFAULT_CONFIG_LOCK_FILE), \
             exclusive_file_lock(INVENTORY_LOCK_FILE):
            payload = _save_tracking_as_collector(request)
        result_json(payload)
    except Exception as exc:
        result_json({
            'success': False,
            'error_code': 'tracking_write_failed',
            'error': str(exc) or 'Handover assignments could not be saved',
        })

# ======================== ZTP TAB BULK LOAD ========================

def action_load_ztp_tab():
    """Load all ZTP tab data in a single request to avoid multiple CGI startups."""
    result = {}

    # ZTP script
    try:
        if os.path.exists(ZTP_SCRIPT_FILE):
            with open(ZTP_SCRIPT_FILE, 'r') as f:
                result['ztp_script'] = {"success": True, "content": f.read(), "file": ZTP_SCRIPT_FILE}
        else:
            result['ztp_script'] = {"success": True, "content": "", "file": ZTP_SCRIPT_FILE}
    except Exception as e:
        result['ztp_script'] = {"success": False, "error": str(e)}

    # SSH key
    try:
        pub_key, key_type, key_file = get_ssh_key_info()
        result['ssh_key'] = {"success": True, "public_key": pub_key or "", "key_type": key_type or "", "key_file": key_file or ""}
    except Exception as e:
        result['ssh_key'] = {"success": False, "error": str(e)}

    # OS images
    try:
        result['os_images'] = {"success": True, "images": list_os_image_objects()}
    except Exception as e:
        result['os_images'] = {"success": False, "error": str(e)}

    # Serial mapping
    try:
        mappings = []
        if os.path.exists(SERIAL_MAPPING_FILE):
            with open(SERIAL_MAPPING_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        mappings.append({'serial': parts[0], 'hostname': parts[1]})
        result['serial_mapping'] = {"success": True, "mappings": mappings}
    except Exception as e:
        result['serial_mapping'] = {"success": False, "error": str(e)}

    # Generated configs
    try:
        configs = []
        if os.path.isdir(GENERATED_CONFIGS_DIR):
            for f in sorted(os.listdir(GENERATED_CONFIGS_DIR)):
                if f.endswith(('.yaml', '.yml')):
                    filepath = os.path.join(GENERATED_CONFIGS_DIR, f)
                    stat = os.stat(filepath)
                    configs.append({'filename': f, 'hostname': f.rsplit('.', 1)[0], 'size': stat.st_size, 'mtime': int(stat.st_mtime)})
        result['generated_configs'] = {"success": True, "configs": configs}
    except Exception as e:
        result['generated_configs'] = {"success": False, "error": str(e)}

    result['success'] = True
    result_json(result)

# ======================== ROUTER ========================

# Any process entering Provision waits behind an active inventory transaction.
# If the previous writer was killed after publishing its durable marker, finish
# that recovery before readers, schedulers or workers consume mixed generations.
try:
    recover_pending_provision_transaction()
except Exception as recovery_exc:
    if ACTION in ('discovery-worker', 'discovery-schedule', 'upgrade-resume',
                  'upgrade-worker'):
        print(
            'Provision transaction recovery failed: ' + str(recovery_exc),
            file=sys.stderr,
        )
        sys.exit(1)
    result_json({
        'success': False,
        'error_code': 'provision_recovery_failed',
        'error': 'A previous Provision save could not be recovered: ' +
                 str(recovery_exc),
    })

if ACTION == 'discovery-worker':
    run_discovery_worker(DISCOVERY_JOB_ID)
    sys.exit(0)
elif ACTION == 'discovery-schedule':
    run_discovery_schedule()
    sys.exit(0)
elif ACTION == 'upgrade-resume':
    resume_upgrade_workers()
    sys.exit(0)
elif ACTION == 'upgrade-worker':
    run_upgrade_worker(UPGRADE_JOB_ID)
    sys.exit(0)
elif ACTION == 'list-bindings':
    action_list_bindings()
elif ACTION == 'save-bindings':
    action_save_bindings()
elif ACTION == 'discovered':
    # Legacy: replaced by subnet-scan. Kept for backward compat.
    action_discovered()
elif ACTION == 'get-ztp-script':
    action_get_ztp_script()
elif ACTION == 'save-ztp-script':
    action_save_ztp_script()
elif ACTION == 'dhcp-service-status':
    action_dhcp_service_status()
elif ACTION == 'dhcp-service-control':
    action_dhcp_service_control()
elif ACTION == 'get-dhcp-hosts':
    hosts_path = get_dhcp_hosts_path()
    bindings = parse_dhcp_hosts(hosts_path)
    result_json({"success": True, "bindings": bindings, "file": hosts_path})
elif ACTION == 'get-dhcp-config':
    action_get_dhcp_config()
elif ACTION == 'save-dhcp-config':
    action_save_dhcp_config()
elif ACTION == 'dhcp-leases':
    action_dhcp_leases()
elif ACTION == 'dhcp-log':
    action_dhcp_log()
elif ACTION == 'list-devices':
    action_list_devices()
elif ACTION == 'deploy-base-config':
    action_deploy_base_config()
elif ACTION == 'upgrade-candidates':
    action_upgrade_candidates()
elif ACTION == 'upgrade-precheck':
    action_upgrade_precheck()
elif ACTION == 'upgrade-start':
    action_upgrade_start()
elif ACTION == 'upgrade-status':
    action_upgrade_status()
elif ACTION == 'upgrade-active':
    action_upgrade_active()
elif ACTION == 'upgrade-cancel':
    action_upgrade_cancel()
elif ACTION == 'ping-scan':
    # Legacy: replaced by subnet-scan. Kept for backward compat.
    action_ping_scan()
elif ACTION == 'subnet-scan':
    action_subnet_scan()
elif ACTION == 'discovery-start':
    action_discovery_start()
elif ACTION == 'discovery-status':
    action_discovery_status()
elif ACTION == 'discovery-active':
    action_discovery_active()
elif ACTION == 'discovery-cache':
    action_get_discovery_cache()
elif ACTION == 'save-post-provision':
    action_save_post_provision()
elif ACTION == 'get-ssh-key':
    action_get_ssh_key()
elif ACTION == 'generate-ssh-key':
    action_generate_ssh_key()
elif ACTION == 'import-ssh-key':
    action_import_ssh_key()
elif ACTION == 'list-os-images':
    action_list_os_images()
elif ACTION == 'upload-os-image':
    action_upload_os_image()
elif ACTION == 'delete-os-image':
    action_delete_os_image()
elif ACTION == 'get-serial-mapping':
    action_get_serial_mapping()
elif ACTION == 'save-serial-mapping':
    action_save_serial_mapping()
elif ACTION == 'list-generated-configs':
    action_list_generated_configs()
elif ACTION == 'sync-generated-configs':
    action_sync_generated_configs()
elif ACTION == 'upload-generated-config':
    action_upload_generated_config()
elif ACTION == 'deploy-generated-config':
    action_deploy_generated_config()
elif ACTION == 'load-ztp-tab':
    action_load_ztp_tab()
elif ACTION == 'update-role':
    action_update_role()
elif ACTION == 'list-roles':
    action_list_roles()
elif ACTION == 'rebuild-devices-yaml':
    action_rebuild_devices_yaml()
elif ACTION == 'get-tracking':
    action_get_tracking()
elif ACTION == 'save-tracking':
    action_save_tracking()
else:
    error_json(f"Unknown action: {ACTION}")

PYTHON_SCRIPT
